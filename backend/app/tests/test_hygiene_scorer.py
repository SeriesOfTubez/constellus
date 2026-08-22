"""Unit + DB-driver coverage of the asset hygiene scorer (planning#130, L1).

Two layers of test here, deliberately kept apart:

  * The five dimension functions (`_dim_coverage`/`_dim_health`/
    `_dim_currency`/`_dim_exposure`/`_dim_ownership`) and `score_asset`
    itself are PURE — no DB queries inside, per the module's own docstring
    — so most of the tests below construct plain `AssetCanonical`/
    `AssetState`/`ClaimRow` objects directly (never added to a session,
    never committed) and call the scoring functions straight, no DB round-
    trip at all. This mirrors `test_partition_maintenance.py` importing
    private helpers (`_add_months`, `_month_start`, ...) directly rather
    than only exercising the public `run()` entry point.
  * `run()` itself — the batching, the exclusion filter, the upsert, the
    stale-row delete — genuinely needs a live DB, so those tests (bottom of
    this file) seed real rows the same direct way `test_projector.py` and
    `test_claims_query.py` do, then call `hygiene_scorer.run(db)` and
    inspect the resulting `asset_hygiene_score` rows.

Run with:  python -m app.tests.test_hygiene_scorer
       or: pytest app/tests/test_hygiene_scorer.py
"""

import uuid
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import event, text

from app.core.database import SessionLocal, engine
from app.models.asset_canonical import AssetCanonical
from app.models.asset_hygiene_score import AssetHygieneScore
from app.models.asset_state import AssetState
from app.models.claim import AssetClaim
from app.models.observer import Observer
from app.services import hygiene_scorer
from app.services.hygiene_scorer import (
    BATCH_SIZE,
    GRADE_SCORES,
    ClaimRow,
    _dim_coverage,
    _dim_currency,
    _dim_exposure,
    _dim_health,
    _dim_ownership,
    score_asset,
)

_NOW = datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc)


# ── helpers ──────────────────────────────────────────────────────────────

def _transient_asset(tags: list | None = None) -> AssetCanonical:
    """An in-memory-only AssetCanonical — never added to a session. Valid
    for score_asset()/the dimension functions, which only ever read
    `.tags` off it and never query the DB themselves."""
    return AssetCanonical(id=uuid.uuid4(), asset_type="ip_address", value="unused", tags=tags or [])


def _transient_state(probe_class: str | None = None, open_ports: list | None = None) -> AssetState:
    attributes = {"probe_class": probe_class} if probe_class is not None else {}
    return AssetState(open_ports=open_ports or [], attributes=attributes)


def _observer_id(db, name: str) -> uuid.UUID:
    return db.query(Observer).filter(Observer.name == name).one().id


def _mk_asset(db, value: str, asset_type: str = "ip_address", tags: list | None = None, ignored: bool = False) -> AssetCanonical:
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type=asset_type, value=value,
        first_seen_at=now, last_seen_at=now, ignored=ignored, tags=tags or [],
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _mk_state(db, asset_id: uuid.UUID, estate: str | None = None, open_ports: list | None = None, probe_class: str | None = None) -> None:
    attributes = {"probe_class": probe_class} if probe_class is not None else {}
    db.add(AssetState(
        asset_canonical_id=asset_id, estate=estate, open_ports=open_ports or [],
        attributes=attributes, projected_at=datetime.now(timezone.utc),
    ))
    db.commit()


def _add_claim(db, asset_id: uuid.UUID, observer_name: str, claim_type: str, claim_value: dict, last_observed_at: datetime) -> None:
    db.add(AssetClaim(
        asset_canonical_id=asset_id,
        observer_id=_observer_id(db, observer_name),
        claim_type=claim_type,
        claim_value=claim_value,
        evidence={},
        first_observed_at=last_observed_at,
        last_observed_at=last_observed_at,
    ))
    db.commit()


def _cleanup(values: list[str]) -> None:
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).all()
        ids = [r.id for r in rows]
        if ids:
            db.query(AssetClaim).filter(AssetClaim.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
            db.query(AssetState).filter(AssetState.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
            db.query(AssetHygieneScore).filter(AssetHygieneScore.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _cleanup_prefix(value_prefix: str) -> None:
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value.like(f"{value_prefix}%")).all()
        ids = [r.id for r in rows]
        if ids:
            db.query(AssetClaim).filter(AssetClaim.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
            db.query(AssetState).filter(AssetState.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
            db.query(AssetHygieneScore).filter(AssetHygieneScore.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value.like(f"{value_prefix}%")).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _assert_raises_value_error(fn, *args, **kwargs) -> None:
    try:
        fn(*args, **kwargs)
    except ValueError:
        return
    raise AssertionError(f"expected ValueError from {fn.__name__}{args!r}{kwargs!r}")


def _count_queries(fn) -> int:
    """Number of statements sent to the DBAPI cursor while `fn()` runs —
    the mechanism test_run_is_batched uses to prove run() doesn't issue a
    per-asset query."""
    count = 0

    def _listener(conn, cursor, statement, parameters, context, executemany):
        nonlocal count
        count += 1

    event.listen(engine, "before_cursor_execute", _listener)
    try:
        fn()
    finally:
        event.remove(engine, "before_cursor_execute", _listener)
    return count


# ── the headline acceptance criterion ───────────────────────────────────────

def test_unknown_ranks_below_bad():
    """GRADE_SCORES["unknown"] < GRADE_SCORES["bad"], and that ordering
    actually moves the composite: an asset with unknown dimensions scores
    strictly lower than the same asset with those dimensions bad.

    Two of the five dimensions structurally cannot reach "bad" at all in
    v1: coverage is always unknown (no producer to grade against yet), and
    ownership's worst reachable grade for an in-scope asset is "fair"
    (not_ours — the only path to a truly adverse ownership finding — is
    excluded from scoring entirely, see settled rule 1). So "an asset whose
    dimensions are all bad" is unrealizable literally as five-for-five; the
    two structurally-pinned dimensions are held at the SAME value (unknown)
    in both comparison assets below, and the three dimensions that genuinely
    can reach "bad" — health, currency, exposure — are the ones flipped.
    That is what actually exercises GRADE_SCORES' ordering inside
    score_asset's aggregation; holding coverage/ownership constant doesn't
    weaken the comparison, it just keeps the test realizable.
    """
    assert GRADE_SCORES["unknown"] < GRADE_SCORES["bad"], GRADE_SCORES

    asset = _transient_asset(tags=[])

    # All five dimensions unknown: no state (exposure), no claims
    # (health/currency), surface=unknown (ownership), coverage always.
    all_unknown = score_asset(asset, None, [], "unknown", now=_NOW)
    assert all_unknown["dimensions"]["coverage"]["grade"] == "unknown"
    assert all_unknown["dimensions"]["health"]["grade"] == "unknown"
    assert all_unknown["dimensions"]["currency"]["grade"] == "unknown"
    assert all_unknown["dimensions"]["exposure"]["grade"] == "unknown"
    assert all_unknown["dimensions"]["ownership"]["grade"] == "unknown"

    # health/currency/exposure pushed to bad; coverage/ownership held at
    # the same "unknown" they were above (coverage always is; ownership via
    # the same surface="unknown").
    # Both claims dated 200d stale — health's freshest-of-ANY-type max()
    # would otherwise pick up eol_claim's timestamp and grade excellent
    # even with a genuinely ancient port_observation claim alongside it.
    stale = _NOW - timedelta(days=200)
    stale_claim = ClaimRow("port_observation", {"ports": []}, stale)
    eol_claim = ClaimRow("eol_status", {"services": [{"product": "old-thing", "is_eol": True, "eol_date": "2020-01-01"}]}, stale)
    bad_state = _transient_state(probe_class="direct_addressable", open_ports=[{"port": 3389, "protocol": "tcp"}])
    mixed_bad = score_asset(asset, bad_state, [stale_claim, eol_claim], "unknown", now=_NOW)
    assert mixed_bad["dimensions"]["coverage"]["grade"] == "unknown"
    assert mixed_bad["dimensions"]["health"]["grade"] == "bad"
    assert mixed_bad["dimensions"]["currency"]["grade"] == "bad"
    assert mixed_bad["dimensions"]["exposure"]["grade"] == "bad"
    assert mixed_bad["dimensions"]["ownership"]["grade"] == "unknown"

    assert all_unknown["score"] < mixed_bad["score"], (all_unknown["score"], mixed_bad["score"])


def test_unknown_dimensions_stay_in_denominator():
    """The composite of an asset with one unknown dimension (exposure, here)
    is strictly lower than the same asset with that dimension good — and
    the denominator is 5 in both cases, proven by checking the exact
    composite value, not just its direction: if the unknown dimension were
    (incorrectly) dropped from the mean instead of counted as 0, the
    "unknown" case's composite would come out HIGHER (75, mean of the three
    non-unknown/non-coverage dims) than what dividing by 5 actually gives
    (45) — the opposite of what this test asserts.
    """
    asset = _transient_asset(tags=["team:example"])
    fresh_claim = ClaimRow("naabu_probe", {}, _NOW - timedelta(days=1))
    eol_claim = ClaimRow("eol_status", {"services": [{"product": "current-thing", "is_eol": False, "eol_date": None}]}, _NOW)
    claims = [fresh_claim, eol_claim]

    # exposure unknown (no asset_state row at all); health/currency/ownership
    # all fixed to non-unknown values across both cases below.
    result_unknown = score_asset(asset, None, claims, "claimed_ours", now=_NOW)
    assert result_unknown["dimensions"]["exposure"]["grade"] == "unknown"
    assert result_unknown["dimensions"]["coverage"]["grade"] == "unknown"
    assert result_unknown["dimensions"]["health"]["grade"] == "excellent"
    assert result_unknown["dimensions"]["currency"]["grade"] == "good"
    assert result_unknown["dimensions"]["ownership"]["grade"] == "good"
    assert len(result_unknown["dimensions"]) == 5
    # coverage=0, health=100, currency=75, exposure=0, ownership=75 -> 250/5=50
    assert result_unknown["score"] == 50, result_unknown

    good_state = _transient_state(probe_class="direct_addressable", open_ports=[{"port": 8080, "protocol": "tcp"}])
    result_good = score_asset(asset, good_state, claims, "claimed_ours", now=_NOW)
    assert result_good["dimensions"]["exposure"]["grade"] == "good"
    assert len(result_good["dimensions"]) == 5
    # coverage=0, health=100, currency=75, exposure=75, ownership=75 -> 325/5=65
    assert result_good["score"] == 65, result_good

    assert result_unknown["score"] < result_good["score"], (result_unknown["score"], result_good["score"])


# ── coverage ─────────────────────────────────────────────────────────────

def test_coverage_always_unknown():
    grade, reason_codes, detail = _dim_coverage()
    assert grade == "unknown"
    assert reason_codes == ["coverage_no_producers"]
    assert detail  # non-empty explanation


# ── currency ─────────────────────────────────────────────────────────────

def test_currency_no_eol_claim():
    grade, reason_codes, _ = _dim_currency([], _NOW)
    assert grade == "unknown"
    assert reason_codes == ["currency_no_eol_claim"]


def test_currency_empty_services_is_unknown_not_good():
    """Zero identified products is an observation gap, not a clean bill of
    health — must NOT grade 'good'. This is the inversion running
    backwards if it's ever "fixed" the other way."""
    claims = [ClaimRow("eol_status", {"services": []}, _NOW)]
    grade, reason_codes, _ = _dim_currency(claims, _NOW)
    assert grade == "unknown"
    assert reason_codes == ["currency_no_identifiable_products"]


def test_currency_is_eol_grades_bad():
    """Also the list-vs-dict regression guard: `services` here is a real
    LIST with two entries, and both must be read as list elements (not
    silently discarded by a stray `isinstance(dict)` check like the bug
    the projector's L3c-2 note documents) — the EOL product name from the
    second entry must reach the detail string."""
    claims = [ClaimRow("eol_status", {"services": [
        {"product": "current-thing", "is_eol": False, "eol_date": None},
        {"product": "ancient-thing", "is_eol": True, "eol_date": "2019-06-01"},
    ]}, _NOW)]
    grade, reason_codes, detail = _dim_currency(claims, _NOW)
    assert grade == "bad"
    assert reason_codes == ["currency_eol_product"]
    assert "ancient-thing" in detail, detail


def test_currency_approaching_eol_grades_fair():
    near_date = (_NOW.date() + timedelta(days=60)).isoformat()
    claims = [ClaimRow("eol_status", {"services": [
        {"product": "aging-thing", "is_eol": False, "eol_date": near_date},
    ]}, _NOW)]
    grade, reason_codes, _ = _dim_currency(claims, _NOW)
    assert grade == "fair"
    assert reason_codes == ["currency_approaching_eol"]


def test_currency_elapsed_eol_date_beats_stale_is_eol_flag():
    """A claim written BEFORE the product's EOL date stores `is_eol: False`
    forever, because `eol_enrichment._parse_eol` freezes that flag against
    `date.today()` at WRITE time and the claim outlives that day. Once the
    date passes, the asset is EOL whether or not enrichment has re-run.

    Regression guard: this used to grade `fair` with the reason
    "approaching EOL" for a date already 52 days in the past — a stale
    observation reading as healthier than reality, the exact inversion
    failure this feature exists to prevent.
    """
    past_date = (_NOW.date() - timedelta(days=52)).isoformat()
    claims = [ClaimRow("eol_status", {"services": [
        {"product": "example-runtime", "is_eol": False, "eol_date": past_date},
    ]}, _NOW - timedelta(days=200))]
    grade, reason_codes, detail = _dim_currency(claims, _NOW)
    assert grade == "bad", (grade, detail)
    assert reason_codes == ["currency_eol_product"]
    assert "example-runtime" in detail


def test_currency_unnamed_eol_record_still_grades_bad():
    """An `is_eol: True` record with no product name must still grade
    `bad`. Regression guard: the EOL filter used to require a truthy
    `product` in the same comprehension that detected EOL-ness, so an
    unnamed EOL record was dropped entirely and the asset graded `good`
    with the detail "No EOL or approaching-EOL products identified" —
    asserting the opposite of the truth. Detection must not depend on
    having a name to print.
    """
    for missing in (None, ""):
        claims = [ClaimRow("eol_status", {"services": [
            {"product": missing, "is_eol": True, "eol_date": None},
        ]}, _NOW)]
        grade, reason_codes, detail = _dim_currency(claims, _NOW)
        assert grade == "bad", (missing, grade, detail)
        assert reason_codes == ["currency_eol_product"]
        assert "1 unnamed product(s)" in detail


# ── exposure ─────────────────────────────────────────────────────────────

def test_exposure_never_scanned_vs_nothing_open():
    """The point of this dimension: empty open_ports means two different
    things depending on whether a port_observation claim exists at all."""
    state = _transient_state(probe_class="direct_addressable", open_ports=[])

    never_scanned = _dim_exposure(state, [])
    assert never_scanned[0] == "unknown"
    assert never_scanned[1] == ["exposure_never_scanned"]

    scanned_clean = _dim_exposure(state, [ClaimRow("port_observation", {"ports": []}, _NOW)])
    assert scanned_clean[0] == "excellent"
    assert scanned_clean[1] == ["exposure_no_open_ports"]


def test_exposure_no_projection_and_not_directly_probeable():
    assert _dim_exposure(None, [])[0] == "unknown"
    assert _dim_exposure(None, [])[1] == ["exposure_no_projection"]

    name_only = _transient_state(probe_class="name_only")
    grade, codes, _ = _dim_exposure(name_only, [])
    assert grade == "unknown"
    assert codes == ["exposure_not_directly_probeable"]

    no_probe = _transient_state(probe_class="no_probe")
    grade, codes, _ = _dim_exposure(no_probe, [])
    assert grade == "unknown"
    assert codes == ["exposure_not_directly_probeable"]


def test_exposure_high_risk_port_and_many_ports():
    high_risk_state = _transient_state(probe_class="direct_addressable", open_ports=[
        {"port": 22, "protocol": "tcp"}, {"port": 3389, "protocol": "tcp"},
    ])
    grade, codes, detail = _dim_exposure(high_risk_state, [])
    assert grade == "bad"
    assert codes == ["exposure_high_risk_port"]
    assert "3389" in detail

    many_ports_state = _transient_state(
        probe_class="direct_addressable",
        open_ports=[{"port": p, "protocol": "tcp"} for p in range(8000, 8012)],  # 12 ports, none high-risk
    )
    grade, codes, _ = _dim_exposure(many_ports_state, [])
    assert grade == "fair"
    assert codes == ["exposure_many_ports"]

    normal_state = _transient_state(probe_class="direct_addressable", open_ports=[{"port": 8080, "protocol": "tcp"}])
    grade, codes, _ = _dim_exposure(normal_state, [])
    assert grade == "good"
    assert codes == ["exposure_normal"]


# ── health ───────────────────────────────────────────────────────────────

def test_health_freshness_thresholds():
    assert _dim_health([], _NOW)[0] == "unknown"

    fresh = [ClaimRow("x", {}, _NOW - timedelta(days=3))]
    assert _dim_health(fresh, _NOW)[0] == "excellent"

    recent = [ClaimRow("x", {}, _NOW - timedelta(days=20))]
    assert _dim_health(recent, _NOW)[0] == "good"

    aging = [ClaimRow("x", {}, _NOW - timedelta(days=60))]
    assert _dim_health(aging, _NOW)[0] == "fair"

    stale = [ClaimRow("x", {}, _NOW - timedelta(days=200))]
    grade, codes, _ = _dim_health(stale, _NOW)
    assert grade == "bad"
    assert codes == ["health_stale"]

    # Health looks at the FRESHEST claim of any type, not any one type.
    mixed = [ClaimRow("old_type", {}, _NOW - timedelta(days=200)), ClaimRow("new_type", {}, _NOW - timedelta(days=1))]
    assert _dim_health(mixed, _NOW)[0] == "excellent"


# ── ownership ────────────────────────────────────────────────────────────

def test_ownership_tags_and_surface():
    assert _dim_ownership("unknown", [])[0] == "unknown"
    assert _dim_ownership("unknown", ["team:x"])[0] == "unknown"  # tags irrelevant without a surface signal

    grade, codes, _ = _dim_ownership("proven_ours", [])
    assert grade == "good" and codes == ["ownership_untagged"]
    assert _dim_ownership("proven_ours", ["team:x"])[0] == "excellent"

    grade, codes, _ = _dim_ownership("claimed_ours", [])
    assert grade == "fair" and codes == ["ownership_untagged"]
    assert _dim_ownership("claimed_ours", ["team:x"])[0] == "good"

    _assert_raises_value_error(_dim_ownership, "not_ours", [])


# ── run(): DB-backed batching / exclusion / idempotency ─────────────────────

def test_not_ours_is_excluded():
    """An asset with estate=not_ours gets no score row from run(), and an
    EXISTING row for it (simulating a stale score from before it became
    not_ours) is deleted."""
    suffix = uuid.uuid4().hex[:10]
    value = f"hygiene-notours-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_asset(db, value)
        _mk_state(db, asset.id, estate="not_ours")
        db.add(AssetHygieneScore(
            asset_canonical_id=asset.id, score=80, band="good", dimensions={},
            computed_at=datetime.now(timezone.utc),
        ))
        db.commit()

        hygiene_scorer.run(db)

        assert db.get(AssetHygieneScore, asset.id) is None
    finally:
        db.close()
        _cleanup([value])


def test_name_only_asset_stays_in_scope():
    """Settled rule 1: exclusion is off surface, never probe_class. A
    name_only asset (CDN-fronted/shared hosting) IS scored — its exposure
    dimension just can't be graded (unknown), because there's no port
    truth to grade a name_only asset on."""
    suffix = uuid.uuid4().hex[:10]
    value = f"hygiene-nameonly-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_asset(db, value)
        _mk_state(db, asset.id, probe_class="name_only")  # estate stays NULL -> surface="unknown", not "not_ours"

        hygiene_scorer.run(db)

        row = db.get(AssetHygieneScore, asset.id)
        assert row is not None, "name_only asset must still be scored"
        assert row.dimensions["exposure"]["grade"] == "unknown"
        assert row.dimensions["exposure"]["reason_codes"] == ["exposure_not_directly_probeable"]
    finally:
        db.close()
        _cleanup([value])


def test_run_is_batched():
    """run() must not issue a per-asset query. Seed well over BATCH_SIZE
    (500) assets and prove the query count stays a small, bounded multiple
    of the number of BATCHES (~2 here), not anywhere near one-per-asset —
    at N=600, a per-asset implementation would issue hundreds to
    thousands of statements; the batched implementation issues on the
    order of ten times the chunk count instead. The exact bound below (120)
    is deliberately generous — the point is proving sub-linearity in N, not
    pinning an exact query count that would make this test brittle against
    an unrelated future query added to run()."""
    n = BATCH_SIZE + 100
    suffix = uuid.uuid4().hex[:10]
    prefix = f"hygiene-batch-{suffix}-"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        db.add_all([
            AssetCanonical(id=uuid.uuid4(), asset_type="ip_address", value=f"{prefix}{i}", first_seen_at=now, last_seen_at=now)
            for i in range(n)
        ])
        db.commit()

        query_count = _count_queries(lambda: hygiene_scorer.run(db))

        assert query_count < 120, (
            f"expected a bounded, batched query count for {n} assets; got {query_count}"
        )
    finally:
        db.close()
        _cleanup_prefix(prefix)


def test_run_upserts_idempotently():
    """Two consecutive run() calls leave exactly one row per asset and
    produce an identical score — proves the ON CONFLICT DO UPDATE upsert,
    not an insert-only path that would raise a PK violation on the second
    pass."""
    suffix = uuid.uuid4().hex[:10]
    values = [f"hygiene-idempotent-{suffix}-{i}" for i in range(3)]
    db = SessionLocal()
    try:
        assets = [_mk_asset(db, v, tags=["team:example"]) for v in values]
        for a in assets:
            _mk_state(db, a.id, probe_class="direct_addressable", open_ports=[{"port": 8080, "protocol": "tcp"}])
            _add_claim(db, a.id, "naabu", "port_observation", {"ports": [{"port": 8080}]}, datetime.now(timezone.utc))

        hygiene_scorer.run(db)
        first_pass = {
            a.id: (db.get(AssetHygieneScore, a.id).score, db.get(AssetHygieneScore, a.id).band)
            for a in assets
        }
        assert all(v is not None for v in first_pass.values())

        hygiene_scorer.run(db)
        second_pass = {
            a.id: (db.get(AssetHygieneScore, a.id).score, db.get(AssetHygieneScore, a.id).band)
            for a in assets
        }

        assert first_pass == second_pass, (first_pass, second_pass)
        row_count = db.query(AssetHygieneScore).filter(AssetHygieneScore.asset_canonical_id.in_([a.id for a in assets])).count()
        assert row_count == len(assets), "expected exactly one score row per asset after two run() calls"
    finally:
        db.close()
        _cleanup(values)


def test_hygiene_history_records_a_compensating_dimension_swap():
    """A dimension change that leaves the composite untouched must STILL
    write a history row (planning#131).

    Every dimension grades to one of five values (0/25/50/75/100) and the
    composite is their unweighted mean over five dimensions, so two
    dimensions moving in opposite directions by the same amount produce a
    byte-identical `score` and `band`. `currency` excellent -> bad while
    `exposure` goes bad -> excellent is exactly that case: the asset's
    hygiene genuinely changed, and keying the change-only append on
    `(score, band)` alone would write nothing at all — leaving the flip
    invisible forever and the last stored `dimensions` blob describing an
    asset it no longer describes. `dimensions` is therefore part of the
    comparison key; this test is what holds that in place.

    Exercises `_append_hygiene_history` directly with hand-built rows
    rather than driving `run()`: constructing real claims that produce an
    exactly-compensating swap would be an elaborate fixture proving less.
    No `assets_canonical` row is created — `hygiene_history` deliberately
    carries no FK (history outlives the entity), so an arbitrary id is a
    valid subject here.
    """
    asset_id = uuid.uuid4()
    computed_at = datetime.now(timezone.utc)

    def _row(currency: str, exposure: str) -> dict:
        # Same composite either way: GRADE_SCORES is symmetric about the
        # swap, so the mean over the five dimensions is unchanged.
        dims = {
            "coverage": {"grade": "unknown", "score": GRADE_SCORES["unknown"], "reason_codes": [], "detail": ""},
            "health": {"grade": "good", "score": GRADE_SCORES["good"], "reason_codes": [], "detail": ""},
            "currency": {"grade": currency, "score": GRADE_SCORES[currency], "reason_codes": [], "detail": ""},
            "exposure": {"grade": exposure, "score": GRADE_SCORES[exposure], "reason_codes": [], "detail": ""},
            "ownership": {"grade": "fair", "score": GRADE_SCORES["fair"], "reason_codes": [], "detail": ""},
        }
        composite = round(sum(d["score"] for d in dims.values()) / len(dims))
        return {
            "asset_canonical_id": asset_id,
            "score": composite,
            "band": hygiene_scorer._band_for_score(composite),
            "dimensions": dims,
        }

    before = _row(currency="excellent", exposure="bad")
    after = _row(currency="bad", exposure="excellent")
    assert (before["score"], before["band"]) == (after["score"], after["band"]), (
        "test precondition: the swap must leave score/band identical, "
        "otherwise this proves nothing"
    )
    assert before["dimensions"] != after["dimensions"]

    db = SessionLocal()
    try:
        assert hygiene_scorer._append_hygiene_history(db, computed_at, [before]) == 1, "baseline row"
        # Re-appending the identical row must stay a no-op — the change-only
        # rule still holds; this test widens the key, it doesn't remove it.
        assert hygiene_scorer._append_hygiene_history(db, computed_at, [before]) == 0

        written = hygiene_scorer._append_hygiene_history(db, computed_at, [after])
        assert written == 1, "a compensating dimension swap must still be recorded"

        rows = db.execute(
            text(
                "SELECT score, band, dimensions FROM hygiene_history "
                "WHERE asset_canonical_id = :aid ORDER BY computed_at, id"
            ),
            {"aid": asset_id},
        ).fetchall()
        assert len(rows) == 2
        assert rows[0].dimensions["currency"]["grade"] == "excellent"
        assert rows[1].dimensions["currency"]["grade"] == "bad"
        assert rows[0].score == rows[1].score, "the composite genuinely did not move"
    finally:
        db.execute(text("DELETE FROM hygiene_history WHERE asset_canonical_id = :aid"), {"aid": asset_id})
        db.commit()
        db.close()


def _run():
    tests = [
        test_unknown_ranks_below_bad,
        test_unknown_dimensions_stay_in_denominator,
        test_coverage_always_unknown,
        test_currency_no_eol_claim,
        test_currency_empty_services_is_unknown_not_good,
        test_currency_is_eol_grades_bad,
        test_currency_approaching_eol_grades_fair,
        test_currency_elapsed_eol_date_beats_stale_is_eol_flag,
        test_currency_unnamed_eol_record_still_grades_bad,
        test_exposure_never_scanned_vs_nothing_open,
        test_exposure_no_projection_and_not_directly_probeable,
        test_exposure_high_risk_port_and_many_ports,
        test_health_freshness_thresholds,
        test_ownership_tags_and_surface,
        test_not_ours_is_excluded,
        test_name_only_asset_stays_in_scope,
        test_run_is_batched,
        test_run_upserts_idempotently,
        test_hygiene_history_records_a_compensating_dimension_swap,
    ]
    for fn in tests:
        fn()
        print(f"ok  {fn.__name__}")
    print("all passed")


if __name__ == "__main__":
    _run()
