"""Unit coverage of the claims-layer query surface (planning#145, L4).

`app.services.claims_query` is the reusable primitive every other
consumer — `app/api/claims.py`, `app/api/assets.py`'s serializer and
`_third_party_asset_ids`, and the epic-verification test
(`test_epic_129_verification.py`) — is built on. This file exercises it
directly, seeding `AssetCanonical` / `AssetState` / `AssetClaim` rows by
hand (not through `write_assets`) so each test controls exactly which rows
exist — the same direct-seeding style as `test_projector.py`, since the
whole point of these tests is pinning behaviour at the query-primitive
boundary, not re-proving the ingest path (that's what
`test_epic_129_verification.py` is for).

Run with:  python -m app.tests.test_claims_query
       or: pytest app/tests/test_claims_query.py
"""

import uuid
from datetime import datetime, timezone

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.claim import AssetClaim
from app.models.observer import Observer
from app.services import claims_query

_CLAIM_TYPE = "port_observation"  # any real, seeded CLAIM_TYPES member


# ── helpers ──────────────────────────────────────────────────────────────

def _mk_asset(
    db, value: str, asset_type: str = "ip_address",
    last_seen_at: datetime | None = None, ignored: bool = False,
) -> AssetCanonical:
    now = last_seen_at or datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type=asset_type, value=value,
        first_seen_at=now, last_seen_at=now, ignored=ignored,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _mk_state(db, asset_id: uuid.UUID, estate: str | None) -> None:
    """Insert an `asset_state` row with the given estate (possibly NULL) —
    distinct from an asset having NO asset_state row at all, which is the
    other `"unknown"` case these tests must tell apart."""
    db.add(AssetState(
        asset_canonical_id=asset_id, estate=estate,
        projected_at=datetime.now(timezone.utc),
    ))
    db.commit()


def _observer_id(db, name: str) -> uuid.UUID:
    return db.query(Observer).filter(Observer.name == name).one().id


def _add_claim(db, asset_id: uuid.UUID, observer_name: str, claim_type: str = _CLAIM_TYPE) -> None:
    now = datetime.now(timezone.utc)
    db.add(AssetClaim(
        asset_canonical_id=asset_id,
        observer_id=_observer_id(db, observer_name),
        claim_type=claim_type,
        claim_value={},
        evidence={},
        first_observed_at=now,
        last_observed_at=now,
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
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _assert_raises_value_error(fn, *args, **kwargs) -> None:
    try:
        fn(*args, **kwargs)
    except ValueError:
        return
    raise AssertionError(f"expected ValueError from {fn.__name__}{args!r}{kwargs!r}")


# ── surface / surface_by_asset ──────────────────────────────────────────────

def test_surface_by_asset_maps_missing_row_and_null_estate_to_unknown():
    """The two distinct "unknown" cases the primitive must collapse: an id
    with no `asset_state` row at all, and one whose row has `estate IS
    NULL`. A real stored value must still pass through untouched, and
    every requested id must be present in the result — no `.get(id,
    default)` needed by callers."""
    suffix = uuid.uuid4().hex[:10]
    v_missing = f"claimsq-missing-{suffix}"
    v_null = f"claimsq-null-{suffix}"
    v_real = f"claimsq-real-{suffix}"
    db = SessionLocal()
    try:
        a_missing = _mk_asset(db, v_missing)
        a_null = _mk_asset(db, v_null)
        a_real = _mk_asset(db, v_real)
        _mk_state(db, a_null.id, None)
        _mk_state(db, a_real.id, "proven_ours")

        result = claims_query.surface_by_asset(db, [a_missing.id, a_null.id, a_real.id])

        assert set(result) == {a_missing.id, a_null.id, a_real.id}, (
            "every requested id must appear in the result"
        )
        assert result[a_missing.id] == "unknown", result
        assert result[a_null.id] == "unknown", result
        assert result[a_real.id] == "proven_ours", result
    finally:
        db.close()
        _cleanup([v_missing, v_null, v_real])


def test_surface_by_asset_empty_input_returns_empty_dict():
    db = SessionLocal()
    try:
        assert claims_query.surface_by_asset(db, []) == {}
    finally:
        db.close()


def test_surface_single_asset_matches_batch_form():
    """`surface()` is a thin wrapper over `surface_by_asset` — pin that it
    agrees with the batch form for both a real value and the unknown
    fallback, rather than re-implementing the NULL-mapping rule."""
    suffix = uuid.uuid4().hex[:10]
    v_claimed = f"claimsq-single-claimed-{suffix}"
    v_unknown = f"claimsq-single-unknown-{suffix}"
    db = SessionLocal()
    try:
        a_claimed = _mk_asset(db, v_claimed)
        a_unknown = _mk_asset(db, v_unknown)
        _mk_state(db, a_claimed.id, "claimed_ours")

        assert claims_query.surface(db, a_claimed.id) == "claimed_ours"
        assert claims_query.surface(db, a_unknown.id) == "unknown"
    finally:
        db.close()
        _cleanup([v_claimed, v_unknown])


# ── asset_ids_with_surface ───────────────────────────────────────────────────

def test_asset_ids_with_surface_unknown_includes_missing_row_and_null_estate():
    """The case a naive `estate == NULL` filter misses: an asset with NO
    `asset_state` row at all must still come back under `surface_value=
    "unknown"`, alongside one whose row is NULL. A `not_ours` control asset
    must be excluded."""
    suffix = uuid.uuid4().hex[:10]
    v_missing = f"claimsq-ids-missing-{suffix}"
    v_null = f"claimsq-ids-null-{suffix}"
    v_not_ours = f"claimsq-ids-notours-{suffix}"
    db = SessionLocal()
    try:
        a_missing = _mk_asset(db, v_missing)
        a_null = _mk_asset(db, v_null)
        a_not_ours = _mk_asset(db, v_not_ours)
        _mk_state(db, a_null.id, None)
        _mk_state(db, a_not_ours.id, "not_ours")

        candidate_ids = [a_missing.id, a_null.id, a_not_ours.id]
        matched = {
            r[0] for r in db.query(AssetCanonical.id)
            .filter(
                AssetCanonical.id.in_(candidate_ids),
                AssetCanonical.id.in_(claims_query.asset_ids_with_surface(db, "unknown")),
            )
            .all()
        }
        assert matched == {a_missing.id, a_null.id}, matched
    finally:
        db.close()
        _cleanup([v_missing, v_null, v_not_ours])


def test_asset_ids_with_surface_stored_value_is_a_plain_equality_filter():
    suffix = uuid.uuid4().hex[:10]
    v_ours = f"claimsq-ids-ours-{suffix}"
    v_other = f"claimsq-ids-other-{suffix}"
    db = SessionLocal()
    try:
        a_ours = _mk_asset(db, v_ours)
        a_other = _mk_asset(db, v_other)
        _mk_state(db, a_ours.id, "claimed_ours")
        _mk_state(db, a_other.id, "not_ours")

        matched = {
            r[0] for r in db.query(AssetCanonical.id)
            .filter(
                AssetCanonical.id.in_([a_ours.id, a_other.id]),
                AssetCanonical.id.in_(claims_query.asset_ids_with_surface(db, "claimed_ours")),
            )
            .all()
        }
        assert matched == {a_ours.id}, matched
    finally:
        db.close()
        _cleanup([v_ours, v_other])


def test_asset_ids_with_surface_raises_on_unknown_value():
    db = SessionLocal()
    try:
        _assert_raises_value_error(claims_query.asset_ids_with_surface, db, "bogus_surface")
    finally:
        db.close()


# ── the absence primitive ────────────────────────────────────────────────────

def test_missing_claim_asset_ids_raises_on_unknown_claim_type():
    db = SessionLocal()
    try:
        _assert_raises_value_error(claims_query.missing_claim_asset_ids, db, "bogus_claim_type")
    finally:
        db.close()


def test_missing_claim_asset_ids_raises_on_unknown_observer_name():
    """An unknown observer must fail loud, not silently mean "every asset
    lacks a claim from them" — that would be trivially true and exactly the
    confidently-wrong answer the spec calls out."""
    db = SessionLocal()
    try:
        _assert_raises_value_error(
            claims_query.missing_claim_asset_ids, db, _CLAIM_TYPE,
            observer_name=f"bogus-observer-{uuid.uuid4().hex[:8]}",
        )
    finally:
        db.close()


def test_missing_claim_asset_ids_observer_scoped_vs_any_observer_differ():
    """An asset claimed by naabu but never by shodan: absent from the
    naabu-scoped absence set (it has that claim), present in the
    shodan-scoped absence set (it lacks that one) — and a from-ANY-observer
    query (`observer_name=None`) must not treat naabu's claim as covering
    shodan's absence."""
    suffix = uuid.uuid4().hex[:10]
    v_claimed = f"claimsq-obsscope-claimed-{suffix}"
    v_bare = f"claimsq-obsscope-bare-{suffix}"
    db = SessionLocal()
    try:
        a_claimed = _mk_asset(db, v_claimed)
        a_bare = _mk_asset(db, v_bare)
        _add_claim(db, a_claimed.id, "naabu")

        candidate_ids = [a_claimed.id, a_bare.id]

        def _missing_among(observer_name):
            return {
                r[0] for r in db.query(AssetCanonical.id)
                .filter(
                    AssetCanonical.id.in_(candidate_ids),
                    AssetCanonical.id.in_(
                        claims_query.missing_claim_asset_ids(db, _CLAIM_TYPE, observer_name)
                    ),
                )
                .all()
            }

        assert _missing_among("naabu") == {a_bare.id}, "claimed asset must not be 'missing' for naabu"
        assert _missing_among("shodan") == {a_claimed.id, a_bare.id}, (
            "naabu's claim must not satisfy a shodan-scoped absence query"
        )
        assert _missing_among(None) == {a_bare.id}, (
            "from-any-observer query must count naabu's claim as present"
        )
    finally:
        db.close()
        _cleanup([v_claimed, v_bare])


def test_missing_claim_asset_ids_returns_asset_with_zero_claims_of_any_kind():
    """The NOT-EXISTS correctness case: an asset with no claims at all must
    still be returned — this must not be implemented as an anti-join gated
    on some other claim existing."""
    suffix = uuid.uuid4().hex[:10]
    v_bare = f"claimsq-zero-claims-{suffix}"
    db = SessionLocal()
    try:
        a_bare = _mk_asset(db, v_bare)
        matched = {
            r[0] for r in db.query(AssetCanonical.id)
            .filter(
                AssetCanonical.id == a_bare.id,
                AssetCanonical.id.in_(claims_query.missing_claim_asset_ids(db, _CLAIM_TYPE)),
            )
            .all()
        }
        assert matched == {a_bare.id}
    finally:
        db.close()
        _cleanup([v_bare])


# ── assets_missing_claim: composed filters ───────────────────────────────────

def test_assets_missing_claim_honours_asset_type_ignored_surface_and_limit():
    suffix = uuid.uuid4().hex[:10]
    v_ip_older = f"claimsq-row-ip-older-{suffix}"
    v_ip_newer = f"claimsq-row-ip-newer-{suffix}"
    v_dns = f"claimsq-row-dns-{suffix}.example.com"
    v_ignored = f"claimsq-row-ignored-{suffix}"
    v_notours = f"claimsq-row-notours-{suffix}"
    all_values = [v_ip_older, v_ip_newer, v_dns, v_ignored, v_notours]
    db = SessionLocal()
    try:
        older = datetime(2020, 1, 1, tzinfo=timezone.utc)
        newer = datetime(2020, 6, 1, tzinfo=timezone.utc)

        a_ip_older = _mk_asset(db, v_ip_older, asset_type="ip_address", last_seen_at=older)
        a_ip_newer = _mk_asset(db, v_ip_newer, asset_type="ip_address", last_seen_at=newer)
        a_dns = _mk_asset(db, v_dns, asset_type="dns_record", last_seen_at=newer)
        a_ignored = _mk_asset(db, v_ignored, asset_type="ip_address", ignored=True)
        a_notours = _mk_asset(db, v_notours, asset_type="ip_address")
        _mk_state(db, a_notours.id, "not_ours")
        ip_ids = {a_ip_older.id, a_ip_newer.id, a_ignored.id, a_notours.id}
        # None of the five get a claim of _CLAIM_TYPE, so all are candidates
        # for the base absence set; the assertions below narrow via filters,
        # each time intersecting the result against our own seeded ids so a
        # concurrently-seeded row elsewhere in the (test) database can't
        # affect the assertion.

        # asset_type filter
        dns_only = claims_query.assets_missing_claim(
            db, _CLAIM_TYPE, asset_type="dns_record", limit=1000,
        )
        assert {a.id for a in dns_only} & (ip_ids | {a_dns.id}) == {a_dns.id}

        # ignored excluded by default, included on request
        ip_default = claims_query.assets_missing_claim(
            db, _CLAIM_TYPE, asset_type="ip_address", limit=1000,
        )
        assert a_ignored.id not in {a.id for a in ip_default}
        ip_with_ignored = claims_query.assets_missing_claim(
            db, _CLAIM_TYPE, asset_type="ip_address", include_ignored=True, limit=1000,
        )
        assert a_ignored.id in {a.id for a in ip_with_ignored}

        # surface_value narrows the universe
        not_ours_only = claims_query.assets_missing_claim(
            db, _CLAIM_TYPE, asset_type="ip_address", surface_value="not_ours",
            include_ignored=True, limit=1000,
        )
        assert {a.id for a in not_ours_only} & ip_ids == {a_notours.id}

        # last_seen_at DESC ordering, matching list_assets — scoped to just
        # our two dated ip_address rows so unrelated rows can't reorder it.
        ip_ordered = claims_query.assets_missing_claim(
            db, _CLAIM_TYPE, asset_type="ip_address", include_ignored=True, limit=1000,
        )
        ours_ordered = [a.id for a in ip_ordered if a.id in (a_ip_older.id, a_ip_newer.id)]
        assert ours_ordered == [a_ip_newer.id, a_ip_older.id], (
            f"expected last_seen_at DESC ordering, got {ours_ordered}"
        )

        # limit actually truncates the result set
        limited = claims_query.assets_missing_claim(
            db, _CLAIM_TYPE, asset_type="ip_address", include_ignored=True, limit=1,
        )
        assert len(limited) == 1
    finally:
        db.close()
        _cleanup(all_values)


def _run():
    tests = [
        test_surface_by_asset_maps_missing_row_and_null_estate_to_unknown,
        test_surface_by_asset_empty_input_returns_empty_dict,
        test_surface_single_asset_matches_batch_form,
        test_asset_ids_with_surface_unknown_includes_missing_row_and_null_estate,
        test_asset_ids_with_surface_stored_value_is_a_plain_equality_filter,
        test_asset_ids_with_surface_raises_on_unknown_value,
        test_missing_claim_asset_ids_raises_on_unknown_claim_type,
        test_missing_claim_asset_ids_raises_on_unknown_observer_name,
        test_missing_claim_asset_ids_observer_scoped_vs_any_observer_differ,
        test_missing_claim_asset_ids_returns_asset_with_zero_claims_of_any_kind,
        test_assets_missing_claim_honours_asset_type_ignored_surface_and_limit,
    ]
    for fn in tests:
        fn()
        print(f"ok  {fn.__name__}")
    print("all passed")


if __name__ == "__main__":
    _run()
