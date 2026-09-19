"""Asset hygiene scorer — five-dimension per-asset score (planning#130, L1).

This is the mechanical scorer the epic exists to build: a deterministic,
pre-computed, per-asset "how well is this machine being managed" number,
distinct from and complementary to `risk_scorer.py`'s per-FINDING score.
Risk Score answers "how bad is this specific vulnerability"; hygiene asks
"how much visibility and control do we actually have over this asset",
which is a real, separate question — an asset can score `critical` here
with zero open findings, simply because nothing has looked hard enough to
find one yet. That gap (asset nobody is watching, scored the same as an
asset we've verified is clean) is the vendor failure mode this feature
exists to invert. See `app.services.claims_query`'s module docstring for
the sibling half of that inversion at the ownership layer.

── The settled scoring rule (do not "fix" this) ─────────────────────────────

`unknown` sub-scores BELOW `bad` (0 vs. 25 — see GRADE_SCORES) and every
unknown dimension STAYS in the five-dimension denominator when the
composite is averaged. Both are deliberate, not oversights:

  * Ranking unknown below bad encodes "a machine nothing reports on is a
    worse finding than a machine we've actively looked at and found
    wanting" — silence is not innocence, and a vendor tool that treats "no
    data" as a free pass (or worse, a clean bill of health) is rewarding
    the exact blind spot an EASM exists to close.
  * Keeping unknown dimensions in the denominator is what makes that
    ranking bite. If an unknown dimension were dropped from the average
    instead (the common vendor pattern — "we only score what we can see"),
    an asset with four unmeasured dimensions and one `excellent` would
    score a perfect 100, which is worse than useless: it actively hides
    the asset that needs attention most. The composite here is always the
    mean over all five dimensions, unconditionally — an asset scoring low
    because most of its dimensions are `unknown` is not a scoring bug, it
    is Coverage (see below) doing exactly its job in v1.

If you find yourself thinking "this asset's score looks unfairly capped
because Coverage is always unknown right now" — yes, correct, that is
intentional and stays that way until a real EDR/device-management producer
lands (planning#118, #124) and Coverage grows a real body. Don't special-
case it away in the meantime; the whole point is that the absence is loud.

── The five dimensions ──────────────────────────────────────────────────────

Exactly these, in this order (`DIMENSIONS` below), each independently
graded to one of GRADE_VALUES and combined by unweighted mean:

  1. coverage — stubbed `unknown` in v1 (no EDR/device-management/patch
     producer exists yet to ground it in; see `_dim_coverage`).
  2. health   — freshness of whatever claims DO exist for the asset
     (MAX(asset_claims.last_observed_at)). Not the same as Coverage: this
     grades staleness of what we have, not the absence of what we don't.
  3. currency — EOL exposure, from the `eol_status` claim's `services` list
     (`eol_enrichment.py`). Read from the RAW CLAIM, not
     `asset_state.eol_summary` — see `_latest_claim_value`'s docstring for
     why the projected column can't distinguish "no claim" from "claim
     present, zero products identified", and this dimension must.
  4. exposure — port surface, from `asset_state.open_ports` +
     `attributes["probe_class"]`. Only ever graded for `direct_addressable`
     assets; `no_probe`/`name_only` assets have no port truth to grade and
     stay `unknown` rather than being scored on a port list that was never
     going to be populated for them (see settled rule 1 in the spec this
     module implements — a `name_only` asset stays IN SCOPE for scoring,
     it just can't be graded on this one dimension).
  5. ownership — from `claims_query.surface()` (the estate tri-state +
     unknown) plus `AssetCanonical.tags` as an interim accountability
     proxy. `tags` stands in for a real org/business-unit graph
     (planning#120, unbuilt) — say so here so a future reader doesn't
     mistake the tag check for the intended design rather than a stopgap.

── What is deliberately NOT here ────────────────────────────────────────────

No roll-up summary tables (blocked on #120), no `expected_stack` policy
mechanism for exposure's "does this match what it *should* run" half
(blocked on #137), no frontend, no new connector, no per-asset DB query
inside `score_asset` (it is a pure function over already-loaded inputs —
`run()` below does all the batched loading), and no model/network call
anywhere in this module — deterministic, DB-only, matching every other
scorer in this codebase.
"""

import logging
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import NamedTuple

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models.asset_canonical import AssetCanonical
from app.models.asset_hygiene_score import AssetHygieneScore
from app.models.asset_state import AssetState
from app.models.claim import AssetClaim
from app.services import claim_emitter, claims_query, projector

log = logging.getLogger(__name__)

# ── Config constants (risk_scorer precedent — no magic literals below) ──────

# Sub-score per grade. `unknown` (0) sits strictly below `bad` (25) — the
# whole feature, see module docstring. Keys must equal
# `app.models.asset_hygiene_score.GRADE_VALUES`; nothing enforces that at
# the DB layer (see that module's own comment), so a mismatch here is an
# application bug the test suite is relied on to catch.
GRADE_SCORES: dict[str, int] = {"unknown": 0, "bad": 25, "fair": 50, "good": 75, "excellent": 100}

# Composite bands (inclusive), same dict[str, tuple[int, int]] shape as
# risk_scorer.BANDS. Contiguous and exhaustive over 0..100 by construction —
# every possible composite (see score_asset) falls in exactly one band.
BANDS: dict[str, tuple[int, int]] = {
    "critical": (0, 24),
    "poor": (25, 49),
    "fair": (50, 74),
    "good": (75, 89),
    "excellent": (90, 100),
}

# The five dimensions, in the fixed order the epic specifies. Iteration
# order here is also the key order of score_asset's returned `dimensions`
# dict — stable output, not incidental.
DIMENSIONS: tuple[str, ...] = ("coverage", "health", "currency", "exposure", "ownership")

# ── health thresholds (days since the freshest claim of any type) ───────────
HEALTH_FRESH_DAYS = 7
HEALTH_GOOD_DAYS = 30
HEALTH_FAIR_DAYS = 90

# ── currency thresholds ──────────────────────────────────────────────────
# A product within this many days of its EOL date (but not past it) grades
# `fair` rather than `good` — an early warning before currency's `bad`
# branch (already-EOL) triggers.
CURRENCY_APPROACHING_DAYS = 180

# ── exposure thresholds ──────────────────────────────────────────────────
# Management / database / legacy-cleartext ports — any one of these open on
# a direct_addressable asset grades `bad` regardless of how many other
# ports are open (a single high-risk port dominates the reading; this list
# is intentionally short and about *class* of exposure, not exhaustive).
HIGH_RISK_PORTS: frozenset[int] = frozenset({
    21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017,
})
# More than this many open ports (with none individually high-risk) grades
# `fair` — a wide-open surface even of "ordinary" ports is worse hygiene
# than a narrow one, but not as bad as one confirmed high-risk service.
EXPOSURE_MANY_PORTS = 10

# Batch size for run()'s chunked, no-N+1 sweep — same order of magnitude as
# scan_template's own batch_size default, tuned for "one IN (...) clause
# stays a reasonable query", not measured against this table specifically.
BATCH_SIZE = 500


class ClaimRow(NamedTuple):
    """The three claim fields every dimension function needs, decoupled
    from the ORM row shape. `run()`'s batched claims query selects exactly
    these three columns (never the full `AssetClaim` row — `evidence`/
    `confidence` aren't used here) and wraps each result row in one of
    these; tests construct them directly with no DB round-trip, since
    `score_asset` and every dimension function underneath it take only
    already-loaded plain data (module docstring's "no DB queries inside")."""
    claim_type: str
    claim_value: dict
    last_observed_at: datetime


# ── dimension: coverage ──────────────────────────────────────────────────

def _dim_coverage() -> tuple[str, list[str], str]:
    """Always `unknown` in v1 — takes no arguments on purpose.

    Coverage is meant to answer "is this asset under active management"
    (EDR / device-management / patch-management enrolment), the same shape
    of question `claims_query.missing_claim_asset_ids` answers generically
    for any claim type. But there are 18 seeded claim types today (see
    `app.models.claim.CLAIM_TYPES`) and every one of them is an
    EXTERNAL-OBSERVATION claim type — port scans, DNS, CT logs, hosting
    classification. Zero of them are EDR / device-management /
    patch-management producers, so the set this dimension would need to
    check absence against (`missing_claim_asset_ids(db, "edr_enrolment")`
    or similar) is empty; there is no claim_type to be missing FROM yet.

    Blocked on planning#118 (Wiz) and #124 (Tenable, FortiManager) — when
    either lands and seeds a real claim_type, this function grows a real
    body built the same way `_dim_ownership` reads `claims_query.surface`:
    a claim-presence check, not a heuristic. The dimension slot,
    reason_codes shape, and denominator inclusion around it are already
    correct today; only the grading logic inside is a stub.
    """
    return (
        "unknown",
        ["coverage_no_producers"],
        "No EDR/device-management/patch-management claim producers exist yet "
        "(blocked on planning#118, #124) — the denominator this dimension would "
        "grade against is empty.",
    )


# ── dimension: health ────────────────────────────────────────────────────

def _dim_health(claims: list[ClaimRow], now: datetime) -> tuple[str, list[str], str]:
    """Freshness of the claims that DO exist — MAX(last_observed_at) across
    every claim type, not just one. Distinct from Coverage: an asset with
    a week-old naabu claim and nothing else grades well here (what we have
    is fresh) while still grading `unknown` on Coverage (we have no EDR
    signal at all) — the two dimensions are not redundant.

    v1 is freshness only. Agent-health fields (installed-and-stalled
    detection — an EDR agent present but not phoning home) need the same
    missing connectors Coverage is blocked on; there is no data source for
    that distinction yet, so this dimension can't tell "healthy and quiet"
    apart from "broken and quiet" today.
    """
    if not claims:
        return "unknown", ["health_no_claims"], "No claims of any type have ever been observed for this asset."

    freshest = max(c.last_observed_at for c in claims)
    age = now - freshest
    age_days = age.days

    if age <= timedelta(days=HEALTH_FRESH_DAYS):
        return "excellent", ["health_fresh"], f"Freshest claim observed {age_days}d ago (<= {HEALTH_FRESH_DAYS}d)."
    if age <= timedelta(days=HEALTH_GOOD_DAYS):
        return "good", ["health_recent"], f"Freshest claim observed {age_days}d ago (<= {HEALTH_GOOD_DAYS}d)."
    if age <= timedelta(days=HEALTH_FAIR_DAYS):
        return "fair", ["health_aging"], f"Freshest claim observed {age_days}d ago (<= {HEALTH_FAIR_DAYS}d)."
    return "bad", ["health_stale"], f"Freshest claim observed {age_days}d ago (> {HEALTH_FAIR_DAYS}d) — stale."


# ── dimension: currency ──────────────────────────────────────────────────

def _latest_claim_value(claims: list[ClaimRow], claim_type: str) -> dict | None:
    """The most-recently-observed claim_value of `claim_type` among
    `claims`, or None if none exists.

    Why this dimension reads the RAW claim through this helper instead of
    the projected `asset_state.eol_summary` the projector already
    extracted: the projector's L3c-2 fix collapses BOTH "no eol_status
    claim at all" and "eol_status claim present with `services: []`" down
    to the same `eol_summary = []` — correct for its own purpose (there is
    genuinely nothing to project either way), but currency's job is to
    distinguish exactly those two cases (`currency_no_eol_claim` vs.
    `currency_no_identifiable_products` — see `_dim_currency`), so it has
    to read the claim layer directly rather than the already-collapsed
    projection. `eol_status` is pinned to the `eol_enrichment` observer at
    projection time (`projector._OWNED_CLAIMS`); this helper doesn't
    re-enforce that pin — if more than one observer ever legitimately
    writes `eol_status`, most-recently-observed wins here, same fallback
    `projector.project()` uses for its own non-pinned claim types
    (`cdn_boundary`, `cloud_inventory`).
    """
    matches = [c for c in claims if c.claim_type == claim_type]
    if not matches:
        return None
    return max(matches, key=lambda c: c.last_observed_at).claim_value


def _parse_eol_date(eol_date_str) -> date | None:
    """`eol_date` (an ISO date string, per eol_enrichment's record shape)
    as a `date`, or None if absent/unparseable. Never raises."""
    if not eol_date_str or not isinstance(eol_date_str, str):
        return None
    try:
        return date.fromisoformat(eol_date_str)
    except ValueError:
        return None


def _eol_date_passed(eol_date_str, today: date) -> bool:
    """True if this record's EOL date is in the past as of `today`.

    Deliberately recomputed here rather than trusting the record's stored
    `is_eol` flag alone. `eol_enrichment._parse_eol` freezes `is_eol` at
    WRITE time (`delta = (date.today() - eol_date).days` on the day the
    claim was emitted), and an `eol_status` claim long outlives the day it
    was written — `upsert_single_claim` only rewrites it when enrichment
    re-runs for that asset. So a product whose EOL date passed *since* the
    last enrichment run still carries `is_eol: False` in the stored claim.

    Trusting the flag alone graded exactly that asset `fair` with the
    reason "approaching EOL" for a date already weeks in the past — a
    stale observation reading as healthier than reality, which is the
    precise failure mode this entire feature exists to invert. The stored
    flag is still honoured (it covers the `eol: true`-with-no-date case
    eol_enrichment also emits); it is simply no longer the ONLY route to
    the `bad` branch.
    """
    eol_date = _parse_eol_date(eol_date_str)
    return eol_date is not None and eol_date < today


def _dim_currency(claims: list[ClaimRow], now: datetime) -> tuple[str, list[str], str]:
    """EOL exposure, from the `eol_status` claim's `services` list
    (`eol_enrichment.py` ~line 205 for the record shape: `product`,
    `eol_date` (ISO date string or None), `is_eol` (bool)).

    `services` MUST be read as a list — see `_latest_claim_value`'s
    docstring and the projector's L3c-2 note for the bug this guards
    against (a `isinstance(dict)` check that silently discarded every real
    list into `{}`). This function has no such guard to accidentally
    reintroduce because it never treats `services` as anything but a list.
    """
    eol_claim = _latest_claim_value(claims, "eol_status")
    if eol_claim is None:
        return "unknown", ["currency_no_eol_claim"], "No eol_status claim on this asset."

    services = eol_claim.get("services") if isinstance(eol_claim, dict) else None
    if not isinstance(services, list):
        services = []

    if not services:
        return (
            "unknown",
            ["currency_no_identifiable_products"],
            "eol_status claim present but zero products were identified — an "
            "observation gap in our own fingerprinting, not a clean bill of health.",
        )

    today = now.date()
    eol_records = [
        s for s in services
        if isinstance(s, dict) and (s.get("is_eol") or _eol_date_passed(s.get("eol_date"), today))
    ]
    if eol_records:
        # Name the products we have names for, but NEVER let a missing
        # product name drop a record from the finding. The original filter
        # here was `... and s.get("product")`, which conflated "this record
        # is EOL" with "this record has a name to print" — one unnamed EOL
        # record made the whole asset fall through to `good` ("No EOL or
        # approaching-EOL products identified"), i.e. the detail string
        # asserted the exact opposite of the truth.
        named = sorted({s.get("product") for s in eol_records if s.get("product")})
        label = ", ".join(named) if named else f"{len(eol_records)} unnamed product(s)"
        return "bad", ["currency_eol_product"], f"EOL product(s) in use: {label}."

    approaching: set[str] = set()
    for s in services:
        if not isinstance(s, dict):
            continue
        eol_date = _parse_eol_date(s.get("eol_date"))
        if eol_date is None:
            continue
        # Lower bound of 0 is not redundant: a past date is already caught
        # by the `bad` branch above, and this makes it structurally
        # impossible for an elapsed date to be reported as "approaching"
        # again if that branch is ever edited.
        days_remaining = (eol_date - today).days
        if 0 <= days_remaining <= CURRENCY_APPROACHING_DAYS:
            approaching.add(s.get("product") or eol_date.isoformat())
    if approaching:
        return (
            "fair",
            ["currency_approaching_eol"],
            f"Product(s) approaching EOL within {CURRENCY_APPROACHING_DAYS}d: {', '.join(sorted(approaching))}.",
        )

    return "good", ["currency_no_eol_risk"], "No EOL or approaching-EOL products identified."


# ── dimension: exposure ──────────────────────────────────────────────────

def _dim_exposure(state: AssetState | None, claims: list[ClaimRow]) -> tuple[str, list[str], str]:
    """Port surface, from `asset_state.open_ports` +
    `attributes["probe_class"]`. Only graded for `direct_addressable`
    assets — see module docstring point 4. The "does what it exposes match
    what it *should*" half of this dimension needs the `expected_stack`
    policy mechanism (planning#137) and is deliberately absent in v1; this
    only grades HOW MUCH / HOW RISKY the observed surface is, never whether
    it's the right surface for the asset's role.
    """
    probe_class = (state.attributes or {}).get("probe_class") if state is not None else None
    if state is None or not probe_class:
        return "unknown", ["exposure_no_projection"], "No asset_state projection (or no probe_class) exists for this asset yet."

    if probe_class in ("no_probe", "name_only"):
        return (
            "unknown",
            ["exposure_not_directly_probeable"],
            f"probe_class={probe_class!r} — not directly probeable, no port truth to grade.",
        )

    # direct_addressable (the only remaining probe_class value; see
    # projector.project()'s own if/elif chain).
    open_ports = state.open_ports or []
    has_port_claim = any(c.claim_type == "port_observation" for c in claims)

    if not open_ports:
        if not has_port_claim:
            return (
                "unknown",
                ["exposure_never_scanned"],
                "No port_observation claim from any observer and open_ports is empty — "
                "never looked, not confirmed clean.",
            )
        return "excellent", ["exposure_no_open_ports"], "port_observation claim(s) exist and no open ports are recorded."

    port_numbers = {p.get("port") for p in open_ports if isinstance(p, dict)}
    high_risk = sorted(p for p in port_numbers if p in HIGH_RISK_PORTS)
    if high_risk:
        return "bad", ["exposure_high_risk_port"], f"High-risk port(s) open: {', '.join(str(p) for p in high_risk)}."

    if len(open_ports) > EXPOSURE_MANY_PORTS:
        return "fair", ["exposure_many_ports"], f"{len(open_ports)} open ports (> {EXPOSURE_MANY_PORTS})."

    return "good", ["exposure_normal"], f"{len(open_ports)} open port(s), none high-risk."


# ── dimension: ownership ─────────────────────────────────────────────────

def _dim_ownership(surface_value: str, tags: list) -> tuple[str, list[str], str]:
    """From `claims_query.surface()` + `AssetCanonical.tags`.

    `tags` is an INTERIM accountability proxy, not the intended design — a
    real org / business-unit graph is planning#120 and unbuilt. Say so here
    so a future reader doesn't mistake "we check tags" for a considered
    ownership model rather than a stopgap standing in for one.

    `not_ours` is unreachable in a correctly-driven scorer: `run()` filters
    the candidate set to `surface != "not_ours"` before this function is
    ever called (settled rule 1 — exclusion happens off `surface`, never
    off `probe_class`). Raising here rather than quietly returning
    something is deliberate: this branch executing at all means the
    exclusion filter upstream is broken, and a wrong-but-plausible-looking
    grade would hide that far longer than a loud failure would.
    """
    tags = tags or []
    if surface_value == "unknown":
        return "unknown", ["ownership_no_signal"], "No ownership signal (surface=unknown)."
    if surface_value == "proven_ours":
        if tags:
            return "excellent", ["ownership_proven_tagged"], f"proven_ours with {len(tags)} tag(s)."
        return "good", ["ownership_untagged"], "proven_ours but untagged — no accountability owner recorded."
    if surface_value == "claimed_ours":
        if tags:
            return "good", ["ownership_claimed_tagged"], f"claimed_ours with {len(tags)} tag(s)."
        return "fair", ["ownership_untagged"], "claimed_ours but untagged — no accountability owner recorded."
    raise ValueError(
        f"ownership dimension received surface={surface_value!r} — 'not_ours' assets must be "
        "excluded from the candidate set before score_asset is ever called"
    )


# ── composite ─────────────────────────────────────────────────────────────

def _band_for_score(score: int) -> str:
    for band, (lo, hi) in BANDS.items():
        if lo <= score <= hi:
            return band
    raise ValueError(f"hygiene score {score} is outside the 0..100 range BANDS covers")


def score_asset(
    asset: AssetCanonical,
    state: AssetState | None,
    claims: list[ClaimRow],
    surface_value: str,
    now: datetime | None = None,
) -> dict:
    """Pure function over already-loaded inputs — no DB queries inside.
    `run()` below does all the batched loading; this only computes.

    Returns `{"score": int, "band": str, "dimensions": {name: {"grade",
    "score", "reason_codes", "detail"}}}`. The composite `score` is
    `round(mean(sub_score for each of the five dimensions))` — unweighted,
    over ALL FIVE dimensions unconditionally, including any that graded
    `unknown` (module docstring's settled rule: the denominator is always
    5, never fewer). `band` is derived from `score` via BANDS, so it is
    monotonic in score by construction, same relationship risk_scorer's
    risk_band has to risk_score.
    """
    now = now or datetime.now(timezone.utc)

    graded: dict[str, tuple[str, list[str], str]] = {
        "coverage": _dim_coverage(),
        "health": _dim_health(claims, now),
        "currency": _dim_currency(claims, now),
        "exposure": _dim_exposure(state, claims),
        "ownership": _dim_ownership(surface_value, asset.tags if asset is not None else []),
    }

    dimensions: dict[str, dict] = {}
    sub_scores: list[int] = []
    for name in DIMENSIONS:
        grade, reason_codes, detail = graded[name]
        sub_score = GRADE_SCORES[grade]
        sub_scores.append(sub_score)
        dimensions[name] = {
            "grade": grade,
            "score": sub_score,
            "reason_codes": reason_codes,
            "detail": detail,
        }

    composite = round(sum(sub_scores) / len(sub_scores))
    return {"score": composite, "band": _band_for_score(composite), "dimensions": dimensions}


# ── DB driver ─────────────────────────────────────────────────────────────

def _chunks(seq: list, size: int):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def run(db: Session) -> dict:
    """The nightly driver, signature matching `claim_history_maintenance.run(db)`.

    Candidate assets: `ignored == False` AND
    `claims_query.surface(asset) != "not_ours"` (settled rule 1 — never
    filtered off `probe_class`; a `name_only` asset stays a candidate, it
    just grades `unknown` on the exposure dimension).

    Batched in chunks of `BATCH_SIZE`, no N+1: per chunk, one
    `surface_by_asset` call, one `AssetCanonical` row fetch, one
    `projector.load_states` call, and ONE grouped `asset_claims` query
    covering every claim type for the chunk (health needs the freshest
    claim of ANY type; currency and exposure each need one specific type —
    pulling all of them in one query is simpler and no more expensive than
    three narrower ones over the same id set). A per-asset query inside the
    scoring loop would be a spec violation.

    Upserts one `asset_hygiene_score` row per scored asset
    (`ON CONFLICT DO UPDATE`, the same `postgresql.insert` shape
    `projector.project()` already uses). Separately DELETES any existing
    score row for an asset that is now excluded (`not_ours` or `ignored`) —
    a stale score for a de-scoped asset is worse than no score, so that
    cleanup runs even for assets outside this run's candidate set (see
    `_delete_stale_scores`).

    Returns `{"scored": n, "excluded": n, "deleted": n, "elapsed_ms": n}`
    and logs exactly one summary line — no per-asset logging.
    """
    start = time.monotonic()
    now = datetime.now(timezone.utc)

    all_ids = [
        row[0] for row in
        db.query(AssetCanonical.id).filter(AssetCanonical.ignored == False).all()  # noqa: E712
    ]

    scored = 0
    excluded = 0

    for chunk in _chunks(all_ids, BATCH_SIZE):
        surface_by_id = claims_query.surface_by_asset(db, chunk)
        keep_ids = [asset_id for asset_id in chunk if surface_by_id[asset_id] != "not_ours"]
        excluded += len(chunk) - len(keep_ids)
        if not keep_ids:
            continue

        canonicals = {
            row.id: row
            for row in db.query(AssetCanonical).filter(AssetCanonical.id.in_(keep_ids)).all()
        }
        states = projector.load_states(db, keep_ids)

        claims_by_asset: dict[uuid.UUID, list[ClaimRow]] = {}
        claim_rows = (
            db.query(
                AssetClaim.asset_canonical_id,
                AssetClaim.claim_type,
                AssetClaim.claim_value,
                AssetClaim.last_observed_at,
            )
            .filter(AssetClaim.asset_canonical_id.in_(keep_ids))
            .all()
        )
        for asset_id, claim_type, claim_value, last_observed_at in claim_rows:
            claims_by_asset.setdefault(asset_id, []).append(ClaimRow(claim_type, claim_value, last_observed_at))

        rows_to_upsert: list[dict] = []
        for asset_id in keep_ids:
            canonical = canonicals.get(asset_id)
            if canonical is None:
                continue  # deleted mid-run — mirrors projector.project()'s own guard
            result = score_asset(
                canonical,
                states.get(asset_id),
                claims_by_asset.get(asset_id, []),
                surface_by_id[asset_id],
                now,
            )
            rows_to_upsert.append({
                "asset_canonical_id": asset_id,
                "score": result["score"],
                "band": result["band"],
                "dimensions": result["dimensions"],
                "computed_at": now,
            })
            scored += 1

        if rows_to_upsert:
            stmt = pg_insert(AssetHygieneScore.__table__).values(rows_to_upsert)
            stmt = stmt.on_conflict_do_update(
                index_elements=["asset_canonical_id"],
                set_={
                    "score": stmt.excluded.score,
                    "band": stmt.excluded.band,
                    "dimensions": stmt.excluded.dimensions,
                    "computed_at": stmt.excluded.computed_at,
                },
            )
            db.execute(stmt)
            db.commit()

    deleted = _delete_stale_scores(db)

    elapsed_ms = int((time.monotonic() - start) * 1000)
    stats = {"scored": scored, "excluded": excluded, "deleted": deleted, "elapsed_ms": elapsed_ms}
    log.info(
        "Asset hygiene scoring complete — scored=%d excluded=%d deleted=%d elapsed_ms=%d",
        scored, excluded, deleted, elapsed_ms,
    )
    return stats


def _delete_stale_scores(db: Session) -> int:
    """Delete `asset_hygiene_score` rows for assets that are now excluded —
    `ignored == True` or `surface == "not_ours"`. Bounded by the number of
    EXISTING score rows (typically << the full assets_canonical table),
    batched the same way as the main scoring loop above. Runs
    unconditionally, independent of this run's candidate set, because an
    asset can drop OUT of scope (get ignored, or get reclassified
    not_ours) between runs without ever appearing in `run()`'s own
    candidate loop this time around — its stale row still needs cleaning
    up, and this is the only place that happens.
    """
    existing_ids = [row[0] for row in db.query(AssetHygieneScore.asset_canonical_id).all()]
    if not existing_ids:
        return 0

    deleted = 0
    for chunk in _chunks(existing_ids, BATCH_SIZE):
        ignored_ids = {
            row[0] for row in
            db.query(AssetCanonical.id)
            .filter(AssetCanonical.id.in_(chunk), AssetCanonical.ignored == True)  # noqa: E712
            .all()
        }
        surface_by_id = claims_query.surface_by_asset(db, chunk)
        stale_ids = [
            asset_id for asset_id in chunk
            if asset_id in ignored_ids or surface_by_id.get(asset_id) == "not_ours"
        ]
        if stale_ids:
            deleted += (
                db.query(AssetHygieneScore)
                .filter(AssetHygieneScore.asset_canonical_id.in_(stale_ids))
                .delete(synchronize_session=False)
            )
    if deleted:
        db.commit()
    return deleted


# ── read-side batched helpers (planning#130, L2 — the frontend surface) ────
#
# `run()` above is the only writer. Everything below is read-only, batched
# the same no-N+1 way as `claims_query.surface_by_asset` /
# `projector.load_states`, and exists so `api/assets.py`'s serializer can
# carry hygiene onto the Assets list/detail payload without a per-row query.

def scores_by_asset(db: Session, asset_ids) -> dict[uuid.UUID, AssetHygieneScore]:
    """Batch-load the `asset_hygiene_score` row for each id in `asset_ids`,
    in one query — the read-side counterpart to `run()`'s batched write.

    Same discipline as `claims_query.surface_by_asset` / `projector.load_states`:
    one `IN (...)` query regardless of how many ids are requested, empty
    input returns `{}` without querying. Ids with no score row are simply
    absent from the result — `run()` only ever upserts a row for an asset
    that was actually in scope and got scored, so "no row" already means
    exactly "not yet scored" (or excluded), and callers must read it that
    way: a missing entry means `null`, never a 0.
    """
    ids = list(asset_ids)
    if not ids:
        return {}
    return {
        row.asset_canonical_id: row
        for row in db.query(AssetHygieneScore).filter(AssetHygieneScore.asset_canonical_id.in_(ids)).all()
    }


def scanned_by_asset(db: Session, asset_ids) -> dict[uuid.UUID, bool]:
    """Batch "has anything substantive ever been observed about this asset"
    — the signal planning#100's Assets-list Risk-column fix needs to tell a
    genuinely clean asset apart from one nothing has looked at yet.

    True iff the asset carries at least one `asset_claims` row whose
    `claim_type != "observation"`. `observation` is the bare, value-less
    identity/traceability claim `claim_emitter` writes for every resolved
    observer (see `_accumulate_observation_claim`) — every asset that has
    ever been touched by any observer gets one, so by itself it proves only
    that the asset exists, never that anything looked at it. Any OTHER
    claim type (ports, DNS, TLS, hosting, CT, EOL, ...) means a real
    producer substantively assessed the asset.

    Judgment call / known limitation (flagged per planning#130 L2 spec):
    this is a deliberately GENERAL cross-asset-type proxy for "assessed",
    not a scan-history lookup — it cannot answer "when was this last
    scanned" or "which scanner touched it", only "has anything beyond bare
    identity ever been recorded". A plain DNS record that only ever
    resolved (e.g. an MX/TXT record with no port surface to observe, so it
    accumulates nothing but its `observation` claim) reads as unscanned —
    which is the correct answer for the Risk column's Clean-vs-Unscanned
    distinction this exists to serve, but would want refining into a real
    per-asset scan-history signal if one is ever built for a different
    purpose.

    Every id in `asset_ids` appears in the result (`True` or `False`) — an
    id with no claims at all correctly comes back `False`, never absent
    from the dict, so callers never need `.get(id, False)`. One batched
    query, no N+1.
    """
    ids = list(asset_ids)
    if not ids:
        return {}
    substantive_ids = {
        row[0] for row in
        db.query(AssetClaim.asset_canonical_id)
        .filter(
            AssetClaim.asset_canonical_id.in_(ids),
            AssetClaim.claim_type != claim_emitter._OBSERVATION_CLAIM_TYPE,
        )
        .distinct()
        .all()
    }
    return {asset_id: asset_id in substantive_ids for asset_id in ids}
