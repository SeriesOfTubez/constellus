"""Tier 0 tenancy enricher (planning#181).

Same shape as `ct_refresher.py`: this is a background drip job, not an
inline call. `tick()` reads the local `cloud_ranges` mirror (kept warm by
`app.services.cloud_ranges.refresh`, run separately by the scheduler) and
writes a `tenancy` claim for a bounded batch of assets per tick. The future
probe-authorisation gate (planning#182) reads that claim and never makes a
call itself — a dependency outage here therefore yields a stale or absent
claim, never a silent denial baked into a live decision. This is the eighth
registered scheduler job (ct_refresher, epss_refresher, cpe_index_refresher,
partition_maintenance, hygiene_scoring, nightly_rescore, run_reaper, and
this one), not a new mechanism.

Tier 0 only: an IP is looked up against the mirrored provider-range dataset
and, when a match is decisive, gets a `single_tenant` / `not_single_tenant`
verdict straight from it. Everything else — Azure/GCP/OCI customer compute,
which the dataset cannot itself distinguish (see `tenancy_for_match`) —
comes back `undetermined` and is left for a later Tier 1 (PTR/TLS) or Tier 2
(mnemonic) slice to escalate. Building those tiers is explicitly out of
scope here.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.services import cloud_ranges
from app.services.claim_emitter import upsert_single_claim

log = logging.getLogger(__name__)

TICK_INTERVAL_SECONDS = 60

# Tier 0 is a local indexed query with no external call, so the per-tick
# budget is bounded by DB work rather than by anyone's rate limit. Tier 2
# (mnemonic, 10/min + 1000/day) will need real pacing inside the tick;
# Tier 0 does not.
IPS_PER_TICK = 200

REFRESH_AFTER = timedelta(days=7)                # a decided claim
UNDETERMINED_RETRY_AFTER = timedelta(hours=6)    # planning#113 finding 2

_OBSERVER_NAME = "tenancy_enricher"
_CLAIM_TYPE = "tenancy"

SINGLE_TENANT = "single_tenant"
NOT_SINGLE_TENANT = "not_single_tenant"
UNDETERMINED = "undetermined"


@dataclass
class _AssetRef:
    id: object
    value: str


def tenancy_for_match(match: "cloud_ranges.CloudRangeMatch | None") -> tuple[str, str]:
    """Pure mapping from a `cloud_ranges.lookup` result to (tenancy, reason).
    No DB access — test this directly.

    The `unknown` branch is the COMMON case, not an edge case: Azure
    publishes no VM tag at all in its range feed, GCP carries exactly one
    token across every one of its prefixes, and OCI's tag spans both
    customer-facing and Oracle-run space — none of those three lets the
    dataset alone say "this is customer compute". So Azure/GCP/OCI customer
    compute all land here as `undetermined` and must escalate to Tier 1/2 in
    a later slice. Only AWS `EC2` and the pure-VPS providers publish a tag
    specific enough to yield a positive `compute` today.
    """
    if match is None:
        return UNDETERMINED, "no_matching_prefix"
    if match.service_class == "compute":
        return SINGLE_TENANT, "provider_service_class_compute"
    if match.service_class in ("edge", "storage", "managed"):
        return NOT_SINGLE_TENANT, f"provider_service_class_{match.service_class}"
    # match.service_class == "unknown"
    return UNDETERMINED, "service_class_unknown"


def _claim_value(tenancy: str, reason: str, match, state: "cloud_ranges.DatasetState") -> dict:
    """Build the `tenancy` claim_value.

    Deliberately carries NO ownership field. planning#178's load-bearing
    constraint, restated in #181/#182: tenancy and ownership are separate
    capabilities. Collapsing them here would mean a recycled address that
    happens to sit in a `single_tenant` range gets treated as ours to scan —
    exactly the false-attribution failure mode the claims layer exists to
    prevent. Ownership comes from `affinity_confirmation` / `cloud_inventory`
    and is composed with this claim by the (not-yet-built) #182 gate, never
    merged into it.
    """
    return {
        "tenancy": tenancy,
        # NOT "0 if match is not None else None" — a match on a service_class
        # of 'unknown' still leaves `tenancy` UNDETERMINED (see
        # tenancy_for_match), and an undetermined verdict was not actually
        # decided by anything, so decided_by_tier must be None there too.
        "decided_by_tier": 0 if tenancy != UNDETERMINED else None,
        "reason": reason,
        "provider": match.provider if match else None,
        "service_raw": match.service_raw if match else None,
        "service_class": match.service_class if match else None,
        "prefix": match.prefix if match else None,
        # Pinned so a past authorisation decision stays reconstructable —
        # SCHEMA.md asks consumers to record this alongside the decision it
        # informed. #182 copies it into authorisation_decisions.evidence_snapshot.
        "dataset_sha256": state.dataset_sha256,
        "dataset_generated_at": state.generated_at.isoformat(),
    }


def enrich_asset(db: Session, asset, state, now: datetime) -> bool:
    """Write one asset's `tenancy` claim from the local mirror. Returns True
    if a claim was written.

    Factored out of `tick()` so the inline pre-gate pass (planning#203,
    `scan_executor._precompute_probe_evidence`) and the background drip job
    share ONE definition of what a Tier 0 tenancy claim is, rather than the
    scan path growing a second, drifting copy. `tick()` still owns batching,
    selection and the dataset guards; this owns only the per-asset write.

    Caller-supplied `state` rather than a lookup per asset: `tick()` already
    resolves it once per batch and the dataset guards ("no dataset loaded"
    writes nothing at all) belong with the caller that knows whether it is
    processing a batch or a single scan's addresses. A caller that cannot
    obtain a state must not call this.

    Purely local — one indexed `cloud_ranges` query, no network. That is
    what makes it safe to call inline on the scan path (planning#203): the
    thing this unblocks is a promotion, and a promotion that depended on a
    remote call would be exactly the "dependency outage becomes a silent
    denial" failure this module's docstring exists to rule out.
    """
    match = cloud_ranges.lookup(db, asset.value)
    tenancy, reason = tenancy_for_match(match)
    upsert_single_claim(
        db, asset.id, _OBSERVER_NAME, _CLAIM_TYPE,
        _claim_value(tenancy, reason, match, state), now,
    )
    return True


def tick() -> None:
    """One enricher pass. Idempotent; safe to call from APScheduler."""
    db = SessionLocal()
    try:
        state = cloud_ranges.dataset_state(db)
        if state is None:
            log.warning(
                "tenancy_enricher: no cloud range dataset loaded yet — "
                "writing nothing this tick (planning#181). An IP with no "
                "tenancy claim is 'not yet enriched', which is what this is; "
                "writing 'undetermined' here would report our own outage as "
                "a determination about the asset."
            )
            return
        if state.stale:
            log.warning(
                "tenancy_enricher: cloud range dataset generated_at=%s is "
                "older than %s — enriching anyway, but every claim this tick "
                "records that generated_at so the decision stays reconstructable",
                state.generated_at, cloud_ranges.STALE_AFTER,
            )

        assets = _select_assets_to_enrich(db, IPS_PER_TICK)
        if not assets:
            return

        now = datetime.now(timezone.utc)
        enriched = 0
        for asset in assets:
            try:
                if enrich_asset(db, asset, state, now):
                    enriched += 1
            except Exception:
                # One bad asset must not lose the tick's other writes.
                log.exception("tenancy_enricher: failed to enrich asset %s (%s)", asset.id, asset.value)

        db.commit()   # one commit for the whole tick, not one per asset
        log.info("tenancy_enricher: enriched %d IP(s) this tick", enriched)
    finally:
        db.close()


# ── internals ─────────────────────────────────────────────────────────────────

def _select_assets_to_enrich(db: Session, limit: int) -> list[_AssetRef]:
    """Two ordered passes, deliberately not one query — the ordering rule
    differs per group and the split is the readable way to say so.

    Pass 1 (never enriched, newest first): cold start is the normal steady
    state once enrichment is off the scan path, so a newly-discovered IP
    must not wait behind the whole backlog at `name_only`
    (planning#181 "Cold start" — a deliberate decision, not a default).

    Pass 2 (stale claims due for re-attempt, oldest first): fills any
    remaining budget once pass 1 is exhausted.
    """
    never_enriched = db.execute(
        text(
            "SELECT ac.id, ac.value "
            "FROM assets_canonical ac "
            "WHERE ac.asset_type = 'ip_address' "
            "AND NOT EXISTS ("
            "  SELECT 1 FROM asset_claims cl "
            "  JOIN observers o ON o.id = cl.observer_id "
            "  WHERE cl.asset_canonical_id = ac.id "
            "  AND o.name = :observer_name "
            "  AND cl.claim_type = :claim_type"
            ") "
            "ORDER BY ac.first_seen_at DESC "
            "LIMIT :limit"
        ),
        {"observer_name": _OBSERVER_NAME, "claim_type": _CLAIM_TYPE, "limit": limit},
    ).all()

    result = [_AssetRef(id=row[0], value=row[1]) for row in never_enriched]
    remaining = limit - len(result)
    if remaining <= 0:
        return result

    stale = db.execute(
        text(
            "SELECT ac.id, ac.value "
            "FROM assets_canonical ac "
            "JOIN asset_claims cl ON cl.asset_canonical_id = ac.id "
            "JOIN observers o ON o.id = cl.observer_id "
            "WHERE ac.asset_type = 'ip_address' "
            "AND o.name = :observer_name "
            "AND cl.claim_type = :claim_type "
            "AND ("
            "  (cl.claim_value->>'tenancy' = 'undetermined' AND cl.last_observed_at < :undetermined_cutoff) "
            "  OR (cl.claim_value->>'tenancy' <> 'undetermined' AND cl.last_observed_at < :decided_cutoff)"
            ") "
            "ORDER BY cl.last_observed_at ASC "
            "LIMIT :limit"
        ),
        {
            "observer_name": _OBSERVER_NAME,
            "claim_type": _CLAIM_TYPE,
            "undetermined_cutoff": datetime.now(timezone.utc) - UNDETERMINED_RETRY_AFTER,
            "decided_cutoff": datetime.now(timezone.utc) - REFRESH_AFTER,
            "limit": remaining,
        },
    ).all()

    result.extend(_AssetRef(id=row[0], value=row[1]) for row in stale)
    return result
