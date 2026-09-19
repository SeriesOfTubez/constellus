"""Tier 1b tenancy rung (planning#181).

Same shape as `tenancy_enricher.py` (Tier 0): a background drip job, not an
inline call. `tick()` writes a `tenancy` claim for a bounded batch of assets
per tick. This is the ninth registered scheduler job (ct_refresher,
epss_refresher, cpe_index_refresher, cloud_ranges_refresher,
tenancy_enricher, partition_maintenance, hygiene_scoring, nightly_rescore,
run_reaper, and this one), not a new mechanism.

Tier 1b derives a tenancy opinion from the certificate a **no-SNI TLS
handshake to the bare IP** returns — no hostname is offered, so whatever
certificate the far end presents by default is the evidence. Unlike Tier 0
(a local dataset lookup), this rung sends a real packet to a real host, so
it passes through `probe_authorisation.authorise_probes` under the
`ip_handshake` addressing mode exactly like any other connector — it is
gated, never an exception to the gate. Building it as an ungated background
job would have routed around the safety gate silently, and that was
explicitly rejected (see migration 0051 and `probe_authorisation`'s
`_probe_class_cap` docstring for the argued carve-out that makes
`ip_handshake` narrower than full `ip` addressing).

## The rung is ASYMMETRIC — this is the one design rule that governs the
## whole module

  - **Dissent branch is LIVE.** A certificate that positively matches a
    known provider-managed multi-tenant endpoint (`_MANAGED_ENDPOINT_SUFFIXES`)
    votes `not_single_tenant`. Under `projector._compose_tenancy`'s
    composition rule, dissent wins outright — so this branch can only ever
    *deny*. That is strictly safer than current behaviour: it can never
    cause a scan that would not otherwise have happened.
  - **Promote branch RECORDS BUT ABSTAINS.** Every other successful
    handshake writes the full certificate evidence onto the claim and votes
    `undetermined`. It does **not** vote `single_tenant`, not yet, under any
    condition.

The reason: the obvious promote rule — "a certificate we did not recognise
as a shared endpoint" — is an argument from ABSENCE, which is exactly the
evidence quality `projector._PROMOTING_TIERS` says is not promotable on its
own. The real distribution of certificates presented by Azure/GCP/OCI
customer compute is not known yet; it is gathered from this rung's own
`evidence` field during normal operation, and the promote rule is set from
that data later. Turning promotion on must remain a one-line change to a
rung that is already tested, not a rewrite.
"""

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal
from app.models.target import Target, TargetType
from app.services import probe_authorisation
from app.services.claim_emitter import upsert_single_claim

log = logging.getLogger(__name__)

TICK_INTERVAL_SECONDS = 300

# Unlike Tier 0 (a local indexed query, 200/tick at 60s), this rung emits
# traffic to the target, so the budget is deliberately an order of magnitude
# tighter — at most 25 handshakes per 5 minutes.
IPS_PER_TICK = 25

REFRESH_AFTER = timedelta(days=7)                # a decided (dissent) claim

# Tier 0 retries an `undetermined` after 6 hours because a retry is a free
# local lookup. Here a retry is another handshake, and while the promote
# branch abstains the overwhelming majority of verdicts WILL be
# `undetermined` — a 6-hour retry would re-handshake the same addresses four
# times a day for a vote that cannot change until the promote rule is set.
# One day.
UNDETERMINED_RETRY_AFTER = timedelta(days=1)

_OBSERVER_NAME = "tenancy_tls"
_CLAIM_TYPE = "tenancy"
TLS_PORT = 443

SINGLE_TENANT = "single_tenant"
NOT_SINGLE_TENANT = "not_single_tenant"
UNDETERMINED = "undetermined"
# SINGLE_TENANT is defined but deliberately unreferenced by any vote in this
# slice — it exists for the promote branch that lands once the certificate
# distribution described above is measured. Do not delete it.

_SCANNER_URL = os.environ.get("SCANNER_URL", "http://scanner-worker:8001")
_SCANNER_TOKEN = os.environ.get("SCANNER_INTERNAL_TOKEN", "")
_HEADERS = {"X-Internal-Token": _SCANNER_TOKEN}


@dataclass
class _AssetRef:
    id: object
    value: str


class _TenancyTlsProber:
    """This job's identity handle for the probe-authorisation gate —
    declares `observer` exactly as the Phase 1.5 connectors do
    (`app.connectors.naabu.NaabuConnector`, etc.). `tick()` is not a
    connector instance, it is a scheduler job, but the gate only ever reads
    `.observer` off whatever it is handed (see `probe_authorisation
    .authorise_probes`'s docstring), so a bare class with that one attribute
    is sufficient."""

    observer = _OBSERVER_NAME


# Provider-managed multi-tenant endpoints. A certificate presenting one of
# these names to a no-SNI connection is the provider's own managed service
# answering, not a customer's single-tenant host — the same judgement Tier 0
# makes from a published `edge`/`storage`/`managed` service_class, arrived at
# from the other end.
#
# DELIBERATELY NARROW, and it must stay that way. A `not_single_tenant` vote
# wins OUTRIGHT under `projector._compose_tenancy`'s rule 1, so a false
# positive here is a DENIAL regression — it breaks legitimate scanning of a
# real customer host. That is the opposite failure from the one the rest of
# this ladder guards against, and it is the reason this list is a short,
# provider-specific allowlist of suffixes rather than a general heuristic.
#
# OCI is deliberately absent: no suffix separates OCI customer compute from
# OCI managed services without a wider match than the denial risk justifies.
# Add it only with a specific, verified suffix.
_MANAGED_ENDPOINT_SUFFIXES: tuple[tuple[str, str, str], ...] = (
    # (suffix, provider, service_class-ish label used in the claim reason)
    (".cloudfront.net", "aws", "edge"),
    (".elb.amazonaws.com", "aws", "managed"),
    (".s3.amazonaws.com", "aws", "storage"),
    (".azurewebsites.net", "azure", "managed"),
    (".azureedge.net", "azure", "edge"),
    (".azurefd.net", "azure", "edge"),
    (".trafficmanager.net", "azure", "managed"),
    (".core.windows.net", "azure", "storage"),
    (".appspot.com", "gcp", "managed"),
    (".run.app", "gcp", "managed"),
    (".storage.googleapis.com", "gcp", "storage"),
)


def tenancy_for_cert(cert_row: dict | None) -> tuple[str, str | None, dict]:
    """Map one `/tlsx/scan` result row onto (tenancy, matched_suffix,
    evidence). Pure — no DB, no network. Test this directly.

    Returns:
      - `(UNDETERMINED, None, {})` when `cert_row` is `None` or not a dict —
        the target did not complete a TLS handshake on this port. That is
        "we could not tell", never "the answer is no".
      - `(NOT_SINGLE_TENANT, suffix, evidence)` when any certificate name
        (subject CN or a subject alternative name) matches a
        `_MANAGED_ENDPOINT_SUFFIXES` entry.
      - `(UNDETERMINED, None, evidence)` otherwise — the promote branch, and
        it abstains ON PURPOSE. Voting `single_tenant` here would be an
        argument from absence ("we didn't recognise this certificate as
        shared"), which is exactly the evidence quality
        `projector._PROMOTING_TIERS` rules out as not promotable on its own.
        The `evidence` returned here is what the promote rule will later be
        set from, once the real certificate distribution is measured.
    """
    if cert_row is None or not isinstance(cert_row, dict):
        return UNDETERMINED, None, {}

    raw_names = [cert_row.get("subject_cn")] + list(cert_row.get("subject_an") or [])
    names = [n.strip().lower() for n in raw_names if n]

    evidence = {
        "subject_cn": cert_row.get("subject_cn"),
        "subject_an": cert_row.get("subject_an"),
        "issuer_cn": cert_row.get("issuer_cn"),
        "issuer_org": cert_row.get("issuer_org"),
        "not_before": cert_row.get("not_before"),
        "not_after": cert_row.get("not_after"),
        "fingerprint": cert_row.get("fingerprint"),
        "tls_version": cert_row.get("tls_version"),
        "cipher": cert_row.get("cipher"),
        "port": cert_row.get("port"),
    }

    for suffix, _provider, _label in _MANAGED_ENDPOINT_SUFFIXES:
        bare = suffix.lstrip(".")
        for name in names:
            if name.endswith(suffix) or name == bare:
                return NOT_SINGLE_TENANT, suffix, evidence

    # This is the promote branch, and it abstains on purpose. Voting
    # `single_tenant` here would be an argument from absence — we did not
    # recognise this certificate as a shared endpoint, which is not the same
    # thing as it being single-tenant — and `projector._PROMOTING_TIERS`
    # exists precisely to keep that quality of evidence from promoting on
    # its own. The evidence collected above is what the promote rule will
    # later be set from, once the real distribution of certificates
    # Azure/GCP/OCI customer compute presents is measured.
    return UNDETERMINED, None, evidence


def _suffix_lookup(suffix: str) -> tuple[str, str]:
    for s, provider, label in _MANAGED_ENDPOINT_SUFFIXES:
        if s == suffix:
            return provider, label
    return "unknown", "unknown"


def _claim_value(tenancy: str, reason: str, evidence: dict, observed_at: datetime) -> dict:
    """Build the `tenancy` claim_value.

    Deliberately carries NO ownership field (planning#178, restated in
    `tenancy_enricher._claim_value`): tenancy and ownership are separate
    capabilities, and collapsing them here would make a recycled address in
    a single-tenant range ours to scan.

    `decided_by_tier` is `None` on `undetermined` because an undetermined
    verdict was not decided by anything — and
    `projector._tenancy_opinion_from_claim` derives `promoting` from this
    field, so getting it wrong silently changes gate behaviour.

    No `dataset_sha256`, unlike Tier 0: this rung does not consult the
    cloud-ranges dataset, so there is no dataset digest to pin.
    """
    return {
        "tenancy": tenancy,
        "decided_by_tier": 1 if tenancy != UNDETERMINED else None,
        "reason": reason,
        "evidence": evidence,
        "observed_at": observed_at.isoformat(),
    }


def _handshake(targets) -> list[dict] | None:
    """POST one batch of no-SNI handshake targets to the scanner worker's
    `/tlsx/scan` endpoint. Returns the `results` list, or `None` (distinct
    from `[]`) on any HTTP failure — see `tick()` for why that distinction
    matters."""
    payload = {"targets": list(targets), "timeout": 5.0, "concurrency": 10}
    try:
        resp = httpx.post(f"{_SCANNER_URL}/tlsx/scan", json=payload, headers=_HEADERS, timeout=60.0)
        resp.raise_for_status()
        body = resp.json()
        return body.get("results", []) or []
    except httpx.HTTPError:
        log.exception("tenancy_tls: scanner-worker /tlsx/scan call failed")
        return None


def tick() -> None:
    """One enricher pass. Idempotent; safe to call from APScheduler."""
    db = SessionLocal()
    try:
        assets = _select_assets_to_enrich(db, IPS_PER_TICK)
        if not assets:
            return

        scope = {"domains": [], "ip_ranges": []}
        for t_type, value in db.query(Target.type, Target.value).all():
            key = "domains" if t_type == TargetType.DOMAIN else "ip_ranges"
            scope[key].append(value)

        probes = [DiscoveredAsset(asset_type="ip_address", value=a.value) for a in assets]
        gate = probe_authorisation.authorise_probes(
            db, connector_id=_OBSERVER_NAME, connector=_TenancyTlsProber,
            assets=probes, scope=scope,
        )

        # `gate.permitted` is the UNFILTERED asset list under the default
        # `log_only` mode — that permissiveness exists so the rollout does
        # not stop the product scanning. This job has no such availability
        # requirement: it is a background enricher, and nothing breaks if it
        # collects nothing this tick. So it honours the REAL computed
        # verdict in `gate.permissions` in both modes, which is strictly
        # safer and never sends a handshake the gate would have refused
        # under `enforce`.
        allowed = [
            a for a in assets
            if (p := gate.permissions.get(("ip_address", a.value))) is not None
            and p.allowed and "ip_handshake" in p.modes
        ]
        if not allowed:
            log.info("tenancy_tls: selected %d asset(s), gate allowed 0 — nothing to do this tick", len(assets))
            return

        rows = _handshake({"ip": a.value, "port": TLS_PORT} for a in allowed)

        if rows is None:
            # A worker outage is OUR failure, and writing `undetermined` for
            # it would record our own outage as a determination about the
            # asset. An IP with no `tenancy_tls` claim is "not yet probed",
            # which is exactly what this is — nothing is written this tick.
            return

        by_ip = {row.get("ip"): row for row in rows}

        now = datetime.now(timezone.utc)
        dissented = 0
        abstained = 0
        # Counted separately from `abstained` even though both vote
        # `undetermined`: "the host completed no TLS handshake" and "it
        # presented a certificate we did not classify" are different facts,
        # and planning#177's whole lesson is that collapsing them is how a
        # broken probe path hides as a policy outcome. The claim's `reason`
        # already separates them per-asset; this keeps the tick log honest
        # too, so `dissented + abstained + unreachable` reconciles with the
        # number the gate allowed.
        unreachable = 0
        for asset in allowed:
            try:
                cert_row = by_ip.get(asset.value)
                tenancy, suffix_match, evidence = tenancy_for_cert(cert_row)
                if cert_row is None:
                    reason = "no_tls_handshake"
                    unreachable += 1
                elif tenancy == NOT_SINGLE_TENANT:
                    provider, label = _suffix_lookup(suffix_match)
                    reason = f"managed_endpoint_cert:{provider}:{label}"
                    dissented += 1
                else:
                    reason = "cert_unclassified_promote_branch_abstains"
                    abstained += 1

                upsert_single_claim(
                    db, asset.id, _OBSERVER_NAME, _CLAIM_TYPE,
                    _claim_value(tenancy, reason, evidence, now), now,
                )
            except Exception:
                # One bad asset must not lose the tick's other writes.
                log.exception("tenancy_tls: failed to enrich asset %s (%s)", asset.id, asset.value)

        db.commit()   # one commit for the whole tick, not one per asset
        log.info(
            "tenancy_tls: selected %d, gate allowed %d, dissented %d, abstained %d, "
            "unreachable %d this tick",
            len(assets), len(allowed), dissented, abstained, unreachable,
        )
    finally:
        db.close()


# ── internals ─────────────────────────────────────────────────────────────────

def _select_assets_to_enrich(db: Session, limit: int) -> list[_AssetRef]:
    """Two ordered passes, same shape as `tenancy_enricher._select_assets_to_enrich`.

    Pass 1 (never enriched by THIS observer, newest first). Pass 2 (stale
    claims due for re-attempt, oldest first).

    One additional narrowing in BOTH passes beyond Tier 0's own query: the
    candidate asset must already carry a Tier 0 `tenancy_enricher` claim
    reading `undetermined`. Only addresses Tier 0 could not decide are worth
    a handshake — this is the issue's own "the deciding tier is recorded and
    a later tier is not spent when an earlier one settled" criterion, and it
    is also what keeps the traffic budget pointed at the population Tier 1
    exists for: Azure, GCP and OCI customer compute, which Tier 0 is
    structurally incapable of promoting. An address Tier 0 already settled
    either promotes or denies without us. Requiring the Tier 0 claim to
    EXIST (not merely be absent) also means this rung never runs ahead of
    Tier 0 on a cold-start address.
    """
    _tier0_undetermined = (
        "AND EXISTS ("
        "  SELECT 1 FROM asset_claims t0"
        "  JOIN observers o0 ON o0.id = t0.observer_id"
        "  WHERE t0.asset_canonical_id = ac.id"
        "  AND o0.name = 'tenancy_enricher'"
        "  AND t0.claim_type = 'tenancy'"
        "  AND t0.claim_value->>'tenancy' = 'undetermined'"
        ") "
    )

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
            + _tier0_undetermined +
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
            + _tier0_undetermined +
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
