"""Dangling-DNS finding type — planning#105, epic#81 Phase B Layer 4.

Promotes the Phase-A domain-affinity primitive (services/domain_affinity.py)
and the Phase-B fingerprint layer (services/takeover_fingerprint.py) from
silent attribution inputs into a user-facing `dangling_dns` finding
(`category="exposure"` — locked decision, no new category), with a
High/Medium/Low severity gradient based on which layer fired:

  - High   — a nuclei `takeover` fingerprint hit (Layer 2). Directly
             claimable now (unclaimed SaaS/bucket CNAME target).
  - Medium — no fingerprint hit, record resolves to a shared-hosting origin
             that shows no affinity (Layer 1, verdict=not_affine — the
             epic's motivating contoso.com case). Takeover requires a
             provider vhost-claim / IP reassignment, not immediate.
  - Low    — no fingerprint hit, origin resolves but is completely
             unreachable on every probed port (Layer 1, verdict=indeterminate
             with unreachable_votes == every port). Masked-by-redirect /
             latent — lower urgency, may just be a retired origin behind a
             still-serving edge.

CDN-annotated records with no takeover signature are silent by design —
absence of affinity on a shared edge is normal there (Layer 1 has no origin
IP asset to probe past a CDN boundary anyway); a wrong "your DNS is
takeoverable" verdict is treated as being as damaging as a false attribution
(epic#81 decision 3).

Layer 3 (planning#106, epic#81 Phase C — the affiliated-hostname half) also
lives here: for a Medium/Low tier hit, services/origin_corroboration.py
checks whether Shodan-known OTHER hostnames on the same origin get a real,
SNI-correct response. A strong hit (the other hostname's own cert covers
it) means the origin is alive for someone else, not dead for everyone —
that promotes a Low (which rested on the known-weak no-SNI "default vhost"
probe) to Medium. One-directional only, per decision 3: a negative/absent
corroboration never demotes or suppresses anything, and corroboration
never fires a finding on its own — it only re-grades a tier Layer 1/2
already decided.

Runs as a post-scan step (scan_executor.py) over dns_record assets in this
run's authorized target scope (planning#114, epic#81 Phase D follow-up L2) —
widened from touched-this-run-only the same way planning#113 widened
shared_infra_verifier, via the shared services/target_scope.py helper — union
of `target_scope.target_scoped_asset_ids(scope)` and `touched_asset_ids`,
mirroring exposure_analyzer.py's emit/resolve shape. Flap-guard here has no
`open_ports[]`-equivalent persisted/pruned array to key off, so resolution
instead requires a sustained clean re-check past a grace window
(_DANGLING_GRACE_DAYS) rather than a single miss — a tier hit on a
previously-resolved finding reopens it automatically via finding_writer's
existing reopen-on-reobservation path.

Widening the population to "authorized scope" (not just "touched this run")
introduced a new problem planning#113 didn't have: "a record was evaluated"
and "a record was touched this run" used to be the same fact. They aren't
anymore, so `_evaluate_record`'s per-record outcome is now three-way —
`hit` / `probed_clean` / `skipped_not_judged` — and only `probed_clean`
records ever feed `_resolve_clean_records`'s resolution logic. A record with
no fresh evidence either way (cadence/budget gate closed, or a probe that
came back genuinely empty — see the empty-matrix fix below) must never
silently resolve an open finding just because it wasn't judged this run.

Scope-only records (never touched by a connector this run) are gated by a
cadence/budget mechanism, bucketed by *state*, not severity tier (a "tier"
only exists once an evaluation already fired):
  1. Touched this run -> probe unconditionally (today's entire population at
     today's frequency, no regression, same union-not-replace contract as
     #113).
  2. Has an open/acknowledged dangling_dns finding -> probe unconditionally,
     bypassing TTL and budget. Keeps `_DANGLING_GRACE_DAYS` meaningful:
     resolution still requires the tier to stay quiet across multiple
     genuine clean probes, not one probe after a stale TTL window lapses.
  3. Scope-only, clean, no open finding -> gated: due when
     `dangling_probe_at` is missing/stale (`_DANGLING_PROBE_TTL_DAYS`),
     capped at `_DANGLING_PROBE_BUDGET` records/run, oldest-stamped-first.
     CDN-annotated records are excluded from this bucket entirely — they
     never get a `dangling_probe_at` stamp (Layer 1 doesn't apply past a CDN
     boundary), so leaving them eligible would let them permanently starve
     the budget (always "never stamped", always sorted first, forever).
     `dangling_probe_at` itself lives on `asset_state.attributes` (planning#144
     L3b-3 — moved off `asset_metadata` via `projector.merge_state_attributes`;
     the `cdn` read above stays on `asset_metadata`, that boundary judgment is
     still asset_metadata-authoritative until #147/L3c).

Also fixes a real, pre-existing bug independent of the widening: when the
scanner-worker is unreachable, `domain_affinity.check_affinity` fails soft to
an empty probe matrix, which used to read as a plain "clean" indeterminate
verdict — a multi-day worker outage would silently auto-resolve every open
dangling_dns finding with zero evidence behind it. An empty matrix is now
`skipped_not_judged`, not `probed_clean`.
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.connectors.base import DiscoveredFinding
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.finding_canonical import FindingCanonical
from app.models.target import Target, TargetType
from app.services import domain_affinity, origin_corroboration, projector, target_scope, takeover_fingerprint
from app.services.finding_writer import write_findings
from app.services.target_service import apex_domain

log = logging.getLogger(__name__)

FINDING_TYPE = "dangling_dns"
SOURCE = "constellus"
CATEGORY = "exposure"

_RECORD_TYPES = ("A", "AAAA", "CNAME")

# A single clean re-check doesn't resolve a dangling_dns finding — mirrors
# asset_writer's _CONFIRMED_PORT_GRACE_DAYS convention for the same reason
# (real infra flaps; a transient origin blip must not churn a "takeoverable"
# finding open<->resolved on every scan).
_DANGLING_GRACE_DAYS = 3

# Bucket-3 (scope-only, clean, no open finding) cadence/budget gate —
# planning#114. TTL matches the order of magnitude of a typical weekly
# monitoring cadence; budget keeps one run from live-probing an entire large
# estate at once.
_DANGLING_PROBE_TTL_DAYS = 7
_DANGLING_PROBE_BUDGET = 50

STATUS_HIT = "hit"
STATUS_PROBED_CLEAN = "probed_clean"
STATUS_SKIPPED = "skipped_not_judged"


@dataclass
class RecordOutcome:
    status: str  # STATUS_HIT | STATUS_PROBED_CLEAN | STATUS_SKIPPED
    tier_result: dict | None = None
    # Whether Layer 1's origin probe actually ran and produced usable
    # evidence this call — drives the `dangling_probe_at` freshness stamp.
    # False for a fingerprint hit (Layer 1 never reached), a CDN record
    # (Layer 1 doesn't apply), a gate-closed skip (never attempted), and an
    # empty probe matrix (attempted but produced nothing — see module
    # docstring's empty-matrix fix).
    probed: bool = False


TIER_HIGH = "high"
TIER_MEDIUM = "medium"
TIER_LOW = "low"

LAYER_FINGERPRINT = "fingerprint"
LAYER_AFFINITY_NOT_AFFINE = "affinity_not_affine"
LAYER_AFFINITY_UNREACHABLE = "affinity_unreachable"
LAYER_AFFINITY_CORROBORATED_ALIVE = "affinity_corroborated_alive"

_REMEDIATION: dict[str, str] = {
    TIER_HIGH: (
        "Remove the dangling CNAME or reclaim the target service immediately — "
        "this is directly exploitable now."
    ),
    TIER_MEDIUM: (
        "Verify this record still needs to point at a shared-hosting origin. "
        "If the service was decommissioned, remove or repoint the record."
    ),
    TIER_LOW: (
        "The origin is unreachable on every probed port. Confirm whether this "
        "record is still needed and remove it if the service is retired."
    ),
}


def analyze_dangling_dns(
    db: Session,
    scan_run_id: uuid.UUID,
    scope: dict,
    touched_asset_ids: set[uuid.UUID],
    since: datetime,
    new_canonical_ids_out: list[uuid.UUID] | None = None,
) -> set[uuid.UUID]:
    """Detect dangling-DNS conditions over dns_record assets in this run's
    authorized target scope (planning#114: target_scope.target_scoped_asset_ids(scope),
    unioned with touched_asset_ids — never a replacement, see target_scope.py)
    and emit/resolve dangling_dns findings. Returns the set of canonical
    finding ids touched (emitted/refreshed + resolved) this run."""
    asset_ids = target_scope.target_scoped_asset_ids(db, scope) | touched_asset_ids
    if not asset_ids:
        return set()

    records = (
        db.query(AssetCanonical)
        .filter(
            AssetCanonical.id.in_(asset_ids),
            AssetCanonical.asset_type == "dns_record",
        )
        .all()
    )
    records = [r for r in records if r.record_type in _RECORD_TYPES]
    if not records:
        return set()

    owned_apexes = _owned_apexes(db)
    gate_open_ids = _compute_gate_open_ids(db, records, touched_asset_ids)

    findings: list[DiscoveredFinding] = []
    probed_clean_ids: set[uuid.UUID] = set()
    probed_stamp_ids: set[uuid.UUID] = set()

    for record in records:
        try:
            outcome = _evaluate_record(db, record, since, owned_apexes, gate_open=record.id in gate_open_ids)
        except Exception:
            log.exception(
                "dangling_dns_analyzer: failed to evaluate record %s (%s) — skipping, not judged this run",
                record.id, record.value,
            )
            db.rollback()
            continue

        if outcome.probed:
            probed_stamp_ids.add(record.id)

        if outcome.status == STATUS_HIT:
            findings.append(_build_finding(record, outcome.tier_result))
        elif outcome.status == STATUS_PROBED_CLEAN:
            probed_clean_ids.add(record.id)
        # STATUS_SKIPPED: no fresh evidence either way — no finding, not
        # eligible for resolution, no freshness stamp.

    touched: set[uuid.UUID] = set()
    if findings:
        touched = write_findings(db, scan_run_id, findings, new_canonical_ids_out=new_canonical_ids_out)

    # Aggregate stamping pass, one commit — not per-record, since
    # _evaluate_record isn't fully pure (origin_corroboration.corroborate_liveness
    # -> hosting_classifier.reverse_ip_domains commits mid-loop on hit paths,
    # the same shape #113 handled in shared_infra_verifier.verify_findings).
    if probed_stamp_ids:
        _stamp_probe_timestamps(db, probed_stamp_ids)

    touched |= _resolve_clean_records(db, probed_clean_ids)

    return touched


def _open_dangling_finding_filter(asset_ids):
    """Shared filter for "has an open/acknowledged dangling_dns finding" —
    used by both the bucket-2 gate computation and _resolve_clean_records.
    Kept as one definition (planning#114) so the two can't silently drift
    apart, which would break the bucket-2 grace-preservation guarantee."""
    return (
        FindingCanonical.asset_canonical_id.in_(list(asset_ids)),
        FindingCanonical.source == SOURCE,
        FindingCanonical.finding_type == FINDING_TYPE,
        FindingCanonical.state.in_(["open", "acknowledged"]),
    )


def _open_finding_asset_ids(db: Session, asset_ids: set[uuid.UUID]) -> set[uuid.UUID]:
    if not asset_ids:
        return set()
    rows = (
        db.query(FindingCanonical.asset_canonical_id)
        .filter(*_open_dangling_finding_filter(asset_ids))
        .all()
    )
    return {r[0] for r in rows}


def _compute_gate_open_ids(
    db: Session, records: list[AssetCanonical], touched_asset_ids: set[uuid.UUID],
) -> set[uuid.UUID]:
    """Bucket every record by state (planning#114 — see module docstring):
    bucket 1 (touched) and bucket 2 (open finding) probe unconditionally;
    bucket 3 (scope-only, clean, no open finding, non-CDN) is TTL+budget
    gated, oldest-stamped-first. CDN-annotated records are excluded from
    bucket 3 entirely — they can never be probed (Layer 1 doesn't apply past
    a CDN boundary), so including them would let them permanently starve the
    budget (always "never stamped", always sorted first)."""
    record_ids = {r.id for r in records}
    open_finding_ids = _open_finding_asset_ids(db, record_ids)

    gate_open_ids: set[uuid.UUID] = set()
    due_candidates: list[AssetCanonical] = []
    for record in records:
        if record.id in touched_asset_ids or record.id in open_finding_ids:
            gate_open_ids.add(record.id)
            continue
        meta = record.asset_metadata or {}
        if meta.get("cdn"):
            continue  # never probeable, never occupies a budget slot
        due_candidates.append(record)

    probe_stamps = _dangling_probe_stamps(db, {r.id for r in due_candidates})
    due_candidates.sort(key=lambda r: probe_stamps.get(r.id) or "")

    now = datetime.now(timezone.utc)
    ttl_cutoff = now - timedelta(days=_DANGLING_PROBE_TTL_DAYS)
    budget_left = _DANGLING_PROBE_BUDGET
    for record in due_candidates:
        if budget_left <= 0:
            break
        stamp = probe_stamps.get(record.id)
        due = True
        if stamp:
            try:
                due = datetime.fromisoformat(stamp) < ttl_cutoff
            except ValueError:
                due = True
        if due:
            gate_open_ids.add(record.id)
            budget_left -= 1

    return gate_open_ids


def _dangling_probe_stamps(db: Session, record_ids: set[uuid.UUID]) -> dict[uuid.UUID, str | None]:
    """Batch-read `dangling_probe_at` from `asset_state.attributes` for a set
    of candidate record ids (planning#144 L3b-3 — moved off `asset_metadata`).
    A record id with no `asset_state` row yet (nothing has projected/stamped
    it) simply isn't in the returned dict, same as a missing key would be."""
    if not record_ids:
        return {}
    rows = (
        db.query(AssetState.asset_canonical_id, AssetState.attributes)
        .filter(AssetState.asset_canonical_id.in_(record_ids))
        .all()
    )
    return {asset_id: (attributes or {}).get("dangling_probe_at") for asset_id, attributes in rows}


def _stamp_probe_timestamps(db: Session, stamped_ids: set[uuid.UUID]) -> None:
    """Stamp `dangling_probe_at` on `asset_state.attributes` (planning#144
    L3b-3 — moved off `asset_metadata`) via `projector.merge_state_attributes`,
    which JSONB `||`-merges the single key in without disturbing any other
    attributes key (e.g. the projector's own `probe_class`/`provider_mx`)."""
    now_iso = datetime.now(timezone.utc).isoformat()
    for record_id in stamped_ids:
        projector.merge_state_attributes(db, record_id, {"dangling_probe_at": now_iso})
    db.commit()


def _owned_apexes(db: Session) -> set[str]:
    """Apex domains for every verified domain-type Target, computed once per
    scan run. Used by origin_corroboration to keep from "corroborating"
    with our own other domains that happen to share the same origin —
    not used for Layer 1's own affine/not_affine verdict, which stays
    scoped to just the record's own apex (unchanged from Phase B)."""
    values = (
        db.query(Target.value)
        .filter(Target.type == TargetType.DOMAIN, Target.verified == True)  # noqa: E712
        .all()
    )
    return {apex_domain(v) for (v,) in values}


def _evaluate_record(
    db: Session, record: AssetCanonical, since: datetime, owned_apexes: set[str], gate_open: bool,
) -> RecordOutcome:
    """Return a three-way RecordOutcome (planning#114 — see module
    docstring): STATUS_HIT (a tier fired), STATUS_PROBED_CLEAN (a fresh
    Layer 1 probe ran and found nothing), or STATUS_SKIPPED (no fresh
    evidence either way this call — gate closed, CDN, or an empty probe
    matrix). Only STATUS_PROBED_CLEAN records are eligible for resolution."""
    # Layer 2 first, regardless of gate/CDN status — a fingerprint hit is a
    # free DB query, never gated, and strong evidence that outranks the
    # affinity-derived tiers even on a non-CDN record.
    signal = takeover_fingerprint.find_takeover_signal(db, record.id, since)
    if signal is not None:
        return RecordOutcome(STATUS_HIT, {"tier": TIER_HIGH, "layer": LAYER_FINGERPRINT, "signal": signal})

    if not gate_open:
        # Cadence/budget gate closed (or a CDN scope-only record, which is
        # permanently excluded from the gate — see _compute_gate_open_ids):
        # no fresh evidence attempted this call.
        return RecordOutcome(STATUS_SKIPPED)

    meta = record.asset_metadata or {}
    if meta.get("cdn"):
        # CDN-fronted, no takeover signature — absence of affinity on a
        # shared edge is normal; Layer 1 has no origin IP asset to probe
        # past the CDN boundary anyway (dns_resolve.py suppresses it). Never
        # stamped: no origin probe actually ran.
        return RecordOutcome(STATUS_PROBED_CLEAN, probed=False)

    origin_ip = domain_affinity.resolve_origin(db, record)
    if origin_ip is None:
        return RecordOutcome(STATUS_PROBED_CLEAN, probed=True)

    record_apex = apex_domain(record.value)
    # Layer 1's own affine/not_affine verdict stays scoped to just this
    # record's apex — unchanged from Phase B. The wider org-apex set below
    # is only for Layer 3 corroboration filtering (a broader "don't
    # corroborate with our own other domains" check), a new concern this
    # feature introduces, not a change to Layer 1's established scope.
    result = domain_affinity.check_affinity(record.value, origin_ip, {record_apex})

    if not result.matrix:
        # Regression #1 fix: an empty matrix is what a fully-unreachable
        # scanner-worker looks like (_probe_worker fails soft to
        # {"ports": {}}) — this used to fall through to the final "silent"
        # return and get treated as clean, so a multi-day worker outage
        # would silently auto-resolve every open finding with zero evidence.
        # No evidence was actually gathered — skipped, not stamped.
        return RecordOutcome(STATUS_SKIPPED)

    if result.verdict == domain_affinity.VERDICT_NOT_AFFINE:
        tier_result = {
            "tier": TIER_MEDIUM,
            "layer": LAYER_AFFINITY_NOT_AFFINE,
            "origin_ip": origin_ip,
            "signals": result.signals,
        }
        # Layer 3 (planning#106): additive only here — a not_affine verdict
        # already fired the Medium tier; corroboration just enriches the
        # narrative, it doesn't change the tier.
        tier_result["corroboration"] = origin_corroboration.corroborate_liveness(
            db, origin_ip, record.value, owned_apexes | {record_apex},
        )
        return RecordOutcome(STATUS_HIT, tier_result, probed=True)

    if (
        result.verdict == domain_affinity.VERDICT_INDETERMINATE
        and result.unreachable_votes == len(result.matrix)
    ):
        tier_result = {
            "tier": TIER_LOW,
            "layer": LAYER_AFFINITY_UNREACHABLE,
            "origin_ip": origin_ip,
            "signals": result.signals,
        }
        corroboration = origin_corroboration.corroborate_liveness(
            db, origin_ip, record.value, owned_apexes | {record_apex},
        )
        tier_result["corroboration"] = corroboration
        if corroboration.origin_serves_others:
            # Strong evidence the origin is alive for someone else, not
            # dead for everyone — the Low tier's premise rested on the
            # known-weak no-SNI "default vhost" probe (many SNI-strict
            # servers reject it outright regardless of health). One-
            # directional promotion only: a negative/absent corroboration
            # never demotes or suppresses anything (decision 3).
            tier_result["tier"] = TIER_MEDIUM
            tier_result["layer"] = LAYER_AFFINITY_CORROBORATED_ALIVE
        return RecordOutcome(STATUS_HIT, tier_result, probed=True)

    # affine, or genuinely ambiguous indeterminate — a real probe ran and
    # found nothing actionable.
    return RecordOutcome(STATUS_PROBED_CLEAN, probed=True)


def _build_finding(record: AssetCanonical, tier_result: dict) -> DiscoveredFinding:
    tier = tier_result["tier"]
    layer = tier_result["layer"]
    corroboration = tier_result.get("corroboration")

    detail: dict = {
        "fingerprint": "dangling-dns",
        "tier": tier,
        "layer": layer,
        "remediation": _REMEDIATION[tier],
        # Reserved for epic#81 Phase C (planning#106, Shodan "last-seen-ours"
        # history dating) — a separate, still-unbuilt piece; stays null.
        "last_seen_ours": None,
    }
    if corroboration is not None and corroboration.attempted:
        detail["corroboration"] = {
            "attempted": True,
            "origin_serves_others": corroboration.origin_serves_others,
            "corroborating_hostname": corroboration.corroborating_hostname,
            "evidence": corroboration.evidence,
            "hostnames_probed": corroboration.hostnames_probed,
        }

    # Branches on LAYER, not tier — LAYER_AFFINITY_CORROBORATED_ALIVE is
    # also tier=TIER_MEDIUM (the promoted case) but needs its own narrative,
    # distinct from a "genuine" not_affine Medium.
    if layer == LAYER_FINGERPRINT:
        signal = tier_result["signal"]
        template_id = signal.get("template_id") or "unknown"
        title = f"Possible subdomain takeover: {record.value}"
        description = (
            f"Nuclei flagged a takeover signature on {record.value} "
            f"(template: {template_id}). This DNS record may point at an "
            "unclaimed or deprovisioned third-party service — an attacker "
            "could claim it and serve content under this domain."
        )
        finding_id = signal.get("finding_id")
        detail["nuclei_finding_id"] = str(finding_id) if finding_id else None
        detail["nuclei_template_id"] = signal.get("template_id")
    elif layer == LAYER_AFFINITY_CORROBORATED_ALIVE:
        origin_ip = tier_result["origin_ip"]
        other = corroboration.corroborating_hostname if corroboration else None
        title = f"DNS record points to a shared-hosting origin confirmed alive for other tenants: {record.value}"
        description = (
            f"{record.value} resolves to {origin_ip}. The origin didn't respond "
            f"for this specific hostname, but Constellus confirmed it actively "
            f"serves {other or 'another hostname'} — this is live shared "
            "hosting that no longer answers for this record, not a dead origin."
        )
        detail["origin_ip"] = origin_ip
        detail["signals"] = tier_result["signals"]
    elif layer == LAYER_AFFINITY_NOT_AFFINE:
        origin_ip = tier_result["origin_ip"]
        title = f"DNS record points to a shared-hosting origin with no ownership signal: {record.value}"
        description = (
            f"{record.value} resolves to {origin_ip}, a shared-hosting origin "
            "that shows no evidence of serving content for this specific "
            "hostname. If that origin is ever reassigned to a new tenant, "
            "the new tenant could inherit traffic intended for this domain."
        )
        detail["origin_ip"] = origin_ip
        detail["signals"] = tier_result["signals"]
    else:  # LAYER_AFFINITY_UNREACHABLE
        origin_ip = tier_result["origin_ip"]
        title = f"DNS record points to an unreachable origin: {record.value}"
        description = (
            f"{record.value} resolves to {origin_ip}, which did not respond "
            "on any probed port. The record may be masked by an edge/"
            "redirect that still serves content, or the origin may simply "
            "be retired."
        )
        detail["origin_ip"] = origin_ip
        detail["signals"] = tier_result["signals"]

    return DiscoveredFinding(
        asset_value=record.value,
        asset_id=record.id,
        finding_type=FINDING_TYPE,
        source=SOURCE,
        severity=tier,
        title=title,
        description=description,
        category=CATEGORY,
        detail=detail,
    )


def _resolve_clean_records(db: Session, probed_clean_ids: set[uuid.UUID]) -> set[uuid.UUID]:
    """Resolve open/acknowledged dangling_dns findings on assets that got a
    fresh, clean Layer 1 probe this run (STATUS_PROBED_CLEAN only —
    STATUS_SKIPPED records have no fresh evidence and must never resolve a
    finding just because they weren't judged) — but only once the finding
    hasn't been reconfirmed dangling for longer than the grace window, so one
    clean check doesn't immediately close a finding that might just be a
    transient blip."""
    if not probed_clean_ids:
        return set()

    rows = (
        db.query(FindingCanonical)
        .filter(*_open_dangling_finding_filter(probed_clean_ids))
        .all()
    )
    if not rows:
        return set()

    now = datetime.now(timezone.utc)
    grace_cutoff = now - timedelta(days=_DANGLING_GRACE_DAYS)
    resolved: set[uuid.UUID] = set()
    for row in rows:
        last_seen = row.last_seen_at
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        if last_seen < grace_cutoff:
            row.state = "resolved"
            row.resolved_at = now
            resolved.add(row.id)

    if resolved:
        db.commit()
    return resolved
