"""
Scan executor — orchestrates connector phases for a scan run.

Phase order (per chunk):
  1. DISCOVERY  — built-in tools (CT logs, subfinder, dnsrecon, brute-force)
                  then DNSDiscoveryConnectors (Cloudflare, Route53, etc.)
  2. ENRICHMENT — EnrichmentConnectors (Tenable, Wiz, FortiManager, etc.)
  3. SCANNING   — ScanningConnectors (Nuclei, etc.)

Run-level behavior:
  * Dynamic scope resolution — if the run's template has `dynamic_scope=True`,
    scope is rebuilt from the `targets` table at run start (optionally filtered
    by the template's `target_tag_filter`). Otherwise the run's static scope is
    used as-is.
  * Batching — the resolved scope is sliced into chunks of `template.batch_size`
    and each chunk runs the full Phase 1/2/3 pipeline in sequence. Single
    ScanRun row; chunks are internal. Inter-batch sleep via `batch_delay_seconds`.
  * Fail-soft — a chunk that raises records the error on `scan_runs.partial_failures`
    and the loop continues. Final status is COMPLETED if any chunks ran;
    FAILED is reserved for hard aborts that take down the executor itself.
  * Cancellation — between chunks the run is refetched; if status moved to
    CANCELLED, the loop stops cleanly.
"""

import logging
import time
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.connectors.base import (
    DNSDiscoveryConnector,
    DiscoveredAsset,
    EnrichmentConnector,
    PhaseResult,
    ScanningConnector,
)
from app.core.database import SessionLocal
from app.models.scan import ScanRun, ScanStatus
from app.models.scan_template import ScanTemplate
from app.services import aggressiveness
from app.services import app_settings as settings_svc
from app.services import nuclei_tag_filter
from app.services import projector
from app.services.asset_writer import write_assets
from app.services.finding_writer import write_findings
from app.services.target_service import is_verified, is_scan_authorised, apex_domain

log = logging.getLogger(__name__)


def launch(scan_run_id: uuid.UUID, scope: dict, registry: dict) -> None:
    db = SessionLocal()
    try:
        _run(db, scan_run_id, scope, registry)
    except Exception as exc:
        log.exception("Unhandled error in scan executor for run %s", scan_run_id)
        _fail(db, scan_run_id, str(exc))
    finally:
        db.close()


# ── internal ──────────────────────────────────────────────────────────────────

def _run(db: Session, scan_run_id: uuid.UUID, scope: dict, registry: dict) -> None:
    run = db.get(ScanRun, scan_run_id)
    if not run:
        return

    _set_status(db, run, ScanStatus.RUNNING, started_at=datetime.now(timezone.utc))

    # Pull template-level config if this run is linked to one
    template = db.get(ScanTemplate, run.template_id) if run.template_id else None

    # Resolve scope dynamically if the template asks for it. Falls back to the
    # run's static scope (passed in via `scope`) otherwise — the existing one-shot
    # and per-asset-recheck code paths continue to work unchanged.
    if template and template.dynamic_scope:
        scope = _resolve_dynamic_scope(db, template)
        run.scope = scope  # audit: record what we actually scanned
        db.commit()

    auth_mode = settings_svc.get(db, "scan_authorisation_mode") or "disabled"

    # planning#125 — every declared domain Target (and its subdomains) is
    # "ours" for dns_resolve's boundary detection. Not filtered to verified
    # targets: passive resolution isn't gated on scan authorisation either
    # (see dns_resolve.py's module docstring), and a target the user just
    # added is still their declared scope even before the verification
    # handshake completes.
    from app.models.target import Target, TargetType
    owned_domains: frozenset[str] = frozenset(
        r[0] for r in db.query(Target.value).filter(Target.type == TargetType.DOMAIN).all()
    )
    options: dict = run.options or {}
    skip_discovery: bool = bool(options.get("skip_discovery"))
    # planning#115 — set only by the manual "Re-verify" endpoint
    # (POST /findings/{id}/verify). Threaded to shared_infra_verifier so an
    # explicit human action bypasses the automatic TTL cache / grace guard.
    force_reverify: bool = bool(options.get("force_reverify"))

    # Resolve aggressiveness with the most-specific-wins cascade:
    # target > template/run > global. The template/run "fallback tier" is
    # what gets used for any scope value with no Target row (per-asset
    # rechecks, manual scope, etc.). The per-target override is applied
    # in _partition_scope_by_tier below.
    global_tier = aggressiveness.resolve(db, options)

    batch_size = (template.batch_size if template else None)
    batch_delay = (template.batch_delay_seconds if template else 0) or 0

    domains: list[str] = scope.get("domains", []) or []
    ip_ranges: list[str] = scope.get("ip_ranges", []) or []

    # Partition scope into tier-homogeneous sub-scopes BEFORE chunking by
    # size. Each (tier, sub_scope) pair becomes its own chunk sequence so
    # the executor only ever runs a chunk against a single tier.
    scope_by_tier = _partition_scope_by_tier(db, domains, ip_ranges, global_tier)

    chunks: list[tuple[str, dict]] = []
    for sub_tier, sub_scope in scope_by_tier.items():
        for sub_chunk in _chunk_scope(sub_scope["domains"], sub_scope["ip_ranges"], batch_size):
            chunks.append((sub_tier, sub_chunk))

    if not chunks:
        log.info("Run %s has empty scope, marking complete", scan_run_id)
        run.aggressiveness = global_tier
        db.commit()
        _set_status(db, run, ScanStatus.COMPLETED, completed_at=datetime.now(timezone.utc))
        return

    # run.aggressiveness audit: single tier when all chunks agree, else "mixed".
    tiers_present = sorted({t for t, _ in chunks})
    run.aggressiveness = tiers_present[0] if len(tiers_present) == 1 else "mixed"
    db.commit()

    log.info(
        "Run %s: %d target(s) split into %d chunk(s) across tiers %s, "
        "batch_size=%s, delay=%ss, skip_discovery=%s",
        scan_run_id, len(domains) + len(ip_ranges), len(chunks),
        tiers_present, batch_size, batch_delay, skip_discovery,
    )

    connectors_used: list[str] = []
    new_finding_ids: list[uuid.UUID] = []
    touched_asset_ids: set[uuid.UUID] = set()
    touched_finding_ids: set[uuid.UUID] = set()

    for chunk_idx, (chunk_tier, chunk_scope) in enumerate(chunks):
        # Cancellation check between chunks
        db.refresh(run)
        if run.status == ScanStatus.CANCELLED:
            log.info("Run %s cancelled — stopping at chunk %d/%d", scan_run_id, chunk_idx, len(chunks))
            return

        try:
            _run_pipeline(
                db, scan_run_id, chunk_scope, options, auth_mode, chunk_tier,
                skip_discovery, registry, connectors_used,
                owned_domains=owned_domains,
                new_finding_ids=new_finding_ids,
                touched_asset_ids=touched_asset_ids,
                touched_finding_ids=touched_finding_ids,
            )
        except Exception as exc:
            log.exception("Chunk %d/%d failed for run %s", chunk_idx + 1, len(chunks), scan_run_id)
            # A DB-level failure (e.g. an IntegrityError from a writer) leaves
            # the session's transaction aborted — SQLAlchemy doesn't
            # auto-rollback on a failed flush/execute, so the very next
            # statement on this session (the partial_failures commit below)
            # would itself raise PendingRollbackError and abort the whole
            # run instead of just this chunk, defeating the fail-soft
            # contract this loop otherwise provides. Roll back first so the
            # session recovers cleanly regardless of what raised.
            db.rollback()
            _append_partial_failure(db, run, f"chunk {chunk_idx + 1}/{len(chunks)}: {exc}")

        if batch_delay and chunk_idx < len(chunks) - 1:
            time.sleep(batch_delay)

    # Risky-exposure analysis — turn dangerous open services (RDP, SMB, bare
    # databases, …) into findings. Runs once over the assets this run touched,
    # reading the merged canonical open_ports[]. Gated on run.started_at so only
    # ports observed this run count as open.
    try:
        from app.services.exposure_analyzer import analyze_exposures
        exposure_ids = analyze_exposures(
            db, scan_run_id, touched_asset_ids,
            since=run.started_at,
            new_canonical_ids_out=new_finding_ids,
        )
        touched_finding_ids.update(exposure_ids)
    except Exception:
        log.exception("Exposure analysis failed for scan %s — scan still marked complete", scan_run_id)

    # Dangling-DNS detection (planning#104/#105, epic#81 Phase B; widened by
    # planning#114, epic#81 Phase D follow-up L2) — promotes the
    # domain-affinity primitive + nuclei takeover fingerprint layer into
    # user-facing dangling_dns findings (High/Medium/Low gradient) over
    # dns_record assets in this run's authorized target scope (not just ones
    # touched this run — see target_scope.py), gated by a cadence/budget
    # mechanism for scope-only records (see dangling_dns_analyzer.py).
    try:
        from app.services.dangling_dns_analyzer import analyze_dangling_dns
        dangling_ids = analyze_dangling_dns(
            db, scan_run_id, scope, touched_asset_ids,
            since=run.started_at,
            new_canonical_ids_out=new_finding_ids,
        )
        touched_finding_ids.update(dangling_ids)
    except Exception:
        log.exception("Dangling-DNS analysis failed for scan %s — scan still marked complete", scan_run_id)

    # CPE normalization — turn each touched IP asset's banner/Shodan service
    # data into structured software intel (vendor/product/full-version/CPE 2.3)
    # written as software[] onto every open_ports[] entry. Feeds the native
    # version→CVE matcher (planning #66). Pure string work; runs before EOL so
    # the normalized version is available to it later.
    try:
        from app.services.cpe_normalizer import enrich_cpe
        enrich_cpe(db, touched_asset_ids)
    except Exception:
        log.exception("CPE normalization failed for scan %s — scan still marked complete", scan_run_id)

    # EOL enrichment — check service versions against endoflife.date for each
    # IP asset touched by this run; writes eol_services metadata + eol: tags.
    try:
        from app.services.eol_enrichment import enrich_eol
        enrich_eol(db, touched_asset_ids)
    except Exception:
        log.exception("EOL enrichment failed for scan %s — scan still marked complete", scan_run_id)

    # Mid-pipeline projection pass (planning#144 L3c-3). enrich_cpe and
    # enrich_eol now publish their results as claims (port_observation
    # carrying software[], and eol_status) instead of mutating
    # asset_metadata in place, so those results are NOT visible to a reader
    # of asset_state until they have been projected. match_versions below
    # reads open_ports[].software[] from asset_state, so without this pass it
    # would match against the PREVIOUS run's software and silently miss every
    # newly-detected version. Cheap (one batched fold over touched ids) and
    # idempotent — the final pass further down still runs.
    try:
        projector.project(db, touched_asset_ids, datetime.now(timezone.utc))
    except Exception:
        log.exception("Post-enrichment projection failed for scan %s — scan still marked complete", scan_run_id)

    # Native version→CVE matching — match each touched asset's installed software
    # (open_ports[].software[] from CPE normalization) against the local CPE→CVE
    # range index (#66). Emits source="version_match" CVE findings that the CVE
    # enrichment + risk scoring below then process like any other CVE finding.
    # Runs after enrich_cpe (software[] must exist, and must have been
    # projected — see the pass immediately above) / before cve_enrichment.
    try:
        from app.services.version_matcher import match_versions
        version_ids = match_versions(
            db, scan_run_id, touched_asset_ids,
            since=run.started_at,
            new_canonical_ids_out=new_finding_ids,
        )
        touched_finding_ids.update(version_ids)
    except Exception:
        log.exception("Version matching failed for scan %s — scan still marked complete", scan_run_id)

    # Shared-infra ownership verification (planning#77 MVP / planning#103,
    # epic#81 Phase A; widened by planning#113, epic#81 Phase D follow-up
    # L1) — classifies every ip_address asset in this run's authorized
    # target scope (not just ones touched this run — see target_scope.py),
    # then stamps the verdict onto every eligible finding on that IP (any
    # source/finding_type, not just Shodan — see shared_infra_verifier.py).
    # Runs after match_versions so same-run version_match findings get
    # stamped too, not a full run late (planning#113 Fable review caught
    # this ordering gap against the pre-#113 position, which ran before
    # match_versions). Doesn't change touched_finding_ids (verification is
    # metadata on an existing finding, not a new one) or score_ids
    # (risk_score is still computed for auditability — the verdict only
    # affects default dashboard/list read-time filtering).
    try:
        from app.services.shared_infra_verifier import verify_findings
        verify_findings(db, scope, touched_asset_ids, force=force_reverify)
    except Exception:
        log.exception("Shared-infra verification failed for scan %s — scan still marked complete", scan_run_id)

    # Final projection pass (planning#143 L2 sub-slice C) — re-project this
    # run's touched assets now that enrichment/verification has run, so
    # `asset_state.estate`/`attributes.probe_class` (sourced from the
    # affinity_confirmation/hosting_class claims, planning#144 L3a) reflect
    # this run's data too, not just what write_assets projected mid-scan from
    # port claims alone. Placed here because verify_findings (via
    # shared_infra_verifier -> hosting_classifier.classify_ip) is the last
    # step in this run that writes any claim the projector reads — nothing
    # after this point (CVE/VulnCheck/SSVC/vulnx enrichment, risk scoring)
    # writes asset claims at all, they only touch findings_canonical. A
    # projection failure must not fail the scan.
    try:
        projector.project(db, touched_asset_ids, datetime.now(timezone.utc))
    except Exception:
        log.exception("Final projection failed for scan %s — scan still marked complete", scan_run_id)

    # Post-scan CVE enrichment — runs once across all canonical findings
    # touched by this run. EPSS (FIRST.org), CISA KEV, NVD CVSS (capped fallback).
    # Each enrichment step mirrors CVE-level signals onto every canonical row
    # sharing the CVE (not just touched_finding_ids) — score_ids tracks that
    # wider set so risk scoring below recomputes those rows too, otherwise a
    # finding on an asset outside this run keeps a stale risk_score/building_velocity
    # even though its EPSS/KEV/exploit signals were just updated.
    score_ids: set[uuid.UUID] = set(touched_finding_ids)

    try:
        from app.services.cve_enrichment import enrich_scan_findings
        score_ids |= enrich_scan_findings(db, scan_run_id, canonical_ids=touched_finding_ids)
    except Exception:
        log.exception("CVE enrichment failed for scan %s — scan still marked complete", scan_run_id)

    # VulnCheck enrichment — primary CVE intelligence (NVD2 CVSS gap-fill +
    # KEV/XDB/ransomware/canary signals). Fail-soft without VULNCHECK_API_KEY.
    try:
        from app.services.vulncheck_enrichment import enrich_scan_findings as enrich_vulncheck
        score_ids |= enrich_vulncheck(db, scan_run_id, canonical_ids=touched_finding_ids)
    except Exception:
        log.exception("VulnCheck enrichment failed for scan %s — scan still marked complete", scan_run_id)

    # SSVC enrichment — CISA Vulnrichment decision points (Automatable / Technical
    # Impact / Exploitation) from the CVE.org CISA-ADP block; also merges
    # exploit-tagged refs into cve_intel. Free/keyless; runs after VulnCheck so
    # cve_intel.references exists to merge into. Fail-soft.
    try:
        from app.services.ssvc_enrichment import enrich_scan_findings as enrich_ssvc
        score_ids |= enrich_ssvc(db, scan_run_id, canonical_ids=touched_finding_ids)
    except Exception:
        log.exception("SSVC enrichment failed for scan %s — scan still marked complete", scan_run_id)

    # vulnx / PDCP enrichment — secondary (is_template / is_poc) for candidate CVEs only.
    try:
        from app.services.vulnx_enrichment import enrich_scan_findings as enrich_vulnx
        score_ids |= enrich_vulnx(db, scan_run_id, canonical_ids=touched_finding_ids)
    except Exception:
        log.exception("vulnx enrichment failed for scan %s — scan still marked complete", scan_run_id)

    # Constellus Risk Score — pure computation over the signals above; writes
    # risk_score / risk_band / building_velocity. Runs last in the chain, over
    # both the rows touched by this run and any rows that got mirrored signals.
    try:
        from app.services.risk_scorer import score_scan_findings
        score_scan_findings(db, scan_run_id, canonical_ids=score_ids)
    except Exception:
        log.exception("Risk scoring failed for scan %s — scan still marked complete", scan_run_id)

    # Populate counts so the Activity feed can show them without a join.
    # finding_count is the LOGICAL count — per-source rows that share an
    # (asset, cve_id) collapse to one, matching the read-time rollup the
    # findings/asset views use — so the scan summary doesn't double-count a CVE
    # found by both shodan and version_match.
    run.asset_count = len(touched_asset_ids)
    run.finding_count = _logical_finding_count(db, touched_finding_ids)
    db.commit()

    _set_status(
        db, run, ScanStatus.COMPLETED,
        completed_at=datetime.now(timezone.utc),
        connectors_used=list(dict.fromkeys(connectors_used)),
    )

    # Fire notifications for any genuinely-new findings. Runs inline (not as
    # a BackgroundTask) because we already have a worker thread and the
    # dispatcher opens its own session — keeping this off the request path
    # is irrelevant here.
    if new_finding_ids:
        try:
            from app.services import notification_dispatcher
            notification_dispatcher.dispatch(new_finding_ids)
        except Exception:
            log.exception("notification_dispatcher.dispatch failed for run %s", scan_run_id)


def _resolve_dynamic_scope(db: Session, template: ScanTemplate) -> dict:
    """Build scope from the targets table, respecting tag-based cadence tiers.

    The set of enabled "tier templates" (scan_templates with tag_priority not
    null) partitions the target inventory: each target is owned by the
    lowest-priority tier whose tag it carries, or by the default template if
    no tier matches.

    The resolver decides which targets belong to *this* template:
      - tier template (tag_priority is not null):
            include targets where this template is the winning tier
      - default template (tag_priority is null):
            include targets not claimed by any tier

    Each target's value is re-validated as a safety net for any legacy junk
    rows that slipped in before input validation tightened — a malformed
    value would otherwise be passed to Phase 1 and trigger upstream errors.
    """
    from app.models.target import Target
    from app.services.target_service import detect_type

    tier_templates = (
        db.query(ScanTemplate)
        .filter(ScanTemplate.tag_priority.isnot(None))
        .filter(ScanTemplate.enabled == True)  # noqa: E712
        .filter(ScanTemplate.dynamic_scope == True)  # noqa: E712
        .order_by(ScanTemplate.tag_priority)
        .all()
    )

    def winning_tier_id(target_tags: list[str]) -> uuid.UUID | None:
        tag_set = set(target_tags or [])
        for tier in tier_templates:
            tier_tag = (tier.target_tag_filter or [None])[0]
            if tier_tag and tier_tag in tag_set:
                return tier.id
        return None

    is_tier = template.tag_priority is not None
    targets = db.query(Target).all()

    domains: list[str] = []
    ip_ranges: list[str] = []
    for t in targets:
        owner_id = winning_tier_id(t.tags or [])
        if is_tier:
            if owner_id != template.id:
                continue
        else:
            if owner_id is not None:
                continue
        try:
            t_type = detect_type(t.value)
        except ValueError:
            log.warning("Skipping invalid target %s (id=%s) — not a valid domain/IP/CIDR", t.value, t.id)
            continue
        if t_type.value == "domain":
            domains.append(t.value)
        else:
            ip_ranges.append(t.value)
    return {"domains": domains, "ip_ranges": ip_ranges}


def _partition_scope_by_tier(
    db: Session,
    domains: list[str],
    ip_ranges: list[str],
    fallback_tier: str,
) -> dict[str, dict]:
    """Group scope values by effective aggressiveness tier.

    Looks up each value in the `targets` table and applies the per-target
    override if present. A value that isn't a target itself (a recheck on a
    child IP/subdomain) inherits the tier of the apex it rolls up to, but only
    when that apex is a configured target — so a child of a polite-configured
    domain re-scans at polite, while external CNAME destinations stay at
    `fallback_tier`. Anything still unresolved falls back to `fallback_tier`.

    Returns `{tier_name: {"domains": [...], "ip_ranges": [...]}}`. Empty
    sub-scopes are omitted. Tier order is preserved by insertion.
    """
    if not domains and not ip_ranges:
        return {}

    from app.models.target import Target

    all_values = list(domains) + list(ip_ranges)
    target_rows = (
        db.query(Target.value, Target.aggressiveness)
        .filter(Target.value.in_(all_values))
        .all()
    )
    tier_by_value: dict[str, str] = {}
    for value, agg in target_rows:
        if agg in aggressiveness.TIERS:
            tier_by_value[value] = agg

    # Values with no direct target row (a recheck on a child IP/subdomain) inherit
    # the tier of the target that DISCOVERED them. Records are parented under their
    # discovery apex, so we walk parent_value to the topmost ancestor and match it
    # (or its apex) to a configured target — even a cross-zone CNAME child (e.g. an
    # IP behind a SaaS the domain points to) traces back to the domain you targeted.
    # Same effect as that domain's tier being the default for its assets. Unresolved
    # values keep fallback_tier.
    unmatched = [v for v in all_values if v not in tier_by_value]
    if unmatched:
        from app.models.asset_canonical import AssetCanonical
        for value in unmatched:
            cur, root, seen = value, value, {value}
            for _ in range(8):  # CNAME-chain depth cap
                row = (
                    db.query(AssetCanonical.parent_value)
                    .filter(AssetCanonical.value == cur)
                    .first()
                )
                parent = row[0] if row else None
                if not parent or parent in seen:
                    break
                seen.add(parent)
                root = cur = parent
            for candidate in (root, apex_domain(root)):
                if candidate in tier_by_value:
                    tier_by_value[value] = tier_by_value[candidate]
                    break
                trow = (
                    db.query(Target.aggressiveness)
                    .filter(Target.value == candidate)
                    .first()
                )
                if trow and trow[0] in aggressiveness.TIERS:
                    tier_by_value[value] = trow[0]
                    break

    out: dict[str, dict] = {}
    for d in domains:
        tier = tier_by_value.get(d, fallback_tier)
        bucket = out.setdefault(tier, {"domains": [], "ip_ranges": []})
        bucket["domains"].append(d)
    for v in ip_ranges:
        tier = tier_by_value.get(v, fallback_tier)
        bucket = out.setdefault(tier, {"domains": [], "ip_ranges": []})
        bucket["ip_ranges"].append(v)
    return out


def _chunk_scope(domains: list[str], ip_ranges: list[str], batch_size: int | None):
    """Yield {domains, ip_ranges} dicts where each chunk has at most `batch_size`
    total entries. `batch_size=None` (or 0) yields a single chunk containing
    everything.
    """
    if not batch_size or batch_size <= 0:
        if domains or ip_ranges:
            yield {"domains": list(domains), "ip_ranges": list(ip_ranges)}
        return

    items: list[tuple[str, str]] = [("d", d) for d in domains] + [("i", v) for v in ip_ranges]
    for i in range(0, len(items), batch_size):
        chunk = items[i:i + batch_size]
        yield {
            "domains": [v for t, v in chunk if t == "d"],
            "ip_ranges": [v for t, v in chunk if t == "i"],
        }


def _run_pipeline(
    db: Session,
    scan_run_id: uuid.UUID,
    chunk_scope: dict,
    options: dict,
    auth_mode: str,
    tier: str,
    skip_discovery: bool,
    registry: dict,
    connectors_used: list[str],
    owned_domains: frozenset[str],
    new_finding_ids: list[uuid.UUID] | None = None,
    touched_asset_ids: set[uuid.UUID] | None = None,
    touched_finding_ids: set[uuid.UUID] | None = None,
) -> None:
    """Run Phase 1/2/3 against one chunk's scope."""
    domains: list[str] = chunk_scope.get("domains", [])
    ip_ranges: list[str] = chunk_scope.get("ip_ranges", [])
    all_assets: list[DiscoveredAsset] = []

    # ── Phase 1: Discovery ────────────────────────────────────────────────────
    # Skipped for per-asset rechecks (asset/finding scan-now buttons). Phase 1
    # uses CT logs / subfinder / DNS connectors that enumerate the whole apex
    # and would re-surface every sibling under the same parent — not what the
    # user wants when clicking "scan" on a single row. When skipped, all_assets
    # is seeded from scope so Phase 2/3 still have something to operate on.
    if skip_discovery:
        for domain in domains:
            all_assets.append(DiscoveredAsset(asset_type="dns_record", value=domain))
        for value in ip_ranges:
            all_assets.append(DiscoveredAsset(asset_type="ip_address", value=value))
        # Resolve domains to A/AAAA so Phase 1.5 (naabu, banner_grab) has
        # ip_address assets to probe. Without this, "Recheck" on a DNS
        # record skips port discovery entirely. Same passive resolution
        # path Phase 1 uses below for leaf FQDNs.
        if domains:
            try:
                from app.services.discovery.dns_resolve import resolve_names
                resolved = resolve_names(domains, source="dns_resolve", owned_domains=owned_domains)
                if resolved:
                    asset_ids = write_assets(db, scan_run_id, resolved)
                    if touched_asset_ids is not None:
                        touched_asset_ids.update(asset_ids)
                    all_assets.extend(resolved)
            except Exception:
                log.exception("dns_resolve failed in skip_discovery branch for %s", domains)
        log.debug(
            "Chunk skipped Phase 1 discovery — seeded %d asset(s) from chunk scope",
            len(all_assets),
        )

    from app.models.target import Target
    from app.services.connector_config import get_all as get_all_configs
    enabled_ids = {r.connector_id for r in get_all_configs(db) if r.enabled}

    for domain in (domains if not skip_discovery else []):
        phase_assets: list[DiscoveredAsset] = []
        target_row = db.query(Target).filter(Target.value == domain).first()
        target_ids = [target_row.id] if target_row else []

        # Certificate Transparency is a connector now (certspotter). It's
        # picked up by the index_lookup duck-typed loop below, alongside
        # Shodan's /dns/domain. CT calls are cache-only — actual API hits
        # happen in the background via app.services.ct_refresher.

        apex = apex_domain(domain)
        domain_authorised = is_scan_authorised(db, apex, auth_mode)

        if not domain_authorised:
            log.info(
                "Skipping active discovery tools for %s — apex domain %s not authorised (mode: %s)",
                domain, apex, auth_mode,
            )

        if options.get("subfinder", True) and domain_authorised:
            try:
                from app.services.discovery import subfinder
                if subfinder.available():
                    result = subfinder.run(domain, owned_domains=owned_domains)
                    phase_assets.extend(result.assets)
                    if result.assets:
                        connectors_used.append("subfinder")
            except Exception:
                log.exception("subfinder failed for %s", domain)

        # Resolve the target name itself to A/AAAA. subfinder + CT only
        # resolve their *outputs* (subdomains found), so a leaf-FQDN target
        # with no children would otherwise emit zero ip_address assets and
        # Phase 1.5 (naabu) + Phase 2 host-enrichment would have nothing to
        # work with. Passive — same rationale as dns_records below.
        try:
            from app.services.discovery.dns_resolve import resolve_names
            self_resolved = resolve_names([domain], source="dns_resolve", apex=apex, owned_domains=owned_domains)
            if self_resolved:
                phase_assets.extend(self_resolved)
                connectors_used.append("dns_resolve")
        except Exception:
            log.exception("dns_resolve failed for %s", domain)

        # Direct MX / NS / SPF lookups against the apex. Passive from the
        # target's perspective (queries against public recursors), so no
        # scan-auth gate — same rationale as dns_resolve.
        if options.get("dns_records", True):
            try:
                from app.services.discovery import dns_records
                result = dns_records.run(domain)
                phase_assets.extend(result.assets)
                if result.assets:
                    connectors_used.append("dns_records")
            except Exception:
                log.exception("dns_records failed for %s", domain)

        # dnsrecon: per-run options can force-enable; otherwise the tier decides.
        dnsrecon_tier = aggressiveness.dnsrecon_profile(tier)
        if options.get("dnsrecon", dnsrecon_tier["enabled"]) and domain_authorised:
            try:
                from app.services.discovery import dnsrecon
                if dnsrecon.available():
                    result = dnsrecon.run(domain)
                    phase_assets.extend(result.assets)
                    if result.assets:
                        connectors_used.append("dnsrecon")
            except Exception:
                log.exception("dnsrecon failed for %s", domain)

        # bruteforce: tier sets default enablement + wordlist; per-run options
        # override both independently.
        brute_tier = aggressiveness.bruteforce_profile(tier)
        if options.get("bruteforce", brute_tier["enabled"]) and domain_authorised:
            try:
                from app.services.discovery import bruteforce
                wordlist = options.get("bruteforce_wordlist", brute_tier["wordlist"])
                result = bruteforce.run(domain, wordlist)
                phase_assets.extend(result.assets)
                if result.assets:
                    connectors_used.append("bruteforce")
            except Exception:
                log.exception("bruteforce failed for %s", domain)

        # Connector-based discovery (Cloudflare, Route53, etc.)
        for cid, connector in registry.items():
            if cid not in enabled_ids or not isinstance(connector, DNSDiscoveryConnector):
                continue
            try:
                config = _get_connector_config(db, cid)
                result = connector.discover(domain, config)
                phase_assets.extend(result.assets)
                if result.findings:
                    finding_ids = write_findings(db, scan_run_id, result.findings, new_canonical_ids_out=new_finding_ids)
                    if touched_finding_ids is not None:
                        touched_finding_ids.update(finding_ids)
                if result.assets:
                    connectors_used.append(cid)
            except Exception:
                log.exception("Discovery connector %s failed on domain %s", cid, domain)

        # Index-based passive discovery — enrichment connectors that expose an
        # `index_lookup(domain, config)` method (currently Shodan /dns/domain).
        for cid, connector in registry.items():
            if cid not in enabled_ids or isinstance(connector, DNSDiscoveryConnector):
                continue
            index_lookup = getattr(connector, "index_lookup", None)
            if index_lookup is None:
                continue
            try:
                config = _get_connector_config(db, cid)
                config = {**config, "_owned_domains": owned_domains}
                result = index_lookup(domain, config)
                phase_assets.extend(result.assets)
                if result.assets:
                    connectors_used.append(cid)
            except Exception:
                log.exception("Index lookup via %s failed on domain %s", cid, domain)

        phase_assets = _dedupe_assets(phase_assets)
        if phase_assets:
            asset_ids = write_assets(db, scan_run_id, phase_assets, target_ids=target_ids)
            if touched_asset_ids is not None:
                touched_asset_ids.update(asset_ids)
            all_assets.extend(phase_assets)

    # ── Phase 1.5: Port discovery ─────────────────────────────────────────────
    # Active port scanning (currently Naabu) is its own pre-enrichment pass so
    # that downstream Phase 2/3 tools (and the asset detail UI) have an open-
    # ports list to reason about. Connectors opt in by exposing a
    # `port_scan(assets, config)` method — same duck-typing pattern as Phase
    # 1's `index_lookup`. The connector still inherits from ScanningConnector
    # for taxonomy purposes, and its `scan()` is a no-op so Phase 3 stays
    # cheap to call.
    if all_assets:
        # Copy persisted passive port hints (Shodan host ports from a prior
        # enrichment) onto the in-batch IP assets so naabu can fold them into
        # the nmap-verify candidate set. In-batch assets are rebuilt fresh each
        # run and don't carry persisted metadata, so without this the ports
        # Shodan already found would never reach our own verification/banners.
        _hydrate_port_hints(db, all_assets)
        # Sort by port_scan_order so producers (e.g. naabu) run before
        # consumers (e.g. banner_grab) — the consumer needs the producer's
        # open_ports[] patches in `all_assets` to know what to probe.
        # Default 100 keeps existing connectors in registry-insertion order
        # relative to each other.
        port_scan_connectors = sorted(
            ((cid, c) for cid, c in registry.items() if hasattr(c, "port_scan")),
            key=lambda pair: getattr(pair[1], "port_scan_order", 100),
        )
        for cid, connector in port_scan_connectors:
            if cid not in enabled_ids:
                continue
            port_scan = getattr(connector, "port_scan", None)
            if port_scan is None:
                continue
            try:
                config = _get_connector_config(db, cid)
                config = {**config, "_aggressiveness": aggressiveness.profile(tier), "_tier": tier}
                result = port_scan(all_assets, config)
                if result.assets:
                    asset_ids = write_assets(db, scan_run_id, result.assets)
                    if touched_asset_ids is not None:
                        touched_asset_ids.update(asset_ids)
                    all_assets.extend(result.assets)
                    connectors_used.append(cid)
                if result.findings:
                    finding_ids = write_findings(db, scan_run_id, result.findings, new_canonical_ids_out=new_finding_ids)
                    if touched_finding_ids is not None:
                        touched_finding_ids.update(finding_ids)
            except Exception:
                log.exception("Port-scan connector %s failed", cid)

    # ── Phase 2: Enrichment ───────────────────────────────────────────────────
    if all_assets:
        for cid, connector in registry.items():
            if cid not in enabled_ids or not isinstance(connector, EnrichmentConnector):
                continue
            try:
                config = _get_connector_config(db, cid)
                result = connector.enrich(all_assets, config)
                if result.assets:
                    asset_ids = write_assets(db, scan_run_id, result.assets)
                    if touched_asset_ids is not None:
                        touched_asset_ids.update(asset_ids)
                    all_assets.extend(result.assets)
                if result.findings:
                    finding_ids = write_findings(db, scan_run_id, result.findings, new_canonical_ids_out=new_finding_ids)
                    if touched_finding_ids is not None:
                        touched_finding_ids.update(finding_ids)
                if result.assets or result.findings:
                    connectors_used.append(cid)
            except Exception:
                log.exception("Enrichment connector %s failed", cid)

    # ── Phase 3: Scanning ─────────────────────────────────────────────────────
    targets = _extract_scan_targets(all_assets)
    authorised_targets = [t for t in targets if is_scan_authorised(db, apex_domain(t), auth_mode)]
    skipped = len(targets) - len(authorised_targets)
    if skipped:
        log.info("Skipping %d scan targets — apex domain not authorised (mode: %s)", skipped, auth_mode)

    if authorised_targets:
        # Scan-wide tag union for nuclei's -tags filter — computed once from
        # all_assets (not per-connector, not per-host). See
        # nuclei_tag_filter.compute_tag_union for the mapping rules.
        nuclei_tags = nuclei_tag_filter.compute_tag_union(all_assets)

        for cid, connector in registry.items():
            if cid not in enabled_ids or not isinstance(connector, ScanningConnector):
                continue
            try:
                config = _get_connector_config(db, cid)
                # Inject the resolved tier profile so the connector picks up
                # rate_limit / concurrency / exclude_tags without having to
                # know about app_settings. Reserved key — connectors must
                # treat it as read-only.
                config = {**config, "_aggressiveness": aggressiveness.profile(tier)}
                # Scan-wide detected-tech tag union for nuclei's -tags
                # filter. Reserved key — only NucleiConnector consumes it;
                # other ScanningConnectors ignore unknown config keys.
                config["_nuclei_include_tags"] = nuclei_tags
                result = connector.scan(authorised_targets, config)
                if result.findings:
                    finding_ids = write_findings(db, scan_run_id, result.findings, new_canonical_ids_out=new_finding_ids)
                    if touched_finding_ids is not None:
                        touched_finding_ids.update(finding_ids)
                    connectors_used.append(cid)
            except Exception:
                log.exception("Scanning connector %s failed", cid)


def _logical_finding_count(db: Session, finding_ids: set) -> int:
    """Distinct LOGICAL findings among the given canonical rows: per-source rows
    that share an (asset, cve_id) collapse to one (the read-time rollup the
    findings/asset views apply); non-CVE rows count individually. Keeps the scan
    summary consistent with the deduped counts the user sees, instead of inflating
    when a CVE is found by both shodan and version_match."""
    if not finding_ids:
        return 0
    from app.models.finding_canonical import FindingCanonical

    rows = (
        db.query(FindingCanonical.asset_canonical_id, FindingCanonical.cve_id)
        .filter(FindingCanonical.id.in_(list(finding_ids)))
        .all()
    )
    cve_keys: set = set()
    non_cve = 0
    for asset_id, cve_id in rows:
        if cve_id:
            cve_keys.add((asset_id, cve_id))
        else:
            non_cve += 1
    return len(cve_keys) + non_cve


def _dedupe_assets(assets: list[DiscoveredAsset]) -> list[DiscoveredAsset]:
    """Deduplicate; union sources and fold bare CT rows into resolved ones.

    Discovery layers produce overlapping rows:
      - CT logs / passive enumerators emit bare dns_records (no record_type
        / content) carrying cert issuer + validity metadata.
      - dns_resolve / Shodan index emit fully resolved rows with
        record_type + content.

    Dedup keys match the canonical-write keys (see asset_writer._canonical_key):
      - dns_record: (type, value, record_type, content) so A + AAAA + MX
        each survive as distinct rows.
      - everything else: (type, value).

    Bare dns_records (no record_type) are held aside, then their metadata
    is merged into every resolved row for the same FQDN. If no resolved row
    exists for that FQDN the bare row is kept as-is so the asset is still
    written.
    """
    seen: dict[tuple, DiscoveredAsset] = {}
    bare_dns: dict[str, DiscoveredAsset] = {}

    for a in assets:
        if "sources" not in a.asset_metadata:
            src = a.asset_metadata.pop("source", "unknown")
            a.asset_metadata["sources"] = [src] if src else []

        if a.asset_type == "dns_record":
            rtype = a.asset_metadata.get("record_type")
            if not rtype:
                existing = bare_dns.get(a.value)
                if existing:
                    _merge_metadata_into(existing.asset_metadata, a.asset_metadata)
                else:
                    bare_dns[a.value] = a
                continue
            key = ("dns_record", a.value, rtype, a.asset_metadata.get("content"))
        else:
            key = (a.asset_type, a.value)

        if key not in seen:
            seen[key] = a
        else:
            _merge_metadata_into(seen[key].asset_metadata, a.asset_metadata)

    for fqdn, bare in bare_dns.items():
        resolved = [v for k, v in seen.items() if k[0] == "dns_record" and k[1] == fqdn]
        if resolved:
            for r in resolved:
                _merge_metadata_into(r.asset_metadata, bare.asset_metadata)
        else:
            seen[("dns_record", fqdn, None, None)] = bare

    return list(seen.values())


def _merge_metadata_into(target: dict, src: dict) -> None:
    """Union the sources list and fill any empty target fields with src's non-empty values."""
    target["sources"] = list(dict.fromkeys(
        target.get("sources", []) + src.get("sources", [])
    ))
    for k, v in src.items():
        if k == "sources":
            continue
        if v in (None, "", [], {}):
            continue
        if k not in target or target[k] in (None, "", [], {}):
            target[k] = v


def _extract_scan_targets(assets: list[DiscoveredAsset]) -> list[str]:
    seen: set[str] = set()
    targets: list[str] = []
    for a in assets:
        if a.asset_type in ("dns_record", "ip_address") and a.value not in seen:
            seen.add(a.value)
            targets.append(a.value)
    return targets


def _hydrate_asset_ports(asset, persisted_meta: dict) -> None:
    """Mutate in-batch *asset* in place using persisted canonical metadata.

    Three things are hydrated:

    1. shodan_ports (list[int]) — merged into asset_metadata["shodan_ports"]
       (union, sorted).  naabu reads this list and folds the ports into its
       nmap-verify candidate set, so Shodan-seen ports get independently
       confirmed rather than trusted on Shodan's word.

    2. open_ports[] entries sourced from Shodan — merged onto the in-batch
       asset's open_ports[] via _merge_open_ports.  The Phase-1.5 active
       probers (banner_grab, httpx, tlsx) each read asset_metadata["open_ports"]
       to decide which ports to attempt, so this lets them attempt a
       Shodan-discovered port.  If a prober confirms the port it emits a
       fresh entry (last_seen_at=now, its own source) that merge-wins.  If
       nothing confirms, the hydration is transient — it never reaches
       asset_writer — so the canonical Shodan entry keeps its honest old
       timestamp.

    3. prior_ports (list[int]) — ports whose canonical open_ports[] entry is
       l7_confirmed (a real app-layer service was observed previously).  naabu
       folds these into its nmap-verify candidate set so a known-real port is
       re-confirmed every run even when its (tarpit-flaky) SYN discovery misses
       it; if nmap can't confirm it this run it's simply dropped.

    Pure function (no DB): testable with any object that has .asset_metadata.
    """
    from app.services.projector import _merge_open_ports

    meta = dict(asset.asset_metadata or {})

    # 1. shodan_ports hint — feed naabu candidate set
    raw_ports = persisted_meta.get("shodan_ports")
    if isinstance(raw_ports, list):
        clean = [p for p in raw_ports if isinstance(p, int) and 1 <= p <= 65535]
        if clean:
            existing_ints = {
                p for p in (meta.get("shodan_ports") or []) if isinstance(p, int)
            }
            meta["shodan_ports"] = sorted(existing_ints | set(clean))

    # 2. Shodan-sourced open_ports — feed active probers
    persisted_ports = persisted_meta.get("open_ports")
    if isinstance(persisted_ports, list):
        shodan_entries = [
            e for e in persisted_ports
            if isinstance(e, dict) and "shodan" in (e.get("sources") or [])
        ]
        if shodan_entries:
            existing_open = meta.get("open_ports") or []
            if not isinstance(existing_open, list):
                existing_open = []
            meta["open_ports"] = _merge_open_ports(existing_open, shodan_entries)

    # 3. Prior app-confirmed ports — re-verify known-real ports every run so a
    #    flaky service or a tarpit discovery miss can't silently drop a real port
    #    (naabu's discovery is unreliable behind scan-deception firewalls). Only
    #    l7_confirmed entries (an app-layer service was actually observed by a
    #    prober/nmap), never bare naabu/Shodan/phantom rows. naabu reads
    #    prior_ports and folds them into its nmap-verify candidate set.
    if isinstance(persisted_ports, list):
        prior = [
            e["port"] for e in persisted_ports
            if isinstance(e, dict) and isinstance(e.get("port"), int)
            and 1 <= e["port"] <= 65535 and e.get("l7_confirmed") is True
        ]
        if prior:
            existing_prior = {p for p in (meta.get("prior_ports") or []) if isinstance(p, int)}
            meta["prior_ports"] = sorted(existing_prior | set(prior))

    asset.asset_metadata = meta


def _hydrate_port_hints(db: Session, assets: list) -> None:
    """Copy persisted passive port hints onto in-batch IP assets.

    Two sources are hydrated from the persisted projection onto each in-batch IP:

    * shodan_ports (list[int]) — naabu reads this and folds the ports into its
      nmap-verify candidate set so a Shodan-seen port gets independently
      confirmed by our own stack rather than trusted on Shodan's word.

    * open_ports[] with sources=["shodan"] — the Phase-1.5 active probers
      (banner_grab at port_scan_order 200, httpx at 300, tlsx at 310) probe
      every port present in the in-batch asset's open_ports[].  Hydrating the
      persisted Shodan entries here gives those probers a chance to attempt
      cross-run verification.  If a prober confirms, it emits a fresh entry
      that merge-wins; if nothing confirms, the hydration is transient and
      never re-persisted, so the canonical Shodan entry keeps its original
      honest timestamp.

    No-op when there are no public IPs or no stored hints.

    planning#144 L3c-3: both hints are sourced from the claims layer rather
    than `assets_canonical.metadata` — `open_ports` from the projected
    `asset_state` (which carries the per-entry `sources` and `l7_confirmed`
    this function keys off), `shodan_ports` from the shodan observer's own
    `port_observation` claim. `_hydrate_asset_ports` itself is unchanged and
    still takes a plain metadata-shaped dict.
    """
    # AssetType is a str-Enum, so == "ip_address" matches both the enum members
    # (naabu/banner_grab patches) and bare strings (executor-built assets).
    ip_values = {
        a.value for a in assets
        if getattr(a, "asset_type", None) == "ip_address"
    }
    if not ip_values:
        return

    by_ip = _persisted_port_hints(db, ip_values)
    if not by_ip:
        return

    for a in assets:
        if getattr(a, "asset_type", None) != "ip_address":
            continue
        persisted_meta = by_ip.get(a.value)
        if not persisted_meta:
            continue
        _hydrate_asset_ports(a, persisted_meta)


def _persisted_port_hints(db: Session, ip_values: set[str]) -> dict[str, dict]:
    """{ip_value: metadata-shaped dict} carrying the two persisted port hints
    `_hydrate_asset_ports` consumes — `open_ports` and `shodan_ports`
    (planning#144 L3c-3, replacing a read of `assets_canonical.metadata`).

    Three batched queries regardless of how many IPs are passed: the
    canonical id/value pairs, their projected `asset_state` rows, and the
    shodan-observer `port_observation` claims behind `shodan_ports`. An IP
    with neither hint is omitted, so the caller's existing "no stored hints"
    skip behaves exactly as before.
    """
    from app.models.asset_canonical import AssetCanonical
    from app.models.claim import AssetClaim
    from app.models.observer import Observer
    from app.services import claim_emitter, projector

    id_to_value: dict[uuid.UUID, str] = {
        row.id: row.value
        for row in (
            db.query(AssetCanonical.id, AssetCanonical.value)
            .filter(
                AssetCanonical.asset_type == "ip_address",
                AssetCanonical.value.in_(list(ip_values)),
            )
            .all()
        )
    }
    if not id_to_value:
        return {}

    by_ip: dict[str, dict] = {}
    for asset_id, open_ports in projector.open_ports_by_asset(db, id_to_value).items():
        if open_ports:
            by_ip.setdefault(id_to_value[asset_id], {})["open_ports"] = open_ports

    # shodan_ports: bare port numbers off the shodan observer's own port
    # claim — deliberately that observer's claim rather than the merged
    # asset_state view, matching what the serializer bridge reconstructs.
    shodan_claims = (
        db.query(AssetClaim.asset_canonical_id, AssetClaim.claim_value)
        .join(Observer, AssetClaim.observer_id == Observer.id)
        .filter(
            AssetClaim.asset_canonical_id.in_(list(id_to_value)),
            AssetClaim.claim_type == claim_emitter._PORT_OBSERVATION_CLAIM_TYPE,
            Observer.name == "shodan",
        )
        .all()
    )
    for asset_id, claim_value in shodan_claims:
        ports = (claim_value or {}).get("ports") or []
        port_numbers = [p["port"] for p in ports if isinstance(p, dict) and isinstance(p.get("port"), int)]
        if port_numbers:
            by_ip.setdefault(id_to_value[asset_id], {})["shodan_ports"] = sorted(set(port_numbers))

    return by_ip


def _get_connector_config(db: Session, connector_id: str) -> dict:
    from app.services.connector_config import get_decrypted_config
    return get_decrypted_config(db, connector_id) or {}


def _append_partial_failure(db: Session, run: ScanRun, message: str) -> None:
    """Append a chunk-failure message to the run. SQLAlchemy can't detect
    mutation of a JSONB list in place, so we reassign the column.
    """
    existing = list(run.partial_failures or [])
    existing.append(message)
    run.partial_failures = existing
    db.commit()


def _set_status(
    db: Session,
    run: ScanRun,
    status: ScanStatus,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    connectors_used: list[str] | None = None,
) -> None:
    run.status = status
    if started_at:
        run.started_at = started_at
    if completed_at:
        run.completed_at = completed_at
    if connectors_used is not None:
        run.connectors_used = connectors_used
    db.commit()


def _fail(db: Session, scan_run_id: uuid.UUID, error: str) -> None:
    run = db.get(ScanRun, scan_run_id)
    if run:
        run.status = ScanStatus.FAILED
        run.error = error
        run.completed_at = datetime.now(timezone.utc)
        db.commit()
