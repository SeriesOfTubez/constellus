"""
Scan executor — orchestrates connector phases for a scan run.

Phase order:
  1. DISCOVERY  — built-in tools (CT logs, subfinder, dnsrecon, brute-force)
                  then DNSDiscoveryConnectors (Cloudflare, Route53, etc.)
  2. ENRICHMENT — EnrichmentConnectors (Tenable, Wiz, FortiManager, etc.)
  3. SCANNING   — ScanningConnectors (Nuclei, etc.)
"""

import logging
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
from app.services.asset_writer import write_assets
from app.services.finding_writer import write_findings
from app.services.target_service import is_verified, apex_domain, ensure_connector_verified

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

    options: dict = run.options or {}
    domains: list[str] = scope.get("domains", [])
    connectors_used: list[str] = []
    all_assets: list[DiscoveredAsset] = []

    # ── Phase 1: Discovery ────────────────────────────────────────────────────
    for domain in domains:
        phase_assets: list[DiscoveredAsset] = []

        # Built-in: Certificate Transparency
        if options.get("cert_transparency", True):
            try:
                from app.services.discovery import cert_transparency
                result: PhaseResult = cert_transparency.run(domain)
                phase_assets.extend(result.assets)
                if result.assets:
                    connectors_used.append("cert_transparency")
            except Exception:
                log.exception("CT logs failed for %s", domain)

        # Active built-in tools require the apex domain to be verified
        apex = apex_domain(domain)
        domain_verified = is_verified(db, apex)

        if not domain_verified:
            log.info(
                "Skipping active discovery tools for %s — apex domain %s is not verified",
                domain, apex,
            )

        # Built-in: subfinder (active — requires verification)
        if options.get("subfinder", True) and domain_verified:
            try:
                from app.services.discovery import subfinder
                if subfinder.available():
                    result = subfinder.run(domain)
                    phase_assets.extend(result.assets)
                    if result.assets:
                        connectors_used.append("subfinder")
            except Exception:
                log.exception("subfinder failed for %s", domain)

        # Built-in: dnsrecon (active — requires verification, off by default)
        if options.get("dnsrecon", False) and domain_verified:
            try:
                from app.services.discovery import dnsrecon
                if dnsrecon.available():
                    result = dnsrecon.run(domain)
                    phase_assets.extend(result.assets)
                    if result.assets:
                        connectors_used.append("dnsrecon")
            except Exception:
                log.exception("dnsrecon failed for %s", domain)

        # Built-in: brute-force (active — requires verification, off by default)
        if options.get("bruteforce", False) and domain_verified:
            try:
                from app.services.discovery import bruteforce
                wordlist = options.get("bruteforce_wordlist", "small")
                result = bruteforce.run(domain, wordlist)
                phase_assets.extend(result.assets)
                if result.assets:
                    connectors_used.append("bruteforce")
            except Exception:
                log.exception("bruteforce failed for %s", domain)

        # Connector-based discovery (Cloudflare, Route53, etc.)
        from app.services.connector_config import get_all as get_all_configs
        enabled_ids = {r.connector_id for r in get_all_configs(db) if r.enabled}

        for cid, connector in registry.items():
            if cid not in enabled_ids or not isinstance(connector, DNSDiscoveryConnector):
                continue
            try:
                config = _get_connector_config(db, cid)
                result = connector.discover(domain, config)
                phase_assets.extend(result.assets)
                if result.findings:
                    write_findings(db, scan_run_id, result.findings)
                if result.assets:
                    connectors_used.append(cid)
            except Exception:
                log.exception("Discovery connector %s failed on domain %s", cid, domain)

        # Deduplicate assets by (type, value) before writing
        phase_assets = _dedupe_assets(phase_assets)
        if phase_assets:
            write_assets(db, scan_run_id, phase_assets)
            all_assets.extend(phase_assets)

    # ── Phase 2: Enrichment ───────────────────────────────────────────────────
    from app.services.connector_config import get_all as get_all_configs
    enabled_ids = {r.connector_id for r in get_all_configs(db) if r.enabled}

    if all_assets:
        for cid, connector in registry.items():
            if cid not in enabled_ids or not isinstance(connector, EnrichmentConnector):
                continue
            try:
                config = _get_connector_config(db, cid)
                result = connector.enrich(all_assets, config)
                if result.assets:
                    write_assets(db, scan_run_id, result.assets)
                    all_assets.extend(result.assets)
                    # Connector-sourced assets auto-verify their apex domains
                    for asset in result.assets:
                        ensure_connector_verified(db, apex_domain(asset.value), cid)
                if result.findings:
                    write_findings(db, scan_run_id, result.findings)
                if result.assets or result.findings:
                    connectors_used.append(cid)
            except Exception:
                log.exception("Enrichment connector %s failed", cid)

    # ── Phase 3: Scanning ─────────────────────────────────────────────────────
    # Only scan targets whose apex domain has been verified
    targets = _extract_scan_targets(all_assets)
    verified_targets = [t for t in targets if is_verified(db, apex_domain(t))]
    skipped = len(targets) - len(verified_targets)
    if skipped:
        log.info("Skipping %d scan targets — apex domain not verified", skipped)

    if verified_targets:
        for cid, connector in registry.items():
            if cid not in enabled_ids or not isinstance(connector, ScanningConnector):
                continue
            try:
                config = _get_connector_config(db, cid)
                result = connector.scan(verified_targets, config)
                if result.findings:
                    write_findings(db, scan_run_id, result.findings)
                    connectors_used.append(cid)
            except Exception:
                log.exception("Scanning connector %s failed", cid)

    # ── Post-scan CVE enrichment ──────────────────────────────────────────────
    try:
        from app.services.cve_enrichment import enrich_scan_findings
        enrich_scan_findings(db, scan_run_id)
    except Exception:
        log.exception("CVE enrichment failed for scan %s — scan still marked complete", scan_run_id)

    _set_status(
        db, run, ScanStatus.COMPLETED,
        completed_at=datetime.now(timezone.utc),
        connectors_used=list(dict.fromkeys(connectors_used)),
    )


def _dedupe_assets(assets: list[DiscoveredAsset]) -> list[DiscoveredAsset]:
    """Deduplicate by (type, value), merging sources from all contributors."""
    seen: dict[tuple, DiscoveredAsset] = {}
    for a in assets:
        # Normalise to sources[] array
        if "sources" not in a.asset_metadata:
            src = a.asset_metadata.pop("source", "unknown")
            a.asset_metadata["sources"] = [src] if src else []

        key = (a.asset_type, a.value)
        if key in seen:
            existing = seen[key]
            merged = list(dict.fromkeys(
                existing.asset_metadata.get("sources", []) +
                a.asset_metadata.get("sources", [])
            ))
            existing.asset_metadata["sources"] = merged
        else:
            seen[key] = a
    return list(seen.values())


def _extract_scan_targets(assets: list[DiscoveredAsset]) -> list[str]:
    seen: set[str] = set()
    targets: list[str] = []
    for a in assets:
        if a.asset_type in ("dns_record", "ip_address") and a.value not in seen:
            seen.add(a.value)
            targets.append(a.value)
    return targets


def _get_connector_config(db: Session, connector_id: str) -> dict:
    from app.services.connector_config import get_decrypted_config
    return get_decrypted_config(db, connector_id) or {}



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
