"""
Post-scan vulnx / PDCP enrichment — secondary CVE intelligence (Nuclei template
presence + public PoC) for the Constellus Risk Score.

Runs after vulncheck_enrichment. Scoped narrowly: only CVEs already flagged as
*candidates* by VulnCheck/EPSS signals are looked up, because vulnx is
rate-limited (and is_template alone never surfaces a finding — it only
contributes once a finding is otherwise interesting). This keeps request volume
low and respects the unauthenticated rate limit.

API: ProjectDiscovery Cloud (PDCP). GET /v2/vulnerability/{cve_id} → {data: {...}}.
Auth header X-PDCP-Key is optional — works unauthenticated (rate-limited); a free
PDCP key (stored as PDCP_API_KEY) raises the limit. NOT the same key as VulnCheck.

Fields consumed: is_template (a Nuclei template exists ⇒ automated attack tooling)
and is_poc (a public PoC exists).
"""

import logging
import time
import uuid

from sqlalchemy.orm import Session

from app.connectors.http import connector_get
from app.core.secrets import get_secret
from app.models.finding_canonical import FindingCanonical

log = logging.getLogger(__name__)

_API_BASE = "https://api.projectdiscovery.io"

# Candidacy gate — only look up CVEs that already show exploitation interest.
# EPSS floor mirrors the "genuinely elevated" band used elsewhere in the UI.
_CANDIDATE_EPSS_FLOOR = 0.10

# Per-CVE cache: CVE_ID_UPPER → ({is_template, is_poc}, monotonic_ts). 24h TTL.
_cache: dict[str, tuple[dict, float]] = {}
_CACHE_TTL = 86_400


def enrich_scan_findings(
    db: Session,
    scan_run_id: uuid.UUID,
    canonical_ids: set[uuid.UUID] | None = None,
) -> set[uuid.UUID]:
    """Look up is_template / is_poc for candidate CVE findings touched this run.

    A finding is a candidate if VulnCheck already flagged exploitation interest
    (has_exploit / ransomware_use) or EPSS is at least the elevated floor. Signals
    are mirrored across all canonical rows sharing each looked-up CVE.

    Returns the IDs of every canonical row whose signals were mirrored, so the
    caller can re-run risk scoring over the full set."""
    if not canonical_ids:
        return set()

    findings = (
        db.query(FindingCanonical)
        .filter(FindingCanonical.id.in_(canonical_ids))
        .filter(FindingCanonical.cve_id.isnot(None))
        .all()
    )
    if not findings:
        return set()

    candidate_cves = {
        f.cve_id.upper()
        for f in findings
        if f.cve_id and _is_candidate(f)
    }
    if not candidate_cves:
        log.info("vulnx enrichment: no candidate CVEs for scan %s", scan_run_id)
        return set()

    log.info("vulnx enrichment: %d candidate CVE IDs for scan %s", len(candidate_cves), scan_run_id)

    # Auth header is optional; include it only if a key is configured.
    headers = {"Accept": "application/json"}
    pdcp_key = get_secret("PDCP_API_KEY")
    if pdcp_key:
        headers["X-PDCP-Key"] = pdcp_key

    signals: dict[str, dict] = {}
    for cid in candidate_cves:
        sig = _lookup_cve(cid, headers)
        if sig:
            signals[cid] = sig

    if not signals:
        return set()

    canonical_rows = (
        db.query(FindingCanonical)
        .filter(FindingCanonical.cve_id.isnot(None))
        .filter(FindingCanonical.cve_id.in_(list(signals.keys())))
        .all()
    )
    for c in canonical_rows:
        sig = signals.get((c.cve_id or "").upper())
        if not sig:
            continue
        c.is_template = sig["is_template"]
        c.is_poc = sig["is_poc"]
        # Merge vulnx's additive fields into cve_intel (VulnCheck wrote it first;
        # we only add what it lacks). Reassign detail so SQLAlchemy flags JSONB dirty.
        intel_add: dict = {}
        if sig.get("remediation"):
            intel_add["remediation"] = sig["remediation"]
        if sig.get("impact"):
            intel_add["impact"] = sig["impact"]
        if sig.get("is_remote") is not None:
            intel_add["is_remote"] = sig["is_remote"]
        if sig.get("is_auth") is not None:
            intel_add["is_auth"] = sig["is_auth"]
        if intel_add:
            existing = (c.detail or {}).get("cve_intel") or {}
            c.detail = {**(c.detail or {}), "cve_intel": {**existing, **intel_add}}

    db.commit()
    log.info(
        "vulnx enrichment complete for scan %s — with-template: %d, with-poc: %d",
        scan_run_id,
        sum(1 for s in signals.values() if s["is_template"]),
        sum(1 for s in signals.values() if s["is_poc"]),
    )
    return {c.id for c in canonical_rows}


def _is_candidate(f: FindingCanonical) -> bool:
    return bool(
        f.has_exploit
        or f.ransomware_use
        or (f.epss_score is not None and f.epss_score >= _CANDIDATE_EPSS_FLOOR)
    )


def _lookup_cve(cve_id: str, headers: dict) -> dict | None:
    now = time.monotonic()
    cached = _cache.get(cve_id)
    if cached is not None and (now - cached[1]) < _CACHE_TTL:
        return cached[0]

    try:
        resp = connector_get(
            f"{_API_BASE}/v2/vulnerability/{cve_id}",
            headers=headers,
            timeout=20,
        )
        if resp.status_code == 404:
            sig = {"is_template": False, "is_poc": False}
            _cache[cve_id] = (sig, now)
            return sig
        if resp.status_code != 200:
            log.warning("vulnx %s → HTTP %d", cve_id, resp.status_code)
            return None
        data = resp.json().get("data") or {}
    except Exception:
        log.warning("vulnx fetch failed for %s", cve_id, exc_info=True)
        return None

    sig = {
        "is_template": bool(data.get("is_template")),
        "is_poc": bool(data.get("is_poc")),
        # Additive narrative/flags VulnCheck/NVD don't provide. remediation is
        # especially valuable for non-KEV CVEs (no CISA required_action to show).
        "remediation": (data.get("remediation") or "").strip() or None,
        "impact": (data.get("impact") or "").strip() or None,
        "is_remote": data.get("is_remote"),
        "is_auth": data.get("is_auth"),
    }
    _cache[cve_id] = (sig, now)
    return sig
