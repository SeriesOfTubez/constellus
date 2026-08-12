"""
Post-scan SSVC enrichment — CISA Vulnrichment decision points per CVE.

For CVE-bearing findings touched in a scan run, this service fetches the CVE.org
record and extracts the CISA-ADP ("Vulnrichment") SSVC block:
  * Exploitation     → none / poc / active   (source-agnostic exploit signal, max-wins)
  * Automatable      → yes / no (bool)        (Risk Score capability axis)
  * Technical Impact → total / partial        (Risk Score impact term)
plus the SSVC timestamp (provenance / staleness). It also merges CISA-ADP
references tagged "exploit" into the finding's existing reference list
(detail.cve_intel.references), deduped by URL.

Free, key-less feed (cveawg.mitre.org) — no VULNCHECK/NVD key needed. Coverage is
partial: CVEs CISA hasn't scored leave the columns NULL, where a derived
CVSS-vector fallback takes over (chunk c, risk_scorer). Fail-soft throughout —
a fetch failure for one CVE never aborts the run.

Runs after vulncheck_enrichment in scan_executor so cve_intel.references already
exists to merge into. Like the other enrichers, SSVC is a CVE-level fact, so
values are mirrored onto every canonical row sharing each touched CVE — not just
the rows seen this run — and the mirrored ids are returned so risk scoring
recomputes them.
"""

import logging
import time
import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from app.connectors.http import connector_get
from app.models.finding_canonical import FindingCanonical

log = logging.getLogger(__name__)

_CVE_URL = "https://cveawg.mitre.org/api/cve/{cve}"

# Per-CVE cache: CVE_ID_UPPER → (parsed_dict, monotonic_ts). 24h TTL.
# parsed_dict is {} when the CVE has no CISA-ADP SSVC (a valid "absent" answer,
# cached); a transient/hard fetch failure returns None and is NOT cached so the
# next scan retries.
_cache: dict[str, tuple[dict, float]] = {}
_CACHE_TTL = 86_400  # 24h

_AUTOMATABLE = {"yes": True, "no": False}
_EXPLOITATION = {"none", "poc", "active"}
_TECH_IMPACT = {"total", "partial"}


def enrich_scan_findings(
    db: Session,
    scan_run_id: uuid.UUID,
    canonical_ids: set[uuid.UUID] | None = None,
) -> set[uuid.UUID]:
    """Enrich CVE-bearing canonical findings touched by this run with CISA SSVC
    decision points, and merge CISA-ADP exploit references into cve_intel.

    Returns the IDs of every canonical row whose values were mirrored, so the
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

    cve_ids = list({f.cve_id.upper() for f in findings if f.cve_id})
    log.info("SSVC enrichment: %d unique CVE IDs for scan %s", len(cve_ids), scan_run_id)

    sigs: dict[str, dict] = {}
    for cid in cve_ids:
        sig = _lookup_ssvc(cid)
        if sig:  # non-empty: has an SSVC block and/or exploit refs
            sigs[cid] = sig

    if not sigs:
        log.info("SSVC enrichment: no Vulnrichment data for scan %s", scan_run_id)
        return set()

    # Mirror onto every canonical row sharing the touched CVE IDs.
    canonical_rows = (
        db.query(FindingCanonical)
        .filter(FindingCanonical.cve_id.isnot(None))
        .filter(FindingCanonical.cve_id.in_(list(sigs.keys())))
        .all()
    )
    for c in canonical_rows:
        sig = sigs.get((c.cve_id or "").upper())
        if not sig:
            continue
        if sig.get("has_ssvc"):
            c.ssvc_exploitation = sig["exploitation"]
            c.ssvc_automatable = sig["automatable"]
            c.ssvc_technical_impact = sig["technical_impact"]
            c.ssvc_source = "vulnrichment"
            c.ssvc_scored_at = sig["scored_at"]
        if sig.get("exploit_refs"):
            _merge_exploit_refs(c, sig["exploit_refs"])

    db.commit()
    log.info(
        "SSVC enrichment complete for scan %s — SSVC scored: %d, exploit-ref merges: %d",
        scan_run_id,
        sum(1 for s in sigs.values() if s.get("has_ssvc")),
        sum(1 for s in sigs.values() if s.get("exploit_refs")),
    )
    return {c.id for c in canonical_rows}


def _merge_exploit_refs(c: FindingCanonical, refs: list[dict]) -> None:
    """Append CISA-ADP exploit references into detail.cve_intel.references, deduped
    by URL. Reassigns detail (not in-place) so SQLAlchemy flags the JSONB dirty."""
    intel = dict((c.detail or {}).get("cve_intel") or {})
    existing = list(intel.get("references") or [])
    seen = {r.get("url") for r in existing}
    added = False
    for r in refs:
        if r["url"] not in seen:
            existing.append(r)
            seen.add(r["url"])
            added = True
    if added:
        intel["references"] = existing
        c.detail = {**(c.detail or {}), "cve_intel": intel}


# ── fetch + parse ──────────────────────────────────────────────────────────────

def _lookup_ssvc(cve_id: str) -> dict | None:
    """Parsed SSVC + exploit refs for one CVE, cached 24h. {} when the CVE has no
    CISA-ADP SSVC (cached). None on transient failure (not cached → retry)."""
    now = time.monotonic()
    cached = _cache.get(cve_id)
    if cached is not None and (now - cached[1]) < _CACHE_TTL:
        return cached[0]

    try:
        resp = connector_get(_CVE_URL.format(cve=cve_id), timeout=20)
        if resp.status_code == 404:
            _cache[cve_id] = ({}, now)  # unknown CVE — valid empty answer
            return {}
        if resp.status_code != 200:
            log.warning("SSVC %s → HTTP %d", cve_id, resp.status_code)
            return None
        data = resp.json()
    except Exception:
        log.warning("SSVC fetch failed for %s", cve_id, exc_info=True)
        return None

    parsed = _parse(data)
    _cache[cve_id] = (parsed, now)
    return parsed


def _parse(data: dict) -> dict:
    """Extract the SSVC block + exploit-tagged references from the CISA-ADP
    container. Returns {} when there's no CISA-ADP container / nothing usable."""
    result: dict = {}
    for adp in data.get("containers", {}).get("adp", []):
        if adp.get("providerMetadata", {}).get("shortName") != "CISA-ADP":
            continue
        # SSVC decision points
        for metric in adp.get("metrics", []):
            other = metric.get("other", {})
            if other.get("type") != "ssvc":
                continue
            content = other.get("content", {})
            opts = {k: v for opt in content.get("options", []) for k, v in opt.items()}
            exploitation = (opts.get("Exploitation") or "").lower() or None
            tech_impact = (opts.get("Technical Impact") or "").lower() or None
            result.update(
                has_ssvc=True,
                exploitation=exploitation if exploitation in _EXPLOITATION else None,
                automatable=_AUTOMATABLE.get((opts.get("Automatable") or "").lower()),
                technical_impact=tech_impact if tech_impact in _TECH_IMPACT else None,
                scored_at=_parse_ts(content.get("timestamp")),
            )
        # Exploit-tagged references (CISA-curated exploit pointers)
        refs = [
            {"url": r["url"], "tags": r.get("tags") or []}
            for r in adp.get("references", [])
            if r.get("url") and "exploit" in [t.lower() for t in (r.get("tags") or [])]
        ]
        if refs:
            result["exploit_refs"] = refs
    return result


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
