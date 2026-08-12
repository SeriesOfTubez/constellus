"""
Post-scan VulnCheck enrichment — primary CVE intelligence for the Constellus
Risk Score.

For CVE-bearing findings touched in a scan run, this service queries:
  * vulncheck-kev   → has_exploit, exploit_count, ransomware_use, canary_detected,
                      vulncheck_kev (membership); plus narrative (vulnerabilityName,
                      required_action, PoC + reported-exploitation links)
  * nist-nvd2       → CVSS/CWE gap-fill, plus the canonical description + references.
                      Fetched for every CVE (the KEV index only covers exploited
                      ones, so NVD2 is the reliable narrative source for the rest).

Narrative is stored in finding.detail["cve_intel"] (no schema change) so the UI can
explain *what* a finding is, not just score it. The scoring chain reads the signal
columns; the score is unchanged by this capture. This step also normalises the CVE
finding *title* with a precedence chain: authoritative MITRE CNA title (from the
mitre-cvelist-v5 index) → NVD description's first sentence → the bare CVE id
(dropping source-specific noise like "CVE-X exposed (via Shodan)"). VulnCheck's
vulnerabilityName is intentionally NOT used as the title — it's a generated
"{vendor} {product} {CWE}" label biased to one affected vendor.

Runs after cve_enrichment in scan_executor. Fail-soft: if no VULNCHECK_API_KEY is
configured, returns immediately and the Risk Score degrades gracefully to the
CVSS/EPSS/CISA-KEV signals cve_enrichment already wrote.

Field paths verified against live community-tier responses (2026-06-10); see the
"VulnCheck" section of the Obsidian vault's Constellus — Connectors doc for the
full endpoint/quirk reference. Notable shapes:
  * knownRansomwareCampaignUse is the STRING "Known"/"Unknown", not a bool.
  * vulncheck_xdb[] length is the exploit count; presence ⇒ has_exploit.
  * reported_exploited_by_vulncheck_canaries (bool) is present on the community
    tier — only the granular vulncheck-canaries index is paid.
  * nist-nvd2 carries no EPSS (EPSS stays sourced from FIRST.org in cve_enrichment).
"""

import logging
import time
import uuid

from sqlalchemy.orm import Session

from app.connectors.http import connector_get
from app.core.secrets import get_secret
from app.models.finding_canonical import FindingCanonical

log = logging.getLogger(__name__)

_API_BASE = "https://api.vulncheck.com/v3"
_KEV_URL = f"{_API_BASE}/index/vulncheck-kev"
_NVD2_URL = f"{_API_BASE}/index/nist-nvd2"
_CVELIST_URL = f"{_API_BASE}/index/mitre-cvelist-v5"

# Per-CVE cache: CVE_ID_UPPER → (signals_dict, monotonic_ts). 24h TTL.
_cache: dict[str, tuple[dict, float]] = {}
_CACHE_TTL = 86_400  # 24h


def enrich_scan_findings(
    db: Session,
    scan_run_id: uuid.UUID,
    canonical_ids: set[uuid.UUID] | None = None,
) -> set[uuid.UUID]:
    """Enrich CVE-bearing canonical findings touched by this run with VulnCheck
    KEV/XDB signals and (where still missing) NVD2 CVSS.

    Signals are CVE-level facts, so — like cve_enrichment — they're mirrored onto
    every canonical row sharing each touched CVE, not just the rows seen this run.

    Returns the IDs of every canonical row whose signals were mirrored, so the
    caller can re-run risk scoring over the full set."""
    if not canonical_ids:
        return set()

    api_key = get_secret("VULNCHECK_API_KEY")
    if not api_key:
        log.info("VulnCheck enrichment skipped — no VULNCHECK_API_KEY configured")
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
    log.info("VulnCheck enrichment: %d unique CVE IDs for scan %s", len(cve_ids), scan_run_id)

    headers = {"Accept": "application/json", "Authorization": f"Bearer {api_key}"}

    signals: dict[str, dict] = {}
    for cid in cve_ids:
        sig = _lookup_cve(cid, headers)
        if sig:
            signals[cid] = sig

    if not signals:
        log.info("VulnCheck enrichment: no signals returned for scan %s", scan_run_id)
        return set()

    # Mirror onto every canonical row sharing the touched CVE IDs.
    canonical_rows = (
        db.query(FindingCanonical)
        .filter(FindingCanonical.cve_id.isnot(None))
        .filter(FindingCanonical.cve_id.in_(list(signals.keys())))
        .all()
    )
    for c in canonical_rows:
        cid = (c.cve_id or "").upper()
        sig = signals.get(cid)
        if not sig:
            continue
        c.vulncheck_kev = sig["vulncheck_kev"]
        c.has_exploit = sig["has_exploit"]
        c.exploit_count = sig["exploit_count"]
        c.exploit_types = sig.get("exploit_types") or []
        c.ransomware_use = sig["ransomware_use"]
        c.canary_detected = sig["canary_detected"]
        # CVSS score gap-fill only — never overwrite a score a connector provided.
        if c.cvss_score is None and sig.get("cvss_score") is not None:
            c.cvss_score = sig["cvss_score"]
        # Vector/version/CWE fill whenever missing (needed for impact_class) — these
        # don't overwrite, they only populate gaps the source connector left empty.
        if c.cvss_vector is None and sig.get("cvss_vector"):
            c.cvss_vector = sig["cvss_vector"]
            c.cvss_version = c.cvss_version or sig.get("cvss_version")
        if c.cwe is None and sig.get("cwe"):
            c.cwe = sig["cwe"]
        # Narrative ("what is it / what to do / proof") → detail.cve_intel. The
        # scoring chain consumes the signal columns; this keeps the human-readable
        # story so the UI isn't a black box. Reassign detail (not in-place mutate)
        # so SQLAlchemy flags the JSONB column dirty.
        intel = {k: v for k, v in (sig.get("intel") or {}).items() if v}
        if intel:
            c.detail = {**(c.detail or {}), "cve_intel": intel}
        # Title precedence: authoritative MITRE CNA title → NVD description's first
        # sentence → strip source-specific noise (e.g. "CVE-X exposed (via Shodan)")
        # down to the bare CVE id. We deliberately do NOT use VulnCheck's
        # vulnerabilityName: it's an auto-generated "{vendor} {product} {CWE}" label
        # biased to a single affected vendor (e.g. "SonicWall sma_6200_firmware …"
        # for the OpenSSH regreSSHion CVE). It's still kept in detail.cve_intel.name
        # for reference; the source is shown separately in the UI.
        new_title = _clean_cna_title(intel.get("cna_title")) or _first_sentence(intel.get("description"))
        if new_title:
            c.title = new_title
        elif c.cve_id and c.title and "(via " in c.title:
            c.title = c.cve_id

    db.commit()
    kev_hits = sum(1 for s in signals.values() if s["vulncheck_kev"])
    exploit_hits = sum(1 for s in signals.values() if s["has_exploit"])
    log.info(
        "VulnCheck enrichment complete for scan %s — VC-KEV: %d, with-exploit: %d, NVD2 CVSS fills: %d",
        scan_run_id, kev_hits, exploit_hits,
        sum(1 for s in signals.values() if s.get("cvss_score") is not None),
    )
    return {c.id for c in canonical_rows}


# ── lookups ─────────────────────────────────────────────────────────────────────

def _lookup_cve(cve_id: str, headers: dict) -> dict | None:
    """Returns the merged signal dict for one CVE, cached 24h. None on hard failure.

    Always pulls NVD2 too: it's the reliable description/reference source for *any*
    CVE (the KEV index only covers exploited ones), and it's how non-KEV findings
    get their narrative. CVSS/CWE from NVD2 are still gap-fill-only at write time."""
    now = time.monotonic()
    cached = _cache.get(cve_id)
    if cached is not None and (now - cached[1]) < _CACHE_TTL:
        return cached[0]

    sig = _fetch_kev_signals(cve_id, headers)
    if sig is None:
        return None  # transient failure — don't cache, retry next scan

    nvd = _fetch_nvd2(cve_id, headers)
    if nvd:
        nvd_intel = nvd.pop("intel", {})
        sig.update(nvd)  # cvss_score / cvss_vector / cvss_version / cwe
        intel = sig.setdefault("intel", {})
        # NVD description is canonical — prefer it over KEV's shortDescription.
        if nvd_intel.get("description"):
            intel["description"] = nvd_intel["description"]
        if nvd_intel.get("references"):
            intel["references"] = nvd_intel["references"]

    # CVE 5.0 record → the CNA-assigned title (authoritative, vendor-neutral).
    # Used as the preferred finding title; absent for many CVEs (the chain falls
    # back to the NVD description sentence).
    cna_title = _fetch_cvelist(cve_id, headers)
    if cna_title:
        sig.setdefault("intel", {})["cna_title"] = cna_title

    _cache[cve_id] = (sig, now)
    return sig


def _fetch_kev_signals(cve_id: str, headers: dict) -> dict | None:
    """VulnCheck KEV record → exploit/ransomware/canary/membership signals.

    A CVE absent from the index (data: []) is a valid 'not in VulnCheck KEV'
    answer, returned with all signals false — distinct from a transient failure."""
    try:
        resp = connector_get(_KEV_URL, headers=headers, params={"cve": cve_id}, timeout=20)
        if resp.status_code != 200:
            log.warning("VulnCheck KEV %s → HTTP %d", cve_id, resp.status_code)
            return None
        data = resp.json().get("data", [])
    except Exception:
        log.warning("VulnCheck KEV fetch failed for %s", cve_id, exc_info=True)
        return None

    if not data:
        return {
            "vulncheck_kev": False,
            "has_exploit": False,
            "exploit_count": 0,
            "exploit_types": [],
            "ransomware_use": False,
            "canary_detected": False,
            "intel": {},
        }

    rec = data[0]
    xdb = rec.get("vulncheck_xdb") or []
    # Distinct exploit-type tags (VulnCheck taxonomy: initial-access / infoleak / …),
    # sorted for stable storage. Filters out empty/None types.
    exploit_types = sorted({x.get("exploit_type") for x in xdb if x.get("exploit_type")})
    # PoC exploit links + reported-in-the-wild sources — kept in full (the Intel
    # tab paginates), so the panel count matches exploit_count. Date sliced to YYYY-MM-DD.
    exploits = [
        {"url": x["xdb_url"], "type": x.get("exploit_type"), "date": (x.get("date_added") or "")[:10]}
        for x in xdb if x.get("xdb_url")
    ]
    reported = [
        {"url": r["url"], "date": (r.get("date_added") or "")[:10]}
        for r in (rec.get("vulncheck_reported_exploitation") or []) if r.get("url")
    ]
    intel = {
        "name": rec.get("vulnerabilityName"),
        "description": rec.get("shortDescription"),  # NVD desc overrides later if present
        "required_action": rec.get("required_action"),
        "exploits": exploits,
        "reported_exploitation": reported,
    }
    return {
        "vulncheck_kev": True,
        "has_exploit": len(xdb) > 0,
        "exploit_count": len(xdb),
        "exploit_types": exploit_types,
        # NOTE: string "Known"/"Unknown", not a bool.
        "ransomware_use": rec.get("knownRansomwareCampaignUse") == "Known",
        "canary_detected": bool(rec.get("reported_exploited_by_vulncheck_canaries")),
        "intel": {k: v for k, v in intel.items() if v},
    }


def _fetch_nvd2(cve_id: str, headers: dict) -> dict | None:
    """VulnCheck NVD2 record → {cvss_score, cvss_vector, cvss_version, cwe} for the
    highest available CVSS version, plus an `intel` sub-dict with the canonical
    English description and references. None on failure / empty."""
    try:
        resp = connector_get(_NVD2_URL, headers=headers, params={"cve": cve_id}, timeout=20)
        if resp.status_code != 200:
            return None
        data = resp.json().get("data", [])
    except Exception:
        log.warning("VulnCheck NVD2 fetch failed for %s", cve_id, exc_info=True)
        return None
    if not data:
        return None

    rec = data[0]
    metrics = rec.get("metrics", {})
    result: dict = {}
    for key, version in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key) or []
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            result = {
                "cvss_score": cvss_data.get("baseScore"),
                "cvss_vector": cvss_data.get("vectorString"),
                "cvss_version": version,
            }
            break

    # CWE from the first weakness description, if present.
    for weakness in rec.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                result["cwe"] = val
                break
        if result.get("cwe"):
            break

    # Narrative: English description + references (deduped by URL, capped).
    description = next(
        (d.get("value") for d in rec.get("descriptions", []) if d.get("lang") == "en" and d.get("value")),
        None,
    )
    # Keep all references (deduped by URL) with their NVD tags — the Intel tab
    # filters by tag + paginates, so the full set doesn't clutter the UI.
    references, seen = [], set()
    for r in rec.get("references", []):
        url = r.get("url")
        if url and url not in seen:
            seen.add(url)
            references.append({"url": url, "tags": r.get("tags") or []})
    result["intel"] = {k: v for k, v in {"description": description, "references": references}.items() if v}

    return result or None


def _fetch_cvelist(cve_id: str, headers: dict) -> str | None:
    """VulnCheck mitre-cvelist-v5 record → the CNA-assigned title (authoritative,
    vendor-neutral). None when the CVE has no CNA title (common) or on failure."""
    try:
        resp = connector_get(_CVELIST_URL, headers=headers, params={"cve": cve_id}, timeout=20)
        if resp.status_code != 200:
            return None
        data = resp.json().get("data", [])
    except Exception:
        log.warning("VulnCheck cvelist fetch failed for %s", cve_id, exc_info=True)
        return None
    if not data:
        return None
    rec = data[0]
    # VulnCheck flattens the CNA title to a top-level `title`; fall back to the
    # nested CNA container if that's ever empty.
    return rec.get("title") or (
        rec.get("mitre_ref", {}).get("containers", {}).get("cna", {}).get("title")
    ) or None


# ── title helpers ─────────────────────────────────────────────────────────────

def _clean_cna_title(title: str | None) -> str | None:
    """Normalise a CNA-provided title: collapse whitespace and capitalise the
    first character. Internal casing is left as the CNA wrote it — re-casing
    acronyms (RCE/DoS, SSH, OpenSSH) safely isn't feasible."""
    if not title:
        return None
    t = " ".join(title.split())
    if not t:
        return None
    return (t[0].upper() + t[1:]) if t[0].islower() else t


def _first_sentence(text: str | None, cap: int = 120) -> str | None:
    """First sentence of an NVD-style description, length-capped — the
    vendor-neutral title fallback when no CNA title exists."""
    if not text:
        return None
    t = " ".join(text.split())
    idx = t.find(". ")
    sentence = t[: idx + 1] if idx != -1 else t
    if len(sentence) > cap:
        sentence = sentence[:cap].rstrip() + "…"
    return sentence or None
