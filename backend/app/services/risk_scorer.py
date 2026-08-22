"""
Constellus Risk Score — per-finding scorer (v1).

Pure computation over signals already written by the enrichment chain
(cve_enrichment → vulncheck_enrichment → vulnx_enrichment). Runs last in
scan_executor. No external calls.

Model (see the "Constellus Risk Score" design note):
  * Two orthogonal axes. Severity = the verdict tier (the cascade). Momentum =
    the Building Velocity flag (about to jump tiers). They do NOT mix.
  * Tier cascade is first-match-wins; the tier owns a score *band*; an intra-band
    intensity positions the finding within it. So risk_band is derivable from
    risk_score (monotonic by construction) — both stored for query convenience.
  * Two scoring tracks feed the same bands: a CVE track (CVSS+EPSS+exploit signals)
    and a severity track (the analyzer/connector severity — covers exposure,
    misconfig, and every other non-CVE finding).

v1 locked rules (2026-06-09):
  * promote-only, never demote (the cascade only ever lifts above the CVSS band).
  * EPSS alone never promotes a tier — high EPSS without a confirmed exploit lights
    Building Velocity instead.
  * Building Velocity v1 = rising EPSS (sample-diff vs epss_score_previous); to be
    replaced by FIRST.org time-series later.

v2 SSVC integration (2026-06-18, see epic constellus-planning#65 + BOD-26-04 note):
  * Exploitation evidence is source-agnostic / max-wins — an SSVC poc/active counts
    like a VulnCheck poc/exploit (anyexploit). SSVC `active` is a HARD imminent
    trigger alongside CISA KEV.
  * Structural SSVC facts temper, never override: Automatable==no GATES a SOFT
    (predictive) imminent promotion back to the CVSS band; it never touches a HARD
    (confirmed-exploitation) one. vc_kev is SOFT (gateable); CISA KEV is HARD.
    automatable+total+anyexploit escalates to imminent (BOD 3-day shape).
  * Gate/escalator trust ONLY real Vulnrichment values (ssvc_source=='vulnrichment');
    a derived CVSS-vector fallback (ssvc_derive) feeds intensity only and never
    gates — so missing real SSVC can never demote a finding.
  * Intensity adds an IMPACT term (Technical Impact) + an Automatable capability
    bonus; the promote-only CVSS floor is preserved.

All weights / band edges / thresholds are module constants here, not literals
scattered through the logic — they are slated to become per-deployment config.
"""

import logging
import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.finding_canonical import FindingCanonical
from app.services import projector
from app.services.ssvc_derive import derive_automatable, derive_technical_impact

log = logging.getLogger(__name__)

# ── Config constants (destined to become per-deployment settings) ───────────────

# Tier score bands (inclusive). "secure" is asset-level only — a finding is never secure.
BANDS: dict[str, tuple[int, int]] = {
    "imminent_compromise": (75, 100),
    "high": (50, 74),
    "elevated": (25, 49),
    "low": (1, 24),
}

# CVE-track intensity weights (must sum to 1.0). v2 adds an IMPACT term (SSVC
# Technical Impact) and folds Automatable into capability.
W_CVSS = 0.25
W_EPSS = 0.25
W_CAP = 0.20     # exploitation capability (exploit availability + automatable)
W_IMPACT = 0.15  # consequence severity (SSVC Technical Impact, real or derived)
W_CTX = 0.15     # asset context

# Capability factor by strongest exploit signal present, plus an Automatable bonus.
CAP_HAS_EXPLOIT = 1.0
CAP_IS_TEMPLATE = 0.6
CAP_IS_POC = 0.4
CAP_AUTOMATABLE_BONUS = 0.3   # additive when mass-automatable; capped at 1.0

# Impact factor by SSVC Technical Impact (real or derived). Unknown = neutral midpoint.
IMPACT_TOTAL = 1.0
IMPACT_PARTIAL = 0.5
IMPACT_UNKNOWN = 0.5

# Context factor components (summed, capped at 1.0).
CTX_INTERNET_FACING = 0.7
CTX_EOL = 0.3

# Severity-track base intensities (non-CVE findings).
EXPOSURE_CONFIRMED = 0.7
EXPOSURE_INFERRED = 0.5
SEVERITY_TRACK_DEFAULT = 0.6  # non-exposure, non-CVE findings (misconfig, tags, …)

# Imminent thresholds.
IMMINENT_EPSS_WITH_EXPLOIT = 0.50

# Building Velocity (rising-EPSS, v1 sample-diff).
VELOCITY_BUMP = 0.10
VELOCITY_ABS_DELTA = 0.05   # absolute EPSS jump
VELOCITY_REL_FACTOR = 2.0   # or ≥2× the prior sample (catches near-zero spikes)

# severity string → tier (severity track + non-CVE fallback).
_SEVERITY_TO_BAND = {
    "critical": "imminent_compromise",
    "high": "high",
    "medium": "elevated",
    "low": "low",
    "info": "low",
    "unknown": "low",
}


# CWEs that imply code execution regardless of CVSS impact shape.
_EXEC_CWES = {"CWE-94", "CWE-77", "CWE-78", "CWE-502", "CWE-434", "CWE-98", "CWE-917"}


@dataclass
class ScoreInputs:
    cve_id: str | None = None
    cvss_score: float | None = None
    epss_score: float | None = None
    epss_score_previous: float | None = None
    kev: bool | None = None              # CISA KEV
    vulncheck_kev: bool | None = None
    canary_detected: bool | None = None
    has_exploit: bool | None = None
    ransomware_use: bool | None = None
    is_template: bool | None = None
    is_poc: bool | None = None
    # SSVC (real Vulnrichment or derived fallback; ssvc_source distinguishes which).
    ssvc_exploitation: str | None = None       # none | poc | active
    ssvc_automatable: bool | None = None
    ssvc_technical_impact: str | None = None   # total | partial
    ssvc_source: str | None = None             # vulnrichment | derived
    category: str | None = None
    severity: str | None = None
    internet_facing: bool = False
    eol: bool = False
    exposure_confirmed: bool = True      # exposure findings: confirmed service vs port-only inference


def score_finding(s: ScoreInputs) -> tuple[int, str, bool]:
    """Return (risk_score, risk_band, building_velocity) for one finding."""
    velocity = _building_velocity(s)

    if s.cve_id:
        band = _cve_tier(s)
        intensity = _cve_intensity(s)
    else:
        band = _severity_band(s.severity)
        intensity = _severity_intensity(s)

    if velocity:
        intensity = min(1.0, intensity + VELOCITY_BUMP)

    score = _place_in_band(band, intensity)
    return score, band, velocity


# ── tier selection ──────────────────────────────────────────────────────────────

def _cve_tier(s: ScoreInputs) -> str:
    """First-match-wins cascade (v2). Imminent conditions only ever promote above
    the CVSS-implied band (promote-only); EPSS alone never reaches Imminent.

    HARD imminent = confirmed exploitation; never gated. SOFT imminent = predictive;
    gated back to the CVSS band when SSVC says Automatable==no. Gate/escalator trust
    only real Vulnrichment values (ssvc_source=='vulnrichment'), so a derived
    fallback can never demote a finding."""
    real = s.ssvc_source == "vulnrichment"
    automatable = s.ssvc_automatable if real else None          # gate/escalator: real only
    ssvc_known = real and s.ssvc_automatable is not None
    total = real and s.ssvc_technical_impact == "total"
    active = real and s.ssvc_exploitation == "active"
    epss = s.epss_score or 0.0
    # Source-agnostic exploit evidence (max-wins): VulnCheck signals OR an SSVC
    # poc/active count the same.
    anyexploit = bool(
        s.has_exploit or s.is_template or s.is_poc
        or (real and s.ssvc_exploitation in ("poc", "active"))
    )

    # HARD imminent — confirmed exploitation; never gated.
    if s.kev or s.canary_detected or active or (s.ransomware_use and anyexploit):
        return "imminent_compromise"

    # SOFT imminent — predictive; gated by SSVC Automatable==no.
    soft = (
        s.vulncheck_kev
        or (anyexploit and epss >= IMMINENT_EPSS_WITH_EXPLOIT)
        or (bool(automatable) and total and anyexploit)
    )
    if soft and not (ssvc_known and automatable is False):
        return "imminent_compromise"

    cvss = s.cvss_score or 0.0
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "elevated"
    return "low"


def _severity_band(severity: str | None) -> str:
    return _SEVERITY_TO_BAND.get((severity or "").lower(), "low")


# ── intensity (intra-band position) ─────────────────────────────────────────────

def _cve_intensity(s: ScoreInputs) -> float:
    """Intra-band position (v2). Adds an IMPACT term (Technical Impact, real or
    derived) and an Automatable capability bonus. Effective SSVC values (the stored
    columns) are used here regardless of source — derived values legitimately inform
    intensity, just not the tier."""
    cvss_norm = (s.cvss_score or 0.0) / 10.0
    epss = s.epss_score or 0.0
    real = s.ssvc_source == "vulnrichment"
    # Capability: strongest exploit signal (source-agnostic — SSVC poc/active count),
    # plus a bonus when the vuln is mass-automatable.
    exploit_signal = s.has_exploit or (real and s.ssvc_exploitation == "active")
    poc_signal = s.is_poc or (real and s.ssvc_exploitation == "poc")
    base_cap = (
        CAP_HAS_EXPLOIT if exploit_signal
        else CAP_IS_TEMPLATE if s.is_template
        else CAP_IS_POC if poc_signal
        else 0.0
    )
    cap = min(1.0, base_cap + (CAP_AUTOMATABLE_BONUS if s.ssvc_automatable else 0.0))
    # Impact: SSVC Technical Impact (real or derived); unknown = neutral midpoint.
    impact = (
        IMPACT_TOTAL if s.ssvc_technical_impact == "total"
        else IMPACT_PARTIAL if s.ssvc_technical_impact == "partial"
        else IMPACT_UNKNOWN
    )
    ctx = min(1.0, (CTX_INTERNET_FACING if s.internet_facing else 0.0)
                   + (CTX_EOL if s.eol else 0.0))
    return (W_CVSS * cvss_norm + W_EPSS * epss + W_CAP * cap
            + W_IMPACT * impact + W_CTX * ctx)


def _severity_intensity(s: ScoreInputs) -> float:
    if (s.category or "") == "exposure":
        return EXPOSURE_CONFIRMED if s.exposure_confirmed else EXPOSURE_INFERRED
    return SEVERITY_TRACK_DEFAULT


def _place_in_band(band: str, intensity: float) -> int:
    lo, hi = BANDS[band]
    intensity = max(0.0, min(1.0, intensity))
    return round(lo + intensity * (hi - lo))


# ── Building Velocity ─────────────────────────────────────────────────────────

def _building_velocity(s: ScoreInputs) -> bool:
    """v1: rising EPSS via sample-diff. True when the current EPSS jumped
    meaningfully over the prior sample — either an absolute delta or a relative
    multiple (the latter catches near-zero CVEs spiking, the early-warning case)."""
    cur, prev = s.epss_score, s.epss_score_previous
    if cur is None or prev is None:
        return False
    if cur - prev >= VELOCITY_ABS_DELTA:
        return True
    if prev > 0 and cur >= VELOCITY_REL_FACTOR * prev and cur - prev > 0:
        return True
    return False


# ── DB driver ───────────────────────────────────────────────────────────────────

def score_scan_findings(
    db: Session,
    scan_run_id: uuid.UUID,
    canonical_ids: set[uuid.UUID] | None = None,
) -> None:
    """Compute and persist risk_score / risk_band / building_velocity for every
    finding touched by this run."""
    if not canonical_ids:
        return

    findings = (
        db.query(FindingCanonical)
        .filter(FindingCanonical.id.in_(canonical_ids))
        .all()
    )
    if not findings:
        return

    # Batch-load the owning assets for context (internet-facing / EOL).
    # planning#144 L3c-3: the two context signals below (open_ports, EOL) come
    # from the projected `asset_state` row, not `asset_metadata` — loaded in
    # the same batched shape so this stays two queries regardless of finding
    # count.
    asset_ids = {f.asset_canonical_id for f in findings}
    assets = {
        a.id: a
        for a in db.query(AssetCanonical).filter(AssetCanonical.id.in_(asset_ids)).all()
    }
    states = projector.load_states(db, asset_ids)

    scored = 0
    for f in findings:
        asset = assets.get(f.asset_canonical_id)
        # impact_class (v1.1 consequence label) — computed first because the derived
        # SSVC fallback below reads it. CVE findings only.
        f.impact_class = derive_impact_class(f.cvss_vector, f.cwe) if f.cve_id else None
        # Derived SSVC fallback (chunk c): fill Automatable / Technical Impact from the
        # CVSS vector / impact_class when CISA Vulnrichment hasn't scored the CVE.
        # Marked ssvc_source='derived'; feeds intensity only, never gates (the tier
        # trusts only ssvc_source=='vulnrichment'). Re-derived each run unless real
        # values exist, so it tracks CVSS/impact_class changes.
        if f.cve_id and f.ssvc_source != "vulnrichment":
            da = derive_automatable(f.cvss_vector)
            dti = derive_technical_impact(f.impact_class)
            if da is not None or dti is not None:
                f.ssvc_automatable = da
                f.ssvc_technical_impact = dti
                f.ssvc_source = "derived"
        s = ScoreInputs(
            cve_id=f.cve_id,
            cvss_score=f.cvss_score,
            epss_score=f.epss_score,
            epss_score_previous=f.epss_score_previous,
            kev=f.kev,
            vulncheck_kev=f.vulncheck_kev,
            canary_detected=f.canary_detected,
            has_exploit=f.has_exploit,
            ransomware_use=f.ransomware_use,
            is_template=f.is_template,
            is_poc=f.is_poc,
            ssvc_exploitation=f.ssvc_exploitation,
            ssvc_automatable=f.ssvc_automatable,
            ssvc_technical_impact=f.ssvc_technical_impact,
            ssvc_source=f.ssvc_source,
            category=f.category,
            severity=f.severity,
            internet_facing=_internet_facing(asset, states.get(f.asset_canonical_id)),
            eol=_is_eol(asset, states.get(f.asset_canonical_id)),
            exposure_confirmed=_exposure_confirmed(f),
        )
        f.risk_score, f.risk_band, f.building_velocity = score_finding(s)
        scored += 1

    db.commit()
    log.info(
        "Risk scoring complete for scan %s — %d findings scored, %d Building Velocity",
        scan_run_id, scored, sum(1 for f in findings if f.building_velocity),
    )


# ── asset/finding context helpers ───────────────────────────────────────────────

def _internet_facing(asset: AssetCanonical | None, state: AssetState | None = None) -> bool:
    """planning#144 L3c-3: the port inventory is `asset_state.open_ports`
    (projected from port_observation claims), not `asset_metadata`. An asset
    with no projected state row yet is treated as having no ports, exactly as
    an absent metadata key was."""
    if asset is None:
        return False
    if asset.asset_type == "ip_address":
        return True
    return bool(state is not None and state.open_ports)


def _is_eol(asset: AssetCanonical | None, state: AssetState | None = None) -> bool:
    """planning#144 L3c-3: EOL records come from `asset_state.eol_summary`
    (projected from eol_enrichment's `eol_status` claim), not
    `asset_metadata["eol_services"]`. The `eol:` tag check is unchanged and
    still short-circuits first."""
    if asset is None:
        return False
    if any(str(t).startswith("eol:") for t in (asset.tags or [])):
        return True
    eol_summary = state.eol_summary if state is not None else None
    if not isinstance(eol_summary, list):
        return False
    return any(isinstance(svc, dict) and svc.get("is_eol") for svc in eol_summary)


def _exposure_confirmed(f: FindingCanonical) -> bool:
    """Exposure findings flag port-only inference as 'service unconfirmed'.
    Confirmed-service hits score at full exposure intensity; inferred take the haircut."""
    if (f.category or "") != "exposure":
        return True
    blob = f"{f.title or ''} {(f.detail or {})}".lower()
    return "unconfirmed" not in blob


# ── impact class (v1.1 — context only, does NOT affect score) ───────────────────

def _cvss_impact_metrics(vector: str | None) -> tuple[str | None, str | None, str | None]:
    """Extract the (C, I, A) impact sub-metrics from a CVSS vector string.
    Exact-key match so AV:/AC: don't collide with A:/C:."""
    if not vector:
        return None, None, None
    out: dict[str, str] = {}
    for tok in vector.split("/"):
        k, _, v = tok.partition(":")
        if k in ("C", "I", "A") and v:
            out[k] = v.upper()
    return out.get("C"), out.get("I"), out.get("A")


def derive_impact_class(cvss_vector: str | None, cwe: str | None) -> str | None:
    """Consequence category from the CVSS impact vector (C/I/A), refined by CWE.
    The vector is the impact source — CWE describes the bug class (e.g. 416
    use-after-free can be either RCE or info-leak), so it only confirms exec.
    Returns None when there's no vector to reason from."""
    if cwe and cwe.upper() in _EXEC_CWES:
        return "rce"

    c, i, a = _cvss_impact_metrics(cvss_vector)
    if c is None and i is None and a is None:
        return None  # no vector → unknown, leave null

    def impacted(x: str | None) -> bool:
        return x not in (None, "N")

    def high(x: str | None) -> bool:
        return x in ("H", "C")  # v3 High or v2 Complete

    if high(c) and high(i) and high(a):
        return "rce"
    if impacted(a) and not impacted(c) and not impacted(i):
        return "denial_of_service"
    if impacted(c) and not impacted(i) and not impacted(a):
        return "data_exposure"
    if impacted(i):
        return "tampering"
    return "other"
