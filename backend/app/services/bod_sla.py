"""
BOD-26-04 Remediation SLA Lens.

Computes a finding's fix-due date using the remediation windows of CISA Binding
Operational Directive 26-04 (Table 1), chosen from four binary inputs derived
from the finding and its asset. This is a compliance lens, separate from and not
replacing the Constellus Risk Score.

The clock starts at the finding's first_seen_at, never at the CISA KEV listing
(planning#381). The directive counts from the earlier of the listing and the
agency's own enumeration; we deliberately count from when we found it, so the
result is OUR due date using the directive's windows and must not be presented
as the BOD 26-04 deadline. Being in CISA KEV still selects the shorter window.

Only applied when:
  - the finding has a CVE id, AND
  - ssvc_source == 'vulnrichment' (real CISA Vulnrichment data — a derived or
    absent SSVC fallback is not authoritative enough for a compliance deadline).

Decision table (Table 1 from BOD-26-04):
  Axes: exposed, kev (CISA only), automatable, total (Technical Impact == total)
  Values: "3d", "3d+triage", "14d", "60d", "upgrade"

  (T,T,T,T):"3d+triage"  (T,T,T,F):"3d"        (T,T,F,T):"3d+triage"  (T,T,F,F):"14d"
  (T,F,T,T):"3d"         (T,F,T,F):"14d"        (T,F,F,T):"14d"        (T,F,F,F):"60d"
  (F,T,T,T):"3d+triage"  (F,T,T,F):"14d"        (F,T,F,T):"14d"        (F,T,F,F):"14d"
  (F,F,T,T):"60d"        (F,F,T,F):"60d"        (F,F,F,T):"upgrade"    (F,F,F,F):"upgrade"
"""

from datetime import date, timedelta

# ── Table 1 lookup ────────────────────────────────────────────────────────────

# Key: (exposed, kev, automatable, total) → window string
_TABLE: dict[tuple[bool, bool, bool, bool], str] = {
    (True,  True,  True,  True):  "3d+triage",
    (True,  True,  True,  False): "3d",
    (True,  True,  False, True):  "3d+triage",
    (True,  True,  False, False): "14d",
    (True,  False, True,  True):  "3d",
    (True,  False, True,  False): "14d",
    (True,  False, False, True):  "14d",
    (True,  False, False, False): "60d",
    (False, True,  True,  True):  "3d+triage",
    (False, True,  True,  False): "14d",
    (False, True,  False, True):  "14d",
    (False, True,  False, False): "14d",
    (False, False, True,  True):  "60d",
    (False, False, True,  False): "60d",
    (False, False, False, True):  "upgrade",
    (False, False, False, False): "upgrade",
}

# Window string → calendar days (None = no fixed deadline, plan upgrade cycle)
_DAYS: dict[str, int | None] = {
    "3d":        3,
    "3d+triage": 3,
    "14d":       14,
    "60d":       60,
    "upgrade":   None,
}


def compute_window(exposed: bool, kev: bool, automatable: bool, total: bool) -> str:
    """Return the BOD-26-04 remediation window string for the given axis values."""
    return _TABLE[(exposed, kev, automatable, total)]


def compute_sla(finding, asset, state=None) -> dict | None:
    """Compute the fix-due envelope (BOD-26-04 windows, first-seen clock) for one finding + its asset.

    `state` is the asset's projected `asset_state` row (or None). As of
    planning#144 L3c-3 the `exposed` axis reads its port inventory from
    there rather than `asset_metadata`; callers on a list path must
    batch-load it (`projector.load_states`) rather than let this reach for
    it per finding.

    Returns None when the finding doesn't meet the preconditions (no CVE, or
    SSVC data isn't from real Vulnrichment — a derived fallback is not
    authoritative enough to anchor a compliance deadline).

    Returns a dict with:
      window        — BOD table cell string
      forensic_triage — True when window == "3d+triage"
      due_date      — ISO date string or None (upgrade path has no date)
      days_remaining — int or None
      overdue       — bool
    """
    # Preconditions: CVE-backed, real Vulnrichment SSVC only.
    if not finding.cve_id:
        return None
    if finding.ssvc_source != "vulnrichment":
        return None

    # Axis 1: exposed — mirrors risk_scorer._internet_facing, including its
    # treatment of a missing projection as "no ports" (planning#144 L3c-3).
    exposed: bool = (
        asset is not None
        and (
            asset.asset_type == "ip_address"
            or bool(state is not None and state.open_ports)
        )
    )

    # Axis 2: kev — CISA KEV only (NOT vulncheck_kev)
    kev: bool = bool(finding.kev)

    # Axis 3 & 4: from real Vulnrichment
    automatable: bool = bool(finding.ssvc_automatable)
    total: bool = finding.ssvc_technical_impact == "total"

    window = compute_window(exposed, kev, automatable, total)
    forensic_triage = window == "3d+triage"
    days_n = _DAYS[window]

    # Clock start: always first seen (planning#381). The directive's own clock
    # (the KEV listing) could make a finding overdue before we knew of it; the
    # due date is ours, using the directive's windows. KEV still picks the window.
    clock_start: date = finding.first_seen_at.date()

    if days_n is not None:
        due_date = clock_start + timedelta(days=days_n)
        days_remaining = (due_date - date.today()).days
        overdue = days_remaining < 0
        due_date_iso: str | None = due_date.isoformat()
    else:
        due_date_iso = None
        days_remaining = None
        overdue = False

    return {
        "window":          window,
        "forensic_triage": forensic_triage,
        "due_date":        due_date_iso,
        "days_remaining":  days_remaining,
        "overdue":         overdue,
    }
