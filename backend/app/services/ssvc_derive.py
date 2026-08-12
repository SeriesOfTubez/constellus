"""Derived SSVC fallback — approximate Automatable + Technical Impact from data we
already have (CVSS vector / impact_class) when CISA Vulnrichment hasn't scored a CVE.

These are LOWER-confidence proxies, persisted with ssvc_source='derived' (vs
'vulnrichment' for real CISA values). Per the locked Risk Score design they feed
**intensity only** — they NEVER gate a tier promotion. The Automatable gate and the
automatable+total escalator fire solely on real Vulnrichment values (risk_scorer
checks ssvc_source == 'vulnrichment'). This honours "never demote on absent/derived
data": a missing real SSVC can't pull a finding's tier down via a guessed value.
"""


def derive_technical_impact(impact_class: str | None) -> str | None:
    """impact_class (from the CVSS C/I/A vector + CWE, see risk_scorer.derive_impact_class)
    → SSVC Technical Impact proxy. `rce` ⇒ total (adversary gains full control);
    every other consequence class is bounded ⇒ partial. None when impact_class is
    unknown (no vector to reason from)."""
    if impact_class is None:
        return None
    return "total" if impact_class == "rce" else "partial"


def derive_automatable(cvss_vector: str | None) -> bool | None:
    """Approximate SSVC Automatable from the CVSS exploitability metrics: a vuln is
    likely mass-automatable when it is network/adjacent-reachable, low-complexity,
    needs no privileges and no user interaction. Conservative — anything missing
    those reads as not-automatable. None when there's no vector to reason from.

    Handles CVSS v3.x and v4.0 vector strings (both expose AV/AC/PR/UI). Sanity-checked
    against real Vulnrichment values: regreSSHion (AC:H)→no, CVE-2023-38408
    (AV:N/AC:L/PR:N/UI:N)→yes, CVE-2025-23419 (PR:L)→no — all match CISA."""
    if not cvss_vector:
        return None
    metrics: dict[str, str] = {}
    for tok in cvss_vector.split("/"):
        k, _, v = tok.partition(":")
        if k and v:
            metrics[k] = v.upper()
    if "AV" not in metrics:  # not a recognisable CVSS vector
        return None
    return (
        metrics.get("AV") in ("N", "A")   # network / adjacent reachable
        and metrics.get("AC") == "L"       # low attack complexity
        and metrics.get("PR") == "N"       # no privileges required
        and metrics.get("UI") == "N"       # no user interaction
    )
