# Risk Scoring

Every finding is scored by `score_finding()` (`app/services/risk_scorer.py`), the last step in the post-scan enrichment chain (`cve_enrichment` → `vulncheck_enrichment` → `vulnx_enrichment` → `ssvc_enrichment` → risk scoring). It writes three columns onto the finding: **`risk_score`** (0–100), **`risk_band`** (one of four tiers), and **`building_velocity`** (a momentum flag).

Two orthogonal concepts drive the score, and it's worth keeping them separate when reading a finding:

- **Band (the verdict)** — which tier the finding lands in.
- **Intensity (the position within the tier)** — where in that tier's range it sits.

## Bands

| Band | Score range | Meaning |
|---|---|---|
| **Imminent Threat** | 75–100 | Confirmed or near-certain exploitation risk — act now |
| **High Risk** | 50–74 | CVSS ≥ 7.0 track (or "high" severity for non-CVE findings) |
| **Elevated Risk** | 25–49 | CVSS ≥ 4.0 track (or "medium") |
| **Low Risk** | 1–24 | |
| **Secure Posture** | — | Asset/org-level only — zero open findings. A single finding is never "secure." |

## How the band is decided

CVE findings go through a first-match-wins cascade that is **promote-only** — it can lift a finding above what raw CVSS implies, but never demote it below what CVSS already earned:

- **Hard trigger → top tier** — confirmed exploitation: CISA KEV membership, active SSVC exploitation, VulnCheck "canary" ground-truth sightings, or ransomware use with any exploit evidence.
- **Soft trigger → top tier** — predictive signals: VulnCheck KEV listing, exploit availability + high EPSS, or SSVC Automatable + Total technical impact + exploit evidence. Soft triggers can be gated back down if CISA Vulnrichment data explicitly says the CVE is *not* automatable.
- Otherwise, the band falls out of the CVSS-based intensity score below.

Non-CVE findings (exposure, misconfiguration, etc.) use a separate severity track that maps the connector's own severity string onto the same four bands.

## Intensity — the weighted blend

Within a band, the exact score is a weighted sum:

| Factor | Weight | Inputs |
|---|---|---|
| CVSS | 25% | Normalized base score |
| EPSS | 25% | Current exploit-probability sample |
| Exploitation capability | 20% | Exploit / PoC / Nuclei-template availability, plus an Automatable bonus |
| Technical impact | 15% | SSVC Technical Impact (from CISA Vulnrichment, or derived from the CVSS vector when Vulnrichment hasn't scored the CVE) |
| Asset context | 15% | Internet-facing exposure, end-of-life software |

## Building Velocity

An **⚡ Building Velocity** badge can appear on any band — it means EPSS is rising fast for that CVE (a meaningful absolute jump, or ≥2× relative jump, versus the prior sample). It contributes a small intensity bump but never changes the band by itself; it's a heads-up that a Low or Elevated finding may escalate soon.

## EPSS and its trend

EPSS (Exploit Prediction Scoring System, from FIRST.org) is a 0–100% probability that a CVE will be exploited in the wild within the next 30 days, plus a percentile rank. Constellus stores the current and previous sample on the finding and feeds both into the intensity score and the Building Velocity flag.

Separately, `app/services/epss_history_service.py` maintains a daily time-series per CVE (the `epss_history` hypertable, 12-week / 84-day retention): new CVEs are backfilled with 12 weekly points, and a 12h scheduler job refreshes today's sample for every CVE attached to an active finding. This backs the **EPSS trend** sparkline on the finding detail view (`GET /findings/{id}/epss-history`) — the practical answer to "is this vulnerability becoming more dangerous over time," independent of the finding's current band.

## CISA BOD 26-04 — the compliance-deadline lens

BOD 26-04 is a **separate lens from the Risk Score**, computed by `compute_sla()` in `app/services/bod_sla.py`. It implements CISA's four-axis SSVC decision table, and only fires when a finding has a CVE **and** real CISA Vulnrichment SSVC data — a CVSS-derived ("Derived") SSVC estimate isn't treated as authoritative enough to anchor a regulatory deadline.

The four axes:

| Axis | Question |
|---|---|
| **Exposed** | Is the asset internet-facing (public IP, or open ports observed)? |
| **KEV** | Is the CVE on the *CISA* Known Exploited Vulnerabilities list (not VulnCheck's separate feed)? |
| **Automatable** | Can exploitation be scripted / mass-automated (network-reachable, low complexity, no privileges or user interaction)? |
| **Technical Impact = Total** | Does successful exploitation give an attacker full control, versus only partial impact? |

The resulting 16-cell table maps to a remediation window: **3 days** (occasionally **3 days + forensic triage**, when the combination signals likely prior compromise), **14 days**, **60 days**, or **upgrade** (no fixed date — fix on the next planned upgrade cycle). The clock starts from the CISA KEV "date added" when the CVE is on KEV, otherwise from when Constellus first observed the finding.

On a finding, this surfaces as a **BOD badge** — e.g. "BOD: 14d · 5d left" or "BOD: overdue" — color-coded red (3-day / overdue), amber (14-day), or neutral (60-day / upgrade). It only appears once CISA has actually scored the CVE's SSVC values, so most findings won't show it.

!!! note
    SSVC/BOD-26-04 is deliberately not merged into the Risk Score. A finding can be "Elevated Risk" by score and still carry a 3-day BOD deadline (or vice versa) — read both, they answer different questions ("how dangerous is this" vs. "what does the federal directive require").

## VulnCheck and vulnx enrichment

Two optional third-party sources, both fail-soft — scoring degrades gracefully if either is unconfigured or unreachable:

- **VulnCheck** (`app/connectors/vulncheck.py`) — primary CVE intelligence, requires an API key. Supplies KEV-equivalent membership, exploit availability/count/type, ransomware-campaign association, "canary" ground-truth exploitation sightings, CVSS/CWE gap-fill, and the human-readable narrative (description, required action, exploit/PoC links) shown in the finding's Intel panel. Also the authoritative source for CVE titles.
- **vulnx** (`app/services/vulnx_enrichment.py`, via ProjectDiscovery Cloud) — secondary and lighter-weight; only queried for CVEs already flagged interesting (exploit evidence, or EPSS ≥ 10%) to respect rate limits. Adds `is_template` (a Nuclei attack template exists) and `is_poc` (a public proof-of-concept exists).

Both surface as small badges on the finding: Exploit ×N, Nuclei, PoC, Ransomware, Canary, VC-KEV.

## Security score rollups

- **Org-level** — `GET /findings/security-score`. Deliberately **worst-driven, not averaged**: the org score/band equals the single highest-risk open finding across the whole org. Breadth is shown separately via a count of how many open findings currently share that worst band, plus a day-over-day new/resolved trend. This is the Dashboard's headline gauge.
- **Per-asset** — each asset inherits the `risk_score`/`risk_band` of its own worst open finding (rolled up to parent assets where applicable).

## What you see on a finding

- A verdict badge (band name + numeric score), or the raw CVSS severity badge if not yet scored.
- An optional ⚡ Building Velocity badge.
- Enrichment badges: CVSS, EPSS %, KEV / VC-KEV, Ransomware, Canary, Exploit count, Nuclei, PoC, CWE.
- An EPSS row plus the 12-week trend sparkline.
- An SSVC evidence panel (Technical Impact, Automatable, Exploitation), labeled "CISA Vulnrichment" or "Derived" so you know the provenance.
- An Impact class chip (Code Execution, Data Exposure, Service Disruption, Tampering).
- A BOD-26-04 badge, when CISA has scored the CVE.
- A provenance panel naming which scanner/connector produced the finding.

Findings excluded by [shared-infrastructure verification](shared-infra-verification.md) (`rejected_shared_infra`, `ownership_unverifiable`) are removed from the Risk Score entirely — that classification runs before scoring, so misattributed shared-hosting noise never inflates your org's score.
