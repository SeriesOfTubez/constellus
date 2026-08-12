# Shared Infrastructure & Dangling DNS

Public IPs are frequently shared — cloud load balancers, CDNs, and hosting platforms put many unrelated tenants behind the same address. A naive EASM tool that attributes every finding on an IP to every hostname that resolves to it will misattribute vulnerabilities that actually belong to someone else's tenant, and will also miss real subdomain-takeover risk on records that point at infrastructure nobody controls anymore. Constellus addresses both problems with the same underlying primitive: **domain affinity**.

## The core check: domain affinity

`app/services/domain_affinity.py::check_affinity()` resolves a hostname's true origin IP, then probes it twice — once with the hostname's own SNI/Host header (the "owned vhost") and once without it (the "default vhost") — and compares identity (TLS certificate, response fingerprint). The result is one of three verdicts:

- **affine** — the origin genuinely serves this hostname.
- **not_affine** — the origin answers, but not for this hostname (classic shared-hosting signature).
- **indeterminate** — the origin didn't answer either probe cleanly (unreachable, timeout).

Everything downstream — shared-infra rejection and dangling-DNS detection — is built on top of this one primitive, applied in different directions.

## Shared-infrastructure false-attribution

`app/services/shared_infra_verifier.py::classify_ip_ownership()` runs the affinity check against every one of your owned hostnames that shares a suspect IP, and writes an auditable verdict onto the `finding.verification` column (`app/models/finding_canonical.py`):

| Verdict | Meaning | Findings list |
|---|---|---|
| *(unset)* | Never evaluated — no owned hostname to test, or not shared infrastructure | Included |
| `confirmed_ours` | At least one owned hostname showed real affinity to the origin | Included |
| `unverified` | Checked but inconclusive (e.g. every owned hostname was unreachable) | Included — findings are never stamped `unverified` from an unset state, so this is effectively invisible in the UI |
| `rejected_shared_infra` | Every owned hostname on that IP showed **no** affinity — unanimous disproof | **Excluded** from the main Findings list and the Risk Score |
| `ownership_unverifiable` | Not a unanimous disproof, but positive evidence (a co-tenant hostname genuinely responds) that the origin serves someone else | **Excluded**, but surfaced as "pending review" rather than disproven |

`rejected_shared_infra` and `ownership_unverifiable` findings still exist — they're pulled into a dedicated **Ownership Unverifiable** tab on the Findings page instead of the default view, with a `VerificationBadge` and an evidence panel (hosting classification, the corroborating hostname, and a tech-absence signal) so you can audit *why* Constellus excluded it.

## Dangling DNS (subdomain takeover)

A DNS record — A/AAAA/CNAME — that still points at infrastructure you no longer control is a classic takeover vector: if an attacker can claim that infrastructure (an expired cloud resource, an unclaimed CDN slot), they inherit your subdomain. `app/services/dangling_dns_analyzer.py` turns this into a user-facing finding: `finding_type=dangling_dns`, `category=exposure`, with a High / Medium / Low severity gradient.

### Three-layer pipeline

| Layer | Module | What it checks | Effect |
|---|---|---|---|
| **1 — Affinity probe** | `domain_affinity.py` | Base signal, same primitive as shared-infra rejection | `not_affine` or fully-unreachable feeds into dangling-DNS scoring |
| **2 — Takeover fingerprint** | `takeover_fingerprint.py` | Did Nuclei's `takeover` template already fire on this asset this run? | Strongest, most direct signal — wins outright, produces the High-severity tier, and bypasses Layer 1 entirely |
| **3 — Origin corroboration** | `origin_corroboration.py` | When Layer 1 is weak/negative, probes *other* hostnames known (via Shodan/HackerTarget) to share the same origin IP, with correct SNI | Can **promote** a Low finding to Medium, or corroborate a shared-infra rejection — never demotes or suppresses |

Layer 3's "never fire alone, only re-grade" rule is deliberate: it keeps false "your DNS is takeoverable" claims rare, the same way shared-infra rejection requires unanimous disproof before excluding a finding.

Evaluation order for a `dangling_dns` candidate: Layer 2 first (free — no network call), then Layer 1 (gated by a cadence/budget), then Layer 3 corroboration on a weak/negative Layer 1 result.

### What you see

- A `DetectionLayerBadge` on `dangling_dns` findings, labeled with which layer fired: "Fingerprint match," "No ownership signal," "Origin unreachable," or "Origin serves others."
- A **Re-verify** button on the finding detail view (`POST /findings/{id}/verify`) — queues an immediate, authoritative recheck that bypasses both the TTL cache and the grace guard. This is the only operator-facing control; the internal tuning constants (probe TTL, re-check budget, grace periods before auto-resolving or flipping a verdict) aren't currently exposed in Settings.
- A `DanglingDnsSiblingLink` cross-linking an excluded shared-infra finding to its sibling `dangling_dns` finding on the same origin IP, when both fired for the same underlying cause.

## Relationship to Risk Scoring

Shared-infra classification runs *before* [risk scoring](risk-scoring.md) in the pipeline. `rejected_shared_infra` and `ownership_unverifiable` findings are excluded from the Risk Score calculation entirely — so a misattributed shared-hosting CVE never inflates your org's security score. SSVC/BOD-26-04 has no direct interaction with verification; it only evaluates findings that already survived this filter.
