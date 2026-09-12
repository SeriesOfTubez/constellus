# Constellus

> *Connect the dots, find the truth.*

**Open Source External Attack Surface Management**

[![Security Pipeline](https://github.com/SeriesOfTubez/constellus/actions/workflows/security.yml/badge.svg)](https://github.com/SeriesOfTubez/constellus/actions/workflows/security.yml)
[![Docs](https://readthedocs.org/projects/constellus/badge/?version=latest)](https://constellus.readthedocs.io)
![Status](https://img.shields.io/badge/status-pre--alpha-orange)
![Python](https://img.shields.io/badge/python-3.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

> [!WARNING]
> **Pre-Alpha — Work in Progress**
> Constellus is in active development and not yet suitable for production use. The core platform is functional but incomplete. APIs, data models, and configuration may change without notice between releases.
>
> Feedback, bug reports, and contributions are welcome.

> [!NOTE]
> **Branch policy:** `dev` is the default branch and contains the latest in-progress code. If you want to deploy or evaluate Constellus, clone from **`main`** — it tracks stable, tested releases only. Everything merged to `main` has passed the full security pipeline and a manual promotion review from `dev`.

---

## What it does

Constellus discovers, correlates, and risk-scores your public-facing infrastructure — from DNS records through to open ports, exposed services, and active vulnerabilities.

```
Target (domain / IP / CIDR)  ── added by an admin ──┐
    │                                                │
    │ daily monitoring run                           │ initial discovery
    ▼                                                ▼
Phase 1: Discovery    → CT logs, subfinder, dnsrecon, DNS connectors (Cloudflare)
    ↓
Phase 2: Enrichment  → Tenable, Wiz, FortiManager, Shodan
    ↓
Phase 3: Scanning    → Nuclei (CVEs, misconfigs, exposed services, default creds)
    ↓
Post-scan enrichment → CVSS (NVD) · EPSS exploit probability · CISA KEV status
    ↓
Findings + Assets stored in TimescaleDB
```

---

## Current state

### Built and functional

- **Auth** — JWT + SAML 2.0 SSO, RBAC (Admin / Viewer / Integration Admin / Report Admin), setup wizard
- **Targets** — Domain / IP / CIDR management; adding a target authorises it and queues an initial discovery run
- **Continuous monitoring** — a single seeded default template runs all targets daily via dynamic-scope resolution; chunked execution with per-chunk fail-soft so a few bad targets don't kill the run
- **Connectors** — Cloudflare (DNS discovery), Shodan / Tenable / Wiz / FortiManager (enrichment), Nuclei (scanning), Mailtrap (notifications)
- **Scan pipeline** — 3-phase executor: Discovery → Enrichment → Scanning (FastAPI BackgroundTasks + APScheduler)
- **Built-in discovery** — CT logs (Certspotter), subfinder, dnsrecon, subdomain brute-force; passive DNS resolution against public recursors so discovered names carry real record types + IPs
- **Findings** — Triage (acknowledge / suppress / re-verify), CVSS / EPSS / KEV enrichment, category taxonomy
- **Assets** — Source badges, ignore/restore, on-demand scan, flyout detail panels; grouped by apex domain; apex-level deletion with auto-exclusion from source connector
- **WHOIS enrichment** — IP RDAP (org, ASN) and domain WHOIS (registrar, registrant, expiry) surfaced lazily in asset detail; persistent DB cache
- **Admin** — Connector config, structured log viewer with retention policy, audit trail

### Planned

- Firewall NAT correlation (FortiManager VIP mappings, Cisco FMC, Palo Alto)
- Emerging threats feed (CISA KEV, NVD, GitHub Security Advisories) with asset correlation
- AppSec connectors (Dependabot, Snyk) for package-level vulnerability correlation
- Armis asset enrichment
- Tagging system with auto-tag rulesets
- Reports

---

## Quick start

**Prerequisites:** Docker + Docker Compose

```bash
git clone --branch main https://github.com/SeriesOfTubez/constellus.git
cd constellus

# Configure environment
cp .env.example .env
# Edit .env — set at minimum:
#   SECRET_KEY             — generate with: openssl rand -hex 32
#   SCANNER_INTERNAL_TOKEN — generate with: openssl rand -hex 32

# Start the stack
docker compose up -d
```

Navigate to [http://localhost:3000](http://localhost:3000) and complete the setup wizard.

📖 [Full documentation →](https://constellus.readthedocs.io)

---

## Stack

| Layer | Technology |
|---|---|
| Frontend | React + Vite + TanStack Query + shadcn/ui |
| Backend | Python 3.12 + FastAPI |
| Database | TimescaleDB (PostgreSQL 16) |
| Auth | JWT + SAML 2.0 (python3-saml) |
| Background jobs | FastAPI BackgroundTasks |
| Scanning | Nuclei (dedicated sidecar container) |

---

## Connectors

All connectors are optional and independently togglable via **Admin → Connectors**.

| Connector | Phase | What it provides |
|---|---|---|
| Cloudflare | Discovery | DNS records, WAF proxy status |
| Shodan | Discovery + Enrichment | Passive subdomain index (/dns/domain); per-IP open ports, services, banners, known CVEs |
| Tenable | Enrichment | Asset inventory, patch status, vulnerabilities |
| Wiz | Enrichment | Credentialed proof a public IP belongs to a cloud resource you control (Wiz findings not yet ingested) |
| FortiManager | Enrichment | Asset and policy data |
| Nuclei | Scanning | CVEs, misconfigs, exposed panels, default credentials |
| Mailtrap | Notification | Email alerts (sandbox + live) |

---

## Security pipeline

Every push runs the following checks automatically. The build only proceeds if all security checks pass.

| Tool | Check |
|---|---|
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secret scanning |
| [Semgrep](https://github.com/semgrep/semgrep) | SAST (OWASP Top 10, security audit) |
| [Trivy](https://github.com/aquasecurity/trivy) | SCA — vulnerable dependencies |
| [Checkov](https://github.com/bridgecrewio/checkov) | IaC — Dockerfile and GitHub Actions |
| [Hadolint](https://github.com/hadolint/hadolint) | Dockerfile best practices |
| Trivy (image) | Container image CVE scan |

---

## About this project

Constellus is designed and maintained by a security practitioner with experience across security engineering, network security, DevOps, AppSec, and security architecture.

**This project uses AI-assisted development.** The implementation is written with [Claude](https://claude.ai) (Anthropic) as a coding assistant. The architecture, security requirements, threat model, and domain decisions are authored by the human maintainer. This is disclosed openly — AI-generated code has different failure modes than human-written code, and the security community deserves to know.

The security pipeline exists precisely because of this. Every commit is scanned for secrets, SAST findings, vulnerable dependencies, and IaC misconfigurations. No finding at HIGH or CRITICAL severity ships.

---

## Transparency

### Software Bill of Materials

A CycloneDX SBOM covering the full dependency tree and built container image is generated on every CI run and attached as a workflow artifact. See the [Actions tab](https://github.com/SeriesOfTubez/constellus/actions) for the latest.

### Security policy

To report a vulnerability, please use [GitHub Security Advisories](https://github.com/SeriesOfTubez/constellus/security/advisories/new) rather than a public issue.

---

## Contributing

Contributions are welcome. Please open an issue before submitting a PR for significant changes.

All submitted code runs through the security pipeline. PRs with HIGH or CRITICAL findings in Gitleaks, Semgrep, or Trivy will not be merged until resolved.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development principles, the AI assistance policy, and dependency standards.

---

## License

MIT — see [LICENSE](LICENSE)
