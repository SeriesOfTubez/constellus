# Constellus

> *Connect the dots, find the truth.*

**External Attack Surface Management with end-to-end visibility.**

Constellus maps your public-facing attack surface from DNS records all the way through to the internal asset serving the traffic — including cloud resource identity, firewall NAT mappings, patch status, and vulnerability data. No commercial tool on the market provides this complete chain in a single solution.

[![Security Pipeline](https://github.com/SeriesOfTubez/constellus/actions/workflows/security.yml/badge.svg)](https://github.com/SeriesOfTubez/constellus/actions/workflows/security.yml)
![Python](https://img.shields.io/badge/python-3.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## The Problem

Commercial EASM tools (Cortex Xpanse, CrowdStrike Falcon Surface, Tenable ASM) stop at the perimeter. They see what's exposed externally but cannot answer:

- *Which cloud resource is actually behind this public IP?*
- *Which internal server is being NATed through the firewall?*
- *Is that server patched?*
- *Is the IPS sensor on the firewall rule in blocking mode or just logging?*

Constellus answers all of it.

---

## End-to-End Visibility Chain

```
Public DNS Record
    → Public IP + WAF Status
    → Open Ports + Services
    → Risk Findings (CVEs, misconfigs, exposed credentials, EOL software)
    → Cloud Asset (via Wiz)  OR  Internal Host (via FortiManager VIP)
    → Patch Status + Vulnerabilities (via Tenable)
```

---

## Features

- **DNS Discovery** — enumerate DNS records from Cloudflare-managed zones; detect WAF coverage gaps (direct-to-origin records)
- **Port & Service Scanning** — fast port discovery via Masscan, service fingerprinting via Naabu + httpx + Nmap
- **Risk Detection** — Nuclei-powered scanning with thousands of templates covering CVEs, misconfigurations, exposed files, default credentials, and EOL software
- **Cloud Correlation** — map public IPs to cloud resources via Wiz; resolves load balancer and CDN → origin mappings
- **On-Premises Correlation** — query FortiManager VIP objects to map public IPs to internal hosts; retrieve firewall ACLs and IPS sensor status
- **Patch Correlation** — cross-reference internal IPs with Tenable asset data for patch status and known vulnerabilities
- **Firewall Analysis** — compare scan results against firewall policy to detect shadow IT, stale ACL rules, and IPS gaps
- **Optional Connectors** — every integration can be enabled or disabled independently; the tool provides value at each layer
- **Change Tracking** — time-series storage (TimescaleDB) surfaces new exposures, remediated issues, and drift over time
- **RBAC** — four roles (Viewer, Admin, Report Admin, Integration Admin) with JWT-based authentication
- **SSO** — SAML 2.0 with IdP metadata URL support; seamlessly links existing local accounts to SSO identities on first login
- **Portable Secrets** — pluggable secrets provider (environment variables, Azure KeyVault, AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault) configured via setup wizard
- **Secure by Design** — hardened container images, SAST/SCA/secret scanning in CI/CD, audit logging, TDE

---

## Architecture

Constellus is a container-based pipeline. Each scanning stage runs in its own container, spun up on demand with no idle infrastructure.

```
Targets (CIDR / IPs / Domains)
    │
    ├─ DNS Discovery     Cloudflare API + cert transparency + subfinder
    │
    ├─ Port Discovery    Masscan container  (fast SYN scan)
    │
    ├─ Service Detection Naabu + httpx (web)  /  Nmap (non-HTTP)
    │
    ├─ Risk Detection    Nuclei container
    │
    └─ Asset Correlation
           Cloud    →  Wiz API / MCP
           On-Prem  →  FortiManager connector  →  Tenable API
```

### Stack

| Component | Technology |
|---|---|
| Backend API | Python 3.12 + FastAPI |
| Database | PostgreSQL 16 + TimescaleDB |
| Migrations | Alembic |
| Scan containers | Masscan, Naabu, httpx, Nmap, Nuclei (Docker) |
| Auth | JWT (local) + SAML 2.0 (SSO) via python3-saml |
| Secrets | Pluggable provider (env / Azure KV / AWS SM / GCP SM / HashiCorp Vault) |

---

## Connectors

All connectors are optional and independently togglable. Each has a **Test** button that validates credentials and connectivity before use.

| Connector | Category | What It Provides |
|---|---|---|
| Cloudflare | DNS | DNS records, WAF proxy status per record |
| Masscan | Scanning | Fast port discovery |
| Naabu | Scanning | Port scanning (ProjectDiscovery ecosystem) |
| httpx | Scanning | HTTP/S probing, tech fingerprinting |
| Nuclei | Risk Detection | CVEs, misconfigs, exposed files, default creds |
| Wiz | Cloud Correlation | Cloud resource identity and existing Wiz findings |
| FortiManager | On-Prem Correlation | VIP mappings, firewall ACLs, IPS sensor status |
| Tenable | Patch Correlation | Asset record, vulnerabilities, patch status |

> **FortiManager note:** If FortiManager lives in a restricted network enclave, deploy the FortiManager connector as a sidecar container in that network. It exposes a simple internal REST API — the main application never needs direct FortiManager access.

---

## Risk Findings

| Finding | Source |
|---|---|
| Vulnerable software / CVEs | Nuclei |
| Exposed admin panels | Nuclei |
| Default credentials | Nuclei |
| Exposed sensitive files (.env, .git, etc.) | Nuclei |
| EOL / unsupported software | Nuclei |
| TLS misconfigurations | Nuclei / httpx |
| Missing HTTP security headers | Nuclei / httpx |
| No WAF on direct-to-origin DNS record | Cloudflare |
| Port open externally but not in firewall policy | Masscan vs FortiManager |
| Stale firewall ACL (allowed but not listening) | FortiManager vs Masscan |
| IPS sensor in monitor-only mode | FortiManager |
| No IPS sensor on inbound policy | FortiManager |
| Unpatched internal asset | Tenable |

---

## Getting Started

### Prerequisites

- Docker + Docker Compose
- Python 3.12 (for local backend development)
- A GitHub account (for CI/CD)

### Local Development

```bash
# Clone the repo
git clone https://github.com/SeriesOfTubez/constellus.git
cd sextant

# Configure environment
cp .env.example .env
# Edit .env — generate a SECRET_KEY with:
# python -c "import secrets; print(secrets.token_hex(32))"

# Start the database
docker compose up db -d

# Set up a Python virtual environment
cd backend
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run database migrations
alembic upgrade head

# Start the API
uvicorn app.main:app --reload
```

The API will be available at `http://localhost:8000`.  
Interactive docs: `http://localhost:8000/docs`

### First Run

On a fresh install, create the first admin account:

```bash
curl -X POST http://localhost:8000/api/auth/setup \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "changeme", "full_name": "Admin"}'
```

This endpoint is only available when no users exist. It is automatically disabled after the first account is created.

### Full Stack (Docker Compose)

```bash
docker compose up --build
```

---

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env` and populate the values.

| Variable | Description |
|---|---|
| `SECRET_KEY` | JWT signing key — generate with `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DATABASE_URL` | PostgreSQL connection string |
| `SECRETS_PROVIDER` | `env` \| `azure_keyvault` \| `aws` \| `gcp` \| `hashicorp_vault` |
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token (Zone.DNS read) |
| `WIZ_CLIENT_ID` | Wiz service account client ID |
| `WIZ_CLIENT_SECRET` | Wiz service account client secret |
| `WIZ_API_ENDPOINT` | Wiz GraphQL API endpoint |
| `FORTIMANAGER_CONNECTOR_URL` | Internal URL of the FortiManager connector sidecar |
| `FORTIMANAGER_CONNECTOR_API_KEY` | API key for the FortiManager connector |
| `TENABLE_API_KEY` | Tenable.io access key |
| `TENABLE_API_SECRET` | Tenable.io secret key |

### Secrets Provider

Constellus reads all secrets from environment variables. What populates those variables is pluggable — point the setup wizard at your vault and Constellus handles the rest.

| Deployment | Provider | Bootstrap |
|---|---|---|
| Local dev | `.env` file | Manual |
| GitHub Actions | GitHub Environment Secrets | Automatic |
| Azure (ACI) | Azure KeyVault | Managed Identity |
| AWS | AWS Secrets Manager | IAM Role |
| On-premises | HashiCorp Vault | AppRole |

---

## Authentication

### Local Accounts

Constellus ships with email/password authentication using bcrypt password hashing and short-lived JWT access tokens (30 min) with rotating refresh tokens (7 days).

### SAML SSO

SAML 2.0 is supported via [python3-saml](https://github.com/SAML-Toolkits/python3-saml). Configure it by pointing Constellus at your IdP's metadata URL — the app fetches and parses it automatically.

**Seamless account migration:** When SSO is enabled, existing local accounts are automatically linked to their SSO identity on first login (matched by email). Roles and settings are preserved. No manual account recreation or RBAC reassignment required.

**JIT provisioning:** Optionally auto-create accounts for users who authenticate via SSO but don't have a local account yet.

**Local fallback:** Optionally keep password login available during the transition period, then disable it once SSO is fully rolled out.

Configure SSO at `PATCH /api/auth/saml/config` (Integration Admin role required).

### RBAC Roles

| Role | Permissions |
|---|---|
| **Viewer** | Read-only access to scan results, findings, and asset inventory |
| **Admin** | Full access including scan configuration and user management |
| **Report Admin** | Create, schedule, and export reports; read access to all data |
| **Integration Admin** | Enable/disable connectors, manage API keys and SAML configuration |

---

## Deployment

### Azure (Recommended for Production)

```
Internet
    → Azure Application Gateway (WAF)
    → ACI containers (VNet-integrated)
    → Azure PostgreSQL Flexible Server (Private Endpoint)
    → Azure KeyVault (Managed Identity)
```

Key controls:
- Managed Identity on all containers — no static credentials
- Private Endpoints for database and KeyVault — no public exposure
- TDE on Azure PostgreSQL (default)
- Separate subnets per tier (app / data / connectors)
- Azure Monitor + Log Analytics for centralised logging

### On-Premises (Self-Hosted)

```
Internet
    → Caddy / Nginx (TLS termination)
    → Docker bridge networks (app containers)
    → PostgreSQL (encrypted volume, separate network)
    → HashiCorp Vault (secrets)
```

Key controls:
- Non-root container user
- Docker bridge networks for segmentation — no `--network=host`
- LUKS encryption on PostgreSQL data volume (TDE equivalent)
- Structured JSON logs shipped to Loki + Grafana
- Falco for container runtime anomaly detection

---

## Security

### CI/CD Pipeline

Every pull request runs the following checks automatically. The build stage only runs if all security checks pass.

| Tool | Check |
|---|---|
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secret scanning |
| [Semgrep](https://github.com/semgrep/semgrep) | SAST (OWASP Top 10, security audit) |
| [Trivy](https://github.com/aquasecurity/trivy) | SCA — vulnerable dependencies |
| [Checkov](https://github.com/bridgecrewio/checkov) | IaC — Dockerfile and GitHub Actions |
| [Hadolint](https://github.com/hadolint/hadolint) | Dockerfile best practices |
| Trivy (image) | Container image CVE scan on build |

### Audit Logging

All security-relevant events are written to an append-only audit log:

- Authentication (login, logout, failed attempts)
- Scan initiated / completed / failed
- Connector enabled / disabled / configured
- Finding acknowledged or suppressed
- User created / modified / deactivated
- Role assignment changes

---

## Contributing

Contributions are welcome. Please open an issue before submitting a pull request for significant changes.

All submitted code runs through the security pipeline. PRs that introduce findings in Gitleaks, Semgrep, or Trivy at HIGH or CRITICAL severity will not be merged until resolved.

### Adding a Connector

1. Create `backend/app/connectors/yourconnector.py` implementing `BaseConnector`
2. Implement `test()`, `get_config_schema()`, and `is_configured()`
3. Register it in `backend/app/api/connectors.py`
4. Add required secrets to `.env.example` with descriptive comments
5. Document the connector in this README

---

## License

MIT — see [LICENSE](LICENSE)
