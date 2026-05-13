# Architecture Overview

## Stack

| Layer | Technology |
|---|---|
| Frontend | React + Vite + TanStack Query + shadcn/ui |
| Backend | FastAPI + SQLAlchemy |
| Database | TimescaleDB (PostgreSQL 16) |
| Auth | JWT + SAML SSO |
| Background jobs | FastAPI BackgroundTasks (no Celery) |

## High-level flow

```
Targets (verified domains/IPs)
    ↓
Scan Run created
    ↓
Phase 1: Discovery    → CT logs, subfinder, dnsrecon, DNS connectors
    ↓
Phase 2: Enrichment  → Tenable, Wiz, FortiManager
    ↓
Phase 3: Scanning    → Nuclei (verified targets only)
    ↓
Post-scan enrichment → CVSS (NVD), EPSS (FIRST.org), KEV (CISA)
    ↓
Findings + Assets stored in TimescaleDB
```

## Key design decisions

- **No Celery** — scan phases run as FastAPI `BackgroundTasks`. Sufficient for the current scale; Celery can be added when task queue management is needed.
- **TimescaleDB hypertables** — `assets`, `findings`, and `audit_logs` are time-series hypertables. Enables trending, regression detection, and time-based queries at scale.
- **Verified targets gate** — active tools (dnsrecon, brute-force, Nuclei) only run against domains you've proven ownership of via DNS TXT record or explicit acknowledgement.
- **Connector phases** — connectors are typed by phase so the executor runs them in the correct order without hardcoding.
