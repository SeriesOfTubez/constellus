# Architecture Overview

## Stack

| Layer | Technology |
|---|---|
| Frontend | React + Vite + TanStack Query + shadcn/ui |
| Backend | FastAPI + SQLAlchemy |
| Database | TimescaleDB (PostgreSQL 16) |
| Auth | JWT + SAML SSO |
| Background jobs | FastAPI BackgroundTasks (per-scan execution) + APScheduler (scheduled scans) |

## High-level flow

```
User adds Target (domain / IP / CIDR)
    ↓
Initial discovery run fires immediately (BackgroundTask)
    +
Daily default monitoring template runs all targets via dynamic scope
    ↓
Phase 1: Discovery    → CT logs, subfinder, dnsrecon, DNS connectors
    ↓
Phase 2: Enrichment  → Tenable, Wiz, FortiManager, Shodan
    ↓
Phase 3: Scanning    → Nuclei
    ↓
Post-scan enrichment → CVSS (NVD), EPSS (FIRST.org), KEV (CISA)
    ↓
Findings + Assets stored in TimescaleDB (identity in canonical tables)
```

## Key design decisions

- **Continuous monitoring, not scan-builder** — there is no scan-creation UI. Targets are the user-facing handle; a single global default template (`dynamic_scope=True`) covers every target on a daily schedule, and adding a target queues an immediate one-off run for fast first-impression results. See [scan-pipeline.md](scan-pipeline.md).
- **Identity / observation split** — `assets_canonical`, `findings_canonical`, and `scan_templates` hold durable identity; `assets`, `findings`, and `scan_runs` hold observations. The UI reads from canonical; observations are time-series audit data (and the `assets` / `findings` hypertables are being retired).
- **Polymorphic FK edges** — `asset_edges` connects any two graph nodes via `(source_type, source_id)` / `(target_type, target_id)` + `edge_type` (text + `CHECK`, not Postgres enum). A trigger validates referenced rows exist. See [data-model.md](data-model.md#graph-edges).
- **No Celery** — one-shot scans (target-add, on-demand rechecks) run as FastAPI `BackgroundTasks`; scheduled scans are fired by an in-process APScheduler BackgroundScheduler (`app/services/scheduler.py`). Both queue work into the same `scan_executor.launch` entry point.
- **Chunked execution** — templates with `dynamic_scope=True` resolve scope from the `targets` table at run start and process it in chunks (`batch_size` / `batch_delay_seconds`). Per-chunk failures are captured in `scan_runs.partial_failures` rather than aborting the run.
- **TimescaleDB hypertables** — `audit_logs` and `system_logs` remain hypertables. The `assets` and `findings` hypertables are transitional and will be dropped once their last consumers move to canonical.
- **Authorisation by adding** — adding a target is the authorisation. The Add Target dialog warns the user; the verification / acknowledgement backend is preserved but not surfaced in the current UI.
- **Connector phases** — connectors are typed by phase so the executor runs them in the correct order without hardcoding.
