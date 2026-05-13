# Data Model

## Key tables

| Table | Type | Description |
|---|---|---|
| `scan_runs` | Standard | A single scan execution with scope and status |
| `assets` | Hypertable | Discovered assets partitioned by `discovered_at` |
| `findings` | Hypertable | Vulnerability findings partitioned by `discovered_at` |
| `targets` | Standard | Verified domains, IPs, and CIDRs in scope |
| `audit_logs` | Hypertable | Immutable audit trail partitioned by `occurred_at` |
| `connector_configs` | Standard | Encrypted connector credentials |
| `system_logs` | Hypertable | Application logs with configurable retention |
| `app_settings` | Standard | Key-value configuration store |

## TimescaleDB hypertables

`assets`, `findings`, and `audit_logs` are TimescaleDB hypertables. This enables:

- Time-range queries across large datasets without full table scans
- Automatic chunk compression for older data
- Continuous aggregates for trend reporting

!!! warning
    TimescaleDB hypertables require `TEXT` columns, not `VARCHAR(n)`. All string columns on hypertables use `Text` in the SQLAlchemy model.
