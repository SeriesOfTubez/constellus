# Data Model

## Identity vs. observation split

Constellus separates **what something is** (durable identity) from **when we saw it** (observation event). For scans this remains a split; for assets and findings the legacy observation hypertables were dropped in migration 0025 once readers moved off them — `last_seen_at` on the canonical row plus the `scan_runs` log carries enough history for the current UI.

| Entity | Identity (durable) | Observation log |
|---|---|---|
| Scans | `scan_templates` — scope, options, schedule, owner | `scan_runs` — one execution per fire with started_at / completed_at / status / kind / asset_count / finding_count |
| Assets | `assets_canonical` — one row per (asset_type, value), and per (asset_type, value, record_type, content) for `dns_record`; first_seen_at, last_seen_at, ignored, tags | `asset_claims` — per-observer current values, with `claim_history` as the append-only change log |
| Findings | `findings_canonical` — one row per (asset_canonical_id, finding_type, source, fingerprint); state, suppressed_until, first_seen_at, last_seen_at | (none — `last_seen_at` only) |

## Key tables

| Table | Type | Description |
|---|---|---|
| `scan_templates` | Standard | Scan identity — scope, options, optional cron schedule, enabled flag, `tag_priority` for cadence tiers |
| `scan_runs` | Standard | One execution (status, kind, started_at / completed_at / error, template_id, asset_count, finding_count, partial_failures) |
| `assets_canonical` | Standard | One row per (asset_type, value); durable identity surfaced in the UI |
| `findings_canonical` | Standard | One row per (asset, type, source, fingerprint); durable identity |
| `target_asset_links` | Standard | N-to-N join between `targets` and `assets_canonical` with refcount semantics |
| `asset_edges` | Standard | Typed directed edges between graph nodes (polymorphic FK) |
| `asset_claims` | Standard | **Current-state store.** One row per (asset, observer, claim_type) — what a given producer currently asserts about an asset |
| `asset_state` | Standard | Projection of `asset_claims` down to one row per asset: `open_ports`, `estate`, `hosting`, `eol_summary`, `attributes` |
| `claim_history` | Partitioned | Append-only log of claim *changes*, range-partitioned monthly on `changed_at` (24-month retention) |
| `claim_types` | Reference | Claim vocabulary + per-type authorisation/reporting TTL policy |
| `observers` | Reference | Registry of claim producers with their kind / trust / addressing taxonomy |
| `edge_type_relationships` | Reference | Maps an `edge_type` to its attribution relationship (`dependency`, `recipient`) |
| `targets` | Standard | Domains, IPs, and CIDRs in scope (with `source_type` + `auto_managed`) |
| `audit_logs` | Hypertable | Immutable audit trail partitioned by `occurred_at` |
| `connector_configs` | Standard | Encrypted connector credentials |
| `system_logs` | Hypertable | Application logs with configurable retention |
| `app_settings` | Standard | Key-value configuration store |
| `monitoring_policy_overrides` (via `scan_templates`) | — | Cadence tiers are scan_templates with `tag_priority` populated; managed through `/api/monitoring/policies` |
| `notification_rules` | Standard | Severity / category / recipient rules for finding-landed notifications |
| `ct_query_cache` | Standard | Certspotter response cache, populated by the background refresher |

## Findings schema

The `findings_canonical` table captures durable identity for every finding. Key columns:

| Column | Type | Description |
|---|---|---|
| `id` | UUID | Primary key |
| `asset_canonical_id` | UUID | FK to `assets_canonical` (CASCADE on delete) |
| `finding_type` | text | Nuclei template ID or connector-specific type |
| `source` | text | `nuclei`, `cloudflare`, `fortimanager`, `tenable`, `shodan`, `manual` |
| `fingerprint` | text | Source-specific uniqueness key — see Finding fingerprinting below |
| `severity` | text | `critical`, `high`, `medium`, `low`, `info` |
| `category` | text | Normalized category — see below |
| `state` | text | `open`, `acknowledged`, `suppressed`, `resolved` |
| `suppressed_until` | timestamptz | Populated when state = `suppressed` |
| `cve_id` | text | CVE identifier extracted from template tags or classification block |
| `cvss_score` | float | CVSS base score (from Nuclei classification or NVD fallback) |
| `cvss_vector` | text | Full CVSS vector string |
| `cvss_version` | text | `4.0`, `3.1`, `3.0`, or `2.0` |
| `epss_score` | float | FIRST.org EPSS exploit probability (0–1) |
| `epss_percentile` | float | EPSS percentile (0–1) |
| `kev` | bool | True if CVE appears in CISA Known Exploited Vulnerabilities list |
| `kev_date_added` | date | Date the CVE was added to KEV |
| `cwe` | text | CWE identifier from Nuclei classification |
| `first_seen_at`, `last_seen_at` | timestamptz | Lifecycle timestamps; `last_seen_at` advances on every observation |
| `detail` | JSONB | Raw connector output (Nuclei: matched_at, tags, references, curl_command) |

The `epss_score` / `epss_percentile` columns hold the **latest** sample for convenience. The full **trend history** lives separately in the `epss_history` hypertable — one row per `(cve_id, recorded_date)` with an 84-day (12-week) TimescaleDB retention policy. It's keyed by CVE, not per-finding, because EPSS is a CVE-level fact mirrored across findings. A 12h scheduler job refreshes today's sample for every CVE in active findings, and new CVEs are backfilled with 12 weekly-spaced points. Backs the EPSS sparkline + change indicator on the Finding detail view (`epss_history_service.py`, `GET /findings/{id}/epss-history`).

### Finding categories

Populated at ingest by `app/services/finding_category.py`. First matching rule wins:

| Category | Matched Nuclei tags |
|---|---|
| `cve` | `cve` |
| `app_security` | `sqli`, `xss`, `rce`, `ssrf`, `lfi`, `xxe`, `ssti`, `injection`, `traversal`, `idor`, `csrf`, `deserialization`, `upload`, `open-redirect` |
| `exposed_asset` | `panel`, `unauth`, `login`, `debug`, `backup`, `exposure` |
| `information_disclosure` | `info-disclosure`, `leakage`, `logs`, `token`, `api-key`, `disclosure`, `secret`, `leak` |
| `configuration` | `misconfig`, `default-login`, `default-password`, `default-credential` |
| `network_security` | `network`, `firewall`, `ssl`, `tls`, `dns`, `port` |
| `outdated_software` | `eol`, `outdated`, `version`, `end-of-life` |
| `other` | anything not matched above |

### Finding state lifecycle

```
open → acknowledged  (analyst reviews, confirms it's real)
open → suppressed    (intentionally accepted for a fixed duration)
open/acknowledged → resolved  (re-verification scan finds the issue no longer present)
suppressed → open    (suppression expires or analyst reopens)
```

State transitions are logged with `acknowledged_by_id` and `acknowledged_at`. Bulk state updates are available via `POST /api/findings/bulk/state`.

## Claims layer

Asset attributes used to live in a single untyped `metadata` JSONB blob on `assets_canonical`, shallow-merged by every producer. That had no per-observer attribution (a value could never be traced, aged, or retired), no schema, and accumulate-only semantics — a signal that disappeared never cleared. It was replaced by the claims layer and dropped in migration 0043.

| Concept | Table | What it answers |
|---|---|---|
| **Who says what, now** | `asset_claims` | One row per (asset, observer, claim_type). naabu's port list and Shodan's port list are separate rows — conflicting values are preserved, not merged away |
| **What changed, when** | `claim_history` | Append-only. A re-observation of an *unchanged* value bumps `last_observed_at` and writes nothing here; only a changed value appends |
| **The current view** | `asset_state` | One row per asset, projected from its claims: `open_ports`, `estate`, `hosting`, `eol_summary`, `attributes` |
| **Who is allowed to say it** | `observers` | Each producer's kind (scan / discovery / connector / verify / enrich), trust, and addressing mode |

Two properties this buys that the blob could not:

- **Absence is queryable.** "An internet-visible asset with no EDR claim and no device-management claim" is a real query now. Against a flat dict, a missing key and an unobserved fact were indistinguishable.
- **Estate is derived, not asserted.** `asset_state.estate` (`proven_ours` / `claimed_ours` / `not_ours`) comes from claims with observers and timestamps behind them, which is what makes it safe to *reject* a finding rather than merely flag it.

The API still serves an `asset_metadata` object, but it is **reconstructed per request** by `app/services/metadata_bridge.py` from claims + `asset_state` + columns — the frontend contract outlived the column.

### Querying the claims layer

`app/services/claims_query.py` is the query surface every consumer of the claims layer reads through — the epic's mechanical predicates are `surface(asset)` and the absence primitive below, not an ad hoc re-query of `asset_claims`/`asset_state`.

**`surface(asset)`** is the estate tri-state plus a fourth, query-layer-only value: `proven_ours`, `claimed_ours`, `not_ours`, or `unknown`. `asset_state.estate` itself stays nullable — the projector deliberately never invents a stored default when there is no ownership signal — so `unknown` is a *read-time mapping* over a `NULL` estate (or over an asset with no `asset_state` row at all), not a value anything ever writes. That mapping matters because `unknown` must rank *below* `not_ours`: a machine nothing reports on is a machine nobody is managing, which is a worse finding than one positively excluded as someone else's. `surface(asset) == "not_ours"` is the exclusion predicate the rest of the codebase keys off (`app/api/assets.py`'s third-party filter included) — never the IONIX operational-layer view, which is ontological and reporting-only.

**The absence primitive** — "no claim of type T, optionally from observer O" — is what makes a claim's *absence* a first-class, queryable fact instead of indistinguishable from an unobserved one. `missing_claim_asset_ids` / `assets_missing_claim` express it as a NOT-IN/NOT-EXISTS over `asset_claims`, so an asset with zero claims of any kind is correctly returned, not silently excluded by an anti-join that assumes some other row exists. The worked example the epic is built around: **an internet-visible asset with no EDR claim and no device-management claim is an unmanaged asset** — the foundation for planning#130's Coverage/unmanaged hygiene dimension, where the same unknown-ranks-below-not_ours inversion applies: an asset nothing reports coverage for is worse than one confirmed out of scope, not better.

**Reporting vs. authorisation TTL:** neither `surface()` nor the absence primitive applies any TTL — `claim_types.authorisation_ttl` is the freshness window the cross-epic probe-authorisation gate reads at authorisation time, while these are reporting-time consumers with no `reporting_ttl` policy seeded yet.

**Endpoints** (`app/api/claims.py`): `GET /api/claims/surface/{asset_id}` returns `{asset_id, surface}`; `GET /api/claims/absence?claim_type=&observer=&asset_type=&surface=&include_ignored=&limit=` returns a list of `{asset_id, asset_type, value, last_seen_at, surface}`, with `claim_type` required and an unrecognised `claim_type` / `observer` / `surface` value rejected as 422 rather than silently matching everything.

## Graph edges

`asset_edges` connects any two graph nodes using a **polymorphic FK** pattern:

| Column | Description |
|---|---|
| `source_type`, `source_id` | Type tag + id of the source node |
| `target_type`, `target_id` | Type tag + id of the target node |
| `edge_type` | Relationship vocabulary (`text` with `CHECK` constraint, not Postgres enum) |
| `weight` | Optional float, populated only for edges relevant to attack-path scoring |
| `first_seen_at`, `last_seen_at` | Observation window |
| `metadata` | JSONB context |

A trigger function (`asset_edges_validate_endpoints`) enforces app-level FK integrity by checking the referenced row exists in the right table on insert/update. Text + CHECK was chosen over Postgres enum because adding new edge types is just a migration that loosens the constraint, no `ALTER TYPE` dance.

**Edge vocabulary:**

| `edge_type` | Source → Target | Purpose |
|---|---|---|
| `resolves_to` | `dns_record` → `ip_address` / `dns_record` | DNS resolution chain (A / AAAA, and CNAME hops between owned names) |
| `cname` | `dns_record` → `dns_record` | The customer → third-party CNAME boundary specifically |
| `runs_service` | `ip_address` → service asset | What's listening |
| `has_finding` | `asset_canonical` → `finding_canonical` | Asset is affected by a finding |
| `registered_to` | `asset_canonical` → `whois_org` | WHOIS / RDAP ownership |
| `discovered_in_target` | `asset_canonical` → `target` | Provenance — which target surfaced this asset |
| `belongs_to_apex` | subdomain → apex `dns_record` | Domain hierarchy |

!!! note "Why `cname` is separate from `resolves_to`"

    `resolves_to` is DNS mechanics, shared with A/AAAA records. `cname` carries
    the **attribution** axis — its `edge_type_relationships` row is
    `dependency`, and it is only emitted for the hop that crosses from
    customer-owned infrastructure to a third party. Tagging `resolves_to` as a
    dependency instead would make an A record pointing at the org's *own* IP
    read as a third-party dependency. The boundary hop emits `cname` **instead
    of** `resolves_to`, never both.

    Ports stopped being first-class asset nodes in migration 0029, so the old
    `has_open_port` edge no longer exists — ports live on
    `asset_state.open_ports`.

`target_asset_links` parallels the `discovered_in_target` edges but is a denormalized fast-path table optimized for "give me all assets for target X." It also carries refcount semantics: an asset is garbage-collected when its link count reaches zero.

## Finding fingerprinting

`findings_canonical` is unique on `(asset_canonical_id, finding_type, source, fingerprint)`. The `fingerprint` is source-specific:

| Source | Fingerprint |
|---|---|
| Shodan CVE finding | `cve_id` |
| Shodan tag finding (malware / honeypot etc.) | tag name |
| Nuclei finding (CVE) | `cve_id` |
| Nuclei finding (non-CVE) | `template_id` |
| WHOIS expiry | `expiry:{domain}` |
| Fallback | `{finding_type}:{title}` |

The writer re-opens a `resolved` canonical finding when it's observed again; the `verify` endpoint marks one resolved when a fresh scan didn't re-observe it (checked via `last_seen_at` advancement past the scan start time).

## TimescaleDB hypertables

`audit_logs` and `system_logs` are the only remaining TimescaleDB hypertables. They retain hypertable semantics for:

- Time-range queries across large log volumes without full table scans
- Automatic chunk compression for older data
- Continuous aggregates for trend reporting

!!! warning
    TimescaleDB hypertables require `TEXT` columns, not `VARCHAR(n)`. All string columns on hypertables use `Text` in the SQLAlchemy model.

!!! note
    The transitional `assets` and `findings` hypertables were dropped in migration 0025 once every reader had moved to canonical. Aggregate counts the Activity feed used to derive from those tables now live as `asset_count` and `finding_count` columns on `scan_runs`, populated by the executor at run completion. Identity lives on `assets_canonical` and `findings_canonical`; per-observation time-series is no longer kept.
