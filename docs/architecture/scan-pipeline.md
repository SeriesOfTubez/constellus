# Scan Pipeline

## Continuous monitoring model

Constellus follows the Wiz / Censys pattern: the user adds targets, and the platform handles discovery, enrichment, and scanning on a recurring schedule. There is no scan-builder UI — scans are an implementation detail. The user-facing surface is **Targets**, **Assets**, **Findings**, and **Activity**.

The model rests on a small set of pieces:

- A **scan template** holds the durable identity of *what / how / when* to scan: scope, options, optional cron schedule, enabled flag, batching parameters, dynamic-scope flag, and an optional target-tag filter.
- A **scan run** is one execution of a template. Every run references its template via `template_id` (`SET NULL` on template delete).
- A single **default monitoring template** (fixed UUID `00000000-0000-0000-0000-000000000001`) is seeded on first startup. It runs daily at 02:00 UTC with `dynamic_scope=True` — at run time the executor reads the `targets` table and uses every target as scope, so adding a target automatically opts it into monitoring on the next tick.
- **Adding a target** fires a one-off initial-discovery run against just that target so the user sees results immediately rather than waiting for the next cron tick.
- **On-demand rechecks** (single-asset "Scan" button, future bulk asset/finding actions) create runs with `options.skip_discovery=True` and a tight scope — no Phase 1 discovery, no sibling re-enumeration.

| Trigger | Path |
|---|---|
| User adds a target | `POST /api/targets/` queues a `FastAPI BackgroundTask` to `scan_executor.launch` with scope = just that target. |
| APScheduler cron tick | Fires `_run_template`, which builds a run, resolves dynamic scope from `targets`, and hands it to `scan_executor.launch`. |
| On-demand recheck (asset / finding) | Per-asset or per-finding API endpoint creates a run with `options.skip_discovery=True`. |

The in-process scheduler (`app/services/scheduler.py`) starts on app lifespan startup, seeds the default monitoring template if absent, loads every enabled template with a `schedule_cron`, and refreshes its jobs live when templates are created / patched / disabled / deleted. Single-worker uvicorn is assumed; multi-worker deployments would need a shared job store or advisory-lock guard.

## Dynamic scope and batching

A template with `dynamic_scope=True` does not store a static `scope` — instead the executor resolves the target list at run start by querying the `targets` table (optionally filtered by `target_tag_filter`). This is what lets a single global template cover an unbounded number of targets without per-target template proliferation.

To avoid stampedes when a deployment has hundreds or thousands of targets, the executor processes the resolved scope in chunks:

- `scan_templates.batch_size` (nullable int) — domains + IP ranges per chunk; `NULL` means no chunking
- `scan_templates.batch_delay_seconds` (int, default 0) — sleep between chunks
- Each chunk runs the full Phase 1 → 2 → 3 pipeline against its slice of scope.
- A chunk that raises does not abort the run. The error is appended to `scan_runs.partial_failures` (jsonb list) and the next chunk proceeds.
- A run reports `COMPLETED` if every chunk ran (even with partial failures). `FAILED` is reserved for hard aborts (DB down, etc.).
- Post-scan CVE enrichment runs once at the end, across all chunks.

## Phases

### Phase 1: Discovery

Runs for every domain in scope. Built-in tools run first, then connector-based discovery.

#### Third-party infrastructure boundary

When passive resolution (`app/services/discovery/dns_resolve.py`) follows a CNAME chain, it only creates a scannable `dns_record` asset for a hostname that falls under one of your **declared target domains**. The first hop whose target *isn't* a subdomain of anything you've added as a Target is treated as the customer/third-party boundary: everything up to and including that hop is kept (the CNAME pointing at the boundary is retained and annotated so web-app scanning still runs against your own hostname via its correct SNI), and everything past it is suppressed rather than attributed to you.

The boundary **target itself** — the vendor or CDN hostname your record points at — is captured as a *context node*: recorded with a `cname` edge (relationship `dependency`) from your record, classified `estate = not_ours` and `probe_class = no_probe`. That node exists so a WHOIS check, takeover fingerprint or vendor-incident query has something to attach to; without it a CNAME to a lapsed third-party domain is just a string, and third-party attribution has nothing to reason about.

!!! warning "Capture is not scan eligibility"

    A captured third-party node is **never actively scanned**. It is excluded from the scan target list, projected `no_probe`, and — most durably — falls outside target scope by construction, because being outside every declared domain is exactly what made it the boundary in the first place. Vendor infrastructure is represented, not probed.

    These nodes are also hidden from the default asset list (`show_third_party` surfaces them), so recording a dependency doesn't inflate the inventory you read as *your* assets.

This is an **allowlist**, not a curated denylist of known CDN/SaaS suffixes — any shared-hosting provider (a CDN, a CMS platform, a page-builder's shared proxy) is suppressed automatically the first time you scan, whether or not Constellus has ever seen that provider before. A CNAME hop that lands on a *different* domain you've also declared as a target is correctly **not** treated as a boundary — the allowlist covers every target you own, not just the apex being resolved.

**Built-in tools** (per-scan options):

| Tool | Default | Type |
|---|---|---|
| subfinder | On | Passive |
| dnsrecon | Off | Active |
| Subdomain brute-force | Off | Active |

**Connector-based discovery:** enabled discovery connectors run for each domain in scope:

- **DNS connectors** (Cloudflare and similar) call `discover(domain)` against zones the operator owns.
- **Passive index connectors** (Certspotter, Shodan) call `index_lookup(domain)` to read CT logs and public DNS indexes.

#### Certificate Transparency: cache + background refresher

Certspotter (the connector backing the CT logs) is enabled by default and works with no configuration — the free tier is 100 req/hr, raised to 1000 req/hr by adding a free API token via **Admin → Connectors → Certificate Transparency**. The token can also be set via `CERTSPOTTER_API_TOKEN` in the environment; the UI value takes precedence.

The connector itself never blocks on the network — CT is treated as a **background-refreshed resource**:

- `ct_query_cache` holds the most recent issuance payload per domain.
- `app/services/ct_refresher.py` runs every 60 s. Each tick picks the oldest / missing entries and refreshes them at the allowed rate (~1/min unauthenticated, ~15/min with a token), spaced within the tick so we stay under the cap.
- The connector's `index_lookup()` reads `ct_query_cache` and returns immediately. Cache misses produce no CT data for that target this run.
- Newly added targets get one foreground Certspotter call from the target-add hook (`cert_transparency.prime_cache()`), so the user sees CT data on the very first scan rather than waiting for the next refresher tick.

### Phase 1.5: Port discovery & verification

Between discovery and enrichment, Constellus actively scans the public IPs found in Phase 1 for open TCP ports and verifies them. Connectors opt into this phase by exposing a duck-typed `port_scan(assets, config)` hook and run in `port_scan_order` so producers precede consumers:

1. **Naabu** discovers candidate open ports (tier-selected set) and re-validates them with `-verify`, dropping the phantom ports that SYN-flood-protected firewalls (SonicWall et al.) fake by completing handshakes on a fast scan.
2. **nmap `-sV`** (in the scanner-worker) verifies the survivors, identifies services, and drops anything it can only call `tcpwrapped`. Shodan-reported ports (`shodan_ports`) are hydrated onto the IP beforehand and folded in here, so they are confirmed by our own probe rather than trusted on Shodan's word.
3. **banner-grab, httpx, tlsx** enrich each confirmed port with banners, HTTP metadata, and TLS certificates.

Results are written as `open_ports[]` entries on each `ip_address` asset; the Assets API hides entries not re-confirmed in the latest scan (see staleness handling in the [Naabu connector](../connectors/naabu.md) doc, which covers the full pipeline and the firewall-deception problem it solves).

### Phase 2: Enrichment

Runs against all discovered assets. Enabled enrichment connectors (Tenable, Wiz, FortiManager) add context: open ports, software inventory, cloud metadata, NAT mappings.

### Phase 3: Scanning

Runs Nuclei against authorised targets only. Results are written as `Finding` records with `category`, `cve_id`, `cvss_score`, and `cwe` populated from the Nuclei classification block.

### Post-scan CVE enrichment

After Phase 3, findings with a `cve_id` are automatically enriched:

- **EPSS** — exploit probability score from FIRST.org (bulk API call). Also recorded to the `epss_history` hypertable (12-week rolling window) so the Finding view shows a trend sparkline + change indicator; a 12h scheduler job keeps it fresh for every CVE in active findings. See [data model](data-model.md).
- **CISA KEV** — checked against the full KEV list (cached daily)
- **NVD CVSS** — fallback only, for findings where Nuclei didn't provide CVSS
- **VulnCheck, vulnx, SSVC, and the Constellus Risk Score** run last, after shared-infrastructure verification (below) has excluded any misattributed findings — see [Risk Scoring](risk-scoring.md).

## Scan aggressiveness

Aggressiveness only affects the **active** phases — Naabu port discovery, nmap `-sV`, banner-grab/httpx/tlsx, Nuclei, dnsrecon, and subdomain brute-force. Passive sources (CT logs, subfinder, Shodan, DNS connectors) are unaffected by tier — they run the same regardless.

| Tier | Port scanning | Nuclei | Notes |
|---|---|---|---|
| `stealth` | Disabled (and everything downstream of it: banner-grab, httpx, tlsx) | Rate-limited (10 req/s), critical/high/medium severities only, excludes intrusive/fuzz/dos/default-login templates | Quietest option |
| `polite` *(default)* | Top 100 ports, moderate rate | Up to "low" severity | Small brute-force wordlist |
| `standard` | Top 1000 ports, higher concurrency | Includes "info" severity | Medium brute-force wordlist |
| `aggressive` | Full 65535-port range, highest rates (Nuclei 500 req/s) | Same as standard | Large brute-force wordlist |

`dos`-tagged Nuclei templates are excluded at **every** tier — aggressiveness controls scan intensity, not whether a scan is allowed to disrupt a target.

The effective tier is resolved by a **target > template/run > global** cascade (`app/services/aggressiveness.py::effective_for_target`): a per-target override (set on the Targets page) always wins if present; otherwise a per-run/template override; otherwise the org-wide default set in **Admin → Settings**.

## Monitoring policies

Beyond the single default daily template, you can layer **tag-based cadence tiers** on top: a monitoring policy is a `ScanTemplate` scoped to a target tag (`target_tag_filter`) with its own cron schedule and a `tag_priority` (lower number wins if a target matches multiple tagged policies). Manage these under **Admin → Settings → Monitoring policies** (`/api/monitoring/policies`) — for example, tag your production domains `prod` and scan them hourly while everything else stays on the daily default.

## Authorisation model

**`scan_authorisation_mode`** (**Admin → Settings**; API-only today, no dedicated UI control) gates whether *active* discovery and scanning tools are allowed to run against a domain's apex. Default is `disabled`.

| Mode | Gate |
|---|---|
| `disabled` *(default)* | No gate — active tools always run. |
| `acknowledge` | The apex domain just needs to exist as a Target row. |
| `strict` | The apex domain's Target must be `verified=true`. |

The check runs per-domain in two places — before Phase 1's active discovery tools, and again before Phase 3 scanning — via `is_scan_authorised()`. A domain that fails the check is skipped, not the whole run; the pipeline stays fail-soft and logs the skip.

In practice, most manually-added targets are auto-verified on creation (`verification_method='manual'`) on the theory that adding a target *is* the authorisation — the Add Target dialog warns you to only add infrastructure you own. Two other verification methods exist for cases where that implicit trust isn't appropriate:

- **TXT record** — add a `_constellus-verify.<domain>` TXT record with the token shown on the target's detail page, then click Verify.
- **Acknowledge** — for IP/CIDR targets, an explicit confirmation step in place of a DNS challenge.

A `connector` method also exists for targets pulled in automatically by a DNS connector sync (Cloudflare zones you already control are auto-verified), and `ptr_match` (reverse-DNS corroboration against an already-verified domain) is defined but not yet wired to a live code path.

## Findings triage

After a scan completes, findings appear in the Findings page. Each finding shows severity, category, and enrichment badges (CVSS, EPSS, KEV). Clicking a row opens a detail flyout.

Findings on shared-hosting infrastructure that can't be confidently attributed to you are pulled into a separate "Ownership Unverifiable" view rather than the default list — see [Shared Infrastructure & Dangling DNS](shared-infra-verification.md).

**Single-finding actions** (row buttons or flyout footer):

| Action | Description |
|---|---|
| Acknowledge | Marks the finding reviewed. Sets `acknowledged_by_id` and `acknowledged_at`. |
| Suppress | Hides the finding until a chosen date (7d / 30d / 90d / 1y). Requires `suppressed_until`. |
| Re-verify | Queues a new single-target scan. If the finding is not reproduced, it is auto-resolved. |
| Reopen | Returns a suppressed finding to `open`. |

**Bulk actions** — select multiple findings via checkboxes (header checkbox selects all visible rows), then use the bulk action bar:

- **Acknowledge** — marks all selected findings acknowledged
- **Suppress** — prompts for duration, then suppresses all selected findings
- **Reopen** — returns all selected findings to open

Bulk operations call `POST /api/findings/bulk/state`. Selection clears automatically when filters change.

## Asset deduplication

Assets are deduplicated by `(type, value)` within a scan. When multiple sources discover the same asset, their source identifiers are merged into the `sources[]` array.
