# Scan Pipeline

## Phases

### Phase 1: Discovery

Runs for every domain in scope. Built-in tools run first, then connector-based discovery.

**Built-in tools** (configured per scan run):

| Tool | Default | Type |
|---|---|---|
| Certificate Transparency | On | Passive |
| subfinder | On | Passive |
| dnsrecon | Off | Active |
| Subdomain brute-force | Off | Active |

**Connector-based discovery:** enabled DNS connectors (e.g. Cloudflare) run their `discover()` method for each domain and contribute assets.

### Phase 2: Enrichment

Runs against all discovered assets. Enabled enrichment connectors (Tenable, Wiz, FortiManager) add context: open ports, software inventory, cloud metadata, NAT mappings.

### Phase 3: Scanning

Runs Nuclei against verified targets only. Results are written as `Finding` records with `category`, `cve_id`, `cvss_score`, and `cwe` populated from the Nuclei classification block.

### Post-scan CVE enrichment

After Phase 3, findings with a `cve_id` are automatically enriched:

- **EPSS** — exploit probability score from FIRST.org (bulk API call)
- **CISA KEV** — checked against the full KEV list (cached daily)
- **NVD CVSS** — fallback only, for findings where Nuclei didn't provide CVSS

## Asset deduplication

Assets are deduplicated by `(type, value)` within a scan. When multiple sources discover the same asset, their source identifiers are merged into the `sources[]` array.
