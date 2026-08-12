# Naabu Connector

**Phase:** Port discovery & verification (Phase 1.5 — between Discovery and Enrichment)
**Purpose:** Active TCP port discovery on public IP assets, with nmap verification and service enrichment

## What it finds

For every public IP discovered during Phase 1 (DNS resolution, Shodan index, CT log → DNS resolve, etc.), Naabu probes a tier-selected port set and records each confirmed-open port as an entry in the `open_ports[]` metadata array on the parent `ip_address` asset. Each entry is `{port, protocol, sources, last_seen_at, naabu_tier, …}`; the service enrichers (nmap, banner-grab, httpx, tlsx) merge their findings into the same per-port entry, adding `service`, `service_version`, `http_title`, `cert_summary`, etc.

Ports are modelled as **properties of a host**, not as standalone graph nodes — the same model every major EASM uses (Tenable, Qualys, Shodan, Censys, Defender EASM). Findings against a port attach to the IP with `port` in their metadata. Naabu also writes `naabu_last_scan_at` and `naabu_tier` on the IP asset.

## The verification pipeline

A raw port scan is not trustworthy on its own. Stateful firewalls with SYN-flood / anti-reconnaissance protection (SonicWall and similar) **complete the TCP handshake on many ports** during a fast scan, so naabu sees dozens or hundreds of phantom "open" ports that aren't real services. Constellus runs a multi-stage pipeline to separate real services from this noise:

1. **naabu discovery + `-verify`** — naabu scans the tier port set, then re-validates every candidate with a second, gentler TCP pass. The slow re-check doesn't trip the firewall's flood protection, so phantom ports collapse back to closed. This is the primary false-positive filter, and it is cheap: `-verify` only re-checks the ports the first pass found open (≈0s extra on a normal host, a few seconds on a flooded one).
2. **nmap `-sV` verification + enrichment** (issue #84) — the confirmed ports are handed to `nmap -sV` in the scanner-worker, which identifies the service/product/version and acts as a backstop: any port nmap can only label `tcpwrapped` (handshake completed, no application data) is dropped. nmap is the only layer that identifies non-HTTP services such as DNS (`53 → NLnet Labs NSD`). *(Naabu's own `-sV` service-detection flag is unimplemented as of v2.6.1 — it exits with "service discovery feature is not implemented" — which is why nmap is integrated separately.)*
3. **Service enrichers** — banner-grab (zgrab2 modules + a raw HTTP/1.0 probe for servers that don't speak HTTP/1.1, e.g. TR-069 on 7547), httpx, and tlsx add banners, Server headers, page titles, tech stack, and TLS certificates to each confirmed port.

### Passive port hints (Shodan)

Ports that Shodan reports open for an IP (`shodan_ports` metadata, written by the Shodan enrichment) are fed back into this pipeline: before Phase 1.5 the executor hydrates them onto the in-batch IP, naabu folds them into the nmap-verification set, and they are kept **only if our own probe confirms a real service on them**. This covers services on ports outside the tier baseline (e.g. 4433 SonicWall SSL-VPN, 7547 TR-069) without trusting Shodan's word — confirmation always comes from a Constellus probe.

## Requirements

The Naabu and nmap binaries are bundled into the `scanner-worker` sidecar. No host install required. The worker is granted `CAP_NET_RAW` (docker-compose `cap_add`) so naabu and nmap can use raw sockets where it helps. Naabu still defaults to a CONNECT scan; a deployer who wants the faster SYN scan can add `-scan-type s` to the worker invocation.

## Aggressiveness tiers

Naabu uses the same global aggressiveness setting as the rest of the active pipeline (Nuclei, dnsrecon, brute-force). The tier controls *which* ports Naabu probes and *how fast*:

| Tier | Top Ports | Rate (pps) | Concurrency | Notes |
|---|---|---|---|---|
| **stealth** | n/a | n/a | n/a | Naabu disabled at this tier |
| **polite** | 100 | 500 | 10 | Default. Quick, low-noise. |
| **standard** | 1,000 | 1,000 | 25 | nmap's "top 1000" — covers ~95% of services seen in the wild |
| **aggressive** | 65,535 | 5,000 | 50 | Full TCP range |

The "top N" lists Naabu uses are sourced from the [`nmap-services`](https://github.com/nmap/nmap/blob/master/nmap-services) frequency rankings that ship with the Nmap project. The same data drives Naabu's `-top-ports` flag — see the [Naabu documentation](https://docs.projectdiscovery.io/tools/naabu/usage#port-input) for the exact lookup logic.

If you need a port list that isn't covered by the tier (e.g. port 631 IPP, 9200 Elasticsearch, 27017 MongoDB), add it via the **Additional Ports** field rather than bumping the entire scan to a louder tier. Ports Shodan already knows about are pulled in automatically (see *Passive port hints* above).

## Configuration

| Field | Default | Description |
|---|---|---|
| Additional Ports | `(none)` | Comma-separated TCP ports to scan **on top of** the tier baseline. Triggers a second Naabu pass against just these ports (Naabu's `-top-ports` and `-p` flags are mutually exclusive). |
| Exclude Ports | `(none)` | Comma-separated TCP ports to skip entirely (e.g. mail ports your provider blocks). |

Naabu scans every public IP surfaced by Phase 1 discovery for the active targets in your Constellus instance. The act of adding a target is the authorisation to scan it — same policy as every other active tool in the pipeline.

## Re-observation & staleness

Each time naabu scans an IP it stamps `naabu_last_scan_at`. The Assets API hides any `open_ports[]` entry whose `last_seen_at` predates the latest `naabu_last_scan_at` — i.e. a port that wasn't re-confirmed in the most recent verified scan is treated as closed and disappears from the UI. The raw entry is retained in the database (the per-port merge is additive); only the display is filtered. This is how a port that closes between scans stops showing without destroying observation history.

## Limitations

- **TCP only** (Naabu does not currently support UDP scanning).
- **Public IPs only** — RFC1918 / loopback / link-local addresses are filtered out before the worker is called.
- **Connect scan by default** — slower than SYN but no privilege requirement; `-verify` re-validation runs regardless of scan type.
- **`-verify` is timing-based** — it reliably defeats SYN-flood-style firewall deception in testing, but a host that genuinely floods even the slow re-check pass would lean on the nmap `tcpwrapped` backstop to clean up the remainder.
