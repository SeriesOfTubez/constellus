# Connectors Overview

Connectors are the integration layer that feeds data into Constellus. Each connector belongs to a phase of the scan pipeline.

## Phases

| Phase | Purpose | Connectors |
|---|---|---|
| **Discovery** | Find domains and subdomains | Cloudflare |
| **Enrichment** | Add context to discovered assets | Tenable, Wiz, FortiManager |
| **Scanning** | Active vulnerability detection | Nuclei |
| **Notification** | Send alerts | Mailtrap |

## Managing connectors

All connectors are configured via **Admin → Connectors**. Each connector can be:

- **Configured** — credentials stored encrypted in the database
- **Tested** — validate credentials and connectivity
- **Enabled / Disabled** — include or exclude from scan runs
- **Synced** — manually trigger a full re-sync (Discovery connectors)

## Built-in discovery tools

In addition to connectors, Constellus runs built-in discovery tools during every scan:

| Tool | Type | Description |
|---|---|---|
| Certificate Transparency | Passive | Queries crt.sh and Certspotter for historical SSL certs |
| subfinder | Passive | Aggregates 40+ passive subdomain sources |
| dnsrecon | Active | DNS enumeration against target nameservers |
| Brute-force | Active | Resolves common subdomain names |

Active tools only run against **verified targets**.
