# Constellus

**Open Source External Attack Surface Management**

> Connect the dots, find the truth.

Constellus discovers, correlates, and risk-scores your public-facing infrastructure — from DNS records through to open ports, exposed services, and active vulnerabilities.

---

## What it does

- **Discovers** your attack surface via certificate transparency logs, DNS connectors (Cloudflare, Route53), passive subdomain enumeration, and active DNS tools
- **Enriches** assets with data from security platforms (Tenable, Wiz, FortiManager)
- **Scans** verified targets with Nuclei — surfacing CVEs, misconfigurations, exposed services, and default credentials
- **Correlates** findings with CVSS scores, EPSS exploit probability, and CISA KEV status
- **Alerts** via notification connectors (Mailtrap, SMTP) when new critical findings appear

## Quick links

- [Quick Start](getting-started/quickstart.md)
- [Connector overview](connectors/overview.md)
- [Scan pipeline architecture](architecture/scan-pipeline.md)
- [GitHub repository](https://github.com/SeriesOfTubez/constellus)
