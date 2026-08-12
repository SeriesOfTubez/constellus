# Nuclei Connector

**Phase:** Scanning  
**Purpose:** Active vulnerability detection via Nuclei template engine

## What it finds

- CVEs in web applications and services
- Misconfigurations (exposed panels, default credentials, debug endpoints)
- Information disclosure
- Outdated software
- Network-level findings

Findings are automatically categorized and enriched with CVSS scores, EPSS exploit probability, and CISA KEV status.

## Requirements

The Nuclei connector runs Nuclei via Docker. The backend container must have access to the Docker socket — see [Docker Compose setup](../getting-started/docker.md).

## Configuration

| Field | Default | Description |
|---|---|---|
| Container Image | `projectdiscovery/nuclei:latest` | Nuclei Docker image |
| Severity Filter | `critical, high, medium` | Severities to include |

## Notes

Nuclei only runs against **verified targets**. Add and verify your domains on the Targets page before scanning.
