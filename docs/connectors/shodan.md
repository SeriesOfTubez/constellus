# Shodan Connector

**Phase:** Discovery (passive domain index) + Enrichment (per-IP host data)
**Purpose:** Add internet-exposure context and known CVEs to public IP assets, and supplement passive subdomain discovery with Shodan's domain index

## Passive subdomain discovery

For each apex domain in a scan's scope, Shodan's `/dns/domain/{domain}` endpoint is queried during Phase 1 — returning subdomains Shodan has historically indexed with their record types and values. Records mirror the DNS-connector format: `A`, `AAAA`, `CNAME`, `MX` are kept; provider-managed MX hosts are tagged `provider_mx`. Each record carries a `shodan_last_seen` timestamp so stale entries are visible.

Cost: **1 query credit per scan target**. Records may be historical — the live DNS resolution step (built into CT and subfinder) establishes current state.

## What it enriches

For every unique **public** IP discovered during a scan, Shodan adds:

- **Network identity:** organisation, ISP, ASN, country code
- **OS fingerprint** (when Shodan has one)
- **Open ports + service banners** (`shodan_ports`, `shodan_hostnames`)
- **Tags:** Shodan's own classification — `cdn`, `cloud`, `vpn`, `malware`, `compromised`, `honeypot`, etc.

Private, loopback, multicast, and otherwise non-routable IPs are skipped without a network call.

## Findings emitted

| Source | Mapping | Severity |
|---|---|---|
| Each entry in Shodan's `vulns` field | One `cve` finding per CVE-ID, including CVSS where available | Derived from CVSS (critical ≥9, high ≥7, medium ≥4, otherwise low / fallback medium) |
| `malware` / `compromised` tag | `malware` finding | Critical |
| `honeypot` tag | `honeypot` finding | Critical |

CVE findings are picked up automatically by the post-scan enrichment pipeline (EPSS, CISA KEV, NVD CVSS).

## Setup

1. Create an account at [account.shodan.io](https://account.shodan.io) and copy your API key
2. Navigate to **Admin → Connectors → Shodan**
3. Paste the API key and click **Test** — the result shows your detected plan and remaining query credits
4. Click **Enable**

A key is required for **all tiers** — Shodan has no anonymous access.

## Plan auto-detection

At the start of each scan, the connector calls `/api-info` once (this does not consume query credits) and uses the returned plan name to pick a safe inter-request delay:

| Plan | Inter-request delay | Rate |
|---|---|---|
| Free / OSS / Dev | 1.0 s | 1 req/s (hard limit) |
| Any paid plan (Membership, Small, Corporate, etc.) | 0.1 s | ~10 req/s (conservative — most paid plans allow more) |

The plan is logged in the scan output for visibility.

!!! warning "Free tier limitation"
    The free tier does **not** return the `vulns` field — Shodan reserves it for Membership and above. Asset enrichment (ports, services, tags) still works, but no CVE findings will be emitted. To get CVE findings from Shodan, you need a paid plan.

## Credit usage

Each unique public IP in a scan consumes **one query credit**. Plan accordingly when scanning large asset sets — the connector logs the IP count at scan start so you can predict cost.

## Required permissions

| Permission | Notes |
|---|---|
| Shodan API key | Any tier; paid plans unlock the `vulns` field |
