# Cloudflare Connector

**Phase:** Discovery  
**Purpose:** Enumerate zones and DNS records from your Cloudflare account

## What it discovers

- All active zones (domains) managed in your Cloudflare account
- DNS records of type: `A`, `AAAA`, `CNAME`, `MX`
- Cloudflare proxy status per record
- Provider-managed MX hosts (Google Workspace, Microsoft 365, etc.) are tagged `provider_mx` and skipped during active scanning

## Setup

1. Create a Cloudflare API token with **Zone → DNS → Read** permission
2. Navigate to **Admin → Connectors → Cloudflare**
3. Enter the API token and click **Test**
4. Click **Enable** once the test passes
5. Use **Sync** to trigger an immediate domain sync, or run a scan to discover assets

## Required permissions

| Permission | Level |
|---|---|
| Zone → DNS → Read | All zones (or specific zones) |

!!! tip
    Create a dedicated token for Constellus rather than using your global API key.
