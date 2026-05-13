# Mailtrap Connector

**Phase:** Notification  
**Purpose:** Send email alerts via Mailtrap sandbox or live API

## Configuration

| Field | Description |
|---|---|
| API Token | Mailtrap API token |
| Inbox ID | Sandbox inbox ID (required for sandbox mode) |
| From Email | Sender address |
| From Name | Sender display name |
| Mode | `sandbox` (testing) or `live` (production) |

!!! warning
    Sandbox mode sends to your Mailtrap inbox only. Switch to `live` for real email delivery.
