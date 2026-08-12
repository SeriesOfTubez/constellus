# Authentication & Access Control

Constellus supports local username/password auth and SAML 2.0 SSO side by side — a deployment can run either, or both at once during a rollout.

## Local authentication

`POST /auth/setup` bootstraps the very first user (forced to the `admin` role) and only works while no users exist yet. After that, `POST /auth/login` / `POST /auth/refresh` issue the JWT access/refresh pair used by the frontend. Passwords are hashed with bcrypt.

## SAML SSO

Configured under **Admin → SSO**, backed by a single active `SamlConfig` row. Set up:

1. **Metadata URL** — your IdP's metadata endpoint (HTTPS only). Click **Preview** before saving to confirm the parsed Entity ID, SSO URL, and that a signing certificate is present — there's no manual certificate upload field, the signing cert comes from the fetched metadata.
2. **SP Entity ID** and **Assertion Consumer Service (ACS) URL** — register these on the IdP side (the ACS URL is typically `https://<your-constellus-host>/api/auth/saml/acs`).
3. **JIT provisioning** — auto-create an account for a new SSO user on first login. JIT-provisioned accounts always start as `viewer`; grant a higher role afterward via **Admin → Users**.
4. **Allow local fallback** — keep password login available alongside SSO, useful while rolling SSO out.
5. **Refresh metadata** — re-pulls and caches the IdP's XML, so login doesn't depend on the IdP being reachable at request time.

Login flow: `GET /auth/saml/login` redirects to the IdP; `POST /auth/saml/acs` validates the response and issues the same JWT pair local login uses — once signed in, SSO and local users are indistinguishable to the rest of the app.

### Account linking

An incoming SSO assertion matches an existing account by its SSO subject first, then by email. An email match is only auto-linked if that account has **no local password set** — otherwise the SSO login is refused with a "contact an administrator" error. This closes an account-takeover path where an attacker registers an SSO identity matching an existing local user's email.

!!! note
    SAML metadata fetches go through an SSRF-guarded HTTP client that resolves DNS itself, blocklists private/internal ranges, and pins the connection to the validated IP — closing the DNS-rebinding gap that a naive metadata fetch would leave open.

## Roles

| Role | Scope |
|---|---|
| `admin` | Full access. Sole role for user management, SSO/system settings, log retention, and org branding. |
| `integration_admin` | Day-to-day operator — paired with `admin` on most write endpoints: assets, connectors, targets, findings actions, scans, scan templates, tags, notifications, and SAML config itself. Cannot manage users. |
| `viewer` | Read-only. Default role for SSO JIT-provisioned users, and the default wherever no elevated role is required. |
| `report_admin` | Defined in the model but not currently enforced by any endpoint — reserved for future use. |

## Audit logging

An immutable, append-only `audit_logs` table exists in the schema, but nothing in the backend currently writes to it yet — it's on the roadmap ("Audit Log" is listed under Admin with a "Soon" badge), not a working feature today.

## Hardening notes for self-hosters

- Constellus refuses to boot outside debug mode if `SECRET_KEY` is left at its placeholder default. That key both signs JWTs and (domain-separated) derives the key encrypting stored connector credentials — set a real secret before going to production.
- Scan-authorisation and target-verification settings (who your deployment is allowed to actively scan) are covered separately in [Scan Pipeline → Authorisation model](scan-pipeline.md#authorisation-model).
