# CodeQL alert triage

Durable record of CodeQL code-scanning alerts that have been dismissed, and the
reasoning behind each.

## Why this file exists

**Alert dismissals live in GitHub's database, not in git.** They do not survive the
repository being deleted and recreated, and they are invisible to anyone reading the
code. This repository has already lost them once: it was republished on 2026-08-12 to
purge sensitive data from commit history, and every previously-triaged alert came back
open with no record of the analysis behind it.

That is expensive in a specific way — the next person to see the alert cannot tell the
difference between "this was carefully investigated and found to be a false positive"
and "nobody has looked at this yet". They either redo the audit or, worse, dismiss it
on the strength of the previous dismissal without checking anything.

So: **dismiss the alert in GitHub, and record the reasoning here in the same change.**
The GitHub comment is capped at 280 characters and is the pointer; this file is the
argument.

## Triage rules

1. **Never dismiss on the strength of a mitigation's existence.** "It's guarded" is not
   a finding. Read what the guard actually does, and test it. See the entry below for
   why this is not a theoretical concern.
2. **Prefer fixing to dismissing.** A dismissal is a last resort, per the project's
   security posture, and needs the criteria below.
3. **Record which commit verified the claim.** A dismissal that cites a PR can be
   re-checked in a minute. One that cites an opinion cannot.
4. **Re-verify on resurface.** If an alert returns after a code change, treat it as new
   — the mitigation it was dismissed against may no longer be in the path.

Criteria for a legitimate false-positive dismissal:

- The alert's *claim* is untrue of the current code (not merely "the risk is low"), and
- the reason CodeQL cannot see it is understood and stated, and
- the mitigation has been tested, not just read.

---

## Dismissed alerts

### Alert #1 — `py/full-ssrf`, `backend/app/services/saml.py:70`

| | |
|---|---|
| **Rule** | `py/full-ssrf` (Full server-side request forgery) |
| **Severity** | critical (CodeQL's rating) |
| **Status** | dismissed 2026-08-22, reason `false positive` |
| **Verified by** | PR #3 (`650a0ac`) |
| **Re-verify with** | `backend/app/tests/test_ssrf.py` |

**What CodeQL sees.** `fetch_metadata_xml` takes a URL that originates from user input
(an admin-supplied SAML IdP metadata URL) and passes it to `client.get()`. Taint
reaches an HTTP-request sink, and the rule fires.

**Why it is a false positive.** The request is issued through
`app.core.ssrf.ssrf_safe_client`, whose `SSRFGuardTransport` resolves the hostname
itself, validates every returned address against a blocklist, and **pins the connection
to the validated IP** by rewriting the request URL — closing the resolve-then-connect
(DNS rebinding) window that makes naive SSRF checks useless. The original hostname is
preserved as the `Host` header and as `sni_hostname`, so TLS certificate verification
still targets the real name. Redirects are off by default, and when enabled each hop
re-enters the same guard. A second, static barrier (`_validate_metadata_url`) enforces
HTTPS-only, rejects embedded credentials, and pre-checks IP-literal hosts.

CodeQL cannot see any of this because the sanitizer is a custom `httpx` transport, not
a recognizable sanitizing call on the URL value. There is no supported way to teach it
— see "Why not a model pack" below.

**What the dismissal is NOT.** It is not "the fetch is guarded, therefore fine". The
guard was audited before this alert was dismissed, and **it had real holes**:

The blocklist enumerated IPv4 networks, but an `IPv6Address` is never `in` an IPv4
network — so every internal IPv4 range was reachable by spelling it as IPv6.
`https://[::ffff:10.0.0.1]/` passed *both* barriers and connects to `10.0.0.1` on any
dual-stack host. It was not literal-only either: `::ffff:10.0.0.1` is a legal `AAAA`
record value, so an attacker-controlled hostname resolving to it took the same path.

Coverage was uneven rather than absent, which is what made it easy to miss. Python's
`IPv6Address.is_loopback` / `.is_link_local` *do* see through IPv4-mapped addresses, so
`::ffff:169.254.169.254` — cloud IMDS, the obvious thing to spot-check — *was* blocked,
while `::ffff:10.0.0.1` was not. Checking the highest-value target looked reassuring
and proved nothing.

Fixed in PR #3: `is_blocked` now unwraps every IPv6 form that embeds an IPv4 address
(ipv4-mapped, ipv4-compatible, 6to4, Teredo, NAT64 well-known) and classifies what the
address actually reaches; RFC 8215 local-use NAT64 is blocked wholesale. Deliberately a
classification rather than a ban on those encodings — `::ffff:8.8.8.8` still resolves
public and is still allowed.

**Blast radius, for context.** The only consumer today is SAML metadata fetch, gated to
`ADMIN` / `INTEGRATION_ADMIN`, so this was a privilege-boundary crossing rather than
unauthenticated SSRF, and IMDS was never exposed. `ssrf_safe_client` is documented as
the general guard for *any* user-supplied outbound URL ("connector favicons, etc."),
though, so the next consumer may not be admin-gated — which is why it was worth fixing
well beyond the one call site.

**If this alert resurfaces**, it means either the repository was recreated (expected —
re-dismiss citing this file) or `fetch_metadata_xml` changed. If the latter, check that
the fetch still goes through `ssrf_safe_client` before re-dismissing, and run
`pytest backend/app/tests/test_ssrf.py`. Those tests assert every bypass listed above
stays closed, and that public addresses stay reachable.

---

## Why not a model pack

The durable-looking answer is to teach CodeQL about the sanitizer instead of dismissing
the alert, which would also make *future* call sites analyze correctly rather than each
needing human triage. `barrierModel` became available for models-as-data in April 2026
and does cover Python.

It was evaluated and not taken, for two reasons:

1. **Model packs must be published to a registry to be consumed.** The CodeQL Action's
   `packs:` option accepts published pack names only; there is no supported local path,
   so a YAML file committed under `.github/codeql/` would sit inert. Making it live
   means a GHCR package, a publish workflow, and version pinning — and a failed publish
   degrades every subsequent analysis.

2. **The barrier has nowhere correct to attach as the code stands.** Taint flows through
   the *URL*, not the client, so a barrier on `ssrf_safe_client`'s return value does not
   cut the path. The two candidate placements both have problems:
     - `client.get()`'s argument, justified by the client it is called on — requires
       CodeQL's Python API graph to resolve through `with ssrf_safe_client(...) as
       client`, i.e. through `__enter__`. Unverified.
     - `_validate_metadata_url`'s return value — but `fetch_metadata_xml` currently
       **discards** it and passes the original `metadata_url` to `client.get()`, so no
       taint flows through the validator. Making this work needs a one-line change
       (`metadata_url = _validate_metadata_url(...)`), which is worth doing on its own
       merits: a validator that returns a checked value every caller ignores is a smell.

If the cost/benefit changes — more `ssrf_safe_client` consumers, or first-party support
for local model packs — revisit it. The one-line validator change is the prerequisite.
