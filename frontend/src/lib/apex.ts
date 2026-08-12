// Registrable-domain (apex) extraction + IDN display helpers.
//
// Mirrors backend/app/core/apex.py so frontend grouping and backend
// authorisation/scope decisions agree on what an apex is and what the
// canonical (punycode) vs. display (unicode) form of a domain is.

import { getDomain } from "tldts"
import { toUnicode } from "punycode"

export function apexFromFqdn(fqdn: string | null | undefined): string {
  if (!fqdn) return ""
  const cleaned = fqdn.replace(/\.+$/, "").toLowerCase()
  // allowPrivateDomains:false → e.g. user.github.io → "github.io" (matches
  // backend tldextract default). Bare IPs / single-label names like
  // "localhost" don't match and fall through.
  const apex = getDomain(cleaned, { allowPrivateDomains: false })
  return apex ?? cleaned
}

// ── IDN display ──────────────────────────────────────────────────────────────
//
// Domain values are stored as ASCII-compatible punycode (`xn--mnchen-3ya.de`)
// to keep one canonical form across DNS, WHOIS, TLS, and database
// comparisons. `displayName()` is the read-time inverse — render the
// human-readable unicode form so users see `münchen.de` in tables.
//
// Pure-ASCII input round-trips unchanged. Inputs that fail to decode are
// returned as-is so display never crashes (matches backend `to_unicode`).

export function displayName(value: string | null | undefined): string {
  if (!value) return ""
  const cleaned = value.replace(/\.+$/, "").toLowerCase()
  if (!cleaned) return ""
  try {
    return toUnicode(cleaned)
  } catch {
    return cleaned
  }
}
