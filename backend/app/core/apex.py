"""Registrable-domain (apex) extraction backed by the Public Suffix List.

Previously the codebase had two near-identical naive implementations:

    parts = fqdn.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else fqdn

This is wrong for multi-level TLDs:

    api.example.co.uk     →  "co.uk"     (should be "example.co.uk")
    foo.example.com.au    →  "com.au"    (should be "example.com.au")
    *.example.s3.amazonaws.com — also wrong, etc.

This module uses `tldextract` (which ships the PSL bundled) so apex
derivation is correct for every public TLD without runtime lookups.

`apex_domain(fqdn)` returns the registrable apex (e.g. "example.co.uk")
or the input unchanged if no public suffix matches — that fallback
preserves behaviour for arbitrary internal names like "intranet" or
".local" that aren't real public domains but might still flow through
test paths.
"""

from __future__ import annotations

import idna
import tldextract

# Cache the bundled PSL snapshot once at module import. `include_psl_private_domains`
# is left default-False so e.g. "user.github.io" → "github.io" (which is the
# correct registrable boundary for our purposes — we don't treat github
# Pages projects as separate registrable apexes).
_extract = tldextract.TLDExtract(suffix_list_urls=())  # no runtime fetches


def apex_domain(fqdn: str | None) -> str:
    """Return the registrable apex domain for fqdn.

    Examples:
        apex_domain("api.example.com")          → "example.com"
        apex_domain("foo.example.co.uk")        → "example.co.uk"
        apex_domain("example.s3.amazonaws.com") → "amazonaws.com"  (treat as one registrable)
        apex_domain("example.com")              → "example.com"
        apex_domain("localhost")                → "localhost"      (no PSL match, returned as-is)
        apex_domain("")                         → ""

    None / empty inputs are returned as empty strings.
    """
    if not fqdn:
        return ""
    cleaned = fqdn.rstrip(".").lower()
    parts = _extract(cleaned)
    if parts.domain and parts.suffix:
        return f"{parts.domain}.{parts.suffix}"
    # PSL didn't recognise the suffix (e.g. ".local", a single label, bare IP).
    # Return the input unchanged so callers don't have to special-case it.
    return cleaned


# ── IDN normalisation ────────────────────────────────────────────────────────
#
# Constellus stores domain values as ASCII-compatible punycode (RFC 5891).
# That gives a single canonical form for string comparison, dedup, and the
# wire-level systems (DNS, WHOIS, TLS SNI) that only accept ASCII anyway.
# The UI calls `displayName()` on read so users still see `münchen.de`
# instead of `xn--mnchen-3ya.de`.

def to_punycode(name: str | None) -> str:
    """Return the ASCII-compatible (punycode) form of `name`.

    Accepts either a unicode IDN (`münchen.de`) or an already-encoded
    punycode value (`xn--mnchen-3ya.de`) — both round-trip to the same
    canonical ASCII form. Empty / None inputs become "".

    Raises `idna.IDNAError` for genuinely malformed input. Callers that
    want a non-throwing path can use the higher-level `normalize_domain()`.
    """
    if not name:
        return ""
    cleaned = name.strip().rstrip(".").lower()
    if not cleaned:
        return ""
    # uts46=True lets `idna` accept already-ASCII forms, mixed-case input,
    # and UTS#46-compatible characters without raising.
    return idna.encode(cleaned, uts46=True).decode("ascii")


def to_unicode(name: str | None) -> str:
    """Return the human-readable unicode form of `name`.

    Pure-ASCII names round-trip unchanged (`example.com` → `example.com`).
    Already-unicode input is normalised through punycode and back, which
    also folds confusable / non-NFC inputs to a canonical form.
    Empty / None inputs become "". On decode failure the cleaned ASCII is
    returned so display never crashes.
    """
    if not name:
        return ""
    cleaned = name.strip().rstrip(".").lower()
    if not cleaned:
        return ""
    try:
        return idna.decode(cleaned)
    except idna.IDNAError:
        return cleaned


def normalize_domain(name: str | None) -> str:
    """Best-effort punycode normalisation.

    Wraps `to_punycode` and falls back to a lowercased, dot-trimmed ASCII
    form when the input isn't a valid IDN at all (so callers can still
    feed values like "intranet" or a bare IP through this pipe without a
    try/except). The downstream hostname regex still gets to reject
    genuinely malformed values.
    """
    if not name:
        return ""
    try:
        return to_punycode(name)
    except idna.IDNAError:
        return name.strip().rstrip(".").lower()
