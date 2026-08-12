"""Direct DNS lookups for apex enumeration — MX, NS, SPF.

Native dnspython queries against public recursors. Same shape as
`dns_resolve.py` but focused on apex-level record types instead of
name → IP resolution. Distinct from `dnsrecon.py`, which shells out
to a Docker container and is off by default.

Active from the resolver's perspective but passive from the target —
these are exactly the queries any receiving mail server / DNS-aware
client makes against your published records. No scan-auth gate needed.

What we emit:
  - MX:  one dns_record per MX target, with mx_preference + provider_mx flag.
  - NS:  one dns_record per NS target. Useful for understanding DNS hosting.
  - SPF: one dns_record for the apex's SPF TXT, with the policy + every
         include/redirect/ip4/ip6 token parsed into structured metadata.
         The SPF DNS lookup count is tracked so we can surface the common
         "more than 10 lookups" deliverability bug.

CIDR assets from `ip4:` / `ip6:` SPF mechanisms are *not* emitted as
separate assets in v1 — assets_canonical doesn't have a CIDR asset type
and broader provider ranges (e.g. Google's /17s) aren't useful as
individual entries. The CIDRs are preserved in the SPF metadata so the
flyout can render them. Promoting to first-class assets is a follow-up.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.resolver

from app.connectors.base import (
    DiscoveredAsset,
    PhaseResult,
    is_dns_policy_name,
    is_provider_managed_mx,
)
from app.models.asset import AssetType

log = logging.getLogger(__name__)

_DEFAULT_NAMESERVERS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"]
_TIMEOUT = 4.0
_LIFETIME = 6.0
_SPF_MAX_LOOKUPS = 10  # RFC 7208 §4.6.4


def _make_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = list(_DEFAULT_NAMESERVERS)
    r.timeout = _TIMEOUT
    r.lifetime = _LIFETIME
    return r


def run(apex: str) -> PhaseResult:
    """Discover MX / NS / SPF records on an apex domain.

    The three queries run in parallel — independent, each ~one round-trip.
    """
    apex = apex.lower().strip().rstrip(".")
    if not apex:
        return PhaseResult()

    resolver = _make_resolver()
    assets: list[DiscoveredAsset] = []

    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = {
            ex.submit(_query_mx, resolver, apex): "MX",
            ex.submit(_query_ns, resolver, apex): "NS",
            ex.submit(_query_spf, resolver, apex): "SPF",
        }
        for f in as_completed(futures):
            kind = futures[f]
            try:
                assets.extend(f.result())
            except Exception:
                log.exception("dns_records %s lookup failed for %s", kind, apex)

    log.info("dns_records: %d MX/NS/SPF asset(s) for %s", len(assets), apex)
    return PhaseResult(assets=assets)


# ── MX ────────────────────────────────────────────────────────────────────────

def _query_mx(resolver: dns.resolver.Resolver, apex: str) -> list[DiscoveredAsset]:
    try:
        answer = resolver.resolve(apex, "MX")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.DNSException as exc:
        log.debug("MX lookup failed for %s: %s", apex, exc)
        return []

    assets: list[DiscoveredAsset] = []
    for rdata in answer:
        target = str(rdata.exchange).rstrip(".").lower()
        if not target or target == "." or is_dns_policy_name(target):
            continue
        meta: dict = {
            "sources": ["dns_records"],
            "record_type": "MX",
            "content": target,
            "mx_preference": int(rdata.preference),
        }
        if is_provider_managed_mx(target):
            meta["provider_mx"] = True
        assets.append(DiscoveredAsset(
            asset_type=AssetType.DNS_RECORD,
            value=apex,
            parent_value=None,
            asset_metadata=meta,
        ))
    return assets


# ── NS ────────────────────────────────────────────────────────────────────────

def _query_ns(resolver: dns.resolver.Resolver, apex: str) -> list[DiscoveredAsset]:
    try:
        answer = resolver.resolve(apex, "NS")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.DNSException as exc:
        log.debug("NS lookup failed for %s: %s", apex, exc)
        return []

    assets: list[DiscoveredAsset] = []
    for rdata in answer:
        target = str(rdata.target).rstrip(".").lower()
        if not target:
            continue
        assets.append(DiscoveredAsset(
            asset_type=AssetType.DNS_RECORD,
            value=apex,
            parent_value=None,
            asset_metadata={
                "sources": ["dns_records"],
                "record_type": "NS",
                "content": target,
            },
        ))
    return assets


# ── SPF ───────────────────────────────────────────────────────────────────────

def _query_spf(resolver: dns.resolver.Resolver, apex: str) -> list[DiscoveredAsset]:
    """Parse the apex's SPF record, recursing through `include:` / `redirect=`.

    RFC 7208 §4.6.4 caps SPF evaluation at 10 DNS lookups (include, a, mx,
    ptr, exists, redirect each count). Exceeding it is a real deliverability
    bug — receiving servers treat the SPF as PermError, which on a strict
    DMARC policy means the mail is rejected. We track the count and flag
    `exceeds_limit=True` so it can be surfaced as a finding later.
    """
    spf_string = _fetch_spf(resolver, apex)
    if not spf_string:
        return []

    state: dict = {
        "ip4": [],
        "ip6": [],
        "includes": [],
        "mechanisms": [],
        "lookup_count": 0,
        "exceeds_limit": False,
    }
    _walk_spf(resolver, apex, spf_string, state, seen=set())

    return [DiscoveredAsset(
        asset_type=AssetType.DNS_RECORD,
        value=apex,
        parent_value=None,
        asset_metadata={
            "sources": ["dns_records"],
            "record_type": "TXT",
            "content": spf_string,
            "spf": {
                "policy": _extract_spf_policy(spf_string),
                "includes": list(dict.fromkeys(state["includes"])),
                "ip4": list(dict.fromkeys(state["ip4"])),
                "ip6": list(dict.fromkeys(state["ip6"])),
                "mechanisms": list(dict.fromkeys(state["mechanisms"])),
                "lookup_count": state["lookup_count"],
                "exceeds_limit": state["exceeds_limit"],
            },
        },
    )]


def _fetch_spf(resolver: dns.resolver.Resolver, name: str) -> str | None:
    """Return the v=spf1 TXT record for `name`, or None if absent / unparsable."""
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None
    except dns.exception.DNSException:
        return None
    for rdata in answer:
        # TXT records are chunked into 255-byte strings; join them.
        txt = b"".join(rdata.strings).decode("ascii", errors="replace")
        if txt.lower().startswith("v=spf1"):
            return txt
    return None


def _walk_spf(
    resolver: dns.resolver.Resolver,
    name: str,
    spf: str,
    state: dict,
    seen: set,
) -> None:
    """Recursively process SPF mechanisms, tracking lookups and cycles."""
    if name in seen:
        return
    seen.add(name)

    for token in spf.split()[1:]:  # skip 'v=spf1'
        body = token[1:] if token and token[0] in "+-~?" else token
        body_lower = body.lower()

        if body_lower.startswith("ip4:"):
            state["ip4"].append(body.split(":", 1)[1])
        elif body_lower.startswith("ip6:"):
            state["ip6"].append(body.split(":", 1)[1])
        elif body_lower.startswith("include:"):
            included = body.split(":", 1)[1].lower()
            state["includes"].append(included)
            state["lookup_count"] += 1
            if state["lookup_count"] > _SPF_MAX_LOOKUPS:
                state["exceeds_limit"] = True
                continue
            nested = _fetch_spf(resolver, included)
            if nested:
                _walk_spf(resolver, included, nested, state, seen)
        elif body_lower.startswith("redirect="):
            target = body.split("=", 1)[1].lower()
            state["includes"].append(target)
            state["lookup_count"] += 1
            if state["lookup_count"] > _SPF_MAX_LOOKUPS:
                state["exceeds_limit"] = True
                continue
            nested = _fetch_spf(resolver, target)
            if nested:
                _walk_spf(resolver, target, nested, state, seen)
        elif body_lower in ("a", "mx", "ptr", "exists"):
            state["mechanisms"].append(body_lower)
            state["lookup_count"] += 1
            if state["lookup_count"] > _SPF_MAX_LOOKUPS:
                state["exceeds_limit"] = True
        elif (
            body_lower.startswith("a:")
            or body_lower.startswith("mx:")
            or body_lower.startswith("ptr:")
            or body_lower.startswith("exists:")
        ):
            state["mechanisms"].append(body_lower)
            state["lookup_count"] += 1
            if state["lookup_count"] > _SPF_MAX_LOOKUPS:
                state["exceeds_limit"] = True


def _extract_spf_policy(spf: str) -> str:
    """Return the policy from the trailing `all` mechanism.

      -all = fail (strict — recommended for sending domains)
      ~all = softfail (recommended baseline)
      ?all = neutral (no policy — receivers treat as if no SPF)
      +all = pass (allows anyone to send as you — broken/dangerous)
    """
    for token in reversed(spf.split()):
        t = token.lower()
        if t == "-all":
            return "fail"
        if t == "~all":
            return "softfail"
        if t == "?all":
            return "neutral"
        if t in ("+all", "all"):
            return "pass"
    return "unknown"
