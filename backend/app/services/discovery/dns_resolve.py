"""Passive DNS resolution for discovery names.

CT logs and passive enumerators (subfinder) return subdomain names without
record types or values. This helper resolves them against public recursive
resolvers (1.1.1.1, 8.8.8.8) so downstream enrichers (Shodan, etc.) have
real IPs to act on.

CNAME chains are followed automatically (`dnspython` does it for us when
resolving A). Each name in the chain — the query name, every intermediate
CNAME target, and the terminal — is emitted as its own dns_record asset
under the *correct* owner: the A/AAAA records attach to the terminal name
(the one the recursor actually answered with), not the query name. The IP
asset's parent is the terminal too, so downstream graph traversal sees
`query → CNAME → terminal → resolves_to → IP` rather than collapsing the
chain onto the query name. Names that don't resolve to anything are
silently dropped — CT certs frequently outlive their DNS, and dead names
pollute the asset list.

Queries against public recursors are passive — same DNS that any browser
makes — so this step is NOT gated on scan authorisation.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

import dns.exception
import dns.resolver

from app.connectors.base import DiscoveredAsset
from app.models.asset import AssetType

log = logging.getLogger(__name__)

_DEFAULT_NAMESERVERS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"]
_TIMEOUT = 4.0
_LIFETIME = 6.0
_MAX_WORKERS = 20


def _make_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = list(_DEFAULT_NAMESERVERS)
    r.timeout = _TIMEOUT
    r.lifetime = _LIFETIME
    return r


def resolve_names(
    names: Iterable[str],
    source: str,
    owned_domains: frozenset[str],
    apex: str | None = None,
) -> list[DiscoveredAsset]:
    """Resolve a batch of names in parallel.

    Returns DiscoveredAsset list: one dns_record per resolved record + one
    ip_address per unique A/AAAA hit. Names that fail to resolve produce no
    assets — they're either dead or behind authoritative-only DNS.

    owned_domains: every domain (and its subdomains) the org has declared as
    a Target — the full set, not just the apex being resolved right now (a
    CNAME can legitimately hop to a *different* target the org owns). A
    hostname that falls outside this set is third-party infrastructure: its
    terminal A/AAAA records and resolved IPs are suppressed.  The CNAME
    pointing at it is kept and annotated with cdn/cdn_domain metadata so
    web-app scanning still runs via the customer-owned hostname.
    """
    from app.connectors.base import is_dns_policy_name
    name_list = sorted(
        n for n in {n.lower().strip().rstrip(".") for n in names if n}
        if not is_dns_policy_name(n)
    )
    if not name_list:
        return []

    resolver = _make_resolver()
    name_records: dict[str, list[dict]] = {}

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
        futures = {executor.submit(_try_resolve, resolver, n): n for n in name_list}
        for future in as_completed(futures):
            name = futures[future]
            try:
                records = future.result()
            except Exception as exc:
                log.debug("Resolution error for %s: %s", name, exc)
                continue
            if records:
                name_records[name] = records

    log.info(
        "dns_resolve: %d / %d names resolved (source=%s)",
        len(name_records), len(name_list), source,
    )
    return _emit_assets(name_records, source, apex, owned_domains)


def _is_owned(fqdn: str, owned_domains: frozenset[str]) -> bool:
    """True if fqdn is (or is a subdomain of) one of the org's declared target domains."""
    fqdn = fqdn.lower()
    return any(fqdn == d or fqdn.endswith("." + d) for d in owned_domains)


def _emit_assets(
    name_records: dict[str, list[dict]],
    source: str,
    apex: str | None,
    owned_domains: frozenset[str],
) -> list[DiscoveredAsset]:
    assets: list[DiscoveredAsset] = []
    seen_ips: set[str] = set()

    def parent_of(n: str) -> str | None:
        return apex if apex and n != apex else None

    for query_name, records in name_records.items():
        # `records` arrives in chain order: zero or more CNAMEs (one per hop)
        # followed by the A/AAAA rdata from the terminal.
        cname_hops = [r for r in records if r["type"] == "CNAME"]
        addr_records = [r for r in records if r["type"] in ("A", "AAAA")]

        # Reconstruct the chain as (owner, target) pairs so each hop knows the
        # record it lives on. `terminal` is the final target (or query_name
        # when there are no CNAMEs).
        chain: list[tuple[str, str]] = []
        owner = query_name
        for hop in cname_hops:
            target = hop["content"]
            chain.append((owner, target))
            owner = target
        terminal = owner

        # Customer→third-party boundary: the first hop whose TARGET falls
        # outside every declared target domain. That hop's owner is the last
        # customer-owned record; the target and everything past it is
        # third-party infra — known CDN or not, doesn't matter. Checking the
        # *first* out-of-scope hop — not just the terminal — is what makes
        # multi-hop SaaS chains work: e.g. go.contoso.com → go.pardot.com →
        # app-ue1-public.fe.pardot.com must annotate go.contoso.com, not the
        # intermediate Pardot name. A CNAME to a *different* target the org
        # also owns (e.g. fabrikam.com → something.northwind.com) is
        # NOT a boundary — owned_domains covers every declared target, not
        # just this chain's own apex.
        boundary_idx: int | None = None
        for i, (_owner, target) in enumerate(chain):
            if not _is_owned(target, owned_domains):
                boundary_idx = i
                break

        if boundary_idx is not None:
            # Emit customer-owned hops up to and including the boundary hop; the
            # boundary hop is annotated with cdn/cdn_domain. The boundary target
            # and everything past it (third-party names and their IPs) are
            # suppressed. We deliberately do NOT synthesize open_ports here:
            # open_ports means "observed open", and asserting 80/443 we never
            # probed would be misleading. The web enrichers (tlsx/httpx) probe
            # the customer hostname directly via its own SNI and write the real
            # observed ports back to this record.
            for i in range(boundary_idx + 1):
                hop_owner, hop_target = chain[i]
                meta = {
                    "sources": [source],
                    "record_type": "CNAME",
                    "content": hop_target,
                }
                if i == boundary_idx:
                    meta["cdn"] = True
                    meta["cdn_domain"] = hop_target
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.DNS_RECORD,
                    value=hop_owner,
                    parent_value=parent_of(hop_owner),
                    asset_metadata=meta,
                ))
            log.debug(
                "dns_resolve: suppressed third-party chain from %s (not an owned domain) for %s",
                chain[boundary_idx][1], query_name,
            )
            continue

        # A bare terminal with no customer CNAME in front may itself be a
        # directly-queried third-party name (e.g. discovered via CT) that
        # isn't under any declared target — suppress it whole; there's no
        # customer record to annotate or scan.
        if not chain and not _is_owned(terminal, owned_domains):
            log.debug("dns_resolve: suppressed direct non-owned name %s", terminal)
            continue

        # Normal path — no third-party infra in the chain. Emit every CNAME hop
        # on its own owner, then attribute the terminal's A/AAAA records and IP
        # children.
        for hop_owner, hop_target in chain:
            assets.append(DiscoveredAsset(
                asset_type=AssetType.DNS_RECORD,
                value=hop_owner,
                parent_value=parent_of(hop_owner),
                asset_metadata={
                    "sources": [source],
                    "record_type": "CNAME",
                    "content": hop_target,
                },
            ))
        for record in addr_records:
            rtype = record["type"]
            content = record["content"]
            assets.append(DiscoveredAsset(
                asset_type=AssetType.DNS_RECORD,
                value=terminal,
                parent_value=parent_of(terminal),
                asset_metadata={
                    "sources": [source],
                    "record_type": rtype,
                    "content": content,
                },
            ))
            if content not in seen_ips:
                seen_ips.add(content)
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.IP_ADDRESS,
                    value=content,
                    parent_value=terminal,
                    asset_metadata={"sources": [source]},
                ))

    return assets


def _try_resolve(resolver: dns.resolver.Resolver, fqdn: str) -> list[dict]:
    """Try A → AAAA → bare CNAME. Returns list of {type, content} records.

    For A/AAAA queries, `dnspython` automatically follows CNAME chains;
    intermediate hops are exposed via `answer.chaining_result.cnames` so
    we can emit them as separate dns_record assets.
    """
    results: list[dict] = []
    seen_cnames: set[str] = set()

    for rtype in ("A", "AAAA"):
        try:
            answer = resolver.resolve(fqdn, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.exception.DNSException as exc:
            log.debug("%s lookup for %s: %s", rtype, fqdn, exc)
            continue

        # CNAME hops, if any (chain captured before final A/AAAA). The chain
        # is identical across the A and AAAA passes, so dedupe by target —
        # otherwise dual-stack names (e.g. CloudFront, which serves both A and
        # AAAA) append every hop twice. That duplication corrupts the chain
        # walk in _emit_assets: the repeated hop advances `chain_owner` past
        # the customer-owned name and shifts the CDN annotation (and synthetic
        # ports) onto the CDN's own terminal name instead of the CNAME.
        chaining = getattr(answer, "chaining_result", None)
        cname_rrsets = getattr(chaining, "cnames", None) or []
        for rrset in cname_rrsets:
            for rdata in rrset:
                target = str(rdata.target).rstrip(".")
                if target in seen_cnames:
                    continue
                seen_cnames.add(target)
                results.append({"type": "CNAME", "content": target})

        for rdata in answer:
            results.append({"type": rtype, "content": str(rdata)})

    # Bare CNAME fallback — name is a CNAME whose target has no A/AAAA
    if not results:
        try:
            answer = resolver.resolve(fqdn, "CNAME")
            for rdata in answer:
                target = str(rdata.target).rstrip(".")
                results.append({"type": "CNAME", "content": target})
        except dns.exception.DNSException:
            pass

    return results
