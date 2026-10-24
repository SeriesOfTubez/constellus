"""Passive facts about one domain, for the org-discovery verifiers
(planning#277 S1b): its nameservers, MX hosts, SPF senders and WHOIS
registrant organization.

Everything here is a lookup of PUBLIC records about a domain we were handed;
nothing connects to the domain. A lookup that fails is recorded in
`lookup_errors` and yields empty facts. A failure is never a match.

## Transaction ownership

`collect` calls `whois_service.lookup_domain_cached`, which COMMITS the
session (it writes the WHOIS cache row). Call `collect` only from the
session's owner, at a point where committing is safe.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

import dns.exception
import dns.resolver
from sqlalchemy.orm import Session

from app.services import whois_service
from app.services.discovery import dns_records
from app.services.org_discovery.lists import fold_org, is_bulk_spf_include

log = logging.getLogger(__name__)

# Broadest ip4/ip6 network that can be a shared SPF sender (a guard; see
# `walk_spf_senders`).
_MIN_IP4_PREFIX = 16
_MIN_IP6_PREFIX = 32


@dataclass(frozen=True)
class DomainFacts:
    domain: str
    ns: tuple[str, ...]
    mx: tuple[str, ...]
    spf_senders: tuple[str, ...]
    spf_includes: tuple[str, ...]  # every include/redirect target seen, bulk ones too (evidence)
    registrant_org: str | None  # as WHOIS gave it
    registrant_org_folded: str | None
    lookup_errors: tuple[str, ...]  # "ns" | "mx" | "spf" | "whois"


def _host(value: object) -> str:
    return str(value).rstrip(".").strip().lower()


def _query_hosts(resolver, domain: str, rdtype: str, attr: str) -> tuple[tuple[str, ...], bool]:
    """(sorted hosts, failed). NoAnswer / NXDOMAIN are answers, not failures."""
    try:
        answer = resolver.resolve(domain, rdtype)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return (), False
    except dns.exception.DNSException as exc:
        log.debug("%s lookup failed for %s: %s", rdtype, domain, exc)
        return (), True
    hosts = {h for h in (_host(getattr(r, attr)) for r in answer) if h}
    return tuple(sorted(hosts)), False


def _fetch_spf_strict(resolver, domain: str) -> tuple[str | None, bool]:
    """The domain's own SPF record, telling "no record" from "lookup failed"
    (`dns_records._fetch_spf` folds both into None)."""
    try:
        answer = resolver.resolve(domain, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None, False
    except dns.exception.DNSException as exc:
        log.debug("TXT lookup failed for %s: %s", domain, exc)
        return None, True
    for rdata in answer:
        txt = b"".join(rdata.strings).decode("ascii", errors="replace")
        if txt.lower().startswith("v=spf1"):
            return txt, False
    return None, False


def walk_spf_senders(resolver, domain: str, spf: str, state: dict, seen: set) -> None:
    """Collect the senders an SPF record names, without descending into a
    bulk-provider include (its subtree is the provider's, shared by everyone).

    `state`: `lookups` (int), `exceeds_limit` (bool), `senders` (set of
    non-bulk include/redirect domains and normalised ip networks), `includes`
    (every include/redirect target seen, bulk or not). Honours the RFC 7208
    lookup cap and detects cycles. A bulk include still counts as a lookup
    against the cap, as it would for a real evaluator."""
    if domain in seen:
        return
    seen.add(domain)
    for token in spf.split()[1:]:
        if token and token[0] in "-~?":
            # Fail / softfail / neutral: the record says this is NOT an
            # authorised sender, so it is never a shared one.
            continue
        body = token[1:] if token and token[0] == "+" else token
        lower = body.lower()
        if lower.startswith(("ip4:", "ip6:")):
            try:
                net = ipaddress.ip_network(body.split(":", 1)[1], strict=False)
            except ValueError:
                continue
            if net.prefixlen < (_MIN_IP4_PREFIX if net.version == 4 else _MIN_IP6_PREFIX):
                # A guard, not a setting: two catch-all records
                # (`ip4:0.0.0.0/0`) or two huge provider blocks are not a
                # shared sender.
                continue
            state["senders"].add(str(net))
        elif lower.startswith(("include:", "redirect=")):
            target = _host(body.split(":" if lower.startswith("include:") else "=", 1)[1])
            if not target:
                continue
            state["includes"].add(target)
            state["lookups"] += 1
            if state["lookups"] > dns_records._SPF_MAX_LOOKUPS:
                state["exceeds_limit"] = True
                continue
            if is_bulk_spf_include(target):
                continue
            state["senders"].add(target)
            if target in seen:  # a cycle: already fetched, not asked for again
                continue
            nested = dns_records._fetch_spf(resolver, target)
            if nested:
                walk_spf_senders(resolver, target, nested, state, seen)
        elif lower in ("a", "mx", "ptr", "exists") or lower.startswith(("a:", "mx:", "ptr:", "exists:")):
            state["lookups"] += 1
            if state["lookups"] > dns_records._SPF_MAX_LOOKUPS:
                state["exceeds_limit"] = True


def collect(db: Session, domain: str, *, resolver=None) -> DomainFacts:
    """Passive lookups for `domain`. Never raises on a lookup failure.
    Commits `db` (WHOIS cache); see the module docstring."""
    domain = domain.strip().rstrip(".").lower()
    resolver = resolver or dns_records._make_resolver()
    errors: list[str] = []

    ns, failed = _query_hosts(resolver, domain, "NS", "target")
    if failed:
        errors.append("ns")
    mx, failed = _query_hosts(resolver, domain, "MX", "exchange")
    if failed:
        errors.append("mx")

    state: dict = {"lookups": 0, "exceeds_limit": False, "senders": set(), "includes": set()}
    spf, failed = _fetch_spf_strict(resolver, domain)
    if failed:
        errors.append("spf")
    elif spf:
        walk_spf_senders(resolver, domain, spf, state, set())

    registrant = None
    try:
        registrant = (whois_service.lookup_domain_cached(db, domain).get("registrant_org") or "").strip() or None
    except Exception as exc:  # a WHOIS failure must not abort verification
        db.rollback()
        log.debug("WHOIS lookup failed for %s: %s", domain, exc)
        errors.append("whois")

    return DomainFacts(
        domain=domain,
        ns=ns,
        mx=mx,
        spf_senders=tuple(sorted(state["senders"])),
        spf_includes=tuple(sorted(state["includes"])),
        registrant_org=registrant,
        registrant_org_folded=fold_org(registrant),
        lookup_errors=tuple(errors),
    )
