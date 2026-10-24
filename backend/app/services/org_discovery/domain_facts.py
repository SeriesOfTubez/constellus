"""Passive facts about one domain, for the org-discovery verifiers
(planning#277 S1b): its nameservers, MX hosts, SPF senders, DMARC report
addresses (with the RFC 7489 s7.1 external-destination authorisation
lookups) and WHOIS registrant organization.

Everything here is a lookup of PUBLIC DNS records about a domain we were
handed; nothing connects to the domain. A lookup that fails is recorded in
`lookup_errors` and yields empty facts. A failure is never a match.

## Transaction ownership

`collect` calls `whois_service.lookup_domain_cached`, which COMMITS the
session (it writes the WHOIS cache row). Call `collect` only from the
session's owner, at a point where committing is safe.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import secrets
import urllib.parse
from dataclasses import dataclass

import dns.exception
import dns.resolver
from sqlalchemy.orm import Session

from app.core.apex import apex_domain
from app.services import whois_service
from app.services.discovery import dns_records
from app.services.org_discovery.lists import fold_org, is_bulk_spf_include

log = logging.getLogger(__name__)

# Broadest ip4/ip6 network that can be a shared SPF sender (a guard; see
# `walk_spf_senders`).
_MIN_IP4_PREFIX = 16
_MIN_IP6_PREFIX = 32

# Guards against a hostile DMARC record, NOT settings: at most this many
# addresses are kept per rua / ruf tag ...
_MAX_REPORT_ADDRESSES = 10
# ... and at most this many external report hosts get authorisation lookups
# (the rest are recorded as "unchecked", with no query).
_MAX_REPORT_AUTH_HOSTS = 5

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass(frozen=True)
class DomainFacts:
    domain: str
    ns: tuple[str, ...]
    mx: tuple[str, ...]
    spf_senders: tuple[str, ...]
    spf_includes: tuple[str, ...]  # every include/redirect target seen, bulk ones too (evidence)
    registrant_org: str | None  # as WHOIS gave it
    registrant_org_folded: str | None
    lookup_errors: tuple[str, ...]  # "ns" | "mx" | "spf" | "whois" | "dmarc" | "dmarc_report_auth"
    dmarc_record_name: str | None = None  # "_dmarc.<name>" the policy was read from (apex fallback), None = none found
    dmarc_rua: tuple[str, ...] = ()  # normalised mailto addresses, record order, deduped
    dmarc_ruf: tuple[str, ...] = ()
    dmarc_report_auth: tuple[tuple[str, str], ...] = ()  # (report host, status), sorted by host


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


def _txt_strings(answer) -> list[str]:
    return [b"".join(rdata.strings).decode("ascii", errors="replace") for rdata in answer]


def parse_dmarc(txt: str) -> dict[str, str] | None:
    """Tag map of a DMARC record, or None when the first tag is not v=DMARC1."""
    tags: list[tuple[str, str]] = []
    for part in txt.split(";"):
        part = part.strip()
        if not part:
            continue
        key, _, value = part.partition("=")
        tags.append((key.strip().lower(), value.strip()))
    if not tags or tags[0][0] != "v" or tags[0][1].lower() != "dmarc1":
        return None
    return dict(tags)


def _valid_host(host: str) -> bool:
    if len(host) > 253:
        return False
    labels = host.split(".")
    return len(labels) >= 2 and all(_LABEL_RE.match(label) for label in labels)


def parse_report_uris(value: str) -> tuple[str, ...]:
    """Normalised `local@host` addresses from a rua / ruf value (mailto only)."""
    out: list[str] = []
    for uri in value.split(","):
        uri = uri.strip()
        if uri[:7].lower() != "mailto:":
            continue
        rest = uri[7:].split("!", 1)[0].split("?", 1)[0]  # RFC 7489 s6.2 size limit; header params
        addr = urllib.parse.unquote(rest).strip().lower()
        if addr.count("@") != 1:
            continue
        local, host = addr.split("@")
        if not 1 <= len(local) <= 64 or any(ch.isspace() for ch in local):
            continue
        if not _valid_host(host):
            continue
        if addr not in out:
            out.append(addr)
        if len(out) >= _MAX_REPORT_ADDRESSES:
            break
    return tuple(out)


def _fetch_dmarc_strict(resolver, host: str) -> tuple[str | None, bool]:
    """The DMARC record at `_dmarc.<host>`: (record, failed). No record and
    several records (RFC 7489 s6.6.3: no policy) are answers, not failures."""
    try:
        answer = resolver.resolve(f"_dmarc.{host}", "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None, False
    except dns.exception.DNSException as exc:
        log.debug("DMARC lookup failed for %s: %s", host, exc)
        return None, True
    found = [t for t in _txt_strings(answer) if parse_dmarc(t) is not None]
    return (found[0], False) if len(found) == 1 else (None, False)


def _report_txt_is_dmarc(resolver, qname: str) -> str:
    """"yes" | "no" | "error" for a v=DMARC1 TXT answer at `qname`."""
    try:
        answer = resolver.resolve(qname, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return "no"
    except dns.exception.DNSException as exc:
        log.debug("DMARC authorisation lookup failed for %s: %s", qname, exc)
        return "error"
    return "yes" if any(t.strip().lower().startswith("v=dmarc1") for t in _txt_strings(answer)) else "no"


def _report_auth(resolver, apex: str, host: str) -> str:
    """RFC 7489 s7.1: does `host` publish `<apex>._report._dmarc.<host>`?
    "authorised" | "wildcard" | "absent" | "error". A wildcard authorises
    everyone, so it proves nothing; it is detected with a random probe label
    that is never stored (evidence stays deterministic)."""
    specific = _report_txt_is_dmarc(resolver, f"{apex}._report._dmarc.{host}")
    if specific == "error":
        return "error"
    if specific == "no":
        return "absent"
    probe = _report_txt_is_dmarc(resolver, f"{secrets.token_hex(8)}._report._dmarc.{host}")
    if probe == "error":
        return "error"
    return "wildcard" if probe == "yes" else "authorised"


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

    apex = apex_domain(domain)
    dmarc_record_name = None
    dmarc_txt, failed = _fetch_dmarc_strict(resolver, domain)
    if failed:
        errors.append("dmarc")  # a failure is not an absence: no apex fallback
    elif dmarc_txt is not None:
        dmarc_record_name = f"_dmarc.{domain}"
    elif apex and apex != domain:
        dmarc_txt, failed = _fetch_dmarc_strict(resolver, apex)
        if failed:
            errors.append("dmarc")
        elif dmarc_txt is not None:
            dmarc_record_name = f"_dmarc.{apex}"

    rua: tuple[str, ...] = ()
    ruf: tuple[str, ...] = ()
    auth: list[tuple[str, str]] = []
    tags = parse_dmarc(dmarc_txt) if dmarc_txt else None
    if tags is not None:
        rua = parse_report_uris(tags.get("rua", ""))
        ruf = parse_report_uris(tags.get("ruf", ""))
        if apex:
            hosts = sorted({a.split("@")[1] for a in rua + ruf})
            external = [h for h in hosts if h != apex and not h.endswith("." + apex)]
            for h in external[:_MAX_REPORT_AUTH_HOSTS]:
                auth.append((h, _report_auth(resolver, apex, h)))
            auth.extend((h, "unchecked") for h in external[_MAX_REPORT_AUTH_HOSTS:])
            if any(status == "error" for _, status in auth):
                errors.append("dmarc_report_auth")

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
        dmarc_record_name=dmarc_record_name,
        dmarc_rua=rua,
        dmarc_ruf=ruf,
        dmarc_report_auth=tuple(sorted(auth)),
    )
