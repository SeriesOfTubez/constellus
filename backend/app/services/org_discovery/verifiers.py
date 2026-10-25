"""Verifiers: DNS / WHOIS rules that relate an OPEN candidate domain to a
CLAIMED one (planning#277 S1b).

Rules cover shared / claimed nameservers, MX, SPF senders, DMARC report
addresses (reports sent to a claimed domain, or the same vendor mailbox) and
the WHOIS registrant organization.

Each `match_*` rule is a pure function over two `DomainFacts` (the candidate
`c` and the claimed anchor `a`) and returns a `Match` or None. `verify_pair`
checks the pair is eligible, stores the rule's inputs as evidence and records
one signal per matching rule through `candidates.record_signal` -- the single
writer. A verifier only ever relates two domains already in the tree; it
never reads an entity name and never decides anything (a signal is
Supporting at most, and the strength calculation requires two families).

## Transaction ownership

`verify_pair` flushes via `record_signal` and never commits itself.
`entity_graph.store_evidence` commits its own evidence row, as it always has.

## Observer

DNS and WHOIS observations have no `Observer` row of their own, and this
module does not invent one: `observer_id` is a parameter, resolved by the
caller (None is accepted by the column).

## Evidence is deterministic

The JSON body has no timestamps, so re-observing the same answers stores the
same bytes under the same `source_url`, `store_evidence` returns the existing
row, and `record_signal` sees the same route: `created_signal` is False and
only `last_seen_at` moves.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.connectors.base import is_provider_managed_mx
from app.core.apex import apex_domain
from app.models.scope_candidate import ScopeCandidate
from app.services import entity_graph
from app.services.org_discovery import candidates
from app.services.org_discovery.candidates import SignalOutcome
from app.services.org_discovery.domain_facts import DomainFacts
from app.services.org_discovery.lists import dmarc_vendor_address_kind, is_provider_ns

_SHOW = 3  # matched values spelled out in a quote; the rest are "+N more"


@dataclass(frozen=True)
class Match:
    signal_type: str
    matched_values: tuple[str, ...]
    evidence: dict
    quote: str


def _shown(values: tuple[str, ...]) -> str:
    head = ", ".join(values[:_SHOW])
    rest = len(values) - _SHOW
    return f"{head} +{rest} more" if rest > 0 else head


def _quote(c: DomainFacts, a: DomainFacts, what: str, values: tuple[str, ...]) -> str:
    return f"{c.domain} and claimed {a.domain} share {what} {_shown(values)}"


def _base(rule: str, c: DomainFacts, a: DomainFacts, matched: tuple[str, ...], **inputs: object) -> dict:
    return {"rule": rule, "candidate": c.domain, "claimed": a.domain, "matched": list(matched), **inputs}


def _under_or_equal(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def match_ns(c: DomainFacts, a: DomainFacts, claimed_domains: frozenset[str] = frozenset()) -> Match | None:
    """A shared nameserver is VANITY only when its host sits under the
    candidate itself or under a domain this root has claimed (the anchor
    always counts). A small hoster's shared nameservers link its customers,
    not one organization; the provider list stays as a backstop (Jason,
    #277 comment 6378172425)."""
    owners = claimed_domains | {a.domain, c.domain}
    matched = tuple(sorted(
        h for h in set(c.ns) & set(a.ns)
        if not is_provider_ns(h) and any(_under_or_equal(h, d) for d in owners)
    ))
    if not matched:
        return None
    return Match(
        signal_type="shared_vanity_ns",
        matched_values=matched,
        evidence=_base("shared_vanity_ns", c, a, matched, candidate_ns=list(c.ns), claimed_ns=list(a.ns)),
        quote=_quote(c, a, "nameserver" if len(matched) == 1 else "nameservers", matched),
    )


def match_mx(c: DomainFacts, a: DomainFacts) -> Match | None:
    matched = tuple(sorted(
        h for h in set(c.mx)
        if not is_provider_managed_mx(h) and (h in a.mx or _under_or_equal(h, a.domain))
    ))
    if not matched:
        return None
    return Match(
        signal_type="mx_into_claimed",
        matched_values=matched,
        evidence=_base("mx_into_claimed", c, a, matched, candidate_mx=list(c.mx), claimed_mx=list(a.mx)),
        quote=_quote(c, a, "mail host" if len(matched) == 1 else "mail hosts", matched),
    )


def match_spf(c: DomainFacts, a: DomainFacts) -> Match | None:
    matched_set = set(c.spf_senders) & set(a.spf_senders)
    matched_set |= {s for s in c.spf_senders if _under_or_equal(s, a.domain)}
    matched = tuple(sorted(matched_set))
    if not matched:
        return None
    return Match(
        signal_type="spf_sender_shared",
        matched_values=matched,
        evidence=_base(
            "spf_sender_shared", c, a, matched,
            candidate_spf_senders=list(c.spf_senders), claimed_spf_senders=list(a.spf_senders),
            candidate_spf_includes=list(c.spf_includes), claimed_spf_includes=list(a.spf_includes),
        ),
        quote=_quote(c, a, "SPF sender" if len(matched) == 1 else "SPF senders", matched),
    )


def match_registrant_org(c: DomainFacts, a: DomainFacts) -> Match | None:
    folded = c.registrant_org_folded
    if folded is None or folded != a.registrant_org_folded:
        return None
    return Match(
        signal_type="registrant_org_match",
        matched_values=(folded,),
        evidence=_base(
            "registrant_org_match", c, a, (folded,),
            candidate_registrant_org=c.registrant_org, claimed_registrant_org=a.registrant_org,
            candidate_registrant_org_folded=folded, claimed_registrant_org_folded=a.registrant_org_folded,
        ),
        quote=_quote(c, a, "registrant organization", (folded,)),
    )


def _addr_host(address: str) -> str:
    return address.partition("@")[2]


def match_dmarc_report(c: DomainFacts, a: DomainFacts) -> Match | None:
    """The candidate's DMARC reports go to the claimed anchor, and the anchor's
    own DNS authorises it (RFC 7489 s7.1, status "authorised": a wildcard
    authorises everyone and proves nothing). Never the reverse direction."""
    auth = dict(c.dmarc_report_auth)
    matched = tuple(sorted({
        addr for addr in c.dmarc_rua + c.dmarc_ruf
        if _under_or_equal(_addr_host(addr), a.domain) and auth.get(_addr_host(addr)) == "authorised"
    }))
    if not matched:
        return None
    return Match(
        signal_type="dmarc_report_to_claimed",
        matched_values=matched,
        evidence=_base(
            "dmarc_report_to_claimed", c, a, matched,
            candidate_dmarc_record_name=c.dmarc_record_name,
            candidate_rua=list(c.dmarc_rua), candidate_ruf=list(c.dmarc_ruf),
            report_auth={h: auth[h] for h in sorted({_addr_host(m) for m in matched})},
        ),
        quote=(
            f"{c.domain} sends DMARC reports to claimed {a.domain} ({_shown(matched)}), "
            f"authorised in {a.domain}'s DNS"
        ),
    )


def match_dmarc_exact(c: DomainFacts, a: DomainFacts, claimed_domains: frozenset[str] = frozenset()) -> Match | None:
    """Both domains report to the same address, which is not under a claimed
    domain (that is `dmarc_report_to_claimed`) nor under the candidate's own
    apex (the reverse direction). A per-customer mailbox at a known DMARC
    vendor is `dmarc_exact_vendor`; any other shared address is Context only."""
    owners = claimed_domains | {a.domain}
    c_apex = apex_domain(c.domain) or c.domain
    shared = {
        addr for addr in set(c.dmarc_rua + c.dmarc_ruf) & set(a.dmarc_rua + a.dmarc_ruf)
        if not any(_under_or_equal(_addr_host(addr), d) for d in owners)
        and not _under_or_equal(_addr_host(addr), c_apex)
    }
    vendor = tuple(sorted(x for x in shared if dmarc_vendor_address_kind(x) == "per_customer"))
    inputs = dict(
        candidate_dmarc_record_name=c.dmarc_record_name, claimed_dmarc_record_name=a.dmarc_record_name,
        candidate_rua=list(c.dmarc_rua), candidate_ruf=list(c.dmarc_ruf),
        claimed_rua=list(a.dmarc_rua), claimed_ruf=list(a.dmarc_ruf),
    )
    if vendor:
        return Match(
            signal_type="dmarc_exact_vendor",
            matched_values=vendor,
            evidence=_base(
                "dmarc_exact_vendor", c, a, vendor, **inputs,
                vendor_kind={x: dmarc_vendor_address_kind(x) for x in vendor},
            ),
            quote=_quote(c, a, "DMARC reporting address" if len(vendor) == 1 else "DMARC reporting addresses", vendor),
        )
    if shared:
        matched = tuple(sorted(shared))
        return Match(
            signal_type="dmarc_exact_generic",
            matched_values=matched,
            evidence=_base("dmarc_exact_generic", c, a, matched, **inputs),
            quote=_quote(c, a, "DMARC reporting address" if len(matched) == 1 else "DMARC reporting addresses", matched),
        )
    return None


RULES = (match_ns, match_mx, match_spf, match_registrant_org, match_dmarc_report, match_dmarc_exact)
# Rules that also need every claimed domain in the root.
_TAKES_CLAIMED = frozenset({match_ns, match_dmarc_exact})


def _eligible(candidate: ScopeCandidate, anchor: ScopeCandidate, cf: DomainFacts, af: DomainFacts) -> bool:
    return (
        candidate.status == "open"
        and anchor.status == "claimed"
        and candidate.root_entity_id == anchor.root_entity_id
        and candidate.id != anchor.id
        and candidate.value != anchor.value
        # the facts must be about these two rows, or the quote would name the wrong domains
        and cf.domain == candidate.value
        and af.domain == anchor.value
    )


def verify_pair(
    db: Session,
    *,
    candidate: ScopeCandidate,
    anchor: ScopeCandidate,
    candidate_facts: DomainFacts,
    anchor_facts: DomainFacts,
    observer_id: uuid.UUID | None = None,
    claimed_domains: frozenset[str] | None = None,
) -> list[SignalOutcome]:
    """Record one signal per rule that matches `candidate` against the
    claimed `anchor`. Returns [] without writing when the pair is not
    eligible (see `_eligible`). Flushes; never commits (see module docstring).

    `claimed_domains`: every claimed domain in the root, for `match_ns`'s
    vanity / DMARC-owner tests; read from the database when not given."""
    if not _eligible(candidate, anchor, candidate_facts, anchor_facts):
        return []
    if claimed_domains is None:
        claimed_domains = frozenset(db.execute(
            select(ScopeCandidate.value).where(
                ScopeCandidate.root_entity_id == candidate.root_entity_id,
                ScopeCandidate.kind == "domain",
                ScopeCandidate.status == "claimed",
            )
        ).scalars())
    outcomes: list[SignalOutcome] = []
    for rule in RULES:
        if rule in _TAKES_CLAIMED:
            match = rule(candidate_facts, anchor_facts, claimed_domains)
        else:
            match = rule(candidate_facts, anchor_facts)
        if match is None:
            continue
        body = json.dumps(match.evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
        evidence = entity_graph.store_evidence(
            db,
            content=body,
            content_type="application/json",
            source_url=(
                f"https://org-discovery.invalid/verify/{match.signal_type}/{candidate.value}/{anchor.value}"
            ),
            fetched_at=datetime.now(timezone.utc),
            origin="fetched",
        )
        outcomes.append(candidates.record_signal(
            db,
            root_entity_id=candidate.root_entity_id,
            value=candidate.value,
            signal_type=match.signal_type,
            anchor_kind="claimed_candidate",
            anchor_candidate_id=anchor.id,
            via_entity_id=anchor.affiliated_entity_id,
            evidence_id=evidence.id,
            quote=match.quote,
            observer_id=observer_id,
            matched_values=list(match.matched_values),
        ))
    return outcomes
