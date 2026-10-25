"""Generators: turn evidence the system already holds into signals
(planning#277 S1a).

Built so far: the filer-website generator (S1a) and the reverse-IP generator
(S1b part C). A generator never commits (its caller owns the session) -- except
where it calls a helper that does, which its docstring then says -- and never
reads an entity name.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.apex import apex_domain
from app.models.asset_canonical import AssetCanonical
from app.models.observer import Observer
from app.models.org_entity import OrgEntity
from app.models.scope_candidate import ScopeCandidate
from app.services import edgar_html, entity_graph, hosting_classifier
from app.services.org_discovery import candidates


def record_filer_websites(
    db: Session,
    *,
    filer: OrgEntity,
    observer: Observer,
    evidence_id: uuid.UUID,
    lines: list[str],
    filing_date: date,
    created_candidate_ids: list[uuid.UUID] | None = None,
) -> tuple[int, int, int]:
    """Every domain a confirmed filer's own 10-K names as its website becomes
    a `filer_10k_website` signal on each root the filer belongs to. Returns
    `(recorded, existing, unanchored)`:

    - `recorded`   -- signals newly inserted
    - `existing`   -- signals already on file (re-sighted: `last_seen_at` moved)
    - `unanchored` -- website mentions found for a filer that belongs to no
                      root; nothing is written for them

    `filing_date` is accepted for the caller's symmetry with the old
    proposer; the signal's own timestamps are when WE saw it, and the 10-K's
    date is on the cited evidence.

    `created_candidate_ids`, when given, collects the id of every candidate
    this call newly CREATED (a re-sighting adds nothing), so the caller can
    verify them once its own commit has happened.
    """
    recorded = existing = unanchored = 0
    mentions = edgar_html.find_website_mentions(lines)
    if not mentions:
        return recorded, existing, unanchored
    roots = candidates.roots_of(db, filer.id)
    if not roots:
        return 0, 0, len(mentions)
    for domain, quote in mentions:
        for root in roots:
            try:
                outcome = candidates.record_signal(
                    db,
                    root_entity_id=root.id,
                    value=domain,
                    signal_type="filer_10k_website",
                    anchor_kind="filer_filing",
                    anchor_entity_id=filer.id,
                    via_entity_id=filer.id,
                    evidence_id=evidence_id,
                    quote=quote,
                    observer_id=observer.id,
                )
            except candidates.CandidateInvalid:
                # A string the extractor found that is not a storable domain.
                continue
            if outcome.created_candidate and created_candidate_ids is not None and outcome.candidate is not None:
                created_candidate_ids.append(outcome.candidate.id)
            if outcome.created_signal:
                recorded += 1
            else:
                existing += 1
    return recorded, existing, unanchored


@dataclass
class ReverseIpResult:
    ips_checked: int = 0
    not_dedicated: int = 0  # a claim was read and its verdict was not "dedicated"
    no_claim: int = 0  # no pDNS data: no ip asset, budget exhausted, or a failed lookup
    signals_recorded: int = 0
    signals_resighted: int = 0
    skipped_inactive_or_previous_tenant: int = 0
    no_claimed_history: int = 0  # dedicated, but pDNS never saw the claimed domain there
    invalid: int = 0
    created_candidate_ids: list[uuid.UUID] = field(default_factory=list)


def _parse_seen(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _claimed_ips(db: Session, domain: str) -> list[str]:
    """The distinct A/AAAA answers of `domain`'s OWN dns_record assets that
    also exist as ip_address assets."""
    answers = set(db.execute(
        select(AssetCanonical.content).where(
            AssetCanonical.asset_type == "dns_record",
            AssetCanonical.value == domain,
            AssetCanonical.record_type.in_(("A", "AAAA")),
            AssetCanonical.content.is_not(None),
        )
    ).scalars())
    if not answers:
        return []
    known = set(db.execute(
        select(AssetCanonical.value).where(
            AssetCanonical.asset_type == "ip_address", AssetCanonical.value.in_(answers)
        )
    ).scalars())
    return sorted(answers & known)


def record_reverse_ip(
    db: Session,
    *,
    claimed: ScopeCandidate,
    observer_id: uuid.UUID | None = None,
) -> ReverseIpResult:
    """Domains that share a DEDICATED address with a claimed domain become
    `reverse_ip_dedicated` signals (a Supporting signal, so a lead).

    Scope of this first slice, deliberately: only the claimed domain's OWN
    A/AAAA records are followed -- not its subdomains, not CNAME targets.

    Transaction ownership: `hosting_classifier.reverse_ip_domains` may fetch
    and COMMITS the session, so only a session owner may call this; the
    signal writes after it are flushed, and the caller commits them.

    The co-residency guard (false attribution is the failure this product
    cannot afford). An address verdict of "dedicated" is necessary, not
    sufficient. A pDNS record qualifies only if the other name was seen
    within the active window, did not leave before the claimed domain
    arrived (the earliest first sighting across names folding to it; an
    address where pDNS never saw the claimed domain is skipped whole, since
    co-residency cannot be shown), and its registrable domain is
    neither the claimed domain nor another claimed domain of the root.
    Hostnames fold to their registrable domain, which is what is proposed;
    a claimed domain that is itself a subdomain never causes its own
    registrable domain to be proposed.
    Never reads an entity name.
    """
    result = ReverseIpResult()
    if claimed.status != "claimed" or claimed.kind != "domain":
        return result
    claimed_value = claimed.value
    claimed_apex = apex_domain(claimed_value)
    root_id = claimed.root_entity_id
    affiliated_id = claimed.affiliated_entity_id
    claimed_id = claimed.id
    ips = _claimed_ips(db, claimed_value)
    now = datetime.now(timezone.utc)

    for ip in ips:
        result.ips_checked += 1
        # May fetch and commit: nothing of ours is pending here, and the ORM
        # rows below are re-read after it.
        hosting_classifier.reverse_ip_domains(db, ip)
        claim = hosting_classifier.reverse_ip_claim(db, ip)
        if claim is None:
            result.no_claim += 1
            continue
        if claim.get("sharing") != "dedicated":
            result.not_dedicated += 1
            continue
        records = [r for r in (claim.get("records") or []) if isinstance(r, dict) and isinstance(r.get("domain"), str)]
        claimed_here = {
            r_seen for r in records
            if apex_domain(r["domain"]) == claimed_apex and (r_seen := _parse_seen(r.get("first_seen"))) is not None
        }
        if not claimed_here:
            # pDNS has no sighting of the claimed domain on this address, so
            # nothing proves the other names were there at the same time
            # rather than a previous holder's: reject what we cannot prove.
            result.no_claimed_history += 1
            continue
        arrived = min(claimed_here)
        root_claimed = set(db.execute(
            select(ScopeCandidate.value).where(
                ScopeCandidate.root_entity_id == root_id, ScopeCandidate.kind == "domain",
                ScopeCandidate.status == "claimed",
            )
        ).scalars())

        by_apex: dict[str, set[str]] = {}
        for rec in records:
            apex = apex_domain(rec["domain"])
            if not apex or "." not in apex or apex in (claimed_value, claimed_apex) or apex in root_claimed:
                continue
            last_seen = _parse_seen(rec.get("last_seen"))
            if not hosting_classifier.is_active_record(rec.get("last_seen"), now) or last_seen is None:
                result.skipped_inactive_or_previous_tenant += 1
                continue
            if last_seen < arrived:
                result.skipped_inactive_or_previous_tenant += 1
                continue
            by_apex.setdefault(apex, set()).add(rec["domain"])

        for apex in sorted(by_apex):
            names = sorted(by_apex[apex])
            body = json.dumps(
                {
                    "rule": "reverse_ip_dedicated", "ip": ip, "sharing": "dedicated",
                    "candidate": apex, "claimed": claimed_value, "pdns_names": names,
                },
                sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
            evidence = entity_graph.store_evidence(
                db,
                content=body,
                content_type="application/json",
                source_url=f"https://org-discovery.invalid/generate/reverse_ip_dedicated/{apex}/{claimed_value}/{ip}",
                fetched_at=now,
                origin="fetched",
            )
            try:
                outcome = candidates.record_signal(
                    db,
                    root_entity_id=root_id,
                    value=apex,
                    signal_type="reverse_ip_dedicated",
                    anchor_kind="claimed_candidate",
                    anchor_candidate_id=claimed_id,
                    via_entity_id=affiliated_id,
                    evidence_id=evidence.id,
                    quote=f"{apex} resolves to {ip}, a dedicated address that claimed {claimed_value} also resolves to",
                    observer_id=observer_id,
                    matched_values=[ip],
                )
            except candidates.CandidateInvalid:
                result.invalid += 1
                continue
            if outcome.created_signal:
                result.signals_recorded += 1
            else:
                result.signals_resighted += 1
            if outcome.created_candidate and outcome.candidate is not None:
                result.created_candidate_ids.append(outcome.candidate.id)
    return result
