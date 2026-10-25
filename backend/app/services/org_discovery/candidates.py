"""Scope candidates: record signals, add by person, claim, reject
(planning#277 S1a). Replaces the former candidate-domains service.

## No name -> domain path, by construction

Nothing in this package reads `org_entities.legal_name`, and no function
here takes a company name. A candidate exists only because a SIGNAL names its
value, and a signal is either borne by something already decided (a claimed
candidate, a confirmed filer's own filing) or by a person. The chain is
enforced twice: here (`record_signal`) and in the database
(`trg_scope_signals_anchor`, migration 0083).
`tests/test_org_discovery_invariants.py` pins the "no name" half with an AST
walk over every module in this package.

## Transaction ownership (CONTRIBUTING.md)

Helpers `flush()` and never commit. The owners are the top-level functions
documented as such: `add_by_person`, `claim`, `reject`. (`add_by_person`'s
evidence write goes through `entity_graph.store_evidence`, which commits its
own evidence row, as it always has.) `_claim_seed` is the helper
`organizations.add_organization` uses; that function owns the commit.

## Claim creates the target INSIDE its destination, in one transaction

`claim` does not use `target_service.ensure_pending`, which commits a new
target with no engagement (an unrestricted owned-estate target) before a
caller could attach it. The `Target` row is inserted with
`engagement_id`/`entity_id` already set, and the decision is written in the
SAME commit.

The destination comes from the ROOT organization (planning#240, #277): `ours`
-> our estate (no engagement); `ma_target` -> the root's one live engagement.
There is no picker. A root with no relationship, or whose engagements are all
abandoned, blocks the claim.

An existing target with the same value: same destination and a compatible
entity -> attached (idempotent); anything else -> `CandidateConflict`,
nothing changed. Moving a target is a `PATCH /targets/{id}` decision with its
own widening rules.

## Unlock

A rejected candidate comes back to `open` only when a NEW Strong signal of a
type that was NOT present at rejection arrives. Re-seeing the same evidence,
or any Supporting/Context signal, is stored and changes nothing.

## Errors

`CandidateNotFound` (404), `CandidateConflict` (409), `CandidateInvalid`
(400), `CandidateForbidden` (403). Audit rows are the CALLER's job.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import literal_column, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.connector_instance import ConnectorInstance
from app.models.engagement import Engagement, EngagementPosture
from app.models.org_entity import RELATIONSHIP_MA_TARGET, RELATIONSHIP_OURS, OrgEntity
from app.models.scope_candidate import (
    ANCHOR_KINDS,
    CANDIDATE_KINDS,
    RIRS,
    ScopeCandidate,
    ScopeCandidateEvent,
    ScopeSignal,
)
from app.models.target import Target, TargetType, VerificationMethod
from app.services import cloud_ranges, entity_graph, entity_relationship, target_service
from app.services.org_discovery import strength as strength_sql
from app.services.org_discovery.tiers import SIGNALS, STRONG

TARGET_SOURCE_TYPE = "candidate_domain"
CIDR_TARGET_SOURCE_TYPE = "candidate_cidr"

# Same shape as migration 0083's `ck_scope_candidates_domain_shape`.
_DOMAIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63}|xn--[a-z0-9-]{1,59})$")

# A cited URL is stored, never requested -- validated by shape only. Not
# `urllib.parse`: `test_egress_gate_guard` treats any `urllib` import as a
# network transport, and this package must stay one that makes no requests.
_SOURCE_URL_RE = re.compile(r"^https?://[^\s/?#@]+(?:[/?#][^\s]*)?$", re.IGNORECASE)
_MAX_SOURCE_URL = 2048
_MAX_EXCERPT = 50_000
_MAX_QUOTE = 2_000
MAX_REJECTION_REASON = 500

NOT_PROPOSABLE_MESSAGE = "not enough evidence to claim: add evidence or wait for a second independent signal"
NOT_IN_TREE_MESSAGE = "not in this organization's tree"


class CandidateError(Exception):
    pass


class CandidateNotFound(CandidateError):
    pass


class CandidateConflict(CandidateError):
    pass


class CandidateInvalid(CandidateError):
    pass


class CandidateForbidden(CandidateError):
    pass


def normalise_domain(value: str) -> str:
    """Canonical form stored in `scope_candidates.value` and, on claim,
    `targets.value`: `target_service.canonicalize_value` (lowercase,
    punycode, no scheme/path), then a leading `www.` removed. Raises
    `CandidateInvalid` for anything that is not a hostname."""
    try:
        canonical = target_service.canonicalize_value(value or "")
    except Exception as exc:  # canonicalize_value raises on undecodable IDNs
        raise CandidateInvalid(f"not a domain: {exc}") from exc
    if canonical.startswith("www."):
        canonical = canonical[4:]
    if not canonical or not _DOMAIN_RE.match(canonical):
        raise CandidateInvalid("not a domain (expected a hostname such as example.com)")
    try:
        if target_service.detect_type(canonical) != TargetType.DOMAIN:
            raise CandidateInvalid("not a domain")
    except ValueError as exc:
        raise CandidateInvalid(str(exc)) from exc
    return canonical


_ASN_RE = re.compile(r"^(?:as)?([0-9]{1,10})$", re.IGNORECASE)
# Private / reserved ASNs (RFC 6996, 7300, 6793). The documentation ranges
# (RFC 5398: 64496-64511, 65536-65551) are NOT here: they are allowed.
_BAD_ASN_RANGES = (
    (0, 0), (23456, 23456), (64512, 65534), (65535, 65535), (4200000000, 4294967294), (4294967295, 4294967295),
)


def normalise_asn(value: str) -> str:
    """Canonical form stored in `scope_candidates.value` for an ASN:
    `AS<number>`. Accepts `AS64500`, `as64500` and `64500` (trimmed).
    Raises `CandidateInvalid` for anything that is not a public ASN
    (0, AS_TRANS 23456, 64512-65535 and 4200000000-4294967295, or beyond 32 bits)."""
    match = _ASN_RE.match((value or "").strip())
    if match is None:
        raise CandidateInvalid("not an ASN (expected AS64500 or 64500)")
    number = int(match.group(1))
    if number > 4294967295 or any(low <= number <= high for low, high in _BAD_ASN_RANGES):
        raise CandidateInvalid("not a public ASN (zero, AS_TRANS, private-use or reserved)")
    return f"AS{number}"


# Space an organization cannot own, as networks so that a prefix which merely
# OVERLAPS one (a /1, a supernet) is refused as well as one inside it.
# Documentation ranges (RFC 5737, 2001:db8::/32) are deliberately absent.
_NON_CLAIMABLE_V4 = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8",        # "this network", unspecified
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC 1918
    "100.64.0.0/10",    # CGNAT
    "127.0.0.0/8",      # loopback
    "169.254.0.0/16",   # link-local
    "224.0.0.0/4",      # multicast
    "240.0.0.0/4",      # reserved (and the broadcast address)
))
_NON_CLAIMABLE_V6 = tuple(ipaddress.ip_network(n) for n in (
    "::/96",            # unspecified, loopback and the deprecated IPv4-compatible block
    "::ffff:0:0/96",    # IPv4-mapped
    "fc00::/7",         # unique local
    "fe80::/10",        # link-local
    "ff00::/8",         # multicast
))
_GLOBAL_UNICAST_V6 = ipaddress.ip_network("2000::/3")  # everything else is reserved


def normalise_cidr(value: str) -> str:
    """Canonical form stored in `scope_candidates.value` for a CIDR: Python's
    `str(network)`, which equals Postgres's `value::cidr::text` (lower-case,
    `::` compressed). Host bits set is refused (strict). Raises
    `CandidateInvalid` for a network that is, or overlaps, loopback,
    link-local, multicast, unspecified, reserved, RFC 1918, CGNAT, ULA or the
    IPv4-mapped / IPv4-compatible IPv6 blocks."""
    try:
        network = ipaddress.ip_network((value or "").strip(), strict=True)
    except ValueError as exc:
        raise CandidateInvalid(f"not a CIDR: {exc}") from exc
    if network.version == 4:
        blocked = any(network.overlaps(b) for b in _NON_CLAIMABLE_V4)
    else:
        blocked = any(network.overlaps(b) for b in _NON_CLAIMABLE_V6) or not network.subnet_of(_GLOBAL_UNICAST_V6)
    if blocked:
        raise CandidateInvalid("not a claimable public network (private, reserved, loopback, link-local or multicast space)")
    return str(network).lower()


def _normalise_registry(rir: str | None, rir_handle: str | None) -> tuple[str, str]:
    """`rir` (lower-cased, one of `RIRS`) and the holder handle (trimmed,
    non-empty, otherwise kept as written) an ASN / CIDR candidate requires."""
    rir = (rir or "").strip().lower()
    if rir not in RIRS:
        raise CandidateInvalid(f"rir must be one of {', '.join(sorted(RIRS))}")
    handle = (rir_handle or "").strip()
    if not handle:
        raise CandidateInvalid("rir_handle is required for an ASN or CIDR")
    return rir, handle


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── the tree ────────────────────────────────────────────────────────────────


def roots_of(db: Session, entity_id: uuid.UUID) -> list[OrgEntity]:
    """The roots `entity_id` belongs to: the `resolve()` stops' entities
    (ours or ma_target). An entity with no stop has no root, so nothing can
    be anchored to it."""
    stops = entity_relationship.resolve(db, entity_id).stops
    found: list[OrgEntity] = []
    for stop in stops:
        entity = db.get(OrgEntity, stop.entity_id)
        if entity is not None and entity not in found:
            found.append(entity)
    return found


def _in_tree(db: Session, root_entity_id: uuid.UUID, entity_id: uuid.UUID) -> bool:
    return root_entity_id in {s.entity_id for s in entity_relationship.resolve(db, entity_id).stops}


# ── signals ─────────────────────────────────────────────────────────────────


@dataclass
class SignalOutcome:
    outcome: str  # "recorded" | "skipped_context_only"
    candidate: ScopeCandidate | None = None
    signal: ScopeSignal | None = None
    created_candidate: bool = False
    created_signal: bool = False
    unlocked: bool = False


def record_signal(
    db: Session,
    *,
    root_entity_id: uuid.UUID,
    value: str,
    kind: str = "domain",
    signal_type: str,
    anchor_kind: str,
    anchor_candidate_id: uuid.UUID | None = None,
    anchor_entity_id: uuid.UUID | None = None,
    anchor_user_id: uuid.UUID | None = None,
    anchor_connector_instance_id: uuid.UUID | None = None,
    via_entity_id: uuid.UUID,
    evidence_id: uuid.UUID | None = None,
    quote: str | None = None,
    observer_id: uuid.UUID | None = None,
    matched_values: list[str] | None = None,
    rir: str | None = None,
    rir_handle: str | None = None,
) -> SignalOutcome:
    """Record one signal for (root, kind, value), creating the candidate if
    this is its first Strong/Supporting signal. Flushes; never commits.

    `matched_values` is what the two domains share (a verifier's NS host,
    an IP, ...); stored sorted and de-duplicated, never empty.

    `kind` 'asn' / 'cidr' REQUIRE `rir` and `rir_handle` (the registry and the
    holder handle the resource was found under) and a domain refuses them. An
    existing candidate under a different registry / handle is a conflict: a
    prefix is never silently moved between holders."""
    spec = SIGNALS.get(signal_type)
    if spec is None:
        raise CandidateInvalid(f"unknown signal type {signal_type!r}")
    if matched_values is not None:
        if any(not isinstance(v, str) or not v.strip() for v in matched_values):
            raise CandidateInvalid("matched values must be non-blank strings")
        matched_values = sorted(set(matched_values)) or None
        if matched_values is None:
            raise CandidateInvalid("matched values, when given, must not be empty")
    if kind not in CANDIDATE_KINDS:
        raise CandidateInvalid(f"unknown candidate kind {kind!r}")
    if kind == "domain":
        if rir is not None or rir_handle is not None:
            raise CandidateInvalid("rir and rir_handle are only for an ASN or CIDR")
        value = normalise_domain(value)
        quote_needle = value
    else:
        rir, rir_handle = _normalise_registry(rir, rir_handle)
        if kind == "asn":
            value = normalise_asn(value)
            quote_needle = value.lower()
        else:
            value = normalise_cidr(value)
            quote_needle = str(ipaddress.ip_network(value).network_address)
    if anchor_kind not in ANCHOR_KINDS:
        raise CandidateInvalid(f"unknown anchor kind {anchor_kind!r}")

    if (signal_type == "connector_zone") != (anchor_kind == "connector_instance"):
        raise CandidateInvalid("connector_zone signals, and only they, use the connector_instance anchor")
    if anchor_kind != "connector_instance" and anchor_connector_instance_id is not None:
        raise CandidateInvalid("a connector instance id is only for a connector_instance anchor")

    if (evidence_id is None) != (quote is None):
        raise CandidateInvalid("evidence and quote are given together or not at all")
    if evidence_id is None and signal_type != "admin_seed":
        raise CandidateInvalid("this signal type needs evidence and a quote")
    if quote is not None:
        if not quote.strip():
            raise CandidateInvalid("quote is required")
        if len(quote) > _MAX_QUOTE:
            raise CandidateInvalid(f"quote is longer than {_MAX_QUOTE} characters")
        if quote_needle not in quote.lower():
            raise CandidateInvalid(
                {
                    "domain": "quote must contain the domain as written (ASCII or punycode form)",
                    "asn": "quote must contain the ASN as written",
                    "cidr": "quote must contain the network address (the registry's range or prefix as written)",
                }[kind]
            )

    if not _in_tree(db, root_entity_id, via_entity_id):
        raise CandidateInvalid(f"via entity is {NOT_IN_TREE_MESSAGE}")

    if anchor_kind == "filer_filing":
        if anchor_entity_id is None:
            raise CandidateInvalid("a filer_filing anchor needs the filer entity")
        filer = db.get(OrgEntity, anchor_entity_id)
        if filer is None or not filer.cik:
            raise CandidateInvalid("the anchoring filer has no CIK")
        if not _in_tree(db, root_entity_id, anchor_entity_id):
            raise CandidateInvalid(f"anchoring filer is {NOT_IN_TREE_MESSAGE}")
    elif anchor_kind == "claimed_candidate":
        if anchor_candidate_id is None:
            raise CandidateInvalid("a claimed_candidate anchor needs the anchoring candidate")
        anchor = db.get(ScopeCandidate, anchor_candidate_id)
        if anchor is None or anchor.status != "claimed" or anchor.root_entity_id != root_entity_id:
            raise CandidateInvalid("the anchoring candidate must be claimed, under the same organization")

    elif anchor_kind == "connector_instance":
        if anchor_connector_instance_id is None:
            raise CandidateInvalid("a connector_instance anchor needs the connector instance")
        instance = db.get(ConnectorInstance, anchor_connector_instance_id)
        if instance is None or instance.bound_entity_id != root_entity_id:
            raise CandidateInvalid("the anchoring connector instance must be bound to the organization")

    candidate = db.execute(
        select(ScopeCandidate)
        .where(
            ScopeCandidate.root_entity_id == root_entity_id,
            ScopeCandidate.kind == kind,
            ScopeCandidate.value == value,
        )
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    created_candidate = False
    if candidate is None:
        if spec.tier not in (STRONG, "supporting"):
            # A Context signal never creates a candidate.
            return SignalOutcome(outcome="skipped_context_only")
        inserted = db.execute(
            pg_insert(ScopeCandidate.__table__)
            .values(
                id=uuid.uuid4(), root_entity_id=root_entity_id, kind=kind, value=value, status="open",
                rir=rir, rir_handle=rir_handle,
            )
            .on_conflict_do_nothing(constraint="uq_scope_candidates_root_kind_value")
            .returning(ScopeCandidate.__table__.c.id)
        ).scalar()
        created_candidate = inserted is not None
        candidate = db.execute(
            select(ScopeCandidate)
            .where(
                ScopeCandidate.root_entity_id == root_entity_id,
                ScopeCandidate.kind == kind,
                ScopeCandidate.value == value,
            )
            .execution_options(populate_existing=True)
        ).scalar_one()
    if (candidate.rir, candidate.rir_handle) != (rir, rir_handle):
        raise CandidateConflict(
            f"{value} is already a candidate under a different registry or holder handle; it is never moved"
        )

    table = ScopeSignal.__table__
    row = db.execute(
        pg_insert(table)
        .values(
            id=uuid.uuid4(),
            candidate_id=candidate.id,
            signal_type=signal_type,
            anchor_kind=anchor_kind,
            anchor_candidate_id=anchor_candidate_id,
            anchor_entity_id=anchor_entity_id,
            anchor_connector_instance_id=anchor_connector_instance_id,
            anchor_user_id=anchor_user_id,
            via_entity_id=via_entity_id,
            evidence_id=evidence_id,
            quote=quote,
            observer_id=observer_id,
            matched_values=matched_values,
        )
        .on_conflict_do_update(constraint="uq_scope_signals_route", set_={"last_seen_at": _now()})
        .returning(table.c.id, literal_column("(xmax = 0)").label("inserted"))
    ).one()
    created_signal = bool(row.inserted)
    signal = db.execute(
        select(ScopeSignal).where(ScopeSignal.id == row.id).execution_options(populate_existing=True)
    ).scalar_one()

    unlocked = False
    if created_signal and spec.tier == STRONG:
        # Whatever status we read above: a reject may have committed since,
        # without our new type among its `rejected_strong_types`. The helper
        # locks the row and re-checks.
        unlocked = _maybe_unlock(db, candidate_id=candidate.id, signal=signal)
        if unlocked:
            db.refresh(candidate)
    db.flush()
    return SignalOutcome(
        outcome="recorded", candidate=candidate, signal=signal,
        created_candidate=created_candidate, created_signal=created_signal, unlocked=unlocked,
    )


def _maybe_unlock(db: Session, *, candidate_id: uuid.UUID, signal: ScopeSignal) -> bool:
    candidate = db.execute(
        select(ScopeCandidate).where(ScopeCandidate.id == candidate_id).with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    if candidate.status != "rejected" or signal.signal_type in (candidate.rejected_strong_types or []):
        return False
    old_reason = candidate.rejection_reason
    candidate.status = "open"
    candidate.rejection_reason = None
    candidate.rejected_strong_types = None
    candidate.decided_at = None
    candidate.decided_by_id = None
    db.add(ScopeCandidateEvent(
        id=uuid.uuid4(), candidate_id=candidate.id, event="unlocked", reason=old_reason, signal_id=signal.id,
    ))
    db.flush()
    return True


# ── a person adds a domain ──────────────────────────────────────────────────


def add_by_person(
    db: Session,
    *,
    root_entity_id: uuid.UUID,
    via_entity_id: uuid.UUID,
    domain: str,
    source_url: str,
    excerpt: str,
    quote: str,
    user,
    new_candidate_ids: list[uuid.UUID] | None = None,
) -> ScopeCandidate:
    """A person adds a domain with evidence. `excerpt` is stored as
    `person_supplied` evidence attributed to `source_url`; `quote` must be a
    substring of `excerpt` and must contain the domain as written (ASCII or
    punycode). The signal is Strong (`person_evidence`). Owner: commits. `new_candidate_ids`,
    when given, receives the candidate's id only if this call CREATED it
    (appended after the commit)."""
    if db.get(OrgEntity, root_entity_id) is None:
        raise CandidateNotFound("organization not found")
    domain = normalise_domain(domain)

    source_url = (source_url or "").strip()
    if not _SOURCE_URL_RE.match(source_url) or len(source_url) > _MAX_SOURCE_URL:
        raise CandidateInvalid("source_url must be an http(s) URL")
    if not excerpt or not excerpt.strip():
        raise CandidateInvalid("excerpt is required")
    if len(excerpt) > _MAX_EXCERPT:
        raise CandidateInvalid(f"excerpt is longer than {_MAX_EXCERPT} characters")
    quote = (quote or "").strip()
    if not quote:
        raise CandidateInvalid("quote is required")
    if len(quote) > _MAX_QUOTE:
        raise CandidateInvalid(f"quote is longer than {_MAX_QUOTE} characters")
    if quote not in excerpt:
        raise CandidateInvalid("quote must appear verbatim in the excerpt")
    if domain not in quote.lower():
        raise CandidateInvalid("quote must contain the domain as written (ASCII or punycode form)")
    if not _in_tree(db, root_entity_id, via_entity_id):
        raise CandidateInvalid(f"company is {NOT_IN_TREE_MESSAGE}")

    evidence = entity_graph.store_evidence(
        db,
        content=excerpt.encode("utf-8"),
        content_type="text/plain; charset=utf-8",
        source_url=source_url,
        fetched_at=_now(),
        origin="person_supplied",
    )
    try:
        outcome = record_signal(
            db, root_entity_id=root_entity_id, value=domain, signal_type="person_evidence",
            anchor_kind="person", anchor_user_id=user.id, via_entity_id=via_entity_id,
            evidence_id=evidence.id, quote=quote,
        )
        candidate = outcome.candidate
        db.commit()
    except CandidateError:
        db.rollback()
        raise
    except IntegrityError as exc:
        db.rollback()
        raise CandidateConflict("could not record the domain; it may have been added at the same time") from exc
    db.refresh(candidate)
    if outcome.created_candidate and new_candidate_ids is not None:
        new_candidate_ids.append(candidate.id)
    return candidate


# ── claim ───────────────────────────────────────────────────────────────────


@dataclass
class PrefixClaim:
    """One CIDR candidate claimed by an ASN's cascade."""

    candidate: ScopeCandidate
    target: Target
    created: bool


@dataclass
class ClaimResult:
    candidate: ScopeCandidate
    target: Target | None  # None for an ASN: it has no target, its prefixes do
    created: bool
    prefixes: list[PrefixClaim] = field(default_factory=list)  # an ASN's cascaded CIDRs


def _strength_row(db: Session, candidate_id: uuid.UUID):
    s = strength_sql.strength_subquery(candidate_ids=[candidate_id])
    return db.execute(
        select(s.subquery.c.proposable, s.subquery.c.strength, s.subquery.c.strong_types)
        .where(s.candidate_id == candidate_id)
    ).one_or_none()


def _live_engagements(db: Session, root_entity_id: uuid.UUID) -> list[Engagement]:
    return list(
        db.execute(
            select(Engagement)
            .where(
                Engagement.subject_entity_id == root_entity_id,
                Engagement.posture != EngagementPosture.ABANDONED.value,
            )
            .order_by(Engagement.created_at, Engagement.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalars()
    )


def _destination(db: Session, root: OrgEntity) -> Engagement | None:
    """The engagement to claim into, or None for our own estate. `root` is
    locked and fresh. Raises unless there is exactly one destination."""
    if root.relationship == RELATIONSHIP_OURS:
        return None
    if root.relationship == RELATIONSHIP_MA_TARGET:
        live = _live_engagements(db, root.id)
        if not live:
            raise CandidateConflict("this deal's engagement was abandoned; nothing can be claimed into it")
        if len(live) > 1:
            raise CandidateConflict("this organization has more than one live engagement; the destination is ambiguous")
        return live[0]
    raise CandidateConflict("set this organization's relationship first (ours or M&A target)")


def _attach_or_create_target(
    db: Session, *, value: str, target_type: TargetType, source_type: str, destination_id: uuid.UUID | None,
    entity_id: uuid.UUID, user, now: datetime, elsewhere_message: str, other_entity_message: str,
) -> tuple[Target, bool]:
    # FOR UPDATE: the check below and the write must not interleave with another
    # claim attributing the same target (held until the caller's commit).
    existing = db.execute(
        select(Target).where(Target.value == value).with_for_update().execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if existing is not None:
        if existing.engagement_id != destination_id:
            raise CandidateConflict(elsewhere_message)
        if existing.entity_id is not None and existing.entity_id != entity_id:
            raise CandidateConflict(other_entity_message)
        existing.entity_id = entity_id
        return existing, False
    target = Target(
        id=uuid.uuid4(),
        type=target_type.value,
        value=value,
        verified=True,
        verification_method=VerificationMethod.MANUAL.value,
        verified_by_id=user.id,
        verified_at=now,
        source_type=source_type,
        engagement_id=destination_id,
        entity_id=entity_id,
    )
    db.add(target)
    return target, True


def _write_claim(
    db: Session, candidate: ScopeCandidate, *, affiliated_id: uuid.UUID, destination_id: uuid.UUID | None,
    target: Target | None, user, now: datetime, connector_instance: ConnectorInstance | None = None,
) -> None:
    """The decider is a person (`user`) or, for `claim_by_connector`, a
    connector instance (`user` None): exactly one of the two. `target` is
    None only for an ASN."""
    candidate.status = "claimed"
    candidate.affiliated_entity_id = affiliated_id
    candidate.decided_at = now
    candidate.decided_by_id = user.id if user is not None else None
    candidate.decided_by_connector_instance_id = connector_instance.id if connector_instance is not None else None
    candidate.accepted_into = "engagement" if destination_id is not None else "estate"
    candidate.engagement_id = destination_id
    candidate.target_id = target.id if target is not None else None
    db.add(ScopeCandidateEvent(
        id=uuid.uuid4(), candidate_id=candidate.id, event="claimed",
        user_id=user.id if user is not None else None,
        connector_instance_id=connector_instance.id if connector_instance is not None else None,
    ))


def _require_cloud_dataset(db: Session) -> None:
    """Fail CLOSED: a prefix cannot be shown not to be cloud space while the
    cloud-range dataset has never been loaded. A stale dataset still counts
    as loaded. Called once per claim of a CIDR or an ASN, before any prefix."""
    if cloud_ranges.dataset_state(db) is None:
        raise CandidateConflict(
            "the cloud-range dataset has not been loaded, so this prefix cannot be shown not to be cloud space"
        )


def _claim_rolled_back(exc: IntegrityError) -> CandidateConflict:
    # Most likely `uq_targets_value` (the same target added concurrently).
    constraint = getattr(getattr(exc.orig, "diag", None), "constraint_name", None) or "integrity error"
    return CandidateConflict(f"claim was rolled back ({constraint}); nothing was changed")


def _refuse_cloud_space(db: Session, prefix: str) -> None:
    """Cloud and hosting space is never claimable (planning#278): a
    provider's published range is the provider's, whoever rents an address."""
    if cloud_ranges.overlaps_any(db, prefix):
        raise CandidateConflict(f"{prefix} overlaps published cloud ranges; cloud and hosting space is never claimable")


def _claim_handle_prefixes(
    db: Session, *, asn: ScopeCandidate, affiliated_id: uuid.UUID, destination_id: uuid.UUID | None, user, now: datetime,
) -> list[PrefixClaim]:
    """Claiming an ASN claims its RIR handle's ALLOCATIONS (never its BGP
    announcements): every CIDR candidate of the same root, registry and
    handle that is `open` and proposable becomes a CIDR target in the same
    destination, with the same affiliate, in the caller's transaction.
    Rejected and already-claimed prefixes are left alone. Locks the handle's
    CIDR candidates `ORDER BY id`. Flushes only. Raises `CandidateConflict`
    (the caller rolls back) when ANY of the handle's prefixes, in any status,
    overlaps a published cloud range, or when a prefix cannot be claimed."""
    handle_cidrs = list(db.execute(
        select(ScopeCandidate).where(
            ScopeCandidate.root_entity_id == asn.root_entity_id,
            ScopeCandidate.kind == "cidr",
            ScopeCandidate.rir == asn.rir,
            ScopeCandidate.rir_handle == asn.rir_handle,
        ).order_by(ScopeCandidate.id).with_for_update().execution_options(populate_existing=True)
    ).scalars())
    for cidr in handle_cidrs:
        if cloud_ranges.overlaps_any(db, cidr.value):
            raise CandidateConflict(
                f"the holder's space ({cidr.value}) overlaps published cloud ranges; "
                "cloud and hosting ASNs are never claimable"
            )
    open_ids = [c.id for c in handle_cidrs if c.status == "open"]
    proposable: set[uuid.UUID] = set()
    if open_ids:
        s = strength_sql.strength_subquery(candidate_ids=open_ids)
        proposable = set(db.execute(select(s.subquery.c.candidate_id).where(s.subquery.c.proposable)).scalars())
    claimed: list[PrefixClaim] = []
    for cidr in handle_cidrs:
        if cidr.id not in proposable:
            continue
        target, created = _attach_or_create_target(
            db, value=cidr.value, target_type=TargetType.CIDR, source_type=CIDR_TARGET_SOURCE_TYPE,
            destination_id=destination_id, entity_id=affiliated_id, user=user, now=now,
            elsewhere_message=f"{cidr.value} is already a target outside this destination; change it on the target itself",
            other_entity_message=f"the target {cidr.value} is already attributed to a different entity",
        )
        if created:
            db.flush()
        _write_claim(db, cidr, affiliated_id=affiliated_id, destination_id=destination_id,
                     target=target, user=user, now=now)
        claimed.append(PrefixClaim(candidate=cidr, target=target, created=created))
    db.flush()
    return claimed


def claim_by_connector(
    db: Session, *, candidate: ScopeCandidate, instance: ConnectorInstance, target: Target
) -> None:
    """A connector instance's active zone claims its own candidate under the
    instance's bound organization (planning#277 S1b): a person created the
    connector, so a person passively decided. Skips the proposable gate (a
    `connector_zone` signal is Strong; that is checked, not assumed). Flushes
    only; the caller owns the commit. Fails closed on any mismatch."""
    locked = db.execute(
        select(ScopeCandidate).where(ScopeCandidate.id == candidate.id).with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if locked is None:
        raise CandidateNotFound("candidate not found")
    if locked.status != "open":
        raise CandidateConflict(f"candidate is already {locked.status}")
    if locked.kind != "domain":
        raise CandidateConflict("a connector zone can only claim a domain")
    if instance.bound_entity_id is None or locked.root_entity_id != instance.bound_entity_id:
        raise CandidateConflict("the candidate belongs to a different organization than the connector instance")
    from app.services.connector_instances import SCOPE_ESTATE, instance_scope_key

    destination_id = target.engagement_id
    target_scope = SCOPE_ESTATE if destination_id is None else str(destination_id)
    if instance_scope_key(db, instance) != target_scope:
        raise CandidateConflict("the target is outside the connector instance's scope")
    has_signal = db.execute(
        select(ScopeSignal.id).where(
            ScopeSignal.candidate_id == locked.id,
            ScopeSignal.signal_type == "connector_zone",
            ScopeSignal.anchor_connector_instance_id == instance.id,
        ).limit(1)
    ).first()
    if has_signal is None:
        raise RuntimeError("the candidate has no connector_zone signal from this connector instance")
    _write_claim(
        db, locked, affiliated_id=instance.bound_entity_id, destination_id=destination_id,
        target=target, user=None, now=_now(), connector_instance=instance,
    )
    db.flush()


def claim(
    db: Session, *, candidate_id: uuid.UUID, user, affiliated_entity_id: uuid.UUID | None = None
) -> ClaimResult:
    """A person claims a proposable candidate. Owner: commits once."""
    candidate = db.execute(
        select(ScopeCandidate).where(ScopeCandidate.id == candidate_id).with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if candidate is None:
        raise CandidateNotFound("candidate not found")
    if candidate.status != "open":
        db.rollback()
        raise CandidateConflict(f"candidate is already {candidate.status}")

    row = _strength_row(db, candidate.id)
    if row is None or not row.proposable:
        db.rollback()
        raise CandidateConflict(NOT_PROPOSABLE_MESSAGE)

    affiliated_id = affiliated_entity_id
    if affiliated_id is None:
        affiliated_id = db.execute(
            select(strength_sql.default_affiliate_expr(candidate.id))
        ).scalar_one()
    if affiliated_id is None:
        db.rollback()
        raise CandidateInvalid(f"affiliated company is {NOT_IN_TREE_MESSAGE}")

    # Serialise against a concurrent relationship change on any company this
    # answer rests on (`entity_relationship`'s writers lock the same rows):
    # walk once, lock everything the walk read PLUS the root in one ordered
    # statement (one lock order for every claim), reloading past the identity
    # map, then walk again under the lock.
    first = entity_relationship.resolve(db, affiliated_id)
    lock_ids = sorted(set(first.visited) | {candidate.root_entity_id})
    locked = {
        e.id: e for e in db.execute(
            select(OrgEntity).where(OrgEntity.id.in_(lock_ids)).order_by(OrgEntity.id)
            .with_for_update().execution_options(populate_existing=True)
        ).scalars()
    }
    root = locked.get(candidate.root_entity_id)
    if root is None:
        db.rollback()
        raise CandidateNotFound("organization not found")
    # The destination first: it is the more truthful refusal when the root's
    # relationship has been cleared (the tree check below would then fail on
    # every company, the root included).
    try:
        engagement = _destination(db, root)
    except CandidateError:
        db.rollback()
        raise
    destination_id = engagement.id if engagement is not None else None

    second = entity_relationship.resolve(db, affiliated_id)
    if second.visited != first.visited or [(s.entity_id, s.relationship) for s in second.stops] != [
        (s.entity_id, s.relationship) for s in first.stops
    ]:
        db.rollback()
        raise CandidateConflict("this company's relationships changed while claiming; try again")
    if root.id not in {s.entity_id for s in second.stops}:
        db.rollback()
        raise CandidateInvalid(f"affiliated company is {NOT_IN_TREE_MESSAGE}")

    now = _now()
    target: Target | None = None
    created = False
    prefixes: list[PrefixClaim] = []
    try:
        if candidate.kind in ("asn", "cidr"):
            _require_cloud_dataset(db)
        if candidate.kind == "asn":
            prefixes = _claim_handle_prefixes(
                db, asn=candidate, affiliated_id=affiliated_id, destination_id=destination_id, user=user, now=now,
            )
        elif candidate.kind == "cidr":
            _refuse_cloud_space(db, candidate.value)
            target, created = _attach_or_create_target(
                db, value=candidate.value, target_type=TargetType.CIDR, source_type=CIDR_TARGET_SOURCE_TYPE,
                destination_id=destination_id, entity_id=affiliated_id, user=user, now=now,
                elsewhere_message="that prefix is already a target outside this destination; change it on the target itself",
                other_entity_message="that target is already attributed to a different entity",
            )
        else:
            target, created = _attach_or_create_target(
                db, value=candidate.value, target_type=TargetType.DOMAIN, source_type=TARGET_SOURCE_TYPE,
                destination_id=destination_id, entity_id=affiliated_id, user=user, now=now,
                elsewhere_message="that domain is already a target outside this destination; change it on the target itself",
                other_entity_message="that target is already attributed to a different entity",
            )
    except CandidateConflict:
        db.rollback()
        raise
    except IntegrityError as exc:
        # A flush inside the ASN cascade (or a target insert): nothing is committed.
        db.rollback()
        raise _claim_rolled_back(exc) from exc

    try:
        if created:
            # INSERT before the candidate's UPDATE references it (no ORM
            # relationship orders the two). A flush, not a commit: nothing
            # is visible to any other session until the single commit below.
            db.flush()
        _write_claim(db, candidate, affiliated_id=affiliated_id, destination_id=destination_id,
                     target=target, user=user, now=now)
        db.commit()
    except IntegrityError as exc:
        # Nothing was written: the target insert and the decision share this one commit.
        db.rollback()
        raise _claim_rolled_back(exc) from exc
    db.refresh(candidate)
    if target is not None:
        db.refresh(target)
    if created:
        # Tag rules -- the same step `ensure_pending` runs for a new target.
        target_service._apply_target_rules(db, target)
    for prefix in prefixes:
        db.refresh(prefix.candidate)
        db.refresh(prefix.target)
        if prefix.created:
            target_service._apply_target_rules(db, prefix.target)
    return ClaimResult(candidate=candidate, target=target, created=created, prefixes=prefixes)


def _claim_seed(
    db: Session, *, candidate: ScopeCandidate, root: OrgEntity, engagement: Engagement | None, user,
    elsewhere_message: str,
) -> ClaimResult:
    """`organizations.add_organization`'s claim of the seed domain: the same
    target and decision logic as `claim` without the proposable gate (the
    seed's own `admin_seed` signal is Strong; that is checked, not assumed).
    The destination is the one the caller just created. Flushes only; the
    caller owns the commit and the rollback."""
    if candidate.kind != "domain":
        raise ValueError("the seed candidate must be a domain")
    row = _strength_row(db, candidate.id)
    if row is None or not row.proposable or "admin_seed" not in (row.strong_types or []):
        raise RuntimeError("the seed candidate has no admin_seed signal")
    destination_id = engagement.id if engagement is not None else None
    now = _now()
    target, created = _attach_or_create_target(
        db, value=candidate.value, target_type=TargetType.DOMAIN, source_type=TARGET_SOURCE_TYPE,
        destination_id=destination_id, entity_id=root.id, user=user, now=now,
        elsewhere_message=elsewhere_message, other_entity_message=elsewhere_message,
    )
    if created:
        db.flush()
    _write_claim(db, candidate, affiliated_id=root.id, destination_id=destination_id,
                 target=target, user=user, now=now)
    db.flush()
    return ClaimResult(candidate=candidate, target=target, created=created)


# ── reject ──────────────────────────────────────────────────────────────────


def _reject_locked(db: Session, candidate: ScopeCandidate, *, user, reason: str) -> None:
    """Reject an `open` candidate already locked by the caller. Flushes."""
    strong = sorted(
        db.execute(
            select(ScopeSignal.signal_type).where(
                ScopeSignal.candidate_id == candidate.id,
                ScopeSignal.signal_type.in_(strength_sql.STRONG_TYPES),
            ).distinct()
        ).scalars()
    )
    candidate.status = "rejected"
    candidate.decided_at = _now()
    candidate.decided_by_id = user.id
    candidate.rejection_reason = reason
    candidate.rejected_strong_types = strong
    db.add(ScopeCandidateEvent(
        id=uuid.uuid4(), candidate_id=candidate.id, event="rejected", user_id=user.id, reason=reason,
    ))
    db.flush()


def reject(db: Session, *, candidate_id: uuid.UUID, user, reason: str) -> ScopeCandidate:
    """A person rejects an open candidate, with a reason. Owner: commits."""
    reason = (reason or "").strip()
    if not reason:
        raise CandidateInvalid("a reason is required")
    if len(reason) > MAX_REJECTION_REASON:
        raise CandidateInvalid(f"reason is longer than {MAX_REJECTION_REASON} characters")
    candidate = db.execute(
        select(ScopeCandidate).where(ScopeCandidate.id == candidate_id).with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if candidate is None:
        raise CandidateNotFound("candidate not found")
    if candidate.status != "open":
        db.rollback()
        raise CandidateConflict(f"candidate is already {candidate.status}")
    _reject_locked(db, candidate, user=user, reason=reason)
    db.commit()
    db.refresh(candidate)
    return candidate
