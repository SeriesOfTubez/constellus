"""Has part of a claimed CIDR candidate been reassigned away? (planning#278 S3c3a)

`detect` is pure: given the prefix a candidate was claimed under, the holder
handle it was claimed on, and what the registry reports for that space now, it
says which parts of the prefix a different holder (or no one) governs. It does
no I/O. Fetching the registry answer and calling the writer from a Re-check is
S3c3b.

`record_reassignment` stores one such part against the claimed candidate
(migration 0089). It records only: the candidate stays claimed and its Target
stays.

Three outcomes of `detect`, never conflated: `None` = indeterminate (the answer
was incomplete or unreadable; nothing may be concluded), `()` = checked, nothing
reassigned, a tuple of `Reassigned` = those parts are held elsewhere.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from sqlalchemy import func, literal_column
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

from app.models.scope_candidate import ScopeCandidateReassignment

HolderKind = Literal["org", "customer", "unknown"]
NewHolderKind = Literal["org", "customer", "unknown", "unregistered"]

_Net = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class Registration:
    prefix: str  # one CIDR the registry reports (callers flatten multi-block nets)
    holder_kind: HolderKind
    holder_handle: str | None  # None iff holder_kind == "unknown"


@dataclass(frozen=True)
class RegistryAnswer:
    complete: bool  # False: fetch error / truncation / budget -> indeterminate
    registrations: tuple[Registration, ...]


@dataclass(frozen=True)
class Reassigned:
    prefix: str  # canonical CIDR text
    new_holder_kind: NewHolderKind
    new_holder_handle: str | None


def _net(text: str) -> _Net | None:
    try:
        return ipaddress.ip_network(text, strict=True)
    except (ValueError, TypeError):
        return None


def _consistent(reg: Registration) -> bool:
    if reg.holder_kind in ("org", "customer"):
        return bool(reg.holder_handle and reg.holder_handle.strip())
    return reg.holder_kind == "unknown" and reg.holder_handle is None


def _same_holder(reg: Registration, claimed_handle: str) -> bool:
    return (
        reg.holder_kind in ("org", "customer")
        and reg.holder_handle is not None
        and reg.holder_handle.casefold() == claimed_handle.casefold()
    )


def detect(claimed_prefix: str, holder_handle: str, answer: RegistryAnswer) -> tuple[Reassigned, ...] | None:
    """See the module docstring. Most specific registration wins per address;
    an address is reassigned away iff its governing registration is not held by
    `holder_handle` (case-insensitively; `unknown` is never the holder), or no
    registration governs it."""
    if not answer.complete or not holder_handle or not holder_handle.strip():
        return None
    claimed = _net(claimed_prefix)
    if claimed is None:
        return None

    overlapping: list[tuple[_Net, Registration]] = []
    for reg in answer.registrations:
        net = _net(reg.prefix)
        if net is None or not _consistent(reg):
            return None
        # Other-version registrations are ignored. CIDRs nest or are disjoint,
        # so `overlaps` means one contains the other (no partial overlaps).
        if net.version == claimed.version and net.overlaps(claimed):
            overlapping.append((net, reg))

    # Two registrations for the very same prefix with different holders: ambiguous.
    seen: dict[_Net, Registration] = {}
    for net, reg in overlapping:
        other = seen.get(net)
        if other is not None and (other.holder_kind, other.holder_handle) != (reg.holder_kind, reg.holder_handle):
            return None
        seen[net] = reg

    # Walk most specific first, carving each registration's share out of what remains.
    groups: dict[tuple[str, str | None], list[_Net]] = {}
    remaining: list[_Net] = [claimed]
    for net, reg in sorted(seen.items(), key=lambda item: item[0].prefixlen, reverse=True):
        still: list[_Net] = []
        taken: list[_Net] = []
        for piece in remaining:
            if not piece.overlaps(net):
                still.append(piece)
            elif piece.subnet_of(net):  # the registration covers the whole piece
                taken.append(piece)
            else:  # the registration lies inside the piece
                taken.append(net)
                still.extend(piece.address_exclude(net))
        remaining = still
        if taken and not _same_holder(reg, holder_handle):
            groups.setdefault((reg.holder_kind, reg.holder_handle), []).extend(taken)
    if remaining:
        groups.setdefault(("unregistered", None), []).extend(remaining)

    out = [
        Reassigned(str(n), kind, handle)  # type: ignore[arg-type]
        for (kind, handle), pieces in groups.items()
        for n in ipaddress.collapse_addresses(pieces)
    ]
    out.sort(key=lambda r: _sort_key(r))
    return tuple(out)


def _sort_key(r: Reassigned) -> tuple[int, int, int, str, str]:
    net = ipaddress.ip_network(r.prefix)
    return (net.version, int(net.network_address), net.prefixlen, r.new_holder_kind, r.new_holder_handle or "")


def record_reassignment(
    db: Session, *, candidate_id: uuid.UUID, found: Reassigned, evidence_id: uuid.UUID, now: datetime
) -> Literal["created", "seen"]:
    """Record one reassigned part against a claimed CIDR candidate, or move
    `last_seen_at` forward if it is already recorded (never backwards, and the
    first evidence stays). Flushes nothing and commits nothing: the caller owns
    the transaction. Never reads or writes the candidate or its Target. A
    candidate that is not a claimed cidr containing the prefix raises from the
    database trigger."""
    table = ScopeCandidateReassignment.__table__
    stmt = postgresql.insert(ScopeCandidateReassignment).values(
        candidate_id=candidate_id,
        prefix=found.prefix,
        new_holder_kind=found.new_holder_kind,
        new_holder_handle=found.new_holder_handle,
        evidence_id=evidence_id,
        first_detected_at=now,
        last_seen_at=now,
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_scope_candidate_reassignments_route",
        set_={"last_seen_at": func.greatest(table.c.last_seen_at, stmt.excluded.last_seen_at)},
    ).returning(literal_column("(xmax = 0)").label("created"))
    created = db.execute(stmt).scalar_one()
    return "created" if created else "seen"
