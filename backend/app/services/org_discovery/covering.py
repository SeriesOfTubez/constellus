"""Prefix-first covering lookups for a claimed CIDR (planning#278 S3c3b1).

For one claimed prefix, ask one registry what is registered over that space now
and flatten the answer into a `reassignment.RegistryAnswer`. Wiring this into a
Re-check, storing evidence and calling `reassignment.detect` is S3c3b2.

- Prefix first: the lookups are by the claimed prefix itself, never by holder.
  ARIN: `cidr/<net>/<len>/less` (everything containing it) and `/more`
  (everything inside it), both inclusive of an exact match. RIPE: the default
  lookup (the exact object, else the smallest covering one) and `all-more`
  (every object strictly inside, all depths).
- Callers pick the registry from the candidate's `rir`. A registry answers for
  space it does not hold (ARIN returns a stub covering net for RIPE space), so a
  404 or a stub never means "unregistered" by itself.
- Only a fully read answer is `complete`. Truncation, a missing or unreadable
  body, an answer that does not nest around the claimed prefix, too many objects,
  a budget stop or a transport error each give `complete=False` and a reason
  code, so `detect` returns "indeterminate" and nothing is concluded.
- A RIPE root placeholder (`ALLOCATED UNSPECIFIED`, e.g. the whole IPv4 space)
  is a registry placeholder, not a holder: it is skipped so space only it covers
  reads as unregistered. A RIPE holder is the object's `org` attribute; a
  contact is never a holder (`unknown` when there is no `org`).
- Addresses, not strings: every prefix and range is compared as an
  `ipaddress` object (ARIN returns IPv6 in upper case).
- Never raises for registry or data problems and never commits; the only flush
  is inside `rir_fetch.get`. Logs carry counts and reason codes only, never a
  prefix or a handle.
- `sources` keeps every body read (labelled with the cache key), in fetch order,
  404s omitted, for the evidence S3c3b2 stores.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.services.org_discovery import arin, rir_fetch, ripe
from app.services.org_discovery.reassignment import Registration, RegistryAnswer

log = logging.getLogger(__name__)

ARIN_MAX_NET_FETCHES = 64  # planning#313
RIPE_MAX_OBJECTS = 1000  # planning#313

_PLACEHOLDER_STATUS = "ALLOCATED UNSPECIFIED"
_IP_TYPES = ("inetnum", "inet6num")

_Net = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class Covering:
    answer: RegistryAnswer  # complete=False on any failure
    reason: str | None  # None iff answer.complete
    sources: tuple[tuple[str, dict], ...]  # (cache-key label, raw JSON body), fetch order, 404s omitted


def _failed(reason: str, sources: list[tuple[str, dict]]) -> Covering:
    log.info("covering lookup incomplete: %s (%d bodies read)", reason, len(sources))
    return Covering(RegistryAnswer(False, ()), reason, tuple(sources))


def _complete(registrations: tuple[Registration, ...], sources: list[tuple[str, dict]]) -> Covering:
    log.info("covering lookup complete: %d registrations (%d bodies read)", len(registrations), len(sources))
    return Covering(RegistryAnswer(True, registrations), None, tuple(sources))


# ── pure flatteners ──────────────────────────────────────────────────────────

def arin_net_registrations(net_body: dict) -> tuple[Registration, ...]:
    """One Registration per netBlock CIDR of an ARIN `net/<handle>` body.
    ValueError when the body has no parseable block."""
    net = arin._sub(net_body, "net")
    if not isinstance(net, dict):
        raise ValueError("no net object")
    try:
        _, blocks = arin._parse_blocks(net)
    except (ValueError, TypeError) as exc:
        raise ValueError("unparseable netBlock") from exc
    if not blocks:
        raise ValueError("no netBlock")
    kind, handle = arin._holder(net)
    return tuple(Registration(str(b), kind, handle) for b in blocks)


def _ripe_nets(obj: dict) -> list[_Net]:
    """The networks of one RIPE inetnum / inet6num object; ValueError if unreadable."""
    pk = ripe._pk(obj)
    if pk is None:
        raise ValueError("object without a primary key")
    return ripe._ranges(obj.get("type"), pk)


def _ripe_ip_objects(body: dict | None) -> list[dict]:
    return [o for o in ripe._objects(body) if o.get("type") in _IP_TYPES]


def ripe_registrations(body: dict) -> tuple[Registration, ...]:
    """Registrations for every inetnum / inet6num object in a RIPE search body.
    ValueError for an object not from the RIPE source or one that cannot be parsed."""
    out: list[Registration] = []
    for obj in _ripe_ip_objects(body):
        if not ripe._source_ok(obj):
            raise ValueError("object not from the ripe source")
        attrs = ripe._attrs(obj)
        status = attrs.get("status", [""])[0]
        if status.upper() == _PLACEHOLDER_STATUS:
            continue
        nets = _ripe_nets(obj)
        orgs = attrs.get("org")
        for n in nets:
            if orgs:
                out.append(Registration(str(n), "org", orgs[0]))
            else:
                out.append(Registration(str(n), "unknown", None))
    return tuple(out)


# ── fetch ────────────────────────────────────────────────────────────────────

def _read(db: Session, rir: str, path: str, params: rir_fetch.Params | None, budget: rir_fetch.Budget,
          sources: list[tuple[str, dict]]) -> dict | None:
    body = rir_fetch.get(db, rir, path, budget, params=params)
    if body is not None:
        sources.append((f"{rir}:{rir_fetch.cache_key(path, params)}", body))
    return body


def _contains(outer: _Net, inner: _Net) -> bool:
    return outer.version == inner.version and inner.subnet_of(outer)


def _arin_refs(body: dict) -> list[tuple[str, int, int, int]]:
    """(handle, version, start, end) per netRef; ValueError when unreadable."""
    nets = arin._sub(body, "nets")
    if not isinstance(nets, dict):
        raise ValueError("no nets object")
    out = []
    for ref in arin._as_list(nets.get("netRef")):
        handle = rir_fetch.validate_handle(arin._attr(ref, "@handle") or "")
        start = ipaddress.ip_address(arin._attr(ref, "@startAddress"))
        end = ipaddress.ip_address(arin._attr(ref, "@endAddress"))
        if start.version != end.version or int(start) > int(end):
            raise ValueError("bad range")
        out.append((handle, start.version, int(start), int(end)))
    return out


def fetch_arin(db: Session, claimed_prefix: str, budget: rir_fetch.Budget) -> Covering:
    sources: list[tuple[str, dict]] = []
    try:
        claimed = rir_fetch._canonical_cidr(claimed_prefix)
        less_path = rir_fetch.arin_cidr_less(claimed_prefix)
        more_path = rir_fetch.arin_cidr_more(claimed_prefix)
    except ValueError:
        return _failed("bad_prefix", sources)
    lo, hi = int(claimed.network_address), int(claimed.broadcast_address)

    try:
        less = _read(db, "arin", less_path, None, budget, sources)
        if less is None:
            return _failed("no_covering", sources)
        more = _read(db, "arin", more_path, None, budget, sources)
    except rir_fetch.BudgetExhausted:
        return _failed("budget", sources)
    except rir_fetch.RirFetchError:
        return _failed("fetch_error", sources)

    if arin._truncated(arin._sub(less, "nets")) or arin._truncated(arin._sub(more, "nets")):
        return _failed("truncated", sources)
    try:
        less_refs = _arin_refs(less)
        more_refs = _arin_refs(more) if more is not None else []
    except (ValueError, TypeError):
        return _failed("unparseable", sources)
    if not less_refs:
        return _failed("no_covering", sources)
    if any(v != claimed.version or s > lo or e < hi for _, v, s, e in less_refs):
        return _failed("escaping", sources)
    if any(v != claimed.version or s < lo or e > hi for _, v, s, e in more_refs):
        return _failed("escaping", sources)

    smallest = min(e - s for _, _, s, e in less_refs)
    handles: list[str] = []
    for h, _, s, e in less_refs:
        if e - s == smallest and h not in handles:
            handles.append(h)
    for h, _, _, _ in more_refs:
        if h not in handles:
            handles.append(h)
    if len(handles) > ARIN_MAX_NET_FETCHES:
        return _failed("too_many", sources)

    regs: list[Registration] = []
    try:
        for h in handles:
            body = _read(db, "arin", rir_fetch.arin_net(h), None, budget, sources)
            if body is None:
                return _failed("net_missing", sources)
            try:
                regs.extend(arin_net_registrations(body))
            except ValueError:
                return _failed("unparseable", sources)
    except rir_fetch.BudgetExhausted:
        return _failed("budget", sources)
    except rir_fetch.RirFetchError:
        return _failed("fetch_error", sources)
    return _complete(tuple(regs), sources)


def fetch_ripe(db: Session, claimed_prefix: str, budget: rir_fetch.Budget) -> Covering:
    sources: list[tuple[str, dict]] = []
    try:
        claimed = rir_fetch._canonical_cidr(claimed_prefix)
        key, otype = rir_fetch.ripe_key(claimed_prefix)
        cov_q = rir_fetch.ripe_covering(key, otype)
        more_q = rir_fetch.ripe_all_more(key, otype)
    except ValueError:
        return _failed("bad_prefix", sources)

    try:
        cov = _read(db, "ripe", cov_q[0], cov_q[1], budget, sources)
        if cov is None or ripe._has_error(cov):
            return _failed("no_covering", sources)
        allm = _read(db, "ripe", more_q[0], more_q[1], budget, sources)
    except rir_fetch.BudgetExhausted:
        return _failed("budget", sources)
    except rir_fetch.RirFetchError:
        return _failed("fetch_error", sources)
    if allm is not None and ripe._has_error(allm):
        return _failed("fetch_error", sources)

    if len(ripe._objects(cov)) + len(ripe._objects(allm)) > RIPE_MAX_OBJECTS:
        return _failed("too_many", sources)

    cov_objs = _ripe_ip_objects(cov)
    if len(cov_objs) != 1:
        return _failed("unparseable", sources)
    try:
        cov_nets = _ripe_nets(cov_objs[0])
        more_nets = [n for o in _ripe_ip_objects(allm) for n in _ripe_nets(o)]
    except ValueError:
        return _failed("unparseable", sources)
    if cov_objs[0].get("type") != otype or not any(_contains(n, claimed) for n in cov_nets):
        return _failed("escaping", sources)
    if not all(_contains(claimed, n) for n in more_nets):
        return _failed("escaping", sources)

    try:
        regs = ripe_registrations(cov) + ripe_registrations(allm or {})
    except ValueError:
        return _failed("unparseable", sources)
    return _complete(regs, sources)
