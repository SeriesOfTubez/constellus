"""ARIN Whois-RWS collection for one claimed domain (planning#278 S3b1).

Returns PURE DATA (frozen dataclasses: no ORM objects, no signals). Slice C
turns an `ArinCollection` into signals.

What it collects, for one domain: the POCs ARIN lists for it, each POC's own
emails and status, the orgs each matched POC is linked to, each org's ASNs and
nets, and for every net the carve-out of space held by someone else.

Semantics (each one is tested):

- Exact-domain re-check. ARIN's `pocs;domain=` match is loose (tens of POCs
  for a bare domain), so the hit list is never trusted. A POC matches only if
  one of its own email addresses has a domain part (after the LAST "@",
  lower-cased) equal to the domain or a subdomain of it. A trailing dot
  ("example.com.") does NOT match: ARIN does not store addresses that way, so
  we fail closed rather than normalise it.
- validated = the POC's status code is exactly "PV" (a wrapped scalar).
  Anything else, including a missing or oddly shaped status, is not validated.
- The reassignee owns a reassigned prefix. A net is held by an org only if
  its `orgRef` is that org; a sub-allocation held by anyone else (another
  org, a customer, or an unparseable/absent holder) is FOREIGN and is carved
  out of the parent's space. A net that cannot be carved out proves nothing.
- Fail closed. Any net that cannot be fully walked (fetch error, budget,
  truncated children, depth, too many pieces, unparseable ranges) has
  `failed` set and `pieces == ()`.

`record_arin` turns a collection into signals (S3b1 part C). It flushes; the
evidence store it calls commits (see its docstring). Each `record_signal` runs in its own SAVEPOINT so one refused
resource does not poison the rest.

Transaction ownership: cache rows are flushed through `rir_fetch.get`; this
module never commits. Logs carry counts only (a path carries a domain or a
handle).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.scope_candidate import ScopeCandidate
from app.services import entity_graph
from app.services.org_discovery import candidates
from app.services.org_discovery import rir_fetch

log = logging.getLogger(__name__)

MAX_DEPTH = 3  # planning#313
MAX_PIECES = 64  # planning#313
ALLOWED_BLOCK_TYPES = frozenset({"DA", "DS", "A", "S", "R"})


@dataclass(frozen=True)
class ExcludedChild:
    handle: str
    holder_kind: Literal["org", "customer", "unknown"]
    holder_handle: str | None
    prefixes: tuple[str, ...]


@dataclass(frozen=True)
class RawBlock:
    start_address: str
    cidr_length: str
    type: str


@dataclass(frozen=True)
class NetResult:
    net_handle: str
    org_handle: str
    blocks: tuple[RawBlock, ...]
    pieces: tuple[str, ...]
    excluded: tuple[ExcludedChild, ...]
    failed: str | None


@dataclass(frozen=True)
class OrgResult:
    handle: str
    asns: tuple[str, ...]
    nets: tuple[NetResult, ...]
    asns_truncated: bool
    nets_truncated: bool
    skipped_nested: int
    skipped_not_held: int
    skipped_type: int
    invalid: int


@dataclass(frozen=True)
class MatchedPoc:
    handle: str
    validated: bool
    email_domains: tuple[str, ...]
    org_links: tuple[tuple[str, tuple[str, ...]], ...]


@dataclass(frozen=True)
class ArinCollection:
    domain: str
    pocs_listed: int
    pocs_truncated: bool
    pocs_not_exact: int
    matched: tuple[MatchedPoc, ...]
    orgs: dict[str, OrgResult] = field(default_factory=dict)
    fetch_failed: int = 0
    budget_exhausted: bool = False
    invalid_handles: int = 0


# ── shape helpers ────────────────────────────────────────────────────────────

def _as_list(x) -> list[dict]:
    """ARIN returns one result as an object and several as a list."""
    if x is None:
        return []
    if isinstance(x, dict):
        return [x]
    if isinstance(x, list):
        return [i for i in x if isinstance(i, dict)]
    return []


def _text(x) -> str | None:
    """`{"$": "v"}` -> "v" (stripped), anything else -> None."""
    if isinstance(x, dict):
        v = x.get("$")
        if isinstance(v, str):
            v = v.strip()
            return v or None
    return None


def _attr(x, key: str) -> str | None:
    """A reference attribute (`@handle`, ...) as a stripped string."""
    if isinstance(x, dict):
        v = x.get(key)
        if isinstance(v, str):
            v = v.strip()
            return v or None
    return None


def _truncated(container) -> bool:
    if isinstance(container, dict):
        return _text(container.get("limitExceeded")) == "true"
    return False


def _sub(x, key: str):
    return x.get(key) if isinstance(x, dict) else None


# ── control flow ─────────────────────────────────────────────────────────────

class _Stop(Exception):
    """The request budget is spent: stop all further fetching."""


class _NetFail(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _Run:
    def __init__(self, db: Session, budget: rir_fetch.Budget):
        self.db = db
        self.budget = budget
        self.fetch_failed = 0
        self.invalid_handles = 0
        self.budget_exhausted = False

    def fetch(self, path: str) -> dict | None:
        """rir_fetch.get; RirFetchError propagates, budget exhaustion becomes _Stop."""
        if self.budget_exhausted:
            raise _Stop()
        try:
            return rir_fetch.get(self.db, "arin", path, self.budget)
        except rir_fetch.BudgetExhausted:
            self.budget_exhausted = True
            raise _Stop() from None

    def handle(self, value: str | None) -> str | None:
        """Validate a handle taken from a response; count and drop an invalid one."""
        try:
            return rir_fetch.validate_handle(value)  # type: ignore[arg-type]
        except ValueError:
            self.invalid_handles += 1
            return None


# ── net handling ─────────────────────────────────────────────────────────────

def _parse_blocks(net: dict) -> tuple[list[dict], list[ipaddress._BaseNetwork]]:
    raw = _as_list(_sub(_sub(net, "netBlocks"), "netBlock"))
    nets = []
    for b in raw:
        nets.append(ipaddress.ip_network(f"{_text(b.get('startAddress'))}/{_text(b.get('cidrLength'))}", strict=True))
    return raw, nets


def _foreign_prefixes(child_ref: dict, child: dict | None) -> list[ipaddress._BaseNetwork]:
    """The child's own netBlocks as CIDRs, else the ref's start/end range."""
    if child is not None:
        try:
            _, nets = _parse_blocks(child)
            if nets:
                return nets
        except (ValueError, TypeError):
            pass
    try:
        start = ipaddress.ip_address(child_ref.get("@startAddress"))
        end = ipaddress.ip_address(child_ref.get("@endAddress"))
        return list(ipaddress.summarize_address_range(start, end))
    except (ValueError, TypeError):
        raise _NetFail("bad_child") from None


def _holder(net: dict | None) -> tuple[Literal["org", "customer", "unknown"], str | None]:
    if net is not None:
        org = _sub(net, "orgRef")
        if _attr(org, "@handle"):
            return "org", _attr(org, "@handle")
        cust = _sub(net, "customerRef")
        if _attr(cust, "@handle"):
            return "customer", _attr(cust, "@handle")
    return "unknown", None


def _walk(run: _Run, org: str, net_handle: str, depth: int, excluded: list[ExcludedChild]) -> None:
    body = run.fetch(rir_fetch.arin_net_children(net_handle))
    nets = _sub(body, "nets")
    if _truncated(nets):
        raise _NetFail("children_truncated")
    for ref in _as_list(_sub(nets, "netRef")):
        ch = run.handle(_attr(ref, "@handle"))
        if ch is None:
            raise _NetFail("bad_child")  # cannot prove what to exclude
        try:
            cbody = run.fetch(rir_fetch.arin_net(ch))
        except rir_fetch.RirFetchError:
            run.fetch_failed += 1
            raise _NetFail("fetch_failed") from None
        child = _sub(cbody, "net")
        child = child if isinstance(child, dict) else None
        if child is not None and _attr(_sub(child, "orgRef"), "@handle") == org:
            if depth + 1 > MAX_DEPTH:
                raise _NetFail("too_deep")
            _walk(run, org, ch, depth + 1, excluded)
            continue
        kind, holder = _holder(child)
        prefixes = _foreign_prefixes(ref, child)
        excluded.append(ExcludedChild(ch, kind, holder, tuple(str(p) for p in prefixes)))


def _remainder(blocks: list, foreign: list) -> list[str]:
    pieces: list = []
    for block in blocks:
        remaining = [block]
        for f in foreign:
            nxt = []
            for r in remaining:
                if r.version != f.version or not r.overlaps(f):
                    nxt.append(r)
                elif f != r and f.subnet_of(r):
                    nxt.extend(r.address_exclude(f))
                # else: f equals or contains r -> drop r
            remaining = nxt
        pieces.extend(remaining)
    out: list[str] = []
    for version in (4, 6):
        out.extend(str(p) for p in ipaddress.collapse_addresses([p for p in pieces if p.version == version]))
    return out


def _process_net(run: _Run, org: str, net_handle: str, body: dict) -> NetResult:
    net = _sub(body, "net")
    raw_blocks = _as_list(_sub(_sub(net, "netBlocks"), "netBlock"))
    raws = tuple(RawBlock(_text(b.get("startAddress")) or "", _text(b.get("cidrLength")) or "", _text(b.get("type")) or "")
                 for b in raw_blocks)
    excluded: list[ExcludedChild] = []

    def failed(code: str) -> NetResult:
        return NetResult(net_handle, org, raws, (), tuple(excluded), code)

    try:
        _, blocks = _parse_blocks(net)
    except (ValueError, TypeError):
        return failed("bad_block")
    if not blocks:
        return failed("bad_block")
    try:
        _walk(run, org, net_handle, 0, excluded)
    except _NetFail as exc:
        return failed(exc.code)
    except _Stop:
        return failed("budget")
    except rir_fetch.RirFetchError:
        run.fetch_failed += 1
        return failed("fetch_failed")
    foreign = [ipaddress.ip_network(p) for e in excluded for p in e.prefixes]
    pieces = _remainder(blocks, foreign)
    if len(pieces) > MAX_PIECES:
        return failed("too_many_pieces")
    return NetResult(net_handle, org, raws, tuple(pieces), tuple(excluded), None)


def _collect_org(run: _Run, org: str) -> OrgResult | None:
    """None when the org could not be fetched (counted)."""
    try:
        asn_body = run.fetch(rir_fetch.arin_org_asns(org))
        net_body = run.fetch(rir_fetch.arin_org_nets(org))
    except _Stop:
        return None
    except rir_fetch.RirFetchError:
        run.fetch_failed += 1
        return None

    asns_c = _sub(asn_body, "asns")
    nets_c = _sub(net_body, "nets")
    invalid = 0
    asns: list[str] = []
    for ref in _as_list(_sub(asns_c, "asnRef")):
        h = _attr(ref, "@handle")
        try:
            a = candidates.normalise_asn(h or "")
        except candidates.CandidateInvalid:
            invalid += 1
            continue
        if a not in asns:
            asns.append(a)

    refs: list[str] = []
    for ref in _as_list(_sub(nets_c, "netRef")):
        h = run.handle(_attr(ref, "@handle"))
        if h is not None and h not in refs:
            refs.append(h)
    own = set(refs)

    results: list[NetResult] = []
    skipped_nested = skipped_not_held = skipped_type = 0
    for nh in refs:
        try:
            body = run.fetch(rir_fetch.arin_net(nh))
        except _Stop:
            results.append(NetResult(nh, org, (), (), (), "budget"))
            break
        except rir_fetch.RirFetchError:
            run.fetch_failed += 1
            results.append(NetResult(nh, org, (), (), (), "fetch_failed"))
            continue
        net = _sub(body, "net")
        if not isinstance(net, dict) or _attr(_sub(net, "orgRef"), "@handle") != org:
            skipped_not_held += 1
            continue
        parent = _attr(_sub(net, "parentNetRef"), "@handle")
        if parent is not None and parent != nh and parent in own:
            skipped_nested += 1
            continue
        types = [_text(b.get("type")) for b in _as_list(_sub(_sub(net, "netBlocks"), "netBlock"))]
        if any(t not in ALLOWED_BLOCK_TYPES for t in types):
            skipped_type += 1
            continue
        res = _process_net(run, org, nh, body)
        results.append(res)
        if res.failed == "budget":
            break

    return OrgResult(
        handle=org,
        asns=tuple(asns),
        nets=tuple(results),
        asns_truncated=_truncated(asns_c),
        nets_truncated=_truncated(nets_c),
        skipped_nested=skipped_nested,
        skipped_not_held=skipped_not_held,
        skipped_type=skipped_type,
        invalid=invalid,
    )


# ── POC handling ─────────────────────────────────────────────────────────────

def _domain_matches(email_domain: str, d: str) -> bool:
    return email_domain == d or email_domain.endswith("." + d)


def _matching_domains(poc: dict | None, d: str) -> tuple[str, ...]:
    found: list[str] = []
    for e in _as_list(_sub(_sub(poc, "emails"), "email")):
        addr = _text(e)
        if addr is None or "@" not in addr:
            continue
        dom = addr.rpartition("@")[2].strip().lower()
        if dom and _domain_matches(dom, d) and dom not in found:
            found.append(dom)
    return tuple(sorted(found))


def collect(db: Session, domain: str, budget: rir_fetch.Budget) -> ArinCollection:
    d = candidates.normalise_domain(domain)
    run = _Run(db, budget)
    matched: list[MatchedPoc] = []
    orgs: dict[str, OrgResult] = {}
    seen_orgs: set[str] = set()  # memo, including orgs that failed
    listed = 0
    truncated = False
    not_exact = 0

    def result() -> ArinCollection:
        log.info(
            "arin collect: pocs_listed=%d matched=%d orgs=%d fetch_failed=%d budget_exhausted=%s",
            listed, len(matched), len(orgs), run.fetch_failed, run.budget_exhausted,
        )
        return ArinCollection(
            domain=d, pocs_listed=listed, pocs_truncated=truncated, pocs_not_exact=not_exact,
            matched=tuple(matched), orgs=orgs, fetch_failed=run.fetch_failed,
            budget_exhausted=run.budget_exhausted, invalid_handles=run.invalid_handles,
        )

    try:
        body = run.fetch(rir_fetch.arin_pocs_by_domain(d))
    except _Stop:
        return result()
    except rir_fetch.RirFetchError:
        run.fetch_failed += 1
        return result()
    pocs = _sub(body, "pocs")
    refs = _as_list(_sub(pocs, "pocRef"))
    listed = len(refs)
    truncated = _truncated(pocs)

    try:
        for ref in refs:
            ph = run.handle(_attr(ref, "@handle"))
            if ph is None:
                continue
            try:
                pbody = run.fetch(rir_fetch.arin_poc(ph))
            except rir_fetch.RirFetchError:
                run.fetch_failed += 1
                continue
            poc = _sub(pbody, "poc")
            domains = _matching_domains(poc, d)
            if not domains:
                not_exact += 1
                continue
            validated = _text(_sub(_sub(poc, "status"), "code")) == "PV"

            links: dict[str, list[str]] = {}
            stopped = False
            try:
                obody = run.fetch(rir_fetch.arin_poc_orgs(ph))
            except _Stop:
                obody, stopped = None, True
            except rir_fetch.RirFetchError:
                run.fetch_failed += 1
                obody = None
            for link in _as_list(_sub(_sub(obody, "orgs"), "orgPocLinkRef")):
                oh = run.handle(_attr(link, "@handle"))
                if oh is None:
                    continue
                fn = _attr(link, "@relPocFunction")
                funcs = links.setdefault(oh, [])
                if fn and fn not in funcs:
                    funcs.append(fn)
            matched.append(MatchedPoc(
                handle=ph, validated=validated, email_domains=domains,
                org_links=tuple((o, tuple(f)) for o, f in links.items()),
            ))
            if stopped:
                raise _Stop()
            for oh in links:
                if oh in seen_orgs:
                    continue
                seen_orgs.add(oh)
                res = _collect_org(run, oh)
                if res is not None:
                    orgs[oh] = res
                if run.budget_exhausted:
                    raise _Stop()
    except _Stop:
        pass
    return result()


# ── signals ──────────────────────────────────────────────────────────────────

_MAX_QUOTE = 2000


@dataclass
class ArinRecordResult:
    signals_recorded: int = 0
    signals_resighted: int = 0
    created_candidate_ids: list[uuid.UUID] = field(default_factory=list)
    orgs_holding_nothing: int = 0
    invalid: int = 0
    holder_conflict: int = 0
    context_recorded: int = 0
    context_no_candidate: int = 0
    # copied through from the collection
    pocs_listed: int = 0
    pocs_truncated: bool = False
    pocs_not_exact: int = 0
    fetch_failed: int = 0
    budget_exhausted: bool = False
    invalid_handles: int = 0
    nets_failed: dict[str, int] = field(default_factory=dict)


def _json(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _evidence_url(rule: str, resource: str, *parts: str) -> str:
    return "https://org-discovery.invalid/generate/" + "/".join((rule, "arin", resource.replace("/", "_"), *parts))


def _block_text(net: NetResult) -> list[str]:
    return [f"{b.start_address}/{b.cidr_length} {b.type}" for b in net.blocks]


def _cidr_quote(piece: str, net: NetResult, org: str, funcs: str, poc: MatchedPoc, claimed: str) -> str:
    """The needle (the piece) leads; only the block list is ever truncated."""
    head = f"{piece} is in ARIN net {net.net_handle} ("
    tail = f") held by org {org}; its {funcs} contact {poc.handle} ({'validated' if poc.validated else 'not validated'}) has an email at {claimed}"
    if net.excluded:
        tail += f"; {len(net.excluded)} reassigned sub-range(s) held elsewhere are excluded"
    blocks = ", ".join(_block_text(net))
    room = _MAX_QUOTE - len(head) - len(tail)
    if len(blocks) > room:
        blocks = blocks[: max(room - 3, 0)] + "..."
    return head + blocks + tail


def record_arin(
    db: Session,
    *,
    claimed: ScopeCandidate,
    collection: ArinCollection,
    observer_id: uuid.UUID | None = None,
) -> ArinRecordResult:
    """ARIN resources whose org has a contact with an email at the claimed
    domain become ASN / CIDR candidates (Strong when the contact is validated,
    Supporting otherwise); space reassigned away from a matched org decorates
    an EXISTING candidate with a Context signal.

    Flushes. It does not commit itself, but `entity_graph.store_evidence`
    COMMITS the session once per record (the same as `record_reverse_ip`), so
    only a session owner may call it, with nothing pending it cannot lose.
    Each `record_signal` runs in a SAVEPOINT: `CandidateInvalid` and `CandidateConflict` are counted and the
    next record still runs; anything else propagates. Never reads an entity
    name."""
    result = ArinRecordResult()
    if claimed.status != "claimed" or claimed.kind != "domain":
        return result
    claimed_value = claimed.value
    claimed_id = claimed.id
    root_id = claimed.root_entity_id
    affiliated_id = claimed.affiliated_entity_id
    now = datetime.now(timezone.utc)

    result.pocs_listed = collection.pocs_listed
    result.pocs_truncated = collection.pocs_truncated
    result.pocs_not_exact = collection.pocs_not_exact
    result.fetch_failed = collection.fetch_failed
    result.budget_exhausted = collection.budget_exhausted
    result.invalid_handles = collection.invalid_handles
    for o in collection.orgs.values():
        for n in o.nets:
            if n.failed is not None:
                result.nets_failed[n.failed] = result.nets_failed.get(n.failed, 0) + 1

    holding_nothing: set[str] = set()
    context_done: set[tuple[str, str, str, str]] = set()

    def _count(outcome) -> None:
        if outcome.created_signal:
            result.signals_recorded += 1
        else:
            result.signals_resighted += 1
        if outcome.created_candidate and outcome.candidate is not None:
            result.created_candidate_ids.append(outcome.candidate.id)

    for poc in sorted(collection.matched, key=lambda m: m.handle):
        rule = "rir_contact_email_claimed" if poc.validated else "rir_contact_email_unvalidated"
        for org, functions in poc.org_links:
            res = collection.orgs.get(org)
            if res is None:
                continue
            funcs = "/".join(functions) or "linked"
            verdict = "validated" if poc.validated else "not validated"
            resources: list[tuple[str, str, NetResult | None]] = [("asn", a, None) for a in res.asns]
            for n in res.nets:
                if n.failed is None:
                    resources.extend(("cidr", p, n) for p in n.pieces)
            if not resources:
                holding_nothing.add(org)
            for kind, value, net in resources:
                body: dict = {
                    "rule": rule, "rir": "arin", "claimed": claimed_value, "poc": poc.handle,
                    "poc_validated": poc.validated, "poc_email_domains": list(poc.email_domains), "org": org,
                    "functions": list(functions), "resource_kind": kind, "resource": value,
                }
                if net is None:
                    quote = (
                        f"{value} is held by ARIN org {org}; its {funcs} contact {poc.handle} ({verdict}) "
                        f"has an email at {claimed_value}"
                    )
                else:
                    body["net"] = net.net_handle
                    body["blocks"] = [
                        {"start": b.start_address, "cidrLength": b.cidr_length, "type": b.type} for b in net.blocks
                    ]
                    body["excluded"] = [
                        {"handle": e.handle, "holder_kind": e.holder_kind, "holder_handle": e.holder_handle,
                         "prefixes": list(e.prefixes)}
                        for e in net.excluded
                    ]
                    quote = _cidr_quote(value, net, org, funcs, poc, claimed_value)
                # `store_evidence` COMMITS (as in `record_reverse_ip`), so it runs outside the savepoint.
                evidence = entity_graph.store_evidence(
                    db, content=_json(body), content_type="application/json",
                    source_url=_evidence_url(rule, value, poc.handle, claimed_value),
                    fetched_at=now, origin="fetched",
                )
                try:
                    with db.begin_nested():
                        common = dict(
                            root_entity_id=root_id, kind=kind, value=value, rir="arin", rir_handle=org,
                            anchor_kind="claimed_candidate", anchor_candidate_id=claimed_id,
                            via_entity_id=affiliated_id, evidence_id=evidence.id, quote=quote,
                            observer_id=observer_id, matched_values=list(poc.email_domains),
                        )
                        if poc.validated:
                            outcome = candidates.record_signal(db, signal_type="rir_contact_email_claimed", **common)
                        else:
                            outcome = candidates.record_signal(db, signal_type="rir_contact_email_unvalidated", **common)
                except candidates.CandidateInvalid:
                    result.invalid += 1
                    continue
                except candidates.CandidateConflict:
                    result.holder_conflict += 1
                    continue
                _count(outcome)

            # Context: space reassigned away from this org, whatever the POC's validation.
            for n in res.nets:
                for ex in n.excluded:
                    for prefix in ex.prefixes:
                        key = (org, n.net_handle, ex.handle, prefix)
                        if key in context_done:
                            continue
                        context_done.add(key)
                        try:
                            norm = candidates.normalise_cidr(prefix)
                        except candidates.CandidateInvalid:
                            result.invalid += 1
                            continue
                        existing = db.execute(
                            select(ScopeCandidate).where(
                                ScopeCandidate.root_entity_id == root_id,
                                ScopeCandidate.kind == "cidr",
                                ScopeCandidate.value == norm,
                            )
                        ).scalar_one_or_none()
                        if existing is None or existing.rir != "arin":
                            result.context_no_candidate += 1
                            continue
                        ex_rir, ex_handle = existing.rir, existing.rir_handle
                        cbody = {
                            "rule": "rir_reassigned_elsewhere", "rir": "arin", "claimed": claimed_value, "org": org,
                            "net": n.net_handle, "child": ex.handle, "holder_kind": ex.holder_kind,
                            "holder_handle": ex.holder_handle, "prefix": prefix,
                        }
                        cquote = (
                            f"{prefix} is inside ARIN net {n.net_handle} held by org {org} but is reassigned to "
                            f"{ex.holder_kind} {ex.holder_handle or 'unknown'}"
                        )
                        evidence = entity_graph.store_evidence(
                            db, content=_json(cbody), content_type="application/json",
                            source_url=_evidence_url("rir_reassigned_elsewhere", prefix, org, n.net_handle, ex.handle, claimed_value),
                            fetched_at=now, origin="fetched",
                        )
                        try:
                            with db.begin_nested():
                                candidates.record_signal(
                                    db, root_entity_id=root_id, kind="cidr", value=prefix, rir=ex_rir, rir_handle=ex_handle,
                                    signal_type="rir_reassigned_elsewhere", anchor_kind="claimed_candidate",
                                    anchor_candidate_id=claimed_id, via_entity_id=affiliated_id,
                                    evidence_id=evidence.id, quote=cquote, observer_id=observer_id,
                                )
                        except candidates.CandidateInvalid:
                            result.invalid += 1
                            continue
                        except candidates.CandidateConflict:
                            result.holder_conflict += 1
                            continue
                        result.context_recorded += 1

    result.orgs_holding_nothing = len(holding_nothing)
    db.flush()
    return result
