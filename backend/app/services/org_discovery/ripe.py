"""RIPE database collection for one claimed domain (planning#278 S3b2).

Returns PURE DATA (frozen dataclasses: no ORM objects, no signals, no
evidence). Slice C turns a `RipeCollection` into signals.

What it collects, for one domain: the organisation / role / person objects the
RIPE full-text index lists for it, re-checked exactly; the resources
(inetnum, inet6num, aut-num) each matched contact is linked to, directly or
through an organisation it administers; and for every IP resource the one-level
carve-out of space registered to someone else.

Semantics (each one is tested):

- Exact-domain re-check. The full-text hit list is loose (documents whose
  addresses are at other domains are returned), so it is never trusted. A
  document matches only if one of its own `e-mail` / `abuse-mailbox` values
  (cut at the first "#", which starts a comment) has a domain part (after the
  LAST "@", lower-cased) equal to the domain or a subdomain of it. A trailing
  dot does NOT match: fail closed rather than normalise it. Only
  organisation / role / person documents are considered.
- A hit list longer than the page cap is reported (`fulltext_truncated`) and
  what was seen is still processed: fewer leads, never wrong scope.
- Holder. A resource's `org` attribute when present (holder_kind "org"),
  otherwise the lexicographically smallest matched contact that led to it
  (holder_kind "contact"). One holder per resource, deterministic.
- Only objects whose source is exactly "ripe" and whose status is on the
  per-type allowlist are ever proposed.
- Carve-out: ONE `one-more` lookup per allowed IP resource. EVERY child is
  subtracted from the parent's space. A child proposed on its own with the same
  holder is `nested`; a child of the same org that was not collected is
  `nested_not_collected` (not proposed, not foreign); every other child is an
  `ExcludedChild`. Nothing deeper is ever fetched.
- Fail closed. Any resource that cannot be fully carved out (fetch error,
  budget, error response, unparseable or escaping child, too many pieces) has
  `failed` set and `pieces == ()`.

Signals (`record_ripe`): every RIPE match is SUPPORTING, never Strong. RIPE has
no per-object validation and a holder can cite someone else's role object, so
this module writes only `rir_contact_email_unvalidated` (and the Context signal
`rir_reassigned_elsewhere`).

Transaction ownership: `collect` flushes cache rows through `rir_fetch` and
never commits; `record_ripe` is a session-owner call (see its docstring). It reads no person, role or organisation name. Logs carry
counts only (a query carries a domain or a handle).
"""

from __future__ import annotations

import ipaddress
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
from app.services.org_discovery.arin import (
    ExcludedChild, MAX_PIECES, _MAX_QUOTE, _domain_matches, _json, _remainder,
)

log = logging.getLogger(__name__)

# ARIN's children list stops at 256 (`limitExceeded`) and fails closed; RIPE's
# one-more has no cap (a live LIR allocation returned 22k children), so the
# same bound is applied here.
MAX_CHILDREN = 256  # planning#313

CONTACT_TYPES = frozenset({"organisation", "role", "person"})
RESOURCE_TYPES = ("inetnum", "inet6num", "aut-num")
ALLOWED_STATUS: dict[str, frozenset[str]] = {
    "inetnum": frozenset({
        "ALLOCATED PA", "ALLOCATED PI", "ALLOCATED-ASSIGNED PA", "SUB-ALLOCATED PA", "LIR-PARTITIONED PA",
        "ASSIGNED PA", "ASSIGNED PI", "ASSIGNED ANYCAST", "LEGACY",
    }),
    "inet6num": frozenset({
        "ALLOCATED-BY-RIR", "ALLOCATED-BY-LIR", "ALLOCATED-ASSIGNED PA", "ASSIGNED", "ASSIGNED PI", "ASSIGNED ANYCAST",
    }),
    "aut-num": frozenset({"ASSIGNED", "LEGACY"}),
}
_CONTACT_ATTRS = ("admin-c", "tech-c", "abuse-c")


@dataclass(frozen=True)
class MatchedContact:
    handle: str
    object_type: str
    email_domains: tuple[str, ...]


@dataclass(frozen=True)
class RipeResource:
    object_type: str
    primary_key: str  # verbatim, for quoting
    status: str
    holder: str
    holder_kind: Literal["org", "contact"]
    via: tuple[str, ...]
    via_attributes: tuple[str, ...]
    asn: str | None
    pieces: tuple[str, ...]
    excluded: tuple[ExcludedChild, ...]
    nested: tuple[str, ...]
    nested_not_collected: int
    failed: str | None


@dataclass(frozen=True)
class RipeCollection:
    domain: str
    docs_found: int
    docs_seen: int
    fulltext_truncated: bool
    docs_other_type: int
    contacts_not_exact: int
    matched: tuple[MatchedContact, ...]
    resources: tuple[RipeResource, ...]
    orgs_followed: int
    fetch_failed: int
    budget_exhausted: bool
    invalid_handles: int
    invalid: int
    skipped_status: int
    skipped_source: int


# ── shape helpers ────────────────────────────────────────────────────────────

def _dicts(x) -> list[dict]:
    """RIPE returns lists; tolerate a lone object, drop anything else."""
    if isinstance(x, dict):
        return [x]
    if isinstance(x, list):
        return [i for i in x if isinstance(i, dict)]
    return []


def _sub(x, key: str):
    return x.get(key) if isinstance(x, dict) else None


def _str(x) -> str | None:
    if isinstance(x, str):
        x = x.strip()
        return x or None
    return None


def _objects(body: dict | None) -> list[dict]:
    return _dicts(_sub(_sub(body, "objects"), "object"))


def _pk(obj: dict) -> str | None:
    for a in _dicts(_sub(_sub(obj, "primary-key"), "attribute")):
        v = _str(a.get("value"))
        if v is not None:
            return v
    return None


def _attrs(obj: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for a in _dicts(_sub(_sub(obj, "attributes"), "attribute")):
        k, v = _str(a.get("name")), _str(a.get("value"))
        if k is not None and v is not None:
            out.setdefault(k, []).append(v)
    return out


def _source_ok(obj: dict) -> bool:
    return _sub(_sub(obj, "source"), "id") == "ripe"


def _has_error(body: dict | None) -> bool:
    return any(m.get("severity") == "Error" for m in _dicts(_sub(_sub(body, "errormessages"), "errormessage")))


def _ranges(object_type: str, pk: str) -> list:
    """The resource's networks; ValueError when it cannot be parsed."""
    if object_type == "inetnum":
        parts = pk.split(" - ")
        if len(parts) != 2:
            raise ValueError("bad range")
        a, b = ipaddress.IPv4Address(parts[0].strip()), ipaddress.IPv4Address(parts[1].strip())
        return list(ipaddress.summarize_address_range(a, b))
    if object_type == "inet6num":
        return [ipaddress.IPv6Network(pk, strict=True)]
    raise ValueError("not an IP resource")


# ── control flow ─────────────────────────────────────────────────────────────

class _Stop(Exception):
    """The request budget is spent: stop all further fetching."""


class _Fail(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _Run:
    def __init__(self, db: Session, budget: rir_fetch.Budget):
        self.db = db
        self.budget = budget
        self.fetch_failed = 0
        self.invalid_handles = 0
        self.invalid = 0
        self.skipped_status = 0
        self.skipped_source = 0
        self.budget_exhausted = False

    def fetch(self, query) -> dict | None:
        """rir_fetch.ripe_get; RirFetchError propagates, budget exhaustion becomes _Stop."""
        if self.budget_exhausted:
            raise _Stop()
        try:
            return rir_fetch.ripe_get(self.db, query, self.budget)
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


class _Rec:
    """A collected resource, before status / holder / carve-out."""

    def __init__(self, object_type: str, pk: str, attrs: dict[str, list[str]]):
        self.object_type = object_type
        self.pk = pk
        self.attrs = attrs
        self.via: set[str] = set()
        self.via_attrs: set[str] = set()


# ── full text ────────────────────────────────────────────────────────────────

def _fulltext(run: _Run, d: str) -> tuple[int, bool, list[dict]]:
    """(numFound, truncated, docs); RirFetchError ends paging, _Stop propagates."""
    docs: list[dict] = []
    found = 0
    page = 0
    while True:
        try:
            body = run.fetch(rir_fetch.ripe_fulltext_by_domain(d, page))
        except rir_fetch.RirFetchError:
            run.fetch_failed += 1
            break
        if body is None:
            break
        if _has_error(body):
            run.fetch_failed += 1
            break
        result = _sub(body, "result")
        page_docs = _dicts(_sub(result, "docs"))
        n = _sub(result, "numFound")
        num = n if isinstance(n, int) and not isinstance(n, bool) else len(page_docs)
        if page == 0:
            found = num
        s = _sub(result, "start")
        start = s if isinstance(s, int) and not isinstance(s, bool) else page * rir_fetch.RIPE_FULLTEXT_ROWS
        docs.extend(page_docs)
        page += 1
        if start + rir_fetch.RIPE_FULLTEXT_ROWS < num and page < rir_fetch.RIPE_MAX_FULLTEXT_PAGES:
            continue
        break
    truncated = found > rir_fetch.RIPE_MAX_FULLTEXT_PAGES * rir_fetch.RIPE_FULLTEXT_ROWS
    return found, truncated, docs


def _doc_fields(doc: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for s in _dicts(_sub(_sub(doc, "doc"), "strs")):
        item = _sub(s, "str")
        k, v = _str(_sub(item, "name")), _str(_sub(item, "value"))
        if k is not None and v is not None:
            out.setdefault(k, []).append(v)
    return out


def _matching_domains(fields: dict[str, list[str]], d: str) -> tuple[str, ...]:
    found: set[str] = set()
    for key in ("e-mail", "abuse-mailbox"):
        for value in fields.get(key, []):
            addr = value.split("#", 1)[0].strip()
            if "@" not in addr:
                continue
            dom = addr.rpartition("@")[2].strip().lower()
            if dom and _domain_matches(dom, d):
                found.add(dom)
    return tuple(sorted(found))


# ── collection ───────────────────────────────────────────────────────────────

class _Gather:
    def __init__(self, run: _Run):
        self.run = run
        self.recs: dict[tuple[str, str], _Rec] = {}
        self.org_keys: dict[str, list[tuple[str, str]]] = {}
        self.orgs_followed = 0

    def lookup(self, handle: str, attrs: tuple[str, ...], types: tuple[str, ...], via: str,
               bucket: list[tuple[str, str]] | None) -> None:
        run = self.run
        try:
            body = run.fetch(rir_fetch.ripe_inverse(handle, attrs, types))
        except rir_fetch.RirFetchError:
            run.fetch_failed += 1
            return
        if body is None:
            return  # 404: the handle holds nothing
        if _has_error(body):
            run.fetch_failed += 1
            return
        for obj in _objects(body):
            otype = obj.get("type")
            if otype not in types:
                continue
            if not _source_ok(obj):
                run.skipped_source += 1
                continue
            pk = _pk(obj)
            if pk is None:
                continue
            if otype == "organisation":
                oh = run.handle(pk)
                if oh is not None:
                    self.follow_org(oh, via)
                continue
            key = (otype, pk)
            rec = self.recs.get(key)
            if rec is None:
                rec = self.recs[key] = _Rec(otype, pk, _attrs(obj))
            rec.via.add(via)
            for a in attrs:
                if any(v.lower() == handle.lower() for v in rec.attrs.get(a, [])):
                    rec.via_attrs.add(a)
            if bucket is not None and key not in bucket:
                bucket.append(key)

    def follow_org(self, org: str, via: str) -> None:
        """Follow an organisation ONCE per run; later contacts only add themselves to `via`."""
        known = self.org_keys.get(org)
        if known is not None:
            for key in known:
                self.recs[key].via.add(via)
            return
        bucket: list[tuple[str, str]] = []
        self.org_keys[org] = bucket
        self.orgs_followed += 1
        self.lookup(org, ("org",), RESOURCE_TYPES, via, bucket)

    def contact(self, c: MatchedContact) -> None:
        if c.object_type == "organisation":
            known = self.org_keys.get(c.handle)
            if known is not None:
                for key in known:
                    self.recs[key].via.add(c.handle)
                return
            bucket: list[tuple[str, str]] = []
            self.org_keys[c.handle] = bucket
            self.lookup(c.handle, ("org",), RESOURCE_TYPES, c.handle, bucket)
        else:
            self.lookup(c.handle, _CONTACT_ATTRS, (*RESOURCE_TYPES, "organisation"), c.handle, None)


# ── resources ────────────────────────────────────────────────────────────────

def _holder(run: _Run, rec: _Rec) -> tuple[Literal["org", "contact"], str] | None:
    org = rec.attrs.get("org")
    if org:
        h = run.handle(org[0])
        return ("org", h) if h is not None else None
    return "contact", min(rec.via)


def _carve(run: _Run, rec: _Rec, blocks: list, holder: tuple[str, str],
           in_set: dict[tuple[str, str], tuple[str, str]], excluded: list[ExcludedChild],
           nested: list[str]) -> tuple[list[str], int]:
    """(pieces, nested_not_collected); raises _Fail with the code."""
    try:
        query = rir_fetch.ripe_one_more(rec.pk, rec.object_type)
    except ValueError:
        raise _Fail("bad_range") from None
    try:
        body = run.fetch(query)
    except _Stop:
        raise _Fail("budget") from None
    except rir_fetch.RirFetchError:
        run.fetch_failed += 1
        raise _Fail("fetch_failed") from None
    if body is None:
        return _remainder(blocks, []), 0
    if _has_error(body):
        raise _Fail("error_response")
    if len(_objects(body)) > MAX_CHILDREN:
        raise _Fail("too_many_children")
    children: list = []
    seen: set[str] = set()
    not_collected = 0
    for obj in _objects(body):
        if obj.get("type") != rec.object_type or not _source_ok(obj):
            raise _Fail("bad_child")
        cpk = _pk(obj)
        if cpk is None:
            raise _Fail("bad_child")
        try:
            nets = _ranges(rec.object_type, cpk)
        except ValueError:
            raise _Fail("bad_child") from None
        if set(nets) == set(blocks):
            continue  # the parent itself
        if not all(any(n.subnet_of(b) for b in blocks) for n in nets):
            raise _Fail("bad_child")
        if cpk in seen:
            continue
        seen.add(cpk)
        children.extend(nets)
        corg = _attrs(obj).get("org")
        ch = run.handle(corg[0]) if corg else None
        if in_set.get((rec.object_type, cpk)) == holder:
            nested.append(cpk)
        elif holder[0] == "org" and ch is not None and ch == holder[1]:
            not_collected += 1
        else:
            excluded.append(ExcludedChild(
                handle=cpk, holder_kind="org" if ch is not None else "unknown", holder_handle=ch,
                prefixes=tuple(str(n) for n in nets),
            ))
    pieces = _remainder(blocks, children)
    if len(pieces) > MAX_PIECES:
        raise _Fail("too_many_pieces")
    return pieces, not_collected


def collect(db: Session, domain: str, budget: rir_fetch.Budget) -> RipeCollection:
    d = candidates.normalise_domain(domain)
    run = _Run(db, budget)
    found = 0
    truncated = False
    docs: list[dict] = []
    try:
        found, truncated, docs = _fulltext(run, d)
    except _Stop:
        pass

    other_type = not_exact = 0
    contacts: dict[str, tuple[str, set[str]]] = {}
    for doc in docs:
        fields = _doc_fields(doc)
        otype = (fields.get("object-type") or [None])[0]
        if otype not in CONTACT_TYPES:
            other_type += 1
            continue
        domains = _matching_domains(fields, d)
        if not domains:
            not_exact += 1
            continue
        h = run.handle((fields.get("lookup-key") or [None])[0])
        if h is None:
            continue
        prev = contacts.get(h)
        if prev is None:
            contacts[h] = (otype, set(domains))
        else:
            prev[1].update(domains)
    matched = tuple(MatchedContact(h, t, tuple(sorted(ds))) for h, (t, ds) in sorted(contacts.items()))

    gather = _Gather(run)
    if not run.budget_exhausted:
        try:
            for c in matched:
                gather.contact(c)
        except _Stop:
            pass

    # pass 1: status, holder, and the set of resources that will be proposed
    kept: list[tuple[_Rec, tuple[str, str]]] = []
    in_set: dict[tuple[str, str], tuple[str, str]] = {}
    for key in sorted(gather.recs):
        rec = gather.recs[key]
        status = (rec.attrs.get("status") or [""])[0]
        if status not in ALLOWED_STATUS[rec.object_type]:
            run.skipped_status += 1
            continue
        holder = _holder(run, rec)
        if holder is None:
            continue
        kept.append((rec, holder))
        in_set[key] = holder

    # pass 2: ASN normalisation and the one-level carve-out
    resources: list[RipeResource] = []
    for rec, holder in kept:
        status = rec.attrs["status"][0]
        base = dict(
            object_type=rec.object_type, primary_key=rec.pk, status=status, holder=holder[1], holder_kind=holder[0],
            via=tuple(sorted(rec.via)), via_attributes=tuple(sorted(rec.via_attrs)),
        )
        if rec.object_type == "aut-num":
            try:
                asn = candidates.normalise_asn(rec.pk)
            except candidates.CandidateInvalid:
                run.invalid += 1
                continue
            resources.append(RipeResource(**base, asn=asn, pieces=(), excluded=(), nested=(),
                                          nested_not_collected=0, failed=None))
            continue
        excluded: list[ExcludedChild] = []
        nested: list[str] = []
        not_collected = 0
        pieces: list[str] = []
        failed: str | None = None
        try:
            try:
                blocks = _ranges(rec.object_type, rec.pk)
            except ValueError:
                raise _Fail("bad_range") from None
            pieces, not_collected = _carve(run, rec, blocks, holder, in_set, excluded, nested)
        except _Fail as exc:
            failed = exc.code
            pieces = []
        resources.append(RipeResource(
            **base, asn=None, pieces=tuple(pieces), excluded=tuple(excluded), nested=tuple(nested),
            nested_not_collected=not_collected, failed=failed,
        ))

    log.info(
        "ripe collect: docs_found=%d docs_seen=%d matched=%d resources=%d orgs_followed=%d fetch_failed=%d "
        "budget_exhausted=%s",
        found, len(docs), len(matched), len(resources), gather.orgs_followed, run.fetch_failed, run.budget_exhausted,
    )
    return RipeCollection(
        domain=d, docs_found=found, docs_seen=len(docs), fulltext_truncated=truncated,
        docs_other_type=other_type, contacts_not_exact=not_exact, matched=matched,
        resources=tuple(sorted(resources, key=lambda r: (r.object_type, r.primary_key))),
        orgs_followed=gather.orgs_followed, fetch_failed=run.fetch_failed,
        budget_exhausted=run.budget_exhausted, invalid_handles=run.invalid_handles, invalid=run.invalid,
        skipped_status=run.skipped_status, skipped_source=run.skipped_source,
    )


# ── signals ──────────────────────────────────────────────────────────────────

@dataclass
class RipeRecordResult:
    signals_recorded: int = 0
    signals_resighted: int = 0
    created_candidate_ids: list[uuid.UUID] = field(default_factory=list)
    holders_holding_nothing: int = 0
    invalid: int = 0
    holder_conflict: int = 0
    context_recorded: int = 0
    context_no_candidate: int = 0
    # copied through from the collection
    docs_found: int = 0
    fulltext_truncated: bool = False
    contacts_not_exact: int = 0
    fetch_failed: int = 0
    budget_exhausted: bool = False
    invalid_handles: int = 0
    skipped_status: int = 0
    skipped_source: int = 0
    resources_failed: dict[str, int] = field(default_factory=dict)


def _evidence_url(rule: str, resource: str, *parts: str) -> str:
    """Every segment is made path-safe: an inet6num key carries a `/` and an
    inetnum key (`a - b`) carries spaces."""
    segs = (rule, "ripe", resource, *parts)
    return "https://org-discovery.invalid/generate/" + "/".join(s.replace("/", "_").replace(" ", "") for s in segs)


def _cidr_quote(piece: str, res: RipeResource, contacts: list[str], claimed: str) -> str:
    """The needle (the piece) leads; only the contact list is ever truncated."""
    head = f"{piece} is in RIPE {res.object_type} {res.primary_key} ({res.status}) held by {res.holder_kind} {res.holder}; contact(s) "
    tail = f" have an email at {claimed}"
    if res.excluded:
        tail += f"; {len(res.excluded)} more-specific(s) held elsewhere are excluded"
    who = ", ".join(contacts)
    room = _MAX_QUOTE - len(head) - len(tail)
    if len(who) > room:
        who = who[: max(room - 3, 0)] + "..."
    return head + who + tail


def record_ripe(
    db: Session,
    *,
    claimed: ScopeCandidate,
    collection: RipeCollection,
    observer_id: uuid.UUID | None = None,
) -> RipeRecordResult:
    """RIPE resources reached through a contact with an email at the claimed
    domain become ASN / CIDR candidates with ONE Supporting signal per
    (resource, value); never Strong. Space registered to someone else inside a
    collected inetnum decorates an EXISTING RIPE candidate with a Context signal.

    Flushes. It does not commit itself, but `entity_graph.store_evidence`
    COMMITS the session once per record, so only a session owner may call it,
    with nothing pending it cannot lose. Each `record_signal` runs in a
    SAVEPOINT: `CandidateInvalid` and `CandidateConflict` are counted and the
    next record still runs; anything else propagates. Never reads a name."""
    result = RipeRecordResult()
    if claimed.status != "claimed" or claimed.kind != "domain":
        return result
    claimed_value = claimed.value
    claimed_id = claimed.id
    root_id = claimed.root_entity_id
    affiliated_id = claimed.affiliated_entity_id
    now = datetime.now(timezone.utc)

    result.docs_found = collection.docs_found
    result.fulltext_truncated = collection.fulltext_truncated
    result.contacts_not_exact = collection.contacts_not_exact
    result.fetch_failed = collection.fetch_failed
    result.budget_exhausted = collection.budget_exhausted
    result.invalid_handles = collection.invalid_handles
    result.skipped_status = collection.skipped_status
    result.skipped_source = collection.skipped_source
    for r in collection.resources:
        if r.failed is not None:
            result.resources_failed[r.failed] = result.resources_failed.get(r.failed, 0) + 1

    matched = {m.handle: m for m in collection.matched}
    yielded: dict[str, int] = {}
    seen_holders: set[str] = set()
    context_done: set[tuple[str, str, str, str]] = set()

    def _count(outcome) -> None:
        if outcome.created_signal:
            result.signals_recorded += 1
        else:
            result.signals_resighted += 1
        if outcome.created_candidate and outcome.candidate is not None:
            result.created_candidate_ids.append(outcome.candidate.id)

    for res in collection.resources:
        seen_holders.add(res.holder)
        yielded.setdefault(res.holder, 0)
        via_matched = [matched[h] for h in sorted(res.via) if h in matched]
        contact_handles = [m.handle for m in via_matched] or sorted(res.via)
        domains = sorted({d for m in via_matched for d in m.email_domains})

        if res.failed is None:
            if res.object_type == "aut-num":
                values: list[tuple[str, str]] = [("asn", res.asn)] if res.asn else []
            else:
                values = [("cidr", p) for p in res.pieces]
            yielded[res.holder] += len(values)
            for kind, value in values:
                body: dict = {
                    "rule": "rir_contact_email_unvalidated", "rir": "ripe", "claimed": claimed_value,
                    "holder": res.holder, "holder_kind": res.holder_kind,
                    "via": [
                        {"handle": m.handle, "object_type": m.object_type, "email_domains": list(m.email_domains)}
                        for m in via_matched
                    ],
                    "via_handles": sorted(res.via), "via_attributes": list(res.via_attributes),
                    "object_type": res.object_type, "primary_key": res.primary_key, "status": res.status,
                    "resource_kind": kind, "resource": value,
                }
                if kind == "cidr":
                    body["excluded"] = [
                        {"handle": e.handle, "holder_kind": e.holder_kind, "holder_handle": e.holder_handle,
                         "prefixes": list(e.prefixes)}
                        for e in res.excluded
                    ]
                    body["nested"] = list(res.nested)
                    quote = _cidr_quote(value, res, contact_handles, claimed_value)
                else:
                    quote = (
                        f"{value} is RIPE aut-num {res.primary_key} ({res.status}) held by {res.holder_kind} "
                        f"{res.holder}; contact(s) {', '.join(contact_handles)} have an email at {claimed_value}"
                    )[:_MAX_QUOTE]
                # `store_evidence` COMMITS, so it runs outside the savepoint.
                evidence = entity_graph.store_evidence(
                    db, content=_json(body), content_type="application/json",
                    source_url=_evidence_url("rir_contact_email_unvalidated", value, res.holder, claimed_value),
                    fetched_at=now, origin="fetched",
                )
                try:
                    with db.begin_nested():
                        outcome = candidates.record_signal(
                            db, signal_type="rir_contact_email_unvalidated",
                            root_entity_id=root_id, kind=kind, value=value, rir="ripe", rir_handle=res.holder,
                            anchor_kind="claimed_candidate", anchor_candidate_id=claimed_id,
                            via_entity_id=affiliated_id, evidence_id=evidence.id, quote=quote,
                            observer_id=observer_id, matched_values=domains,
                        )
                except candidates.CandidateInvalid:
                    result.invalid += 1
                    continue
                except candidates.CandidateConflict:
                    result.holder_conflict += 1
                    continue
                _count(outcome)

        # Context: space registered to someone else inside this resource.
        for ex in res.excluded:
            for prefix in ex.prefixes:
                key = (res.holder, res.primary_key, ex.handle, prefix)
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
                if existing is None or existing.rir != "ripe":
                    result.context_no_candidate += 1
                    continue
                ex_rir, ex_handle = existing.rir, existing.rir_handle
                cbody = {
                    "rule": "rir_reassigned_elsewhere", "rir": "ripe", "claimed": claimed_value,
                    "holder": res.holder, "object_type": res.object_type, "primary_key": res.primary_key,
                    "child": ex.handle, "holder_kind": ex.holder_kind, "holder_handle": ex.holder_handle,
                    "prefix": prefix,
                }
                cquote = (
                    f"{prefix} is inside RIPE {res.object_type} {res.primary_key} held by {res.holder_kind} "
                    f"{res.holder} but is registered to {ex.holder_kind} {ex.holder_handle or 'unknown'}"
                )
                evidence = entity_graph.store_evidence(
                    db, content=_json(cbody), content_type="application/json",
                    source_url=_evidence_url(
                        "rir_reassigned_elsewhere", prefix, res.holder, res.primary_key, ex.handle, claimed_value),
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

    result.holders_holding_nothing = sum(1 for h in seen_holders if yielded.get(h, 0) == 0)
    db.flush()
    return result
