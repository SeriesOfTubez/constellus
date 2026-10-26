"""Fixed-URL fetcher for RIR lookups: ARIN Whois-RWS (S3b1) and RIPE (S3b2).

Outbound-safety rules (this module is the only place org discovery talks to a
registry):

- The base URL per registry is a module constant (`BASE_URLS`). No caller can
  supply a host, scheme or port, and no caller supplies a raw query string.
- A path is only ever built by the `arin_*` / `ripe_*` builders, each of which
  validates its input (`validate_handle`, `candidates.normalise_domain`, IP
  forms). `get` checks the path again against the registry's path regex, which
  allows exactly the builders' shapes, and refuses anything else (`..`, `?`,
  extra segments, a trailing slash).
- RIPE queries carry parameters: a validated params allowlist
  (`_validate_ripe`: keys, values, flag sets, canonical IP forms, the one
  fulltext shape) that `get` re-checks before the cache read or any transport
  call. Params are part of the cache key (`path?<sorted urlencoded pairs>`, in
  the existing `path` column) and are handed to httpx as a dict, never
  concatenated into the URL. ARIN takes no params.
- Redirects are never followed (`follow_redirects=False`).
- Only 200 (a JSON object) and 404 are accepted and cached; every other outcome
  raises `RirFetchError` and caches nothing.
- A per-run `Budget` caps network requests; a cache hit costs nothing.
- Logs carry counts or the registry only, never a path (it carries a domain or
  handle).

Transaction ownership: this module flushes but never commits. Its caller owns
the session (CONTRIBUTING.md, "Development principles").
"""

from __future__ import annotations

import logging
import ipaddress
import re
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import null
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.connectors.http import connector_get
from app.models.rir_lookup_cache import RirLookupCache
from app.services.org_discovery import candidates

log = logging.getLogger(__name__)

BASE_URLS = {"arin": "https://whois.arin.net/rest/", "ripe": "https://rest.db.ripe.net/"}  # fixed
CACHE_TTL = timedelta(days=7)  # first slice: promote to settings in planning#313
MAX_REQUESTS_PER_RUN = 300  # planning#313
RIPE_FULLTEXT_ROWS = 100  # planning#313
RIPE_MAX_FULLTEXT_PAGES = 3  # planning#313

Params = tuple[tuple[str, str], ...]  # key/value pairs; a key may repeat


class RirFetchError(Exception):
    """Transport error, unexpected status or non-object JSON. Never cached."""


class BudgetExhausted(RirFetchError):
    pass


@dataclass
class Budget:
    limit: int = MAX_REQUESTS_PER_RUN
    used: int = 0  # network requests made
    cache_hits: int = 0
    # A cached row fetched before this time is refetched. Set by a manual
    # Re-check to the run start, so a key repeated inside the run is fetched once.
    fresh_since: datetime | None = None


_HANDLE_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?$", re.ASCII)
_H = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?"
_DOMAIN_PART = r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?"
_ARIN_PATH_RE = re.compile(
    rf"(?:poc/{_H}(?:/orgs)?"
    rf"|org/{_H}/(?:nets|asns)"
    rf"|net/{_H}(?:/children)?"
    rf"|pocs;domain={_DOMAIN_PART}(?:\.{_DOMAIN_PART})+)",
    re.ASCII,
)
_RIPE_PATH_RE = re.compile(r"search\.json|fulltextsearch/select")
_PATH_RES = {"arin": _ARIN_PATH_RE, "ripe": _RIPE_PATH_RE}

_RIPE_TYPES = frozenset({"inetnum", "inet6num", "aut-num", "organisation"})
_RIPE_INVERSE = frozenset({"org", "admin-c", "tech-c", "abuse-c"})
_RIPE_SEARCH_KEYS = frozenset({"query-string", "type-filter", "inverse-attribute", "flags"})
_RIPE_FLAGS_REQUIRED = frozenset({"no-referenced", "no-irt"})
_RIPE_FLAGS_ALLOWED = _RIPE_FLAGS_REQUIRED | {"one-more"}
_RIPE_Q_RE = re.compile(r'\(e-mail:"([a-z0-9.-]+)"\) OR \(abuse-mailbox:"([a-z0-9.-]+)"\)', re.ASCII)


def validate_handle(value: str) -> str:
    if not isinstance(value, str) or _HANDLE_RE.fullmatch(value) is None:
        raise ValueError("not a valid registry handle")
    return value


def arin_pocs_by_domain(domain: str) -> str:
    try:
        d = candidates.normalise_domain(domain)
    except candidates.CandidateInvalid as exc:
        raise ValueError("not a valid domain") from exc
    return f"pocs;domain={d}"


def arin_poc(handle: str) -> str:
    return f"poc/{validate_handle(handle)}"


def arin_poc_orgs(handle: str) -> str:
    return f"poc/{validate_handle(handle)}/orgs"


def arin_org_nets(handle: str) -> str:
    return f"org/{validate_handle(handle)}/nets"


def arin_org_asns(handle: str) -> str:
    return f"org/{validate_handle(handle)}/asns"


def arin_net(handle: str) -> str:
    return f"net/{validate_handle(handle)}"


def arin_net_children(handle: str) -> str:
    return f"net/{validate_handle(handle)}/children"


def _canonical_ipv4_range(value: str) -> bool:
    parts = value.split(" - ")
    if len(parts) != 2:
        return False
    try:
        a, b = ipaddress.IPv4Address(parts[0]), ipaddress.IPv4Address(parts[1])
    except ValueError:
        return False
    return a <= b and value == f"{a} - {b}"


def _canonical_ipv6_network(value: str) -> bool:
    try:
        net = ipaddress.IPv6Network(value, strict=True)
    except ValueError:
        return False
    return str(net) == value


def _ip_form_ok(object_type: str, value: str) -> bool:
    if object_type == "inetnum":
        return _canonical_ipv4_range(value)
    if object_type == "inet6num":
        return _canonical_ipv6_network(value)
    return False


def _validate_ripe(path: str, params: Params) -> None:
    """Raise ValueError unless (path, params) is a query a `ripe_*` builder makes."""
    if len(set(params)) != len(params):
        raise ValueError("duplicate param")
    by_key: dict[str, list[str]] = {}
    for k, v in params:
        by_key.setdefault(k, []).append(v)

    if path == "fulltextsearch/select":
        if set(by_key) != {"q", "rows", "start"} or any(len(v) != 1 for v in by_key.values()):
            raise ValueError("bad fulltext params")
        if by_key["rows"][0] != str(RIPE_FULLTEXT_ROWS):
            raise ValueError("bad rows")
        if by_key["start"][0] not in {str(i * RIPE_FULLTEXT_ROWS) for i in range(RIPE_MAX_FULLTEXT_PAGES)}:
            raise ValueError("bad start")
        m = _RIPE_Q_RE.fullmatch(by_key["q"][0])
        if m is None or m.group(1) != m.group(2):
            raise ValueError("bad q")
        try:
            canonical = candidates.normalise_domain(m.group(1))
        except candidates.CandidateInvalid as exc:
            raise ValueError("bad q domain") from exc
        if canonical != m.group(1):
            raise ValueError("q domain is not canonical")
        return

    if path != "search.json":
        raise ValueError("unknown ripe path")
    if not set(by_key) <= _RIPE_SEARCH_KEYS:
        raise ValueError("unknown param key")
    qs = by_key.get("query-string", [])
    if len(qs) != 1:
        raise ValueError("need exactly one query-string")
    types = by_key.get("type-filter", [])
    if not types or not set(types) <= _RIPE_TYPES:
        raise ValueError("bad type-filter")
    inverse = by_key.get("inverse-attribute", [])
    if not set(inverse) <= _RIPE_INVERSE:
        raise ValueError("bad inverse-attribute")
    flags = set(by_key.get("flags", []))
    if not _RIPE_FLAGS_REQUIRED <= flags or not flags <= _RIPE_FLAGS_ALLOWED:
        raise ValueError("bad flags")

    if "one-more" in flags:
        if inverse or len(types) != 1 or types[0] not in ("inetnum", "inet6num"):
            raise ValueError("bad one-more query")
        if not _ip_form_ok(types[0], qs[0]):
            raise ValueError("one-more needs the canonical IP form")
    elif inverse:
        if _HANDLE_RE.fullmatch(qs[0]) is None:
            raise ValueError("inverse query needs a handle")
    else:
        raise ValueError("not a query the builders make")


def ripe_fulltext_by_domain(domain: str, page: int) -> tuple[str, Params]:
    try:
        d = candidates.normalise_domain(domain)
    except candidates.CandidateInvalid as exc:
        raise ValueError("not a valid domain") from exc
    if isinstance(page, bool) or not isinstance(page, int) or page not in range(RIPE_MAX_FULLTEXT_PAGES):
        raise ValueError("page out of range")
    params: Params = (
        ("q", f'(e-mail:"{d}") OR (abuse-mailbox:"{d}")'),
        ("rows", str(RIPE_FULLTEXT_ROWS)),
        ("start", str(page * RIPE_FULLTEXT_ROWS)),
    )
    _validate_ripe("fulltextsearch/select", params)
    return "fulltextsearch/select", params


def ripe_inverse(handle: str, attributes: tuple[str, ...], types: tuple[str, ...]) -> tuple[str, Params]:
    params: Params = (
        (("query-string", validate_handle(handle)),)
        + tuple(("inverse-attribute", a) for a in attributes)
        + tuple(("type-filter", t) for t in types)
        + (("flags", "no-referenced"), ("flags", "no-irt"))
    )
    _validate_ripe("search.json", params)
    return "search.json", params


def ripe_one_more(key: str, object_type: str) -> tuple[str, Params]:
    if object_type not in ("inetnum", "inet6num"):
        raise ValueError("one-more is for inetnum / inet6num only")
    params: Params = (
        ("query-string", key),
        ("type-filter", object_type),
        ("flags", "one-more"),
        ("flags", "no-referenced"),
        ("flags", "no-irt"),
    )
    _validate_ripe("search.json", params)
    return "search.json", params


def ripe_get(db: Session, query: tuple[str, Params], budget: Budget, *, now: datetime | None = None) -> dict | None:
    return get(db, "ripe", query[0], budget, params=query[1], now=now)


def get(
    db: Session, rir: str, path: str, budget: Budget, *, params: Params | None = None, now: datetime | None = None
) -> dict | None:
    """Return the registry's JSON object for `path`, or None for a 404.

    Raises ValueError for an unknown registry or a path no builder makes,
    BudgetExhausted when the run's request budget is spent, and RirFetchError
    for any transport or response problem. Flushes; never commits."""
    if rir not in BASE_URLS:
        raise ValueError("unknown registry")
    if not isinstance(path, str) or _PATH_RES[rir].fullmatch(path) is None:
        raise ValueError("path is not one the builders make")
    if rir == "arin":
        if params:
            raise ValueError("arin takes no params")
        params = None
    else:
        if not params:
            raise ValueError("ripe needs params")
        params = tuple(params)
        _validate_ripe(path, params)
    cache_key = path if params is None else path + "?" + urllib.parse.urlencode(sorted(params))
    wire_params: dict[str, list[str]] | None = None
    if params is not None:
        wire_params = {}
        for k, v in sorted(params):
            wire_params.setdefault(k, []).append(v)
    now = now or datetime.now(timezone.utc)

    row = db.get(RirLookupCache, (rir, cache_key))
    if (
        row is not None and now - row.fetched_at < CACHE_TTL
        and (budget.fresh_since is None or row.fetched_at >= budget.fresh_since)
    ):
        budget.cache_hits += 1
        return row.body

    if budget.used >= budget.limit:
        raise BudgetExhausted(f"{rir} request budget of {budget.limit} exhausted")
    budget.used += 1

    try:
        resp = connector_get(
            BASE_URLS[rir] + path,
            headers={"Accept": "application/json"},
            params=wire_params,
            timeout=20.0,
            follow_redirects=False,
        )
    except Exception as exc:
        raise RirFetchError(f"{rir} request failed: {type(exc).__name__}") from exc

    if resp.status_code == 200:
        try:
            body = resp.json()
        except Exception as exc:
            raise RirFetchError(f"{rir} returned a non-JSON 200") from exc
        if not isinstance(body, dict):
            raise RirFetchError(f"{rir} returned a non-object JSON 200")
    elif resp.status_code == 404:
        body = None
    else:
        raise RirFetchError(f"{rir} returned status {resp.status_code}")

    stmt = pg_insert(RirLookupCache).values(
        rir=rir, path=cache_key, status_code=resp.status_code, body=body if body is not None else null(), fetched_at=now
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=[RirLookupCache.rir, RirLookupCache.path],
        set_={"status_code": stmt.excluded.status_code, "body": stmt.excluded.body, "fetched_at": stmt.excluded.fetched_at},
    )
    db.execute(stmt)
    db.flush()
    # an ORM instance loaded earlier in this session would otherwise be stale
    if row is not None:
        db.refresh(row)
    return body
