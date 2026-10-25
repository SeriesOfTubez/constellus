"""Fixed-URL fetcher for RIR Whois-RWS lookups (planning#278 S3b1).

Outbound-safety rules (this module is the only place org discovery talks to a
registry):

- The base URL per registry is a module constant (`BASE_URLS`). No caller can
  supply a host, scheme, port or query string.
- A path is only ever built by the `arin_*` builders, each of which validates
  its input (`validate_handle`, `candidates.normalise_domain`). `get` checks the
  path again against `_ARIN_PATH_RE`, which allows exactly the builders' shapes,
  and refuses anything else (`..`, `?`, extra segments, a trailing slash).
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
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import null
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.connectors.http import connector_get
from app.models.rir_lookup_cache import RirLookupCache
from app.services.org_discovery import candidates

log = logging.getLogger(__name__)

BASE_URLS = {"arin": "https://whois.arin.net/rest/"}  # fixed; RIPE is added in S3b2
CACHE_TTL = timedelta(days=7)  # first slice: promote to settings in planning#313
MAX_REQUESTS_PER_RUN = 300  # planning#313


class RirFetchError(Exception):
    """Transport error, unexpected status or non-object JSON. Never cached."""


class BudgetExhausted(RirFetchError):
    pass


@dataclass
class Budget:
    limit: int = MAX_REQUESTS_PER_RUN
    used: int = 0  # network requests made
    cache_hits: int = 0


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


def get(db: Session, rir: str, path: str, budget: Budget, *, now: datetime | None = None) -> dict | None:
    """Return the registry's JSON object for `path`, or None for a 404.

    Raises ValueError for an unknown registry or a path no builder makes,
    BudgetExhausted when the run's request budget is spent, and RirFetchError
    for any transport or response problem. Flushes; never commits."""
    if rir not in BASE_URLS:
        raise ValueError("unknown registry")
    if not isinstance(path, str) or _ARIN_PATH_RE.fullmatch(path) is None:
        raise ValueError("path is not one the builders make")
    now = now or datetime.now(timezone.utc)

    row = db.get(RirLookupCache, (rir, path))
    if row is not None and now - row.fetched_at < CACHE_TTL:
        budget.cache_hits += 1
        return row.body

    if budget.used >= budget.limit:
        raise BudgetExhausted(f"{rir} request budget of {budget.limit} exhausted")
    budget.used += 1

    try:
        resp = connector_get(
            BASE_URLS[rir] + path,
            headers={"Accept": "application/json"},
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
        rir=rir, path=path, status_code=resp.status_code, body=body if body is not None else null(), fetched_at=now
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
