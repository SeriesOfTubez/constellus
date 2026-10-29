"""Rolling re-discovery: refresh org-discovery units oldest-due first (planning#277 S6b).

One run (hourly, see `scheduler._register_rediscovery_tick`) reads the units
that are due and refreshes them oldest first until it runs out of due units or
out of time. Each unit is therefore refreshed about weekly, with the load
spread across the week instead of one window that "becomes untenable" as the
estate grows.

The three units:
  - "claimed": a claimed domain candidate (reverse-IP + RIR refresh,
    `runner.refresh_claimed_domain`), stamped on `scope_candidates.rediscovered_at`.
  - "root": an organization root (reassignment sweep + dedicated-IP sweep,
    `runner.refresh_root`), stamped on `org_entities.rediscovered_at`.
  - "open": an open domain candidate re-verified against its root's claimed
    domains (`runner.verify_new_candidates`), stamped on `reverified_at`.

The due rule is `runner.due_clause`: never refreshed, or failed more than a day
ago, or refreshed more than a week ago.

Rate-limited is not failed: a unit that hit a rate limit is not stamped (it
stays due) and the run stops, leaving the rest due for the next hour. The
runner's caches are honoured (no `fresh_since`). Eligible roots are
`candidates.refreshable_root_clause()`: ours and live deals; an abandoned deal
stops. Claimed and root units take the root's Re-check slot (one root at a
time, never concurrently with a manual Re-check) and release it themselves;
open units run no RIR/pDNS and take no slot.

This opens its own sessions (a short read per unit, no session held across
third-party calls); never call it inside a request.
"""

import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select

from app.core.database import SessionLocal
from app.models.org_entity import OrgEntity
from app.models.scope_candidate import ScopeCandidate
from app.services.org_discovery import runner
from app.services.org_discovery.candidates import refreshable_root_clause

log = logging.getLogger(__name__)

TICK_TIME_LIMIT_S = 600  # one run works at most this long (planning#320 makes it a setting)
UNIT_PAUSE_S = 2  # between units: third-party lookups stay paced
DUE_BATCH = 200  # at most this many of each kind are read per run
_sleep = time.sleep  # tests patch it
_monotonic = time.monotonic  # tests patch it

_KIND_ORDER = {"claimed": 0, "root": 1, "open": 2}


@dataclass
class RollingResult:
    due: int = 0  # units read as due this run
    ok: int = 0
    failed: int = 0
    rate_limited: int = 0  # 0 or 1: the run stopped on it
    skipped_busy: int = 0  # root slot held (manual Re-check running)
    skipped: int = 0  # unit no longer eligible/due when reached
    errors: int = 0  # an unexpected exception in a unit
    out_of_time: bool = False


def _read_due(now: datetime) -> list[tuple[str, uuid.UUID, uuid.UUID, datetime | None]]:
    """The three due lists, merged oldest first: (kind, id, root_id, at)."""
    eligible = refreshable_root_clause()
    db = SessionLocal()
    try:
        claimed = db.execute(
            select(ScopeCandidate.id, ScopeCandidate.root_entity_id, ScopeCandidate.rediscovered_at)
            .join(OrgEntity, OrgEntity.id == ScopeCandidate.root_entity_id)
            .where(
                ScopeCandidate.kind == "domain", ScopeCandidate.status == "claimed", eligible,
                runner.due_clause(ScopeCandidate.rediscovered_at, ScopeCandidate.rediscovery_failed, now),
            )
            .order_by(ScopeCandidate.rediscovered_at.asc().nulls_first(), ScopeCandidate.id)
            .limit(DUE_BATCH)
        ).all()
        roots = db.execute(
            select(OrgEntity.id, OrgEntity.id, OrgEntity.rediscovered_at)
            .where(eligible, runner.due_clause(OrgEntity.rediscovered_at, OrgEntity.rediscovery_failed, now))
            .order_by(OrgEntity.rediscovered_at.asc().nulls_first(), OrgEntity.id)
            .limit(DUE_BATCH)
        ).all()
        opened = db.execute(
            select(ScopeCandidate.id, ScopeCandidate.root_entity_id, ScopeCandidate.reverified_at)
            .join(OrgEntity, OrgEntity.id == ScopeCandidate.root_entity_id)
            .where(
                ScopeCandidate.kind == "domain", ScopeCandidate.status == "open", eligible,
                runner.due_clause(ScopeCandidate.reverified_at, ScopeCandidate.reverify_failed, now),
            )
            .order_by(ScopeCandidate.reverified_at.asc().nulls_first(), ScopeCandidate.id)
            .limit(DUE_BATCH)
        ).all()
        db.rollback()
    finally:
        db.close()
    merged = (
        [("claimed", r[0], r[1], r[2]) for r in claimed]
        + [("root", r[0], r[1], r[2]) for r in roots]
        + [("open", r[0], r[1], r[2]) for r in opened]
    )
    epoch = datetime.min.replace(tzinfo=timezone.utc)  # None (never refreshed) sorts first
    merged.sort(key=lambda u: (u[3] or epoch, _KIND_ORDER[u[0]], str(u[1])))
    return merged


def _still_due(kind: str, unit_id: uuid.UUID) -> bool:
    """A short read at unit time: the row exists, its root is still eligible,
    it still has the right status, and it is still due now."""
    now = datetime.now(timezone.utc)
    eligible = refreshable_root_clause()
    db = SessionLocal()
    try:
        if kind == "root":
            stmt = select(OrgEntity.id).where(
                OrgEntity.id == unit_id, eligible,
                runner.due_clause(OrgEntity.rediscovered_at, OrgEntity.rediscovery_failed, now),
            )
        elif kind == "claimed":
            stmt = (
                select(ScopeCandidate.id).join(OrgEntity, OrgEntity.id == ScopeCandidate.root_entity_id)
                .where(
                    ScopeCandidate.id == unit_id, ScopeCandidate.kind == "domain",
                    ScopeCandidate.status == "claimed", eligible,
                    runner.due_clause(ScopeCandidate.rediscovered_at, ScopeCandidate.rediscovery_failed, now),
                )
            )
        else:
            stmt = (
                select(ScopeCandidate.id).join(OrgEntity, OrgEntity.id == ScopeCandidate.root_entity_id)
                .where(
                    ScopeCandidate.id == unit_id, ScopeCandidate.kind == "domain",
                    ScopeCandidate.status == "open", eligible,
                    runner.due_clause(ScopeCandidate.reverified_at, ScopeCandidate.reverify_failed, now),
                )
            )
        found = db.execute(stmt).first() is not None
        db.rollback()
        return found
    finally:
        db.close()


def _run_unit(kind: str, unit_id: uuid.UUID, root_id: uuid.UUID) -> str | None:
    """One unit; returns a runner UNIT_* outcome, or None when the root's slot
    is held (skipped_busy)."""
    if kind == "open":
        report = runner.verify_new_candidates([unit_id])
        if report.candidates_skipped > 0:
            return runner.UNIT_SKIPPED
        return runner.UNIT_FAILED if report.pairs_failed > 0 else runner.UNIT_OK
    if not runner.try_begin_recheck(root_id):
        return None
    try:
        if kind == "claimed":
            return runner.refresh_claimed_domain(unit_id)
        return runner.refresh_root(root_id, fresh_since=None)[0]
    finally:
        runner.end_recheck(root_id)


def run_rediscovery_tick() -> RollingResult:
    result = RollingResult()
    start = _monotonic()
    units = _read_due(datetime.now(timezone.utc))
    result.due = len(units)
    for index, (kind, unit_id, root_id, _at) in enumerate(units):
        if _monotonic() - start >= TICK_TIME_LIMIT_S:
            result.out_of_time = True
            break
        if index > 0:
            _sleep(UNIT_PAUSE_S)
        try:
            if not _still_due(kind, unit_id):
                result.skipped += 1
                continue
            outcome = _run_unit(kind, unit_id, root_id)
        except Exception:
            result.errors += 1
            log.exception("org-discovery rolling unit failed kind=%s id=%s", kind, unit_id)
            continue
        if outcome is None:
            result.skipped_busy += 1
        elif outcome == runner.UNIT_OK:
            result.ok += 1
        elif outcome == runner.UNIT_FAILED:
            result.failed += 1
        elif outcome == runner.UNIT_RATE_LIMITED:
            result.rate_limited = 1
            log.warning(
                "org-discovery rolling tick stopped: rate limited on %s unit; %d due units left untouched",
                kind, len(units) - index - 1,
            )
            break
        else:
            result.skipped += 1
    log.info(
        "org-discovery rolling tick due=%d ok=%d failed=%d rate_limited=%d skipped_busy=%d skipped=%d errors=%d out_of_time=%s",
        result.due, result.ok, result.failed, result.rate_limited, result.skipped_busy, result.skipped,
        result.errors, result.out_of_time,
    )
    return result
