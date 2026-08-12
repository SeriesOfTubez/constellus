"""
Background refresher for the Certificate Transparency cache.

Certspotter's API is rate-limited heavily — 100 req/hr unauthenticated,
1000 req/hr with a free API token. Calling CT inline in every scan would
either blow through the limit or block runs for hours, so we maintain
ct_query_cache as a background-refreshed resource:

  - APScheduler fires `tick()` every TICK_INTERVAL_SECONDS.
  - Each tick picks up to `_calls_per_tick()` domain targets whose cache
    entry is missing or older than REFRESH_AFTER_SECONDS, oldest-first.
  - Each call writes to ct_query_cache. Calls within a tick are spaced
    by the per-call interval so we stay under the rate limit even if
    APScheduler runs ticks back-to-back during catch-up.

The scan executor reads `ct_query_cache` and never blocks on the
Certspotter API.
"""

import logging
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.secrets import get_secret
from app.models.ct_query_cache import CTQueryCache
from app.models.target import Target

log = logging.getLogger(__name__)

# How often the refresher tick fires.
TICK_INTERVAL_SECONDS = 60

# Refresh entries older than this — matches the cache success TTL so the
# executor's cache reads stay within the freshness window.
REFRESH_AFTER_SECONDS = 6 * 3600

# Rate caps per hour (Certspotter docs).
_RATE_PER_HOUR_AUTH = 1000
_RATE_PER_HOUR_UNAUTH = 100

# Leave headroom so foreground calls (initial discovery) don't push us
# over the cap on a tick-heavy hour.
_HEADROOM_FACTOR = 0.85


def tick() -> None:
    """One refresher pass. Idempotent; safe to call from APScheduler."""
    db = SessionLocal()
    try:
        budget = _calls_per_tick(db)
        if budget <= 0:
            return

        targets = _select_targets_to_refresh(db, budget)
        if not targets:
            return

        per_call_delay = 60.0 / budget if budget > 0 else 0
        log.info(
            "ct_refresher: refreshing %d domain(s) this tick (budget=%d, delay=%.1fs)",
            len(targets), budget, per_call_delay,
        )

        # Lazy import to avoid a startup cycle (cert_transparency imports
        # this module's siblings).
        from app.services.discovery import cert_transparency

        for i, domain in enumerate(targets):
            if i > 0 and per_call_delay > 0:
                time.sleep(per_call_delay)
            try:
                cert_transparency.prime_cache(domain)
            except Exception:
                log.exception("ct_refresher: prime_cache failed for %s", domain)
    finally:
        db.close()


# ── internals ─────────────────────────────────────────────────────────────────

def _calls_per_tick(db: Session) -> int:
    """How many calls this tick is allowed to make, given the current API
    plan and the configured tick interval."""
    has_token = bool(get_secret("CERTSPOTTER_API_TOKEN"))
    rate_per_hour = _RATE_PER_HOUR_AUTH if has_token else _RATE_PER_HOUR_UNAUTH
    ticks_per_hour = 3600 / TICK_INTERVAL_SECONDS
    return max(1, int((rate_per_hour * _HEADROOM_FACTOR) / ticks_per_hour))


def _select_targets_to_refresh(db: Session, limit: int) -> list[str]:
    """Pick domain targets whose CT cache is missing or stale, oldest first.

    Returns a list of target values (domain strings), up to `limit`. Missing
    cache entries take priority, then stale ones in fetched_at order.
    """
    domain_values = [
        v[0]
        for v in db.query(Target.value).filter(Target.type == "domain").all()
    ]
    if not domain_values:
        return []

    cached = {
        c.domain: c.fetched_at
        for c in db.query(CTQueryCache)
        .filter(CTQueryCache.domain.in_(domain_values))
        .all()
    }
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=REFRESH_AFTER_SECONDS)

    missing: list[str] = [v for v in domain_values if v not in cached]
    stale: list[tuple[str, datetime]] = [
        (v, cached[v]) for v in domain_values
        if v in cached and cached[v] < cutoff
    ]
    stale.sort(key=lambda x: x[1])

    return (missing + [v for v, _ in stale])[:limit]
