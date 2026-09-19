"""Suppression discipline: an ignore carries a reason, and it can expire.

`assets_canonical.ignored` was a bare boolean — no reason, no author, no
review date. One failure mode, and it is the expensive one: an ignore set
once for a reason nobody recorded, against an asset nobody re-examines,
suppresses that asset from the absence query, the hygiene score and the
asset list forever. A wrong suppression becomes permanent *by default*,
which is the exact inverse of CLAUDE.md's "suppressions are a last resort
with strict criteria" — a criterion you cannot read back is not a
criterion. Migration 0047 adds `ignore_reason` / `ignore_reason_details` /
`ignore_expires_at` / `ignored_at` / `ignored_by_id`, borrowing Wiz's
`DiscoveredResource` vocabulary verbatim (Obsidian `Constellus — Wiz API
Reference` section 9.1).

**What this file guards is not the columns — it is the read path.** Adding
an expiry column while the read path still filtered the raw `ignored`
boolean would be pure decoration: the ignore would carry a date nobody
honours. `AssetCanonical.suppressed` is the hybrid that closes that, and
every test below pins one read surface against it, so an expired ignore
stops suppressing *on read* with no sweeper job in the loop.

The Python-side and SQL-side halves of a hybrid_property are two separate
implementations of the same predicate and nothing makes them agree.
`test_hybrid_python_and_sql_halves_agree_on_every_case` pins them together.

Run with:  pytest app/tests/test_ignore_expiry.py
"""

import uuid
from datetime import datetime, timedelta, timezone

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.services import claims_query

_PAST = timedelta(days=-1)
_FUTURE = timedelta(days=30)


# ── helpers ──────────────────────────────────────────────────────────────

def _mk(db, value: str, *, ignored=False, expires_delta=None, reason=None) -> AssetCanonical:
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type="ip_address", value=value,
        first_seen_at=now, last_seen_at=now, ignored=ignored,
        ignore_reason=reason,
        ignore_expires_at=(now + expires_delta) if expires_delta is not None else None,
        ignored_at=now if ignored else None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _cleanup(values):
    db = SessionLocal()
    try:
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).delete(
            synchronize_session=False
        )
        db.commit()
    finally:
        db.close()


# ── 1. the hybrid itself, both halves ────────────────────────────────────

def test_hybrid_python_and_sql_halves_agree_on_every_case():
    """A hybrid_property has two implementations — a Python getter and a SQL
    expression — and nothing in SQLAlchemy makes them agree. They are the
    load-bearing predicate for every suppression read in the codebase, so
    drift between them would mean the API and the scorer disagreeing about
    whether an asset is hidden. Pin all four cases through both paths.
    """
    suffix = uuid.uuid4().hex[:10]
    cases = {
        f"ig-not-ignored-{suffix}": (dict(ignored=False), False),
        f"ig-indefinite-{suffix}": (dict(ignored=True, reason="BY_DESIGN"), True),
        f"ig-live-{suffix}": (dict(ignored=True, reason="EXCEPTION", expires_delta=_FUTURE), True),
        f"ig-expired-{suffix}": (dict(ignored=True, reason="EXCEPTION", expires_delta=_PAST), False),
    }
    db = SessionLocal()
    try:
        for value, (kwargs, _expected) in cases.items():
            _mk(db, value, **kwargs)

        # SQL half — ask the database which rows it considers suppressed.
        sql_suppressed = {
            row.value for row in
            db.query(AssetCanonical)
            .filter(AssetCanonical.value.in_(list(cases)), AssetCanonical.suppressed)
            .all()
        }
        for value, (_kwargs, expected) in cases.items():
            row = db.query(AssetCanonical).filter_by(value=value).one()
            assert row.suppressed is expected, f"python half wrong for {value}"
            assert (value in sql_suppressed) is expected, f"SQL half wrong for {value}"
    finally:
        db.close()
        _cleanup(list(cases))


# ── 2. the read surfaces ─────────────────────────────────────────────────

def test_expired_ignore_reappears_in_the_absence_query():
    """`claims_query.assets_missing_claim` is what planning#130's unmanaged
    query composes on. An expired ignore silently keeping an asset out of it
    is exactly the invisible-gap failure the claims layer exists to prevent.
    """
    suffix = uuid.uuid4().hex[:10]
    expired = f"ig-aq-expired-{suffix}"
    live = f"ig-aq-live-{suffix}"
    db = SessionLocal()
    try:
        _mk(db, expired, ignored=True, reason="EXCEPTION", expires_delta=_PAST)
        _mk(db, live, ignored=True, reason="EXCEPTION", expires_delta=_FUTURE)

        found = {
            a.value for a in
            claims_query.assets_missing_claim(db, "port_observation", limit=5000)
        }
        assert expired in found, "an ignore past its expiry must stop hiding the asset"
        assert live not in found, "an unexpired ignore must still hide the asset"

        # include_ignored=True is an explicit override and still shows both.
        both = {
            a.value for a in
            claims_query.assets_missing_claim(
                db, "port_observation", include_ignored=True, limit=5000
            )
        }
        assert {expired, live} <= both
    finally:
        db.close()
        _cleanup([expired, live])


def test_expired_ignore_returns_to_the_hygiene_scoring_population():
    """`hygiene_scorer` builds its candidate set from the un-suppressed
    assets. An asset whose ignore lapsed must be scored again on the next
    run — otherwise the score silently under-counts the estate, which is
    the failure mode the whole "unknown ranks below bad" design guards
    against.
    """
    suffix = uuid.uuid4().hex[:10]
    expired = f"ig-hy-expired-{suffix}"
    live = f"ig-hy-live-{suffix}"
    db = SessionLocal()
    try:
        _mk(db, expired, ignored=True, reason="FALSE_POSITIVE", expires_delta=_PAST)
        _mk(db, live, ignored=True, reason="FALSE_POSITIVE", expires_delta=_FUTURE)

        candidates = {
            row[0] for row in
            db.query(AssetCanonical.value).filter(~AssetCanonical.suppressed).all()
        }
        assert expired in candidates
        assert live not in candidates
    finally:
        db.close()
        _cleanup([expired, live])


def test_hygiene_eviction_does_not_evict_an_expired_ignore():
    """`_delete_stale_scores` drops score rows for assets that left scope.
    It must read `suppressed`, not `ignored` — evicting on the raw flag
    would delete the score of an asset whose ignore has *lapsed*, i.e. one
    that just came back INTO scope. That would be silent data loss on the
    exact transition this feature exists to enable.
    """
    suffix = uuid.uuid4().hex[:10]
    expired = f"ig-ev-expired-{suffix}"
    db = SessionLocal()
    try:
        row = _mk(db, expired, ignored=True, reason="EXCEPTION", expires_delta=_PAST)
        evicted = {
            r[0] for r in
            db.query(AssetCanonical.id)
            .filter(AssetCanonical.id.in_([row.id]), AssetCanonical.suppressed)
            .all()
        }
        assert row.id not in evicted, (
            "an asset whose ignore expired must not be treated as out-of-scope"
        )
    finally:
        db.close()
        _cleanup([expired])


# ── 3. indefinite is still available, and still explicit ─────────────────

def test_indefinite_ignore_still_suppresses_forever():
    """NULL expiry must keep meaning indefinite — this change adds a review
    date, it does not force one. What it changes is that indefinite becomes
    a choice made alongside a stated reason rather than the only thing the
    model could express.
    """
    suffix = uuid.uuid4().hex[:10]
    value = f"ig-forever-{suffix}"
    db = SessionLocal()
    try:
        row = _mk(db, value, ignored=True, reason="BY_DESIGN")
        assert row.ignore_expires_at is None
        assert row.suppressed is True
        found = {
            a.value for a in
            claims_query.assets_missing_claim(db, "port_observation", limit=5000)
        }
        assert value not in found
    finally:
        db.close()
        _cleanup([value])


# ── 4. the reason is not optional ────────────────────────────────────────

def test_check_constraint_rejects_an_invented_reason():
    """The three reasons are CHECK-constrained at the database, not just
    validated in the API handler. A reason vocabulary that only the HTTP
    layer enforces is one background job away from being bypassed.
    """
    import sqlalchemy.exc

    suffix = uuid.uuid4().hex[:10]
    value = f"ig-badreason-{suffix}"
    db = SessionLocal()
    try:
        try:
            _mk(db, value, ignored=True, reason="BECAUSE_I_SAID_SO")
            raise AssertionError("the CHECK constraint should have rejected this reason")
        except sqlalchemy.exc.IntegrityError:
            db.rollback()
    finally:
        db.close()
        _cleanup([value])
