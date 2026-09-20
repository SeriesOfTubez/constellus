"""`claim_history` never accumulates rows whose asset is gone (planning#191).

`claim_history` held 4,827 rows on the dev DB and **4,808 of them (99.6%)
referenced an `assets_canonical` row that no longer existed.** Same class as
planning#189's decision-log residue, different mechanism: nothing here was a
broken cleanup. There was no cleanup at all, by schema design — `asset_claims`
has had `ON DELETE CASCADE` since migration 0039 and `claim_history`, sitting
right beside it, had no foreign key of any kind. Every test that emitted a
claim and then deleted its asset stranded history rows silently.

Migration 0053 purged the backlog and added the FK, so the retention rule
decided in planning#191 — **if an asset is deleted its claim history goes with
it** — is now enforced by the database instead of by whoever remembers.

Why this file is thinner than `test_zz_decision_log_hygiene.py`
--------------------------------------------------------------
That file needs a second test that re-runs the decision-writing suites and
compares row counts, because those cleanups are hand-written and a cleanup can
silently stop matching. Here the cleanup IS the schema: there is no per-test
cleanup that could rot, and "running the suite twice adds zero orphans" is not
a property that can fail while the constraint exists. So the equivalent guard
is `test_the_cascade_is_actually_wired` below, which checks the constraint by
using it rather than by reading `pg_constraint` and hoping.

Mutation proof (the real one, and it is the schema, not a cleanup):

    ALTER TABLE claim_history DROP CONSTRAINT fk_claim_history_asset_canonical;

`test_the_cascade_is_actually_wired` then fails on the same run, and
`test_claim_history_holds_no_orphaned_rows` fails on the next one — it is a
ratchet, a leaked row is still there next time.

Why `test_zz_` — pytest collects in sort order, so this runs after every other
file and sees the whole suite's residue in one run. A nicety, not load-bearing.

Requires a live DB. Run with:
    pytest app/tests/test_zz_claim_history_hygiene.py
"""

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from app.core.database import SessionLocal
from app.tests import _docaddr

_FK_NAME = "fk_claim_history_asset_canonical"

_ORPHAN_COUNT = text("""
    SELECT count(*) FROM claim_history h
     WHERE NOT EXISTS (SELECT 1 FROM assets_canonical a WHERE a.id = h.asset_canonical_id)
""")


def _two_partition_timestamps(db) -> tuple[list[datetime], list[str]]:
    """Two `changed_at` values landing in two DIFFERENT non-default partitions,
    read from the catalogue rather than guessed.

    The partition question is the whole reason the FK was avoided for so long
    ("an FK would make a future partition DROP/DETACH more expensive"), so the
    cascade is worth proving ACROSS partitions and not just within one. Reading
    the real bounds keeps that from going stale when the monthly partitions
    roll: if fewer than two non-default partitions exist, the caller falls back
    to two plain timestamps and proves the cascade without the partition claim,
    rather than failing for a reason that is not a bug.
    """
    rows = db.execute(text("""
        SELECT c.relname, pg_get_expr(c.relpartbound, c.oid) AS bound
          FROM pg_class c
          JOIN pg_inherits i ON i.inhrelid = c.oid
          JOIN pg_class p ON p.oid = i.inhparent
         WHERE p.relname = 'claim_history'
           AND pg_get_expr(c.relpartbound, c.oid) <> 'DEFAULT'
         ORDER BY c.relname
    """)).all()
    stamps: list[datetime] = []
    names: list[str] = []
    for r in rows[:2]:
        # FOR VALUES FROM ('2026-09-01 00:00:00+00') TO ('2026-10-01 00:00:00+00')
        lower = r.bound.split("FROM ('")[1].split("')")[0]
        # One day inside the lower bound — comfortably within the range.
        stamps.append(datetime.fromisoformat(lower) + timedelta(days=1))
        names.append(r.relname)
    if len(stamps) < 2:
        now = datetime.now(timezone.utc)
        return [now, now - timedelta(days=40)], []
    return stamps, names


def test_claim_history_holds_no_orphaned_rows():
    """The invariant, stated directly: no `claim_history` row may reference an
    asset that does not exist.

    This is the shape all 4,808 purged rows had. With the FK in place it can
    only fail if the constraint is dropped, or if some future history table
    repeats the pattern and someone points this guard at it — which is exactly
    what it is for. planning#189's lesson was that a silent cleanup is how a
    leak hides; a cascade is a silent cleanup too, so it gets an alarm.
    """
    db = SessionLocal()
    try:
        orphans = db.execute(_ORPHAN_COUNT).scalar_one()
    finally:
        db.close()
    assert orphans == 0, (
        f"{orphans} orphaned claim_history row(s) — rows describing an asset "
        f"that no longer exists. The '{_FK_NAME}' FK (migration 0053) should "
        "make this impossible; check whether it was dropped. Do NOT fix this "
        "with a table-wide DELETE: the dev DB is the test DB and the rows "
        "belonging to live assets are irreplaceable."
    )


def test_the_cascade_is_actually_wired():
    """Delete an asset, and its history goes — across two partitions.

    Uses the constraint rather than asserting its presence in `pg_constraint`,
    because what matters is the behaviour: a constraint that exists but was
    added `NOT VALID`, or added to the parent without reaching a partition,
    would pass a catalogue check and still leak.

    Also the direct statement of planning#191's retention decision, so a future
    reader who disagrees with it has one obvious place to argue.
    """
    db = SessionLocal()
    asset_id = uuid.uuid4()
    ip = _docaddr.alloc()
    try:
        now = datetime.now(timezone.utc)
        db.execute(text("""
            INSERT INTO assets_canonical (id, asset_type, value, first_seen_at, last_seen_at)
            VALUES (:i, 'ip_address', :v, :n, :n)
        """), {"i": asset_id, "v": ip, "n": now})
        observer_id = db.execute(text("SELECT id FROM observers LIMIT 1")).scalar_one()

        stamps, partitions = _two_partition_timestamps(db)
        for ts in stamps:
            db.execute(text("""
                INSERT INTO claim_history
                    (asset_canonical_id, observer_id, claim_type, claim_value, changed_at)
                VALUES (:i, :o, 'observation', '{}'::jsonb, :t)
            """), {"i": asset_id, "o": observer_id, "t": ts})
        db.commit()

        landed = [r[0] for r in db.execute(text("""
            SELECT DISTINCT tableoid::regclass::text FROM claim_history
             WHERE asset_canonical_id = :i
        """), {"i": asset_id}).all()]
        assert len(landed) == 2, (
            f"expected the two seeded rows in two different partitions, got "
            f"{landed} (targeted {partitions or 'no named partitions'}). The "
            "cross-partition half of this proof did not run."
        )

        db.execute(text("DELETE FROM assets_canonical WHERE id = :i"), {"i": asset_id})
        db.commit()

        left = db.execute(text(
            "SELECT count(*) FROM claim_history WHERE asset_canonical_id = :i"
        ), {"i": asset_id}).scalar_one()
        assert left == 0, (
            f"{left} claim_history row(s) survived their asset's deletion "
            f"(seeded across {landed}). planning#191's rule is that history "
            f"goes with the asset; the '{_FK_NAME}' FK is what enforces it, so "
            "check whether it exists and reaches every partition."
        )
    finally:
        # Scoped to this test's own asset. Deleting the asset is itself the
        # cleanup — the cascade takes the history — but the delete above is
        # inside the assertion path, so repeat it here for the failure case.
        db.execute(text("DELETE FROM assets_canonical WHERE id = :i"), {"i": asset_id})
        db.execute(text("DELETE FROM claim_history WHERE asset_canonical_id = :i"), {"i": asset_id})
        db.commit()
        db.close()


if __name__ == "__main__":
    test_claim_history_holds_no_orphaned_rows()
    test_the_cascade_is_actually_wired()
    print("claim-history hygiene: ok")
