"""Shared decision-log test hygiene helpers (planning#189).

`authorisation_decisions` is the audit trail the #148 `enforce` flip is
decided from, and the backend suite runs against the DEV database — so a
test row written here lands in the same table a policy decision is read
from. Between 2026-09-12 and 2026-09-20 that produced 329 unreachable test
rows and a wrong statistic ("87% of decisions die at
`scope:unresolved_asset`") that steered the roadmap through three hand-offs.
No real scan has ever fired that rule.

The rows at issue are the ones a test CANNOT clean up the ordinary way.
Every other cleanup in this suite keys on `asset_canonical_id`, but the
tests that matter here deliberately probe an asset that has NO canonical
row — that absence is the thing under test — so an id-keyed delete matches
nothing and the row survives forever.

Why a timestamp watermark rather than `test_phase3_gate.py`'s synthetic
`scan_run_id`
-------------------------------------------------------------------------
`test_phase3_gate.py:96` solves its own version of this by generating a
`scan_run_id` and deleting by it. That works, and it is the in-repo idiom,
but it is deliberately NOT what this module does.

`evidence_snapshot->>'scan_run_id'` is the ONLY field separating a real
scan row from a test row; it is what the 48-vs-329 split was measured on.
Handing test rows a synthetic one puts fake rows in the "real" bucket for
the duration of the test, so a cleanup that silently stops matching — the
exact failure that produced this issue — would leave residue that reads as
production evidence. It also blunts the guard in
`test_zz_decision_log_hygiene.py`: a leaked row carrying a `scan_run_id` no
longer has the residue shape, so the invariant could not detect its own
regression and could not be mutation-proved.

A watermark keeps test rows recognisably fake. The cost is that it is not
the idiom used one file over, which is what this docstring is for.

`decided_at` carries a `server_default=func.now()`, so the watermark must
come from the DATABASE clock, not the Python process — `clock_timestamp()`
rather than `now()`, because `now()` is the transaction timestamp and the
watermark is read in a different transaction than the one that writes.

## planning#195 checked the residue shape against `ON DELETE SET NULL` and
deliberately changed nothing here

planning#195 made `authorisation_decisions.asset_canonical_id`
`ON DELETE SET NULL` (it was `NO ACTION`, which made every gate-evaluated
asset undeletable). The issue that requested it worried this would start
making `_unreachable` below match rows it shouldn't — a real decision row,
orphaned by an ordinary asset delete, wearing the same
`asset_canonical_id IS NULL` shape residue does.

Measured against dev at the time: **all 92 rows carried a `scan_run_id`**
(80 with a canonical id, 12 without, zero without a run id). SET NULL
touches only `asset_canonical_id` — it does not and cannot touch
`evidence_snapshot` — so an orphaned real row keeps its `scan_run_id` and
still fails `_unreachable`'s second term exactly as before it was
orphaned. Real scan rows always carry a run id (see `_unreachable`'s own
docstring); this migration does not change that, and does not need to.

The guard's coverage only grows: a test that writes a decision row with NO
run id and then deletes that row's asset now creates genuinely
unreachable residue (NULL canonical id, still no run id), and
`test_zz_decision_log_hygiene.py` firing on that is the guard working as
designed, not a new false positive to chase.

Do **not** add a `decision_scope` term to `_unreachable` to try to carve
out "orphaned by a SET NULL delete" from "never resolved a canonical row".
There is nothing for such a term to exclude — both measured findings above
show a real orphaned row already fails on `scan_run_id` alone. A term that
excludes nothing is noise dressed up as a safeguard, and it would weaken
the invariant for the next reader who assumes it must be pulling its
weight. This paragraph exists so that reader checks the measurement again
before "fixing" it.
"""

from datetime import datetime

from sqlalchemy import func

from app.core.database import SessionLocal
from app.models.authorisation_decision import AuthorisationDecision


def _unreachable(query):
    """The residue shape: a decision row about an asset that has no
    canonical row (so no id-keyed cleanup can ever reach it) AND with no
    `scan_run_id` (so it did not come from a scan). Real scan rows always
    carry a run id; rows with a canonical id are reachable by the ordinary
    `_cleanup` helpers."""
    return query.filter(
        AuthorisationDecision.asset_canonical_id.is_(None),
        AuthorisationDecision.evidence_snapshot["scan_run_id"].astext.is_(None),
    )


def watermark() -> datetime:
    """A database-clock timestamp to bound a later cleanup by.

    Call BEFORE the code under test writes its decision rows, from its own
    short transaction, so every row written afterwards compares `>=` it.
    """
    db = SessionLocal()
    try:
        # `func.clock_timestamp()`, not `text("SELECT clock_timestamp()")`:
        # the expression form keeps this off `avoid-sqlalchemy-text`'s radar
        # entirely rather than relying on the adjacent-literal exemption.
        return db.query(func.clock_timestamp()).scalar()
    finally:
        db.close()


def cleanup_since(mark: datetime) -> int:
    """Delete unreachable decision rows written at or after `mark`.

    Bounded three ways — NULL canonical id, no `scan_run_id`, and newer
    than this test's own watermark — so it cannot reach a real scan row
    even if one shared the other two properties. Returns the row count, so
    a caller can assert it actually matched something.
    """
    db = SessionLocal()
    try:
        removed = _unreachable(
            db.query(AuthorisationDecision).filter(AuthorisationDecision.decided_at >= mark)
        ).delete(synchronize_session=False)
        db.commit()
        return removed
    finally:
        db.close()


def cleanup_for_run(scan_run_id) -> int:
    """Delete every decision row stamped with `scan_run_id`.

    For tests that drive a real (stubbed) pipeline: `_run_pipeline` mints a
    genuine run id and stamps it on every row it writes, so the test owns a
    precise handle and does not need the watermark above. This is
    `test_phase3_gate.py:96`'s idiom, lifted here so the three files that
    need it cannot drift apart — drift between two spellings of the same
    cleanup is what planning#189 is about.

    The distinction from `cleanup_since`: there, the test calls
    `authorise_probes` directly and would have to INVENT a run id, which
    would disguise its rows as scan evidence. Here the run id is real.

    Note these rows are NOT unreachable-shaped — they carry a run id, so
    they read as production evidence, which makes leaking one strictly
    worse than leaking residue. `test_cidr_sweep.py` leaked four per run
    this way, undetected, because `_run_pipeline_with_stub` generated its
    run id inline and discarded it.
    """
    db = SessionLocal()
    try:
        removed = (
            db.query(AuthorisationDecision)
            .filter(AuthorisationDecision.evidence_snapshot["scan_run_id"].astext == str(scan_run_id))
            .delete(synchronize_session=False)
        )
        db.commit()
        return removed
    finally:
        db.close()


def unreachable_count() -> int:
    """How many unreachable rows the table holds right now. The invariant
    asserted by `test_zz_decision_log_hygiene.py` is that this is zero."""
    db = SessionLocal()
    try:
        return _unreachable(db.query(AuthorisationDecision)).count()
    finally:
        db.close()


def total_count() -> int:
    """Every row in the table, residue and real alike — the before/after
    measure for "running the suite twice adds zero rows"."""
    db = SessionLocal()
    try:
        return db.query(AuthorisationDecision).count()
    finally:
        db.close()
