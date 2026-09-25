"""The decision log stays readable without a filter clause (planning#189).

`authorisation_decisions` is the table the #148 `enforce` flip is decided
from, and the backend suite runs against the DEV database. Between
2026-09-12 and 2026-09-20 three tests wrote rows their cleanups could not
reach, 329 accumulated, and a summary over the table produced "87% of
decisions die at `scope:unresolved_asset`" — a figure that steered #178,
#188 and #148 through three hand-offs and was 100% test residue. No real
scan has ever fired that rule.

The purge was the one-off part. These two guards are the deliverable: a
cleanup that silently stops matching is how this arrived, so the thing that
has to survive is an alarm that fires when it happens again.

Why `test_zz_` — pytest collects files in sort order, so this runs after
every other test file and sees the whole suite's residue in the same run.
That is a nicety, not the load-bearing part: the leak is a RATCHET (a
leaked row is still there on the next run), so a guard that ran first would
still catch it one run later. The prefix only shortens the feedback loop.

Requires a live DB. Run with:
    pytest app/tests/test_zz_decision_log_hygiene.py
"""

import pathlib
import subprocess
import sys

from app.tests import _decision_log

# `backend/` — the directory CI runs pytest from (security.yml: `python -m
# pytest app/tests/ -q` with working-directory backend). Derived from
# __file__ rather than assumed, so the subprocess below resolves its
# targets the same way whatever the caller's cwd is.
_BACKEND = pathlib.Path(__file__).resolve().parents[2]

# The files that write to `authorisation_decisions`. Re-run in a subprocess
# by the second guard below. THIS file is deliberately not in the list —
# it would recurse.
#
# Found by measurement, not by reading: run each candidate file alone and
# diff `SELECT count(*)`. `test_cidr_sweep.py` is on this list because that
# bisect caught it leaking four rows a run; nothing about the file's name
# or its docstring suggests it touches the decision log at all. A new
# entry belongs here whenever a test drives `_run_pipeline` or calls
# `probe_authorisation.authorise_probes` OR
# `probe_authorisation.authorise_discovery` (planning#196 step 2 — the
# domain-shaped gate writes a decision row on every denial, same as the
# asset-shaped gate).
_DECISION_WRITING_TESTS = [
    "app/tests/test_asset_delete_with_decisions.py",
    "app/tests/test_cidr_sweep.py",
    "app/tests/test_engagement_acceptance.py",
    "app/tests/test_phase3_gate.py",
    "app/tests/test_posture_policy.py",
    "app/tests/test_probe_authorisation.py",
    "app/tests/test_scan_executor_pre_close.py",
    "app/tests/test_scope_cap.py",
]


def test_decision_log_holds_no_unreachable_rows():
    """The invariant, stated directly: no row may exist with BOTH a NULL
    `asset_canonical_id` and no `scan_run_id`.

    Such a row came from no scan (no run id) and is about no known asset
    (no canonical id), so nothing can ever clean it up by the ordinary
    id-keyed route and nothing can ever read it as evidence. It is residue
    by construction. This is the shape all 329 purged rows had.

    Mutation-proof: revert either watermark cleanup — `test_scope_cap.py`'s
    `test_unresolved_asset_is_denied_under_a_distinct_rule` is the cheapest
    — run the suite, and this fails. That check is why the cleanups key on
    a timestamp rather than a synthetic `scan_run_id`: a leaked row wearing
    a run id would not have this shape, and this guard could not detect its
    own regression (see `_decision_log`'s docstring).
    """
    residue = _decision_log.unreachable_count()
    assert residue == 0, (
        f"{residue} unreachable decision row(s) in authorisation_decisions "
        "(NULL asset_canonical_id AND no scan_run_id). A test wrote decision "
        "rows it cannot clean up. Take a _decision_log.watermark() before the "
        "call under test and _decision_log.cleanup_since(mark) in its finally. "
        "Do NOT widen an existing cleanup into a table-wide DELETE — the dev "
        "DB is the test DB and the real scan rows are irreplaceable."
    )


def test_rerunning_the_decision_tests_adds_no_rows():
    """Running the suite twice adds zero rows — the acceptance criterion,
    as an assertion rather than a thing someone checks by hand.

    Broader than the invariant above and deliberately so: this counts EVERY
    row, so it also catches a leak of rows that carry a `scan_run_id` or an
    `asset_canonical_id` — residue that is reachable in principle but was
    not actually reached. `test_phase3_gate.py` writes exactly that kind.
    """
    before = _decision_log.total_count()
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *_DECISION_WRITING_TESTS],
        cwd=_BACKEND, capture_output=True, text=True,
    )
    assert proc.returncode == 0, (
        f"the decision-writing tests did not pass on re-run, so their row "
        f"counts prove nothing:\n{proc.stdout[-3000:]}\n{proc.stderr[-2000:]}"
    )
    after = _decision_log.total_count()
    assert after == before, (
        f"re-running {len(_DECISION_WRITING_TESTS)} decision-writing test "
        f"file(s) added {after - before} row(s) to authorisation_decisions "
        f"({before} -> {after}). Every test that triggers a decision write "
        "must clean up exactly the rows it caused."
    )


if __name__ == "__main__":
    test_decision_log_holds_no_unreachable_rows()
    test_rerunning_the_decision_tests_adds_no_rows()
    print("decision-log hygiene: ok")
