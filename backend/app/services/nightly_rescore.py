"""Nightly full-scope risk re-scoring driver (planning#131, temporal layer
slice 1).

Everything else that calls `risk_scorer.score_scan_findings` does so over a
SCAN'S touched set — the findings a particular run actually looked at. That
leaves a real gap: `risk_score` is a function of `epss_score`, KEV status,
SSVC decision points, and other signals that can change on their own
between scans (EPSS drifts daily, CISA adds a CVE to KEV, Vulnrichment
publishes a new SSVC block) without any new scan ever touching the
affected finding again. This job closes that gap by re-scoring every
in-scope finding once a night, independent of scan activity, so a finding
that quietly crossed into a higher band from signal drift alone still gets
caught and, if it warrants one, still generates a promotion notification.

Scope: every `findings_canonical` row with `state == "open"`. Resolved
findings are NOT re-scored — a resolved finding's `risk_score` is a
historical fact about the risk at the moment it mattered (when it was open
and something needed to be done about it), not a live number; re-scoring
it would churn `score_history` with rows nobody will ever act on and would
have to be filtered back out at every read site.

Rows whose `verification` is in `EXCLUDED_VERIFICATIONS` (imported from
`app.models.finding_canonical`, never re-spelled here — see that module's
comment for the current list and epic#81 for why the exclusion exists) ARE
still re-scored, so the stored score stays correct if the verification is
later cleared by a human or a re-run of the shared-infra verifier. They
are, however, filtered OUT of the promotion list handed to
`notification_dispatcher.dispatch_promotions` below — a finding we can't
prove is ours must never page anyone, matching the same exclusion
`notification_dispatcher._dispatch` already applies to new-finding
notifications. `dispatch_promotions` independently re-applies the same
filter when it loads the findings (defence in depth, per its own
docstring), so the filtering here is belt-and-braces, not the only place
it happens.

`scored_at` is computed ONCE at the top of `run()`, before the first
chunk, so every `score_history` row this nightly pass writes shares one
timestamp — both because that's the natural meaning of "this is what the
2026-08-23 03:00 pass found" and because it lets this function count
`history_rows` with a plain `COUNT(*) WHERE scored_at = scored_at` after
all chunks finish, rather than growing `score_history.capture`'s
`list[Promotion]` return into a second, count-returning contract just for
this one caller.

Scheduling: registered by `app.services.scheduler` as a `CronTrigger`
job at 03:00 UTC, deliberately after the seeded default monitoring
template's 02:00 daily scan (`scheduler._seed_default_template`) — see
that module for why the ordering matters (re-scoring a settled post-scan
state, not racing the scan's own scoring pass).
"""

import logging
import time
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.finding_canonical import EXCLUDED_VERIFICATIONS, FindingCanonical
from app.models.score_history import ScoreHistory
from app.services import notification_dispatcher, risk_scorer, score_history

log = logging.getLogger(__name__)

# Same constant name/value as hygiene_scorer.BATCH_SIZE / score_history.BATCH_SIZE.
BATCH_SIZE = 500


def _chunks(seq: list, size: int):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def run(db: Session) -> dict:
    """The nightly driver. Signature and return-a-stats-dict style match
    `hygiene_scorer.run(db)` / `partition_maintenance.run(db)`.

    For each chunk of `BATCH_SIZE` open-finding ids: calls
    `risk_scorer.score_scan_findings(db, scan_run_id=None,
    canonical_ids=chunk)` (writing fresh risk_score/risk_band/
    building_velocity), then `score_history.capture(db, chunk,
    scored_at=scored_at)`, accumulating every returned `Promotion`.

    After all chunks: promotions belonging to an
    `EXCLUDED_VERIFICATIONS` finding are dropped from the DISPATCHED list
    (module docstring); if anything remains,
    `notification_dispatcher.dispatch_promotions` is called inside a
    try/except that logs and swallows — a notification failure must not
    fail the job, same fail-soft posture as every step in
    `scan_executor.py`.

    Returns `{"rescored": n, "history_rows": n, "promotions": n,
    "elapsed_ms": n}` and logs exactly one summary line — no per-finding
    logging. `"promotions"` counts every promotion `capture()` detected
    this run (including ones later excluded from dispatch by
    verification), so it reflects what actually changed rather than only
    what got sent.
    """
    start = time.monotonic()
    scored_at = datetime.now(timezone.utc)

    scope_rows = (
        db.query(FindingCanonical.id, FindingCanonical.verification)
        .filter(FindingCanonical.state == "open")
        .all()
    )
    verification_by_id: dict[uuid.UUID, str | None] = {row[0]: row[1] for row in scope_rows}
    all_ids = list(verification_by_id.keys())

    rescored = 0
    all_promotions: list[score_history.Promotion] = []

    for chunk in _chunks(all_ids, BATCH_SIZE):
        chunk_ids = set(chunk)
        risk_scorer.score_scan_findings(db, scan_run_id=None, canonical_ids=chunk_ids)
        rescored += len(chunk_ids)

        all_promotions.extend(score_history.capture(db, chunk_ids, scored_at=scored_at))

    dispatchable = [
        p for p in all_promotions
        if verification_by_id.get(p.finding_canonical_id) not in EXCLUDED_VERIFICATIONS
    ]
    if dispatchable:
        try:
            notification_dispatcher.dispatch_promotions(dispatchable)
        except Exception:
            log.exception("nightly_rescore: dispatch_promotions failed")

    history_rows = (
        db.query(ScoreHistory)
        .filter(ScoreHistory.scored_at == scored_at)
        .count()
    )

    elapsed_ms = int((time.monotonic() - start) * 1000)
    stats = {
        "rescored": rescored,
        "history_rows": history_rows,
        "promotions": len(all_promotions),
        "elapsed_ms": elapsed_ms,
    }
    log.info(
        "Nightly re-score complete — rescored=%d history_rows=%d promotions=%d elapsed_ms=%d",
        rescored, history_rows, len(all_promotions), elapsed_ms,
    )
    return stats
