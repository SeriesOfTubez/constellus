"""Score-history capture — the per-finding risk-score change log
(planning#131, temporal layer slice 1).

This module is the SOLE writer of `score_history`. It never scores
anything itself — `app.services.risk_scorer` stays the only scorer — it
only reads whatever `risk_score`/`risk_band`/`building_velocity` values
`risk_scorer.score_scan_findings` already wrote onto `findings_canonical`
and decides whether that state is worth recording as a new history row and
whether it constitutes a promotion. Two callers: `scan_executor.py` (right
after a scan's own risk-scoring pass) and `nightly_rescore.py` (the
full-scope nightly re-score).

── Change-only append, not one row per (finding, scored_at) ────────────────

planning#131's issue text describes "one row per (finding, scored_at)".
This module deliberately does NOT do that: a new row is inserted only when
there is no prior row for the finding (a baseline) OR when
`(risk_score, risk_band, building_velocity)` differs from the finding's
own most recent prior row. Two reasons, both load-bearing:

  1. It mirrors `claim_history`'s own change-log semantics (`changed_at`,
     written on change, not on every tick) — this codebase already has one
     established shape for "append-only log of what changed and when";
     inventing a second, denser one here for score history would be an
     unforced inconsistency.
  2. It keeps the table's size proportional to actual score MOVEMENT
     rather than to `findings x nights` — a finding that sits quietly in
     `low` for a year does not grow 365 identical rows just because the
     nightly job touched it 365 times. Trend queries carry the last value
     forward across the gaps, which is the standard read pattern for any
     change log; a caller that wants "the score on date X" does a
     `<= X ORDER BY scored_at DESC LIMIT 1` lookup, not a row scan expecting
     one entry per day.

Comparing against the STORED prior history row is why this design is worth
defending, and a future editor WILL be tempted to "simplify" it into
diffing an in-memory pre/post snapshot instead — do not. Reading the prior
row back from `score_history` itself (rather than remembering what the
finding's columns were before this call started) is exactly what makes
`capture()` idempotent and de-duplicating across independent callers: if a
scan at 22:00 already wrote a row recording a band promotion, the nightly
job the following 03:00 recomputes the same score, compares it against
that SAME stored row, sees no change, and neither writes a duplicate row
nor re-reports a promotion. An in-memory snapshot compared only against
whatever `capture()` happened to see at the START of ITS OWN call would
lose that cross-caller de-duplication entirely — each caller would only
ever know about changes it personally straddled, not the finding's actual
history. The DISTINCT ON query below is the whole mechanism.

── Promotion vs. baseline ───────────────────────────────────────────────────

A finding with NO prior row is a baseline, and baselines are NEVER
promotions — even if `risk_band` starts at `imminent_compromise` on its
very first capture. If a first-ever capture counted as a promotion, the
first time this feature runs it would page everyone about the entire
existing backlog at once, which is exactly the opposite of what a
promotion notification is supposed to mean ("something got worse since we
last looked"). Covered by `test_score_history.py`.

── Band ranking has ONE source of truth ─────────────────────────────────────

Rank comes from `risk_scorer.BANDS[band][0]` (each band's lower score
edge) — never a second hardcoded ordered list of band names. `risk_scorer`
already owns the band vocabulary and its ordering (see its own module
docstring and `BANDS` dict); duplicating that ordering here would drift
the moment a band is added, renamed, or reordered in one place and not the
other. A band absent from `BANDS` (defensive only — should not happen in
practice) ranks lowest and never counts as a promotion source; a warning
is logged so the gap is visible rather than silently swallowed.

── `inputs` JSONB ────────────────────────────────────────────────────────────

Captures exactly the signals `risk_scorer` used to produce the score, so a
historical row is self-explaining without re-deriving anything from
`findings_canonical` (which may have since moved on). NULL-valued keys are
omitted to keep rows small — a finding with no CVE carries no
`cvss_score`/`epss_score` keys at all rather than explicit nulls. `False`
is NOT omitted, only `None`: `kev=False` ("checked, not in KEV") and a
missing `kev` key ("never checked") are different facts and stay
distinguishable.

Read `inputs` as "the signals as of this row's score CHANGE", not "the
signals as of this row's timestamp" — a direct consequence of the
change-only rule above. EPSS drifting from 0.11 to 0.14 without moving the
finding across a band edge writes no row, so the newest stored `inputs`
still reads 0.11. That is correct for this table's purpose (it explains
why the score is what it is, and the score did not change), and
`epss_history` already exists as the per-CVE signal time-series for
anyone who needs the drift itself. Contrast `hygiene_history`, whose
`dimensions` IS part of its change key — there the stored blob is the
per-dimension detail rather than a rationale for a number, so a change to
it has to write a row (see `hygiene_scorer._append_hygiene_history`).
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import insert, text
from sqlalchemy.orm import Session

from app.models.finding_canonical import FindingCanonical
from app.models.score_history import ScoreHistory
from app.services import risk_scorer

log = logging.getLogger(__name__)

# Same constant name/value as hygiene_scorer.BATCH_SIZE — one "IN (...)"
# clause stays a reasonable query regardless of how many findings a caller
# hands in at once.
BATCH_SIZE = 500

# The signals that produced the score (module docstring's "self-explaining
# without re-deriving" rationale). These are exactly the fields risk_scorer
# reads off FindingCanonical into its own ScoreInputs dataclass — kept as
# scalar attribute names here (not ORM objects) so the JSONB blob below is
# already JSON-safe with no serialization step.
_INPUT_KEYS: tuple[str, ...] = (
    "cve_id", "cvss_score", "cvss_source", "epss_score", "epss_score_previous",
    "kev", "vulncheck_kev", "has_exploit", "is_poc", "is_template",
    "ransomware_use", "canary_detected", "ssvc_exploitation", "ssvc_automatable",
    "ssvc_technical_impact", "ssvc_source", "severity", "category",
)


@dataclass(frozen=True)
class Promotion:
    """A detected band-up or velocity-started event for one finding, ready
    to hand to `notification_dispatcher.dispatch_promotions`. `capture()`
    only ever constructs one of these when a genuine prior row existed —
    see the module docstring's baseline rule."""

    finding_canonical_id: uuid.UUID
    asset_canonical_id: uuid.UUID
    previous_band: str | None
    new_band: str
    previous_score: int | None
    new_score: int
    velocity_started: bool  # building_velocity went false/None -> True


# ── Public API ────────────────────────────────────────────────────────────────

def capture(db: Session, canonical_ids: set[uuid.UUID], scored_at: datetime) -> list[Promotion]:
    """Compare each finding in `canonical_ids` against its own latest
    `score_history` row and append a change-only row where warranted.

    Runs strictly AFTER `risk_scorer.score_scan_findings` has already
    written `risk_score`/`risk_band`/`building_velocity` for these
    findings — this function never computes a score itself. Findings whose
    `risk_score` or `risk_band` is still NULL (never scored) are skipped
    entirely; they have nothing yet worth recording.

    Batched in chunks of `BATCH_SIZE`: one `FindingCanonical` load, one
    DISTINCT ON query for the latest prior row per finding, and (when
    there are rows to write) one bulk INSERT per chunk, followed by
    `db.commit()`.

    Returns the list of detected `Promotion`s across every chunk. Logs
    exactly one summary line, never per-finding.
    """
    if not canonical_ids:
        return []

    promotions: list[Promotion] = []
    rows_inserted = 0
    considered = 0

    for chunk in _chunks(list(canonical_ids), BATCH_SIZE):
        findings = (
            db.query(FindingCanonical)
            .filter(
                FindingCanonical.id.in_(chunk),
                FindingCanonical.risk_score.isnot(None),
                FindingCanonical.risk_band.isnot(None),
            )
            .all()
        )
        if not findings:
            continue
        considered += len(findings)

        prior_by_finding = _latest_prior_rows(db, [f.id for f in findings])

        rows_to_insert: list[dict] = []
        for f in findings:
            new_velocity = bool(f.building_velocity)
            prior = prior_by_finding.get(f.id)

            if prior is None:
                # Baseline — always recorded, never a promotion.
                rows_to_insert.append(_row(f, scored_at, new_velocity))
                continue

            changed = (
                prior["risk_score"] != f.risk_score
                or prior["risk_band"] != f.risk_band
                or prior["building_velocity"] != new_velocity
            )
            if not changed:
                continue

            rows_to_insert.append(_row(f, scored_at, new_velocity))

            if _is_promotion(prior["risk_band"], prior["building_velocity"], f.risk_band, new_velocity):
                promotions.append(Promotion(
                    finding_canonical_id=f.id,
                    asset_canonical_id=f.asset_canonical_id,
                    previous_band=prior["risk_band"],
                    new_band=f.risk_band,
                    previous_score=prior["risk_score"],
                    new_score=f.risk_score,
                    velocity_started=new_velocity and not prior["building_velocity"],
                ))

        if rows_to_insert:
            db.execute(insert(ScoreHistory.__table__), rows_to_insert)
            db.commit()
            rows_inserted += len(rows_to_insert)

    log.info(
        "score_history capture complete — considered=%d rows_inserted=%d promotions=%d",
        considered, rows_inserted, len(promotions),
    )
    return promotions


# ── Internal ──────────────────────────────────────────────────────────────────

def _chunks(seq: list, size: int):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def _row(f: FindingCanonical, scored_at: datetime, velocity: bool) -> dict:
    return {
        "finding_canonical_id": f.id,
        "asset_canonical_id": f.asset_canonical_id,
        "scored_at": scored_at,
        "risk_score": f.risk_score,
        "risk_band": f.risk_band,
        "building_velocity": velocity,
        "inputs": _capture_inputs(f),
    }


def _capture_inputs(f: FindingCanonical) -> dict:
    """Exactly the keys listed in `_INPUT_KEYS`, NULLs omitted — see module
    docstring. Values are already JSON-safe scalars (str/float/bool/None);
    no ORM objects are ever stuffed in here."""
    values = {key: getattr(f, key) for key in _INPUT_KEYS}
    return {k: v for k, v in values.items() if v is not None}


def _latest_prior_rows(db: Session, finding_ids: list[uuid.UUID]) -> dict[uuid.UUID, dict]:
    """The latest `score_history` row per finding in ONE query — the
    mechanism that makes `capture()` idempotent (module docstring). Reads
    only the three columns the comparison/promotion logic needs."""
    rows = db.execute(
        text(
            "SELECT DISTINCT ON (finding_canonical_id) "
            "finding_canonical_id, risk_score, risk_band, building_velocity "
            "FROM score_history "
            "WHERE finding_canonical_id = ANY(:ids) "
            "ORDER BY finding_canonical_id, scored_at DESC"
        ),
        {"ids": finding_ids},
    ).fetchall()
    return {
        row.finding_canonical_id: {
            "risk_score": row.risk_score,
            "risk_band": row.risk_band,
            "building_velocity": row.building_velocity,
        }
        for row in rows
    }


def _band_rank(band: str) -> int:
    """Rank derived from `risk_scorer.BANDS[band][0]` (the band's lower
    score edge) — the ONE source of truth for band ordering; see module
    docstring. A band absent from `BANDS` ranks lowest and is logged."""
    entry = risk_scorer.BANDS.get(band)
    if entry is None:
        log.warning("score_history: risk_band %r not found in risk_scorer.BANDS — ranking lowest", band)
        return -1
    return entry[0]


def _is_promotion(prior_band: str, prior_velocity: bool, new_band: str, new_velocity: bool) -> bool:
    """Promotion = `risk_band` moved UP a tier, OR `building_velocity`
    turned on (false/None -> True). Never the reverse: a band drop, an
    unchanged band, or velocity remaining True is not a promotion. Pure
    function over plain values — no DB, so every adjacent band transition
    is directly unit-testable (see test_score_history.py)."""
    band_up = _band_rank(new_band) > _band_rank(prior_band)
    velocity_started = bool(new_velocity) and not prior_velocity
    return band_up or velocity_started
