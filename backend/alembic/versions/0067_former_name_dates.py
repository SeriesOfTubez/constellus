"""Backfill `formerly_named` event dates from their stored quotes (planning#241)

SEC's `formerNames[].to` is an ISO datetime ("2015-06-30T04:00:00.000Z"),
but `edgar_ingest._parse_event_date` accepted only a bare `YYYY-MM-DD`
until planning#241, so every `formerly_named` row the `edgar_former_names`
observer wrote was stored `event_date = NULL, precision = 'unknown'`. The
date was never lost: each row's `quote` is the canonical JSON of the SEC
entry itself. A re-ingest cannot repair them (the former-names reuse
lookup skips any existing row), so this migration does, deterministically
and without any fetch (Jason, 2026-09-28).

## Upgrade

Only rows that are ALL of: relation `formerly_named`, observer
`edgar_former_names`, `event_date IS NULL`, and a quote that is a JSON
object whose `to` matches the pattern below and is a real calendar date.
Each gets `(date part of to, 'day')`, the same rule the fixed parser now
applies (the pattern is copied, not imported: a migration must not change
meaning when app code does). Any other row, including one whose quote does
not parse, is left untouched. The UPDATE re-checks `event_date IS NULL`.

`status` is not touched, so `trg_entity_relations_no_demotion` (which only
refuses a move back to `proposed`) does not fire, and
`ck_entity_relations_precision_matches_event_date` holds because date and
precision are set together.

## Downgrade

Restores what the pre-#241 parser would have stored: re-nulls the
`edgar_former_names` rows whose quote's `to` is in the DATETIME form
(bare-date quotes were always dated, so they keep their dates) and whose
`event_date` equals that date part. That is exactly the rows this upgrade
filled, plus any the fixed code wrote since; the old code could date none
of them.
"""

import json
import re
from datetime import date

import sqlalchemy as sa
from alembic import op

revision = "0067"
down_revision = "0066"
branch_labels = None
depends_on = None

_EVENT_DATE_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$"
)

_SELECT = sa.text(
    """
    SELECT r.id, r.quote, r.event_date
    FROM entity_relations r
    JOIN observers o ON o.id = r.observer_id
    WHERE r.relation = 'formerly_named'
      AND o.name = 'edgar_former_names'
    """
)


def _to_date(quote: str | None) -> tuple[date, bool] | None:
    """(date part of the quote's `to`, whether `to` was a datetime), or None."""
    try:
        entry = json.loads(quote or "")
    except ValueError:
        return None
    raw = entry.get("to") if isinstance(entry, dict) else None
    if not isinstance(raw, str):
        return None
    m = _EVENT_DATE_RE.match(raw)
    if not m:
        return None
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3))), "T" in raw
    except ValueError:
        return None


def upgrade() -> None:
    bind = op.get_bind()
    for row in bind.execute(_SELECT).all():
        if row.event_date is not None:
            continue
        parsed = _to_date(row.quote)
        if parsed is None:
            continue
        bind.execute(
            sa.text(
                "UPDATE entity_relations SET event_date = :d, event_date_precision = 'day' "
                "WHERE id = :id AND event_date IS NULL"
            ),
            {"d": parsed[0], "id": row.id},
        )


def downgrade() -> None:
    bind = op.get_bind()
    for row in bind.execute(_SELECT).all():
        parsed = _to_date(row.quote)
        if parsed is None or not parsed[1] or row.event_date != parsed[0]:
            continue
        bind.execute(
            sa.text(
                "UPDATE entity_relations SET event_date = NULL, event_date_precision = 'unknown' "
                "WHERE id = :id AND event_date = :d"
            ),
            {"d": parsed[0], "id": row.id},
        )
