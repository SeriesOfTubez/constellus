"""Generators: turn evidence the system already holds into signals
(planning#277 S1a).

Only the filer-website generator is built in this slice. A generator never
commits (its caller owns the session) and never reads an entity name.
"""

from __future__ import annotations

import uuid
from datetime import date

from sqlalchemy.orm import Session

from app.models.observer import Observer
from app.models.org_entity import OrgEntity
from app.services import edgar_html
from app.services.org_discovery import candidates


def record_filer_websites(
    db: Session,
    *,
    filer: OrgEntity,
    observer: Observer,
    evidence_id: uuid.UUID,
    lines: list[str],
    filing_date: date,
) -> tuple[int, int, int]:
    """Every domain a confirmed filer's own 10-K names as its website becomes
    a `filer_10k_website` signal on each root the filer belongs to. Returns
    `(recorded, existing, unanchored)`:

    - `recorded`   -- signals newly inserted
    - `existing`   -- signals already on file (re-sighted: `last_seen_at` moved)
    - `unanchored` -- website mentions found for a filer that belongs to no
                      root; nothing is written for them

    `filing_date` is accepted for the caller's symmetry with the old
    proposer; the signal's own timestamps are when WE saw it, and the 10-K's
    date is on the cited evidence.
    """
    recorded = existing = unanchored = 0
    mentions = edgar_html.find_website_mentions(lines)
    if not mentions:
        return recorded, existing, unanchored
    roots = candidates.roots_of(db, filer.id)
    if not roots:
        return 0, 0, len(mentions)
    for domain, quote in mentions:
        for root in roots:
            try:
                outcome = candidates.record_signal(
                    db,
                    root_entity_id=root.id,
                    value=domain,
                    signal_type="filer_10k_website",
                    anchor_kind="filer_filing",
                    anchor_entity_id=filer.id,
                    via_entity_id=filer.id,
                    evidence_id=evidence_id,
                    quote=quote,
                    observer_id=observer.id,
                )
            except candidates.CandidateInvalid:
                # A string the extractor found that is not a storable domain.
                continue
            if outcome.created_signal:
                recorded += 1
            else:
                existing += 1
    return recorded, existing, unanchored
