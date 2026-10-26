"""Test-only cleanup for `scope_candidates` and what hangs off them
(planning#277 S1a).

`scope_candidate_events` is append-only in production: its trigger refuses
DELETE. Candidates reference their events (RESTRICT), so a test that made a
decision cannot remove its candidate without removing the events first. The
tests run against a throwaway database (`constellus_test`), so this helper
disables that one trigger for the duration of one transaction and puts it
back; nothing in application code does this.
"""

from __future__ import annotations

import uuid

from sqlalchemy import or_, select, text

from app.models.scope_candidate import ScopeCandidate, ScopeCandidateEvent, ScopeCandidateReassignment, ScopeSignal


def purge(db, *, entity_ids=(), candidate_ids=(), connector_instance_ids=()) -> set[uuid.UUID]:
    """Delete every candidate under or affiliated with `entity_ids` (plus
    `candidate_ids`), their signals and events, and any signal elsewhere that
    cites those entities or candidates. Returns the evidence ids those
    signals cited, so the caller can delete the evidence after. Does not
    roll back first: a caller mid-cleanup has uncommitted deletes of its own
    (the commit at the end publishes them)."""
    entity_ids, candidate_ids = list(entity_ids), list(candidate_ids)
    instance_ids = list(connector_instance_ids)
    cids = set(candidate_ids)
    if instance_ids:
        # Candidates a connector instance decided or signalled (planning#277 S1b):
        # the instance cannot be deleted while these reference it (RESTRICT).
        cids |= set(db.execute(
            select(ScopeCandidate.id).where(ScopeCandidate.decided_by_connector_instance_id.in_(instance_ids))
        ).scalars())
        cids |= set(db.execute(
            select(ScopeSignal.candidate_id).where(ScopeSignal.anchor_connector_instance_id.in_(instance_ids))
        ).scalars())
    if entity_ids:
        cids |= set(db.execute(
            select(ScopeCandidate.id).where(
                or_(ScopeCandidate.root_entity_id.in_(entity_ids), ScopeCandidate.affiliated_entity_id.in_(entity_ids))
            )
        ).scalars())
    sig = ScopeSignal
    conds = [sig.candidate_id.in_(cids), sig.anchor_candidate_id.in_(cids)]
    if instance_ids:
        conds.append(sig.anchor_connector_instance_id.in_(instance_ids))
    if entity_ids:
        conds += [sig.via_entity_id.in_(entity_ids), sig.anchor_entity_id.in_(entity_ids)]
    signals = db.execute(select(sig.id, sig.evidence_id, sig.candidate_id).where(or_(*conds))).all()
    sids = [s.id for s in signals]
    evidence = {s.evidence_id for s in signals if s.evidence_id is not None}
    if not (cids or sids):
        return evidence
    ev = ScopeCandidateEvent
    db.execute(text("ALTER TABLE scope_candidate_events DISABLE TRIGGER trg_scope_candidate_events_append_only"))
    try:
        conds_ev = [ev.candidate_id.in_(cids), ev.signal_id.in_(sids)]
        if instance_ids:
            conds_ev.append(ev.connector_instance_id.in_(instance_ids))
        db.query(ev).filter(or_(*conds_ev)).delete(synchronize_session=False)
    finally:
        db.execute(text("ALTER TABLE scope_candidate_events ENABLE TRIGGER trg_scope_candidate_events_append_only"))
    # Reassigned-away records (planning#278 S3c3a) reference the candidate and their evidence (RESTRICT).
    reassigned = db.query(ScopeCandidateReassignment).filter(ScopeCandidateReassignment.candidate_id.in_(cids))
    evidence |= {r.evidence_id for r in reassigned.all()}
    reassigned.delete(synchronize_session=False)
    db.query(sig).filter(sig.id.in_(sids)).delete(synchronize_session=False)
    db.query(ScopeCandidate).filter(ScopeCandidate.id.in_(cids)).delete(synchronize_session=False)
    db.commit()
    return evidence


def make_candidate(db, *, root_id, via_id=None, value=None, signal_type="person_evidence", user_id=None, track=None):
    """A real open candidate under `root_id` with one Strong signal, through
    `record_signal` (so every service rule ran). Returns `(candidate,
    evidence_fetch)`; the caller deletes the evidence after `purge`. `track`
    (a list) receives the evidence id as soon as it exists, so a refused
    signal does not strand the evidence row."""
    from app.services.org_discovery import candidates
    from app.tests._entity_graph import make_evidence

    value = value or f"sc277-{uuid.uuid4().hex[:10]}.example.com"
    evidence = make_evidence(
        db, content=f"sc277 excerpt {uuid.uuid4().hex}".encode(), source_url=f"https://example.test/{uuid.uuid4().hex[:8]}"
    )
    if track is not None:
        track.append(evidence.id)
    outcome = candidates.record_signal(
        db, root_entity_id=root_id, value=value, signal_type=signal_type, anchor_kind="person",
        anchor_user_id=user_id, via_entity_id=via_id or root_id, evidence_id=evidence.id,
        quote=f"Our site is {value}.",
    )
    db.commit()
    return outcome.candidate, evidence
