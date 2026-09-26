"""Corporate entity graph — service layer (planning#212, L3).

This module is the ONLY writer for `org_entities`/`entity_relations` (via
`assert_relation`) short of the review endpoints (`decide`), and the only
reader that groups per-source rows into displayable edges
(`project_edges`). It deliberately has NO function that maps a name or a
domain to an entity — entity lookup is by id or CIK only, so nothing here
can silently merge two entities by string similarity, which is exactly the
auto-merge migration 0061 forbids.

## `store_evidence` — content-addressed, idempotent

Two inserts, both `ON CONFLICT DO NOTHING` (same idiom as
`claim_emitter._upsert_claim`'s `pg_insert(...).on_conflict_do_nothing(...)
.returning(...)`): the blob by its sha256 (so identical bytes are stored
once), then the fetch by `(source_url, sha256)` (so re-fetching identical
bytes from the same URL is a no-op, not a duplicate row). Either insert may
lose the race to a concurrent caller; the final SELECT reads back whichever
row exists, ours or theirs.

## `assert_relation` — the one function that can create a CONFIRMED row

Sets `status='confirmed', decision_kind='source', decided_at=now()` IFF
`observers.confirms_relations` is true for the given observer — never based
on `trust`, and never writable by the caller directly, so the "AI never
confirms without a person" invariant holds no matter what an ingest script
passes in. `decided_by_id` is never written here: an auto-confirmation has
no person to attribute it to, and `decided_by_id`'s only writer is `decide`.
`ON CONFLICT DO NOTHING` (never `DO UPDATE SET status = ...`) — the
demotion-guard trigger (migration 0061) exists specifically because an
upsert that overwrites `status` would silently re-propose an already
decided row; this function does not even attempt to.

## `decide` — the only writer of `decision_kind = 'person'`

Audit logging is the CALLER's job (the API handler has the `Request` this
function does not) — see `app/api/entities.py`'s `decide_relation`, which
calls `audit.record_detail` with keys that avoid the substring "auth"
(`audit.scrub`'s `SECRET_KEY_HINTS` redacts any detail key containing it;
see `app/api/engagements.py`'s `transition_engagement` for the same
precaution around `authorisation_reference`).
"""

import uuid
from datetime import datetime, timezone
from typing import Literal

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models.entity_relation import EntityRelation
from app.models.evidence import EvidenceBlob, EvidenceFetch
from app.models.observer import Observer


def store_evidence(
    db: Session,
    *,
    content: bytes,
    content_type: str,
    source_url: str,
    fetched_at: datetime,
    origin: Literal["fetched", "person_supplied"] = "fetched",
) -> EvidenceFetch:
    """Store `content` (deduplicated by sha256) and record this
    (source_url, content, fetched_at) observation. Idempotent: re-storing
    the same bytes from the same URL returns the existing fetch row rather
    than creating a duplicate — including its existing `origin`.

    `origin="person_supplied"` (planning#216) is for an excerpt a person
    pasted and attributed to `source_url`: nothing was fetched, and
    `fetched_at` is when it was supplied."""
    import hashlib

    digest = hashlib.sha256(content).digest()

    db.execute(
        pg_insert(EvidenceBlob.__table__)
        .values(sha256=digest, content=content, content_type=content_type, byte_length=len(content))
        .on_conflict_do_nothing(index_elements=["sha256"])
    )

    fetch_id = uuid.uuid4()
    inserted_id = db.execute(
        pg_insert(EvidenceFetch.__table__)
        .values(id=fetch_id, sha256=digest, source_url=source_url, fetched_at=fetched_at, origin=origin)
        .on_conflict_do_nothing(constraint="uq_evidence_fetches_source_url_sha256")
        .returning(EvidenceFetch.id)
    ).scalar()
    db.commit()

    row_id = inserted_id if inserted_id is not None else db.execute(
        select(EvidenceFetch.id).where(
            EvidenceFetch.source_url == source_url, EvidenceFetch.sha256 == digest
        )
    ).scalar_one()
    return db.get(EvidenceFetch, row_id)


def assert_relation(
    db: Session,
    *,
    subject_id: uuid.UUID,
    object_id: uuid.UUID,
    relation: str,
    observer_id: uuid.UUID,
    evidence_id: uuid.UUID,
    quote: str,
    event_date,
    event_date_precision: str,
    grounding: str | None = None,
) -> EntityRelation:
    """Insert a proposed (or, for a granted observer, pre-confirmed) source
    assertion. `ON CONFLICT DO NOTHING` on the same unique constraint as the
    table (`uq_entity_relations_subject_object_relation_observer_evidence`)
    — re-ingesting the same source is a no-op, never a status overwrite
    (see module docstring)."""
    observer = db.get(Observer, observer_id)
    if observer is None:
        raise ValueError(f"observer {observer_id} not found")

    confirms = bool(observer.confirms_relations)
    values = dict(
        id=uuid.uuid4(),
        subject_id=subject_id,
        object_id=object_id,
        relation=relation,
        event_date=event_date,
        event_date_precision=event_date_precision,
        observer_id=observer_id,
        observer_confirms=confirms,
        evidence_id=evidence_id,
        quote=quote,
        grounding=grounding,
    )
    if confirms:
        values["status"] = "confirmed"
        values["decision_kind"] = "source"
        values["decided_at"] = datetime.now(timezone.utc)

    inserted_id = db.execute(
        pg_insert(EntityRelation.__table__)
        .values(**values)
        .on_conflict_do_nothing(constraint="uq_entity_relations_subject_object_relation_observer_evidence")
        .returning(EntityRelation.id)
    ).scalar()
    db.commit()

    row_id = inserted_id if inserted_id is not None else db.execute(
        select(EntityRelation.id).where(
            EntityRelation.subject_id == subject_id,
            EntityRelation.object_id == object_id,
            EntityRelation.relation == relation,
            EntityRelation.observer_id == observer_id,
            EntityRelation.evidence_id == evidence_id,
        )
    ).scalar_one()
    return db.get(EntityRelation, row_id)


def decide(
    db: Session,
    *,
    relation_id: uuid.UUID,
    status: Literal["confirmed", "rejected"],
    user,
) -> EntityRelation:
    """A person confirms or rejects a proposed (or previously
    source-confirmed) relation. Always `decision_kind='person'` — a person
    may confirm OR reject; only a granted observer's own assertion may
    self-confirm (`assert_relation`), and nothing here can reject on an
    observer's behalf (`ck_entity_relations_decision` requires
    `decision_kind='person'` for every rejection).

    Raises `IntegrityError` (uncaught, propagated to the caller) if the
    CHECK or the demotion trigger refuses the update — the caller (`app/api
    /entities.py`) turns that into a 409."""
    if status not in ("confirmed", "rejected"):
        raise ValueError("status must be 'confirmed' or 'rejected'")

    relation = db.get(EntityRelation, relation_id)
    if relation is None:
        raise ValueError(f"entity_relation {relation_id} not found")

    relation.status = status
    relation.decision_kind = "person"
    relation.decided_by_id = user.id
    relation.decided_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(relation)
    return relation


def project_edges(db: Session, *, entity_id: uuid.UUID | None = None) -> list[dict]:
    """Group non-rejected `entity_relations` rows by (subject, object,
    relation) into one displayable edge per triple, each carrying every
    source that asserted it. `confirmed` is true iff ANY source's row is
    `confirmed` — a proposed-only edge is still returned (visible, labelled
    `confirmed=False`), never silently dropped, but must never be counted
    for attribution by a caller that reads this."""
    query = db.query(EntityRelation).filter(EntityRelation.status != "rejected")
    if entity_id is not None:
        query = query.filter(
            (EntityRelation.subject_id == entity_id) | (EntityRelation.object_id == entity_id)
        )
    rows = query.all()
    if not rows:
        return []

    observer_ids = {r.observer_id for r in rows}
    evidence_ids = {r.evidence_id for r in rows}
    observers_by_id = {o.id: o for o in db.query(Observer).filter(Observer.id.in_(observer_ids)).all()}
    fetches_by_id = {f.id: f for f in db.query(EvidenceFetch).filter(EvidenceFetch.id.in_(evidence_ids)).all()}

    edges: dict[tuple, dict] = {}
    for r in rows:
        key = (r.subject_id, r.object_id, r.relation)
        edge = edges.setdefault(
            key,
            {"subject": r.subject_id, "object": r.object_id, "relation": r.relation, "confirmed": False, "sources": []},
        )
        if r.status == "confirmed":
            edge["confirmed"] = True
        observer = observers_by_id.get(r.observer_id)
        fetch = fetches_by_id.get(r.evidence_id)
        edge["sources"].append(
            {
                "relation_id": r.id,
                "evidence_id": r.evidence_id,
                "observer": observer.name if observer else None,
                "trust": observer.trust if observer else None,
                "status": r.status,
                "evidence_url": fetch.source_url if fetch else None,
                "fetched_at": fetch.fetched_at.isoformat() if fetch else None,
                "event_date": r.event_date.isoformat() if r.event_date else None,
                "precision": r.event_date_precision,
            }
        )
    return list(edges.values())
