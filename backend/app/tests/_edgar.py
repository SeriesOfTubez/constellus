"""Shared fixture helpers for SEC EDGAR ingest tests (planning#213, L4
slice 1). Mirrors `_entity_graph.py`'s pattern: throwaway rows, invented
names/CIKs only (`feedback_real_customer_data` — never a real company or a
real CIK).

## Synthetic CIKs

`make_cik(db)` draws from `uuid4().int`, formats as 10 digits, and forces
the first two digits to "99" — real SEC CIKs are assigned sequentially from
a much lower range (Apple's is 0000320193; the live counter is still well
under 2,000,000), so no `99##########`-prefixed value can collide with a
real filer. It also re-draws on a collision with an existing `org_entities.
cik` row, per the spec.

## Cleanup

`cleanup_cik(db, cik)` deletes everything one `ingest_cik(db, cik)` call (or
a test seeding the same shape by hand) could have created, in FK-safe
order: `entity_relations` (by subject) -> `entity_filing_events` (by
entity) -> `evidence_fetches`/`evidence_blobs` (found by CIK appearing in
`source_url`, since every URL this slice fetches embeds the CIK) ->
former-name `org_entities` (the relations' objects) -> the main entity.
Never deletes the seeded `edgar_former_names`/`edgar_8k_items` observer
rows — those are migration-owned, not test-owned.
"""

import uuid

from sqlalchemy import select

from app.models.entity_filing_event import EntityFilingEvent
from app.models.entity_relation import EntityRelation
from app.models.org_entity import OrgEntity
from app.tests._entity_graph import cleanup_evidence


def make_cik(db) -> str:
    while True:
        cik = "99" + f"{uuid.uuid4().int % 10**8:08d}"
        exists = db.execute(select(OrgEntity.id).where(OrgEntity.cik == cik)).first()
        if exists is None:
            return cik


def cleanup_cik(db, cik: str | None) -> None:
    if cik is None:
        return

    entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one_or_none()

    object_ids: set[uuid.UUID] = set()
    if entity is not None:
        relations = db.execute(select(EntityRelation).where(EntityRelation.subject_id == entity.id)).scalars().all()
        object_ids = {r.object_id for r in relations}
        if relations:
            db.query(EntityRelation).filter(EntityRelation.id.in_([r.id for r in relations])).delete(
                synchronize_session=False
            )
            db.commit()

        events = db.execute(select(EntityFilingEvent).where(EntityFilingEvent.entity_id == entity.id)).scalars().all()
        if events:
            db.query(EntityFilingEvent).filter(EntityFilingEvent.id.in_([e.id for e in events])).delete(
                synchronize_session=False
            )
            db.commit()

    # Every URL this slice fetches embeds the CIK
    # (.../submissions/CIK<cik>.json or .../CIK<cik>-submissions-NNN.json),
    # so finding evidence by CIK-in-source_url catches fetches even when
    # nothing ended up referencing them (e.g. a denied-signal run that still
    # fetched the main submissions JSON for the other, permitted signal).
    from app.models.evidence import EvidenceFetch

    fetch_rows = db.execute(select(EvidenceFetch).where(EvidenceFetch.source_url.contains(cik))).scalars().all()
    for f in fetch_rows:
        cleanup_evidence(db, f.id)

    if object_ids:
        db.query(OrgEntity).filter(OrgEntity.id.in_(object_ids)).delete(synchronize_session=False)
        db.commit()

    if entity is not None:
        db.query(OrgEntity).filter(OrgEntity.id == entity.id).delete(synchronize_session=False)
        db.commit()
