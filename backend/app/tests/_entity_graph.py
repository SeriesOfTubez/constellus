"""Shared fixture helpers for entity-graph tests (planning#212, L3).

Mirrors `_engagement.py`'s pattern: throwaway rows, created and deleted by
id, invented names/CIKs only (`feedback_real_customer_data` — never a real
company). Cleanup order matters: `entity_relations` rows must be deleted
before the `org_entities`/`evidence_fetches` they reference (RESTRICT FKs),
and `evidence_fetches` before `evidence_blobs` (also RESTRICT).
"""

import uuid
from datetime import datetime, timezone

from app.core.database import SessionLocal
from app.models.entity_relation import EntityRelation
from app.models.evidence import EvidenceBlob, EvidenceFetch
from app.models.observer import Observer
from app.models.org_entity import OrgEntity


def make_observer(db, *, trust: str = "observed", confirms_relations: bool = False, **overrides) -> Observer:
    overrides.setdefault("name", f"eg212-observer-{uuid.uuid4().hex[:10]}")
    overrides.setdefault("kind", "connector")
    overrides.setdefault("addressing", "none")
    overrides.setdefault("noise_class", "silent")
    overrides.setdefault("description", "throwaway test observer (planning#212)")
    o = Observer(id=uuid.uuid4(), trust=trust, confirms_relations=confirms_relations, **overrides)
    db.add(o)
    db.commit()
    return o


def cleanup_observer(db, observer_id: uuid.UUID | None) -> None:
    if observer_id is None:
        return
    db.query(Observer).filter(Observer.id == observer_id).delete(synchronize_session=False)
    db.commit()


def make_entity(db, *, legal_name: str | None = None, cik: str | None = None, lei: str | None = None) -> OrgEntity:
    e = OrgEntity(
        id=uuid.uuid4(),
        legal_name=legal_name or f"Example Holdings {uuid.uuid4().hex[:8]}",
        cik=cik,
        lei=lei,
    )
    db.add(e)
    db.commit()
    return e


def cleanup_entity(db, entity_id: uuid.UUID | None) -> None:
    if entity_id is None:
        return
    db.query(OrgEntity).filter(OrgEntity.id == entity_id).delete(synchronize_session=False)
    db.commit()


def make_evidence(
    db,
    *,
    content: bytes = b"an invented press release body for planning#212 tests",
    content_type: str = "text/plain",
    source_url: str = "https://example.test/filing",
    fetched_at: datetime | None = None,
) -> EvidenceFetch:
    from app.services import entity_graph

    return entity_graph.store_evidence(
        db,
        content=content,
        content_type=content_type,
        source_url=source_url,
        fetched_at=fetched_at or datetime.now(timezone.utc),
    )


def cleanup_evidence(db, fetch_id: uuid.UUID | None) -> None:
    """Deletes the fetch row, then its blob IFF no other fetch still
    references that sha256 (two fetches may legitimately share one blob —
    see migration 0061's docstring)."""
    if fetch_id is None:
        return
    fetch = db.get(EvidenceFetch, fetch_id)
    if fetch is None:
        return
    sha = fetch.sha256
    db.query(EvidenceFetch).filter(EvidenceFetch.id == fetch_id).delete(synchronize_session=False)
    db.commit()
    remaining = db.query(EvidenceFetch).filter(EvidenceFetch.sha256 == sha).count()
    if remaining == 0:
        db.query(EvidenceBlob).filter(EvidenceBlob.sha256 == sha).delete(synchronize_session=False)
        db.commit()


def cleanup_relation(db, relation_id: uuid.UUID | None) -> None:
    if relation_id is None:
        return
    db.query(EntityRelation).filter(EntityRelation.id == relation_id).delete(synchronize_session=False)
    db.commit()
