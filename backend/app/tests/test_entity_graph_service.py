"""Service-layer behaviour for the corporate entity graph
(planning#212, L3) — `app.services.entity_graph`.

Complements `test_entity_graph_schema.py` (which proves the DB-level
constraints hold even when the service is bypassed) by proving the SERVICE
itself does the right thing: `store_evidence`'s content-addressed
idempotency, `assert_relation`'s auto-confirm gate and re-ingest safety, and
`project_edges`'s grouping of multiple sources into one edge.

Run with:  pytest app/tests/test_entity_graph_service.py
       or: python -m app.tests.test_entity_graph_service
"""

import uuid
from datetime import date, datetime, timezone

from app.core.database import SessionLocal
from app.models.entity_relation import EntityRelation
from app.services import entity_graph
from app.tests._entity_graph import (
    cleanup_entity,
    cleanup_evidence,
    cleanup_observer,
    cleanup_relation,
    make_entity,
    make_evidence,
    make_observer,
)


# ── store_evidence: content-addressed, idempotent ───────────────────────────

def test_store_evidence_is_idempotent_for_the_same_url_and_bytes():
    db = SessionLocal()
    fetch_id = None
    try:
        content = f"planning#212 store_evidence idempotency {uuid.uuid4().hex}".encode()
        url = f"https://example.test/{uuid.uuid4().hex[:8]}"
        fetched_at = datetime.now(timezone.utc)

        f1 = entity_graph.store_evidence(db, content=content, content_type="text/plain", source_url=url, fetched_at=fetched_at)
        f2 = entity_graph.store_evidence(db, content=content, content_type="text/plain", source_url=url, fetched_at=fetched_at)
        fetch_id = f1.id

        assert f1.id == f2.id, "re-storing identical (url, bytes) must return the SAME fetch row, not a duplicate"
        count = db.query(entity_graph.EvidenceFetch).filter(entity_graph.EvidenceFetch.source_url == url).count()
        assert count == 1
    finally:
        cleanup_evidence(db, fetch_id)
        db.close()


# ── assert_relation: the auto-confirm gate ──────────────────────────────────

def test_assert_relation_proposes_for_a_non_granted_observer():
    db = SessionLocal()
    subject = obj = observer = evidence = relation = None
    try:
        subject = make_entity(db)
        obj = make_entity(db)
        observer = make_observer(db, trust="observed", confirms_relations=False)
        evidence = make_evidence(db, source_url=f"https://example.test/{uuid.uuid4().hex[:8]}")

        relation = entity_graph.assert_relation(
            db, subject_id=subject.id, object_id=obj.id, relation="acquired",
            observer_id=observer.id, evidence_id=evidence.id,
            quote="an invented supporting passage", event_date=None, event_date_precision="unknown",
        )
        assert relation.status == "proposed"
        assert relation.decision_kind is None
        assert relation.decided_at is None
        assert relation.decided_by_id is None
        assert relation.observer_confirms is False
    finally:
        cleanup_relation(db, relation.id if relation else None)
        cleanup_observer(db, observer.id if observer else None)
        cleanup_evidence(db, evidence.id if evidence else None)
        cleanup_entity(db, subject.id if subject else None)
        cleanup_entity(db, obj.id if obj else None)
        db.close()


def test_assert_relation_auto_confirms_for_a_granted_observer_and_never_sets_decided_by():
    db = SessionLocal()
    subject = obj = observer = evidence = relation = None
    try:
        subject = make_entity(db)
        obj = make_entity(db)
        observer = make_observer(db, trust="observed", confirms_relations=True)
        evidence = make_evidence(db, source_url=f"https://example.test/{uuid.uuid4().hex[:8]}")

        relation = entity_graph.assert_relation(
            db, subject_id=subject.id, object_id=obj.id, relation="acquired",
            observer_id=observer.id, evidence_id=evidence.id,
            quote="an invented supporting passage", event_date=date(2026, 3, 1), event_date_precision="day",
        )
        assert relation.status == "confirmed"
        assert relation.decision_kind == "source"
        assert relation.decided_at is not None
        assert relation.decided_by_id is None, "assert_relation must never write decided_by_id"
        assert relation.observer_confirms is True
    finally:
        cleanup_relation(db, relation.id if relation else None)
        cleanup_observer(db, observer.id if observer else None)
        cleanup_evidence(db, evidence.id if evidence else None)
        cleanup_entity(db, subject.id if subject else None)
        cleanup_entity(db, obj.id if obj else None)
        db.close()


def test_reasserting_a_person_confirmed_relation_leaves_it_confirmed():
    """Acceptance item 7's second half, and the killing test for mutation
    #4 (`assert_relation` using `ON CONFLICT DO UPDATE SET status = ...`).
    A person confirms a proposed row; the SAME source is then re-ingested
    (identical subject/object/relation/observer/evidence — the natural key
    `assert_relation` upserts on). With the real `ON CONFLICT DO NOTHING`,
    this is a silent no-op and the row stays exactly as the person left it.
    If `assert_relation` instead used `DO UPDATE SET status = ...`, the
    UPDATE would either (a) fire the demotion trigger and raise, since the
    observer here is NOT granted and would compute `status='proposed'`, or
    (b) silently overwrite the person's decision — either way this test
    fails: it asserts a clean return with `status='confirmed'` and
    `decision_kind='person'` UNCHANGED."""
    db = SessionLocal()
    subject = obj = observer = evidence = relation = None
    try:
        from app.models.user import User, UserRole

        subject = make_entity(db)
        obj = make_entity(db)
        observer = make_observer(db, trust="observed", confirms_relations=False)
        evidence = make_evidence(db, source_url=f"https://example.test/{uuid.uuid4().hex[:8]}")
        user = User(
            id=uuid.uuid4(), email=f"eg212-decide-{uuid.uuid4().hex[:8]}@example.invalid",
            full_name="eg212 test decider", role=UserRole.ADMIN.value, is_active=True,
        )
        db.add(user)
        db.commit()

        relation = entity_graph.assert_relation(
            db, subject_id=subject.id, object_id=obj.id, relation="acquired",
            observer_id=observer.id, evidence_id=evidence.id,
            quote="an invented supporting passage", event_date=None, event_date_precision="unknown",
        )
        assert relation.status == "proposed"

        decided = entity_graph.decide(db, relation_id=relation.id, status="confirmed", user=user)
        assert decided.status == "confirmed"
        assert decided.decision_kind == "person"
        decided_by_before = decided.decided_by_id
        decided_at_before = decided.decided_at

        # Re-ingest the exact same source assertion.
        reasserted = entity_graph.assert_relation(
            db, subject_id=subject.id, object_id=obj.id, relation="acquired",
            observer_id=observer.id, evidence_id=evidence.id,
            quote="an invented supporting passage", event_date=None, event_date_precision="unknown",
        )
        assert reasserted.id == relation.id, "re-ingesting the same source must not create a second row"
        assert reasserted.status == "confirmed", "re-asserting must never demote an already-decided row"
        assert reasserted.decision_kind == "person"
        assert reasserted.decided_by_id == decided_by_before
        assert reasserted.decided_at == decided_at_before

        db.query(EntityRelation).filter(EntityRelation.id == relation.id).first()  # sanity read
        db.query(User).filter(User.id == user.id).delete(synchronize_session=False)
        db.commit()
    finally:
        cleanup_relation(db, relation.id if relation else None)
        cleanup_observer(db, observer.id if observer else None)
        cleanup_evidence(db, evidence.id if evidence else None)
        cleanup_entity(db, subject.id if subject else None)
        cleanup_entity(db, obj.id if obj else None)
        db.close()


# ── project_edges: two sources, one edge ────────────────────────────────────

def test_project_edges_groups_two_sources_into_one_edge():
    db = SessionLocal()
    subject = obj = observer_a = observer_b = evidence_a = evidence_b = None
    try:
        subject = make_entity(db)
        obj = make_entity(db)
        observer_a = make_observer(db, trust="observed", confirms_relations=False, name=f"eg212-source-a-{uuid.uuid4().hex[:6]}")
        observer_b = make_observer(db, trust="inferred", confirms_relations=False, name=f"eg212-source-b-{uuid.uuid4().hex[:6]}")
        evidence_a = make_evidence(db, source_url=f"https://example.test/a-{uuid.uuid4().hex[:8]}")
        evidence_b = make_evidence(db, source_url=f"https://example.test/b-{uuid.uuid4().hex[:8]}")

        r1 = entity_graph.assert_relation(
            db, subject_id=subject.id, object_id=obj.id, relation="acquired",
            observer_id=observer_a.id, evidence_id=evidence_a.id,
            quote="source A's invented passage", event_date=None, event_date_precision="unknown",
        )
        r2 = entity_graph.assert_relation(
            db, subject_id=subject.id, object_id=obj.id, relation="acquired",
            observer_id=observer_b.id, evidence_id=evidence_b.id,
            quote="source B's invented passage", event_date=None, event_date_precision="unknown",
            grounding="verified",
        )

        edges = entity_graph.project_edges(db, entity_id=subject.id)
        assert len(edges) == 1, f"expected one grouped edge, got {len(edges)}"
        edge = edges[0]
        assert edge["subject"] == subject.id
        assert edge["object"] == obj.id
        assert edge["relation"] == "acquired"
        assert edge["confirmed"] is False, "neither source is confirmed — the edge must not read as confirmed"
        assert len(edge["sources"]) == 2
        observer_names = {s["observer"] for s in edge["sources"]}
        assert observer_names == {observer_a.name, observer_b.name}

        cleanup_relation(db, r1.id)
        cleanup_relation(db, r2.id)
    finally:
        cleanup_evidence(db, evidence_a.id if evidence_a else None)
        cleanup_evidence(db, evidence_b.id if evidence_b else None)
        cleanup_observer(db, observer_a.id if observer_a else None)
        cleanup_observer(db, observer_b.id if observer_b else None)
        cleanup_entity(db, subject.id if subject else None)
        cleanup_entity(db, obj.id if obj else None)
        db.close()


def test_project_edges_confirmed_true_when_any_source_confirmed():
    db = SessionLocal()
    subject = obj = observer_granted = observer_plain = evidence_a = evidence_b = None
    try:
        subject = make_entity(db)
        obj = make_entity(db)
        observer_granted = make_observer(db, trust="observed", confirms_relations=True)
        observer_plain = make_observer(db, trust="observed", confirms_relations=False)
        evidence_a = make_evidence(db, source_url=f"https://example.test/a-{uuid.uuid4().hex[:8]}")
        evidence_b = make_evidence(db, source_url=f"https://example.test/b-{uuid.uuid4().hex[:8]}")

        r1 = entity_graph.assert_relation(
            db, subject_id=subject.id, object_id=obj.id, relation="subsidiary_of",
            observer_id=observer_granted.id, evidence_id=evidence_a.id,
            quote="granted source's invented passage", event_date=None, event_date_precision="unknown",
        )
        r2 = entity_graph.assert_relation(
            db, subject_id=subject.id, object_id=obj.id, relation="subsidiary_of",
            observer_id=observer_plain.id, evidence_id=evidence_b.id,
            quote="plain source's invented passage", event_date=None, event_date_precision="unknown",
        )

        edges = entity_graph.project_edges(db, entity_id=subject.id)
        assert len(edges) == 1
        assert edges[0]["confirmed"] is True

        cleanup_relation(db, r1.id)
        cleanup_relation(db, r2.id)
    finally:
        cleanup_evidence(db, evidence_a.id if evidence_a else None)
        cleanup_evidence(db, evidence_b.id if evidence_b else None)
        cleanup_observer(db, observer_granted.id if observer_granted else None)
        cleanup_observer(db, observer_plain.id if observer_plain else None)
        cleanup_entity(db, subject.id if subject else None)
        cleanup_entity(db, obj.id if obj else None)
        db.close()


def _run():
    tests = [
        test_store_evidence_is_idempotent_for_the_same_url_and_bytes,
        test_assert_relation_proposes_for_a_non_granted_observer,
        test_assert_relation_auto_confirms_for_a_granted_observer_and_never_sets_decided_by,
        test_reasserting_a_person_confirmed_relation_leaves_it_confirmed,
        test_project_edges_groups_two_sources_into_one_edge,
        test_project_edges_confirmed_true_when_any_source_confirmed,
    ]
    for fn in tests:
        fn()
        print(f"OK: {fn.__name__}")
    print("ALL PASS")


if __name__ == "__main__":
    _run()
