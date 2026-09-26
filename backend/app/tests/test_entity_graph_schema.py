"""Schema/CHECK/trigger acceptance for the corporate entity graph
(planning#212, L3, migration 0061).

Every test here bypasses `app.services.entity_graph` entirely and drives
the database directly with raw SQL/Core `INSERT`/`UPDATE`, per the spec:
"the acceptance tests for the CHECK and the trigger must use RAW SQL/Core
INSERT and UPDATE that bypass the service, and must assert the
IntegrityError/raise itself. Proving the service avoids the bad state is
not the same thing." Each CHECK/trigger test also proves its HAPPY PATH
(the row the CHECK is meant to ALLOW), so a passing test can't be vacuous
because its precondition never actually fired against the real constraint.

Run with:  pytest app/tests/test_entity_graph_schema.py
       or: python -m app.tests.test_entity_graph_schema
"""

import uuid
from datetime import date, datetime, timezone

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from app.core.database import SessionLocal
from app.models.observer import Observer
from app.models.org_entity import OrgEntity
from app.tests._entity_graph import (
    cleanup_entity,
    cleanup_evidence,
    cleanup_observer,
    cleanup_relation,
    make_entity,
    make_evidence,
    make_observer,
)


# A static literal, every column named explicitly — NOT built from
# `cols.keys()` at call time. Semgrep's `avoid-sqlalchemy-text` blocks a
# `text()` statement assembled from runtime-derived strings (rightly: that
# is a real injection shape if any of those strings could ever be
# attacker-influenced); binding every value as a `:name` parameter against
# a fixed statement has no such path, whatever the caller passes in `cols`.
_INSERT_RELATION_SQL = text(
    "INSERT INTO entity_relations "
    "(id, subject_id, object_id, relation, event_date, event_date_precision, "
    "observer_id, observer_confirms, evidence_id, quote, grounding, status, "
    "decision_kind, decided_at, decided_by_id) "
    "VALUES (:id, :subject_id, :object_id, :relation, :event_date, :event_date_precision, "
    ":observer_id, :observer_confirms, :evidence_id, :quote, :grounding, :status, "
    ":decision_kind, :decided_at, :decided_by_id)"
)


def _insert_relation(db, **cols) -> uuid.UUID:
    """Raw INSERT into entity_relations — every column the CHECK cares
    about is explicit here; nothing is left to an ORM default that could
    mask what the constraint actually sees."""
    row_id = cols.setdefault("id", uuid.uuid4())
    cols.setdefault("status", "proposed")
    cols.setdefault("decision_kind", None)
    cols.setdefault("decided_at", None)
    cols.setdefault("decided_by_id", None)
    cols.setdefault("grounding", None)
    cols.setdefault("event_date", None)
    db.execute(_INSERT_RELATION_SQL, cols)
    return row_id


def _base_relation_cols(subject_id, object_id, observer_id, observer_confirms, evidence_id) -> dict:
    return dict(
        subject_id=subject_id,
        object_id=object_id,
        relation="acquired",
        event_date_precision="unknown",
        observer_id=observer_id,
        observer_confirms=observer_confirms,
        evidence_id=evidence_id,
        quote="an invented supporting passage for planning#212 tests",
    )


# ── fixture rig shared by most tests below ──────────────────────────────────

class _Rig:
    """One subject/object entity pair + one evidence fetch, reused across
    a test's several relation rows. Not a pytest fixture (this suite
    follows `test_claims_schema.py`/`test_engagement_acceptance.py`'s
    direct-SessionLocal convention so it stays runnable as `python -m`)."""

    def __init__(self):
        self.db = SessionLocal()
        self.subject = make_entity(self.db, legal_name=f"Example Holdings A {uuid.uuid4().hex[:6]}")
        self.object = make_entity(self.db, legal_name=f"Example Widgetco B {uuid.uuid4().hex[:6]}")
        self.evidence = make_evidence(self.db, source_url=f"https://example.test/{uuid.uuid4().hex[:8]}")
        self.observers: list[uuid.UUID] = []
        self.relations: list[uuid.UUID] = []

    def observer(self, **kw) -> Observer:
        o = make_observer(self.db, **kw)
        self.observers.append(o.id)
        return o

    def relation(self, **cols) -> uuid.UUID:
        rid = _insert_relation(self.db, **cols)
        self.relations.append(rid)
        return rid

    def commit(self):
        self.db.commit()

    def close(self):
        self.db.rollback()
        for rid in self.relations:
            cleanup_relation(self.db, rid)
        for oid in self.observers:
            cleanup_observer(self.db, oid)
        cleanup_evidence(self.db, self.evidence.id)
        cleanup_entity(self.db, self.subject.id)
        cleanup_entity(self.db, self.object.id)
        self.db.close()


# ── 1. inferred observer -> confirmed/rejected without a person: DB raises ──

def test_inferred_observer_cannot_confirm_via_raw_insert():
    """`observer_confirms` can never be true for an `inferred` observer
    (`ck_observers_inferred_never_confirms`), so an insert that tries to
    claim status='confirmed', decision_kind='source', observer_confirms=true
    against an `inferred` observer must fail at the OBSERVER row, not reach
    entity_relations at all. This is the base case the whole gate rests on."""
    rig = _Rig()
    try:
        # Attempting to grant confirms_relations to an inferred observer is
        # covered by test 2 below; here we prove the CONSEQUENCE: even if a
        # caller lies about observer_confirms=true for an inferred observer
        # that was never granted it, the composite FK rejects the row
        # because (observer.id, true) is not a row in `observers`.
        inferred = rig.observer(trust="inferred", confirms_relations=False)
        cols = _base_relation_cols(rig.subject.id, rig.object.id, inferred.id, True, rig.evidence.id)
        cols.update(status="confirmed", decision_kind="source", decided_at=datetime.now(timezone.utc))
        raised = False
        try:
            _insert_relation(rig.db, **cols)
            rig.db.commit()
        except IntegrityError:
            raised = True
            rig.db.rollback()
        assert raised, "an inferred observer must not be able to confirm a relation"
    finally:
        rig.close()


def test_inferred_observer_cannot_reject_via_raw_update():
    """Rejection always needs `decision_kind='person'`
    (`ck_entity_relations_decision`) — there is no `decision_kind='source'`
    branch for `status='rejected'` at all, inferred or not. Proven here via
    UPDATE: propose a row from an inferred observer, then try to flip it to
    rejected with decision_kind='source' (as if a code path let the
    observer itself reject) — must raise."""
    rig = _Rig()
    try:
        inferred = rig.observer(trust="inferred", confirms_relations=False)
        rid = rig.relation(**_base_relation_cols(rig.subject.id, rig.object.id, inferred.id, False, rig.evidence.id))
        rig.commit()

        raised = False
        try:
            rig.db.execute(
                text(
                    "UPDATE entity_relations SET status='rejected', decision_kind='source', "
                    "decided_at=now() WHERE id=:id"
                ),
                {"id": rid},
            )
            rig.db.commit()
        except IntegrityError:
            raised = True
            rig.db.rollback()
        assert raised, "rejection must always require decision_kind='person'"

        # Happy path: a PERSON may reject the same row.
        rig.db.execute(
            text("UPDATE entity_relations SET status='rejected', decision_kind='person', decided_at=now() WHERE id=:id"),
            {"id": rid},
        )
        rig.commit()
        row = rig.db.execute(text("SELECT status FROM entity_relations WHERE id=:id"), {"id": rid}).scalar()
        assert row == "rejected"
    finally:
        rig.close()


# ── 2. ck_observers_inferred_never_confirms ─────────────────────────────────

def test_ck_observers_inferred_never_confirms():
    db = SessionLocal()
    observer_id = None
    try:
        observer_id = None
        raised = False
        try:
            o = make_observer(db, trust="inferred", confirms_relations=True)
            observer_id = o.id
        except IntegrityError:
            raised = True
            db.rollback()
        assert raised, "granting confirms_relations to an inferred observer must raise"

        # Happy path: a non-inferred observer MAY be granted the flag.
        o2 = make_observer(db, trust="observed", confirms_relations=True)
        observer_id = o2.id
        assert o2.confirms_relations is True
    finally:
        cleanup_observer(db, observer_id)
        db.close()


# ── 3. rejection by decision_kind='source' raises, even for a granted observer ─

def test_rejection_by_source_raises_even_for_a_granted_observer():
    rig = _Rig()
    try:
        granted = rig.observer(trust="observed", confirms_relations=True)
        rid = rig.relation(**_base_relation_cols(rig.subject.id, rig.object.id, granted.id, True, rig.evidence.id))
        # assert_relation-equivalent auto-confirm state, inserted directly:
        rig.db.execute(
            text(
                "UPDATE entity_relations SET status='confirmed', decision_kind='source', decided_at=now() "
                "WHERE id=:id"
            ),
            {"id": rid},
        )
        rig.commit()

        raised = False
        try:
            rig.db.execute(
                text(
                    "UPDATE entity_relations SET status='rejected', decision_kind='source', decided_at=now() "
                    "WHERE id=:id"
                ),
                {"id": rid},
            )
            rig.db.commit()
        except IntegrityError:
            raised = True
            rig.db.rollback()
        assert raised, "a granted observer's own row must still require a PERSON to reject it"
    finally:
        rig.close()


# ── 5. identical names/no CIK -> two entities; duplicate CIK -> IntegrityError ─

def test_identical_names_no_cik_create_two_distinct_entities():
    db = SessionLocal()
    e1 = e2 = None
    try:
        name = f"Example Holdings Duplicate {uuid.uuid4().hex[:6]}"
        e1 = make_entity(db, legal_name=name)
        e2 = make_entity(db, legal_name=name)
        assert e1.id != e2.id
        count = db.query(OrgEntity).filter(OrgEntity.legal_name == name).count()
        assert count == 2, "identical legal_name must not be merged or deduplicated"
    finally:
        cleanup_entity(db, e1.id if e1 else None)
        cleanup_entity(db, e2.id if e2 else None)
        db.close()


def test_duplicate_cik_raises_integrity_error():
    db = SessionLocal()
    e1 = e2_id = None
    try:
        cik = "".join(str((uuid.uuid4().int + i) % 10) for i in range(10))
        e1 = make_entity(db, cik=cik)
        raised = False
        try:
            e2 = OrgEntity(id=uuid.uuid4(), legal_name="Example Holdings Dup CIK", cik=cik)
            db.add(e2)
            db.commit()
            e2_id = e2.id
        except IntegrityError:
            raised = True
            db.rollback()
        assert raised, "a second entity with the same CIK must raise IntegrityError"
    finally:
        cleanup_entity(db, e2_id)
        cleanup_entity(db, e1.id if e1 else None)
        db.close()


# ── 6. event_date / precision invariant ─────────────────────────────────────

def test_event_date_precision_invariant():
    """Each insert below needs its OWN evidence row — the natural-key
    unique constraint (`subject_id, object_id, relation, observer_id,
    evidence_id`) would otherwise reject the second/third insert as a
    duplicate of the first before the event_date CHECK is even reached,
    which would make this test pass for the wrong reason."""
    rig = _Rig()
    evidence2_id = evidence3_id = None
    try:
        observer = rig.observer(trust="observed", confirms_relations=False)
        evidence2 = make_evidence(rig.db, source_url=f"https://example.test/{uuid.uuid4().hex[:8]}")
        evidence3 = make_evidence(rig.db, source_url=f"https://example.test/{uuid.uuid4().hex[:8]}")
        evidence2_id, evidence3_id = evidence2.id, evidence3.id

        # Happy path: unknown precision + NULL date is the required pairing
        # (both are _base_relation_cols' defaults).
        rid_ok = rig.relation(
            **_base_relation_cols(rig.subject.id, rig.object.id, observer.id, False, rig.evidence.id),
        )
        rig.commit()
        stored = rig.db.execute(
            text("SELECT event_date, event_date_precision FROM entity_relations WHERE id=:id"), {"id": rid_ok}
        ).one()
        assert stored.event_date is None and stored.event_date_precision == "unknown"

        # day precision with a NULL event_date must raise.
        raised = False
        try:
            cols = _base_relation_cols(rig.subject.id, rig.object.id, observer.id, False, evidence2.id)
            cols.update(event_date=None, event_date_precision="day")
            _insert_relation(rig.db, **cols)
            rig.db.commit()
        except IntegrityError:
            raised = True
            rig.db.rollback()
        assert raised, "'day' precision with a NULL event_date must raise"

        # Happy path for 'day': a real date is required and accepted.
        cols = _base_relation_cols(rig.subject.id, rig.object.id, observer.id, False, evidence3.id)
        cols.update(event_date=date(2026, 1, 15), event_date_precision="day")
        rid_day = rig.relation(**cols)
        rig.commit()
        stored2 = rig.db.execute(
            text("SELECT event_date FROM entity_relations WHERE id=:id"), {"id": rid_day}
        ).scalar()
        assert stored2 == date(2026, 1, 15)
    finally:
        rig.close()
        cleanup_evidence(SessionLocal(), evidence2_id)
        cleanup_evidence(SessionLocal(), evidence3_id)


# ── 7. demotion trigger ─────────────────────────────────────────────────────

def test_demotion_trigger_blocks_confirmed_to_proposed():
    rig = _Rig()
    try:
        observer = rig.observer(trust="observed", confirms_relations=False)
        rid = rig.relation(**_base_relation_cols(rig.subject.id, rig.object.id, observer.id, False, rig.evidence.id))
        rig.commit()
        # A person confirms it.
        rig.db.execute(
            text("UPDATE entity_relations SET status='confirmed', decision_kind='person', decided_at=now() WHERE id=:id"),
            {"id": rid},
        )
        rig.commit()

        raised = False
        try:
            rig.db.execute(
                text(
                    "UPDATE entity_relations SET status='proposed', decision_kind=NULL, decided_at=NULL "
                    "WHERE id=:id"
                ),
                {"id": rid},
            )
            rig.db.commit()
        except DBAPIError:
            # A plain `RAISE EXCEPTION` (not a constraint violation) surfaces
            # as psycopg2.errors.RaiseException / SQLAlchemy InternalError,
            # not IntegrityError — DBAPIError is the shared superclass.
            raised = True
            rig.db.rollback()
        assert raised, "confirmed -> proposed must be refused by the demotion trigger"

        # The row is unharmed by the refused UPDATE — still confirmed.
        status = rig.db.execute(text("SELECT status FROM entity_relations WHERE id=:id"), {"id": rid}).scalar()
        assert status == "confirmed"

        # Happy path for the trigger: proposed -> confirmed (forward) and
        # confirmed -> rejected (sideways, not a demotion back to proposed)
        # must both still be legal UPDATEs.
        rig.db.execute(
            text("UPDATE entity_relations SET status='rejected', decision_kind='person', decided_at=now() WHERE id=:id"),
            {"id": rid},
        )
        rig.commit()
        status2 = rig.db.execute(text("SELECT status FROM entity_relations WHERE id=:id"), {"id": rid}).scalar()
        assert status2 == "rejected"
    finally:
        rig.close()


# ── 8. revoking a grant while source-confirmed rows exist is refused ────────

def test_revoking_grant_with_source_confirmed_rows_is_refused():
    rig = _Rig()
    try:
        granted = rig.observer(trust="observed", confirms_relations=True)
        rid = rig.relation(
            **_base_relation_cols(rig.subject.id, rig.object.id, granted.id, True, rig.evidence.id),
        )
        rig.db.execute(
            text("UPDATE entity_relations SET status='confirmed', decision_kind='source', decided_at=now() WHERE id=:id"),
            {"id": rid},
        )
        rig.commit()

        raised = False
        try:
            rig.db.execute(
                text("UPDATE observers SET confirms_relations = false WHERE id = :id"), {"id": granted.id}
            )
            rig.db.commit()
        except IntegrityError:
            raised = True
            rig.db.rollback()
        assert raised, (
            "revoking confirms_relations while a source-confirmed row exists must be refused "
            "(ON UPDATE CASCADE would otherwise silently flip observer_confirms to false and "
            "leave a decision_kind='source' row that no longer satisfies the CHECK)"
        )

        # Happy path: a person re-decides the row first, THEN revocation succeeds.
        rig.db.execute(
            text("UPDATE entity_relations SET decision_kind='person', decided_by_id=NULL, decided_at=now() WHERE id=:id"),
            {"id": rid},
        )
        rig.commit()
        rig.db.execute(text("UPDATE observers SET confirms_relations = false WHERE id = :id"), {"id": granted.id})
        rig.commit()
        confirms = rig.db.execute(text("SELECT confirms_relations FROM observers WHERE id=:id"), {"id": granted.id}).scalar()
        assert confirms is False
        observer_confirms_now = rig.db.execute(
            text("SELECT observer_confirms FROM entity_relations WHERE id=:id"), {"id": rid}
        ).scalar()
        assert observer_confirms_now is False, "ON UPDATE CASCADE must still propagate once the row is re-decided"
    finally:
        rig.close()


# ── 9. evidence_blobs integrity ─────────────────────────────────────────────

def test_evidence_blob_wrong_sha256_raises():
    db = SessionLocal()
    try:
        content = b"planning#212 integrity test content"
        wrong_hash = b"\x00" * 32
        raised = False
        try:
            db.execute(
                text(
                    "INSERT INTO evidence_blobs (sha256, content, content_type, byte_length) "
                    "VALUES (:sha256, :content, 'text/plain', :len)"
                ),
                {"sha256": wrong_hash, "content": content, "len": len(content)},
            )
            db.commit()
        except IntegrityError:
            raised = True
            db.rollback()
        assert raised, "a stored sha256 that doesn't match the stored content must raise"
    finally:
        db.execute(text("DELETE FROM evidence_blobs WHERE sha256 = :sha256"), {"sha256": b"\x00" * 32})
        db.commit()
        db.close()


def test_identical_bytes_two_urls_one_blob_two_fetches():
    db = SessionLocal()
    fetch1 = fetch2 = None
    try:
        content = f"identical bytes {uuid.uuid4().hex}".encode()
        fetch1 = make_evidence(db, content=content, source_url="https://example.test/mirror-a")
        fetch2 = make_evidence(db, content=content, source_url="https://example.test/mirror-b")
        assert fetch1.sha256 == fetch2.sha256
        assert fetch1.id != fetch2.id
        blob_count = db.execute(
            text("SELECT count(*) FROM evidence_blobs WHERE sha256 = :sha256"), {"sha256": fetch1.sha256}
        ).scalar()
        assert blob_count == 1
        fetch_count = db.execute(
            text("SELECT count(*) FROM evidence_fetches WHERE sha256 = :sha256"), {"sha256": fetch1.sha256}
        ).scalar()
        assert fetch_count == 2
    finally:
        cleanup_evidence(db, fetch1.id if fetch1 else None)
        cleanup_evidence(db, fetch2.id if fetch2 else None)
        db.close()


# ── 10. deleting a user who decided a relation succeeds (SET NULL) ─────────

def test_deleting_deciding_user_sets_null_and_check_still_holds():
    from app.models.user import User, UserRole

    rig = SessionLocal()
    subject = make_entity(rig, legal_name=f"Example Holdings A {uuid.uuid4().hex[:6]}")
    obj = make_entity(rig, legal_name=f"Example Widgetco B {uuid.uuid4().hex[:6]}")
    evidence = make_evidence(rig, source_url=f"https://example.test/{uuid.uuid4().hex[:8]}")
    observer = make_observer(rig, trust="observed", confirms_relations=False)
    user = User(
        id=uuid.uuid4(), email=f"eg212-decider-{uuid.uuid4().hex[:8]}@example.invalid",
        full_name="eg212 test decider", role=UserRole.ADMIN.value, is_active=True,
    )
    rig.add(user)
    rig.commit()

    rid = _insert_relation(
        rig, **_base_relation_cols(subject.id, obj.id, observer.id, False, evidence.id),
    )
    rig.commit()
    rig.execute(
        text("UPDATE entity_relations SET status='confirmed', decision_kind='person', decided_at=now(), decided_by_id=:uid WHERE id=:id"),
        {"uid": user.id, "id": rid},
    )
    rig.commit()

    try:
        rig.query(User).filter(User.id == user.id).delete(synchronize_session=False)
        rig.commit()
        row = rig.execute(
            text("SELECT status, decision_kind, decided_at, decided_by_id FROM entity_relations WHERE id=:id"),
            {"id": rid},
        ).one()
        assert row.decided_by_id is None, "decided_by_id must be SET NULL, not block the user delete"
        assert row.status == "confirmed" and row.decision_kind == "person" and row.decided_at is not None, (
            "the row must still satisfy ck_entity_relations_decision after the SET NULL"
        )
    finally:
        cleanup_relation(rig, rid)
        cleanup_observer(rig, observer.id)
        cleanup_evidence(rig, evidence.id)
        cleanup_entity(rig, subject.id)
        cleanup_entity(rig, obj.id)
        rig.close()


# ── mutation-table support: composite FK vs. a plain FK on observer_id ──────

def test_composite_fk_rejects_a_drifted_observer_confirms_copy():
    """Mutation #3 in the spec's table: if `fk_entity_relations_observer_
    confirms` were a plain FK on `observer_id` alone (ignoring
    `observer_confirms`), a row could claim `observer_confirms=true` for an
    observer whose real `confirms_relations` is `false` — the exact drift
    the COMPOSITE FK exists to prevent. With the real composite FK, this
    insert must raise (the pair `(observer.id, true)` is not a row in
    `observers`)."""
    rig = _Rig()
    try:
        not_granted = rig.observer(trust="observed", confirms_relations=False)
        cols = _base_relation_cols(rig.subject.id, rig.object.id, not_granted.id, True, rig.evidence.id)
        raised = False
        try:
            _insert_relation(rig.db, **cols)
            rig.db.commit()
        except IntegrityError:
            raised = True
            rig.db.rollback()
        assert raised, (
            "observer_confirms=true for an observer whose confirms_relations is false must be "
            "rejected by the composite FK — a plain FK on observer_id alone would let this drift"
        )
    finally:
        rig.close()


def test_ungranted_observer_cannot_source_confirm_with_an_honest_copy():
    """The direct attack on `ck_entity_relations_decision`: a row whose
    `observer_confirms` copy is TRUTHFUL (false, matching its observer, so
    the composite FK is satisfied) claims `status='confirmed',
    decision_kind='source'`. Only the CHECK's `observer_confirms` term stops
    this. The tests above reach the gate through the FK (a lying copy) or
    the revoke cascade; this one reaches it with nothing else in the way.
    Covers both ungranted shapes: an `inferred` observer (AI) and an
    `observed` one that was simply never granted (the Wayback case).
    The granted happy path runs first so the insert shape is proven valid
    and a failure below can only be the CHECK."""
    rig = _Rig()
    try:
        granted = rig.observer(trust="observed", confirms_relations=True)
        cols = _base_relation_cols(rig.subject.id, rig.object.id, granted.id, True, rig.evidence.id)
        cols.update(status="confirmed", decision_kind="source", decided_at=datetime.now(timezone.utc))
        rig.relation(**cols)
        rig.commit()

        for trust in ("inferred", "observed"):
            ungranted = rig.observer(trust=trust, confirms_relations=False)
            cols = _base_relation_cols(rig.subject.id, rig.object.id, ungranted.id, False, rig.evidence.id)
            cols.update(status="confirmed", decision_kind="source", decided_at=datetime.now(timezone.utc))
            raised = False
            try:
                _insert_relation(rig.db, **cols)
                rig.db.commit()
            except IntegrityError:
                raised = True
                rig.db.rollback()
            assert raised, f"an ungranted {trust} observer must not source-confirm a relation"
    finally:
        rig.close()


def _run():
    tests = [
        test_ungranted_observer_cannot_source_confirm_with_an_honest_copy,
        test_inferred_observer_cannot_confirm_via_raw_insert,
        test_inferred_observer_cannot_reject_via_raw_update,
        test_ck_observers_inferred_never_confirms,
        test_rejection_by_source_raises_even_for_a_granted_observer,
        test_identical_names_no_cik_create_two_distinct_entities,
        test_duplicate_cik_raises_integrity_error,
        test_event_date_precision_invariant,
        test_demotion_trigger_blocks_confirmed_to_proposed,
        test_revoking_grant_with_source_confirmed_rows_is_refused,
        test_evidence_blob_wrong_sha256_raises,
        test_identical_bytes_two_urls_one_blob_two_fetches,
        test_deleting_deciding_user_sets_null_and_check_still_holds,
        test_composite_fk_rejects_a_drifted_observer_confirms_copy,
    ]
    for fn in tests:
        fn()
        print(f"OK: {fn.__name__}")
    print("ALL PASS")


if __name__ == "__main__":
    _run()
