"""Schema and seed-data assertions for the claims layer (planning#142, L1).

Migration 0039 lays down 7 new tables plus seed rows for the 3 reference
tables (observers, claim_types, edge_type_relationships). This is a green
slice: asset_metadata stays authoritative and nothing reads or writes these
tables from application code yet, so these are schema/seed/constraint
assertions, not behaviour tests of a reader that doesn't exist yet.

Requires a live DB connection with migration 0039 applied — same style as
test_database_requirements.py and test_target_scope.py.

Run with:  python -m app.tests.test_claims_schema
       or: pytest app/tests/test_claims_schema.py
"""

import uuid

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical

EXPECTED_TABLES = {
    "observers",
    "claim_types",
    "asset_claims",
    "claim_history",
    "asset_state",
    "edge_type_relationships",
    "authorisation_decisions",
}


def _table_exists(db, name: str) -> bool:
    return db.execute(text("SELECT to_regclass(:n)"), {"n": name}).scalar() is not None


def _mk_asset(db, asset_type: str = "ip_address") -> AssetCanonical:
    suffix = uuid.uuid4().hex[:8]
    asset = AssetCanonical(asset_type=asset_type, value=f"claims-schema-test-{suffix}")
    db.add(asset)
    db.commit()
    return asset


def _cleanup_asset(db, asset_id):
    db.rollback()
    db.execute(text("DELETE FROM asset_claims WHERE asset_canonical_id = :aid"), {"aid": asset_id})
    db.execute(text("DELETE FROM asset_state WHERE asset_canonical_id = :aid"), {"aid": asset_id})
    db.execute(text("DELETE FROM assets_canonical WHERE id = :aid"), {"aid": asset_id})
    db.commit()


def test_all_seven_claims_layer_tables_exist():
    db = SessionLocal()
    try:
        missing = {t for t in EXPECTED_TABLES if not _table_exists(db, t)}
    finally:
        db.close()
    assert not missing, f"Missing claims-layer tables: {sorted(missing)}"


def test_observers_seeded_with_18_rows_and_correct_addressing():
    db = SessionLocal()
    try:
        rows = db.execute(text("SELECT name, addressing FROM observers")).all()
    finally:
        db.close()
    by_name = dict(rows)
    assert len(by_name) == 18, f"expected 18 seeded observers, got {len(by_name)}: {sorted(by_name)}"
    assert by_name["naabu"] == "ip"
    assert by_name["banner_grab"] == "ip"
    assert by_name["tlsx"] == "name"
    assert by_name["httpx"] == "name"
    assert by_name["domain_affinity"] == "name"
    assert by_name["dns_resolve"] == "none"
    assert by_name["shodan"] == "none"
    assert by_name["cloudflare"] == "none"
    # cloud_inventory observer arrives with #118 — must NOT be seeded yet.
    assert "cloud_inventory" not in by_name


def test_claim_types_seeded_with_18_rows_and_exactly_two_authorisation_ttls():
    db = SessionLocal()
    try:
        rows = db.execute(text("SELECT claim_type, authorisation_ttl FROM claim_types")).all()
    finally:
        db.close()
    assert len(rows) == 18, f"expected 18 seeded claim types, got {len(rows)}"
    with_ttl = {claim_type for claim_type, ttl in rows if ttl is not None}
    assert with_ttl == {"affinity_confirmation", "cloud_inventory"}, with_ttl
    by_type = dict(rows)
    assert "observation" in by_type, "observation claim type (0041, L3c-2a) must be seeded"
    assert by_type["observation"] is None, "observation carries no authorisation_ttl"
    assert "cdn_boundary" in by_type, "cdn_boundary claim type (0042, L3c-3) must be seeded"
    assert by_type["cdn_boundary"] is None, "cdn_boundary carries no authorisation_ttl"
    assert "third_party_dependency" in by_type, (
        "third_party_dependency claim type (0044, planning#147) must be seeded"
    )
    assert by_type["third_party_dependency"] is None, (
        "third_party_dependency is an observation, not a probe authorisation — no TTL"
    )


def test_claim_types_frozenset_matches_the_seeded_table():
    """CLAIM_TYPES and the claim_types table are edited in separate files by
    every claim-type migration (0041, 0042, ...) and there is a CHECK
    constraint keyed off the same list — drift between them fails writes at
    runtime, not at import, so pin them together here."""
    from app.models.claim import CLAIM_TYPES
    db = SessionLocal()
    try:
        seeded = {r[0] for r in db.execute(text("SELECT claim_type FROM claim_types")).all()}
    finally:
        db.close()
    assert seeded == set(CLAIM_TYPES), (
        f"only in table: {seeded - set(CLAIM_TYPES)}; only in CLAIM_TYPES: {set(CLAIM_TYPES) - seeded}"
    )


def test_edge_type_relationships_seeded_with_7_rows():
    db = SessionLocal()
    try:
        rows = db.execute(text("SELECT edge_type, relationship FROM edge_type_relationships")).all()
    finally:
        db.close()
    by_type = dict(rows)
    assert len(by_type) == 7, f"expected 7 seeded edge_type_relationships, got {len(by_type)}"
    assert by_type["cname"] == "dependency"
    assert by_type["ns"] == "dependency"
    assert by_type["mx"] == "dependency"
    assert by_type["spf_include"] == "dependency"
    assert by_type["script_include"] == "dependency"
    assert by_type["dmarc_rua"] == "recipient"
    assert by_type["tls_rpt_rua"] == "recipient"


def test_claim_history_is_natively_partitioned_with_at_least_3_partitions():
    db = SessionLocal()
    try:
        is_partitioned = db.execute(text(
            "SELECT count(*) FROM pg_partitioned_table pt "
            "JOIN pg_class c ON c.oid = pt.partrelid "
            "WHERE c.relname = 'claim_history'"
        )).scalar()
        assert is_partitioned == 1, "claim_history is not declared PARTITION BY in pg_partitioned_table"

        partition_count = db.execute(text(
            "SELECT count(*) FROM pg_inherits i "
            "JOIN pg_class parent ON parent.oid = i.inhparent "
            "WHERE parent.relname = 'claim_history'"
        )).scalar()
        assert partition_count >= 3, f"expected >=3 claim_history partitions (incl. default), got {partition_count}"

        has_default = db.execute(text(
            "SELECT count(*) FROM pg_class WHERE relname = 'claim_history_default'"
        )).scalar()
        assert has_default == 1, "claim_history_default partition is missing"
    finally:
        db.close()


def test_asset_claims_unique_constraint_behavior():
    db = SessionLocal()
    asset = _mk_asset(db)
    try:
        observer_ids = dict(db.execute(text(
            "SELECT name, id FROM observers WHERE name IN ('naabu', 'banner_grab')"
        )).all())
        naabu_id = observer_ids["naabu"]
        banner_id = observer_ids["banner_grab"]

        # Two rows differing only in observer_id: both should succeed.
        db.execute(text(
            "INSERT INTO asset_claims (asset_canonical_id, observer_id, claim_type, claim_value) "
            "VALUES (:aid, :oid, 'port_observation', '{}'::jsonb)"
        ), {"aid": asset.id, "oid": naabu_id})
        db.execute(text(
            "INSERT INTO asset_claims (asset_canonical_id, observer_id, claim_type, claim_value) "
            "VALUES (:aid, :oid, 'port_observation', '{}'::jsonb)"
        ), {"aid": asset.id, "oid": banner_id})
        db.commit()

        count = db.execute(text(
            "SELECT count(*) FROM asset_claims WHERE asset_canonical_id = :aid"
        ), {"aid": asset.id}).scalar()
        assert count == 2

        # A duplicate (asset, observer, claim_type) must raise IntegrityError.
        raised = False
        try:
            db.execute(text(
                "INSERT INTO asset_claims (asset_canonical_id, observer_id, claim_type, claim_value) "
                "VALUES (:aid, :oid, 'port_observation', '{}'::jsonb)"
            ), {"aid": asset.id, "oid": naabu_id})
            db.commit()
        except IntegrityError:
            raised = True
            db.rollback()
        assert raised, "duplicate (asset_canonical_id, observer_id, claim_type) did not raise IntegrityError"
    finally:
        _cleanup_asset(db, asset.id)
        db.close()


def _assert_check_violation(db, sql: str, params: dict, label: str):
    raised = False
    try:
        db.execute(text(sql), params)
        db.commit()
    except IntegrityError:
        raised = True
        db.rollback()
    assert raised, f"{label} CHECK constraint did not reject an out-of-vocabulary value"


def test_observers_addressing_check_rejects_bad_vocabulary():
    db = SessionLocal()
    try:
        _assert_check_violation(
            db,
            "INSERT INTO observers (name, kind, trust, emits_traffic_to_target, addressing, description) "
            "VALUES (:name, 'scan', 'observed', true, 'bogus_addressing', 'test row')",
            {"name": f"check-test-{uuid.uuid4().hex[:8]}"},
            "observers.addressing",
        )
    finally:
        db.close()


def test_edge_type_relationships_relationship_check_rejects_bad_vocabulary():
    db = SessionLocal()
    try:
        _assert_check_violation(
            db,
            "INSERT INTO edge_type_relationships (edge_type, relationship, description) "
            "VALUES (:edge_type, 'bogus_relationship', 'test row')",
            {"edge_type": f"check-test-{uuid.uuid4().hex[:8]}"},
            "edge_type_relationships.relationship",
        )
    finally:
        db.close()


def test_asset_state_estate_check_rejects_bad_vocabulary():
    db = SessionLocal()
    asset = _mk_asset(db)
    try:
        _assert_check_violation(
            db,
            "INSERT INTO asset_state (asset_canonical_id, estate) VALUES (:aid, 'bogus_estate')",
            {"aid": asset.id},
            "asset_state.estate",
        )
    finally:
        _cleanup_asset(db, asset.id)
        db.close()


def test_asset_claims_claim_type_check_rejects_bad_vocabulary():
    db = SessionLocal()
    asset = _mk_asset(db)
    try:
        naabu_id = db.execute(text("SELECT id FROM observers WHERE name = 'naabu'")).scalar()
        _assert_check_violation(
            db,
            "INSERT INTO asset_claims (asset_canonical_id, observer_id, claim_type, claim_value) "
            "VALUES (:aid, :oid, 'bogus_claim_type', '{}'::jsonb)",
            {"aid": asset.id, "oid": naabu_id},
            "asset_claims.claim_type",
        )
    finally:
        _cleanup_asset(db, asset.id)
        db.close()


def _run():
    tests = [
        test_all_seven_claims_layer_tables_exist,
        test_observers_seeded_with_18_rows_and_correct_addressing,
        test_claim_types_seeded_with_18_rows_and_exactly_two_authorisation_ttls,
        test_claim_types_frozenset_matches_the_seeded_table,
        test_edge_type_relationships_seeded_with_7_rows,
        test_claim_history_is_natively_partitioned_with_at_least_3_partitions,
        test_asset_claims_unique_constraint_behavior,
        test_observers_addressing_check_rejects_bad_vocabulary,
        test_edge_type_relationships_relationship_check_rejects_bad_vocabulary,
        test_asset_state_estate_check_rejects_bad_vocabulary,
        test_asset_claims_claim_type_check_rejects_bad_vocabulary,
    ]
    for fn in tests:
        try:
            fn()
            print(f"OK: {fn.__name__}")
        except AssertionError as exc:
            print(f"FAIL: {fn.__name__}: {exc}")
            raise SystemExit(1)
    print("ALL PASS")


if __name__ == "__main__":
    _run()
