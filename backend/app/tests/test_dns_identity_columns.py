"""Tests for promoting dns_record identity (record_type/content) to real
assets_canonical columns (L3b-1, planning#144).

Migration 0026 keyed dns_record dedup off a partial unique index on
`coalesce(metadata->>'record_type', ''), coalesce(metadata->>'content', '')`
— a JSONB path, not a column. Migration 0040 promotes both to real columns
and repoints the unique index at them; asset_writer._canonical_key /
_defensive_insert_assets' ON CONFLICT inference move in lockstep with that
index. This is the delicate slice: if the ON CONFLICT index_elements ever
drift out of exact sync with uq_assets_canonical_dns, a colliding INSERT
raises IntegrityError instead of deduping — the tests below run everything
through write_assets() (never raw SQL) specifically to catch that.

Requires a live DB connection with migration 0040 applied — same style as
test_finding_writer_asset_disambiguation.py / test_claim_emission.py.

Run with:  python -m app.tests.test_dns_identity_columns
       or: pytest app/tests/test_dns_identity_columns.py
"""

import uuid

from sqlalchemy import text

from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.services.asset_writer import write_assets
from app.services.shared_infra_verifier import _owned_hostnames_for_ip


def _cleanup(value: str) -> None:
    db = SessionLocal()
    try:
        db.query(AssetCanonical).filter(AssetCanonical.value == value).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


# ── dedup preservation (the gate) ───────────────────────────────────────────

def test_two_a_records_same_fqdn_stay_two_rows():
    """Two A records for one FQDN with different `content` (round-robin)
    must survive as 2 distinct canonical rows, not collapse onto one."""
    suffix = uuid.uuid4().hex[:10]
    host = f"dns-ident-two-a-{suffix}.example.com"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="dns_record", value=host, parent_value=None,
                             asset_metadata={"record_type": "A", "content": "203.0.113.10"}),
            DiscoveredAsset(asset_type="dns_record", value=host, parent_value=None,
                             asset_metadata={"record_type": "A", "content": "203.0.113.11"}),
        ])
        rows = db.query(AssetCanonical).filter(AssetCanonical.value == host).all()
        assert len(rows) == 2, f"expected 2 rows, got {len(rows)}"
        contents = {r.content for r in rows}
        assert contents == {"203.0.113.10", "203.0.113.11"}
        assert all(r.record_type == "A" for r in rows)
    finally:
        db.close()
        _cleanup(host)


def test_a_aaaa_mx_same_fqdn_stay_three_rows():
    """A + AAAA + MX for one FQDN must survive as 3 distinct canonical rows —
    each (record_type, content) pair is its own identity."""
    suffix = uuid.uuid4().hex[:10]
    host = f"dns-ident-three-rt-{suffix}.example.com"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="dns_record", value=host, parent_value=None,
                             asset_metadata={"record_type": "A", "content": "203.0.113.20"}),
            DiscoveredAsset(asset_type="dns_record", value=host, parent_value=None,
                             asset_metadata={"record_type": "AAAA", "content": "2001:db8::20"}),
            DiscoveredAsset(asset_type="dns_record", value=host, parent_value=None,
                             asset_metadata={"record_type": "MX", "content": "mail.example.com"}),
        ])
        rows = db.query(AssetCanonical).filter(AssetCanonical.value == host).all()
        assert len(rows) == 3, f"expected 3 rows, got {len(rows)}"
        by_type = {r.record_type: r for r in rows}
        assert by_type.keys() == {"A", "AAAA", "MX"}
        assert by_type["A"].content == "203.0.113.20"
        assert by_type["AAAA"].content == "2001:db8::20"
        assert by_type["MX"].content == "mail.example.com"
    finally:
        db.close()
        _cleanup(host)


def test_reobserving_identical_record_dedups_no_integrityerror():
    """Writing the SAME (value, record_type, content) twice across two
    separate write_assets() calls must dedup onto 1 row, not raise
    IntegrityError — this is what breaks first if the ON CONFLICT
    index_elements ever drift out of sync with uq_assets_canonical_dns."""
    suffix = uuid.uuid4().hex[:10]
    host = f"dns-ident-reobserve-{suffix}.example.com"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="dns_record", value=host, parent_value=None,
                             asset_metadata={"record_type": "A", "content": "203.0.113.30",
                                              "sources": ["dns_records"]}),
        ])
        # Second, separate batch — same identity, different in-band data
        # (ttl) so this also exercises the metadata-merge path alongside dedup.
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="dns_record", value=host, parent_value=None,
                             asset_metadata={"record_type": "A", "content": "203.0.113.30",
                                              "sources": ["dns_records"], "ttl": 300}),
        ])
        rows = db.query(AssetCanonical).filter(AssetCanonical.value == host).all()
        assert len(rows) == 1, f"expected 1 deduped row, got {len(rows)}"
        assert rows[0].record_type == "A"
        assert rows[0].content == "203.0.113.30"
        assert rows[0].asset_metadata.get("ttl") == 300
    finally:
        db.close()
        _cleanup(host)


def test_reobserving_identical_record_in_same_batch_dedups():
    """Same identity twice WITHIN one write_assets() batch (e.g. two
    connectors both reporting the same A record) must also collapse to 1
    row — exercises the in-batch `unique` dict keying, not just the
    ON CONFLICT path."""
    suffix = uuid.uuid4().hex[:10]
    host = f"dns-ident-same-batch-{suffix}.example.com"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="dns_record", value=host, parent_value=None,
                             asset_metadata={"record_type": "A", "content": "203.0.113.40"}),
            DiscoveredAsset(asset_type="dns_record", value=host, parent_value=None,
                             asset_metadata={"record_type": "A", "content": "203.0.113.40"}),
        ])
        rows = db.query(AssetCanonical).filter(AssetCanonical.value == host).all()
        assert len(rows) == 1, f"expected 1 deduped row, got {len(rows)}"
    finally:
        db.close()
        _cleanup(host)


# ── columns + metadata agree ────────────────────────────────────────────────

def test_columns_and_metadata_agree_on_fresh_write():
    """A freshly written dns_record must carry its identity in BOTH the
    record_type/content COLUMNS (authority) and asset_metadata (still
    written, still what the API serializes — L3c's job to remove)."""
    suffix = uuid.uuid4().hex[:10]
    host = f"dns-ident-agree-{suffix}.example.com"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="dns_record", value=host, parent_value=None,
                             asset_metadata={"record_type": "CNAME", "content": "target.example.net"}),
        ])
        row = db.query(AssetCanonical).filter(AssetCanonical.value == host).one()
        assert row.record_type == "CNAME"
        assert row.content == "target.example.net"
        assert row.asset_metadata.get("record_type") == "CNAME"
        assert row.asset_metadata.get("content") == "target.example.net"
    finally:
        db.close()
        _cleanup(host)


# ── backfill (migration 0040's UPDATE) ──────────────────────────────────────

def test_backfill_populates_columns_from_metadata():
    """Replicates migration 0040's backfill UPDATE against a row inserted
    the way a pre-0040 row would have looked (metadata carries identity,
    columns NULL) — proves the exact backfill statement (not just the ORM
    write path) correctly derives record_type/content from JSONB.

    Doesn't cycle the DB through a live alembic downgrade/upgrade (which
    would perturb schema state for the rest of the suite); instead inserts
    directly with raw SQL to leave the new columns NULL, matching what
    alembic upgrade head's ADD COLUMN step produces for existing rows
    before the backfill UPDATE runs, then executes that exact UPDATE.
    """
    suffix = uuid.uuid4().hex[:10]
    host = f"dns-ident-backfill-{suffix}.example.com"
    row_id = uuid.uuid4()
    db = SessionLocal()
    try:
        db.execute(
            text(
                "INSERT INTO assets_canonical "
                "(id, asset_type, value, first_seen_at, last_seen_at, metadata, tags) "
                "VALUES (:id, 'dns_record', :value, now(), now(), "
                "CAST(:metadata AS jsonb), '[]'::jsonb)"
            ),
            {"id": row_id, "value": host, "metadata": '{"record_type": "A", "content": "203.0.113.50"}'},
        )
        db.commit()

        row = db.get(AssetCanonical, row_id)
        assert row.record_type is None and row.content is None, "precondition: columns start NULL"

        # The exact backfill statement from migration 0040's upgrade().
        db.execute(
            text(
                "UPDATE assets_canonical "
                "SET record_type = metadata->>'record_type', content = metadata->>'content' "
                "WHERE asset_type = 'dns_record' AND id = :id"
            ),
            {"id": row_id},
        )
        db.commit()

        db.expire_all()
        row = db.get(AssetCanonical, row_id)
        assert row.record_type == "A"
        assert row.content == "203.0.113.50"
    finally:
        db.query(AssetCanonical).filter(AssetCanonical.id == row_id).delete(synchronize_session=False)
        db.commit()
        db.close()


# ── shared_infra_verifier reads the columns ─────────────────────────────────

def test_shared_infra_verifier_selects_by_column():
    """_owned_hostnames_for_ip must select A/AAAA rows whose `content`
    column matches the target IP — repointed off asset_metadata['content']
    onto the column (L3b-1)."""
    suffix = uuid.uuid4().hex[:10]
    host_a = f"dns-ident-siv-a-{suffix}.example.com"
    host_mx = f"dns-ident-siv-mx-{suffix}.example.com"
    ip = "203.0.113.60"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="dns_record", value=host_a, parent_value=None,
                             asset_metadata={"record_type": "A", "content": ip}),
            # Different content — must NOT be selected.
            DiscoveredAsset(asset_type="dns_record", value=host_mx, parent_value=None,
                             asset_metadata={"record_type": "MX", "content": "mail.example.com"}),
        ])
        owned = _owned_hostnames_for_ip(db, ip)
        values = {r.value for r in owned}
        assert host_a in values
        assert host_mx not in values
    finally:
        db.close()
        _cleanup(host_a)
        _cleanup(host_mx)


def _run():
    tests = [
        test_two_a_records_same_fqdn_stay_two_rows,
        test_a_aaaa_mx_same_fqdn_stay_three_rows,
        test_reobserving_identical_record_dedups_no_integrityerror,
        test_reobserving_identical_record_in_same_batch_dedups,
        test_columns_and_metadata_agree_on_fresh_write,
        test_backfill_populates_columns_from_metadata,
        test_shared_infra_verifier_selects_by_column,
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
