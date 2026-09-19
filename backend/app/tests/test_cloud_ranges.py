"""Tests for the local `cloud_ranges` mirror (planning#181 Tier 0).

Real dev DB, no isolation — every row this suite inserts is tracked by id
and deleted in a finally block. `cloud_ranges_meta` is a real, shared
singleton row: tests that touch it snapshot whatever is there beforehand
and restore exactly that afterward, rather than ever doing a table-wide
DELETE (a table-wide DELETE FROM cloud_ranges would wipe a real loaded
dataset — see the module docstring in cloud_ranges.py).

IP addresses are RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) per the repo's gitleaks
non-reserved-public-ipv4 rule — a handful of specific addresses, not a wide
swathe of a reserved range (planning#171).

Run with:  python -m app.tests.test_cloud_ranges
       or: pytest app/tests/test_cloud_ranges.py
"""

import gzip
import hashlib
import json
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from app.core.database import SessionLocal
from app.models.cloud_range import CloudRange
from app.services import cloud_ranges as cr


# ── helpers ──────────────────────────────────────────────────────────────

def _insert_range(db, prefix, provider, service_class, service_raw=None, region=None, source="test", ip_version=4):
    row = CloudRange(
        id=uuid.uuid4(), prefix=prefix, ip_version=ip_version, provider=provider,
        service_raw=service_raw, service_class=service_class, region=region, source=source,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _cleanup_ranges(db, ids):
    db.rollback()
    if ids:
        db.query(CloudRange).filter(CloudRange.id.in_(ids)).delete(synchronize_session=False)
        db.commit()


def _fake_response(payload: dict):
    from types import SimpleNamespace
    return SimpleNamespace(raise_for_status=lambda: None, json=lambda: payload)


def _snapshot_meta(db):
    db.rollback()
    return db.execute(text(
        "SELECT dataset_sha256, generated_at, record_count, refreshed_at, manifest "
        "FROM cloud_ranges_meta WHERE id = true"
    )).first()


def _restore_meta(db, snapshot):
    db.rollback()
    db.execute(text("DELETE FROM cloud_ranges_meta"))
    if snapshot is not None:
        db.execute(text(
            "INSERT INTO cloud_ranges_meta (id, dataset_sha256, generated_at, record_count, refreshed_at, manifest) "
            "VALUES (true, :sha, :gen, :cnt, :ref, CAST(:manifest AS jsonb))"
        ), {
            "sha": snapshot.dataset_sha256, "gen": snapshot.generated_at,
            "cnt": snapshot.record_count, "ref": snapshot.refreshed_at,
            "manifest": json.dumps(snapshot.manifest),
        })
    db.commit()


@contextmanager
def _isolated_meta(db):
    """Snapshot cloud_ranges_meta, clear it, yield, then restore exactly what
    was there before — never a table-wide assumption about what "empty" means.

    The clear is load-bearing: cloud_ranges_meta is a single-row table
    (boolean PK + CHECK(id)), so a test that inserts its own row while a real
    refreshed row is present takes a UniqueViolation. These tests passed
    originally only because nobody had run the refresher yet."""
    snapshot = _snapshot_meta(db)
    db.execute(text("DELETE FROM cloud_ranges_meta"))
    db.commit()
    try:
        yield
    finally:
        _restore_meta(db, snapshot)


def _write_gzip_ndjson(tmp_path: str, lines: list[dict]) -> bytes:
    content = ("\n".join(json.dumps(line) for line in lines) + "\n").encode("utf-8")
    with gzip.open(tmp_path, "wb") as f:
        f.write(content)
    return content


# ── specificity ──────────────────────────────────────────────────────────

def test_lookup_longest_prefix_wins():
    db = SessionLocal()
    ids = []
    try:
        r1 = _insert_range(db, "192.0.2.0/24", "azure", "unknown", service_raw="AzureCloud.eastus")
        r2 = _insert_range(db, "192.0.2.128/25", "azure", "edge", service_raw="AzureFrontDoor.eastus")
        ids = [r1.id, r2.id]

        specific = cr.lookup(db, "192.0.2.130")
        assert specific is not None
        assert specific.service_class == "edge"
        assert specific.prefix == "192.0.2.128/25"

        broad = cr.lookup(db, "192.0.2.10")
        assert broad is not None
        assert broad.service_class == "unknown"
        assert broad.prefix == "192.0.2.0/24"
    finally:
        _cleanup_ranges(db, ids)
        db.close()


def test_lookup_equal_length_prefers_non_unknown():
    db = SessionLocal()
    ids = []
    try:
        r1 = _insert_range(db, "198.51.100.0/24", "gcp", "unknown", service_raw="all-google-cloud")
        r2 = _insert_range(db, "198.51.100.0/24", "gcp", "compute", service_raw="Compute Engine")
        ids = [r1.id, r2.id]

        match = cr.lookup(db, "198.51.100.5")
        assert match is not None
        assert match.service_class == "compute"
    finally:
        _cleanup_ranges(db, ids)
        db.close()


def test_lookup_no_match_returns_none():
    db = SessionLocal()
    ids = []
    try:
        r1 = _insert_range(db, "192.0.2.0/24", "aws", "compute", service_raw="EC2")
        ids = [r1.id]
        assert cr.lookup(db, "203.0.113.77") is None
    finally:
        _cleanup_ranges(db, ids)
        db.close()


def test_lookup_malformed_ip_returns_none_not_raise():
    db = SessionLocal()
    try:
        assert cr.lookup(db, "not-an-ip") is None
    finally:
        db.close()


# ── refresh: digest-unchanged path ──────────────────────────────────────

def test_refresh_digest_unchanged_does_not_download():
    db = SessionLocal()
    existing_sha = hashlib.sha256(b"planning-181-existing-dataset").hexdigest()
    with _isolated_meta(db):
        db.execute(text(
            "INSERT INTO cloud_ranges_meta (id, dataset_sha256, generated_at, record_count, refreshed_at, manifest) "
            "VALUES (true, :sha, now() - interval '1 day', 42, now() - interval '1 day', '{}'::jsonb)"
        ), {"sha": existing_sha})
        db.commit()

        manifest = {
            "dataset_sha256": existing_sha,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "record_count": 42,
        }
        cr.connector_get = lambda url, **kw: _fake_response(manifest)

        called = {"n": 0}

        def _must_not_download(tmp_path):
            called["n"] += 1
            raise AssertionError("dataset stream must not be invoked when digest is unchanged")

        cr._download_dataset_to_file = _must_not_download

        result = cr.refresh(db)

        assert called["n"] == 0, "digest-unchanged refresh must not stream the dataset"
        assert result.ok is True
        assert result.changed is False

        state = cr.dataset_state(db)
        assert state is not None
        assert state.dataset_sha256 == existing_sha
    db.close()


# ── refresh: digest mismatch ─────────────────────────────────────────────

def test_refresh_digest_mismatch_leaves_table_untouched():
    db = SessionLocal()
    ids = []
    try:
        with _isolated_meta(db):
            pre_existing = _insert_range(db, "192.0.2.0/24", "aws", "compute", service_raw="EC2")
            ids = [pre_existing.id]

            bogus_sha = "0" * 64
            manifest = {
                "dataset_sha256": bogus_sha,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "record_count": 1,
            }
            cr.connector_get = lambda url, **kw: _fake_response(manifest)

            def _write_mismatched_dataset(tmp_path):
                _write_gzip_ndjson(tmp_path, [
                    {"prefix": "198.51.100.0/24", "ip_version": 4, "provider": "aws",
                     "service_class": "compute", "source": "test"},
                ])

            cr._download_dataset_to_file = _write_mismatched_dataset

            result = cr.refresh(db)

            assert result.ok is False
            assert result.reason == "digest_mismatch"

            still_there = db.query(CloudRange).filter(CloudRange.id == pre_existing.id).first()
            assert still_there is not None, "digest mismatch must leave pre-existing rows untouched"

            assert cr.dataset_state(db) is None, "meta must be untouched on digest mismatch"
    finally:
        _cleanup_ranges(db, ids)
        db.close()


# ── dataset_state staleness ──────────────────────────────────────────────

def test_dataset_state_staleness():
    db = SessionLocal()
    with _isolated_meta(db):
        db.execute(text("DELETE FROM cloud_ranges_meta"))
        db.execute(text(
            "INSERT INTO cloud_ranges_meta (id, dataset_sha256, generated_at, record_count, refreshed_at, manifest) "
            "VALUES (true, 'stale-test-sha', now() - interval '4 days', 1, now(), '{}'::jsonb)"
        ))
        db.commit()
        state = cr.dataset_state(db)
        assert state is not None
        assert state.stale is True, "generated_at 4 days old must be stale"

        db.execute(text("DELETE FROM cloud_ranges_meta"))
        db.execute(text(
            "INSERT INTO cloud_ranges_meta (id, dataset_sha256, generated_at, record_count, refreshed_at, manifest) "
            "VALUES (true, 'fresh-test-sha', now() - interval '1 day', 1, now(), '{}'::jsonb)"
        ))
        db.commit()
        state = cr.dataset_state(db)
        assert state is not None
        assert state.stale is False, "generated_at 1 day old must not be stale"
    db.close()


def _run():
    tests = [
        test_lookup_longest_prefix_wins,
        test_lookup_equal_length_prefers_non_unknown,
        test_lookup_no_match_returns_none,
        test_lookup_malformed_ip_returns_none_not_raise,
        test_refresh_digest_unchanged_does_not_download,
        test_refresh_digest_mismatch_leaves_table_untouched,
        test_dataset_state_staleness,
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
