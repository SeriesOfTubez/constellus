"""Coverage for migration 0102 (planning#347): the `finding_endpoints` table and
its backfill from what each existing finding already proves.

The test database is already at head, so the findings here are seeded directly
with NO endpoint rows, then the migration's own `downgrade()` (drops the table)
and `upgrade()` (recreates it and backfills every finding in the database) are
run through alembic's `Operations`. That scans the whole `findings_canonical`
table, which is fine on the throwaway `constellus_test` database this suite
refuses to run without. Synthetic data only.

Run with:  backend/scripts/test.sh app/tests/test_migration_0102_finding_endpoints.py
"""

import importlib.util
import ipaddress
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from sqlalchemy import text

from app.core.database import SessionLocal, engine
from app.models.asset_canonical import AssetCanonical
from app.models.finding_canonical import FindingCanonical
from app.models.finding_endpoint import FindingEndpoint
from app.tests import _docaddr

_PATH = Path(__file__).resolve().parents[2] / "alembic" / "versions" / "0102_finding_endpoints.py"

FIRST = datetime(2019, 3, 4, 5, 6, tzinfo=timezone.utc)
LAST = datetime(2020, 5, 6, 7, 8, tzinfo=timezone.utc)
V6_NET = "2001:db8::/32"


_ADDRS: list[str] = []


def _a(i: int) -> str:
    """The module's i-th documentation address, drawn on first use and reused
    (the shared `_docaddr` pool is small); the fixture purges by value first."""
    while len(_ADDRS) <= i:
        _ADDRS.append(_docaddr.alloc())
    return _ADDRS[i]


def _migration():
    spec = importlib.util.spec_from_file_location("migration_0102", _PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(fn_name: str) -> None:
    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            getattr(_migration(), fn_name)()


def _table_exists() -> bool:
    with engine.begin() as conn:
        return conn.execute(text("SELECT to_regclass('public.finding_endpoints') IS NOT NULL")).scalar_one()


@pytest.fixture
def seeded():
    """Findings keyed by label, on a handful of assets, with no endpoint rows.
    Yields (findings, expected, rows, shape, state_of)."""
    db = SessionLocal()
    suffix = uuid.uuid4().hex[:4]
    ip = _a(0)
    v6 = str(ipaddress.ip_address(f"2001:db8::{suffix}"))
    cidr_asset = f"2001:db8:{suffix}::/48"
    host = f"mig0102-{uuid.uuid4().hex[:10]}.example.com"
    origin = _a(1)
    other_origin = _a(2)

    asset_values = [ip, v6, cidr_asset, host]
    stale = [r[0] for r in db.query(AssetCanonical.id).filter(AssetCanonical.value.in_(asset_values))]
    if stale:  # delete-then-insert: a failed earlier test cannot poison this one
        db.query(FindingCanonical).filter(FindingCanonical.asset_canonical_id.in_(stale)).delete(
            synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.id.in_(stale)).delete(synchronize_session=False)
        db.commit()
    assets: dict[str, AssetCanonical] = {}
    for kind, value, atype in (("ip", ip, "ip_address"), ("v6", v6, "ip_address"),
                               ("cidr", cidr_asset, "ip_address"), ("dns", host, "dns_record")):
        a = AssetCanonical(asset_type=atype, value=value)
        db.add(a)
        assets[kind] = a
    db.flush()

    findings: dict[str, uuid.UUID] = {}

    def add(label, kind, detail, *, ftype="exposed_service", state="open"):
        f = FindingCanonical(
            asset_canonical_id=assets[kind].id, finding_type=ftype, source="constellus",
            fingerprint=label, severity="low", title=label, state=state, detail=detail,
            first_seen_at=FIRST, last_seen_at=LAST,
        )
        db.add(f)
        db.flush()
        findings[label] = f.id

    add("ip_port_proto", "ip", {"port": 8443, "protocol": "TCP"})
    add("ip_no_port", "ip", {})
    add("v6_port", "v6", {"port": 22})
    add("dns_port", "dns", {"port": 8443})
    add("dns_no_port", "dns", {})
    add("dangling_origin", "dns", {"origin_ip": origin}, ftype="dangling_dns")
    add("dangling_origin_with_port", "dns", {"origin_ip": other_origin, "port": 25}, ftype="dangling_dns")
    add("dangling_not_ip", "dns", {"origin_ip": "not-an-ip"}, ftype="dangling_dns")
    add("dangling_cidr", "dns", {"origin_ip": V6_NET}, ftype="dangling_dns")
    add("dangling_not_string", "dns", {"origin_ip": 12345}, ftype="dangling_dns")
    add("origin_ip_on_other_type", "dns", {"origin_ip": origin}, ftype="exposed_service")
    add("port_string", "ip", {"port": "443"})
    add("port_zero", "ip", {"port": 0})
    add("port_70000", "ip", {"port": 70000})
    add("port_fractional", "ip", {"port": 80.5})
    add("port_bool", "ip", {"port": True})
    add("port_1", "ip", {"port": 1})
    add("port_65535", "ip", {"port": 65535})
    add("protocol_http", "ip", {"port": 80, "protocol": "http"})
    add("protocol_udp_upper", "ip", {"port": 53, "protocol": "UDP"})
    add("protocol_not_string", "ip", {"port": 53, "protocol": 6})
    add("resolved", "ip", {"port": 8443, "protocol": "tcp"}, state="resolved")
    add("cidr_valued_ip_asset", "cidr", {"port": 22})
    db.commit()

    expected = {
        "ip_port_proto": (ip, 8443, "tcp"),
        "ip_no_port": (ip, None, None),
        "v6_port": (v6, 22, None),
        "dns_port": (None, 8443, None),
        "dns_no_port": None,
        "dangling_origin": (origin, None, None),
        "dangling_origin_with_port": (other_origin, 25, None),
        "dangling_not_ip": None,
        "dangling_cidr": None,
        "dangling_not_string": None,
        "origin_ip_on_other_type": None,
        "port_string": (ip, None, None),
        "port_zero": (ip, None, None),
        "port_70000": (ip, None, None),
        "port_fractional": (ip, None, None),
        "port_bool": (ip, None, None),
        "port_1": (ip, 1, None),
        "port_65535": (ip, 65535, None),
        "protocol_http": (ip, 80, None),
        "protocol_udp_upper": (ip, 53, "udp"),
        "protocol_not_string": (ip, 53, None),
        "resolved": (ip, 8443, "tcp"),
        "cidr_valued_ip_asset": (None, 22, None),
    }

    # Reads use a short-lived session of their own: a transaction left open on
    # this one would hold a lock on finding_endpoints and block the migration's
    # DROP TABLE.
    def rows(label):
        with SessionLocal() as reader:
            return reader.query(FindingEndpoint).filter(FindingEndpoint.finding_id == findings[label]).all()

    def shape(label):
        return sorted((None if r.address is None else str(r.address), r.port, r.protocol) for r in rows(label))

    def state_of(label):
        with SessionLocal() as reader:
            return reader.get(FindingCanonical, findings[label])

    try:
        assert not any(rows(label) for label in findings)
        yield findings, expected, rows, shape, state_of
    finally:
        if not _table_exists():
            _run("upgrade")  # never leave the shared test database without the table
        db.rollback()
        asset_ids = [a.id for a in assets.values()]
        db.query(FindingCanonical).filter(FindingCanonical.asset_canonical_id.in_(asset_ids)).delete(
            synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(asset_values)).delete(synchronize_session=False)
        db.commit()
        db.close()


def _migrate_down_up():
    _run("downgrade")
    _run("upgrade")


def test_backfill_records_exactly_what_each_finding_proves(seeded):
    findings, expected, rows, shape, state_of = seeded
    _migrate_down_up()
    for label, want in expected.items():
        assert state_of(label) is not None, f"{label}: finding vanished"
        assert shape(label) == ([] if want is None else [want]), label


def test_backfill_copies_the_findings_own_timestamps(seeded):
    findings, expected, rows, shape, state_of = seeded
    _migrate_down_up()
    (row,) = rows("ip_port_proto")  # the row exists, so the comparison below is reached
    assert row.first_seen_at == FIRST
    assert row.last_seen_at == LAST
    f = state_of("ip_port_proto")
    assert (row.first_seen_at, row.last_seen_at) == (f.first_seen_at, f.last_seen_at)


def test_backfill_covers_a_resolved_finding_like_any_other(seeded):
    findings, expected, rows, shape, state_of = seeded
    _migrate_down_up()
    assert state_of("resolved").state == "resolved"
    assert shape("resolved") == [(expected["resolved"])]


def test_round_trip_is_idempotent_and_constraints_and_indexes_exist(seeded):
    findings, expected, rows, shape, state_of = seeded

    def snapshot():
        return {
            label: sorted(
                (None if r.address is None else str(r.address), r.port, r.protocol, r.first_seen_at, r.last_seen_at)
                for r in rows(label)
            )
            for label in findings
        }

    _migrate_down_up()
    once = snapshot()
    assert any(once.values()), "backfill produced nothing; the round trip proves nothing"
    _migrate_down_up()
    assert snapshot() == once

    with engine.begin() as conn:
        constraints = {
            r[0] for r in conn.execute(text(
                "SELECT conname FROM pg_constraint WHERE conrelid = 'public.finding_endpoints'::regclass"))
        }
        indexes = {
            r[0] for r in conn.execute(text(
                "SELECT indexname FROM pg_indexes WHERE tablename = 'finding_endpoints'"))
        }
    assert {
        "uq_finding_endpoints_endpoint",
        "ck_finding_endpoints_address_or_port",
        "ck_finding_endpoints_address_is_host",
        "ck_finding_endpoints_port_range",
        "ck_finding_endpoints_protocol",
        "ck_finding_endpoints_last_after_first",
    } <= constraints
    assert {"ix_finding_endpoints_address", "ix_finding_endpoints_port"} <= indexes
