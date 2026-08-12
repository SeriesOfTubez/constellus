"""Regression for the finding_writer dns_record asset-misattachment bug
(planning#112).

Before this fix, _resolve_asset_canonicals keyed its result by the bare
asset_value string. A hostname with multiple dns_record rows of different
record types (A, AAAA, MX, CNAME, ...) all share that same string, so a
batch containing findings meant for two different rows of the same
hostname would silently collapse onto whichever row happened to resolve
last — a dangling_dns finding computed from an AAAA record could end up
attached to that hostname's MX record instead, where it can never be
picked up by the record-type-filtered flap-guard resolver again.

Requires a live DB connection — this is an integration test, not a pure-unit
test like the rest of app/tests/ (mirrors test_writer_concurrency.py).

Run with:  python -m app.tests.test_finding_writer_asset_disambiguation
       or: pytest app/tests/test_finding_writer_asset_disambiguation.py
"""

import uuid

from app.connectors.base import DiscoveredAsset, DiscoveredFinding
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.finding_canonical import FindingCanonical
from app.services.asset_writer import write_assets
from app.services.finding_writer import write_findings


def _cleanup(value: str) -> None:
    db = SessionLocal()
    try:
        db.query(FindingCanonical).filter(
            FindingCanonical.asset_canonical_id.in_(
                db.query(AssetCanonical.id).filter(AssetCanonical.value == value)
            )
        ).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value == value).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def test_same_hostname_different_record_types_resolve_to_distinct_assets():
    """A and MX rows sharing one hostname, each given a real DiscoveredFinding
    with asset_id explicitly set, must resolve to their OWN distinct
    finding_canonical row attached to the matching asset — not collapse
    onto one arbitrary winner."""
    suffix = uuid.uuid4().hex[:10]
    host = f"disambig-{suffix}.example.com"

    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="dns_record", value=host, parent_value=None,
                             asset_metadata={"record_type": "A", "content": "203.0.113.20"}),
            DiscoveredAsset(asset_type="dns_record", value=host, parent_value=None,
                             asset_metadata={"record_type": "MX", "content": "mail.example.com"}),
        ])
        a_row = db.query(AssetCanonical).filter(
            AssetCanonical.value == host,
            AssetCanonical.asset_metadata["record_type"].astext == "A",
        ).one()
        mx_row = db.query(AssetCanonical).filter(
            AssetCanonical.value == host,
            AssetCanonical.asset_metadata["record_type"].astext == "MX",
        ).one()

        write_findings(db, uuid.uuid4(), [
            DiscoveredFinding(
                asset_value=host, asset_id=a_row.id, finding_type="dangling_dns",
                source="constellus", severity="low", title="A-record finding",
                description="d", detail={"fingerprint": "dangling-dns"},
            ),
            DiscoveredFinding(
                asset_value=host, asset_id=mx_row.id, finding_type="dangling_dns",
                source="constellus", severity="low", title="MX-record finding",
                description="d", detail={"fingerprint": "dangling-dns"},
            ),
        ])

        rows = db.query(FindingCanonical).filter(
            FindingCanonical.asset_canonical_id.in_([a_row.id, mx_row.id])
        ).all()
        by_asset = {r.asset_canonical_id: r for r in rows}

        assert len(rows) == 2, f"expected 2 distinct finding rows, got {len(rows)}"
        assert by_asset[a_row.id].title == "A-record finding"
        assert by_asset[mx_row.id].title == "MX-record finding"
    finally:
        db.close()
        _cleanup(host)


def _run():
    tests = [test_same_hostname_different_record_types_resolve_to_distinct_assets]
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
