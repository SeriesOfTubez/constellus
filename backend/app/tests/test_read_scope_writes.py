"""planning#261 (Jason, 2026-10-22): the single-id write routes on assets and
findings answer 404 for a row the caller cannot read, exactly as for an
unknown id. A global integration_admin holds the write permissions but not
`engagements.read_restricted`, so a pre-close asset is closed to it.

Each refusal is paired with the same route succeeding for an admin on the same
row (the path was reached), except delete and scan, where the admin side would
destroy the shared world or start a scan; there the row is checked unchanged.
The bulk routes are slice 1b.
"""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.database import SessionLocal
from app.main import app
from app.models.asset_canonical import AssetCanonical
from app.models.finding_canonical import FindingCanonical
from app.models.scan import ScanRun
from app.tests._scope_world import ScopeWorld
from app.tests.test_edgar_ingest_api import _cleanup_user, _make_user

client = TestClient(app)


@pytest.fixture(scope="module")
def w():
    world = ScopeWorld().build()
    yield world
    world.close()


@pytest.fixture(scope="module")
def tokens(w):
    admin, admin_id = _make_user("admin")
    integ, integ_id = _make_user("integration_admin")
    yield {"admin": admin, "integration_admin": integ}
    for uid in (admin_id, integ_id):
        _cleanup_user(uid)


def _scalar(stmt):
    db = SessionLocal()
    try:
        return db.execute(stmt).scalar_one()
    finally:
        db.close()


def test_ignore_a_hidden_asset_is_404_and_admin_reaches_it(w, tokens):
    url = f"/api/assets/{w.a['a1']}/ignore"
    body = {"ignored": True, "reason": "BY_DESIGN", "reason_details": "test"}
    hidden = client.patch(url, json=body, headers=tokens["integration_admin"])
    unknown = client.patch(f"/api/assets/{uuid.uuid4()}/ignore", json=body, headers=tokens["integration_admin"])
    assert hidden.status_code == 404 and hidden.json() == unknown.json()
    assert _scalar(select(AssetCanonical.ignored).where(AssetCanonical.id == w.a["a1"])) is False
    # a visible asset is still writable by the same caller, and admin reaches the hidden one
    assert client.patch(f"/api/assets/{w.a['a0']}/ignore", json={"ignored": False},
                        headers=tokens["integration_admin"]).status_code == 200
    admin = client.patch(url, json={"ignored": False}, headers=tokens["admin"])
    assert admin.status_code == 200


def test_delete_and_scan_a_hidden_asset_are_404_and_change_nothing(w, tokens):
    runs_before = _scalar(select(func.count()).select_from(ScanRun))
    assert client.delete(f"/api/assets/{w.a['a1']}", headers=tokens["integration_admin"]).status_code == 404
    assert client.post(f"/api/assets/{w.a['a1']}/scan", headers=tokens["integration_admin"]).status_code == 404
    assert _scalar(select(func.count()).select_from(AssetCanonical).where(AssetCanonical.id == w.a["a1"])) == 1
    assert _scalar(select(func.count()).select_from(ScanRun)) == runs_before


def test_triage_a_hidden_finding_is_404_and_admin_reaches_it(w, tokens):
    url = f"/api/findings/{w.f['a1']}/state"
    hidden = client.patch(url, json={"state": "acknowledged"}, headers=tokens["integration_admin"])
    assert hidden.status_code == 404 and hidden.json()["detail"] == "Finding not found"
    assert _scalar(select(FindingCanonical.state).where(FindingCanonical.id == w.f["a1"])) == "open"
    admin = client.patch(url, json={"state": "open"}, headers=tokens["admin"])
    assert admin.status_code == 200


def test_verify_a_hidden_finding_is_404(w, tokens):
    r = client.post(f"/api/findings/{w.f['a1']}/verify", headers=tokens["integration_admin"])
    assert r.status_code == 404 and r.json()["detail"] == "Finding not found"
