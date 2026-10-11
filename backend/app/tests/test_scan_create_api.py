"""POST /api/scans/ creates the one-shot template and its run together.

Regression: the template's INSERT was not flushed before the run that
references it, so the commit failed on fk_scan_runs_template_id (found
2026-10-10 while scanning the lab target for planning#231)."""

import uuid

from fastapi.testclient import TestClient

from app.api import scans as scans_api
from app.core.database import SessionLocal
from app.main import app
from app.models.scan import ScanRun
from app.models.scan_template import ScanTemplate
from app.models.user import UserRole
from app.tests.test_edgar_ingest_api import _cleanup_user, _make_user

client = TestClient(app)


def test_create_scan_inserts_the_template_before_its_run(monkeypatch):
    launched = []
    monkeypatch.setattr(scans_api.scan_executor, "launch", lambda run_id, *a, **k: launched.append(run_id))
    headers, uid = _make_user(UserRole.ADMIN.value)
    run_id = None
    try:
        r = client.post("/api/scans/", headers=headers, json={
            "name": "scan-create regression", "scope": {"domains": ["scan-create.fabrikam.example"], "ip_ranges": []},
        })
        assert r.status_code == 201, r.text
        run_id = uuid.UUID(r.json()["id"])
        db = SessionLocal()
        try:
            run = db.get(ScanRun, run_id)
            assert run is not None and run.template_id is not None
            assert db.get(ScanTemplate, run.template_id) is not None
        finally:
            db.close()
        assert launched == [run_id]  # the background launch was reached
    finally:
        db = SessionLocal()
        try:
            if run_id is not None:
                run = db.get(ScanRun, run_id)
                tmpl_id = run.template_id if run else None
                if run:
                    db.delete(run)
                    db.flush()
                if tmpl_id:
                    db.query(ScanTemplate).filter(ScanTemplate.id == tmpl_id).delete(synchronize_session=False)
                db.commit()
        finally:
            db.close()
        _cleanup_user(uid)
