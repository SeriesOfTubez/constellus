"""planning#224 item 5 — no model id in application code; a fresh install
with no saved role bindings reports "AI models not configured".

`app_settings.DEFAULTS` carries no `llm.role_bindings`, so until an admin
saves bindings `load_bindings` raises `ModelsNotConfigured` (an
`LLMConfigError`), the call path refuses before any request or ledger row,
and `models_configured` is False. The suite seeds bindings for the session
(`conftest.py`, from `llm_fixtures.py`); these tests delete that row and
put it back.

Run with:  backend/scripts/test.ps1 app/tests/test_llm_models_unconfigured.py
"""

import re
import uuid
from pathlib import Path

import httpx
import pytest

from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.llm_call import LlmCall
from app.services import app_settings, connector_instances as connector_instances_svc
from app.tests import connector_helpers as ch
from app.services import llm_connector as llmc
from app.tests.llm_fixtures import TEST_ROLE_BINDINGS

_KEY = "llm.role_bindings"
_TEST_API_KEY = "sk-or-test-224"
_APP_DIR = Path(__file__).resolve().parents[1]  # backend/app


class _Unbound:
    """Delete the stored bindings for the duration; restore after."""

    def __init__(self, db):
        self.db = db
        self.saved = None

    def __enter__(self):
        row = self.db.get(AppSetting, _KEY)
        assert row is not None, "precondition: the session fixture seeded bindings"
        self.saved = row.value
        self.db.delete(row)
        self.db.commit()
        return self

    def __exit__(self, *exc):
        self.db.rollback()
        if self.db.get(AppSetting, _KEY) is None:
            self.db.add(AppSetting(key=_KEY, value=self.saved))
            self.db.commit()
        return False


def _configure_openrouter(db):
    # Connector fully configured, so a refusal below is provably the
    # bindings' doing, not the connector's.
    existing = connector_instances_svc.single(db, "openrouter")
    snapshot = None if existing is None else (existing.enabled, existing.config_encrypted)
    ch.set_config(db, "openrouter", {"api_key": _TEST_API_KEY})
    ch.set_enabled(db, "openrouter", True)
    assert llmc.is_configured(db)
    return snapshot


def _restore_openrouter(snapshot):
    from app.models.connector_instance import ConnectorInstance
    db = SessionLocal()
    try:
        if snapshot is None:
            db.query(ConnectorInstance).filter(ConnectorInstance.type == "openrouter").delete()
        else:
            row = connector_instances_svc.single(db, "openrouter")
            row.enabled, row.config_encrypted = snapshot
        db.commit()
    finally:
        db.close()


def test_defaults_carry_no_role_bindings():
    assert _KEY not in app_settings.DEFAULTS


def test_no_model_id_in_application_code():
    """The acceptance criterion, literally: none of the model ids the old
    code default named appears in any non-test module under app/."""
    ids = {m for binding in TEST_ROLE_BINDINGS.values() for m in binding["models"]}
    offenders = []
    scanned = 0
    for path in _APP_DIR.rglob("*.py"):
        if "tests" in path.relative_to(_APP_DIR).parts:
            continue
        scanned += 1
        text = path.read_text(encoding="utf-8")
        offenders += [f"{path.relative_to(_APP_DIR)}: {m}" for m in ids if m in text]
    assert scanned > 50  # the walk really covered the app package
    assert offenders == []


def test_unconfigured_bindings_refuse_before_any_request():
    task = f"llm224-unbound-{uuid.uuid4().hex[:8]}"
    db = SessionLocal()
    snap_or = _configure_openrouter(db)
    requests: list[httpx.Request] = []
    llmc._transport = httpx.MockTransport(lambda r: requests.append(r) or httpx.Response(500))
    try:
        assert llmc.models_configured(db) is True  # positive twin first
        with _Unbound(db):
            assert llmc.models_configured(db) is False
            with pytest.raises(llmc.ModelsNotConfigured) as exc:
                llmc.load_bindings(db)
            assert isinstance(exc.value, llmc.LLMConfigError)
            assert "AI models not configured" in str(exc.value)

            with pytest.raises(llmc.ModelsNotConfigured):
                llmc.complete(
                    db, role=llmc.Role.CLASSIFY, messages=[{"role": "user", "content": "hi"}],
                    target_id=None, engagement_id=None, task=task,
                )
            assert requests == []
            assert db.query(LlmCall).filter(LlmCall.task == task).count() == 0
        assert llmc.models_configured(db) is True
    finally:
        llmc._transport = None
        _restore_openrouter(snap_or)
        db.query(LlmCall).filter(LlmCall.task == task).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_a_stored_but_corrupt_value_is_configured_and_still_errors_loudly():
    """Corrupt is not "never configured": it must surface what is wrong,
    not be reported as a fresh install."""
    db = SessionLocal()
    try:
        with _Unbound(db):
            for raw in ("not json{{", "[1, 2]", '{"classify": {}}'):
                app_settings.set_value(db, _KEY, raw)
                assert llmc.models_configured(db) is True
                with pytest.raises(llmc.LLMConfigError) as exc:
                    llmc.load_bindings(db)
                assert not isinstance(exc.value, llmc.ModelsNotConfigured)
            db.delete(db.get(AppSetting, _KEY))
            db.commit()
    finally:
        db.close()


def test_the_message_names_where_to_fix_it():
    with pytest.raises(llmc.ModelsNotConfigured, match=re.escape("Admin -> AI models")):
        db = SessionLocal()
        try:
            with _Unbound(db):
                llmc.load_bindings(db)
        finally:
            db.close()
