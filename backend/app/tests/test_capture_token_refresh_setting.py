"""The capture token refresh threshold setting (planning#332): `_refresh_below_s` against the
real app_settings table, and its fail-soft fallback.

Run with:  backend/scripts/test.sh app/tests/test_capture_token_refresh_setting.py
"""

import logging

import pytest

from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.services import app_settings
from app.services import capture_token_secret as ts
from app.services import page_capture as pc

SENTINEL = "SECRET-SENTINEL"


@pytest.fixture
def setting():
    with SessionLocal() as db:
        row = db.get(AppSetting, pc.STORE_ACCESS_REFRESH_BELOW_KEY)
        before = row.value if row else None

    def put(value):
        with SessionLocal() as s:
            app_settings.set_value(s, pc.STORE_ACCESS_REFRESH_BELOW_KEY, str(value))
            s.commit()

    yield put
    with SessionLocal() as s:
        row = s.get(AppSetting, pc.STORE_ACCESS_REFRESH_BELOW_KEY)
        if before is None and row is not None:
            s.delete(row)
        elif before is not None:
            app_settings.set_value(s, pc.STORE_ACCESS_REFRESH_BELOW_KEY, before)
        s.commit()


@pytest.fixture(autouse=True)
def reset_flag(monkeypatch):
    monkeypatch.setattr(ts, "_fallback_active", False)


def test_stored_value_in_range_is_used(setting):
    setting(2400)
    assert ts._refresh_below_s() == 2400


@pytest.mark.parametrize("bad", [500, 659, 3001, 3600])
def test_out_of_range_row_is_the_default(setting, bad):
    setting(bad)
    assert ts._refresh_below_s() == 1800


def test_bounds_inclusive(setting):
    setting(660)
    assert ts._refresh_below_s() == 660
    setting(3000)
    assert ts._refresh_below_s() == 3000


def test_failure_falls_back_warns_once_and_logs_recovery_once(setting, monkeypatch, caplog):
    setting(2400)
    caplog.set_level(logging.INFO, logger=ts.log.name)

    def boom():
        raise RuntimeError(SENTINEL)

    import app.core.database as database
    real = database.SessionLocal
    monkeypatch.setattr(database, "SessionLocal", boom)
    assert ts._refresh_below_s() == 1800
    assert ts._refresh_below_s() == 1800
    warns = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warns) == 1 and "RuntimeError" in warns[0].getMessage() and "1800" in warns[0].getMessage()
    assert SENTINEL not in caplog.text
    monkeypatch.setattr(database, "SessionLocal", real)
    assert ts._refresh_below_s() == 2400  # the stored value, not the default: the read really happened
    assert ts._refresh_below_s() == 2400
    infos = [r for r in caplog.records if r.levelno == logging.INFO and "readable again" in r.getMessage()]
    assert len(infos) == 1
    assert SENTINEL not in caplog.text
