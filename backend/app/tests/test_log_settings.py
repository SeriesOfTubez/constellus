"""planning#335 — `log_settings.tuning` reads the admin DB log queue tuning.
Synthetic data only.

Run with:  backend/scripts/test.sh app/tests/test_log_settings.py
"""

import pytest

from app.core import logging as app_logging
from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.services import app_settings, audit, log_settings as ls

KEYS = (ls.QUEUE_MAX_KEY, ls.BATCH_MAX_KEY, ls.FLUSH_INTERVAL_S_KEY)
DEFAULTS = ls.LogQueueTuning(app_logging.DEFAULT_QUEUE_MAX, app_logging.DEFAULT_BATCH_MAX,
                             app_logging.DEFAULT_FLUSH_INTERVAL_S)
# (key, attribute, min, max)
SPECS = [
    (ls.QUEUE_MAX_KEY, "queue_max", ls.QUEUE_MAX_MIN, ls.QUEUE_MAX_MAX),
    (ls.BATCH_MAX_KEY, "batch_max", ls.BATCH_MAX_MIN, ls.BATCH_MAX_MAX),
    (ls.FLUSH_INTERVAL_S_KEY, "flush_interval_s", ls.FLUSH_INTERVAL_S_MIN, ls.FLUSH_INTERVAL_S_MAX),
]


def _wipe():
    with SessionLocal() as s:
        s.query(AppSetting).filter(AppSetting.key.in_(KEYS)).delete(synchronize_session=False)
        s.commit()


@pytest.fixture
def db():
    _wipe()
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()
        _wipe()


def _store(db, key, value):
    app_settings.set_value(db, key, value)
    db.commit()


def test_defaults_when_no_rows(db):
    assert ls.tuning(db) == DEFAULTS


def test_defaults_match_the_documented_values():
    assert (DEFAULTS.queue_max, DEFAULTS.batch_max, DEFAULTS.flush_interval_s) == (10_000, 200, 1.0)


@pytest.mark.parametrize("key,attr,lo,hi", SPECS)
def test_valid_stored_value_is_returned(db, key, attr, lo, hi):
    mid = (lo + hi) / 2
    value = mid if attr == "flush_interval_s" else int(mid)
    _store(db, key, str(value))
    got = ls.tuning(db)
    assert getattr(got, attr) == value
    assert getattr(got, attr) != getattr(DEFAULTS, attr)  # not just the default coming back
    for _, other, _, _ in SPECS:
        if other != attr:
            assert getattr(got, other) == getattr(DEFAULTS, other)


@pytest.mark.parametrize("key,attr,lo,hi", SPECS)
@pytest.mark.parametrize("which", ["below", "above", "garbage"])
def test_out_of_bounds_or_garbage_reads_as_default(db, key, attr, lo, hi, which):
    if attr == "flush_interval_s":
        bad = {"below": str(lo / 2), "above": str(hi * 2), "garbage": "abc"}[which]
    else:
        bad = {"below": str(lo - 1), "above": str(hi + 1), "garbage": "abc"}[which]
    _store(db, key, bad)
    assert app_settings.get(db, key) == bad  # the bad value really is stored
    assert getattr(ls.tuning(db), attr) == getattr(DEFAULTS, attr)


@pytest.mark.parametrize("bad", ["nan", "inf", "-inf"])
def test_non_finite_flush_interval_reads_as_default(db, bad):
    _store(db, ls.FLUSH_INTERVAL_S_KEY, bad)
    assert app_settings.get(db, ls.FLUSH_INTERVAL_S_KEY) == bad
    assert ls.tuning(db).flush_interval_s == DEFAULTS.flush_interval_s


@pytest.mark.parametrize("key,attr,lo,hi", SPECS)
@pytest.mark.parametrize("edge", ["min", "max"])
def test_boundary_values_are_accepted(db, key, attr, lo, hi, edge):
    value = lo if edge == "min" else hi
    _store(db, key, str(value))
    got = getattr(ls.tuning(db), attr)
    assert got == value
    assert got != getattr(DEFAULTS, attr)


def test_keys_are_not_treated_as_secret():
    names = list(KEYS) + ["logs_queue_max_records", "logs_batch_max_records", "logs_flush_interval_s"]
    for name in names:
        assert audit._is_secret_key(name) is False, name
    assert audit._is_secret_key("api_key") is True  # control: the predicate does fire


def test_read_tuning_reads_the_stored_values_with_its_own_session(db):
    _store(db, ls.BATCH_MAX_KEY, "37")
    _store(db, ls.FLUSH_INTERVAL_S_KEY, "2.5")
    got = app_logging._read_tuning()
    assert (got.batch_max, got.flush_interval_s) == (37, 2.5)
    assert got.queue_max == DEFAULTS.queue_max
