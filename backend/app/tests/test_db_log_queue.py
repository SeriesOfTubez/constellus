"""planning#328 — DBLogHandler queues, a single writer thread batches to the DB.

Isolated `DBLogHandler` / `_DBLogWriter` instances are used throughout (the
module singletons belong to the app); only the round-trip test touches the
real DB, and it cleans up the rows it wrote. Synthetic data only.
"""

import asyncio
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from app.core import logging as app_logging
from app.services import log_settings


def _rec(name="app.x", msg="m", level=logging.INFO):
    return logging.LogRecord(name, level, __file__, 1, msg, None, None)


@pytest.fixture(autouse=True)
def tuning_stub(monkeypatch):
    """No test opens a DB session through `_read_tuning` implicitly. The
    returned dict is what the stub reports; a test may change it."""
    state = {"queue_max": app_logging.DEFAULT_QUEUE_MAX,
             "batch_max": app_logging.DEFAULT_BATCH_MAX,
             "flush_interval_s": app_logging.DEFAULT_FLUSH_INTERVAL_S}
    monkeypatch.setattr(app_logging, "_read_tuning",
                        lambda: log_settings.LogQueueTuning(**state))
    return state


def _handler(monkeypatch, qmax=10_000):
    monkeypatch.setattr(app_logging, "DEFAULT_QUEUE_MAX", qmax)
    h = app_logging.DBLogHandler()
    h.setFormatter(logging.Formatter("%(message)s"))
    return h


def _drain(h):
    out = []
    while not h.queue.empty():
        out.append(h.queue.get_nowait())
    return out


# 1
def test_emit_never_touches_the_pool(monkeypatch):
    import app.core.database as database

    calls = []

    def boom(*a, **k):
        calls.append(1)
        raise AssertionError("emit opened a session")

    monkeypatch.setattr(database, "SessionLocal", boom)
    h = _handler(monkeypatch)
    h.enable()
    h.emit(_rec("app.connectors.shodan", "hello-328"))
    assert h.queue.qsize() == 1  # reached
    row = h.queue.get_nowait()
    assert row["level"] == "INFO"
    assert row["source"] == "shodan"
    assert row["logger_name"] == "app.connectors.shodan"
    assert row["message"] == "hello-328"
    assert row["created_at"].utcoffset() == timedelta(0)
    assert calls == []


# 2
def test_disabled_handler_enqueues_nothing(monkeypatch):
    h = _handler(monkeypatch)
    h.emit(_rec())
    assert h.queue.qsize() == 0
    h.enable()  # control: same record is queued once enabled
    h.emit(_rec())
    assert h.queue.qsize() == 1


def test_skip_filtered_record_never_reaches_the_queue(monkeypatch):
    h = _handler(monkeypatch)
    h.enable()
    h.handle(_rec("httpx", "GET https://x.test/?key=SECRET328"))
    h.handle(_rec("httpcore.http11", "send"))
    assert h.queue.qsize() == 0
    h.handle(_rec("app.x", "kept"))  # control: path reached, passes filter
    rows = _drain(h)
    assert [r["message"] for r in rows] == ["kept"]


# 3
def test_full_queue_drops_newest_and_reports_once(monkeypatch, capsys):
    h = _handler(monkeypatch, qmax=3)
    h.enable()
    for i in range(5):
        h.emit(_rec(msg=f"m{i}"))
    assert [r["message"] for r in _drain(h)] == ["m0", "m1", "m2"]
    w = app_logging._DBLogWriter(h)
    capsys.readouterr()
    w.report_dropped()
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "dropped 2 records" in err
    w.report_dropped()
    assert capsys.readouterr().err == ""
    assert h.take_dropped() == 0


def test_take_dropped_returns_then_resets(monkeypatch):
    h = _handler(monkeypatch, qmax=3)
    h.enable()
    for i in range(5):
        h.emit(_rec(msg=f"m{i}"))
    assert h.take_dropped() == 2
    assert h.take_dropped() == 0


# 4
def test_emit_does_not_block_on_a_full_queue(monkeypatch):
    h = _handler(monkeypatch, qmax=2)
    h.enable()
    h.emit(_rec())
    h.emit(_rec())
    assert h.queue.full()  # reached
    # On a thread, so a regression to a blocking put fails here instead of
    # hanging the suite.
    t = threading.Thread(target=lambda: [h.emit(_rec()) for _ in range(1000)],
                         daemon=True)
    t.start()
    t.join(1.0)
    assert not t.is_alive()
    assert h.take_dropped() == 1000


# 5
def test_next_batch_respects_batch_max(monkeypatch):
    h = _handler(monkeypatch)
    h.enable()
    for i in range(7):
        h.emit(_rec(msg=f"m{i}"))
    w = app_logging._DBLogWriter(h)
    w.batch_max = 3
    sizes = [len(w.next_batch(0.05)) for _ in range(3)]
    assert sizes == [3, 3, 1]


def test_next_batch_waits_then_returns_empty(monkeypatch):
    h = _handler(monkeypatch)
    w = app_logging._DBLogWriter(h)
    t0 = time.monotonic()
    assert w.next_batch(0.05) == []
    assert time.monotonic() - t0 >= 0.04


def test_next_batch_does_not_wait_once_stopping(monkeypatch):
    h = _handler(monkeypatch)
    h.enable()
    h.emit(_rec(msg="queued"))
    w = app_logging._DBLogWriter(h)
    w._stopping.set()
    t0 = time.monotonic()
    assert [r["message"] for r in w.next_batch(5.0)] == ["queued"]  # reached
    assert w.next_batch(5.0) == []
    assert time.monotonic() - t0 < 1.0


def test_stop_does_not_wait_out_the_flush_interval(monkeypatch, tuning_stub):
    tuning_stub["flush_interval_s"] = 5.0
    h = _handler(monkeypatch)
    w = app_logging._DBLogWriter(h)
    written = []
    monkeypatch.setattr(w, "_insert", lambda batch: written.extend(batch))
    h.enable()
    w.start()
    time.sleep(0.1)  # writer is parked in its 5s wait
    h.emit(_rec(msg="last"))
    t0 = time.monotonic()
    w.stop()
    assert time.monotonic() - t0 < 2.0
    assert [r["message"] for r in written] == ["last"]


# 6, 7
def test_write_retries_once_and_succeeds(monkeypatch, capsys):
    w = app_logging._DBLogWriter(_handler(monkeypatch))
    calls = []

    def flaky(batch):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("transient")

    monkeypatch.setattr(w, "_insert", flaky)
    capsys.readouterr()
    assert w.write([{"x": 1}]) is True
    assert len(calls) == 2
    assert capsys.readouterr().err == ""


def test_write_failing_twice_drops_without_leaking_exception_text(monkeypatch, capsys):
    w = app_logging._DBLogWriter(_handler(monkeypatch))
    calls = []

    def always(batch):
        calls.append(1)
        raise RuntimeError("SECRET-MARKER-328 bound params")

    monkeypatch.setattr(w, "_insert", always)
    capsys.readouterr()
    assert w.write([{"x": 1}, {"x": 2}]) is False
    assert len(calls) == 2
    err = capsys.readouterr().err
    assert "dropped 2 records" in err
    assert "RuntimeError" in err
    assert "SECRET-MARKER-328" not in err


# 8
def test_insert_round_trip_is_one_commit(monkeypatch):
    from sqlalchemy.orm import Session

    from app.core.database import SessionLocal
    from app.models.system_log import SystemLog

    name = "app.test_db_log_queue.roundtrip328"
    h = _handler(monkeypatch)
    h.enable()
    for i in range(3):
        h.emit(_rec(name, f"row-{i}"))
    batch = _drain(h)
    assert len(batch) == 3

    commits = []
    real_commit = Session.commit

    def spy(self):
        commits.append(1)
        return real_commit(self)

    monkeypatch.setattr(Session, "commit", spy)
    w = app_logging._DBLogWriter(h)
    try:
        w._insert(batch)
        monkeypatch.setattr(Session, "commit", real_commit)
        assert len(commits) == 1
        db = SessionLocal()
        try:
            rows = db.query(SystemLog).filter(SystemLog.logger_name == name).all()
            assert sorted(r.message for r in rows) == ["row-0", "row-1", "row-2"]
            assert all(r.source == "system" and r.level == "INFO" for r in rows)
        finally:
            db.close()
    finally:
        monkeypatch.setattr(Session, "commit", real_commit)
        db = SessionLocal()
        try:
            db.query(SystemLog).filter(SystemLog.logger_name == name).delete()
            db.commit()
        finally:
            db.close()


def test_insert_rolls_back_and_closes_on_failure(monkeypatch):
    import app.core.database as database

    sess = MagicMock()
    sess.commit.side_effect = RuntimeError("commit failed")
    monkeypatch.setattr(database, "SessionLocal", lambda: sess)
    w = app_logging._DBLogWriter(_handler(monkeypatch))
    row = {"created_at": datetime.now(timezone.utc),
           "level": "INFO", "source": "system", "logger_name": "app.x", "message": "m"}
    with pytest.raises(RuntimeError):
        w._insert([row])
    assert sess.commit.call_count == 1  # reached
    sess.rollback.assert_called_once()
    sess.close.assert_called_once()


# 9
def test_stop_flushes_queue_and_ends_thread(monkeypatch):
    h = _handler(monkeypatch)
    w = app_logging._DBLogWriter(h)
    written = []
    monkeypatch.setattr(w, "_insert", lambda batch: written.extend(batch))
    h.enable()
    w.start()
    for i in range(5):
        h.emit(_rec(msg=f"m{i}"))
    w.stop()
    assert sorted(r["message"] for r in written) == [f"m{i}" for i in range(5)]
    assert w._thread is None
    assert not [t for t in threading.enumerate() if t.name == "db-log-writer" and t.is_alive()
                and t is not threading.current_thread() and getattr(t, "_target", None) == w._run]
    assert h._enabled is False
    h.emit(_rec())
    assert h.queue.qsize() == 0


def test_stop_returns_within_timeout_when_the_writer_is_stuck(monkeypatch, capsys):
    h = _handler(monkeypatch)
    w = app_logging._DBLogWriter(h)
    entered, release = threading.Event(), threading.Event()

    def stuck(batch):
        entered.set()
        release.wait(10)

    monkeypatch.setattr(w, "_insert", stuck)
    h.enable()
    w.start()
    h.emit(_rec())
    assert entered.wait(5)  # the writer really is blocked in _insert
    thread = w._thread
    capsys.readouterr()
    try:
        t0 = time.monotonic()
        w.stop(timeout=0.2)
        assert time.monotonic() - t0 < 2.0
        assert "still busy" in capsys.readouterr().err
        assert thread.is_alive()
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive()


# 10
def test_writer_loop_survives_an_exception_and_keeps_writing(monkeypatch, capsys, tuning_stub):
    tuning_stub["flush_interval_s"] = 0.05
    h = _handler(monkeypatch)
    w = app_logging._DBLogWriter(h)
    written = []
    monkeypatch.setattr(w, "_insert", lambda batch: written.extend(batch))
    real = w.report_dropped
    state = {"raised": 0}

    def flaky():
        if not state["raised"]:
            state["raised"] = 1
            raise ValueError("report-boom")
        real()

    monkeypatch.setattr(w, "report_dropped", flaky)
    h.enable()
    capsys.readouterr()
    w.start()
    try:
        deadline = time.monotonic() + 5
        while not state["raised"] and time.monotonic() < deadline:
            time.sleep(0.01)
        assert state["raised"]  # the failure path was reached
        h.emit(_rec(msg="after-failure"))
        while not written and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        w.stop()
    assert [r["message"] for r in written] == ["after-failure"]
    err = capsys.readouterr().err
    assert "writer error (ValueError); continuing" in err
    assert "report-boom" not in err


# 11
def test_lifespan_stops_db_logging_after_the_scheduler(monkeypatch):
    from app import main
    from app.core import config
    from app.services import connector_instances, scheduler

    order = []
    root = logging.getLogger()
    saved = (list(root.handlers), root.level, app_logging._stderr_handler)
    app_logging._stderr_handler = None
    monkeypatch.setattr(config.settings, "debug", True)

    def fake_get_db():
        yield MagicMock()

    monkeypatch.setattr(main, "get_db", fake_get_db)
    monkeypatch.setattr(connector_instances, "seed_from_env", lambda *a, **k: None)
    monkeypatch.setattr(app_logging, "setup_db_logging", lambda: order.append("setup"))
    monkeypatch.setattr(scheduler, "start", lambda: order.append("sched_start"))
    monkeypatch.setattr(scheduler, "shutdown", lambda: order.append("sched_shutdown"))
    monkeypatch.setattr(app_logging, "stop_db_logging", lambda: order.append("stop_db"))

    async def run():
        async with main.lifespan(main.app):
            order.append("serving")

    try:
        asyncio.run(run())
    finally:
        for hd in list(root.handlers):
            root.removeHandler(hd)
        for hd in saved[0]:
            root.addHandler(hd)
        root.setLevel(saved[1])
        app_logging._stderr_handler = saved[2]
    assert order == ["setup", "sched_start", "serving", "sched_shutdown", "stop_db"]


# 12
@pytest.mark.parametrize("name,expected", [
    ("app.connectors.shodan", "shodan"),
    ("app.services.discovery.cert_transparency", "cert_transparency"),
    ("app.services.scan_executor", "scan_executor"),
    ("app.services.target_service", "target_service"),
    ("app.main", "system"),
])
def test_extract_source_unchanged(name, expected):
    assert app_logging._extract_source(name) == expected


# planning#335 — tuning re-read, resize, startup sizing
def _spy_tuning(monkeypatch, tuning_stub, fail=None):
    """Replace `_read_tuning` with a counting spy; `fail` is an exception to raise."""
    calls = []
    box = {"fail": fail}

    def spy():
        calls.append(1)
        if box["fail"] is not None:
            raise box["fail"]
        return log_settings.LogQueueTuning(**tuning_stub)

    monkeypatch.setattr(app_logging, "_read_tuning", spy)
    return calls, box


def test_refresh_tuning_applies_new_batch_and_flush(monkeypatch, tuning_stub):
    calls, _ = _spy_tuning(monkeypatch, tuning_stub)
    tuning_stub.update(batch_max=2, flush_interval_s=0.3)
    h = _handler(monkeypatch)
    h.enable()
    for i in range(5):
        h.emit(_rec(msg=f"m{i}"))
    w = app_logging._DBLogWriter(h)
    assert (w.batch_max, w.flush_interval_s) == (200, 1.0)
    w.refresh_tuning()
    assert len(calls) == 1  # reached
    assert (w.batch_max, w.flush_interval_s) == (2, 0.3)
    assert [len(w.next_batch(0.05)) for _ in range(3)] == [2, 2, 1]


def test_refresh_tuning_rereads_at_most_every_interval(monkeypatch, tuning_stub):
    calls, _ = _spy_tuning(monkeypatch, tuning_stub)
    w = app_logging._DBLogWriter(_handler(monkeypatch))
    w.refresh_tuning()
    w.refresh_tuning()
    assert len(calls) == 1
    w._next_reread = 0.0
    w.refresh_tuning()
    assert len(calls) == 2


def test_refresh_tuning_failure_keeps_values_and_tells_stderr_once(monkeypatch, tuning_stub, capsys):
    calls, box = _spy_tuning(monkeypatch, tuning_stub, fail=ConnectionError("SECRET-MARKER-335 dsn"))
    w = app_logging._DBLogWriter(_handler(monkeypatch))
    w.batch_max, w.flush_interval_s = 77, 0.7
    seen = []

    class Capture(logging.Handler):
        def emit(self, record):
            seen.append(record)

    root = logging.getLogger()
    cap = Capture(level=logging.NOTSET)
    root.addHandler(cap)
    capsys.readouterr()
    try:
        w.refresh_tuning()
        w._next_reread = 0.0
        w.refresh_tuning()
        assert len(calls) == 2  # the failure path ran twice
        err = capsys.readouterr().err
        assert err.count("settings unreadable") == 1
        assert err.count("\n") == 1
        assert "ConnectionError" in err
        assert "SECRET-MARKER-335" not in err
        assert (w.batch_max, w.flush_interval_s) == (77, 0.7)
        assert seen == []  # nothing went through logging

        box["fail"] = None
        tuning_stub.update(batch_max=33, flush_interval_s=0.4)
        w._next_reread = 0.0
        w.refresh_tuning()
        assert len(calls) == 3
        err = capsys.readouterr().err
        assert err.count("settings readable again") == 1 and err.count("\n") == 1
        assert (w.batch_max, w.flush_interval_s) == (33, 0.4)
        assert seen == []
    finally:
        root.removeHandler(cap)


def test_run_does_not_refresh_tuning_once_stopping(monkeypatch, tuning_stub):
    calls, _ = _spy_tuning(monkeypatch, tuning_stub)
    h = _handler(monkeypatch)
    w = app_logging._DBLogWriter(h)
    written = []
    monkeypatch.setattr(w, "_insert", lambda batch: written.extend(batch))
    h.enable()
    h.emit(_rec(msg="queued"))
    w._stopping.set()
    t = threading.Thread(target=w._run, daemon=True)
    t.start()
    t.join(5)
    assert not t.is_alive()
    assert [r["message"] for r in written] == ["queued"]  # the loop really ran
    assert calls == []


def test_resize_on_disabled_empty_handler(monkeypatch):
    h = _handler(monkeypatch)
    assert h.resize(2_000) is True
    assert h.queue.maxsize == 2_000


def test_resize_refused_when_enabled(monkeypatch):
    h = _handler(monkeypatch)
    h.enable()
    q = h.queue
    assert h.resize(2_000) is False
    assert h.queue is q and q.maxsize == 10_000


def test_resize_refused_when_queue_has_a_record(monkeypatch):
    h = _handler(monkeypatch)
    h.enable()
    h.emit(_rec(msg="keep"))
    h.disable()
    q = h.queue
    assert h.resize(2_000) is False
    assert h.queue is q and q.maxsize == 10_000
    assert [r["message"] for r in _drain(h)] == ["keep"]


def test_size_queue_applies_the_stored_bound(monkeypatch, tuning_stub):
    calls, _ = _spy_tuning(monkeypatch, tuning_stub)
    tuning_stub["queue_max"] = 2_000
    h = _handler(monkeypatch)
    monkeypatch.setattr(app_logging, "db_handler", h)
    app_logging._size_queue()
    assert len(calls) == 1
    assert h.queue.maxsize == 2_000


def test_size_queue_falls_back_to_default_when_unreadable(monkeypatch, tuning_stub, capsys):
    calls, _ = _spy_tuning(monkeypatch, tuning_stub, fail=ConnectionError("SECRET-MARKER-335 dsn"))
    h = _handler(monkeypatch)
    h.resize(5_000)  # make a fallback distinguishable from "untouched"
    monkeypatch.setattr(app_logging, "db_handler", h)
    capsys.readouterr()
    app_logging._size_queue()
    assert len(calls) == 1
    assert h.queue.maxsize == app_logging.DEFAULT_QUEUE_MAX
    err = capsys.readouterr().err
    assert err.count("\n") == 1
    assert "ConnectionError" in err and "SECRET-MARKER-335" not in err


def test_setup_sizes_the_queue_before_the_writer_starts(monkeypatch, tuning_stub):
    tuning_stub["queue_max"] = 2_000
    h = _handler(monkeypatch)
    seen = []
    writer = MagicMock()
    writer.start.side_effect = lambda: seen.append((h.queue.maxsize, h._enabled))
    monkeypatch.setattr(app_logging, "db_handler", h)
    monkeypatch.setattr(app_logging, "db_writer", writer)
    root = logging.getLogger()
    try:
        app_logging.setup_db_logging()
    finally:
        root.removeHandler(h)
        h.disable()
    assert seen == [(2_000, False)]
