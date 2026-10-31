"""planning#326 — application logs reach container stderr.

`DBLogHandler` used to be the only root handler, so `docker compose logs` /
`kubectl logs` showed uvicorn only. These pin the stderr handler, its level,
and the shared skip-list filter that keeps httpx request URLs (Shodan's
`?key=`) out of BOTH handlers.
"""

import asyncio
import io
import logging
import re

import pytest
from pydantic import ValidationError

from app.core import logging as app_logging
from app.core.config import Settings


@pytest.fixture
def root_logging():
    """Save and restore the root logger and the module's stderr handler."""
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    saved_stderr = app_logging._stderr_handler
    app_logging._stderr_handler = None
    for h in saved_handlers:
        root.removeHandler(h)
    root.setLevel(logging.NOTSET)
    yield root
    for h in list(root.handlers):
        root.removeHandler(h)
    for h in saved_handlers:
        root.addHandler(h)
    root.setLevel(saved_level)
    app_logging._stderr_handler = saved_stderr


def _capture(level: str) -> io.StringIO:
    app_logging.setup_stderr_logging(level)
    buf = io.StringIO()
    app_logging._stderr_handler.setStream(buf)
    return buf


def test_app_record_reaches_stderr_with_utc_timestamp(root_logging):
    buf = _capture("INFO")
    logging.getLogger("app.services.page_capture").info("wrote proxy limits")
    line = buf.getvalue().strip()
    assert re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ INFO app\.services\.page_capture: wrote proxy limits",
        line,
    ), line


def test_timestamp_is_utc_even_when_local_time_is_not(root_logging, monkeypatch):
    import time

    monkeypatch.setenv("TZ", "Pacific/Auckland")
    time.tzset()
    try:
        app_logging.setup_stderr_logging("INFO")
        rec = logging.LogRecord("app.t", logging.INFO, __file__, 1, "m", None, None)
        rec.created = 0.0
        out = app_logging._stderr_handler.format(rec)
    finally:
        monkeypatch.undo()
        time.tzset()
    assert out == "1970-01-01T00:00:00Z INFO app.t: m"


def test_traceback_reaches_stderr(root_logging):
    buf = _capture("INFO")
    try:
        raise ValueError("boom-326")
    except ValueError:
        logging.getLogger("app.main").exception("startup step failed")
    out = buf.getvalue()
    assert "ERROR app.main: startup step failed" in out
    assert "Traceback (most recent call last)" in out
    assert "ValueError: boom-326" in out


def test_httpx_request_url_never_reaches_stderr(root_logging):
    buf = _capture("DEBUG")
    logging.getLogger("httpx").info(
        'HTTP Request: GET https://api.example.test/dns?key=SECRET326 "HTTP/1.1 200 OK"'
    )
    logging.getLogger("httpcore.http11").debug("send_request key=SECRET326")
    logging.getLogger("app.connectors.shodan").info("shodan lookup done")
    out = buf.getvalue()
    # Reached: the same handler wrote the app line in the same run.
    assert "shodan lookup done" in out
    assert "SECRET326" not in out


@pytest.mark.parametrize("name", ["sqlalchemy.engine", "uvicorn.error", "alembic.runtime"])
def test_other_skip_prefixes_filtered_from_stderr(root_logging, name):
    buf = _capture("DEBUG")
    logging.getLogger(name).warning("library-noise-326")
    logging.getLogger("app.x").warning("app-line-326")
    out = buf.getvalue()
    assert "app-line-326" in out
    assert "library-noise-326" not in out


def test_db_handler_uses_the_same_skip_filter():
    def rec(name):
        return logging.LogRecord(name, logging.INFO, __file__, 1, "m", None, None)

    assert app_logging.db_handler.filter(rec("app.connectors.shodan"))
    assert not app_logging.db_handler.filter(rec("httpx"))
    assert not app_logging.db_handler.filter(rec("httpcore.connection"))


def test_warning_level_drops_info_but_root_stays_info_for_the_db(root_logging):
    buf = _capture("WARNING")
    log = logging.getLogger("app.y")
    log.info("info-326")
    log.warning("warn-326")
    out = buf.getvalue()
    assert "warn-326" in out
    assert "info-326" not in out
    app_logging.setup_db_logging()
    assert root_logging.level == logging.INFO


def test_debug_level_lowers_root(root_logging):
    buf = _capture("DEBUG")
    assert root_logging.level == logging.DEBUG
    logging.getLogger("app.z").debug("debug-326")
    assert "DEBUG app.z: debug-326" in buf.getvalue()


def test_setup_is_idempotent_and_relevels(root_logging):
    app_logging.setup_stderr_logging("INFO")
    first = app_logging._stderr_handler
    app_logging.setup_stderr_logging("ERROR")
    assert app_logging._stderr_handler is first
    assert root_logging.handlers.count(first) == 1
    assert first.level == logging.ERROR


def test_log_level_setting_is_case_insensitive_and_validated(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "warning")
    assert Settings().log_level == "WARNING"
    monkeypatch.setenv("LOG_LEVEL", "verbose")
    with pytest.raises(ValidationError):
        Settings()
    monkeypatch.delenv("LOG_LEVEL")
    assert Settings().log_level == "INFO"


def test_lifespan_installs_stderr_before_the_secret_key_refusal(root_logging, monkeypatch):
    from app import main
    from app.core import config

    monkeypatch.setattr(config.settings, "debug", False)
    monkeypatch.setattr(config.settings, "secret_key", config.DEFAULT_SECRET_KEY)

    async def run():
        async with main.lifespan(main.app):
            pass

    with pytest.raises(RuntimeError, match="secret_key"):
        asyncio.run(run())
    assert app_logging._stderr_handler in root_logging.handlers
