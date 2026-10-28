"""Page capture: the backend half of the spool (planning#280 S5b-2a).

Asks the capture browser for one page load of a scope candidate's domain
(`request_capture`) and takes the results back (`ingest_results`,
`sweep_timeouts`, driven by `tick`). The contract, including every
untrusted-input rule implemented below, is `docs/architecture/capture-spool.md`.

**Everything under the spool is untrusted input**: the browser that wrote it
rendered an arbitrary page. Every read here is `lstat`-checked, size-capped,
JSON-only, and the screenshot is never decoded. `pinned_ip` comes from the
proxy log only (the browser never mounts that volume), never from result.json.

A capture row is evidence a person reads, never an authorisation.
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import shutil
import stat
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.org_entity import OrgEntity
from app.models.page_capture import USER_AGENT_MODES, PageCapture, PageCaptureRequest
from app.models.scope_candidate import ScopeCandidate
from app.models.user import User
from app.services import app_settings, wayback
from app.services.probe_authorisation import authorise_candidate_browse

log = logging.getLogger(__name__)

# ── limits ───────────────────────────────────────────────────────────────────
# SETTINGS (admin-configurable, planning#280 S5b-2b; read through the typed
# accessors below, which clamp a stored value back to its default when it is
# out of bounds): browse revisit days, archive freshness days, user-agent mode, identifying
# user-agent, max image bytes, queue timeout.
# GUARDS (constants, never settings): IMAGE_BYTES_CEILING and the *_MIN/_MAX
# bounds, USER_AGENT_MAX, VIEWPORT_*, WEBP_QUALITIES, TICK_INTERVAL_SECONDS and
# the JOB/RESULT/PROXYLOG byte caps.
REVISIT_DAYS_KEY = "capture.browse_revisit_days"
ARCHIVE_FRESHNESS_DAYS_KEY = "capture.archive_freshness_days"
USER_AGENT_MODE_KEY = "capture.user_agent_mode"
IDENTIFYING_UA_KEY = "capture.identifying_user_agent"
MAX_IMAGE_BYTES_KEY = "capture.max_image_bytes"
QUEUE_TIMEOUT_KEY = "capture.queue_timeout_seconds"
IMAGE_KEEP_COUNT_KEY = "capture.image_keep_count"
PROXY_CONNECT_TIMEOUT_KEY = "capture.proxy_connect_timeout_seconds"
PROXY_IDLE_TIMEOUT_KEY = "capture.proxy_idle_timeout_seconds"
PROXY_MAX_CONNECTIONS_KEY = "capture.proxy_max_connections"

# Job contract v3 (docs/architecture/capture-spool.md). A plain literal: a drift
# test compares it with capture-browser's spool.py by ast.
JOB_VERSION = 3
CAPTURE_MODES = ("live", "archive")
PROXY_KEY_MIN_LEN = 32

DEFAULT_REVISIT_DAYS = 30
DEFAULT_ARCHIVE_FRESHNESS_DAYS = 7
DEFAULT_USER_AGENT_MODE = "stock"
DEFAULT_MAX_IMAGE_BYTES = 2 * 1024 * 1024
DEFAULT_QUEUE_TIMEOUT_S = 600
DEFAULT_IMAGE_KEEP_COUNT = 3
PROXY_CONNECT_TIMEOUT_DEFAULT = 10
PROXY_IDLE_TIMEOUT_DEFAULT = 30
PROXY_MAX_CONNECTIONS_DEFAULT = 256

REVISIT_DAYS_MIN = 1
REVISIT_DAYS_MAX = 365
ARCHIVE_FRESHNESS_DAYS_MIN = 1
ARCHIVE_FRESHNESS_DAYS_MAX = 90
IMAGE_BYTES_MIN = 64 * 1024
IMAGE_BYTES_CEILING = 8 * 1024 * 1024  # a guard: no setting or row can exceed it
QUEUE_TIMEOUT_MIN = 60
QUEUE_TIMEOUT_MAX = 3600
# Slack on top of the queue timeout for a run to finish; the proxy bounds the
# credential lifetime by QUEUE_TIMEOUT_MAX + this (a drift test asserts it).
CREDENTIAL_RUN_MARGIN_S = 300
USER_AGENT_MAX = 256
IMAGE_KEEP_MIN = 1
IMAGE_KEEP_MAX = 50
PRUNE_BATCH = 500
PROXY_CONNECT_TIMEOUT_MIN = 1
PROXY_CONNECT_TIMEOUT_MAX = 60
PROXY_IDLE_TIMEOUT_MIN = 5
PROXY_IDLE_TIMEOUT_MAX = 600
PROXY_MAX_CONNECTIONS_MIN = 1
PROXY_MAX_CONNECTIONS_MAX = 1024
PROXY_LIMITS_FILE = "proxy_limits.json"
PROXY_LIMITS_VERSION = 1
PROXY_LIMITS_MAX_BYTES = 4096

WEBP_QUALITIES = (80, 60, 40)
VIEWPORT_WIDTH = 1280
VIEWPORT_HEIGHT = 800
RESULT_MIN_AGE_S = 5
JOB_MAX_BYTES = 16 * 1024
RESULT_MAX_BYTES = 1024 * 1024
PROXYLOG_MAX_BYTES = 4 * 1024 * 1024
TICK_INTERVAL_SECONDS = 10

_MAX_URL = 8192
_MAX_CHAIN = 50
_MAX_SAN = 1000


def valid_user_agent(value: object) -> bool:
    """A str of 1..USER_AGENT_MAX printable ASCII chars (0x20..0x7e). CR/LF,
    other controls and non-ASCII are refused: the string becomes an HTTP header."""
    return (
        isinstance(value, str)
        and 1 <= len(value) <= USER_AGENT_MAX
        and all(0x20 <= ord(ch) <= 0x7E for ch in value)
    )


def _bounded_int(db: Session, key: str, default: int, lo: int, hi: int) -> int:
    value = app_settings.get_int(db, key)
    return value if value is not None and lo <= value <= hi else default


def revisit_days(db: Session) -> int:
    return _bounded_int(db, REVISIT_DAYS_KEY, DEFAULT_REVISIT_DAYS, REVISIT_DAYS_MIN, REVISIT_DAYS_MAX)


def archive_freshness_days(db: Session) -> int:
    return _bounded_int(
        db, ARCHIVE_FRESHNESS_DAYS_KEY, DEFAULT_ARCHIVE_FRESHNESS_DAYS,
        ARCHIVE_FRESHNESS_DAYS_MIN, ARCHIVE_FRESHNESS_DAYS_MAX,
    )


def user_agent_mode(db: Session) -> str:
    value = app_settings.get(db, USER_AGENT_MODE_KEY)
    return value if value in USER_AGENT_MODES else DEFAULT_USER_AGENT_MODE


def identifying_user_agent(db: Session) -> str | None:
    value = app_settings.get(db, IDENTIFYING_UA_KEY)
    return value if valid_user_agent(value) else None


def max_image_bytes(db: Session) -> int:
    return _bounded_int(db, MAX_IMAGE_BYTES_KEY, DEFAULT_MAX_IMAGE_BYTES, IMAGE_BYTES_MIN, IMAGE_BYTES_CEILING)


def queue_timeout_seconds(db: Session) -> int:
    return _bounded_int(db, QUEUE_TIMEOUT_KEY, DEFAULT_QUEUE_TIMEOUT_S, QUEUE_TIMEOUT_MIN, QUEUE_TIMEOUT_MAX)


def image_keep_count(db: Session) -> int:
    return _bounded_int(db, IMAGE_KEEP_COUNT_KEY, DEFAULT_IMAGE_KEEP_COUNT, IMAGE_KEEP_MIN, IMAGE_KEEP_MAX)


def proxy_connect_timeout_seconds(db: Session) -> int:
    return _bounded_int(
        db, PROXY_CONNECT_TIMEOUT_KEY, PROXY_CONNECT_TIMEOUT_DEFAULT,
        PROXY_CONNECT_TIMEOUT_MIN, PROXY_CONNECT_TIMEOUT_MAX,
    )


def proxy_idle_timeout_seconds(db: Session) -> int:
    return _bounded_int(
        db, PROXY_IDLE_TIMEOUT_KEY, PROXY_IDLE_TIMEOUT_DEFAULT, PROXY_IDLE_TIMEOUT_MIN, PROXY_IDLE_TIMEOUT_MAX
    )


def proxy_max_connections(db: Session) -> int:
    return _bounded_int(
        db, PROXY_MAX_CONNECTIONS_KEY, PROXY_MAX_CONNECTIONS_DEFAULT,
        PROXY_MAX_CONNECTIONS_MIN, PROXY_MAX_CONNECTIONS_MAX,
    )


def spool_dir() -> str:
    return os.environ.get("CAPTURE_SPOOL_DIR", "/spool")


def proxylog_dir() -> str:
    return os.environ.get("CAPTURE_PROXYLOG_DIR", "/proxylog")


def images_dir() -> str:
    return os.environ.get("CAPTURE_IMAGES_DIR", "/captures")


def config_dir() -> str:
    return os.environ.get("CAPTURE_CONFIG_DIR", "/capture_config")


def _proxy_key() -> str | None:
    """CAPTURE_PROXY_KEY read at CALL time; None when absent or too short."""
    key = os.environ.get("CAPTURE_PROXY_KEY", "").strip()
    return key if len(key) >= PROXY_KEY_MIN_LEN else None


def proxy_token(capture_id: str, mode: str, exp: int) -> str | None:
    """Per-job proxy credential: HMAC-SHA256 over `v3|<capture_id>|<mode>|<exp>`.

    None when the key is not configured. The browser gets only this token, never
    the key. Never log the result."""
    if mode not in CAPTURE_MODES:
        raise ValueError(f"unknown capture mode: {mode!r}")
    if not _is_canonical_uuid(capture_id):
        raise ValueError("capture_id is not a canonical uuid")
    key = _proxy_key()
    if key is None:
        return None
    if isinstance(exp, bool) or not isinstance(exp, int) or not 1 <= exp < 10**12:
        raise ValueError("exp out of range")
    msg = f"v3|{capture_id}|{mode}|{exp}".encode("ascii")
    return hmac.new(key.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def _is_canonical_uuid(value: str) -> bool:
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError, TypeError):
        return False


class CaptureRefused(Exception):
    """The capture was not queued. `.rule` says why (a gate rule such as
    `candidate:not_open`, or a producer rule such as `capture:already_queued`)."""

    def __init__(self, rule: str):
        super().__init__(rule)
        self.rule = rule


class _Invalid(Exception):
    """A result that fails an untrusted-input guard; `.reason` becomes the row's failure_reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# ── small helpers ────────────────────────────────────────────────────────────

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _valid_hostname(value: object) -> bool:
    """Strict: lowercase LDH labels of 1-63 chars, <=253 total, at least one
    dot, no trailing dot, no port/path/userinfo, and not an IP literal (the
    last label is never all digits)."""
    if not isinstance(value, str) or not value or len(value) > 253 or value != value.lower():
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    if not all(_LABEL_RE.fullmatch(label) for label in labels):
        return False
    return not labels[-1].isdigit()


def _canonical_uuid(name: str) -> bool:
    try:
        return str(uuid.UUID(name)) == name
    except (ValueError, AttributeError):
        return False


def _check_spool_dirs() -> None:
    """The backend does not create the spool: the images pre-create jobs/, claimed/
    and results/ with the shared-group mode. A missing directory, or one that is
    not a real directory (a symlink is refused), raises OSError."""
    for sub in ("jobs", "claimed", "results"):
        path = os.path.join(spool_dir(), sub)
        if not stat.S_ISDIR(os.lstat(path).st_mode):
            raise NotADirectoryError(path)


def _unlink_quiet(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError:
        log.warning("page_capture: could not remove %s", path)


def _remove_entry(path: str) -> None:
    """Remove a spool entry without following symlinks (rmtree refuses a
    symlinked top, and unlinks symlinks inside rather than entering them)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    try:
        if stat.S_ISDIR(st.st_mode):
            shutil.rmtree(path)
        else:
            os.unlink(path)
    except OSError:
        log.warning("page_capture: could not remove %s", path)


def _open_regular(path: str) -> int:
    """Open a spool file for reading, safely against a swap after the caller's
    lstat: O_NOFOLLOW refuses a symlink, O_NONBLOCK keeps a FIFO from blocking
    the scheduler thread on open, and the fstat re-checks the opened object is
    a regular file. Raises OSError otherwise."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError(f"not a regular file: {path}")
    return fd


def _read_regular(path: str, cap: int) -> bytes:
    """lstat, require a regular file within `cap`, then open without following
    symlinks. Raises _Invalid('invalid_result') otherwise."""
    try:
        st = os.lstat(path)
    except OSError:
        raise _Invalid("invalid_result")
    if not stat.S_ISREG(st.st_mode) or st.st_size > cap:
        raise _Invalid("invalid_result")
    try:
        fd = _open_regular(path)
    except OSError:
        raise _Invalid("invalid_result")
    with os.fdopen(fd, "rb") as f:
        data = f.read(cap + 1)
    if len(data) > cap:
        raise _Invalid("invalid_result")
    return data


def _s(value: object, cap: int, *, truncate: bool = False) -> str | None:
    """A string within `cap` (or truncated to it), NULs removed (Postgres text
    and jsonb both refuse them). Anything else is None."""
    if not isinstance(value, str):
        return None
    value = value.replace("\x00", "")
    if len(value) > cap:
        return value[:cap] if truncate else None
    return value


def _int(value: object, lo: int, hi: int) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if lo <= value <= hi else None


def _parse_http_url(s: str) -> tuple[str, int] | None:
    """(lowercase host, effective port) of a plain http(s) URL, else None.
    Userinfo is refused; an IPv6 literal host is allowed; a bad port is None."""
    try:
        parts = urlsplit(s)
        if parts.scheme not in ("http", "https") or "@" in parts.netloc:
            return None
        host = parts.hostname
        if not host:
            return None
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return None
    return host.lower(), port


def _http_url(value: object) -> str | None:
    s = _s(value, _MAX_URL)
    return s if s is not None and _parse_http_url(s) is not None else None


def _ip(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


_WAYBACK_FINAL_RE = re.compile(r"/web/([0-9]{14})[a-z_]*/")  # Wayback replay flags like id_, im_


def _archive_rendered_at(final_url: str | None) -> datetime | None:
    """The snapshot time of the page actually shown: the /web/<14 digits>/ of an
    https web.archive.org final URL. None when it cannot be read."""
    if not final_url:
        return None
    try:
        parts = urlsplit(final_url)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme != "https" or parts.hostname != wayback.ARCHIVE_HOST or port not in (None, 443):
        return None
    m = _WAYBACK_FINAL_RE.match(parts.path)
    if m is None:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _fail(row: PageCapture, reason: str, now: datetime) -> None:
    row.status = "failed"
    row.failure_reason = reason
    row.finished_at = now


# ── request ──────────────────────────────────────────────────────────────────


def request_capture(db: Session, *, candidate_id: uuid.UUID, user: User, manual: bool) -> PageCapture:
    """Queue one capture of a candidate's domain. An automatic request
    (`manual=False`) is refused by the revisit budget (a queued or recently
    finished capture of the same domain); a manual re-capture bypasses it.

    This function OWNS its session's commits (unlike a helper that only
    flushes): the job file must only exist after the `page_captures` row is
    durable, or the worker could produce a result for a row the ingest cannot
    see yet, which the ingest would discard as unknown. The gate also commits
    (it logs a denial), so nothing earlier in the caller's transaction
    survives this call uncommitted either: call it first.

    The gate runs before any write. Under a restricting posture
    (`auth.passive_only`) the capture is archive-first: the newest non-error Wayback
    CDX capture no older than `capture.archive_freshness_days` is captured instead of the live
    site (an ARCHIVE job); an explicit "no fresh snapshot" answer falls back to
    a normal live job (the revisit budget still applies to an automatic
    request). `manual` bypasses only the revisit budget, never the posture or
    archive-first. A failed lookup refuses (`archive:lookup_unavailable`) and
    never falls through to live. The lookup is an outbound fetch, so it runs
    only after every cheap refusal has passed, and before any DB write. Without
    a restricting posture there is no lookup at all.
    """
    candidate = db.get(ScopeCandidate, candidate_id)
    if candidate is None:
        raise CaptureRefused("candidate:not_found")
    root = db.get(OrgEntity, candidate.root_entity_id)
    auth = authorise_candidate_browse(db, candidate=candidate, root=root)
    if not auth.allowed:
        raise CaptureRefused(auth.rule_fired or "candidate:denied")
    already = (
        db.query(PageCapture.id)
        .filter(PageCapture.candidate_id == candidate.id, PageCapture.status == "queued")
        .first()
    )
    if already is not None:
        raise CaptureRefused("capture:already_queued")
    domain = candidate.value
    if not _valid_hostname(domain):
        raise CaptureRefused("candidate:invalid_domain")
    now = datetime.now(timezone.utc)
    if not manual:
        cutoff = now - timedelta(days=revisit_days(db))
        recent = (
            db.query(PageCapture.id)
            .filter(
                PageCapture.domain == domain,
                or_(
                    PageCapture.status == "queued",
                    and_(PageCapture.status == "done", PageCapture.finished_at >= cutoff),
                ),
            )
            .first()
        )
        if recent is not None:
            raise CaptureRefused("capture:revisit_budget")
    mode = user_agent_mode(db)
    ua = identifying_user_agent(db)
    if mode == "identifying" and ua is None:
        raise CaptureRefused("capture:identifying_user_agent_unset")
    if _proxy_key() is None:
        # No key, no credential the proxy would accept: refuse before any row exists.
        raise CaptureRefused("capture:not_configured")

    capture_mode = "live"
    requested_url = f"https://{domain}/"
    archive_fields: dict = {}
    if auth.passive_only:
        try:
            since = now - timedelta(days=archive_freshness_days(db))
            snap = wayback.latest_snapshot(domain, now, since)
        except wayback.WaybackUnavailable:
            raise CaptureRefused("archive:lookup_unavailable")
        if snap is not None:  # wayback validated captured_at >= since
            # archive_snapshot_at is PROVISIONAL (the capture requested); ingest replaces it
            # with the snapshot time the page actually shown carries.
            capture_mode = "archive"
            requested_url = wayback.snapshot_url(snap, domain)
            archive_fields = {"archive_snapshot_at": snap.captured_at, "archive_host": wayback.ARCHIVE_HOST}

    row = PageCapture(
        candidate_id=candidate.id,
        domain=domain,
        observer_id=auth.observer.id,
        requested_url=requested_url,
        source=capture_mode,
        **archive_fields,
        requested_by_id=user.id,
        user_agent_mode=mode,
        image_max_bytes=max_image_bytes(db),
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError as e:
        db.rollback()
        if "uq_page_captures_one_queued_per_candidate" in str(e.orig):
            raise CaptureRefused("capture:already_queued")
        raise
    capture_id = str(row.id)
    exp = int(time.time()) + queue_timeout_seconds(db) + CREDENTIAL_RUN_MARGIN_S

    job = {
        "v": JOB_VERSION,
        "capture_id": capture_id,
        "url": row.requested_url,
        "mode": capture_mode,
        "proxy_token": proxy_token(capture_id, capture_mode, exp),
        "proxy_expires": exp,
        "viewport": {"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
        "user_agent_mode": mode,
        "max_image_bytes": row.image_max_bytes,
        "webp_qualities": list(WEBP_QUALITIES),
    }
    if mode == "identifying":
        job["user_agent"] = ua
    payload = json.dumps(job).encode()
    tmp = None
    try:
        _check_spool_dirs()
        jobs = os.path.join(spool_dir(), "jobs")
        tmp = os.path.join(jobs, f".{capture_id}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
        os.rename(tmp, os.path.join(jobs, f"{capture_id}.json"))
    except OSError:
        log.exception("page_capture: could not write job %s", capture_id)
        if tmp is not None:
            _unlink_quiet(tmp)
        _fail(row, "spool_unavailable", datetime.now(timezone.utc))
        db.commit()
        raise CaptureRefused("spool_unavailable")
    return row


# ── ingest ───────────────────────────────────────────────────────────────────


def ingest_results(db: Session, now: datetime | None = None) -> int:
    """Ingest every `results/<id>/` directory at least RESULT_MIN_AGE_S old.
    Each capture is its own unit of work. Returns how many queued rows were
    resolved (done or failed)."""
    now = now or datetime.now(timezone.utc)
    results = os.path.join(spool_dir(), "results")
    try:
        names = sorted(os.listdir(results))
    except FileNotFoundError:
        return 0
    resolved = 0
    for name in names:
        if name.startswith("."):
            continue
        path = os.path.join(results, name)
        if not _canonical_uuid(name):
            log.warning("page_capture: removing non-UUID spool result %r", name)
            _remove_entry(path)
            continue
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if now.timestamp() - st.st_mtime < RESULT_MIN_AGE_S:
            continue
        capture_id = uuid.UUID(name)
        proxylog = os.path.join(proxylog_dir(), f"{name}.jsonl")
        try:
            row = db.get(PageCapture, capture_id)
            if row is None or row.status != "queued":
                log.warning("page_capture: discarding result for %s (not a queued capture)", name)
                _remove_entry(path)
                _unlink_quiet(proxylog)
                continue
            if not stat.S_ISDIR(st.st_mode):
                raise _Invalid("invalid_result")
            _ingest_one(db, row, path, proxylog, now)
            db.commit()
        except _Invalid as bad:
            db.rollback()
            _unlink_quiet(os.path.join(images_dir(), f"{name}.webp"))
            if _mark_failed(db, capture_id, bad.reason, now):
                resolved += 1
                _remove_entry(path)
                _unlink_quiet(proxylog)
            continue
        except Exception:
            db.rollback()
            _unlink_quiet(os.path.join(images_dir(), f"{name}.webp"))
            log.exception("page_capture: ingest failed for %s", name)
            if _mark_failed(db, capture_id, "ingest_error", now):
                resolved += 1
            continue
        resolved += 1
        _remove_entry(path)
        _unlink_quiet(proxylog)
    return resolved


def _mark_failed(db: Session, capture_id: uuid.UUID, reason: str, now: datetime) -> bool:
    """Its own small unit of work: fail the row if it is still queued."""
    try:
        row = db.get(PageCapture, capture_id)
        if row is None or row.status != "queued":
            return False
        _fail(row, reason, now)
        db.commit()
        return True
    except Exception:
        db.rollback()
        log.exception("page_capture: could not mark %s failed (%s)", capture_id, reason)
        return False


def _ingest_one(db: Session, row: PageCapture, path: str, proxylog: str, now: datetime) -> None:
    name = str(row.id)
    # lstat every entry: a symlink or anything not a regular file is refused.
    try:
        entries = os.listdir(path)
    except OSError:
        raise _Invalid("invalid_result")
    for entry in entries:
        try:
            mode = os.lstat(os.path.join(path, entry)).st_mode
        except OSError:
            raise _Invalid("invalid_result")
        if not stat.S_ISREG(mode):
            raise _Invalid("invalid_result")

    try:
        result = json.loads(_read_regular(os.path.join(path, "result.json"), RESULT_MAX_BYTES))
    except (ValueError, RecursionError):
        raise _Invalid("invalid_result")
    if not isinstance(result, dict) or result.get("capture_id") != name:
        raise _Invalid("invalid_result")

    row.final_url = _http_url(result.get("final_url"))
    row.http_status = _int(result.get("status"), 100, 599)
    row.redirect_chain = _chain(result.get("redirect_chain"))
    row.title = _s(result.get("title"), 1024, truncate=True)
    row.user_agent = _s(result.get("user_agent"), 512, truncate=True)
    cert, san, sha = _cert(result.get("cert"))
    row.cert, row.cert_san_dns, row.cert_sha256 = cert, san, sha

    error = result.get("error")
    if error is not None:
        row.error = _s(error, 2000, truncate=True) if isinstance(error, str) else _s(str(error), 2000, truncate=True)

    _ingest_proxylog(db, row, proxylog)

    image = None
    claimed = result.get("screenshot")
    if claimed is None:
        row.image_omitted_reason = _s(result.get("screenshot_omitted_reason"), 200, truncate=True)
    else:
        image = _read_image(
            os.path.join(path, "screenshot.webp"), min(row.image_max_bytes, IMAGE_BYTES_CEILING)
        )
        if image is None:
            row.image_omitted_reason = "invalid_image"
        else:
            quality = _int(claimed.get("quality"), 1, 100) if isinstance(claimed, dict) else None
            _store_image(row, name, image, quality)

    if error is not None:
        _fail(row, "capture_error", now)
    elif row.source == "archive":
        # The time goes on the evidence: the page shown, not the capture we
        # asked for (a redirect capture replays the target's NEAREST capture).
        rendered = _archive_rendered_at(row.final_url)
        if rendered is None:
            _fail(row, "archive_snapshot_unverified", now)
            return
        row.archive_snapshot_at = rendered
        window_start = row.requested_at - timedelta(days=archive_freshness_days(db))
        if rendered < window_start or rendered - row.requested_at > timedelta(days=1):
            _fail(row, "archive_snapshot_stale", now)
        else:
            row.status = "done"
            row.finished_at = now
    else:
        row.status = "done"
        row.finished_at = now


def _chain(value: object) -> list | None:
    if not isinstance(value, list) or len(value) > _MAX_CHAIN:
        return None
    out = []
    for hop in value:
        if not isinstance(hop, dict):
            continue
        url = _s(hop.get("url"), _MAX_URL)
        if url is None:
            continue
        out.append({"url": url, "status": _int(hop.get("status"), 100, 599)})
    return out


def _cert(value: object) -> tuple[dict | None, list[str] | None, str | None]:
    if not isinstance(value, dict):
        return None, None, None
    cert: dict = {}
    for key in ("subject", "issuer", "not_before", "not_after"):
        s = _s(value.get(key), 1024)
        if s is not None:
            cert[key] = s
    san = None
    raw = value.get("san_dns")
    if isinstance(raw, list):
        san = [s.lower() for s in (_s(x, 253) for x in raw[:_MAX_SAN]) if s is not None]
        cert["san_dns"] = san
    sha = _s(value.get("sha256"), 64)
    if sha is not None and re.fullmatch(r"[0-9a-fA-F]{64}", sha):
        sha = sha.lower()
        cert["sha256"] = sha
    else:
        sha = None
    return cert, san, sha


def _read_image(path: str, cap: int) -> bytes | None:
    """The screenshot bytes if (and only if) a regular file within `cap`
    that starts RIFF....WEBP. Never decoded. A symlink is not 'bad image', it
    is a refused entry (checked by the caller's lstat sweep)."""
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > cap:
            return None
        fd = _open_regular(path)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        data = f.read(cap + 1)
    if len(data) > cap or len(data) < 12:
        return None
    if data[0:4] != b"RIFF" or data[8:12] != b"WEBP":
        return None
    return data


def read_stored_image(row: PageCapture) -> bytes | None:
    """The stored screenshot's bytes, or None unless every check holds: the
    recorded name is exactly `<capture id>.webp` (never a path from the row),
    a regular file within the row's cap, opened without following symlinks,
    RIFF....WEBP magic, and the sha256 recorded at ingest. Never decoded.
    A mismatch logs a warning (no domain) and returns None."""
    if row.image_path is None or row.image_path != f"{row.id}.webp":
        if row.image_path is not None:
            log.warning("page_capture: stored image name mismatch for %s", row.id)
        return None
    cap = min(row.image_max_bytes, IMAGE_BYTES_CEILING)
    path = os.path.join(images_dir(), row.image_path)
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > cap:
            log.warning("page_capture: stored image for %s is not a regular file within its cap", row.id)
            return None
        fd = _open_regular(path)
        with os.fdopen(fd, "rb") as f:
            data = f.read(cap + 1)
    except OSError:
        log.warning("page_capture: stored image for %s could not be read", row.id)
        return None
    if len(data) > cap or len(data) < 12 or data[0:4] != b"RIFF" or data[8:12] != b"WEBP":
        log.warning("page_capture: stored image for %s failed the size/magic check", row.id)
        return None
    if hashlib.sha256(data).hexdigest() != row.image_sha256:
        log.warning("page_capture: stored image for %s does not match its recorded sha256", row.id)
        return None
    return data


def _store_image(row: PageCapture, name: str, data: bytes, quality: int | None) -> None:
    dest_dir = images_dir()
    tmp = os.path.join(dest_dir, f".{name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.rename(tmp, os.path.join(dest_dir, f"{name}.webp"))
    except OSError:
        _unlink_quiet(tmp)
        raise
    row.image_path = f"{name}.webp"
    row.image_bytes = len(data)
    row.image_sha256 = hashlib.sha256(data).hexdigest()
    row.image_quality = quality


def _ingest_proxylog(db: Session, row: PageCapture, path: str) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(st.st_mode):
        log.warning("page_capture: ignoring non-regular proxy log for %s", row.id)
        return
    try:
        fd = _open_regular(path)
    except OSError:
        return
    with os.fdopen(fd, "rb") as f:
        data = f.read(PROXYLOG_MAX_BYTES)
    row.proxy_log_truncated = st.st_size >= PROXYLOG_MAX_BYTES

    final_host, final_port = None, None
    if row.final_url:
        target = _parse_http_url(row.final_url)
        if target is not None:
            final_host, final_port = target

    cid = str(row.id)
    seq = 0
    pinned = None
    for line in data.decode("utf-8", errors="replace").splitlines():
        try:
            rec = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not isinstance(rec, dict) or rec.get("capture_id") != cid:
            continue
        decision = _s(rec.get("decision"), 32)
        if not decision:
            continue
        host = _s(rec.get("host"), 255, truncate=True)
        host = host.lower() if host else None
        port = _int(rec.get("port"), 0, 65535)
        rec_pinned = _ip(rec.get("pinned_ip"))
        if (
            pinned is None and decision == "allow" and final_host is not None
            and host == final_host and port == final_port
        ):
            pinned = rec_pinned
        resolved = rec.get("resolved")
        db.add(PageCaptureRequest(
            capture_id=row.id,
            seq=seq,
            ts=_ts(rec.get("ts")),
            method=_s(rec.get("method"), 16, truncate=True),
            scheme=_s(rec.get("scheme"), 16, truncate=True),
            host=host,
            port=port,
            resolved=[ip for ip in (_ip(x) for x in resolved[:64]) if ip] if isinstance(resolved, list) else None,
            pinned_ip=rec_pinned,
            decision=decision,
            reason=_s(rec.get("reason"), 500, truncate=True),
            bytes_up=_int(rec.get("bytes_up"), 0, 2**63 - 1),
            bytes_down=_int(rec.get("bytes_down"), 0, 2**63 - 1),
            duration_ms=_int(rec.get("duration_ms"), 0, 2**31 - 1),
        ))
        seq += 1
    row.pinned_ip = pinned


def _ts(value: object) -> datetime | None:
    s = _s(value, 64)
    if s is None:
        return None
    try:
        ts = datetime.fromisoformat(s)
    except ValueError:
        return None
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)


# ── image pruning ────────────────────────────────────────────────────────────


def prune_images(db: Session, now: datetime | None = None) -> int:
    """Keep the latest `image_keep_count` image FILES per domain; remove the rest.
    Rows are never deleted: a pruned row gets `image_path = NULL` and
    `image_pruned_at = now` (migration 0093). Returns the number pruned; at most
    PRUNE_BATCH per call. Flushes, never commits (`tick` owns the commit).

    Unlink-then-record, on purpose. If the commit fails, the row still points at
    a missing file: the image route already returns None for that, and the next
    tick's unlink gets FileNotFoundError and records it, so it self-heals. The
    reverse order (record, then unlink) would leak the file forever once the row
    no longer pointed at it.

    The path is built from the row id, never from the row's string, and
    `os.unlink` never follows a symlink. A row whose recorded name is not
    exactly `<id>.webp` is NULLed without touching any file."""
    now = now or datetime.now(timezone.utc)
    root = images_dir()
    try:
        if not stat.S_ISDIR(os.lstat(root).st_mode):
            raise NotADirectoryError(root)
    except OSError:
        log.error("page_capture: images directory is missing or not a real directory; skipping prune", exc_info=True)
        return 0

    ranked = (
        select(
            PageCapture.id.label("id"),
            func.row_number().over(
                partition_by=PageCapture.domain,
                order_by=(PageCapture.finished_at.desc(), PageCapture.id.desc()),
            ).label("rnk"),
        )
        .where(PageCapture.image_path.is_not(None))
        .subquery()
    )
    ids = db.execute(
        select(ranked.c.id).where(ranked.c.rnk > image_keep_count(db)).limit(PRUNE_BATCH)
    ).scalars().all()
    if not ids:
        return 0
    rows = db.query(PageCapture).filter(PageCapture.id.in_(ids)).all()

    pruned = 0
    for row in rows:
        if row.image_path != f"{row.id}.webp":
            log.warning("page_capture: pruning %s with a mismatched image name; no file touched", row.id)
        else:
            try:
                os.unlink(os.path.join(root, f"{row.id}.webp"))
            except FileNotFoundError:
                pass
            except OSError:
                log.warning("page_capture: could not remove the image for %s; will retry", row.id, exc_info=True)
                continue
        row.image_path = None
        row.image_pruned_at = now
        pruned += 1
    db.flush()
    return pruned


# ── proxy limits ─────────────────────────────────────────────────────────────


def proxy_limits_bytes(db: Session) -> bytes:
    return json.dumps(
        {
            "version": PROXY_LIMITS_VERSION,
            "connect_timeout_s": proxy_connect_timeout_seconds(db),
            "idle_timeout_s": proxy_idle_timeout_seconds(db),
            "max_connections": proxy_max_connections(db),
        },
        sort_keys=True, separators=(",", ":"),
    ).encode() + b"\n"


def write_proxy_limits(db: Session) -> bool:
    """Write the proxy's limits file when its content differs from the settings
    (so a fresh volume or a restart heals itself). True if it wrote. The proxy
    has no DB and no route here; it mounts the directory read-only."""
    want = proxy_limits_bytes(db)
    root = config_dir()
    try:
        if not stat.S_ISDIR(os.lstat(root).st_mode):
            raise NotADirectoryError(root)
    except OSError:
        log.error("page_capture: config directory is missing or not a real directory; limits not written", exc_info=True)
        return False
    target = os.path.join(root, PROXY_LIMITS_FILE)
    try:
        fd = _open_regular(target)
        with os.fdopen(fd, "rb") as f:
            if f.read(PROXY_LIMITS_MAX_BYTES + 1) == want:
                return False
    except OSError:
        pass
    tmp = os.path.join(root, f".{PROXY_LIMITS_FILE}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(want)
        os.rename(tmp, target)
    except OSError:
        _unlink_quiet(tmp)
        raise
    log.info("page_capture: wrote proxy limits %s", want.decode().strip())
    return True


# ── timeout sweep and tick ───────────────────────────────────────────────────


def sweep_timeouts(db: Session, now: datetime | None = None) -> int:
    """Queued rows older than the queue-timeout setting fail as 'timeout'; their job and
    claim files go. Returns the number swept."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=queue_timeout_seconds(db))
    rows = db.query(PageCapture).filter(PageCapture.status == "queued", PageCapture.requested_at < cutoff).all()
    ids = [str(r.id) for r in rows]
    for r in rows:
        _fail(r, "timeout", now)
    db.commit()
    for i in ids:
        _unlink_quiet(os.path.join(spool_dir(), "jobs", f"{i}.json"))
        _unlink_quiet(os.path.join(spool_dir(), "claimed", f"{i}.json"))
    return len(ids)


def tick() -> None:
    """One pass: ingest, then sweep. Never raises (the scheduler must keep
    firing). Registered in scheduler.py as job `page_capture`."""
    db = SessionLocal()
    try:
        try:
            write_proxy_limits(db)
        except Exception:
            db.rollback()
            log.exception("page_capture: writing the proxy limits failed")
        try:
            _check_spool_dirs()
        except OSError:
            log.error("page_capture: spool directories are missing; skipping ingest", exc_info=True)
        else:
            try:
                ingest_results(db)
            except Exception:
                db.rollback()
                log.exception("page_capture: ingest pass failed")
        try:
            sweep_timeouts(db)
        except Exception:
            db.rollback()
            log.exception("page_capture: timeout sweep failed")
        try:
            prune_images(db)
            db.commit()
        except Exception:
            db.rollback()
            log.exception("page_capture: image prune failed")
    except Exception:
        log.exception("page_capture: tick failed")
    finally:
        db.close()
