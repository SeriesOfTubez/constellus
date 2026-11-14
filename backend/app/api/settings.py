import re

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.permissions import Permission
from app.core.database import get_db

from app.services import aggressiveness as aggr
from app.services import app_settings as svc
from app.core import logging as app_logging
from app.services import audit, cpe_cve_sync, job_runs, log_settings, page_capture
from app.services.org_discovery import pacing as discovery_pacing

router = APIRouter()

SCAN_AUTH_MODES = ("strict", "acknowledge", "disabled")

# The accent set is curated: a raw picker could land on a severity hue. Every option is
# OKLCH L 0.80 / C 0.10, so one dark --brand-fg serves all of them, with its hue 40
# degrees or more from every severity hue. That floor leaves only the bands 204-213 and
# 294-333; lime is the one named exception (37 degrees from clean, 38 from medium;
# planning#367). The same four live in frontend/src/lib/branding.ts and
# test_settings_branding.py keeps them equal and holds the floor and the exception.
ACCENT_PALETTE = {
    "#66d0df",  # cyan  (default)
    "#aeca82",  # lime
    "#c7aff5",  # violet
    "#e3a6dc",  # pink
}

_HTTPS_RE = re.compile(r"^https://\S+$")
_HEX_RE   = re.compile(r"^#[0-9a-fA-F]{6}$")


class OrgBrandingResponse(BaseModel):
    org_name: str
    org_logo_url: str | None
    org_brand_accent: str
    org_name_color: str | None


class SettingsResponse(OrgBrandingResponse):
    scan_authorisation_mode: str
    aggressiveness: str


class SettingsUpdate(BaseModel):
    scan_authorisation_mode: str | None = None
    aggressiveness: str | None = None
    org_name: str | None = None
    org_logo_url: str | None = None
    org_brand_accent: str | None = None
    org_name_color: str | None = None


def _accent(db: Session) -> str:
    # A stored accent that has left the curated set reads as the default.
    stored = svc.get(db, "org.brand_accent")
    return stored if stored in ACCENT_PALETTE else svc.DEFAULTS["org.brand_accent"]


def _branding(db: Session) -> OrgBrandingResponse:
    name_color = svc.get(db, "org.name_color")
    return OrgBrandingResponse(
        org_name=svc.get(db, "org.name") or "Constellus",
        org_logo_url=svc.get(db, "org.logo_url") or None,
        org_brand_accent=_accent(db),
        org_name_color=name_color if name_color else None,
    )


def _current(db: Session) -> SettingsResponse:
    b = _branding(db)
    return SettingsResponse(
        scan_authorisation_mode=svc.get(db, "scan_authorisation_mode") or "disabled",
        aggressiveness=aggr.normalize(svc.get(db, "aggressiveness")),
        org_name=b.org_name,
        org_logo_url=b.org_logo_url,
        org_brand_accent=b.org_brand_accent,
        org_name_color=b.org_name_color,
    )


@router.get("/branding", response_model=OrgBrandingResponse)
def get_branding(db: Session = Depends(get_db)):
    """Public — no auth required.

    Returns org branding (name, logo URL, accent colour). Called at app boot so
    the login page and CSS vars are set before the user authenticates.
    """
    return _branding(db)


@router.get("/", response_model=SettingsResponse)
def get_settings(
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.SETTINGS_READ)),
):
    return _current(db)


@router.put("/", response_model=SettingsResponse)
def update_settings(
    data: SettingsUpdate,
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.SETTINGS_UPDATE)),
):
    if data.scan_authorisation_mode is not None:
        if data.scan_authorisation_mode not in SCAN_AUTH_MODES:
            raise HTTPException(
                status_code=422,
                detail=f"scan_authorisation_mode must be one of {list(SCAN_AUTH_MODES)}",
            )
        svc.set_value(db, "scan_authorisation_mode", data.scan_authorisation_mode)

    if data.aggressiveness is not None:
        if data.aggressiveness not in aggr.TIERS:
            raise HTTPException(
                status_code=422,
                detail=f"aggressiveness must be one of {list(aggr.TIERS)}",
            )
        svc.set_value(db, "aggressiveness", data.aggressiveness)

    if data.org_name is not None:
        name = data.org_name.strip()
        if not name:
            raise HTTPException(status_code=422, detail="org_name cannot be empty")
        svc.set_value(db, "org.name", name)

    if data.org_logo_url is not None:
        url = data.org_logo_url.strip()
        if url and not _HTTPS_RE.match(url):
            raise HTTPException(
                status_code=422,
                detail="org_logo_url must be an https:// URL or empty string",
            )
        svc.set_value(db, "org.logo_url", url)

    if data.org_name_color is not None:
        color = data.org_name_color.strip()
        if color and not _HEX_RE.match(color):
            raise HTTPException(
                status_code=422,
                detail="org_name_color must be a 6-digit hex colour (e.g. #ff0000) or empty string",
            )
        svc.set_value(db, "org.name_color", color)

    if data.org_brand_accent is not None:
        accent = data.org_brand_accent.lower()
        if accent not in ACCENT_PALETTE:
            raise HTTPException(
                status_code=422,
                detail=f"org_brand_accent must be one of {sorted(ACCENT_PALETTE)}",
            )
        svc.set_value(db, "org.brand_accent", accent)

    return _current(db)


# ── page capture (planning#280 S5b-2b) ──────────────────────────────────────


class CaptureSettings(BaseModel):
    browse_revisit_days: int
    archive_freshness_days: int
    user_agent_mode: str
    identifying_user_agent: str  # "" when unset or invalid
    max_image_bytes: int
    queue_timeout_seconds: int
    image_keep_count: int
    proxy_connect_timeout_seconds: int
    proxy_idle_timeout_seconds: int
    proxy_max_connections: int
    sweep_pause_seconds: int
    sweep_lookup_backoff_seconds: int
    sweep_time_limit_seconds: int
    sweep_max_consecutive_lookup_failures: int
    sweep_retry_after_lookup_days: int
    sweep_retry_after_other_days: int
    store_access_refresh_below_seconds: int


class CaptureSettingsUpdate(BaseModel):
    browse_revisit_days: int | None = Field(
        default=None, ge=page_capture.REVISIT_DAYS_MIN, le=page_capture.REVISIT_DAYS_MAX
    )
    archive_freshness_days: int | None = Field(
        default=None, ge=page_capture.ARCHIVE_FRESHNESS_DAYS_MIN, le=page_capture.ARCHIVE_FRESHNESS_DAYS_MAX
    )
    # Must equal `models.page_capture.USER_AGENT_MODES` (a test asserts it).
    user_agent_mode: Literal["stock", "identifying"] | None = None
    identifying_user_agent: str | None = None
    max_image_bytes: int | None = Field(
        default=None, ge=page_capture.IMAGE_BYTES_MIN, le=page_capture.IMAGE_BYTES_CEILING
    )
    queue_timeout_seconds: int | None = Field(
        default=None, ge=page_capture.QUEUE_TIMEOUT_MIN, le=page_capture.QUEUE_TIMEOUT_MAX
    )
    image_keep_count: int | None = Field(
        default=None, ge=page_capture.IMAGE_KEEP_MIN, le=page_capture.IMAGE_KEEP_MAX
    )
    proxy_connect_timeout_seconds: int | None = Field(
        default=None, ge=page_capture.PROXY_CONNECT_TIMEOUT_MIN, le=page_capture.PROXY_CONNECT_TIMEOUT_MAX
    )
    proxy_idle_timeout_seconds: int | None = Field(
        default=None, ge=page_capture.PROXY_IDLE_TIMEOUT_MIN, le=page_capture.PROXY_IDLE_TIMEOUT_MAX
    )
    proxy_max_connections: int | None = Field(
        default=None, ge=page_capture.PROXY_MAX_CONNECTIONS_MIN, le=page_capture.PROXY_MAX_CONNECTIONS_MAX
    )
    sweep_pause_seconds: int | None = Field(
        default=None, ge=page_capture.SWEEP_PAUSE_MIN, le=page_capture.SWEEP_PAUSE_MAX
    )
    sweep_lookup_backoff_seconds: int | None = Field(
        default=None, ge=page_capture.SWEEP_LOOKUP_BACKOFF_MIN, le=page_capture.SWEEP_LOOKUP_BACKOFF_MAX
    )
    sweep_time_limit_seconds: int | None = Field(
        default=None, ge=page_capture.SWEEP_TIME_LIMIT_MIN, le=page_capture.SWEEP_TIME_LIMIT_MAX
    )
    sweep_max_consecutive_lookup_failures: int | None = Field(
        default=None, ge=page_capture.SWEEP_MAX_LOOKUP_FAILURES_MIN, le=page_capture.SWEEP_MAX_LOOKUP_FAILURES_MAX
    )
    sweep_retry_after_lookup_days: int | None = Field(
        default=None, ge=page_capture.SWEEP_RETRY_LOOKUP_DAYS_MIN, le=page_capture.SWEEP_RETRY_LOOKUP_DAYS_MAX
    )
    sweep_retry_after_other_days: int | None = Field(
        default=None, ge=page_capture.SWEEP_RETRY_OTHER_DAYS_MIN, le=page_capture.SWEEP_RETRY_OTHER_DAYS_MAX
    )
    store_access_refresh_below_seconds: int | None = Field(
        default=None, ge=page_capture.STORE_ACCESS_REFRESH_BELOW_MIN, le=page_capture.STORE_ACCESS_REFRESH_BELOW_MAX
    )

    @field_validator("identifying_user_agent")
    @classmethod
    def _ua(cls, v: str | None) -> str | None:
        if v is not None and v != "" and not page_capture.valid_user_agent(v):
            raise ValueError(
                f"identifying_user_agent must be empty or 1-{page_capture.USER_AGENT_MAX} printable ASCII characters"
            )
        return v


def _capture_current(db: Session) -> CaptureSettings:
    pacing = page_capture.sweep_pacing(db)
    return CaptureSettings(
        browse_revisit_days=page_capture.revisit_days(db),
        archive_freshness_days=page_capture.archive_freshness_days(db),
        user_agent_mode=page_capture.user_agent_mode(db),
        identifying_user_agent=page_capture.identifying_user_agent(db) or "",
        max_image_bytes=page_capture.max_image_bytes(db),
        queue_timeout_seconds=page_capture.queue_timeout_seconds(db),
        image_keep_count=page_capture.image_keep_count(db),
        proxy_connect_timeout_seconds=page_capture.proxy_connect_timeout_seconds(db),
        proxy_idle_timeout_seconds=page_capture.proxy_idle_timeout_seconds(db),
        proxy_max_connections=page_capture.proxy_max_connections(db),
        sweep_pause_seconds=pacing.pause_s,
        sweep_lookup_backoff_seconds=pacing.lookup_backoff_s,
        sweep_time_limit_seconds=pacing.time_limit_s,
        sweep_max_consecutive_lookup_failures=pacing.max_consecutive_lookup_failures,
        sweep_retry_after_lookup_days=pacing.retry_after_lookup.days,
        sweep_retry_after_other_days=pacing.retry_after_other.days,
        store_access_refresh_below_seconds=page_capture.store_access_refresh_below_s(db),
    )


@router.get("/capture", response_model=CaptureSettings)
def get_capture_settings(
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.SETTINGS_READ)),
):
    return _capture_current(db)


@router.put("/capture", response_model=CaptureSettings)
def put_capture_settings(
    data: CaptureSettingsUpdate,
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.SETTINGS_UPDATE)),
):
    """Set any of the capture settings, audited old -> new per changed key."""
    old = _capture_current(db)
    new = old.model_copy(update=data.model_dump(exclude_none=True))
    if new.user_agent_mode == "identifying" and not page_capture.valid_user_agent(new.identifying_user_agent):
        raise HTTPException(
            status_code=422, detail="Set an identifying User-Agent before choosing identifying mode."
        )
    keys = {
        "browse_revisit_days": page_capture.REVISIT_DAYS_KEY,
        "archive_freshness_days": page_capture.ARCHIVE_FRESHNESS_DAYS_KEY,
        "user_agent_mode": page_capture.USER_AGENT_MODE_KEY,
        "identifying_user_agent": page_capture.IDENTIFYING_UA_KEY,
        "max_image_bytes": page_capture.MAX_IMAGE_BYTES_KEY,
        "queue_timeout_seconds": page_capture.QUEUE_TIMEOUT_KEY,
        "image_keep_count": page_capture.IMAGE_KEEP_COUNT_KEY,
        "proxy_connect_timeout_seconds": page_capture.PROXY_CONNECT_TIMEOUT_KEY,
        "proxy_idle_timeout_seconds": page_capture.PROXY_IDLE_TIMEOUT_KEY,
        "proxy_max_connections": page_capture.PROXY_MAX_CONNECTIONS_KEY,
        "sweep_pause_seconds": page_capture.SWEEP_PAUSE_KEY,
        "sweep_lookup_backoff_seconds": page_capture.SWEEP_LOOKUP_BACKOFF_KEY,
        "sweep_time_limit_seconds": page_capture.SWEEP_TIME_LIMIT_KEY,
        "sweep_max_consecutive_lookup_failures": page_capture.SWEEP_MAX_LOOKUP_FAILURES_KEY,
        "sweep_retry_after_lookup_days": page_capture.SWEEP_RETRY_LOOKUP_KEY,
        "sweep_retry_after_other_days": page_capture.SWEEP_RETRY_OTHER_KEY,
        "store_access_refresh_below_seconds": page_capture.STORE_ACCESS_REFRESH_BELOW_KEY,
    }
    changes = {}
    for field, key in keys.items():
        before, after = getattr(old, field), getattr(new, field)
        if before != after:
            svc.set_value(db, key, str(after))
            changes[f"capture_{field}"] = {"from": before, "to": after}
    if changes:
        audit.record_detail(request, **changes)
    return _capture_current(db)


# ── org re-discovery pacing (planning#320) ──────────────────────────────────


class DiscoverySettings(BaseModel):
    rediscovery_time_limit_seconds: int
    rediscovery_unit_pause_seconds: int
    rediscovery_due_batch: int
    rediscovery_refresh_interval_days: int
    rediscovery_failed_retry_days: int


class DiscoverySettingsUpdate(BaseModel):
    rediscovery_time_limit_seconds: int | None = Field(
        default=None, ge=discovery_pacing.TIME_LIMIT_MIN, le=discovery_pacing.TIME_LIMIT_MAX
    )
    rediscovery_unit_pause_seconds: int | None = Field(
        default=None, ge=discovery_pacing.UNIT_PAUSE_MIN, le=discovery_pacing.UNIT_PAUSE_MAX
    )
    rediscovery_due_batch: int | None = Field(
        default=None, ge=discovery_pacing.DUE_BATCH_MIN, le=discovery_pacing.DUE_BATCH_MAX
    )
    rediscovery_refresh_interval_days: int | None = Field(
        default=None, ge=discovery_pacing.REFRESH_INTERVAL_MIN, le=discovery_pacing.REFRESH_INTERVAL_MAX
    )
    rediscovery_failed_retry_days: int | None = Field(
        default=None, ge=discovery_pacing.FAILED_RETRY_MIN, le=discovery_pacing.FAILED_RETRY_MAX
    )


def _discovery_current(db: Session) -> DiscoverySettings:
    pacing = discovery_pacing.read(db)
    return DiscoverySettings(
        rediscovery_time_limit_seconds=pacing.time_limit_s,
        rediscovery_unit_pause_seconds=pacing.unit_pause_s,
        rediscovery_due_batch=pacing.due_batch,
        rediscovery_refresh_interval_days=pacing.refresh_interval.days,
        rediscovery_failed_retry_days=pacing.failed_retry_after.days,
    )


@router.get("/discovery", response_model=DiscoverySettings)
def get_discovery_settings(
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.SETTINGS_READ)),
):
    return _discovery_current(db)


@router.put("/discovery", response_model=DiscoverySettings)
def put_discovery_settings(
    data: DiscoverySettingsUpdate,
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.SETTINGS_UPDATE)),
):
    """Set any of the re-discovery pacing settings, audited old -> new per changed key."""
    old = _discovery_current(db)
    new = old.model_copy(update=data.model_dump(exclude_none=True))
    if new.rediscovery_failed_retry_days > new.rediscovery_refresh_interval_days:
        raise HTTPException(
            status_code=422, detail="Retrying a failed item must not take longer than the refresh interval."
        )
    keys = {
        "rediscovery_time_limit_seconds": discovery_pacing.TIME_LIMIT_KEY,
        "rediscovery_unit_pause_seconds": discovery_pacing.UNIT_PAUSE_KEY,
        "rediscovery_due_batch": discovery_pacing.DUE_BATCH_KEY,
        "rediscovery_refresh_interval_days": discovery_pacing.REFRESH_INTERVAL_KEY,
        "rediscovery_failed_retry_days": discovery_pacing.FAILED_RETRY_KEY,
    }
    changes = {}
    for field, key in keys.items():
        before, after = getattr(old, field), getattr(new, field)
        if before != after:
            svc.set_value(db, key, str(after))
            changes[f"discovery_{field}"] = {"from": before, "to": after}
    if changes:
        audit.record_detail(request, **changes)
    return _discovery_current(db)


# ── job run history retention (planning#329) ────────────────────────────────


class JobsSettings(BaseModel):
    run_history_days: int


class JobsSettingsUpdate(BaseModel):
    run_history_days: int | None = Field(
        default=None, ge=job_runs.RUN_HISTORY_DAYS_MIN, le=job_runs.RUN_HISTORY_DAYS_MAX
    )


def _jobs_current(db: Session) -> JobsSettings:
    return JobsSettings(run_history_days=job_runs.run_history_days(db))


@router.get("/jobs", response_model=JobsSettings)
def get_jobs_settings(
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.SETTINGS_READ)),
):
    return _jobs_current(db)


@router.put("/jobs", response_model=JobsSettings)
def put_jobs_settings(
    data: JobsSettingsUpdate,
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.SETTINGS_UPDATE)),
):
    """Set how many days of scheduler run history are kept, audited old -> new."""
    before = job_runs.run_history_days(db)
    after = data.run_history_days if data.run_history_days is not None else before
    if before != after:
        svc.set_value(db, job_runs.RUN_HISTORY_DAYS_KEY, str(after))
        audit.record_detail(request, jobs_run_history_days={"from": before, "to": after})
    return _jobs_current(db)


# ── DB log queue tuning (planning#335) ──────────────────────────────────────


class LogQueueSettings(BaseModel):
    queue_max_records: int
    batch_max_records: int
    flush_interval_s: float
    # The bound the running queue was built with. It differs from
    # `queue_max_records` between a change and the next restart.
    queue_max_records_active: int


class LogQueueSettingsUpdate(BaseModel):
    queue_max_records: int | None = Field(
        default=None, ge=log_settings.QUEUE_MAX_MIN, le=log_settings.QUEUE_MAX_MAX
    )
    batch_max_records: int | None = Field(
        default=None, ge=log_settings.BATCH_MAX_MIN, le=log_settings.BATCH_MAX_MAX
    )
    flush_interval_s: float | None = Field(
        default=None, ge=log_settings.FLUSH_INTERVAL_S_MIN, le=log_settings.FLUSH_INTERVAL_S_MAX
    )


def _log_queue_current(db: Session) -> LogQueueSettings:
    t = log_settings.tuning(db)
    return LogQueueSettings(
        queue_max_records=t.queue_max,
        batch_max_records=t.batch_max,
        flush_interval_s=t.flush_interval_s,
        queue_max_records_active=app_logging.db_handler.queue.maxsize,
    )


@router.get("/logging", response_model=LogQueueSettings)
def get_log_queue_settings(
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.SETTINGS_READ)),
):
    return _log_queue_current(db)


@router.put("/logging", response_model=LogQueueSettings)
def put_log_queue_settings(
    data: LogQueueSettingsUpdate,
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.SETTINGS_UPDATE)),
):
    """Set the DB log queue tuning, audited old -> new. Batch size and flush
    interval reach the writer on its next re-read; the queue bound applies
    after the next restart."""
    old = log_settings.tuning(db)
    fields = (
        ("queue_max_records", log_settings.QUEUE_MAX_KEY, old.queue_max),
        ("batch_max_records", log_settings.BATCH_MAX_KEY, old.batch_max),
        ("flush_interval_s", log_settings.FLUSH_INTERVAL_S_KEY, old.flush_interval_s),
    )
    changes = {}
    for field, key, before in fields:
        after = getattr(data, field)
        if after is not None and after != before:
            svc.set_value(db, key, str(after))
            changes[f"logs_{field}"] = {"from": before, "to": after}
    if changes:
        audit.record_detail(request, **changes)
    return _log_queue_current(db)


# ── CPE index delta pacing (planning#369) ──


class CpeIndexSettings(BaseModel):
    page_size: int
    run_time_limit_seconds: int


class CpeIndexSettingsUpdate(BaseModel):
    page_size: int | None = Field(
        default=None, ge=cpe_cve_sync.PAGE_SIZE_MIN, le=cpe_cve_sync.PAGE_SIZE_MAX
    )
    run_time_limit_seconds: int | None = Field(
        default=None, ge=cpe_cve_sync.RUN_TIME_LIMIT_MIN, le=cpe_cve_sync.RUN_TIME_LIMIT_MAX
    )


def _cpe_index_current(db: Session) -> CpeIndexSettings:
    p = cpe_cve_sync.pacing(db)
    return CpeIndexSettings(page_size=p.page_size, run_time_limit_seconds=p.time_limit_s)


@router.get("/cpe-index", response_model=CpeIndexSettings)
def get_cpe_index_settings(
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.SETTINGS_READ)),
):
    return _cpe_index_current(db)


@router.put("/cpe-index", response_model=CpeIndexSettings)
def put_cpe_index_settings(
    data: CpeIndexSettingsUpdate,
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.SETTINGS_UPDATE)),
):
    """Set the CPE index delta pacing, audited old -> new. Read by the next run."""
    old = cpe_cve_sync.pacing(db)
    fields = (
        ("page_size", cpe_cve_sync.PAGE_SIZE_KEY, old.page_size),
        ("run_time_limit_seconds", cpe_cve_sync.RUN_TIME_LIMIT_KEY, old.time_limit_s),
    )
    changes = {}
    for field, key, before in fields:
        after = getattr(data, field)
        if after is not None and after != before:
            svc.set_value(db, key, str(after))
            changes[f"cpe_index_{field}"] = {"from": before, "to": after}
    if changes:
        audit.record_detail(request, **changes)
    return _cpe_index_current(db)
