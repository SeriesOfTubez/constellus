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
from app.services import audit, page_capture

router = APIRouter()

SCAN_AUTH_MODES = ("strict", "acknowledge", "disabled")

# Pre-vetted accent colours — all verified clear of severity hues (red/orange/amber/blue/green).
# A raw hex picker would let orgs land on a severity colour; this set prevents that.
ACCENT_PALETTE = {
    "#8b7bf0",  # violet  (default)
    "#6366f1",  # indigo
    "#a855f7",  # purple
    "#d946ef",  # fuchsia
    "#06b6d4",  # cyan
    "#14b8a6",  # teal
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


def _branding(db: Session) -> OrgBrandingResponse:
    name_color = svc.get(db, "org.name_color")
    return OrgBrandingResponse(
        org_name=svc.get(db, "org.name") or "Constellus",
        org_logo_url=svc.get(db, "org.logo_url") or None,
        org_brand_accent=svc.get(db, "org.brand_accent") or "#8b7bf0",
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

    @field_validator("identifying_user_agent")
    @classmethod
    def _ua(cls, v: str | None) -> str | None:
        if v is not None and v != "" and not page_capture.valid_user_agent(v):
            raise ValueError(
                f"identifying_user_agent must be empty or 1-{page_capture.USER_AGENT_MAX} printable ASCII characters"
            )
        return v


def _capture_current(db: Session) -> CaptureSettings:
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
