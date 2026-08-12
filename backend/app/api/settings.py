import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import require_role
from app.core.database import get_db
from app.models.user import UserRole
from app.services import aggressiveness as aggr
from app.services import app_settings as svc

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
    _=Depends(require_role(UserRole.ADMIN)),
):
    return _current(db)


@router.put("/", response_model=SettingsResponse)
def update_settings(
    data: SettingsUpdate,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
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
