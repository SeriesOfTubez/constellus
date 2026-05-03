from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.api.deps import require_role
from app.core.auth import create_access_token, create_refresh_token
from app.core.database import get_db
from app.models.user import UserRole
from app.schemas.saml import (
    IdpMetadataPreview,
    SamlConfigCreate,
    SamlConfigResponse,
    SamlConfigUpdate,
)
from app.services import saml as saml_svc

router = APIRouter()


# ── Config management (Integration Admin only) ────────────────────────────────

@router.get("/config", response_model=SamlConfigResponse)
def get_config(
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    config = saml_svc.get_config(db)
    if not config:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SAML not configured")
    return config


@router.post("/config", response_model=SamlConfigResponse, status_code=status.HTTP_201_CREATED)
def create_config(
    data: SamlConfigCreate,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    if saml_svc.get_config(db):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="SAML config already exists — use PATCH to update")
    try:
        return saml_svc.create_config(db, data)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Failed to fetch metadata: {e}")


@router.patch("/config", response_model=SamlConfigResponse)
def update_config(
    data: SamlConfigUpdate,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    config = saml_svc.get_config(db)
    if not config:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SAML not configured")
    try:
        return saml_svc.update_config(db, config, data)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Failed to fetch metadata: {e}")


@router.post("/config/refresh-metadata", response_model=SamlConfigResponse)
def refresh_metadata(
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Re-fetch and cache the IdP metadata XML from the configured URL."""
    config = saml_svc.get_config(db)
    if not config:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SAML not configured")
    try:
        return saml_svc.refresh_metadata(db, config)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Failed to fetch metadata: {e}")


@router.get("/config/preview-metadata", response_model=IdpMetadataPreview)
def preview_metadata(
    metadata_url: str,
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """
    Fetch and parse a metadata URL without saving it.
    Used by the UI to show the admin what the IdP config looks like before committing.
    """
    try:
        xml = saml_svc.fetch_metadata_xml(metadata_url)
        return saml_svc.parse_metadata(xml)
    except Exception as e:
        return IdpMetadataPreview(entity_id="", sso_url="", valid=False, error=str(e))


# ── SAML auth flow ─────────────────────────────────────────────────────────────

@router.get("/login")
def saml_login(db: Session = Depends(get_db)):
    """Initiate SAML login — redirects to IdP SSO URL."""
    config = saml_svc.get_config(db)
    if not config or not config.enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SAML not enabled")
    try:
        from app.auth.saml import build_authn_request
        redirect_url, _ = build_authn_request(config)
        return RedirectResponse(url=redirect_url)
    except ImportError as e:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(e))


@router.post("/acs")
async def saml_acs(request: Request, db: Session = Depends(get_db)):
    """
    Assertion Consumer Service — IdP posts the SAML Response here.
    Validates the response, links or creates the user account, issues JWT.
    """
    config = saml_svc.get_config(db)
    if not config or not config.enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SAML not enabled")

    form = await request.form()
    post_data = dict(form)

    request_data = {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.url.hostname,
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": post_data,
    }

    from app.auth.saml import validate_saml_response
    result = validate_saml_response(config, post_data, request_data)

    if not result.success:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=result.error)

    user = saml_svc.find_or_link_sso_user(
        db=db,
        email=result.email,
        sso_subject=result.email,
        jit_provisioning=config.jit_provisioning,
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No account found and JIT provisioning is disabled. Contact your administrator.",
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    return {
        "access_token": create_access_token(str(user.id), user.role),
        "refresh_token": create_refresh_token(str(user.id)),
        "token_type": "bearer",
    }
