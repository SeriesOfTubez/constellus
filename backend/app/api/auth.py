from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth.local import LocalAuthProvider
from app.core.auth import create_access_token, create_refresh_token, decode_token
from app.core.database import get_db
from app.models.user import UserRole
from app.schemas.auth import LoginRequest, RefreshRequest, TokenResponse
from app.schemas.user import UserCreate, UserResponse
from app.services.user import create_user, get_user, get_user_by_email, is_first_run
from app.api.deps import get_current_user
import uuid

router = APIRouter()


@router.post("/setup", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def setup(data: UserCreate, db: Session = Depends(get_db)):
    """Create the first admin user. Only available when no users exist."""
    if not is_first_run(db):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Setup already complete")
    data.role = UserRole.ADMIN
    return create_user(db, data)


@router.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    provider = LocalAuthProvider(db)
    result = provider.authenticate(email=data.email, password=data.password)

    if not result.success:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=result.error)

    user = get_user_by_email(db, data.email)
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    return TokenResponse(
        access_token=create_access_token(str(user.id), user.role),
        refresh_token=create_refresh_token(str(user.id)),
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(data: RefreshRequest, db: Session = Depends(get_db)):
    payload = decode_token(data.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    user = get_user(db, uuid.UUID(payload["sub"]))
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    return TokenResponse(
        access_token=create_access_token(str(user.id), user.role),
        refresh_token=create_refresh_token(str(user.id)),
    )


@router.get("/me", response_model=UserResponse)
def me(current_user=Depends(get_current_user)):
    return current_user
