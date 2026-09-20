import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.user import UserRole
from app.schemas.user import UserCreate, UserResponse, UserUpdate
from app.services import audit
from app.services.user import create_user, get_user, get_user_by_email, list_users, update_user

router = APIRouter()


@router.get("/", response_model=list[UserResponse])
def get_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    return list_users(db, skip=skip, limit=limit)


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create(
    data: UserCreate,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    if get_user_by_email(db, data.email):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")
    return create_user(db, data)


@router.get("/{user_id}", response_model=UserResponse)
def get_one(
    user_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    # Users can view their own profile; admins can view anyone
    if str(current_user.id) != str(user_id) and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    user = get_user(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.patch("/{user_id}", response_model=UserResponse)
def update(
    request: Request,
    user_id: uuid.UUID,
    data: UserUpdate,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    user = get_user(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # planning#194 — "who changed this role" is only useful with "from what,
    # to what", and the middleware cannot know the old value. Captured before
    # the update, recorded by the choke point after the response.
    before = {"role": user.role, "is_active": user.is_active}
    result = update_user(db, user, data)
    changed = {
        field: {"from": was, "to": getattr(result, field)}
        for field, was in before.items()
        if getattr(result, field) != was
    }
    if changed:
        audit.record_detail(request, **changed)
    return result
