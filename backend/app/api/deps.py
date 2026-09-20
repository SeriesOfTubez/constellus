from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.auth import decode_token
from app.core.database import get_db
from app.models.user import User, UserRole
from app.services.user import get_user
import uuid

bearer = HTTPBearer()


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    payload = decode_token(credentials.credentials)
    if not payload or payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    user = get_user(db, uuid.UUID(payload["sub"]))
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    # The audit choke point (planning#194). This is the one dependency every
    # authenticated route resolves — `require_role` depends on it — so
    # stashing the principal here makes "authenticated" and "audited" the
    # same set by construction. `services/audit.AuditMiddleware` reads it
    # back off the ASGI scope once the response is out; a route that forgets
    # to call anything still gets a row.
    #
    # The ID, not the `User` — deliberately. `get_db`'s session is closed
    # when the response is generated, which is BEFORE the middleware runs,
    # so a `User` handed across that boundary is detached and expired and
    # every attribute access on it raises DetachedInstanceError. A UUID
    # survives; the read endpoint joins back to `users` for the name.
    request.state.audit_actor_id = user.id

    return user


def require_role(*roles: UserRole):
    def dependency(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in [r.value for r in roles]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return current_user
    return dependency
