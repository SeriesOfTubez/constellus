from sqlalchemy.orm import Session

from app.auth.base import AuthProvider, AuthResult
from app.core.auth import verify_password
from app.models.user import User


class LocalAuthProvider(AuthProvider):
    name = "local"

    def __init__(self, db: Session):
        self.db = db

    def authenticate(self, email: str, password: str) -> AuthResult:
        user = self.db.query(User).filter(User.email == email.lower()).first()

        if not user or not user.is_active:
            return AuthResult(success=False, error="Invalid credentials")

        if not verify_password(password, user.hashed_password):
            return AuthResult(success=False, error="Invalid credentials")

        return AuthResult(success=True, user_id=str(user.id), email=user.email)
