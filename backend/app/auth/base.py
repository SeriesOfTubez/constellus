from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class AuthResult:
    success: bool
    user_id: Optional[str] = None
    email: Optional[str] = None
    error: Optional[str] = None


class AuthProvider(ABC):
    """
    All authentication methods implement this interface.
    After a successful auth, JWT tokens are issued regardless of provider.
    Add SAML or OIDC by implementing this class — nothing else changes.
    """

    name: str

    @abstractmethod
    def authenticate(self, **credentials) -> AuthResult:
        ...
