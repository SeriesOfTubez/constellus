import ipaddress
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from sqlalchemy.orm import Session

from app.core.ssrf import SSRFBlockedError, is_blocked, ssrf_safe_client
from app.models.saml_config import SamlConfig
from app.models.user import User
from app.schemas.saml import IdpMetadataPreview, SamlConfigCreate, SamlConfigUpdate


class LocalAccountLinkBlocked(Exception):
    """Raised when an SSO-asserted email matches an existing account that has
    a local password set. "Same email" isn't "same principal" — auto-linking
    would let anyone who can get an IdP (or a compromised/self-asserted
    email claim) to assert that email silently take over the local account,
    including an admin's. Refused; an administrator must link it explicitly."""

    def __init__(self, email: str):
        self.email = email
        super().__init__(f"Refusing to auto-link SSO identity to local account: {email}")


def _validate_metadata_url(url: str, allowed_host: str | None = None) -> str:
    """Static validation of a metadata URL.

    Network-layer SSRF protection is handled by the SSRFGuardTransport at
    fetch time — that's the real defense, since DNS results can change
    between this check and the actual connection. The checks here are
    static (no DNS) belt-and-braces: scheme, host presence, no embedded
    credentials, and a blocklist pre-check when the host is an IP literal
    (the transport repeats this at request time).
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Metadata URL must use HTTPS")
    host = parsed.hostname
    if not host:
        raise ValueError("Invalid metadata URL: missing host")
    if parsed.username or parsed.password:
        # httpx would forward Basic auth derived from userinfo to the
        # resolved host — a credential-leak vector independent of SSRF.
        raise ValueError("Metadata URL must not contain credentials")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and is_blocked(literal):
        raise ValueError(f"Metadata URL host {host} is on the SSRF blocklist")
    if allowed_host is not None and host.lower() != allowed_host.lower():
        raise ValueError("Metadata URL host does not match the configured IdP host")
    return url


def fetch_metadata_xml(metadata_url: str, allowed_host: str | None = None) -> bytes:
    """Fetch IdP metadata over the SSRF-guarded HTTP client.

    Replaces `OneLogin_Saml2_IdPMetadataParser.get_metadata`, which uses
    `urllib.request.urlopen` and re-resolves DNS — losing the IP we just
    validated. Our guarded transport pins the connection to the IP it
    validated, preserving Host header + TLS SNI for cert verification.
    """
    _validate_metadata_url(metadata_url, allowed_host=allowed_host)
    try:
        with ssrf_safe_client(timeout=15.0) as client:
            resp = client.get(metadata_url, headers={"User-Agent": "Constellus-SAML/1.0"})
            resp.raise_for_status()
            return resp.content
    except SSRFBlockedError as exc:
        raise ValueError(str(exc)) from exc
    except httpx.HTTPError as exc:
        raise ValueError(f"Metadata fetch failed: {exc}") from exc


def parse_metadata(xml: bytes | str) -> IdpMetadataPreview:
    try:
        data = OneLogin_Saml2_IdPMetadataParser.parse(xml)
        idp = data.get("idp", {})
        entity_id = idp.get("entityId", "")
        sso_url = idp.get("singleSignOnService", {}).get("url", "")
        certs = idp.get("x509certMulti", {})
        cert = (
            (certs.get("signing") or certs.get("encryption") or [""])[0]
            if certs else idp.get("x509cert", "")
        )
        cert_subject = f"Certificate present ({len(cert.strip())} chars)" if cert.strip() else None
        return IdpMetadataPreview(
            entity_id=entity_id,
            sso_url=sso_url,
            certificate_subject=cert_subject,
            valid=bool(entity_id and sso_url),
        )
    except Exception as e:
        return IdpMetadataPreview(entity_id="", sso_url="", valid=False, error=str(e))


def get_config(db: Session) -> Optional[SamlConfig]:
    return db.query(SamlConfig).first()


def create_config(db: Session, data: SamlConfigCreate) -> SamlConfig:
    xml = fetch_metadata_xml(data.metadata_url)
    config = SamlConfig(
        metadata_url=data.metadata_url,
        metadata_xml=xml,
        metadata_fetched_at=datetime.now(timezone.utc),
        sp_entity_id=data.sp_entity_id,
        sp_acs_url=data.sp_acs_url,
        jit_provisioning=data.jit_provisioning,
        allow_local_fallback=data.allow_local_fallback,
    )
    db.add(config)
    db.commit()
    db.refresh(config)
    return config


def update_config(db: Session, config: SamlConfig, data: SamlConfigUpdate) -> SamlConfig:
    for field, value in data.model_dump(exclude_none=True).items():
        setattr(config, field, value)

    if data.metadata_url:
        existing_host = urlparse(config.metadata_url).hostname
        config.metadata_xml = fetch_metadata_xml(data.metadata_url, allowed_host=existing_host)
        config.metadata_fetched_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(config)
    return config


def refresh_metadata(db: Session, config: SamlConfig) -> SamlConfig:
    stored_host = urlparse(config.metadata_url).hostname
    config.metadata_xml = fetch_metadata_xml(config.metadata_url, allowed_host=stored_host)
    config.metadata_fetched_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(config)
    return config


def find_or_link_sso_user(
    db: Session,
    email: str,
    sso_subject: str,
    jit_provisioning: bool,
) -> Optional[User]:
    """
    Account-linking logic for seamless SSO transition:

    1. Look up by sso_subject — already linked, return immediately.
    2. Look up by email — existing account with no local password set
       (already SSO-only, or an admin-created stub). Link it to SSO in
       place, preserving role and all settings.
       An existing account that HAS a local password is never auto-linked —
       raises LocalAccountLinkBlocked instead, since "same email" isn't a
       reliable proof of "same principal" and this is the account-takeover
       path (see LocalAccountLinkBlocked docstring).
    3. Not found + JIT enabled — create a new account.
    4. Not found + JIT disabled — return None (login rejected).
    """
    user = db.query(User).filter(User.sso_subject == sso_subject).first()
    if user:
        return user

    user = db.query(User).filter(User.email == email.lower()).first()
    if user:
        if user.hashed_password is not None:
            raise LocalAccountLinkBlocked(email)
        user.auth_provider = "saml"
        user.sso_subject = sso_subject
        db.commit()
        db.refresh(user)
        return user

    if jit_provisioning:
        from app.core.auth import hash_password
        from app.models.user import UserRole
        user = User(
            email=email.lower(),
            hashed_password=None,
            full_name=email.split("@")[0],
            role=UserRole.VIEWER,
            auth_provider="saml",
            sso_subject=sso_subject,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    return None
