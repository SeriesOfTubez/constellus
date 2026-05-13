import ipaddress
import socket
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from sqlalchemy.orm import Session

from app.models.saml_config import SamlConfig
from app.models.user import User
from app.schemas.saml import IdpMetadataPreview, SamlConfigCreate, SamlConfigUpdate

_BLOCKED_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / AWS metadata
    ipaddress.ip_network("100.64.0.0/10"),   # RFC 6598 shared address space
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def _validate_metadata_url(url: str, allowed_host: str | None = None) -> None:
    """
    Validate a metadata URL before passing it to the library.
    python3-saml explicitly documents that callers are responsible for URL validation.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Metadata URL must use HTTPS")
    host = parsed.hostname
    if not host:
        raise ValueError("Invalid metadata URL: missing host")
    if allowed_host is not None and host.lower() != allowed_host.lower():
        raise ValueError("Metadata URL host does not match the configured IdP host")
    try:
        resolved = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve metadata URL host: {exc}") from exc
    for _family, _type, _proto, _canon, sockaddr in resolved:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_loopback or ip.is_reserved or any(ip in net for net in _BLOCKED_NETWORKS):
            raise ValueError("Metadata URL resolves to a private or reserved address")


def fetch_metadata_xml(metadata_url: str, allowed_host: str | None = None) -> bytes:
    _validate_metadata_url(metadata_url, allowed_host=allowed_host)
    return OneLogin_Saml2_IdPMetadataParser.get_metadata(metadata_url, validate_cert=True, timeout=15)


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
    2. Look up by email — existing local account.
       Link it to SSO in place, preserving role and all settings.
    3. Not found + JIT enabled — create a new account.
    4. Not found + JIT disabled — return None (login rejected).
    """
    user = db.query(User).filter(User.sso_subject == sso_subject).first()
    if user:
        return user

    user = db.query(User).filter(User.email == email.lower()).first()
    if user:
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
