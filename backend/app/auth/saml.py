"""
SAML authentication provider.

Uses python3-saml for AuthnRequest generation and Response validation.
The full flow:
  1. GET  /api/auth/saml/login  → generate AuthnRequest, redirect to IdP SSO URL
  2. POST /api/auth/saml/acs    → validate Response, extract NameID/email, link/create user, issue JWT

Requires system packages: libxmlsec1-dev, libxml2-dev, pkg-config
Install: apt-get install xmlsec1 libxmlsec1-dev libxml2-dev pkg-config
"""

from typing import Any, Optional

from app.auth.base import AuthProvider, AuthResult


def _build_saml_settings(config) -> dict[str, Any]:
    """Build python3-saml settings dict from SamlConfig model."""
    from app.services.saml import parse_metadata

    idp_meta = parse_metadata(config.metadata_xml or "")

    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": config.sp_entity_id,
            "assertionConsumerService": {
                "url": config.sp_acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": idp_meta.entity_id,
            "singleSignOnService": {
                "url": idp_meta.sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": _extract_cert(config.metadata_xml or ""),
        },
    }


def _extract_cert(metadata_xml: str) -> str:
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(metadata_xml)
        cert = root.find(".//{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
        return cert.text.strip() if cert is not None and cert.text else ""
    except ET.ParseError:
        return ""


def build_authn_request(config) -> tuple[str, str]:
    """
    Returns (redirect_url, relay_state).
    Raises ImportError if python3-saml is not installed.
    """
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        from onelogin.saml2.utils import OneLogin_Saml2_Utils
    except ImportError as e:
        raise ImportError("python3-saml is required for SAML login. Install system deps first.") from e

    settings = _build_saml_settings(config)
    # python3-saml requires a request-like object; we build a minimal one
    req = {
        "https": "on",
        "http_host": config.sp_acs_url.split("/")[2],
        "script_name": "/api/auth/saml/login",
        "get_data": {},
        "post_data": {},
    }
    auth = OneLogin_Saml2_Auth(req, settings)
    return auth.login(), ""


def validate_saml_response(config, post_data: dict, request_data: dict) -> AuthResult:
    """
    Validate an incoming SAML Response from the IdP.
    Returns AuthResult with email extracted from NameID or attributes.
    """
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
    except ImportError as e:
        return AuthResult(success=False, error="python3-saml not installed")

    settings = _build_saml_settings(config)
    auth = OneLogin_Saml2_Auth(request_data, settings)
    auth.process_response()

    errors = auth.get_errors()
    if errors:
        return AuthResult(success=False, error=f"SAML validation failed: {', '.join(errors)}")

    if not auth.is_authenticated():
        return AuthResult(success=False, error="SAML response not authenticated")

    email = auth.get_nameid()
    if not email:
        attrs = auth.get_attributes()
        email = next(iter(attrs.get("email", attrs.get("emailAddress", [None]))), None)

    if not email:
        return AuthResult(success=False, error="No email in SAML assertion")

    return AuthResult(success=True, email=email, user_id=None)
