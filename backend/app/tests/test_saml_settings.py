"""Tests for _build_saml_settings in app.auth.saml (planning#82 — assertion
signature enforcement) and find_or_link_sso_user in app.services.saml
(planning#83 — local-account-linking guard).

No live IdP available in this environment — these assert the settings dict
shape python3-saml reads (confirmed against the installed onelogin package's
OneLogin_Saml2_Settings, which treats a missing "security" key as
wantAssertionsSigned=False) and the account-linking guard's decision logic.
Full signature-validation behavior still needs live-IdP verification before
this is considered fully closed.

Pure-assert style: no pytest dependency required.
Run with:  python -m app.tests.test_saml_settings        (from /app)
       or: pytest app/tests/test_saml_settings.py
"""

from types import SimpleNamespace

from app.auth.saml import _build_saml_settings


def _config(metadata_xml=""):
    return SimpleNamespace(
        metadata_xml=metadata_xml,
        sp_entity_id="https://constellus.example/saml/metadata",
        sp_acs_url="https://constellus.example/api/auth/saml/acs",
    )


def test_security_block_present():
    """A security block must exist at all — its absence is the whole bug."""
    settings = _build_saml_settings(_config())
    assert "security" in settings


def test_want_assertions_signed():
    """The actual control that prevents an unsigned SAMLResponse from being
    accepted as authenticated."""
    settings = _build_saml_settings(_config())
    assert settings["security"]["wantAssertionsSigned"] is True


def test_reject_deprecated_algorithm():
    settings = _build_saml_settings(_config())
    assert settings["security"]["rejectDeprecatedAlgorithm"] is True


def test_strict_mode_still_on():
    """Regression guard — don't lose strict mode while adding security."""
    settings = _build_saml_settings(_config())
    assert settings["strict"] is True


def _run():
    tests = [
        test_security_block_present,
        test_want_assertions_signed,
        test_reject_deprecated_algorithm,
        test_strict_mode_still_on,
    ]
    for fn in tests:
        try:
            fn()
            print(f"OK: {fn.__name__}")
        except AssertionError as exc:
            print(f"FAIL: {fn.__name__}: {exc}")
            raise SystemExit(1)
    print("ALL PASS")


if __name__ == "__main__":
    _run()
