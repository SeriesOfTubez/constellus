"""CAB token minting (planning#322 slice 2b-2). No database, no real Google call: google-auth's
entry points are replaced by fakes; the boundary classes are the real ones."""

from datetime import datetime, timezone

import google.auth
import pytest
from google.auth import downscoped, impersonated_credentials

from app.services import capture_token_minter as m
from app.services.capture_store import StoreConfigError
from app.services.capture_store_s3 import GCS_DATA_SCOPE, GCS_SIGN_SCOPE, S3Buckets, S3Config

EMAIL = "backend@example-project.iam.gserviceaccount.com"
FAKE_TOKEN = "ya29.fake-secret-token"


def cfg(jobs="jobs-bucket", proxylog="proxylog-bucket"):
    return S3Config(
        endpoint="https://storage.googleapis.com", public_endpoint=None, region="auto", access_key=None,
        secret_key=None, path_style=True, auth="gcs-wi",
        buckets=S3Buckets(jobs=jobs, results="results-bucket", proxylog=proxylog, images="images-bucket"))


def test_exact_worker_and_proxy_boundaries():
    b = m.boundaries(cfg())
    assert set(b) == {"worker", "proxy"}
    w, p = b["worker"], b["proxy"]
    assert (w.consumer, w.bucket, w.role, w.prefix) == ("worker", "jobs-bucket", "roles/storage.objectViewer", "jobs/")
    assert w.expression == (
        "resource.name.startsWith('projects/_/buckets/jobs-bucket/objects/jobs/') || "
        "api.getAttribute('storage.googleapis.com/objectListPrefix', '').startsWith('jobs/')")
    assert (p.consumer, p.bucket, p.role, p.prefix) == ("proxy", "proxylog-bucket", "roles/storage.objectCreator", "proxylog/")
    assert p.expression == "resource.name.startsWith('projects/_/buckets/proxylog-bucket/objects/proxylog/')"


@pytest.mark.parametrize("bad", ["a'b-bucket", "a\\b-bucket", "Upper-bucket", "a", "ab", "-lead-bucket", "trail-bucket-", "a b-bucket", ""])
def test_bad_bucket_names_are_refused(bad):
    with pytest.raises(StoreConfigError):
        m.boundaries(cfg(jobs=bad))
    with pytest.raises(StoreConfigError):
        m.boundaries(cfg(proxylog=bad))


def test_valid_dotted_and_underscored_bucket_names_pass():
    b = m.boundaries(cfg(jobs="my.jobs_bucket-1", proxylog="abc"))
    assert b["worker"].bucket == "my.jobs_bucket-1" and b["proxy"].bucket == "abc"


def test_fingerprint_is_stable_and_changes_with_the_bucket():
    a1 = m.fingerprint(m.boundaries(cfg())["worker"])
    a2 = m.fingerprint(m.boundaries(cfg())["worker"])
    c = m.fingerprint(m.boundaries(cfg(jobs="other-jobs-bucket"))["worker"])
    assert a1 == a2 and len(a1) == 64
    assert a1 != c
    assert m.fingerprint(m.boundaries(cfg())["worker"]) != m.fingerprint(m.boundaries(cfg())["proxy"])


# ── make_source ──────────────────────────────────────────────────────────────


class FakeSigning:
    def __init__(self, email=EMAIL, refresh_raises=None):
        self.service_account_email = email
        self.refreshed = 0
        self._raises = refresh_raises

    def refresh(self, request):
        self.refreshed += 1
        if self._raises:
            raise self._raises


@pytest.fixture
def fake_google(monkeypatch):
    state = {"default_scopes": None, "imp": None, "signing": FakeSigning()}

    def default(scopes=None, **kw):
        state["default_scopes"] = scopes
        return state["signing"], "example-project"

    class Imp:
        def __init__(self, **kw):
            state["imp"] = kw

    monkeypatch.setattr(google.auth, "default", default)
    monkeypatch.setattr(impersonated_credentials, "Credentials", Imp)
    return state


def test_make_source_impersonates_itself_for_the_data_scope(fake_google):
    src = m.make_source()
    kw = fake_google["imp"]
    assert src is not None and kw is not None  # the impersonation was REACHED
    assert fake_google["default_scopes"] == [GCS_SIGN_SCOPE]
    assert fake_google["signing"].refreshed == 1
    assert kw["source_credentials"] is fake_google["signing"]
    assert kw["target_principal"] == EMAIL
    assert kw["target_scopes"] == [GCS_DATA_SCOPE]
    assert kw["lifetime"] == 3600


@pytest.mark.parametrize("email", ["default", "", None, "no-at-sign"])
def test_make_source_rejects_a_bad_identity(fake_google, email):
    fake_google["signing"] = FakeSigning(email=email)
    with pytest.raises(m.MintError, match="^source: ValueError$"):
        m.make_source()
    assert fake_google["signing"].refreshed == 1  # reached the identity check
    assert fake_google["imp"] is None


def test_make_source_error_carries_the_type_name_only(fake_google):
    fake_google["signing"] = FakeSigning(refresh_raises=RuntimeError(f"boom https://x/?t={FAKE_TOKEN}"))
    with pytest.raises(m.MintError) as ei:
        m.make_source()
    assert fake_google["signing"].refreshed == 1
    assert str(ei.value) == "source: RuntimeError"
    assert FAKE_TOKEN not in repr(ei.value)
    assert ei.value.__cause__ is None and ei.value.__suppress_context__


# ── mint ─────────────────────────────────────────────────────────────────────


@pytest.fixture
def fake_downscoped(monkeypatch):
    state = {"made": []}

    class Creds:
        token_value = FAKE_TOKEN
        expiry_value = datetime(2026, 11, 2, 10, 0, 0)  # naive UTC, as google-auth returns it
        raises = None

        def __init__(self, source_credentials, credential_access_boundary):
            self.source = source_credentials
            self.cab = credential_access_boundary
            self.token = None
            self.expiry = None
            state["made"].append(self)

        def refresh(self, request):
            if Creds.raises:
                raise Creds.raises
            self.token, self.expiry = Creds.token_value, Creds.expiry_value

    state["cls"] = Creds
    monkeypatch.setattr(downscoped, "Credentials", Creds)
    return state


def test_mint_builds_the_rule_and_returns_aware_utc(fake_downscoped):
    b = m.boundaries(cfg())["worker"]
    src = object()
    out = m.mint(src, b)
    c = fake_downscoped["made"][0]
    assert c.source is src
    rule = c.cab.rules[0]
    assert rule.available_resource == "//storage.googleapis.com/projects/_/buckets/jobs-bucket"
    assert list(rule.available_permissions) == ["inRole:roles/storage.objectViewer"]
    assert rule.availability_condition.expression == b.expression
    assert out.token == FAKE_TOKEN
    assert out.expires_at == datetime(2026, 11, 2, 10, 0, 0, tzinfo=timezone.utc)
    assert out.expires_at.utcoffset().total_seconds() == 0


def test_mint_empty_token_is_an_error(fake_downscoped):
    fake_downscoped["cls"].token_value = ""
    with pytest.raises(m.MintError, match="^mint worker: ValueError$"):
        m.mint(object(), m.boundaries(cfg())["worker"])
    assert len(fake_downscoped["made"]) == 1  # reached the refresh


def test_mint_missing_expiry_is_an_error(fake_downscoped):
    fake_downscoped["cls"].expiry_value = None
    with pytest.raises(m.MintError, match="^mint proxy: ValueError$"):
        m.mint(object(), m.boundaries(cfg())["proxy"])
    assert len(fake_downscoped["made"]) == 1


def test_mint_exception_text_never_propagates(fake_downscoped):
    fake_downscoped["cls"].raises = RuntimeError(f"sts said {FAKE_TOKEN}")
    with pytest.raises(m.MintError) as ei:
        m.mint(object(), m.boundaries(cfg())["worker"])
    assert len(fake_downscoped["made"]) == 1
    assert str(ei.value) == "mint worker: RuntimeError"
    assert FAKE_TOKEN not in repr(ei.value) and ei.value.__cause__ is None
