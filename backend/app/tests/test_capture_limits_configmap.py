"""The Kubernetes proxy-limits sink (planning#324 slice 2). No database."""

import datetime
import http.server
import json
import ssl
import threading

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.services import capture_limits_configmap as m
from app.services import page_capture
from app.services.capture_limits_configmap import ConfigMapSinkError, write_configmap_limits

WANT = b'{"connect_timeout_s":10,"idle_timeout_s":30,"max_connections":256,"version":1}\n'
URL = "https://10.96.0.1/api/v1/namespaces/constellus/configmaps/capture-proxy-limits"


@pytest.fixture
def sa(tmp_path, monkeypatch):
    d = tmp_path / "sa"
    d.mkdir()
    (d / "token").write_text("tok-1\n")
    (d / "namespace").write_text("constellus\n")
    (d / "ca.crt").write_text("-----BEGIN CERTIFICATE-----\nxx\n-----END CERTIFICATE-----\n")
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")
    monkeypatch.delenv("CAPTURE_LIMITS_CONFIGMAP", raising=False)
    return str(d)


class FakeApi:
    def __init__(self, data=None, get_status=200, patch_status=200, get_body=None, get_headers=None, raises=None):
        self.data = data
        self.get_status = get_status
        self.patch_status = patch_status
        self.get_body = get_body
        self.get_headers = get_headers or {}
        self.raises = raises
        self.requests = []

    def handler(self, request):
        self.requests.append(request)
        if self.raises:
            raise self.raises
        if request.method == "GET":
            if self.get_body is not None:
                return httpx.Response(self.get_status, content=self.get_body, headers=self.get_headers)
            if self.get_status == 404:
                return httpx.Response(404, json={"kind": "Status", "code": 404})
            if self.get_status != 200:
                return httpx.Response(self.get_status, json={"kind": "Status"}, headers=self.get_headers)
            body = {"kind": "ConfigMap", "apiVersion": "v1", "metadata": {"name": "x", "namespace": "y"}}
            if self.data is not None:
                body["data"] = self.data
            return httpx.Response(200, json=body)
        return httpx.Response(self.patch_status, json={})

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self.handler))


def equal_api(**kw):
    return FakeApi(data={"proxy_limits.json": WANT.decode()}, **kw)


def test_key_matches_the_file_name():
    assert m.CONFIGMAP_KEY == page_capture.PROXY_LIMITS_FILE


def test_equal_content_is_a_noop(sa):
    api = equal_api()
    assert write_configmap_limits(WANT, client=api.client(), sa_dir=sa) is False
    assert len(api.requests) == 1
    r = api.requests[0]
    assert r.method == "GET" and str(r.url) == URL
    assert r.headers["Authorization"] == "Bearer tok-1"
    assert "json" in r.headers["Accept"]


def test_different_content_patches(sa):
    api = FakeApi(data={"proxy_limits.json": "old"})
    assert write_configmap_limits(WANT, client=api.client(), sa_dir=sa) is True
    assert [r.method for r in api.requests] == ["GET", "PATCH"]
    p = api.requests[1]
    assert str(p.url) == URL
    assert p.headers["Content-Type"] == "application/merge-patch+json"
    assert json.loads(p.content) == {"data": {"proxy_limits.json": WANT.decode()}}
    assert p.headers["Authorization"] == "Bearer tok-1"


def test_configmap_without_data_is_patched(sa):
    api = FakeApi()
    assert write_configmap_limits(WANT, client=api.client(), sa_dir=sa) is True
    assert [r.method for r in api.requests] == ["GET", "PATCH"]


def test_missing_configmap_logs_and_does_not_create(sa, caplog):
    api = FakeApi(get_status=404)
    assert write_configmap_limits(WANT, client=api.client(), sa_dir=sa) is False
    assert [r.method for r in api.requests] == ["GET"]
    assert "is missing" in caplog.text


def test_get_forbidden_raises(sa):
    api = FakeApi(get_status=403)
    with pytest.raises(ConfigMapSinkError) as ei:
        write_configmap_limits(WANT, client=api.client(), sa_dir=sa)
    assert isinstance(ei.value, OSError)
    assert len(api.requests) == 1


def test_patch_conflict_raises(sa):
    api = FakeApi(patch_status=409)
    with pytest.raises(ConfigMapSinkError):
        write_configmap_limits(WANT, client=api.client(), sa_dir=sa)
    assert [r.method for r in api.requests] == ["GET", "PATCH"]


def test_transport_error_never_leaks_the_token(sa):
    api = FakeApi(raises=httpx.ConnectError("boom"))
    with pytest.raises(ConfigMapSinkError) as ei:
        write_configmap_limits(WANT, client=api.client(), sa_dir=sa)
    assert len(api.requests) == 1
    e = ei.value
    seen = 0
    while e is not None:
        seen += 1
        assert "tok-1" not in str(e) and "tok-1" not in repr(e)
        e = e.__cause__
    assert seen >= 2


def test_redirect_is_not_followed(sa):
    api = FakeApi(get_status=302, get_headers={"Location": "https://elsewhere.example.invalid/x"})
    # The production client has follow_redirects=False; use the same setting on the mock client.
    c = httpx.Client(transport=httpx.MockTransport(api.handler), follow_redirects=False)
    with pytest.raises(ConfigMapSinkError, match="HTTP 302"):
        write_configmap_limits(WANT, client=c, sa_dir=sa)
    assert len(api.requests) == 1


def test_production_client_does_not_follow_redirects_or_trust_env():
    c = None
    try:
        import certifi
        c = m._client(certifi.where())
        assert c.follow_redirects is False
        assert c.trust_env is False
    finally:
        if c is not None:
            c.close()


def test_token_is_reread_each_call(sa):
    api = equal_api()
    write_configmap_limits(WANT, client=api.client(), sa_dir=sa)
    (__import__("pathlib").Path(sa) / "token").write_text("tok-2\n")
    write_configmap_limits(WANT, client=api.client(), sa_dir=sa)
    assert [r.headers["Authorization"] for r in api.requests] == ["Bearer tok-1", "Bearer tok-2"]


def test_namespace_comes_from_the_file(sa):
    from pathlib import Path
    Path(sa, "namespace").write_text("other-ns\n")
    api = equal_api()
    write_configmap_limits(WANT, client=api.client(), sa_dir=sa)
    assert len(api.requests) == 1
    assert "/namespaces/other-ns/" in api.requests[0].url.path


def test_bad_namespace_raises_before_any_request(sa):
    from pathlib import Path
    Path(sa, "namespace").write_text("Bad_NS\n")
    api = equal_api()
    with pytest.raises(ConfigMapSinkError):
        write_configmap_limits(WANT, client=api.client(), sa_dir=sa)
    assert api.requests == []


def test_configmap_name_override(sa, monkeypatch):
    monkeypatch.setenv("CAPTURE_LIMITS_CONFIGMAP", "my-limits")
    api = equal_api()
    write_configmap_limits(WANT, client=api.client(), sa_dir=sa)
    assert len(api.requests) == 1
    assert api.requests[0].url.path.endswith("/configmaps/my-limits")


@pytest.mark.parametrize("bad", ["Bad_Name", "a" * 254])
def test_bad_configmap_name_raises(sa, monkeypatch, bad):
    monkeypatch.setenv("CAPTURE_LIMITS_CONFIGMAP", bad)
    api = equal_api()
    with pytest.raises(ConfigMapSinkError):
        write_configmap_limits(WANT, client=api.client(), sa_dir=sa)
    assert api.requests == []


def test_ipv6_host_is_bracketed(sa, monkeypatch):
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "fd00::1")
    api = equal_api()
    write_configmap_limits(WANT, client=api.client(), sa_dir=sa)
    assert len(api.requests) == 1
    assert api.requests[0].url.host == "fd00::1"
    assert "[fd00::1]" in str(api.requests[0].url)


def test_custom_port(sa, monkeypatch):
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "6443")
    api = equal_api()
    write_configmap_limits(WANT, client=api.client(), sa_dir=sa)
    assert len(api.requests) == 1
    assert api.requests[0].url.port == 6443


def test_unset_host_raises(sa, monkeypatch):
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST")
    api = equal_api()
    with pytest.raises(ConfigMapSinkError):
        write_configmap_limits(WANT, client=api.client(), sa_dir=sa)
    assert api.requests == []


def test_bad_port_raises(sa, monkeypatch):
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "abc")
    api = equal_api()
    with pytest.raises(ConfigMapSinkError):
        write_configmap_limits(WANT, client=api.client(), sa_dir=sa)
    assert api.requests == []


def test_missing_token_raises(sa):
    from pathlib import Path
    Path(sa, "token").unlink()
    api = equal_api()
    with pytest.raises(ConfigMapSinkError):
        write_configmap_limits(WANT, client=api.client(), sa_dir=sa)
    assert api.requests == []


def test_missing_ca_raises(sa):
    from pathlib import Path
    Path(sa, "ca.crt").unlink()
    api = equal_api()
    with pytest.raises(ConfigMapSinkError):
        write_configmap_limits(WANT, client=api.client(), sa_dir=sa)
    assert api.requests == []


def test_blank_token_raises(sa):
    from pathlib import Path
    Path(sa, "token").write_text("  \n")
    api = equal_api()
    with pytest.raises(ConfigMapSinkError):
        write_configmap_limits(WANT, client=api.client(), sa_dir=sa)
    assert api.requests == []


def test_oversized_response_raises(sa):
    api = FakeApi(get_body=b"x" * (m.MAX_RESPONSE_BYTES + 1))
    with pytest.raises(ConfigMapSinkError, match="larger than"):
        write_configmap_limits(WANT, client=api.client(), sa_dir=sa)
    assert [r.method for r in api.requests] == ["GET"]


def test_non_json_response_raises(sa):
    api = FakeApi(get_body=b"<html>not json</html>")
    with pytest.raises(ConfigMapSinkError, match="not JSON"):
        write_configmap_limits(WANT, client=api.client(), sa_dir=sa)
    assert [r.method for r in api.requests] == ["GET"]


# ── real TLS pinning ─────────────────────────────────────────────────────────


def _ca(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf(ca_key, ca_cert):
    import ipaddress
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(ca_cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _pem_cert(c):
    return c.public_bytes(serialization.Encoding.PEM)


def test_tls_is_pinned_to_the_service_account_ca(sa, tmp_path, monkeypatch):
    from pathlib import Path
    ca_key, ca_cert = _ca("test-ca-one")
    _, other_cert = _ca("test-ca-two")
    leaf_key, leaf_cert = _leaf(ca_key, ca_cert)
    certfile = tmp_path / "server.pem"
    certfile.write_bytes(
        _pem_cert(leaf_cert)
        + leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("Authorization"))
            body = json.dumps({"kind": "ConfigMap", "data": {"proxy_limits.json": WANT.decode()}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(certfile))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "127.0.0.1")
        monkeypatch.setenv("KUBERNETES_SERVICE_PORT", str(srv.server_address[1]))
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
        monkeypatch.setenv("https_proxy", "http://127.0.0.1:9")
        Path(sa, "ca.crt").write_bytes(_pem_cert(ca_cert))
        assert write_configmap_limits(WANT, sa_dir=sa) is False
        assert seen == ["Bearer tok-1"]
        Path(sa, "ca.crt").write_bytes(_pem_cert(other_cert))
        with pytest.raises(ConfigMapSinkError):
            write_configmap_limits(WANT, sa_dir=sa)
        assert seen == ["Bearer tok-1"]
    finally:
        srv.shutdown()
        srv.server_close()
