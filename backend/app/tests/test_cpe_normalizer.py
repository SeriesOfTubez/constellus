"""Tests for app.services.cpe_normalizer.

Pure-assert style: no pytest dependency required.
Run with:  python -m app.tests.test_cpe_normalizer       (from /app)
       or: pytest app/tests/test_cpe_normalizer.py        (if pytest installed)
"""

from app.services.cpe_normalizer import (
    build_cpe23,
    normalize_port_software,
    _parse_cpe_string,
)


def _by_product(software: list[dict]) -> dict[str, dict]:
    return {s["product"]: s for s in software}


def test_acceptance_full_version_and_cpe():
    """Chunk A acceptance: Apache/2.4.6, PHP/7.4.16, OpenSSL/1.0.2k, nginx,
    OpenSSH → correct cpe + FULL version."""
    cases = [
        ("http", "Apache/2.4.6",   "apache",  "http_server", "2.4.6"),
        ("http", "PHP/7.4.16",     "php",     "php",         "7.4.16"),
        ("http", "OpenSSL/1.0.2k", "openssl", "openssl",     "1.0.2k"),
        ("http", "nginx/1.20.1",   "f5",      "nginx",       "1.20.1"),
        ("ssh",  "OpenSSH 8.9p1 Ubuntu-3ubuntu0.1", "openbsd", "openssh", "8.9p1"),
    ]
    for service, sv, vendor, product, version in cases:
        out = normalize_port_software({"service": service, "service_version": sv})
        assert len(out) == 1, f"{sv!r} → {out!r}"
        sw = out[0]
        assert sw["vendor"] == vendor, f"{sv!r} vendor {sw!r}"
        assert sw["product"] == product, f"{sv!r} product {sw!r}"
        assert sw["version"] == version, f"{sv!r} version {sw!r}"
        assert sw["cpe23"] == f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*", sw
        assert sw["basis"] == "banner_regex", sw


def test_nmap_space_separated_banners():
    """nmap/Shodan product form (space-separated) is caught too, not just the
    httpx Server-header slash form — so banner-only hosts still normalize."""
    cases = [
        ("http", "Apache httpd 2.4.6", "apache", "http_server", "2.4.6"),
        ("http", "nginx 1.21.6",       "f5",     "nginx",       "1.21.6"),
        ("ssh",  "OpenSSH 8.7",        "openbsd", "openssh",    "8.7"),
    ]
    for service, sv, vendor, product, version in cases:
        out = normalize_port_software({"service": service, "service_version": sv})
        assert len(out) == 1, f"{sv!r} → {out!r}"
        assert (out[0]["vendor"], out[0]["product"], out[0]["version"]) == (vendor, product, version), out


def test_apache_tomcat_not_misparsed():
    """`Apache Tomcat/9.0.50` and `Apache-Coyote/1.1` must NOT match http_server."""
    for sv in ("Apache Tomcat/9.0.50", "Apache-Coyote/1.1"):
        out = normalize_port_software({"service": "http", "service_version": sv})
        assert all(s["product"] != "http_server" for s in out), f"{sv!r} → {out!r}"


def test_multi_product_server_header():
    """A real Apache Server header advertises 3 products in one string — all 3
    must be emitted with their own full versions."""
    sv = "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16"
    out = normalize_port_software({"service": "http", "service_version": sv})
    byp = _by_product(out)
    assert set(byp) == {"http_server", "openssl", "php"}, byp
    assert byp["http_server"]["version"] == "2.4.6"
    assert byp["openssl"]["version"] == "1.0.2k"   # -fips suffix stripped
    assert byp["php"]["version"] == "7.4.16"
    assert byp["http_server"]["vendor"] == "apache"
    assert byp["openssl"]["vendor"] == "openssl"


def test_shodan_cpe_parsed():
    """Shodan per-port cpe[] (CPE 2.3) is folded in as authoritative."""
    out = normalize_port_software({
        "service": "ssh",
        "cpe": ["cpe:2.3:a:openbsd:openssh:8.9p1"],
    })
    assert len(out) == 1, out
    sw = out[0]
    assert (sw["vendor"], sw["product"], sw["version"]) == ("openbsd", "openssh", "8.9p1")
    assert sw["basis"] == "shodan_cpe"


def test_shodan_cpe_22_format():
    """Legacy CPE 2.2 (cpe:/a:...) also parses."""
    sw = _parse_cpe_string("cpe:/a:apache:http_server:2.4.6")
    assert sw is not None
    assert (sw["vendor"], sw["product"], sw["version"]) == ("apache", "http_server", "2.4.6")


def test_shodan_cpe_wildcard_dropped():
    """A versionless/wildcard CPE is not matchable → dropped."""
    assert _parse_cpe_string("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*") is None
    assert _parse_cpe_string("cpe:2.3:a:nginx:nginx:-") is None


def test_dedupe_prefers_shodan():
    """Banner + Shodan agree on OpenSSH 8.9p1 → one entry, shodan_cpe basis."""
    out = normalize_port_software({
        "service": "ssh",
        "service_version": "OpenSSH 8.9p1 Ubuntu-3ubuntu0.1",
        "cpe": ["cpe:2.3:a:openbsd:openssh:8.9p1"],
    })
    assert len(out) == 1, out
    assert out[0]["basis"] == "shodan_cpe", out


def test_mysql_gated_on_service():
    """The loose bare-version MySQL pattern only fires on the mysql service."""
    assert normalize_port_software(
        {"service": "http", "service_version": "8.0.31-0ubuntu0.1"}
    ) == []
    out = normalize_port_software(
        {"service": "mysql", "service_version": "8.0.31-0ubuntu0.1"}
    )
    assert len(out) == 1 and out[0]["product"] == "mysql"
    assert out[0]["vendor"] == "oracle" and out[0]["version"] == "8.0.31"


def test_no_software_signal():
    assert normalize_port_software({"service": "https"}) == []
    assert normalize_port_software({}) == []


def test_build_cpe23():
    assert build_cpe23("php", "php", "7.4.16") == "cpe:2.3:a:php:php:7.4.16:*:*:*:*:*:*:*"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
