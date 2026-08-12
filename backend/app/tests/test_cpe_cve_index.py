"""Tests for app.services.cpe_cve_index.parse_configurations + the
cpe_normalizer canonical/alias helpers.

Pure-assert style: no pytest dependency required.
Run with:  python -m app.tests.test_cpe_cve_index        (from /app)
       or: pytest app/tests/test_cpe_cve_index.py         (if pytest installed)
"""

from datetime import datetime, timezone

from app.services.cpe_cve_index import parse_configurations
from app.services.cpe_normalizer import to_canonical_product, split_cpe

NOW = datetime(2026, 6, 20, tzinfo=timezone.utc)


def _cfg(*cpematches):
    return [{"nodes": [{"cpeMatch": list(cpematches)}]}]


def test_canonical_and_alias_resolution():
    assert to_canonical_product("apache", "http_server") == ("apache", "http_server")
    assert to_canonical_product("f5", "nginx") == ("f5", "nginx")
    assert to_canonical_product("nginx", "nginx") == ("f5", "nginx")          # alias
    assert to_canonical_product("oracle", "mysql_server") == ("oracle", "mysql")  # alias
    assert to_canonical_product("mysql", "mysql") == ("oracle", "mysql")      # alias
    assert to_canonical_product("microsoft", "iis") is None                   # out of scope


def test_split_cpe():
    assert split_cpe("cpe:2.3:a:apache:http_server:2.4.6:*:*:*:*:*:*:*") == (
        "a", "apache", "http_server", "2.4.6")
    assert split_cpe("cpe:/a:openssl:openssl:1.0.2k") == ("a", "openssl", "openssl", "1.0.2k")
    assert split_cpe("not-a-cpe") is None


def test_range_row_fixed_version():
    """CVE-2017-3167 shape: Apache 2.4.0 ≤ v < 2.4.26 → versionEndExcluding is
    the fixed version (#34's input)."""
    rows = parse_configurations("CVE-2017-3167", _cfg(
        {"criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "vulnerable": True,
         "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.26"},
        {"criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "vulnerable": True,
         "versionStartIncluding": "2.2.0", "versionEndExcluding": "2.2.33"},
    ), "nvd", NOW)
    assert len(rows) == 2, rows
    r = next(r for r in rows if r["version_start_including"] == "2.4.0")
    assert (r["vendor"], r["product"]) == ("apache", "http_server")
    assert r["version_end_excluding"] == "2.4.26"
    assert r["exact_version"] is None and r["all_versions"] is False
    assert r["cve_id"] == "CVE-2017-3167"


def test_exact_version_row():
    """CVE-2021-41773 shape: exact 2.4.49, no range → exact_version."""
    rows = parse_configurations("CVE-2021-41773", _cfg(
        {"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "vulnerable": True},
    ), "nvd", NOW)
    assert len(rows) == 1, rows
    assert rows[0]["exact_version"] == "2.4.49"
    assert rows[0]["all_versions"] is False
    assert all(rows[0][k] is None for k in (
        "version_start_including", "version_end_excluding"))


def test_alias_folded_to_canonical():
    """An NVD nginx:nginx cpeMatch lands under canonical f5:nginx."""
    rows = parse_configurations("CVE-2019-20372", _cfg(
        {"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "vulnerable": True,
         "versionStartIncluding": "0.7.12", "versionEndExcluding": "1.17.7"},
    ), "nvd", NOW)
    assert len(rows) == 1
    assert (rows[0]["vendor"], rows[0]["product"]) == ("f5", "nginx")


def test_out_of_scope_and_nonvuln_skipped():
    rows = parse_configurations("CVE-2021-44790", _cfg(
        {"criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "vulnerable": True,
         "versionEndExcluding": "2.4.52"},
        {"criteria": "cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*", "vulnerable": True},  # OS, out of scope
        {"criteria": "cpe:2.3:a:oracle:http_server:12.2.1.4.0:*:*:*:*:*:*:*", "vulnerable": True},  # oracle http, not D7
        {"criteria": "cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*", "vulnerable": False},  # not vulnerable
    ), "nvd", NOW)
    # only the first (apache range, vulnerable) survives
    assert len(rows) == 1, rows
    assert rows[0]["version_end_excluding"] == "2.4.52"


def test_all_versions_row():
    """cpeMatch with version '*' and no bounds → every version vulnerable."""
    rows = parse_configurations("CVE-9999-0001", _cfg(
        {"criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", "vulnerable": True},
    ), "nvd", NOW)
    assert len(rows) == 1
    assert rows[0]["all_versions"] is True
    assert rows[0]["exact_version"] is None


def test_dedup_within_cve():
    rows = parse_configurations("CVE-9999-0002", _cfg(
        {"criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", "vulnerable": True,
         "versionEndExcluding": "1.0.2m"},
        {"criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", "vulnerable": True,
         "versionEndExcluding": "1.0.2m"},  # duplicate across nodes
    ), "nvd", NOW)
    assert len(rows) == 1, rows


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
