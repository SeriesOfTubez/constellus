"""Tests for app.services.version_matcher version-comparison logic.

Pure-assert style: no pytest dependency required.
Run with:  python -m app.tests.test_version_matcher        (from /app)
       or: pytest app/tests/test_version_matcher.py         (if pytest installed)
"""

from app.models.cpe_cve_range import CpeCveRange
from app.services.version_matcher import _matches, _vclass, _affected_range
from univers.versions import OpensslVersion, NginxVersion, RpmVersion


def _row(**kw) -> CpeCveRange:
    base = dict(cve_id="CVE-X", vendor="apache", product="http_server",
                version_start_including=None, version_start_excluding=None,
                version_end_including=None, version_end_excluding=None,
                exact_version=None, all_versions=False)
    base.update(kw)
    return CpeCveRange(**base)


def test_vclass_mapping():
    assert _vclass("openssl", "openssl") is OpensslVersion
    assert _vclass("f5", "nginx") is NginxVersion
    assert _vclass("apache", "http_server") is RpmVersion   # default
    assert _vclass("php", "php") is RpmVersion


def test_apache_range_numeric_not_lexical():
    """The case GenericVersion gets wrong: 2.4.6 IS in [2.4.0, 2.4.26)."""
    vc = RpmVersion
    r = _row(version_start_including="2.4.0", version_end_excluding="2.4.26")
    assert _matches("2.4.6", r, vc) is True
    assert _matches("2.4.26", r, vc) is False   # end excluded (fixed version)
    assert _matches("2.4.30", r, vc) is False
    assert _matches("2.3.9", r, vc) is False     # below start


def test_two_part_bound():
    """NVD bounds can be 2-part (e.g. 2.4)."""
    r = _row(version_start_including="2.4", version_end_excluding="2.4.52")
    assert _matches("2.4.6", r, RpmVersion) is True


def test_exact_version():
    r = _row(exact_version="2.4.49")
    assert _matches("2.4.49", r, RpmVersion) is True
    assert _matches("2.4.6", r, RpmVersion) is False


def test_end_including_boundary():
    r = _row(version_start_including="2.4.0", version_end_including="2.4.25")
    assert _matches("2.4.25", r, RpmVersion) is True    # inclusive
    assert _matches("2.4.26", r, RpmVersion) is False


def test_openssl_letter_versions():
    """OpenSSL letter suffixes order correctly with OpensslVersion."""
    vc = OpensslVersion
    r = _row(vendor="openssl", product="openssl",
             version_start_including="1.0.2", version_end_excluding="1.0.2m")
    assert _matches("1.0.2k", r, vc) is True
    assert _matches("1.0.2m", r, vc) is False
    assert _matches("1.1.1f", r, vc) is False    # above range


def test_fail_closed_on_unparseable():
    r = _row(version_start_including="2.4.0", version_end_excluding="2.4.26")
    assert _matches("not-a-version!!", r, RpmVersion) is False
    # a bound that won't parse also fails closed, not crash
    bad = _row(version_end_excluding="@@@")
    assert _matches("2.4.6", bad, RpmVersion) is False


def test_range_row_with_no_bounds_matches_nothing():
    assert _matches("2.4.6", _row(), RpmVersion) is False


def test_affected_range_format():
    assert _affected_range(_row(version_start_including="2.4.0", version_end_excluding="2.4.26")) == ">=2.4.0, <2.4.26"
    assert _affected_range(_row(exact_version="2.4.49")) == "=2.4.49"
    assert _affected_range(_row(version_end_including="2.4.25")) == "<=2.4.25"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
