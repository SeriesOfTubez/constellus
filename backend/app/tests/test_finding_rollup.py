"""Tests for the read-time CVE rollup (#66 D3) + confidence map (D4).

Pure-assert style: no pytest dependency required.
Run with:  python -m app.tests.test_finding_rollup        (from /app)
"""

from app.api.findings import _rollup_cve_findings
from app.services.finding_confidence import confidence_for, strongest


def _f(fid, aid, source, cve=None, fixed=None):
    """Minimal serialized-finding dict, as _serialize_finding would produce."""
    return {
        "id": fid,
        "asset_canonical_id": aid,
        "source": source,
        "confidence": confidence_for(source),
        "cve_id": cve,
        "detail": {"fixed_version": fixed} if fixed else {},
    }


def test_confidence_map():
    assert confidence_for("shodan") == "potential"
    assert confidence_for("version_match") == "potential"
    assert confidence_for("nuclei") == "confirmed"
    assert confidence_for("tenable") == "confirmed"
    assert confidence_for("constellus") == "confirmed"
    assert confidence_for(None) == "confirmed"
    assert strongest("potential", "confirmed") == "confirmed"
    assert strongest("potential", "potential") == "potential"


def test_three_sources_collapse_to_confirmed():
    """shodan + version_match + nuclei for CVE-X on one asset → one finding,
    confidence=confirmed, all sources listed (the D acceptance)."""
    items = [
        _f("1", "A", "shodan", cve="CVE-X"),
        _f("2", "A", "version_match", cve="CVE-X", fixed="2.4.55"),
        _f("3", "A", "nuclei", cve="CVE-X"),
    ]
    out = _rollup_cve_findings(items)
    assert len(out) == 1, out
    r = out[0]
    assert r["confidence"] == "confirmed"
    assert r["sources"] == ["nuclei", "shodan", "version_match"]
    assert r["fixed_version"] == "2.4.55"          # from the version_match row
    assert sorted(r["rolled_up_ids"]) == ["1", "2", "3"]
    assert r["id"] == "1"                            # representative = first row


def test_two_potential_sources_stay_potential():
    items = [
        _f("1", "A", "shodan", cve="CVE-Y"),
        _f("2", "A", "version_match", cve="CVE-Y", fixed="1.1.1m"),
    ]
    out = _rollup_cve_findings(items)
    assert len(out) == 1
    assert out[0]["confidence"] == "potential"
    assert out[0]["fixed_version"] == "1.1.1m"


def test_not_merged_across_assets_or_cves():
    items = [
        _f("1", "A", "version_match", cve="CVE-X"),
        _f("2", "B", "version_match", cve="CVE-X"),   # different asset
        _f("3", "A", "version_match", cve="CVE-Z"),   # different cve
    ]
    out = _rollup_cve_findings(items)
    assert len(out) == 3


def test_non_cve_passthrough_keeps_shape():
    items = [_f("1", "A", "constellus", cve=None)]
    out = _rollup_cve_findings(items)
    assert len(out) == 1
    assert out[0]["sources"] == ["constellus"]
    assert out[0]["rolled_up_ids"] == ["1"]
    assert out[0]["confidence"] == "confirmed"


def test_order_preserved_by_first_occurrence():
    items = [
        _f("hi", "A", "shodan", cve="CVE-HI"),       # highest risk (first)
        _f("lo", "B", "version_match", cve="CVE-LO"),
        _f("hi2", "A", "version_match", cve="CVE-HI"),  # dup of first
    ]
    out = _rollup_cve_findings(items)
    assert [r["id"] for r in out] == ["hi", "lo"]
    assert sorted(out[0]["rolled_up_ids"]) == ["hi", "hi2"]


def test_lone_version_match_surfaces_fixed_version():
    out = _rollup_cve_findings([_f("1", "A", "version_match", cve="CVE-1", fixed="2.4.9")])
    assert out[0]["fixed_version"] == "2.4.9"
    assert out[0]["confidence"] == "potential"
    assert out[0]["sources"] == ["version_match"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
