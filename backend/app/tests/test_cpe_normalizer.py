"""Tests for app.services.cpe_normalizer.

Pure-assert style for the parsing helpers below (no pytest dependency
required). The `enrich_cpe` claim-emission section further down (planning#144
L3c-1) needs a real DB — same convention as test_projector.py/
test_hosting_classifier.py: a persisted ip_address AssetCanonical row to
resolve the "cpe_normalizer" observer + asset_claims round-trip, run through
`projector.project` to prove `software` actually lands on
asset_state.open_ports alongside naabu's own fields.

Run with:  python -m app.tests.test_cpe_normalizer       (from /app)
       or: pytest app/tests/test_cpe_normalizer.py        (if pytest installed)
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy.orm.attributes import flag_modified

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.claim import AssetClaim, ClaimHistory
from app.models.observer import Observer
from app.services import projector
from app.services.cpe_normalizer import (
    build_cpe23,
    enrich_cpe,
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


# ── enrich_cpe: port_observation claim emission (planning#144 L3c-1, real DB) ─
#
# `enrich_cpe` writes software[] onto asset_metadata.open_ports entries (kept
# as-is — the API still serializes it) AND upserts a "cpe_normalizer"
# port_observation claim carrying just {port, software} for ports with
# software. The projector's `_merge_open_ports` folds that claim's
# contribution in by port number alongside whatever naabu already claimed
# for the same port, so `software` lands on the same asset_state.open_ports
# entry naabu populated (incl. naabu's own last_seen_at) — proven end-to-end
# below via projector.project(), not just by inspecting the claim row.

def _observer_id(db, name: str) -> uuid.UUID:
    return db.query(Observer).filter(Observer.name == name).one().id


def _make_ip_asset(db, ip: str, open_ports: list[dict]) -> AssetCanonical:
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type="ip_address", value=ip, parent_value=None,
        first_seen_at=now, last_seen_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _add_naabu_port_claim(db, asset_id, ports: list[dict], last_observed_at: datetime) -> None:
    """Insert-or-update the naabu port_observation claim — a plain insert
    would violate asset_claims' (asset, observer, claim_type) unique
    constraint on the second call for the same asset (the software-removal
    test re-seeds naabu's claim to simulate a later scan)."""
    observer_id = _observer_id(db, "naabu")
    existing = (
        db.query(AssetClaim)
        .filter(
            AssetClaim.asset_canonical_id == asset_id,
            AssetClaim.observer_id == observer_id,
            AssetClaim.claim_type == "port_observation",
        )
        .first()
    )
    if existing is None:
        db.add(AssetClaim(
            asset_canonical_id=asset_id,
            observer_id=observer_id,
            claim_type="port_observation",
            claim_value={"ports": ports},
            evidence={},
            first_observed_at=last_observed_at,
            last_observed_at=last_observed_at,
        ))
    else:
        existing.claim_value = {"ports": ports}
        existing.last_observed_at = last_observed_at
    db.commit()


def _cpe_claim(db, asset_id) -> AssetClaim | None:
    return (
        db.query(AssetClaim)
        .filter(
            AssetClaim.asset_canonical_id == asset_id,
            AssetClaim.observer_id == _observer_id(db, "cpe_normalizer"),
            AssetClaim.claim_type == "port_observation",
        )
        .first()
    )


def _cleanup(value: str) -> None:
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value == value).all()
        ids = [r.id for r in rows]
        if ids:
            db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value == value).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def test_enrich_cpe_claim_merges_with_naabu_into_projected_open_ports():
    """OpenSSH banner on port 22, naabu-observed -> enrich_cpe's
    cpe_normalizer claim carries {port: 22, software: [...]}; projector.project
    folds it onto the SAME open_ports entry naabu's own claim populated, so
    the projected entry carries BOTH naabu's fields (protocol, last_seen_at)
    AND software.

    planning#144 L3c-3: enrich_cpe's INPUT is asset_state.open_ports now, so
    the naabu claim has to be projected before it runs — that first
    projection is the scan pipeline's own mid-run pass, not test scaffolding.
    Its output is the claim alone; the asset_metadata mutation L3c-1 kept
    alongside it is gone (no readers left), so nothing is asserted about the
    column here any more."""
    ip = f"203.0.113.{20 + (uuid.uuid4().int % 40)}"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        port_entry = {
            "port": 22, "protocol": "tcp", "service": "ssh",
            "service_version": "OpenSSH 8.9p1 Ubuntu-3ubuntu0.1",
            "last_seen_at": now.isoformat(),
        }
        asset = _make_ip_asset(db, ip, [dict(port_entry)])
        _add_naabu_port_claim(db, asset.id, [dict(port_entry)], now)

        # enrich_cpe reads asset_state.open_ports — project naabu's claim first.
        projector.project(db, {asset.id}, now)
        db.commit()

        enrich_cpe(db, {asset.id})

        # cpe_normalizer's own claim carries just {port, software}.
        claim = _cpe_claim(db, asset.id)
        assert claim is not None
        assert list(claim.claim_value) == ["ports"], claim.claim_value
        assert len(claim.claim_value["ports"]) == 1, claim.claim_value
        claimed = claim.claim_value["ports"][0]
        assert claimed["port"] == 22, claimed
        assert claimed["software"][0]["product"] == "openssh", claimed

        projector.project(db, {asset.id}, now)
        db.commit()

        state = db.query(AssetState).filter(AssetState.asset_canonical_id == asset.id).one()
        by_port = {p["port"]: p for p in state.open_ports}
        assert set(by_port) == {22}, by_port
        entry = by_port[22]
        # naabu's own fields survive the merge.
        assert entry["protocol"] == "tcp", entry
        assert entry["last_seen_at"] == now.isoformat(), entry
        # cpe_normalizer's contribution lands on the SAME entry.
        assert entry.get("software"), entry
        assert entry["software"][0]["product"] == "openssh", entry
        assert entry["software"][0]["version"] == "8.9p1", entry
    finally:
        db.close()
        _cleanup(ip)


def test_enrich_cpe_software_removal_propagates_to_projected_state():
    """Banner signal disappearing (service_version cleared) must clear
    `software` from the projected asset_state.open_ports entry too — proves
    upsert_single_claim's whole-value replace (empty `ports` list once no
    entry has software) actually removes the stale software claim rather
    than leaving it stuck from a prior scan."""
    ip = f"203.0.113.{80 + (uuid.uuid4().int % 40)}"
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        port_entry = {
            "port": 22, "protocol": "tcp", "service": "ssh",
            "service_version": "OpenSSH 8.9p1 Ubuntu-3ubuntu0.1",
            "last_seen_at": now.isoformat(),
        }
        asset = _make_ip_asset(db, ip, [dict(port_entry)])
        _add_naabu_port_claim(db, asset.id, [dict(port_entry)], now)

        # First pass: software present. enrich_cpe reads asset_state, so the
        # naabu claim is projected before it runs and its own claim after.
        projector.project(db, {asset.id}, now)
        db.commit()
        enrich_cpe(db, {asset.id})
        projector.project(db, {asset.id}, now)
        db.commit()
        state = db.query(AssetState).filter(AssetState.asset_canonical_id == asset.id).one()
        assert {p["port"]: p for p in state.open_ports}[22].get("software"), state.open_ports

        # Banner signal disappears (e.g. re-scanned host now returns a
        # generic/unrecognized banner). planning#144 L3c-3: enrich_cpe's
        # ongoing input is the PROJECTED port list, so a later scan is
        # simulated by re-seeding naabu's claim and re-projecting — which is
        # exactly what a fresh scan_executor pass does.
        later = datetime.now(timezone.utc)
        _add_naabu_port_claim(db, asset.id, [{
            "port": 22, "protocol": "tcp", "service": "ssh",
            "service_version": "unknown/9.9", "last_seen_at": later.isoformat(),
        }], later)
        projector.project(db, {asset.id}, later)
        db.commit()

        enrich_cpe(db, {asset.id})

        claim = _cpe_claim(db, asset.id)
        assert claim is not None
        assert claim.claim_value == {"ports": []}, claim.claim_value

        projector.project(db, {asset.id}, later)
        db.commit()
        state = db.query(AssetState).filter(AssetState.asset_canonical_id == asset.id).one()
        entry = {p["port"]: p for p in state.open_ports}[22]
        assert "software" not in entry, entry
    finally:
        db.close()
        _cleanup(ip)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")
