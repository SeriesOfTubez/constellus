"""Tests for the asset_metadata claims-bridge in app.api.assets (L3c-2/L3c-4,
planning#144 — THE crux of the claims-migration cutover).

`_serialize_asset` used to return `row.asset_metadata` (the column) verbatim.
`_bridge_metadata` reconstructs the same dict from asset_claims + asset_state
+ the record_type/content columns instead — the exact inverse of
claim_emitter.emit_claims' Table 1 mapping.

**The gate changed shape at L3c-4.** While the column still existed this
compared bridged == row.asset_metadata: the column was the baseline the
reconstruction had to reproduce. Migration 0043 dropped it, so that baseline
is gone and there is nothing left to diff against — the bridge is now the
sole producer of the API's asset_metadata payload. The comparison therefore
moves from "matches the old column" to "matches what was SEEDED", which is
the stronger contract anyway: it pins the payload to intent rather than to
another implementation of the same thing.

Seeds representative assets through the REAL write path — write_assets()
(-> claim_emitter.emit_claims -> projector.project, all invoked internally),
plus the two enrichment services whose claims aren't written by
write_assets() (hosting_classifier, eol_enrichment) — with only their
network calls stubbed out (upsert_single_claim / _fetch_eol respectively are
the real persistence functions; only the HTTP fetch is faked, to keep this
hermetic).

HARD GATE (must pass): for every seeded asset, the bridged payload carries
the values that were written, semantically compared (order-insensitive on
lists, ports by port number): record_type, content, open_ports, sources,
eol_services, provider_mx, shodan_org/asn/isp/country/os/tags/hostnames/ports.

REPORT (not a gate): the full bridged payload for every seeded asset is
printed. It IS the API response now, so it stays worth eyeballing after any
change to Table 1 or the projector.

Run with:  python -m app.tests.test_serializer_bridge
       or: pytest -s app/tests/test_serializer_bridge.py   (-s to see the
           payload printout; pytest captures stdout by default)
"""

import json
import uuid
from datetime import datetime, timezone

from app.api.assets import _bridge_metadata, _filter_stale_ports, load_bridge_sources
from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.claim import ClaimHistory
from app.services import eol_enrichment
from app.services.asset_writer import write_assets
from app.services.claim_emitter import upsert_single_claim
from app.services.projector import project


# ── helpers ──────────────────────────────────────────────────────────────

def _normalize(value):
    """Order-insensitive normalization for the semantic diff: lists sort by
    their canonical JSON representation (works for both primitive and dict
    entries); everything else compares as-is."""
    if isinstance(value, list):
        try:
            return sorted(value, key=lambda x: json.dumps(x, sort_keys=True, default=str))
        except TypeError:
            return value
    return value


def _ports_by_number(open_ports) -> dict:
    return {e["port"]: e for e in (open_ports or []) if isinstance(e, dict) and isinstance(e.get("port"), int)}


def _bridge_for(db, row: AssetCanonical) -> dict:
    """Run the real serializer bridge for one row via the same batch-loader
    the API endpoints use (single-asset slice)."""
    sources = load_bridge_sources(db, [row.id])
    bridged = _bridge_metadata(row, sources[row.id]["state"], sources[row.id])
    if row.asset_type == "ip_address":
        bridged = _filter_stale_ports(bridged)
    return bridged


def _cleanup(values: list[str]) -> None:
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).all()
        ids = [r.id for r in rows]
        if ids:
            db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


# ── the test ─────────────────────────────────────────────────────────────

def test_bridge_metadata_reconstructs_seeded_assets(monkeypatch):
    suffix = uuid.uuid4().hex[:10]
    apex = f"bridge-{suffix}.example.com"
    cname_value = f"cdn.bridge-{suffix}.example.com"
    ip = f"203.0.113.{100 + (int(suffix[:2], 16) % 100)}"
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    all_values = [apex, cname_value, ip]

    db = SessionLocal()
    try:
        # ── DNS records ─────────────────────────────────────────────────
        # _upsert_canonical_batch dedupes DiscoveredAssets sharing the same
        # canonical key WITHIN one write_assets() call down to just the last
        # one (its own `unique: dict[key] = asset` collapse) — so two
        # observers' contributions to the SAME record only both land in
        # asset_metadata (via its incremental "existing row" merge branch)
        # if they arrive in SEPARATE write_assets() calls, exactly like two
        # separate scans would. The distinct-identity records (A, MX x2,
        # CNAME, TXT/SPF) can share one batch; the second observer on the A
        # and CNAME records needs its own call.
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(
                asset_type="dns_record", value=apex, parent_value=None,
                asset_metadata={
                    "sources": ["dns_records"], "record_type": "A", "content": ip, "ttl": 300,
                },
            ),
            DiscoveredAsset(
                asset_type="dns_record", value=apex, parent_value=None,
                asset_metadata={
                    "sources": ["dns_records"], "record_type": "MX", "content": "aspmx.l.google.com",
                    "mx_preference": 10, "provider_mx": True,
                },
            ),
            DiscoveredAsset(
                asset_type="dns_record", value=apex, parent_value=None,
                asset_metadata={
                    "sources": ["dns_records"], "record_type": "MX", "content": "mail.unmanaged-mx.example.net",
                    "mx_preference": 20,
                },
            ),
            DiscoveredAsset(
                asset_type="dns_record", value=cname_value, parent_value=apex,
                asset_metadata={
                    "sources": ["dns_records"], "record_type": "CNAME", "content": "target.example.net",
                },
            ),
            DiscoveredAsset(
                asset_type="dns_record", value=apex, parent_value=None,
                asset_metadata={
                    "sources": ["dns_records"], "record_type": "TXT", "content": "v=spf1 ip4:203.0.113.0/24 -all",
                    "spf": {
                        "policy": "-all", "includes": [], "ip4": ["203.0.113.0/24"], "ip6": [],
                        "mechanisms": ["ip4:203.0.113.0/24"], "lookup_count": 0, "exceeds_limit": False,
                    },
                },
            ),
        ])

        # A record, second observer (cloudflare) — merges into the existing
        # row: `sources` becomes the union {dns_records, cloudflare}.
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(
                asset_type="dns_record", value=apex, parent_value=None,
                asset_metadata={
                    "sources": ["cloudflare"], "record_type": "A", "content": ip,
                    "proxied": True, "zone_id": "zone-abc123",
                },
            ),
        ])

        # CNAME, second observer (cert_transparency) — merges in the CT
        # cert-issuance fields; `sources` becomes {dns_records, cert_transparency}.
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(
                asset_type="dns_record", value=cname_value, parent_value=apex,
                asset_metadata={
                    "sources": ["cert_transparency"], "record_type": "CNAME", "content": "target.example.net",
                    "ct_source": "certspotter",
                    "not_before": "2026-01-01T00:00:00+00:00",
                    "not_after": "2027-01-01T00:00:00+00:00",
                    "issuer": "Let's Encrypt",
                },
            ),
        ])

        # ── ip_address: naabu (port 22), then tlsx (port 443, l7_confirmed,
        # service_version parseable by eol_enrichment), then shodan (host
        # claim + its own port 8080 + bare shodan_ports overlapping/
        # extending it) — three separate calls for the same reason as
        # above: each observer's ports/fields must land via the writer's
        # incremental merge (_merge_open_ports / "first non-empty wins"),
        # not get discarded by the same-batch dedup.
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(
                asset_type="ip_address", value=ip, parent_value=None,
                asset_metadata={
                    "sources": ["naabu"],
                    # No last_seen_at: _prune_stale_ports (writer + projector)
                    # keeps any entry with no timestamp unconditionally — sidesteps
                    # a real timing race otherwise, since write_assets() stamps
                    # the naabu claim's own last_observed_at (the pruning cutoff)
                    # with its own internal `now`, computed strictly AFTER this
                    # dict is built, so a `now_iso` captured here would always
                    # read as "stale by a few microseconds" relative to it.
                    "open_ports": [{
                        "port": 22, "protocol": "tcp", "sources": ["naabu"],
                        "service": "OpenSSH", "service_version": "OpenSSH_8.9",
                    }],
                    "naabu_last_scan_at": now_iso,
                    "naabu_tier": "standard",
                    "tarpit_detected": False,
                },
            ),
        ])
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(
                asset_type="ip_address", value=ip, parent_value=None,
                asset_metadata={
                    "sources": ["tlsx"],
                    "open_ports": [{
                        "port": 443, "protocol": "tcp", "sources": ["tlsx"], "l7_confirmed": True,
                        "service": "nginx", "service_version": "nginx/1.18",
                    }],
                },
            ),
        ])
        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(
                asset_type="ip_address", value=ip, parent_value=None,
                asset_metadata={
                    "sources": ["shodan"],
                    "shodan_org": "Example Hosting Co",
                    "shodan_os": "Linux",
                    "shodan_country": "US",
                    "shodan_isp": "Example ISP",
                    "shodan_asn": "AS64500",
                    "shodan_ports": [22, 443, 8080],
                    "shodan_tags": ["cloud"],
                    "shodan_hostnames": ["host.example.net"],
                    "shodan_last_update": "2026-08-18T00:00:00",
                    "open_ports": [{
                        "port": 8080, "protocol": "tcp", "sources": ["shodan"],
                    }],
                },
            ),
        ])

        ip_row = db.query(AssetCanonical).filter(AssetCanonical.value == ip, AssetCanonical.asset_type == "ip_address").one()

        # ── hosting_class claim: drive the real persistence function
        # (upsert_single_claim) directly rather than hosting_classifier's
        # network-calling classify_ip() wrapper, so this test stays
        # hermetic. Same claim shape classify_ip() would write.
        upsert_single_claim(
            db, ip_row.id, "hosting_classifier", "hosting_class",
            {"is_datacenter": True, "company_name": "Example Cloud", "asn": 64500}, now,
        )

        # ── eol claim: drive the real enrich_eol() end to end, stubbing
        # only the network fetch (_fetch_eol) so the endoflife.date lookup
        # for nginx/1.18 (from the tlsx port-443 entry above) is canned
        # instead of hitting the live API.
        def _fake_fetch_eol(product, cycle):
            assert (product, cycle) == ("nginx", "1.18")
            return {"eol": "2020-04-01", "latest": "1.25"}

        monkeypatch.setattr(eol_enrichment, "_fetch_eol", _fake_fetch_eol)
        eol_enrichment.enrich_eol(db, {ip_row.id})

        # enrich_eol (and upsert_single_claim) don't re-run the projector —
        # same as production (scan_executor runs enrich_eol after
        # write_assets' own project() call, with no second projection until
        # the asset's next scan). Re-project explicitly here to fold both
        # the new hosting_class claim and the newly-written eol_services
        # metadata into asset_state, exactly like that next scan would.
        project(db, {ip_row.id}, datetime.now(timezone.utc))
        db.commit()

        # -- Bridge every seeded asset --------------------------------------
        # A, MX(managed), MX(unmanaged), TXT/SPF (all value=apex) + CNAME
        # (value=cname_value) + ip_address (value=ip) = 6 distinct canonical
        # rows -- the two-observer merges (A+cloudflare, CNAME+cert_transparency,
        # naabu+tlsx+shodan) fold into their existing row, not new ones.
        rows = db.query(AssetCanonical).filter(AssetCanonical.value.in_(all_values)).all()
        assert len(rows) == 6, f"expected 6 canonical rows, got {len(rows)}"

        payloads = {
            f"{row.asset_type}:{row.value}:{row.record_type}:{row.content}": _bridge_for(db, row)
            for row in rows
        }

        # -- REPORT: the bridged payload IS the API response now -------------
        print("\n=== bridged asset_metadata payload, per seeded asset ===")
        print(json.dumps(payloads, indent=2, default=str, sort_keys=True))
        print("=== end payloads ===\n")

        # -- HARD GATE: the payload carries what was seeded ------------------
        ip_bridged = _bridge_for(db, ip_row)

        # ip_address rows carry no DNS identity.
        assert ip_bridged.get("record_type") is None, ip_bridged
        assert ip_bridged.get("content") is None, ip_bridged

        # open_ports: naabu's 22 + tlsx's 443 + shodan's 8080, merged across
        # the three observers' port_observation claims by the projector.
        assert set(_ports_by_number(ip_bridged.get("open_ports"))) == {22, 443, 8080}, (
            f"open_ports mismatch: {sorted(_ports_by_number(ip_bridged.get('open_ports')))}"
        )
        # ...and each observer's own fields survive onto its entry.
        by_port = _ports_by_number(ip_bridged.get("open_ports"))
        assert by_port[22].get("service_version") == "OpenSSH_8.9", by_port[22]
        assert by_port[443].get("l7_confirmed") is True, by_port[443]
        assert by_port[443].get("service_version") == "nginx/1.18", by_port[443]

        assert set(ip_bridged.get("sources") or []) == {"naabu", "tlsx", "shodan"}, (
            f"sources mismatch: {ip_bridged.get('sources')}"
        )

        def _eol_key(rec):
            return (rec.get("port"), rec.get("product"), rec.get("version"), rec.get("is_eol"))

        # eol_services: seeded indirectly -- enrich_eol parsed the tlsx port-443
        # nginx/1.18 banner against the canned endoflife response above. Gated
        # against both the seed's intent and the projection the bridge reads.
        bridged_eol = {_eol_key(r) for r in (ip_bridged.get("eol_services") or [])}
        assert bridged_eol == {(443, "nginx", "1.18", True)}, bridged_eol
        state = db.query(AssetState).filter(AssetState.asset_canonical_id == ip_row.id).one()
        assert {_eol_key(r) for r in (state.eol_summary or [])} == bridged_eol

        for key, expected_value in (
            ("shodan_org", "Example Hosting Co"),
            ("shodan_os", "Linux"),
            ("shodan_country", "US"),
            ("shodan_isp", "Example ISP"),
            ("shodan_asn", "AS64500"),
        ):
            assert ip_bridged.get(key) == expected_value, (
                f"{key} mismatch: bridged={ip_bridged.get(key)!r} seeded={expected_value!r}"
            )

        for key, expected_set in (
            ("shodan_tags", {"cloud"}),
            ("shodan_hostnames", {"host.example.net"}),
            # bare shodan_ports ints fold into the shodan observer's own port
            # claim alongside its richer 8080 entry -- see
            # claim_emitter._accumulate_port_observation.
            ("shodan_ports", {22, 443, 8080}),
        ):
            assert set(ip_bridged.get(key) or []) == expected_set, (
                f"{key} mismatch: bridged={ip_bridged.get(key)} seeded={sorted(expected_set)}"
            )

        # A/MX(managed)/MX(unmanaged)/CNAME record_type + content sanity
        a_row = db.query(AssetCanonical).filter(
            AssetCanonical.value == apex, AssetCanonical.record_type == "A"
        ).one()
        a_bridged = _bridge_for(db, a_row)
        assert a_bridged.get("record_type") == "A"
        assert a_bridged.get("content") == ip
        assert a_bridged.get("ttl") == 300, a_bridged
        # cloudflare's own keys landed on the same row via its separate write.
        assert a_bridged.get("proxied") is True, a_bridged
        assert a_bridged.get("zone_id") == "zone-abc123", a_bridged
        assert set(a_bridged.get("sources") or []) == {"dns_records", "cloudflare"}

        mx_managed = db.query(AssetCanonical).filter(
            AssetCanonical.value == apex, AssetCanonical.content == "aspmx.l.google.com"
        ).one()
        mx_unmanaged = db.query(AssetCanonical).filter(
            AssetCanonical.value == apex, AssetCanonical.content == "mail.unmanaged-mx.example.net"
        ).one()
        for mx_row, expected_pref, expect_provider_mx in (
            (mx_managed, 10, True), (mx_unmanaged, 20, False),
        ):
            mx_bridged = _bridge_for(db, mx_row)
            assert mx_bridged.get("record_type") == "MX"
            assert mx_bridged.get("content") == mx_row.content
            assert mx_bridged.get("mx_preference") == expected_pref, mx_bridged
            # provider_mx is RECOMPUTED by the projector from the content
            # column (is_provider_managed_mx), never echoed from the seed --
            # the unmanaged MX must not carry the key at all.
            if expect_provider_mx:
                assert mx_bridged.get("provider_mx") is True, mx_bridged
            else:
                assert "provider_mx" not in mx_bridged, mx_bridged

        txt_row = db.query(AssetCanonical).filter(
            AssetCanonical.value == apex, AssetCanonical.record_type == "TXT"
        ).one()
        txt_bridged = _bridge_for(db, txt_row)
        assert (txt_bridged.get("spf") or {}).get("policy") == "-all", txt_bridged
        assert (txt_bridged.get("spf") or {}).get("ip4") == ["203.0.113.0/24"], txt_bridged

        cname_row = db.query(AssetCanonical).filter(
            AssetCanonical.value == cname_value, AssetCanonical.record_type == "CNAME"
        ).one()
        cname_bridged = _bridge_for(db, cname_row)
        assert cname_bridged.get("record_type") == "CNAME"
        assert cname_bridged.get("content") == "target.example.net"
        # cert_transparency's issuance fields landed on the same row.
        assert cname_bridged.get("issuer") == "Let's Encrypt", cname_bridged
        # Previously a KNOWN GAP: "dns_records" used to be dropped from
        # cname_bridged["sources"] because its DiscoveredAsset write for this
        # CNAME carried ONLY identity fields (record_type/content, no ttl/
        # spf/mx_preference/etc) -- the real, common shape dns_resolve.py
        # writes for A/AAAA/CNAME hops -- and claim_emitter used to emit no
        # claim at all for identity-only metadata. Fixed by the `observation`
        # claim type (0041, L3c-2a, planning#144): emit_claims now always
        # records a base-provenance claim for the asset-level observer, so
        # even an identity-only write leaves a trace for `sources` to
        # recover. Both observers survive the bridge round-trip.
        assert set(cname_bridged.get("sources") or []) == {"dns_records", "cert_transparency"}, (
            f"expected both observers in bridged sources, got {cname_bridged.get('sources')}"
        )

        print("HARD GATE: all seeded-value assertions passed.")
    finally:
        db.close()
        _cleanup(all_values)


if __name__ == "__main__":
    class _FakeMonkeypatch:
        def __init__(self):
            self._restores = []

        def setattr(self, obj, name, value):
            self._restores.append((obj, name, getattr(obj, name)))
            setattr(obj, name, value)

        def undo(self):
            for obj, name, old in reversed(self._restores):
                setattr(obj, name, old)

    mp = _FakeMonkeypatch()
    try:
        test_bridge_metadata_reconstructs_seeded_assets(mp)
        print("ok  test_bridge_metadata_reconstructs_seeded_assets")
        print("all passed")
    finally:
        mp.undo()
