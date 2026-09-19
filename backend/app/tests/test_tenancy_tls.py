"""Tests for the Tier 1b tenancy rung (planning#181, slice 2a) —
`app.services.tenancy_tls`.

Real dev DB, no isolation (see the module warning in
`test_tenancy_enricher.py`, which this suite mirrors). Every asset/claim
this suite creates is tracked by id/value and deleted in a `finally` block;
never a table-wide DELETE.

`tenancy_tls` is not registered in `conftest.py`'s `_GUARDED_MODULES` (it is
new this slice), so a monkeypatch here is NOT auto-restored between tests —
every test that reaches `tick()` saves the original `tenancy_tls._handshake`
(and, where used, `tenancy_tls.IPS_PER_TICK`) and restores it in a `finally`,
by hand.

`_select_assets_to_enrich` sweeps `ip_address` assets across the WHOLE
table, same as Tier 0's. A test that calls `tick()` end to end sets
`tenancy_tls.IPS_PER_TICK = 1` for the duration: the test's own freshly
created asset is always the newest row (`ORDER BY ac.first_seen_at DESC`),
so a limit of 1 deterministically selects only it, regardless of what real
Tier-0-undetermined, gate-permitted inventory already exists in the dev DB.
Without this, a test asserting "the handshake was never/always called"
would be at the mercy of ambient rows this suite does not own.

IP addresses are RFC 5737 documentation ranges per the repo's gitleaks
non-reserved-public-ipv4 rule (planning#171).

No test makes a real network call: every test that reaches `tick()`
monkeypatches `tenancy_tls._handshake` to a stub, restored in `finally`.

Run with:  python -m app.tests.test_tenancy_tls
       or: pytest app/tests/test_tenancy_tls.py
"""

import uuid
from datetime import datetime, timezone

from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.authorisation_decision import AuthorisationDecision
from app.models.claim import ClaimHistory
from app.services import app_settings
from app.services import tenancy_tls as tls
from app.services.claim_emitter import get_current_claim, upsert_single_claim

_MODE_KEY = "probe_authorisation_mode"


# ── helpers ──────────────────────────────────────────────────────────────

def _make_ip_asset(db, ip: str, first_seen_at: datetime | None = None) -> AssetCanonical:
    now = first_seen_at or datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type="ip_address", value=ip, parent_value=None,
        first_seen_at=now, last_seen_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _seed_tier0(db, asset_id: uuid.UUID, tenancy: str, now: datetime | None = None) -> None:
    """Seed the Tier 0 `tenancy_enricher` claim `_select_assets_to_enrich`
    requires to exist before this rung will ever consider an address."""
    now = now or datetime.now(timezone.utc)
    upsert_single_claim(
        db, asset_id, "tenancy_enricher", "tenancy",
        {
            "tenancy": tenancy,
            "decided_by_tier": 0 if tenancy != "undetermined" else None,
            "reason": "test_seed", "provider": None, "service_raw": None,
            "service_class": None, "prefix": None,
            "dataset_sha256": "test-sha", "dataset_generated_at": now.isoformat(),
        },
        now,
    )
    db.commit()


def _set_asset_state(db, asset_id: uuid.UUID, probe_class: str) -> None:
    """Same shape as `test_probe_authorisation.py`'s `_set_state` — the gate
    reads `asset_state.attributes['probe_class']`."""
    existing = db.get(AssetState, asset_id)
    now = datetime.now(timezone.utc)
    if existing is None:
        db.add(AssetState(asset_canonical_id=asset_id, attributes={"probe_class": probe_class}, projected_at=now))
    else:
        existing.attributes = {"probe_class": probe_class}
        existing.projected_at = now
    db.commit()


def _set_mode(db, value: str | None) -> None:
    """Same shape as `test_probe_authorisation.py`'s `_set_mode`. `None`
    deletes the override row so `probe_authorisation_mode` falls back to its
    documented default, `log_only`."""
    if value is None:
        db.query(AppSetting).filter(AppSetting.key == _MODE_KEY).delete()
        db.commit()
    else:
        app_settings.set_value(db, _MODE_KEY, value)


def _cleanup(values: list[str]) -> None:
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).all()
        ids = [r.id for r in rows]
        if ids:
            # ClaimHistory has no FK (append-only log) but is cleaned for
            # tidiness. AuthorisationDecision's FK to assets_canonical has no
            # ON DELETE action, so it MUST be cleared before the canonical
            # row, or the delete below fails with a FK violation.
            # AssetState/AssetClaim cascade on delete (migration 0039/0040)
            # and need no explicit cleanup here.
            db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
            db.query(AuthorisationDecision).filter(AuthorisationDecision.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


# ── tenancy_for_cert: pure mapping ───────────────────────────────────────

def test_tenancy_for_cert_dissents_on_a_managed_endpoint_certificate():
    cn_match = {"subject_cn": "*.azurewebsites.net", "subject_an": []}
    tenancy, suffix, _evidence = tls.tenancy_for_cert(cn_match)
    assert tenancy == tls.NOT_SINGLE_TENANT
    assert suffix == ".azurewebsites.net"

    # A match found only in subject_an must dissent too, not just subject_cn.
    an_only_match = {"subject_cn": "app1.internal.example", "subject_an": ["foo.core.windows.net"]}
    tenancy2, suffix2, _evidence2 = tls.tenancy_for_cert(an_only_match)
    assert tenancy2 == tls.NOT_SINGLE_TENANT
    assert suffix2 == ".core.windows.net"

    # Matching is case-insensitive.
    case_insensitive = {"subject_cn": "SOMETHING.AZUREWEBSITES.NET", "subject_an": []}
    tenancy3, suffix3, _evidence3 = tls.tenancy_for_cert(case_insensitive)
    assert tenancy3 == tls.NOT_SINGLE_TENANT
    assert suffix3 == ".azurewebsites.net"


def test_tenancy_for_cert_abstains_on_an_unclassified_certificate():
    """This is the asymmetry — the promote branch records and abstains, it
    does not vote `single_tenant`."""
    cert_row = {
        "subject_cn": "www.example.com", "subject_an": ["example.com"],
        "issuer_cn": "R3", "issuer_org": "Let's Encrypt",
        "not_before": "2026-01-01T00:00:00Z", "not_after": "2026-04-01T00:00:00Z",
        "fingerprint": "aa:bb:cc:dd", "tls_version": "TLSv1.3",
        "cipher": "TLS_AES_128_GCM_SHA256", "port": 443,
    }
    tenancy, suffix, evidence = tls.tenancy_for_cert(cert_row)
    assert tenancy == tls.UNDETERMINED
    assert suffix is None
    assert evidence["subject_cn"] == "www.example.com"
    assert evidence["subject_an"] == ["example.com"]
    assert evidence["issuer_cn"] == "R3"
    assert evidence["issuer_org"] == "Let's Encrypt"
    assert evidence["fingerprint"] == "aa:bb:cc:dd"
    assert evidence["tls_version"] == "TLSv1.3"
    assert evidence["cipher"] == "TLS_AES_128_GCM_SHA256"
    assert evidence["port"] == 443


def test_tenancy_for_cert_abstains_when_there_was_no_handshake():
    assert tls.tenancy_for_cert(None) == (tls.UNDETERMINED, None, {})


# ── claim value shape ─────────────────────────────────────────────────────

def test_claim_value_carries_no_ownership_field_and_no_dataset_digest():
    now = datetime.now(timezone.utc)
    dissent = tls._claim_value(tls.NOT_SINGLE_TENANT, "managed_endpoint_cert:azure:managed", {}, now)
    assert set(dissent.keys()) == {"tenancy", "decided_by_tier", "reason", "evidence", "observed_at"}
    assert dissent["decided_by_tier"] == 1

    undetermined = tls._claim_value(
        tls.UNDETERMINED, "cert_unclassified_promote_branch_abstains", {"subject_cn": "x"}, now,
    )
    assert set(undetermined.keys()) == {"tenancy", "decided_by_tier", "reason", "evidence", "observed_at"}
    assert undetermined["decided_by_tier"] is None


# ── tick(): the safety test ────────────────────────────────────────────────

def test_tick_honours_the_computed_verdict_even_in_log_only():
    """planning#181's whole point for this rung: `gate.permitted` under
    `log_only` is the UNFILTERED input (so naabu et al. keep scanning), but
    `tick()` must read `gate.permissions` — the real computed verdict — not
    `gate.permitted`, or a denied asset would get handshaked anyway under
    the default mode."""
    ip = "203.0.113.70"
    db = SessionLocal()
    orig_handshake = tls._handshake
    orig_ips_per_tick = tls.IPS_PER_TICK
    calls = []
    try:
        asset = _make_ip_asset(db, ip)
        _seed_tier0(db, asset.id, "undetermined")
        _set_asset_state(db, asset.id, "no_probe")
        _set_mode(db, None)  # ensure default (log_only) — no override row
        tls.IPS_PER_TICK = 1  # isolate selection to just this freshly-created asset

        def _fake_handshake(targets):
            calls.append(list(targets))
            return []

        tls._handshake = _fake_handshake

        tls.tick()

        assert calls == [], "a probe_class:no_probe asset must never reach the scanner worker, even in log_only"
        claim = get_current_claim(db, asset.id, "tenancy_tls", "tenancy")
        assert claim is None, "a denied asset must get no tenancy_tls claim"
    finally:
        tls.IPS_PER_TICK = orig_ips_per_tick
        tls._handshake = orig_handshake
        _set_mode(db, None)
        db.close()
        _cleanup([ip])


def test_worker_outage_writes_nothing_rather_than_undetermined():
    """Our own outage must not be recorded as a determination about the
    asset — an IP with no `tenancy_tls` claim is 'not yet probed', which is
    exactly what this is."""
    ip = "203.0.113.71"
    db = SessionLocal()
    orig_handshake = tls._handshake
    orig_ips_per_tick = tls.IPS_PER_TICK
    try:
        asset = _make_ip_asset(db, ip)
        _seed_tier0(db, asset.id, "undetermined")
        _set_asset_state(db, asset.id, "name_only")
        tls.IPS_PER_TICK = 1

        tls._handshake = lambda targets: None

        tls.tick()

        claim = get_current_claim(db, asset.id, "tenancy_tls", "tenancy")
        assert claim is None
    finally:
        tls.IPS_PER_TICK = orig_ips_per_tick
        tls._handshake = orig_handshake
        db.close()
        _cleanup([ip])


def test_tick_writes_a_dissent_claim_end_to_end():
    ip = "203.0.113.72"
    db = SessionLocal()
    orig_handshake = tls._handshake
    orig_ips_per_tick = tls.IPS_PER_TICK
    try:
        asset = _make_ip_asset(db, ip)
        _seed_tier0(db, asset.id, "undetermined")
        _set_asset_state(db, asset.id, "name_only")
        tls.IPS_PER_TICK = 1

        tls._handshake = lambda targets: [
            {"ip": ip, "port": 443, "subject_cn": "*.azurewebsites.net", "subject_an": []}
        ]

        tls.tick()

        claim = get_current_claim(db, asset.id, "tenancy_tls", "tenancy")
        assert claim is not None
        assert claim.claim_value["tenancy"] == tls.NOT_SINGLE_TENANT
        assert claim.claim_value["decided_by_tier"] == 1
    finally:
        tls.IPS_PER_TICK = orig_ips_per_tick
        tls._handshake = orig_handshake
        db.close()
        _cleanup([ip])


# ── selection ────────────────────────────────────────────────────────────

def test_only_tier0_undetermined_addresses_are_selected():
    ip_single = "203.0.113.73"
    ip_undetermined = "203.0.113.74"
    values = [ip_single, ip_undetermined]
    db = SessionLocal()
    try:
        asset_single = _make_ip_asset(db, ip_single)
        asset_undetermined = _make_ip_asset(db, ip_undetermined)
        _seed_tier0(db, asset_single.id, "single_tenant")
        _seed_tier0(db, asset_undetermined.id, "undetermined")

        selected = tls._select_assets_to_enrich(db, 200)
        selected_ids = {a.id for a in selected}
        assert asset_undetermined.id in selected_ids, "a Tier 0 'undetermined' address must be selected"
        assert asset_single.id not in selected_ids, "a Tier 0 'single_tenant' address must not be selected"
    finally:
        db.close()
        _cleanup(values)


def _run():
    tests = [
        test_tenancy_for_cert_dissents_on_a_managed_endpoint_certificate,
        test_tenancy_for_cert_abstains_on_an_unclassified_certificate,
        test_tenancy_for_cert_abstains_when_there_was_no_handshake,
        test_claim_value_carries_no_ownership_field_and_no_dataset_digest,
        test_tick_honours_the_computed_verdict_even_in_log_only,
        test_worker_outage_writes_nothing_rather_than_undetermined,
        test_tick_writes_a_dissent_claim_end_to_end,
        test_only_tier0_undetermined_addresses_are_selected,
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
