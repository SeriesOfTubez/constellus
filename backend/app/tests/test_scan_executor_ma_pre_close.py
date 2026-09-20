"""Tests for planning#193 route (c)'s discovery-phase enforcement point —
`scan_executor._run_pipeline`'s domain loop skipping dnsrecon/bruteforce for
a pre-close M&A target.

This is the SECOND of the two enforcement points planning#193 requires (the
first is `probe_authorisation._posture_cap`, covered by
`test_probe_authorisation.py`). It exists because the discovery phase never
reaches the probe gate at all — it gates enumeration on `is_scan_authorised`,
which knows nothing about posture — so a pre-close M&A target with dnsrecon/
bruteforce force-enabled via per-run `options` would otherwise still hammer
the target's own authoritative nameservers, unseen by the gate entirely.

`_run_pipeline` is driven directly with `skip_discovery=False` (unlike
`test_phase3_gate.py`, which uses `skip_discovery=True` specifically to avoid
the domain loop this file needs to exercise) and `auth_mode="disabled"` so
`is_scan_authorised` passes unconditionally and would not itself suppress
anything — isolating the assertion to the posture check alone. The five
discovery functions the domain loop can call are monkeypatched by raw
module-attribute assignment (this suite's established convention — see
`test_probe_authorisation.py`'s module docstring) so the test needs neither
Docker (subfinder/dnsrecon images) nor real outbound DNS (dns_resolve/
dns_records/bruteforce's socket lookups) to be hermetic and fast.

## Why there are two tests, not one

A test that only asserts "dnsrecon and bruteforce were NOT called" passes
just as happily against a bug that disabled them unconditionally, for every
target, as it does against the feature working. So the skip case is paired
with an ordinary-target control that asserts the same two tools ARE called
under identical conditions. Both go through `_drive_pipeline`, which differs
between them in exactly one input — `ma_pre_close` — so the pair actually
isolates the posture flag rather than merely co-existing.

Dev-DB caveat (same as test_phase3_gate.py / test_cidr_sweep.py): no
dedicated test database. The one `targets` row each case creates is deleted
by id in a `finally` block; nothing else touches the database.

Address hygiene: the domains used are synthetic `.example.test` names (RFC
2606 reserved TLD), never a real registered domain.

Run with:  python -m app.tests.test_scan_executor_ma_pre_close
       or: pytest app/tests/test_scan_executor_ma_pre_close.py
"""

import uuid

from app.connectors.base import PhaseResult
from app.core.database import SessionLocal
from app.models.target import Target
from app.services import scan_executor
from app.services.discovery import bruteforce, dns_records, dns_resolve, dnsrecon, subfinder


def _mk_recorder(return_value):
    """A stand-in for a discovery module's `run`/`resolve_names` that
    records every call it receives and returns a fixed, network-free
    result — the same role `_StubConnector` plays in
    `test_probe_authorisation.py`, just for a bare function instead of a
    connector object."""
    calls: list[tuple[tuple, dict]] = []

    def _fn(*args, **kwargs):
        calls.append((args, kwargs))
        return return_value

    return _fn, calls


def _drive_pipeline(domain: str, ma_pre_close: bool) -> dict[str, list]:
    """Create one `targets` row with the given posture, monkeypatch every
    discovery entry point the domain loop can reach, drive `_run_pipeline`
    once, restore everything and delete the row. Returns the per-tool call
    lists, keyed by tool name.

    Factored out so the pre-close case and the ordinary-target control
    differ in exactly ONE input — `ma_pre_close` — and nothing else. A
    control that re-stated the whole setup could drift from the case it is
    controlling for, which would quietly turn it back into no control at
    all.

    `dnsrecon.available` is patched alongside the `run` functions because
    `_run_pipeline` guards the call with `if dnsrecon.available()`, which
    shells out to check for the tool's image — on a machine without it the
    control case would record zero calls and "pass" for entirely the wrong
    reason, which is precisely the failure this control exists to rule out.
    `bruteforce` has no such guard (it resolves in-process), so it needs
    none here.
    """
    db = SessionLocal()
    target_id = None

    real = {
        "subfinder_available": subfinder.available,
        "subfinder_run": subfinder.run,
        "dns_resolve": dns_resolve.resolve_names,
        "dns_records_run": dns_records.run,
        "dnsrecon_available": dnsrecon.available,
        "dnsrecon_run": dnsrecon.run,
        "bruteforce_run": bruteforce.run,
    }

    subfinder_run_fn, subfinder_calls = _mk_recorder(PhaseResult())
    dns_resolve_fn, dns_resolve_calls = _mk_recorder([])
    dns_records_fn, dns_records_calls = _mk_recorder(PhaseResult())
    dnsrecon_run_fn, dnsrecon_calls = _mk_recorder(PhaseResult())
    bruteforce_run_fn, bruteforce_calls = _mk_recorder(PhaseResult())

    try:
        row = Target(id=uuid.uuid4(), type="domain", value=domain, ma_pre_close=ma_pre_close)
        db.add(row)
        db.commit()
        target_id = row.id

        # Monkeypatched by module-attribute assignment, matching
        # test_probe_authorisation.py's convention — `_run_pipeline`
        # imports each module locally (`from app.services.discovery
        # import dnsrecon`) and then calls `dnsrecon.run(...)`, which
        # re-reads the attribute off the SAME module object at call time,
        # so patching it here is visible there regardless of the local
        # import.
        subfinder.available = lambda: True
        subfinder.run = subfinder_run_fn
        dns_resolve.resolve_names = dns_resolve_fn
        dns_records.run = dns_records_fn
        dnsrecon.available = lambda: True
        dnsrecon.run = dnsrecon_run_fn
        bruteforce.run = bruteforce_run_fn

        scan_executor._run_pipeline(
            db, uuid.uuid4(), {"domains": [domain], "ip_ranges": []},
            {"dnsrecon": True, "bruteforce": True},  # force-enable both
            "disabled",  # auth_mode — is_scan_authorised always True, isolating the assertion to posture
            "standard", False,  # skip_discovery=False — the domain loop must actually run
            {}, [], frozenset(),
        )
    finally:
        subfinder.available = real["subfinder_available"]
        subfinder.run = real["subfinder_run"]
        dns_resolve.resolve_names = real["dns_resolve"]
        dns_records.run = real["dns_records_run"]
        dnsrecon.available = real["dnsrecon_available"]
        dnsrecon.run = real["dnsrecon_run"]
        bruteforce.run = real["bruteforce_run"]
        if target_id is not None:
            db.query(Target).filter(Target.id == target_id).delete()
            db.commit()
        db.close()

    return {
        "subfinder": subfinder_calls,
        "dns_resolve": dns_resolve_calls,
        "dns_records": dns_records_calls,
        "dnsrecon": dnsrecon_calls,
        "bruteforce": bruteforce_calls,
    }


def test_dnsrecon_and_bruteforce_skipped_for_pre_close_target_passive_discovery_continues():
    """The behaviour planning#193 §3 exists to ship.

    `options={"dnsrecon": True, "bruteforce": True}` force-enables both
    tools for this run — proving `posture_passive` overrides even an
    explicit per-run override, which is why the spec requires it to be the
    LAST term in both conditions (`scan_executor.py`'s two
    `and not posture_passive` clauses). If a future edit reordered those
    clauses so `options.get(...)` short-circuited first, this test would
    catch it: dnsrecon/bruteforce would run.
    """
    calls = _drive_pipeline(f"pa193-discovery-{uuid.uuid4().hex[:10]}.example.test", ma_pre_close=True)

    assert calls["dnsrecon"] == [], (
        f"dnsrecon.run must not be called against a pre-close M&A target, even "
        f"force-enabled: {calls['dnsrecon']!r}"
    )
    assert calls["bruteforce"] == [], (
        f"bruteforce.run must not be called against a pre-close M&A target, even "
        f"force-enabled: {calls['bruteforce']!r}"
    )
    # Passive discovery is the point of the feature, not a side effect of
    # narrowly scoping the posture check — these three must still run
    # exactly as they would for an ordinary target.
    assert calls["subfinder"], "subfinder (passive, API-aggregation only) must still run"
    assert calls["dns_resolve"], "dns_resolve (passive, self-resolution) must still run"
    assert calls["dns_records"], "dns_records (passive, public-recursor queries) must still run"


def test_ordinary_target_still_runs_dnsrecon_and_bruteforce():
    """The control for the test above, and the reason this file has two
    cases rather than one.

    Identical inputs except `ma_pre_close=False`. Without this, a change
    that disabled dnsrecon/bruteforce for EVERY target — a stray `and
    False`, a broken `options.get` default, a tier profile regression —
    would leave the skip test passing and green while the scanner had
    silently stopped doing DNS enumeration for anyone. Asserting the
    tools DO fire here is what makes the pair a statement about the
    posture flag specifically.
    """
    calls = _drive_pipeline(f"pa193-control-{uuid.uuid4().hex[:10]}.example.test", ma_pre_close=False)

    assert calls["dnsrecon"], "dnsrecon.run must still fire for an ordinary (non-pre-close) target"
    assert calls["bruteforce"], "bruteforce.run must still fire for an ordinary (non-pre-close) target"
    assert calls["subfinder"], "subfinder must fire for an ordinary target"
    assert calls["dns_resolve"], "dns_resolve must fire for an ordinary target"
    assert calls["dns_records"], "dns_records must fire for an ordinary target"


if __name__ == "__main__":
    for fn in (
        test_dnsrecon_and_bruteforce_skipped_for_pre_close_target_passive_discovery_continues,
        test_ordinary_target_still_runs_dnsrecon_and_bruteforce,
    ):
        fn()
        print(f"ok  {fn.__name__}")
    print("all passed")
