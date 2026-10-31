"""Shared pytest fixtures for backend/app/tests.

Several test files monkeypatch module-level functions via direct attribute
assignment (e.g. `da.check_affinity = lambda ...`) rather than pytest's
monkeypatch fixture, matching this suite's long-standing "pure-assert, no
pytest dependency required" convention (most test files are also runnable
via `python -m app.tests.<module>`, see each file's own docstring). Direct
assignment has no automatic teardown, so a reassignment in one test file
silently persists for the rest of the pytest process.

Real bug found 2026-08-09 while wiring pytest into CI (planning#68):
test_shared_infra_verifier.py leaves domain_affinity.check_affinity
permanently replaced with its last test's stub. That made every test in
test_domain_affinity_unreachable.py fail 100% of the time whenever it ran
afterward in the same pytest process, while passing 100% of the time in
isolation — a real, deterministic cross-file leak, not flakiness.

This autouse fixture snapshots and restores the full attribute dict of
every module known to be a raw-assignment monkeypatch target in this suite,
around each individual test — closing the gap without requiring the
existing tests to be rewritten onto monkeypatch.setattr(). New raw-
assignment monkeypatching of a module already in _GUARDED_MODULES is
automatically covered; monkeypatching a NEW module for the first time
needs adding it here.
"""

import pytest

# The non-test-database guard lives in this package's `__init__.py`, not here:
# `python -m app.tests.<module>` does not load conftest.py, and that door has
# to be closed too. See that file's docstring.

from app.services import audit
from app.services import cloud_ranges
from app.services import domain_affinity
from app.services import hosting_classifier
from app.services import llm_connector
from app.services import notification_dispatcher
from app.services import origin_corroboration
from app.services import probe_authorisation
from app.services import scan_executor
from app.services import sec_edgar
from app.services import shared_infra_verifier
from app.services import takeover_fingerprint
from app.services import tenancy_enricher

_GUARDED_MODULES = [
    audit,
    cloud_ranges,
    domain_affinity,
    hosting_classifier,
    llm_connector,
    notification_dispatcher,
    origin_corroboration,
    probe_authorisation,
    scan_executor,
    sec_edgar,
    shared_infra_verifier,
    takeover_fingerprint,
    tenancy_enricher,
]


@pytest.fixture(autouse=True)
def _no_connector_autosync(request, monkeypatch):
    """planning#277 S1b: creating or rebinding a configured connector instance
    queues a zone sync, which under `TestClient` runs inline and would call the
    provider's real API from every test that creates an instance. It is off
    unless the test module sets `REAL_CONNECTOR_AUTOSYNC = True` (and then
    patches the provider transport itself)."""
    if getattr(request.module, "REAL_CONNECTOR_AUTOSYNC", False):
        return
    from app.api import connectors

    monkeypatch.setattr(connectors, "_should_sync", lambda db, connector, instance: False)


@pytest.fixture(autouse=True)
def scan_launches(request, monkeypatch):
    """planning#321: claiming a candidate or adding a target queues
    `targets._prime_ct_and_launch`, which under `TestClient` runs inline and
    makes a real Certspotter call and then `docker run`s subfinder. It is
    replaced by a recorder unless the test module sets `REAL_SCAN_LAUNCH = True`.
    A test that asserts a launch happened requests this fixture by name and
    reads the list of `(target_value, run_id, scope)` it was called with."""
    launched: list[tuple] = []
    if getattr(request.module, "REAL_SCAN_LAUNCH", False):
        return launched
    from app.api import targets

    monkeypatch.setattr(
        targets, "_prime_ct_and_launch",
        lambda target_value, run_id, scope: launched.append((target_value, run_id, scope)),
    )
    return launched


_BLOCKED_SPAWNS = frozenset({
    "docker", "subfinder", "dnsrecon", "nuclei", "naabu", "nmap", "httpx", "podman", "kubectl", "kind",
})


def _argv0_basename(args, shell) -> str:
    import os
    import shlex

    if isinstance(args, (str, bytes, os.PathLike)):
        first = os.fsdecode(args)
        if shell:
            try:
                parts = shlex.split(first)
            except ValueError:
                parts = first.split()
            first = parts[0] if parts else ""
        else:
            first = first.split()[0] if first.split() else ""
    else:
        seq = list(args)
        first = os.fsdecode(seq[0]) if seq else ""
    return os.path.basename(first)


@pytest.fixture(autouse=True)
def subprocess_violations(monkeypatch):
    """planning#321: suite-wide tripwire. A test must never start a scanner or a
    container runtime. `scan_executor.launch` swallows every exception, so
    raising from `Popen` alone would leave the test green; the attempt is also
    recorded and this fixture fails the test at teardown. There is no opt-out:
    stub the launch seam instead. Everything not in the blocked set runs for real."""
    import os
    import subprocess

    violations: list = []
    real_popen = subprocess.Popen

    class _GuardedPopen(real_popen):
        def __init__(self, args, *a, **kw):
            name = _argv0_basename(args, kw.get("shell", False))
            if kw.get("executable"):  # `executable=` runs that binary whatever argv[0] says
                name = os.path.basename(os.fsdecode(kw["executable"]))
            if name in _BLOCKED_SPAWNS:
                violations.append(args)
                raise RuntimeError(f"planning#321: test tried to spawn {name} ({args!r}); stub the launch seam instead")
            super().__init__(args, *a, **kw)

    monkeypatch.setattr(subprocess, "Popen", _GuardedPopen)
    yield violations
    if violations:
        pytest.fail(f"planning#321: test spawned blocked process(es): {violations!r}")


@pytest.fixture(autouse=True)
def _offline_org_verifier_facts(monkeypatch):
    """planning#277 S1b: claiming / adding through the API schedules the
    verifier run, and under `TestClient` a background task runs inline. Left
    alone it would do real DNS and WHOIS lookups from every such test, so the
    runner's one network seam answers "nothing known" unless a test installs
    its own (test_org_discovery_runner.py does). DMARC and its s7.1
    authorisation lookups are covered by the same stub."""
    from app.services.org_discovery import runner
    from app.services.org_discovery.domain_facts import DomainFacts

    monkeypatch.setattr(
        runner, "_collect",
        lambda db, domain: DomainFacts(
            domain=domain, ns=(), mx=(), spf_senders=(), spf_includes=(), registrant_org=None,
            registrant_org_folded=None, lookup_errors=(), dmarc_record_name=None, dmarc_rua=(), dmarc_ruf=(),
            dmarc_report_auth=(),
        ),
    )


@pytest.fixture(autouse=True)
def _offline_org_rir_collect(request, monkeypatch):
    """planning#278 S3b1/S3b2: a claimed domain's follow-up also asks ARIN and
    RIPE, and under `TestClient` a background task runs inline, so every API
    test that claims a domain would reach them live. The runner's two RIR seams
    (`_rir_collect`, `_ripe_collect`) answer "no contacts" unless the test
    module sets `REAL_RIR_COLLECT = True` (and then patches both seams, or
    `rir_fetch.connector_get`, itself)."""
    if getattr(request.module, "REAL_RIR_COLLECT", False):
        return
    from app.services.org_discovery import arin, ripe, runner

    monkeypatch.setattr(
        runner, "_ripe_collect",
        lambda db, domain, fresh_since=None: ripe.RipeCollection(
            domain=domain, docs_found=0, docs_seen=0, fulltext_truncated=False, docs_other_type=0,
            contacts_not_exact=0, matched=(), resources=(), orgs_followed=0, fetch_failed=0,
            budget_exhausted=False, invalid_handles=0, invalid=0, skipped_status=0, skipped_source=0,
        ),
    )

    monkeypatch.setattr(
        runner, "_rir_collect",
        lambda db, domain, fresh_since=None: arin.ArinCollection(
            domain=domain, pocs_listed=0, pocs_truncated=False, pocs_not_exact=0, matched=(),
        ),
    )


@pytest.fixture(autouse=True)
def _restore_monkeypatched_modules():
    snapshots = [(mod, vars(mod).copy()) for mod in _GUARDED_MODULES]
    yield
    for mod, snapshot in snapshots:
        for name, original_value in snapshot.items():
            if vars(mod).get(name) is not original_value:
                setattr(mod, name, original_value)


@pytest.fixture(scope="session", autouse=True)
def _seed_llm_role_bindings():
    """planning#224 item 5: there is no code default for
    `llm.role_bindings`, so store the test bindings for the session (an
    install whose admin has configured AI models) and remove them after,
    keeping the run's zero-residue guarantee. See `llm_fixtures.py`."""
    import json

    from app.core.database import SessionLocal
    from app.models.app_settings import AppSetting
    from app.services import app_settings
    from app.tests.llm_fixtures import TEST_ROLE_BINDINGS

    key = "llm.role_bindings"
    db = SessionLocal()
    try:
        created = db.get(AppSetting, key) is None
        if created:
            app_settings.set_value(db, key, json.dumps(TEST_ROLE_BINDINGS))
    finally:
        db.close()
    yield
    if created:
        db = SessionLocal()
        try:
            row = db.get(AppSetting, key)
            if row is not None:
                db.delete(row)
                db.commit()
        finally:
            db.close()
