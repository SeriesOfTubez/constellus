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

from app.services import domain_affinity
from app.services import hosting_classifier
from app.services import origin_corroboration
from app.services import shared_infra_verifier
from app.services import takeover_fingerprint

_GUARDED_MODULES = [
    domain_affinity,
    hosting_classifier,
    origin_corroboration,
    shared_infra_verifier,
    takeover_fingerprint,
]


@pytest.fixture(autouse=True)
def _restore_monkeypatched_modules():
    snapshots = [(mod, vars(mod).copy()) for mod in _GUARDED_MODULES]
    yield
    for mod, snapshot in snapshots:
        for name, original_value in snapshot.items():
            if vars(mod).get(name) is not original_value:
                setattr(mod, name, original_value)
