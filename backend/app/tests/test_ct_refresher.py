"""ct_refresher tick results (planning#336 slice 2). Runnable alone: python -m app.tests.test_ct_refresher"""

import pytest

from app.services import ct_refresher
from app.services.discovery import cert_transparency


@pytest.fixture
def patched(monkeypatch):
    monkeypatch.setattr(ct_refresher, "_calls_per_tick", lambda db: 5)
    monkeypatch.setattr(ct_refresher.time, "sleep", lambda s: None)


def test_tick_counts_refreshed_and_errors(patched, monkeypatch):
    calls = []

    def fake(domain):
        calls.append(domain)
        if domain == "b.example.com":
            raise RuntimeError("boom")

    monkeypatch.setattr(ct_refresher, "_select_targets_to_refresh", lambda db, limit: ["a.example.com", "b.example.com"])
    monkeypatch.setattr(cert_transparency, "prime_cache", fake)
    assert ct_refresher.tick() == ct_refresher.TickResult(targets=2, budget=5, refreshed=1, errors=1)
    assert calls == ["a.example.com", "b.example.com"]  # the loop WAS reached for both


def test_tick_with_no_targets_primes_nothing(patched, monkeypatch):
    calls = []
    monkeypatch.setattr(ct_refresher, "_select_targets_to_refresh", lambda db, limit: [])
    monkeypatch.setattr(cert_transparency, "prime_cache", lambda d: calls.append(d))
    assert ct_refresher.tick() == ct_refresher.TickResult(0, 5, 0, 0)
    assert calls == []


def test_a_selection_failure_propagates(patched, monkeypatch):
    def boom(db, limit):
        raise ValueError("x")

    monkeypatch.setattr(ct_refresher, "_select_targets_to_refresh", boom)
    with pytest.raises(ValueError):
        ct_refresher.tick()
