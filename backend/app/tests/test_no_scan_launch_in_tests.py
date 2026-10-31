"""planning#321: the suite never starts a scan launch, a scanner or a container runtime.

Claiming a candidate queues `targets._prime_ct_and_launch`, which under `TestClient`
runs inline (real Certspotter call, then `docker run` subfinder). The autouse
`scan_launches` fixture replaces it with a recorder and `subprocess_violations`
is a suite-wide tripwire on `subprocess.Popen`. These tests prove both are live.
"""
import subprocess
import sys

import pytest

from app.tests._org_world import World, client, hexid


@pytest.fixture
def w():
    world = World()
    try:
        yield world
    finally:
        world.close()


def test_a_claim_reaches_the_launch_recorder_and_spawns_nothing(w, scan_launches, subprocess_violations, monkeypatch):
    spawned: list = []
    tripwire_popen = subprocess.Popen

    class _Spy(tripwire_popen):
        def __init__(self, args, *a, **kw):
            spawned.append(args)
            super().__init__(args, *a, **kw)

    monkeypatch.setattr(subprocess, "Popen", _Spy)  # transport spy, wrapping the tripwire

    root = w.ours()
    c = w.candidate(root, value=f"w321-{hexid()}.example.com")
    r = client.post(f"/api/organizations/candidates/{c.id}/claim", json={}, headers=w.headers())
    assert r.status_code == 200, r.text
    w.track_target(c.value)

    assert len(scan_launches) == 1 and scan_launches[0][0] == c.value  # the path was REACHED
    assert spawned == []
    assert subprocess_violations == []


def test_the_tripwire_records_even_when_the_exception_is_swallowed(subprocess_violations):
    raised = False
    try:
        subprocess.run(["docker", "info"], capture_output=True)
    except Exception:  # scan_executor.launch does exactly this
        raised = True
    assert raised
    assert subprocess_violations == [["docker", "info"]]
    # The fixture fails the test at teardown if anything is left in the list; this
    # attempt was deliberate, so clear it or this test would fail on purpose-built input.
    subprocess_violations.clear()


def test_the_tripwire_reads_shell_strings_and_executable(subprocess_violations):
    for call in (
        lambda: subprocess.run('"/usr/bin/docker" run x', shell=True),  # quoted: needs shlex
        lambda: subprocess.run(["innocent", "info"], executable="/usr/local/bin/subfinder"),
    ):
        try:
            call()
        except RuntimeError:
            pass
    assert subprocess_violations == ['"/usr/bin/docker" run x', ["innocent", "info"]]
    subprocess_violations.clear()


def test_a_command_outside_the_blocked_set_still_runs(subprocess_violations):
    assert subprocess.run([sys.executable, "-c", "pass"]).returncode == 0
    assert subprocess_violations == []
