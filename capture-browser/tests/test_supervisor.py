"""The PID-1 capture supervisor (planning#324). Never calls the real kill(-1)."""

import os
import signal

import pytest

from capture import supervisor


class FakeChild:
    def __init__(self, rc=0, on_wait=None, events=None):
        self.rc, self.on_wait, self.events = rc, on_wait, events
        self.signals = []

    def wait(self):
        if self.on_wait:
            self.on_wait()
        return self.rc

    def poll(self):
        return None

    def send_signal(self, sig):
        self.signals.append(sig)


class Rig:
    def __init__(self, tmp_path):
        self.events = []
        self.kills = []
        self.scratch = tmp_path / "scratch"
        self.scratch.mkdir()
        self.children = []
        self.waitpids = 0
        self.wipe_calls = 0

    def kill(self, pid, sig):
        self.kills.append((pid, sig))
        self.events.append("kill")

    def waitpid(self, pid, opts):
        self.waitpids += 1
        self.events.append("waitpid")
        if self.waitpids % 3 == 0:  # third call of each round: nothing left
            raise ChildProcessError
        return (123, 0)

    def run(self, spawn, **kw):
        return supervisor.supervise(
            kill=self.kill, waitpid=self.waitpid, spawn=spawn,
            scratch_dirs=(str(self.scratch),), getpid=lambda: 1,
            install_signals=False, **kw,
        )


@pytest.fixture
def rig(tmp_path, monkeypatch):
    r = Rig(tmp_path)
    real = supervisor.wipe_scratch

    def wipe(dirs):
        r.wipe_calls += 1
        r.events.append("wipe")
        real(dirs)

    monkeypatch.setattr(supervisor, "wipe_scratch", wipe)
    return r


def test_refuses_when_not_pid_1(rig):
    spawned = []
    with pytest.raises(SystemExit) as exc:
        supervisor.supervise(
            kill=rig.kill, waitpid=rig.waitpid, spawn=lambda: spawned.append(1),
            scratch_dirs=(str(rig.scratch),), getpid=lambda: 4242, install_signals=False,
        )
    assert "PID 1" in str(exc.value)
    assert spawned == [] and rig.kills == []


def test_exit_zero_cleans_then_respawns_in_order(rig):
    state = {}

    def spawn():
        rig.events.append("spawn")
        n = sum(1 for e in rig.events if e == "spawn")
        (rig.scratch / f"junk{n}").write_text("x")
        stop = (lambda: state.update(stop=True)) if n == 2 else None
        return FakeChild(0, on_wait=stop)

    assert rig.run(spawn, state=state) == 0
    assert rig.kills == [(-1, signal.SIGKILL)] * 2
    # per round: spawn, kill, reap (until ChildProcessError), wipe; then next spawn
    ev = rig.events
    assert ev[0] == "spawn"
    first_kill, first_wipe = ev.index("kill"), ev.index("wipe")
    second_spawn = ev.index("spawn", 1)
    assert first_kill < first_wipe < second_spawn
    assert "waitpid" in ev[first_kill:first_wipe]
    assert rig.waitpids >= 3  # the reap loop ran until ChildProcessError
    assert os.listdir(rig.scratch) == []  # wiped after the last child too


@pytest.mark.parametrize("rc", [3, -9])
def test_failing_child_cleans_up_and_exits_one_without_respawn(rig, rc):
    spawned = []

    def spawn():
        spawned.append(1)
        return FakeChild(rc)

    assert rig.run(spawn) == 1
    assert len(spawned) == 1
    assert rig.kills == [(-1, signal.SIGKILL)] and rig.wipe_calls == 1


def test_wipe_does_not_follow_symlinks(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    outside_file = tmp_path / "outside_file.txt"
    outside_file.write_text("keep too")
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(); b.mkdir()
    (a / "f").write_text("x")
    (a / "nested" / "deeper").mkdir(parents=True)
    (a / "nested" / "deeper" / "g").write_text("x")
    (a / "link_dir").symlink_to(outside, target_is_directory=True)
    (a / "nested" / "inner_link").symlink_to(outside, target_is_directory=True)
    (b / "link_file").symlink_to(outside_file)
    supervisor.wipe_scratch((str(a), str(b), str(tmp_path / "missing")))
    assert a.is_dir() and os.listdir(a) == []
    assert b.is_dir() and os.listdir(b) == []
    assert (outside / "keep.txt").read_text() == "keep"
    assert outside_file.read_text() == "keep too"
    assert not (tmp_path / "missing").exists()


def test_wipe_failure_exits_nonzero_without_respawn(rig, monkeypatch):
    (rig.scratch / "stuck").write_text("x")

    def boom(path):
        raise OSError("read-only")

    monkeypatch.setattr(supervisor.os, "unlink", boom)
    spawned = []

    def spawn():
        spawned.append(1)
        return FakeChild(0)

    assert rig.run(spawn) == 1
    assert len(spawned) == 1
    assert (rig.scratch / "stuck").exists()  # the failure path was reached


def test_signal_terminates_child_cleans_and_exits_zero(rig):
    child = FakeChild(0)
    state = {}

    def trigger():
        state["on_signal"](signal.SIGTERM, None)

    child.on_wait = trigger
    spawned = []

    def spawn():
        spawned.append(1)
        return child

    assert rig.run(spawn, state=state) == 0
    assert child.signals == [signal.SIGTERM]
    assert len(spawned) == 1  # no respawn after stop
    assert rig.kills == [(-1, signal.SIGKILL)] and rig.wipe_calls == 1


def test_reap_all_stops_on_child_process_error():
    calls = []

    def wp(pid, opts):
        calls.append(pid)
        if len(calls) == 3:
            raise ChildProcessError
        return (1, 0)

    supervisor.reap_all(wp)
    assert calls == [-1, -1, -1]


def test_kill_ignores_nothing_left():
    def kill(pid, sig):
        raise ProcessLookupError

    supervisor.kill_everything(kill)
