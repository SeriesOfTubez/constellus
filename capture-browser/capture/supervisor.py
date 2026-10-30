"""PID-1 supervisor for the capture worker (planning#324).

The worker captures ONE page per process. A container restart per capture works
in Docker but the kubelet applies CrashLoopBackOff even to exit 0 (74-321 s
between captures on the kind lab). So this supervisor stays alive as PID 1 and
starts a fresh worker process per capture, restoring the isolation the restart
used to give: after EVERY worker exit it kills every other process in the
container, reaps them, and wipes the scratch directories.

Run as ``python -m capture.supervisor``. ``capture.worker`` stays runnable alone.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys

from capture.worker import _make_undumpable

SCRATCH_DIRS = ("/tmp", "/home/capture", "/dev/shm")


def _log(msg: str) -> None:
    print(f"capture-supervisor: {msg}", file=sys.stderr, flush=True)


def _spawn() -> subprocess.Popen:
    # Inherits env and stdio; the worker drops CAPTURE_S3_* from its own env.
    return subprocess.Popen([sys.executable, "-m", "capture.worker"])


def kill_everything(kill=os.kill) -> None:
    """SIGKILL every process we may signal. Only safe as the namespace's PID 1:
    kill(-1) from anything else would hit the user's other same-uid processes."""
    try:
        kill(-1, signal.SIGKILL)
    except ProcessLookupError:
        pass  # nothing left


def reap_all(waitpid=os.waitpid) -> None:
    """Orphans re-parent to PID 1; unreaped they stay zombies."""
    while True:
        try:
            waitpid(-1, 0)
        except ChildProcessError:
            return
        except InterruptedError:
            continue


def wipe_scratch(scratch_dirs=SCRATCH_DIRS) -> None:
    """Empty each scratch dir (never the mount point itself). Symlinks and
    non-directories are unlinked, never followed; rmtree does not follow
    symlinks inside. Raises OSError on any failure."""
    for base in scratch_dirs:
        if not os.path.isdir(base):
            continue
        with os.scandir(base) as it:
            entries = list(it)
        for entry in entries:
            if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                os.unlink(entry.path)
            else:
                shutil.rmtree(entry.path)


def _cleanup(kill, waitpid, scratch_dirs) -> bool:
    """Kill, reap, wipe, in that order. False when the wipe failed."""
    kill_everything(kill)
    reap_all(waitpid)
    try:
        wipe_scratch(scratch_dirs)
    except OSError as exc:
        _log(f"scratch wipe failed: {exc!r}; exiting so the container restarts clean")
        return False
    return True


def _wait_child(child) -> int:
    while True:
        try:
            return child.wait()
        except InterruptedError:
            continue


def supervise(
    *,
    kill=os.kill,
    waitpid=os.waitpid,
    spawn=_spawn,
    scratch_dirs=SCRATCH_DIRS,
    getpid=os.getpid,
    install_signals=True,
    state: dict | None = None,
) -> int:
    # kill(-1, SIGKILL) from anything but the namespace's PID 1 would hit every
    # other process of this uid (on a dev machine: all of the user's processes).
    if getpid() != 1:
        raise SystemExit("capture-supervisor: refusing to start: not PID 1 in its namespace")

    state = {} if state is None else state  # a test passes its own to reach on_signal
    state.update(stop=False, child=None)

    def on_signal(signum, _frame):
        state["stop"] = True
        child = state["child"]
        if child is not None and child.poll() is None:
            try:
                child.send_signal(signal.SIGTERM)
            except ProcessLookupError:
                pass

    if install_signals:
        # PID 1 only receives signals it has handlers for.
        signal.signal(signal.SIGTERM, on_signal)
        signal.signal(signal.SIGINT, on_signal)
    state["on_signal"] = on_signal

    _log("started")
    while not state["stop"]:
        child = spawn()
        state["child"] = child
        if state["stop"]:  # signal landed between the check and the assignment
            child.send_signal(signal.SIGTERM)
        rc = _wait_child(child)
        state["child"] = None
        if not _cleanup(kill, waitpid, scratch_dirs):
            return 1
        if state["stop"]:
            break
        if rc != 0:
            _log(f"worker exited with status {rc}; exiting so the container restarts")
            return 1
    _log("stopping")
    return 0


def main() -> int:
    _make_undumpable()  # we hold the store key in our env too
    return supervise()


if __name__ == "__main__":
    sys.exit(main())
