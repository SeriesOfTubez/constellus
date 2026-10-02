"""Mutation-check a branch's guards: run the tests unmutated (the baseline
must pass), then once per mutation, and report which mutations the tests
kill.

    backend/.venv/Scripts/python.exe scripts/mutate.py <worktree> <mutations.py> [label-prefix ...]

`<mutations.py>` is a plain Python file (keep it in your scratchpad, not the
repo) defining:

    TESTS = ["app/tests/test_foo.py"]          # passed to backend/scripts/test.sh
    MUTATIONS = {
        "M1 guard removed": [
            ("backend/app/services/foo.py", "if x is None:\\n    return\\n", ""),
        ],
        # several edits in one mutation are applied together
    }

Each edit's OLD text must occur exactly once in its file, or the run stops:
a mutation that silently applies nowhere is a vacuous pass. Files are read
and written byte-exact (`newline=""`), restored after every mutation, and
compared against the originals at the end.

A SURVIVED mutation is either a real test gap or an equivalent mutation
(e.g. two guards that back each other up) — say which in the report. A
mutation that kills an UNEXPECTED test is good evidence: it proves that
test's precondition really fires.

Runs `backend/scripts/test.sh` through Git Bash (full path), which recreates
`constellus_test` each time — do not run two of these at once.
"""

from __future__ import annotations

import os
import re
import runpy
import subprocess
import sys
from pathlib import Path

GIT_BASH = r"C:\Program Files\Git\usr\bin\bash.exe"


def _read(path: Path) -> str:
    with open(path, encoding="utf-8", newline="") as f:
        return f.read()


def _write(path: Path, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def _run_tests(worktree: Path, tests: list[str]) -> tuple[int, list[str], str]:
    env = {**os.environ, "COMPOSE_PROJECT_NAME": "constellus"}
    r = subprocess.run(
        [GIT_BASH, "backend/scripts/test.sh", *tests, "-q", "-p", "no:cacheprovider", "-rf"],
        cwd=worktree, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
    )
    failed = sorted(set(re.findall(r"^FAILED (\S+)", r.stdout, re.M)))
    return r.returncode, failed, r.stdout + r.stderr


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    worktree = Path(sys.argv[1]).resolve()
    spec = runpy.run_path(sys.argv[2])
    tests: list[str] = spec["TESTS"]
    mutations: dict[str, list[tuple[str, str, str]]] = spec["MUTATIONS"]
    only = sys.argv[3:]

    files = {p for edits in mutations.values() for p, _, _ in edits}
    originals = {p: _read(worktree / p) for p in files}

    print("M0 baseline ...", flush=True)
    code, failed, out = _run_tests(worktree, tests)
    if code != 0:
        print(out[-4000:])
        print("BASELINE FAILED — fix the tests before mutating.")
        return 1
    print("M0 baseline: PASS", flush=True)

    results = []
    try:
        for label, edits in mutations.items():
            if only and not any(label.startswith(o) for o in only):
                continue
            try:
                for rel, old, new in edits:
                    current = _read(worktree / rel)
                    count = current.count(old)
                    if count != 1:
                        raise SystemExit(f"{label}: OLD text occurs {count}x in {rel} (must be exactly 1)")
                    _write(worktree / rel, current.replace(old, new))
                code, failed, _ = _run_tests(worktree, tests)
            finally:
                for rel in {r for r, _, _ in edits}:
                    _write(worktree / rel, originals[rel])
            verdict = "KILLED" if code != 0 else "SURVIVED"
            results.append((label, verdict))
            print(f"{label}: {verdict} ({len(failed)} failed)", flush=True)
            for f in failed:
                print(f"    {f.split('::')[-1][:120]}", flush=True)
    finally:
        for rel, text in originals.items():
            if _read(worktree / rel) != text:
                _write(worktree / rel, text)
                print(f"RESTORED {rel} (it had not been restored!)")

    survived = [label for label, v in results if v == "SURVIVED"]
    print(f"\n{len(results) - len(survived)}/{len(results)} killed")
    for label in survived:
        print(f"  SURVIVED: {label} — test gap or equivalent? say which")
    return 0


if __name__ == "__main__":
    sys.exit(main())
