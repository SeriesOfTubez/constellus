"""Drift alarm for the duplicated `store_auth.py` (capture-browser/capture/ and capture-proxy/).

The two build contexts cannot share a file, so the module exists twice. An identical copy of
this test lives in both suites; it fails on any divergence. The repo root is found by walking up.
"""

import hashlib
from pathlib import Path


def _find_repo_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "capture-browser").is_dir() and (parent / "capture-proxy").is_dir():
            return parent
    raise RuntimeError("repo root not found above " + __file__)


_ROOT = _find_repo_root()
_BROWSER_COPY = _ROOT / "capture-browser" / "capture" / "store_auth.py"
_PROXY_COPY = _ROOT / "capture-proxy" / "store_auth.py"


def test_both_copies_exist():
    assert _BROWSER_COPY.is_file() and _PROXY_COPY.is_file()


def test_the_two_copies_are_byte_identical():
    a = hashlib.sha256(_BROWSER_COPY.read_bytes()).hexdigest()
    b = hashlib.sha256(_PROXY_COPY.read_bytes()).hexdigest()
    assert a == b, "capture-browser/capture/store_auth.py and capture-proxy/store_auth.py have drifted"
