"""Guard: page_capture.py reaches files only through capture_store (planning#318)."""

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "services" / "page_capture.py"
OS_CALLS = {"open", "fdopen", "listdir", "scandir", "lstat", "stat", "unlink", "remove", "rename", "replace"}
# The filesystem helpers page_capture imports for write_proxy_limits.
FS_HELPERS = {"open", "_open_regular", "_unlink_quiet", "_remove_entry"}
ALLOWED_FUNCTION = "write_proxy_limits"


def _offences(node: ast.AST) -> list[str]:
    out = []
    for n in ast.walk(node):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if isinstance(f, ast.Name) and f.id in FS_HELPERS:
            out.append(f"{f.id}( at line {n.lineno}")
        elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            if (f.value.id == "os" and f.attr in OS_CALLS) or f.value.id == "shutil":
                out.append(f"{f.value.id}.{f.attr} at line {n.lineno}")
    return out


def test_page_capture_uses_the_store_for_file_access():
    tree = ast.parse(SRC.read_text())
    found = False
    offences: list[str] = []
    allowed_ranges = []
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name == ALLOWED_FUNCTION:
            found = True
            allowed_ranges.append((n.lineno, n.end_lineno))
    assert found, f"{ALLOWED_FUNCTION} not found: the guard would pass vacuously"
    for o in _offences(tree):
        line = int(o.rsplit(" ", 1)[1])
        if not any(a <= line <= b for a, b in allowed_ranges):
            offences.append(o)
    assert not offences, f"direct file access in page_capture.py: go through capture_store (planning#318): {offences}"


def test_the_guard_detects_an_offence():
    bad = ast.parse(
        "import os\ndef f():\n    os.unlink('x')\n    open('y')\n    _open_regular('z')\n    os.fdopen(3)\n"
    )
    assert len(_offences(bad)) == 4
