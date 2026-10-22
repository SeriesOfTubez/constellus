"""Static guard for the `/httpx/probe` command line (planning#231).

The web classifier needs the response headers and the Location header, so the
command asks httpx for them (`-irh`, `-location`). It must NEVER follow a
redirect: the Location target can be any host, including one outside the
authorised scan scope, and following it would fetch that host.

Read from the source rather than run: no subprocess, no network.
"""

import ast
from pathlib import Path

_MAIN = Path(__file__).resolve().parents[1] / "main.py"
_FOLLOW_FLAGS = {"-fr", "-follow-redirects", "-fhr", "-follow-host-redirects", "-maxr", "-max-redirects"}


def _probe_function() -> ast.FunctionDef:
    tree = ast.parse(_MAIN.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                if (isinstance(dec, ast.Call) and dec.args and isinstance(dec.args[0], ast.Constant)
                        and dec.args[0].value == "/httpx/probe"):
                    return node
    raise AssertionError("the /httpx/probe handler was not found")


def _command_flags(fn: ast.FunctionDef) -> list[str]:
    for node in ast.walk(fn):
        if (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "cmd" for t in node.targets)
                and isinstance(node.value, ast.List)):
            consts = [e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if consts and consts[0] == "httpx":
                return consts
    raise AssertionError("the httpx command list was not found")


def test_probe_asks_for_headers_and_location():
    flags = _command_flags(_probe_function())
    assert flags[0] == "httpx"  # reached: this is the real command
    assert "-irh" in flags and "-location" in flags


def test_probe_keeps_no_fallback_flag():
    flags = _command_flags(_probe_function())
    assert flags[0] == "httpx"  # reached: this is the real command
    assert "-nf" in flags


def test_probe_never_follows_redirects():
    flags = set(_command_flags(_probe_function()))
    assert not (flags & _FOLLOW_FLAGS)


def test_probe_output_whitelist_carries_header_and_location():
    keys = {n.value for n in ast.walk(_probe_function()) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    assert {"header", "location"} <= keys
