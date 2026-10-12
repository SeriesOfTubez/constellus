"""Tests for /httpx/fetch (planning#268): one URL, one IP literal, no redirects.

The subprocess transport (`subprocess.run`, which `_run_subprocess_soft`
calls) is replaced with a spy that records each command and the `-l` file
content, and writes a canned httpx JSONL row to the `-o` path.
"""

import json
import os
import sys

import pytest
from pydantic import ValidationError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main
from main import HttpxFetchRequest, httpx_fetch

PUBLIC = "203.0.113.10"  # RFC 5737; not on the worker blocklist
FOLLOW_FLAGS = ["-fr", "-follow-redirects", "-fhr", "-follow-host-redirects", "-maxr", "-max-redirects"]


def _t(**over):
    base = {"id": "a1", "ip": PUBLIC, "port": 443, "scheme": "https", "path": "/login.php?x=1", "host": None}
    base.update(over)
    return base


class Spy:
    def __init__(self, row=None, write=True):
        self.row = row
        self.write = write
        self.calls = []  # (cmd, url_file_content)

    def __call__(self, cmd, **kwargs):
        with open(cmd[cmd.index("-l") + 1]) as f:
            self.calls.append((cmd, f.read()))
        if self.write and self.row is not None:
            with open(cmd[cmd.index("-o") + 1], "w") as f:
                f.write(json.dumps(self.row) + "\n")

        class R:
            returncode = 0
            stdout = ""
            stderr = ""

        return R()


@pytest.fixture
def spy(monkeypatch):
    s = Spy(row={"status_code": 200, "title": "t", "location": ""})
    monkeypatch.setattr(main.subprocess, "run", s)
    return s


def _run(targets, **kw):
    return httpx_fetch(HttpxFetchRequest(targets=targets, **kw), None)["results"]


@pytest.mark.parametrize("over", [
    {"ip": "example.com"},
    {"path": "login"},
    {"path": "/a b"},
    {"path": "//evil.example/x"},
    {"path": "/a#frag"},
    {"path": "/a\x00b"},
    {"scheme": "ftp"},
    {"port": 0},
    {"id": "bad id"},
    {"host": "bad host!"},
    {"host": "-sni-flag.example.com"},
])
def test_invalid_target_rejected(over):
    with pytest.raises(ValidationError):
        HttpxFetchRequest(targets=[_t(**over)])


def test_201_targets_rejected():
    with pytest.raises(ValidationError):
        HttpxFetchRequest(targets=[_t(id=f"i{n}") for n in range(201)])


def test_200_targets_accepted():
    assert len(HttpxFetchRequest(targets=[_t(id=f"i{n}") for n in range(200)]).targets) == 200


@pytest.mark.parametrize("blocked", ["169.254.169.254", "10.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a9fe:a9fe"])
def test_blocked_ip_never_spawns_subprocess(spy, blocked):
    res = _run([_t(id="bad", ip=blocked), _t(id="good")])
    assert [r["id"] for r in res] == ["bad", "good"]
    assert res[0]["error"] == "blocked"
    # reached: the public target in the same request DID run
    assert len(spy.calls) == 1
    assert spy.calls[0][1].strip() == f"https://{PUBLIC}:443/login.php?x=1"
    assert res[1]["error"] is None and res[1]["status_code"] == 200


def test_hostname_host_command_shape(spy):
    _run([_t(host="app.example.com")])
    cmd, content = spy.calls[0]
    assert content == f"https://{PUBLIC}:443/login.php?x=1\n"
    assert cmd[cmd.index("-H") + 1] == "Host: app.example.com"
    assert "-sni=app.example.com" in cmd
    assert "-sni" not in cmd  # never a separate argv element
    assert "-nfs" in cmd
    assert cmd[cmd.index("-rstr") + 1] == "1048576"
    for flag in FOLLOW_FLAGS:
        assert flag not in cmd
    assert not any(PUBLIC in a for a in cmd)  # URL only via -l file


def test_subprocess_cap_is_timeout_plus_ten(monkeypatch):
    seen = {}

    def fake(cmd, **kw):
        seen.update(kw)
        raise main.subprocess.TimeoutExpired(cmd, kw["timeout"])

    monkeypatch.setattr(main.subprocess, "run", fake)
    res = _run([_t()], timeout=7.9)
    assert seen["timeout"] == 17
    assert res[0]["error"] == "timeout"


def test_ipv6_is_bracketed(spy):
    _run([_t(ip="2001:db8::1", port=8443)])
    assert spy.calls[0][1] == "https://[2001:db8::1]:8443/login.php?x=1\n"


def test_null_host_adds_no_host_flags(spy):
    _run([_t(host=None)])
    cmd = spy.calls[0][0]
    assert "-H" not in cmd and not any(a.startswith("-sni") for a in cmd)


def test_ip_literal_host_adds_no_host_flags(spy):
    _run([_t(host="198.51.100.7")])
    cmd = spy.calls[0][0]
    assert "-H" not in cmd and not any(a.startswith("-sni") for a in cmd)


def test_parse_redirect_row(monkeypatch):
    monkeypatch.setattr(main.subprocess, "run", Spy(row={"status_code": 302, "title": "Moved\x07", "location": "https://x.example/n"}))
    r = _run([_t()])[0]
    assert r == {"id": "a1", "status_code": 302, "title": "Moved", "location": "https://x.example/n", "error": None}


def test_hyphenated_status_key(monkeypatch):
    monkeypatch.setattr(main.subprocess, "run", Spy(row={"status-code": 404}))
    assert _run([_t()])[0]["status_code"] == 404


@pytest.mark.parametrize("bad", [999, 99, True, "200", None])
def test_out_of_range_status_is_null(monkeypatch, bad):
    monkeypatch.setattr(main.subprocess, "run", Spy(row={"status_code": bad, "title": "x"}))
    r = _run([_t()])[0]
    assert r["status_code"] is None and r["error"] is None


def test_truncation(monkeypatch):
    monkeypatch.setattr(main.subprocess, "run", Spy(row={"status_code": 200, "title": "a" * 900, "location": "b" * 900}))
    r = _run([_t()])[0]
    assert len(r["title"]) == 512 and len(r["location"]) == 300


def test_empty_output_is_no_response(monkeypatch):
    monkeypatch.setattr(main.subprocess, "run", Spy(row=None))
    assert _run([_t()])[0]["error"] == "no_response"


def test_results_in_input_order(spy):
    res = _run([_t(id=f"n{i}") for i in range(8)], concurrency=4)
    assert [r["id"] for r in res] == [f"n{i}" for i in range(8)]
    assert len(spy.calls) == 8
