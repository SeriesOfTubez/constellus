"""Tests for planning#270: /httpx/probe and /tlsx/scan hand the tool ONLY the
address that passed the egress check, never a hostname the tool could
re-resolve (DNS TOCTOU).

Two transports are replaced:
  * `main.socket.getaddrinfo` answers a PUBLIC address on the FIRST lookup of a
    name and a PRIVATE one on every later lookup, so any second lookup anywhere
    in the code under test would hand a private address to the tool;
  * `main.subprocess.run` (what `_run_subprocess_soft` calls) records each
    command and the `-l` file content and writes JSONL (real wire shape, port
    as a STRING) for exactly the lines it received.
"""

import json
import os
import socket
import subprocess
import sys
import threading

import pytest
from fastapi import HTTPException

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main
from main import HttpxProbeRequest, TlsxScanRequest, httpx_probe, tlsx_scan

PUBLIC = "203.0.113.10"  # RFC 5737; not on the worker blocklist
PUBLIC2 = "203.0.113.20"
PRIVATE = "10.0.0.5"
FOLLOW_FLAGS = ["-fr", "-follow-redirects", "-fhr", "-follow-host-redirects", "-maxr", "-max-redirects"]


def _v4(ip):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]


def _v6(ip):
    return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, 0, 0, 0))]


class FakeDNS:
    """First lookup of a name -> its public answer; later lookups -> PRIVATE."""

    def __init__(self, first=None):
        self.first = first or {}  # name -> addrinfo list
        self.calls = {}
        self.lock = threading.Lock()

    def __call__(self, host, port=None, *a, **k):
        with self.lock:
            n = self.calls.get(host, 0)
            self.calls[host] = n + 1
        if n == 0:
            return self.first.get(host, _v4(PUBLIC))
        return _v4(PRIVATE)


def _split_hostport(line):
    host, _, port = line.rpartition(":")
    return host.strip("[]"), port


class Spy:
    def __init__(self, kind, rc_for=None, timeout_for=None):
        self.kind = kind
        self.rc_for = rc_for or (lambda lines: 0)
        self.timeout_for = timeout_for or (lambda lines: False)
        self.calls = []  # (cmd, [lines of the -l file])
        self.lock = threading.Lock()

    def __call__(self, cmd, **kwargs):
        with open(cmd[cmd.index("-l") + 1]) as f:
            lines = f.read().split()
        with self.lock:
            self.calls.append((cmd, lines))
        with open(cmd[cmd.index("-o") + 1], "w") as f:
            for line in lines:
                host, port = _split_hostport(line)
                if self.kind == "httpx":
                    row = {"input": line, "host": host, "port": port, "scheme": "https",
                           "status_code": 200, "title": "t", "tech": [], "jarm_hash": "j"}
                else:
                    row = {"host": host, "ip": host, "port": port, "subject_cn": "cn",
                           "subject_an": [], "issuer_org": ["org"], "tls_version": "tls13"}
                f.write(json.dumps(row) + "\n")
        if self.timeout_for(lines):
            raise subprocess.TimeoutExpired(cmd, 300)

        rc = self.rc_for(lines)

        class R:
            returncode = rc
            stdout = ""
            stderr = "boom" if rc else ""

        return R()


ENDPOINTS = {
    "httpx": (lambda targets: httpx_probe(HttpxProbeRequest(targets=targets), None), "input_host"),
    "tlsx": (lambda targets: tlsx_scan(TlsxScanRequest(targets=targets), None), "host"),
}


@pytest.fixture(params=["httpx", "tlsx"])
def ep(request, monkeypatch):
    kind = request.param
    call, name_key = ENDPOINTS[kind]

    class Ctx:
        pass

    c = Ctx()
    c.kind, c.name_key = kind, name_key
    c.dns = FakeDNS()
    monkeypatch.setattr(main.socket, "getaddrinfo", c.dns)

    def install(**kw):
        c.spy = Spy(kind, **kw)
        monkeypatch.setattr(main.subprocess, "run", c.spy)

    install()
    c.install = install
    c.call = lambda targets: call([{"ip": ip, "port": p} for ip, p in targets])
    return c


def _names_in(cmd, kind):
    return [a[len("-sni="):] for a in cmd if a.startswith("-sni=")]


def _is_host_run(cmd):
    return any(a.startswith("-sni=") for a in cmd)


def test_hostname_target_is_pinned(ep):
    out = ep.call([("shop.example.com", 443), ("shop.example.com", 8443)])
    assert ep.dns.calls == {"shop.example.com": 1}  # REACHED, and resolved exactly once
    assert len(ep.spy.calls) == 1
    cmd, lines = ep.spy.calls[0]
    assert lines == [f"{PUBLIC}:443", f"{PUBLIC}:8443"]
    assert "shop.example.com" not in "".join(lines)
    assert "-sni=shop.example.com" in cmd
    if ep.kind == "httpx":
        assert cmd[cmd.index("-H") + 1] == "Host: shop.example.com"
    else:
        assert "-H" not in cmd
    rows = out["results"]
    assert len(rows) == 2
    assert {r["ip"] for r in rows} == {PUBLIC}
    assert {r[ep.name_key] for r in rows} == {"shop.example.com"}
    assert sorted(r["port"] for r in rows) == [443, 8443]


def test_mixed_batch_three_runs(ep):
    ep.dns.first["fabrikam.example"] = _v4(PUBLIC2)
    out = ep.call([
        ("192.0.2.7", 443), ("198.51.100.9", 8443),
        ("shop.example.com", 443), ("shop.example.com", 8443),
        ("fabrikam.example", 443),
    ])
    assert len(ep.spy.calls) == 3
    ip_runs = [(c, l) for c, l in ep.spy.calls if not _is_host_run(c)]
    host_runs = {_names_in(c, ep.kind)[0]: (c, l) for c, l in ep.spy.calls if _is_host_run(c)}
    assert len(ip_runs) == 1
    cmd, lines = ip_runs[0]
    assert sorted(lines) == ["192.0.2.7:443", "198.51.100.9:8443"]
    assert "-H" not in cmd and not any(a.startswith("-sni") for a in cmd)
    assert set(host_runs) == {"shop.example.com", "fabrikam.example"}
    for name, (c, l) in host_runs.items():
        assert _names_in(c, ep.kind) == [name]
        assert sum(a == f"-sni={name}" for a in c) == 1
    assert host_runs["shop.example.com"][1] == [f"{PUBLIC}:443", f"{PUBLIC}:8443"]
    assert host_runs["fabrikam.example"][1] == [f"{PUBLIC2}:443"]
    assert len(out["results"]) == 5
    by_name = {r[ep.name_key]: r for r in out["results"] if r[ep.name_key] == "fabrikam.example"}
    assert by_name["fabrikam.example"]["ip"] == PUBLIC2
    assert ep.dns.calls == {"shop.example.com": 1, "fabrikam.example": 1}


def test_hostname_resolving_private_is_not_run(ep):
    ep.dns.first["internal.example"] = _v4(PRIVATE)
    out = ep.call([("internal.example", 443), ("192.0.2.7", 443)])
    assert ep.dns.calls == {"internal.example": 1}  # REACHED: the check ran
    assert len(ep.spy.calls) == 1  # only the IP run
    assert all("internal.example" not in " ".join(c) and "internal.example" not in "".join(l)
               for c, l in ep.spy.calls)
    assert [r["ip"] for r in out["results"]] == ["192.0.2.7"]


def test_leading_dash_hostname_dropped(ep):
    out = ep.call([("-oops.example", 443), ("shop.example.com", 443), ("192.0.2.7", 443)])
    assert "-oops.example" in ep.dns.calls  # REACHED the partition, then dropped
    assert len(ep.spy.calls) == 2
    for cmd, lines in ep.spy.calls:
        assert not any("oops" in a for a in cmd)
        assert not any("oops" in l for l in lines)
    assert len(out["results"]) == 2


def test_ipv6_pinned_and_bracketed(ep):
    ep.dns.first["v6.example.com"] = _v6("2001:db8::10")
    out = ep.call([("v6.example.com", 443), ("2001:db8::5", 443)])
    assert len(ep.spy.calls) == 2
    lines = sorted(l for _, ls in ep.spy.calls for l in ls)
    assert lines == ["[2001:db8::10]:443", "[2001:db8::5]:443"]
    by = {r["ip"]: r for r in out["results"]}
    assert set(by) == {"2001:db8::10", "2001:db8::5"}
    assert by["2001:db8::10"][ep.name_key] == "v6.example.com"


def test_one_failed_run_does_not_fail_the_batch(ep):
    ep.dns.first["fabrikam.example"] = _v4(PUBLIC2)
    ep.install(rc_for=lambda lines: 1 if lines == [f"{PUBLIC2}:443"] else 0)
    out = ep.call([("shop.example.com", 443), ("fabrikam.example", 443)])
    assert len(ep.spy.calls) == 2  # REACHED: both runs happened
    assert [r["ip"] for r in out["results"]] == [PUBLIC]  # failed run: no rows


def test_all_runs_failing_raises_500(ep):
    ep.install(rc_for=lambda lines: 1)
    with pytest.raises(HTTPException) as ei:
        ep.call([("shop.example.com", 443), ("192.0.2.7", 443)])
    assert ei.value.status_code == 500
    assert len(ep.spy.calls) == 2


def test_timeout_is_ored_and_partial_rows_kept(ep):
    ep.install(timeout_for=lambda lines: lines == [f"{PUBLIC}:443"])
    out = ep.call([("shop.example.com", 443), ("192.0.2.7", 443)])
    assert out["timed_out"] is True
    assert len(out["results"]) == 2  # the timed-out run's partial output is parsed
    assert len(ep.spy.calls) == 2


def test_timeout_plus_failed_run_keeps_partial_rows(ep):
    # The only other run exits non-zero; the timed-out run's partial rows must
    # still come back rather than a 500 discarding them.
    ep.install(
        timeout_for=lambda lines: lines == [f"{PUBLIC}:443"],
        rc_for=lambda lines: 1,
    )
    out = ep.call([("shop.example.com", 443), ("192.0.2.7", 443)])
    assert len(ep.spy.calls) == 2  # REACHED: both runs happened
    assert out["timed_out"] is True
    assert [r["ip"] for r in out["results"]] == [PUBLIC]


def test_httpx_hostname_run_keeps_nf_and_never_follows_redirects(monkeypatch):
    monkeypatch.setattr(main.socket, "getaddrinfo", FakeDNS())
    spy = Spy("httpx")
    monkeypatch.setattr(main.subprocess, "run", spy)
    httpx_probe(HttpxProbeRequest(targets=[{"ip": "shop.example.com", "port": 443}]), None)
    assert len(spy.calls) == 1
    cmd = spy.calls[0][0]
    assert any(a.startswith("-sni=") for a in cmd)  # REACHED: this is the hostname run
    assert "-nf" in cmd
    assert not set(cmd) & set(FOLLOW_FLAGS)
