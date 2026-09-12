"""The drift alarm for the duplicated egress blocklist.

`ip_blocklist.py` exists twice — once here, once at
`backend/app/core/ip_blocklist.py` — because the backend and the worker are
separate Docker build contexts and neither can COPY from a shared parent.
The duplication is forced by the build topology. The DRIFT is not.

Before this file existed, the two copies were kept in step by a comment
asking the next maintainer to keep them in sync. That failed exactly the way
such comments do: the backend gained IPv4-in-IPv6 unwrapping, this copy
never did, and for some period the component that actually opens sockets
would happily connect to `64:ff9b::a9fe:a9fe` — the cloud metadata endpoint
behind a NAT64 prefix.

Two independent checks, because each catches what the other misses:

  * a SHA-256 comparison — catches any divergence at all, including a
    comment or a new network added to one side only;
  * a behavioural case table run against BOTH copies — catches the case
    where someone "fixes" the hash by copying a file that is itself wrong,
    and documents what the guard is actually for.

An identical copy of this file lives in the backend suite, so the alarm
fires whichever side CI runs.
"""

import hashlib
import ipaddress
import importlib.util
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKER_COPY = _REPO_ROOT / "scanner-worker" / "ip_blocklist.py"
_BACKEND_COPY = _REPO_ROOT / "backend" / "app" / "core" / "ip_blocklist.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# Every address here is a documentation/special-use value or a well-known
# public resolver — no real customer address in a tracked file (CLAUDE.md).
# (address, must_be_blocked, why)
_CASES = [
    # The drift that prompted this file. Each of these reaches an internal
    # address while being spelled as IPv6, and each passed the worker's old
    # guard because an IPv6Address is never `in` an IPv4 network.
    ("::ffff:10.0.0.1", True, "IPv4-mapped RFC1918"),
    ("::ffff:192.168.1.1", True, "IPv4-mapped RFC1918"),
    ("::ffff:169.254.169.254", True, "IPv4-mapped cloud metadata"),
    ("::10.0.0.1", True, "IPv4-compatible (RFC 4291, deprecated but parsed)"),
    ("2002:0a00:0001::", True, "6to4 relay -> 10.0.0.1"),
    ("64:ff9b::a01:a01", True, "NAT64 well-known -> 10.1.10.1"),
    ("64:ff9b::a9fe:a9fe", True, "NAT64 well-known -> cloud metadata"),
    ("64:ff9b:1::1", True, "RFC 8215 local-use NAT64, blocked wholesale"),
    # Plain forms.
    ("10.0.0.1", True, "RFC1918"),
    ("172.16.0.1", True, "RFC1918"),
    ("192.168.1.1", True, "RFC1918"),
    ("127.0.0.1", True, "loopback"),
    ("169.254.169.254", True, "cloud metadata"),
    ("100.64.0.1", True, "CGNAT"),
    ("0.0.0.0", True, "unspecified"),
    ("224.0.0.1", True, "multicast"),
    ("::1", True, "IPv6 loopback"),
    ("fe80::1", True, "IPv6 link-local"),
    ("fc00::1", True, "IPv6 unique local"),
    ("ff02::1", True, "IPv6 multicast"),
    # Must still be ALLOWED. The encoding was never the danger — the
    # destination was. A guard that blocked these would break real scanning
    # and would pass every test above.
    ("8.8.8.8", False, "public IPv4"),
    ("1.1.1.1", False, "public IPv4"),
    ("2606:4700::1111", False, "public IPv6"),
    ("::ffff:8.8.8.8", False, "IPv4-mapped PUBLIC address"),
]


def test_the_two_copies_are_byte_identical():
    assert _WORKER_COPY.exists(), _WORKER_COPY
    assert _BACKEND_COPY.exists(), _BACKEND_COPY
    worker, backend = _sha(_WORKER_COPY), _sha(_BACKEND_COPY)
    assert worker == backend, (
        "ip_blocklist.py has DRIFTED between the backend and the scanner-worker.\n"
        f"  {_BACKEND_COPY}  sha256={backend}\n"
        f"  {_WORKER_COPY}  sha256={worker}\n"
        "Edit one, then copy it over the other. The worker is the component "
        "that actually opens sockets, so a worker copy lagging the backend is "
        "a live egress hole, not a style inconsistency."
    )


def test_both_copies_agree_on_every_case():
    """Guards against 'fixing' the hash by copying a file that is itself
    wrong — the hash check alone would go green."""
    worker = _load(_WORKER_COPY, "_parity_worker_blocklist")
    backend = _load(_BACKEND_COPY, "_parity_backend_blocklist")
    for value, _expected, why in _CASES:
        ip = ipaddress.ip_address(value)
        assert worker.is_blocked(ip) == backend.is_blocked(ip), f"{value} ({why})"


def test_internal_destinations_are_blocked_however_they_are_spelled():
    worker = _load(_WORKER_COPY, "_parity_worker_blocklist")
    for value, expected, why in _CASES:
        ip = ipaddress.ip_address(value)
        assert worker.is_blocked(ip) is expected, f"{value} ({why})"


def test_embedded_ipv4_does_not_claim_loopback_embeds_an_address():
    """`::` and `::1` fall inside ::/96 but are the unspecified and loopback
    addresses, not IPv4-compatible ones. Both are blocked by the first
    branch regardless, so this pins the helper's honesty rather than a
    verdict."""
    worker = _load(_WORKER_COPY, "_parity_worker_blocklist")
    assert worker.embedded_ipv4(ipaddress.ip_address("::")) is None
    assert worker.embedded_ipv4(ipaddress.ip_address("::1")) is None
    assert worker.embedded_ipv4(ipaddress.ip_address("8.8.8.8")) is None


def test_teredo_classifies_the_server_not_the_client():
    """Teredo carries two IPv4 addresses. The SERVER is where the packet
    actually goes; the client address is a payload. Classifying the client
    would both miss a hostile server and false-positive on a benign one."""
    worker = _load(_WORKER_COPY, "_parity_worker_blocklist")
    # 2001:0:<server>:... — server 10.0.0.1, an internal destination.
    embedded = worker.embedded_ipv4(ipaddress.ip_address("2001:0:0a00:0001::"))
    assert embedded == ipaddress.IPv4Address("10.0.0.1"), embedded


if __name__ == "__main__":
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
    print("blocklist parity verified")
