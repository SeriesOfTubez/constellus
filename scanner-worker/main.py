import asyncio
import concurrent.futures
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import tempfile
import defusedxml.ElementTree as ET  # XXE-safe parser for nmap XML output

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, field_validator

log = logging.getLogger(__name__)

# Single shared token for every endpoint on this worker.
_TOKEN = os.environ.get("SCANNER_INTERNAL_TOKEN", "")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def _require_token(request: Request) -> None:
    if not _TOKEN:
        raise HTTPException(status_code=500, detail="SCANNER_INTERNAL_TOKEN not configured")
    if request.headers.get("X-Internal-Token", "") != _TOKEN:
        raise HTTPException(status_code=403)


# Allow-lists so user-controlled strings can never become CLI flag injections.
# subprocess.run(..., shell=False) is already safe from shell metacharacters, but
# both nuclei and naabu interpret leading `-` as a flag, so a value like "-foo"
# would still be smuggled in as a new argument. We map each accepted user token
# to its canonical *module-level constant* string before handing it to
# subprocess — every byte passed to the binary is therefore a literal from
# this file. CodeQL's taint analysis sees the final args as built from literals.
_SEVERITY_LOOKUP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "unknown",
}
_TAG_LOOKUP: dict[str, str] = {
    "intrusive": "intrusive",
    "fuzz": "fuzz",
    "dos": "dos",
    "cve": "cve",
    "exposure": "exposure",
    "misconfig": "misconfig",
    "default-login": "default-login",
    "tech": "tech",
}
# Allow-list for nuclei's -tags (include) filter — Session D / issue #12.
# Every value backend/app/services/nuclei_tag_filter.py's compute_tag_union()
# can produce MUST appear here, mapped to itself, following the same
# CodeQL-taint-cleansing pattern as _TAG_LOOKUP above. Unknown tags are
# rejected (422) rather than silently dropped. Note "cve"/"vuln" are
# intentionally absent — see nuclei_tag_filter.py for why.
_INCLUDE_TAG_LOOKUP: dict[str, str] = {
    # Baseline (tech-agnostic) categories — always present.
    "panel": "panel",
    "exposure": "exposure",
    "misconfig": "misconfig",
    "default-login": "default-login",
    "takeover": "takeover",
    "unauth": "unauth",
    "config": "config",
    "network": "network",
    "ssl": "ssl",
    "tech": "tech",
    # Service-derived tags (zgrab2/banner_grab).
    "ssh": "ssh",
    "ftp": "ftp",
    "smtp": "smtp",
    "pop3": "pop3",
    "imap": "imap",
    "mysql": "mysql",
    "redis": "redis",
    "postgresql": "postgresql",
    "mssql": "mssql",
    "modbus": "modbus",
    "mongodb": "mongodb",
    "smb": "smb",
    "rdp": "rdp",
    "memcached": "memcached",
    "vnc": "vnc",
    "http": "http",
    # Tech-stack-derived tags (httpx/Wappalyzer).
    "wordpress": "wordpress",
    "joomla": "joomla",
    "drupal": "drupal",
    "jenkins": "jenkins",
    "apache": "apache",
    "nginx": "nginx",
    "iis": "iis",
    "tomcat": "tomcat",
    "grafana": "grafana",
    "gitlab": "gitlab",
    "confluence": "confluence",
    "jira": "jira",
    "magento": "magento",
    "php": "php",
    "nodejs": "nodejs",
}
_SEVERITY_RE = re.compile(r"^(critical|high|medium|low|info|unknown)(,(critical|high|medium|low|info|unknown))*$")
_TAG_TOKEN_RE = re.compile(r"^[a-z0-9_-]{1,40}$")
_TAGS_RE = re.compile(r"^[a-z0-9_-]+(,[a-z0-9_-]+)*$")
_TARGET_RE = re.compile(r"^[a-zA-Z0-9._:\-/\[\]]{1,253}$")

# Hosts naabu scans are IPs or hostnames — same syntax as nuclei targets but
# no scheme/port suffix; naabu reports the port itself.
_NAABU_HOST_RE = re.compile(r"^[a-zA-Z0-9._\-]{1,253}$")


# ──────────────────────────────────────────────────────────────────────────────
# SSRF egress guard (planning#89).
#
# Every endpoint below eventually resolves a hostname (or accepts a literal
# IP) and connects to it — that's the whole point of an active scanner. Without
# a check here, ANY authorized DNS record pointing at a private/loopback/
# link-local/metadata address (e.g. a benign internal split-horizon record, or
# 169.254.169.254) causes this worker to connect to the deployer's own internal
# network or the cloud metadata endpoint — no attacker-controlled DNS required.
#
# Mirrors backend/app/core/ssrf.py's blocklist — duplicated, not imported,
# because scanner-worker is a separate Docker build context (only main.py is
# copied in; see Dockerfile) with no access to the backend package. Keep the
# two lists in sync.
#
# Two usage patterns depending on whether the tool needs the real hostname:
#   - naabu / banner_grab / zgrab2 / nmap-verify don't need Host header / SNI
#     correctness — resolve, validate, and PIN the connection to one validated
#     IP (_resolve_public_ip / _resolve_public_ip_async). This also closes the
#     resolve-vs-connect TOCTOU/DNS-rebind window for these tools.
#   - nuclei / httpx / tlsx are subprocess CLI tools that must keep the real
#     hostname as their target — that's the entire reason CDN-fronted hostnames
#     are sent instead of an IP (connectors/base.py:cdn_scan_targets needs the
#     correct Host header / TLS SNI to reach the customer's app behind a CDN
#     edge). We validate the hostname resolves to a public address before
#     invoking the tool, but the tool re-resolves internally — a genuinely
#     time-of-check DNS-rebinding attacker (as opposed to the far more common
#     static internal-pointing record) could still race this window. Accepted
#     residual risk for these three tools; the static case — the one this
#     issue is about — is fully closed for every tool.
#
# A target that fails validation is DROPPED, not treated as a request error —
# erroring the whole batch would let one poisoned record blank an entire scan
# (the same failure mode as planning#90), which is worse than just skipping it.
# ──────────────────────────────────────────────────────────────────────────────

_BLOCKED_NETWORKS: tuple = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),    # RFC 6598 CGNAT
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / cloud metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),    # benchmarking
    ipaddress.ip_network("224.0.0.0/4"),      # multicast
    ipaddress.ip_network("240.0.0.0/4"),      # reserved
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("ff00::/8"),         # IPv6 multicast
)


class EgressBlockedError(ValueError):
    """Raised when a target is (or resolves only to) a blocked/private/
    internal address. Callers catch this and drop the offending target
    rather than failing the whole batch."""


def _is_blocked_ip(ip: "ipaddress.IPv4Address | ipaddress.IPv6Address") -> bool:
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    if isinstance(ip, ipaddress.IPv4Address) and ip.is_reserved:
        return True
    return any(ip in net for net in _BLOCKED_NETWORKS)


def _first_public_addr(addrinfo: list[tuple]) -> str | None:
    """Return the first non-blocked address string from a getaddrinfo()
    result, or None if every answer is blocked."""
    for _family, _type, _proto, _canon, sockaddr in addrinfo:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if not _is_blocked_ip(ip):
            return sockaddr[0]
    return None


def _resolve_public_ip(value: str) -> str:
    """Validate `value` (IP literal or hostname) resolves to at least one
    public address and return ONE pinned public IP. Raises
    EgressBlockedError if `value` is a blocked IP literal, DNS resolution
    fails, or every resolved address is blocked.

    Synchronous — safe to call from sync handlers and from thread-pool
    workers (_resolve_targets_parallel). Use _resolve_public_ip_async inside
    async code that's on the running event loop (_grab_one)."""
    try:
        literal = ipaddress.ip_address(value)
    except ValueError:
        literal = None
    if literal is not None:
        if _is_blocked_ip(literal):
            raise EgressBlockedError(f"blocked address: {value}")
        return value

    try:
        addrinfo = socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise EgressBlockedError(f"DNS resolution failed for {value!r}: {exc}")

    pinned = _first_public_addr(addrinfo)
    if pinned is None:
        raise EgressBlockedError(f"all resolved addresses for {value!r} are blocked")
    return pinned


async def _resolve_public_ip_async(value: str) -> str:
    """Event-loop-safe variant of _resolve_public_ip — uses asyncio's own
    resolver (thread-pool-backed, non-blocking to the loop) instead of
    calling socket.getaddrinfo directly. Use inside async functions that run
    per-target on the event loop (_grab_one)."""
    try:
        literal = ipaddress.ip_address(value)
    except ValueError:
        literal = None
    if literal is not None:
        if _is_blocked_ip(literal):
            raise EgressBlockedError(f"blocked address: {value}")
        return value

    try:
        addrinfo = await asyncio.get_running_loop().getaddrinfo(value, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise EgressBlockedError(f"DNS resolution failed for {value!r}: {exc}")

    pinned = _first_public_addr(addrinfo)
    if pinned is None:
        raise EgressBlockedError(f"all resolved addresses for {value!r} are blocked")
    return pinned


def _resolve_targets_parallel(values: list[str], *, host_fn=lambda v: v) -> dict[str, str | None]:
    """Resolve `values` in parallel (DNS is I/O-bound; a naabu/nuclei batch
    can be hundreds of targets, and resolving serially would multiply request
    latency). `host_fn` extracts the host/IP substring to resolve from each
    value (e.g. stripping a :port suffix) — the dict keys stay the original
    values so callers can map back. A blocked/unresolvable value maps to None
    and is logged; callers drop those from the batch.

    Deduplicates by host_fn(v) before resolving — httpx/tlsx batches
    routinely have many ports sharing one host, and each would otherwise
    trigger a redundant DNS lookup."""
    if not values:
        return {}

    unique_hosts = {host_fn(v) for v in values}

    def _one(host: str) -> tuple[str, str | None]:
        try:
            return host, _resolve_public_ip(host)
        except EgressBlockedError as exc:
            log.warning("target dropped by egress guard — %s", exc)
            return host, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, len(unique_hosts))) as ex:
        by_host = dict(ex.map(_one, unique_hosts))

    return {v: by_host[host_fn(v)] for v in values}


def _target_host(target: str) -> str:
    """Extract the host/IP portion of a nuclei target string for the egress
    guard — strips an optional :port suffix (or [ipv6]:port bracket form).
    Best-effort: on ambiguity, returns the target unchanged (a safe default —
    resolution simply fails-closed if the value isn't a valid host)."""
    t = target.strip()
    if t.startswith("["):
        end = t.find("]")
        return t[1:end] if end != -1 else t
    if t.count(":") > 1:
        return t  # bare IPv6, no brackets
    if ":" in t:
        host, _, port = t.rpartition(":")
        if port.isdigit():
            return host
    return t


def _validate_target(value: str) -> str:
    """Targets are FQDNs, IPs (with optional :port), or scheme-stripped hostnames.
    Reject anything that doesn't look like one — defends against newline-smuggling
    into the targets file and against control characters."""
    value = value.strip()
    if not value or not _TARGET_RE.fullmatch(value):
        raise ValueError(f"invalid target: {value!r}")
    # IPv6 in brackets is fine; raw IPv6 also fine via ipaddress check below.
    if ":" in value and not value.startswith("["):
        host, _, port = value.partition(":")
        if port and not port.isdigit():
            # Could be IPv6 without brackets — validate as IP.
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise ValueError(f"invalid target: {value!r}")
    return value


def _validate_naabu_host(value: str) -> str:
    """Naabu hosts are IPs or hostnames — no port suffix, no scheme. Stricter
    than the nuclei target regex because naabu owns the port and CIDR parsing
    via its own flags; we accept IPs (v4 or v6) and DNS hostnames only."""
    value = value.strip()
    if not value:
        raise ValueError("empty host")
    # IPv4 / IPv6 first — accept any valid address.
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if not _NAABU_HOST_RE.fullmatch(value):
        raise ValueError(f"invalid host: {value!r}")
    return value


class ScanRequest(BaseModel):
    targets: list[str]
    severity: str = "critical,high,medium"
    # Aggressiveness-tier flags. Defaults match the "polite" tier so
    # legacy callers that don't pass these stay in a sensible regime.
    rate_limit: int = 50
    concurrency: int = 25
    exclude_tags: str = "intrusive,fuzz,dos"
    tags: str = ""

    @field_validator("targets")
    @classmethod
    def _validate_targets(cls, v: list[str]) -> list[str]:
        return [_validate_target(t) for t in v]

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: str) -> str:
        if not _SEVERITY_RE.fullmatch(v):
            raise ValueError("severity must be a comma-separated list of nuclei severity names")
        return v

    @field_validator("exclude_tags")
    @classmethod
    def _validate_exclude_tags(cls, v: str) -> str:
        if v and not _TAGS_RE.fullmatch(v):
            raise ValueError("exclude_tags must be a comma-separated list of [a-z0-9_-] tag names")
        return v

    @field_validator("tags")
    @classmethod
    def _validate_tags(cls, v: str) -> str:
        if v and not _TAGS_RE.fullmatch(v):
            raise ValueError("tags must be a comma-separated list of [a-z0-9_-] tag names")
        return v

    @field_validator("rate_limit", "concurrency")
    @classmethod
    def _validate_positive(cls, v: int) -> int:
        if v < 1 or v > 10_000:
            raise ValueError("must be between 1 and 10000")
        return v


class NaabuScanRequest(BaseModel):
    """Tier-resolved naabu request.

    Exactly one of `top_ports` (one of 100 / 1000 / 65535 — the same tiers
    naabu's -top-ports flag supports) or `ports` (an explicit list) must
    be supplied. `exclude_ports` is layered on top via naabu's
    -exclude-ports flag.

    Note on `additional_ports`: naabu's -top-ports and -p are mutually
    exclusive, so "top-100 plus a few extras" requires two scans. The
    connector layer handles that by issuing two requests and merging
    results client-side — this endpoint stays single-pass.
    """

    hosts: list[str]
    top_ports: int | None = None
    ports: list[int] | None = None
    exclude_ports: list[int] = []
    rate: int = 1000      # packets per second
    concurrency: int = 25  # parallel hosts
    # Per-port connect timeout (ms). naabu's 1s default is too tight for
    # connect-scan handshakes to internet hosts through a NAT'd container
    # network (e.g. Docker Desktop's VM): the connect times out before the
    # handshake completes, so genuinely-open ports read as closed — and retries
    # inherit the same ceiling, so they don't help. Empirically, 3s gives
    # reliable results even at full rate; 1s dropped ports (sometimes the whole
    # scan). See the naabu reliability investigation (2026-06-16).
    timeout: int = 3000   # milliseconds
    retries: int = 3
    # -verify: re-confirm each SYN-discovered candidate with a full TCP connect.
    # Removed from the default fast path in PR #94 (slow second pass), but it's
    # the validated *narrower* for tarpit / scan-deception hosts: a connect pass
    # collapses the phantom flood to ~the real ports (planning#69). The connector
    # turns this on only for already-flagged tarpit IPs, where the speed cost is
    # acceptable and the downstream gentle nmap verify needs a small candidate set.
    verify: bool = False

    @field_validator("hosts")
    @classmethod
    def _v_hosts(cls, v: list[str]) -> list[str]:
        return [_validate_naabu_host(h) for h in v]

    @field_validator("top_ports")
    @classmethod
    def _v_top_ports(cls, v: int | None) -> int | None:
        if v is None:
            return None
        if v not in (100, 1000, 65535):
            raise ValueError("top_ports must be one of 100, 1000, 65535")
        return v

    @field_validator("ports", "exclude_ports")
    @classmethod
    def _v_port_list(cls, v: list[int] | None) -> list[int]:
        v = v or []
        for p in v:
            if not (1 <= p <= 65535):
                raise ValueError(f"port out of range: {p}")
        return v

    @field_validator("rate", "concurrency")
    @classmethod
    def _v_positive(cls, v: int) -> int:
        if v < 1 or v > 10_000:
            raise ValueError("must be between 1 and 10000")
        return v

    @field_validator("timeout")
    @classmethod
    def _v_timeout(cls, v: int) -> int:
        if v < 100 or v > 60_000:
            raise ValueError("timeout must be 100..60000 ms")
        return v

    @field_validator("retries")
    @classmethod
    def _v_retries(cls, v: int) -> int:
        if v < 0 or v > 10:
            raise ValueError("retries must be 0..10")
        return v


def _run_subprocess_soft(
    cmd: list[str], timeout: float, *, tool: str,
) -> tuple["subprocess.CompletedProcess | None", bool]:
    """Run a scan subprocess, catching timeout/failure so one slow or
    hostile target can't blank an entire batch's results (planning#90).

    Mirrors _run_nmap_verify_host's per-host catch/degrade contract, but at
    the whole-batch level: previously an uncaught TimeoutExpired propagated
    out of the endpoint -> FastAPI 500 -> the connector's blanket except
    silently dropped every finding/port in the batch, including whatever
    partial output the tool had already flushed to its output file before
    being killed.

    Returns (completed_process, timed_out). On timeout/failure, returns
    (None, True) — the caller should still attempt to parse whatever
    partial output already exists rather than discarding it.
    """
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout), False
    except subprocess.TimeoutExpired:
        log.warning("%s subprocess timed out after %ss", tool, timeout)
        return None, True
    except Exception:
        log.exception("%s subprocess failed", tool)
        return None, True


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/scan")
def scan(req: ScanRequest, _: None = Depends(_require_token)) -> dict:
    if not req.targets:
        return {"findings": []}

    # Map each accepted token to the canonical literal in _SEVERITY_LOOKUP /
    # _TAG_LOOKUP. Unknown tokens are rejected. The strings that get joined
    # come straight out of these module-level constant dicts — taint
    # analysis (CodeQL) sees the final args as built from literals.
    severity_canonical: list[str] = []
    for raw in req.severity.split(","):
        token = _SEVERITY_LOOKUP.get(raw)
        if token is None:
            raise HTTPException(status_code=422, detail="invalid severity")
        severity_canonical.append(token)
    if not severity_canonical:
        raise HTTPException(status_code=422, detail="invalid severity")
    severity_arg = ",".join(severity_canonical)

    exclude_tags_arg = ""
    if req.exclude_tags:
        tag_canonical: list[str] = []
        for raw in req.exclude_tags.split(","):
            if not _TAG_TOKEN_RE.fullmatch(raw):
                raise HTTPException(status_code=422, detail="invalid exclude_tags")
            # Unknown tags get rejected; only the known set is forwarded.
            token = _TAG_LOOKUP.get(raw)
            if token is None:
                raise HTTPException(status_code=422, detail=f"unknown tag: {raw}")
            tag_canonical.append(token)
        exclude_tags_arg = ",".join(tag_canonical)

    tags_arg = ""
    if req.tags:
        include_tag_canonical: list[str] = []
        for raw in req.tags.split(","):
            if not _TAG_TOKEN_RE.fullmatch(raw):
                raise HTTPException(status_code=422, detail="invalid tags")
            # Unknown tags get rejected; only the known set is forwarded.
            token = _INCLUDE_TAG_LOOKUP.get(raw)
            if token is None:
                raise HTTPException(status_code=422, detail=f"unknown tag: {raw}")
            include_tag_canonical.append(token)
        tags_arg = ",".join(include_tag_canonical)

    # Pydantic guarantees these are ints, but int() is the recognised
    # sanitiser; str() of int is taint-free.
    rate_limit_arg = str(int(req.rate_limit))
    concurrency_arg = str(int(req.concurrency))

    with tempfile.TemporaryDirectory() as tmpdir:
        targets_path = f"{tmpdir}/targets.txt"
        output_path = f"{tmpdir}/results.jsonl"

        for t in req.targets:
            if not _TARGET_RE.fullmatch(t):
                raise HTTPException(status_code=422, detail=f"invalid target: {t!r}")

        # Egress guard (planning#89) — resolve each target's host/IP and drop
        # any that resolve only to private/internal addresses. The original
        # target string (with hostname, not a pinned IP) is what nuclei
        # receives — it needs the real hostname for correct Host header / SNI.
        resolved = _resolve_targets_parallel(req.targets, host_fn=_target_host)
        safe_targets = [t for t in req.targets if resolved.get(t) is not None]
        if not safe_targets:
            return {"findings": []}

        with open(targets_path, "w") as f:
            for t in safe_targets:
                f.write(t + "\n")

        cmd = [
            "nuclei",
            "-list", targets_path,
            "-severity", severity_arg,
            "-rate-limit", rate_limit_arg,
            "-c", concurrency_arg,
            "-output", output_path,
            "-jsonl", "-silent",
            "-disable-update-check",
        ]
        if exclude_tags_arg:
            cmd.extend(["-etags", exclude_tags_arg])
        if tags_arg:
            cmd.extend(["-tags", tags_arg])

        result, timed_out = _run_subprocess_soft(cmd, timeout=600, tool="nuclei /scan")

        if result is not None and result.returncode not in (0, 1):
            raise HTTPException(
                status_code=500,
                detail=f"Nuclei exited {result.returncode}: {result.stderr[:500]}",
            )

        findings: list[dict] = []
        try:
            with open(output_path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except FileNotFoundError:
            pass

        response: dict = {"findings": findings}
        if timed_out:
            response["timed_out"] = True
        return response


@app.post("/naabu/scan")
def naabu_scan(req: NaabuScanRequest, _: None = Depends(_require_token)) -> dict:
    """Run naabu against `hosts` and return open-port observations.

    Response shape: `{"results": [{"host": str, "ip": str|None, "port": int}, ...]}`.
    Empty list on no findings or naabu-soft-failure (rc=1 with no output).
    """
    if not req.hosts:
        return {"results": []}

    if (req.top_ports is None) == (not req.ports):
        # Exactly one must be supplied. naabu accepts both flags but the
        # behaviour is documented as "if -top-ports is set, -p is ignored" —
        # we surface the ambiguity instead of letting it slip.
        raise HTTPException(
            status_code=422,
            detail="exactly one of top_ports or ports must be supplied",
        )

    # All numeric flags are coerced via int() for CodeQL taint cleansing.
    rate_arg = str(int(req.rate))
    concurrency_arg = str(int(req.concurrency))
    timeout_arg = str(int(req.timeout))
    retries_arg = str(int(req.retries))

    with tempfile.TemporaryDirectory() as tmpdir:
        hosts_path = f"{tmpdir}/hosts.txt"
        output_path = f"{tmpdir}/results.jsonl"

        for h in req.hosts:
            # Re-validate at file-write time. Defends against any future
            # bypass of the pydantic validator (e.g. direct .construct()).
            _validate_naabu_host(h)

        # Egress guard (planning#89) — resolve each host and PIN to the
        # validated public IP (naabu needs no Host header / SNI, so pinning
        # also closes the resolve-vs-connect TOCTOU window here).
        resolved = _resolve_targets_parallel(req.hosts)
        safe_hosts = [resolved[h] for h in req.hosts if resolved.get(h) is not None]
        if not safe_hosts:
            return {"results": []}

        with open(hosts_path, "w") as f:
            for h in safe_hosts:
                f.write(h + "\n")

        cmd = [
            "naabu",
            "-list", hosts_path,
            "-rate", rate_arg,
            "-c", concurrency_arg,
            "-timeout", timeout_arg,
            "-retries", retries_arg,
            # `-verify` (full-connect re-confirmation) is OFF by default — it
            # roughly doubles naabu's time and the downstream nmap step is the
            # authoritative open/closed gate on normal hosts. It is turned on
            # ONLY for tarpit-flagged hosts (req.verify), where it's the validated
            # narrower that collapses the phantom flood before the gentle nmap
            # verify (planning#69/#72).
            "-json",
            "-silent",
            "-disable-update-check",
            "-o", output_path,
        ]

        if req.verify:
            cmd.append("-verify")

        if req.top_ports is not None:
            # naabu's -top-ports accepts only the literal strings 100, 1000,
            # or "full" — passing 65535 errors out. Translate the full-range
            # sentinel here so the connector contract stays numeric.
            tp_arg = "full" if int(req.top_ports) == 65535 else str(int(req.top_ports))
            cmd.extend(["-top-ports", tp_arg])
        else:
            # Sanitised list — every value is an int already validated 1..65535.
            cmd.extend(["-p", ",".join(str(int(p)) for p in req.ports or [])])

        if req.exclude_ports:
            cmd.extend([
                "-exclude-ports",
                ",".join(str(int(p)) for p in req.exclude_ports),
            ])

        result, timed_out = _run_subprocess_soft(cmd, timeout=900, tool="naabu /naabu/scan")

        # naabu returns 0 on success (even with 0 findings). Any other code
        # is a hard error — surface stderr (capped) so the connector logs it.
        if result is not None and result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"Naabu exited {result.returncode}: {result.stderr[:500]}",
            )

        results: list[dict] = []
        try:
            with open(output_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    # naabu JSONL fields: host (only present when input was a
                    # hostname; absent when input was an IP), ip (resolved
                    # IP, always present), port. Fall back to ip for host
                    # so IP-only scans don't get silently dropped.
                    host = row.get("host") or row.get("ip")
                    port = row.get("port")
                    if not host or port is None:
                        continue
                    results.append({
                        "host": str(host),
                        "ip": row.get("ip"),
                        "port": int(port),
                    })
        except FileNotFoundError:
            pass

        response: dict = {"results": results}
        if timed_out:
            response["timed_out"] = True
        return response


# ──────────────────────────────────────────────────────────────────────────────
# Banner grab — Service Identification Stack Layer 1.
#
# Pure-asyncio TCP connect + read. For "talker" protocols (SSH/FTP/SMTP/POP3/
# IMAP/MySQL/Postgres/etc) the server sends a greeting immediately, so a bare
# read suffices. For HTTP-ish ports nothing arrives until we ask for it; we
# send a minimal `GET /` and parse the Server header from the response.
#
# We deliberately do NOT handle TLS-wrapped ports here — they'd require a
# full TLS handshake to get any visible bytes, which is tlsx territory (Stack
# Layer 3). Listed in _TLS_PORTS and skipped.
#
# Output per port:
#   banner          — first ~512 bytes, decoded as latin-1 (lossless byte→char)
#                     and stripped of NULs; surfaced as `banner_snippet` on the
#                     port dict
#   service         — normalised service label (ssh, http, smtp, ftp, …)
#   service_version — extracted product/version where the protocol announces it
# ──────────────────────────────────────────────────────────────────────────────


# TLS-wrapped ports — skip until Stack Layer 3 (tlsx) lands. Doing a raw
# read on a TLS port returns nothing visible; doing a probe writes plaintext
# into a TLS socket and gets a connection close.
_TLS_PORTS: frozenset[int] = frozenset({
    443, 465, 636, 853, 989, 990, 992, 993, 995, 1443, 2376, 2484, 5061,
    5986, 6443, 6697, 8443, 9443,
})

# Plaintext, non-HTTP/TLS protocols with a real zgrab2 module. Ports not
# listed here (telnet, nntp, irc, ldap, anything in _TLS_PORTS,
# or anything unrecognised) fall back to _grab_one.
# LDAP has no zgrab2 module as of v1.0.0/latest — stays on the fallback.
#
# This table is the "conventional port" fast path (run with the longer
# connect/target timeouts in _run_zgrab2). It's a confidence signal, not a
# gate — _CORE8_CASCADE_MODULES below additionally probes every open port
# for the silent protocols, so non-default placements are still found.
#
# Extensible: a future zgrab2 http/tls pass (on top of #10's httpx/tlsx)
# would just add more {port: "http"|"tls"} rows here plus matching
# branches in _parse_zgrab2_result — no restructuring needed.
_ZGRAB2_PORT_MODULES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    110: "pop3",
    143: "imap",
    445: "smb",
    502: "modbus",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    6379: "redis",
    11211: "memcached",
    27017: "mongodb",
}

# "Silent" (client-speaks-first) protocols — _grab_one's passive read gets
# nothing from these, and a port not in _ZGRAB2_PORT_MODULES would otherwise
# get zero identification. Probed against EVERY open port (see
# _run_zgrab2_cascade) with a short timeout, independent of port number, so
# these services are found regardless of where they're listening.
_CORE8_CASCADE_MODULES: list[str] = [
    "postgres", "mssql", "mongodb", "redis", "smb", "rdp", "memcached", "modbus",
]

# (regex, service, version-group-index|None) — applied to first 512 bytes
# decoded as latin-1. Order matters; first match wins. Patterns are
# deliberately tight (start-of-string anchored) so an HTTP body containing
# the word "SSH-2.0" doesn't false-positive.
_SERVICE_PATTERNS: list[tuple[re.Pattern[str], str, int | None]] = [
    # Talking protocols (server-initiated greetings)
    # Capture the whole rest of the line (not just \S+) — many OpenSSH
    # banners append a distro/OS tag after a space (e.g.
    # "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"), which is exactly the
    # detail needed for OS/EOL identification downstream.
    (re.compile(r"^SSH-\d+\.\d+-(.+)"), "ssh", 1),
    (re.compile(r"^220[- ].*?\b(ProFTPD|vsftpd|FileZilla|Pure-FTPd|FTP)\b.*?(\d+\.\d+(?:\.\d+)?)?", re.I), "ftp", 2),
    (re.compile(r"^220[- ].*?ESMTP\s+(\S+(?:\s+\S+)?)", re.I), "smtp", 1),
    (re.compile(r"^220[- ].*?SMTP\b", re.I), "smtp", None),
    (re.compile(r"^\+OK\s+(.*)"), "pop3", 1),
    (re.compile(r"^\* OK\s+(.*)"), "imap", 1),
    (re.compile(r"^NNTP Service\b", re.I), "nntp", None),
    (re.compile(r"^:[^\s]+\s+(?:NOTICE|001)\b"), "irc", None),
    (re.compile(r"^RFB (\d{3}\.\d{3})"), "vnc", 1),
    # MySQL: 1-byte len + 1-byte protocol + null-terminated version string
    (re.compile(r"^.{4}\x0a([0-9][0-9.\-]+\S*)", re.S), "mysql", 1),
    # Redis announces nothing — we'd have to send PING. Detect via raw bytes
    # of "+PONG" / "-ERR" after probe. For now, leave for probe pass.
    # Telnet — option negotiation bytes start with IAC (0xff)
    (re.compile(r"^\xff[\xfb-\xfe]"), "telnet", None),
    # Postgres doesn't announce on connect — needs StartupMessage. Skip.
    # HTTP response (from our probe)
    (re.compile(r"^HTTP/\d\.\d\s+\d{3}\b", re.I), "http", None),
]
# Secondary parse on HTTP responses to pull Server header.
_HTTP_SERVER_RE = re.compile(r"^Server:\s*(.+?)(?:\r|\n)", re.I | re.M)


class BannerGrabTarget(BaseModel):
    ip: str
    port: int

    @field_validator("ip")
    @classmethod
    def _v_ip(cls, v: str) -> str:
        # Accept IP addresses or hostnames (FQDNs). Hostname targets are used
        # by tlsx for CDN CNAME scanning so the correct SNI is sent; public-IP
        # filtering is the caller's (backend connector's) responsibility.
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            pass
        if _NAABU_HOST_RE.fullmatch(v):
            return v
        raise ValueError(f"invalid ip or hostname: {v!r}")

    @field_validator("port")
    @classmethod
    def _v_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("port out of range")
        return v


class BannerGrabRequest(BaseModel):
    targets: list[BannerGrabTarget]
    # Per-target timeout for the whole connect+read cycle, seconds.
    timeout: float = 4.0
    # Max parallel probes in flight at once.
    concurrency: int = 25
    # Cap how many bytes we read from each socket. Banners that don't fit
    # in this window are very rarely useful for identification.
    read_bytes: int = 1024

    @field_validator("timeout")
    @classmethod
    def _v_timeout(cls, v: float) -> float:
        if not (0.5 <= v <= 30):
            raise ValueError("timeout must be 0.5..30 seconds")
        return v

    @field_validator("concurrency")
    @classmethod
    def _v_concurrency(cls, v: int) -> int:
        if not (1 <= v <= 200):
            raise ValueError("concurrency must be 1..200")
        return v

    @field_validator("read_bytes")
    @classmethod
    def _v_read_bytes(cls, v: int) -> int:
        if not (64 <= v <= 8192):
            raise ValueError("read_bytes must be 64..8192")
        return v


async def _grab_one(
    target: BannerGrabTarget,
    *,
    timeout: float,
    read_bytes: int,
) -> dict:
    """Connect, read (maybe probe), parse — entirely best-effort.

    Returns a result dict even on failure (with empty banner/service) so the
    caller can distinguish "we tried and got nothing" from "we never tried".
    """
    port = target.port
    # `result["ip"]` mirrors the input (may be a hostname passed through from
    # a CDN target) so callers can key back to the asset they asked about;
    # the actual socket below connects to the resolved+validated `ip`.
    result: dict = {"ip": target.ip, "port": port, "banner": "", "service": None, "service_version": None}

    # Egress guard (planning#89) — resolve + validate + pin. Closes the
    # resolve-vs-connect TOCTOU window since we control the connect() call
    # directly here (no Host header / SNI correctness to preserve for a raw
    # banner grab).
    try:
        ip = await _resolve_public_ip_async(target.ip)
    except EgressBlockedError as exc:
        log.warning("banner grab target dropped by egress guard — %s", exc)
        return result

    if port in _TLS_PORTS:
        # tlsx territory — not handled here.
        result["service"] = "tls"
        return result

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
    except (OSError, asyncio.TimeoutError):
        return result

    try:
        data = b""
        # First pass: wait briefly for a server-initiated greeting.
        try:
            data = await asyncio.wait_for(reader.read(read_bytes), timeout=min(timeout, 2.5))
        except asyncio.TimeoutError:
            data = b""

        # Second pass: if the server stayed quiet it's likely a request-first
        # protocol (HTTP and friends). Send a minimal HTTP/1.0 GET on any silent
        # non-TLS port — TLS ports already returned above — and parse whatever
        # comes back. Catches HTTP services on arbitrary ports (e.g. TR-069 on
        # 7547) that speak HTTP/1.0 only and so never answer httpx's HTTP/1.1.
        if not data:
            try:
                writer.write(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\nUser-Agent: constellus-banner/1\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(read_bytes), timeout=timeout)
            except (OSError, asyncio.TimeoutError):
                data = data or b""
    finally:
        try:
            writer.close()
            # wait_closed can hang on half-open sockets; cap it.
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except (OSError, asyncio.TimeoutError):
            pass

    if not data:
        return result

    # Latin-1 is lossless byte→char and never raises; we strip NULs because
    # they'd corrupt JSON encoding downstream.
    text = data.decode("latin-1").replace("\x00", "")
    # Keep the banner as a single line for the UI (truncate to first \r/\n).
    first_line = text.split("\r\n", 1)[0].split("\n", 1)[0].strip()
    result["banner"] = first_line[:256]

    for pattern, svc, group in _SERVICE_PATTERNS:
        m = pattern.search(text)
        if not m:
            continue
        result["service"] = svc
        if svc == "http":
            srv = _HTTP_SERVER_RE.search(text)
            if srv:
                result["service_version"] = srv.group(1).strip()[:128]
        elif group is not None:
            try:
                result["service_version"] = m.group(group).strip()[:128]
            except IndexError:
                pass
        break

    return result


@app.post("/banner/grab")
async def banner_grab(req: BannerGrabRequest, _: None = Depends(_require_token)) -> dict:
    """Banner-grab a batch of (ip, port) pairs.

    Response: `{"results": [{ip, port, banner, service, service_version}, ...]}`.
    """
    if not req.targets:
        return {"results": []}

    sem = asyncio.Semaphore(req.concurrency)

    async def bounded(t: BannerGrabTarget) -> dict:
        async with sem:
            return await _grab_one(t, timeout=req.timeout, read_bytes=req.read_bytes)

    results = await asyncio.gather(*(bounded(t) for t in req.targets), return_exceptions=False)
    return {"results": results}


# ──────────────────────────────────────────────────────────────────────────────
# zgrab2 scan — Service Identification Stack Layer 1, plaintext protocols.
#
# Replaces _grab_one's regex banner table with zgrab2's real protocol-
# handshake modules for the protocols in _ZGRAB2_PORT_MODULES (ssh, ftp,
# smtp, pop3, imap, mysql, redis, postgres, mssql, modbus). zgrab2 can
# actively speak these protocols (e.g. redis PING, postgres StartupMessage)
# instead of just reading whatever the server volunteers on connect.
#
# Ports outside that table (telnet, nntp, irc, ldap, HTTP/TLS ports,
# anything unrecognised) fall back to the existing _grab_one path — no
# regression for those.
# ──────────────────────────────────────────────────────────────────────────────


def _parse_zgrab2_result(ip: str, port: int, module: str, entry: dict) -> dict:
    """Map one zgrab2 `data.<module>` entry to the banner_grab result shape.

    `zgrab2_detail` carries the module's full raw result (status/result/error/
    protocol/port) unchanged for every protocol — the fields below are just a
    normalised "headline" view for `_build_phase_result`/OpenPortsPanel.
    """
    base: dict = {
        "ip": ip,
        "port": port,
        "banner": "",
        "service": None,
        "service_version": None,
        "zgrab2_detail": {"module": module, **entry},
    }

    if entry.get("status") != "success":
        return base

    result = entry.get("result") or {}
    if not result:
        # Some modules (observed: smb) report status="success" with a null
        # result when the cascade probes a port speaking a different
        # protocol — got bytes back, but nothing this module could parse.
        # Treat that as "not identified" rather than a false positive.
        return base

    if module in ("ssh", "ftp", "smtp", "pop3", "imap"):
        if module == "ssh":
            text = str((result.get("server_id") or {}).get("raw") or "")
        else:
            text = str(result.get("banner") or "")
        base["banner"] = text.split("\r\n", 1)[0].split("\n", 1)[0].strip()[:256]
        for pattern, svc, group in _SERVICE_PATTERNS:
            if svc != module:
                continue
            m = pattern.search(text)
            if not m:
                continue
            base["service"] = svc
            if group is not None:
                try:
                    base["service_version"] = m.group(group).strip()[:128]
                except IndexError:
                    pass
            break
    elif module == "mysql":
        base["service"] = "mysql"
        version = result.get("server_version")
        if version:
            base["service_version"] = str(version)[:128]
            base["banner"] = str(version)[:256]
    elif module == "mssql":
        base["service"] = "mssql"
        version = result.get("version")
        instance_name = result.get("instance_name")
        if version:
            base["service_version"] = str(version)[:128]
        banner_parts = [str(p) for p in (version, instance_name) if p]
        if banner_parts:
            base["banner"] = " ".join(banner_parts)[:256]
    elif module == "postgres":
        base["service"] = "postgres"
        server_params = result.get("server_parameters")
        version = server_params.get("server_version") if isinstance(server_params, dict) else None
        if version:
            base["service_version"] = str(version)[:128]
            base["banner"] = f"PostgreSQL {version}"[:256]
        else:
            # No StartupMessage user/database supplied -> server never gets
            # far enough to report its version. zgrab2_detail still carries
            # protocol_error/startup_error/is_ssl for later use.
            base["banner"] = "PostgreSQL"
    elif module == "redis":
        base["service"] = "redis"
        major, minor, patch = result.get("major"), result.get("minor"), result.get("patchlevel")
        if major is not None and minor is not None and patch is not None:
            version = f"{major}.{minor}.{patch}"
            base["service_version"] = version[:128]
            base["banner"] = f"Redis {version}"[:256]
        else:
            base["banner"] = "Redis"
    elif module == "modbus":
        base["service"] = "modbus"
        # Best-effort — not live-tested. Surface whatever the module
        # returned without raising; zgrab2_detail keeps the full result.
        for key in ("unit_id", "function_code", "raw_response"):
            val = result.get(key)
            if val is not None:
                base["banner"] = str(val)[:256]
                break
    elif module == "mongodb":
        base["service"] = "mongodb"
        build_info = result.get("build_info") or {}
        version = build_info.get("version")
        if version:
            base["service_version"] = str(version)[:128]
            base["banner"] = f"MongoDB {version}"[:256]
        else:
            base["banner"] = "MongoDB"
    elif module == "smb":
        base["service"] = "smb"
        smb_version = result.get("smb_version") or {}
        version_string = smb_version.get("version_string")
        native_os = result.get("native_os")
        if version_string:
            base["service_version"] = str(version_string)[:128]
        banner_parts = [str(p) for p in (native_os, version_string) if p]
        base["banner"] = (" ".join(banner_parts) if banner_parts else "SMB")[:256]
    elif module == "rdp":
        base["service"] = "rdp"
        selected_protocol = result.get("selected_protocol")
        base["banner"] = (f"RDP ({selected_protocol})" if selected_protocol else "RDP")[:256]
    elif module == "memcached":
        base["service"] = "memcached"
        version = result.get("version")
        if version:
            base["service_version"] = str(version)[:128]
            base["banner"] = f"Memcached {version}"[:256]
        else:
            base["banner"] = "Memcached"

    return base


def _zgrab2_timeout(seconds: float) -> str:
    # multiple.ini's connect-timeout/target-timeout are durations like "5s".
    return f"{max(1, round(seconds))}s"


def _run_zgrab2_multiple(
    rows: list[tuple[str, str, int]],
    *, connect_timeout: str, target_timeout: str, concurrency: int, outer_timeout: float,
) -> tuple[list[dict], bool]:
    """Run `zgrab2 multiple` against `rows` of `(ip, module, port)`.

    Every module appearing in `rows` gets the same `connect_timeout`/
    `target_timeout`. Returns (results, timed_out) — one
    `_parse_zgrab2_result(...)` dict per (ip, port, module) zgrab2 produced
    output for, plus whether the outer subprocess timed out (planning#90:
    the caller should still use whatever partial results were recovered,
    but the flag lets it distinguish "confirmed empty" from "cut short").
    """
    if not rows:
        return [], False

    modules_present = {module for _, module, _ in rows}
    senders = str(max(1, min(int(concurrency), 1000)))

    with tempfile.TemporaryDirectory() as tmpdir:
        targets_path = os.path.join(tmpdir, "targets.csv")
        output_path = os.path.join(tmpdir, "results.jsonl")
        ini_path = os.path.join(tmpdir, "multiple.ini")
        blocklist_path = os.path.join(tmpdir, "blocklist.conf")

        with open(targets_path, "w") as f:
            for ip, module, port in rows:
                f.write(f"{ip},,{module},{port}\n")

        # Empty file — disables zgrab2's default blocklist lookup
        # ($(HOME)/.config/zgrab2/blocklist.conf, which doesn't exist in
        # this image and makes zgrab2 exit fatally without -b pointed
        # somewhere that exists).
        open(blocklist_path, "w").close()

        with open(ini_path, "w") as f:
            for module in sorted(modules_present):
                f.write(f"[{module}]\n")
                f.write(f'trigger="{module}"\n')
                f.write(f'name="{module}"\n')
                f.write(f'connect-timeout="{connect_timeout}"\n')
                f.write(f'target-timeout="{target_timeout}"\n')
                f.write("\n")

        cmd = [
            "zgrab2",
            "-b", blocklist_path,
            "-f", targets_path,
            "-o", output_path,
            "-s", senders,
            "multiple",
            "-c", ini_path,
        ]

        result, timed_out = _run_subprocess_soft(cmd, timeout=outer_timeout, tool="zgrab2 multiple")

        parsed: list[dict] = []
        try:
            with open(output_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    ip = row.get("ip")
                    data = row.get("data")
                    if not ip or not isinstance(data, dict):
                        continue
                    row_port = row.get("port")
                    for module, entry in data.items():
                        if not isinstance(entry, dict):
                            continue
                        entry_port = entry.get("port", row_port)
                        if not isinstance(entry_port, int):
                            continue
                        parsed.append(_parse_zgrab2_result(str(ip), entry_port, module, entry))
        except FileNotFoundError:
            if result is not None and result.returncode != 0:
                raise HTTPException(
                    status_code=500,
                    detail=f"zgrab2 exited {result.returncode}: {result.stderr[:500]}",
                )

        return parsed, timed_out


def _run_zgrab2(targets: list[BannerGrabTarget], *, timeout: float, concurrency: int) -> tuple[list[dict], bool]:
    """Run the table-matched zgrab2 module (`_ZGRAB2_PORT_MODULES`) for each
    target, at the standard connect/target timeouts. High-confidence "this
    port is conventionally X" pass.
    """
    rows = [(t.ip, _ZGRAB2_PORT_MODULES[t.port], t.port) for t in targets]
    outer_timeout = max(60.0, timeout * (len(targets) / max(concurrency, 1) + 2) * 4)
    return _run_zgrab2_multiple(
        rows,
        connect_timeout=_zgrab2_timeout(timeout),
        target_timeout=_zgrab2_timeout(timeout * 2),
        concurrency=concurrency,
        outer_timeout=outer_timeout,
    )


def _run_zgrab2_cascade(targets: list[BannerGrabTarget], *, timeout: float, concurrency: int) -> tuple[list[dict], bool]:
    """Probe every open port (except TLS-wrapped ones — _TLS_PORTS, tlsx
    territory) with all of `_CORE8_CASCADE_MODULES`, at a short timeout.

    Catches "silent" protocols (postgres/mssql/mongodb/redis/smb/rdp/
    memcached/modbus) regardless of which port they're listening on —
    _ZGRAB2_PORT_MODULES only covers their conventional ports.
    """
    cascade_connect_s = min(timeout, 2.0)
    cascade_target_s = min(timeout * 2, 4.0)
    eligible = [t for t in targets if t.port not in _TLS_PORTS]
    rows = [(t.ip, module, t.port) for t in eligible for module in _CORE8_CASCADE_MODULES]
    if not rows:
        return [], False
    outer_timeout = max(60.0, cascade_target_s * (len(rows) / max(concurrency, 1) + 2) * 4)
    return _run_zgrab2_multiple(
        rows,
        connect_timeout=_zgrab2_timeout(cascade_connect_s),
        target_timeout=_zgrab2_timeout(cascade_target_s),
        concurrency=concurrency,
        outer_timeout=outer_timeout,
    )


def _pick_best_zgrab2_result(
    ip: str,
    port: int,
    pass1: dict | None,
    cascade_by_module: dict[str | None, dict],
    passive: dict | None,
) -> dict:
    """Priority: pass1 success > first cascade success (in
    _CORE8_CASCADE_MODULES order) > passive > pass1 (for its error
    zgrab2_detail) > passive (even with service=None) > empty stub.
    """
    if pass1 and pass1.get("service") is not None:
        return pass1
    for module in _CORE8_CASCADE_MODULES:
        cascade = cascade_by_module.get(module)
        if cascade and cascade.get("service") is not None:
            return cascade
    if passive and passive.get("service") is not None:
        return passive
    if pass1 is not None:
        return pass1
    if passive is not None:
        return passive
    return {"ip": ip, "port": port, "banner": "", "service": None, "service_version": None}


def _merge_zgrab2_results(pass1: list[dict], cascade: list[dict], passive: list[dict]) -> list[dict]:
    """Merge pass-1 (table-matched), cascade (Core-8), and passive
    (_grab_one) results into one entry per (ip, port).
    """
    pass1_by_port = {(r["ip"], r["port"]): r for r in pass1}
    passive_by_port = {(r["ip"], r["port"]): r for r in passive}

    cascade_by_port: dict[tuple[str, int], dict[str | None, dict]] = {}
    for r in cascade:
        module = (r.get("zgrab2_detail") or {}).get("module")
        cascade_by_port.setdefault((r["ip"], r["port"]), {})[module] = r

    all_keys = set(pass1_by_port) | set(cascade_by_port) | set(passive_by_port)
    return [
        _pick_best_zgrab2_result(
            ip, port,
            pass1_by_port.get((ip, port)),
            cascade_by_port.get((ip, port), {}),
            passive_by_port.get((ip, port)),
        )
        for ip, port in all_keys
    ]


@app.post("/zgrab2/scan")
async def zgrab2_scan(req: BannerGrabRequest, _: None = Depends(_require_token)) -> dict:
    """Banner-grab a batch of (ip, port) pairs.

    Three sources are combined per port:
      - pass 1: the table-matched zgrab2 module (`_ZGRAB2_PORT_MODULES`), at
        the standard timeouts — high-confidence "conventional port" probe.
      - cascade: all of `_CORE8_CASCADE_MODULES` (the silent protocols), at a
        short timeout, against every non-TLS port — catches those protocols
        on non-default ports.
      - passive: `_grab_one` for ports with no table match — catches
        "talking" protocols (incl. VNC) on any port.

    `_merge_zgrab2_results` picks the best result per (ip, port).

    Response: `{"results": [{ip, port, banner, service, service_version,
    zgrab2_detail?}, ...]}`. `zgrab2_detail` is only present where zgrab2
    produced output, and carries that module's full raw result.
    """
    if not req.targets:
        return {"results": []}

    # Egress guard (planning#89) — resolve + validate + pin every target
    # before any subprocess/socket call. zgrab2's own target CSV carries no
    # hostname field (only ip,,module,port — see _run_zgrab2_multiple), and
    # the passive fallback (_grab_one) needs no Host/SNI correctness either,
    # so pinning to the resolved IP is safe for both paths below.
    ips = [t.ip for t in req.targets]
    resolved = await asyncio.to_thread(_resolve_targets_parallel, ips)
    safe_targets = [
        t.model_copy(update={"ip": resolved[t.ip]})
        for t in req.targets
        if resolved.get(t.ip) is not None
    ]
    if not safe_targets:
        return {"results": []}

    zgrab2_targets = [t for t in safe_targets if t.port in _ZGRAB2_PORT_MODULES]
    fallback_targets = [t for t in safe_targets if t.port not in _ZGRAB2_PORT_MODULES]

    passive_results: list[dict] = []

    if fallback_targets:
        sem = asyncio.Semaphore(req.concurrency)

        async def bounded(t: BannerGrabTarget) -> dict:
            async with sem:
                return await _grab_one(t, timeout=req.timeout, read_bytes=req.read_bytes)

        passive_results = list(await asyncio.gather(*(bounded(t) for t in fallback_targets)))

    pass1_results: list[dict] = []
    pass1_timed_out = False
    if zgrab2_targets:
        pass1_results, pass1_timed_out = await asyncio.to_thread(
            _run_zgrab2, zgrab2_targets, timeout=req.timeout, concurrency=req.concurrency,
        )

    cascade_results, cascade_timed_out = await asyncio.to_thread(
        _run_zgrab2_cascade, safe_targets, timeout=req.timeout, concurrency=req.concurrency,
    )

    results = _merge_zgrab2_results(pass1_results, cascade_results, passive_results)
    response: dict = {"results": results}
    if pass1_timed_out or cascade_timed_out:
        response["timed_out"] = True
    return response


# ──────────────────────────────────────────────────────────────────────────────
# httpx probe — Service Identification Stack Layer 2.
#
# Port-agnostic HTTP probing of every open port: scheme/status, page title,
# tech-stack (Wappalyzer), favicon hash, web-server header, JARM. Non-HTTP
# ports simply produce no JSONL line and are silently dropped.
# ──────────────────────────────────────────────────────────────────────────────


class HttpxProbeRequest(BaseModel):
    targets: list[BannerGrabTarget]
    # Per-probe timeout, seconds (httpx -timeout takes an int).
    timeout: float = 5.0
    # httpx -threads.
    concurrency: int = 20

    @field_validator("timeout")
    @classmethod
    def _v_timeout(cls, v: float) -> float:
        if not (1 <= v <= 60):
            raise ValueError("timeout must be 1..60 seconds")
        return v

    @field_validator("concurrency")
    @classmethod
    def _v_concurrency(cls, v: int) -> int:
        if not (1 <= v <= 200):
            raise ValueError("concurrency must be 1..200")
        return v


@app.post("/httpx/probe")
def httpx_probe(req: HttpxProbeRequest, _: None = Depends(_require_token)) -> dict:
    """Probe a batch of (ip, port) pairs with httpx.

    Response: `{"results": [{ip, port, scheme, status_code, title, webserver,
    tech: [...], favicon, jarm}, ...]}`. Non-HTTP ports produce no entry.
    """
    if not req.targets:
        return {"results": []}

    # Egress guard (planning#89) — resolve + validate each target's host/IP,
    # dropping any that resolve only to private/internal addresses. httpx
    # gets the original hostname (not a pinned IP): correct Host header / TLS
    # SNI is the entire reason CDN-fronted targets are hostnames here.
    ips = [t.ip for t in req.targets]
    resolved = _resolve_targets_parallel(ips)
    safe_targets = [t for t in req.targets if resolved.get(t.ip) is not None]
    if not safe_targets:
        return {"results": []}

    timeout_arg = str(int(req.timeout))
    threads_arg = str(int(req.concurrency))

    with tempfile.TemporaryDirectory() as tmpdir:
        targets_path = f"{tmpdir}/targets.txt"
        output_path = f"{tmpdir}/results.jsonl"

        with open(targets_path, "w") as f:
            for t in safe_targets:
                f.write(f"{t.ip}:{t.port}\n")

        cmd = [
            "httpx",
            "-l", targets_path,
            "-json", "-silent",
            "-td", "-title", "-favicon", "-jarm", "-server",
            "-timeout", timeout_arg,
            "-threads", threads_arg,
            "-disable-update-check",
            "-o", output_path,
            # Without -nf, a probe on a port with no real listener (e.g. a
            # stale TLS port) falls back to the *default* port for the
            # other scheme (typically 80) and reports that port instead —
            # silently misattributing results to a port we never asked
            # about. -nf disables that fallback so each result's "port"
            # always matches one of our input targets.
            "-nf",
        ]

        result, timed_out = _run_subprocess_soft(cmd, timeout=300, tool="httpx /httpx/probe")

        if result is not None and result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"httpx exited {result.returncode}: {result.stderr[:500]}",
            )

        results: list[dict] = []
        try:
            with open(output_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if row.get("failed"):
                        continue
                    host = row.get("host")
                    port = row.get("port")
                    if not host or port is None:
                        continue
                    # httpx `host` is the *resolved* IP; `input` echoes the
                    # target we sent ("host:port"). Recover the original target
                    # host so the backend can route hostname probes (CDN CNAME
                    # scanning) back to the dns_record instead of the CDN IP.
                    raw_input = row.get("input") or ""
                    input_host = raw_input.rpartition(":")[0] or str(host)
                    results.append({
                        "ip": str(host),
                        "input_host": input_host,
                        "port": int(port),
                        "scheme": row.get("scheme"),
                        "status_code": row.get("status_code"),
                        "title": row.get("title"),
                        "webserver": row.get("webserver"),
                        "tech": row.get("tech", []),
                        "favicon": row.get("favicon"),
                        "jarm": row.get("jarm_hash"),
                    })
        except FileNotFoundError:
            pass

        response: dict = {"results": results}
        if timed_out:
            response["timed_out"] = True
        return response


# ──────────────────────────────────────────────────────────────────────────────
# nmap verification — port state confirmation + service enrichment.
#
# Runs after naabu to filter out false-positive ports (e.g. firewalls that
# accept TCP connections on random ports) and enrich confirmed ports with
# nmap's service/version probe data. Only ports nmap marks as "open" are
# returned; the backend connector drops anything not in this list.
#
# With NET_RAW capability (cap_add in docker-compose) nmap uses SYN scan,
# which is more accurate than connect-scan against stateful firewalls. Without
# it, nmap falls back to connect scan — still more discriminating than naabu
# because nmap validates response timing and RST behaviour before marking open.
# ──────────────────────────────────────────────────────────────────────────────


class NmapVerifyRequest(BaseModel):
    targets: list[BannerGrabTarget]
    # Outer timeout passed to subprocess.run, seconds. nmap only sees the
    # handful of ports naabu's -verify pass already confirmed, so a single
    # invocation per host finishes quickly — no chunking needed.
    timeout: float = 120.0
    # IPs to verify GENTLY (full-connect -sT at -T2). Tarpit / scan-deception
    # firewalls fake port state under scan volume; a slow, full-handshake probe
    # keeps the firewall out of deception mode so real ports answer and phantoms
    # don't. The connector flags these (its tarpit_ips set). Non-listed IPs keep
    # the fast default (SYN at -T4). See _run_nmap_verify_host.
    gentle_ips: list[str] = []

    @field_validator("timeout")
    @classmethod
    def _v_timeout(cls, v: float) -> float:
        if not (10 <= v <= 600):
            raise ValueError("timeout must be 10..600 seconds")
        return v


@app.post("/nmap/verify")
def nmap_verify(req: NmapVerifyRequest, _: None = Depends(_require_token)) -> dict:
    """Verify naabu-discovered ports with nmap and enrich with service data.

    Groups targets by IP, runs one nmap -sV invocation per host against only
    the ports naabu found, parses the XML result, and returns only the ports
    nmap confirms as open — enriched with service/product/version.

    Response: {"results": [{ip, port, service, product, version, extra_info}],
               "scanned_ips": [<ips where nmap completed successfully>]}

    If nmap fails or times out for a given host, that host's ports are omitted
    from results and the IP is absent from scanned_ips; the caller (naabu
    connector) treats absent IPs as unverifiable and retains naabu's results
    rather than silently dropping them.
    """
    if not req.targets:
        return {"results": [], "scanned_ips": []}

    # One nmap invocation per host against the ports naabu's -verify confirmed.
    by_ip: dict[str, list[int]] = {}
    for t in req.targets:
        by_ip.setdefault(t.ip, []).append(t.port)

    gentle_set = set(req.gentle_ips)
    results: list[dict] = []
    scanned_ips: list[str] = []
    for ip, ports in by_ip.items():
        scanned, ports_found = _run_nmap_verify_host(
            ip, sorted(set(ports)), req.timeout, gentle=ip in gentle_set,
        )
        results.extend(ports_found)
        if scanned:
            scanned_ips.append(ip)

    return {"results": results, "scanned_ips": scanned_ips}


def _parse_nmap_xml(xml_text: str, ip: str) -> tuple[bool, list[dict]]:
    """Parse nmap XML output and return (scanned, ports).

    scanned=True if the XML parsed and contains at least one <host> element
    (nmap ran to completion for this host, even if no ports are open).
    scanned=False if the text is empty, garbage, or contains no <host> element
    (treat as a failure — indistinguishable from nmap not running).

    ports is the list of open-port dicts, same shape as before:
      {ip, port, service, product, version, extra_info}
    Only ports with state=="open" are included.
    """
    if not xml_text.strip():
        return False, []

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        log.warning("nmap XML parse error for %s: %.200s", ip, xml_text)
        return False, []

    host_elements = root.findall("host")
    if not host_elements:
        return False, []

    out: list[dict] = []
    for host_el in host_elements:
        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            try:
                portid = int(port_el.get("portid", 0))
            except (TypeError, ValueError):
                continue
            svc = port_el.find("service")
            out.append({
                "ip": ip,
                "port": portid,
                "service": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
                "extra_info": svc.get("extrainfo") if svc is not None else None,
            })
    return True, out


def _verify_subprocess_timeout(timeout: float, gentle: bool) -> float:
    """Effective subprocess budget for one nmap-verify host.

    Gentle (tarpit) hosts scan slower at -T2, so they get a roomier window than
    the caller's default. Kept SEPARATE from the argv builder on purpose: when
    the command list and this (numeric, non-argv) timeout shared a return tuple,
    CodeQL conflated the two tuple elements and read the validated timeout float
    as taint reaching the argv — the real source of false positive #86. With the
    timeout off the command's return path there is no such cross-contamination.
    """
    return max(timeout, 300.0) if gentle else timeout


def _build_nmap_verify_cmd(ip: str, ports: list[int], gentle: bool) -> list[str]:
    """Build the nmap verify argv (the command only — see _verify_subprocess_timeout).

    Gentle path (tarpit / scan-deception hosts): explicit full-connect (-sT) at
    slow timing (-T2). The slow rate keeps the firewall out of deception mode so
    phantoms read no-response/filtered (never "open"); the completed handshake +
    -sV app-layer probe is the backstop that exposes any phantom that does slip
    to "open" as `tcpwrapped` (no app data → dropped by the connector). Validated
    2026-06-23 (planning#69/#72) vs a SonicWall-style tarpit. Non-gentle (normal)
    hosts keep the fast default: SYN (-sS via NET_RAW) at -T4. `-sV` is kept in
    BOTH paths — on a tarpit it's the discriminator, elsewhere it's enrichment.
    """
    # Every argv element is a literal or laundered input: ports via int(), the
    # target ip via ipaddress() in the caller, --host-timeout an app-chosen
    # literal. No raw request string reaches the binary.
    port_arg = ",".join(str(int(p)) for p in ports)
    if gentle:
        timing_args = ["-sT", "-T2", "--reason"]
        host_timeout = "240s"
    else:
        timing_args = ["-T4"]
        host_timeout = "60s"
    return [
        "nmap",
        "-sV", "--version-intensity", "3",
        # -Pn: skip host discovery and always port-scan. Required now that the
        # connector treats nmap as authoritative — without it nmap would skip a
        # ping-unresponsive (e.g. ICMP-filtered) host and report zero ports,
        # which the connector would wrongly read as "all candidates closed".
        "-Pn",
        *timing_args,
        "-p", port_arg,
        "--open",
        "-oX", "-",
        "--host-timeout", host_timeout,
        ip,
    ]


def _run_nmap_verify_host(
    ip: str, ports: list[int], timeout: float, gentle: bool = False,
) -> tuple[bool, list[dict]]:
    """nmap -sV one IP + its confirmed ports; return (scanned, open_ports).

    scanned=True means nmap ran to completion for this host (even with zero
    open ports). scanned=False means nmap failed, timed out, or produced no
    parseable output — the caller should not treat absence of results as
    "confirmed closed".
    """
    # Guard the subprocess target: nmap-verify only ever runs against resolved
    # IPs. Re-validating here (defense-in-depth, independent of the request
    # validator) makes the argv provably free of argument injection — str(
    # ip_address(x)) is the canonical form (only [0-9a-fA-F:.]) and ip_address()
    # raises on anything that isn't an IP, so no byte of the request string
    # survives into the argv.
    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError:
        log.warning("nmap verify skipped — non-IP target %r", ip)
        return False, []
    # Egress guard (planning#89) — this endpoint only ever receives literal
    # IPs (no hostname resolution happens here), but nothing upstream of it
    # currently checks the IP itself isn't private/internal.
    if _is_blocked_ip(parsed_ip):
        log.warning("nmap verify skipped — blocked address %r", ip)
        return False, []
    ip = str(parsed_ip)   # normalize

    timeout = _verify_subprocess_timeout(timeout, gentle)
    cmd = _build_nmap_verify_cmd(ip, ports, gentle)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        log.warning("nmap verify subprocess timed out for %s (%d ports)", ip, len(ports))
        return False, []
    except Exception:
        log.exception("nmap verify failed for %s", ip)
        return False, []

    if not proc.stdout.strip():
        return False, []

    return _parse_nmap_xml(proc.stdout, ip)


# ──────────────────────────────────────────────────────────────────────────────
# tlsx scan — Service Identification Stack Layer 3.
#
# Port-agnostic TLS handshake of every open port: certificate subject/SAN/
# issuer/validity, negotiated cipher/TLS version, JARM. Non-TLS ports simply
# produce no JSONL line and are silently dropped.
# ──────────────────────────────────────────────────────────────────────────────


class TlsxScanRequest(BaseModel):
    targets: list[BannerGrabTarget]
    # Per-connection timeout, seconds (tlsx -timeout takes an int).
    timeout: float = 5.0
    # tlsx -c (concurrency).
    concurrency: int = 20

    @field_validator("timeout")
    @classmethod
    def _v_timeout(cls, v: float) -> float:
        if not (1 <= v <= 60):
            raise ValueError("timeout must be 1..60 seconds")
        return v

    @field_validator("concurrency")
    @classmethod
    def _v_concurrency(cls, v: int) -> int:
        if not (1 <= v <= 200):
            raise ValueError("concurrency must be 1..200")
        return v


@app.post("/tlsx/scan")
def tlsx_scan(req: TlsxScanRequest, _: None = Depends(_require_token)) -> dict:
    """TLS-handshake a batch of (ip, port) pairs with tlsx.

    Response: `{"results": [{ip, port, subject_cn, subject_an: [...],
    issuer_cn, issuer_org, not_before, not_after, cipher, tls_version, jarm,
    fingerprint (sha256), ja3, ja3s, serial}, ...]}`. Non-TLS ports produce no entry.
    """
    if not req.targets:
        return {"results": []}

    # Egress guard (planning#89) — resolve + validate each target's host/IP,
    # dropping any that resolve only to private/internal addresses. tlsx gets
    # the original hostname (not a pinned IP): the correct TLS SNI is the
    # entire reason CDN-fronted targets are hostnames here.
    ips = [t.ip for t in req.targets]
    resolved = _resolve_targets_parallel(ips)
    safe_targets = [t for t in req.targets if resolved.get(t.ip) is not None]
    if not safe_targets:
        return {"results": []}

    timeout_arg = str(int(req.timeout))
    concurrency_arg = str(int(req.concurrency))

    with tempfile.TemporaryDirectory() as tmpdir:
        targets_path = f"{tmpdir}/targets.txt"
        output_path = f"{tmpdir}/results.jsonl"

        with open(targets_path, "w") as f:
            for t in safe_targets:
                f.write(f"{t.ip}:{t.port}\n")

        cmd = [
            "tlsx",
            "-l", targets_path,
            "-json", "-silent",
            "-tv", "-cipher", "-jarm",
            # -hash sha256 → cert fingerprint (cross-asset cert-reuse signal, #56);
            # -ja3/-ja3s → client/server JA3 hashes. All emitted in the JSON row.
            "-hash", "sha256", "-ja3", "-ja3s",
            "-timeout", timeout_arg,
            "-c", concurrency_arg,
            "-disable-update-check",
            "-o", output_path,
        ]

        result, timed_out = _run_subprocess_soft(cmd, timeout=300, tool="tlsx /tlsx/scan")

        if result is not None and result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"tlsx exited {result.returncode}: {result.stderr[:500]}",
            )

        results: list[dict] = []
        try:
            with open(output_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    raw_host = row.get("host") or ""
                    ip = row.get("ip") or raw_host
                    port = row.get("port")
                    if not ip or port is None:
                        continue
                    issuer_org = row.get("issuer_org")
                    results.append({
                        "ip": str(ip),
                        "host": str(raw_host) if raw_host else str(ip),
                        "port": int(port),
                        "subject_cn": row.get("subject_cn"),
                        "subject_an": row.get("subject_an", []),
                        "issuer_cn": row.get("issuer_cn"),
                        "issuer_org": issuer_org[0] if issuer_org else None,
                        "not_before": row.get("not_before"),
                        "not_after": row.get("not_after"),
                        "cipher": row.get("cipher"),
                        "tls_version": row.get("tls_version"),
                        "jarm": row.get("jarm_hash"),
                        # sha256 cert fingerprint + JA3 hashes + serial (#56).
                        "fingerprint": (row.get("fingerprint_hash") or {}).get("sha256"),
                        "ja3": row.get("ja3_hash"),
                        "ja3s": row.get("ja3s_hash"),
                        "serial": row.get("serial"),
                    })
        except FileNotFoundError:
            pass

        response: dict = {"results": results}
        if timed_out:
            response["timed_out"] = True
        return response


# ──────────────────────────────────────────────────────────────────────────────
# Domain-affinity probe — planning#89 / planning#102 (epic #81 Phase A Layer 1).
#
# The shared primitive behind both native dangling-DNS detection (epic #81)
# and the shared-infra finding verifier (planning#77): "does this hostname
# still show affinity with a given origin IP?" Given a single (hostname,
# origin_ip) pair, probes TWO identities on the origin — the OWNED vhost
# (hostname:port — correct SNI + Host, "what does this origin show when
# addressed as us?") and the DEFAULT vhost (origin_ip:port — no real SNI,
# "what does this IP show with no hostname match?") — with both httpx (HTTP
# layer) and tlsx (TLS layer), matching the existing service-identification
# tool split. The backend (services/domain_affinity.py) turns the resulting
# matrix into a verdict; this endpoint only returns raw probe data.
#
# Deliberately per-host, not batched: this is the endpoint that connects to
# origins a dangling record may have handed to an attacker, so it's the
# natural chokepoint for the egress guard above, and per-host scoping
# sidesteps the batch-timeout data-loss failure mode (planning#90).
# ──────────────────────────────────────────────────────────────────────────────

_AAP_DEFAULT_PORTS: list[int] = [443, 80]
_AAP_MAX_PORTS = 8
_AAP_TIMEOUT = 8.0


class AffinityProbeRequest(BaseModel):
    hostname: str
    origin_ip: str
    ports: list[int] = _AAP_DEFAULT_PORTS

    @field_validator("hostname")
    @classmethod
    def _v_hostname(cls, v: str) -> str:
        v = v.strip()
        if not _NAABU_HOST_RE.fullmatch(v):
            raise ValueError(f"invalid hostname: {v!r}")
        return v

    @field_validator("origin_ip")
    @classmethod
    def _v_origin_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"origin_ip must be a literal IP: {v!r}")
        return v

    @field_validator("ports")
    @classmethod
    def _v_ports(cls, v: list[int]) -> list[int]:
        if not v:
            raise ValueError("ports must not be empty")
        for p in v:
            if not (1 <= p <= 65535):
                raise ValueError(f"port out of range: {p}")
        return v[:_AAP_MAX_PORTS]


def _target_with_port(host: str, port: int) -> str:
    """Format a host:port target, bracketing IPv6 literals so httpx/tlsx
    parse the target correctly (origin_ip may be IPv6, which contains
    colons of its own)."""
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _httpx_probe_one(origin_ip: str, port: int, *, sni_host: str | None) -> dict:
    """Probe origin_ip:port with httpx. ALWAYS connects to origin_ip — the
    whole point of this probe is testing a SPECIFIC origin, not whatever the
    hostname's own current DNS happens to resolve to (which may differ from
    a stale/shared/dangling origin_ip we were actually asked to check; this
    was a real bug caught in manual verification of planning#102 — the first
    cut let httpx re-resolve the hostname itself and silently probed the
    wrong IP).

    sni_host, when given, is sent as BOTH the HTTP Host header (-H) and the
    TLS SNI (-sni) — the "owned vhost" probe: correct identity against this
    specific origin at both layers. When None, neither override is sent —
    httpx defaults Host to origin_ip itself and sends no SNI (the "default
    vhost" probe: whatever this IP shows with no real hostname match at
    either layer).

    Setting only -H without -sni was a real bug (planning#81 follow-up,
    live-verified): TLS-terminating proxies/CDNs route on SNI *before* the
    HTTP layer ever sees the Host header, so a probe with -H alone but no
    SNI override can land on a completely different vhost at the TLS layer
    (or fail the handshake outright) before the Host header is ever read —
    e.g. against a real Cloudflare-fronted origin, omitting -sni produced a
    generic "plain HTTP sent to HTTPS port" protocol-mismatch page (status
    400, scheme silently downgraded to http) instead of the true owned
    vhost's actual response (a real 301 redirect) that -sni correctly reached.

    Returns {} if httpx produced no result (connection failed, or a
    non-HTTP port)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        targets_path = f"{tmpdir}/targets.txt"
        output_path = f"{tmpdir}/results.jsonl"

        with open(targets_path, "w") as f:
            f.write(_target_with_port(origin_ip, port) + "\n")

        cmd = [
            "httpx",
            "-l", targets_path,
            "-json", "-silent",
            "-td", "-title", "-server", "-location",
            "-timeout", str(int(_AAP_TIMEOUT)),
            "-threads", "1",
            "-disable-update-check",
            "-o", output_path,
            # See /httpx/probe above — without -nf a dead port silently
            # falls back to the other scheme's default port.
            "-nf",
        ]
        if sni_host:
            cmd.extend(["-H", f"Host: {sni_host}", "-sni", sni_host])
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=_AAP_TIMEOUT + 15)
        except subprocess.TimeoutExpired:
            return {}

        try:
            with open(output_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if row.get("failed"):
                        continue
                    return {
                        "status_code": row.get("status_code"),
                        "webserver": row.get("webserver"),
                        "title": row.get("title"),
                        "tech": row.get("tech", []),
                        "redirect_location": row.get("location"),
                        "scheme": row.get("scheme"),
                    }
        except FileNotFoundError:
            pass
    return {}


def _tlsx_probe_one(origin_ip: str, port: int, *, sni_host: str | None) -> dict:
    """TLS-handshake origin_ip:port with tlsx. ALWAYS connects to origin_ip
    (see _httpx_probe_one's docstring — same fix, same reason).

    sni_host, when given, is sent as the TLS SNI via -sni (the "owned
    vhost" probe — does this origin present OUR cert?). When None, no SNI
    override is sent — tlsx's default behavior on a bare IP target is
    exactly the "default vhost" probe: whatever cert the server presents
    with no real hostname match.

    Returns {"tls_ok": False} on a failed/incomplete handshake, else the
    parsed cert summary with tls_ok=True."""
    with tempfile.TemporaryDirectory() as tmpdir:
        targets_path = f"{tmpdir}/targets.txt"
        output_path = f"{tmpdir}/results.jsonl"

        with open(targets_path, "w") as f:
            f.write(_target_with_port(origin_ip, port) + "\n")

        cmd = [
            "tlsx",
            "-l", targets_path,
            "-json", "-silent",
            "-timeout", str(int(_AAP_TIMEOUT)),
            "-c", "1",
            "-disable-update-check",
            "-o", output_path,
        ]
        if sni_host:
            cmd.extend(["-sni", sni_host])
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=_AAP_TIMEOUT + 15)
        except subprocess.TimeoutExpired:
            return {"tls_ok": False}

        try:
            with open(output_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    issuer_org = row.get("issuer_org")
                    return {
                        "tls_ok": True,
                        "subject_cn": row.get("subject_cn"),
                        "sans": row.get("subject_an", []),
                        "issuer_cn": row.get("issuer_cn"),
                        "issuer_org": issuer_org[0] if issuer_org else None,
                    }
        except FileNotFoundError:
            pass
    return {"tls_ok": False}


@app.post("/affinity/probe")
def affinity_probe(req: AffinityProbeRequest, _: None = Depends(_require_token)) -> dict:
    """Probe one (hostname, origin_ip) pair for domain affinity.

    BOTH the owned and default probes connect to origin_ip — that's the
    entire point (testing a SPECIFIC origin, e.g. one a passive finding is
    attributed to, which may not be what the hostname's own current DNS
    resolves to right now). `hostname` is never itself a connection target;
    it's only sent as the Host header / TLS SNI on the "owned" probe, via
    -H/-sni (see _httpx_probe_one / _tlsx_probe_one).

    Response: {"ports": {"<port>": {"owned": {...}, "default": {...}}}}.
    A port where neither probe returned anything is omitted (nothing to
    compare). `owned`/`default` merge the httpx and tlsx result dicts for
    that side; either may be {} if the corresponding layer produced nothing.

    Egress-guarded (planning#89): origin_ip is the only actual connection
    target, so it's the only thing validated against the blocklist — a
    blocked origin_ip is rejected with 422 (single-target endpoint, no
    "rest of the batch" to preserve by silently dropping instead).
    """
    try:
        _resolve_public_ip(req.origin_ip)
    except EgressBlockedError as exc:
        raise HTTPException(status_code=422, detail=f"origin_ip blocked by egress guard: {exc}")

    # 4 probes per port (owned http/tls, default http/tls) run in parallel —
    # each is a blocking subprocess call up to _AAP_TIMEOUT+15s; run serially
    # across len(ports)*4 calls the worst case badly exceeds the backend
    # caller's own request timeout (a real timeout hit during manual
    # verification of planning#102 against an unresponsive host). Bounds
    # worst-case wall time to ~one probe's timeout regardless of port count.
    calls: list[tuple[str, str, "concurrent.futures.Future"]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(req.ports) * 4)) as ex:
        for port in req.ports:
            calls.append(("owned", str(port), ex.submit(_httpx_probe_one, req.origin_ip, port, sni_host=req.hostname)))
            calls.append(("owned", str(port), ex.submit(_tlsx_probe_one, req.origin_ip, port, sni_host=req.hostname)))
            calls.append(("default", str(port), ex.submit(_httpx_probe_one, req.origin_ip, port, sni_host=None)))
            calls.append(("default", str(port), ex.submit(_tlsx_probe_one, req.origin_ip, port, sni_host=None)))

        merged: dict[tuple[str, str], dict] = {}
        for side, port_str, future in calls:
            merged.setdefault((side, port_str), {}).update(future.result())

    ports_result: dict[str, dict] = {}
    for port in req.ports:
        port_str = str(port)
        owned = merged.get(("owned", port_str), {})
        default = merged.get(("default", port_str), {})
        if not owned and not default:
            continue
        ports_result[port_str] = {"owned": owned, "default": default}

    return {"ports": ports_result}


_CORR_MAX_HOSTNAMES = 5


class CorroborationProbeRequest(BaseModel):
    hostnames: list[str]
    origin_ip: str
    ports: list[int] = _AAP_DEFAULT_PORTS

    @field_validator("hostnames")
    @classmethod
    def _v_hostnames(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("hostnames must not be empty")
        out = []
        for h in v:
            h = h.strip()
            if not _NAABU_HOST_RE.fullmatch(h):
                raise ValueError(f"invalid hostname: {h!r}")
            out.append(h)
        return out[:_CORR_MAX_HOSTNAMES]

    @field_validator("origin_ip")
    @classmethod
    def _v_origin_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"origin_ip must be a literal IP: {v!r}")
        return v

    @field_validator("ports")
    @classmethod
    def _v_ports(cls, v: list[int]) -> list[int]:
        if not v:
            raise ValueError("ports must not be empty")
        for p in v:
            if not (1 <= p <= 65535):
                raise ValueError(f"port out of range: {p}")
        return v[:_AAP_MAX_PORTS]


@app.post("/affinity/corroborate")
def affinity_corroborate(req: CorroborationProbeRequest, _: None = Depends(_require_token)) -> dict:
    """Owned-side-only probe for MULTIPLE candidate hostnames against ONE
    origin_ip — epic#81 Phase C corroboration (planning#106). Unlike
    /affinity/probe (one hostname, owned+default, comparing the two), this
    only runs the OWNED side (correct SNI+Host) for each candidate — the
    question here isn't "owned vs default," it's "does this origin serve
    THIS OTHER hostname at all," so there's no default-vhost probe to run.

    Response: {"hostnames": {"<hostname>": {"<port>": {...merged httpx+tlsx
    result...}}}}. A (hostname, port) with no probe result is omitted
    entirely — the caller treats absence as "couldn't corroborate via this
    hostname," not as evidence of anything.

    Egress-guarded (planning#89): origin_ip is the only actual connection
    target — the candidate hostnames are never themselves resolved or
    connected to, only sent as Host header / TLS SNI, identically to how
    /affinity/probe's owned side already works.
    """
    try:
        _resolve_public_ip(req.origin_ip)
    except EgressBlockedError as exc:
        raise HTTPException(status_code=422, detail=f"origin_ip blocked by egress guard: {exc}")

    calls: list[tuple[str, str, "concurrent.futures.Future"]] = []
    max_workers = max(1, len(req.hostnames) * len(req.ports) * 2)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for hostname in req.hostnames:
            for port in req.ports:
                calls.append((hostname, str(port), ex.submit(_httpx_probe_one, req.origin_ip, port, sni_host=hostname)))
                calls.append((hostname, str(port), ex.submit(_tlsx_probe_one, req.origin_ip, port, sni_host=hostname)))

        merged: dict[tuple[str, str], dict] = {}
        for hostname, port_str, future in calls:
            merged.setdefault((hostname, port_str), {}).update(future.result())

    result: dict[str, dict] = {}
    for hostname in req.hostnames:
        ports_result: dict[str, dict] = {}
        for port in req.ports:
            port_str = str(port)
            data = merged.get((hostname, port_str), {})
            if data:
                ports_result[port_str] = data
        if ports_result:
            result[hostname] = ports_result

    return {"hostnames": result}
