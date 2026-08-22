"""Domain-affinity primitive — planning#89 / planning#102 (epic #81 Phase A
Layer 1).

"Does this hostname still show affinity with a given origin IP?" — the
shared spine behind two features asking related but distinct questions of
the same probe:

  - Native dangling-DNS detection (epic #81): does the record's resolved
    target still serve/identify as ours? (detection)
  - Shared-infra finding verifier (planning#77, this module's first
    consumer — see planning#103): does OUR vhost serve the vulnerable
    artifact, or only a co-tenant/default vhost on the same shared IP?
    (attribution)

Both need: resolve the true origin → probe it as the owned vhost (correct
SNI/Host) and as the default vhost (no real SNI) → compare identities. This
module returns the FULL probe matrix, not just a verdict — #81 slices it to
affine/not_affine/indeterminate; #77 slices it for artifact-level comparison
(is the vulnerable component present on the owned side, the default side, or
both).

Phase A scope only: this module computes verdicts, it does not emit
findings. Wiring the verdict into #77's finding-verification state is
planning#103.
"""

import logging
import os
from dataclasses import dataclass, field

import dns.exception
import dns.resolver
import httpx
from sqlalchemy.orm import Session

from app.models.asset_canonical import AssetCanonical
from app.services.asset_chain import chain_target_ids

log = logging.getLogger(__name__)

_SCANNER_URL = os.environ.get("SCANNER_URL", "http://scanner-worker:8001")
_SCANNER_TOKEN = os.environ.get("SCANNER_INTERNAL_TOKEN", "")
_HEADERS = {"X-Internal-Token": _SCANNER_TOKEN}

# Same public recursors as services/discovery/dns_resolve.py — kept as a
# separate small resolver here rather than importing that module, which is
# built around bulk name -> DiscoveredAsset emission, a different concern
# from this module's single-hostname live corroboration check.
_PUBLIC_NAMESERVERS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"]
_RESOLVE_TIMEOUT = 4.0
_RESOLVE_LIFETIME = 6.0

VERDICT_AFFINE = "affine"
VERDICT_NOT_AFFINE = "not_affine"
VERDICT_INDETERMINATE = "indeterminate"

# Status codes that read as "this vhost doesn't recognize the request" —
# a bare/default nginx or Apache install, a proxy with no matching rule, or
# TLS refusing to present a cert for this SNI at all.
_NEGATIVE_STATUS = frozenset({400, 404, 421, 495, 496})


@dataclass
class AffinityResult:
    hostname: str
    origin_ip: str
    verdict: str  # affine | not_affine | indeterminate
    signals: list[str]
    # Raw {"ports": {"<port>": {"owned": {...}, "default": {...}}}} from the
    # worker — #77 (planning#103) needs this for artifact-level comparison,
    # not just the verdict (locked design decision — see epic#81).
    matrix: dict = field(default_factory=dict)
    # Count of probed ports where NEITHER the owned nor default vhost
    # answered at all (origin completely dead, not just ambiguous). A
    # generic `indeterminate` verdict conflates this with "identity-
    # indistinguishable" / "only one side reachable" — genuinely different
    # conditions. planning#81 Phase B (dangling_dns) needs to tell them
    # apart: `unreachable_votes == len(matrix)` (every port dead) is the
    # "masked-by-redirect / origin dead" signal; anything else stays silent
    # (conservative, matches decision 3). Tracked as a count, not a
    # signal-string match, so it doesn't break if signal wording changes.
    unreachable_votes: int = 0


def _make_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = list(_PUBLIC_NAMESERVERS)
    r.timeout = _RESOLVE_TIMEOUT
    r.lifetime = _RESOLVE_LIFETIME
    return r


def _live_resolve_all(hostname: str) -> set[str]:
    """Current public A/AAAA answers for `hostname`, queried fresh against
    1.1.1.1/8.8.8.8 (not the canonical DB, which may be stale)."""
    resolver = _make_resolver()
    ips: set[str] = set()
    for rtype in ("A", "AAAA"):
        try:
            answer = resolver.resolve(hostname, rtype)
            ips.update(str(rdata) for rdata in answer)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.exception.DNSException as exc:
            log.debug("live resolve %s %s failed: %s", rtype, hostname, exc)
            continue
    return ips


def resolve_origin(db: Session, dns_record: AssetCanonical) -> str | None:
    """Determine the origin IP `dns_record` actually points at.

    - A/AAAA records: `content` IS the origin, straight from the DNS
      source's API (Cloudflare's connector always captures the real origin
      in `content` regardless of `proxied` status — the proxy only affects
      what PUBLIC resolvers see, not what we were told). No public-resolver
      cross-check applies here: a proxied origin is by design never
      returned by public DNS, so requiring that corroboration would reject
      every legitimate proxied origin.
    - CNAME records: walk the chain via the canonical DB (chain_target_ids,
      cheap — no live call) to the terminal ip_address asset, then
      cross-check that candidate against LIVE public resolution. This is
      the planning#78 guard: a non-proxied (grey-cloud) record can look
      directly exposed yet never actually be returned by public resolvers
      because a proxied record of the same type takes precedence — an
      un-corroborated candidate is treated as not live and rejected (None),
      not silently trusted from possibly-stale canonical state.

    Returns None when there's nothing resolvable, or a CNAME chain's
    candidate isn't corroborated by current public DNS.
    """
    record_type = dns_record.record_type
    content = dns_record.content
    if not content:
        return None

    if record_type in ("A", "AAAA"):
        import ipaddress
        try:
            ipaddress.ip_address(content)
        except ValueError:
            return None
        return content

    if record_type != "CNAME":
        return None

    def get_by_value(value: str) -> list[AssetCanonical]:
        return db.query(AssetCanonical).filter(AssetCanonical.value == value).all()

    target_ids = chain_target_ids(dns_record, get_by_value)
    if not target_ids:
        return None

    terminal = (
        db.query(AssetCanonical)
        .filter(AssetCanonical.id.in_(target_ids), AssetCanonical.asset_type == "ip_address")
        .first()
    )
    if not terminal:
        return None
    candidate_ip = terminal.value

    live_ips = _live_resolve_all(dns_record.value)
    if candidate_ip not in live_ips:
        log.info(
            "domain_affinity: origin candidate %s for %s not corroborated by live "
            "public resolution (live=%s) — treating as unresolved",
            candidate_ip, dns_record.value, sorted(live_ips) or "none",
        )
        return None
    return candidate_ip


def _probe_worker(hostname: str, origin_ip: str, ports: list[int] | None = None) -> dict:
    """Call the scanner-worker /affinity/probe endpoint. Returns the raw
    {"ports": {...}} matrix, or {"ports": {}} on any failure (fail-soft —
    callers treat an empty matrix as indeterminate, not as an exception)."""
    payload: dict = {"hostname": hostname, "origin_ip": origin_ip}
    if ports:
        payload["ports"] = ports
    try:
        resp = httpx.post(
            f"{_SCANNER_URL}/affinity/probe",
            json=payload,
            headers=_HEADERS,
            # Worker runs 4 probes/port in parallel (worst case ~_AAP_TIMEOUT
            # + 15s each, see scanner-worker/main.py:affinity_probe) — 90s
            # gives headroom over that under thread-pool contention. A hit
            # host that hangs the full worker-side subprocess timeout is
            # exactly the case that needs this margin, not a rare one.
            timeout=90,
        )
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as exc:
        log.warning(
            "domain_affinity: probe rejected for %s / %s: %s",
            hostname, origin_ip, exc.response.text[:300],
        )
        return {"ports": {}}
    except httpx.HTTPError:
        log.exception("domain_affinity: probe request failed for %s / %s", hostname, origin_ip)
        return {"ports": {}}


def probe_corroboration_candidates(
    hostnames: list[str], origin_ip: str, ports: list[int] | None = None,
) -> dict:
    """Call the scanner-worker /affinity/corroborate endpoint — owned-side-
    only probes for MULTIPLE candidate hostnames against one origin_ip
    (planning#106, epic#81 Phase C). Returns the raw
    {"<hostname>": {"<port>": {...}}} matrix, or {} on any failure
    (fail-soft, mirrors _probe_worker — callers treat an empty result as
    "couldn't corroborate," not as an exception)."""
    payload: dict = {"hostnames": hostnames, "origin_ip": origin_ip}
    if ports:
        payload["ports"] = ports
    try:
        resp = httpx.post(
            f"{_SCANNER_URL}/affinity/corroborate",
            json=payload,
            headers=_HEADERS,
            timeout=90,
        )
        resp.raise_for_status()
        return resp.json().get("hostnames") or {}
    except httpx.HTTPStatusError as exc:
        log.warning(
            "domain_affinity: corroboration probe rejected for %s / %s: %s",
            hostnames, origin_ip, exc.response.text[:300],
        )
        return {}
    except httpx.HTTPError:
        log.exception(
            "domain_affinity: corroboration probe request failed for %s / %s",
            hostnames, origin_ip,
        )
        return {}


def apex_match(hostname: str, sans: set[str], owned_apexes: set[str]) -> bool:
    """True if any SAN on the probed cert covers `hostname` under one of
    `owned_apexes` (exact match or a subdomain of the apex).

    Public (not `_apex_match`) — planning#106 (epic#81 Phase C, origin
    liveness corroboration) reuses this same trust bar cross-module: does a
    corroboration candidate's own cert actually cover ITS apex, the same
    "is this cert genuinely for this name" test used for our own affinity
    verdict."""
    for san in sans:
        san = san.lstrip("*.")
        for apex in owned_apexes:
            if san == apex or san.endswith("." + apex):
                return True
    return hostname in sans


def _vhost_alive(side: dict) -> bool:
    return bool(side) and (side.get("status_code") is not None or side.get("tls_ok"))


def _identity_key(side: dict) -> tuple:
    """A coarse fingerprint of "what identity is this vhost showing" —
    distinct keys across owned/default means the two sides are genuinely
    different vhosts, not the same catch-all answering both."""
    return (
        side.get("webserver"),
        (side.get("subject_cn") or "").lower(),
        tuple(sorted(s.lower() for s in (side.get("sans") or []))),
    )


def _score_port(port: str, matrix: dict, hostname: str, owned_apexes: set[str]) -> tuple[str | None, str, bool]:
    """Return (vote, signal, unreachable) for one port. vote is 'affine',
    'not_affine', or None (no opinion — e.g. neither side reachable, or the
    two sides are indistinguishable and neither carries our identity).
    unreachable is True only for the "neither side answered at all" case —
    a distinct condition from a merely-ambiguous abstention (see
    AffinityResult.unreachable_votes)."""
    owned = matrix.get("owned") or {}
    default = matrix.get("default") or {}

    owned_sans = set(owned.get("sans") or [])
    if apex_match(hostname, owned_sans, owned_apexes):
        return VERDICT_AFFINE, f"port {port}: owned vhost's cert covers {hostname} / an owned apex", False

    owned_alive = _vhost_alive(owned)
    default_alive = _vhost_alive(default)

    if not owned_alive and not default_alive:
        return None, f"port {port}: neither owned nor default vhost reachable", True

    if not owned_alive and default_alive:
        return VERDICT_NOT_AFFINE, f"port {port}: owned vhost unreachable while the default vhost answers", False

    owned_status = owned.get("status_code")
    # tls_ok=False only counts as a negative signal when it's the ONLY data
    # point (no HTTP status at all) — a plaintext port (e.g. 80) legitimately
    # never completes a TLS handshake, and that's not a vhost-identity signal.
    # A live-tested false positive: itsupport.contoso.com:80 healthily
    # 301-redirects (owned_status=301) but still carries tls_ok=False from
    # the (expected-to-fail) TLS probe on a plaintext port — treating that
    # as "negative" wrongly flagged a working redirect as not_affine.
    owned_negative = owned_status in _NEGATIVE_STATUS or (owned_status is None and owned.get("tls_ok") is False)

    if owned_alive and not default_alive:
        # Owned answers, default doesn't. A NEGATIVE owned response (404/
        # 400/etc.) is itself evidence — "reachable, but nothing here for
        # our hostname" doesn't need a default-side comparison to mean
        # something (planning#81 follow-up: a Cloudflare-fronted origin can
        # answer our SNI with a generic vhost-mismatch error while genuinely
        # serving other tenants fine — that error IS the signal). A
        # POSITIVE owned response with nothing to compare against stays a
        # true abstention — normal for a single-vhost host, not evidence
        # either way unless the cert already matched above.
        if owned_negative:
            return VERDICT_NOT_AFFINE, (
                f"port {port}: owned vhost returns {owned_status!r} (default unreachable)"
            ), False
        return None, f"port {port}: only the owned vhost answered (default unreachable)", False

    # Both alive — compare identity.
    if _identity_key(owned) == _identity_key(default):
        return None, f"port {port}: owned and default vhosts are identity-indistinguishable", False

    if owned_negative:
        return VERDICT_NOT_AFFINE, (
            f"port {port}: owned vhost returns {owned_status!r} while the "
            f"default vhost presents a distinct identity"
        ), False

    # Distinct identities, owned side answers positively (2xx/3xx, valid
    # TLS) — the owned vhost IS being served, just differently from the
    # default. That's exactly what a correctly-configured multi-vhost host
    # looks like from the owned side; treat as affine.
    return VERDICT_AFFINE, f"port {port}: owned vhost answers with a distinct, positive identity", False


def check_affinity(
    hostname: str,
    origin_ip: str,
    owned_apexes: set[str],
    ports: list[int] | None = None,
) -> AffinityResult:
    """Probe `hostname` against `origin_ip` and return an affinity verdict.

    Conservative by construction: a verdict of affine or not_affine requires
    at least one port to actually vote that way; ports that are
    unreachable-both-sides or identity-indistinguishable abstain rather than
    forcing a guess. No port casting a vote -> indeterminate. This mirrors
    the shared-infra verifier's own three-state model (planning#77) and the
    epic's locked decision to start conservative (planning#81, decision 3).

    First real worked example (epic#81 motivating case): probing origin
    203.0.113.44 with hostname itsupport.contoso.com — the owned vhost
    404s (nginx, no matching Host) while the default vhost is a live,
    distinct Apache identity (www.brightleaf-goods.com) -> not_affine.
    """
    matrix = _probe_worker(hostname, origin_ip, ports).get("ports") or {}

    signals: list[str] = []
    affine_votes = 0
    not_affine_votes = 0
    unreachable_votes = 0

    for port, port_matrix in matrix.items():
        vote, signal, unreachable = _score_port(port, port_matrix, hostname, owned_apexes)
        signals.append(signal)
        if vote == VERDICT_AFFINE:
            affine_votes += 1
        elif vote == VERDICT_NOT_AFFINE:
            not_affine_votes += 1
        if unreachable:
            unreachable_votes += 1

    if not matrix:
        signals.append("no ports probed successfully")

    # Affine wins on any positive signal — a host can legitimately answer
    # differently across ports (e.g. a redirect-only 80 alongside a real
    # 443), and one confirmed-ours port is enough to call the origin ours.
    # not_affine only wins when nothing voted affine.
    if affine_votes:
        verdict = VERDICT_AFFINE
    elif not_affine_votes:
        verdict = VERDICT_NOT_AFFINE
    else:
        verdict = VERDICT_INDETERMINATE

    return AffinityResult(
        hostname=hostname,
        origin_ip=origin_ip,
        verdict=verdict,
        signals=signals,
        matrix=matrix,
        unreachable_votes=unreachable_votes,
    )
