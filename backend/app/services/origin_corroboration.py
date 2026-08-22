"""Origin liveness corroboration — planning#106, epic#81 Phase C
(the affiliated-hostname half; the separate "last_seen_ours" Shodan
history-dating half is out of scope here and needs its own module — it
depends on Shodan's paid `history=true` endpoint and a real tier/quota
gate, neither of which this feature needs).

When dangling_dns_analyzer flags a dns_record's origin as not_affine or
fully unreachable, that verdict rests on domain_affinity's own probe —
which for the "is the origin alive at all" question leans on a *known-weak*
signal, the no-SNI "default vhost" probe. Many modern SNI-strict servers
simply refuse a no-SNI connection outright regardless of whether the
origin is healthy, so a live, correctly-configured multi-tenant origin can
look identical to a genuinely dead one under that probe alone.

This module corroborates using a stronger, already-available source:
Shodan's `hostnames` field (captured for free during ordinary IP
enrichment — see services/shodan.py — no extra API cost, no live Shodan
call here) lists OTHER hostnames historically observed resolving to the
same IP. Probing those with correct SNI (domain_affinity.
probe_corroboration_candidates, the same "owned vhost" primitive the rest
of epic#81 already trusts) answers a sharper question than the no-SNI
probe can: is this origin alive and serving SOMEONE, just not us?

Deliberately conservative (epic#81 decision 3 — "start silent," carried
forward): a positive hit can only ever STRENGTHEN a dangling_dns_analyzer
verdict (promoting Low -> Medium when the origin turns out to be alive for
other tenants, not dead for everyone). It never creates a finding from
nothing, never demotes an existing verdict, and only "strong" evidence — a
candidate's own TLS cert genuinely covering its own apex, the same trust
bar domain_affinity.apex_match already uses for our own affinity verdict —
counts toward that promotion. A bare HTTP 2xx is recorded as weak evidence
only; it could just be a parking/catch-all page (see the parking-page-
detection backlog item, planning-adjacent, not yet built). Absence of a
positive hit proves nothing (those other hostnames could be stale
themselves) and changes nothing.
"""

import ipaddress
import logging
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.models.asset_canonical import AssetCanonical
from app.models.claim import AssetClaim
from app.services import claim_emitter, domain_affinity, hosting_classifier
from app.services.target_service import apex_domain

log = logging.getLogger(__name__)

# Bumped from the original 3 (Shodan-hostnames-only) now that candidates can
# also come from HackerTarget's reverse-IP density list (epic#81 Phase D,
# planning#107) — hundreds of candidates there, not a handful. A larger
# selection cap is cheap because probing batches with early-exit (below)
# keeps actual probe volume low in the common case; a real dry run found a
# strong hit within the first 15 of 407 candidates.
_MAX_CANDIDATES = 20
# Matches scanner-worker's own _CORR_MAX_HOSTNAMES cap on /affinity/corroborate.
_PROBE_BATCH_SIZE = 5
_CORROBORATION_PORTS = [443, 80]

# Client-side technologies Wappalyzer/httpx tech-detect reliably surfaces via
# script refs or generator meta tags — deliberately small and conservative.
# Absence-of-tech is a weak, false-negative-prone signal on its own (minified/
# renamed bundles, unprobed paths); only ship it for products where a miss is
# unlikely, and always as a supporting signal, never a sole trigger (see
# corroborate_tech_absence + epic#81 Phase D §3.2).
_FINGERPRINTABLE_PRODUCTS = frozenset({"jquery", "bootstrap", "wordpress", "drupal"})

# Auto-generated reverse-DNS / cloud-provider PTR patterns that resolve to
# an IP mechanically, not because a real tenant is being served there —
# probing these would falsely "corroborate" (of course a cloud provider's
# own PTR name resolves back to the IP it's assigned).
_INFRA_SUFFIXES = (
    ".in-addr.arpa", ".ip6.arpa",
    ".amazonaws.com", ".googleusercontent.com", ".cloudapp.azure.com",
)


@dataclass
class CorroborationResult:
    attempted: bool
    origin_serves_others: bool = False
    corroborating_hostname: str | None = None
    evidence: str | None = None  # "tls_san_match" (strong) | "http_2xx" (weak) | None
    hostnames_probed: list[str] = field(default_factory=list)


def corroborate_liveness(
    db: Session,
    origin_ip: str,
    subject_value: str,
    owned_apexes: set[str],
) -> CorroborationResult:
    """Best-effort: does origin_ip serve real content for any hostname
    OTHER than subject_value? `attempted=False` is the graceful-degradation
    path — it covers Shodan not configured, this IP unknown to Shodan and
    HackerTarget, or enrichment never having run, all in one check: the
    *absence* of any candidate from either source IS the availability
    signal, no separate connector-config lookup needed.

    Candidates come from two sources, unioned before selection: Shodan's
    `hostnames` (free during ordinary IP enrichment, effectively live/
    current) and HackerTarget's reverse-IP density list (planning#107 —
    historical/cumulative, much larger, no last-seen date). Probed in
    batches with early-exit on the first strong hit (matches scanner-
    worker's own per-call cap) — the batching means a big reverse-IP
    candidate pool doesn't turn into probing hundreds of hostnames; a real
    dry run against 407 candidates found a strong hit in the first 15."""
    ip_asset = (
        db.query(AssetCanonical)
        .filter(AssetCanonical.asset_type == "ip_address", AssetCanonical.value == origin_ip)
        .first()
    )
    if ip_asset is None:
        return CorroborationResult(attempted=False)

    shodan_hostnames = _shodan_hostnames(db, ip_asset.id)
    reverse_ip_hostnames = hosting_classifier.reverse_ip_domains(db, origin_ip)
    raw_hostnames = list(shodan_hostnames) + list(reverse_ip_hostnames)

    candidates = _select_candidates(raw_hostnames, subject_value, owned_apexes, origin_ip)
    if not candidates:
        return CorroborationResult(attempted=False)

    hostnames_probed: list[str] = []
    weak_result: str | None = None
    for i in range(0, len(candidates), _PROBE_BATCH_SIZE):
        batch = candidates[i:i + _PROBE_BATCH_SIZE]
        hostnames_probed.extend(batch)
        try:
            matrix = domain_affinity.probe_corroboration_candidates(batch, origin_ip, _CORROBORATION_PORTS)
        except Exception:
            log.exception("origin_corroboration: probe failed for %s against %s", origin_ip, subject_value)
            continue
        if not matrix:
            continue
        strong_hit, weak_hit = _evaluate(matrix)
        if strong_hit:
            return CorroborationResult(
                attempted=True, origin_serves_others=True,
                corroborating_hostname=strong_hit, evidence="tls_san_match",
                hostnames_probed=hostnames_probed,
            )
        if weak_hit and weak_result is None:
            weak_result = weak_hit

    if weak_result:
        return CorroborationResult(
            attempted=True, origin_serves_others=False,
            corroborating_hostname=weak_result, evidence="http_2xx",
            hostnames_probed=hostnames_probed,
        )
    return CorroborationResult(attempted=True, hostnames_probed=hostnames_probed)


def _shodan_hostnames(db: Session, ip_asset_id) -> list:
    """Shodan's reverse-DNS `hostnames` for this IP, from the `reverse_hostname`
    claim (planning#144 L3c-3 — moved off `asset_metadata["shodan_hostnames"]`,
    which was the same data written by the same connector; see
    claim_emitter._SIMPLE_KEY_CLAIMS).

    Not observer-scoped on purpose: `reverse_hostname` is Shodan's today, but
    the key's meaning here is "third-party reverse-DNS candidates for this
    IP", and a second producer of that claim should feed the same candidate
    pool rather than be silently ignored. Returns [] when nothing has
    claimed it — the caller treats an empty candidate pool as
    `attempted=False` (graceful degradation), unchanged.
    """
    claim = (
        db.query(AssetClaim.claim_value)
        .filter(
            AssetClaim.asset_canonical_id == ip_asset_id,
            AssetClaim.claim_type == claim_emitter._SIMPLE_KEY_CLAIMS["shodan_hostnames"][0],
        )
        .order_by(AssetClaim.last_observed_at.desc())
        .first()
    )
    if claim is None:
        return []
    value_key = claim_emitter._SIMPLE_KEY_CLAIMS["shodan_hostnames"][1]
    hostnames = (claim[0] or {}).get(value_key)
    return list(hostnames) if isinstance(hostnames, list) else []


def _ip_in_hostname(origin_ip: str, hostname: str) -> bool:
    """True if `hostname` looks like an auto-generated reverse-DNS-style
    name embedding origin_ip itself — e.g. "203-0-113-44.elastic-ssl.ui-r.com"
    or "syn-198-051-100-077.biz.spectrum.com" (zero-padded octets). These
    are DNS/hosting-infra artifacts, not real tenant hostnames — probing
    them risks a false "strong" corroboration hit if the hosting provider's
    own generic wildcard cert happens to cover its own auto-PTR name.
    Provider-agnostic (checks the IP pattern itself, live-discovered
    against real data) rather than a per-provider suffix allowlist, which
    would only ever catch providers we happened to already know about."""
    try:
        ip = ipaddress.ip_address(origin_ip)
    except ValueError:
        return False
    if ip.version == 4:
        octets = origin_ip.split(".")
        plain = "-".join(octets)
        padded = "-".join(o.zfill(3) for o in octets)
        return plain in hostname or padded in hostname
    dashed = ip.exploded.replace(":", "-")
    return dashed in hostname


def _select_candidates(raw_hostnames: list, subject_value: str, owned_apexes: set[str], origin_ip: str) -> list[str]:
    """Dedupe by apex (probing three subdomains of the same third party is
    near-useless — they live or die together; distinct apexes maximise
    independent evidence per probe), drop our own apexes and infra/PTR
    noise, cap at _MAX_CANDIDATES."""
    subject = subject_value.lower().rstrip(".")
    seen_apexes: set[str] = set()
    candidates: list[str] = []
    for h in raw_hostnames:
        if not isinstance(h, str) or not h:
            continue
        h = h.lower().rstrip(".")
        if h == subject:
            continue
        if h.endswith(_INFRA_SUFFIXES) or _ip_in_hostname(origin_ip, h):
            continue
        apex = apex_domain(h)
        if apex in owned_apexes or apex in seen_apexes:
            continue
        seen_apexes.add(apex)
        candidates.append(h)
        if len(candidates) >= _MAX_CANDIDATES:
            break
    return candidates


def corroborate_tech_absence(matrix: dict, cve_product: str | None) -> dict | None:
    """Supporting-only corroborator (epic#81 Phase D, planning#107/#108): if
    a CVE's vulnerable product is one we can reliably fingerprint, and the
    OWNED side of Layer 1's own probe matrix actually answered (not
    silence), and none of the detected tech mentions that product, that
    absence is corroborating evidence the vulnerable content isn't served
    for this hostname — checked against the exact vhost identity Layer 1
    already established, not a fresh generic scan. Reuses
    domain_affinity.AffinityResult.matrix the verifier already has in
    hand — no extra probe.

    Returns None when the signal isn't applicable at all (no product
    mapping, or the owned side never answered — silence proves nothing).
    Otherwise always returns state_affecting=False: this ships explain-only
    first (surfaced as evidence, never moves a verdict alone) until it's
    been watched against real data — a single tech-detect false negative
    must never be able to hide a finding by itself."""
    product = (cve_product or "").strip().lower()
    if product not in _FINGERPRINTABLE_PRODUCTS:
        return None

    checked_ports: list[str] = []
    tech_observed: set[str] = set()
    answered = False
    for port, port_matrix in (matrix or {}).items():
        owned = (port_matrix or {}).get("owned") or {}
        if owned.get("status_code") is None:
            continue  # didn't answer at all — absence here proves nothing
        answered = True
        checked_ports.append(str(port))
        for t in owned.get("tech") or []:
            tech_observed.add(str(t).lower())

    if not answered:
        return None

    return {
        "cve_product": product,
        "checked_ports": checked_ports,
        "tech_observed": sorted(tech_observed),
        "expected_tech_absent": product not in tech_observed,
        "state_affecting": False,
    }


def _evaluate(matrix: dict) -> tuple[str | None, str | None]:
    """Return (strong_hit_hostname, weak_hit_hostname) — strong wins and
    short-circuits; weak is only reported when no candidate produced a
    strong hit."""
    weak: str | None = None
    for hostname, ports in matrix.items():
        candidate_apex = {apex_domain(hostname)}
        for port_data in ports.values():
            sans = set(port_data.get("sans") or [])
            if sans and domain_affinity.apex_match(hostname, sans, candidate_apex):
                return hostname, None
            status = port_data.get("status_code")
            if weak is None and status is not None and 200 <= status < 400:
                weak = hostname
    return None, weak
