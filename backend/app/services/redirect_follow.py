"""app.services.redirect_follow - follow the HTTP redirects of probed
endpoints, every hop through the probe gate (planning#268).

httpx records, per probed endpoint, the status and raw `Location` it was
answered with. This module takes the endpoints that answered 3xx with a
Location and walks the chain, one fetch per hop, each hop authorised on its
own:

  parse -> loop check -> hop cap -> probe gate -> SSRF pin -> fetch

A Location is attacker-controlled input naming an arbitrary destination, so
nothing is requested that the gate has not licensed for THAT destination, and
no DNS lookup of ours is made for a host the gate has not allowed. The verdict
used is `ProbePermission.allowed`, the gate's REAL verdict, in both gate modes:
`GateResult.permitted` is the unfiltered input under the default `log_only`
mode and would let every hop through (Jason, planning#268 decision).

What is recorded goes to `http_redirect_hops` (one row per Location
destination, about the HOP's URL); the origin's `open_ports` entry is never
touched, so no hop data is attributed to the origin.

A hostname first seen in a Location that is not an asset becomes a lead and is
NEVER fetched in the same run: an owned name is recorded as a discovered
`dns_record`; any other name is recorded as a third-party context node (the
same `no_probe` shape a CNAME boundary gets). An IP literal never mints
anything.

Transaction ownership: this module only flushes. The caller (the scan
executor) commits. The one exception is `write_assets`, which commits its own
unit (that is how it is written everywhere) when leads are minted.
"""

import ipaddress
import logging
import uuid
from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit, urljoin

import httpx
from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from app.connectors.base import DiscoveredAsset
from app.core.ssrf import SSRFBlockedError, pin_address
from app.models.asset_canonical import AssetCanonical
from app.models.http_redirect_hop import HttpRedirectHop
from app.services import probe_authorisation
from app.services.asset_writer import write_assets
from app.services.discovery import dns_resolve

log = logging.getLogger(__name__)

# Constants for now; promote to settings in planning#269. The guards below are
# never settings.
MAX_HOPS = 5          # followed fetches per chain
MAX_URL_LEN = 2048    # mirrors ck_http_redirect_hops_url
TITLE_CAP = 512       # mirrors ck_http_redirect_hops_title
LOCATION_CAP = 300    # mirrors ck_http_redirect_hops_location
GATE_CONNECTOR_ID = "httpx_probe"

_DEFAULT_PORTS = {"http": 80, "https": 443}
_PATH_SAFE = "/%:@!$&'()*+,;=-._~"
_QUERY_SAFE = "/%:@!$&'()*+,;=-._~?"

REASON_UNSUPPORTED_URL = "unsupported_url"
REASON_LOOP = "loop"
REASON_HOP_CAP = "hop_cap"
REASON_UNRESOLVED = "unresolved_asset"
REASON_SSRF = "ssrf_blocked"
REASON_DNS = "dns_failed"
REASON_WORKER = "worker_unavailable"


# -- hop parsing (pure) ---------------------------------------------------------

@dataclass(frozen=True)
class Hop:
    url: str          # normalised absolute URL, no userinfo or fragment
    scheme: str       # http / https
    host: str         # lower-cased, no trailing dot, IPv6 unbracketed
    port: int         # effective port (explicit, else the scheme default)
    path: str         # path plus ?query, always starts with a single "/"
    is_ip: bool

    @property
    def visit_key(self) -> tuple[str, str, int, str]:
        return (self.scheme, self.host, self.port, self.path)


def bracket_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def origin_url(scheme: str, host: str, port: int) -> str:
    return f"{scheme}://{bracket_host(host)}:{port}/"


def _display_url(location: str) -> str:
    """A storable stand-in for a refused, unparseable Location: printable
    characters only (Postgres text rejects NUL), 1..MAX_URL_LEN long."""
    cleaned = "".join(ch for ch in location if ch.isprintable()).strip()
    return cleaned[:MAX_URL_LEN] or "(empty)"


def parse_hop(base_url: str, location: str) -> tuple[Hop | None, str]:
    """Resolve `location` against `base_url` (RFC 3986) and normalise it.

    Returns `(Hop, url)` on success, or `(None, display_url)` when the
    destination is refused as `unsupported_url` (no request is made for it).
    `display_url` is the URL to store on the refused row."""
    raw = (location or "").strip()
    fallback = _display_url(raw)
    try:
        joined = urljoin(base_url, raw)
    except ValueError:
        return None, fallback
    shown = _display_url(joined)
    if len(joined) > MAX_URL_LEN:
        return None, shown
    try:
        parts = urlsplit(joined)
        port = parts.port
        host = parts.hostname
    except ValueError:
        return None, shown

    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        return None, shown
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        return None, shown
    if not host:
        return None, shown
    if port is not None and not 1 <= port <= 65535:
        return None, shown

    host = host.lower().rstrip(".")
    if not host or "%" in host:
        return None, shown
    is_ip = False
    try:
        host = str(ipaddress.ip_address(host))
        is_ip = True
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None, shown
        if not host or any(not 0x21 <= ord(c) <= 0x7E for c in host):
            return None, shown

    path = quote(parts.path or "/", safe=_PATH_SAFE)
    query = quote(parts.query, safe=_QUERY_SAFE) if parts.query else ""
    path_and_query = f"{path}?{query}" if query else path
    if not path_and_query.startswith("/") or path_and_query.startswith("//"):
        return None, shown
    if any(not 0x21 <= ord(c) <= 0x7E for c in path_and_query):
        return None, shown

    effective_port = port if port is not None else _DEFAULT_PORTS[scheme]
    port_part = f":{port}" if port is not None and port != _DEFAULT_PORTS[scheme] else ""
    url = f"{scheme}://{bracket_host(host)}{port_part}{path_and_query}"
    if len(url) > MAX_URL_LEN:
        return None, shown
    return Hop(url=url, scheme=scheme, host=host, port=effective_port, path=path_and_query, is_ip=is_ip), url


# -- chain state ----------------------------------------------------------------

@dataclass
class _Chain:
    origin_asset_id: uuid.UUID
    port: int
    scheme: str
    current_url: str
    pending_location: str
    visited: set = field(default_factory=set)
    fetches: int = 0
    live: bool = True
    rows: list = field(default_factory=list)  # dicts, one per hop row


@dataclass
class _Candidate:
    """A canonical row that could license a hop host, as the gate would see it."""
    row: AssetCanonical
    asset: DiscoveredAsset


def _text(value, cap: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(ch for ch in value if ch.isprintable()).strip()
    return cleaned[:cap] or None


def _normal_host(value: str) -> str:
    """The origin host spelled as `parse_hop` spells a hop host, so a hop back
    to the origin is recognised as a loop."""
    host = value.lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host


def _entries(patch: DiscoveredAsset) -> list[dict]:
    ports = (patch.asset_metadata or {}).get("open_ports") or []
    return [e for e in ports if isinstance(e, dict) and isinstance(e.get("port"), int) and not isinstance(e.get("port"), bool)]


def _is_redirect(entry: dict) -> bool:
    status = entry.get("http_status")
    return (
        isinstance(status, int) and not isinstance(status, bool)
        and 300 <= status < 400 and bool(entry.get("http_location"))
    )


# -- gate verdicts --------------------------------------------------------------

@dataclass
class _Verdict:
    allowed: bool
    rule: str | None
    asset_id: uuid.UUID | None
    resolved: bool  # False = no canonical row at all (gate not called)


def _judge_hosts(
    db: Session, *, connector, hops: list[Hop], scope: dict, scan_run_id: uuid.UUID,
) -> dict[tuple[bool, str], _Verdict]:
    """One verdict per distinct hop host, keyed `(is_ip, host)`.

    The gate keys its result by `(asset_type, value)`, so two `dns_record`
    rows of one hostname (A and AAAA) would overwrite each other in a single
    call. Candidates are therefore sent in layers: layer i holds the i-th
    candidate of every host, so a round costs max(candidates per host) gate
    calls, usually one."""
    ips = sorted({h.host for h in hops if h.is_ip})
    names = sorted({h.host for h in hops if not h.is_ip})

    candidates: dict[tuple[bool, str], list[_Candidate]] = {}
    if ips:
        for row in db.execute(
            select(AssetCanonical).where(
                AssetCanonical.asset_type == "ip_address", AssetCanonical.value.in_(ips)
            ).order_by(AssetCanonical.id)
        ).scalars():
            candidates.setdefault((True, row.value), []).append(
                _Candidate(row, DiscoveredAsset(asset_type="ip_address", value=row.value))
            )
    if names:
        for row in db.execute(
            select(AssetCanonical).where(
                AssetCanonical.asset_type == "dns_record", AssetCanonical.value.in_(names)
            ).order_by(AssetCanonical.id)
        ).scalars():
            meta = {}
            if row.record_type:
                meta["record_type"] = row.record_type
            if row.content:
                meta["content"] = row.content
            candidates.setdefault((False, row.value), []).append(
                _Candidate(row, DiscoveredAsset(asset_type="dns_record", value=row.value, asset_metadata=meta))
            )

    verdicts: dict[tuple[bool, str], _Verdict] = {}
    wanted = {(True, h) for h in ips} | {(False, n) for n in names}
    for key in wanted:
        if key not in candidates:
            verdicts[key] = _Verdict(allowed=False, rule=REASON_UNRESOLVED, asset_id=None, resolved=False)

    # permissions[key][i] = ProbePermission for candidate i of host `key`
    permissions: dict[tuple[bool, str], list] = {k: [] for k in candidates}
    depth = max((len(v) for v in candidates.values()), default=0)
    for layer in range(depth):
        layer_keys = [k for k, v in candidates.items() if len(v) > layer]
        gate = probe_authorisation.authorise_probes(
            db, connector_id=GATE_CONNECTOR_ID, connector=connector,
            assets=[candidates[k][layer].asset for k in layer_keys],
            scope=scope, scan_run_id=scan_run_id,
        )
        for k in layer_keys:
            asset = candidates[k][layer].asset
            permissions[k].append(gate.permissions[(asset.asset_type, asset.value)])

    for key, cands in candidates.items():
        host = key[1]
        verdict = _Verdict(allowed=True, rule=None, asset_id=cands[0].row.id, resolved=True)
        for cand, perm in zip(cands, permissions[key]):
            # Tightest wins: every candidate row must allow, and name the host.
            if not perm.allowed:
                verdict = _Verdict(allowed=False, rule=perm.rule_fired, asset_id=cands[0].row.id, resolved=True)
                break
            if not key[0] and host not in perm.names:   # a hostname must be an authorised name; an IP literal is not a name
                verdict = _Verdict(allowed=False, rule="name_not_authorised", asset_id=cands[0].row.id, resolved=True)
                break
        verdicts[key] = verdict
    return verdicts


# -- the walk -------------------------------------------------------------------

def _refuse(chain: _Chain, *, url: str, reason: str, asset_id: uuid.UUID | None = None,
            unresolved_host: str | None = None) -> None:
    chain.rows.append({
        "url": url, "followed": False, "reason": reason, "hop_asset_id": asset_id,
        "status": None, "title": None, "location": None,
        "unresolved_host": unresolved_host,
    })
    chain.live = False


def _walk(
    db: Session, *, connector, chains: list[_Chain], scope: dict, scan_run_id: uuid.UUID, timeout: float,
    stats: dict,
) -> None:
    for _round in range(MAX_HOPS + 1):
        live = [c for c in chains if c.live]
        if not live:
            return

        # 1-3: parse, loop, hop cap.
        pending: list[tuple[_Chain, Hop]] = []
        for chain in live:
            hop, shown = parse_hop(chain.current_url, chain.pending_location)
            if hop is None:
                _refuse(chain, url=shown, reason=REASON_UNSUPPORTED_URL)
                continue
            if hop.visit_key in chain.visited:
                _refuse(chain, url=hop.url, reason=REASON_LOOP)
                continue
            if chain.fetches >= MAX_HOPS:
                _refuse(chain, url=hop.url, reason=REASON_HOP_CAP)
                continue
            chain.visited.add(hop.visit_key)
            pending.append((chain, hop))
        if not pending:
            continue

        # 4: the probe gate, real verdict.
        verdicts = _judge_hosts(
            db, connector=connector, hops=[h for _, h in pending], scope=scope, scan_run_id=scan_run_id,
        )
        allowed: list[tuple[_Chain, Hop, _Verdict]] = []
        for chain, hop in pending:
            verdict = verdicts[(hop.is_ip, hop.host)]
            if not verdict.allowed:
                _refuse(
                    chain, url=hop.url, reason=verdict.rule or "denied", asset_id=verdict.asset_id,
                    unresolved_host=None if (verdict.resolved or hop.is_ip) else hop.host,
                )
                continue
            allowed.append((chain, hop, verdict))

        # 5: SSRF pin, only for hosts the gate allowed.
        batch: list[dict] = []
        batch_meta: dict[str, tuple[_Chain, Hop, _Verdict]] = {}
        for chain, hop, verdict in allowed:
            try:
                pinned = pin_address(hop.host, hop.port)
            except SSRFBlockedError:
                _refuse(chain, url=hop.url, reason=REASON_SSRF, asset_id=verdict.asset_id)
                continue
            except (httpx.ConnectError, UnicodeError, OSError):
                _refuse(chain, url=hop.url, reason=REASON_DNS, asset_id=verdict.asset_id)
                continue
            fetch_id = f"h{len(batch_meta)}"
            batch_meta[fetch_id] = (chain, hop, verdict)
            batch.append({
                "id": fetch_id, "ip": pinned, "port": hop.port, "scheme": hop.scheme,
                "path": hop.path, "host": None if hop.is_ip else hop.host,
            })
        if not batch:
            continue

        # 6: fetch.
        results = {r.get("id"): r for r in connector.fetch_urls(batch, timeout=timeout)}
        for fetch_id, (chain, hop, verdict) in batch_meta.items():
            res = results.get(fetch_id) or {"error": "no_response"}
            error = res.get("error")
            if error == "blocked":
                # The worker's own SSRF check refused it: nothing was sent.
                _refuse(chain, url=hop.url, reason=REASON_SSRF, asset_id=verdict.asset_id)
                continue
            if error == "worker_unavailable":
                # The worker was never reached, so no request went out:
                # `followed` would over-claim. Not a policy refusal either,
                # hence its own reason; the next probe of this endpoint retries.
                _refuse(chain, url=hop.url, reason=REASON_WORKER, asset_id=verdict.asset_id)
                continue
            chain.fetches += 1
            status = res.get("status_code")
            if not (isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599):
                status = None
            if error or status is None:
                label = error or "no_response"
                stats["fetch_errors"][label] = stats["fetch_errors"].get(label, 0) + 1
                log.info("redirect_follow: fetch of hop %s ended with %s", hop.url, label)
            location = _text(res.get("location"), LOCATION_CAP) if status is not None else None
            chain.rows.append({
                "url": hop.url, "followed": True, "reason": None, "hop_asset_id": verdict.asset_id,
                "status": status,
                "title": _text(res.get("title"), TITLE_CAP) if status is not None else None,
                "location": location, "unresolved_host": None,
            })
            # 7: continue only on a redirect.
            if status is not None and 300 <= status < 400 and location:
                chain.current_url = hop.url
                chain.pending_location = location
            else:
                chain.live = False


# -- leads ----------------------------------------------------------------------

def _owning_domain(host: str, owned_domains) -> str | None:
    matches = [d for d in owned_domains if host == d or host.endswith("." + d)]
    return max(matches, key=len) if matches else None


def _mint_leads(
    db: Session, *, hosts: list[str], owned_domains, scan_run_id: uuid.UUID, target_ids,
) -> dict[str, uuid.UUID]:
    """Record each unknown hostname once; returns host -> canonical id."""
    if not hosts:
        return {}
    minted: list[DiscoveredAsset] = []
    for host in hosts:
        if dns_resolve._is_owned(host, owned_domains):
            # Copied from subfinder's bare discovered hostname: dns_record,
            # parent_value = the owning target domain, sources only.
            minted.append(DiscoveredAsset(
                asset_type="dns_record", value=host,
                parent_value=_owning_domain(host, owned_domains),
                asset_metadata={"sources": ["redirect"]},
            ))
        else:
            minted.append(dns_resolve._third_party_node(host, source="redirect", discovered_via="redirect"))
    write_assets(db, scan_run_id, minted, target_ids=target_ids)
    by_key = probe_authorisation._resolve_canonical_batch(db, minted)
    out: dict[str, uuid.UUID] = {}
    for asset in minted:
        row = by_key.get(probe_authorisation._canonical_key_for(asset))
        if row is not None:
            out[asset.value] = row.id
    return out


# -- entry point ----------------------------------------------------------------

def follow_redirects(
    db: Session, *, connector, patches: list[DiscoveredAsset], scope: dict, scan_run_id: uuid.UUID,
    owned_domains, target_ids, timeout: float,
) -> dict:
    """Follow the redirects of this run's httpx results and store the chains.

    Returns counts: `chains`, `followed`, `refused` (by reason),
    `leads_minted`, `fetch_errors` (by worker error). Flushes; never commits
    (except inside `write_assets`)."""
    stats: dict = {"chains": 0, "followed": 0, "refused": {}, "leads_minted": 0, "fetch_errors": {}}

    canonical_by_key = probe_authorisation._resolve_canonical_batch(db, patches)

    probed: dict[tuple[uuid.UUID, int], None] = {}
    chains: list[_Chain] = []
    for patch in patches:
        origin = canonical_by_key.get(probe_authorisation._canonical_key_for(patch))
        entries = _entries(patch)
        if origin is None:
            if entries:
                log.warning("redirect_follow: no canonical row for origin %s; its chains are skipped", patch.value)
            continue
        for entry in entries:
            probed[(origin.id, entry["port"])] = None
            scheme = entry.get("service")
            if scheme not in _DEFAULT_PORTS or not _is_redirect(entry):
                continue
            if not 1 <= entry["port"] <= 65535:
                continue
            start = origin_url(scheme, patch.value, entry["port"])
            chain = _Chain(
                origin_asset_id=origin.id, port=entry["port"], scheme=scheme,
                current_url=start, pending_location=entry["http_location"],
            )
            chain.visited.add((scheme, _normal_host(patch.value), entry["port"], "/"))
            chains.append(chain)

    if chains:
        _walk(db, connector=connector, chains=chains, scope=scope, scan_run_id=scan_run_id, timeout=timeout, stats=stats)

    # Leads: a refused hostname hop with no canonical dns_record row at all.
    lead_hosts: list[str] = []
    for chain in chains:
        for row in chain.rows:
            host = row.get("unresolved_host")
            if host and host not in lead_hosts:
                lead_hosts.append(host)
    minted_ids = _mint_leads(
        db, hosts=lead_hosts, owned_domains=owned_domains, scan_run_id=scan_run_id, target_ids=target_ids,
    )
    stats["leads_minted"] = len(minted_ids)

    # Storage: replace the chain of EVERY probed endpoint (one that stopped
    # redirecting loses its chain; one not probed this run keeps its rows).
    if probed:
        db.query(HttpRedirectHop).filter(
            tuple_(HttpRedirectHop.origin_asset_id, HttpRedirectHop.origin_port).in_(list(probed))
        ).delete(synchronize_session=False)
    for chain in chains:
        stats["chains"] += 1
        for index, row in enumerate(chain.rows, start=1):
            asset_id = row["hop_asset_id"]
            if asset_id is None and row.get("unresolved_host"):
                asset_id = minted_ids.get(row["unresolved_host"])
            db.add(HttpRedirectHop(
                origin_asset_id=chain.origin_asset_id, origin_port=chain.port, origin_scheme=chain.scheme,
                hop_index=index, url=row["url"][:MAX_URL_LEN], hop_asset_id=asset_id,
                followed=row["followed"], reason=row["reason"], http_status=row["status"],
                http_title=row["title"], http_location=row["location"], scan_run_id=scan_run_id,
            ))
            if row["followed"]:
                stats["followed"] += 1
            else:
                stats["refused"][row["reason"]] = stats["refused"].get(row["reason"], 0) + 1
    db.flush()
    return stats
