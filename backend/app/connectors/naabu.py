"""Naabu port-discovery connector.

Runs against every public IP asset surfaced by Phase 1, asks the
scanner-worker to probe the tier-resolved port set, and emits a single
metadata patch per IP that adds the discovered ports to
`ip.asset_metadata.open_ports[]`. Each entry is a dict
`{port, protocol, sources, last_seen_at, naabu_tier}` — future enrichers
(tlsx, httpx, banner grab) merge into the same entry under the same
port number, adding `service`, `service_version`, `tech_stack[]`, etc.

Ports are properties of a host, not assets in their own right — same
model every other EASM uses (Tenable, Qualys, Shodan, Censys, Defender
EASM). Findings against a port attach to the IP with `port` in
metadata + fingerprint so per-port uniqueness still works.

Phase placement: this connector is technically a ScanningConnector for
config/UI taxonomy purposes, but its real work happens via the
`port_scan(assets, config)` duck-typed hook in Phase 1.5. The standard
`scan(targets, config)` method is a no-op so the Phase 3 loop has
nothing to do for this connector.

User configuration:
  - additional_ports — list of extra ports to scan on top of the tier
    (e.g. "631,9200"). Triggers a second naabu pass against those ports
    because naabu's -top-ports and -p flags are mutually exclusive.
  - exclude_ports — list of ports to skip entirely.
"""

import ipaddress
import logging
import os
import re
from typing import Any

import httpx

from app.connectors.base import (
    DiscoveredAsset,
    PhaseResult,
    ScanningConnector,
    TestResult,
)
from app.models.asset import AssetType
from app.services import aggressiveness

log = logging.getLogger(__name__)

_SCANNER_URL = os.environ.get("SCANNER_URL", "http://scanner-worker:8001")
_SCANNER_TOKEN = os.environ.get("SCANNER_INTERNAL_TOKEN", "")
_HEADERS = {"X-Internal-Token": _SCANNER_TOKEN}

# Broad-sweep open-port count above which a host is treated as tarpitted
# (SYN-flood / scan-deception firewall answering every probe). Real hosts rarely
# expose this many services; a tarpit returns dozens-to-hundreds. See the tarpit
# guard in port_scan.
_TARPIT_PORT_THRESHOLD = 30

# When nmap verify returns nothing (infra hiccup), fail OPEN to naabu's own
# discoveries only if there are at most this many — a normal host with a
# transient nmap failure. More than this with zero nmap confirmations is almost
# certainly flood-protection noise, so we fail CLOSED rather than store phantoms.
_FAIL_OPEN_MAX_PORTS = 15

# Sanitiser for user-supplied port-list config. Anything that isn't a
# comma-separated list of integers gets rejected.
_PORT_LIST_RE = re.compile(r"^\s*\d{1,5}(\s*,\s*\d{1,5})*\s*$")


def _parse_port_list(raw: Any) -> list[int]:
    """Coerce a config field (string CSV, list, or empty) into a sanitised
    list of unique ints 1..65535. Invalid input returns [] — connector
    config UI validates at edit time, this is belt-and-braces."""
    if not raw:
        return []
    items: list[str] = []
    if isinstance(raw, list):
        items = [str(x).strip() for x in raw if str(x).strip()]
    elif isinstance(raw, str):
        if not _PORT_LIST_RE.match(raw):
            return []
        items = [s.strip() for s in raw.split(",") if s.strip()]
    out: list[int] = []
    seen: set[int] = set()
    for s in items:
        try:
            p = int(s)
        except ValueError:
            continue
        if 1 <= p <= 65535 and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        addr.is_private or addr.is_loopback or addr.is_multicast
        or addr.is_link_local or addr.is_reserved or addr.is_unspecified
    )


class NaabuConnector(ScanningConnector):
    name = "Naabu"
    description = (
        "Active port discovery — probes public IP assets for open TCP ports. "
        "Tier (stealth/polite/standard/aggressive) controls how many ports get scanned."
    )
    core = True

    def get_config_schema(self) -> dict:
        return {
            "additional_ports": {
                "label": "Additional Ports",
                "type": "text",
                "default": "",
                "placeholder": "631, 9200, 27017",
                "help": (
                    "Comma-separated TCP ports to scan on top of the tier baseline. "
                    "Useful for ports outside the top-1000 (e.g. 631, 9200)."
                ),
            },
            "exclude_ports": {
                "label": "Exclude Ports",
                "type": "text",
                "default": "",
                "placeholder": "25, 587",
                "help": "Comma-separated TCP ports to skip (e.g. mail ports your provider blocks).",
            },
        }

    def is_configured(self) -> bool:
        # Connector is config-free; the scanner-worker token is what
        # actually authenticates the request. Without a token nothing
        # can reach the worker so the connector is "unconfigured".
        return bool(_SCANNER_TOKEN)

    def _test(self, config: dict) -> TestResult:
        try:
            resp = httpx.get(f"{_SCANNER_URL}/health", headers=_HEADERS, timeout=10)
            if resp.status_code == 200:
                return TestResult(success=True, message=f"Scanner worker reachable at {_SCANNER_URL}")
            return TestResult(
                success=False,
                message=f"Scanner worker returned HTTP {resp.status_code}",
            )
        except httpx.ConnectError:
            return TestResult(
                success=False,
                message=f"Cannot reach scanner worker at {_SCANNER_URL}",
            )
        except Exception as e:
            return TestResult(success=False, message=str(e))

    def scan(self, targets: list[str], config: dict[str, Any]) -> PhaseResult:
        # Phase 3 no-op. Naabu's actual work runs via the port_scan()
        # duck-typed hook in Phase 1.5. See module docstring.
        return PhaseResult()

    def port_scan(
        self,
        assets: list[DiscoveredAsset],
        config: dict[str, Any],
    ) -> PhaseResult:
        """Phase 1.5 entry point — probe every public IP in `assets`."""
        tier_name = config.get("_tier", "")
        tier_profile = (config.get("_aggressiveness") or {}).get("naabu") or {}
        if not tier_profile.get("enabled", False):
            log.info("Naabu skipped — disabled at %s tier", tier_name or "current")
            return PhaseResult()

        # Public IPs only. Private addresses inside containers can be
        # legitimate scan targets but we surface them via the existing
        # internal-host flow, not naabu — same posture as Shodan.
        ip_values: list[str] = []
        seen: set[str] = set()
        for a in assets:
            if a.asset_type != AssetType.IP_ADDRESS:
                continue
            if a.value in seen:
                continue
            if not _is_public_ip(a.value):
                continue
            seen.add(a.value)
            ip_values.append(a.value)

        if not ip_values:
            log.info("Naabu skipped — no public IPs in scope")
            return PhaseResult()

        top_ports = int(tier_profile.get("top_ports", 100))
        rate = int(tier_profile.get("rate", 500))
        concurrency = int(tier_profile.get("concurrency", 10))

        additional_ports = _parse_port_list(config.get("additional_ports"))
        exclude_ports = _parse_port_list(config.get("exclude_ports"))

        log.info(
            "Naabu starting — tier=%s top_ports=%d rate=%dpps concurrency=%d "
            "additional=%d exclude=%d ips=%d",
            tier_name or "?", top_ports, rate, concurrency,
            len(additional_ports), len(exclude_ports), len(ip_values),
        )

        # Pass 1 — tier baseline via -top-ports
        baseline = self._invoke_worker(
            hosts=ip_values,
            top_ports=top_ports,
            ports=None,
            exclude_ports=exclude_ports,
            rate=rate,
            concurrency=concurrency,
        )

        # Tarpit detection — a host returning an absurd number of ports from the
        # broad top-ports sweep is almost certainly behind SYN-flood / scan-
        # deception (the firewall answers every probe). We FLAG it and then
        # RE-DISCOVER it with a narrower full-connect pass (`naabu -verify`):
        # the connect re-confirmation collapses the phantom flood to ~the real
        # ports, giving the downstream GENTLE nmap verify (`-sT -T2`, gated on
        # tarpit_ips) a small candidate set. This keeps naabu's real discoveries
        # (unlike the old discard-baseline approach) while keeping the verify set
        # small enough for gentle timing. Validated live 2026-06-23 (planning#69/#72):
        # broad naabu flaps 2–134 phantoms run-to-run, but -verify reliably narrows
        # to the real ports, and gentle nmap then drops any phantom that survives.
        baseline_per_ip: dict[str, int] = {}
        for r in baseline:
            h = r.get("host", "")
            baseline_per_ip[h] = baseline_per_ip.get(h, 0) + 1
        tarpit_ips = {ip for ip, n in baseline_per_ip.items() if n >= _TARPIT_PORT_THRESHOLD}

        # Re-discover tarpit hosts with naabu -verify (union of 2 passes — a single
        # pass can miss a flaky real port; union catches it). Non-tarpit hosts keep
        # their fast broad baseline untouched.
        verify_rows: list[dict] = []
        if tarpit_ips:
            log.warning(
                "Tarpit suspected on %s (naabu port counts=%s) — re-discovering with "
                "naabu -verify (x2 union), then confirming with gentle nmap (-sT -T2)",
                sorted(tarpit_ips), {ip: baseline_per_ip[ip] for ip in sorted(tarpit_ips)},
            )
            seen_v: set[tuple[str, int]] = set()
            for _ in range(2):
                for row in self._invoke_worker(
                    hosts=sorted(tarpit_ips),
                    top_ports=top_ports,
                    ports=None,
                    exclude_ports=exclude_ports,
                    rate=rate,
                    concurrency=concurrency,
                    verify=True,
                ):
                    k = (row.get("host", ""), int(row.get("port", 0)))
                    if k not in seen_v:
                        seen_v.add(k)
                        verify_rows.append(row)
            log.info(
                "Tarpit narrowing: naabu -verify on %d host(s) → %d candidate(s) (was flood)",
                len(tarpit_ips), len(verify_rows),
            )

        # Merge naabu's discoveries by (host, port). Tarpit hosts use the -verify
        # narrowed rows (their broad baseline is a phantom flood — dropped here);
        # non-tarpit hosts keep their fast baseline as-is.
        merged: dict[tuple[str, int], dict] = {}
        for row in baseline:
            if row.get("host", "") in tarpit_ips:
                continue
            merged.setdefault((row.get("host", ""), int(row.get("port", 0))), row)
        for row in verify_rows:
            merged.setdefault((row.get("host", ""), int(row.get("port", 0))), row)

        log.info("Naabu found %d candidate ports across %d IPs", len(merged), len(ip_values))

        # Additional ports (operator-declared) are folded into the nmap-verify
        # candidate set directly rather than scanned by a SECOND naabu call —
        # that separate `-p` request cost a full ~30-60s round-trip per scan
        # (naabu's fixed per-invocation overhead). nmap confirms whether each is
        # actually open, exactly like a Shodan hint; an unconfirmed one is dropped.
        for ip in ip_values:
            for p in additional_ports:
                key = (ip, p)
                if key not in merged:
                    merged[key] = {"host": ip, "ip": ip, "port": p, "hint_source": "additional"}

        # Fold in passive port hints (e.g. Shodan host ports, hydrated onto the
        # IP metadata by the executor from a prior enrichment). They join naabu's
        # own discoveries in the nmap-verify set below; a hint nmap can't confirm
        # is retained provisionally (marked hint_source) so the banner enrichers
        # get a chance to corroborate it — see _apply_nmap_verification.
        hint_added = 0
        for ip, ports in self._collect_port_hints(assets).items():
            for p in ports:
                key = (ip, p)
                if key not in merged:
                    merged[key] = {"host": ip, "ip": ip, "port": p, "hint_source": "shodan"}
                    hint_added += 1
        if hint_added:
            log.info("Naabu folded in %d passive port hint(s) for nmap verification", hint_added)

        # Fold in prior app-confirmed ports (executor-hydrated `prior_ports`).
        # These re-enter the nmap-verify set every run so a known-real port that
        # naabu's flaky tarpit discovery missed is still re-confirmed (the live
        # port-80 dropout case, planning#69). nmap remains authoritative — a prior
        # port it can't confirm this run is dropped, like any other hint.
        prior_added = 0
        for ip, ports in self._collect_prior_ports(assets).items():
            for p in ports:
                key = (ip, p)
                if key not in merged:
                    merged[key] = {"host": ip, "ip": ip, "port": p, "hint_source": "prior"}
                    prior_added += 1
        if prior_added:
            log.info("Naabu folded in %d prior-confirmed port(s) for re-verification", prior_added)

        # Pass 3 — nmap verification. Filter out false positives (e.g. stateful
        # firewalls that accept TCP on random ports) and enrich confirmed ports
        # with nmap service/version data. If nmap is unavailable or times out
        # for a host, that host's naabu results are kept as-is (fail open).
        # Tarpit hosts (now narrowed by naabu -verify above) are verified GENTLY
        # (-sT -T2) so the firewall's deception stays off; non-tarpit hosts use the
        # fast default. Safe because the tarpit candidate set is small post-narrowing.
        nmap_data = self._invoke_nmap_verify(merged, gentle_ips=tarpit_ips)
        merged = self._apply_nmap_verification(merged, nmap_data)

        log.info("Nmap confirmed %d open ports across %d IPs", len(merged), len(ip_values))
        return self._build_phase_result(
            merged.values(), tier_name, scanned_ips=set(ip_values), tarpit_ips=tarpit_ips,
        )

    # ── internals ────────────────────────────────────────────────────────

    def _collect_port_hints(
        self,
        assets: list[DiscoveredAsset],
    ) -> dict[str, set[int]]:
        """Ports discovered by passive sources (currently Shodan host data) that
        the executor copied onto the in-batch IP metadata. Returned as
        {ip: {ports}} for folding into the nmap-verify candidate set."""
        hints: dict[str, set[int]] = {}
        for a in assets:
            if a.asset_type != AssetType.IP_ADDRESS or not _is_public_ip(a.value):
                continue
            for p in (a.asset_metadata or {}).get("shodan_ports") or []:
                if isinstance(p, int) and 1 <= p <= 65535:
                    hints.setdefault(a.value, set()).add(p)
        return hints

    def _collect_prior_ports(
        self,
        assets: list[DiscoveredAsset],
    ) -> dict[str, set[int]]:
        """Prior app-confirmed ports (l7_confirmed) the executor hydrated onto IP
        metadata as `prior_ports`. Folded into the nmap-verify set so a known-real
        port is re-confirmed every run even if naabu's (tarpit-flaky) discovery
        missed it this run. Returned as {ip: {ports}}."""
        prior: dict[str, set[int]] = {}
        for a in assets:
            if a.asset_type != AssetType.IP_ADDRESS or not _is_public_ip(a.value):
                continue
            for p in (a.asset_metadata or {}).get("prior_ports") or []:
                if isinstance(p, int) and 1 <= p <= 65535:
                    prior.setdefault(a.value, set()).add(p)
        return prior

    def _invoke_worker(
        self,
        *,
        hosts: list[str],
        top_ports: int | None,
        ports: list[int] | None,
        exclude_ports: list[int],
        rate: int,
        concurrency: int,
        verify: bool = False,
    ) -> list[dict]:
        payload: dict[str, Any] = {
            "hosts": hosts,
            "exclude_ports": exclude_ports,
            "rate": rate,
            "concurrency": concurrency,
        }
        if top_ports is not None:
            payload["top_ports"] = top_ports
        if ports is not None:
            payload["ports"] = ports
        if verify:
            payload["verify"] = True

        try:
            resp = httpx.post(
                f"{_SCANNER_URL}/naabu/scan",
                json=payload,
                headers=_HEADERS,
                timeout=930,
            )
            resp.raise_for_status()
            body = resp.json()
            results = body.get("results", []) or []
            if body.get("timed_out"):
                log.warning(
                    "Naabu worker call timed out for %d host(s) — %d result(s) recovered from partial "
                    "output before the subprocess was killed", len(hosts), len(results),
                )
            return results
        except httpx.HTTPError:
            log.exception("Naabu worker request failed (top_ports=%s, ports=%s)", top_ports, ports)
            return []

    def _invoke_nmap_verify(
        self,
        merged: dict[tuple[str, int], dict],
        gentle_ips: set[str] | None = None,
    ) -> dict[str, dict[int, dict]]:
        """Call /nmap/verify on the scanner worker for all (ip, port) pairs
        in merged. Returns {ip: {port: {service, product, version, extra_info}}}.

        `gentle_ips` (tarpit-flagged hosts) are verified with a slow full-connect
        probe (-sT -T2) so the firewall's scan-deception stays off; other hosts
        keep the fast default. On any error the result is an empty dict; the
        caller then trusts naabu's -verify'd discoveries and drops unconfirmed
        passive hints.
        """
        if not merged:
            return {}

        # Build target list — BannerGrabTarget shape: {ip, port}
        targets = []
        for row in merged.values():
            ip = row.get("ip") or row.get("host", "")
            port = row.get("port")
            if ip and port:
                targets.append({"ip": ip, "port": int(port)})

        if not targets:
            return {}

        try:
            resp = httpx.post(
                f"{_SCANNER_URL}/nmap/verify",
                json={"targets": targets, "gentle_ips": sorted(gentle_ips or ())},
                headers=_HEADERS,
                timeout=600,
            )
            resp.raise_for_status()
            results = resp.json().get("results", []) or []
        except httpx.HTTPError:
            log.warning("nmap verify request failed — retaining naabu results as-is")
            return {}

        # Index by ip → port → service data, tcpwrapped included. The keep/drop
        # decision (tcpwrapped = handshake but no app data) lives in
        # _apply_nmap_verification so it can distinguish "nmap saw a phantom"
        # from "nmap never reached this port".
        by_ip: dict[str, dict[int, dict]] = {}
        for r in results:
            ip = r.get("ip", "")
            port = r.get("port")
            if not ip or port is None:
                continue
            by_ip.setdefault(ip, {})[int(port)] = {
                "service": r.get("service"),
                "product": r.get("product"),
                "version": r.get("version"),
                "extra_info": r.get("extra_info"),
            }
        return by_ip

    def _apply_nmap_verification(
        self,
        merged: dict[tuple[str, int], dict],
        nmap_data: dict[str, dict[int, dict]],
    ) -> dict[tuple[str, int], dict]:
        """nmap is the open/closed authority; keep only ports it confirms open.

        Empirically (2026-06-21), naabu `-verify` is NOT a reliable gatekeeper
        behind SYN-flood / scan-deception firewalls: the firewall completes
        handshakes on hundreds of ports, so naabu (and a *broad* nmap scan) report
        phantoms — non-deterministically, and differently each run. The one thing
        that stays accurate is nmap probing a SMALL set of ports: it returns a real
        open/filtered/closed state per port. So the rule is now simple and the same
        for every source:

          • keep a port ONLY if nmap returned it `open` with real service data;
          • drop it if nmap returned nothing (filtered/closed/no-response) or only
            `tcpwrapped` (handshake, no app data) — i.e. fail **closed**.

        This relies on the candidate set being small (the tarpit guard in
        `port_scan` re-discovers a flood-suspected host with `naabu -verify` and
        feeds nmap that narrowed set instead of the broad phantom baseline; those
        hosts are then verified gently, -sT -T2). When nmap is entirely unavailable
        we fail **open** to naabu's discoveries (better to over-report than to blank
        the host on an infra hiccup) and drop the uncorroborated hints.
        """
        def _nmap_real(svc: dict | None) -> bool:
            return bool(svc) and not (
                svc.get("service") == "tcpwrapped"
                and not svc.get("product") and not svc.get("version")
            )

        if not nmap_data:
            # nmap returned nothing. Fail OPEN to naabu's discoveries only when
            # there are few (a transient nmap hiccup on a normal host); if naabu
            # found many ports and nmap confirmed none, that's flood-protection
            # noise — fail CLOSED rather than store unverified phantoms.
            discoveries = {k: r for k, r in merged.items() if not r.get("hint_source")}
            if len(discoveries) <= _FAIL_OPEN_MAX_PORTS:
                return discoveries
            log.warning(
                "nmap verify returned nothing for %d naabu port(s) — failing closed "
                "(likely flood-protection noise; nmap confirmed none)",
                len(discoveries),
            )
            return {}

        verified: dict[tuple[str, int], dict] = {}
        for key, row in merged.items():
            ip = row.get("ip") or row.get("host", "")
            port = int(row.get("port", 0))
            svc = nmap_data.get(ip, {}).get(port)
            # nmap-authoritative: keep only what nmap confirms open (real service).
            if _nmap_real(svc):
                verified[key] = {**row, **{k: v for k, v in svc.items() if v}}
            # else: dropped — nmap didn't confirm an open service here.

        return verified

    def _build_phase_result(
        self,
        rows: Any,
        tier_name: str,
        scanned_ips: set[str] | None = None,
        tarpit_ips: set[str] | None = None,
    ) -> PhaseResult:
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat()
        tarpit_ips = tarpit_ips or set()
        # {ip: {port: row}} — preserve full row so nmap service fields survive
        per_ip: dict[str, dict[int, dict]] = {}

        for row in rows:
            host = row.get("host")
            ip = row.get("ip") or host
            port = row.get("port")
            if not host or port is None:
                continue
            try:
                p = int(port)
            except (TypeError, ValueError):
                continue
            if not (1 <= p <= 65535):
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            per_ip.setdefault(ip, {})[p] = row

        # One metadata patch per IP carrying the open_ports[] dict-list.
        # asset_writer merges these per-port (union sources, last-write-wins
        # for primitives) so successive scans + future enrichers compose.
        patches: list[DiscoveredAsset] = []
        for ip, port_rows in per_ip.items():
            open_ports = []
            for p in sorted(port_rows):
                row = port_rows[p]
                # A hint-sourced row (Shodan) carries its origin as the base
                # source instead of "naabu" — it wasn't naabu that found it.
                hint_source = row.get("hint_source")
                base_source = hint_source or "naabu"
                entry: dict = {
                    "port": p,
                    "protocol": "tcp",
                    "sources": [base_source],
                    "last_seen_at": now,
                    "naabu_tier": tier_name,
                }
                # Attach nmap service data when present (written by
                # _apply_nmap_verification). "nmap" added to sources so
                # downstream enrichers know this port was nmap-verified.
                nmap_fields = ("service", "product", "version", "extra_info")
                has_nmap = any(row.get(f) for f in nmap_fields)
                if has_nmap:
                    entry["sources"] = list(dict.fromkeys([base_source, "nmap"]))
                    if row.get("service"):
                        entry["service"] = row["service"]
                    # nmap reports product/version as separate fields, but the UI
                    # renders the secondary line from `service_version` — so fold
                    # them into one string. For non-HTTP services nmap is often the
                    # only identifier (e.g. DNS → "NLnet Labs NSD"); without this
                    # the product never displays. banner_grab/httpx run later and
                    # override service_version for HTTP ports with their richer
                    # Server string.
                    sv = " ".join(
                        x for x in (row.get("product"), row.get("version")) if x
                    ).strip()
                    if sv:
                        entry["service_version"] = sv
                open_ports.append(entry)

            patches.append(DiscoveredAsset(
                asset_type=AssetType.IP_ADDRESS,
                value=ip,
                parent_value=None,
                asset_metadata={
                    "sources": ["naabu"],
                    "open_ports": open_ports,
                    "naabu_last_scan_at": now,
                    "naabu_tier": tier_name,
                    "tarpit_detected": ip in tarpit_ips,
                },
            ))

        # IPs naabu scanned but nmap confirmed zero open ports still need a
        # naabu_last_scan_at update. Without it the staleness filter in the
        # assets API never advances past the previous scan's timestamp and
        # the old ports remain visible. Writing an empty open_ports patch
        # updates the timestamp while the merge leaves existing port rows
        # untouched — the API filter then hides them as stale.
        ips_with_patches = set(per_ip.keys())
        for ip in (scanned_ips or set()) - ips_with_patches:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            patches.append(DiscoveredAsset(
                asset_type=AssetType.IP_ADDRESS,
                value=ip,
                parent_value=None,
                asset_metadata={
                    "sources": ["naabu"],
                    "open_ports": [],
                    "naabu_last_scan_at": now,
                    "naabu_tier": tier_name,
                    "tarpit_detected": ip in tarpit_ips,
                },
            ))

        return PhaseResult(assets=patches)
