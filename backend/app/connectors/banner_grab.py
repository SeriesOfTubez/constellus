"""Banner-grab connector — Service Identification Stack Layer 1.

Reads ports discovered by naabu (`ip.asset_metadata.open_ports[]`) and
identifies the service on each. Plaintext protocols with a zgrab2 module
(ssh, ftp, smtp, pop3, imap, mysql, redis, postgres, mssql, modbus, mongodb,
smb, rdp, memcached — see scanner-worker's `_ZGRAB2_PORT_MODULES`) get a
high-confidence probe on their conventional port; every open port also gets
a short-timeout zgrab2 "cascade" of the silent-protocol modules
(`_CORE8_CASCADE_MODULES`) so those services are identified even on
non-default ports. VNC is identified passively via its `RFB x.y` banner.
Anything else falls back to a bare asyncio TCP connect + read (`_grab_one`).

The scanner-worker does the actual probing. Stays in step with the
existing scanner-worker token + sidecar deployment model.

Architecturally identical to naabu: ScanningConnector subclass with a
no-op `scan()` and a real `port_scan(assets, config)` Phase 1.5 hook.
Ordering is set by `port_scan_order` (higher runs later), which is read
by `scan_executor` so banner_grab always sees the naabu patches that
got appended to `all_assets` in the same phase.

What it adds per port:
  service          — normalised label (ssh, http, smtp, ftp, …)
  service_version  — vendor/version where the protocol announces it
  banner_snippet   — first line of raw bytes, lossy-truncated
  zgrab2           — full raw zgrab2 module result, for zgrab2-scanned
                      ports (additive, same pattern as tlsx's cert_summary)
  sources          — "banner_grab" appended via the writer's union

Doesn't touch TLS-wrapped ports (443, 8443, etc) — those need a TLS
handshake to reveal anything, which is Stack Layer 3 (tlsx).
"""

import ipaddress
import logging
import os
from typing import Any

import httpx

from app.connectors.base import (
    DiscoveredAsset,
    PhaseResult,
    ScanningConnector,
    TestResult,
)
from app.models.asset import AssetType

log = logging.getLogger(__name__)

_SCANNER_URL = os.environ.get("SCANNER_URL", "http://scanner-worker:8001")
_SCANNER_TOKEN = os.environ.get("SCANNER_INTERNAL_TOKEN", "")
_HEADERS = {"X-Internal-Token": _SCANNER_TOKEN}


def _is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        addr.is_private or addr.is_loopback or addr.is_multicast
        or addr.is_link_local or addr.is_reserved or addr.is_unspecified
    )


class BannerGrabConnector(ScanningConnector):
    name = "Banner Grab"
    description = (
        "Service identification — connects to each open port discovered by Naabu, "
        "captures the protocol banner, and extracts service/version info."
    )
    core = True

    # Runs AFTER naabu (default 100) in the Phase 1.5 loop. Asset writer
    # merges per-port, so naabu's open_ports[] patches must be present in
    # `all_assets` before this connector iterates them.
    port_scan_order = 200

    def get_config_schema(self) -> dict:
        return {}

    def is_configured(self) -> bool:
        return bool(_SCANNER_TOKEN)

    def _test(self, config: dict) -> TestResult:
        try:
            resp = httpx.get(f"{_SCANNER_URL}/health", headers=_HEADERS, timeout=10)
            if resp.status_code == 200:
                return TestResult(success=True, message=f"Scanner worker reachable at {_SCANNER_URL}")
            return TestResult(success=False, message=f"Scanner worker returned HTTP {resp.status_code}")
        except httpx.ConnectError:
            return TestResult(success=False, message=f"Cannot reach scanner worker at {_SCANNER_URL}")
        except Exception as e:
            return TestResult(success=False, message=str(e))

    def scan(self, targets: list[str], config: dict[str, Any]) -> PhaseResult:
        # Phase 3 no-op — real work is the port_scan() hook below.
        return PhaseResult()

    def port_scan(
        self,
        assets: list[DiscoveredAsset],
        config: dict[str, Any],
    ) -> PhaseResult:
        tier_name = config.get("_tier", "")
        tier_profile = (config.get("_aggressiveness") or {}).get("banner_grab") or {}
        if not tier_profile.get("enabled", False):
            log.info("Banner grab skipped — disabled at %s tier", tier_name or "current")
            return PhaseResult()

        # Collect (ip, port) pairs from the open_ports[] metadata that naabu
        # (or any earlier port enricher) populated on each public IP.
        # Dedupe across multiple patches for the same IP.
        per_ip_ports: dict[str, set[int]] = {}
        for a in assets:
            if a.asset_type != AssetType.IP_ADDRESS:
                continue
            if not _is_public_ip(a.value):
                continue
            open_ports = (a.asset_metadata or {}).get("open_ports") or []
            if not isinstance(open_ports, list):
                continue
            for entry in open_ports:
                if not isinstance(entry, dict):
                    continue
                port = entry.get("port")
                if isinstance(port, int) and 1 <= port <= 65535:
                    per_ip_ports.setdefault(a.value, set()).add(port)

        if not per_ip_ports:
            log.info("Banner grab skipped — no open ports to probe")
            return PhaseResult()

        targets = [
            {"ip": ip, "port": port}
            for ip, ports in per_ip_ports.items()
            for port in sorted(ports)
        ]

        timeout = float(tier_profile.get("timeout", 4.0))
        concurrency = int(tier_profile.get("concurrency", 25))

        log.info(
            "Banner grab starting — tier=%s targets=%d ips=%d timeout=%.1fs concurrency=%d",
            tier_name or "?", len(targets), len(per_ip_ports), timeout, concurrency,
        )

        results = self._invoke_worker(
            targets=targets,
            timeout=timeout,
            concurrency=concurrency,
        )

        log.info(
            "Banner grab returned %d results (%d with service identified)",
            len(results),
            sum(1 for r in results if r.get("service")),
        )

        return self._build_phase_result(results)

    # ── internals ────────────────────────────────────────────────────────

    def _invoke_worker(
        self,
        *,
        targets: list[dict],
        timeout: float,
        concurrency: int,
    ) -> list[dict]:
        payload: dict[str, Any] = {
            "targets": targets,
            "timeout": timeout,
            "concurrency": concurrency,
        }
        # Worker timeout bound = per-target timeout × ceil(targets/concurrency)
        # with a generous floor for HTTP/connect overhead.
        outer_timeout = max(60.0, timeout * (len(targets) / max(concurrency, 1) + 2))

        try:
            resp = httpx.post(
                f"{_SCANNER_URL}/zgrab2/scan",
                json=payload,
                headers=_HEADERS,
                timeout=outer_timeout,
            )
            resp.raise_for_status()
            body = resp.json()
            results = body.get("results", []) or []
            if body.get("timed_out"):
                log.warning(
                    "Banner-grab (zgrab2) worker call timed out for %d target(s) — %d result(s) recovered "
                    "from partial output before the subprocess was killed", len(targets), len(results),
                )
            return results
        except httpx.HTTPError:
            log.exception("Banner-grab worker request failed (targets=%d)", len(targets))
            return []

    def _build_phase_result(self, rows: list[dict]) -> PhaseResult:
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat()
        per_ip: dict[str, list[dict]] = {}

        for row in rows:
            ip = row.get("ip")
            port = row.get("port")
            if not ip or not isinstance(port, int):
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue

            entry: dict[str, Any] = {
                "port": port,
                "protocol": "tcp",
                "sources": ["banner_grab"],
                "last_seen_at": now,
            }
            # Only include identification fields when the worker filled them
            # in — empty strings would override real data via the writer's
            # last-write-wins for non-empty values.
            service = row.get("service")
            if isinstance(service, str) and service:
                entry["service"] = service
            version = row.get("service_version")
            if isinstance(version, str) and version:
                entry["service_version"] = version
            banner = row.get("banner")
            if isinstance(banner, str) and banner:
                entry["banner_snippet"] = banner
            zgrab2_detail = row.get("zgrab2_detail")
            if isinstance(zgrab2_detail, dict) and zgrab2_detail:
                entry["zgrab2"] = zgrab2_detail

            # A real banner/service is positive application-layer confirmation —
            # the port actually spoke a protocol, not a firewall-proxied handshake.
            # (A phantom completes TCP then resets, yielding no banner here.)
            if entry.get("service") or entry.get("banner_snippet") or entry.get("zgrab2"):
                entry["l7_confirmed"] = True

            per_ip.setdefault(ip, []).append(entry)

        patches: list[DiscoveredAsset] = []
        for ip, entries in per_ip.items():
            patches.append(DiscoveredAsset(
                asset_type=AssetType.IP_ADDRESS,
                value=ip,
                parent_value=None,
                asset_metadata={
                    "sources": ["banner_grab"],
                    "open_ports": entries,
                },
            ))

        return PhaseResult(assets=patches)
