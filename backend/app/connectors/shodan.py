"""Shodan enrichment connector.

For each public IP in the scan asset set, queries Shodan's host endpoint to add:
  - Open ports, detected services, OS, ISP/ASN, geolocation
  - Shodan-derived tags (cdn, cloud, malware, compromised, …)
  - Known CVEs from Shodan's `vulns` field → DiscoveredFindings (opt-in via
    `import_vulns`, OFF by default — noisy CPE-match firehose; see enrich())
  - Critical tags (malware / compromised / honeypot) → emitted as findings

Rate limiting: Shodan free tier allows 1 request per second; the connector
sleeps between host lookups. Private/non-routable IPs are skipped without a
network call. The standard connector_get retry/backoff wrapper handles
429 / 5xx responses.

By default the connector is enrichment-only — `index_lookup` is gated behind
the `import_assets` config flag. Shodan's public DNS index aggregates records
seen across the entire internet, which means an apex domain can pick up
historical / unrelated entries that an operator never controlled. Asset
import is opt-in for users who actively curate Shodan Monitoring.
"""

import ipaddress
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from app.connectors.base import (
    DNS_KEEP_TYPES,
    DiscoveredAsset,
    DiscoveredFinding,
    EnrichmentConnector,
    PhaseResult,
    TestResult,
    is_dns_policy_name,
    is_provider_managed_mx,
)
from app.connectors.http import connector_get
from app.core.secrets import get_secret
from app.models.asset import AssetType

log = logging.getLogger(__name__)

_BASE = "https://api.shodan.io"
_CRITICAL_TAGS: frozenset[str] = frozenset({"malware", "compromised", "honeypot"})

# Hostname regex used to validate Shodan-emitted DNS records before we trust
# them. Mirrors the validator in target_service.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def _truthy(value: Any) -> bool:
    """Coerce a connector-config value (which may be a real bool, the string
    'true', or even 1) to a Python bool. Config storage is JSON so any of
    these can show up depending on the frontend version."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "on"}
    return False


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _valid_hostname(value: str) -> bool:
    return bool(_HOSTNAME_RE.match(value))

# Per-plan inter-request delay. /api-info reports the plan; we map it to a safe
# delay. Free tier is hard-capped at 1 req/sec; paid plans allow much higher but
# we stay conservative (10 req/sec for any paid tier).
_FREE_DELAY = 1.0
_PAID_DELAY = 0.1
_FREE_PLANS: frozenset[str] = frozenset({"oss", "free", "dev"})


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private or addr.is_loopback or addr.is_multicast
        or addr.is_link_local or addr.is_reserved or addr.is_unspecified
    )


def _severity_from_cvss(cvss: float | None) -> str:
    if cvss is None:
        return "medium"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _iso_utc(ts) -> str | None:
    """Parse a Shodan timestamp string to a tz-aware ISO-8601 UTC string.

    Shodan emits naive strings like "2026-06-01T12:34:56.789012" (no tz).
    Treat any naive datetime as UTC. Returns None if input is falsy or
    unparseable.
    """
    if not ts:
        return None
    if isinstance(ts, datetime):
        dt = ts
    else:
        try:
            dt = datetime.fromisoformat(str(ts))
        except (ValueError, TypeError):
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _cert_dt(value) -> str | None:
    """Parse a Shodan cert validity timestamp to ISO-8601 UTC.

    Shodan emits ASN.1 GeneralizedTime like "20260829214126Z" for
    cert.expires / cert.issued. Falls back to ISO parsing (some responses use
    that). Returns None on anything unparseable."""
    if not value:
        return None
    s = str(value).strip()
    try:
        dt = datetime.strptime(s, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except ValueError:
        return _iso_utc(s)


def _cert_sans(cert: dict) -> list[str]:
    """Best-effort SAN list from a Shodan cert. Shodan stuffs SANs into the
    subjectAltName extension as a single comma-joined "DNS:a, DNS:b" string;
    parse the DNS entries out. Returns [] when none are present (caller falls
    back to the subject CN)."""
    for ext in cert.get("extensions") or []:
        if not isinstance(ext, dict) or ext.get("name") != "subjectAltName":
            continue
        data = ext.get("data")
        if not isinstance(data, str):
            continue
        sans = [
            part.split("DNS:", 1)[1].strip()
            for part in data.split(",")
            if "DNS:" in part
        ]
        return [s for s in sans if s]
    return []


def _parse_ssl_cert(ssl: dict) -> dict | None:
    """Build a per-port cert_summary from a Shodan service's `ssl` block —
    the same shape tlsx writes (so the unified TLS panel reads both, #56).
    Returns None when there's no usable cert. None/empty fields are omitted."""
    if not isinstance(ssl, dict):
        return None
    cert = ssl.get("cert")
    cert = cert if isinstance(cert, dict) else {}
    cipher = ssl.get("cipher")
    cipher = cipher if isinstance(cipher, dict) else {}
    fingerprint = ssl.get("cert", {}).get("fingerprint") if isinstance(ssl.get("cert"), dict) else None
    fingerprint = fingerprint if isinstance(fingerprint, dict) else {}

    subject_cn = (cert.get("subject") or {}).get("CN") if isinstance(cert.get("subject"), dict) else None
    issuer = cert.get("issuer") if isinstance(cert.get("issuer"), dict) else {}

    summary: dict[str, Any] = {}
    if subject_cn:
        summary["subject_cn"] = subject_cn
    sans = _cert_sans(cert) or ([subject_cn] if subject_cn else [])
    if sans:
        summary["sans"] = sans
    if issuer.get("CN"):
        summary["issuer_cn"] = issuer["CN"]
    if issuer.get("O"):
        summary["issuer_org"] = issuer["O"]
    not_before = _cert_dt(cert.get("issued"))
    if not_before:
        summary["not_before"] = not_before
    not_after = _cert_dt(cert.get("expires"))
    if not_after:
        summary["not_after"] = not_after
    if cipher.get("name"):
        summary["cipher"] = cipher["name"]
    if cipher.get("version"):
        summary["tls_version"] = cipher["version"]
    if fingerprint.get("sha256"):
        summary["fingerprint"] = fingerprint["sha256"]
    if cert.get("serial") not in (None, ""):
        summary["serial"] = str(cert["serial"])
    if ssl.get("ja3s"):
        summary["ja3s"] = ssl["ja3s"]
    alpn = ssl.get("alpn")
    if isinstance(alpn, list) and alpn:
        summary["alpn"] = alpn

    return summary or None


def _parse_host_ports(host: dict) -> list[dict]:
    """Build a list of open_ports[] entries from a Shodan host response.

    Iterates host['data'] (per-service dicts) and collapses duplicate ports
    (first occurrence wins). Each entry carries the canonical open_ports[]
    keys used by other connectors (port, protocol, sources, last_seen_at,
    service, service_version, banner_snippet, cert_summary, jarm) plus
    Shodan-specific additive keys (cpe, shodan_module). None/""/[] values are
    omitted to keep entries lean. Returns entries sorted ascending by port.
    """
    seen: dict[int, dict] = {}
    for svc in host.get("data") or []:
        port = svc.get("port")
        if not isinstance(port, int) or not (1 <= port <= 65535):
            continue
        if port in seen:
            continue

        protocol = (svc.get("transport") or "tcp").lower()

        # last_seen_at: prefer per-service timestamp, fall back to host-level
        raw_ts = svc.get("timestamp") or host.get("last_update")
        last_seen_at = _iso_utc(raw_ts)

        shodan_meta = svc.get("_shodan") or {}
        module = shodan_meta.get("module") or None

        product = svc.get("product") or None
        version = svc.get("version") or None
        service = product or module or None

        sv_parts = [x for x in (product, version) if x]
        service_version = " ".join(sv_parts).strip() or None

        raw_banner = svc.get("data")
        if raw_banner and isinstance(raw_banner, str):
            banner_snippet = raw_banner.strip()[:256] or None
        else:
            banner_snippet = None

        cpe_raw = svc.get("cpe23") or svc.get("cpe")
        cpe = cpe_raw if isinstance(cpe_raw, list) and cpe_raw else None

        entry: dict = {
            "port": port,
            "protocol": protocol,
            "sources": ["shodan"],
        }
        if last_seen_at is not None:
            entry["last_seen_at"] = last_seen_at
        if service is not None:
            entry["service"] = service
        if service_version is not None:
            entry["service_version"] = service_version
        if banner_snippet is not None:
            entry["banner_snippet"] = banner_snippet
        if cpe is not None:
            entry["cpe"] = cpe
        if module is not None:
            entry["shodan_module"] = module

        # Per-port TLS: fold Shodan's `ssl` block into the same cert_summary
        # shape tlsx writes, so the unified TLS panel reads both sources (#56).
        cert_summary = _parse_ssl_cert(svc.get("ssl"))
        if cert_summary:
            entry["cert_summary"] = cert_summary
        jarm = (svc.get("ssl") or {}).get("jarm") if isinstance(svc.get("ssl"), dict) else None
        if isinstance(jarm, str) and jarm:
            entry["jarm"] = jarm

        seen[port] = entry

    return sorted(seen.values(), key=lambda e: e["port"])


class ShodanConnector(EnrichmentConnector):
    name = "Shodan"
    description = "Internet exposure context — open ports, services, banners, and known CVEs for public IPs"
    env_key_map = {"api_key": "SHODAN_API_KEY"}

    def get_config_schema(self) -> dict:
        return {
            "api_key": {
                "label": "API Key",
                "type": "secret",
                "help": (
                    "Shodan API key from account.shodan.io. Required for all tiers — Shodan has no "
                    "anonymous access. Plan is auto-detected; paid tiers get faster lookups and "
                    "include CVE findings (`vulns`), which the free tier does not return."
                ),
            },
            "import_assets": {
                "label": "Import assets from Shodan index",
                "type": "boolean",
                "default": False,
                "help": (
                    "Off by default. When on, Shodan's public /dns/domain index is queried as a "
                    "passive subdomain source. Most operators want enrichment only — Shodan's "
                    "public index contains records observed across the entire internet and may "
                    "import unrelated infrastructure. Enable only if you actively curate Shodan "
                    "Monitoring (paid feature) and want those assets reflected here."
                ),
            },
            "import_vulns": {
                "label": "Import Shodan CPE-match CVEs",
                "type": "boolean",
                "default": False,
                "help": (
                    "Off by default. Shodan's `vulns` field is an exhaustive CPE→CVE match against "
                    "detected product versions — no exploitability check and no awareness of distro "
                    "backports, so it returns a high-noise firehose (hundreds of mostly-inapplicable "
                    "historical CVEs per EOL host). Constellus does its own controlled version "
                    "matching; enable this only if you specifically want Shodan's raw CPE matches as "
                    "findings. The host's malware/compromised/honeypot tag findings are unaffected."
                ),
            },
        }

    def is_configured(self) -> bool:
        return bool(get_secret("SHODAN_API_KEY"))

    def _test(self, config: dict) -> TestResult:
        api_key = get_secret("SHODAN_API_KEY")
        if not api_key:
            return TestResult(success=False, message="API key not configured")
        try:
            response = httpx.get(
                f"{_BASE}/api-info",
                params={"key": api_key},
                timeout=10,
            )
            if response.status_code == 401:
                return TestResult(success=False, message="Invalid API key")
            if response.status_code != 200:
                return TestResult(
                    success=False,
                    message=f"Shodan returned HTTP {response.status_code}",
                    details={"status": response.status_code},
                )
            data = response.json()
            plan = data.get("plan", "unknown")
            credits = data.get("query_credits", "?")
            scan_credits = data.get("scan_credits", "?")
            return TestResult(
                success=True,
                message=f"Connected — plan: {plan}, query credits: {credits}, scan credits: {scan_credits}",
                details=data,
            )
        except Exception as exc:
            return TestResult(success=False, message=str(exc))

    def index_lookup(self, domain: str, config: dict[str, Any]) -> PhaseResult:
        """Look up Shodan's index for the given apex domain (passive subdomain discovery).

        Calls `GET /dns/domain/{domain}` — returns subdomains Shodan has historically
        observed, with record types and values. Costs 1 query credit per call.
        Unlike DNSDiscoveryConnector.discover(), this does NOT require zone ownership —
        it queries Shodan's public index. Records may be stale; the DNS resolver step
        in passive discovery establishes current state.

        Gated by the `import_assets` config flag (default off) — without it set, this
        method emits nothing, leaving Shodan as enrichment-only.
        """
        if not _truthy(config.get("import_assets")):
            return PhaseResult()
        api_key = get_secret("SHODAN_API_KEY")
        if not api_key:
            return PhaseResult()

        try:
            resp = connector_get(
                f"{_BASE}/dns/domain/{domain}",
                params={"key": api_key},
                timeout=15,
            )
        except Exception as exc:
            log.warning("Shodan /dns/domain failed for %s: %s", domain, exc)
            return PhaseResult()

        if resp.status_code == 404:
            log.info("Shodan: no index data for %s", domain)
            return PhaseResult()
        if resp.status_code == 401:
            log.error("Shodan: API key rejected on /dns/domain")
            return PhaseResult()
        if resp.status_code != 200:
            log.warning("Shodan /dns/domain returned HTTP %d for %s", resp.status_code, domain)
            return PhaseResult()

        try:
            payload = resp.json()
        except Exception:
            return PhaseResult()

        records: list[dict] = payload.get("data") or []
        assets: list[DiscoveredAsset] = []
        seen_ips: set[str] = set()
        skipped_invalid = 0

        for r in records:
            rtype = (r.get("type") or "").upper()
            if rtype not in DNS_KEEP_TYPES:
                continue

            subdomain = (r.get("subdomain") or "").strip().rstrip(".")
            fqdn = f"{subdomain}.{domain}" if subdomain else domain
            if is_dns_policy_name(fqdn):
                continue
            content = (r.get("value") or "").strip()
            if not content:
                continue

            # Validate before trusting Shodan's response: A/AAAA content must
            # be a real IP; CNAME/MX content must be a valid hostname. Without
            # this the public index occasionally feeds us partial IPs or
            # otherwise malformed values.
            if rtype in ("A", "AAAA"):
                if not _valid_ip(content):
                    skipped_invalid += 1
                    continue
            elif rtype in ("CNAME", "MX"):
                if not _valid_hostname(content):
                    skipped_invalid += 1
                    continue

            if not _valid_hostname(fqdn):
                skipped_invalid += 1
                continue

            metadata: dict[str, Any] = {
                "sources": ["shodan"],
                "record_type": rtype,
                "content": content,
                "shodan_last_seen": r.get("last_seen"),
            }
            if rtype == "MX" and is_provider_managed_mx(content):
                metadata["provider_mx"] = True

            assets.append(DiscoveredAsset(
                asset_type=AssetType.DNS_RECORD,
                value=fqdn,
                parent_value=domain if fqdn != domain else None,
                asset_metadata=metadata,
            ))

            if rtype in ("A", "AAAA") and content not in seen_ips:
                seen_ips.add(content)
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.IP_ADDRESS,
                    value=content,
                    parent_value=fqdn,
                    asset_metadata={"sources": ["shodan"]},
                ))

        if skipped_invalid:
            log.warning(
                "Shodan /dns/domain: skipped %d malformed record(s) for %s",
                skipped_invalid, domain,
            )

        log.info(
            "Shodan /dns/domain: %d record(s) for %s, %d unique IP(s)",
            len(assets) - len(seen_ips), domain, len(seen_ips),
        )
        return PhaseResult(assets=assets)

    def enrich(self, assets: list[DiscoveredAsset], config: dict[str, Any]) -> PhaseResult:
        api_key = get_secret("SHODAN_API_KEY")
        if not api_key:
            return PhaseResult()

        # Unique public IPs from the asset batch
        ips: list[str] = []
        seen: set[str] = set()
        for a in assets:
            if a.asset_type != "ip_address":
                continue
            if a.value in seen or not _is_public_ip(a.value):
                continue
            seen.add(a.value)
            ips.append(a.value)

        if not ips:
            log.info(
                "Shodan: no public IPs in asset set (%d total assets, %d are ip_address) — nothing to enrich",
                len(assets),
                sum(1 for a in assets if a.asset_type == "ip_address"),
            )
            return PhaseResult()

        # Detect plan to pick a safe rate limit. /api-info doesn't consume query credits.
        plan, rate_delay = _detect_plan_and_delay(api_key)
        log.info(
            "Shodan: enriching %d public IP(s) — plan=%s, delay=%.2fs between lookups",
            len(ips), plan, rate_delay,
        )

        new_assets: list[DiscoveredAsset] = []
        new_findings: list[DiscoveredFinding] = []

        for i, ip in enumerate(ips):
            try:
                resp = connector_get(
                    f"{_BASE}/shodan/host/{ip}",
                    params={"key": api_key, "minify": "false"},
                    timeout=15,
                )
            except Exception as exc:
                log.warning("Shodan host lookup failed for %s: %s", ip, exc)
                _sleep_between(i, len(ips), rate_delay)
                continue

            if resp.status_code == 404:
                # IP not in Shodan's database — nothing to enrich
                _sleep_between(i, len(ips), rate_delay)
                continue
            if resp.status_code == 401:
                log.error("Shodan: API key rejected; aborting remaining lookups")
                break
            if resp.status_code != 200:
                log.warning("Shodan host %s returned HTTP %d", ip, resp.status_code)
                _sleep_between(i, len(ips), rate_delay)
                continue

            try:
                host = resp.json()
            except Exception:
                _sleep_between(i, len(ips), rate_delay)
                continue

            metadata: dict[str, Any] = {
                "sources": ["shodan"],
                "shodan_org": host.get("org"),
                "shodan_os": host.get("os"),
                "shodan_country": host.get("country_code"),
                "shodan_isp": host.get("isp"),
                "shodan_asn": host.get("asn"),
                "shodan_ports": host.get("ports", []),
                "shodan_tags": host.get("tags", []),
                "shodan_hostnames": host.get("hostnames", []),
                "shodan_last_update": host.get("last_update"),
            }
            metadata["open_ports"] = _parse_host_ports(host)
            # Drop empty / null fields but keep sources
            metadata = {k: v for k, v in metadata.items() if v not in (None, "", [], {})}
            metadata["sources"] = ["shodan"]

            new_assets.append(DiscoveredAsset(
                asset_type=AssetType.IP_ADDRESS,
                value=ip,
                parent_value=None,
                asset_metadata=metadata,
            ))

            # CVE findings from Shodan's `vulns` — OFF by default (opt-in via the
            # `import_vulns` config flag). Shodan's `vulns` is an exhaustive
            # CPE->CVE match against the detected product versions, with no
            # exploitability check and no awareness of distro backports — so on an
            # EOL host it returns a firehose of hundreds of mostly-inapplicable
            # historical CVEs (and more than Shodan's own web UI surfaces).
            # Constellus does its own controlled version matching; only enable this
            # if you specifically want Shodan's raw CPE matches as findings.
            if _truthy(config.get("import_vulns")):
                vulns = host.get("vulns")
                vuln_items: list[tuple[str, dict]] = []
                if isinstance(vulns, dict):
                    vuln_items = [(k, v if isinstance(v, dict) else {}) for k, v in vulns.items()]
                elif isinstance(vulns, list):
                    vuln_items = [(v, {}) for v in vulns if isinstance(v, str)]

                for cve_id, details in vuln_items:
                    cvss = details.get("cvss")
                    try:
                        cvss = float(cvss) if cvss is not None else None
                    except (TypeError, ValueError):
                        cvss = None
                    new_findings.append(DiscoveredFinding(
                        asset_value=ip,
                        finding_type="cve",
                        source="shodan",
                        severity=_severity_from_cvss(cvss),
                        # Bare CVE id — source is tracked separately (and shown in
                        # the flyout), and vulncheck_enrichment upgrades this to the
                        # curated vulnerability name when one exists.
                        title=cve_id,
                        description=details.get("summary"),
                        detail={
                            "shodan_cvss": cvss,
                            "shodan_verified": details.get("verified"),
                        },
                        cve_id=cve_id,
                        cvss_score=cvss,
                    ))

            # Tag findings — flag malware / compromised / honeypot classifications
            for tag in host.get("tags", []) or []:
                if tag in _CRITICAL_TAGS:
                    new_findings.append(DiscoveredFinding(
                        asset_value=ip,
                        finding_type="malware" if tag in ("malware", "compromised") else "honeypot",
                        source="shodan",
                        severity="critical",
                        title=f"Shodan classification: {tag}",
                        description=(
                            f"Shodan tagged this IP as '{tag}'. This may indicate the host is "
                            f"compromised, hosting malware, or acting as a honeypot."
                        ),
                        detail={"shodan_tag": tag, "shodan_tags": list(host.get("tags", []))},
                    ))

            _sleep_between(i, len(ips), rate_delay)

        log.info(
            "Shodan: emitted %d enriched asset(s), %d finding(s)",
            len(new_assets), len(new_findings),
        )
        return PhaseResult(assets=new_assets, findings=new_findings)


def _sleep_between(idx: int, total: int, delay: float) -> None:
    if idx < total - 1 and delay > 0:
        time.sleep(delay)


def _detect_plan_and_delay(api_key: str) -> tuple[str, float]:
    """Query /api-info to determine plan tier; pick a safe inter-request delay.
    Falls back to free-tier rate if the call fails."""
    try:
        resp = connector_get(
            f"{_BASE}/api-info",
            params={"key": api_key},
            timeout=10,
            max_retries=1,
        )
        if resp.status_code != 200:
            return "unknown", _FREE_DELAY
        plan_name = str(resp.json().get("plan", "")).strip().lower()
    except Exception as exc:
        log.warning("Shodan: /api-info failed (%s) — assuming free-tier rate limit", exc)
        return "unknown", _FREE_DELAY
    if not plan_name or plan_name in _FREE_PLANS:
        return plan_name or "free", _FREE_DELAY
    return plan_name, _PAID_DELAY
