"""Risky internet-exposed service analyzer.

Turns dangerous services that are reachable on the public internet into
first-class findings (`category=exposure`) — no CVE required. The exposure
itself is the vulnerability: RDP, SMB, a bare database, etc. on a public IP.

Runs as a post-scan step (see scan_executor) over the assets a run touched,
reading the *merged* `open_ports[]` off each canonical ip_address asset. The
rules live in `app/data/risky_exposures.yaml`; severities are the product's
opinion. See that file's header for the data-sourcing rationale.

Matching model (the service is the risk; the port is a predictor):
  - service known  → match the detected service name (with aliases). Confirmed.
                     A known-but-non-risky service SUPPRESSES port inference —
                     http on 3389 is not RDP.
  - service unknown→ fall back to the well-known port (RDP/3389, MSSQL/1433…).
                     Inferred ("service unconfirmed"). Only near-dedicated ports
                     are listed for inference — never reused-for-web ports.

Source-agnostic: matches on normalized service labels + ports, never on the
connector that wrote them, so the banner-grab tool can be swapped out freely.

Emit vs. resolve use two different signals:
  - EMIT only for ports observed in *this* run (last_seen_at >= run.started_at).
    Assets with no freshly-observed ports are skipped entirely, so a recheck
    that didn't port-scan neither emits nor resolves anything.
  - RESOLVE only when a port has left the *retained* inventory. `open_ports[]`
    is already pruned by asset_writer before we run, so a genuinely-retired port
    is gone, while a port held by the confirmed-port flap-guard (planning#72) is
    still present (with a stale `last_seen_at`). Keying resolution off presence-
    in-inventory rather than per-run freshness means a risky service that briefly
    flaps is NOT resolved-then-reopened on every scan (planning#73): its finding
    resolves exactly when the port leaves the inventory (past the confirmed /
    Shodan grace).
"""

import ipaddress
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sqlalchemy.orm import Session

from app.connectors.base import DiscoveredFinding
from app.models.asset_canonical import AssetCanonical
from app.models.finding_canonical import FindingCanonical
from app.services.finding_writer import write_findings

log = logging.getLogger(__name__)

_RULESET_PATH = Path(__file__).resolve().parent.parent / "data" / "risky_exposures.yaml"

_SEV_RANK: dict[str, int] = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

FINDING_TYPE = "exposed_service"
SOURCE = "constellus"
CATEGORY = "exposure"


@dataclass(frozen=True)
class BannerOverride:
    """Severity adjustment keyed on a substring of banner_snippet (case-insensitive)."""
    pattern: re.Pattern  # type: ignore[type-arg]
    severity: str
    label: str


@dataclass(frozen=True)
class TagOverride:
    """Severity adjustment keyed on an asset tag. Takes priority over banner overrides."""
    tag: str
    severity: str
    label: str


@dataclass(frozen=True)
class ExposureRule:
    id: str
    name: str
    severity: str
    ports: frozenset[int]
    services: frozenset[str]   # normalized (lowercased) labels + aliases
    rationale: str
    remediation: str
    references: tuple[str, ...]
    exposure_class: str = "other"   # remote_access | data_store | infrastructure | orchestration | other
    banner_overrides: tuple[BannerOverride, ...] = field(default_factory=tuple)
    tag_overrides: tuple[TagOverride, ...] = field(default_factory=tuple)


# Classification axis over the ruleset: WHY a service is flagged. `infrastructure`
# is the "should be internal — exposure is usually accidental" bucket (DNS, LDAP,
# SMB, SNMP…). A rule's YAML `class:` wins; otherwise this map; otherwise "other".
_CLASS_BY_ID: dict[str, str] = {
    # remote access — interactive / admin shells & desktops
    "exposed-rdp": "remote_access", "exposed-ssh": "remote_access", "exposed-telnet": "remote_access",
    "exposed-vnc": "remote_access", "exposed-winrm": "remote_access", "exposed-rservices": "remote_access",
    "exposed-x11": "remote_access",
    # data store — databases & caches
    "exposed-mssql": "data_store", "exposed-mysql": "data_store", "exposed-postgres": "data_store",
    "exposed-mongodb": "data_store", "exposed-redis": "data_store", "exposed-elasticsearch": "data_store",
    "exposed-memcached": "data_store", "exposed-oracle-db": "data_store", "exposed-couchdb": "data_store",
    "exposed-cassandra": "data_store", "exposed-influxdb": "data_store", "exposed-neo4j": "data_store",
    # infrastructure — directory / auth / name / file / management services
    "exposed-dns": "infrastructure", "exposed-ldap": "infrastructure", "exposed-kerberos": "infrastructure",
    "exposed-smb": "infrastructure", "exposed-netbios": "infrastructure", "exposed-netbios-ns": "infrastructure",
    "exposed-msrpc": "infrastructure", "exposed-snmp": "infrastructure", "exposed-tftp": "infrastructure",
    "exposed-ftp": "infrastructure", "exposed-rsync": "infrastructure",
    # orchestration — container / cluster control planes & brokers
    "exposed-docker-api": "orchestration", "exposed-kubernetes-api": "orchestration", "exposed-kubelet": "orchestration",
    "exposed-etcd": "orchestration", "exposed-kafka": "orchestration", "exposed-rabbitmq": "orchestration",
    "exposed-zookeeper": "orchestration",
}


@dataclass
class _Ruleset:
    rules: tuple[ExposureRule, ...]
    port_to_rules: dict[int, list[ExposureRule]]
    service_to_rules: dict[str, list[ExposureRule]]


_cache: _Ruleset | None = None
_cache_mtime: float = 0.0


def _load_ruleset() -> _Ruleset:
    """Parse and index the YAML ruleset (mtime-cached). UDP-only rules are dropped —
    the current port scanner is TCP-only, so they would never fire.

    The cache is invalidated when the YAML file's mtime changes — uvicorn
    --reload only watches .py files, so YAML edits would otherwise silently
    use a stale cache until the next process restart."""
    global _cache, _cache_mtime
    try:
        current_mtime = _RULESET_PATH.stat().st_mtime
    except OSError:
        current_mtime = 0.0
    if _cache is not None and current_mtime == _cache_mtime:
        return _cache

    try:
        raw = yaml.safe_load(_RULESET_PATH.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        log.exception("Failed to load exposure ruleset at %s — exposure analysis disabled", _RULESET_PATH)
        _cache = _Ruleset(rules=(), port_to_rules={}, service_to_rules={})
        return _cache

    defaults = raw.get("defaults") or {}
    rules: list[ExposureRule] = []
    for entry in raw.get("rules") or []:
        if entry.get("udp_only"):
            continue
        severity = (entry.get("severity") or "").lower()
        if severity not in _SEV_RANK:
            log.warning("Exposure rule %s has invalid severity %r — skipping", entry.get("id"), severity)
            continue
        banner_overrides: list[BannerOverride] = []
        for bo in entry.get("banner_overrides") or []:
            bo_sev = (bo.get("severity") or "").lower()
            if bo_sev not in _SEV_RANK:
                log.warning("banner_override in rule %s has invalid severity %r — skipped", entry.get("id"), bo_sev)
                continue
            try:
                compiled = re.compile(str(bo["pattern"]), re.IGNORECASE)
            except re.error as exc:
                log.warning("banner_override pattern %r in rule %s is invalid: %s — skipped", bo.get("pattern"), entry.get("id"), exc)
                continue
            banner_overrides.append(BannerOverride(pattern=compiled, severity=bo_sev, label=str(bo.get("label", ""))))

        tag_overrides: list[TagOverride] = []
        for to in entry.get("tag_overrides") or []:
            to_sev = (to.get("severity") or "").lower()
            if to_sev not in _SEV_RANK:
                log.warning("tag_override in rule %s has invalid severity %r — skipped", entry.get("id"), to_sev)
                continue
            tag_overrides.append(TagOverride(tag=str(to["tag"]), severity=to_sev, label=str(to.get("label", ""))))

        rule_id = str(entry.get("id", ""))
        rules.append(ExposureRule(
            id=rule_id,
            name=str(entry.get("name", entry.get("id", "Exposed service"))),
            severity=severity,
            ports=frozenset(int(p) for p in (entry.get("ports") or []) if isinstance(p, int)),
            services=frozenset(s.lower() for s in (entry.get("services") or []) if isinstance(s, str)),
            rationale=str(entry.get("rationale") or "").strip(),
            remediation=str(entry.get("remediation") or defaults.get("remediation") or "").strip(),
            references=tuple(entry.get("references") or []),
            exposure_class=str(entry.get("class") or _CLASS_BY_ID.get(rule_id) or "other"),
            banner_overrides=tuple(banner_overrides),
            tag_overrides=tuple(tag_overrides),
        ))

    port_to_rules: dict[int, list[ExposureRule]] = {}
    service_to_rules: dict[str, list[ExposureRule]] = {}
    for rule in rules:
        for p in rule.ports:
            port_to_rules.setdefault(p, []).append(rule)
        for s in rule.services:
            service_to_rules.setdefault(s, []).append(rule)

    log.info("Loaded %d risky-exposure rules from %s", len(rules), _RULESET_PATH.name)
    _cache = _Ruleset(rules=tuple(rules), port_to_rules=port_to_rules, service_to_rules=service_to_rules)
    _cache_mtime = current_mtime
    return _cache


def _is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        addr.is_private or addr.is_loopback or addr.is_multicast
        or addr.is_link_local or addr.is_reserved or addr.is_unspecified
    )


def _aware_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _parse_ts(value) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return _aware_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None


def _classify_ports(open_ports: list, since: datetime) -> tuple[list[dict], set[int]]:
    """Split an (already-pruned) `open_ports[]` into (fresh, retained).

    - fresh: entries observed in THIS run (last_seen_at >= since) → drive
      emission. Only fresh ports re-confirm/emit a finding.
    - retained: every non-phantom port still present in the inventory,
      regardless of freshness → drives resolution. A port held by the
      confirmed-port flap-guard (planning#72) is stale-but-present here, so its
      exposure finding is not resolved on a brief miss (planning#73); a
      genuinely-retired port was already dropped by the prune, so it's absent
      here and its finding resolves.

    Phantom ports (`l7_confirmed is False`) are firewall artifacts — excluded
    from BOTH (they never trip an exposure and must not keep one alive). `is not
    False` blocks only explicit False; True and missing pass (back-compat).
    """
    fresh: list[dict] = []
    retained: set[int] = set()
    for entry in open_ports:
        if not isinstance(entry, dict) or not isinstance(entry.get("port"), int):
            continue
        if entry.get("l7_confirmed") is False:
            continue
        retained.add(entry["port"])
        seen = _parse_ts(entry.get("last_seen_at"))
        if seen is not None and seen >= since:
            fresh.append(entry)
    return fresh, retained


def _match_entry(ruleset: _Ruleset, port: int, service: str | None) -> tuple[ExposureRule, str] | None:
    """Return (rule, confidence) for the worst-severity match, or None.

    Service known → only confirmed service matches (a known non-risky service
    suppresses port inference). Service unknown → fall back to port inference.
    """
    candidates: list[tuple[ExposureRule, str]] = []
    if service:
        for rule in ruleset.service_to_rules.get(service, []):
            candidates.append((rule, "confirmed"))
    else:
        for rule in ruleset.port_to_rules.get(port, []):
            candidates.append((rule, "inferred"))

    if not candidates:
        return None
    return max(candidates, key=lambda rc: _SEV_RANK.get(rc[0].severity, 0))


def _resolve_severity(
    rule: ExposureRule,
    banner_snippet: str | None,
    asset_tags: list[str],
) -> tuple[str, str | None, str | None, str | None]:
    """Return (final_severity, override_label, override_kind, override_tag).

    Priority: tag_overrides (user intent) > banner_overrides (detected product)
    > rule.severity (default stance). When the default is adjusted, the label +
    kind ("tag"/"banner") + matched tag are returned so callers can surface the
    reason as a pill in the UI (not jammed into the title).
    """
    for to in rule.tag_overrides:
        if to.tag in asset_tags:
            return to.severity, to.label, "tag", to.tag

    if banner_snippet:
        for bo in rule.banner_overrides:
            if bo.pattern.search(banner_snippet):
                return bo.severity, bo.label, "banner", None

    return rule.severity, None, None, None


def _build_finding(asset_value: str, port: int, protocol: str, service: str | None,
                   service_version: str | None, rule: ExposureRule, confidence: str,
                   severity: str, override_label: str | None,
                   override_kind: str | None = None, override_tag: str | None = None) -> DiscoveredFinding:
    # Title stays clean: just the service + port. The override reason (tag/banner)
    # is carried in detail and surfaced as a pill in the UI, not appended here.
    if confidence == "confirmed":
        title = f"{rule.name} (port {port})"
    else:
        title = f"{rule.name} (port {port}, service unconfirmed)"

    return DiscoveredFinding(
        asset_value=asset_value,
        finding_type=FINDING_TYPE,
        source=SOURCE,
        severity=severity,
        title=title,
        description=rule.rationale,
        category=CATEGORY,
        detail={
            "fingerprint": f"exposed-service:{port}",  # port-stable; asset is in the uniqueness key
            "rule_id": rule.id,
            "exposure_class": rule.exposure_class,
            "port": port,
            "protocol": protocol,
            "service": service,
            "service_version": service_version,
            "confidence": confidence,
            "severity_override": override_label,  # reason text; None when default rule severity applies
            "override_kind": override_kind,       # "tag" | "banner" | None — drives the UI pill
            "override_tag": override_tag,          # matched asset tag (tag overrides only)
            "remediation": rule.remediation,
            "references": list(rule.references),
        },
    )


def analyze_exposures(
    db: Session,
    scan_run_id: uuid.UUID,
    asset_ids: set[uuid.UUID],
    since: datetime | None,
    new_canonical_ids_out: list[uuid.UUID] | None = None,
) -> set[uuid.UUID]:
    """Emit/refresh exposure findings for risky open services on the given
    assets, and resolve findings whose port has left the (pruned) inventory.

    `since` is the run's started_at and gates EMISSION: only ports with a
    `last_seen_at` at or after it count as observed this run. Resolution keys off
    the retained inventory instead, so a briefly-flapping service isn't churned
    resolved↔open (see module docstring / planning#73). Returns the set of
    canonical finding ids touched (emitted + resolved) so the executor can count.
    """
    ruleset = _load_ruleset()
    if not ruleset.rules or not asset_ids:
        return set()

    since = _aware_utc(since)
    if since is None:
        log.warning("Exposure analysis skipped for run %s — no run start time to gate port freshness", scan_run_id)
        return set()

    assets = (
        db.query(AssetCanonical)
        .filter(AssetCanonical.id.in_(asset_ids), AssetCanonical.asset_type == "ip_address")
        .all()
    )

    # Effective tags for the override include the parent dns_record's tags. In the
    # UI an ip_address row is hidden behind its tracked dns_record (the domain is
    # the visible, taggable row representing the whole chain), so a stance tag like
    # `ssh:sftp-only` is applied to the name, not the bare IP — it must still count.
    parent_values = {a.parent_value for a in assets if a.parent_value}
    parent_tags: dict[str, set[str]] = {}
    if parent_values:
        for value, tags in (
            db.query(AssetCanonical.value, AssetCanonical.tags)
            .filter(AssetCanonical.value.in_(parent_values))
            .all()
        ):
            if tags:
                parent_tags.setdefault(value, set()).update(tags)

    findings: list[DiscoveredFinding] = []
    # {asset_id: set(ports still present in the pruned inventory)} — only for
    # assets we had fresh port data for, so resolution is correctly scoped. A
    # finding resolves only when its port leaves THIS set (planning#73), not on
    # a single missed scan.
    retained_by_asset: dict[uuid.UUID, set[int]] = {}

    for asset in assets:
        if not _is_public_ip(asset.value):
            continue
        open_ports = (asset.asset_metadata or {}).get("open_ports")
        if not isinstance(open_ports, list):
            continue

        fresh, retained = _classify_ports(open_ports, since)
        if not fresh:
            # No port data refreshed this run (e.g. recheck without naabu) —
            # leave existing findings untouched rather than false-resolving.
            continue

        asset_tags_set: set[str] = set(asset.tags or [])
        if asset.parent_value and asset.parent_value in parent_tags:
            asset_tags_set |= parent_tags[asset.parent_value]
        asset_tags: list[str] = list(asset_tags_set)
        for entry in fresh:
            port = entry["port"]
            service = (entry.get("service") or "").strip().lower() or None
            match = _match_entry(ruleset, port, service)
            if match is None:
                continue
            rule, confidence = match
            banner_snippet = entry.get("banner_snippet") or None
            severity, override_label, override_kind, override_tag = _resolve_severity(rule, banner_snippet, asset_tags)
            findings.append(_build_finding(
                asset_value=asset.value,
                port=port,
                protocol=entry.get("protocol") or "tcp",
                service=entry.get("service"),
                service_version=entry.get("service_version"),
                rule=rule,
                confidence=confidence,
                severity=severity,
                override_label=override_label,
                override_kind=override_kind,
                override_tag=override_tag,
            ))
        retained_by_asset[asset.id] = retained

    touched: set[uuid.UUID] = set()
    if findings:
        touched = write_findings(db, scan_run_id, findings, new_canonical_ids_out=new_canonical_ids_out)

    resolved = _resolve_closed_exposures(db, retained_by_asset)
    touched.update(resolved)

    if findings or resolved:
        log.info(
            "Exposure analysis run %s: %d finding(s) emitted/refreshed, %d resolved",
            scan_run_id, len(findings), len(resolved),
        )
    return touched


def _resolve_closed_exposures(
    db: Session,
    retained_by_asset: dict[uuid.UUID, set[int]],
) -> set[uuid.UUID]:
    """Resolve open/acknowledged exposure findings whose port has left the inventory.

    Scoped to assets we had fresh port data for this run. A finding resolves only
    when its port is absent from the asset's *retained* (post-prune) inventory —
    not merely missed this scan — so a flapping risky service isn't churned
    resolved↔open (planning#73). Suppressed findings are left alone — the user
    explicitly silenced those.
    """
    if not retained_by_asset:
        return set()

    rows = (
        db.query(FindingCanonical)
        .filter(
            FindingCanonical.asset_canonical_id.in_(list(retained_by_asset.keys())),
            FindingCanonical.source == SOURCE,
            FindingCanonical.finding_type == FINDING_TYPE,
            FindingCanonical.state.in_(["open", "acknowledged"]),
        )
        .all()
    )

    now = datetime.now(timezone.utc)
    resolved: set[uuid.UUID] = set()
    for row in rows:
        port = (row.detail or {}).get("port")
        if not isinstance(port, int):
            continue
        if port not in retained_by_asset.get(row.asset_canonical_id, set()):
            row.state = "resolved"
            row.resolved_at = now
            resolved.add(row.id)

    if resolved:
        db.commit()
    return resolved
