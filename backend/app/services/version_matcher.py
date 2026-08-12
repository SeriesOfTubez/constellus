"""Native version→CVE matching (#66 chunk B).

For each touched IP asset, takes the structured software intel chunk A wrote onto
`open_ports[].software[]` ({vendor, product, installed version, cpe, basis}),
looks the product up in the local CPE→CVE range index (chunk B0), and keeps the
CVEs whose affected version range — or exact version — includes the installed
version. Each match becomes a `source="version_match"` CVE finding that then
flows through the existing EPSS/KEV/CVSS/SSVC enrichment + risk scoring unchanged
(D2: confidence is a display facet, it does NOT modulate the score).

Version comparison uses `univers` per-ecosystem schemes (D5) — critically NOT a
naive/lexicographic compare (which gets 2.4.6 vs 2.4.26 backwards). OpenSSL and
nginx have dedicated schemes; everything else uses RpmVersion, which compares
numeric segments numerically and handles alpha suffixes (openssl `k`, openssh
`p1`) and 2-part NVD bounds. Unparseable versions fail closed (no match).

Version-unspecified index rows (`all_versions` — NVD `-`/bare-`*` data gaps) are
excluded: matching them would false-positive a 1999 CVE onto a current install.

Confidence is `potential` (D4) — kept in `detail` here; the dedicated column +
derivation land in chunk C. Findings carry the structured remediation data #34
consumes: installed_version, affected_range, fixed_version.

Runs post-scan after enrich_cpe/eol_enrichment, before cve_enrichment. Mirrors
exposure_analyzer: freshness-gated on ports seen this run; resolves matches that
no longer apply (e.g. the host upgraded).
"""

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session
from univers.versions import NginxVersion, OpensslVersion, RpmVersion

from app.connectors.base import DiscoveredFinding
from app.models.asset_canonical import AssetCanonical
from app.models.cpe_cve_range import CpeCveRange
from app.models.finding_canonical import FindingCanonical
from app.services.cpe_cve_index import ranges_for_product
from app.services.cpe_normalizer import to_canonical_product
from app.services.finding_writer import write_findings

log = logging.getLogger(__name__)

FINDING_TYPE = "cve"
SOURCE = "version_match"
CONFIDENCE = "potential"

# univers version scheme per canonical product. RpmVersion is the numeric-aware
# default (verified vs apache/php/mysql/openssh/haproxy/dovecot incl. p-suffixes
# and 2-part bounds); openssl/nginx have dedicated, verified schemes.
_VERSION_CLASS: dict[tuple[str, str], type] = {
    ("openssl", "openssl"): OpensslVersion,
    ("f5", "nginx"): NginxVersion,
}


def _vclass(vendor: str, product: str) -> type:
    return _VERSION_CLASS.get((vendor, product), RpmVersion)


def _matches(installed: str, row: CpeCveRange, vcls: type) -> bool:
    """Is the installed version covered by this index row? Fail-closed on any
    unparseable version (never match what we can't compare)."""
    try:
        iv = vcls(installed)
        if row.exact_version is not None:
            return vcls(row.exact_version) == iv
        bounds = (row.version_start_including, row.version_start_excluding,
                  row.version_end_including, row.version_end_excluding)
        if not any(bounds):
            return False  # defensive — a range row with no bounds matches nothing
        if row.version_start_including is not None and iv < vcls(row.version_start_including):
            return False
        if row.version_start_excluding is not None and iv <= vcls(row.version_start_excluding):
            return False
        if row.version_end_including is not None and iv > vcls(row.version_end_including):
            return False
        if row.version_end_excluding is not None and iv >= vcls(row.version_end_excluding):
            return False
        return True
    except Exception:
        return False


def _affected_range(row: CpeCveRange) -> str:
    if row.exact_version:
        return f"={row.exact_version}"
    parts = []
    if row.version_start_including:
        parts.append(f">={row.version_start_including}")
    if row.version_start_excluding:
        parts.append(f">{row.version_start_excluding}")
    if row.version_end_including:
        parts.append(f"<={row.version_end_including}")
    if row.version_end_excluding:
        parts.append(f"<{row.version_end_excluding}")
    return ", ".join(parts)


def _build_finding(asset_value: str, cve_id: str, sw: dict, row: CpeCveRange,
                   port: int | None) -> DiscoveredFinding:
    vendor, product, installed = sw["vendor"], sw["product"], sw["version"]
    affected = _affected_range(row)
    # version_end_excluding is the clean "fixed in" version (#34's input); a
    # last-vulnerable (end_including) or exact match has no clean fixed version.
    fixed = row.version_end_excluding
    desc = f"{product} {installed} is within the affected range ({affected}) of {cve_id}."
    if fixed:
        desc += f" Fixed in {fixed}."
    return DiscoveredFinding(
        asset_value=asset_value,
        finding_type=FINDING_TYPE,
        source=SOURCE,
        severity="info",  # placeholder — risk pipeline sets the authoritative band
        title=f"{cve_id} in {product} {installed}",
        description=desc,
        cve_id=cve_id,
        detail={
            "vendor": vendor,
            "product": product,
            "installed_version": installed,
            "affected_range": affected,
            "fixed_version": fixed,
            "cpe": sw.get("cpe23"),
            "match_basis": sw.get("basis"),       # shodan_cpe | banner_regex
            "confidence": CONFIDENCE,             # column + derivation land in chunk C
            "port": port,
        },
    )


def match_versions(
    db: Session,
    scan_run_id: uuid.UUID,
    asset_ids: set[uuid.UUID],
    since: datetime | None,
    new_canonical_ids_out: list[uuid.UUID] | None = None,
) -> set[uuid.UUID]:
    """Emit version_match CVE findings for touched assets and resolve ones that no
    longer apply. Returns the set of canonical finding ids touched (emitted +
    resolved) so the executor re-enriches/re-scores them."""
    if not asset_ids:
        return set()

    since = since if (since is None or since.tzinfo) else since.replace(tzinfo=timezone.utc)

    assets = (
        db.query(AssetCanonical)
        .filter(AssetCanonical.id.in_(asset_ids), AssetCanonical.asset_type == "ip_address")
        .all()
    )

    # Cache product → index rows for this run (one query per distinct product).
    ranges_cache: dict[tuple[str, str], list[CpeCveRange]] = {}

    findings: list[DiscoveredFinding] = []
    # {asset_id: set(cve_id currently matched)} — only for assets we had fresh
    # software data for, so resolution is correctly scoped.
    matched_by_asset: dict[uuid.UUID, set[str]] = {}

    for asset in assets:
        open_ports = (asset.asset_metadata or {}).get("open_ports")
        if not isinstance(open_ports, list):
            continue

        had_software = False
        # one finding per (cve_id) on this asset — prefer a match carrying a
        # clean fixed_version for the detail
        best_by_cve: dict[str, DiscoveredFinding] = {}
        for entry in open_ports:
            if not isinstance(entry, dict):
                continue
            # Freshness: only ports observed this run (cumulative list keeps stale).
            seen = _parse_ts(entry.get("last_seen_at"))
            if since is not None and (seen is None or seen < since):
                continue
            software = entry.get("software")
            if not isinstance(software, list) or not software:
                continue
            port = entry.get("port") if isinstance(entry.get("port"), int) else None
            for sw in software:
                canon = to_canonical_product(sw.get("vendor", ""), sw.get("product", ""))
                if canon is None or not sw.get("version"):
                    continue
                had_software = True
                cvendor, cproduct = canon
                if canon not in ranges_cache:
                    ranges_cache[canon] = ranges_for_product(db, cvendor, cproduct)
                vcls = _vclass(cvendor, cproduct)
                installed = sw["version"]
                for row in ranges_cache[canon]:
                    if row.all_versions:
                        continue
                    if not _matches(installed, row, vcls):
                        continue
                    cid = row.cve_id
                    existing = best_by_cve.get(cid)
                    # keep the first match, but upgrade to one with a fixed_version
                    if existing is None or (
                        existing.detail.get("fixed_version") is None and row.version_end_excluding
                    ):
                        best_by_cve[cid] = _build_finding(asset.value, cid, sw, row, port)

        if had_software:
            matched_by_asset[asset.id] = set(best_by_cve.keys())
            findings.extend(best_by_cve.values())

    touched: set[uuid.UUID] = set()
    if findings:
        touched = write_findings(db, scan_run_id, findings, new_canonical_ids_out=new_canonical_ids_out)

    resolved = _resolve_stale(db, matched_by_asset)
    touched.update(resolved)

    if findings or resolved:
        log.info(
            "Version matching run %s: %d finding(s) emitted/refreshed, %d resolved",
            scan_run_id, len(findings), len(resolved),
        )
    return touched


def _resolve_stale(db: Session, matched_by_asset: dict[uuid.UUID, set[str]]) -> set[uuid.UUID]:
    """Resolve open/acknowledged version_match findings on assets we re-matched
    this run whose CVE is no longer matched (e.g. the host was upgraded). Scoped
    to assets we had fresh software for; suppressed findings are left alone."""
    if not matched_by_asset:
        return set()

    rows = (
        db.query(FindingCanonical)
        .filter(
            FindingCanonical.asset_canonical_id.in_(list(matched_by_asset.keys())),
            FindingCanonical.source == SOURCE,
            FindingCanonical.finding_type == FINDING_TYPE,
            FindingCanonical.state.in_(["open", "acknowledged"]),
        )
        .all()
    )

    now = datetime.now(timezone.utc)
    resolved: set[uuid.UUID] = set()
    for row in rows:
        still = matched_by_asset.get(row.asset_canonical_id, set())
        if row.cve_id not in still:
            row.state = "resolved"
            row.resolved_at = now
            resolved.add(row.id)
    if resolved:
        db.commit()
    return resolved


def _parse_ts(value) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
