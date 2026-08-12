"""Local CPE→CVE version-range index — native version→CVE matching (#66 B0).

Maintains `cpe_cve_ranges`: a product-scoped mirror of NVD `cpeMatch` ranges for
the D7 product set, so the version matcher (chunk B) resolves "installed version
→ affected CVEs + fixed version" against a LOCAL table — no per-scan API call.

Sources (S0 established VulnCheck's online CPE→CVE lookup is paywalled):
  * SEED  — free NVD 2.0 API, server-side CPE filter (`virtualMatchString`) per
            canonical product. ~one request/product; covers NVD-analyzed history.
  * DELTA — VulnCheck nist-nvd2 `lastMod` window. Its vcConfigurations fills the
            NVD analysis backlog so freshly-disclosed CVEs on *supported* (not
            just EOL) versions are caught without waiting for NVD.

This module owns the **parser + persistence** (source-agnostic — NVD and
VulnCheck share the NVD `configurations`/`cpeMatch` schema) and the read helper
the matcher uses. The HTTP sync clients live in `cpe_cve_sync`.
"""

import logging
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.cpe_cve_range import CpeCveRange
from app.services.cpe_normalizer import split_cpe, to_canonical_product

log = logging.getLogger(__name__)


def parse_configurations(
    cve_id: str,
    configurations: list[dict] | None,
    source: str,
    synced_at: datetime,
) -> list[dict]:
    """NVD/VulnCheck `configurations[]` → CpeCveRange row dicts for the D7 set.

    Keeps only vulnerable application cpeMatch entries whose (vendor, product)
    resolves to an in-scope canonical product (aliases folded in). Each entry
    becomes a range row, an exact-version row, or an all-versions row. Deduped
    within the CVE."""
    rows: list[dict] = []
    seen: set[tuple] = set()
    for cfg in configurations or []:
        for node in cfg.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable", False):
                    continue
                split = split_cpe(m.get("criteria") or "")
                if split is None:
                    continue
                part, vendor, product, version = split
                if part != "a":  # software (application) CPEs only
                    continue
                canon = to_canonical_product(vendor, product)
                if canon is None:
                    continue
                cvendor, cproduct = canon

                vsi = m.get("versionStartIncluding")
                vse = m.get("versionStartExcluding")
                vei = m.get("versionEndIncluding")
                vee = m.get("versionEndExcluding")
                has_range = any((vsi, vse, vei, vee))
                exact: str | None = None
                all_versions = False
                if not has_range:
                    if version in ("*", "-", ""):
                        # NVD `-`/bare-`*` with no bounds = version UNSPECIFIED.
                        # Almost always an NVD version-data gap (e.g. old CVEs
                        # like CVE-1999-0289 on apache:http_server:-), NOT a real
                        # "every version" claim. Stored for audit, but the
                        # matcher (chunk B) MUST exclude all_versions rows from
                        # confident matches or it false-positives a 1999 CVE onto
                        # a 2024 install.
                        all_versions = True
                    else:
                        exact = version

                key = (cvendor, cproduct, vsi, vse, vei, vee, exact, all_versions)
                if key in seen:
                    continue
                seen.add(key)
                rows.append({
                    "cve_id": cve_id.upper(),
                    "vendor": cvendor,
                    "product": cproduct,
                    "version_start_including": vsi,
                    "version_start_excluding": vse,
                    "version_end_including": vei,
                    "version_end_excluding": vee,
                    "exact_version": exact,
                    "all_versions": all_versions,
                    "source": source,
                    "cpe_criteria": m.get("criteria"),
                    "last_synced_at": synced_at,
                })
    return rows


def replace_cve_ranges(db: Session, cve_id: str, rows: list[dict]) -> int:
    """Delete-then-insert the rows for one CVE (idempotent refresh). Does NOT
    commit — the caller batches commits. Returns the number of rows written."""
    db.query(CpeCveRange).filter(CpeCveRange.cve_id == cve_id.upper()).delete(
        synchronize_session=False
    )
    for r in rows:
        db.add(CpeCveRange(**r))
    return len(rows)


def ranges_for_product(db: Session, vendor: str, product: str) -> list[CpeCveRange]:
    """All indexed ranges for a canonical (vendor, product). The matcher loads
    these and tests the installed version against each in Python (version
    semantics aren't SQL-sortable)."""
    return (
        db.query(CpeCveRange)
        .filter(CpeCveRange.vendor == vendor.lower(), CpeCveRange.product == product.lower())
        .all()
    )


def index_size(db: Session) -> int:
    return db.query(CpeCveRange).count()
