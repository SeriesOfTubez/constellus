"""CPE normalization — banner/Shodan service data → structured software intel.

The #33 "banner → software-intel" slice and the hard dependency of the native
version→CVE matcher (planning #66 chunk B). Where `eol_enrichment._parse_product`
reduces a service_version to a `(product, major.minor cycle)` for the
endoflife.date lookup, this module:

  (i)   keeps the **full installed version** (`2.4.6`, not `2.4`);
  (ii)  parses **every** product in a multi-product banner — an Apache Server
        header routinely advertises Apache + OpenSSL + PHP in one string;
  (iii) maps each to a canonical **NVD CPE 2.3 vendor:product** (verified live
        against nist-nvd2 cpeMatch criteria, 2026-06-20) so the matcher can
        range-compare against NVD `cpeMatch` data.

Shodan's per-port `cpe[]` (already CPE-formatted, captured in #32) is folded in
for free long-tail coverage and takes precedence over a banner-regex guess for
the same product/version.

Output is written as `software[]` onto each `open_ports[]` entry, each item:
    {vendor, product, version, cpe23, basis}
where `basis` ∈ {"shodan_cpe", "banner_regex"} (kept so the matcher can record
`match_basis` per #66 D4). Pure string work — no network calls. Runs as a
post-scan pass *before* eol_enrichment in scan_executor.

CPE-string parsing and CPE-2.3 construction are hand-rolled here (trivial,
well-defined). The `cpe`/`univers` libraries (#66 D5) are deferred to chunk B,
where the version *range* comparison actually needs them.
"""

import logging
import re
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.asset import AssetType
from app.models.asset_canonical import AssetCanonical
from app.services import projector
from app.services.claim_emitter import upsert_single_claim

log = logging.getLogger(__name__)

_OBSERVER_NAME = "cpe_normalizer"
_CLAIM_TYPE = "port_observation"

# (optional service filter, regex, cpe_vendor, cpe_product, version_group)
# Applied to service_version; ALL that match contribute (multi-product banner).
# Vendor:product tokens verified against live nist-nvd2 cpeMatch criteria:
#   apache:http_server, f5:nginx, openssl:openssl, php:php, haproxy:haproxy,
#   dovecot:dovecot, oracle:mysql, openbsd:openssh.
# Version groups keep the FULL version, including OpenSSL letter suffixes
# (1.0.2k) and OpenSSH portable suffixes (8.9p1) — both are part of the NVD
# CPE version token.
# The product/version separator is `[ /]` so both the httpx Server-header form
# (`Apache/2.4.6`) and the nmap/Shodan product form (`Apache httpd 2.4.6`,
# `nginx 1.21.6`) are caught — a host scanned without Shodan still normalizes.
_CPE_PATTERNS: list[tuple[str | None, re.Pattern[str], str, str, int]] = [
    (None,    re.compile(r"Apache(?: httpd)?[ /](\d+\.\d+(?:\.\d+)?)", re.I), "apache",  "http_server", 1),
    (None,    re.compile(r"nginx[ /](\d+\.\d+(?:\.\d+)?)", re.I),      "f5",      "nginx",       1),
    (None,    re.compile(r"OpenSSL[ /](\d+\.\d+\.\d+[a-z]?)", re.I),   "openssl", "openssl",     1),
    (None,    re.compile(r"PHP[ /](\d+\.\d+(?:\.\d+)?)", re.I),        "php",     "php",         1),
    (None,    re.compile(r"OpenSSH[_/ ](\d+\.\d+(?:p\d+)?)", re.I),    "openbsd", "openssh",     1),
    (None,    re.compile(r"HAProxy[ /](\d+\.\d+(?:\.\d+)?)", re.I),    "haproxy", "haproxy",     1),
    (None,    re.compile(r"Dovecot(?:\s+(?:IMAP|POP3)\s+release\s+)?(\d+\.\d+\.\d+)", re.I), "dovecot", "dovecot", 1),
    # MySQL: service_version is the raw greeting (e.g. "8.0.31-0ubuntu0.1"); the
    # bare-version pattern is loose, so gate it on the mysql service.
    ("mysql", re.compile(r"^(\d+\.\d+\.\d+)"),                         "oracle",  "mysql",       1),
]

# Vendor/product aliases NVD also uses for the same software — recorded for the
# chunk-B matcher (which must accept any alias), NOT emitted as the primary cpe.
VENDOR_PRODUCT_ALIASES: dict[tuple[str, str], list[tuple[str, str]]] = {
    ("f5", "nginx"): [("nginx", "nginx")],
    ("oracle", "mysql"): [("oracle", "mysql_server"), ("mysql", "mysql")],
}

# The canonical (vendor, product) set we normalize to / match on — derived from
# the pattern table so the two never drift.
CANONICAL_PRODUCTS: frozenset[tuple[str, str]] = frozenset(
    (vendor, product) for _, _, vendor, product, _ in _CPE_PATTERNS
)

# alias (vendor, product) → canonical (vendor, product). Lets the CVE index fold
# NVD's alias CPEs (nginx:nginx, oracle:mysql_server) into the canonical row the
# matcher queries by.
ALIAS_TO_CANONICAL: dict[tuple[str, str], tuple[str, str]] = {
    alias: canonical
    for canonical, aliases in VENDOR_PRODUCT_ALIASES.items()
    for alias in aliases
}


def to_canonical_product(vendor: str, product: str) -> tuple[str, str] | None:
    """Canonical (vendor, product) if this is an in-scope D7 product or a known
    alias of one; else None. Used by both the normalizer and the CVE index so a
    CVE's alias CPE lands under the same key the installed software normalizes to."""
    vp = (vendor.lower(), product.lower())
    if vp in CANONICAL_PRODUCTS:
        return vp
    return ALIAS_TO_CANONICAL.get(vp)


def split_cpe(cpe_str: str) -> tuple[str, str, str, str] | None:
    """Parse a CPE 2.3 or legacy 2.2 string → (part, vendor, product, version).
    None if it isn't a parseable CPE. Version may be `*`/`-` (caller decides)."""
    s = (cpe_str or "").strip()
    if s.startswith("cpe:2.3:"):
        parts = s.split(":")
        # cpe:2.3:<part>:<vendor>:<product>:<version>:...
        if len(parts) < 6:
            return None
        return parts[2], parts[3].lower(), parts[4].lower(), parts[5]
    if s.startswith("cpe:/"):
        # cpe:/<part>:<vendor>:<product>:<version>
        parts = s[len("cpe:/"):].split(":")
        if len(parts) < 4:
            return None
        return parts[0], parts[1].lower(), parts[2].lower(), parts[3]
    return None


def _cpe_escape(value: str) -> str:
    """Escape CPE 2.3 formatted-string special characters in a version token.
    Versions we emit (8.9p1, 1.0.2k, 7.4.16) need no escaping in practice; this
    just keeps the output well-formed if an odd character slips through."""
    return re.sub(r"([:*?\\])", r"\\\1", value)


def build_cpe23(vendor: str, product: str, version: str) -> str:
    """Canonical CPE 2.3 application string for vendor:product:version."""
    return f"cpe:2.3:a:{vendor}:{product}:{_cpe_escape(version)}:*:*:*:*:*:*:*"


def _software(vendor: str, product: str, version: str, basis: str) -> dict:
    return {
        "vendor": vendor.lower(),
        "product": product.lower(),
        "version": version,
        "cpe23": build_cpe23(vendor.lower(), product.lower(), version),
        "basis": basis,
    }


def _parse_banner(service: str, service_version: str) -> list[dict]:
    """Every product the banner advertises → software dicts (basis=banner_regex)."""
    out: list[dict] = []
    for svc_filter, pattern, vendor, product, group in _CPE_PATTERNS:
        if svc_filter and service != svc_filter:
            continue
        m = pattern.search(service_version)
        if m:
            out.append(_software(vendor, product, m.group(group), "banner_regex"))
    return out


def _parse_cpe_string(cpe_str: str) -> dict | None:
    """Parse a Shodan CPE 2.3 or 2.2 string → software dict (basis=shodan_cpe).

    Only application/OS CPEs with a concrete version are kept — a wildcard or
    missing version (`*`/`-`) isn't matchable, so it's dropped."""
    split = split_cpe(cpe_str)
    if split is None:
        return None
    part, vendor, product, version = split
    if part not in ("a", "o"):
        return None
    if not version or version in ("*", "-"):
        return None
    # Shodan 2.3 strings carry the version verbatim; re-emit a clean 2.3 cpe.
    return _software(vendor, product, version, "shodan_cpe")


def normalize_port_software(entry: dict) -> list[dict]:
    """Structured software intel for one open_ports[] entry.

    Merges banner-regex products and Shodan cpe[] entries, deduped by
    (vendor, product, version); the authoritative shodan_cpe basis wins a tie."""
    service = (entry.get("service") or "").lower()
    sv = entry.get("service_version") or ""

    candidates: list[dict] = []
    if sv:
        candidates.extend(_parse_banner(service, sv))
    for cpe_str in entry.get("cpe") or []:
        sw = _parse_cpe_string(cpe_str)
        if sw:
            candidates.append(sw)

    # Dedupe by (vendor, product, version); prefer the shodan_cpe basis.
    by_key: dict[tuple[str, str, str], dict] = {}
    for sw in candidates:
        key = (sw["vendor"], sw["product"], sw["version"])
        existing = by_key.get(key)
        if existing is None or (existing["basis"] != "shodan_cpe" and sw["basis"] == "shodan_cpe"):
            by_key[key] = sw
    return list(by_key.values())


def enrich_cpe(db: Session, touched_asset_ids: set[uuid.UUID]) -> None:
    """Post-scan CPE normalization. Writes `software[]` onto each open_ports[]
    entry of every touched IP asset. Idempotent — recomputed from the current
    banner/cpe each scan. Called from scan_executor before eol_enrichment.

    planning#144 L3c-1 made this emit a `port_observation` claim per touched
    IP asset carrying just `{port, software}` for each port with software.
    The projector's `_merge_open_ports` folds this claim's contribution
    across observers by port number, so `software` ends up on the same
    asset_state.open_ports entry naabu (or another prober) already populates.

    L3c-3 completes the move: the input inventory is read from
    `asset_state.open_ports`, and the transitional in-place
    `asset_metadata["open_ports"][*]["software"]` mutation L3c-1 kept
    alongside the claim is GONE. It had no readers left — L3c-2 repointed
    the API serializer onto the bridge, and version_matcher (the only other
    consumer of `software`) reads asset_state as of this slice — and, now
    that the input is a copy out of asset_state rather than the metadata
    dict itself, an in-place mutation would no longer have reached the
    column anyway. The merge loop is once again asset_metadata's only writer.

    Emitted for every touched IP asset with open_ports, even when no entry
    has software (empty `ports` list) — `upsert_single_claim` replaces the
    whole claim_value, so this is what lets a software signal that
    disappears (banner/cpe gone) actually clear out of the projected state
    instead of leaving a stale claim behind.
    """
    if not touched_asset_ids:
        return

    assets = (
        db.query(AssetCanonical)
        .filter(
            AssetCanonical.id.in_(touched_asset_ids),
            AssetCanonical.asset_type == AssetType.IP_ADDRESS,
        )
        .all()
    )
    if not assets:
        return

    now = datetime.now(timezone.utc)
    updated = 0
    # planning#144 L3c-3: port inventory from the projected asset_state, one
    # batched query. Copied per entry because the claim built below is the
    # only output — mutating asset_state's own JSONB in place here would be
    # an undeclared write into another module's table.
    ports_by_asset = projector.open_ports_by_asset(db, [a.id for a in assets])
    for asset in assets:
        open_ports: list[dict] = [
            dict(entry) for entry in (ports_by_asset.get(asset.id) or []) if isinstance(entry, dict)
        ]
        if not open_ports:
            continue

        for entry in open_ports:
            software = normalize_port_software(entry)
            if software:
                entry["software"] = software
                updated += 1
            elif "software" in entry:
                # Software signal disappeared (banner/cpe gone) — drop it so
                # a stale value can't ride into the claim below.
                del entry["software"]

        claim_value = {
            "ports": [
                {"port": entry["port"], "software": entry["software"]}
                for entry in open_ports
                if isinstance(entry, dict) and entry.get("software") and isinstance(entry.get("port"), int)
            ]
        }
        upsert_single_claim(db, asset.id, _OBSERVER_NAME, _CLAIM_TYPE, claim_value, now)

    if updated:
        log.info("CPE normalization: wrote software intel on %d port(s)", updated)
    db.commit()
