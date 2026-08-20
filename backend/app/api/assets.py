import ipaddress
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.connectors import REGISTRY
from app.api.deps import get_current_user, require_role
from app.api.findings import _NOT_EXCLUDED_FROM_MAIN
from app.core.database import get_db
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.claim import AssetClaim
from app.models.finding_canonical import FindingCanonical
from app.models.observer import Observer
from app.models.scan import ScanKind, ScanRun, ScanStatus
from app.models.target_asset_link import TargetAssetLink
from app.models.user import UserRole
from app.services import claim_emitter, scan_executor, whois_service
from app.services.asset_chain import chain_target_ids

# ── Severity helpers ──────────────────────────────────────────────────────────

_SEV_RANK: dict[str, int] = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _compute_asset_risk(db: Session, assets: list[AssetCanonical]) -> dict:
    """Return {asset_id: {"worst_severity", "risk_score", "risk_band"}} per asset.

    Worst-driven rollup (matches the locked org-gauge philosophy): an asset
    inherits its single worst open/acknowledged finding — the highest
    `risk_score` (and that finding's band), and separately the highest raw
    `severity` for the legacy severity chip.

    Findings propagate both to the asset itself AND to any parent asset whose
    value matches the child's parent_value.  This is necessary because ip_address
    rows whose parent dns_record is tracked are hidden in the UI — the dns_record
    row represents the whole chain, so it must inherit the IP's risk.

    Multiple assets can share the same value (e.g. A + AAAA records both have
    value='example.com'), so we map value → [list of IDs].
    """
    if not assets:
        return {}

    asset_ids_set = {a.id for a in assets}
    asset_vals    = [a.value for a in assets]

    # value → [asset_id, ...] — needed because A + AAAA share the same value.
    # Only A/AAAA dns_record rows (and non-dns_record assets) are valid
    # propagation targets: an apex domain commonly has MX/NS/TXT/SOA records
    # sharing the same `value` as its A/AAAA record, but those represent
    # unrelated infrastructure (mail servers, nameservers, DNS policy) and
    # must not inherit the risk of whatever IP the A/AAAA record resolves to.
    val_to_ids: dict[str, list] = {}
    for a in assets:
        if a.asset_type == "dns_record" and a.record_type not in ("A", "AAAA"):
            continue
        val_to_ids.setdefault(a.value, []).append(a.id)

    # Assets whose parent_value is one of our values (includes IPs already in list)
    child_rows = (
        db.query(AssetCanonical.id, AssetCanonical.parent_value)
        .filter(AssetCanonical.parent_value.in_(asset_vals))
        .all()
    )
    child_to_parent_val: dict = {cid: pval for cid, pval in child_rows}

    # CNAME chain propagation: a CNAME record inherits the risk of the host it
    # resolves to — every asset along the chain it points at (intermediate
    # records + the terminal IP), across multi-hop chains (host1 → host2 → IP).
    # A/AAAA already inherit their IP's risk via parent_value above; MX/NS/TXT
    # don't resolve to a host and are intentionally left out (re-adding them
    # here would re-break the apex MX/NS/TXT-inherits-IP-risk case).
    index: dict[str, list] = {}
    for a in assets:
        index.setdefault(a.value, []).append(a)

    def _get_by_value(value: str) -> list:
        if value in index:
            return index[value]
        rows = db.query(AssetCanonical).filter(AssetCanonical.value == value).all()
        index[value] = rows  # memoise (covers the single-asset detail view)
        return rows

    target_to_owners: dict = {}
    for a in assets:
        if a.asset_type == "dns_record" and a.record_type == "CNAME":
            for tid in chain_target_ids(a, _get_by_value):
                target_to_owners.setdefault(tid, []).append(a.id)

    # Fetch findings for our main assets + any children not already in the list
    # + any CNAME chain targets pulled in above.
    extra_ids = (set(child_to_parent_val) | set(target_to_owners)) - asset_ids_set
    all_ids   = asset_ids_set | extra_ids

    finding_rows = (
        db.query(
            FindingCanonical.asset_canonical_id,
            FindingCanonical.severity,
            FindingCanonical.risk_score,
            FindingCanonical.risk_band,
        )
        .filter(
            FindingCanonical.asset_canonical_id.in_(all_ids),
            FindingCanonical.state.in_(["open", "acknowledged"]),
            # A finding the shared-infra verifier excluded (rejected or
            # ownership_unverifiable) doesn't drive the asset's risk rollup
            # by default — same shared exclusion as the dashboard
            # security-score (api/findings.py) — consolidated onto the one
            # constant there so a future 5th excluded value is one edit.
            _NOT_EXCLUDED_FROM_MAIN,
        )
        .all()
    )

    rollup: dict = {}

    def _apply(owner_id: object, sev: str, score: int | None, band: str | None) -> None:
        cur = rollup.get(owner_id)
        if cur is None:
            cur = {"worst_severity": None, "risk_score": None, "risk_band": None}
            rollup[owner_id] = cur
        if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(cur["worst_severity"], 0):
            cur["worst_severity"] = sev
        if (score or 0) > (cur["risk_score"] or 0):
            cur["risk_score"] = score
            cur["risk_band"] = band

    for fid, sev, score, band in finding_rows:
        # Direct: attribute finding to the asset itself
        if fid in asset_ids_set:
            _apply(fid, sev, score, band)

        # Propagate: also attribute to parent asset(s), regardless of whether
        # the child is in the main list — covers both hidden IP rows and
        # children fetched via extra_ids
        pval = child_to_parent_val.get(fid)
        if pval:
            for parent_id in val_to_ids.get(pval, []):
                _apply(parent_id, sev, score, band)

        # Chain-propagate: a CNAME inherits the risk of every asset along the
        # chain it resolves to (terminal records + IP).
        for owner_id in target_to_owners.get(fid, []):
            _apply(owner_id, sev, score, band)

    return rollup


router = APIRouter()


class AssetIgnoreUpdate(BaseModel):
    ignored: bool


class DeleteByApexRequest(BaseModel):
    apex: str
    asset_ids: list[uuid.UUID]
    exclude_from_connector: bool = True


class BulkRecheckRequest(BaseModel):
    asset_ids: list[uuid.UUID]


class BulkAssetDeleteRequest(BaseModel):
    asset_ids: list[uuid.UUID]


@router.get("/whois")
def lookup_whois(
    ip: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Look up WHOIS / RDAP info for an IP. Cached for 30 days. Returns null fields for private/non-public IPs."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")
    result = whois_service.lookup_cached(db, ip)
    if not result:
        return {"ip": ip, "org": None, "asn": None, "looked_up_at": None, "public": False}
    return {
        "ip": ip,
        "org": result["org"] or None,
        "asn": result["asn"] or None,
        "looked_up_at": result["looked_up_at"],
        "public": True,
    }


@router.get("/whois-domain")
def lookup_domain_whois(
    domain: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Look up domain registration info. Cached for 7 days. Returns null fields when WHOIS is unavailable for the TLD."""
    cleaned = domain.lower().strip().rstrip(".")
    if not cleaned or "." not in cleaned or any(c.isspace() for c in cleaned):
        raise HTTPException(status_code=400, detail="Invalid domain")
    return whois_service.lookup_domain_cached(db, cleaned)


@router.delete("/by-apex", status_code=200)
def delete_assets_by_apex(
    data: DeleteByApexRequest,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Delete all canonical assets for an apex group, optionally excluding the
    domain from its source connector. Cascades remove target_asset_links and
    asset_edges via FK; the legacy `assets` hypertable's rows are also cleared
    by value so the transitional dual-write doesn't resurrect them.

    Also follows CNAME chains rooted at the deleted dns_records — any IP asset
    or downstream dns_record whose parent_value is one of the values being
    deleted is swept too. Without this, IPs that resolved through a CNAME to a
    SaaS hostname (e.g. *.cloudfront.net, *.azureedge.net) would survive and
    surface as new orphan apex groups under the external domain after delete.
    """
    swept_total = 0
    if data.asset_ids:
        from app.api.targets import _sweep_cname_descendants

        seed_values = {
            r[0] for r in db.query(AssetCanonical.value)
            .filter(AssetCanonical.id.in_(data.asset_ids))
            .all()
            if r[0]
        }
        db.query(AssetCanonical).filter(
            AssetCanonical.id.in_(data.asset_ids)
        ).delete(synchronize_session=False)
        swept_total = _sweep_cname_descendants(db, seed_values)

    connector_excluded = None
    if data.exclude_from_connector:
        from app.models.target import Target
        from app.services import connector_config as conn_svc

        target = db.query(Target).filter(Target.value == data.apex).first()
        if target and target.connector_id:
            config = conn_svc.get_decrypted_config(db, target.connector_id) or {}
            excluded = list(set(config.get("excluded_zones", []) + [data.apex]))
            conn_svc.upsert_config(db, target.connector_id, {**config, "excluded_zones": excluded})
            connector_excluded = target.connector_id

    db.commit()
    return {
        "deleted": len(data.asset_ids) + swept_total,
        "connector_excluded": connector_excluded,
    }


@router.get("/")
def list_assets(
    asset_type: str | None = None,
    show_ignored: bool = False,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """List canonical assets. Returns durable identity rows — one per
    (asset_type, value) — not observation rows."""
    q = db.query(AssetCanonical)
    if asset_type:
        q = q.filter(AssetCanonical.asset_type == asset_type)
    if not show_ignored:
        q = q.filter(AssetCanonical.ignored == False)  # noqa: E712
    assets = q.order_by(AssetCanonical.last_seen_at.desc()).limit(1000).all()
    risk = _compute_asset_risk(db, assets)
    bridge_sources = load_bridge_sources(db, [a.id for a in assets])
    return [_serialize_asset(a, risk.get(a.id), bridge_sources.get(a.id)) for a in assets]


@router.delete("/bulk", status_code=200)
def bulk_delete_assets(
    data: BulkAssetDeleteRequest,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Delete a set of canonical assets and sweep their CNAME descendants. Same
    cascade semantics as the apex delete — used by the Assets-page bulk action
    bar to remove multiple apex groups in one click without per-group dialogs.

    Registered above `/{asset_id}` so FastAPI doesn't try to parse 'bulk' as a UUID.
    """
    if not data.asset_ids:
        raise HTTPException(status_code=422, detail="No assets selected")

    from app.api.targets import _sweep_cname_descendants

    seed_values = {
        r[0] for r in db.query(AssetCanonical.value)
        .filter(AssetCanonical.id.in_(data.asset_ids))
        .all()
        if r[0]
    }
    db.query(AssetCanonical).filter(
        AssetCanonical.id.in_(data.asset_ids)
    ).delete(synchronize_session=False)
    swept = _sweep_cname_descendants(db, seed_values)
    db.commit()
    return {"deleted": len(data.asset_ids) + swept}


@router.get("/{asset_id}")
def get_asset(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Fetch a single canonical asset by ID — drives the full-detail page."""
    asset = db.get(AssetCanonical, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    risk = _compute_asset_risk(db, [asset])
    bridge_sources = load_bridge_sources(db, [asset.id])
    return _serialize_asset(asset, risk.get(asset.id), bridge_sources.get(asset.id))


@router.patch("/{asset_id}/ignore", status_code=200)
def set_asset_ignored(
    asset_id: uuid.UUID,
    data: AssetIgnoreUpdate,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    asset = db.get(AssetCanonical, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    asset.ignored = data.ignored
    db.commit()
    return {"id": str(asset_id), "ignored": asset.ignored}


@router.delete("/{asset_id}", status_code=204)
def delete_asset(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    asset = db.get(AssetCanonical, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(asset)
    db.commit()


@router.post("/{asset_id}/scan", status_code=202)
def scan_asset(
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Kick off an on-demand scan targeting a single asset."""
    asset = db.get(AssetCanonical, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    run = ScanRun(
        id=uuid.uuid4(),
        name=f"On-demand: {asset.value}",
        status=ScanStatus.PENDING,
        kind=ScanKind.RECHECK,
        scope={"domains": [asset.value] if asset.asset_type == "dns_record" else [],
               "ip_ranges": [asset.value] if asset.asset_type == "ip_address" else []},
        options={"skip_discovery": True},
        created_by_id=current_user.id,
    )
    db.add(run)
    db.commit()

    background_tasks.add_task(scan_executor.launch, run.id, run.scope, REGISTRY)
    return {"scan_id": run.id, "status": "queued"}


@router.post("/bulk/recheck", status_code=202)
def bulk_recheck(
    data: BulkRecheckRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Queue a single recheck scan covering all selected assets.

    One ScanRun per bulk request — not N runs — so the Activity feed stays
    legible and the executor's chunking can pace them naturally. The run is
    kind=RECHECK with skip_discovery so Phase 1 doesn't re-enumerate siblings.
    """
    if not data.asset_ids:
        raise HTTPException(status_code=422, detail="No assets selected")

    assets = (
        db.query(AssetCanonical)
        .filter(AssetCanonical.id.in_(data.asset_ids))
        .all()
    )
    if not assets:
        raise HTTPException(status_code=404, detail="No matching assets found")

    domains = sorted({a.value for a in assets if a.asset_type == "dns_record"})
    ip_ranges = sorted({a.value for a in assets if a.asset_type == "ip_address"})

    if not domains and not ip_ranges:
        raise HTTPException(
            status_code=422,
            detail="Selected assets have no scannable values (only dns_record / ip_address are supported)",
        )

    run = ScanRun(
        id=uuid.uuid4(),
        name=f"Bulk recheck: {len(assets)} asset{'s' if len(assets) != 1 else ''}",
        status=ScanStatus.PENDING,
        kind=ScanKind.RECHECK,
        scope={"domains": domains, "ip_ranges": ip_ranges},
        options={"skip_discovery": True},
        created_by_id=current_user.id,
    )
    db.add(run)
    db.commit()

    background_tasks.add_task(scan_executor.launch, run.id, run.scope, REGISTRY)
    return {"scan_id": run.id, "asset_count": len(assets), "status": "queued"}


# ── helpers ───────────────────────────────────────────────────────────────────

# How long a Shodan-sourced port stays visible as intel after naabu next scans
# the IP without confirming it.  Within this window the port appears in the UI
# so operators can investigate; after the window it is dropped as presumed
# closed.  Verified ports (re-observed >= naabu_last_scan_at) are unaffected.
_SHODAN_PORT_GRACE_DAYS = 14

# Flap-guard: a port confirmed by an active prober (l7_confirmed=True) is kept
# this many days past its last confirmation even if later scans miss it. Real
# services flap (intermittent / firewall throttling), so one missed scan must not
# retire a known-real port. Mirrors the write-time grace in
# asset_writer._prune_stale_ports. See planning#69/#72.
_CONFIRMED_PORT_GRACE_DAYS = 3


def _filter_stale_ports(metadata: dict, now: datetime | None = None) -> dict:
    """Remove open_ports entries not re-observed in the most recent naabu scan.

    naabu_last_scan_at is written to asset_metadata each time naabu (now with
    nmap verification) completes for this IP. Any port whose last_seen_at
    predates that timestamp was not confirmed in the latest verified scan and
    is treated as closed — with two exceptions: (1) a previously app-confirmed
    port (l7_confirmed) is kept for _CONFIRMED_PORT_GRACE_DAYS past its last
    confirmation so an intermittent/flapping real port isn't retired on one miss;
    (2) a Shodan-sourced port is kept as time-boxed intel for
    _SHODAN_PORT_GRACE_DAYS days from its last_seen_at so operators can
    investigate before it is silently dropped.

    If no naabu scan has ever run, all ports are kept.

    The `now` parameter is exposed for testing (defaults to UTC now).
    """
    naabu_last_scan_at = metadata.get("naabu_last_scan_at")
    open_ports = metadata.get("open_ports")
    if not naabu_last_scan_at or not isinstance(open_ports, list):
        return metadata
    try:
        cutoff = datetime.fromisoformat(naabu_last_scan_at)
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return metadata
    now = now or datetime.now(timezone.utc)
    grace_cutoff = now - timedelta(days=_SHODAN_PORT_GRACE_DAYS)
    confirmed_grace_cutoff = now - timedelta(days=_CONFIRMED_PORT_GRACE_DAYS)
    fresh = []
    for entry in open_ports:
        if not isinstance(entry, dict):
            continue
        raw_ts = entry.get("last_seen_at")
        if not raw_ts:
            fresh.append(entry)
            continue
        try:
            ts = datetime.fromisoformat(raw_ts)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= cutoff:
                # Re-observed in this scan cycle — always keep.
                fresh.append(entry)
            elif entry.get("l7_confirmed") is True and ts >= confirmed_grace_cutoff:
                # Flap-guard: a previously-confirmed real port flaps; keep it
                # through brief misses until the confirmed grace expires.
                fresh.append(entry)
            elif (
                "shodan" in (entry.get("sources") or [])
                and ts >= grace_cutoff
            ):
                # Shodan intel within grace window — keep as unverified intel.
                fresh.append(entry)
            # else: stale / grace-expired — drop.
        except (ValueError, AttributeError):
            fresh.append(entry)
    return {**metadata, "open_ports": fresh}


# ── claims-bridge (planning#144 L3c-2) ──────────────────────────────────────
#
# `_serialize_asset` used to return `row.asset_metadata` verbatim. Now that
# claim_emitter/projector (L2/L3) have decomposed asset_metadata's producers
# into asset_claims + asset_state, this reconstructs the same dict shape from
# those sources instead — the exact inverse of claim_emitter.emit_claims'
# Table 1 mapping — so a later slice can drop the asset_metadata column
# without changing the API response. The column still exists and the merge
# loop (asset_writer._upsert_canonical_batch) still writes it; this bridge
# just stops the serializer from READING it.
#
# A metadata key is included only when its source exists (claim/state key
# present), matching asset_metadata's own sparse-key shape — the emitters
# never write a key for data that wasn't observed.

_EMPTY_BRIDGE_SOURCES: dict = {
    "state": None,
    "by_type": {},
    "ports_by_observer": {},
    "observers": [],
    "shodan_last_observed_at": None,
}

# `asset_metadata["sources"]` has only ever meant "which scan/discovery/
# connector observer produced this asset" — every real writer of that key
# (naabu, tlsx, httpx, banner_grab, dns_records, dnsrecon, subfinder,
# bruteforce, cert_transparency, shodan, cloudflare) is one of these three
# Observer.kind values (verified against every literal `"sources": [...]`
# write in app/connectors + app/services). `verify`/`enrich`-kind observers
# (hosting_classifier, eol_enrichment, cpe_normalizer, shared_infra_verifier,
# domain_affinity, dangling_dns_analyzer) write claims about an asset but
# have NEVER contributed to its `sources` — they read/modify an
# already-persisted asset directly, outside write_assets' DiscoveredAsset
# path, and asset_writer's merge loop never puts them there. Restricting
# the bridge's `sources` to these kinds keeps it faithful to that existing
# meaning; the broader "every claim's observer" reading would silently pull
# derived-judgment observers into a field the frontend (and any consumer
# treating `sources` as "who observed this asset exists") has never seen
# them in.
_SOURCES_OBSERVER_KINDS: frozenset[str] = frozenset({"scan", "discovery", "connector"})


def load_bridge_sources(db: Session, asset_ids: list[uuid.UUID]) -> dict[uuid.UUID, dict]:
    """Batch-load `_bridge_metadata`'s per-asset sources for `asset_ids`:
    one `asset_state` query + one `asset_claims` (joined to `observers` for
    the name/kind) query, regardless of how many asset_ids are passed in.
    Callers (list_assets / get_asset) must call this once per request and
    pass the per-asset slice into `_serialize_asset` — no per-row query
    belongs in the serializer itself.

    Returns {asset_id: {"state", "by_type", "ports_by_observer", "observers",
    "shodan_last_observed_at"}} for every id in `asset_ids` (present with
    empty/None defaults even if the asset has no state row or claims yet).
    """
    result: dict[uuid.UUID, dict] = {
        aid: {
            "state": None,
            "by_type": {},
            "ports_by_observer": {},
            "observers": set(),
            "shodan_last_observed_at": None,
        }
        for aid in asset_ids
    }
    if not asset_ids:
        return result

    for state in db.query(AssetState).filter(AssetState.asset_canonical_id.in_(asset_ids)).all():
        result[state.asset_canonical_id]["state"] = state

    claim_rows = (
        db.query(
            AssetClaim.asset_canonical_id,
            AssetClaim.claim_type,
            AssetClaim.claim_value,
            AssetClaim.last_observed_at,
            Observer.name,
            Observer.kind,
        )
        .join(Observer, AssetClaim.observer_id == Observer.id)
        .filter(AssetClaim.asset_canonical_id.in_(asset_ids))
        .all()
    )

    # by_type keeps only the most-recently-observed row per (asset, claim_type)
    # — the same claim_type can theoretically be written by more than one
    # observer over an asset's lifetime (emit_claims attributes each batch's
    # claims to that batch's resolved observer), so this picks a single
    # current value the same way a fresh re-observation would in
    # asset_metadata (last write wins). port_observation is excluded from
    # this collapse — every observer's port list is kept separately in
    # `ports_by_observer`, since shodan_ports needs specifically the
    # shodan-observer's own claim, not a collapsed/merged view.
    latest_at: dict[tuple, datetime] = {}
    for asset_id, claim_type, claim_value, last_observed_at, observer_name, observer_kind in claim_rows:
        bucket = result[asset_id]
        if observer_kind in _SOURCES_OBSERVER_KINDS:
            bucket["observers"].add(observer_name)

        if claim_type == claim_emitter._PORT_OBSERVATION_CLAIM_TYPE:
            bucket["ports_by_observer"][observer_name] = claim_value
            continue

        key = (asset_id, claim_type)
        if key not in latest_at or last_observed_at > latest_at[key]:
            latest_at[key] = last_observed_at
            bucket["by_type"][claim_type] = claim_value

        if claim_type == claim_emitter._SHODAN_HOST_CLAIM_TYPE:
            current = bucket["shodan_last_observed_at"]
            if current is None or last_observed_at > current:
                bucket["shodan_last_observed_at"] = last_observed_at

    for bucket in result.values():
        bucket["observers"] = sorted(bucket["observers"])

    return result


def _bridge_metadata(canonical: AssetCanonical, state: AssetState | None, claims: dict) -> dict:
    """Reconstruct `asset_metadata` from claims-layer sources — the inverse
    of claim_emitter.emit_claims' Table 1 mapping, plus the projector's
    asset_state derivations. `claims` is one asset's slice of
    `load_bridge_sources`' return value.

    Driven directly off claim_emitter's own key maps (_SIMPLE_KEY_CLAIMS /
    _SHODAN_HOST_KEYS / _CT_KEYS / the spf/port constants) rather than a
    hand-duplicated copy, so every value-key those maps carry has a
    reconstruction path here by construction, and a future addition to
    claim_emitter's Table 1 doesn't silently go unbridged.
    """
    md: dict = {}

    # identity — promoted to columns by L3b-1
    if canonical.record_type is not None:
        md["record_type"] = canonical.record_type
    if canonical.content is not None:
        md["content"] = canonical.content

    # asset_state projections
    if state is not None:
        if state.open_ports:
            md["open_ports"] = state.open_ports
        if state.eol_summary:
            md["eol_services"] = state.eol_summary
        attrs = state.attributes or {}
        if attrs.get("provider_mx"):
            md["provider_mx"] = attrs["provider_mx"]
        for attr_key in ("cdn", "cdn_domain", "naabu_last_scan_at"):
            if attr_key in attrs:
                md[attr_key] = attrs[attr_key]

    # sources: distinct scan/discovery/connector-kind observer names across
    # every claim this asset has (not just the ones individually bridged
    # below) — restricted to those three Observer.kind values so this
    # matches asset_metadata["sources"]'s existing meaning; see
    # _SOURCES_OBSERVER_KINDS.
    if claims.get("observers"):
        md["sources"] = sorted(claims["observers"])

    by_type: dict = claims.get("by_type", {})

    # dns_ttl / proxy_state / cloudflare_zone / mx_preference / host_tarpit /
    # reverse_hostname — every claim_emitter._SIMPLE_KEY_CLAIMS entry.
    for meta_key, (claim_type, value_key) in claim_emitter._SIMPLE_KEY_CLAIMS.items():
        claim_value = by_type.get(claim_type)
        if claim_value and value_key in claim_value:
            md[meta_key] = claim_value[value_key]

    # spf: the whole parsed dict rides straight through as claim_value.
    spf = by_type.get(claim_emitter._SPF_CLAIM_TYPE)
    if spf:
        md[claim_emitter._SPF_METADATA_KEY] = spf

    # ct_cert_issuance -> not_before / not_after / issuer
    ct = by_type.get(claim_emitter._CT_CLAIM_TYPE)
    if ct:
        for meta_key, value_key in claim_emitter._CT_KEYS.items():
            if value_key in ct:
                md[meta_key] = ct[value_key]

    # shodan_host -> shodan_org/os/country/isp/asn/tags/last_update
    shodan_host = by_type.get(claim_emitter._SHODAN_HOST_CLAIM_TYPE)
    if shodan_host:
        for meta_key, value_key in claim_emitter._SHODAN_HOST_KEYS.items():
            if value_key in shodan_host and shodan_host[value_key] is not None:
                md[meta_key] = shodan_host[value_key]
        shodan_last_observed_at = claims.get("shodan_last_observed_at")
        if shodan_last_observed_at is not None:
            md["shodan_last_seen"] = shodan_last_observed_at.isoformat()

    # shodan_ports: the shodan-observer's own port_observation claim, bare
    # port numbers only (distinct from `open_ports`, which is the merged
    # cross-observer view projected into asset_state).
    shodan_ports_claim = claims.get("ports_by_observer", {}).get("shodan")
    if shodan_ports_claim:
        ports = shodan_ports_claim.get("ports") or []
        port_numbers = [p["port"] for p in ports if isinstance(p, dict) and "port" in p]
        if port_numbers:
            md["shodan_ports"] = port_numbers

    return md


def _serialize_asset(row: AssetCanonical, risk: dict | None = None, bridge_sources: dict | None = None) -> dict:
    risk = risk or {}
    claims = bridge_sources if bridge_sources is not None else _EMPTY_BRIDGE_SOURCES
    metadata = _bridge_metadata(row, claims.get("state"), claims)
    if row.asset_type == "ip_address":
        metadata = _filter_stale_ports(metadata)
    return {
        "id": str(row.id),
        "asset_type": row.asset_type,
        "value": row.value,
        "parent_value": row.parent_value,
        "asset_metadata": metadata,
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "ignored": row.ignored,
        "tags": row.tags or [],
        "worst_severity": risk.get("worst_severity"),
        "risk_score": risk.get("risk_score"),
        "risk_band": risk.get("risk_band"),
    }
