"""Build the exposure path of a finding at read time (planning#347).

One path per `finding_endpoints` row: internet → host → address → port →
service → the finding. The path is assembled on read because the links it
draws on (which names point at an address, what runs on a port) change between
scans; only what a source observed is stored.

Rules this module keeps:

* A hop the record does not single out is never filled in. A hop taken from
  DNS records is `derived` and is always a list of candidates, one or many.
* `protocol` None means the source did not record it. It is never read as tcp.
* **Read scope.** The finding is already readable by the caller
  (`_readable_finding`). Everything else here is data about OTHER assets:
  candidate hostnames and addresses, the address asset, and the port
  inventory. Each query that reads them carries `read_scope.asset_clause`, so
  a walk never passes through an asset the reader may not read, and nothing
  derived from one reaches the response. A withheld asset and a missing one
  produce the same hop, word for word: no status, count or reason may differ.
* Words are about the record, not the world: "not seen again", never "closed".
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime

from sqlalchemy import false, select
from sqlalchemy.orm import Session

from app.core.permissions import Permission, has_permission
from app.models.asset_canonical import AssetCanonical
from app.models.asset_edge import AssetEdge
from app.models.finding_canonical import FindingCanonical
from app.models.finding_endpoint import FindingEndpoint
from app.models.user import User
from app.schemas.exposure_path import (
    AddressHop,
    ExposurePath,
    FindingHop,
    HopCandidate,
    HostHop,
    InternetHop,
    PortHop,
    ServiceHop,
)
from app.services import projector, read_scope

# Sources whose observations are made from outside the network: our own
# scanners and analyzers working from their results, and Shodan. A source that
# is not listed gets an `unknown` internet hop rather than an assumed one, so a
# future inside-out connector has to be classified here deliberately.
EXTERNAL_SOURCES: frozenset[str] = frozenset({"nuclei", "shodan", "version_match", "constellus"})

# Finding types that are about a DNS record, where a port does not apply.
PORTLESS_FINDING_TYPES: frozenset[str] = frozenset({"dangling_dns"})

# Response-size bound on one hop's candidates (a shared address can have
# thousands of names), and the guard on how far a CNAME chain is followed.
MAX_CANDIDATES = 50
MAX_CHAIN_DEPTH = 8
_LEVEL_ROW_LIMIT = 500

_NODE = "asset_canonical"
# A CNAME step is normally a `resolves_to` edge; the hop into third-party CDN
# infrastructure is typed `cname` instead (planning#147). Both are DNS links.
_DNS_EDGE_TYPES = ("resolves_to", "cname")

# One reason per situation, shared by "no such asset" and "an asset the reader
# may not read": the two must be indistinguishable.
_NO_HOSTNAME = "The source saw this on the address, not on a hostname, and no hostname on record points at the address."
_DERIVED_HOSTNAMES = (
    "The source saw this on the address, not on a hostname. "
    "These hostnames point at the address in DNS records."
)
_NO_ADDRESS = "The source did not record the address it reached, and no address on record is linked to this hostname."
_DERIVED_ADDRESSES = (
    "The source did not record the address it reached. "
    "These addresses are what the hostname points at in DNS records."
)
_NO_INVENTORY_ENTRY = "This port is not in the port inventory on record for this address."


def build_exposure_paths(
    db: Session, user: User, finding: FindingCanonical, asset: AssetCanonical | None
) -> list[ExposurePath]:
    """Every exposure path of `finding`, which `user` is already known to be
    allowed to read. `asset` is the finding's own asset. Read-only."""
    return _Builder(db, user, finding, asset).build()


def _norm_name(name: str) -> str:
    return name.lower().rstrip(".")


def _host_address(value) -> str | None:
    """`value` (an INET column value or an asset's text) as a canonical host
    address, or None when it is not one."""
    if value is None:
        return None
    try:
        return str(ipaddress.ip_interface(str(value)).ip)
    except ValueError:
        return None


def _parse_time(value) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


class _Builder:
    def __init__(self, db: Session, user: User, finding: FindingCanonical, asset: AssetCanonical | None):
        self.db = db
        self.user = user
        self.finding = finding
        self.asset = asset
        self._address_ids: dict[str, uuid.UUID | None] = {}
        self._above: dict[uuid.UUID, tuple[list[HopCandidate], bool]] = {}
        self._below: tuple[list[HopCandidate], bool] | None = None
        self._ports: dict[uuid.UUID, list] = {}
        self._own_readable: bool | None = None

    # ── assembly ────────────────────────────────────────────────────────────

    def build(self) -> list[ExposurePath]:
        f = self.finding
        endpoints = (
            self.db.execute(
                select(FindingEndpoint)
                .where(FindingEndpoint.finding_id == f.id)
                .order_by(
                    FindingEndpoint.last_seen_at.desc(),
                    FindingEndpoint.address.asc().nulls_last(),
                    FindingEndpoint.port.asc().nulls_last(),
                    FindingEndpoint.protocol.asc().nulls_last(),
                    FindingEndpoint.id,
                )
            )
            .scalars()
            .all()
        )
        if not endpoints:
            return [self._path(None)]
        return [self._path(ep) for ep in endpoints]

    def _path(self, ep: FindingEndpoint | None) -> ExposurePath:
        f = self.finding
        if ep is None:
            observation = "not_recorded"
            first, last = f.first_seen_at, f.last_seen_at
        else:
            # finding_writer stamps the finding and every endpoint it re-observed
            # with one `now`, so an older endpoint was not in the latest observation.
            observation = "current" if ep.last_seen_at >= f.last_seen_at else "not_reobserved"
            first, last = ep.first_seen_at, ep.last_seen_at

        address = _host_address(ep.address) if ep is not None else None
        port = ep.port if ep is not None else None
        protocol = ep.protocol if ep is not None else None

        asset_is_host = self.asset is not None and self.asset.asset_type == "dns_record"
        own_address = (
            _host_address(self.asset.value)
            if self.asset is not None and self.asset.asset_type == "ip_address"
            else None
        )
        if address is None and own_address is not None:
            # The producer attached the finding to this address asset.
            address = own_address

        # The address asset, only if the reader may read it as an asset. It
        # gates everything taken from that asset: names above it, its ports.
        address_asset_id = self._readable_address_asset(address) if address is not None else None

        port_hop = self._port_hop(port, protocol, first, last)
        hops = [
            self._internet_hop(first, last),
            self._host_hop(asset_is_host, address, address_asset_id, first, last),
            self._address_hop(address, own_address, address_asset_id, asset_is_host, first, last),
            port_hop,
            self._service_hop(port_hop, protocol, address_asset_id, asset_is_host),
            FindingHop(
                status="observed",
                sources=[f.source],
                first_seen_at=f.first_seen_at,
                last_seen_at=f.last_seen_at,
                finding_id=f.id,
                finding_type=f.finding_type,
            ),
        ]
        return ExposurePath(
            endpoint_id=ep.id if ep is not None else None,
            observation=observation,
            first_seen_at=first,
            last_seen_at=last,
            hops=hops,
        )

    # ── hops ────────────────────────────────────────────────────────────────

    def _internet_hop(self, first, last) -> InternetHop:
        source = self.finding.source
        if source in EXTERNAL_SOURCES:
            return InternetHop(status="observed", sources=[source], first_seen_at=first, last_seen_at=last)
        return InternetHop(
            status="unknown",
            reason="It is not on record whether this source looks from the internet.",
        )

    def _host_hop(self, asset_is_host: bool, address, address_asset_id, first, last) -> HostHop:
        if asset_is_host:
            return HostHop(
                status="observed",
                sources=[self.finding.source],
                first_seen_at=first,
                last_seen_at=last,
                asset_id=self.asset.id,
                hostname=self.asset.value,
            )
        if address is None:
            return HostHop(status="unknown", reason="No hostname or address is recorded for this finding.")
        candidates, truncated = self._hostnames_above(address_asset_id) if address_asset_id else ([], False)
        if not candidates:
            return HostHop(status="unknown", reason=_NO_HOSTNAME)
        return HostHop(
            status="derived",
            reason=_DERIVED_HOSTNAMES,
            candidates=candidates,
            candidates_truncated=truncated,
        )

    def _address_hop(self, address, own_address, address_asset_id, asset_is_host, first, last) -> AddressHop:
        if address is not None:
            # The finding's own asset id is already part of the response; any
            # other address asset is linked only when the reader may read it.
            asset_id = self.asset.id if own_address == address else address_asset_id
            return AddressHop(
                status="observed",
                sources=[self.finding.source],
                first_seen_at=first,
                last_seen_at=last,
                asset_id=asset_id,
                address=address,
            )
        if not asset_is_host:
            return AddressHop(status="unknown", reason="The source did not record an address.")
        candidates, truncated = self._addresses_below()
        if not candidates:
            return AddressHop(status="unknown", reason=_NO_ADDRESS)
        return AddressHop(
            status="derived",
            reason=_DERIVED_ADDRESSES,
            candidates=candidates,
            candidates_truncated=truncated,
        )

    def _port_hop(self, port, protocol, first, last) -> PortHop:
        if port is None:
            if self.finding.finding_type in PORTLESS_FINDING_TYPES:
                return PortHop(status="not_applicable", reason="This finding is about a DNS record, not a port.")
            return PortHop(status="unknown", reason="The source did not record a port.")
        return PortHop(
            status="observed",
            reason=None if protocol else "The source recorded the port but not the protocol.",
            sources=[self.finding.source],
            first_seen_at=first,
            last_seen_at=last,
            port=port,
            protocol=protocol,
        )

    def _service_hop(self, port_hop: PortHop, protocol, address_asset_id, asset_is_host) -> ServiceHop:
        if port_hop.status == "not_applicable":
            return ServiceHop(status="not_applicable", reason="This finding is about a DNS record, not a service.")
        if port_hop.port is None:
            return ServiceHop(status="unknown", reason="No port is recorded, so no service can be matched to it.")

        # The address asset's inventory first. A CDN-fronted hostname carries
        # its port rows on the hostname asset instead, so the finding's own
        # hostname is the fallback.
        inventory_ids = [address_asset_id] if address_asset_id else []
        if asset_is_host and self._own_asset_readable():
            inventory_ids.append(self.asset.id)
        entry, inventory_id = None, None
        for asset_id in inventory_ids:
            entry = self._port_entry(asset_id, port_hop.port)
            if entry is not None:
                inventory_id = asset_id
                break
        if entry is None:
            return ServiceHop(status="unknown", reason=_NO_INVENTORY_ENTRY)

        raw_sources = entry.get("sources")
        sources = [s for s in raw_sources if isinstance(s, str)] if isinstance(raw_sources, list) else []
        seen = _parse_time(entry.get("last_seen_at"))
        inv_protocol = entry.get("protocol") if isinstance(entry.get("protocol"), str) else None
        common = dict(sources=sources, last_seen_at=seen, asset_id=inventory_id, protocol=inv_protocol)

        # The inventory is keyed by port number alone, so its entry may be the
        # other transport's.
        if protocol and inv_protocol and inv_protocol.lower() != protocol:
            return ServiceHop(
                status="unknown",
                reason=(
                    f"The port inventory lists this port number as {inv_protocol.lower()}; "
                    f"the finding was seen on {protocol}."
                ),
                **common,
            )
        service = entry.get("service") if isinstance(entry.get("service"), str) and entry.get("service") else None
        version = (
            entry.get("service_version")
            if isinstance(entry.get("service_version"), str) and entry.get("service_version")
            else None
        )
        if service is None and version is None:
            return ServiceHop(
                status="unknown",
                reason="The port is in the port inventory, but no service was identified on it.",
                **common,
            )
        return ServiceHop(status="observed", service=service, version=version, **common)

    # ── scoped reads of other assets ────────────────────────────────────────

    def _clause(self, entity):
        # The route's gate is findings.read. Every role holds assets.read as
        # well today; if that ever splits, a reader without it gets no data
        # about other assets here.
        if not has_permission(self.user, Permission.ASSETS_READ):
            return false()
        return read_scope.asset_clause(self.user, entity)

    def _own_asset_readable(self) -> bool:
        if self._own_readable is None:
            A = AssetCanonical
            self._own_readable = (
                self.db.execute(select(A.id).where(A.id == self.asset.id, self._clause(A))).first() is not None
            )
        return self._own_readable

    def _readable_address_asset(self, address: str) -> uuid.UUID | None:
        if address not in self._address_ids:
            A = AssetCanonical
            # Asset values are stored as the connector sent them, so an IPv6
            # asset may be in either the compressed or the full form.
            forms = {address, ipaddress.ip_address(address).exploded}
            self._address_ids[address] = self.db.execute(
                select(A.id)
                .where(A.asset_type == "ip_address", A.value.in_(forms), self._clause(A))
                .order_by(A.id)
                .limit(1)
            ).scalar_one_or_none()
        return self._address_ids[address]

    def _port_entry(self, asset_id: uuid.UUID, port: int) -> dict | None:
        """`asset_id`'s inventory entry for `port`. Callers pass only assets
        that passed `asset_clause`."""
        if asset_id not in self._ports:
            self._ports[asset_id] = projector.open_ports_by_asset(self.db, [asset_id]).get(asset_id, [])
        for entry in self._ports[asset_id]:
            if isinstance(entry, dict) and type(entry.get("port")) is int and entry["port"] == port:
                return entry
        return None

    def _hostnames_above(self, address_asset_id: uuid.UUID) -> tuple[list[HopCandidate], bool]:
        if address_asset_id not in self._above:
            self._above[address_asset_id] = self._walk([address_asset_id], upward=True)
        return self._above[address_asset_id]

    def _addresses_below(self) -> tuple[list[HopCandidate], bool]:
        if self._below is None:
            self._below = self._walk(self._record_ids_for_names([self.asset.value]), upward=False)
        return self._below

    def _record_ids_for_names(self, names) -> list[uuid.UUID]:
        """Every readable dns_record row for `names`. A hostname has one row
        per record, and a CNAME edge points at any one of them."""
        names = list(names)
        if not names:
            return []
        A = AssetCanonical
        return list(
            self.db.execute(
                select(A.id)
                .where(A.asset_type == "dns_record", A.value.in_(names), self._clause(A))
                .order_by(A.id)
                .limit(_LEVEL_ROW_LIMIT)
            ).scalars()
        )

    def _walk(self, start_ids: list[uuid.UUID], *, upward: bool) -> tuple[list[HopCandidate], bool]:
        """Follow DNS edges from `start_ids`, level by level.

        Upward (from an address): collect the hostnames that point at it, then
        the names that CNAME to those. Downward (from a hostname's records):
        follow CNAMEs and collect the addresses they end at. Every asset read
        passes `asset_clause`, so the walk stops at one the reader may not
        read. Returns (candidates, truncated).
        """
        A = AssetCanonical
        near, far = (AssetEdge.target_id, AssetEdge.source_id) if upward else (AssetEdge.source_id, AssetEdge.target_id)
        wanted = "dns_record" if upward else "ip_address"

        # Keyed by name: a hostname has one asset row per DNS record, and it is
        # one candidate, listed at the nearest row that links it.
        found: dict[str, HopCandidate] = {}
        truncated = False
        frontier = list(start_ids)
        expanded_ids: set[uuid.UUID] = set(start_ids)
        expanded_names: set[str] = set()

        for distance in range(1, MAX_CHAIN_DEPTH + 1):
            if not frontier:
                break
            rows = self.db.execute(
                select(
                    A.id, A.asset_type, A.value,
                    AssetEdge.edge_metadata, AssetEdge.first_seen_at, AssetEdge.last_seen_at,
                )
                .join(AssetEdge, far == A.id)
                .where(
                    near.in_(frontier),
                    AssetEdge.source_type == _NODE,
                    AssetEdge.target_type == _NODE,
                    AssetEdge.edge_type.in_(_DNS_EDGE_TYPES),
                    A.asset_type.in_(("dns_record", "ip_address")),
                    self._clause(A),
                )
                .order_by(A.value, A.id)
                .limit(_LEVEL_ROW_LIMIT + 1)
            ).all()
            if len(rows) > _LEVEL_ROW_LIMIT:
                truncated = True
                rows = rows[:_LEVEL_ROW_LIMIT]

            next_names: list[str] = []
            for asset_id, asset_type, value, metadata, link_first, link_last in rows:
                if asset_type == wanted and _norm_name(value) not in found:
                    record_type = (metadata or {}).get("record_type") if isinstance(metadata, dict) else None
                    found[_norm_name(value)] = HopCandidate(
                        asset_id=asset_id,
                        asset_type=asset_type,
                        value=value,
                        record_type=record_type if isinstance(record_type, str) else None,
                        distance=distance,
                        link_first_seen_at=link_first,
                        link_last_seen_at=link_last,
                    )
                if asset_type == "dns_record" and _norm_name(value) not in expanded_names:
                    expanded_names.add(_norm_name(value))
                    next_names.append(value)

            if len(found) > MAX_CANDIDATES:
                truncated = True
                break
            # The next level starts from every record row of the names just
            # reached; `expanded_names` is what stops a CNAME loop.
            frontier = [i for i in self._record_ids_for_names(next_names) if i not in expanded_ids]
            expanded_ids.update(frontier)

        candidates = sorted(found.values(), key=lambda c: (c.distance, c.value, str(c.asset_id)))
        return candidates[:MAX_CANDIDATES], truncated
