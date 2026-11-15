"""Build the attribution of an asset at read time (planning#358).

The chains of records that link an asset to an organization (organization,
entities, scope, hostnames, the asset itself), and the ownership verdict on
record for it. Assembled on read because the links change between scans and
decisions; only what a source recorded is stored.

Rules this module keeps:

* A link no record states is `unknown` or `derived`, never filled in. A link
  with no evidence row has no tier (`attribution_tiers`).
* The chain says how the record links the asset to an organization. Whether
  the asset is ours is `ownership`, the projected estate, and is never
  inferred from the chain.
* Several chains are all listed. Nothing is promoted over another.
* **Read scope.** The asset is already readable by the caller (the route
  checked). Everything else here is data about OTHER rows: targets,
  organizations, relations, candidates and their signals, and other assets
  (candidate hostnames). Each query that reads them carries the matching
  `read_scope` clause, and a reader without the matching permission gets
  `false()`: targets `targets.read` + `target_clause`, entities `entities.read`
  + `entity_clause`, relations `entities.read` + `relation_clause`, candidates
  and signals `entities.read` + `domain_clause`, other assets `assets.read` +
  `asset_clause`. A row the reader may not read and a row that does not exist
  produce the same output, word for word: no status, count or reason may
  differ. The asset's own claims and links are read without a clause.
* Words are about the record, not the world.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum

from sqlalchemy import and_, case, false, or_, select
from sqlalchemy.orm import Session

from app.core.permissions import Permission, has_permission
from app.models.asset_canonical import AssetCanonical
from app.models.claim import AssetClaim
from app.models.entity_relation import EntityRelation
from app.models.observer import Observer
from app.models.org_entity import OrgEntity
from app.models.scope_candidate import ScopeCandidate, ScopeSignal
from app.models.target import Target
from app.models.target_asset_link import TargetAssetLink
from app.models.user import User
from app.schemas.attribution_chain import (
    AddressHop,
    Attribution,
    AttributionChain,
    ClaimEvidence,
    EntityHop,
    HostHop,
    OrganizationHop,
    Ownership,
    RelationEvidence,
    ScopeHop,
    SignalEvidence,
)
from app.services import attribution_tiers, claims_query, dns_walk, read_scope, target_scope
from app.services.org_discovery import tiers

# Response-size bounds: rows listed per hop, chains returned, and how far up
# the organization graph one path is followed.
MAX_EVIDENCE_ROWS = 50
MAX_CHAINS = 20
MAX_DEPTH = 12

_NO_TARGET = "No target on record covers this asset."
_NO_TARGET_ORG = "No target on record covers this asset, so no organization is linked to it."
_NO_ORG_ON_TARGET = "No organization is recorded for this target."
_NO_ORG_ABOVE_ENTITY = (
    "No confirmed relation links this entity to an organization marked as yours or as an acquisition target."
)
_SCOPE_NO_CANDIDATE = "The target record names this organization. No candidate record is on file for the link."
_DERIVED_NAMES_ABOVE_HOST = "These hostnames under the target point at this host in DNS records."
_NO_NAME_ABOVE_HOST = "No DNS record on file links a hostname under this target to this host."
_DERIVED_NAMES_ABOVE_ADDRESS = "These hostnames under the target point at this address in DNS records."
_NO_NAME_ABOVE_ADDRESS = "No DNS record on file links a hostname under this target to this address."
_WALK_CUT_SHORT = (
    "More DNS records lead here than were read. None of those read is a hostname under this target."
)
_DERIVED_BY_NAME = "No discovery under this target recorded this asset. Its name is under the target's domain."
_DERIVED_BY_PARENT = (
    "No discovery under this target recorded this address. "
    "The hostname recorded as its parent is under the target's domain."
)
_DERIVED_BY_RANGE = "The address is inside the target's range."
_CLAIMED = "A check found this address serving a name of yours. No credentialed inventory confirms it."
_NOT_OURS_THIRD_PARTY = "This name is outside every target's domain and was reached through a CNAME record."
_NOT_OURS_REJECTED = "The ownership check found this address on shared infrastructure."
_NO_OWNERSHIP_CHECK = "No ownership check is recorded for this asset."


def build_attribution(db: Session, user: User, asset: AssetCanonical) -> Attribution:
    """The attribution of `asset`, which `user` is already known to be allowed
    to read. Read-only: no flush, no commit."""
    return _Builder(db, user, asset).build()


def _under(name: str, domain: str) -> bool:
    n, d = name.lower().rstrip("."), domain.lower().rstrip(".")
    return n == d or n.endswith("." + d)


def _enum_value(value):
    return value.value if isinstance(value, Enum) else value


@dataclass
class _Link:
    """One step up the organization graph: the relation that links an entity
    to the one above it, and the confirmed rows (one per source) behind it."""

    relation: str
    rows: list  # (EntityRelation, observer name)


@dataclass
class _Parent:
    entity: OrgEntity
    link: _Link


@dataclass
class _Path:
    # Entities from the target's own entity upward, and the links between
    # neighbours (links[i] joins nodes[i] to nodes[i + 1]).
    nodes: list[OrgEntity]
    links: list[_Link]
    # The last node is an entity marked ours or an acquisition target.
    stopped: bool


@dataclass
class _Sightings:
    listed: list = field(default_factory=list)
    truncated: bool = False
    tier: str | None = None


class _Builder:
    def __init__(self, db: Session, user: User, asset: AssetCanonical):
        self.db = db
        self.user = user
        self.asset = asset
        self._entities: dict[uuid.UUID, OrgEntity | None] = {}
        self._walks: dict[tuple, tuple[list, bool]] = {}
        self._sightings: _Sightings | None = None

    # ── assembly ────────────────────────────────────────────────────────────

    def build(self) -> Attribution:
        chains, truncated = self._chains()
        return Attribution(ownership=self._ownership(), chains=chains, chains_truncated=truncated)

    def _chains(self) -> tuple[list[AttributionChain], bool]:
        targets = self._targets()
        if not targets:
            return [self._chain_without_target()], False
        links = self._links([t.id for t in targets])
        chains: list[AttributionChain] = []
        for target in targets:
            scope = self._scope_hop(target)
            tail = self._tail_hops(target, links.get(target.id))
            for org, entity_hops in self._organization_hops(target):
                if len(chains) >= MAX_CHAINS:
                    return chains, True
                chains.append(AttributionChain(target_id=target.id, hops=[org, *entity_hops, scope, *tail]))
        return chains, False

    def _chain_without_target(self) -> AttributionChain:
        hops = [
            OrganizationHop(status="unknown", reason=_NO_TARGET_ORG),
            ScopeHop(status="unknown", reason=_NO_TARGET),
            self._asset_hop(None, None),
        ]
        return AttributionChain(target_id=None, hops=hops)

    # ── scoped clauses ──────────────────────────────────────────────────────

    def _target_clause(self, entity):
        if not has_permission(self.user, Permission.TARGETS_READ):
            return false()
        return read_scope.target_clause(self.user, entity)

    def _entity_clause(self, entity):
        if not has_permission(self.user, Permission.ENTITIES_READ):
            return false()
        return read_scope.entity_clause(self.user, entity)

    def _relation_clause(self, relation):
        if not has_permission(self.user, Permission.ENTITIES_READ):
            return false()
        return read_scope.relation_clause(self.user, relation)

    def _domain_clause(self, candidate):
        if not has_permission(self.user, Permission.ENTITIES_READ):
            return false()
        return read_scope.domain_clause(self.user, candidate)

    def _asset_clause(self, entity):
        if not has_permission(self.user, Permission.ASSETS_READ):
            return false()
        return read_scope.asset_clause(self.user, entity)

    # ── targets and the asset's links to them ───────────────────────────────

    def _targets(self) -> list[Target]:
        A = AssetCanonical
        return list(
            self.db.execute(
                select(Target)
                .join(A, and_(A.id == self.asset.id, target_scope.asset_falls_under(A, Target)))
                .where(self._target_clause(Target))
                .order_by(Target.created_at, Target.id)
            ).scalars()
        )

    def _links(self, target_ids: list[uuid.UUID]) -> dict[uuid.UUID, TargetAssetLink]:
        rows = self.db.execute(
            select(TargetAssetLink).where(
                TargetAssetLink.asset_canonical_id == self.asset.id,
                TargetAssetLink.target_id.in_(target_ids),
            )
        ).scalars()
        return {r.target_id: r for r in rows}

    # ── organization and entities ───────────────────────────────────────────

    def _entity(self, entity_id: uuid.UUID | None) -> OrgEntity | None:
        if entity_id is None:
            return None
        if entity_id not in self._entities:
            self._entities[entity_id] = self.db.execute(
                select(OrgEntity).where(OrgEntity.id == entity_id, self._entity_clause(OrgEntity))
            ).scalar_one_or_none()
        return self._entities[entity_id]

    def _organization_hops(self, target: Target) -> list[tuple[OrganizationHop, list[EntityHop]]]:
        entity = self._entity(target.entity_id)
        if entity is None:
            return [(OrganizationHop(status="unknown", reason=_NO_ORG_ON_TARGET), [])]
        out: list[tuple[OrganizationHop, list[EntityHop]]] = []
        for path in self._paths_up(entity):
            if path.stopped:
                org = self._stop_hop(path.nodes[-1])
                below = path.nodes[:-1]
            else:
                org = OrganizationHop(status="unknown", reason=_NO_ORG_ABOVE_ENTITY)
                below = path.nodes
            hops: list[EntityHop] = []
            for i in range(len(below) - 1, -1, -1):
                link = path.links[i] if i < len(path.links) else None
                hops.append(self._entity_hop(below[i], link))
            out.append((org, hops))
        return out

    def _stop_hop(self, entity: OrgEntity) -> OrganizationHop:
        ours = entity.relationship == "ours"
        return OrganizationHop(
            status="observed",
            entity_id=entity.id,
            name=entity.legal_name,
            relationship=entity.relationship,
            marked_at=entity.ours_authorised_at if ours else None,
            marked_by_id=entity.ours_authorised_by_id if ours else None,
        )

    def _entity_hop(self, entity: OrgEntity, link: _Link | None) -> EntityHop:
        if link is None:
            return EntityHop(status="observed", entity_id=entity.id, name=entity.legal_name)
        evidence = [self._relation_evidence(row, observer) for row, observer in link.rows]
        listed, truncated = _cap(evidence)
        return EntityHop(
            status="observed",
            entity_id=entity.id,
            name=entity.legal_name,
            relation=link.relation,
            evidence=listed,
            evidence_truncated=truncated,
            tier=attribution_tiers.highest(e.tier for e in evidence),
        )

    def _relation_evidence(self, row: EntityRelation, observer: str | None) -> RelationEvidence:
        return RelationEvidence(
            relation_id=row.id,
            relation=row.relation,
            source=observer,
            tier=attribution_tiers.RELATION_TIER,
            event_date=row.event_date,
            event_date_precision=row.event_date_precision,
            evidence_id=row.evidence_id,
            confirmed_by=row.decision_kind,
            confirmed_at=row.decided_at,
        )

    def _paths_up(self, start: OrgEntity) -> list[_Path]:
        """Every path from `start` up through confirmed relations to the
        nearest entity marked ours or an acquisition target (never walking
        past one), or to where no confirmed readable parent is left. One path
        per distinct route; none is preferred. Stops collecting once more
        than `MAX_CHAINS` paths exist, as the caller keeps no more."""
        out: list[_Path] = []

        def go(nodes: list[OrgEntity], links: list[_Link]) -> None:
            current = nodes[-1]
            if current.relationship is not None:
                out.append(_Path(nodes, links, stopped=True))
                return
            seen = {n.id for n in nodes}
            parents = [] if len(links) >= MAX_DEPTH else self._parents(current.id)
            parents = [p for p in parents if p.entity.id not in seen]
            if not parents:
                out.append(_Path(nodes, links, stopped=False))
                return
            for parent in parents:
                if len(out) > MAX_CHAINS:
                    return
                go([*nodes, parent.entity], [*links, parent.link])

        go([start], [])
        return out

    def _parents(self, entity_id: uuid.UUID) -> list[_Parent]:
        """Confirmed readable parents of `entity_id`, ordered by entity id and
        relation. The direction rule is `entity_relationship.parents`'
        (`subsidiary_of`: the subject is the child; `acquired`: the object is),
        with the relation and entity clauses on every row read."""
        R = EntityRelation
        parent_id = case((R.relation == "subsidiary_of", R.object_id), else_=R.subject_id)
        rows = self.db.execute(
            select(R, Observer.name, OrgEntity)
            .join(Observer, Observer.id == R.observer_id)
            .join(OrgEntity, OrgEntity.id == parent_id)
            .where(
                R.status == "confirmed",
                or_(
                    and_(R.relation == "subsidiary_of", R.subject_id == entity_id),
                    and_(R.relation == "acquired", R.object_id == entity_id),
                ),
                parent_id != entity_id,
                self._relation_clause(R),
                self._entity_clause(OrgEntity),
            )
            .order_by(R.created_at, R.id)
        ).all()
        grouped: dict[tuple[uuid.UUID, str], _Parent] = {}
        for relation, observer, parent in rows:
            key = (parent.id, relation.relation)
            if key not in grouped:
                grouped[key] = _Parent(parent, _Link(relation.relation, []))
            grouped[key].link.rows.append((relation, observer))
        return [grouped[k] for k in sorted(grouped)]

    # ── scope ───────────────────────────────────────────────────────────────

    def _scope_hop(self, target: Target) -> ScopeHop:
        hop = ScopeHop(
            status="observed",
            target_id=target.id,
            target_type=_enum_value(target.type),
            value=target.value,
            first_seen_at=target.created_at,
        )
        C = ScopeCandidate
        candidate = self.db.execute(
            select(C)
            .where(C.target_id == target.id, C.status == "claimed", self._domain_clause(C))
            .order_by(C.decided_at, C.id)
            .limit(1)
        ).scalar_one_or_none()
        if candidate is None:
            if self._entity(target.entity_id) is not None:
                hop.reason = _SCOPE_NO_CANDIDATE
            return hop
        S = ScopeSignal
        rows = self.db.execute(
            select(S, Observer.name)
            .outerjoin(Observer, Observer.id == S.observer_id)
            .where(S.candidate_id == candidate.id)
            .order_by(S.first_seen_at, S.id)
        ).all()
        evidence = [self._signal_evidence(signal, observer) for signal, observer in rows]
        hop.candidate_id = candidate.id
        hop.claimed_at = candidate.decided_at
        hop.claimed_by_id = candidate.decided_by_id
        hop.evidence, hop.evidence_truncated = _cap(evidence)
        hop.tier = attribution_tiers.highest(e.tier for e in evidence)
        return hop

    def _signal_evidence(self, signal: ScopeSignal, observer: str | None) -> SignalEvidence:
        # Never the signal's quote or matched values: they can name other candidates.
        spec = tiers.SIGNALS.get(signal.signal_type)
        return SignalEvidence(
            signal_id=signal.id,
            signal_type=signal.signal_type,
            label=spec.label if spec is not None else None,
            source=observer,
            tier=attribution_tiers.signal_tier(signal.signal_type),
            evidence_id=signal.evidence_id,
            first_seen_at=signal.first_seen_at,
            last_seen_at=signal.last_seen_at,
        )

    # ── hostnames between the scope and the asset, then the asset ───────────

    def _tail_hops(self, target: Target, link: TargetAssetLink | None) -> list:
        a = self.asset
        domain = _enum_value(target.type) == "domain"
        hops: list = []
        if domain and a.asset_type == "dns_record" and not _under(a.value, target.value):
            # A third-party name reached by CNAME: the names under the target
            # that point at it stand in for the host.
            start_ids = dns_walk.record_ids_for_names(self.db, self._asset_clause, [a.value])
            candidates, truncated = self._names_above(start_ids, target.value, ("rec", a.value, target.value))
            hops.append(self._derived_host(candidates, truncated, _DERIVED_NAMES_ABOVE_HOST, _NO_NAME_ABOVE_HOST))
        elif domain and a.asset_type == "ip_address":
            candidates, truncated = self._names_above([a.id], target.value, ("ip", a.id, target.value))
            hops.append(self._derived_host(candidates, truncated, _DERIVED_NAMES_ABOVE_ADDRESS, _NO_NAME_ABOVE_ADDRESS))
        hops.append(self._asset_hop(target, link))
        return hops

    def _names_above(self, start_ids, domain: str, key: tuple) -> tuple[list, bool]:
        if key not in self._walks:
            # Only names under the target are kept, and the cap counts those
            # alone: an address shared with other parties' names still lists
            # this target's.
            self._walks[key] = dns_walk.walk(
                self.db, self._asset_clause, start_ids, upward=True, keep=lambda name: _under(name, domain)
            )
        return self._walks[key]

    def _derived_host(self, candidates, truncated: bool, derived: str, unknown: str) -> HostHop:
        if not candidates:
            # A walk cut short read only part of the records, so "none on
            # file" would claim more than was looked at.
            return HostHop(status="unknown", reason=_WALK_CUT_SHORT if truncated else unknown)
        return HostHop(status="derived", reason=derived, candidates=candidates, candidates_truncated=truncated)

    def _asset_hop(self, target: Target | None, link: TargetAssetLink | None):
        a = self.asset
        sightings = self._asset_sightings()
        common = dict(
            asset_id=a.id,
            evidence=sightings.listed,
            evidence_truncated=sightings.truncated,
            tier=sightings.tier,
        )
        if target is None:
            common.update(status="unknown", reason=_NO_TARGET)
        elif link is not None:
            common.update(status="observed", first_seen_at=link.first_linked_at, last_seen_at=link.last_observed_at)
        elif _enum_value(target.type) != "domain":
            common.update(status="derived", reason=_DERIVED_BY_RANGE)
        elif a.asset_type == "ip_address":
            common.update(status="derived", reason=_DERIVED_BY_PARENT)
        else:
            common.update(status="derived", reason=_DERIVED_BY_NAME)
        if a.asset_type == "ip_address":
            return AddressHop(address=a.value, **common)
        return HostHop(hostname=a.value, **common)

    def _asset_sightings(self) -> _Sightings:
        if self._sightings is None:
            rows = self._claim_rows(attribution_tiers.SIGHTING_CLAIM_TYPES, AssetClaim.first_observed_at, AssetClaim.id)
            evidence = [
                self._claim_evidence(
                    claim, observer, trust, attribution_tiers.sighting_tier(claim.claim_type, trust), None
                )
                for claim, observer, trust in rows
            ]
            listed, truncated = _cap(evidence)
            self._sightings = _Sightings(listed, truncated, attribution_tiers.highest(e.tier for e in evidence))
        return self._sightings

    # ── ownership ───────────────────────────────────────────────────────────

    def _ownership(self) -> Ownership:
        surface = claims_query.surface(self.db, self.asset.id)
        rows = self._claim_rows(
            attribution_tiers.OWNERSHIP_CLAIM_TYPES,
            AssetClaim.claim_type, AssetClaim.first_observed_at, AssetClaim.id,
        )
        evidence = [
            self._claim_evidence(
                claim, observer, trust,
                attribution_tiers.ownership_tier(claim.claim_type, claim.claim_value),
                _outcome(claim.claim_type, claim.claim_value),
            )
            for claim, observer, trust in rows
        ]
        ours = surface in ("proven_ours", "claimed_ours")
        if surface == "proven_ours":
            reason = None
        elif surface == "claimed_ours":
            reason = _CLAIMED
        elif surface == "not_ours":
            third_party = any(c.claim_type == "third_party_dependency" for c, _o, _t in rows)
            reason = _NOT_OURS_THIRD_PARTY if third_party else _NOT_OURS_REJECTED
        else:
            reason = _NO_OWNERSHIP_CHECK
        return Ownership(
            surface=surface,
            reason=reason,
            evidence=evidence,
            tier=attribution_tiers.highest(e.tier for e in evidence) if ours else None,
        )

    # ── the asset's own claims ──────────────────────────────────────────────

    def _claim_rows(self, claim_types, *order) -> list:
        """The asset's own claim rows of `claim_types` with the observer's name
        and trust. Its own rows, so no read-scope clause."""
        return list(
            self.db.execute(
                select(AssetClaim, Observer.name, Observer.trust)
                .join(Observer, Observer.id == AssetClaim.observer_id)
                .where(AssetClaim.asset_canonical_id == self.asset.id, AssetClaim.claim_type.in_(sorted(claim_types)))
                .order_by(*order)
            ).all()
        )

    def _claim_evidence(self, claim: AssetClaim, observer: str, trust: str, tier, outcome) -> ClaimEvidence:
        return ClaimEvidence(
            claim_id=claim.id,
            claim_type=claim.claim_type,
            source=observer,
            source_trust=trust,
            tier=tier,
            outcome=outcome,
            first_seen_at=claim.first_observed_at,
            last_seen_at=claim.last_observed_at,
        )


def _cap(rows: list) -> tuple[list, bool]:
    return rows[:MAX_EVIDENCE_ROWS], len(rows) > MAX_EVIDENCE_ROWS


def _outcome(claim_type: str, claim_value) -> str | None:
    """What an ownership claim concluded. Only these fields of a claim's value
    are ever returned."""
    value = claim_value if isinstance(claim_value, dict) else {}
    if claim_type == "cloud_inventory":
        return "confirmed" if value.get("confirmed") is True else None
    if claim_type == "affinity_confirmation":
        verdict = value.get("verdict")
        return verdict if isinstance(verdict, str) else None
    if claim_type == "tenancy":
        tenancy = value.get("tenancy")
        return tenancy if isinstance(tenancy, str) else None
    if claim_type == "third_party_dependency":
        return "third_party_dependency"
    return None
