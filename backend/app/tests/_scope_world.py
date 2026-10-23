"""The read-scope world shared by test_read_scope.py and test_read_scope_api.py.

Engagements: E1 pre_close, E2 abandoned, E3 day_0.
Targets:     T1 domain `fabrikam.com` (E1); T2 cidr 198.51.100.0/24 (E2, no
             link rows); T3 domain `example.net` (E3); T0 domain `example.com`
             (no engagement).
Assets (one finding each, in `f`):
  a1     `www.fabrikam.com`            under T1 by name, no link
  a1L    `unrelated.example.org`       linked to T1 only
  a2     ip 198.51.100.7               under T2 by CIDR, no link
  a3     `api.example.net`             under T3 (day_0)
  a0     `www.example.com`             linked to T0 (no engagement)
  aMulti `multi.example.org`           linked to T1 and T3
  aBoth  ip 198.51.100.9               linked to T1 AND inside T2's CIDR

`close()` deletes every row the world made (findings, links, targets, assets,
engagements, in an order the RESTRICT keys allow).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.engagement import Engagement
from app.models.finding_canonical import FindingCanonical
from app.models.target import Target
from app.models.target_asset_link import TargetAssetLink
from app.tests._engagement import cleanup_engagement, make_engagement

ASSET_KEYS = ("a1", "a1L", "a2", "a3", "a0", "aMulti", "aBoth")


class ScopeWorld:
    def __init__(self):
        self.E: dict[str, uuid.UUID] = {}
        self.T: dict[str, uuid.UUID] = {}
        self.a: dict[str, uuid.UUID] = {}
        self.f: dict[str, uuid.UUID] = {}

    def build(self) -> "ScopeWorld":
        db = SessionLocal()
        now = datetime.now(timezone.utc)
        try:
            e1 = make_engagement(db, "pre_close")
            e2 = make_engagement(db, "abandoned")
            e3 = make_engagement(db, "day_0", authorised_at=now, authorisation_reference="read-scope-test")
            self.E = {"E1": e1.id, "E2": e2.id, "E3": e3.id}

            def target(key, type_, value, engagement_id):
                t = Target(id=uuid.uuid4(), type=type_, value=value, engagement_id=engagement_id)
                db.add(t)
                db.flush()
                self.T[key] = t.id

            target("T1", "domain", "fabrikam.com", e1.id)
            target("T2", "cidr", "198.51.100.0/24", e2.id)
            target("T3", "domain", "example.net", e3.id)
            target("T0", "domain", "example.com", None)

            def asset(key, asset_type, value, *linked):
                a = AssetCanonical(id=uuid.uuid4(), asset_type=asset_type, value=value, tags=[],
                                   first_seen_at=now, last_seen_at=now, ignored=False)
                db.add(a)
                db.flush()
                db.add(AssetState(asset_canonical_id=a.id, estate="claimed_ours", open_ports=[], projected_at=now))
                for t in linked:
                    db.add(TargetAssetLink(target_id=self.T[t], asset_canonical_id=a.id,
                                           first_linked_at=now, last_observed_at=now))
                db.add(FindingCanonical(
                    id=(fid := uuid.uuid4()), asset_canonical_id=a.id, finding_type="cve", source="test",
                    fingerprint=f"scope-{key}-{uuid.uuid4().hex[:8]}", severity="critical",
                    title=f"scope finding {key}", state="open", first_seen_at=now, last_seen_at=now,
                    detail={}, tags=[], cve_id=f"CVE-2099-{len(self.f) + 1:04d}", risk_score=90,
                    risk_band="imminent_compromise"))
                self.a[key] = a.id
                self.f[key] = fid

            asset("a1", "dns_record", "www.fabrikam.com")
            asset("a1L", "dns_record", "unrelated.example.org", "T1")
            asset("a2", "ip_address", "198.51.100.7")
            asset("a3", "dns_record", "api.example.net")
            asset("a0", "dns_record", "www.example.com", "T0")
            asset("aMulti", "dns_record", "multi.example.org", "T1", "T3")
            asset("aBoth", "ip_address", "198.51.100.9", "T1")
            db.commit()
        finally:
            db.close()
        return self

    def ids(self, *keys: str) -> set[uuid.UUID]:
        return {self.a[k] for k in keys}

    def close(self) -> None:
        db = SessionLocal()
        try:
            asset_ids = list(self.a.values())
            if asset_ids:
                db.query(FindingCanonical).filter(FindingCanonical.asset_canonical_id.in_(asset_ids)).delete(
                    synchronize_session=False)
                db.query(TargetAssetLink).filter(TargetAssetLink.asset_canonical_id.in_(asset_ids)).delete(
                    synchronize_session=False)
            db.query(Target).filter(Target.id.in_(list(self.T.values()))).delete(synchronize_session=False)
            if asset_ids:
                db.query(AssetCanonical).filter(AssetCanonical.id.in_(asset_ids)).delete(
                    synchronize_session=False)
            db.commit()
            for eid in self.E.values():
                cleanup_engagement(db, eid)
        finally:
            db.close()
