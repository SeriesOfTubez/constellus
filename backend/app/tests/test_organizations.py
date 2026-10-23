"""Add organization and the organizations API (planning#277 S1a).

Service tests call `organizations.add_organization` directly; API tests go
through the real app with real tokens (`AuditMiddleware` writes a row for each
mutating call). "Nothing written" is measured by counting rows in EVERY table
the call can touch, before and after.

A user who may create organizations but does not read every restricted
engagement does not exist in the shipped role table (only `admin` holds
`organizations.create`, and `admin` also holds `engagements.read_restricted`),
so those tests give `integration_admin` the one extra permission with
`monkeypatch.setitem(ROLE_PERMISSIONS, ...)`: the same global-assignment
mechanism, with the table widened for the test.

Run with:  scripts/test.sh app/tests/test_organizations.py
"""

import uuid

import pytest
from sqlalchemy import func, select

from app.core.permissions import ROLE_PERMISSIONS, Permission, has_permission
from app.models.audit import AuditLog
from app.models.engagement import Engagement
from app.models.entity_ingest_run import EntityIngestRun
from app.models.evidence import EvidenceFetch
from app.models.org_entity import OrgEntity
from app.models.role_assignment import RoleAssignment
from app.models.scope_candidate import ScopeCandidate, ScopeCandidateEvent, ScopeSignal
from app.models.target import Target
from app.models.user import UserRole
from app.services import organizations, read_scope
from app.services.org_discovery import candidates as cd
from app.services.org_discovery import strength as strength_sql
from app.tests._org_world import World, client, hexid
from app.tests.test_org_discovery_schema import _insert_candidate, _insert_signal

TABLES = (OrgEntity, Engagement, Target, ScopeCandidate, ScopeSignal, ScopeCandidateEvent, RoleAssignment,
          EntityIngestRun, EvidenceFetch)


@pytest.fixture
def w():
    world = World()
    world.actor = world.user()  # made up front so a before/after row count never sees it appear
    try:
        yield world
    finally:
        world.close()


def _counts(db) -> dict:
    db.rollback()
    return {t.__tablename__: db.execute(select(func.count()).select_from(t)).scalar_one() for t in TABLES}


def _domain() -> str:
    return f"org277-{hexid()}.example.com"


def _name() -> str:
    return f"Example Holdings {hexid()}"


def _kw(w, **over):
    name = over.pop("org_name", _name())
    w.entity_names.append(name)
    base = dict(
        seed_domain=_domain(), org_name=name, cik=None, relationship="ours", reference="board approval 277",
        engagement_name=None, may_mark_ours=True,
    )
    base.update(over)
    if "user" not in base:
        base["user"] = w.actor
    return base


def _widen(monkeypatch, role=UserRole.INTEGRATION_ADMIN.value, *extra):
    perms = ROLE_PERMISSIONS[role] | {Permission.ORGANIZATIONS_CREATE, *extra}
    monkeypatch.setitem(ROLE_PERMISSIONS, role, frozenset(perms))


def _track(w, result):
    w.track_target(result.candidate.value)
    w.entities.append(result.entity.id)
    if result.engagement is not None:
        w.engagements.append(result.engagement.id)


# ── 1. the ours path ────────────────────────────────────────────────────────


def test_adding_an_ours_organization_records_everything_in_one_commit(w):
    admin = w.user()
    kw = _kw(w, user=admin)
    result = organizations.add_organization(w.db, **kw)
    _track(w, result)
    e, c, t = result.entity, result.candidate, result.target

    assert (e.legal_name, e.cik, e.relationship, e.ours_reference, e.ours_authorised_by_id, e.created_by_id) == (
        kw["org_name"], None, "ours", "board approval 277", admin.id, admin.id,
    )
    assert e.ours_authorised_at is not None
    assert (result.engagement, result.assignment, result.ingest_run, result.engagement_created) == (None, None, None, False)

    assert (c.root_entity_id, c.value, c.status, c.affiliated_entity_id, c.accepted_into, c.engagement_id) == (
        e.id, kw["seed_domain"], "claimed", e.id, "estate", None,
    )
    assert (t.value, t.engagement_id, t.entity_id, t.verified, t.target_id if hasattr(t, "target_id") else None) == (
        kw["seed_domain"], None, e.id, True, None,
    )
    assert c.target_id == t.id
    sig = w.db.query(ScopeSignal).filter_by(candidate_id=c.id).one()
    assert (sig.signal_type, sig.anchor_kind, sig.anchor_user_id, sig.via_entity_id, sig.evidence_id) == (
        "admin_seed", "person", admin.id, e.id, None,
    )
    assert w.db.query(ScopeCandidateEvent).filter_by(candidate_id=c.id, event="claimed").count() == 1
    assert w.db.query(RoleAssignment).filter_by(engagement_id=None, user_id=admin.id).count() == 1  # only the global one


def test_the_organization_name_is_never_a_signal_input(w):
    """The seed's signal is about the DOMAIN; nothing derived from the name is stored."""
    kw = _kw(w, org_name="Example Holdings Zeta Nine")
    result = organizations.add_organization(w.db, **kw)
    _track(w, result)
    assert "zeta" not in result.candidate.value
    sig = w.db.query(ScopeSignal).filter_by(candidate_id=result.candidate.id).one()
    assert sig.quote is None and sig.evidence_id is None


# ── 2. the M&A path ─────────────────────────────────────────────────────────


def test_an_ma_organization_creates_a_pre_close_engagement_and_a_viewer_assignment(w, monkeypatch):
    _widen(monkeypatch)
    creator = w.user(UserRole.INTEGRATION_ADMIN.value)
    assert has_permission(creator, Permission.ORGANIZATIONS_CREATE)  # the precondition for this persona
    assert not has_permission(creator, Permission.ENGAGEMENTS_READ_RESTRICTED)
    kw = _kw(w, user=creator, relationship="ma_target", engagement_name=f"Project {hexid()}", may_mark_ours=False)
    result = organizations.add_organization(w.db, **kw)
    _track(w, result)
    e, eng = result.entity, result.engagement

    assert (e.relationship, e.ours_reference, e.ours_authorised_at) == ("ma_target", None, None)
    assert (eng.name, eng.posture, eng.subject_entity_id, eng.created_by_id) == (
        kw["engagement_name"], "pre_close", e.id, creator.id,
    )
    assert result.engagement_created is True
    # planning#277 S1a spec asked for the authorisation fields here; migration 0059's
    # ck_engagements_authorisation_matches_posture forbids them on a pre_close engagement.
    assert (eng.authorised_by_id, eng.authorised_at, eng.authorisation_reference) == (None, None, None)
    # ...but the reference is queryable on its own columns.
    assert (eng.deal_reference, eng.deal_reference_by_id) == (kw["reference"], creator.id)
    assert eng.deal_reference_at is not None

    assert (result.assignment.user_id, result.assignment.role, result.assignment.engagement_id) == (
        creator.id, "viewer", eng.id,
    )
    assert w.db.query(RoleAssignment).filter_by(user_id=creator.id, engagement_id=eng.id).count() == 1
    assert (result.target.engagement_id, result.target.entity_id, result.candidate.accepted_into,
            result.candidate.engagement_id) == (eng.id, e.id, "engagement", eng.id)


def test_an_ours_organization_creates_no_engagement_so_no_deal_reference(w):
    kw = _kw(w, reference="DEAL-0001")
    result = organizations.add_organization(w.db, **kw)
    _track(w, result)
    assert result.entity.ours_reference == "DEAL-0001"  # the path was reached: the reference landed on the entity
    assert result.engagement is None
    assert w.db.query(Engagement).filter(Engagement.subject_entity_id == result.entity.id).count() == 0


def test_an_admin_adding_an_ma_organization_gets_no_assignment(w):
    admin = w.user()
    kw = _kw(w, user=admin, relationship="ma_target", engagement_name=f"Project {hexid()}")
    result = organizations.add_organization(w.db, **kw)
    _track(w, result)
    assert result.assignment is None
    assert w.db.query(RoleAssignment).filter_by(user_id=admin.id, engagement_id=result.engagement.id).count() == 0
    assert result.engagement.posture == "pre_close"  # the path was reached


def test_ours_without_the_mark_ours_permission_is_forbidden_and_writes_nothing(w):
    kw = _kw(w, may_mark_ours=False)
    before = _counts(w.db)
    with pytest.raises(cd.CandidateForbidden):
        organizations.add_organization(w.db, **kw)
    assert _counts(w.db) == before


def test_a_duplicate_engagement_name_conflicts_and_writes_nothing(w):
    existing = w.engagement("pre_close")
    kw = _kw(w, relationship="ma_target", engagement_name=existing.name)
    before = _counts(w.db)
    with pytest.raises(Exception) as exc:
        organizations.add_organization(w.db, **kw)
    assert type(exc.value).__name__ == "RelationshipConflict" and "already exists" in str(exc.value)
    assert _counts(w.db) == before  # the entity created a step earlier was rolled back too


def test_a_seed_that_is_already_a_target_elsewhere_conflicts_and_writes_nothing(w):
    seed = _domain()
    elsewhere = w.engagement("pre_close")
    owned = Target(id=uuid.uuid4(), type="domain", value=seed, engagement_id=elsewhere.id)
    w.db.add(owned)
    w.db.commit()
    w.track_target(seed)
    before = _counts(w.db)
    # ours: the existing target sits in an engagement, not the estate
    with pytest.raises(cd.CandidateConflict, match="already a target elsewhere"):
        organizations.add_organization(w.db, **_kw(w, seed_domain=seed))
    assert _counts(w.db) == before
    # M&A: any existing target is elsewhere from a brand-new engagement
    with pytest.raises(cd.CandidateConflict, match="already a target elsewhere"):
        organizations.add_organization(
            w.db, **_kw(w, seed_domain=seed, relationship="ma_target", engagement_name=f"Project {hexid()}")
        )
    assert _counts(w.db) == before


def test_a_seed_in_the_estate_with_no_entity_is_attached_for_an_ours_organization(w):
    seed = _domain()
    estate = Target(id=uuid.uuid4(), type="domain", value=seed)
    w.db.add(estate)
    w.db.commit()
    w.track_target(seed)
    result = organizations.add_organization(w.db, **_kw(w, seed_domain=seed))
    _track(w, result)
    assert (result.target.id, result.target.entity_id, result.target.engagement_id) == (estate.id, result.entity.id, None)
    assert w.db.query(Target).filter(Target.value == seed).count() == 1
    # ...but a target already attributed to another entity is a conflict
    seed2 = _domain()
    other = w.entity()
    w.db.add(Target(id=uuid.uuid4(), type="domain", value=seed2, entity_id=other.id))
    w.db.commit()
    w.track_target(seed2)
    before = _counts(w.db)
    with pytest.raises(cd.CandidateConflict, match="already a target elsewhere"):
        organizations.add_organization(w.db, **_kw(w, seed_domain=seed2))
    assert _counts(w.db) == before


# ── 3. the CIK rules ────────────────────────────────────────────────────────


def test_a_cik_is_padded_and_queues_an_ingest_run(w):
    admin = w.user()
    cik = "99" + f"{uuid.uuid4().int % 10**6:06d}"
    result = organizations.add_organization(w.db, **_kw(w, user=admin, cik=cik))
    _track(w, result)
    assert result.entity.cik == cik.zfill(10)
    run = result.ingest_run
    assert (run.cik, run.status, run.kind, run.requested_by_id) == (cik.zfill(10), "queued", "edgar_ingest", admin.id)


def test_a_bare_entity_with_the_cik_is_reused_and_keeps_its_name(w):
    cik = "99" + f"{uuid.uuid4().int % 10**8:08d}"
    bare = w.entity(legal_name="Example Original Name Ltd", cik=cik)
    result = organizations.add_organization(w.db, **_kw(w, cik=cik, org_name="Example Typed Over Name Ltd"))
    _track(w, result)
    assert result.entity.id == bare.id
    w.db.refresh(bare)
    assert (bare.legal_name, bare.relationship) == ("Example Original Name Ltd", "ours")
    assert w.db.query(OrgEntity).filter(OrgEntity.cik == cik).count() == 1


def test_a_filer_that_is_already_an_organization_conflicts(w):
    cik = "99" + f"{uuid.uuid4().int % 10**8:08d}"
    root = w.ours(w.entity(cik=cik))
    before = _counts(w.db)
    with pytest.raises(cd.CandidateConflict, match="already an organization"):
        organizations.add_organization(w.db, **_kw(w, cik=cik))
    assert _counts(w.db) == before
    # An engagement subject too (here without the relationship column set, so the engagement check is what fires).
    cik2 = "99" + f"{uuid.uuid4().int % 10**8:08d}"
    subject = w.entity(cik=cik2)
    w.engagement("pre_close", subject=subject)
    w.db.execute(OrgEntity.__table__.update().where(OrgEntity.id == subject.id).values(relationship=None))
    w.db.commit()
    with pytest.raises(cd.CandidateConflict, match="already an organization"):
        organizations.add_organization(w.db, **_kw(w, cik=cik2))
    del root


def test_an_in_flight_ingest_does_not_stop_the_organization_being_added(w):
    cik = "99" + f"{uuid.uuid4().int % 10**8:08d}"
    w.db.add(EntityIngestRun(cik=cik, status="queued"))
    w.db.commit()
    result = organizations.add_organization(w.db, **_kw(w, cik=cik))
    _track(w, result)
    assert result.ingest_run is None
    assert result.entity.relationship == "ours" and result.candidate.status == "claimed"
    assert w.db.query(EntityIngestRun).filter(EntityIngestRun.cik == cik).count() == 1


@pytest.mark.parametrize("cik", ["abc", "12345678901", "", "12 34"])
def test_a_malformed_cik_is_refused(w, cik):
    before = _counts(w.db)
    with pytest.raises(cd.CandidateInvalid, match="cik"):
        organizations.add_organization(w.db, **_kw(w, cik=cik))
    assert _counts(w.db) == before


# ── 4. validation ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("over,message", [
    ({"org_name": "   "}, "organization name"),
    ({"org_name": "x" * 201}, "organization name"),
    ({"reference": "  "}, "reference"),
    ({"relationship": "partner"}, "relationship"),
    ({"relationship": "ma_target", "engagement_name": None}, "engagement name"),
    ({"relationship": "ma_target", "engagement_name": "  "}, "engagement name"),
    ({"relationship": "ours", "engagement_name": "Project X"}, "only for an M&A"),
    ({"seed_domain": "192.0.2.1"}, "not a domain"),
    ({"seed_domain": ""}, "not a domain"),
])
def test_invalid_input_is_refused_before_anything_is_written(w, over, message):
    before = _counts(w.db)
    with pytest.raises(cd.CandidateInvalid, match=message):
        organizations.add_organization(w.db, **_kw(w, **over))
    assert _counts(w.db) == before


def test_a_seed_the_old_root_still_holds_conflicts_without_writing(w):
    """A cleared root keeps its candidates (RESTRICT); adding it again must
    not claim a candidate that is not open."""
    cik = "99" + f"{uuid.uuid4().int % 10**8:08d}"
    first = organizations.add_organization(w.db, **_kw(w, cik=cik))
    _track(w, first)
    from app.services import entity_relationship
    entity_relationship.clear(w.db, entity_id=first.entity.id, may_clear_ours=True)
    before = _counts(w.db)
    with pytest.raises(cd.CandidateConflict, match="already a candidate"):
        organizations.add_organization(w.db, **_kw(w, cik=cik, seed_domain=first.candidate.value))
    assert _counts(w.db) == before


# ── 5. the API ──────────────────────────────────────────────────────────────


def _post_org(w, headers, **over):
    name = over.pop("org_name", _name())
    w.entity_names.append(name)
    body = {
        "seed_domain": _domain(), "org_name": name, "relationship": "ours", "reference": "board approval 277",
        **over,
    }
    w.track_target(body["seed_domain"])
    return client.post("/api/organizations/", json=body, headers=headers), body


def _audit(w, user_id, key, value):
    w.db.rollback()
    return (
        w.db.query(AuditLog)
        .filter(AuditLog.user_id == user_id, AuditLog.detail["changes"][key].astext == value)
        .all()
    )


def test_an_integration_admin_cannot_add_an_organization(w):
    r, _ = _post_org(w, w.headers(role=UserRole.INTEGRATION_ADMIN.value))
    assert r.status_code == 403
    r, _ = _post_org(w, w.headers(role=UserRole.VIEWER.value))
    assert r.status_code == 403
    admin_r, body = _post_org(w, w.headers())  # the path IS reachable for an admin
    assert admin_r.status_code == 201, admin_r.text


def test_post_organizations_ours_and_its_audit_detail(w):
    admin = w.user()
    r, body = _post_org(w, w.headers(admin))
    assert r.status_code == 201, r.text
    out = r.json()
    w.entities.append(uuid.UUID(out["organization_id"]))
    assert (out["relationship"], out["engagement"], out["assignment_role"], out["ingest"], out["ingest_run_id"]) == (
        "ours", None, None, "not_requested", None,
    )
    rows = _audit(w, admin.id, "organization", out["organization_id"])
    assert len(rows) == 1
    changes = rows[0].detail["changes"]
    assert changes == {
        "organization": out["organization_id"], "relationship": "ours", "reference": "board approval 277",
        "engagement": None, "engagement_created": False, "seed": body["seed_domain"], "assignment": None,
        "filer_cik_set": False,
    }
    assert not [k for k in changes if "auth" in k]  # audit.scrub would have redacted it


def test_post_organizations_ma_target_with_a_cik_schedules_the_ingest(w, monkeypatch):
    import app.api.entities as entities_api

    scheduled: list[tuple] = []
    monkeypatch.setattr(entities_api, "_run_ingest_then_read", lambda *a: scheduled.append(a))
    admin = w.user()
    cik = "99" + f"{uuid.uuid4().int % 10**8:08d}"
    r, body = _post_org(w, w.headers(admin), relationship="ma_target", engagement_name=f"Project {hexid()}", cik=cik)
    assert r.status_code == 201, r.text
    out = r.json()
    w.entities.append(uuid.UUID(out["organization_id"]))
    assert out["engagement"]["posture"] == "pre_close" and out["ingest"] == "queued"
    assert out["engagement"]["deal_reference"] == body["reference"].strip()
    assert len(scheduled) == 1
    run_id, entity_id, scheduled_cik, user_id, followup = scheduled[0]
    assert (str(run_id), str(entity_id), scheduled_cik, user_id) == (
        out["ingest_run_id"], out["organization_id"], cik.zfill(10), admin.id,
    )
    assert followup.__name__ == "_no_followup_for_ma_target"
    changes = _audit(w, admin.id, "organization", out["organization_id"])[0].detail["changes"]
    assert (changes["engagement_created"], changes["filer_cik_set"], changes["assignment"]) == (True, True, None)
    # no cik, no task
    scheduled.clear()
    r2, _ = _post_org(w, w.headers(admin))
    w.entities.append(uuid.UUID(r2.json()["organization_id"]))
    assert scheduled == []


def test_post_organizations_ours_schedules_the_onboarding_followup(w, monkeypatch):
    import app.api.entities as entities_api
    from app.services import onboarding

    scheduled: list[tuple] = []
    monkeypatch.setattr(entities_api, "_run_ingest_then_read", lambda *a: scheduled.append(a))
    cik = "99" + f"{uuid.uuid4().int % 10**8:08d}"
    r, _ = _post_org(w, w.headers(), cik=cik)
    assert r.status_code == 201, r.text
    w.entities.append(uuid.UUID(r.json()["organization_id"]))
    assert scheduled[0][4] is onboarding.followup_read


def test_post_organizations_errors_map_to_statuses(w, monkeypatch):
    _widen(monkeypatch)
    ops = w.headers(role=UserRole.INTEGRATION_ADMIN.value)
    r, _ = _post_org(w, ops, relationship="ours")
    assert r.status_code == 403 and "ours" in r.json()["detail"]   # no entities.mark_ours
    existing = w.engagement("pre_close")
    r, _ = _post_org(w, w.headers(), relationship="ma_target", engagement_name=existing.name)
    assert r.status_code == 409
    r, _ = _post_org(w, w.headers(), seed_domain="not a domain")
    assert r.status_code == 400
    r, _ = _post_org(w, w.headers(), relationship="ma_target")
    assert r.status_code == 400
    r, _ = _post_org(w, w.headers(), relationship="partner")
    assert r.status_code == 422                                     # pydantic
    r, _ = _post_org(w, ops, relationship="ma_target", engagement_name=f"Project {hexid()}")
    assert r.status_code == 201, r.text
    out = r.json()
    w.entities.append(uuid.UUID(out["organization_id"]))
    assert out["assignment_role"] == "viewer"      # the non-admin creator can see the deal


def _org_with_candidates(w, headers=None):
    """A root with a mix: strong, supporting (2 families), a lead, a claimed and a rejected."""
    root = w.ours()
    child = w.child_of(root)
    ids = {}
    ids["strong"] = w.candidate(root, via=child, value="a-strong.example.com").id
    # supporting: two families, inserted raw (types without a generator)
    ids["supp"] = _insert_candidate(w.db, root.id, value="b-supporting.example.com")
    for t in ("mx_into_claimed", "shared_vanity_ns"):
        ev = w.evidence_row()
        _insert_signal(w.db, ids["supp"], root.id, signal_type=t, evidence_id=ev.id, quote="q")
    ids["lead"] = _insert_candidate(w.db, root.id, value="c-lead.example.com")
    ev = w.evidence_row()
    _insert_signal(w.db, ids["lead"], root.id, signal_type="research_quote", evidence_id=ev.id, quote="q")
    ids["claimed"] = w.candidate(root, value="d-claimed.example.com").id
    claimed = cd.claim(w.db, candidate_id=ids["claimed"], user=w.user())
    w.track_target(claimed.target.value)
    ids["rejected"] = w.candidate(root, value="e-rejected.example.com").id
    cd.reject(w.db, candidate_id=ids["rejected"], user=w.user(), reason="a vendor")
    return root, child, ids


def test_list_organizations_summarises_roots_and_counts(w):
    root, _child, _ids = _org_with_candidates(w)
    deal, eng = w.deal()
    seeded = organizations.add_organization(w.db, **_kw(w, relationship="ma_target", engagement_name=f"Project {hexid()}"))
    _track(w, seeded)
    unset = w.entity()
    r = client.get("/api/organizations/", headers=w.headers(role=UserRole.VIEWER.value))
    assert r.status_code == 200
    by_id = {o["id"]: o for o in r.json()}
    assert str(unset.id) not in by_id                      # not a root
    o = by_id[str(root.id)]
    assert (o["relationship"], o["engagement"], o["seed_domain"]) == ("ours", None, None)  # a legacy root: no seed
    assert (o["claimed"], o["proposed"], o["leads"], o["rejected"]) == (1, 2, 1, 1)
    d = by_id[str(deal.id)]
    assert (d["relationship"], d["engagement"]["id"], d["engagement"]["posture"]) == ("ma_target", str(eng.id), "pre_close")
    s = by_id[str(seeded.entity.id)]
    assert s["seed_domain"] == seeded.candidate.value and s["claimed"] == 1 and s["engagement"]["name"] == seeded.engagement.name
    assert seeded.engagement.deal_reference and s["engagement"]["deal_reference"] == seeded.engagement.deal_reference
    assert d["engagement"]["deal_reference"] is None       # created without one


def test_candidates_default_to_open_and_proposable_sorted_by_strength(w):
    root, child, ids = _org_with_candidates(w)
    h = w.headers(role=UserRole.VIEWER.value)
    r = client.get(f"/api/organizations/{root.id}/candidates", headers=h)
    assert r.status_code == 200
    rows = r.json()
    assert [x["value"] for x in rows] == ["a-strong.example.com", "b-supporting.example.com"]  # no lead, no decided
    strong, supp = rows
    assert (strong["strength"], strong["proposable"], strong["status"]) == ("strong", True, "open")
    assert (supp["strength"], supp["proposable"]) == ("supporting", True)
    # default affiliate = the via entity of the best signal; flagged as a default
    assert (strong["affiliated"]["id"], strong["affiliated_is_default"]) == (str(child.id), True)
    assert strong["affiliated"]["name"] == child.legal_name
    assert strong["signals"] == [{"signal_type": "person_evidence", "tier": "strong", "family": "person", "count": 1}]
    assert {s["signal_type"] for s in supp["signals"]} == {"mx_into_claimed", "shared_vanity_ns"}
    assert strong["first_seen_at"] and strong["previously_rejected"] is None and strong["target_id"] is None


def test_candidate_filters(w):
    root, child, ids = _org_with_candidates(w)
    h = w.headers(role=UserRole.VIEWER.value)
    base = f"/api/organizations/{root.id}/candidates"

    def values(qs):
        r = client.get(f"{base}?{qs}", headers=h)
        assert r.status_code == 200, r.text
        return [x["value"] for x in r.json()]

    assert values("include_leads=true") == ["a-strong.example.com", "b-supporting.example.com", "c-lead.example.com"]
    assert values("status=claimed") == ["d-claimed.example.com"]
    assert values("status=rejected") == ["e-rejected.example.com"]
    assert values("status=all&include_leads=true") == [   # strength desc (claimed/rejected rank as their signals), then value
        "a-strong.example.com", "d-claimed.example.com", "e-rejected.example.com",
        "b-supporting.example.com", "c-lead.example.com",
    ]
    assert values("status=all") == ["a-strong.example.com", "d-claimed.example.com", "e-rejected.example.com",
                                    "b-supporting.example.com"]  # open leads hidden, decided ones shown
    assert values("strength=lead&include_leads=true") == ["c-lead.example.com"]
    assert values("strength=strong&status=all") == ["a-strong.example.com", "d-claimed.example.com", "e-rejected.example.com"]
    assert values(f"affiliated_entity_id={child.id}") == ["a-strong.example.com"]
    assert values(f"affiliated_entity_id={root.id}&status=claimed") == ["d-claimed.example.com"]
    assert values("status=all&include_leads=true&limit=2") == ["a-strong.example.com", "d-claimed.example.com"]
    assert values("status=all&include_leads=true&limit=2&offset=2") == ["e-rejected.example.com", "b-supporting.example.com"]
    for bad in ("limit=0", "limit=1001", "offset=-1", "status=nope", "strength=nope"):
        assert client.get(f"{base}?{bad}", headers=h).status_code == 422, bad


def test_a_stored_affiliate_is_not_flagged_as_a_default(w):
    root, _child, ids = _org_with_candidates(w)
    rows = client.get(f"/api/organizations/{root.id}/candidates?status=claimed", headers=w.headers()).json()
    assert (rows[0]["affiliated"]["id"], rows[0]["affiliated_is_default"]) == (str(root.id), False)
    assert rows[0]["target_id"] is not None


def test_candidates_404_for_unknown_and_non_root_organizations(w):
    h = w.headers(role=UserRole.VIEWER.value)
    assert client.get(f"/api/organizations/{uuid.uuid4()}/candidates", headers=h).status_code == 404
    assert client.get(f"/api/organizations/{w.entity().id}/candidates", headers=h).status_code == 404  # not a root
    assert client.get(f"/api/organizations/candidates/{uuid.uuid4()}", headers=h).status_code == 404
    root = w.ours()
    assert client.get(f"/api/organizations/{root.id}/candidates", headers=h).status_code == 200  # the path is reachable


def test_candidate_detail_has_every_signal_with_its_anchor_and_the_events(w):
    root, child, ids = _org_with_candidates(w)
    # a second, Supporting signal with a filer anchor on the strong candidate, plus a rejection and an unlock
    cid = ids["rejected"]
    cd.record_signal(w.db, root_entity_id=root.id, value="e-rejected.example.com", signal_type="admin_seed",
                     anchor_kind="person", via_entity_id=root.id)
    w.db.commit()
    r = client.get(f"/api/organizations/candidates/{cid}", headers=w.headers(role=UserRole.VIEWER.value))
    assert r.status_code == 200, r.text
    d = r.json()
    assert (d["status"], d["strength"], d["rejection_reason"]) == ("open", "strong", None)
    assert d["previously_rejected"]["reason"] == "a vendor"
    assert [e["event"] for e in d["events"]] == ["rejected", "unlocked"]
    assert d["events"][1]["reason"] == "a vendor" and d["events"][1]["signal_id"]
    types = {s["signal_type"]: s for s in d["signal_details"]}
    assert set(types) == {"person_evidence", "admin_seed"}
    assert types["admin_seed"]["anchor"]["kind"] == "person" and types["admin_seed"]["evidence_id"] is None
    assert types["person_evidence"]["quote"] and types["person_evidence"]["evidence_id"]
    assert types["person_evidence"]["via_entity"]["id"] == str(root.id)
    assert (types["admin_seed"]["tier"], types["admin_seed"]["family"]) == ("strong", "seed")

    # filer + claimed-candidate anchors are named
    filer = child
    filer.cik = "0000000077"
    w.db.commit()
    ev = w.evidence_row()
    cd.record_signal(w.db, root_entity_id=root.id, value="a-strong.example.com", signal_type="filer_10k_website",
                     anchor_kind="filer_filing", anchor_entity_id=filer.id, via_entity_id=filer.id,
                     evidence_id=ev.id, quote="Our website is a-strong.example.com")
    cd.record_signal(w.db, root_entity_id=root.id, value="a-strong.example.com", signal_type="redirect_to_claimed",
                     anchor_kind="claimed_candidate", anchor_candidate_id=ids["claimed"], via_entity_id=root.id,
                     evidence_id=w.evidence_row().id, quote="a-strong.example.com")
    w.db.commit()
    d = client.get(f"/api/organizations/candidates/{ids['strong']}", headers=w.headers()).json()
    anchors = {s["signal_type"]: s["anchor"] for s in d["signal_details"]}
    assert anchors["filer_10k_website"]["entity_name"] == filer.legal_name
    assert anchors["redirect_to_claimed"]["candidate_value"] == "d-claimed.example.com"


def test_add_claim_and_reject_over_http(w, monkeypatch):
    import app.api.targets as targets_api

    launched: list[tuple] = []
    monkeypatch.setattr(targets_api, "_prime_ct_and_launch", lambda v, run_id, scope: launched.append((v, run_id, scope)))
    root, eng = w.deal()
    admin = w.user()
    admin_h, viewer_h = w.headers(admin), w.headers(role=UserRole.VIEWER.value)
    d1, d2 = _domain(), _domain()
    body = lambda d: {  # noqa: E731
        "domain": d, "source_url": "https://news.example.test/deal",
        "excerpt": f"Deal announcement. The acquired business operates www.{d} today.", "quote": f"operates www.{d} today",
    }
    base = f"/api/organizations/{root.id}/candidates"

    assert client.post(base, json=body(d1), headers=viewer_h).status_code == 403
    r = client.post(base, json=body(d1), headers=admin_h)
    assert r.status_code == 201, r.text
    c1 = r.json()
    assert (c1["value"], c1["status"], c1["strength"], c1["proposable"]) == (d1, "open", "strong", True)
    w.evidence.extend(s.evidence_id for s in w.db.query(ScopeSignal).filter_by(candidate_id=uuid.UUID(c1["id"])))
    c2 = client.post(base, json=body(d2), headers=admin_h).json()
    w.evidence.extend(s.evidence_id for s in w.db.query(ScopeSignal).filter_by(candidate_id=uuid.UUID(c2["id"])))
    # bad domain -> 400; unknown organization -> 404; a company outside the tree -> 400
    assert client.post(base, json=body("not a domain"), headers=admin_h).status_code == 400
    assert client.post(f"/api/organizations/{uuid.uuid4()}/candidates", json=body(d1), headers=admin_h).status_code == 404
    assert client.post(base, json={**body(_domain()), "via_entity_id": str(w.entity().id)}, headers=admin_h).status_code == 400

    claim = f"/api/organizations/candidates/{c1['id']}/claim"
    assert client.post(claim, json={}, headers=viewer_h).status_code == 403
    assert client.post(f"/api/organizations/candidates/{uuid.uuid4()}/claim", json={}, headers=admin_h).status_code == 404
    r = client.post(claim, json={}, headers=admin_h)
    assert r.status_code == 200, r.text
    claimed = r.json()
    assert (claimed["status"], claimed["affiliated"]["id"], claimed["affiliated_is_default"]) == ("claimed", str(root.id), False)
    w.track_target(d1)
    target = w.db.query(Target).filter(Target.value == d1).one()
    assert (target.engagement_id, target.entity_id) == (eng.id, root.id)
    assert claimed["target_id"] == str(target.id)
    # Initial discovery was REACHED (queued and launched), scoped to exactly this domain.
    assert len(launched) == 1 and launched[0][0] == d1
    changes = _audit(w, admin.id, "candidate", c1["id"])
    assert any(a.detail["changes"].get("destination") == "engagement" for a in changes)
    detail = next(a.detail["changes"] for a in changes if a.detail["changes"].get("destination"))
    assert detail["target"] == str(target.id) and detail["created"] is True and detail["value"] == d1
    assert client.post(claim, json={}, headers=admin_h).status_code == 409   # already claimed
    assert client.post(claim, json={"affiliated_entity_id": "not-a-uuid"}, headers=admin_h).status_code == 422

    reject = f"/api/organizations/candidates/{c2['id']}/reject"
    assert client.post(reject, json={"reason": "no"}, headers=viewer_h).status_code == 403
    assert client.post(reject, json={}, headers=admin_h).status_code == 422
    assert client.post(reject, json={"reason": "   "}, headers=admin_h).status_code == 400
    r = client.post(reject, json={"reason": "a vendor"}, headers=admin_h)
    assert r.status_code == 200 and r.json()["status"] == "rejected"
    row = w.db.query(ScopeCandidate).filter(ScopeCandidate.id == uuid.UUID(c2["id"])).one()
    assert (row.rejection_reason, row.rejected_strong_types) == ("a vendor", ["person_evidence"])
    rej = _audit(w, admin.id, "candidate", c2["id"])
    assert any(a.detail["changes"].get("decision") == {"from": "open", "to": "rejected"} for a in rej)
    assert len(launched) == 1                                    # a rejection launches nothing
    assert client.post(reject, json={"reason": "again"}, headers=admin_h).status_code == 409


def test_claiming_a_lead_over_http_is_a_409(w):
    root = w.ours()
    lead = _insert_candidate(w.db, root.id, value=_domain())
    _insert_signal(w.db, lead, root.id, signal_type="research_quote", evidence_id=w.evidence_row().id, quote="q")
    r = client.post(f"/api/organizations/candidates/{lead}/claim", json={}, headers=w.headers())
    assert r.status_code == 409 and "not enough evidence" in r.json()["detail"]


# ── 6. the read_scope hooks ─────────────────────────────────────────────────


def test_every_organization_read_calls_both_read_scope_hooks_and_a_filtered_row_is_a_404(w, monkeypatch):
    from sqlalchemy import false, true

    root, _child, ids = _org_with_candidates(w)
    h = w.headers(role=UserRole.VIEWER.value)
    admin_h = w.headers()
    calls: list[str] = []

    def entity_clause(user, entity):
        calls.append("entity")
        return true()

    def domain_clause(user, domain):
        calls.append("domain")
        return true()

    monkeypatch.setattr(read_scope, "entity_clause", entity_clause)
    monkeypatch.setattr(read_scope, "domain_clause", domain_clause)
    urls = [
        ("get", "/api/organizations/"),
        ("get", f"/api/organizations/{root.id}/candidates"),
        ("get", f"/api/organizations/candidates/{ids['strong']}"),
    ]
    for method, url in urls:
        calls.clear()
        assert getattr(client, method)(url, headers=h).status_code == 200
        assert "entity" in calls, url
    for url in (f"/api/organizations/{root.id}/candidates", f"/api/organizations/candidates/{ids['strong']}"):
        calls.clear()
        client.get(url, headers=h)
        assert "domain" in calls, url

    # now a clause that hides the row: single-id routes answer 404, the list drops it
    monkeypatch.setattr(read_scope, "domain_clause", lambda user, domain: false())
    assert client.get(f"/api/organizations/candidates/{ids['strong']}", headers=h).status_code == 404
    assert client.post(f"/api/organizations/candidates/{ids['strong']}/claim", json={}, headers=admin_h).status_code == 404
    assert client.post(f"/api/organizations/candidates/{ids['strong']}/reject", json={"reason": "x"},
                       headers=admin_h).status_code == 404
    assert client.get(f"/api/organizations/{root.id}/candidates?status=all", headers=h).json() == []
    monkeypatch.setattr(read_scope, "domain_clause", domain_clause)
    monkeypatch.setattr(read_scope, "entity_clause", lambda user, entity: false())
    assert client.get(f"/api/organizations/{root.id}/candidates", headers=h).status_code == 404
    assert client.post(f"/api/organizations/{root.id}/candidates", json={
        "domain": _domain(), "source_url": "https://x.example.test/a", "excerpt": "e", "quote": "e"},
        headers=admin_h).status_code == 404
    assert client.get("/api/organizations/", headers=h).json() == []


def test_the_strength_sort_helper_matches_the_documented_ranks():
    assert strength_sql.STRENGTH_RANK == {"strong": 3, "supporting": 2, "lead": 1, "context": 0}


# ── review fixes F3, F5 ─────────────────────────────────────────────────────


def _spy_discovery(monkeypatch):
    import app.api.targets as targets_api

    launched: list[tuple] = []
    monkeypatch.setattr(targets_api, "_launch_initial_discovery",
                        lambda db, target, user_id, bg: launched.append((target.value, target.engagement_id, user_id)))
    return launched


def test_a_created_seed_target_gets_initial_discovery_after_the_add(w, monkeypatch):
    launched = _spy_discovery(monkeypatch)
    admin = w.user()
    r, body = _post_org(w, w.headers(admin))
    assert r.status_code == 201, r.text
    w.entities.append(uuid.UUID(r.json()["organization_id"]))
    assert launched == [(body["seed_domain"], None, admin.id)]
    # M&A: launched into the new engagement (posture is enforced inside the helper)
    r2, body2 = _post_org(w, w.headers(admin), relationship="ma_target", engagement_name=f"Project {hexid()}")
    w.entities.append(uuid.UUID(r2.json()["organization_id"]))
    assert launched[1] == (body2["seed_domain"], uuid.UUID(r2.json()["engagement"]["id"]), admin.id)


def test_an_attached_seed_target_does_not_get_a_second_discovery_run(w, monkeypatch):
    launched = _spy_discovery(monkeypatch)
    seed = _domain()
    w.db.add(Target(id=uuid.uuid4(), type="domain", value=seed))
    w.db.commit()
    r, _ = _post_org(w, w.headers(), seed_domain=seed)
    assert r.status_code == 201, r.text
    w.entities.append(uuid.UUID(r.json()["organization_id"]))
    assert w.db.query(Target).filter(Target.value == seed).one().entity_id is not None  # it WAS attached
    assert launched == []
    # and a refused add launches nothing
    r = client.post("/api/organizations/", json={"seed_domain": "not a domain", "org_name": _name(),
                    "relationship": "ours", "reference": "x"}, headers=w.headers())
    assert r.status_code == 400 and launched == []


def test_list_organizations_pages(w):
    names = [f"Org277 {letter} {hexid()}" for letter in "ABC"]
    for n in names:
        w.ours(w.entity(legal_name=n))
    h = w.headers(role=UserRole.VIEWER.value)

    def page(qs):
        r = client.get(f"/api/organizations/{qs}", headers=h)
        assert r.status_code == 200, r.text
        return [o["name"] for o in r.json()]

    assert page("") == names
    assert page("?limit=1") == names[:1]
    assert page("?limit=1&offset=1") == names[1:2]
    assert page("?limit=5&offset=2") == names[2:]
    for bad in ("limit=0", "limit=1001", "offset=-1"):
        assert client.get(f"/api/organizations/?{bad}", headers=h).status_code == 422
