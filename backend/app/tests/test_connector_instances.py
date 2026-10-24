"""Connector instances (planning#284 slice A): schema, service, credentials.

Real DB (the throwaway `constellus_test`), synthetic names only. Every
"refused" case also proves the path was REACHED: the same call with the
precondition fixed succeeds, so a refusal cannot be an unrelated failure.

Run: backend/scripts/test.sh app/tests/test_connector_instances.py
"""

import ast
import re
import uuid
from pathlib import Path

import httpx
import pytest
from sqlalchemy.exc import IntegrityError

from app.api.connectors import REGISTRY
from app.connectors.cloudflare import CloudflareConnector
from app.connectors.fortimanager import FortiManagerConnector
from app.connectors.mailtrap import MailtrapConnector
from app.connectors.openrouter import OpenRouterConnector
from app.connectors.shodan import ShodanConnector
from app.connectors.tenable import TenableConnector
from app.connectors.vulncheck import VulnCheckConnector
from app.connectors.wiz import WizConnector
from app.models.connector_instance import (
    ACCOUNT_TYPES,
    CONNECTOR_TYPES,
    ConnectorEnvSeed,
    ConnectorInstance,
)
from app.models.org_entity import OrgEntity
from app.models.target import Target
from app.services import connector_instances as svc
from app.tests._engagement import make_engagement
from app.tests._org_world import World, hexid

_MIGRATION = Path(__file__).resolve().parents[2] / "alembic" / "versions" / "0085_connector_instances.py"

# Types these tests create instances of; cleared before and after each test
# so a leak elsewhere cannot make a single-instance cap fire spuriously.
_TOUCHED = ("shodan", "mailtrap", "vulncheck", "openrouter", "cloudflare", "wiz", "tenable", "fortimanager", "naabu")


class Env:
    def __init__(self) -> None:
        self.w = World()
        self.db = self.w.db

    def purge(self) -> None:
        db = self.db
        db.rollback()
        ids = [i for (i,) in db.query(ConnectorInstance.id).filter(ConnectorInstance.type.in_(_TOUCHED)).all()]
        if ids:
            db.query(Target).filter(Target.connector_instance_id.in_(ids)).delete(synchronize_session=False)
        db.query(ConnectorEnvSeed).filter(ConnectorEnvSeed.type.in_(_TOUCHED)).delete(synchronize_session=False)
        db.query(ConnectorInstance).filter(ConnectorInstance.type.in_(_TOUCHED)).delete(synchronize_session=False)
        db.commit()

    # ── companies ──
    def ours(self) -> OrgEntity:
        return self.w.ours()

    def deal(self, posture: str = "day_0"):
        """An ma_target root with ONE engagement at `posture`."""
        entity = self.w.entity()
        eng = self.engagement(entity, posture)
        self.db.refresh(entity)
        return entity, eng

    def engagement(self, entity: OrgEntity, posture: str):
        from datetime import datetime, timezone

        extra = {}
        if posture in ("day_0", "integrated"):
            extra = {"authorised_at": datetime.now(timezone.utc), "authorisation_reference": "conn284 ref"}
        eng = make_engagement(self.db, posture, subject_entity_id=entity.id, **extra)
        self.w.engagements.append(eng.id)
        return eng

    def set_posture(self, eng, posture: str) -> None:
        from datetime import datetime, timezone

        eng.posture = posture
        if posture in ("day_0", "integrated"):
            eng.authorised_at = datetime.now(timezone.utc)
            eng.authorisation_reference = "conn284 ref"
        else:
            eng.authorised_at = None
            eng.authorisation_reference = None
        self.db.commit()

    # ── instances ──
    def raw(self, type: str, name: str | None = None, bound: OrgEntity | None = None) -> ConnectorInstance:
        inst = ConnectorInstance(type=type, name=name or f"conn284-{hexid()}", bound_entity_id=bound.id if bound else None)
        self.db.add(inst)
        self.db.flush()
        return inst

    def refused(self, fn) -> None:
        with pytest.raises(IntegrityError):
            fn()
        self.db.rollback()

    def close(self) -> None:
        self.purge()
        self.w.close()


@pytest.fixture
def env():
    e = Env()
    e.purge()
    yield e
    e.close()


# ── 1. schema: CHECKs, uniques ──────────────────────────────────────────────


def test_check_account_type_requires_an_organization(env):
    env.refused(lambda: env.raw("cloudflare"))
    # Reached: the same insert with a binding is accepted.
    assert env.raw("cloudflare", bound=env.ours()).bound_entity_id is not None


def test_check_global_type_refuses_an_organization(env):
    org = env.ours()
    env.refused(lambda: env.raw("shodan", bound=org))
    assert env.raw("shodan").bound_entity_id is None


def test_check_type_vocabulary(env):
    env.refused(lambda: env.raw("not_a_connector"))
    assert env.raw("shodan").type == "shodan"


def test_check_name_not_blank(env):
    env.refused(lambda: env.raw("shodan", name="   "))
    assert env.raw("shodan", name="x").name == "x"


def test_single_instance_per_global_type_but_many_per_account_type(env):
    env.raw("shodan", name="one")
    env.refused(lambda: env.raw("shodan", name="two"))
    org = env.ours()
    env.raw("cloudflare", name="acct-a", bound=org)
    env.raw("cloudflare", name="acct-b", bound=org)  # accepted: different name
    assert len(svc.list_of_type(env.db, "cloudflare")) == 2


def test_name_unique_within_a_type(env):
    org = env.ours()
    env.raw("cloudflare", name="same", bound=org)
    env.refused(lambda: env.raw("cloudflare", name="same", bound=org))
    assert env.raw("cloudflare", name="other", bound=org)


# ── 2. schema: the binding trigger ──────────────────────────────────────────


def test_trigger_accepts_ours(env):
    assert env.raw("wiz", bound=env.ours())


@pytest.mark.parametrize("posture", ["day_0", "integrated"])
def test_trigger_accepts_a_closed_deal(env, posture):
    entity, _eng = env.deal(posture)
    assert entity.relationship == "ma_target"
    assert env.raw("wiz", bound=entity)


def test_trigger_refuses_a_pre_close_deal_until_it_closes(env):
    entity, eng = env.deal("pre_close")
    assert entity.relationship == "ma_target"
    env.refused(lambda: env.raw("wiz", bound=entity))
    env.set_posture(eng, "day_0")
    assert env.raw("wiz", bound=entity)


def test_trigger_refuses_a_deal_with_only_abandoned_engagements(env):
    entity, eng = env.deal("pre_close")
    env.set_posture(eng, "abandoned")
    assert entity.relationship == "ma_target"
    env.refused(lambda: env.raw("wiz", bound=entity))
    env.engagement(entity, "day_0")  # one live, closed engagement now
    assert env.raw("wiz", bound=entity)


def test_trigger_refuses_two_non_abandoned_engagements(env):
    entity, _eng = env.deal("day_0")
    second = env.engagement(entity, "integrated")
    env.refused(lambda: env.raw("wiz", bound=entity))
    env.set_posture(second, "abandoned")
    assert env.raw("wiz", bound=entity)


def test_trigger_refuses_an_entity_with_no_relationship(env):
    entity = env.w.entity()
    assert entity.relationship is None
    env.refused(lambda: env.raw("wiz", bound=entity))
    env.w.ours(entity)
    assert env.raw("wiz", bound=entity)


def test_trigger_does_not_fire_on_unrelated_updates_but_does_on_rebind(env):
    entity, eng = env.deal("day_0")
    inst = env.raw("wiz", bound=entity)
    env.db.commit()
    env.set_posture(eng, "pre_close")  # the deal regresses
    # Reached: the regression is real, so a NEW binding to it is refused...
    other = env.raw("tenable", bound=env.ours())
    env.db.commit()
    other.bound_entity_id = entity.id
    with pytest.raises(IntegrityError):
        env.db.flush()
    env.db.rollback()
    # ...while toggling enabled on the already-bound instance still works.
    inst = env.db.get(ConnectorInstance, inst.id)
    inst.enabled = False
    env.db.commit()
    assert env.db.get(ConnectorInstance, inst.id).enabled is False


def test_target_reference_is_restrict(env):
    inst = env.raw("shodan")
    target = Target(id=uuid.uuid4(), type="domain", value=f"conn284-{hexid()}.example.com", connector_instance_id=inst.id)
    env.db.add(target)
    env.db.commit()
    with pytest.raises(IntegrityError):
        env.db.delete(inst)
        env.db.flush()
    env.db.rollback()
    # Reached: with the target detached the delete goes through.
    target = env.db.get(Target, target.id)
    target.connector_instance_id = None
    env.db.commit()
    env.db.delete(env.db.get(ConnectorInstance, inst.id))
    env.db.flush()
    env.db.delete(env.db.get(Target, target.id))
    env.db.commit()


# ── 3. service ──────────────────────────────────────────────────────────────


def _create(env, **kw):
    args = dict(type="shodan", name="n", bound_entity_id=None, config=None, created_by_id=None)
    args.update(kw)
    return svc.create(env.db, **args)


def test_create_validations(env):
    with pytest.raises(svc.UnknownType):
        _create(env, type="nope")
    with pytest.raises(svc.BindingRequired):
        _create(env, type="cloudflare")
    org = env.ours()
    with pytest.raises(svc.BindingForbidden):
        _create(env, type="shodan", bound_entity_id=org.id)
    pre_close, _ = env.deal("pre_close")
    with pytest.raises(svc.BindingNotAllowed) as exc:
        _create(env, type="cloudflare", bound_entity_id=pre_close.id)
    assert exc.value.reason == "deal_not_closed"
    with pytest.raises(svc.ConnectorInstanceError):
        _create(env, type="shodan", name="   ")

    # Reached: each of those arguments, fixed, succeeds.
    first = _create(env, type="shodan", name="  padded  ", config={"api_key": "k"})
    assert first.name == "padded" and first.config_encrypted
    with pytest.raises(svc.SingleInstanceType):
        _create(env, type="shodan", name="second")
    acct = _create(env, type="cloudflare", name="acct", bound_entity_id=org.id)
    with pytest.raises(svc.DuplicateName):
        _create(env, type="cloudflare", name="acct", bound_entity_id=org.id)
    assert _create(env, type="cloudflare", name="acct2", bound_entity_id=org.id).id != acct.id


def test_create_empty_config_is_stored_as_null_and_service_never_commits(env):
    inst = _create(env, type="shodan", name="n", config={})
    assert inst.config_encrypted is None
    env.db.rollback()  # the service flushed but did not commit
    assert svc.single(env.db, "shodan") is None


def test_binding_allowed_reasons(env):
    ours = env.ours()
    assert svc.binding_allowed(env.db, ours.id) == (True, None)
    assert svc.binding_allowed(env.db, uuid.uuid4()) == (False, "unknown_entity")
    assert svc.binding_allowed(env.db, env.w.entity().id) == (False, "not_an_organization")

    entity, eng = env.deal("pre_close")
    assert svc.binding_allowed(env.db, entity.id) == (False, "deal_not_closed")
    env.set_posture(eng, "day_0")
    assert svc.binding_allowed(env.db, entity.id) == (True, None)
    env.engagement(entity, "integrated")
    assert svc.binding_allowed(env.db, entity.id) == (False, "deal_engagement_ambiguous")

    abandoned, aeng = env.deal("pre_close")
    env.set_posture(aeng, "abandoned")
    assert abandoned.relationship == "ma_target"
    assert svc.binding_allowed(env.db, abandoned.id) == (False, "deal_engagement_ambiguous")


def test_deal_engagement(env):
    entity, eng = env.deal("day_0")
    got = svc.deal_engagement(env.db, entity.id)
    assert got is not None and got.id == eng.id
    assert svc.deal_engagement(env.db, env.ours().id) is None
    env.engagement(entity, "integrated")
    assert svc.deal_engagement(env.db, entity.id) is None  # ambiguous
    lonely, leng = env.deal("pre_close")
    assert svc.deal_engagement(env.db, lonely.id).id == leng.id
    env.set_posture(leng, "abandoned")
    assert svc.deal_engagement(env.db, lonely.id) is None


def test_enabled_config_honours_enabled(env):
    assert svc.enabled_config(env.db, "shodan") is None  # no instance
    inst = _create(env, type="shodan", name="n", config={"api_key": "k"})
    assert svc.enabled_config(env.db, "shodan") == {"api_key": "k"}
    svc.set_enabled(env.db, inst, False)
    assert svc.enabled_config(env.db, "shodan") is None
    with pytest.raises(ValueError):
        svc.enabled_config(env.db, "cloudflare")
    with pytest.raises(ValueError):
        svc.single(env.db, "cloudflare")


def test_decrypted_config_survives_an_undecryptable_blob(env):
    inst = _create(env, type="shodan", name="n", config={"api_key": "k"})
    assert svc.decrypted_config(inst) == {"api_key": "k"}
    inst.config_encrypted = "not-a-fernet-token"
    assert svc.decrypted_config(inst) == {}


def test_rename_and_rebind(env):
    org = env.ours()
    a = _create(env, type="cloudflare", name="a", bound_entity_id=org.id)
    _create(env, type="cloudflare", name="b", bound_entity_id=org.id)
    with pytest.raises(svc.DuplicateName):
        svc.rename(env.db, a, "b")
    assert svc.rename(env.db, a, " c ").name == "c"
    with pytest.raises(svc.BindingRequired):
        svc.rebind(env.db, a, None)
    other = env.ours()
    assert svc.rebind(env.db, a, other.id).bound_entity_id == other.id


# ── 4. env seeding ──────────────────────────────────────────────────────────

_SEED_REGISTRY = {
    "shodan": ShodanConnector(),
    "mailtrap": MailtrapConnector(),
    "vulncheck": VulnCheckConnector(),
    "openrouter": OpenRouterConnector(),
    "cloudflare": CloudflareConnector(),
}


@pytest.fixture
def clean_env(monkeypatch):
    for connector in REGISTRY.values():
        for env_key in getattr(connector, "env_key_map", {}).values():
            monkeypatch.delenv(env_key, raising=False)
    return monkeypatch


def _seed_row(env, type):
    return env.db.get(ConnectorEnvSeed, type)


def test_seed_creates_a_missing_global_instance_once(env, clean_env):
    clean_env.setenv("SHODAN_API_KEY", "seed-value")
    svc.seed_from_env(env.db, _SEED_REGISTRY)
    env.db.commit()
    inst = svc.single(env.db, "shodan")
    assert inst is not None and inst.enabled
    assert svc.decrypted_config(inst) == {"api_key": "seed-value"}
    assert _seed_row(env, "shodan").instance_id == inst.id

    # Second call is a no-op: a changed env value is not applied.
    clean_env.setenv("SHODAN_API_KEY", "other-value")
    svc.seed_from_env(env.db, _SEED_REGISTRY)
    env.db.commit()
    assert svc.decrypted_config(svc.single(env.db, "shodan")) == {"api_key": "seed-value"}


def test_seed_fills_only_empty_fields_of_an_existing_instance(env, clean_env):
    _create(env, type="mailtrap", name="mailtrap", config={"api_token": "keep-me"})
    env.db.commit()
    clean_env.setenv("MAILTRAP_API_TOKEN", "env-token")
    clean_env.setenv("MAILTRAP_INBOX_ID", "12345")
    svc.seed_from_env(env.db, _SEED_REGISTRY)
    env.db.commit()
    config = svc.decrypted_config(svc.single(env.db, "mailtrap"))
    assert config["api_token"] == "keep-me"  # never overwritten
    assert config["inbox_id"] == "12345"  # empty field filled
    assert _seed_row(env, "mailtrap") is not None


def test_seed_never_touches_openrouter(env, clean_env):
    clean_env.setenv("OPENROUTER_API_KEY", "env-only")
    clean_env.setenv("SHODAN_API_KEY", "reached")  # proves the loop ran
    svc.seed_from_env(env.db, _SEED_REGISTRY)
    env.db.commit()
    assert svc.single(env.db, "shodan") is not None
    assert svc.single(env.db, "openrouter") is None
    assert _seed_row(env, "openrouter") is None


def test_seed_type_with_empty_env_is_recorded_without_an_instance(env, clean_env):
    svc.seed_from_env(env.db, _SEED_REGISTRY)
    env.db.commit()
    row = _seed_row(env, "vulncheck")
    assert row is not None and row.instance_id is None
    assert svc.single(env.db, "vulncheck") is None
    assert _seed_row(env, "openrouter") is None  # still never recorded


def test_seed_account_type_binds_to_the_sole_ours_org(env, clean_env):
    org = env.ours()
    assert env.db.query(OrgEntity).filter(OrgEntity.relationship == "ours").count() == 1
    clean_env.setenv("CLOUDFLARE_API_TOKEN", "acct-token")
    svc.seed_from_env(env.db, _SEED_REGISTRY)
    env.db.commit()
    [inst] = svc.list_of_type(env.db, "cloudflare")
    assert inst.bound_entity_id == org.id
    assert svc.decrypted_config(inst) == {"api_token": "acct-token"}
    assert _seed_row(env, "cloudflare").instance_id == inst.id


def test_seed_account_type_skips_and_retries_without_exactly_one_ours_org(env, clean_env):
    clean_env.setenv("CLOUDFLARE_API_TOKEN", "acct-token")
    assert env.db.query(OrgEntity).filter(OrgEntity.relationship == "ours").count() == 0
    svc.seed_from_env(env.db, _SEED_REGISTRY)
    env.db.commit()
    assert svc.list_of_type(env.db, "cloudflare") == [] and _seed_row(env, "cloudflare") is None

    env.ours()
    env.ours()
    assert env.db.query(OrgEntity).filter(OrgEntity.relationship == "ours").count() == 2
    svc.seed_from_env(env.db, _SEED_REGISTRY)
    env.db.commit()
    assert svc.list_of_type(env.db, "cloudflare") == [] and _seed_row(env, "cloudflare") is None


# ── 5. credentials come from the instance config ────────────────────────────

_FULL = {
    "cloudflare": (CloudflareConnector, {"api_token": "x"}, "CLOUDFLARE_API_TOKEN"),
    "wiz": (WizConnector, {"client_id": "i", "client_secret": "s"}, "WIZ_CLIENT_ID"),
    "tenable": (TenableConnector, {"api_key": "k", "api_secret": "s"}, "TENABLE_API_KEY"),
    "fortimanager": (FortiManagerConnector, {"connector_url": "http://u.example.invalid", "api_key": "k"}, "FORTIMANAGER_CONNECTOR_URL"),
}


@pytest.mark.parametrize("type", sorted(_FULL))
def test_account_connectors_read_only_the_instance_config(type, monkeypatch):
    cls, config, env_key = _FULL[type]
    connector = cls()
    monkeypatch.setenv(env_key, "from-the-environment")
    assert connector.is_configured({}) is False  # env is never read
    assert connector.is_configured(config) is True


def test_cloudflare_sends_the_token_from_config(monkeypatch):
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "from-the-environment")
    seen = []

    def spy(method, url, **kw):
        seen.append(kw.get("headers"))
        return httpx.Response(200, json={"result": [{"name": "example.com"}], "result_info": {"total_pages": 1}},
                              request=httpx.Request(method, url))

    monkeypatch.setattr(httpx, "request", spy)
    assert CloudflareConnector().list_domains({"api_token": "config-token"}) == ["example.com"]
    assert seen and seen[0] == {"Authorization": "Bearer config-token"}

    seen.clear()
    assert CloudflareConnector().list_domains({}) == []  # no config token: no request, env ignored
    assert seen == []

    def spy_get(url, **kw):
        seen.append(kw.get("headers"))
        return httpx.Response(200, json={"success": True}, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", spy_get)
    assert CloudflareConnector().test({"api_token": "config-token"}).success is True
    assert seen == [{"Authorization": "Bearer config-token"}]


def test_openrouter_is_configured_only_by_instance_config(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "from-the-environment")
    assert OpenRouterConnector().is_configured({}) is False
    assert OpenRouterConnector().is_configured({"api_key": "k"}) is True


# ── 6. the literals in the model, the registry and the migration agree ──────


def _migration_literal(name: str) -> set[str]:
    tree = ast.parse(_MIGRATION.read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == name for t in node.targets):
            return set(ast.literal_eval(node.value))
    raise AssertionError(f"{name} not found in {_MIGRATION.name}")


def test_type_vocabularies_agree():
    assert set(REGISTRY) == CONNECTOR_TYPES
    assert _migration_literal("TYPES") == CONNECTOR_TYPES
    assert _migration_literal("ACCOUNT_TYPES") == ACCOUNT_TYPES
    assert ACCOUNT_TYPES <= CONNECTOR_TYPES
    # The migration builds its CHECKs from those tuples; prove the SQL text does too.
    source = _MIGRATION.read_text()
    assert re.search(r'type IN \(\{_list\(TYPES\)\}\)', source)
    assert re.search(r'type IN \(\{_list\(ACCOUNT_TYPES\)\}\)', source)
