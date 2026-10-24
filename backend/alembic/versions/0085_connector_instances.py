"""Connector instances (planning#284 slice A). Replaces `connector_configs`.

`connector_configs` held one row per connector TYPE, keyed by the type name.
An account-style connector (a cloud-DNS account, a vulnerability-management
tenant) is really one row per ACCOUNT, and each account belongs to one
organization. This migration moves to `connector_instances` and
`connector_env_seeds`, and re-points `targets` at an instance.

## `connector_instances`

- `type` is one of the 14 connector types (`ck_connector_instances_type`).
  The list is a literal here, and mirrored in
  `app.models.connector_instance.CONNECTOR_TYPES`; edit them together
  (`app/tests/test_connector_instances.py` parses this file to prove it).
- `ck_connector_instances_binding`: an ACCOUNT type (cloudflare, wiz,
  tenable, fortimanager) has `bound_entity_id`; every other type has none.
  Account types may have many instances.
- `uq_connector_instances_single_type` (partial unique): every NON-account
  type (global services and scanning tools) has at most one instance. This
  is a guard, never a setting.
- `uq_connector_instances_type_name`: names are unique within a type.
- `bound_entity_id` is `ON DELETE RESTRICT`: deleting an organization out
  from under an instance must not silently strip its binding.
- `config_encrypted` is the same Fernet blob the old table held. The key is
  derived from `settings.secret_key` alone (not from the row), so the blob
  copies across unchanged.

## `trg_connector_instances_binding_guard`

BEFORE INSERT OR UPDATE OF `bound_entity_id`. When the new binding is not
NULL it must be an organization root (`org_entities.relationship IS NOT
NULL`) and either `ours`, or `ma_target` with EXACTLY ONE non-abandoned
engagement whose posture is `day_0` or `integrated`. Zero, or more than one,
non-abandoned engagements is refused (ambiguity fails closed). It does not
fire on unrelated updates, so a later posture regression cannot make an
enable/disable toggle fail; skipping a regressed binding at run time is the
scan executor's job. The service (`binding_allowed`) mirrors this rule.

## `connector_env_seeds`

One row per connector type whose one-time environment seeding has been
settled (`app.services.connector_instances.seed_from_env`). Queryable on
purpose. `instance_id` is the instance the seed created or filled, if any.

## Data

One instance per old row: `type = name = connector_id`. Rows whose id is not
one of the 14 types are dropped (a NOTICE names the count). Account-type
rows are bound to the sole `ours` organization when exactly one exists,
otherwise dropped (NOTICE). Nothing is inserted into `connector_env_seeds`,
so startup seeding fills EMPTY fields of the migrated instances from the
environment exactly once.

`targets.connector_id` (a type string) becomes `targets.connector_instance_id`
(`ON DELETE RESTRICT`), backfilled by type; at this point each type has at
most one instance, so the match is unambiguous.

## Downgrade

Recreates `connector_configs` (one row per type; for account types the oldest
instance), restores `targets.connector_id` from the instance type, and drops
the new objects. Bindings and extra account instances are lost.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0085"
down_revision = "0084"
branch_labels = None
depends_on = None

# Mirrored in app.models.connector_instance (CONNECTOR_TYPES / ACCOUNT_TYPES).
TYPES = (
    "certspotter", "cloudflare", "shodan", "wiz", "fortimanager", "tenable",
    "vulncheck", "nuclei", "naabu", "banner_grab", "httpx_probe", "tlsx",
    "mailtrap", "openrouter",
)
ACCOUNT_TYPES = ("cloudflare", "wiz", "tenable", "fortimanager")


def _list(values: tuple[str, ...]) -> str:
    return ", ".join(repr(v) for v in values)


_GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION connector_instances_binding_guard()
RETURNS trigger AS $$
DECLARE
    v_rel text;
    v_count integer;
    v_posture text;
BEGIN
    IF NEW.bound_entity_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT relationship INTO v_rel FROM org_entities WHERE id = NEW.bound_entity_id;
    IF NOT FOUND OR v_rel IS NULL THEN
        RAISE EXCEPTION
            'connector_instances: bound_entity_id must be an organization root (a relationship is set)'
            USING ERRCODE = '23514';
    END IF;
    IF v_rel = 'ours' THEN
        RETURN NEW;
    END IF;
    IF v_rel = 'ma_target' THEN
        SELECT count(*), min(posture) INTO v_count, v_posture
        FROM engagements
        WHERE subject_entity_id = NEW.bound_entity_id AND posture <> 'abandoned';
        IF v_count <> 1 THEN
            RAISE EXCEPTION
                'connector_instances: an ma_target binding needs exactly one non-abandoned engagement (found %)', v_count
                USING ERRCODE = '23514';
        END IF;
        IF v_posture NOT IN ('day_0', 'integrated') THEN
            RAISE EXCEPTION
                'connector_instances: an ma_target binding needs a day_0 or integrated engagement (posture is %)', v_posture
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION
        'connector_instances: bound organization has an unsupported relationship'
        USING ERRCODE = '23514';
END;
$$ LANGUAGE plpgsql;
"""

_GUARD_TRIGGER = """
CREATE TRIGGER trg_connector_instances_binding_guard
BEFORE INSERT OR UPDATE OF bound_entity_id ON connector_instances
FOR EACH ROW EXECUTE FUNCTION connector_instances_binding_guard();
"""


def upgrade() -> None:
    op.create_table(
        "connector_instances",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("config_encrypted", sa.Text(), nullable=True),
        sa.Column("bound_entity_id", UUID(as_uuid=True), sa.ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("created_by_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(f"type IN ({_list(TYPES)})", name="ck_connector_instances_type"),
        sa.CheckConstraint("btrim(name) <> ''", name="ck_connector_instances_name"),
        sa.CheckConstraint(
            f"(type IN ({_list(ACCOUNT_TYPES)})) = (bound_entity_id IS NOT NULL)",
            name="ck_connector_instances_binding",
        ),
        sa.UniqueConstraint("type", "name", name="uq_connector_instances_type_name"),
    )
    op.create_index(
        "uq_connector_instances_single_type",
        "connector_instances",
        ["type"],
        unique=True,
        postgresql_where=sa.column("type").notin_(ACCOUNT_TYPES),
    )
    op.create_index("ix_connector_instances_bound_entity_id", "connector_instances", ["bound_entity_id"])
    op.execute(_GUARD_FUNCTION)
    op.execute(_GUARD_TRIGGER)

    op.create_table(
        "connector_env_seeds",
        sa.Column("type", sa.Text(), primary_key=True),
        sa.Column("seeded_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("instance_id", UUID(as_uuid=True), sa.ForeignKey("connector_instances.id", ondelete="SET NULL"), nullable=True),
        sa.CheckConstraint(f"type IN ({_list(TYPES)})", name="ck_connector_env_seeds_type"),
    )

    # Data: one instance per old row (the guard trigger is already in place).
    op.execute(
        f"""
DO $$
DECLARE
    v_ours_n integer;
    v_ours_id uuid;
    v_unknown integer;
    v_account_dropped integer := 0;
BEGIN
    SELECT count(*) INTO v_ours_n FROM org_entities WHERE relationship = 'ours';
    IF v_ours_n = 1 THEN
        SELECT id INTO v_ours_id FROM org_entities WHERE relationship = 'ours';
    END IF;

    SELECT count(*) INTO v_unknown FROM connector_configs
    WHERE connector_id NOT IN ({_list(TYPES)});
    IF v_unknown > 0 THEN
        RAISE NOTICE 'connector_instances: dropped % connector_configs row(s) with an unknown type', v_unknown;
    END IF;

    IF v_ours_id IS NULL THEN
        SELECT count(*) INTO v_account_dropped FROM connector_configs
        WHERE connector_id IN ({_list(ACCOUNT_TYPES)});
        IF v_account_dropped > 0 THEN
            RAISE NOTICE 'connector_instances: dropped % account-type row(s); there is not exactly one ours organization to bind them to', v_account_dropped;
        END IF;
    END IF;

    INSERT INTO connector_instances (type, name, enabled, config_encrypted, bound_entity_id, created_at, updated_at)
    SELECT connector_id, connector_id, enabled, config_encrypted,
           CASE WHEN connector_id IN ({_list(ACCOUNT_TYPES)}) THEN v_ours_id END,
           COALESCE(updated_at, now()), COALESCE(updated_at, now())
    FROM connector_configs
    WHERE connector_id IN ({_list(TYPES)})
      AND (connector_id NOT IN ({_list(ACCOUNT_TYPES)}) OR v_ours_id IS NOT NULL);
END
$$;
"""
    )

    op.add_column(
        "targets",
        sa.Column("connector_instance_id", UUID(as_uuid=True), sa.ForeignKey("connector_instances.id", ondelete="RESTRICT"), nullable=True),
    )
    op.create_index("ix_targets_connector_instance_id", "targets", ["connector_instance_id"])
    op.execute(
        "UPDATE targets SET connector_instance_id = ci.id "
        "FROM connector_instances ci WHERE ci.type = targets.connector_id"
    )
    op.drop_column("targets", "connector_id")

    op.drop_table("connector_configs")


def downgrade() -> None:
    op.create_table(
        "connector_configs",
        sa.Column("connector_id", sa.String(50), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("config_encrypted", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.execute(
        "INSERT INTO connector_configs (connector_id, enabled, config_encrypted, updated_at) "
        "SELECT DISTINCT ON (type) type, enabled, config_encrypted, updated_at "
        "FROM connector_instances ORDER BY type, created_at, id"
    )

    op.add_column("targets", sa.Column("connector_id", sa.String(50), nullable=True))
    op.execute(
        "UPDATE targets SET connector_id = ci.type "
        "FROM connector_instances ci WHERE ci.id = targets.connector_instance_id"
    )
    op.drop_index("ix_targets_connector_instance_id", table_name="targets")
    op.drop_column("targets", "connector_instance_id")

    op.drop_table("connector_env_seeds")
    op.execute("DROP TRIGGER IF EXISTS trg_connector_instances_binding_guard ON connector_instances")
    op.execute("DROP FUNCTION IF EXISTS connector_instances_binding_guard()")
    op.drop_index("ix_connector_instances_bound_entity_id", table_name="connector_instances")
    op.drop_index("uq_connector_instances_single_type", table_name="connector_instances")
    op.drop_table("connector_instances")
