"""Add the `browse` observer noise class (planning#280 S5a).

`browse` is one ordinary page load by a stock browser: a screenshot plus the
final URL, redirect chain, title and certificate that one load yields, and
nothing more (no second request, no link-following, no forms). planning#280
permits it under passive-only (`app.services.posture`), the one deliberate
policy change to the noise-class gate since planning#196.

This migration only widens `ck_observers_noise_class` so a row CAN carry the
value. No observer is seeded with it here: the page-capture observer arrives
with its producer (S5b), because its `addressing` decides which authorisation
grant its claims satisfy and has to be designed together with that producer.

The constraint text is built from literal tuples, not `OBSERVER_NOISE`, so
this migration's DDL never changes when the model's vocabulary does. (0055
builds its constraint from the model; on a fresh database it therefore
already admits `browse`, and this upgrade recreates the same constraint.)
"""

from alembic import op

revision = "0090"
down_revision = "0089"
branch_labels = None
depends_on = None

_BEFORE = ("silent", "third_party_infra", "target_infra", "target_host")
_AFTER = ("silent", "third_party_infra", "browse", "target_infra", "target_host")


def _check(values: tuple[str, ...]) -> str:
    return " OR ".join(f"noise_class = '{v}'" for v in values)


def upgrade() -> None:
    op.drop_constraint("ck_observers_noise_class", "observers", type_="check")
    op.create_check_constraint("ck_observers_noise_class", "observers", _check(_AFTER))


def downgrade() -> None:
    # Refuse rather than reclassify: a `browse` observer's rows would need a
    # deliberate decision about which noise class they fall back to, and
    # guessing one would silently change what passive-only permits.
    op.execute(
        "DO $$ BEGIN "
        "IF EXISTS (SELECT 1 FROM observers WHERE noise_class = 'browse') THEN "
        "RAISE EXCEPTION '0090 downgrade: observers rows carry noise_class browse; reclassify or remove them first'; "
        "END IF; END $$"
    )
    op.drop_constraint("ck_observers_noise_class", "observers", type_="check")
    op.create_check_constraint("ck_observers_noise_class", "observers", _check(_BEFORE))
