"""Seed the `nuclei` observer — closes Phase 3's last gate blocker.

Phase 3 (scanning) is the last active-probe path that does not route through
`app.services.probe_authorisation.authorise_probes` (planning#148 step 2).
The gate's connector-declaration check is always-enforced — it is not subject
to the `log_only`/`enforce` rollout — so routing Phase 3 through the gate
before `nuclei` has both a seeded `observers` row and an `observer` class
attribute on `NucleiConnector` would deny it `unknown_observer` outright, in
both gate modes, and kill Phase 3 scanning entirely. This migration and the
`observer = "nuclei"` attribute added alongside it are what let that routing
change land safely.

Why the taxonomy values are what they are:

  * `kind = "scan"` — an active network probe, the same class as naabu /
    tlsx / httpx / banner_grab. Not `verify` (it derives nothing from other
    claims — it elicits its own response from the target) and not
    `connector` (it is our own traffic against the target, not a read of a
    third-party API like `wiz` or `shodan`).
  * `trust = "observed"` — first-hand: a nuclei finding is a response we
    ourselves elicited from the target, not an inference drawn from someone
    else's report of it.
  * `emits_traffic_to_target = True` — the defining property, and the whole
    point of this row: without it, nuclei cannot be declared as a prober at
    all (see `addressing = "none"` denying `wiz` as a prober in migration
    0048 for the mirror case).
  * `addressing = "name"` — and this is the load-bearing paragraph. Migration
    0039's own seed notes say: "tlsx/httpx are declared `name`-addressing
    here even though the raw sweep is mixed ip+name — the CDN/SNI path is
    the one that actually needs authorisation, and the IP path is already
    covered by naabu/banner_grab being `ip`-addressing. Revisit in L2/#148
    if the ip path ever needs its own observer identity." This migration IS
    that revisit, and the answer is unchanged: nuclei's target list is
    mixed (`_extract_scan_targets` yields both `dns_record` and
    `ip_address` values), its templates are overwhelmingly HTTP/TLS and
    therefore Host/SNI-addressed, and the bare-IP reachability question is
    already gated by naabu/banner_grab being `ip`-addressing on the same
    assets earlier in the same run. Splitting nuclei into two observer
    identities would fork its claim attribution for no gate that isn't
    already applied upstream. This follows the 0039 precedent rather than
    inventing a new rule.

Rollout consequence: this row is what lets Phase 3 pass the gate's
always-enforced connector-declaration check. Without it, `nuclei` is denied
`unknown_observer` in BOTH gate modes.
"""

import sqlalchemy as sa
from alembic import op

revision = "0049"
down_revision = "0048"
branch_labels = None
depends_on = None

_OBSERVER = (
    "nuclei",
    "scan",
    "observed",
    True,
    "name",
    "Template-driven vulnerability/misconfiguration probe addressed by hostname.",
)


def upgrade() -> None:
    observers = sa.table(
        "observers",
        sa.column("name", sa.Text()),
        sa.column("kind", sa.Text()),
        sa.column("trust", sa.Text()),
        sa.column("emits_traffic_to_target", sa.Boolean()),
        sa.column("addressing", sa.Text()),
        sa.column("description", sa.Text()),
    )
    name, kind, trust, emits, addressing, description = _OBSERVER
    op.bulk_insert(
        observers,
        [{
            "name": name,
            "kind": kind,
            "trust": trust,
            "emits_traffic_to_target": emits,
            "addressing": addressing,
            "description": description,
        }],
    )


def downgrade() -> None:
    op.execute("DELETE FROM observers WHERE name = 'nuclei'")
