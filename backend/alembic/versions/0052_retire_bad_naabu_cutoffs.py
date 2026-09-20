"""Drop every stored `asset_state.attributes->naabu_last_scan_at` (planning#190).

Pure data repair, no schema change. Every value of that key currently in
`asset_state` was written by the code this migration ships alongside a fix
for, and every one of them is the WRONG QUANTITY — not merely stale.

`projector` used to set the key (and the write-time prune cutoff) from the
naabu `port_observation` claim's `last_observed_at`, which
`asset_writer.write_assets()` stamps only after the connector has returned.
Every port's own `last_seen_at` comes from a different clock — the sweep's,
stamped inside `connectors/naabu._build_phase_result`. The writer cannot run
before the connector returns, so the stored cutoff is by construction
strictly LATER than every port it is compared against. `_prune_stale_ports`
keeps a port only if `last_seen_at >= cutoff`, so no naabu port has ever
survived the projection that first recorded it: `open_ports` was permanently
`[]` estate-wide.

Why this migration exists at all, given the code fix
----------------------------------------------------
The code fix reads the cutoff from the claim's `evidence["swept_at"]`, which
the emitter now carries from naabu's own clock. A claim written before that
has no `swept_at`, and the deliberate fallback is to prune NOTHING — the
alternative, falling back to `last_observed_at`, would silently reinstate the
exact bug on every pre-existing row.

That fixes the WRITE side for old claims immediately: `open_ports` repopulates
on the next projection. It does not fix the READ side, because
`asset_state.attributes` is upserted with a JSONB `||` merge, so a key the new
projection does not set is carried forward rather than cleared — and
`api.assets._filter_stale_ports` applies the identical `>= cutoff` test at read
time. Without this migration the fixed prune keeps the ports and the stale
cutoff hides them again, which looks exactly like the bug not being fixed.

Removing the key is the same "can't judge it, don't drop it" posture the
filter already takes: `_filter_stale_ports` returns the metadata untouched
when `naabu_last_scan_at` is absent. Ports stay visible until the next naabu
sweep writes a cutoff that means what it says, at which point genuine
retirement resumes. The window is one scan, and nothing is lost in it — the
`port_observation` claim is the record of truth and this migration does not
touch it.

Not reversible, deliberately: `downgrade` is a no-op. Restoring the old values
would restore a quantity that was never meaningful, and the next naabu sweep
overwrites the key regardless.

Revision ID: 0052
Revises: 0051
Create Date: 2026-09-20
"""

from alembic import op

revision = "0052"
down_revision = "0051"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # `- 'key'` on a jsonb removes it. Scoped by `?` so only rows that carry
    # the key are rewritten, and `attributes` is NOT NULL-guarded anyway.
    op.execute(
        """
        UPDATE asset_state
           SET attributes = attributes - 'naabu_last_scan_at'
         WHERE attributes ? 'naabu_last_scan_at'
        """
    )


def downgrade() -> None:
    # Intentionally empty — see the module docstring. The removed values were
    # write timestamps masquerading as sweep timestamps; there is nothing
    # worth putting back, and the next naabu sweep repopulates the key.
    pass
