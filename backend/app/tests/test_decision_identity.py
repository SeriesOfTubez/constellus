"""Coverage for planning#209 — every `authorisation_decisions` row says what
it was about.

## The defect

`probe_authorisation._compose` wrote `evidence_snapshot["asset_type"]` /
`["asset_value"]` from `canonical` alone. `canonical is None` is not a rare
edge — it is exactly the `unresolved_asset` denial, and it is the one branch
where `asset_canonical_id` is **also** NULL because there is no row to
reference. So the single denial path with no foreign key recorded no
identity either: unattributable in both directions at once.

Measured on dev before the fix (run `a4039ae0`, 8 assets): 39 of 155 rows —
26 naabu, 13 nuclei, a third of all denial rows — with `asset_type: null`,
`asset_value: null` and a null `asset_canonical_id`. `_probe_class_cap`'s
own docstring argues that `unresolved_asset` and `probe_class:unprojected`
must stay separate rules because a log-only rollout is read to decide
whether enforcing is safe and collapsing them "would make the deny rate
uninterpretable" — a reasoning undercut by the row not naming its subject.

Three writers had the hole; all three are pinned here:

  1. `_compose` (the composed per-asset path).
  2. The connector-declaration-failure path, which builds the same evidence
     dict inline — and denies the WHOLE batch for a connector, so an
     unattributable row there loses more, not less.
  3. `authorise_ownership_probe` (planning#205), which wrote no identity
     keys at all because it does not route through `_compose`. That made
     `AuthorisationDecision`'s own docstring false for
     `decision_scope = "ownership_probe"`.

## How an asset comes to have no canonical row, and why the test uses that
   shape rather than an easier one

`asset_writer._canonical_key` includes `record_type`/`content` for
`dns_record`, so a bare `DiscoveredAsset` carrying neither does not match a
*typed* canonical row for the same hostname. That is the production cause
named in `_probe_class_cap`'s docstring (the `skip_discovery` seeds, and
CT/subfinder/bruteforce's bare rows), so it is the shape reproduced here.

An asset with no persisted row at all would also yield `canonical is None`
and would be a simpler fixture — and a weaker test, because it would still
pass if the key ever stopped including `record_type`/`content`. The point
of this file is the mismatch.

## What this file does NOT claim

It does not assert that 39 unresolved rows a run is correct, or that it is
a defect. That question could not be asked before this fix, because the
rows did not say what they were about; it is deliberately left open on
planning#209 rather than guessed at here.

Run with:  backend/scripts/test.ps1 app/tests/test_decision_identity.py
       or: python -m app.tests.test_decision_identity
"""

import uuid
from datetime import datetime, timezone

from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.authorisation_decision import AuthorisationDecision
from app.services import probe_authorisation as pa
from app.tests._docaddr import alloc as alloc_ip


# ── helpers ──────────────────────────────────────────────────────────────

class _NaabuStub:
    """`observer = "naabu"` reuses the real seeded observer row (addressing
    == "ip"), so the connector-declaration check resolves it and the gate
    reaches its per-asset loop. Without a resolvable observer the gate
    short-circuits and this file would be testing the wrong branch."""
    observer = "naabu"

    def port_scan(self, assets, config):  # pragma: no cover — the gate never calls this
        raise AssertionError("the gate must never call a connector's port_scan itself")


class _UndeclaredStub:
    """No `observer` attribute at all — drives the connector-declaration
    failure path, which denies every asset in the batch before any state is
    loaded."""
    def port_scan(self, assets, config):  # pragma: no cover
        raise AssertionError("the gate must never call a connector's port_scan itself")


def _mk_typed_dns_record(db, value: str, content: str) -> AssetCanonical:
    """A canonical `dns_record` WITH record_type/content, i.e. one whose
    composite key a bare in-batch row cannot match."""
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type="dns_record", value=value,
        record_type="A", content=content, first_seen_at=now, last_seen_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _bare_dns_record(value: str) -> DiscoveredAsset:
    """The in-batch shape that cannot resolve: no record_type, no content."""
    return DiscoveredAsset(asset_type="dns_record", value=value)


def _rows_for(db, scan_run_id: uuid.UUID) -> list[AuthorisationDecision]:
    return (
        db.query(AuthorisationDecision)
        .filter(AuthorisationDecision.evidence_snapshot["scan_run_id"].astext == str(scan_run_id))
        .all()
    )


def _cleanup(scan_run_id: uuid.UUID, values: list[str]) -> None:
    """Decision rows FIRST. `asset_canonical_id` is ON DELETE SET NULL
    (planning#195), so deleting the asset first would silently orphan them
    into another test's hygiene check rather than erroring here."""
    db = SessionLocal()
    try:
        db.query(AuthorisationDecision).filter(
            AuthorisationDecision.evidence_snapshot["scan_run_id"].astext == str(scan_run_id)
        ).delete(synchronize_session=False)
        rows = db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).all()
        ids = [r.id for r in rows]
        if ids:
            db.query(AuthorisationDecision).filter(
                AuthorisationDecision.asset_canonical_id.in_(ids)
            ).delete(synchronize_session=False)
            db.query(AssetState).filter(AssetState.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


# ── 1. the composed path ────────────────────────────────────────────────────

def test_unresolved_asset_denial_still_records_what_it_denied():
    """The regression this issue exists for.

    Two assertions, not one, because "identity is present" is satisfied both
    by the fallback working and by the asset having resolved after all — and
    those are opposite situations. So this asserts the denial really IS the
    unresolved one (`rule_fired == "unresolved_asset"`, `asset_canonical_id
    is None`) AND that the identity survived anyway.

    MUTATION: reverting either key in `_compose` to
    `... if canonical is not None else None` fails this.
    """
    scan_run_id = uuid.uuid4()
    hostname = f"pa209-{uuid.uuid4().hex[:12]}.example.net"
    db = SessionLocal()
    try:
        _mk_typed_dns_record(db, hostname, alloc_ip())

        pa.authorise_probes(
            db, connector_id="test-naabu", connector=_NaabuStub(),
            assets=[_bare_dns_record(hostname)], scope={}, scan_run_id=scan_run_id,
        )

        rows = _rows_for(db, scan_run_id)
        assert len(rows) == 1, rows
        row = rows[0]

        # precondition: this really is the branch under test
        assert row.rule_fired == "unresolved_asset", row.rule_fired
        assert row.asset_canonical_id is None, row.asset_canonical_id

        # the fix
        assert row.evidence_snapshot["asset_type"] == "dns_record", row.evidence_snapshot
        assert row.evidence_snapshot["asset_value"] == hostname, row.evidence_snapshot
    finally:
        db.close()
        _cleanup(scan_run_id, [hostname])


def test_a_resolvable_asset_still_reports_the_canonical_identity():
    """The fallback must not become the primary. `canonical` wins whenever
    it exists — it is the durable identity, and for a `dns_record` it is the
    row the composite key actually resolved to.

    MUTATION: swapping the branches in `_compose` (in-batch ref first) still
    passes on value, so this pins `asset_canonical_id` being populated as
    well — the pair is what says "this resolved".
    """
    scan_run_id = uuid.uuid4()
    hostname = f"pa209-{uuid.uuid4().hex[:12]}.example.net"
    content = alloc_ip()
    db = SessionLocal()
    try:
        canonical = _mk_typed_dns_record(db, hostname, content)

        asset = DiscoveredAsset(
            asset_type="dns_record", value=hostname,
            asset_metadata={"record_type": "A", "content": content},
        )
        pa.authorise_probes(
            db, connector_id="test-naabu", connector=_NaabuStub(),
            assets=[asset], scope={}, scan_run_id=scan_run_id,
        )

        rows = _rows_for(db, scan_run_id)
        assert len(rows) == 1, rows
        row = rows[0]
        assert row.rule_fired != "unresolved_asset", row.rule_fired
        assert row.asset_canonical_id == canonical.id, row.asset_canonical_id
        assert row.evidence_snapshot["asset_value"] == hostname, row.evidence_snapshot
    finally:
        db.close()
        _cleanup(scan_run_id, [hostname])


# ── 2. the connector-declaration-failure path ───────────────────────────────

def test_declaration_failure_rows_record_identity_for_every_asset():
    """This path denies the WHOLE batch before any asset state is loaded, so
    an unattributable row here loses more than one asset's worth of
    evidence. Two assets in the batch, both named.

    MUTATION: reverting the inline fallback at the declaration-failure site
    fails this while leaving test 1 green — they are separate writers.
    """
    scan_run_id = uuid.uuid4()
    hostnames = [f"pa209-{uuid.uuid4().hex[:12]}.example.net" for _ in range(2)]
    db = SessionLocal()
    try:
        for h in hostnames:
            _mk_typed_dns_record(db, h, alloc_ip())

        pa.authorise_probes(
            db, connector_id="test-undeclared", connector=_UndeclaredStub(),
            assets=[_bare_dns_record(h) for h in hostnames],
            scope={}, scan_run_id=scan_run_id,
        )

        rows = _rows_for(db, scan_run_id)
        assert len(rows) == 2, rows
        # precondition: the declaration check fired, not the per-asset loop
        assert all(r.evidence_snapshot["caps"] == {} for r in rows), [r.evidence_snapshot for r in rows]
        assert {r.evidence_snapshot["asset_value"] for r in rows} == set(hostnames), rows
        assert all(r.evidence_snapshot["asset_type"] == "dns_record" for r in rows), rows
    finally:
        db.close()
        _cleanup(scan_run_id, hostnames)


# ── 3. the ownership-probe gate ─────────────────────────────────────────────

def test_ownership_probe_denial_records_identity():
    """planning#205's gate wrote no identity keys at all, which made
    `AuthorisationDecision`'s docstring false for this decision_scope —
    `asset_canonical_id` is ON DELETE SET NULL, so deleting the asset would
    have left the denial with no identity anywhere on it.

    Denied via `probe_class = no_probe`, which this gate enforces only under
    `enforce`; the row is written in BOTH modes (it is the return value that
    is mode-gated), so no app_settings mutation is needed here.

    MUTATION: removing the two new keys from the ownership evidence dict
    fails this and nothing else.
    """
    scan_run_id = uuid.uuid4()
    hostname = f"pa209-{uuid.uuid4().hex[:12]}.example.net"
    db = SessionLocal()
    try:
        canonical = _mk_typed_dns_record(db, hostname, alloc_ip())
        db.add(AssetState(
            asset_canonical_id=canonical.id,
            attributes={"probe_class": "no_probe"},
            projected_at=datetime.now(timezone.utc),
        ))
        db.commit()

        pa.authorise_ownership_probe(
            db, asset_canonical_ids=[canonical.id],
            subject=hostname, scan_run_id=scan_run_id,
        )

        rows = _rows_for(db, scan_run_id)
        assert len(rows) == 1, rows
        row = rows[0]
        # precondition: the branch under test, not some other denial
        assert row.evidence_snapshot["decision_scope"] == "ownership_probe", row.evidence_snapshot
        assert row.rule_fired == "probe_class:no_probe", row.rule_fired

        assert row.evidence_snapshot["asset_type"] == "dns_record", row.evidence_snapshot
        assert row.evidence_snapshot["asset_value"] == hostname, row.evidence_snapshot
    finally:
        db.close()
        _cleanup(scan_run_id, [hostname])


def _run():
    tests = [
        test_unresolved_asset_denial_still_records_what_it_denied,
        test_a_resolvable_asset_still_reports_the_canonical_identity,
        test_declaration_failure_rows_record_identity_for_every_asset,
        test_ownership_probe_denial_records_identity,
    ]
    for fn in tests:
        fn()
        print(f"ok  {fn.__name__}")
    print("all passed")


if __name__ == "__main__":
    _run()
