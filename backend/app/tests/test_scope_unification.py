"""One authorisation policy across both scope gates — planning#197.

Scope containment was implemented twice, over two keyspaces:

  - `target_service.is_scan_authorised` — over a VALUE, gating Phase 1
    discovery ENUMERATION.
  - `probe_authorisation._resolve_scoped_ids` — over SCOPE ENTRIES, whose
    result feeds `_scope_cap` and gates PROBING.

Their docstrings each claimed to mirror the other. They did not. The
authorisation half — which declared targets count under a given
`scan_authorisation_mode`, and in what order verification is applied
relative to containment — was written out twice and kept in step by hand,
and had drifted in **both directions at once**:

  strict       probe gate TOO NARROW. `_resolve_scoped_ids` narrowed scope
               entries with `Target.value.in_(declared)` — string equality
               — so an entry covered by a verified target but not equal to
               one (a subdomain of a verified apex; an address inside a
               verified CIDR, both of which arise from a per-asset recheck
               or a one-shot run) was discarded. The scope set came back
               EMPTY and every asset in the run was denied
               `scope:out_of_scope`, while discovery authorised the same
               value. This is planning#128's own string-equality bug,
               reintroduced one layer up inside the function whose
               docstring asserted it had been fixed.

  acknowledge  probe gate TOO WIDE. No entry filter ran at all under this
               mode, so an entry no target covers was kept and its assets
               authorised for probing — while discovery refused to
               enumerate the same value. A gate being more permissive than
               the enumeration step above it is the wrong direction.

Both were reproduced live before the fix was written, not inferred from
reading the code. These tests are those repros, kept.

The fix is not a merge of the two functions — see
`probe_authorisation.authorise_discovery`, which must still not route
first-run discovery through `_scope_cap`. It is one definition of the
authorisation half (`target_scope.authorised_target_pool`) consumed by
both, with the keyspaces left apart.

Run with:  backend/scripts/test.ps1 app/tests/test_scope_unification.py
"""

import ipaddress
import uuid

import pytest

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.target import Target, TargetType
from app.models.target_asset_link import TargetAssetLink
from app.services.probe_authorisation import _resolve_scoped_ids
from app.services.target_scope import authorised_target_pool, entry_in_target_scope
from app.services.target_service import is_scan_authorised
from app.tests import _docaddr


def _seed_target(db, value: str, target_type: str, *, verified: bool = True) -> Target:
    """Delete-then-insert one Target — `Target.value` is globally UNIQUE, so
    a row stranded by a run that died before cleanup would otherwise make a
    later run's INSERT fail (planning#170, planning#199)."""
    db.query(Target).filter(Target.value == value).delete(synchronize_session=False)
    db.commit()
    target = Target(id=uuid.uuid4(), type=target_type, value=value, verified=verified)
    db.add(target)
    db.commit()
    return target


def _seed_asset(db, *, asset_type: str, value: str) -> AssetCanonical:
    asset = AssetCanonical(id=uuid.uuid4(), asset_type=asset_type, value=value)
    db.add(asset)
    db.commit()
    return asset


def _cleanup(db, values: list[str]) -> None:
    """Assets before targets. Every value here is either a uuid-suffixed
    hostname or drawn from `_docaddr`, so delete-by-value cannot reach
    another module's rows (planning#199)."""
    if values:
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).delete(
            synchronize_session=False
        )
        db.query(Target).filter(Target.value.in_(values)).delete(synchronize_session=False)
    db.commit()


def _domain(tag: str) -> str:
    return f"s197-{tag}-{uuid.uuid4().hex[:10]}.example.com"


# ── The acceptance test: first-run discovery must keep working ───────────────


def test_first_run_discovery_against_a_brand_new_target_is_authorised():
    """A target added a moment ago, with ZERO canonical rows anywhere, is
    authorised for discovery — apex and subdomain alike, under every gating
    mode.

    This is planning#197's stated acceptance criterion and it had no test.
    It is the regression the issue was most worried about: `_scope_cap`
    denies an asset with no canonical row (`scope:unresolved_asset`), and
    for a domain before its first discovery run "unresolved" is the NORMAL
    state — `assets_canonical` identity for `dns_record` is per RECORD, and
    `write_assets` runs after the discovery tools. So routing the discovery
    gate through the asset-shaped implementation would deny every first
    run.

    It does not, because the domain keyspace never consults a canonical row
    to answer a NAME: `value_in_target_scope`'s final leg is a pure suffix
    match. The asset-shaped path is not on this code path at all. Pinning
    that here means a future "simplification" that routes discovery through
    `target_scoped_asset_ids` fails loudly instead of silently killing
    onboarding.
    """
    apex = _domain("firstrun")
    sub = f"api.{apex}"

    db = SessionLocal()
    try:
        _seed_target(db, apex, TargetType.DOMAIN, verified=True)

        # Nothing has been discovered yet — assert that, rather than assuming it.
        assert db.query(AssetCanonical).filter(
            AssetCanonical.value.in_([apex, sub])
        ).count() == 0

        for mode in ("strict", "acknowledge", "disabled"):
            assert is_scan_authorised(db, apex, mode) is True, mode
            assert is_scan_authorised(db, sub, mode) is True, mode
    finally:
        _cleanup(db, [apex, sub])
        db.close()


def test_first_run_discovery_is_still_denied_for_an_undeclared_domain():
    """The companion to the above — "no canonical rows" must not become a
    blanket permit. A name no target covers is denied even though it is
    equally unresolved."""
    apex = _domain("firstrun-ok")
    stranger = f"s197-stranger-{uuid.uuid4().hex[:10]}.example.net"

    db = SessionLocal()
    try:
        _seed_target(db, apex, TargetType.DOMAIN, verified=True)
        assert is_scan_authorised(db, stranger, "strict") is False
        assert is_scan_authorised(db, stranger, "acknowledge") is False
    finally:
        _cleanup(db, [apex, stranger])
        db.close()


# ── The drift, direction 1: strict was too narrow ────────────────────────────


def test_strict_scope_entry_inside_a_verified_cidr_scopes_its_assets():
    """REGRESSION (planning#197). Scope entry is a single address; the
    declared target is the verified /29 containing it — the shape a
    per-asset recheck produces. The old `Target.value.in_(declared)` filter
    found no target row equal to the address, emptied the scope, and denied
    every asset in the run."""
    cidr, inside = _docaddr.alloc_cidr()

    db = SessionLocal()
    try:
        _seed_target(db, cidr, TargetType.CIDR, verified=True)
        asset = _seed_asset(db, asset_type="ip_address", value=inside)

        assert is_scan_authorised(db, inside, "strict") is True
        scoped = _resolve_scoped_ids(db, {"domains": [], "ip_ranges": [inside]}, "strict")
        assert asset.id in scoped
    finally:
        _cleanup(db, [inside, cidr])
        db.close()


def test_strict_scope_entry_under_a_verified_apex_scopes_its_assets():
    """REGRESSION (planning#197). Same bug, domain keyspace: the entry is a
    subdomain of the verified apex and is not itself a target row.

    This also pins the subtlest part of the change, so note what is NOT in
    the scope dict: the apex. The entries being filtered are the run's
    scope; the targets they are filtered against are the whole declared
    inventory. Those are different sets — `_resolve_dynamic_scope`
    partitions the inventory by cadence tier, so a template's scope is a
    subset of it. If the pool were the run's own scope, "authorised" would
    mean "whatever this template owns this cycle", and a verified apex
    would stop authorising its subdomains whenever a tier template that
    does not own the apex was the one running.
    """
    apex = _domain("narrow")
    sub = f"api.{apex}"

    db = SessionLocal()
    try:
        _seed_target(db, apex, TargetType.DOMAIN, verified=True)
        asset = _seed_asset(db, asset_type="dns_record", value=sub)

        assert is_scan_authorised(db, sub, "strict") is True
        scoped = _resolve_scoped_ids(db, {"domains": [sub], "ip_ranges": []}, "strict")
        assert asset.id in scoped
    finally:
        _cleanup(db, [apex, sub])
        db.close()


def test_strict_still_requires_verification_of_the_covering_target():
    """The planning#197 fix widened `strict` — it must not have dissolved
    it. Coverage by an UNVERIFIED target authorises nothing, while the same
    coverage under `acknowledge` does."""
    apex = _domain("unverified")
    sub = f"api.{apex}"

    db = SessionLocal()
    try:
        _seed_target(db, apex, TargetType.DOMAIN, verified=False)
        asset = _seed_asset(db, asset_type="dns_record", value=sub)

        assert is_scan_authorised(db, sub, "strict") is False
        assert _resolve_scoped_ids(db, {"domains": [sub], "ip_ranges": []}, "strict") == frozenset()

        assert is_scan_authorised(db, sub, "acknowledge") is True
        assert asset.id in _resolve_scoped_ids(
            db, {"domains": [sub], "ip_ranges": []}, "acknowledge"
        )
    finally:
        _cleanup(db, [apex, sub])
        db.close()


# ── The drift, direction 2: acknowledge was too wide ─────────────────────────


def test_acknowledge_drops_a_scope_entry_no_target_covers():
    """REGRESSION (planning#197), and the dangerous direction. `acknowledge`
    used to apply NO entry filter, so a scope entry outside every declared
    target had its assets authorised for probing — while discovery refused
    to enumerate the very same value."""
    apex = _domain("wide")
    stranger = f"s197-wide-{uuid.uuid4().hex[:10]}.example.net"

    db = SessionLocal()
    try:
        _seed_target(db, apex, TargetType.DOMAIN, verified=True)
        asset = _seed_asset(db, asset_type="dns_record", value=stranger)

        assert is_scan_authorised(db, stranger, "acknowledge") is False
        scoped = _resolve_scoped_ids(db, {"domains": [stranger], "ip_ranges": []}, "acknowledge")
        assert asset.id not in scoped
    finally:
        _cleanup(db, [apex, stranger])
        db.close()


# ── The anti-drift invariant ─────────────────────────────────────────────────


def test_both_gates_agree_on_every_value_under_strict_and_acknowledge():
    """THE invariant planning#197 exists to establish: for the same value
    and the same mode, the enumeration gate and the probe gate reach the
    same verdict.

    `disabled` is deliberately excluded. Under it `is_scan_authorised`
    returns True while `_resolve_scoped_ids` returns an EMPTY set — not a
    disagreement, because `_scope_cap` short-circuits on `disabled` before
    it ever reads the set, so building one would be waste. That
    short-circuit is pinned separately below.
    """
    apex = _domain("agree")
    sub = f"api.{apex}"
    stranger = f"s197-agree-{uuid.uuid4().hex[:10]}.example.net"
    cidr, inside = _docaddr.alloc_cidr()
    outside = _docaddr.alloc()

    db = SessionLocal()
    try:
        _seed_target(db, apex, TargetType.DOMAIN, verified=True)
        _seed_target(db, cidr, TargetType.CIDR, verified=True)
        assets = {
            sub: _seed_asset(db, asset_type="dns_record", value=sub),
            stranger: _seed_asset(db, asset_type="dns_record", value=stranger),
            inside: _seed_asset(db, asset_type="ip_address", value=inside),
            outside: _seed_asset(db, asset_type="ip_address", value=outside),
        }
        names = (sub, stranger)
        addresses = (inside, outside)

        for mode in ("strict", "acknowledge"):
            for value in names + addresses:
                key = "domains" if value in names else "ip_ranges"
                other = "ip_ranges" if key == "domains" else "domains"
                enumerated = is_scan_authorised(db, value, mode)
                probed = assets[value].id in _resolve_scoped_ids(
                    db, {key: [value], other: []}, mode
                )
                assert enumerated == probed, (
                    f"gates disagree on {value!r} under {mode!r}: "
                    f"enumeration={enumerated}, probe={probed}"
                )
    finally:
        _cleanup(db, [apex, sub, stranger, cidr, inside, outside])
        db.close()


def test_the_widening_reaches_leg_1_links_of_a_covered_subdomain_target():
    """Pins the furthest consequence of the `strict` widening, because it is
    the thing a reviewer should check and it is NOT self-evident.

    `target_scoped_asset_ids` unions leg 1 (`TargetAssetLink`), which links
    every asset in a domain's discovery batch to that domain's target —
    including, per `value_in_target_scope`'s own warning, a CNAME boundary
    target or shared-hosting IP belonging to a third party. Leg 1 is why
    `_scope_cap`'s answer is a strict SUPERSET of `is_scan_authorised`'s,
    and that asymmetry is pre-existing and deliberate.

    planning#197 widens which ENTRIES feed leg 1 under `strict`: previously
    only entries that were themselves verified targets, now also entries
    covered by a verified target. So an unverified subdomain target under a
    verified apex now contributes its leg-1 links — including ones outside
    the apex, as asserted here.

    This is consistent rather than new: the verified apex, whenever it is
    in scope, already contributes exactly the same kind of link. The
    widening applies the existing rule to entries that were always
    authorised; it does not create a new class of over-inclusion. Narrowing
    leg 1 is a separate question about `target_scoped_asset_ids` and about
    third-party attribution, deliberately NOT decided here.

    In the other direction planning#197 made leg 1 stricter, not looser:
    `acknowledge` used to feed it EVERY scope entry, uncovered ones
    included.
    """
    apex = _domain("leg1")
    sub = f"api.{apex}"
    stranger = f"s197-cname-{uuid.uuid4().hex[:10]}.example.net"

    db = SessionLocal()
    try:
        _seed_target(db, apex, TargetType.DOMAIN, verified=True)
        sub_target = _seed_target(db, sub, TargetType.DOMAIN, verified=False)
        # A third-party CNAME destination, linked to the subdomain target by
        # the discovery batch — outside the verified apex entirely.
        offsite = _seed_asset(db, asset_type="dns_record", value=stranger)
        db.add(TargetAssetLink(target_id=sub_target.id, asset_canonical_id=offsite.id))
        db.commit()

        # The subdomain is unverified, so before planning#197 the entry was
        # dropped by string equality and nothing was scoped.
        scoped = _resolve_scoped_ids(db, {"domains": [sub], "ip_ranges": []}, "strict")
        assert offsite.id in scoped

        # The enumeration gate still refuses the offsite name itself — it
        # omits leg 1, which is exactly why its answer is the subset.
        assert is_scan_authorised(db, stranger, "strict") is False
    finally:
        db.query(TargetAssetLink).filter(
            TargetAssetLink.asset_canonical_id == offsite.id
        ).delete(synchronize_session=False)
        db.commit()
        _cleanup(db, [apex, sub, stranger])
        db.close()


def test_an_unrecognised_mode_fails_closed_on_both_paths():
    """Neither gate may treat a typo'd mode as permissive. Both must route
    it to `strict`, which is now one branch rather than two."""
    apex = _domain("badmode")
    sub = f"api.{apex}"

    db = SessionLocal()
    try:
        _seed_target(db, apex, TargetType.DOMAIN, verified=False)
        asset = _seed_asset(db, asset_type="dns_record", value=sub)

        assert is_scan_authorised(db, sub, "acknowledgeed") is False
        assert asset.id not in _resolve_scoped_ids(
            db, {"domains": [sub], "ip_ranges": []}, "acknowledgeed"
        )
    finally:
        _cleanup(db, [apex, sub])
        db.close()


def test_disabled_short_circuits_before_any_query_on_both_paths():
    """Passing `None` as the session proves neither path touches the DB."""
    assert is_scan_authorised(None, "anything.example.com", "disabled") is True
    assert _resolve_scoped_ids(None, {"domains": ["anything.example.com"]}, "disabled") == frozenset()


def test_authorised_target_pool_refuses_disabled():
    """`disabled` has no honest pool — it means the gate is not consulted.
    Answering it with a narrowed pool would silently under-authorise, so it
    raises instead."""
    with pytest.raises(ValueError, match="disabled"):
        authorised_target_pool(None, "disabled")


# ── entry_in_target_scope's own edges ────────────────────────────────────────


def test_entry_in_target_scope_edges_against_one_declared_range():
    """The three edges of the entry-shaped predicate, against a single
    declared /29.

    One test rather than three because they share a fixture and each
    assertion is one line — and because `alloc_cidr()` draws without
    replacement from a deliberately small pool (see `_docaddr`), so a
    separate declared range per edge spends the pool to say nothing extra.

    - **Exact match** is covered. The floor case.
    - **A merely-overlapping range is NOT.** The entry here is the /28
      CONTAINING the declared /29: it overlaps but is not a subnet, and the
      addresses in its other half were never declared. Half-authorised is
      not authorised.
    - **`/32` and the bare address agree.** The `/32` form takes the
      network branch, so it must be normalised back to a bare address; left
      alone it would fall through to hostname matching and be silently
      denied.
    - **The other address family is denied, not raised.** `subnet_of`
      raises `TypeError` across versions, and a scan must not die on a
      mixed-family scope entry.
    """
    cidr, inside = _docaddr.alloc_cidr()
    supernet = str(ipaddress.ip_network(cidr).supernet(new_prefix=28))

    db = SessionLocal()
    try:
        _seed_target(db, cidr, TargetType.CIDR, verified=True)
        pool = dict(zip(("domains", "ip_ranges"), authorised_target_pool(db, "strict")))

        assert entry_in_target_scope(db, cidr, **pool) is True
        assert entry_in_target_scope(db, supernet, **pool) is False
        assert entry_in_target_scope(db, inside, **pool) is True
        assert entry_in_target_scope(db, f"{inside}/32", **pool) is True
        # RFC 3849 documentation prefix — never a real address.
        assert entry_in_target_scope(db, "2001:db8::/48", **pool) is False
    finally:
        _cleanup(db, [cidr])
        db.close()


def test_an_empty_scope_resolves_without_querying_the_pool():
    """No entries means no assets, and no reason to build a pool. `None` as
    the session proves the short-circuit is real."""
    assert _resolve_scoped_ids(None, {"domains": [], "ip_ranges": []}, "strict") == frozenset()
    assert _resolve_scoped_ids(None, {}, "acknowledge") == frozenset()
