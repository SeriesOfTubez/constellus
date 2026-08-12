"""Shared-infra finding verifier — planning#77 (MVP scope) / planning#103
(epic#81 Phase A Layer 5) / planning#108 (Phase D, ownership_unverifiable) /
planning#113 (Phase D follow-up L1, the IP-level widening below).

Host-level findings from passive sources (Shodan `vulns`) get pinned to an
IP, then bleed onto every asset whose DNS points at that IP — even when the
vulnerable thing belongs to a different tenant on shared hosting (the
contoso.com/jQuery motivating case, epic#81). This module reproduces the
manual ownership proof: for a finding's IP, enumerate the hostnames we own
that resolve to it, probe each for domain affinity (planning#102), and
write a verdict — confirmed_ours / rejected_shared_infra / unverified /
ownership_unverifiable — onto the finding, with evidence, so it's auditable
and reversible rather than silently dropped.

Also Phase-A scope: only DIRECT A/AAAA dns_records pointing at the finding's
IP are enumerated as "owned hostnames" — a CNAME chain that terminates at
the IP through one or more hops is not walked backward here (that's a
different traversal from domain_affinity.resolve_origin's forward walk).
Extend _owned_hostnames_for_ip if direct records prove insufficient.

Phase D (planning#108) added a fourth verdict, `ownership_unverifiable`, for
the case Phase A's own aggregate rule deliberately leaves at 'unverified':
not a clean unanimous not_affine (that's still 'rejected_shared_infra's
job — direct disproof), but positive counter-evidence exists that the
origin genuinely serves a different, unrelated tenant. Fires ONLY on
positive evidence, never on bare inconclusiveness — widening the trigger
to any 'unverified' case would reintroduce the exact false-rejection risk
the unanimity rule above exists to prevent. Gated behind a cheap
hosting_classifier.is_datacenter pre-filter so the rate-limited
HackerTarget reverse-IP lookup (services/hosting_classifier.py) is only
spent on plausible shared-hosting IPs.

planning#115 (epic#81 Phase D follow-up L3) adds re-verification: before it,
`stamp_findings_for_ip` only ever touched `verification IS NULL` rows, so a
finding that landed on a decisive verdict (or even a bare 'unverified', pre
the positive-evidence-only fix below) could never be picked up again
automatically — confirmed live permanently stuck (a jQuery CVE finding on
203.0.113.44 that verified once to 'unverified' before #113's caching
architecture existed). Re-verification is a *directional* grace guard, not a
blanket re-stamp:

  - Toward a decisive verdict from no prior verdict (`verification IS NULL`)
    -> immediate, unchanged Phase A/#113 behavior (still nothing stamps on a
    bare 'unverified' classification — the positive-evidence-only invariant).
  - Away from an ALREADY-decisive verdict (`confirmed_ours` /
    `rejected_shared_infra` / `ownership_unverifiable`) toward a *different*
    verdict -> grace-guarded. The first contrary classification is recorded
    (`verification_evidence["_pending_reversal"]`) but not applied; only once
    the SAME contrary verdict has persisted for `_OWNERSHIP_UNSEGREGATE_GRACE_DAYS`
    does it actually flip. A flaky single-run HackerTarget/SNI-probe failure
    must not churn a finding in and out of the excluded list (which
    re-notifies) or silently downgrade `confirmed_ours`. This single rule
    covers both of the issue's named cases (an excluded finding returning to
    the main list, and `confirmed_ours` never silently downgrading) plus the
    unaddressed case of one decisive verdict flipping straight to a
    different one — all are "current is decisive, new verdict disagrees."
  - The manual "Re-verify" button (`POST /findings/{id}/verify`) sets
    `force=True` end to end (classify_ip_ownership skips its TTL cache;
    stamp_findings_for_ip applies the fresh verdict outright, bypassing the
    grace guard) — an explicit human action wins over automatic cadence.
    This is also the only way to downgrade `confirmed_ours` outside of
    sustained automatic contrary evidence.

planning#113 changes WHERE the decision rule runs and WHICH findings it
reaches — the rule itself (unanimity-for-rejection, affine-wins-outright,
positive-evidence-only ownership_unverifiable) is unchanged:

  - Before #113: the rule ran once PER FINDING (the old verify_finding),
    scoped to Shodan-sourced findings (VERIFIABLE_SOURCES) newly-touched
    this scan run. An IP with 4 Shodan CVE findings ran the full probe —
    including the rate-limited HackerTarget reverse-IP lookup — FOUR
    separate times, once per finding sharing that IP.
  - After #113: the rule runs once PER IP (classify_ip_ownership), cached
    on the ip_address asset (mirroring hosting_classifier's TTL-cache
    pattern), then stamped onto EVERY eligible finding on that IP
    (stamp_findings_for_ip) regardless of source/finding_type. This closes
    the gap flagged in the epic#81 Phase D vault doc §4: an exposed_service
    finding (source=constellus) on the same shared-hosting IP as the
    contoso.com jQuery CVEs (source=shodan) previously got none of this
    treatment, purely because VERIFIABLE_SOURCES didn't include it.

Selection population also widens from touched-this-run-only to
target_scope.target_scoped_asset_ids(scope) | touched_asset_ids, so a
target authorized once keeps getting classified on every run, not only
runs where some connector happened to re-touch its assets. See
services/target_scope.py for the three-legged selection and why the union
(never a replacement) is required — an IP/CIDR-scoped target has zero
TargetAssetLink rows, so a naive replacement would silently stop verifying
it forever (a real regression caught by a Fable-model pressure-test of the
first plan, epic#81 Phase D vault doc §9.2).
"""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.apex import apex_domain
from app.models.asset_canonical import AssetCanonical
from app.models.finding_canonical import FindingCanonical
from app.services import domain_affinity, hosting_classifier, origin_corroboration, target_scope

log = logging.getLogger(__name__)

# dangling_dns findings are themselves derived from the same origin-liveness
# machinery this module leans on (domain_affinity / origin_corroboration) —
# stamping them with an *ownership* verdict on top would be circular.
# Retires the old VERIFIABLE_SOURCES=={"shodan"} allowlist: the widened
# selection below now reaches every source/finding_type by default, so the
# one type that genuinely needs excluding is named directly instead.
# dangling_dns gets its own selection-helper rewire in a separate follow-up
# (planning#114), not here.
NON_STAMPABLE_FINDING_TYPES = frozenset({"dangling_dns"})

# Same curated, conservative product set origin_corroboration.corroborate_tech_absence
# gates on — kept in one place there; referenced here for the title/description hint.
_FINGERPRINTABLE_PRODUCTS = origin_corroboration._FINGERPRINTABLE_PRODUCTS

# How long a computed IP-level ownership verdict is trusted before
# classify_ip_ownership recomputes it live, rather than re-running Layer 1's
# live domain_affinity probes (and potentially the rate-limited
# hosting_classifier.reverse_ip_domains lookup) on every single scan run for
# an IP already classified. Matches the order of magnitude of
# hosting_classifier.reverse_ip_domains' own 14-day TTL, since
# ownership_unverifiable's freshness is gated by that same data source.
_OWNERSHIP_VERDICT_TTL = timedelta(days=14)

# planning#115 — how long a contrary automatic re-verification must persist
# before it's allowed to move a finding OUT of an already-decisive verdict
# (confirmed_ours / rejected_shared_infra / ownership_unverifiable). Matches
# the house convention for this kind of flap guard (_DANGLING_GRACE_DAYS,
# asset_writer._CONFIRMED_PORT_GRACE_DAYS — both 3 days).
_OWNERSHIP_UNSEGREGATE_GRACE_DAYS = 3


def _owned_hostnames_for_ip(db: Session, ip: str) -> list[AssetCanonical]:
    """dns_record assets whose stored A/AAAA content is exactly `ip`."""
    return (
        db.query(AssetCanonical)
        .filter(AssetCanonical.asset_type == "dns_record")
        .filter(AssetCanonical.asset_metadata["record_type"].astext.in_(["A", "AAAA"]))
        .filter(AssetCanonical.asset_metadata["content"].astext == ip)
        .all()
    )


def classify_ip_ownership(db: Session, ip_asset: AssetCanonical, force: bool = False) -> dict:
    """Compute (or reuse a cached) ownership verdict for one ip_address
    asset. Hoisted from the old per-finding verify_finding — the decision
    rule itself (module docstring above) is unchanged; this just runs it
    once per IP instead of once per finding sharing that IP.

    `force=True` (planning#115, the manual "Re-verify" button) skips the
    cache read entirely and always recomputes live — an explicit human
    action shouldn't wait out the TTL. The fresh result still gets written
    to the cache afterward as normal, refreshing the TTL clock.

    Returns {"verdict": ..., "evidence": {...}, "matrices": {...}}.
    `evidence` is the exact shape written onto each finding's
    verification_evidence (stamp_findings_for_ip merges in a per-finding
    tech_absence on top of it); `matrices` carries the raw per-hostname
    domain_affinity probe matrices so tech_absence can still be computed
    per-finding on a cache HIT, where the live probe that produced them
    didn't run this call.
    """
    cached = None if force else _read_cache(ip_asset)
    if cached is not None:
        return cached

    now = datetime.now(timezone.utc)
    owned = _owned_hostnames_for_ip(db, ip_asset.value)

    if not owned:
        # Can't reproduce the check — never asserts ownership either way.
        # Matches #77's "can't reproduce -> unverified" case (no owned vhost
        # answers, just here it's "no owned vhost exists to ask"). A stable,
        # cheaply-recomputed fact — safe to cache at the full TTL.
        result = {
            "verdict": "unverified",
            "evidence": {"ip": ip_asset.value, "reason": "no owned hostnames resolve to this IP"},
            "matrices": {},
        }
        _write_cache(db, ip_asset, result, now)
        return result

    apexes = {apex_domain(h.value) for h in owned}
    per_hostname: dict[str, dict] = {}
    matrices: dict[str, dict] = {}
    verdicts: list[str] = []

    for host in owned:
        probe = domain_affinity.check_affinity(host.value, ip_asset.value, apexes)
        per_hostname[host.value] = {"verdict": probe.verdict, "signals": probe.signals}
        matrices[host.value] = probe.matrix
        verdicts.append(probe.verdict)

    # Any confirmed affinity wins outright — one legitimately-ours hostname
    # on a shared IP is enough to call the finding ours (multiple subdomains
    # sharing an IP, only some actively used, is a normal shape).
    #
    # Rejection requires UNANIMITY: every owned hostname was actually
    # checked and NONE showed affinity. A not_affine verdict on hostname X
    # only tells us about X — it says nothing about hostname Y sitting at
    # indeterminate (couldn't be probed) on the same IP, which could still
    # be the actually-vulnerable vhost. Live-tested case that motivated
    # this (planning#103): an IP with 4 owned hostnames where only 1 came
    # back not_affine and the other 3 were indeterminate (unreachable) —
    # rejecting on that 1-of-4 would have been a false rejection exactly as
    # damaging as a false attribution (#77's own framing). Only when
    # indeterminate is entirely ABSENT and every hostname voted not_affine
    # do we reject; any indeterminate mixed in falls through to unverified.
    if "affine" in verdicts:
        verdict = "confirmed_ours"
    elif verdicts and all(v == "not_affine" for v in verdicts):
        verdict = "rejected_shared_infra"
    else:
        verdict = "unverified"

    evidence: dict = {"ip": ip_asset.value, "hostnames": per_hostname}
    cacheable = True

    # Phase D (planning#108): only reachable from the 'unverified' branch —
    # never widens rejected_shared_infra into a hard reject, never fires on
    # confirmed_ours.
    if verdict == "unverified":
        hosting = hosting_classifier.classify_ip(db, ip_asset.value)
        if not hosting.attempted:
            # Same budget-starvation shape as the HackerTarget guard below,
            # caught in review (planning#113 Fable review, finding 2): a
            # failed/quota-exhausted ipapi.is lookup fails soft to
            # is_datacenter=False (hosting_classifier.py) — indistinguishable
            # from a genuine "checked, not a datacenter" determination unless
            # the caller checks `attempted`. Caching an unattempted lookup at
            # the full TTL would mislabel the IP as non-datacenter (skipping
            # corroboration entirely) for 14 days on what might be a
            # transient failure.
            cacheable = False
        elif hosting.is_datacenter:
            corroboration = origin_corroboration.corroborate_liveness(
                db, ip_asset.value, owned[0].value, apexes,
            )
            if not corroboration.attempted:
                # Budget-starvation guard (planning#113 Fable review,
                # regression 2, epic#81 Phase D vault doc §9.2):
                # corroborate_liveness came up empty because
                # hosting_classifier's ~15/day HackerTarget budget was
                # already spent this call, not because there's genuinely
                # nothing to corroborate against. Caching THIS result at
                # the full TTL would burn the day's budget on ~15 IPs and
                # then pin every other IP at unverified for the whole TTL
                # window — leave the cache untouched instead, so the next
                # call (this run's next IP, or tomorrow's run) tries fresh.
                cacheable = False
            elif corroboration.origin_serves_others:
                verdict = "ownership_unverifiable"
                evidence["hosting_class"] = {
                    "company_name": hosting.company_name, "asn": hosting.asn,
                }
                evidence["corroboration"] = {
                    "origin_serves_others": corroboration.origin_serves_others,
                    "corroborating_hostname": corroboration.corroborating_hostname,
                    "evidence": corroboration.evidence,
                    "hostnames_probed": corroboration.hostnames_probed,
                }

    result = {"verdict": verdict, "evidence": evidence, "matrices": matrices}
    if cacheable:
        _write_cache(db, ip_asset, result, now)
    return result


def _read_cache(ip_asset: AssetCanonical) -> dict | None:
    meta = ip_asset.asset_metadata or {}
    cached = meta.get("ownership_verdict")
    fetched_at = meta.get("ownership_verdict_at")
    if not cached or not fetched_at:
        return None
    try:
        age = datetime.now(timezone.utc) - datetime.fromisoformat(fetched_at)
    except ValueError:
        return None
    if age >= _OWNERSHIP_VERDICT_TTL:
        return None
    return cached


def _write_cache(db: Session, ip_asset: AssetCanonical, result: dict, now: datetime) -> None:
    ip_asset.asset_metadata = {
        **(ip_asset.asset_metadata or {}),
        "ownership_verdict": result,
        "ownership_verdict_at": now.isoformat(),
    }
    db.commit()


def stamp_findings_for_ip(
    db: Session, ip_asset: AssetCanonical, classification: dict, force: bool = False,
) -> set:
    """Write classification's verdict onto eligible findings attached to
    ip_asset — any finding_type/source (planning#113 widens this beyond the
    old Shodan-only VERIFIABLE_SOURCES scope; see module docstring).

    Positive-evidence-only at the stamp layer: a plain 'unverified'
    classification never stamps a finding that has no prior verdict, leaving
    it NULL (planning#113 Fable review, finding 1) — required for
    classify_ip_ownership's own budget-starvation guards to work (they
    refuse to CACHE an inconclusive verdict so the IP gets retried fresh;
    stamping 'unverified' onto a NULL finding would permanently lock it out
    of ever receiving the real verdict once the retry succeeds).

    planning#115 adds directional re-verification for findings that already
    hold a decisive verdict (confirmed_ours / rejected_shared_infra /
    ownership_unverifiable):
      - `force=True` (the manual "Re-verify" button only): re-evaluate and
        apply the fresh classification outright, regardless of current
        verification value — an explicit human action wins over automatic
        cadence/grace guards, and is the only way to downgrade
        `confirmed_ours` outside of sustained automatic contrary evidence.
      - `force=False` (every automatic scan run): a fresh verdict that
        DISAGREES with a finding's current decisive verdict is grace-guarded
        — see _apply_or_record_contrary. A finding with no prior verdict
        still gets the immediate "verify once" treatment unchanged from
        Phase A/#113.
    """
    verdict = classification["verdict"]
    if verdict == "unverified" and not force:
        return set()

    findings = (
        db.query(FindingCanonical)
        .filter(
            FindingCanonical.asset_canonical_id == ip_asset.id,
            ~FindingCanonical.finding_type.in_(NON_STAMPABLE_FINDING_TYPES),
        )
        .all()
    )
    if not findings:
        return set()

    base_evidence = classification["evidence"]
    matrices = classification.get("matrices") or {}
    now = datetime.now(timezone.utc)

    stamped: set = set()
    for finding in findings:
        if force:
            # Always reapply under an explicit human re-verify, even when the
            # verdict comes back unchanged — the point of the click is a
            # fresh confirmation (updated verified_at/evidence), not just a
            # value flip.
            _apply_verdict(finding, verdict, base_evidence, matrices, now)
            stamped.add(finding.id)
            continue

        if finding.verification == verdict:
            continue  # already matches — nothing to change

        if finding.verification is None:
            # Toward a decisive verdict from no prior verdict — immediate,
            # unchanged Phase A/#113 behavior. A plain 'unverified'
            # classification still stamps nothing (positive-evidence-only).
            if verdict != "unverified":
                _apply_verdict(finding, verdict, base_evidence, matrices, now)
                stamped.add(finding.id)
            continue

        # finding.verification already holds a decisive verdict and the
        # fresh classification disagrees — grace-guarded reversal.
        if _contrary_signal_past_grace(finding, verdict, now):
            _apply_verdict(finding, verdict, base_evidence, matrices, now)
            stamped.add(finding.id)

    return stamped


def _apply_verdict(finding: FindingCanonical, verdict: str, base_evidence: dict, matrices: dict, now: datetime) -> None:
    evidence = dict(base_evidence)
    if verdict == "ownership_unverifiable":
        product = _cve_product_hint(finding)
        if product:
            for matrix in matrices.values():
                tech_absence = origin_corroboration.corroborate_tech_absence(matrix, product)
                if tech_absence:
                    evidence["tech_absence"] = tech_absence
                    break
    # Applying any verdict clears prior reversal-tracking state — a fresh
    # decisive verdict resets the grace clock, it doesn't inherit it.
    finding.verification = verdict
    finding.verification_evidence = evidence
    finding.verified_at = now


def _contrary_signal_past_grace(finding: FindingCanonical, new_verdict: str, now: datetime) -> bool:
    """planning#115 directional grace guard: True once `new_verdict` has
    been the CONSISTENT contrary result for at least
    _OWNERSHIP_UNSEGREGATE_GRACE_DAYS; False (and records this as the first
    contrary observation) otherwise. A contrary verdict that differs from
    whatever was previously pending restarts the clock — only a sustained,
    consistent signal counts, so a single flaky HackerTarget/SNI-probe
    failure can't churn a finding in and out of the excluded list."""
    evidence = finding.verification_evidence or {}
    pending = evidence.get("_pending_reversal") or {}

    if pending.get("verdict") == new_verdict:
        first_seen_at = pending.get("first_seen_at")
        try:
            elapsed = now - datetime.fromisoformat(first_seen_at)
        except (TypeError, ValueError):
            elapsed = timedelta(0)
        return elapsed >= timedelta(days=_OWNERSHIP_UNSEGREGATE_GRACE_DAYS)

    finding.verification_evidence = {
        **evidence,
        "_pending_reversal": {"verdict": new_verdict, "first_seen_at": now.isoformat()},
    }
    return False


def _cve_product_hint(finding: FindingCanonical) -> str | None:
    """Cheap substring match against the finding's own title/description for
    one of the curated _FINGERPRINTABLE_PRODUCTS names. Not real CPE-based
    product identification — FindingCanonical has no normalized product
    field to key off today — a deliberately simple starting point,
    consistent with shipping tech-absence explain-only until it's watched
    against real data."""
    if not finding.cve_id:
        return None
    text = f"{finding.title or ''} {finding.description or ''}".lower()
    for product in _FINGERPRINTABLE_PRODUCTS:
        if product in text:
            return product
    return None


def verify_findings(db: Session, scope: dict, touched_asset_ids: set, force: bool = False) -> set:
    """Post-scan step (scan_executor.py — runs after match_versions so
    same-run version_match findings get stamped too, not a full run late;
    see the executor's comment for the ordering fix this closed).

    Classifies every ip_address asset in the run's authorized target scope
    (planning#113: target_scope.target_scoped_asset_ids(scope), unioned
    with touched_asset_ids — see that module for why the union, not a
    replacement, is required), then stamps each IP's verdict onto every
    eligible finding attached to it.

    `force=True` (planning#115 — set only by the manual "Re-verify" scan
    kicked off from POST /findings/{id}/verify, via scan_executor's
    `force_reverify` option) bypasses classify_ip_ownership's TTL cache and
    stamp_findings_for_ip's directional grace guard for every IP this call
    touches.

    Returns the set of finding ids that got a verdict written, so the
    executor can log/count them like every other post-scan step.
    """
    asset_ids = target_scope.target_scoped_asset_ids(db, scope) | touched_asset_ids
    if not asset_ids:
        return set()

    ip_assets = (
        db.query(AssetCanonical)
        .filter(AssetCanonical.id.in_(asset_ids), AssetCanonical.asset_type == "ip_address")
        .all()
    )
    if not ip_assets:
        return set()

    stamped: set = set()
    for ip_asset in ip_assets:
        try:
            classification = classify_ip_ownership(db, ip_asset, force=force)
            ip_stamped = stamp_findings_for_ip(db, ip_asset, classification, force=force)
            if ip_stamped:
                # Commit per-IP rather than deferring to one commit at the
                # end of the loop: classify_ip_ownership's own cache write
                # already commits internally, so a later IP's failure below
                # would otherwise roll back THIS IP's already-computed,
                # still-pending finding stamps too — turning one bad IP into
                # data loss for every IP processed before it in the same
                # run. Committing here bounds that blast radius to the
                # failing IP alone.
                db.commit()
                stamped |= ip_stamped
        except Exception:
            log.exception("shared_infra_verifier: failed to classify/stamp IP %s", ip_asset.value)
            # A DB-level failure (e.g. an IntegrityError from a writer)
            # leaves the session's transaction aborted — the very next
            # statement (the next IP's query) would itself raise
            # PendingRollbackError and abort the whole loop instead of just
            # this IP. Roll back first so the session recovers cleanly;
            # everything already committed above for prior IPs is
            # unaffected (mirrors scan_executor's own chunk-loop fix).
            db.rollback()

    if stamped:
        log.info(
            "shared_infra_verifier: stamped %d finding(s) across %d IP(s)",
            len(stamped), len(ip_assets),
        )
    return stamped
