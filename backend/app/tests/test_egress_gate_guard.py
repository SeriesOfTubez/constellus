"""planning#148 acceptance criterion 1, enforced instead of described.

The criterion is that **one authorisation policy is the only path to emitting
an active probe**. Its literal original wording — "a single function" — stopped
being achievable at planning#196, which added `authorise_discovery` as a second
entry point (a domain being enumerated has no canonical identity yet, so an
asset-shaped gate consulted before any asset exists would deny all first-run
discovery). planning#205 added a third, `authorise_ownership_probe`, for the
same class of reason. Three entry points, one policy, each a different shape of
question — that is the design, not drift.

## Why this file exists rather than a table in the issue

planning#205's hand-off recorded the sweep that established the claim as a
**prose table of every egress path**. That is precisely the artefact
`_docaddr`'s own docstring warns about:

    A hand-maintained audit recorded in prose was wrong within one release of
    being written, which is the reason the rule is now executable.

So the sweep is here, as code, and adding a network transport to
`app/services/` fails the build until somebody classifies it.

## The rules

  R1  Every module under `app/services/` that imports a network transport is
      classified in `_EGRESS` below. A new one fails with instructions rather
      than being silently absorbed.

  R2  Every module classified `TARGET` — it can put packets on a host we are
      pointed at — either calls one of the three gate entry points itself, or
      declares which caller gates it, and that caller is checked too.

## What it deliberately does NOT claim

It does not prove a gate is *consulted on every path* through a module. A
module could gate one function and not another — which is exactly the bug
planning#205 nearly shipped, because `domain_affinity` had TWO egress
functions and the issue body named one. That failure is caught by
`test_affinity_probe_gate.py`, per-function and at the transport. This file
catches the coarser, likelier drift: a whole module that reaches the network
and nobody noticed.

Detection is `ast`-based, not textual, and deliberately so: a `grep` for
`httpx` matches `probe_authorisation.py`, which only ever mentions it in
prose. A guard with false positives gets suppressed, and a suppressed guard
is worse than none.

Run with:  backend/scripts/test.ps1 app/tests/test_egress_gate_guard.py
"""

import ast
import os

_SERVICES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "services")
_SERVICES = os.path.normpath(_SERVICES)

# Top-level modules that put bytes on a socket. `dns` is dnspython, whose
# resolver queries a recursor; `socket` covers the stdlib name resolution
# `bruteforce` uses.
_TRANSPORTS = frozenset({"httpx", "requests", "aiohttp", "socket", "ssl", "urllib", "dns", "http"})

# The three entry points onto the one policy (planning#148 / #196 / #205).
_GATES = frozenset({"authorise_probes", "authorise_discovery", "authorise_ownership_probe"})

# ── the sweep, as code ─────────────────────────────────────────────────────
#
# TARGET            — can reach a host we are pointed at. Needs a gate (R2).
# THIRD_PARTY       — reaches a vendor/API on our own behalf. The target never
#                     sees the packet, so there is nothing to authorise.
# ESTABLISHES_AUTH  — a DNS query to a public recursor that is itself the step
#                     by which a target becomes authorised. Gating it on
#                     authorisation would be circular.
#
# `gated_by` names the module that consults the gate, when it is not this one.
# "self" means this module calls a gate directly.
_EGRESS: dict[str, tuple[str, str, str | None]] = {
    "domain_affinity.py": (
        "TARGET", "owned/default vhost probes + corroboration candidates", "self",
    ),
    "tenancy_tls.py": (
        "TARGET", "bare-IP no-SNI handshake, addressing=ip_handshake (planning#181)", "self",
    ),
    "discovery/bruteforce.py": (
        "TARGET", "resolves candidate names under the target's domain", "scan_executor.py",
    ),
    "discovery/dns_records.py": (
        "TARGET", "enumerates the target's own records", "scan_executor.py",
    ),
    "discovery/dns_resolve.py": (
        "TARGET", "resolves the target's names", "scan_executor.py",
    ),
    "discovery/cert_transparency.py": (
        "TARGET", "CT log query ABOUT the target; third_party_infra noise, still gated", "scan_executor.py",
    ),
    "domain_verification.py": (
        "ESTABLISHES_AUTH", "reads _constellus-verify TXT — this IS the authorisation step", None,
    ),
    "target_service.py": (
        "ESTABLISHES_AUTH", "same TXT verification path", None,
    ),
    "cloud_ranges.py": (
        "THIRD_PARTY", "provider range dataset mirror", None,
    ),
    "cpe_cve_sync.py": (
        "THIRD_PARTY", "CPE/CVE bulk data", None,
    ),
    "saml.py": (
        "THIRD_PARTY", "IdP metadata for our own SSO config", None,
    ),
}


def _modules_with_transport() -> dict[str, set[str]]:
    """{relative module path: {transport names}} for everything under
    app/services that IMPORTS a transport.

    Import-based rather than call-based on purpose: a module that pulls in
    `httpx` is the unit a human should have to classify, and an import is far
    harder to obscure than a call (aliases, indirection, a helper in another
    file). It is the coarse question — "does this thing touch the network at
    all" — which is the one that goes unnoticed."""
    found: dict[str, set[str]] = {}
    for dirpath, dirnames, files in os.walk(_SERVICES):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, _SERVICES).replace(os.sep, "/")
            tree = ast.parse(open(path, encoding="utf-8").read())
            hits: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        if root in _TRANSPORTS:
                            hits.add(root)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    root = node.module.split(".")[0]
                    if root in _TRANSPORTS:
                        hits.add(root)
            if hits:
                found[rel] = hits
    return found


def _calls_a_gate(rel_path: str) -> set[str]:
    """Gate entry points this module actually CALLS. A mention in a docstring
    does not count, which is the whole reason this is an AST walk."""
    path = os.path.join(_SERVICES, rel_path.replace("/", os.sep))
    tree = ast.parse(open(path, encoding="utf-8").read())
    called: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name in _GATES:
            called.add(name)
    return called


# ── R1 ─────────────────────────────────────────────────────────────────────

def test_every_egress_module_is_classified():
    """A module that reaches the network and is not in `_EGRESS` fails here,
    with the classification it needs spelled out — so the sweep cannot rot
    quietly the way the prose table it replaced would have."""
    actual = set(_modules_with_transport())
    unclassified = sorted(actual - set(_EGRESS))

    assert not unclassified, (
        "These modules import a network transport and are not classified in "
        "`_EGRESS`:\n\n  "
        + "\n  ".join(unclassified)
        + "\n\nAdd each one as TARGET (can reach a host we are pointed at — then "
        "it must call a gate, or name the caller that does), THIRD_PARTY (a "
        "vendor API; the target never sees the packet), or ESTABLISHES_AUTH (the "
        "DNS step by which a target becomes authorised). planning#148's "
        "criterion 1 is the reason: one authorisation policy must be the only "
        "path to emitting an active probe."
    )


def test_the_classification_has_no_stale_entries():
    """The other direction. A module that was deleted or stopped reaching the
    network must not keep an entry implying it is still covered — a sweep that
    over-claims is the same defect as one that under-claims."""
    actual = set(_modules_with_transport())
    stale = sorted(set(_EGRESS) - actual)

    assert not stale, (
        "These `_EGRESS` entries no longer import any transport (moved, "
        "deleted, or rewritten):\n\n  " + "\n  ".join(stale)
        + "\n\nRemove them, so the list keeps meaning what it says."
    )


# ── R2 ─────────────────────────────────────────────────────────────────────

def test_every_target_reaching_module_is_gated():
    """Each TARGET module either consults a gate itself or names the caller
    that does — and the named caller is checked, so `gated_by` cannot become a
    way to point at nothing."""
    failures: list[str] = []
    for rel, (kind, reason, gated_by) in sorted(_EGRESS.items()):
        if kind != "TARGET":
            continue
        if gated_by == "self":
            if not _calls_a_gate(rel):
                failures.append(
                    f"{rel} is TARGET/self-gated but calls none of {sorted(_GATES)}"
                )
        elif gated_by:
            if not _calls_a_gate(gated_by):
                failures.append(
                    f"{rel} says it is gated by {gated_by}, but {gated_by} calls no gate"
                )
        else:
            failures.append(f"{rel} is TARGET but declares no gate at all ({reason})")

    assert not failures, "Ungated target-reaching egress:\n  " + "\n  ".join(failures)


def test_all_three_entry_points_are_live():
    """The criterion names three entry points. If one stops being reachable
    from any egress module, either it was collapsed into another — in which
    case this file's prose and planning#148 both need amending — or a gate was
    quietly dropped."""
    reached: set[str] = set()
    for rel, (kind, _reason, gated_by) in _EGRESS.items():
        if kind != "TARGET":
            continue
        reached |= _calls_a_gate(rel if gated_by == "self" else gated_by)

    missing = sorted(_GATES - reached)
    assert not missing, (
        f"No classified egress path reaches {missing}. Either the policy was "
        "restructured (amend planning#148's criterion 1 and this docstring) or "
        "a gate was dropped."
    )


def test_the_gates_are_not_mentioned_only_in_prose():
    """Guards the detection method itself. `_calls_a_gate` is an AST walk
    precisely because a textual search for the gate names matches docstrings
    in modules that never call them — `probe_authorisation.py` discusses
    `httpx` at length and imports nothing. If this ever fails, the AST walk
    has regressed into something grep-like and every R2 result above is
    suspect."""
    assert "probe_authorisation.py" not in _modules_with_transport(), (
        "probe_authorisation.py is being reported as a network-egress module. "
        "It only ever MENTIONS transports in prose — so detection has become "
        "textual, and the guard now has false positives."
    )
