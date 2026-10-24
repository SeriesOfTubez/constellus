"""The anchor-chain invariant (planning#277 S1a). Replaces
the former candidate-domains suite's `test_no_name_to_domain_path`.

The rule: a domain becomes a candidate only because a SIGNAL names it, and a
signal is borne by something already decided (a claimed candidate, a
confirmed filer's own filing) or by a person. There is no path from a company
NAME to a domain. These tests pin it three ways:

1. AST, not grep, over every module in `app.services.org_discovery`
   (enumerated with `pkgutil`, so a new module is covered the day it lands),
   the website extractor, and the route handlers that write candidates.
2. Every literal `signal_type=` passed to `record_signal` anywhere in `app/`
   is a type the tier table says has a generator.
3. Behaviour: a Context signal never creates a candidate, a via entity
   outside the tree is refused, and the database itself refuses an anchor
   that is not a claimed candidate (a raw insert, not the service).

Run with:  scripts/test.sh app/tests/test_org_discovery_invariants.py
"""

import ast
import importlib
import inspect
import pkgutil
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

import app.api.organizations as org_api
import app.services.org_discovery as pkg
from app.services import edgar_html, organizations
from app.services.org_discovery import candidates as cd
from app.services.org_discovery.tiers import SIGNALS
from app.tests._org_world import World, hexid
from app.tests.test_org_discovery_schema import _insert_candidate, _insert_signal

NAME_PARAMS = {"name", "legal_name", "company", "company_name", "display_name", "org_name"}
NAME_ATTRS = {"legal_name", "display_name"}
APP_DIR = Path(pkg.__file__).resolve().parents[2]  # backend/app


@pytest.fixture
def w():
    world = World()
    try:
        yield world
    finally:
        world.close()


def _modules():
    for info in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + "."):
        yield importlib.import_module(info.name)


def _tree(mod) -> ast.AST:
    return ast.parse(Path(inspect.getsourcefile(mod)).read_text(encoding="utf-8"))


def _params(fn: ast.AST) -> list[str]:
    a = fn.args
    return [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs] + [x.arg for x in (a.vararg, a.kwarg) if x]


def _name_violations(tree: ast.AST, *, allow_display_field: bool = False) -> list[str]:
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in NAME_ATTRS:
            bad.append(f"attribute .{node.attr} (line {node.lineno})")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            hit = NAME_PARAMS & set(_params(node))
            if hit:
                bad.append(f"parameter(s) {sorted(hit)} of {node.name}")
        if isinstance(node, ast.Name) and node.id in NAME_ATTRS and not allow_display_field:
            bad.append(f"name {node.id} (line {node.lineno})")
    return bad


# ── 1. the package ──────────────────────────────────────────────────────────


def test_the_package_is_enumerated_and_not_trivially_empty():
    names = {m.__name__.rsplit(".", 1)[-1] for m in _modules()}
    assert {"tiers", "candidates", "strength", "generators", "filer_search"} <= names


def test_no_org_discovery_module_reads_an_entity_name_or_takes_a_name_parameter():
    checked = 0
    for mod in _modules():
        short = mod.__name__.rsplit(".", 1)[-1]
        # filer_search reads `display_names` from the EFTS JSON (a dict key, to show
        # the person) and carries it in its result's `display_name` FIELD; it may
        # never take a name as a parameter or read an entity's name.
        bad = _name_violations(_tree(mod), allow_display_field=(short == "filer_search"))
        assert not bad, f"{mod.__name__}: {bad}"
        checked += 1
    assert checked >= 5


def test_the_name_check_actually_catches_what_it_claims_to():
    """Mutate the subject: the same walk must flag each forbidden shape."""
    for source in (
        "def f(db, name): pass",
        "def f(db, *, company_name=None): pass",
        "def f(e): return e.legal_name",
        "def f(e): return e.display_name",
    ):
        assert _name_violations(ast.parse(source)), source
    assert not _name_violations(ast.parse("def f(db, value, via_entity_id): return value"))


def test_filer_search_neither_imports_nor_calls_the_signal_writers():
    tree = _tree(importlib.import_module("app.services.org_discovery.filer_search"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert "record_signal" not in {a.name for a in node.names}
            assert not (node.module or "").endswith("generators")
        if isinstance(node, ast.Attribute):
            assert node.attr not in {"record_signal", "add_by_person", "claim", "reject", "_claim_seed"}, node.lineno
        if isinstance(node, ast.Name):
            assert node.id not in {"record_signal", "add_by_person"}, node.lineno
    # the only thing it takes from `candidates` is the domain normaliser
    used = {
        n.attr for n in ast.walk(tree)
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "candidates"
    }
    assert used == {"normalise_domain"}


def test_the_website_extractor_reads_no_name():
    tree = ast.parse(inspect.getsource(edgar_html.find_website_mentions))
    assert not _name_violations(tree)


# ── 2. the route handlers that write candidates ─────────────────────────────

_WRITERS = {"add_by_person", "claim", "reject", "record_signal", "add_organization"}


def _handlers():
    for route in org_api.router.routes:
        fn = getattr(route, "endpoint", None)
        if fn is not None:
            yield fn


def _calls_writer(fn) -> bool:
    for node in ast.walk(ast.parse(inspect.getsource(fn))):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in _WRITERS:
            return True
    return False


def test_handlers_that_write_candidates_read_no_name():
    """Read handlers DISPLAY entity names (an affiliated company's, a filer's)
    and so legitimately read `legal_name`; the invariant is about what can
    write a candidate. The set is pinned so a new writer is not silently
    exempt, and every writer is walked with the strict rule."""
    handlers = list(_handlers())
    writers = {fn.__name__ for fn in handlers if _calls_writer(fn)}
    assert writers == {"add_organization", "add_candidate", "claim_candidate", "reject_candidate"}
    assert {fn.__name__ for fn in handlers} >= writers | {"list_organizations", "list_candidates", "get_candidate"}
    for fn in handlers:
        if fn.__name__ in writers:
            assert not _name_violations(ast.parse(inspect.getsource(fn))), fn.__name__


# ── 3. every literal signal type in app/ is one with a generator ────────────


def _app_sources():
    for path in APP_DIR.rglob("*.py"):
        rel = path.relative_to(APP_DIR)
        if rel.parts[0] == "tests":
            continue
        yield rel, ast.parse(path.read_text(encoding="utf-8"))


def test_every_literal_signal_type_passed_to_record_signal_is_built():
    literals: dict[str, list[str]] = {}
    non_literal: list[str] = []
    for rel, tree in _app_sources():
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, (ast.Attribute, ast.Name))):
                continue
            fname = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
            if fname != "record_signal":
                continue
            kw = {k.arg: k.value for k in node.keywords}
            value = kw.get("signal_type")
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                literals.setdefault(value.value, []).append(f"{rel}:{node.lineno}")
            else:
                non_literal.append(f"{rel}:{node.lineno}")
    # the three generators that exist in this slice were FOUND (the scan is not vacuous)
    assert set(literals) >= {"admin_seed", "person_evidence", "filer_10k_website"}, literals
    for signal_type, sites in literals.items():
        assert signal_type in SIGNALS, (signal_type, sites)
        assert SIGNALS[signal_type].built, f"{signal_type} has no generator but is recorded at {sites}"
    # The verifier passes `match.signal_type`; that one file is exempt from the literal rule, and
    # the test below pins every type its `Match(...)` constructors can emit instead.
    assert [site for site in non_literal if not site.startswith("services/org_discovery/verifiers.py")] == [], (
        f"record_signal called with a non-literal signal_type at {non_literal}"
    )
    assert len([s for s in non_literal if s.startswith("services/org_discovery/verifiers.py")]) == 1


def test_every_signal_type_the_verifiers_can_emit_is_built():
    path = APP_DIR / "services" / "org_discovery" / "verifiers.py"
    emitted: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Match":
            kw = {k.arg: k.value for k in node.keywords}
            value = kw.get("signal_type")
            assert isinstance(value, ast.Constant) and isinstance(value.value, str), (
                f"verifiers.py:{node.lineno}: Match(signal_type=...) must be a literal"
            )
            emitted.add(value.value)
    assert emitted == {"shared_vanity_ns", "mx_into_claimed", "spf_sender_shared", "registrant_org_match"}
    for signal_type in emitted:
        assert SIGNALS[signal_type].built, signal_type


def test_the_literal_scan_would_catch_an_unbuilt_type():
    tree = ast.parse("record_signal(db, signal_type='registrant_email_claimed')")
    call = tree.body[0].value
    kw = {k.arg: k.value.value for k in call.keywords}
    assert not SIGNALS[kw["signal_type"]].built  # i.e. the assertion above would fail for this call


# ── 4. org_name reaches exactly one place ───────────────────────────────────


def test_org_name_only_becomes_the_legal_name_of_the_new_entity():
    tree = ast.parse(inspect.getsource(organizations))
    funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert {"add_organization", "_write"} <= set(funcs)

    # (a) nothing that finds or writes a domain is handed the name, at any depth
    for fn in funcs.values():
        for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
            fname = call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", "")
            if fname in {"record_signal", "_claim_seed", "normalise_domain", "add_by_person"}:
                names = {n.id for n in ast.walk(call) if isinstance(n, ast.Name)}
                assert "org_name" not in names, (fn.name, fname)

    # (b) inside `_write`, every use of org_name is `OrgEntity(legal_name=org_name)`
    write = funcs["_write"]
    parents = {child: parent for parent in ast.walk(write) for child in ast.iter_child_nodes(parent)}
    uses = [n for n in ast.walk(write) if isinstance(n, ast.Name) and n.id == "org_name" and isinstance(n.ctx, ast.Load)]
    assert len(uses) == 1
    kw = parents[uses[0]]
    call = parents[kw]
    assert isinstance(kw, ast.keyword) and kw.arg == "legal_name"
    assert isinstance(call, ast.Call) and getattr(call.func, "id", None) == "OrgEntity"

    # (c) in `add_organization` it is validated and handed to `_write`, nothing else
    outer = funcs["add_organization"]
    uses = [n for n in ast.walk(outer) if isinstance(n, ast.Name) and n.id == "org_name" and isinstance(n.ctx, ast.Load)]
    pmap = {child: parent for parent in ast.walk(outer) for child in ast.iter_child_nodes(parent)}
    sinks = []
    for u in uses:
        p = pmap[u]
        if isinstance(p, ast.keyword):
            sinks.append(getattr(pmap[p].func, "id", None) or pmap[p].func.attr)
    assert set(sinks) == {"_write"}


# ── 5. behaviour ────────────────────────────────────────────────────────────


def test_a_context_signal_on_an_unknown_domain_creates_nothing(w):
    root = w.ours()
    d = f"inv277-{hexid()}.example.com"
    ev = w.evidence_row()
    out = cd.record_signal(
        w.db, root_entity_id=root.id, value=d, signal_type="ai_mention", anchor_kind="person",
        via_entity_id=root.id, evidence_id=ev.id, quote=d,
    )
    w.db.commit()
    assert out.outcome == "skipped_context_only"
    assert w.db.execute(text("select count(*) from scope_candidates where root_entity_id = :r"), {"r": root.id}).scalar_one() == 0
    assert w.db.execute(text("select count(*) from scope_signals where via_entity_id = :r"), {"r": root.id}).scalar_one() == 0


def test_a_via_entity_outside_the_roots_tree_is_refused(w):
    root, stranger = w.ours(), w.entity()
    ev = w.evidence_row()
    d = f"inv277-{hexid()}.example.com"
    with pytest.raises(cd.CandidateInvalid, match="tree"):
        cd.record_signal(
            w.db, root_entity_id=root.id, value=d, signal_type="person_evidence", anchor_kind="person",
            via_entity_id=stranger.id, evidence_id=ev.id, quote=d,
        )
    assert w.db.execute(text("select count(*) from scope_candidates where root_entity_id = :r"), {"r": root.id}).scalar_one() == 0


def test_the_database_refuses_a_claimed_candidate_anchor_that_is_open(w):
    """By raw insert: the service is bypassed, the trigger is what answers."""
    root = w.ours()
    target = _insert_candidate(w.db, root.id, value=f"inv277-{hexid()}.example.com")
    anchor = _insert_candidate(w.db, root.id, value=f"inv277-{hexid()}.example.com")  # OPEN, not claimed
    ev = w.evidence_row()
    kw = dict(signal_type="redirect_to_claimed", anchor_kind="claimed_candidate", anchor_candidate_id=anchor,
              evidence_id=ev.id, quote="x")
    with pytest.raises(DBAPIError) as exc:
        _insert_signal(w.db, target, root.id, **kw)
    w.db.rollback()
    assert "must be a claimed candidate under the same root" in str(exc.value.orig)
    assert w.db.execute(text("select count(*) from scope_signals where candidate_id = :c"), {"c": target}).scalar_one() == 0
    # control: once the anchor is claimed the identical insert is accepted
    w.db.execute(text(
        "update scope_candidates set status = 'claimed', affiliated_entity_id = :r, decided_at = now(), "
        "accepted_into = 'estate' where id = :a"), {"r": root.id, "a": anchor})
    w.db.commit()
    _insert_signal(w.db, target, root.id, **kw)
    assert w.db.execute(text("select count(*) from scope_signals where candidate_id = :c"), {"c": target}).scalar_one() == 1
    assert uuid.UUID(str(target))
