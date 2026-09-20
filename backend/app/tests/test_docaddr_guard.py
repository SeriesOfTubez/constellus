"""The `_docaddr` rules, enforced instead of documented (planning#199).

`_docaddr.py` has carried a written convention since planning#170 — *"do not
write these addresses in any other test file"*, plus a paragraph telling you
how to re-audit. Nobody ran it, and by planning#199 the docstring's central
claim was false: it said the pool block was free of every literal and windowed
claim, while two files were drawing inside it. A convention that describes its
own audit method and is still wrong a release later is a convention that has
to become a test.

Three rules, all statically checkable against the test sources:

  R1  No module builds a documentation address by interpolation.
      `f"192.0.2.{...}"` is the probabilistic regime planning#170 and #199
      exist to remove. Every address that becomes a database row comes from
      `_docaddr.alloc()`, which draws without replacement.

  R2  No module holds a documentation prefix in a constant.
      This closes R1's back door: `_IP_PREFIX = "192.0.2."` followed by
      `f"{_IP_PREFIX}{n % 200 + 10}"` is the same windowed draw with the
      prefix moved one line up, and that is exactly how
      `test_cloud_inventory_claim`'s eight draws escaped the first audit —
      a grep for the literal prefix does not see them.

  R3  No address literal falls inside the pool.
      Otherwise a literal and an allocated address can be the same value,
      which is the collision the allocator is supposed to make impossible.
      "The pool" here is both `POOL_BLOCKS` (single addresses, `alloc()`)
      and `CIDR_BLOCKS` (whole /29s, `alloc_cidr()`).

R1 and R2 match text, so they also fire on **comments and docstrings** that
spell out a dead pattern. That is deliberate rather than tolerated: prose
describing a draw regime the code no longer uses is precisely what rotted
last time. Rewrite the comment to describe what the code does now.

## What these rules deliberately do not cover

`is_public_ip` predicate cases (`test_netaddr`), mocked sweep configurations
(`test_cidr_sweep`), and the `("192.0.2.", "198.51.100.", "203.0.113.")`
tuples that stub the public-address filter all name the documentation ranges
*as ranges*, not as the identity of a row. They cannot collide with anything,
so R3 only keeps them out of the pool rather than rewriting them.

**/24-or-wider CIDR literals are not treated as occupying the pool.** Fifteen
test files name a whole documentation /24, so honouring those would leave no
pool at all. They are a *containment* hazard rather than a value hazard: a
`cloud_ranges` row covering `198.51.100.0/24` matches every address the pool
hands out of that /24, for as long as the row exists. That is survivable here
because the suite runs sequentially in one process and every such row is
deleted by the test that inserted it — a full run leaves zero rows (verified
under planning#200). It stops being survivable the day the suite runs in
parallel, which is the note to come back to. Sub-/24 CIDRs (`/25` and
narrower) *are* honoured, because they are specific enough to avoid.

Runnable directly (`python -m app.tests.test_docaddr_guard`) like the rest of
the suite; it touches no database.
"""

import ipaddress
import os
import re

from app.tests._docaddr import CIDR_BLOCKS, POOL_BLOCKS

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))

# `_docaddr.py` owns the pool and documents the banned pattern; this file
# quotes both in its own prose. Everything else is subject to the rules.
_EXEMPT = frozenset({"_docaddr.py", os.path.basename(__file__)})

_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")
_PREFIX_ALT = "|".join(re.escape(p.rstrip(".")) for p in _PREFIXES)

# R1: a documentation prefix immediately followed by an interpolation.
_INTERPOLATED = re.compile(rf"(?:{_PREFIX_ALT})\.\{{")

# R2: a module-level or local name bound to a bare documentation prefix.
_PREFIX_CONST = re.compile(
    rf"""^\s*[_A-Za-z]\w*\s*=\s*["'](?:{_PREFIX_ALT})\.?["']\s*(?:#.*)?$"""
)

# R3: any documentation address, optionally with a prefix length.
_ADDRESS = re.compile(rf"(?:{_PREFIX_ALT})\.(\d{{1,3}})(?:/(\d{{1,3}}))?")


def _sources():
    """Every test module the rules apply to, as (filename, text)."""
    for name in sorted(os.listdir(_TESTS_DIR)):
        if not name.endswith(".py") or name in _EXEMPT:
            continue
        path = os.path.join(_TESTS_DIR, name)
        with open(path, encoding="utf-8") as fh:
            yield name, fh.read()


def _pool_addresses() -> set:
    """Every address the two allocators can hand out."""
    return {
        f"{prefix}{octet}"
        for prefix, first, last in POOL_BLOCKS + CIDR_BLOCKS
        for octet in range(first, last + 1)
    }


def test_no_module_builds_an_address_by_interpolation():
    """R1 — the windowed draw regime is gone and cannot come back."""
    offenders = [
        f"{name}:{i}: {line.strip()}"
        for name, src in _sources()
        for i, line in enumerate(src.splitlines(), 1)
        if _INTERPOLATED.search(line)
    ]
    assert not offenders, (
        "A documentation address is being built by interpolation. That is the "
        "probabilistic draw planning#170 and planning#199 removed — two "
        "modules drawing from overlapping windows eventually produce the same "
        "address, and the delete-by-value cleanups then delete each other's "
        "rows.\n\nUse `_docaddr.alloc()`, which draws without replacement.\n\n"
        "If the match is in a comment describing the old pattern, rewrite the "
        "comment — stale prose about a dead regime is what this guard "
        "replaces.\n\n" + "\n".join(offenders)
    )


def test_no_module_holds_a_documentation_prefix_in_a_constant():
    """R2 — R1's back door, and the one that hid eight draws from the first
    audit (`test_cloud_inventory_claim`, planning#171)."""
    offenders = [
        f"{name}:{i}: {line.strip()}"
        for name, src in _sources()
        for i, line in enumerate(src.splitlines(), 1)
        if _PREFIX_CONST.match(line)
    ]
    assert not offenders, (
        "A documentation prefix is bound to a name. Interpolating that name "
        "is the same windowed draw as R1 with the prefix moved one line up, "
        "and a grep for the literal prefix does not find it — which is how "
        "test_cloud_inventory_claim's eight draws survived planning#170's "
        "audit.\n\nUse `_docaddr.alloc()` for whole addresses. A prefix "
        "needed as data (stubbing `is_public_ip`, say) belongs inline at its "
        "use site, not in a constant.\n\n" + "\n".join(offenders)
    )


def test_no_address_literal_falls_inside_the_pool():
    """R3 — a literal equal to an allocated address defeats the allocator."""
    pool = _pool_addresses()
    offenders = []
    for name, src in _sources():
        for match in _ADDRESS.finditer(src):
            text, plen = match.group(0), match.group(2)
            if plen is None:
                hits = [text] if text in pool else []
            else:
                try:
                    net = ipaddress.ip_network(text, strict=False)
                except ValueError:
                    continue  # deliberately malformed test data, e.g. /33
                if net.prefixlen <= 24:
                    continue  # containment, not value — see this file's header
                hits = [str(h) for h in net if str(h) in pool]
            if hits:
                line = src.count("\n", 0, match.start()) + 1
                offenders.append(
                    f"{name}:{line}: {text} occupies "
                    + (hits[0] if len(hits) == 1 else f"{len(hits)} pool addresses")
                )

    assert not offenders, (
        "An address literal falls inside the `_docaddr` pool, so the allocator "
        "can hand a test the value another test has written down — the exact "
        "collision it exists to prevent.\n\nEither move the literal outside "
        "every block in `_docaddr.POOL_BLOCKS`, or narrow the block. Free "
        "space in the documentation ranges is listed in `_docaddr.py`'s "
        "header.\n\n" + "\n".join(offenders)
    )


def test_pool_blocks_do_not_overlap_each_other():
    """A typo in POOL_BLOCKS or CIDR_BLOCKS that double-lists an address
    would let `alloc()` return it twice — silently, since drawing without
    replacement is only a property of the list it is built from. The two must
    also not overlap each other, or a drawn address could sit inside a drawn
    range."""
    seen = set()
    for prefix, first, last in POOL_BLOCKS + CIDR_BLOCKS:
        assert first <= last, f"{prefix}{first}-{last} is inverted"
        assert 1 <= first and last <= 254, (
            f"{prefix}{first}-{last} includes a network or broadcast address"
        )
        block = {f"{prefix}{octet}" for octet in range(first, last + 1)}
        clash = seen & block
        assert not clash, f"{prefix}{first}-{last} repeats {sorted(clash)[:5]}"
        seen |= block

    assert len(seen) == len(_pool_addresses())

    for prefix, first, last in CIDR_BLOCKS:
        assert first % 8 == 0, f"{prefix}{first} is not /29-aligned"
        assert (last - first + 1) % 8 == 0, (
            f"{prefix}{first}-{last} is not a whole number of /29s"
        )


def _run():
    tests = [
        test_no_module_builds_an_address_by_interpolation,
        test_no_module_holds_a_documentation_prefix_in_a_constant,
        test_no_address_literal_falls_inside_the_pool,
        test_pool_blocks_do_not_overlap_each_other,
    ]
    for fn in tests:
        try:
            fn()
            print(f"OK: {fn.__name__}")
        except AssertionError as exc:
            print(f"FAIL: {fn.__name__}: {exc}")
            raise SystemExit(1)
    print("ALL PASS")


if __name__ == "__main__":
    _run()
