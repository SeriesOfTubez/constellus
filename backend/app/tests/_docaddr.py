"""Collision-free documentation IP addresses for tests (planning#170, #199).

Every test address that becomes a **database row** comes from `alloc()`, which
draws without replacement for the life of the process. Two test modules
therefore cannot be handed the same address — the property is structural, not
probabilistic, and `test_docaddr_guard.py` fails the build if any module goes
back to rolling its own.

## What this replaced, and why it had to be all of them

Test files used to build an address from a random suffix modulo a narrow
window:

    ip = f"192.0.2.{10 + int(uuid.uuid4().hex[:6], 16) % 190}"

which is only *probably* unique. planning#170 introduced this module after
test_ownership_stamping.py drew six such addresses from four overlapping
windows in one /24 and its delete-by-value cleanup started deleting other
tests' rows — three spurious failures in eight full-suite runs, a different
test named each time.

planning#170 fixed one file and left the convention to carry the rest. It did
not carry. The audit for planning#199 found **78 windowed draw sites across 18
files**, overlapping heavily:

    192.0.2.10-49    test_projector          vs  .10-39   test_claim_upsert_concurrency
    192.0.2.100-139  test_projector          vs  .100-149 test_claim_upsert_concurrency
    203.0.113.10-69  five files drawing the same 60 addresses
    198.51.100.1-250 test_audit_log and test_verify_failed_scan, the whole /24

The previous version of this docstring claimed .140-.189 was "free of every
literal and every windowed claim". It was not: `test_claim_upsert_concurrency`
drew `.100-149`, which reaches ten addresses into it, and
`test_cloud_inventory_claim` drew `.10-209`, which swallows it whole. A
hand-maintained audit recorded in prose was wrong within one release of being
written, which is the reason the rule is now executable.

planning#195 raised the stakes: `authorisation_decisions.asset_canonical_id`
is now `ON DELETE SET NULL`, so a test deleting another file's asset by value
no longer raises `ForeignKeyViolation` — it silently orphans that asset's
decision rows. The hygiene guards catch the leak one run later, in a test that
did nothing wrong. Two delete handlers (`_soft_cascade_target_assets`,
`delete_assets_by_apex`) end in `_sweep_cname_descendants`, which deletes by
`parent_value` recursively up to 8 levels, so a collision reaches well past the
one address that collided.

## The pool

Three blocks, each verified disjoint from every address literal in `app/tests`
(`test_docaddr_guard.py` re-verifies on every run, so this is not a claim you
have to trust):

    198.51.100.100 - 198.51.100.254     155 addresses
    203.0.113.100  - 203.0.113.209      110 addresses
    192.0.2.78     - 192.0.2.127         50 addresses

315 total against roughly 110 draws in a full suite run — about 2.9x headroom.

`alloc_cidr()` draws from its own, separate blocks (`CIDR_BLOCKS`, below):
ten /29s against five draws. The original six ran out during planning#197,
which is the failure mode this module is designed to have — a loud
`RuntimeError` naming the fix, not a silent reuse.
`.0` and `.255` are outside every block: they are the network and broadcast
addresses of their /24, and a test that builds a network around a drawn
address should not have to think about that.

The 192.0.2 block is the small one because `test_cloud_ranges` inserts a
literal `192.0.2.128/25`, which spoke for .128-.255 before this module could.
That is a **containment** claim rather than a value claim, and it is the reason
the guard checks CIDRs and not just bare addresses.

The three RFC 5737 /24s are interchangeable for every predicate this repo has:
`app.core.netaddr.is_public_ip` rejects all of them identically (all three are
`not is_global`), so no test's behaviour depends on which /24 its address came
from. That is what makes a pool spanning all three safe.

**Out of scope, deliberately:** address literals written into a test as data
rather than drawn as an identity — `test_netaddr`'s predicate cases,
`test_cidr_sweep`'s mocked sweep configs, the
`("192.0.2.", "198.51.100.", "203.0.113.")` prefix tuples that stub
`is_public_ip`. Those name the documentation ranges *as* documentation ranges;
they are not identities that can collide. The guard keeps them out of the pool
rather than trying to rewrite them.

Documentation ranges only, never a real address (pre-commit hook). No pytest
dependency — the test modules using this are also runnable as
`python -m app.tests.<module>`.
"""

import random
import threading

# (prefix, first octet, last octet), inclusive. Mirrored by
# `test_docaddr_guard.py`, which asserts no literal in app/tests falls inside.
POOL_BLOCKS = (
    ("198.51.100.", 100, 254),
    ("203.0.113.", 100, 209),
    ("192.0.2.", 78, 127),
)

# Handed out whole, as /29s, by `alloc_cidr()`. Held apart from POOL_BLOCKS so
# a declared range and a loose address can never be carved from the same
# octets. Ten /29s:
#   198.51.100.  .24 .32 .40 .48 .56 .64
#   203.0.113.   .216 .224 .232 .240
# The second block was added for planning#197, which exhausted the original
# six. Chosen by reading every 203.0.113.x literal in app/tests: the nearest
# are .212 below and .250 above, so .216-.247 is clear, and it sits outside
# POOL_BLOCKS' .100-.209. It stops at .240 rather than .248 because a /29 at
# .248 would contain the /24's broadcast address.
CIDR_BLOCKS = (
    ("198.51.100.", 24, 71),
    ("203.0.113.", 216, 247),
)

_lock = threading.Lock()
_available = [
    f"{prefix}{octet}"
    for prefix, first, last in POOL_BLOCKS
    for octet in range(first, last + 1)
]
random.shuffle(_available)

_POOL_SIZE = len(_available)

_available_cidrs = [
    (prefix, base)
    for prefix, first, last in CIDR_BLOCKS
    for base in range(first, last + 1, 8)
]
random.shuffle(_available_cidrs)

_CIDR_POOL_SIZE = len(_available_cidrs)


def alloc() -> str:
    """One documentation IPv4 address, never returned twice in this process.

    Randomised order, so no test can come to depend on a particular value;
    drawn without replacement, so no two tests can collide.
    """
    with _lock:
        if not _available:
            raise RuntimeError(
                f"_docaddr pool exhausted ({_POOL_SIZE} addresses across "
                f"{len(POOL_BLOCKS)} blocks: "
                + ", ".join(f"{p}{a}-{b}" for p, a, b in POOL_BLOCKS)
                + "). Add a further disjoint block to POOL_BLOCKS — do not widen "
                "an existing one, and do not reuse addresses. "
                "`test_docaddr_guard.py` will tell you whether the block you "
                "pick collides with a literal; run it after editing."
            )
        return _available.pop()


def alloc_cidr() -> tuple:
    """A /29 no other test can be handed, and one address inside it.

    For the tests that need a **declared range containing a known address**
    — a `TargetType.CIDR` row plus an asset that scope containment should
    find inside it. Returns `(cidr, address)`.

    Deriving the range from an `alloc()` address instead (`f"{ip.rsplit('.',
    1)[0]}.0/24"`) looks equivalent and is not: it yields one of three /24
    strings at random, so two tests doing delete-then-insert on
    `Target.value` — which is globally UNIQUE — start choosing the same
    string some fraction of runs, and one of those strings is the literal
    `192.0.2.0/24` that `test_scope_cap` seeds eight times. That turns a
    deterministic delete-by-value into a random one, which is the exact
    property planning#199 exists to remove. A /29 drawn without replacement
    cannot be handed to two callers at all.

    A /29 rather than a /24 because a /24 of documentation space contains
    most of an address pool block, and a range Target that wide makes every
    address in it look declared. /29 is still a range — containment, not
    string equality, is what the callers are exercising.
    """
    with _lock:
        if not _available_cidrs:
            raise RuntimeError(
                f"_docaddr CIDR pool exhausted ({_CIDR_POOL_SIZE} /29s in "
                + ", ".join(f"{p}{a}-{b}" for p, a, b in CIDR_BLOCKS)
                + "). Add a disjoint block to CIDR_BLOCKS, /29-aligned and "
                "clear of POOL_BLOCKS. `test_docaddr_guard.py` checks it."
            )
        prefix, base = _available_cidrs.pop()
    # `base` is the network address and `base + 7` the broadcast; hand back a
    # host address so a caller can use it without thinking about either.
    return f"{prefix}{base}/29", f"{prefix}{base + 1}"
