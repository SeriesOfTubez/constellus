"""Collision-free documentation IP addresses for tests (planning#170).

Test files that write real DB rows keyed on an IP address used to build that
address from a random suffix modulo a narrow window, e.g.

    ip = f"192.0.2.{10 + int(uuid.uuid4().hex[:6], 16) % 190}"

which is only *probably* unique. test_ownership_stamping.py drew six such
addresses from four overlapping windows in one /24, and its `_cleanup`
deletes AssetCanonical/FindingCanonical rows *by value* — so a collision made
one test delete another's rows mid-run. Three spurious failures in eight
full-suite runs, a different test named each time (planning#170).

`alloc()` draws without replacement, so uniqueness *within this module* is
structural rather than probabilistic. That is the property the fix rests on.

RESERVED — do not write these addresses in any other test file:

    192.0.2.140 - 192.0.2.189           (RFC 5737 TEST-NET-1)

"Reserved" is a convention, not a guarantee, and one file already breaks it:
test_cloud_inventory_claim draws `192.0.2.{uuid4().int % 200 + 10}` — .10-.209,
which swallows this pool and most of the /24. It is not spelled as a literal
prefix, which is exactly why the first audit for this issue missed it. It is
left alone deliberately: it cleans up by value in a `finally`, so a collision
there costs one red run and heals itself, and rewriting eight draws in a file
planning#170 does not own is a wider blast radius than the bug.

The delete-by-value in `_reset_address` stays correct despite that overlap.
The tests run sequentially in one process, so the two files are never inside
the same address at the same moment, and deleting a row that a crashed run of
either file stranded is the repair, not the damage.

The three RFC-5737 /24s are far more crowded than they look: across app/tests
only 139 of 192.0.2's 254 addresses are unclaimed, 32 of 198.51.100's, and 10
of 203.0.113's. This is the largest contiguous block free of every literal and
every *literal and windowed* claim in the suite. Its neighbours are test_projector
(.100-.139, .190-.229, .230-.249) and test_wiz_ownership (.1-.12), so widening
it in either direction collides — if the pool ever runs dry, take a second
disjoint block (192.0.2.45-76 and .78-99 are also free) rather than extending
this one.

To re-audit after adding tests, enumerate both the literals and the
`f"<prefix>.{base + ... % mod}"` windows; a grep for literals alone misses the
windows entirely, which is how .140-.189's neighbours were nearly missed here.

Documentation ranges only, never a real address (pre-commit hook). These
addresses carry the same is_private=True / not-is_global semantics as the ad
hoc 192.0.2.x draws they replace, so app.core.netaddr.is_public_ip still
rejects them exactly as before and no test's behaviour changes.

No pytest dependency — the test modules using this are also runnable as
`python -m app.tests.<module>`.
"""

import random
import threading

_PREFIX = "192.0.2."
_FIRST = 140
_LAST = 189

_lock = threading.Lock()
_available = random.sample(range(_FIRST, _LAST + 1), _LAST - _FIRST + 1)


def alloc() -> str:
    """One documentation IPv4 address, never returned twice in this process.

    Randomised order, so no test can come to depend on a particular value;
    drawn without replacement, so no two tests can collide.
    """
    with _lock:
        if not _available:
            raise RuntimeError(
                f"_docaddr pool exhausted ({_LAST - _FIRST + 1} addresses in "
                f"{_PREFIX}{_FIRST}-{_LAST}). Add a second disjoint block — do "
                "not widen this one, its neighbours are in use. Re-audit "
                "app/tests for literals AND modulo windows first."
            )
        return f"{_PREFIX}{_available.pop()}"
