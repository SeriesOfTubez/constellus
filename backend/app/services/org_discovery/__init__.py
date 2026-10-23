"""Organization scope discovery (planning#277 S1a).

A root organization's tree is searched for things that may belong to it
(domains today). Each finding is a CANDIDATE with one or more SIGNALS;
only a person's `candidates.claim` turns one into a Target.

- `tiers`      -- what each signal type is worth (Strong / Supporting / Context)
- `strength`   -- calculated-on-load strength, in SQL
- `candidates` -- record_signal / add_by_person / claim / reject
- `generators` -- turn evidence the system already holds into signals
- `filer_search` -- SEC full-text search by domain (a hint; stores nothing)

No module in this package reads an entity's NAME to find a domain; the
anchor-chain invariant is pinned by `tests/test_org_discovery_invariants.py`.
"""
