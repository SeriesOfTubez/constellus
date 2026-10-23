"""A measurement, not a performance gate (planning#277 S1a): one root with
2,000 candidates x 3 signals, then `GET /{org_id}/candidates` timed.

The assertions are about correctness (the page is the size asked for and
sorted); the timings are printed (`pytest -s`) for the hand-off report.

Run with:  scripts/test.sh app/tests/test_organizations_measure.py -s
"""

import statistics
import time

from sqlalchemy import text

from app.tests._org_world import World, client

N = 2_000


def test_candidate_list_timing_with_2000_candidates_and_6000_signals():
    w = World()
    try:
        root = w.ours()
        ev = w.evidence_row()
        w.db.execute(text(
            "insert into scope_candidates (root_entity_id, kind, value) "
            "select :r, 'domain', 'm277-' || g || '.example.com' from generate_series(1, :n) g"
        ), {"r": root.id, "n": N})
        # three signals each, of types that exercise every tier: Strong for every 3rd candidate,
        # Supporting (two families) for the next, Context + one Supporting for the rest.
        w.db.execute(text("""
            insert into scope_signals (candidate_id, signal_type, anchor_kind, via_entity_id, evidence_id, quote)
            select c.id, t.signal_type, 'person', :r, :e, 'q'
            from scope_candidates c
            cross join lateral (
                select unnest(case (row_number() over (order by c.value))::int % 3
                    when 0 then array['person_evidence', 'name_similarity', 'ai_mention']
                    when 1 then array['mx_into_claimed', 'shared_vanity_ns', 'name_similarity']
                    else array['research_quote', 'name_similarity', 'ai_mention'] end) as signal_type
            ) t
            where c.root_entity_id = :r
        """), {"r": root.id, "e": ev.id})
        w.db.commit()
        counts = w.db.execute(text(
            "select (select count(*) from scope_candidates where root_entity_id = :r), "
            "(select count(*) from scope_signals s join scope_candidates c on c.id = s.candidate_id where c.root_entity_id = :r)"
        ), {"r": root.id}).one()
        assert tuple(counts) == (N, 3 * N)

        headers = w.headers()

        def measure(phase: str) -> None:
            for label, qs, expected in (
                ("default (open, proposable, limit 200)", "", None),
                ("status=all&include_leads=true&limit=1000", "?status=all&include_leads=true&limit=1000", 1000),
            ):
                url = f"/api/organizations/{root.id}/candidates{qs}"
                client.get(url, headers=headers)  # warm the connection / plan cache
                runs = []
                for _ in range(5):
                    t0 = time.perf_counter()
                    r = client.get(url, headers=headers)
                    runs.append((time.perf_counter() - t0) * 1000)
                    assert r.status_code == 200
                rows = r.json()
                if expected is not None:
                    assert len(rows) == expected
                else:
                    assert 0 < len(rows) <= 200 and all(x["proposable"] for x in rows)
                order = [("strong", "supporting", "lead", "context").index(x["strength"]) for x in rows]
                assert order == sorted(order)
                print(f"\nMEASURE [{phase}] {label}: rows={len(rows)} min={min(runs):.0f}ms "
                      f"median={statistics.median(runs):.0f}ms max={max(runs):.0f}ms")

        # Straight after a bulk load, before autovacuum has gathered statistics...
        measure("no table statistics yet")
        # ...and as it runs once it has (autovacuum analyzes a table this size within a minute).
        w.db.execute(text("analyze scope_signals"))
        w.db.execute(text("analyze scope_candidates"))
        w.db.commit()
        measure("after ANALYZE")
    finally:
        w.close()
