"""The org risk score is worst-driven: it equals the highest risk_score among
open findings. Fixing findings from the top therefore lowers it step by step;
this module turns the open findings' (score, band, count) rows into that
ladder of steps and the band crossings along it. Pure functions, no I/O.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.services import risk_scorer

RULE = "worst_open_finding"
SECURE = "secure"


def band_rank(band: str | None) -> int:
    if band is not None and band in risk_scorer.BANDS:
        return risk_scorer.BANDS[band][0]
    return 0


def band_for_score(score: int) -> str:
    if score <= 0:
        return SECURE
    for name, (lo, hi) in risk_scorer.BANDS.items():
        if lo <= score <= hi:
            return name
    return max(risk_scorer.BANDS, key=lambda n: risk_scorer.BANDS[n][0])


def build_levels(rows: Iterable[tuple[int, str | None, int]]) -> list[dict]:
    counts: dict[int, int] = {}
    stored: dict[int, str] = {}
    for score, band, count in rows:
        if score is None or score <= 0 or count <= 0:
            continue
        counts[score] = counts.get(score, 0) + count
        if band is not None and band in risk_scorer.BANDS:
            best = stored.get(score)
            if best is None or band_rank(band) > band_rank(best):
                stored[score] = band
    scores = sorted(counts, reverse=True)
    bands = {s: stored.get(s) or band_for_score(s) for s in scores}
    levels: list[dict] = []
    before = 0
    for i, s in enumerate(scores):
        nxt = scores[i + 1] if i + 1 < len(scores) else None
        levels.append({
            "score": s,
            "band": bands[s],
            "count": counts[s],
            "fixes_before": before,
            "fixes_through": before + counts[s],
            "score_after": nxt if nxt is not None else 0,
            "band_after": bands[nxt] if nxt is not None else SECURE,
        })
        before += counts[s]
    return levels


def crossings(levels: list[dict]) -> list[dict]:
    out: list[dict] = []
    if not levels:
        return out
    lowest = band_rank(levels[0]["band"])
    for lv in levels:
        rank = band_rank(lv["band_after"])
        if rank < lowest:
            out.append({"band": lv["band_after"], "fixes": lv["fixes_through"], "score": lv["score_after"]})
            lowest = rank
    return out


def score_at(levels: list[dict], position: int) -> tuple[int, str]:
    position = max(position, 0)
    for lv in levels:
        if lv["fixes_before"] <= position < lv["fixes_through"]:
            return lv["score"], lv["band"]
    return 0, SECURE


def summary(levels: list[dict]) -> dict:
    if not levels:
        return {"score": 0, "band": SECURE, "worst_band_count": 0}
    top = levels[0]
    return {
        "score": top["score"],
        "band": top["band"],
        "worst_band_count": sum(lv["count"] for lv in levels if lv["band"] == top["band"]),
    }


def without_one(levels: list[dict], score: int) -> list[dict]:
    rows = []
    removed = False
    for lv in levels:
        count = lv["count"]
        if lv["score"] == score and not removed:
            count -= 1
            removed = True
        rows.append((lv["score"], lv["band"], count))
    return build_levels(rows)
