import type { ScoreBand, ScoreLadder, ScoreLadderCrossing, ScoreLadderFix, ScoreLadderLevel } from "@/lib/api"

export type Row = [score: number, band: ScoreBand, count: number]

/** Test fixture builder: derives the cumulative fields from [score, band, count] rows. */
export function makeLadder(rows: Row[], extra: { unscored_count?: number; firstFixes?: number } = {}): ScoreLadder {
  let done = 0
  const levels: ScoreLadderLevel[] = rows.map(([score, band, count], i) => {
    const next = rows[i + 1]
    const lvl: ScoreLadderLevel = {
      score, band, count,
      fixes_before: done, fixes_through: done + count,
      score_after: next ? next[0] : 0,
      band_after: next ? next[1] : "secure",
    }
    done += count
    return lvl
  })
  const crossings: ScoreLadderCrossing[] = []
  levels.forEach((l, i) => {
    if (i > 0 && l.band !== levels[i - 1].band) crossings.push({ band: l.band, fixes: l.fixes_before, score: l.score })
  })
  crossings.push({ band: "secure", fixes: done, score: 0 })

  const first_fixes: ScoreLadderFix[] = []
  const wanted = Math.min(extra.firstFixes ?? 3, done)
  for (let rank = 1; rank <= wanted; rank++) {
    const l = levels.find((lv) => rank > lv.fixes_before && rank <= lv.fixes_through)!
    const cleared = rank === l.fixes_through
    first_fixes.push({
      rank, id: `finding-${rank}`, title: `Exposed admin panel ${rank}`, asset_value: `vpn${rank}.fabrikam.example`,
      risk_score: l.score, risk_band: l.band,
      score_after: cleared ? l.score_after : l.score,
      band_after: cleared ? l.band_after : l.band,
    })
  }
  return {
    rule: "worst_open_finding",
    score: levels[0]?.score ?? 0, band: levels[0]?.band ?? "secure",
    open_count: done, unscored_count: extra.unscored_count ?? 0,
    levels, crossings, first_fixes,
  }
}

export const MOCK_ROWS: Row[] = [
  [91, "imminent_compromise", 1], [88, "imminent_compromise", 1], [84, "imminent_compromise", 1],
  [71, "high", 1], [68, "high", 1], [65, "high", 1], [62, "high", 1], [59, "high", 1],
  [56, "high", 1], [54, "high", 1], [52, "high", 1], [50, "high", 1],
  [47, "elevated", 1], [44, "elevated", 1], [40, "elevated", 1],
]
