import { type HygieneBand, type HygieneGrade } from "@/lib/api"

/**
 * Asset hygiene badges — the sibling of finding-badges.tsx's Risk Score
 * vocabulary, for the OPPOSITE polarity axis. Risk Score is 0-100 where
 * HIGH is bad; hygiene is 0-100 where HIGH is good. Putting both raw
 * numbers on the same row (the Assets list) is a known UX hazard
 * (planning#97 — the Dashboard gauge already "reads as inverted at a
 * glance") — so every export here that can appear on the Assets list
 * renders the band WORD ONLY, never a number. The one place the numeric
 * score is allowed to appear is AssetHygieneCard's hero, explicitly
 * labelled "Asset Hygiene" so it can't be mistaken for Risk Score sitting
 * on the same screen.
 *
 * `HygieneBandBadge` is the list-safe composite verdict. `HygieneGradeChip`
 * is the per-dimension drill-down chip — a distinct 5-value vocabulary
 * (unknown/bad/fair/good/excellent) from the band's own
 * (critical/poor/fair/good/excellent). `unknown` is the worst possible
 * dimension grade in this model (a machine nothing reports on, not a clean
 * bill of health — see hygiene_scorer.py's module docstring) and must be
 * exactly as visually present as any other grade: never a dash, never
 * empty, never dimmed into invisibility.
 */

export const HYGIENE_BAND_LABEL: Record<HygieneBand, string> = {
  critical:  "Critical",
  poor:      "Poor",
  fair:      "Fair",
  good:      "Good",
  excellent: "Excellent",
}

// Mapped to the LOCKED severity palette by MEANING (Design Decisions —
// severity palette lock): critical -> --sev-critical, poor -> --sev-high,
// fair -> --sev-medium, good -> --sev-low, excellent -> --sev-clean. Uses
// the same Tailwind-hardcoded-hue convention finding-badges.tsx's own
// RISK_BAND_COLOR already established for this palette — not the
// var(--sev-*) inline-style convention Dashboard.tsx/CvssBreakdown.tsx use
// elsewhere. One convention per badge family; this file doesn't invent a
// third one.
export const HYGIENE_BAND_COLOR: Record<HygieneBand, string> = {
  critical:  "bg-red-500/15 text-red-500 border-red-500/30",
  poor:      "bg-orange-500/15 text-orange-500 border-orange-500/30",
  fair:      "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400 border-yellow-500/30",
  good:      "bg-blue-500/15 text-blue-500 border-blue-500/30",
  excellent: "bg-emerald-500/15 text-emerald-500 border-emerald-500/30",
}

export const HYGIENE_GRADE_LABEL: Record<HygieneGrade, string> = {
  unknown:   "Unknown",
  bad:       "Bad",
  fair:      "Fair",
  good:      "Good",
  excellent: "Excellent",
}

// `fair`/`good`/`excellent` reuse HYGIENE_BAND_COLOR's exact classes (same
// word, same meaning). `bad` borrows `poor`'s orange — the worst REAL
// reading, one rung above unknown. `unknown` gets the locked --sev-unknown
// token directly via the var(--sev-*) arbitrary-value convention (the only
// place in this file that isn't a plain Tailwind hue) because it isn't a
// point on the red/orange/yellow/blue/emerald ramp at all — it's a
// distinct "nothing reports on this" signal, not a rating on the same
// scale, and must stand out as such rather than blend into the ramp.
export const HYGIENE_GRADE_COLOR: Record<HygieneGrade, string> = {
  unknown:   "bg-[var(--sev-unknown)]/10 text-[var(--sev-unknown)] border-[var(--sev-unknown)]/40",
  bad:       "bg-orange-500/15 text-orange-500 border-orange-500/30",
  fair:      "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400 border-yellow-500/30",
  good:      "bg-blue-500/15 text-blue-500 border-blue-500/30",
  excellent: "bg-emerald-500/15 text-emerald-500 border-emerald-500/30",
}

/** The Assets-list-safe hygiene verdict chip — band WORD ONLY. There is no
 *  `score` prop on this component, by design: Risk Score and hygiene are
 *  both 0-100 scales with OPPOSITE polarity, and two raw numbers on one row
 *  is the exact hazard planning#97 already reports (the Dashboard gauge
 *  "reads as inverted at a glance"). It is structurally impossible to
 *  render a number through this component — if you need the numeric
 *  score, it belongs in AssetHygieneCard's hero, explicitly labelled
 *  "Asset Hygiene", never here. */
export function HygieneBandBadge({ band }: { band: HygieneBand }) {
  return (
    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold ${HYGIENE_BAND_COLOR[band]}`}>
      {HYGIENE_BAND_LABEL[band]}
    </span>
  )
}

/** Per-dimension drill-down chip (AssetHygieneCard). `unknown` is a real,
 *  worst-tier grade in this model — never a bare dash — so it renders with
 *  the same shape and weight as every other grade, just its own colour. */
export function HygieneGradeChip({ grade }: { grade: HygieneGrade }) {
  return (
    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold ${HYGIENE_GRADE_COLOR[grade]}`}>
      {HYGIENE_GRADE_LABEL[grade]}
    </span>
  )
}
