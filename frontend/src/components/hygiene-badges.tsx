import { type HygieneBand, type HygieneGrade } from "@/lib/api"
import { CHIP, SEV_CHIP } from "@/components/ui/chip"
import { cn } from "@/lib/utils"

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
// severity palette lock): critical -> sev-critical, poor -> sev-high,
// fair -> sev-medium, good -> sev-low, excellent -> sev-clean. Same SEV_CHIP
// tones finding-badges.tsx's RISK_BAND_COLOR uses.
export const HYGIENE_BAND_COLOR: Record<HygieneBand, string> = {
  critical:  SEV_CHIP.critical,
  poor:      SEV_CHIP.high,
  fair:      SEV_CHIP.medium,
  good:      SEV_CHIP.low,
  excellent: SEV_CHIP.clean,
}

export const HYGIENE_GRADE_LABEL: Record<HygieneGrade, string> = {
  unknown:   "Unknown",
  bad:       "Bad",
  fair:      "Fair",
  good:      "Good",
  excellent: "Excellent",
}

// `fair`/`good`/`excellent` reuse the band tones (same word, same meaning).
// `bad` borrows `poor`'s high — the worst REAL reading, one rung above unknown.
// `unknown` is the locked sev-unknown tone: a distinct "nothing reports on
// this" signal, not a rating on the same scale.
export const HYGIENE_GRADE_COLOR: Record<HygieneGrade, string> = {
  unknown:   SEV_CHIP.unknown,
  bad:       SEV_CHIP.high,
  fair:      SEV_CHIP.medium,
  good:      SEV_CHIP.low,
  excellent: SEV_CHIP.clean,
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
    <span className={cn(CHIP, HYGIENE_BAND_COLOR[band])}>
      {HYGIENE_BAND_LABEL[band]}
    </span>
  )
}

/** Per-dimension drill-down chip (AssetHygieneCard). `unknown` is a real,
 *  worst-tier grade in this model — never a bare dash — so it renders with
 *  the same shape and weight as every other grade, just its own colour. */
export function HygieneGradeChip({ grade }: { grade: HygieneGrade }) {
  return (
    <span className={cn(CHIP, HYGIENE_GRADE_COLOR[grade])}>
      {HYGIENE_GRADE_LABEL[grade]}
    </span>
  )
}
