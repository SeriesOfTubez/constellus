import { scaleLinear } from "@visx/scale"
import { epssTone } from "@/components/finding-badges"
import { SEV_VAR } from "./bands"

const TRACK_H = 4
const MARKER_W = 2

// Rounded DOWN to one decimal and capped at 99.9: the sentence says "higher
// than", so it must never overstate, and nothing is higher than 100%.
export function percentileText(percentile: number): string {
  const tenths = Math.min(999, Math.max(0, Math.floor(percentile * 1000 + 1e-6)))
  return tenths % 10 === 0 ? String(tenths / 10) : (tenths / 10).toFixed(1)
}

export function percentileSentence(percentile: number): string {
  return `Higher than ${percentileText(percentile)}% of all known flaws (EPSS)`
}

export function percentileLabel(percentile: number, score: number | null): string {
  const head = `Percentile bar: higher than ${percentileText(percentile)}% of all known flaws`
  return score === null ? head : `${head}; ${(score * 100).toFixed(2)}% chance of attack in 30 days`
}

// Position is the percentile; colour is the SCORE's band. The thresholds are
// on the probability, so a high percentile with a low score stays neutral.
export function markColor(score: number | null): string {
  const tone = score === null ? null : epssTone(score)
  return tone ? SEV_VAR[tone] : "var(--muted-foreground)"
}

export function PercentileBar({
  percentile, score, width, height = 12,
}: {
  percentile: number
  score: number | null
  width: number
  height?: number
}) {
  if (width <= 0 || !Number.isFinite(percentile)) return null

  const x = scaleLinear<number>({ domain: [0, 1], range: [0, width], clamp: true })
  const end = x(percentile)
  const trackY = (height - TRACK_H) / 2
  const label = percentileLabel(percentile, score)

  return (
    <div>
      <svg width={width} height={height} role="img" aria-label={label}>
        <title>{label}</title>
        <rect x={0} y={trackY} width={width} height={TRACK_H} rx={TRACK_H / 2} fill="var(--border)" />
        <rect x={0} y={trackY} width={end} height={TRACK_H} rx={TRACK_H / 2} fill={markColor(score)} />
        <rect x={Math.min(Math.max(end - MARKER_W / 2, 0), width - MARKER_W)} y={1}
          width={MARKER_W} height={height - 2} fill="var(--foreground)" />
      </svg>
      <p className="mt-1 text-xs text-muted-foreground">{percentileSentence(percentile)}</p>
    </div>
  )
}
