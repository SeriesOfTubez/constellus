import { useState } from "react"
import { scaleLinear } from "@visx/scale"
import { LinePath } from "@visx/shape"
import { curveStepAfter } from "@visx/curve"
import type { ScoreBand, ScoreLadder, ScoreLadderFix, ScoreLadderLevel } from "@/lib/api"
import { RISK_BAND_LABEL } from "@/components/finding-badges"
import { BAND_VAR } from "./bands"

const MARGIN = { top: 28, right: 148, bottom: 32, left: 16 }
const MARKER_R = 9

export function fixCountLabel(n: number): string {
  return n === 1 ? "1 fix" : `${n} fixes`
}

export function shownFixes(ladder: ScoreLadder): number {
  const total = ladder.levels.length ? ladder.levels[ladder.levels.length - 1].fixes_through : 0
  if (ladder.crossings.length >= 2) {
    const c = ladder.crossings[1].fixes
    return Math.min(total, c + Math.max(1, Math.round(c * 0.15)))
  }
  return total
}

export function levelSentence(level: ScoreLadderLevel): string {
  const prefix = level.fixes_before === 0 ? "" : `After ${fixCountLabel(level.fixes_before)}: `
  const subject =
    level.count === 1 ? `1 finding scores ${level.score}. Fix it`
    : level.count === 2 ? `2 findings score ${level.score}. Fix both`
    : `${level.count} findings score ${level.score}. Fix all ${level.count}`
  const ending =
    level.score_after > 0
      ? ` and the score drops to ${level.score_after}, ${RISK_BAND_LABEL[level.band_after]}.`
      : ` and no scored finding is left open: ${RISK_BAND_LABEL.secure}.`
  return prefix + subject + ending
}

export function fixSentence(fix: ScoreLadderFix): string {
  const head = `Fix ${fix.rank}: ${fix.title}` + (fix.asset_value ? ` on ${fix.asset_value}` : "") + ". "
  if (fix.score_after < fix.risk_score) {
    return head + (fix.score_after > 0
      ? `The score drops from ${fix.risk_score} to ${fix.score_after}.`
      : `No scored finding is left open after it.`)
  }
  return head + `The score stays at ${fix.risk_score} until the other findings on that score are fixed too.`
}

export function ladderLabel(ladder: ScoreLadder): string {
  const [c0, c1] = ladder.crossings
  if (c0 && c1) {
    return `Step chart: risk score falls from ${ladder.score} to ${c0.score} after ${fixCountLabel(c0.fixes)} and to ${c1.score} after ${fixCountLabel(c1.fixes)}`
  }
  if (c0) {
    return `Step chart: risk score falls from ${ladder.score} to ${c0.score} after ${fixCountLabel(c0.fixes)}`
  }
  return `Step chart: risk score is ${ladder.score}`
}

type Group = { band: ScoreBand; levels: ScoreLadderLevel[] }

export function StepLadder({
  ladder, width, height = 288, onSelectFix,
}: {
  ladder: ScoreLadder
  width: number
  height?: number
  onSelectFix?: (id: string) => void
}) {
  const [activeLevel, setActiveLevel] = useState<number | null>(null)
  const [activeFix, setActiveFix] = useState<string | null>(null)

  if (width <= 0 || ladder.levels.length === 0) return null

  const plotLeft = MARGIN.left
  const plotRight = width - MARGIN.right
  const plotTop = MARGIN.top
  const plotBottom = height - MARGIN.bottom

  const shown = shownFixes(ladder)
  const shownLevels = ladder.levels.filter((l) => l.fixes_before < shown)

  // Consecutive levels in the same band share one coloured line segment.
  const groups: Group[] = []
  for (const l of shownLevels) {
    const g = groups[groups.length - 1]
    if (g && g.band === l.band) g.levels.push(l)
    else groups.push({ band: l.band, levels: [l] })
  }

  const paths = groups.map((g, gi) => {
    const last = g.levels[g.levels.length - 1]
    const nextGroup = groups[gi + 1]
    const endX = Math.min(last.fixes_through, shown)
    const endScore = nextGroup ? nextGroup.levels[0].score : last.score
    const points: [number, number][] = g.levels.map((l) => [l.fixes_before, l.score])
    points.push([endX, endScore])
    return { band: g.band, points }
  })

  const lowScore = Math.min(...paths.flatMap((p) => p.points.map((pt) => pt[1])))

  const x = scaleLinear<number>({ domain: [0, shown], range: [plotLeft, plotRight] })
  const flat = lowScore === ladder.score
  const y = scaleLinear<number>({
    domain: flat ? [ladder.score - 1, ladder.score + 1] : [lowScore, ladder.score],
    range: [plotBottom - 40, plotTop + 12],
  })

  const drawnCrossings = ladder.crossings.filter(
    (c) => c.fixes <= shown && c.score > 0 && c.score >= lowScore,
  )

  const firstTickX = drawnCrossings.length ? x(drawnCrossings[0].fixes) : null
  const showToday = firstTickX === null || firstTickX - plotLeft >= 64

  // Legend: one entry per shown band, centred on that band's drawn extent,
  // pushed down so entries stay at least 20px apart.
  const legendBands: ScoreBand[] = groups.map((g) => g.band).filter((b, i, a) => a.indexOf(b) === i)
  const legendRaw = legendBands.map((band) => {
    const ys = shownLevels.filter((l) => l.band === band).map((l) => y(l.score))
    return { band, y: (Math.min(...ys) + Math.max(...ys)) / 2 }
  }).sort((a, b) => a.y - b.y)
  const legend = legendRaw.reduce<{ band: ScoreBand; y: number }[]>((acc, e) => {
    const prev = acc[acc.length - 1]
    acc.push({ band: e.band, y: prev ? Math.max(e.y, prev.y + 20) : e.y })
    return acc
  }, [])

  const showMarkers = x(1) - x(0) >= 24

  const hoveredFix = activeFix !== null ? ladder.first_fixes.find((f) => f.id === activeFix) : undefined
  const readout = hoveredFix
    ? fixSentence(hoveredFix)
    : levelSentence(activeLevel !== null ? ladder.levels[activeLevel] : ladder.levels[0])

  const levelExtent = (l: ScoreLadderLevel) => {
    const x0 = x(l.fixes_before)
    return { x: x0, w: x(Math.min(l.fixes_through, shown)) - x0 }
  }
  const highlighted = activeLevel !== null ? ladder.levels[activeLevel] : null

  return (
    <div>
      {/* role="group", not "img": the steps and markers inside are focusable. */}
      <svg width={width} height={height} role="group" aria-label={ladderLabel(ladder)}>
        {highlighted && (() => {
          const e = levelExtent(highlighted)
          return (
            <rect x={e.x} y={plotTop} width={e.w} height={plotBottom - plotTop}
              fill="var(--muted)" opacity={0.5} />
          )
        })()}

        {drawnCrossings.map((c) => (
          <line key={`band-${c.band}`} x1={plotLeft} x2={plotRight} y1={y(c.score)} y2={y(c.score)}
            stroke="var(--border)" strokeDasharray="2 4" />
        ))}

        <line x1={plotLeft} x2={plotRight} y1={plotBottom} y2={plotBottom} stroke="var(--border)" />
        {drawnCrossings.map((c) => (
          <g key={`tick-${c.band}`}>
            <line x1={x(c.fixes)} x2={x(c.fixes)} y1={plotBottom} y2={plotBottom - 6} stroke="var(--border)" />
            <text x={x(c.fixes)} y={plotBottom + 20} textAnchor="middle" fontSize={12} fill="var(--muted-foreground)">
              {fixCountLabel(c.fixes)}
            </text>
          </g>
        ))}
        {showToday && (
          <text x={plotLeft} y={plotBottom + 20} textAnchor="start" fontSize={12} fill="var(--muted-foreground)">
            Today
          </text>
        )}

        {paths.map((p, i) => (
          <LinePath<[number, number]>
            key={`${p.band}-${i}`}
            data={p.points}
            x={(d) => x(d[0])}
            y={(d) => y(d[1])}
            curve={curveStepAfter}
            stroke={BAND_VAR[p.band]}
            strokeWidth={2}
            strokeLinejoin="round"
            strokeLinecap="round"
            fill="none"
          />
        ))}

        <text className="font-mono" x={plotLeft} y={y(ladder.score) - 10} fontSize={12} fontWeight={600}
          fill="var(--foreground)">
          {ladder.score}
        </text>
        {drawnCrossings.map((c) => (
          <text key={`score-${c.band}`} className="font-mono" x={x(c.fixes) + 12} y={y(c.score) + 14}
            fontSize={12} fontWeight={600} fill="var(--foreground)">
            {c.score}
          </text>
        ))}

        {legend.map((e) => (
          <g key={`legend-${e.band}`}>
            <rect x={plotRight + 12} y={e.y - 4} width={8} height={8} rx={2} fill={BAND_VAR[e.band]} />
            <text x={plotRight + 28} y={e.y + 4} fontSize={12} fill="var(--muted-foreground)">
              {RISK_BAND_LABEL[e.band]}
            </text>
          </g>
        ))}

        {shownLevels.map((l) => {
          const e = levelExtent(l)
          const idx = ladder.levels.indexOf(l)
          return (
            <rect key={`hover-${idx}`} x={e.x} y={plotTop} width={e.w} height={plotBottom - plotTop}
              fill="transparent" tabIndex={0} aria-label={levelSentence(l)}
              onMouseEnter={() => setActiveLevel(idx)} onFocus={() => setActiveLevel(idx)}
              onMouseLeave={() => setActiveLevel(null)} onBlur={() => setActiveLevel(null)} />
          )
        })}

        {showMarkers && ladder.first_fixes.filter((f) => f.rank <= shown).map((f) => {
          const cx = x(f.rank)
          const cy = f.score_after < f.risk_score
            ? (y(f.risk_score) + y(Math.max(f.score_after, lowScore))) / 2
            : y(f.risk_score)
          const sentence = fixSentence(f)
          return (
            <g key={`fix-${f.id}`} role="link" tabIndex={0} aria-label={sentence}
              style={onSelectFix ? { cursor: "pointer" } : undefined}
              onClick={() => onSelectFix?.(f.id)}
              onKeyDown={(ev) => {
                if (ev.key === "Enter" || ev.key === " ") {
                  ev.preventDefault()
                  onSelectFix?.(f.id)
                }
              }}
              onMouseEnter={() => setActiveFix(f.id)} onFocus={() => setActiveFix(f.id)}
              onMouseLeave={() => setActiveFix(null)} onBlur={() => setActiveFix(null)}>
              <title>{sentence}</title>
              <circle cx={cx} cy={cy} r={MARKER_R} fill="var(--card)"
                stroke={BAND_VAR[f.risk_band ?? ladder.band]} strokeWidth={2} />
              <text x={cx} y={cy + 4} textAnchor="middle" fontSize={12} fontWeight={600} fill="var(--foreground)">
                {f.rank}
              </text>
            </g>
          )
        })}
      </svg>
      <p className="mt-2 min-h-10 text-sm text-muted-foreground" aria-live="polite">{readout}</p>
    </div>
  )
}
