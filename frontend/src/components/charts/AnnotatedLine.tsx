import { scaleLinear } from "@visx/scale"
import { Area, LinePath } from "@visx/shape"
import { SCRUB_FOCUS, SCRUB_SVG, scrubBands, useScrub } from "./scrub"

export type LinePoint = { date: string; value: number }
export type LineAnnotation = { date: string; label: string }
export type LineDomain = { from: string; to: string; max: number }

const MARGIN = { top: 24, right: 80, bottom: 28, left: 8 }
const COMPACT_MARGIN = { top: 16, right: 0, bottom: 8, left: 0 }
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
const LABEL_CHAR_PX = 7

export function dayNumber(iso: string): number {
  const [y, m, d] = iso.split("-").map(Number)
  return Date.UTC(y, m - 1, d) / 86_400_000
}

export function formatDay(iso: string, withYear = false): string {
  const [y, m, d] = iso.split("-").map(Number)
  return `${d} ${MONTHS[m - 1]}${withYear ? ` ${y}` : ""}`
}

export function valueText(value: number, unit: string): string {
  return `${value} ${unit}`
}

export function pointSentence(point: LinePoint, unit: string, annotationLabel?: string): string {
  const head = `${formatDay(point.date)}: ${valueText(point.value, unit)}.`
  return annotationLabel ? `${head} ${annotationLabel}.` : head
}

export function summarySentence(points: LinePoint[], unit: string): string {
  const first = points[0]
  const last = points[points.length - 1]
  if (points.length === 1) return `${valueText(last.value, unit)} on ${formatDay(last.date)}.`
  const withYear = first.date.slice(0, 4) !== last.date.slice(0, 4)
  let out = `${valueText(first.value, unit)} on ${formatDay(first.date, withYear)}, ${valueText(last.value, unit)} on ${formatDay(last.date, withYear)}.`
  const low = points.reduce((a, p) => (p.value < a.value ? p : a), first)
  if (low.value < first.value && low.value < last.value) {
    out += ` Lowest: ${valueText(low.value, unit)} on ${formatDay(low.date, withYear)}.`
  }
  return out
}

export function lineLabel(subject: string, points: LinePoint[], unit: string): string {
  return `Line chart: ${subject}. ${summarySentence(points, unit)}`
}

export function annotationPlacement(args: {
  px: number
  py: number
  risen: boolean
  labelLength: number
  plotLeft: number
  plotRight: number
}): { x: number; y: number; anchor: "start" | "end" } {
  const { px, py, risen, labelLength, plotLeft, plotRight } = args
  const need = labelLength * LABEL_CHAR_PX
  const roomLeft = px - 10 - plotLeft
  const roomRight = plotRight - (px + 10)
  const preferLeft = risen
  const preferredRoom = preferLeft ? roomLeft : roomRight
  const otherRoom = preferLeft ? roomRight : roomLeft
  const left = preferredRoom < need && otherRoom > preferredRoom ? !preferLeft : preferLeft
  return {
    x: left ? px - 10 : px + 10,
    y: Math.max(12, py - 12),
    anchor: left ? "end" : "start",
  }
}

export type PlacedLabel = { x: number; y: number; anchor: "start" | "end" }
type LabelInput = { px: number; py: number; risen: boolean; labelLength: number }

const LABEL_GAP = 8
const LABEL_LINE = 16

function labelExtent(p: PlacedLabel, length: number): [number, number] {
  const w = length * LABEL_CHAR_PX
  return p.anchor === "end" ? [p.x - w, p.x] : [p.x, p.x + w]
}

function labelsCollide(a: PlacedLabel, aLength: number, b: PlacedLabel, bLength: number): boolean {
  const [a0, a1] = labelExtent(a, aLength)
  const [b0, b1] = labelExtent(b, bLength)
  return Math.abs(a.y - b.y) < LABEL_LINE && a0 < b1 + LABEL_GAP && b0 < a1 + LABEL_GAP
}

function otherSide(p: PlacedLabel, px: number): PlacedLabel {
  return p.anchor === "end" ? { ...p, x: px + 10, anchor: "start" } : { ...p, x: px - 10, anchor: "end" }
}

/**
 * Place the labels of annotations given in x order. Two neighbours whose
 * estimated boxes meet are separated by moving the later one to its other
 * side, else the earlier one, else by putting the later one a line above.
 */
export function placeAnnotations(items: LabelInput[], plotLeft: number, plotRight: number): PlacedLabel[] {
  const fits = (p: PlacedLabel, length: number) => {
    const [x0, x1] = labelExtent(p, length)
    return x0 >= plotLeft && x1 <= plotRight
  }
  const out: PlacedLabel[] = []
  items.forEach((it, i) => {
    let cur: PlacedLabel = annotationPlacement({ ...it, plotLeft, plotRight })
    if (i > 0 && labelsCollide(out[i - 1], items[i - 1].labelLength, cur, it.labelLength)) {
      const prevLength = items[i - 1].labelLength
      const curFlip = otherSide(cur, it.px)
      const prevFlip = otherSide(out[i - 1], items[i - 1].px)
      if (fits(curFlip, it.labelLength) && !labelsCollide(out[i - 1], prevLength, curFlip, it.labelLength)) {
        cur = curFlip
      } else if (
        fits(prevFlip, prevLength) && !labelsCollide(prevFlip, prevLength, cur, it.labelLength)
        && !(i > 1 && labelsCollide(out[i - 2], items[i - 2].labelLength, prevFlip, prevLength))
      ) {
        out[i - 1] = prevFlip
      } else {
        // Up is away from the line; down is the fallback when the top is reached.
        const up = out[i - 1].y - LABEL_LINE
        cur = { ...cur, y: up >= 12 ? up : out[i - 1].y + LABEL_LINE }
      }
    }
    out.push(cur)
  })
  return out
}

export function AnnotatedLine({
  points, annotations = [], subject, unit, width, height, domain, lastLabel, compact = false,
}: {
  points: LinePoint[]
  annotations?: LineAnnotation[]
  subject: string
  unit: string
  width: number
  height?: number
  domain?: LineDomain
  lastLabel?: string
  compact?: boolean
}) {
  const { active, setActive, onKeyDown } = useScrub(points.length)

  if (width <= 0 || points.length === 0) return null

  const h = height ?? (compact ? 68 : 184)
  const m = compact ? COMPACT_MARGIN : MARGIN
  const plotLeft = m.left
  const plotRight = width - m.right
  const plotTop = m.top
  const plotBottom = h - m.bottom

  const first = points[0]
  const last = points[points.length - 1]
  const single = points.length === 1

  // A one-day domain needs no widening: the scale maps an empty domain to the middle of its range.
  const d0 = dayNumber(domain?.from ?? first.date)
  const d1 = dayNumber(domain?.to ?? last.date)
  const maxValue = domain?.max ?? Math.max(...points.map((p) => p.value))

  const x = scaleLinear<number>({ domain: [d0, d1], range: [plotLeft, plotRight] })
  const y = scaleLinear<number>({ domain: [0, maxValue > 0 ? maxValue : 1], range: [plotBottom, plotTop] })
  const px = (p: LinePoint) => x(dayNumber(p.date))
  const py = (p: LinePoint) => y(p.value)

  const resolved = annotations.flatMap((a) => {
    const i = points.findIndex((p) => p.date === a.date)
    return i < 0 ? [] : [{ a, i, p: points[i] }]
  }).sort((l, r) => l.i - r.i)
  const placed = placeAnnotations(
    resolved.map(({ a, i, p }) => ({
      px: px(p), py: py(p), risen: i > 0 && p.value > points[i - 1].value, labelLength: a.label.length,
    })),
    plotLeft, plotRight,
  )
  const labelFor = (i: number) => annotations.find((a) => a.date === points[i].date)?.label

  const readout = active !== null
    ? pointSentence(points[active], unit, labelFor(active))
    : summarySentence(points, unit)

  // Bands stop at the series' own ends: in a lane on a shared clock, the empty
  // months before a company arrived must not answer for its first day.
  const xs = points.map(px)
  const bands = single
    ? scrubBands(xs, plotLeft, plotRight)
    : scrubBands(xs, xs[0], xs[xs.length - 1])
  const activePoint = active !== null ? points[active] : null

  return (
    <div>
      {/* role="group", not "img": the slider inside is focusable. */}
      <svg className={SCRUB_SVG} width={width} height={h} role="group" aria-label={lineLabel(subject, points, unit)}>
        <line x1={plotLeft} x2={plotRight} y1={plotBottom} y2={plotBottom} stroke="var(--line-strong)" />

        {!single && (
          <Area<LinePoint>
            data={points}
            x={px}
            y0={plotBottom}
            y1={py}
            fill="var(--foreground)"
            fillOpacity={0.05}
            stroke="none"
          />
        )}
        {!single && (
          <LinePath<LinePoint>
            data={points}
            x={px}
            y={py}
            stroke="var(--fg-2)"
            strokeWidth={2}
            strokeLinejoin="round"
            strokeLinecap="round"
            fill="none"
          />
        )}

        {resolved.map(({ a, p }, n) => {
          const place = placed[n]
          return (
            <g key={`note-${a.date}`}>
              <line x1={px(p)} x2={px(p)} y1={py(p)} y2={plotBottom}
                stroke="var(--line-strong)" strokeDasharray="2 4" />
              <text x={place.x} y={place.y} textAnchor={place.anchor} fontSize={12} fill="var(--muted-foreground)">
                {a.label}
              </text>
            </g>
          )
        })}

        {(!compact || single) && (
          <circle cx={px(last)} cy={py(last)} r={4} fill="var(--foreground)" stroke="var(--card)" strokeWidth={2} />
        )}

        {!compact && (
          <>
            {!single && (
              <text x={plotLeft} y={Math.max(12, py(first) - 8)} fontSize={12} fill="var(--muted-foreground)">
                {valueText(first.value, unit)}
              </text>
            )}
            <text className="font-mono" x={px(last) + 12} y={py(last) + 4} fontSize={12} fontWeight={600}
              fill="var(--foreground)">
              {valueText(last.value, unit)}
            </text>
            {!single && (
              <text x={plotLeft} y={plotBottom + 20} textAnchor="start" fontSize={12} fill="var(--muted-foreground)">
                {formatDay(first.date)}
              </text>
            )}
            <text x={px(last)} y={plotBottom + 20} textAnchor={single ? "middle" : "end"} fontSize={12}
              fill="var(--muted-foreground)">
              {lastLabel ?? formatDay(last.date)}
            </text>
          </>
        )}

        {activePoint && (
          <>
            <line x1={px(activePoint)} x2={px(activePoint)} y1={plotTop} y2={plotBottom} stroke="var(--line-strong)" />
            <circle cx={px(activePoint)} cy={py(activePoint)} r={4} fill="var(--foreground)"
              stroke="var(--card)" strokeWidth={2} />
          </>
        )}

        {/* The whole svg, so the focus ring frames the chart instead of crossing its marks and labels. */}
        <rect className={SCRUB_FOCUS} x={0} y={0} width={width} height={h}
          fill="transparent" tabIndex={0} role="slider" aria-label="Day"
          aria-valuemin={0} aria-valuemax={points.length - 1} aria-valuenow={active ?? points.length - 1}
          aria-valuetext={readout} onKeyDown={onKeyDown} onBlur={() => setActive(null)} />
        {bands.map((b, i) => (
          <rect key={`band-${points[i].date}`} x={b.x} y={plotTop} width={b.w} height={plotBottom - plotTop}
            fill="transparent" onMouseEnter={() => setActive(i)} onMouseLeave={() => setActive(null)} />
        ))}
      </svg>
      <p className="mt-2 min-h-5 text-sm text-muted-foreground" aria-live="polite">{readout}</p>
    </div>
  )
}
