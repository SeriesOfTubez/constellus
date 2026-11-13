import { SCRUB_FOCUS, SCRUB_SVG, scrubBands, useScrub } from "./scrub"

export type HourBucket = { start: string; count: number }

const HOUR_MS = 3_600_000
const LABEL_ROW = 24
const CHAR_W = 7.2
const EDGE_LABEL_W = 5 * CHAR_W
const LABEL_GAP = 8

export function hourText(iso: string, timeZone?: string): string {
  return new Intl.DateTimeFormat("en-GB", {
    hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZone,
  }).format(new Date(iso))
}

export function bucketEnd(iso: string): string {
  return new Date(Date.parse(iso) + HOUR_MS).toISOString()
}

/** The first maximum, widened over neighbours holding at least half the maximum. Inclusive indexes. */
export function busiestRun(counts: number[]): { from: number; to: number } | null {
  const max = Math.max(0, ...counts)
  if (max === 0) return null
  const peak = counts.indexOf(max)
  let from = peak
  let to = peak
  while (from > 0 && counts[from - 1] >= max / 2) from--
  while (to < counts.length - 1 && counts[to + 1] >= max / 2) to++
  return { from, to }
}

export function countText(n: number, noun: [string, string]): string {
  return `${n} ${n === 1 ? noun[0] : noun[1]}`
}

export function hourSentence(bucket: HourBucket, noun: [string, string], timeZone?: string): string {
  return `${hourText(bucket.start, timeZone)} to ${hourText(bucketEnd(bucket.start), timeZone)}: ${countText(bucket.count, noun)}.`
}

export function stripSummary(hours: HourBucket[], noun: [string, string], timeZone?: string): string {
  const span = countText(hours.length, ["hour", "hours"])
  const run = busiestRun(hours.map((h) => h.count))
  if (!run) return `No ${noun[1]} in ${span}.`
  const total = hours.reduce((sum, h) => sum + h.count, 0)
  const from = hourText(hours[run.from].start, timeZone)
  const to = hourText(bucketEnd(hours[run.to].start), timeZone)
  return `${countText(total, noun)} in ${span}, busiest between ${from} and ${to}.`
}

export function stripLabel(hours: HourBucket[], noun: [string, string], timeZone?: string): string {
  return `Bar chart: ${noun[1]} per hour. ${stripSummary(hours, noun, timeZone)}`
}

const n2 = (v: number) => Math.round(v * 100) / 100

/** A bar with rounded top corners and square bottom corners; (x, y) is the top-left. */
export function barPath(x: number, y: number, w: number, h: number, r: number): string {
  const rr = Math.min(r, w / 2, h)
  const [x0, x1, y0, y1] = [n2(x), n2(x + w), n2(y), n2(y + h)]
  return `M${x0} ${y1}V${n2(y + rr)}Q${x0} ${y0} ${n2(x + rr)} ${y0}H${n2(x + w - rr)}Q${x1} ${y0} ${x1} ${n2(y + rr)}V${y1}Z`
}

/**
 * The label over the busiest run, or null when it cannot fit. Text is never
 * measured: width is estimated at 7.2px a character, and the two edge labels
 * are five characters each. Drops the note first, then the whole label.
 */
export function middleLabel(args: {
  hour: string
  note?: string
  centre: number
  width: number
}): { text: string; x: number } | null {
  const { hour, note, centre, width } = args
  const candidates = note ? [`${hour}, ${note}`, hour] : [hour]
  for (const text of candidates) {
    const half = (text.length * CHAR_W) / 2
    const x = Math.min(Math.max(centre, half), width - half)
    if (x - half >= EDGE_LABEL_W + LABEL_GAP && x + half <= width - EDGE_LABEL_W - LABEL_GAP) {
      return { text, x }
    }
  }
  return null
}

export function HourlyStrip({
  hours, noun, width, height = 48, note, timeZone,
}: {
  hours: HourBucket[]
  noun: [string, string]
  width: number
  height?: number
  note?: string
  timeZone?: string
}) {
  const n = hours.length
  const { active, setActive, onKeyDown } = useScrub(n)

  if (width <= 0 || n === 0) return null

  const counts = hours.map((h) => h.count)
  const maxCount = Math.max(...counts)
  const run = busiestRun(counts)
  const step = width / n
  const barW = Math.max(1, step - 2)
  const centres = hours.map((_, i) => i * step + barW / 2)
  const bands = scrubBands(centres, 0, width)

  const summary = stripSummary(hours, noun, timeZone)
  const readout = active !== null ? hourSentence(hours[active], noun, timeZone) : summary

  const middle = run
    ? middleLabel({
        hour: hourText(hours[run.from].start, timeZone),
        note,
        centre: ((run.from + run.to + 1) * step) / 2,
        width,
      })
    : null

  const labelY = height + 16

  return (
    <div>
      {/* role="group", not "img": the slider inside is focusable. */}
      <svg className={SCRUB_SVG} width={width} height={height + LABEL_ROW} role="group" aria-label={stripLabel(hours, noun, timeZone)}>
        {hours.map((h, i) => {
          if (h.count <= 0) return null
          const barH = Math.max(2, Math.round((h.count / maxCount) * height))
          const inRun = run !== null && i >= run.from && i <= run.to
          const fill = i === active ? "var(--fg-2)" : inRun ? "var(--muted-foreground)" : "var(--line-strong)"
          return <path key={h.start} d={barPath(i * step, height - barH, barW, barH, 2)} fill={fill} />
        })}

        <line x1={0} x2={width} y1={height} y2={height} stroke="var(--border)" />

        <text x={0} y={labelY} textAnchor="start" fontSize={12} className="font-mono" fill="var(--muted-foreground)">
          {hourText(hours[0].start, timeZone)}
        </text>
        {middle && (
          <text x={middle.x} y={labelY} textAnchor="middle" fontSize={12} className="font-mono"
            fill="var(--muted-foreground)">
            {middle.text}
          </text>
        )}
        <text x={width} y={labelY} textAnchor="end" fontSize={12} className="font-mono" fill="var(--muted-foreground)">
          {hourText(bucketEnd(hours[n - 1].start), timeZone)}
        </text>

        <rect className={SCRUB_FOCUS} x={0} y={0} width={width} height={height + LABEL_ROW} fill="transparent"
          tabIndex={0} role="slider"
          aria-label="Hour" aria-valuemin={0} aria-valuemax={n - 1} aria-valuenow={active ?? n - 1}
          aria-valuetext={readout} onKeyDown={onKeyDown} onBlur={() => setActive(null)} />
        {bands.map((b, i) => (
          <rect key={`band-${hours[i].start}`} x={b.x} y={0} width={b.w} height={height} fill="transparent"
            onMouseEnter={() => setActive(i)} onMouseLeave={() => setActive(null)} />
        ))}
      </svg>
      <p className="mt-2 min-h-5 text-sm text-muted-foreground" aria-live="polite">{readout}</p>
    </div>
  )
}
