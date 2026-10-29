// Pure logic for the Acquisitions timeline (planning#277 S4b). No React.
import { type AcquisitionRow, formatClosed } from "@/lib/organizations"

export interface Window { start: number; end: number }

const DAY = 86_400_000
const YEAR = 365.25 * DAY
const PAD = 182.5 * DAY
const EPS = 1 // ms; spans are computed from floats

export const ZOOM_SPANS_YEARS = [20, 10, 5, 2, 1]
const ZOOM_SPANS = ZOOM_SPANS_YEARS.map(y => y * YEAR)

/** ISO date -> axis position (UTC ms). Split by hand: never local-parse "YYYY-MM-DD".
 *  month/year precision sit at the midpoint of their period; day (and unknown) at UTC midnight. */
export function placementMs(closed: string | null, precision: string | null): number | null {
  if (!closed) return null
  const [ys, ms, ds] = closed.slice(0, 10).split("-")
  const y = Number(ys), m = Number(ms), d = Number(ds)
  if (!ys || !Number.isFinite(y)) return null
  if (precision === "year") return (Date.UTC(y, 0, 1) + Date.UTC(y + 1, 0, 1)) / 2
  if (!Number.isInteger(m) || m < 1 || m > 12) return null
  if (precision === "month") return (Date.UTC(y, m - 1, 1) + Date.UTC(y, m, 1)) / 2
  if (!Number.isInteger(d) || d < 1 || d > 31) return null
  const t = Date.UTC(y, m - 1, d)
  return new Date(t).getUTCDate() === d ? t : null // Date.UTC rolls 2021-02-31 into March
}

export function extent(points: number[]): Window | null {
  if (points.length === 0) return null
  let start = Math.min(...points) - PAD
  let end = Math.max(...points) + PAD
  const span = end - start
  if (span < YEAR) {
    const extra = (YEAR - span) / 2
    start -= extra
    end += extra
  }
  return { start, end }
}

const spanOf = (w: Window) => w.end - w.start

/** A zoom/pan choice remembers the extent it was made under; new data (a new extent) resets it. */
export interface TimelineView { ext: Window; win: Window }
export function currentWindow(view: TimelineView | null, ext: Window | null): Window | null {
  if (!ext) return null
  return view && view.ext.start === ext.start && view.ext.end === ext.end ? view.win : ext
}

export function clamp(win: Window, ext: Window): Window {
  const span = spanOf(win)
  if (span >= spanOf(ext)) return ext
  if (win.start < ext.start) return { start: ext.start, end: ext.start + span }
  if (win.end > ext.end) return { start: ext.end - span, end: ext.end }
  return win
}

export function canZoomIn(win: Window): boolean {
  return ZOOM_SPANS.some(s => s < spanOf(win) - EPS)
}

export function canZoomOut(win: Window, ext: Window): boolean {
  return Math.abs(spanOf(win) - spanOf(ext)) > EPS || Math.abs(win.start - ext.start) > EPS
}

export function zoomIn(win: Window, ext: Window): Window {
  const span = spanOf(win)
  const next = ZOOM_SPANS.find(s => s < span - EPS)
  if (next === undefined) return win
  const centre = (win.start + win.end) / 2
  return clamp({ start: centre - next / 2, end: centre + next / 2 }, ext)
}

export function zoomOut(win: Window, ext: Window): Window {
  const span = spanOf(win)
  const next = [...ZOOM_SPANS].reverse().find(s => s > span + EPS)
  if (next === undefined || next >= spanOf(ext)) return ext
  const centre = (win.start + win.end) / 2
  return clamp({ start: centre - next / 2, end: centre + next / 2 }, ext)
}

export function pan(win: Window, ext: Window, dir: -1 | 1): Window {
  const shift = (dir * spanOf(win)) / 2
  return clamp({ start: win.start + shift, end: win.end + shift }, ext)
}

export function canPan(win: Window, ext: Window, dir: -1 | 1): boolean {
  return dir === -1 ? win.start > ext.start + EPS : win.end < ext.end - EPS
}

export function xFraction(ms: number, win: Window): number {
  return (ms - win.start) / (win.end - win.start)
}

export function offEdges(points: number[], win: Window): { before: number; after: number } {
  let before = 0, after = 0
  for (const p of points) {
    if (p < win.start) before++
    else if (p > win.end) after++
  }
  return { before, after }
}

/** Index of the nearest point strictly off the given edge (the set `offEdges` counts); ties keep the first. */
export function jumpTarget(points: number[], win: Window, dir: -1 | 1): number | null {
  let best: number | null = null
  points.forEach((p, i) => {
    const off = dir === -1 ? p < win.start : p > win.end
    if (off && (best === null || (dir === -1 ? p > points[best] : p < points[best]))) best = i
  })
  return best
}

/** The window recentred on `ms` at the same zoom, clamped to the extent (so it still contains `ms`). */
export function centreOn(ms: number, win: Window, ext: Window): Window {
  const half = spanOf(win) / 2
  return clamp({ start: ms - half, end: ms + half }, ext)
}

export function yearTicks(win: Window): { year: number; x: number }[] {
  const years = spanOf(win) / YEAR
  const step = years <= 10 ? 1 : years <= 20 ? 2 : 5
  const first = new Date(win.start).getUTCFullYear()
  const last = new Date(win.end).getUTCFullYear() + 1
  const out: { year: number; x: number }[] = []
  for (let y = first; y <= last; y++) {
    if (y % step !== 0) continue
    const t = Date.UTC(y, 0, 1)
    if (t >= win.start && t <= win.end) out.push({ year: y, x: xFraction(t, win) })
  }
  return out
}

/** Greedy lane packing: per input index, the lowest lane whose last dot is >= minGap to the left. */
export function assignLanes(xs: number[], minGap = 0.025): number[] {
  const order = xs.map((_, i) => i).sort((a, b) => xs[a] - xs[b])
  const lastX: number[] = []
  const lanes = new Array<number>(xs.length).fill(0)
  for (const i of order) {
    let lane = lastX.findIndex(l => xs[i] - l >= minGap)
    if (lane === -1) { lane = lastX.length; lastX.push(xs[i]) } else lastX[lane] = xs[i]
    lanes[i] = lane
  }
  return lanes
}

type DotRow = Pick<AcquisitionRow,
  "name" | "closed" | "closed_precision" | "worst_severity"
  | "domains_claimed" | "asns_claimed" | "cidrs_claimed" | "assets">

export function dotKind(row: DotRow): "filled" | "clean" | "none" {
  if (row.worst_severity) return "filled"
  const scope = row.domains_claimed + row.asns_claimed + row.cidrs_claimed + row.assets
  return scope > 0 ? "clean" : "none"
}

export function dotTitle(row: DotRow): string {
  const kind = dotKind(row)
  const sev = kind === "filled" ? `worst open: ${row.worst_severity}`
    : kind === "clean" ? "no open findings" : "no claimed scope"
  const when = row.closed ? formatClosed(row.closed, row.closed_precision) : "date unknown"
  return `${row.name} · ${when} · ${sev}`
}

export function filterByDeal(rows: AcquisitionRow[], deal: string):
  { rows: AcquisitionRow[]; match: AcquisitionRow | null; stale: boolean } {
  if (!deal) return { rows, match: null, stale: false }
  const match = rows.find(r => !r.organic && r.entity_id === deal) ?? null
  return match ? { rows: [match], match, stale: false } : { rows, match: null, stale: true }
}
