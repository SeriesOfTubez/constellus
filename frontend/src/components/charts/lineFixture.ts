import type { LineAnnotation, LinePoint } from "./AnnotatedLine"

const pad = (n: number) => String(n).padStart(2, "0")

/** Consecutive daily points from `start` (YYYY-MM-DD), one per value. */
export function dailySeries(start: string, values: number[]): LinePoint[] {
  const [y, m, d] = start.split("-").map(Number)
  return values.map((value, i) => {
    const t = new Date(Date.UTC(y, m - 1, d + i))
    return { date: `${t.getUTCFullYear()}-${pad(t.getUTCMonth() + 1)}-${pad(t.getUTCDate())}`, value }
  })
}

const GROUND_GAINED_VALUES = [
  38, 38, 37, 36, 36, 35, 34, 33, 33, 32,
  31, 30, 30, 29, 28, 27, 27, 26, 25, 25,
  24, 23, 23, 22, 21, 21, 20,
  29, 26, 24, 23,
]

/** Falls for 27 days, jumps when a new subsidiary is scanned, then falls again. */
export const GROUND_GAINED: { points: LinePoint[]; annotations: LineAnnotation[] } = {
  points: dailySeries("2026-10-13", GROUND_GAINED_VALUES),
  annotations: [{ date: "2026-11-09", label: "Fabrikam Freight scanned, 9 more" }],
}
