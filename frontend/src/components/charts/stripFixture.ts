import type { HourBucket } from "./HourlyStrip"

/** Test fixture builder: consecutive hours from `start`, each start as a UTC ISO string. */
export function hourlyBuckets(start: string, counts: number[]): HourBucket[] {
  const t0 = Date.parse(start)
  return counts.map((count, i) => ({ start: new Date(t0 + i * 3_600_000).toISOString(), count }))
}

/** 18 hours, 41 in total; the busiest run is 02:00 to 04:00 UTC. */
export const OVERNIGHT: HourBucket[] = hourlyBuckets(
  "2026-11-12T15:00:00Z",
  [1, 0, 1, 0, 1, 0, 2, 1, 1, 2, 3, 10, 8, 4, 2, 3, 1, 1],
)
