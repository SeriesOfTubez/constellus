import type { DiscoverySettings } from "@/lib/api"

// Bounds mirror the backend discovery settings. The backend is authoritative
// (it returns 422); these only give early inline feedback.
export const REDISCOVERY_TIME_LIMIT_MIN = 60
export const REDISCOVERY_TIME_LIMIT_MAX = 3000
export const REDISCOVERY_PAUSE_MIN = 1
export const REDISCOVERY_PAUSE_MAX = 60
export const REDISCOVERY_BATCH_MIN = 10
export const REDISCOVERY_BATCH_MAX = 1000
export const REDISCOVERY_REFRESH_MIN = 1
export const REDISCOVERY_REFRESH_MAX = 90
export const REDISCOVERY_FAILED_RETRY_MIN = 1
export const REDISCOVERY_FAILED_RETRY_MAX = 30

const inRange = (n: number, lo: number, hi: number) => Number.isInteger(n) && n >= lo && n <= hi

/** First error message, or null when the draft is acceptable. */
export function validateDiscoverySettings(d: DiscoverySettings): string | null {
  if (!inRange(d.rediscovery_time_limit_seconds, REDISCOVERY_TIME_LIMIT_MIN, REDISCOVERY_TIME_LIMIT_MAX))
    return `The hourly run limit must be a whole number from ${REDISCOVERY_TIME_LIMIT_MIN} to ${REDISCOVERY_TIME_LIMIT_MAX} seconds.`
  if (!inRange(d.rediscovery_unit_pause_seconds, REDISCOVERY_PAUSE_MIN, REDISCOVERY_PAUSE_MAX))
    return `Pause between items must be a whole number from ${REDISCOVERY_PAUSE_MIN} to ${REDISCOVERY_PAUSE_MAX} seconds.`
  if (!inRange(d.rediscovery_due_batch, REDISCOVERY_BATCH_MIN, REDISCOVERY_BATCH_MAX))
    return `Items read per kind per run must be a whole number from ${REDISCOVERY_BATCH_MIN} to ${REDISCOVERY_BATCH_MAX}.`
  if (!inRange(d.rediscovery_refresh_interval_days, REDISCOVERY_REFRESH_MIN, REDISCOVERY_REFRESH_MAX))
    return `The refresh interval must be a whole number from ${REDISCOVERY_REFRESH_MIN} to ${REDISCOVERY_REFRESH_MAX} days.`
  if (!inRange(d.rediscovery_failed_retry_days, REDISCOVERY_FAILED_RETRY_MIN, REDISCOVERY_FAILED_RETRY_MAX))
    return `Retrying a failed item must be a whole number from ${REDISCOVERY_FAILED_RETRY_MIN} to ${REDISCOVERY_FAILED_RETRY_MAX} days.`
  if (d.rediscovery_failed_retry_days > d.rediscovery_refresh_interval_days)
    return "Retrying a failed item must not take longer than the refresh interval."
  return null
}
