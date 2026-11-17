import type { CveRefreshSettings } from "@/lib/api"

// Bounds mirror the backend CVE refresh settings. The backend is authoritative
// (it returns 422); these only give early inline feedback.
export const CVE_REFRESH_TIME_LIMIT_MIN = 60
export const CVE_REFRESH_TIME_LIMIT_MAX = 3000
export const CVE_REFRESH_BATCH_MIN = 10
export const CVE_REFRESH_BATCH_MAX = 5000
export const CVE_REFRESH_INTERVAL_MIN = 1
export const CVE_REFRESH_INTERVAL_MAX = 720
export const CVE_REFRESH_FAILED_RETRY_MIN = 1
export const CVE_REFRESH_FAILED_RETRY_MAX = 720

const inRange = (n: number, lo: number, hi: number) => Number.isInteger(n) && n >= lo && n <= hi

/** First error message, or null when the draft is acceptable. */
export function validateCveRefreshSettings(d: CveRefreshSettings): string | null {
  if (!inRange(d.time_limit_seconds, CVE_REFRESH_TIME_LIMIT_MIN, CVE_REFRESH_TIME_LIMIT_MAX))
    return `The hourly run limit must be a whole number from ${CVE_REFRESH_TIME_LIMIT_MIN} to ${CVE_REFRESH_TIME_LIMIT_MAX} seconds.`
  if (!inRange(d.due_batch, CVE_REFRESH_BATCH_MIN, CVE_REFRESH_BATCH_MAX))
    return `CVEs read per run must be a whole number from ${CVE_REFRESH_BATCH_MIN} to ${CVE_REFRESH_BATCH_MAX}.`
  if (!inRange(d.refresh_interval_hours, CVE_REFRESH_INTERVAL_MIN, CVE_REFRESH_INTERVAL_MAX))
    return `The re-check interval must be a whole number from ${CVE_REFRESH_INTERVAL_MIN} to ${CVE_REFRESH_INTERVAL_MAX} hours.`
  if (!inRange(d.failed_retry_hours, CVE_REFRESH_FAILED_RETRY_MIN, CVE_REFRESH_FAILED_RETRY_MAX))
    return `Retrying a failed CVE must be a whole number from ${CVE_REFRESH_FAILED_RETRY_MIN} to ${CVE_REFRESH_FAILED_RETRY_MAX} hours.`
  if (d.failed_retry_hours > d.refresh_interval_hours)
    return "Retrying a failed CVE must not take longer than the re-check interval."
  return null
}
