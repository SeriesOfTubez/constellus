import type { LogQueueSettings } from "@/lib/api"

// Bounds mirror the backend logging settings. The backend is authoritative
// (it returns 422); these only give early inline feedback.
export const QUEUE_MAX_MIN = 1000
export const QUEUE_MAX_MAX = 100000
export const BATCH_MAX_MIN = 10
export const BATCH_MAX_MAX = 1000
export const FLUSH_INTERVAL_S_MIN = 0.2
export const FLUSH_INTERVAL_S_MAX = 10

export type LogQueueDraft = Pick<LogQueueSettings, "queue_max_records" | "batch_max_records" | "flush_interval_s">

/** First error message in field order, or null when the draft is acceptable. */
export function validateLogQueueSettings(d: LogQueueDraft): string | null {
  const q = d.queue_max_records
  if (!Number.isInteger(q) || q < QUEUE_MAX_MIN || q > QUEUE_MAX_MAX)
    return "Lines held in memory must be a whole number from 1,000 to 100,000."
  const b = d.batch_max_records
  if (!Number.isInteger(b) || b < BATCH_MAX_MIN || b > BATCH_MAX_MAX)
    return "Lines per write must be a whole number from 10 to 1,000."
  const f = d.flush_interval_s
  if (!Number.isFinite(f) || f < FLUSH_INTERVAL_S_MIN || f > FLUSH_INTERVAL_S_MAX)
    return "Longest wait before a write must be a number from 0.2 to 10 seconds."
  return null
}

/** Shown when the saved queue size differs from the one the running backend uses. */
export function queueRestartNote(s: LogQueueSettings): string | null {
  if (s.queue_max_records_active === s.queue_max_records) return null
  return `Running with ${s.queue_max_records_active.toLocaleString("en-US")} until the backend restarts.`
}
