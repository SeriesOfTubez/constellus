import type { JobRun, JobSettings, JobStatus } from "@/lib/api"

// Bounds mirror the backend jobs settings. The backend is authoritative
// (it returns 422); these only give early inline feedback.
export const RUN_HISTORY_DAYS_MIN = 7
export const RUN_HISTORY_DAYS_MAX = 365

/** First error message, or null when the draft is acceptable. */
export function validateJobSettings(d: JobSettings): string | null {
  const n = d.run_history_days
  if (!Number.isInteger(n) || n < RUN_HISTORY_DAYS_MIN || n > RUN_HISTORY_DAYS_MAX)
    return `Run history must be a whole number from ${RUN_HISTORY_DAYS_MIN} to ${RUN_HISTORY_DAYS_MAX} days.`
  return null
}

/** Plain name for a job; an unknown job never echoes its raw identifier. */
export function jobLabel(job: string): string {
  if (job === "capture_sweep") return "Page capture"
  if (job === "rediscovery_tick") return "Organization re-discovery"
  return "Other scheduled job"
}

export function finishReasonText(reason: string): string {
  switch (reason) {
    case "done":
      return "Finished."
    case "time_limit":
      return "Stopped at its time limit. Anything it didn't reach is still due and runs next hour."
    case "lookup_failures":
      return "Stopped after the web archive lookup failed several times in a row. The remaining pages are still due and are tried again next hour."
    case "rate_limited":
      return "Stopped because a data source asked us to slow down. The remaining organisations are still due and are tried again next hour."
    case "not_configured":
      return "Nothing was captured: page capture isn't set up yet (no capture proxy key)."
    case "error":
      return "Failed with an unexpected error. The details are in the logs."
    default:
      return "Ended in a way this page doesn't describe yet. The details are in the logs."
  }
}

/** Only drives a muted vs. amber text colour; the severity palette is for findings. */
export function isProblem(reason: string): boolean {
  return reason !== "done"
}

export function formatDuration(seconds: number): string {
  const s = Math.floor(seconds)
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  return `${h}h ${String(m).padStart(2, "0")}m`
}

const errorsText = (n: number) => `${n} ${n === 1 ? "error" : "errors"}`

/** Null when the run recorded no counts (e.g. it failed): no line beats a line of zeros. */
export function runCountsText(run: JobRun): string | null {
  if (Object.keys(run.counts ?? {}).length === 0) return null
  const c = (k: string) => run.counts?.[k] ?? 0
  if (run.job === "capture_sweep") {
    let t = `${c("queued")} queued for capture out of ${c("candidates")} due`
    if (c("skipped") > 0) t += `, ${c("skipped")} skipped`
    if (c("errors") > 0) t += `, ${errorsText(c("errors"))}`
    return t
  }
  if (run.job === "rediscovery_tick") {
    let t = `${c("ok")} refreshed, ${c("failed")} failed, out of ${c("due")} due`
    const skipped = c("skipped") + c("skipped_busy")
    if (skipped > 0) t += `, ${skipped} skipped`
    if (c("errors") > 0) t += `, ${errorsText(c("errors"))}`
    return t
  }
  return `${run.items_selected} items picked up`
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
const pad2 = (n: number) => String(n).padStart(2, "0")

/** Local HH:MM (24h); prefixed with a short date when not today. */
export function formatSlotTime(iso: string, now: Date = new Date()): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return "—"
  const hhmm = `${pad2(d.getHours())}:${pad2(d.getMinutes())}`
  const sameDay = d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate()
  return sameDay ? hhmm : `${MONTHS[d.getMonth()]} ${d.getDate()} ${hhmm}`
}

// Wording is about the RECORD ("no run recorded"), never the world ("did not run").
export function missedSlotsText(status: JobStatus, windowHours: number, max = 3): { text: string; overflow: string[] } {
  if (status.recorded_since === null) return { text: "No runs recorded yet.", overflow: [] }
  if (status.missed_slots.length === 0)
    return { text: `Every hour in the last ${windowHours} hours has a recorded run.`, overflow: [] }
  const times = status.missed_slots.map((s) => formatSlotTime(s))
  return { text: `No run recorded at ${times.slice(0, max).join(", ")}`, overflow: times.slice(max) }
}
