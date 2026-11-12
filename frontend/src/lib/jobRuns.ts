import type { JobCadence, JobRun, JobSettings, JobStatus } from "@/lib/api"

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
const JOB_LABELS: Record<string, string> = {
  capture_sweep: "Page capture",
  rediscovery_tick: "Organization re-discovery",
  alert_digests: "Alert digests",
  run_reaper: "Stranded scan clean-up",
  nightly_rescore: "Nightly risk re-scoring",
  epss_refresher: "EPSS score refresh",
  cpe_index_refresher: "CPE to CVE index refresh",
  cloud_ranges_refresher: "Cloud provider ranges refresh",
  partition_maintenance: "History table maintenance",
  hygiene_scoring: "Asset hygiene scoring",
  job_run_purger: "Job run history retention",
  llm_ledger_pruner: "AI call ledger retention",
  chat_transcript_purger: "Chat transcript retention",
  report_purger: "Report retention",
  llm_models_refresher: "AI model list refresh",
}

export function jobLabel(job: string): string {
  return Object.prototype.hasOwnProperty.call(JOB_LABELS, job) ? JOB_LABELS[job] : "Other scheduled job"
}

/** The schedule in words in the reader's local clock, since every other time on the
 *  card is local: "hourly at :05", "daily at 21:00", "every 24 h". `offsetMinutes` is
 *  local minus UTC (the default is the browser's); tests pass it explicitly. */
export function cadenceText(c: JobCadence, offsetMinutes: number = -new Date().getTimezoneOffset()): string {
  if (c.kind === "hourly_at" || c.kind === "daily_at") {
    const utcMinutes = (c.hour ?? 0) * 60 + (c.minute ?? 0)
    const local = (((utcMinutes + offsetMinutes) % 1440) + 1440) % 1440
    const hh = String(Math.floor(local / 60)).padStart(2, "0")
    const mm = String(local % 60).padStart(2, "0")
    return c.kind === "hourly_at" ? `hourly at :${mm}` : `daily at ${hh}:${mm}`
  }
  const s = c.every_seconds ?? 0
  if (s % 3600 === 0) return s === 3600 ? "every hour" : `every ${s / 3600} h`
  if (s % 60 === 0) return `every ${s / 60} min`
  return `every ${s} s`
}

/** The schedule as the cron is defined (UTC), for a tooltip next to the local words. Null for intervals. */
export function cadenceUtcText(c: JobCadence): string | null {
  if (c.kind === "hourly_at") return `hourly at :${String(c.minute ?? 0).padStart(2, "0")} UTC`
  if (c.kind === "daily_at")
    return `daily at ${String(c.hour ?? 0).padStart(2, "0")}:${String(c.minute ?? 0).padStart(2, "0")} UTC`
  return null
}

export function finishReasonText(reason: string, job?: string): string {
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
      if (job === "capture_sweep")
        return "Nothing was captured: page capture isn't set up yet (no capture proxy key)."
      if (job === "llm_models_refresher") return "Skipped: the AI connector isn't set up yet."
      return "Skipped: this job isn't set up yet."
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

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`
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
  switch (run.job) {
    case "alert_digests":
      return `${plural(c("digests_created"), "digest", "digests")} created`
    case "job_run_purger":
      return `${plural(c("deleted"), "old run", "old runs")} deleted`
    case "llm_ledger_pruner":
      return `${plural(c("deleted"), "ledger row", "ledger rows")} deleted`
    case "chat_transcript_purger":
      return `${plural(c("deleted"), "conversation", "conversations")} deleted`
    case "report_purger":
      return `${plural(c("deleted"), "report", "reports")} deleted`
    case "epss_refresher":
      return `${c("upserted")} scores updated, ${c("pruned")} expired rows removed`
    case "cpe_index_refresher":
      return `${c("seeded")} seeded, ${c("delta")} updated`
    case "cloud_ranges_refresher":
      return c("changed") > 0 ? `${c("record_count")} ranges loaded (dataset changed)` : "Dataset unchanged"
    case "partition_maintenance":
      return `${c("created")} partitions created, ${c("dropped")} dropped`
    case "hygiene_scoring":
      return `${c("scored")} assets scored, ${c("excluded")} excluded`
    case "nightly_rescore":
      return `${c("rescored")} findings re-scored, ${c("promotions")} promoted`
    case "run_reaper":
      return c("startup") > 0
        ? `Startup sweep: ${plural(c("runs"), "scan", "scans")} and ${plural(c("ingest_runs"), "ingest", "ingests")} marked failed`
        : `${plural(c("runs"), "stranded scan", "stranded scans")} and ${plural(c("ingest_runs"), "ingest", "ingests")} cleaned up`
    case "llm_models_refresher":
      return `${c("models")} models allowed`
    default:
      return `${run.items_selected} items picked up`
  }
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
    return { text: `Every expected start in the last ${windowHours} hours has a recorded run.`, overflow: [] }
  const times = status.missed_slots.map((s) => formatSlotTime(s))
  return { text: `No run recorded at ${times.slice(0, max).join(", ")}`, overflow: times.slice(max) }
}
