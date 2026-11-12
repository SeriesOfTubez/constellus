import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import type { JobCadence, JobRun, JobStatus } from "@/lib/api"
import { jobLabel } from "@/lib/jobRuns"
import { JobRunsList, JobStatusRow } from "@/components/ScheduledJobsParts"

const run = (over: Partial<JobRun> = {}): JobRun => ({
  id: "run-id-123", job: "capture_sweep", started_at: new Date(Date.now() - 3600_000).toISOString(),
  finished_at: new Date().toISOString(), duration_seconds: 192, finish_reason: "done", items_selected: 3,
  counts: { candidates: 5, queued: 3 }, error: null, ...over,
})
const status = (over: Partial<JobStatus> = {}): JobStatus => ({
  job: "capture_sweep", cadence: { kind: "hourly_at", minute: 5, hour: null, every_seconds: null }, last_run: run(), recorded_since: new Date(Date.now() - 86400_000).toISOString(),
  missed_slots: [], last_tick_at: null, ...over,
})
const row = (s: JobStatus, expanded = false) =>
  renderToStaticMarkup(<JobStatusRow status={s} windowHours={24} expanded={expanded} onToggle={() => {}} />)

describe("JobStatusRow", () => {
  it("shows label, cadence and duration", () => {
    const out = row(status())
    expect(out).toContain("Page capture")
    expect(out).toContain("hourly at :")
    expect(out).toContain('title="hourly at :05 UTC"')
    expect(out).toContain("3m 12s")
  })
  it("error run shows the sentence, never the raw error or code", () => {
    const out = row(status({ last_run: run({ finish_reason: "error", error: "TimeoutError" }) }))
    expect(out).toContain("Failed with an unexpected error. The details are in the logs.")
    expect(out).not.toContain("TimeoutError")
    expect(out).not.toContain(">error<")
    expect(out).not.toContain('"error"')
    expect(out).toContain("text-amber-600")
  })
  it("never renders the raw reason code", () => {
    for (const reason of ["done", "time_limit", "lookup_failures", "rate_limited", "not_configured", "mystery_code"]) {
      expect(row(status({ last_run: run({ finish_reason: reason }) }))).not.toContain(reason === "done" ? ">done<" : reason)
    }
  })
  it("done run is not amber", () => expect(row(status())).not.toContain("text-amber-600"))
  it("unknown job shows a generic name, not the raw one", () => {
    const out = row(status({ job: "secret_new_job", last_run: run({ job: "secret_new_job" }) }))
    expect(out).toContain("Other scheduled job")
    expect(out).not.toContain("secret_new_job")
  })
  it("recorded_since null says no runs recorded yet", () => {
    const out = row(status({ recorded_since: null, last_run: null }))
    expect(out.split("No runs recorded yet.").length - 1).toBe(1)
  })
  it("five missed slots show +2", () => {
    const slots = [0, 1, 2, 3, 4].map((h) => new Date(2026, 10, 7, h, 5).toISOString())
    const out = row(status({ missed_slots: slots }))
    expect(out).toContain("No run recorded at")
    expect(out).toContain("+2")
  })
  it("renders each cadence in words", () => {
    const cad = (over: Partial<JobCadence>): JobCadence => ({ kind: "interval", minute: null, hour: null, every_seconds: null, ...over })
    const daily = row(status({ cadence: cad({ kind: "daily_at", hour: 3, minute: 0 }) }))
    expect(daily).toContain("daily at ")
    expect(daily).toContain('title="daily at 03:00 UTC"')
    expect(row(status({ cadence: cad({ every_seconds: 86400 }) }))).not.toContain('title="every')
    expect(row(status({ cadence: cad({ every_seconds: 86400 }) }))).toContain("every 24 h")
    expect(row(status({ cadence: cad({ every_seconds: 3600 }) }))).toContain("every hour")
    expect(row(status({ cadence: cad({ every_seconds: 300 }) }))).toContain("every 5 min")
  })
  it("full coverage adds no coverage line; a missed slot does", () => {
    const covered = row(status())
    expect(covered).not.toContain("Every expected start")
    expect(covered).not.toContain("No run recorded at")
    const missed = row(status({ missed_slots: [new Date(2026, 10, 7, 4, 5).toISOString()] }))
    expect(missed).toContain("No run recorded at")
  })
  it("not_configured on the AI model refresh names the AI connector, not capture", () => {
    const out = row(status({ job: "llm_models_refresher", last_run: run({ job: "llm_models_refresher", finish_reason: "not_configured" }) }))
    expect(out).toContain("Skipped: the AI connector isn&#x27;t set up yet.")
    expect(out).not.toContain("capture proxy")
  })
  it("every known job shows its label and never its raw id", () => {
    const ids = ["alert_digests", "rediscovery_tick", "capture_sweep", "run_reaper", "nightly_rescore", "epss_refresher",
      "cpe_index_refresher", "cloud_ranges_refresher", "partition_maintenance", "hygiene_scoring", "job_run_purger",
      "llm_ledger_pruner", "chat_transcript_purger", "report_purger", "llm_models_refresher",
      "page_capture", "ct_refresher", "capture_tokens", "tenancy_enricher", "tenancy_tls"]
    expect(ids).toHaveLength(20)
    for (const id of ids) {
      const out = row(status({ job: id, last_run: run({ job: id }) }))
      expect(out).toContain(jobLabel(id))
      expect(jobLabel(id)).not.toBe("Other scheduled job")
      expect(out).not.toContain(id)
    }
  })
  const tick = (over: Partial<JobCadence> = {}): JobCadence => ({ kind: "interval", minute: null, hour: null, every_seconds: 10, ...over })
  it("sub-hour job shows the recorded-when-it-does-work note and the last tick line", () => {
    const out = row(status({
      cadence: tick(), job: "page_capture", last_run: run({ job: "page_capture" }),
      last_tick_at: new Date(Date.now() - 5000).toISOString(),
    }))
    for (const s of ["every 10 s", "recorded when it does work", "Last tick", "just now", "in this backend process", "resets on restart"])
      expect(out).toContain(s)
    expect(out).not.toContain("No runs recorded yet.")
  })
  it("sub-hour job with no tick yet and no runs says so", () => {
    const out = row(status({ cadence: tick(), job: "page_capture", last_run: null, last_tick_at: null }))
    expect(out).toContain("No tick has done work yet.")
    expect(out).toContain("No tick yet in this backend process")
    expect(out).not.toContain("No runs recorded yet.")
  })
  it("hour-or-longer jobs show neither note", () => {
    const daily = row(status({ cadence: tick({ every_seconds: 86400 }), last_tick_at: new Date().toISOString() }))
    expect(daily).not.toContain("recorded when it does work")
    expect(daily).not.toContain("Last tick")
    const hourly = row(status({ last_tick_at: new Date().toISOString() }))
    expect(hourly).not.toContain("recorded when it does work")
    expect(hourly).not.toContain("Last tick")
  })
  it("queueing and ingest labels are distinct", () => {
    expect(row(status({ job: "capture_sweep" }))).toContain("Page capture queueing")
    const ingest = row(status({ job: "page_capture", cadence: tick(), last_run: run({ job: "page_capture" }) }))
    expect(ingest).toContain("Page capture ingest")
    expect(ingest).not.toContain("Page capture queueing")
  })
  it("aria-expanded reflects expanded", () => {
    expect(row(status(), true)).toContain('aria-expanded="true"')
    expect(row(status(), true)).toContain("Hide recent runs")
    expect(row(status(), false)).toContain('aria-expanded="false"')
    expect(row(status(), false)).toContain("Recent runs")
  })
})

describe("JobRunsList", () => {
  it("empty list", () => {
    expect(renderToStaticMarkup(<JobRunsList runs={[]} isLoading={false} />)).toContain("No runs recorded in the retention window.")
  })
  it("one run shows counts and hides id and raw error", () => {
    const out = renderToStaticMarkup(<JobRunsList runs={[run({ finish_reason: "time_limit", error: "Boom" })]} isLoading={false} />)
    expect(out).toContain("3 queued for capture out of 5 due")
    expect(out).toContain("Stopped at its time limit.")
    expect(out).not.toContain("run-id-123")
    expect(out).not.toContain("Boom")
    expect(out).not.toContain("time_limit")
  })
  it("a failed run with no counts shows its sentence and no line of zeros", () => {
    const out = renderToStaticMarkup(<JobRunsList runs={[run({ finish_reason: "error", error: "TimeoutError", counts: {} })]} isLoading={false} />)
    expect(out).toContain("Failed with an unexpected error.")
    expect(out).not.toContain("0 queued")
    expect(out).not.toContain("due")
  })
})
