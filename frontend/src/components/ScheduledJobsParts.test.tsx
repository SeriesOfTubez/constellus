import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import type { JobRun, JobStatus } from "@/lib/api"
import { JobRunsList, JobStatusRow } from "@/components/ScheduledJobsParts"

const run = (over: Partial<JobRun> = {}): JobRun => ({
  id: "run-id-123", job: "capture_sweep", started_at: new Date(Date.now() - 3600_000).toISOString(),
  finished_at: new Date().toISOString(), duration_seconds: 192, finish_reason: "done", items_selected: 3,
  counts: { candidates: 5, queued: 3 }, error: null, ...over,
})
const status = (over: Partial<JobStatus> = {}): JobStatus => ({
  job: "capture_sweep", cadence_minute: 5, last_run: run(), recorded_since: new Date(Date.now() - 86400_000).toISOString(),
  missed_slots: [], ...over,
})
const row = (s: JobStatus, expanded = false) =>
  renderToStaticMarkup(<JobStatusRow status={s} windowHours={24} expanded={expanded} onToggle={() => {}} />)

describe("JobStatusRow", () => {
  it("shows label, cadence and duration", () => {
    const out = row(status())
    expect(out).toContain("Page capture")
    expect(out).toContain("hourly at :05")
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
    expect(row(status({ recorded_since: null, last_run: null }))).toContain("No runs recorded yet.")
  })
  it("five missed slots show +2", () => {
    const slots = [0, 1, 2, 3, 4].map((h) => new Date(2026, 10, 7, h, 5).toISOString())
    const out = row(status({ missed_slots: slots }))
    expect(out).toContain("No run recorded at")
    expect(out).toContain("+2")
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
