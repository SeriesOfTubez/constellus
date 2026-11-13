import { describe, expect, it } from "vitest"
import type { JobCadence, JobRun, JobStatus } from "@/lib/api"
import {
  cadenceText, cadenceUtcText, finishReasonText, formatDuration, formatSlotTime, isProblem, isSubHour, jobLabel, missedSlotsText,
  runCountsText, validateJobSettings,
} from "@/lib/jobRuns"

const iso = (y: number, m: number, d: number, h: number, mi: number) => new Date(y, m, d, h, mi).toISOString()
const run = (job: string, counts: Record<string, number>, over: Partial<JobRun> = {}): JobRun => ({
  id: "r1", job, started_at: iso(2026, 10, 8, 10, 0), finished_at: iso(2026, 10, 8, 10, 1), duration_seconds: 60,
  finish_reason: "done", items_selected: 5, counts, error: null, ...over,
})
const status = (over: Partial<JobStatus> = {}): JobStatus => ({
  job: "capture_sweep", cadence: { kind: "hourly_at", minute: 40, hour: null, every_seconds: null }, last_run: null, recorded_since: iso(2026, 10, 7, 0, 0), missed_slots: [], last_tick_at: null, ...over,
})

describe("validateJobSettings", () => {
  const v = (n: number) => validateJobSettings({ run_history_days: n })
  it("checks bounds", () => {
    expect(v(7)).toBeNull()
    expect(v(365)).toBeNull()
    expect(v(6)).toBe("Run history must be a whole number from 7 to 365 days.")
    expect(v(366)).not.toBeNull()
    expect(v(7.5)).not.toBeNull()
    expect(v(NaN)).not.toBeNull()
  })
})

describe("finishReasonText", () => {
  const exact: Record<string, string> = {
    done: "Finished.",
    time_limit: "Stopped at its time limit. Anything it didn't reach is still due and runs next hour.",
    lookup_failures: "Stopped after the web archive lookup failed several times in a row. The remaining pages are still due and are tried again next hour.",
    rate_limited: "Stopped because a data source asked us to slow down. The remaining organisations are still due and are tried again next hour.",
    not_configured: "Nothing was captured: page capture isn't set up yet (no capture proxy key).",
    error: "Failed with an unexpected error. The details are in the logs.",
  }
  it("maps every reason to its exact sentence, with no raw code", () => {
    for (const [code, sentence] of Object.entries(exact)) {
      expect(finishReasonText(code, "capture_sweep")).toBe(sentence)
      expect(sentence).not.toContain("_")
      // "error" is also an ordinary word in its own sentence; the underscore codes and "done" are checkable.
      if (code !== "error") expect(sentence.toLowerCase()).not.toContain(code)
    }
  })
  it("falls back for an unknown reason without echoing it", () => {
    const t = finishReasonText("brand_new_reason")
    expect(t).toBe("Ended in a way this page doesn't describe yet. The details are in the logs.")
    expect(t).not.toContain("brand_new_reason")
  })
  it("isProblem is false only for done", () => {
    expect(isProblem("done")).toBe(false)
    expect(isProblem("time_limit")).toBe(true)
    expect(isProblem("whatever")).toBe(true)
  })
})

describe("jobLabel", () => {
  it("names known jobs and hides unknown ones", () => {
    expect(jobLabel("capture_sweep")).toBe("Page capture queueing")
    expect(jobLabel("rediscovery_tick")).toBe("Organization re-discovery")
    expect(jobLabel("secret_new_job")).toBe("Other scheduled job")
  })
})

const ALL_JOBS: Record<string, string> = {
  capture_sweep: "Page capture queueing",
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
  page_capture: "Page capture ingest",
  ct_refresher: "Certificate transparency cache refresh",
  capture_tokens: "Capture store token publisher",
  tenancy_enricher: "Cloud tenancy enrichment",
  tenancy_tls: "TLS certificate tenancy check",
}

describe("jobLabel, all known jobs", () => {
  it("labels every known job and falls back for others", () => {
    expect(Object.keys(ALL_JOBS)).toHaveLength(20)
    for (const [id, label] of Object.entries(ALL_JOBS)) expect(jobLabel(id)).toBe(label)
    expect(jobLabel("toString")).toBe("Other scheduled job")
  })
})

describe("cadenceText", () => {
  const c = (over: Partial<JobCadence>): JobCadence => ({ kind: "interval", minute: null, hour: null, every_seconds: null, ...over })
  it("hourly and daily", () => {
    expect(cadenceText(c({ kind: "hourly_at", minute: 5 }), 0)).toBe("hourly at :05")
    expect(cadenceText(c({ kind: "hourly_at", minute: 40 }), -360)).toBe("hourly at :40")
    expect(cadenceText(c({ kind: "daily_at", hour: 3, minute: 0 }), 0)).toBe("daily at 03:00")
    expect(cadenceText(c({ kind: "daily_at", hour: 3, minute: 0 }), -360)).toBe("daily at 21:00")
    expect(cadenceText(c({ kind: "daily_at", hour: 23, minute: 30 }), 120)).toBe("daily at 01:30")
    expect(cadenceText(c({ kind: "hourly_at", minute: 5 }), 330)).toBe("hourly at :35")
    expect(cadenceUtcText(c({ kind: "hourly_at", minute: 5 }))).toBe("hourly at :05 UTC")
    expect(cadenceUtcText(c({ kind: "daily_at", hour: 3, minute: 0 }))).toBe("daily at 03:00 UTC")
    expect(cadenceUtcText(c({ every_seconds: 3600 }))).toBeNull()
  })
  it("intervals", () => {
    expect(cadenceText(c({ every_seconds: 3600 }))).toBe("every hour")
    expect(cadenceText(c({ every_seconds: 86400 }))).toBe("every 24 h")
    expect(cadenceText(c({ every_seconds: 43200 }))).toBe("every 12 h")
    expect(cadenceText(c({ every_seconds: 300 }))).toBe("every 5 min")
    expect(cadenceText(c({ every_seconds: 10 }))).toBe("every 10 s")
  })
})

describe("isSubHour", () => {
  const c = (over: Partial<JobCadence>): JobCadence => ({ kind: "interval", minute: null, hour: null, every_seconds: null, ...over })
  it("is true only for intervals under an hour", () => {
    expect(isSubHour(c({ every_seconds: 10 }))).toBe(true)
    expect(isSubHour(c({ every_seconds: 60 }))).toBe(true)
    expect(isSubHour(c({ every_seconds: 300 }))).toBe(true)
    expect(isSubHour(c({ every_seconds: 3600 }))).toBe(false)
    expect(isSubHour(c({ every_seconds: 86400 }))).toBe(false)
    expect(isSubHour(c({ every_seconds: null }))).toBe(false) // an interval with no length is not "sub-hour"
    expect(isSubHour(c({ kind: "hourly_at", minute: 5 }))).toBe(false)
    expect(isSubHour(c({ kind: "daily_at", hour: 3, minute: 0 }))).toBe(false)
  })
})

describe("finishReasonText not_configured per job", () => {
  it("is job specific", () => {
    expect(finishReasonText("not_configured", "capture_sweep")).toBe("Nothing was captured: page capture isn't set up yet (no capture proxy key).")
    expect(finishReasonText("not_configured", "llm_models_refresher")).toBe("Skipped: the AI connector isn't set up yet.")
    expect(finishReasonText("not_configured", "report_purger")).toBe("Skipped: this job isn't set up yet.")
  })
})

describe("runCountsText, newer jobs", () => {
  const t = (job: string, counts: Record<string, number>) => runCountsText(run(job, counts))
  it("each job", () => {
    expect(t("alert_digests", { digests_created: 1 })).toBe("1 digest created")
    expect(t("alert_digests", { digests_created: 3 })).toBe("3 digests created")
    expect(t("job_run_purger", { deleted: 1 })).toBe("1 old run deleted")
    expect(t("job_run_purger", { deleted: 4 })).toBe("4 old runs deleted")
    expect(t("llm_ledger_pruner", { deleted: 1 })).toBe("1 ledger row deleted")
    expect(t("llm_ledger_pruner", { deleted: 2 })).toBe("2 ledger rows deleted")
    expect(t("chat_transcript_purger", { deleted: 1 })).toBe("1 conversation deleted")
    expect(t("chat_transcript_purger", { deleted: 2 })).toBe("2 conversations deleted")
    expect(t("report_purger", { deleted: 1 })).toBe("1 report deleted")
    expect(t("report_purger", { deleted: 2 })).toBe("2 reports deleted")
    expect(t("epss_refresher", { upserted: 9, pruned: 2 })).toBe("9 scores updated, 2 expired rows removed")
    expect(t("cpe_index_refresher", { seeded: 5, delta: 6 })).toBe("5 seeded, 6 updated")
    expect(t("cloud_ranges_refresher", { changed: 1, record_count: 120 })).toBe("120 ranges loaded (dataset changed)")
    expect(t("cloud_ranges_refresher", { changed: 0, record_count: 120 })).toBe("Dataset unchanged")
    expect(t("partition_maintenance", { created: 2, dropped: 1 })).toBe("2 partitions created, 1 dropped")
    expect(t("hygiene_scoring", { scored: 40, excluded: 3 })).toBe("40 assets scored, 3 excluded")
    expect(t("nightly_rescore", { rescored: 12, promotions: 1 })).toBe("12 findings re-scored, 1 promoted")
    expect(t("run_reaper", { startup: 1, runs: 2, ingest_runs: 1 })).toBe("Startup sweep: 2 scans and 1 ingest marked failed")
    expect(t("run_reaper", { startup: 0, runs: 2, ingest_runs: 1 })).toBe("2 stranded scans and 1 ingest cleaned up")
    expect(t("run_reaper", { startup: 0, runs: 1, ingest_runs: 0 })).toBe("1 stranded scan and 0 ingests cleaned up")
    expect(t("llm_models_refresher", { models: 7 })).toBe("7 models allowed")
    expect(t("page_capture", { ingested: 2, swept: 1, pruned: 0, claims_swept: 0, limits_written: 0, errors: 0 })).toBe("2 results ingested, 1 timed out, 0 images pruned")
    expect(t("page_capture", { ingested: 2, swept: 1, pruned: 0, claims_swept: 3, limits_written: 1, errors: 1 })).toBe("2 results ingested, 1 timed out, 0 images pruned, 3 stale claims cleared, proxy limits written, 1 error")
    expect(t("page_capture", { ingested: 1, swept: 0, pruned: 1 })).toBe("1 result ingested, 0 timed out, 1 image pruned")
    expect(t("ct_refresher", { targets: 3, budget: 5, refreshed: 2, errors: 1 })).toBe("2 of 3 domain caches refreshed, 1 error")
    expect(t("ct_refresher", { targets: 1, refreshed: 1 })).toBe("1 of 1 domain cache refreshed")
    expect(t("capture_tokens", { fresh: 1, published: 1 })).toBe("1 published, 1 still fresh")
    expect(t("capture_tokens", { fresh: 0, published: 0, mint_failed: 1, refused_floor: 1, conflict: 0, errors: 2 })).toBe("0 published, 0 still fresh, 1 mint failed, 1 refused (too little lifetime left)")
    expect(t("capture_tokens", { fresh: 0, published: 0, conflict: 2 })).toBe("0 published, 0 still fresh, 2 lost a write race")
    expect(t("tenancy_enricher", { selected: 200, enriched: 150, stale_dataset: 1, errors: 2 })).toBe("150 of 200 addresses enriched, dataset stale, 2 errors")
    expect(t("tenancy_enricher", { selected: 1, enriched: 1 })).toBe("1 of 1 address enriched")
    expect(t("tenancy_tls", { selected: 25, allowed: 20, dissented: 5, abstained: 10, unreachable: 4, errors: 1 })).toBe("20 of 25 allowed by the gate: 5 managed endpoints, 10 unclassified, 4 no handshake, 1 error")
  })
})

describe("formatDuration", () => {
  it("handles boundaries", () => {
    expect(formatDuration(59)).toBe("59s")
    expect(formatDuration(42.9)).toBe("42s")
    expect(formatDuration(60)).toBe("1m 0s")
    expect(formatDuration(192)).toBe("3m 12s")
    expect(formatDuration(3599)).toBe("59m 59s")
    expect(formatDuration(3600)).toBe("1h 00m")
    expect(formatDuration(3720)).toBe("1h 02m")
  })
})

describe("runCountsText", () => {
  it("capture_sweep", () => {
    expect(runCountsText(run("capture_sweep", { candidates: 10, queued: 8 }))).toBe("8 queued for capture out of 10 due")
    expect(runCountsText(run("capture_sweep", { candidates: 10, queued: 6, skipped: 3, errors: 1 })))
      .toBe("6 queued for capture out of 10 due, 3 skipped, 1 error")
    expect(runCountsText(run("capture_sweep", { errors: 2 }))).toBe("0 queued for capture out of 0 due, 2 errors")
  })
  it("rediscovery_tick sums both skip counts", () => {
    expect(runCountsText(run("rediscovery_tick", { due: 9, ok: 6, failed: 1 }))).toBe("6 refreshed, 1 failed, out of 9 due")
    expect(runCountsText(run("rediscovery_tick", { due: 9, ok: 5, failed: 1, skipped: 1, skipped_busy: 2, errors: 1 })))
      .toBe("5 refreshed, 1 failed, out of 9 due, 3 skipped, 1 error")
    expect(runCountsText(run("rediscovery_tick", { due: 0 }))).toBe("0 refreshed, 0 failed, out of 0 due")
  })
  it("unknown job", () => {
    expect(runCountsText(run("other", { x: 1 }, { items_selected: 4 }))).toBe("4 items picked up")
  })
  it("a run that recorded no counts (a failed run) gets no line, not zeros", () => {
    expect(runCountsText(run("rediscovery_tick", {}))).toBeNull()
    expect(runCountsText(run("capture_sweep", {}))).toBeNull()
    expect(runCountsText(run("other", {}, { items_selected: 0 }))).toBeNull()
  })
})

describe("formatSlotTime", () => {
  const now = new Date(2026, 10, 8, 15, 0)
  it("same day shows HH:MM only", () => expect(formatSlotTime(iso(2026, 10, 8, 9, 5), now)).toBe("09:05"))
  it("other day prefixes the date", () => expect(formatSlotTime(iso(2026, 10, 7, 14, 40), now)).toBe("Nov 7 14:40"))
})

describe("missedSlotsText", () => {
  const slots = [0, 1, 2, 3, 4].map((h) => iso(2026, 10, 7, h, 40))
  it("no recorded history", () => {
    expect(missedSlotsText(status({ recorded_since: null }), 24)).toEqual({ text: "No runs recorded yet.", overflow: [] })
  })
  it("nothing missing", () => {
    expect(missedSlotsText(status(), 24)).toEqual({ text: "Every expected start in the last 24 hours has a recorded run.", overflow: [] })
  })
  it("lists up to three and overflows the rest, in record wording", () => {
    const r = missedSlotsText(status({ missed_slots: slots }), 24)
    expect(r.text).toContain("No run recorded")
    expect(r.text).not.toMatch(/did not run|missed|failed to run|skipped/i)
    expect(r.text.split(", ")).toHaveLength(3)
    expect(r.overflow).toHaveLength(2)
    const all = slots.map((s) => formatSlotTime(s))
    expect(r.text).toBe(`No run recorded at ${all.slice(0, 3).join(", ")}`)
    expect(r.overflow).toEqual(all.slice(3))
  })
})

describe("finishReasonText cpe_index_refresher and source_refused", () => {
  const refused = "Stopped because a data source refused a request. What it didn't reach is still due and is tried again on the next run. The details are in the logs."
  const daily = "Stopped at its time limit. The days it didn't reach are still due and it continues on the next run."
  const hourly = "Stopped at its time limit. Anything it didn't reach is still due and runs next hour."
  it("source_refused has one sentence with or without a job", () => {
    expect(finishReasonText("source_refused")).toBe(refused)
    expect(finishReasonText("source_refused", "cpe_index_refresher")).toBe(refused)
    expect(isProblem("source_refused")).toBe(true)
  })
  it("time_limit is job-aware", () => {
    expect(finishReasonText("time_limit", "cpe_index_refresher")).toBe(daily)
    expect(finishReasonText("time_limit", "cpe_index_refresher")).not.toContain("next hour")
    expect(finishReasonText("time_limit", "capture_sweep")).toBe(hourly)
    expect(finishReasonText("time_limit")).toBe(hourly)
  })
  it("not_configured names the vulnerability data connector", () => {
    expect(finishReasonText("not_configured", "cpe_index_refresher")).toBe("Skipped: the vulnerability data connector isn't set up yet.")
  })
})
