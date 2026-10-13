import { describe, expect, it } from "vitest"
import { AI_CONFIGURE_HINT, followupOf, seedProgress, type SeedProgressInput } from "@/lib/companySeed"

function input(over: Partial<SeedProgressInput> = {}): SeedProgressInput {
  return {
    ingest: "queued",
    ingestStatus: undefined,
    ingestError: null,
    followup: undefined,
    readStatus: undefined,
    readError: null,
    ...over,
  }
}

describe("seedProgress", () => {
  it("queued ingest reads as in progress and keeps polling", () => {
    const p = seedProgress(input({ ingestStatus: "queued" }))
    expect(p.phase).toBe("ingest")
    expect(p.ingestLabel).toBe("Reading SEC filings…")
    expect(p.polling).toBe(true)
  })

  it("running ingest reads as in progress and keeps polling", () => {
    const p = seedProgress(input({ ingestStatus: "running" }))
    expect(p.phase).toBe("ingest")
    expect(p.polling).toBe(true)
  })

  it("no run fetched yet is still in progress", () => {
    expect(seedProgress(input()).phase).toBe("ingest")
  })

  it("succeeded with the read queued shows the AI step and keeps polling", () => {
    const p = seedProgress(input({ ingestStatus: "succeeded", followup: { status: "queued", run_id: "r1" }, readStatus: "running" }))
    expect(p.phase).toBe("read")
    expect(p.ingestLabel).toBe("Filings read")
    expect(p.readLabel).toBe("Looking for acquisitions with AI…")
    expect(p.polling).toBe(true)
  })

  it("read run finished stops polling", () => {
    const ok = seedProgress(input({ ingestStatus: "succeeded", followup: { status: "queued", run_id: "r1" }, readStatus: "succeeded" }))
    expect(ok.phase).toBe("done")
    expect(ok.polling).toBe(false)
    const bad = seedProgress(input({ ingestStatus: "succeeded", followup: { status: "queued", run_id: "r1" }, readStatus: "failed", readError: "boom" }))
    expect(bad.readLabel).toContain("boom")
    expect(bad.polling).toBe(false)
  })

  it("skipped for an AI reason shows the configure hint", () => {
    const p = seedProgress(input({ ingestStatus: "succeeded", followup: { status: "skipped", reason: "no AI models configured" } }))
    expect(p.readLabel).toContain("no AI models configured")
    expect(p.hint).toBe(AI_CONFIGURE_HINT)
    expect(p.polling).toBe(false)
  })

  it("skipped because OpenRouter is not set up shows the hint", () => {
    const p = seedProgress(input({ ingestStatus: "succeeded", followup: { status: "skipped", reason: "OpenRouter is not configured" } }))
    expect(p.hint).toBe(AI_CONFIGURE_HINT)
  })

  it("skipped for a non-AI reason does not show the hint", () => {
    const p = seedProgress(input({ ingestStatus: "succeeded", followup: { status: "skipped", reason: "no filing text stored" } }))
    expect(p.readLabel).toContain("no filing text stored")
    expect(p.hint).toBeNull()
  })

  it("failed ingest shows the error and stops polling", () => {
    const p = seedProgress(input({ ingestStatus: "failed", ingestError: "SEC said no" }))
    expect(p.phase).toBe("failed")
    expect(p.ingestLabel).toBe("Couldn't read filings: SEC said no")
    expect(p.polling).toBe(false)
  })

  it("already_running says so and does not poll", () => {
    const p = seedProgress(input({ ingest: "already_running" }))
    expect(p.phase).toBe("already_running")
    expect(p.ingestLabel).toBe("An import of this company is already running.")
    expect(p.polling).toBe(false)
  })
})

describe("followupOf", () => {
  it("parses queued and skipped, ignores anything else", () => {
    expect(followupOf({ acquisition_read: { status: "queued", run_id: "r1" } } as never)).toEqual({ status: "queued", run_id: "r1" })
    expect(followupOf({ acquisition_read: { status: "skipped", reason: "x" } } as never)).toEqual({ status: "skipped", reason: "x" })
    expect(followupOf({ acquisition_read: { status: "weird" } } as never)).toBeUndefined()
    expect(followupOf(null)).toBeUndefined()
  })
})
