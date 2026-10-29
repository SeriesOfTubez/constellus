import { beforeEach, describe, expect, it, vi } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"

const perms = vi.hoisted(() => ({ current: [] as string[] }))
vi.mock("@/lib/permissions", () => ({ useCan: () => (p: string) => perms.current.includes(p) }))

import { api } from "@/lib/api"
import type { CaptureSkip, PageCapture } from "@/lib/organizations"
import {
  CandidateCaptures, CaptureList, CaptureSkipNotice, latestRelevantSkip, archiveBadge, captureFailureText, captureImageState, captureSource, loadCaptureImage,
} from "@/components/CandidateCaptureParts"
import { formatExactTime } from "@/lib/time"

const capture = (over: Partial<PageCapture> = {}): PageCapture => ({
  id: "cap1", status: "done", failure_reason: null, error: null,
  requested_at: "2026-10-28T10:00:00+00:00", finished_at: "2026-10-28T10:00:09+00:00", requested_by_id: null,
  domain: "www.fabrikam.com", requested_url: "https://www.fabrikam.com/", final_url: "https://www.fabrikam.com/",
  http_status: 200, redirect_chain: [], title: "Fabrikam Home", user_agent: null, user_agent_mode: "stock",
  image_max_bytes: 1048576, cert: null, cert_san_dns: null, cert_sha256: null, pinned_ip: "192.0.2.10",
  proxy_log_truncated: false, image_bytes: null, image_sha256: null, image_quality: null,
  image_omitted_reason: null, image_pruned_at: null, has_image: false, request_count: 3,
  source: "live", archive_snapshot_at: null, archive_host: null, archive_freshness_days: null, ...over,
})
const html = (n: React.ReactNode) => renderToStaticMarkup(<MemoryRouter>{n}</MemoryRouter>)
const list = (cs: PageCapture[]) => html(<CaptureList captures={cs} candidateId="c1" />)

describe("captureImageState", () => {
  it("maps the four states", () => {
    expect(captureImageState(capture({ has_image: true }))).toBe("available")
    expect(captureImageState(capture({ image_pruned_at: "2026-10-28T11:00:00+00:00" }))).toBe("pruned")
    expect(captureImageState(capture({ image_omitted_reason: "too_large" }))).toBe("omitted")
    expect(captureImageState(capture())).toBe("none")
  })
  it("has_image wins over pruned/omitted markers", () => {
    expect(captureImageState(capture({ has_image: true, image_pruned_at: "2026-10-28T11:00:00+00:00", image_omitted_reason: "x" }))).toBe("available")
  })
  it("source is live or archive", () => {
    expect(captureSource(capture())).toBe("live")
    expect(captureSource(capture({ source: "archive" }))).toBe("archive")
  })
})

describe("CaptureList", () => {
  it("empty list says so", () => {
    expect(list([])).toContain("No captures yet.")
  })
  it("pruned and omitted stay distinct, in both directions", () => {
    const pruned = list([capture({ image_pruned_at: "2026-10-28T11:00:00+00:00" })])
    expect(pruned).toContain("Screenshot file pruned")
    expect(pruned).toContain("capture details kept")
    expect(pruned).not.toContain("Screenshot not stored")
    const omitted = list([capture({ image_omitted_reason: "too_large" })])
    expect(omitted).toContain("Screenshot not stored: too_large")
    expect(omitted).not.toContain("Screenshot file pruned")
  })
  it("queued row shows no screenshot line at all", () => {
    const out = list([capture({ status: "queued", title: null, final_url: null, http_status: null })])
    expect(out).toContain("Queued")
    expect(out).not.toContain("Screenshot")
    expect(out).not.toContain("No screenshot")
  })
  it("done row without an image says No screenshot", () => {
    expect(list([capture()])).toContain("No screenshot")
  })
  it("an available image is on demand: summary rendered, no <img mounted", () => {
    const out = list([capture({ has_image: true, image_bytes: 20480 })])
    expect(out).toContain("Screenshot (20 KiB)")
    expect(out).not.toContain("<img")
    // Under SSR a mounted CaptureImage renders its loading Skeleton, not <img>:
    // no skeleton proves the closed <details> mounted nothing (so fetched nothing).
    expect(out).not.toContain("animate-pulse")
  })
  it("final_url arrow only when it differs", () => {
    expect(list([capture()])).not.toContain("→")
    expect(list([capture({ final_url: "https://www.fabrikam.com/en/" })])).toContain("→")
  })
  it("renders redirect hops defensively and the Live badge", () => {
    const out = list([capture({ redirect_chain: [{ url: "http://www.fabrikam.com/", status: 301 }, "odd", null] })])
    expect(out).toContain("301 http://www.fabrikam.com/")
    expect(out).toContain("3 redirect hops")
    expect(out).toContain("Live")
  })
  it("proxy log truncation is flagged", () => {
    expect(list([capture({ proxy_log_truncated: true })])).toContain("(log truncated)")
    expect(list([capture()])).not.toContain("(log truncated)")
  })
  it("failed row shows the reason and no destructive styling", () => {
    const out = list([capture({ status: "failed", failure_reason: "navigation_timeout", error: "boom", title: null })])
    expect(out).toContain("Failed")
    expect(out).toContain("An error was encountered while retrieving the page.")
    expect(out).not.toContain("navigation_timeout")
    expect(out).not.toContain("boom")
    expect(out).not.toContain("destructive")
  })
  it("mixed live and archive rows", () => {
    const out = list([
      capture({ id: "a" }),
      capture({ id: "b", source: "archive", archive_snapshot_at: "2026-10-27T10:00:00+00:00", archive_host: "web.archive.org" }),
      capture({ id: "c", source: "archive", status: "failed", failure_reason: "archive_snapshot_stale", error: "SECRET-RAW-ERR",
        archive_snapshot_at: "2026-09-01T10:00:00+00:00", archive_host: "web.archive.org", archive_freshness_days: 14, title: null }),
    ])
    expect(out).toContain(">Live<")
    expect(out).toContain("Archived ·")
    expect(out).toContain("older than the configured window of 14 days")
    expect(out).not.toContain("SECRET-RAW-ERR")
  })
})

const arch = (over: Partial<PageCapture> = {}) => capture({
  source: "archive", archive_host: "web.archive.org", archive_snapshot_at: "2026-10-27T10:00:00+00:00",
  archive_freshness_days: 7, error: "RAW-ERR-TEXT", ...over,
})
const exact = formatExactTime("2026-10-27T10:00:00+00:00")

describe("archiveBadge", () => {
  it("done shows relative time in the label and exact time + host in the title", () => {
    const b = archiveBadge(arch())
    expect(b.label).toContain("Archived ·")
    expect(b.title).toBe(`Snapshot ${exact} from web.archive.org`)
  })
  it("queued and unverified-failed never expose the time", () => {
    for (const c of [
      arch({ status: "queued" }),
      arch({ status: "failed", failure_reason: "archive_snapshot_unverified" }),
    ]) {
      const b = archiveBadge(c)
      expect(b.label).toBe("Archived")
      expect(b.title ?? "").not.toContain(exact)
      expect(b.title).toBe("From web.archive.org")
    }
  })
})

describe("captureFailureText", () => {
  const failed = (reason: string | null, over: Partial<PageCapture> = {}) =>
    arch({ status: "failed", failure_reason: reason, ...over })
  const generic = "An error was encountered while retrieving the page. Check the logs for details."
  const all = [
    failed("archive_snapshot_stale", { archive_snapshot_at: "2026-09-01T10:00:00+00:00" }),
    failed("archive_snapshot_stale", { archive_snapshot_at: "2026-09-01T10:00:00+00:00", archive_freshness_days: null }),
    failed("archive_snapshot_stale", { archive_snapshot_at: "2026-10-29T10:00:00+00:00" }),
    failed("archive_snapshot_unverified"),
    failed("capture_error"), failed("timeout"), failed("something_new"), failed(null),
  ]
  it("stale older, with and without the window", () => {
    const old = formatExactTime("2026-09-01T10:00:00+00:00")
    expect(captureFailureText(all[0])).toBe(`The retrieved snapshot (${old}) is older than the configured window of 7 days, so it was not used.`)
    expect(captureFailureText(all[1])).toBe(`The retrieved snapshot (${old}) is older than the configured window, so it was not used.`)
  })
  it("stale future", () => {
    expect(captureFailureText(all[2])).toBe(`The retrieved snapshot (${formatExactTime("2026-10-29T10:00:00+00:00")}) is dated after the capture was requested, so it was not used.`)
  })
  it("unverified", () => {
    expect(captureFailureText(all[3])).toBe("The snapshot service was not able to determine the snapshot's date, so it was not used.")
  })
  it("everything else is the generic sentence", () => {
    for (const c of all.slice(4)) expect(captureFailureText(c)).toBe(generic)
  })
  it("never includes the raw error", () => {
    for (const c of all) expect(captureFailureText(c)).not.toContain("RAW-ERR-TEXT")
  })
})

describe("loadCaptureImage", () => {
  it("re-wraps the bytes as image/webp whatever the response said", async () => {
    const getBlob = vi.spyOn(api, "getBlob").mockResolvedValue(new Blob(["<html>"], { type: "text/html" }))
    let passed: Blob | null = null
    const create = vi.fn((b: Blob) => { passed = b; return "blob:fake" })
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: create }))
    const url = await loadCaptureImage("c1", "cap1")
    expect(getBlob).toHaveBeenCalledTimes(1)
    expect(getBlob).toHaveBeenCalledWith("/organizations/candidates/c1/captures/cap1/image")
    expect(url).toBe("blob:fake")
    expect(passed!.type).toBe("image/webp")
    expect(await passed!.text()).toBe("<html>")
    getBlob.mockRestore()
  })
})

describe("CandidateCaptures", () => {
  beforeEach(() => { perms.current = [] })
  const render = (status: string) => {
    const qc = new QueryClient()
    qc.setQueryData(["candidate-captures", "c1"], [capture()])
    return html(<QueryClientProvider client={qc}><CandidateCaptures candidateId="c1" candidateStatus={status} /></QueryClientProvider>)
  }
  it("shows the heading, the capture and Re-capture with DECIDE on an open candidate", () => {
    perms.current = ["entities.decide_candidate"]
    const out = render("open")
    expect(out).toContain("Page capture")
    expect(out).toContain("Fabrikam Home")
    expect(out).toContain("Re-capture")
    expect(out).toContain("ignores the revisit window")
    expect(out).toContain("recent copy from the web archive")
  })
  it("hides Re-capture without DECIDE", () => {
    perms.current = ["entities.read"]
    const out = render("open")
    expect(out).toContain("Fabrikam Home")
    expect(out).not.toContain("Re-capture")
    expect(out).not.toContain("web archive")
  })
  it("hides Re-capture when the candidate is not open", () => {
    perms.current = ["entities.decide_candidate"]
    expect(render("claimed")).not.toContain("Re-capture")
  })
})

const skip = (over: Partial<CaptureSkip> = {}): CaptureSkip => ({
  id: "s1", reason: "archive:lookup_unavailable",
  message: "The snapshot service could not be reached, so nothing was captured.",
  skipped_at: "2026-10-29T04:00:00+00:00", ...over,
})

describe("latestRelevantSkip", () => {
  it("no skips gives null", () => {
    expect(latestRelevantSkip([], [capture()])).toBeNull()
    expect(latestRelevantSkip([], [])).toBeNull()
  })
  it("skip newer than the latest capture is returned", () => {
    const s = skip()
    expect(latestRelevantSkip([s], [capture()])).toBe(s)
  })
  it("skip older than the latest capture is history", () => {
    expect(latestRelevantSkip([skip({ skipped_at: "2026-10-27T04:00:00+00:00" })], [capture()])).toBeNull()
  })
  it("no captures and one skip gives the skip", () => {
    const s = skip()
    expect(latestRelevantSkip([s], [])).toBe(s)
  })
  it("picks the newest skip regardless of order", () => {
    const old = skip({ id: "a", skipped_at: "2026-10-29T01:00:00+00:00" })
    const mid = skip({ id: "b", skipped_at: "2026-10-30T01:00:00+00:00" })
    const nw = skip({ id: "c", skipped_at: "2026-10-31T01:00:00+00:00" })
    expect(latestRelevantSkip([mid, nw, old], [capture()])?.id).toBe("c")
    expect(latestRelevantSkip([nw, old, mid], [capture()])?.id).toBe("c")
  })
  it("compares against the newest capture, not the first", () => {
    const caps = [capture({ id: "x", requested_at: "2026-10-20T10:00:00+00:00" }), capture({ id: "y", requested_at: "2026-11-01T10:00:00+00:00" })]
    expect(latestRelevantSkip([skip()], caps)).toBeNull()
  })
})

describe("CaptureSkipNotice", () => {
  it("shows the message and never the raw reason", () => {
    const out = html(<CaptureSkipNotice skip={skip()} />)
    expect(out).toContain("Automatic capture skipped")
    expect(out).toContain("The snapshot service could not be reached")
    expect(out).not.toContain("archive:lookup_unavailable")
  })
})
