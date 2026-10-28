import { beforeEach, describe, expect, it, vi } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"

const perms = vi.hoisted(() => ({ current: [] as string[] }))
vi.mock("@/lib/permissions", () => ({ useCan: () => (p: string) => perms.current.includes(p) }))

import { api } from "@/lib/api"
import type { PageCapture } from "@/lib/organizations"
import {
  CandidateCaptures, CaptureList, captureImageState, captureSource, loadCaptureImage,
} from "@/components/CandidateCaptureParts"

const capture = (over: Partial<PageCapture> = {}): PageCapture => ({
  id: "cap1", status: "done", failure_reason: null, error: null,
  requested_at: "2026-10-28T10:00:00+00:00", finished_at: "2026-10-28T10:00:09+00:00", requested_by_id: null,
  domain: "www.fabrikam.com", requested_url: "https://www.fabrikam.com/", final_url: "https://www.fabrikam.com/",
  http_status: 200, redirect_chain: [], title: "Fabrikam Home", user_agent: null, user_agent_mode: "stock",
  image_max_bytes: 1048576, cert: null, cert_san_dns: null, cert_sha256: null, pinned_ip: "192.0.2.10",
  proxy_log_truncated: false, image_bytes: null, image_sha256: null, image_quality: null,
  image_omitted_reason: null, image_pruned_at: null, has_image: false, request_count: 3, ...over,
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
  it("source is live", () => { expect(captureSource(capture())).toBe("live") })
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
    expect(out).toContain("navigation_timeout")
    expect(out).not.toContain("destructive")
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
  })
  it("hides Re-capture without DECIDE", () => {
    perms.current = ["entities.read"]
    const out = render("open")
    expect(out).toContain("Fabrikam Home")
    expect(out).not.toContain("Re-capture")
  })
  it("hides Re-capture when the candidate is not open", () => {
    perms.current = ["entities.decide_candidate"]
    expect(render("claimed")).not.toContain("Re-capture")
  })
})
