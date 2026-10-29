import { describe, expect, it } from "vitest"
import type { AcquisitionRow } from "@/lib/organizations"
import {
  assignLanes, canPan, canZoomIn, canZoomOut, clamp, currentWindow, dotKind, dotTitle, extent, filterByDeal,
  centreOn, jumpTarget, offEdges, pan, placementMs, xFraction, yearTicks, zoomIn, zoomOut,
} from "@/lib/acquisitionTimeline"

const DAY = 86_400_000
const YEAR = 365.25 * DAY
const U = Date.UTC

const row = (over: Partial<AcquisitionRow> = {}): AcquisitionRow => ({
  entity_id: "e1", name: "Fabrikam Labs", organic: false, closed: "2021-03-12", closed_precision: "day",
  postures: [], domains_claimed: 0, domains_to_review: 0, asns_claimed: 0, cidrs_claimed: 0, ip_to_review: 0,
  assets: 0, open_findings: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, worst_severity: null,
  kev: 0, risk_score_sum: 0, risk_share: null, ...over,
})

describe("currentWindow", () => {
  const ext = { start: U(2010, 0, 1), end: U(2022, 0, 1) }
  const win = { start: U(2015, 0, 1), end: U(2017, 0, 1) }
  it("is the extent with no zoom/pan choice, and null with no extent", () => {
    expect(currentWindow(null, ext)).toEqual(ext)
    expect(currentWindow({ ext, win }, null)).toBeNull()
  })
  it("keeps the choice under the same extent and drops it when the extent changes", () => {
    expect(currentWindow({ ext, win }, { ...ext })).toEqual(win)
    const grown = { start: ext.start, end: U(2024, 0, 1) }
    expect(currentWindow({ ext, win }, grown)).toEqual(grown)
  })
})

describe("placementMs", () => {
  it("places a day at UTC midnight", () => {
    expect(placementMs("2021-03-12", "day")).toBe(U(2021, 2, 12))
    expect(placementMs("2021-03-12", "unknown")).toBe(U(2021, 2, 12))
    expect(placementMs("2021-03-12", null)).toBe(U(2021, 2, 12))
  })
  it("places a month at the midpoint of the month", () => {
    expect(placementMs("2021-02-01", "month")).toBe((U(2021, 1, 1) + U(2021, 2, 1)) / 2)
    // leap-year February is 29 days: midpoint is 14.5 days in
    expect(placementMs("2024-02-01", "month")).toBe(U(2024, 1, 1) + 14.5 * DAY)
  })
  it("places a year at the midpoint of the year", () => {
    expect(placementMs("2019-01-01", "year")).toBe((U(2019, 0, 1) + U(2020, 0, 1)) / 2)
  })
  it("returns null for null or unparseable", () => {
    expect(placementMs(null, "day")).toBeNull()
    expect(placementMs("garbage", "day")).toBeNull()
    expect(placementMs("2021-13-01", "month")).toBeNull()
  })
  it("rejects a day that does not exist instead of rolling it over", () => {
    expect(placementMs("2021-02-28", "day")).toBe(U(2021, 1, 28))
    expect(placementMs("2021-02-31", "day")).toBeNull()
    expect(placementMs("2024-02-29", "day")).toBe(U(2024, 1, 29))
    expect(placementMs("2023-02-29", "day")).toBeNull()
  })
})

describe("extent", () => {
  it("is null with no points", () => expect(extent([])).toBeNull())
  it("pads 6 months and widens a single point to 1 year", () => {
    const p = U(2020, 5, 1)
    const e = extent([p])!
    expect(e.end - e.start).toBeCloseTo(YEAR, 0)
    expect((e.start + e.end) / 2).toBeCloseTo(p, 0)
  })
  it("pads wide spreads by 182.5 days each side", () => {
    const a = U(2010, 0, 1), b = U(2020, 0, 1)
    expect(extent([b, a])).toEqual({ start: a - 182.5 * DAY, end: b + 182.5 * DAY })
  })
})

describe("zoom / clamp / pan", () => {
  const ext = extent([U(2000, 0, 1), U(2030, 0, 1)])!
  it("zooms in through the spans and is a no-op at 1y", () => {
    let w = ext
    const spans: number[] = []
    for (let i = 0; i < 6; i++) { w = zoomIn(w, ext); spans.push(Math.round((w.end - w.start) / YEAR)) }
    expect(spans).toEqual([20, 10, 5, 2, 1, 1])
    expect(canZoomIn(w)).toBe(false)
    expect(zoomIn(w, ext)).toBe(w)
  })
  it("zooms out up to ext", () => {
    let w = zoomIn(zoomIn(zoomIn(zoomIn(zoomIn(ext, ext), ext), ext), ext), ext) // 1y
    const spans: number[] = []
    for (let i = 0; i < 6; i++) { w = zoomOut(w, ext); spans.push(Math.round((w.end - w.start) / YEAR)) }
    expect(spans.slice(0, 4)).toEqual([2, 5, 10, 20])
    expect(w).toEqual(ext)
    expect(canZoomOut(w, ext)).toBe(false)
    expect(canZoomOut({ start: ext.start, end: ext.start + 5 * YEAR }, ext)).toBe(true)
  })
  it("zoomOut returns ext when the next span >= ext span", () => {
    const small = extent([U(2020, 0, 1), U(2023, 0, 1)])! // ~4y
    const w = { start: small.start, end: small.start + 2 * YEAR }
    expect(zoomOut(w, small)).toEqual(small)
  })
  it("clamps by shifting at both edges and returns ext if wider", () => {
    const w = { start: ext.start - 3 * YEAR, end: ext.start + 2 * YEAR }
    expect(clamp(w, ext)).toEqual({ start: ext.start, end: ext.start + 5 * YEAR })
    const w2 = { start: ext.end - 2 * YEAR, end: ext.end + 3 * YEAR }
    expect(clamp(w2, ext)).toEqual({ start: ext.end - 5 * YEAR, end: ext.end })
    expect(clamp({ start: ext.start - YEAR, end: ext.end + YEAR }, ext)).toBe(ext)
  })
  it("pans by half a span, clamps, and canPan is false at edges", () => {
    const w = { start: ext.start, end: ext.start + 4 * YEAR }
    expect(canPan(w, ext, -1)).toBe(false)
    expect(canPan(w, ext, 1)).toBe(true)
    expect(pan(w, ext, -1)).toEqual(w)
    expect(pan(w, ext, 1)).toEqual({ start: ext.start + 2 * YEAR, end: ext.start + 6 * YEAR })
    const last = { start: ext.end - 4 * YEAR, end: ext.end }
    expect(canPan(last, ext, 1)).toBe(false)
    expect(pan(last, ext, 1)).toEqual(last)
  })
})

describe("xFraction / offEdges / yearTicks", () => {
  const win = { start: 1000, end: 2000 }
  it("computes fractions", () => expect(xFraction(1250, win)).toBe(0.25))
  it("counts off-window points", () => {
    expect(offEdges([500, 999, 1000, 1500, 2000, 2001], win)).toEqual({ before: 2, after: 1 })
  })
  it("steps ticks by span", () => {
    const mk = (years: number) => yearTicks({ start: U(2000, 0, 1) - 1, end: U(2000, 0, 1) - 1 + years * YEAR })
    const t8 = mk(8).map(t => t.year)
    expect(t8.length).toBeGreaterThan(1)
    expect(t8[1] - t8[0]).toBe(1)
    const t15 = mk(15).map(t => t.year)
    expect(t15.every(y => y % 2 === 0)).toBe(true)
    expect(t15[1] - t15[0]).toBe(2)
    const t40 = mk(40).map(t => t.year)
    expect(t40.every(y => y % 5 === 0)).toBe(true)
    expect(t40[1] - t40[0]).toBe(5)
    expect(mk(8).every(t => t.x >= 0 && t.x <= 1)).toBe(true)
  })
})

describe("jumpTarget / centreOn", () => {
  const ext = { start: U(2000, 0, 1), end: U(2020, 0, 1) }
  const win = { start: U(2009, 0, 1), end: U(2010, 0, 1) }
  const pts = [U(2001, 5, 1), U(2008, 5, 1), U(2009, 5, 1), U(2012, 5, 1), U(2019, 5, 1), U(2008, 5, 1)]
  it("picks the nearest deal strictly off each edge, skipping visible ones; ties keep the first", () => {
    expect(jumpTarget(pts, win, -1)).toBe(1)
    expect(jumpTarget(pts, win, 1)).toBe(3)
  })
  it("treats a deal on the window edge as visible, matching offEdges", () => {
    const edge = [win.start, win.end, U(2001, 0, 1)]
    expect(jumpTarget(edge, win, -1)).toBe(2)
    expect(jumpTarget(edge, win, 1)).toBeNull()
    expect(offEdges(edge, win)).toEqual({ before: 1, after: 0 })
  })
  it("is null with nothing off that edge", () => {
    expect(jumpTarget([U(2009, 5, 1)], win, -1)).toBeNull()
    expect(jumpTarget([], win, 1)).toBeNull()
  })
  it("recentres at the same zoom, and clamps at the ends while still containing the deal", () => {
    const mid = U(2012, 5, 1), span = win.end - win.start
    expect(centreOn(mid, win, ext)).toEqual({ start: mid - span / 2, end: mid + span / 2 })
    expect(centreOn(U(2019, 11, 1), win, ext)).toEqual({ start: ext.end - span, end: ext.end })
    expect(centreOn(U(2000, 1, 1), win, ext)).toEqual({ start: ext.start, end: ext.start + span })
  })
  it("walks deal by deal in both directions: each jump shows its target, the next goes beyond it", () => {
    for (const [dir, want] of [[1, [3, 4]], [-1, [1, 0]]] as const) {
      let w = win
      const seen: number[] = []
      for (let i = jumpTarget(pts, w, dir); i !== null; i = jumpTarget(pts, w, dir)) {
        w = centreOn(pts[i], w, ext)
        expect(pts[i]).toBeGreaterThanOrEqual(w.start)
        expect(pts[i]).toBeLessThanOrEqual(w.end)
        seen.push(i)
      }
      expect(seen).toEqual(want)
    }
  })
})

describe("assignLanes", () => {
  it("stacks near-equal xs and returns far ones to lane 0, in input order", () => {
    expect(assignLanes([0.5, 0.1, 0.505])).toEqual([0, 0, 1])
    expect(assignLanes([0.5, 0.505, 0.9])).toEqual([0, 1, 0])
    expect(assignLanes([])).toEqual([])
  })
})

describe("dotKind / dotTitle", () => {
  it("filled when worst_severity is set", () => {
    const r = row({ worst_severity: "high" })
    expect(dotKind(r)).toBe("filled")
    expect(dotTitle(r)).toBe("Fabrikam Labs · 12 Mar 2021 · worst open: high")
  })
  it("none when no severity and no scope", () => {
    expect(dotKind(row())).toBe("none")
    expect(dotTitle(row())).toContain("no claimed scope")
  })
  it("clean when any one scope field is set (one field at a time)", () => {
    for (const f of ["domains_claimed", "asns_claimed", "cidrs_claimed", "assets"] as const) {
      const r = row({ [f]: 1 })
      expect(dotKind(r)).toBe("clean")
      expect(dotTitle(r)).toContain("no open findings")
    }
  })
  it("says date unknown for undated", () => {
    expect(dotTitle(row({ closed: null, closed_precision: null }))).toContain("date unknown")
  })
})

describe("filterByDeal", () => {
  const organic = row({ entity_id: null, organic: true, name: "Example Holdings A" })
  const a = row({ entity_id: "a" })
  const b = row({ entity_id: "b", name: "Example Holdings B" })
  const rows = [a, b, organic]
  it("empty deal returns everything", () => {
    expect(filterByDeal(rows, "")).toEqual({ rows, match: null, stale: false })
  })
  it("match shows only that deal", () => {
    expect(filterByDeal(rows, "b")).toEqual({ rows: [b], match: b, stale: false })
  })
  it("stale returns the full table", () => {
    expect(filterByDeal(rows, "zzz")).toEqual({ rows, match: null, stale: true })
  })
})
