import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import {
  HourlyStrip, barPath, bucketEnd, busiestRun, countText, hourSentence, hourText, middleLabel,
  stripLabel, stripSummary,
} from "./HourlyStrip"
import type { HourBucket } from "./HourlyStrip"
import { OVERNIGHT, hourlyBuckets } from "./stripFixture"

const NOUN: [string, string] = ["change", "changes"]

const render = (hours: HourBucket[], width = 480, note?: string) =>
  renderToStaticMarkup(<HourlyStrip hours={hours} noun={NOUN} width={width} note={note} timeZone="UTC" />)

describe("HourlyStrip helpers", () => {
  it("formats hours in the requested zone", () => {
    expect(hourText("2026-11-12T02:00:00Z", "UTC")).toBe("02:00")
    expect(hourText("2026-11-12T02:00:00Z", "Asia/Kolkata")).toBe("07:30")
  })

  it("moves a bucket start forward one hour", () => {
    expect(bucketEnd("2026-11-12T23:00:00Z")).toBe("2026-11-13T00:00:00.000Z")
  })

  it("finds the busiest run", () => {
    expect(busiestRun([])).toBeNull()
    expect(busiestRun([0, 0, 0])).toBeNull()
    expect(busiestRun([0, 1, 10, 4, 0])).toEqual({ from: 2, to: 2 })
    expect(busiestRun([5, 0, 5, 0])).toEqual({ from: 0, to: 0 })
    expect(busiestRun([0, 5, 10, 6, 4, 0])).toEqual({ from: 1, to: 3 })
    expect(busiestRun([10, 6, 1, 0])).toEqual({ from: 0, to: 1 })
    expect(busiestRun([0, 1, 6, 10])).toEqual({ from: 2, to: 3 })
    expect(busiestRun(OVERNIGHT.map((h) => h.count))).toEqual({ from: 11, to: 12 })
  })

  it("pluralises counts", () => {
    expect(countText(1, NOUN)).toBe("1 change")
    expect(countText(41, NOUN)).toBe("41 changes")
    expect(countText(0, NOUN)).toBe("0 changes")
  })

  it("words an hour sentence", () => {
    expect(hourSentence(OVERNIGHT[11], NOUN, "UTC")).toBe("02:00 to 03:00: 10 changes.")
    expect(hourSentence(OVERNIGHT[0], NOUN, "UTC")).toBe("15:00 to 16:00: 1 change.")
  })

  it("words the summary", () => {
    expect(stripSummary(OVERNIGHT, NOUN, "UTC")).toBe("41 changes in 18 hours, busiest between 02:00 and 04:00.")
    expect(stripSummary(hourlyBuckets("2026-11-12T00:00:00Z", [0, 0, 0]), NOUN, "UTC")).toBe("No changes in 3 hours.")
    expect(stripSummary(hourlyBuckets("2026-11-12T00:00:00Z", [0]), NOUN, "UTC")).toBe("No changes in 1 hour.")
    expect(stripSummary(hourlyBuckets("2026-11-12T00:00:00Z", [1]), NOUN, "UTC")).toBe("1 change in 1 hour, busiest between 00:00 and 01:00.")
  })

  it("words the chart label", () => {
    expect(stripLabel(OVERNIGHT, NOUN, "UTC")).toBe(
      "Bar chart: changes per hour. 41 changes in 18 hours, busiest between 02:00 and 04:00.",
    )
  })

  it("draws a bar with rounded top corners and clamps the radius", () => {
    expect(barPath(10, 20, 8, 28, 2)).toBe("M10 48V22Q10 20 12 20H16Q18 20 18 22V48Z")
    expect(barPath(10, 46, 8, 2, 2)).toBe("M10 48V48Q10 46 12 46H16Q18 46 18 48V48Z")
    expect(barPath(0, 10, 1, 4, 2)).toBe("M0 14V10.5Q0 10 0.5 10H0.5Q1 10 1 10.5V14Z")
  })

  it("clamps the radius to the bar height", () => {
    expect(barPath(0, 0, 10, 1, 4)).toBe("M0 1V1Q0 0 1 0H9Q10 0 10 1V1Z")
  })

  it("places the middle label", () => {
    expect(middleLabel({ hour: "02:00", centre: 240, width: 480 })).toEqual({ text: "02:00", x: 240 })
    expect(middleLabel({ hour: "02:00", note: "Fabrikam Freight scan", centre: 240, width: 480 })).toEqual({
      text: "02:00, Fabrikam Freight scan", x: 240,
    })
  })

  it("clamps the middle label inside the strip, then checks the edge labels", () => {
    // A centre beyond either edge is pulled in; there it collides with an edge label.
    expect(middleLabel({ hour: "02:00", centre: -50, width: 480 })).toBeNull()
    expect(middleLabel({ hour: "02:00", centre: 900, width: 480 })).toBeNull()
    // Just clear of the edge labels (36 + 8 = 44px each side) the centre is kept...
    expect(middleLabel({ hour: "02:00", centre: 62, width: 480 })).toEqual({ text: "02:00", x: 62 })
    expect(middleLabel({ hour: "02:00", centre: 418, width: 480 })).toEqual({ text: "02:00", x: 418 })
    // ...and one pixel closer is pulled out to a collision.
    expect(middleLabel({ hour: "02:00", centre: 60, width: 480 })).toBeNull()
    expect(middleLabel({ hour: "02:00", centre: 420, width: 480 })).toBeNull()
  })

  it("drops the note when tight, and the label when even the hour collides", () => {
    // Note makes the label too wide for 200px; the hour alone fits.
    expect(middleLabel({ hour: "02:00", note: "Fabrikam Freight scan", centre: 100, width: 200 })).toEqual({
      text: "02:00", x: 100,
    })
    // Hour needs 36 + 2*44 = 124px of clear room; 120 is not enough.
    expect(middleLabel({ hour: "02:00", centre: 60, width: 120 })).toBeNull()
    expect(middleLabel({ hour: "02:00", note: "Fabrikam Freight scan", centre: 60, width: 120 })).toBeNull()
  })
})

describe("HourlyStrip markup", () => {
  const counts = OVERNIGHT.map((h) => h.count)
  const html = render(OVERNIGHT, 480, "Fabrikam Freight scan")
  const bandRects = [...html.matchAll(/<rect[^>]*>/g)].map((m) => m[0]).filter((r) => !r.includes('role="slider"'))

  it("has zero counts in the fixture, so the bar count is not vacuous", () => {
    expect(counts.filter((c) => c === 0)).toHaveLength(3)
    expect(counts.filter((c) => c > 0)).toHaveLength(15)
  })

  it("draws 1:1 pixels with a label row", () => {
    expect(html).toMatch(/<svg [^>]*width="480" height="72"/)
    expect(html).not.toContain("viewBox")
    expect(html).toContain(`aria-label="${stripLabel(OVERNIGHT, NOUN, "UTC")}"`)
  })

  it("draws one path per non-zero count and two in the busiest run", () => {
    expect(html.match(/<path /g)).toHaveLength(15)
    expect(html.match(/<path [^>]*fill="var\(--muted-foreground\)"/g)).toHaveLength(2)
    expect(html.match(/<path [^>]*fill="var\(--line-strong\)"/g)).toHaveLength(13)
  })

  it("has one slider and one pointer band per bar", () => {
    expect(html.match(/role="slider"/g)).toHaveLength(1)
    expect(html).toContain('aria-valuemax="17"')
    expect(bandRects).toHaveLength(18)
    expect(bandRects.some((r) => r.includes("tabindex"))).toBe(false)
  })

  it("labels both ends and the busiest run", () => {
    expect(html).toContain(">15:00</text>")
    expect(html).toContain(">09:00</text>")
    expect(html).toContain(">02:00, Fabrikam Freight scan</text>")
  })

  it("omits the note when none is given", () => {
    expect(render(OVERNIGHT)).toContain(">02:00</text>")
  })

  it("reads the summary under the chart", () => {
    expect(html).toContain('aria-live="polite">41 changes in 18 hours, busiest between 02:00 and 04:00.</p>')
  })

  it("renders all-zero input without bars or a middle label", () => {
    const zero = render(hourlyBuckets("2026-11-12T00:00:00Z", [0, 0, 0, 0]))
    expect(zero).toContain("<line")
    expect(zero).toContain('role="slider"')
    expect(zero).not.toContain("<path")
    expect(zero.match(/<text /g)).toHaveLength(2)
    expect(zero).toContain("No changes in 4 hours.")
  })

  it("renders one bucket without NaN", () => {
    const one = render(hourlyBuckets("2026-11-12T00:00:00Z", [3]))
    expect(one).not.toContain("NaN")
    expect(one).toContain("<path")
    expect(one).toContain('aria-valuemax="0"')
  })

  it("keeps a small count visible beside a large one", () => {
    // 1 of 100 rounds to no height at 48px; a non-zero hour still gets a 2px bar.
    const lopsided = render(hourlyBuckets("2026-11-12T00:00:00Z", [100, 1]))
    expect(lopsided).toContain(`d="${barPath(240, 46, 238, 2, 2)}"`)
  })

  it("renders nothing without width or hours", () => {
    expect(render(OVERNIGHT, 0)).toBe("")
    expect(render([])).toBe("")
  })

  it("uses CSS variables and font sizes of at least 12", () => {
    expect(html).not.toMatch(/#[0-9a-fA-F]{3,8}\b/)
    const sizes = [...html.matchAll(/font-?size[=:]"?(\d+(?:\.\d+)?)/gi)].map((m) => Number(m[1]))
    expect(sizes.length).toBeGreaterThan(0)
    expect(Math.min(...sizes)).toBeGreaterThanOrEqual(12)
  })
})
