import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import type { LineAnnotation, LinePoint } from "./AnnotatedLine"
import {
  AnnotatedLine, annotationPlacement, dayNumber, formatDay, lineLabel, pointSentence,
  summarySentence, valueText,
} from "./AnnotatedLine"
import { GROUND_GAINED, dailySeries } from "./lineFixture"

type Props = Partial<Parameters<typeof AnnotatedLine>[0]>

const SUBJECT = "Open Critical and High findings"

const render = (props: Props = {}) =>
  renderToStaticMarkup(
    <AnnotatedLine
      points={GROUND_GAINED.points}
      annotations={GROUND_GAINED.annotations}
      subject={SUBJECT}
      unit="open"
      width={560}
      {...props}
    />,
  )

const linePathD = (html: string) => {
  const tag = [...html.matchAll(/<path[^>]*>/g)].map((m) => m[0]).find((t) => t.includes(`fill="none"`))
  return tag?.match(/\sd="([^"]+)"/)?.[1] ?? null
}
const pathPairs = (d: string) => [...d.matchAll(/[ML]([-\d.]+),([-\d.]+)/g)].map((m) => [Number(m[1]), Number(m[2])])

const bandRects = (html: string) =>
  [...html.matchAll(/<rect[^>]*>/g)].map((m) => m[0]).filter((t) => t.includes(`fill="transparent"`) && !t.includes("tabindex"))

describe("AnnotatedLine helpers", () => {
  it("formats days with fixed month names", () => {
    expect(formatDay("2026-11-09")).toBe("9 Nov")
    expect(formatDay("2026-11-09", true)).toBe("9 Nov 2026")
    expect(formatDay("2027-01-01")).toBe("1 Jan")
    expect(formatDay("2026-12-31", true)).toBe("31 Dec 2026")
  })

  it("counts days without timezone dependence", () => {
    expect(dayNumber("2026-11-01") - dayNumber("2026-10-31")).toBe(1)
    expect(dayNumber("2028-03-01") - dayNumber("2028-02-28")).toBe(2)
    expect(dayNumber("2027-03-01") - dayNumber("2027-02-28")).toBe(1)
  })

  it("words values and point sentences", () => {
    expect(valueText(23, "open")).toBe("23 open")
    const p = { date: "2026-11-09", value: 29 }
    expect(pointSentence(p, "open")).toBe("9 Nov: 29 open.")
    expect(pointSentence(p, "open", "Fabrikam Freight scanned, 9 more")).toBe(
      "9 Nov: 29 open. Fabrikam Freight scanned, 9 more.",
    )
  })

  it("summarises one point", () => {
    expect(summarySentence([{ date: "2026-11-12", value: 23 }], "open")).toBe("23 open on 12 Nov.")
  })

  it("summarises two points without a Lowest clause", () => {
    const pts = dailySeries("2026-10-13", [38, 23])
    expect(summarySentence(pts, "open")).toBe("38 open on 13 Oct, 23 open on 14 Oct.")
  })

  it("adds a Lowest clause when the minimum is strictly inside", () => {
    expect(summarySentence(GROUND_GAINED.points, "open")).toBe(
      "38 open on 13 Oct, 23 open on 12 Nov. Lowest: 20 open on 8 Nov.",
    )
  })

  it("omits Lowest when the minimum is the last point or ties an end", () => {
    expect(summarySentence(dailySeries("2026-10-13", [38, 30, 23]), "open")).not.toContain("Lowest")
    expect(summarySentence(dailySeries("2026-10-13", [38, 23, 23]), "open")).not.toContain("Lowest")
    expect(summarySentence(dailySeries("2026-10-13", [5, 9, 7]), "open")).not.toContain("Lowest")
  })

  it("shows the year only when the years differ", () => {
    const across = dailySeries("2026-12-30", [4, 3, 2, 3])
    expect(summarySentence(across, "open")).toBe("4 open on 30 Dec 2026, 3 open on 2 Jan 2027. Lowest: 2 open on 1 Jan 2027.")
    expect(summarySentence(GROUND_GAINED.points, "open")).not.toContain("2026")
  })

  it("builds the label from subject and summary", () => {
    expect(lineLabel(SUBJECT, GROUND_GAINED.points, "open")).toBe(
      "Line chart: Open Critical and High findings. 38 open on 13 Oct, 23 open on 12 Nov. Lowest: 20 open on 8 Nov.",
    )
  })
})

describe("annotationPlacement", () => {
  const base = { labelLength: 10, plotLeft: 8, plotRight: 480 }

  it("puts the label left of the rule when the value rose", () => {
    expect(annotationPlacement({ ...base, px: 300, py: 100, risen: true })).toEqual({ x: 290, y: 88, anchor: "end" })
  })

  it("puts the label right of the rule otherwise", () => {
    expect(annotationPlacement({ ...base, px: 300, py: 100, risen: false })).toEqual({ x: 310, y: 88, anchor: "start" })
  })

  it("flips when the preferred side lacks room and the other has more", () => {
    expect(annotationPlacement({ ...base, px: 40, py: 100, risen: true })).toMatchObject({ x: 50, anchor: "start" })
    expect(annotationPlacement({ ...base, px: 470, py: 100, risen: false })).toMatchObject({ x: 460, anchor: "end" })
  })

  it("does not flip when the other side has no more room", () => {
    // Neither side fits a 700px label: keep the preferred side unless the other has more room.
    expect(annotationPlacement({ ...base, labelLength: 100, px: 200, py: 100, risen: false })).toMatchObject({ anchor: "start" })
    expect(annotationPlacement({ ...base, labelLength: 100, px: 250, py: 100, risen: false })).toMatchObject({ anchor: "end" })
    expect(annotationPlacement({ ...base, labelLength: 100, px: 250, py: 100, risen: true })).toMatchObject({ anchor: "end" })
    expect(annotationPlacement({ ...base, labelLength: 100, px: 240, py: 100, risen: true })).toMatchObject({ anchor: "start" })
  })

  it("clamps y at 12", () => {
    expect(annotationPlacement({ ...base, px: 300, py: 20, risen: false }).y).toBe(12)
  })
})

describe("dailySeries", () => {
  it("crosses month and year ends", () => {
    expect(dailySeries("2026-12-31", [1, 2, 3]).map((p) => p.date)).toEqual(["2026-12-31", "2027-01-01", "2027-01-02"])
    expect(dailySeries("2028-02-28", [1, 2, 3]).map((p) => p.date)).toEqual(["2028-02-28", "2028-02-29", "2028-03-01"])
  })

  it("builds the ground-gained fixture as specified", () => {
    const p = GROUND_GAINED.points
    expect(p).toHaveLength(31)
    expect(p[0]).toEqual({ date: "2026-10-13", value: 38 })
    expect(p[26].value).toBe(20)
    expect(p[27]).toEqual({ date: "2026-11-09", value: 29 })
    expect(p[30]).toEqual({ date: "2026-11-12", value: 23 })
    for (let i = 1; i <= 26; i++) expect(p[i].value).toBeLessThanOrEqual(p[i - 1].value)
  })
})

describe("AnnotatedLine markup", () => {
  const html = render()

  it("draws 1:1 pixels with no viewBox", () => {
    expect(html).toContain(`width="560"`)
    expect(html).not.toContain("viewBox")
  })

  it("labels the svg exactly", () => {
    expect(html).toContain(`aria-label="${lineLabel(SUBJECT, GROUND_GAINED.points, "open")}"`)
  })

  it("shows start value, end value, dates and the annotation", () => {
    expect(html).toContain(">38 open<")
    expect(html).toContain(">23 open<")
    expect(html).toContain(">13 Oct<")
    expect(html).toContain(">12 Nov<")
    expect(html).toContain(">Fabrikam Freight scanned, 9 more<")
  })

  it("has one slider and one pointer band per point", () => {
    expect((html.match(/role="slider"/g) ?? []).length).toBe(1)
    expect(html).toContain(`aria-valuemax="30"`)
    expect(html).toContain(`aria-valuenow="30"`)
    expect(bandRects(html)).toHaveLength(31)
  })

  it("puts the summary in the polite readout", () => {
    const p = html.match(/<p[^>]*aria-live="polite"[^>]*>([^<]*)<\/p>/)
    expect(p?.[1]).toBe(summarySentence(GROUND_GAINED.points, "open"))
  })

  it("draws the line, the area and the dashed annotation rule", () => {
    expect(linePathD(html)).not.toBeNull()
    expect(html).toContain(`stroke-dasharray="2 4"`)
  })

  it("replaces the last date with lastLabel", () => {
    const t = render({ lastLabel: "Today" })
    expect(t).toContain(">Today<")
    expect(t).not.toContain(">12 Nov<")
    expect(t).toContain(">13 Oct<")
  })

  it("does not draw an annotation that matches no point, but draws the one that does", () => {
    const notes: LineAnnotation[] = [
      { date: "2026-11-09", label: "Fabrikam Freight scanned, 9 more" },
      { date: "2025-01-01", label: "Contoso Marine scanned" },
    ]
    const t = render({ annotations: notes })
    expect(t).toContain("Fabrikam Freight scanned, 9 more")
    expect(t).not.toContain("Contoso Marine")
    expect((t.match(/stroke-dasharray="2 4"/g) ?? []).length).toBe(1)
  })
})

describe("AnnotatedLine compact", () => {
  const html = render({ compact: true })

  it("keeps the annotation and readout, drops end value and dates", () => {
    expect(html).toContain(">Fabrikam Freight scanned, 9 more<")
    expect(html).not.toContain(">23 open<")
    expect(html).not.toContain(">38 open<")
    expect(html).not.toContain(">13 Oct<")
    expect(html).not.toContain(">12 Nov<")
    expect(html).toContain(`aria-live="polite"`)
    expect(html).toContain(`height="68"`)
    expect(html).not.toContain("<circle")
  })
})

describe("AnnotatedLine domain", () => {
  const plain = render({ annotations: [] })

  it("starts the line to the right of the left edge when the clock starts earlier", () => {
    const wide = render({ annotations: [], domain: { from: "2026-08-14", to: "2026-11-12", max: 38 } })
    const x0 = pathPairs(linePathD(wide) ?? "")[0][0]
    const plainX0 = pathPairs(linePathD(plain) ?? "")[0][0]
    expect(plainX0).toBe(8)
    expect(x0).toBeGreaterThan(plainX0 + 100)
  })

  it("draws the highest point lower under a larger shared max", () => {
    const top = (html: string) => Math.min(...pathPairs(linePathD(html) ?? "").map((p) => p[1]))
    const doubled = render({ annotations: [], domain: { from: "2026-10-13", to: "2026-11-12", max: 76 } })
    expect(top(doubled)).toBeGreaterThan(top(plain) + 20)
  })
})

describe("AnnotatedLine edge cases", () => {
  it("draws a single point as a dot with no line", () => {
    const html = render({ points: [{ date: "2026-11-12", value: 23 }], annotations: [] })
    expect(linePathD(html)).toBeNull()
    expect(html).toContain("<circle")
    expect(html).toContain("23 open on 12 Nov.")
    expect(html).not.toContain("NaN")
    expect(html).toContain(`aria-valuemax="0"`)
  })

  it("renders a zero-only series without NaN", () => {
    const pts: LinePoint[] = dailySeries("2026-11-01", [0, 0, 0])
    const html = render({ points: pts, annotations: [] })
    expect(html).toContain(">0 open<")
    expect(html).not.toContain("NaN")
    expect(html).not.toContain("Infinity")
  })

  it("renders nothing without width or points", () => {
    expect(render({ width: 0 })).toBe("")
    expect(render({ points: [] })).toBe("")
  })

  it("uses no hex colours and no font below 12", () => {
    for (const html of [render(), render({ compact: true })]) {
      expect(html).not.toMatch(/#[0-9a-fA-F]{3,8}\b/)
      const sizes = [...html.matchAll(/font-?[sS]ize[=:]"?(\d+(?:\.\d+)?)/g)].map((m) => Number(m[1]))
      expect(sizes.length).toBeGreaterThan(0)
      for (const s of sizes) expect(s).toBeGreaterThanOrEqual(12)
    }
  })
})
