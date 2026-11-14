import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { AnnotatedLine, annotationPlacement, placeAnnotations } from "./AnnotatedLine"
import { dailySeries } from "./lineFixture"

// Labels are estimated at 7px a character; these are 10 characters = 70px.
const item = (px: number, risen: boolean, labelLength = 10) => ({ px, py: 60, risen, labelLength })

describe("placeAnnotations", () => {
  it("leaves labels that are clear of each other where annotationPlacement put them", () => {
    const items = [item(100, false), item(400, false)]
    expect(placeAnnotations(items, 0, 760)).toEqual(
      items.map((it) => annotationPlacement({ ...it, plotLeft: 0, plotRight: 760 })),
    )
  })

  it("moves the later label to its other side when that clears the earlier one", () => {
    // 300 goes right (310..380); 420 has risen so goes left (340..410): they meet.
    const [a, b] = placeAnnotations([item(300, false), item(420, true)], 0, 760)
    expect(a).toMatchObject({ x: 310, anchor: "start" })
    expect(b).toMatchObject({ x: 430, anchor: "start", y: a.y })
  })

  it("moves the earlier label when the later one has no room on its other side", () => {
    // The later mark is 10px from the right edge, so only the earlier one can move.
    const [a, b] = placeAnnotations([item(640, false), item(750, true)], 0, 760)
    expect(b).toMatchObject({ x: 740, anchor: "end" })
    expect(a).toMatchObject({ x: 630, anchor: "end", y: b.y })
  })

  it("leaves labels alone when they share a column but sit on different lines", () => {
    // Same x-ranges as the case above, but the second mark is 40px lower on the plot.
    const items = [item(300, false), { ...item(420, true), py: 100 }]
    const [a, b] = placeAnnotations(items, 0, 760)
    expect(a).toMatchObject({ x: 310, anchor: "start", y: 48 })
    expect(b).toMatchObject({ x: 410, anchor: "end", y: 88 })
  })

  it("puts the later label a line above when neither can change sides", () => {
    // Both marks sit against the right edge and the plot is too narrow to flip either.
    const [a, b] = placeAnnotations([item(60, true, 8), item(70, true, 8)], 0, 80)
    expect(a.anchor).toBe("end")
    expect(b.anchor).toBe("end")
    expect(b.y).toBe(a.y - 16)
  })

  it("puts it a line below instead when the earlier label is already at the top", () => {
    const high = (px: number) => ({ px, py: 20, risen: true, labelLength: 8 })
    const [a, b] = placeAnnotations([high(60), high(70)], 0, 80)
    expect(a.y).toBe(12)
    expect(b.y).toBe(28)
  })
})

describe("AnnotatedLine with nothing open", () => {
  it("draws a zero-only series on the baseline, not floating above it", () => {
    const html = renderToStaticMarkup(
      <AnnotatedLine points={dailySeries("2026-11-01", [0, 0, 0])} subject="Open findings" unit="open" width={560} />,
    )
    // Default height 184 with a 28px bottom margin: the baseline is y=156.
    const line = html.match(/<path[^>]*fill="none"[^>]*>/)
    expect(line).not.toBeNull()
    const ys = [...line![0].match(/ d="([^"]+)"/)![1].matchAll(/[ML]([\d.]+),([\d.]+)/g)].map((m) => Number(m[2]))
    expect(ys).toEqual([156, 156, 156])
  })
})

describe("AnnotatedLine with one day of history", () => {
  it("puts the dot in the middle of the plot", () => {
    const html = renderToStaticMarkup(
      <AnnotatedLine points={dailySeries("2026-11-12", [23])} subject="Open findings" unit="open" width={560} />,
    )
    // Plot runs from x=8 to x=480.
    expect(html).toMatch(/<circle cx="244" /)
    expect(html).not.toContain("NaN")
  })
})

describe("AnnotatedLine in a lane on a shared clock", () => {
  const points = dailySeries("2026-08-14", [14, 12, 10, 8, 6, 4, 13])
  const lane = (pts: typeof points) => renderToStaticMarkup(
    <AnnotatedLine compact points={pts} subject="Open findings" unit="open" width={760}
      domain={{ from: "2025-12-01", to: "2026-11-12", max: 40 }} />,
  )
  const pointerBands = (html: string) =>
    [...html.matchAll(/<rect [^>]*>/g)].map((m) => m[0])
      .filter((r) => r.includes('fill="transparent"') && !r.includes("role="))
      .map((r) => ({ x: Number(r.match(/ x="([\d.]+)"/)![1]), w: Number(r.match(/ width="([\d.]+)"/)![1]) }))

  it("keeps the pointer bands on the series, not on the months before it", () => {
    const bands = pointerBands(lane(points))
    expect(bands).toHaveLength(7)
    // 14 Aug is 256 of 346 days into the clock: well right of the lane's left edge.
    expect(bands[0].x).toBeGreaterThan(500)
    const end = bands[6].x + bands[6].w
    expect(end).toBeLessThan(700)
    expect(end).toBeGreaterThan(bands[0].x)
  })

  it("draws a dot for a company with one day of history, and none for a longer series", () => {
    expect(lane(points.slice(0, 1))).toContain("<circle")
    expect(lane(points)).not.toContain("<circle")
  })
})

describe("AnnotatedLine with two annotations close together", () => {
  const points = dailySeries("2026-08-14", [14, 12, 10, 8, 6, 4, 13])
  const first = "Arrives with 14"
  const second = "Second domain claimed, 9 more"

  const labelAt = (html: string, label: string) => {
    const m = html.match(new RegExp(`<text x="([\\d.]+)" y="([\\d.]+)" text-anchor="(start|end)"[^>]*>${label}</text>`))
    if (!m) throw new Error(`label not drawn: ${label}`)
    const [x, y] = [Number(m[1]), Number(m[2])]
    const w = label.length * 7
    return { y, x0: m[3] === "end" ? x - w : x, x1: m[3] === "end" ? x : x + w }
  }

  it("draws both labels without one over the other", () => {
    // A lane on a year-long clock: the seven days are a few pixels apart.
    const html = renderToStaticMarkup(
      <AnnotatedLine compact points={points} subject="Open findings" unit="open" width={760}
        domain={{ from: "2025-12-01", to: "2026-08-21", max: 40 }}
        annotations={[{ date: points[0].date, label: first }, { date: points[6].date, label: second }]} />,
    )
    const a = labelAt(html, first)
    const b = labelAt(html, second)
    const apart = a.x1 <= b.x0 || b.x1 <= a.x0 || Math.abs(a.y - b.y) >= 16
    expect(apart).toBe(true)
  })

  it("places them the same whichever order the caller lists them in", () => {
    const render = (annotations: { date: string; label: string }[]) => renderToStaticMarkup(
      <AnnotatedLine compact points={points} subject="Open findings" unit="open" width={760}
        domain={{ from: "2025-12-01", to: "2026-08-21", max: 40 }} annotations={annotations} />,
    )
    const forward = render([{ date: points[0].date, label: first }, { date: points[6].date, label: second }])
    const reversed = render([{ date: points[6].date, label: second }, { date: points[0].date, label: first }])
    expect(labelAt(reversed, first)).toEqual(labelAt(forward, first))
    expect(labelAt(reversed, second)).toEqual(labelAt(forward, second))
  })
})
