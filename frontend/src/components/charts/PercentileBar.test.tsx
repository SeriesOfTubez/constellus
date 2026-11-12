import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { epssColor, epssTone } from "@/components/finding-badges"
import { SEV_CHIP } from "@/components/ui/chip"
import {
  PercentileBar, markColor, percentileLabel, percentileSentence, percentileText,
} from "./PercentileBar"

const render = (percentile: number, score: number | null, width = 300) =>
  renderToStaticMarkup(<PercentileBar percentile={percentile} score={score} width={width} />)

const rects = (html: string) =>
  [...html.matchAll(/<rect([^>]*)>/g)].map((m) => {
    const attr = (name: string) => m[1].match(new RegExp(`\\s${name}="([^"]+)"`))?.[1] ?? ""
    return { x: Number(attr("x")), width: Number(attr("width")), height: Number(attr("height")), fill: attr("fill") }
  })

describe("PercentileBar helpers", () => {
  it("rounds the percentile down, never up", () => {
    expect(percentileText(0.92)).toBe("92")
    expect(percentileText(0.9296)).toBe("92.9")
    expect(percentileText(0.57)).toBe("57")
    expect(percentileText(0.004)).toBe("0.4")
    expect(percentileText(0)).toBe("0")
  })

  it("never claims higher than 99.9%", () => {
    expect(percentileText(0.9996)).toBe("99.9")
    expect(percentileText(1)).toBe("99.9")
    expect(percentileSentence(1)).toBe("Higher than 99.9% of all known flaws (EPSS)")
  })

  it("names the chart, with the score when there is one", () => {
    expect(percentileLabel(0.999, 0.943)).toBe(
      "Percentile bar: higher than 99.9% of all known flaws; 94.30% chance of attack in 30 days")
    expect(percentileLabel(0.4, null)).toBe("Percentile bar: higher than 40% of all known flaws")
  })

  it("colours by the score's band, at the chip's thresholds", () => {
    expect(markColor(0.5)).toBe("var(--sev-critical)")
    expect(markColor(0.4999)).toBe("var(--sev-high)")
    expect(markColor(0.1)).toBe("var(--sev-high)")
    expect(markColor(0.0999)).toBe("var(--sev-medium)")
    expect(markColor(0.01)).toBe("var(--sev-medium)")
    expect(markColor(0.0099)).toBe("var(--muted-foreground)")
    expect(markColor(null)).toBe("var(--muted-foreground)")
  })

  it("keeps the chip and the bar on one rule", () => {
    for (const score of [0, 0.0099, 0.01, 0.0999, 0.1, 0.4999, 0.5, 1]) {
      const tone = epssTone(score)
      expect(epssColor(score)).toBe(tone ? SEV_CHIP[tone] : "")
      expect(markColor(score)).toBe(tone ? `var(--sev-${tone})` : "var(--muted-foreground)")
    }
  })
})

describe("PercentileBar", () => {
  it("places the fill by percentile and colours it by score", () => {
    // 92nd percentile on a 3% score: far right, but only the Medium colour.
    const [track, fill, marker] = rects(render(0.92, 0.03))
    expect(track).toMatchObject({ x: 0, width: 300, height: 4, fill: "var(--border)" })
    expect(fill).toMatchObject({ x: 0, width: 276, height: 4, fill: "var(--sev-medium)" })
    expect(marker).toMatchObject({ x: 275, width: 2, height: 10, fill: "var(--foreground)" })
  })

  it("does not colour a high percentile critical when the score is low", () => {
    const html = render(0.99, 0.005)
    expect(rects(html)[1].fill).toBe("var(--muted-foreground)")
    expect(html).not.toContain("--sev-")
  })

  it("draws a neutral mark when there is no score", () => {
    expect(rects(render(0.6, null))[1]).toMatchObject({ width: 180, fill: "var(--muted-foreground)" })
  })

  it("keeps the marker inside the track at both ends", () => {
    expect(rects(render(0, 0))[2].x).toBe(0)
    expect(rects(render(1, 0.9))[2].x).toBe(298)
    expect(rects(render(1.4, 0.9))[1].width).toBe(300)
    expect(rects(render(-0.2, 0))[1].width).toBe(0)
  })

  it("draws 1:1 in pixels with no viewBox and no text inside the svg", () => {
    const html = render(0.5, 0.2, 240)
    expect(html).toContain(`<svg width="240" height="12"`)
    expect(html).not.toContain("viewBox")
    expect(html).not.toContain("<text")
    expect(html).not.toContain("font-size")
  })

  it("has an accessible name, a hover title and the sentence under it", () => {
    const html = render(0.999, 0.943)
    const label = "Percentile bar: higher than 99.9% of all known flaws; 94.30% chance of attack in 30 days"
    expect(html).toContain(`role="img" aria-label="${label}"`)
    expect(html).toContain(`<title>${label}</title>`)
    expect(html).toContain(`<p class="mt-1 text-xs text-muted-foreground">Higher than 99.9% of all known flaws (EPSS)</p>`)
  })

  it("draws nothing without a width or a number", () => {
    expect(render(0.5, 0.2, 0)).toBe("")
    expect(render(Number.NaN, 0.2)).toBe("")
  })
})
