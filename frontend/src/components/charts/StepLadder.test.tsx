import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import type { Row } from "./ladderFixture"
import { MOCK_ROWS, makeLadder } from "./ladderFixture"
import {
  StepLadder, fixCountLabel, fixSentence, ladderLabel, levelSentence, shownFixes,
} from "./StepLadder"
import type { ScoreLadder } from "@/lib/api"

const render = (ladder: ScoreLadder, width = 900) =>
  renderToStaticMarkup(<MemoryRouter><StepLadder ladder={ladder} width={width} /></MemoryRouter>)

const circleCys = (html: string) => [...html.matchAll(/<circle[^>]*\scy="([^"]+)"/g)].map((m) => Number(m[1]))

describe("StepLadder helpers", () => {
  it("pluralises fix counts", () => {
    expect(fixCountLabel(1)).toBe("1 fix")
    expect(fixCountLabel(12)).toBe("12 fixes")
  })

  it("words level sentences by count and prefix", () => {
    const l = makeLadder([[92, "imminent_compromise", 2], [67, "high", 1]])
    expect(levelSentence(l.levels[0])).toBe("2 findings score 92. Fix both and the score drops to 67, High Risk.")
    expect(levelSentence(l.levels[1])).toBe("After 2 fixes: 1 finding scores 67. Fix it and no scored finding is left open: Secure Posture.")
    const m = makeLadder([[80, "imminent_compromise", 3]])
    expect(levelSentence(m.levels[0])).toBe("3 findings score 80. Fix all 3 and no scored finding is left open: Secure Posture.")
  })
})

describe("StepLadder with a mock-shaped ladder", () => {
  const ladder = makeLadder(MOCK_ROWS)
  const html = render(ladder)

  it("labels the chart exactly", () => {
    expect(ladderLabel(ladder)).toBe("Step chart: risk score falls from 91 to 71 after 3 fixes and to 47 after 12 fixes")
    expect(html).toContain(`aria-label="Step chart: risk score falls from 91 to 71 after 3 fixes and to 47 after 12 fixes"`)
  })

  it("clips the view just past the second crossing", () => {
    expect(shownFixes(ladder)).toBe(14)
  })

  it("draws ticks, Today and score labels", () => {
    expect(html).toContain(">3 fixes<")
    expect(html).toContain(">12 fixes<")
    expect(html).toContain(">Today<")
    expect(html).toContain(">91<")
    expect(html).toContain(">71<")
    expect(html).toContain(">47<")
  })

  it("has a legend with exactly the three shown bands", () => {
    expect((html.match(/<rect[^>]*width="8"/g) ?? []).length).toBe(3)
    expect(html).toContain(">Imminent Threat<")
    expect(html).toContain(">High Risk<")
    expect(html).toContain(">Elevated Risk<")
    expect(html).not.toContain("Low Risk")
  })

  it("draws three markers with the exact sentences", () => {
    expect(circleCys(html)).toHaveLength(3)
    for (const f of ladder.first_fixes) {
      expect(html).toContain(`<title>${fixSentence(f)}</title>`)
    }
    expect(fixSentence(ladder.first_fixes[0])).toBe(
      "Fix 1: Exposed admin panel 1 on vpn1.fabrikam.example. The score drops from 91 to 88.",
    )
  })

  it("starts with the first level in the readout", () => {
    expect(html).toContain(`aria-live="polite">${levelSentence(ladder.levels[0])}</p>`)
  })

  it("uses no font size under 12 and no hex colour", () => {
    const sizes = [...html.matchAll(/font-size="(\d+)"/g)].map((m) => Number(m[1]))
    expect(sizes.length).toBeGreaterThan(5)
    expect(sizes.filter((s) => s < 12)).toEqual([])
    expect(html).not.toMatch(/#[0-9a-fA-F]{3,8}\b/)
  })
})

describe("StepLadder ties", () => {
  const ladder = makeLadder([[92, "imminent_compromise", 2], [67, "high", 1]])

  it("says the score stays when other findings share it", () => {
    expect(fixSentence(ladder.first_fixes[0])).toBe(
      "Fix 1: Exposed admin panel 1 on vpn1.fabrikam.example. The score stays at 92 until the other findings on that score are fixed too.",
    )
    expect(levelSentence(ladder.levels[0])).toContain("Fix both")
  })

  it("puts marker 1 on the flat and marker 2 on the riser", () => {
    const cys = circleCys(render(ladder))
    expect(cys).toHaveLength(3)
    expect(cys[0]).not.toBe(cys[1])
    // Marker 1 sits on the flat at the top of the plot (y of the highest score).
    expect(cys[0]).toBe(Math.min(...cys))
  })
})

describe("StepLadder edge shapes", () => {
  it("renders a single level without NaN or band lines", () => {
    const ladder = makeLadder([[80, "imminent_compromise", 3]])
    expect(ladder.crossings).toEqual([{ band: "secure", fixes: 3, score: 0 }])
    const html = render(ladder)
    expect(html).toContain("<svg")
    expect(html).not.toContain("NaN")
    expect(html).not.toContain("stroke-dasharray")
  })

  it("clips a long low level and keeps the rule", () => {
    const ladder = makeLadder([
      [90, "imminent_compromise", 1], [70, "high", 2], [50, "elevated", 3], [30, "low", 400],
    ])
    expect(shownFixes(ladder)).toBe(4)
    const big = makeLadder([
      [90, "imminent_compromise", 300], [70, "high", 5], [50, "elevated", 5], [30, "low", 400],
    ])
    expect(shownFixes(big)).toBe(305 + Math.max(1, Math.round(305 * 0.15)))
  })

  it("draws no markers when a fix step is under 24px", () => {
    const big = makeLadder([
      [90, "imminent_compromise", 300], [70, "high", 5], [50, "elevated", 5], [30, "low", 400],
    ])
    const html = render(big)
    expect(circleCys(html)).toHaveLength(0)
    expect(html).not.toContain("role=\"link\"")
    expect(html).not.toContain("NaN")
  })

  it("renders nothing for zero width or an empty ladder", () => {
    expect(render(makeLadder(MOCK_ROWS), 0)).toBe("")
    const rows: Row[] = []
    expect(render(makeLadder(rows))).toBe("")
  })
})
