import { describe, expect, it } from "vitest"
import { scrubBands, scrubKey } from "./scrub"

describe("scrubBands", () => {
  it("splits at the midpoints and reaches both edges", () => {
    expect(scrubBands([10, 30, 70], 0, 100)).toEqual([
      { x: 0, w: 20 },
      { x: 20, w: 30 },
      { x: 50, w: 50 },
    ])
  })

  it("gives a single mark the whole width", () => {
    expect(scrubBands([40], 8, 92)).toEqual([{ x: 8, w: 84 }])
  })

  it("leaves no gap and no overlap between neighbours", () => {
    const bands = scrubBands([5, 6, 50, 51, 99], 0, 100)
    for (let i = 1; i < bands.length; i++) {
      expect(bands[i].x).toBeCloseTo(bands[i - 1].x + bands[i - 1].w)
    }
    expect(bands[0].x).toBe(0)
    expect(bands[4].x + bands[4].w).toBe(100)
  })
})

describe("scrubKey", () => {
  it("starts at the most recent mark on Left and the first on Right", () => {
    expect(scrubKey("ArrowLeft", null, 30)).toBe(29)
    expect(scrubKey("ArrowRight", null, 30)).toBe(0)
  })

  it("steps one mark and stops at the ends", () => {
    expect(scrubKey("ArrowLeft", 5, 30)).toBe(4)
    expect(scrubKey("ArrowRight", 5, 30)).toBe(6)
    expect(scrubKey("ArrowLeft", 0, 30)).toBe(0)
    expect(scrubKey("ArrowRight", 29, 30)).toBe(29)
  })

  it("jumps with Home and End and clears with Escape", () => {
    expect(scrubKey("Home", 12, 30)).toBe(0)
    expect(scrubKey("End", 12, 30)).toBe(29)
    expect(scrubKey("Escape", 12, 30)).toBeNull()
  })

  it("leaves other keys, and an empty chart, alone", () => {
    expect(scrubKey("Tab", 3, 30)).toBeUndefined()
    expect(scrubKey("a", null, 30)).toBeUndefined()
    expect(scrubKey("ArrowLeft", null, 0)).toBeUndefined()
  })
})
