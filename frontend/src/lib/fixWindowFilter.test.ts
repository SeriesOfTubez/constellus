import { describe, expect, it } from "vitest"
import { matchesFixWindow } from "@/lib/fixWindowFilter"

describe("matchesFixWindow", () => {
  it("passes everything for all, including a finding with no window", () => {
    expect(matchesFixWindow("14d", "all")).toBe(true)
    expect(matchesFixWindow(null, "all")).toBe(true)
    expect(matchesFixWindow(undefined, "all")).toBe(true)
  })

  it("3d matches 3d and 3d+triage", () => {
    expect(matchesFixWindow("3d", "3d")).toBe(true)
    expect(matchesFixWindow("3d+triage", "3d")).toBe(true)
  })

  it("3d does not match the other windows", () => {
    for (const w of ["14d", "60d", "upgrade"]) {
      expect(matchesFixWindow(w, "3d")).toBe(false)
    }
  })

  it("3d+triage matches only 3d+triage", () => {
    expect(matchesFixWindow("3d+triage", "3d+triage")).toBe(true)
    expect(matchesFixWindow("3d", "3d+triage")).toBe(false)
  })

  it("reads a space as a plus (a decoded ?bod=3d+triage)", () => {
    expect(matchesFixWindow("3d+triage", "3d triage")).toBe(true)
    expect(matchesFixWindow("3d", "3d triage")).toBe(false)
  })

  it("14d matches only 14d", () => {
    expect(matchesFixWindow("14d", "14d")).toBe(true)
    for (const w of ["3d", "3d+triage", "60d", "upgrade"]) {
      expect(matchesFixWindow(w, "14d")).toBe(false)
    }
  })

  it("a finding with no window fails every filter except all", () => {
    for (const f of ["3d", "3d+triage", "3d triage", "14d", "60d", "upgrade"]) {
      expect(matchesFixWindow(null, f)).toBe(false)
      expect(matchesFixWindow(undefined, f)).toBe(false)
    }
  })
})
