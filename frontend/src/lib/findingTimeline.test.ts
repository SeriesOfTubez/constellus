import { describe, expect, it } from "vitest"
import type { TimelineEvent, TimelineKind } from "@/lib/api"
import { gapText, onlyFirstSeen, sameDay, secondLines, timelineDate, timelineLabel } from "@/lib/findingTimeline"

const ev = (over: Partial<TimelineEvent> = {}): TimelineEvent => ({
  kind: "first_seen", date: "2026-11-09", precision: "day", at: null, source: null,
  entity_id: null, entity_name: null, acquirer_id: null, target_id: null, target_value: null,
  other_dates: [], ...over,
})
const day = (date: string) => ev({ date, precision: "day" })
const month = (date: string) => ev({ date, precision: "month" })
const year = (date: string) => ev({ date, precision: "year" })

// Day N after 2024-01-01 (a leap year; the rule is day arithmetic, so only the count matters).
const plusDays = (n: number) => new Date(Date.UTC(2024, 0, 1) + n * 86_400_000).toISOString().slice(0, 10)

describe("timelineLabel", () => {
  const cases: [TimelineKind, Partial<TimelineEvent>, string][] = [
    ["cve_published", {}, "CVE published"],
    ["listed_exploited_cisa", {}, "Listed by CISA as exploited"],
    ["listed_exploited_vulncheck", {}, "Listed by VulnCheck as exploited"],
    ["acquired", { entity_name: "Example Holdings A" }, "Example Holdings A acquired"],
    ["acquired", { entity_name: null }, "A company acquired"],
    ["claimed", { target_value: "fabrikam.example.com" }, "fabrikam.example.com claimed"],
    ["claimed", { target_value: null }, "A scope claimed"],
    ["first_seen", {}, "First seen"],
    ["ownership_confirmed", {}, "Confirmed ours"],
    ["due", {}, "Fix due"],
  ]
  it.each(cases)("%s %j -> %s", (kind, over, expected) => {
    expect(timelineLabel(ev({ kind, ...over }))).toBe(expected)
  })
})

describe("timelineDate", () => {
  it("formats by precision", () => {
    expect(timelineDate(ev({ date: "2024-04-12", precision: "day" }))).toBe("12 Apr 2024")
    expect(timelineDate(ev({ date: "2026-08-01", precision: "month" }))).toBe("Aug 2026")
    expect(timelineDate(ev({ date: "2019-01-01", precision: "year" }))).toBe("2019")
  })
})

describe("gapText", () => {
  // Expected by the rule: 31..: months = round(days/30.4375) (<12), else years = round(days/365.25).
  const dayCases: [number, string | null][] = [
    [0, null], [1, "1 day later"], [2, "2 days later"], [30, "30 days later"],
    [31, "about 1 month later"], [45, "about 1 month later"],
    [334, "about 11 months later"], [335, "about 11 months later"],
    [365, "about 1 year later"], [366, "about 1 year later"], [800, "about 2 years later"],
  ]
  it.each(dayCases)("day/day %i days -> %s", (n, expected) => {
    expect(gapText(day(plusDays(0)), day(plusDays(n)))).toBe(expected)
  })
  it("negative day difference is null", () => {
    expect(gapText(day("2026-11-09"), day("2026-11-01"))).toBeNull()
  })
  it("US DST day does not shift the count", () => {
    expect(gapText(day("2026-03-08"), day("2026-03-09"))).toBe("1 day later")
  })
  it("month/day pairs use calendar months", () => {
    expect(gapText(month("2026-08-01"), day("2026-11-09"))).toBe("about 3 months later")
    expect(gapText(month("2026-08-01"), day("2026-08-20"))).toBeNull()
    expect(gapText(day("2026-08-20"), month("2026-09-01"))).toBe("about 1 month later")
  })
  it("month, not days: Aug 2026 -> 31 Aug is 0 months though 30 days", () => {
    expect(gapText(month("2026-08-01"), day("2026-08-31"))).toBeNull()
  })
  it("month/month 12+ months become years", () => {
    expect(gapText(month("2024-04-01"), month("2026-08-01"))).toBe("about 2 years later")
    expect(gapText(month("2024-08-01"), month("2025-08-01"))).toBe("about 1 year later")
    expect(gapText(month("2026-01-01"), month("2026-12-01"))).toBe("about 11 months later")
  })
  it("12 Apr 2024 -> Aug 2026 is 28 months, about 2 years", () => {
    expect(gapText(day("2024-04-12"), month("2026-08-01"))).toBe("about 2 years later")
  })
  it("year precision on either side is null", () => {
    expect(gapText(year("2019-01-01"), month("2026-08-01"))).toBeNull()
    expect(gapText(day("2019-05-05"), year("2026-01-01"))).toBeNull()
    expect(gapText(year("2019-01-01"), year("2026-01-01"))).toBeNull()
  })
})

describe("secondLines", () => {
  const today = "2026-11-16"
  const due = (date: string) => secondLines(ev({ kind: "due", date }), today)
  it("due, relative to today", () => {
    expect(due("2026-11-13")).toEqual(["BOD 26-04 · 3 days ago"])
    expect(due("2026-11-15")).toEqual(["BOD 26-04 · 1 day ago"])
    expect(due("2026-11-16")).toEqual(["BOD 26-04 · today"])
    expect(due("2026-11-17")).toEqual(["BOD 26-04 · in 1 day"])
    expect(due("2026-11-21")).toEqual(["BOD 26-04 · in 5 days"])
  })
  it("acquired lists each other source's date", () => {
    const e = ev({
      kind: "acquired", entity_name: "Example Holdings A", date: "2026-08-01", precision: "month",
      other_dates: [
        { date: "2026-09-03", precision: "day", source: null },
        { date: "2019-01-01", precision: "year", source: "registry" },
        { date: "2026-10-01", precision: "month", source: null },
      ],
    })
    expect(secondLines(e, today)).toEqual([
      "Another source says 3 Sep 2026", "Another source says 2019", "Another source says Oct 2026",
    ])
    expect(secondLines(ev({ kind: "acquired" }), today)).toEqual([])
  })
  it("other kinds have none", () => {
    for (const kind of ["cve_published", "listed_exploited_cisa", "listed_exploited_vulncheck", "claimed", "first_seen", "ownership_confirmed"] as const) {
      expect(secondLines(ev({ kind, other_dates: [{ date: "2026-09-03", precision: "day", source: null }] }), today)).toEqual([])
    }
  })
})

describe("sameDay / onlyFirstSeen", () => {
  it("sameDay needs date and precision", () => {
    expect(sameDay(day("2026-08-01"), day("2026-08-01"))).toBe(true)
    expect(sameDay(day("2026-08-01"), month("2026-08-01"))).toBe(false)
    expect(sameDay(day("2026-08-01"), day("2026-08-02"))).toBe(false)
  })
  it("onlyFirstSeen", () => {
    expect(onlyFirstSeen([ev()])).toBe(true)
    expect(onlyFirstSeen([ev(), ev({ kind: "claimed" })])).toBe(false)
    expect(onlyFirstSeen([])).toBe(false)
  })
})
