import { describe, expect, it } from "vitest"
import type { CveRefreshSettings } from "@/lib/api"
import { validateCveRefreshSettings } from "@/lib/cveRefreshSettings"

const ok: CveRefreshSettings = { time_limit_seconds: 300, due_batch: 500, refresh_interval_hours: 24, failed_retry_hours: 6 }
const v = (o: Partial<CveRefreshSettings>) => validateCveRefreshSettings({ ...ok, ...o })
// failed_retry 1 keeps the ordering rule out of the way when the interval itself is at its lower edge
const vInterval = (n: number) => validateCveRefreshSettings({ ...ok, failed_retry_hours: 1, refresh_interval_hours: n })
const CROSS = "Retrying a failed CVE must not take longer than the re-check interval."

describe("validateCveRefreshSettings", () => {
  it("accepts defaults", () => expect(v({})).toBeNull())
  it("checks bounds edges and returns each message", () => {
    const cases: [keyof CveRefreshSettings, number, number, string][] = [
      ["time_limit_seconds", 60, 3000, "The hourly run limit must be a whole number from 60 to 3000 seconds."],
      ["due_batch", 10, 5000, "CVEs read per run must be a whole number from 10 to 5000."],
      ["refresh_interval_hours", 1, 720, "The re-check interval must be a whole number from 1 to 720 hours."],
    ]
    for (const [k, lo, hi, msg] of cases) {
      const v = k === "refresh_interval_hours" ? vInterval : (n: number) => validateCveRefreshSettings({ ...ok, [k]: n })
      expect(v(lo)).toBeNull()
      expect(v(hi)).toBeNull()
      expect(v(lo - 1)).toBe(msg)
      expect(v(hi + 1)).toBe(msg)
      expect(v(lo + 0.5)).toBe(msg)
      expect(v(NaN)).toBe(msg)
    }
  })
  it("checks failed retry bounds", () => {
    const msg = "Retrying a failed CVE must be a whole number from 1 to 720 hours."
    expect(v({ failed_retry_hours: 1 })).toBeNull()
    expect(v({ failed_retry_hours: 0 })).toBe(msg)
    expect(v({ refresh_interval_hours: 720, failed_retry_hours: 720 })).toBeNull()
    expect(v({ refresh_interval_hours: 720, failed_retry_hours: 721 })).toBe(msg)
    expect(v({ failed_retry_hours: 1.5 })).toBe(msg)
    expect(v({ failed_retry_hours: NaN })).toBe(msg)
  })
  it("cross-field: failed retry must not exceed re-check interval", () => {
    expect(v({ refresh_interval_hours: 24, failed_retry_hours: 24 })).toBeNull()
    expect(v({ refresh_interval_hours: 24, failed_retry_hours: 25 })).toBe(CROSS)
    expect(v({ refresh_interval_hours: 2, failed_retry_hours: 3 })).toBe(CROSS)
  })
  it("reports the first problem when several exist", () => {
    expect(v({ time_limit_seconds: 1, due_batch: 1 })).toMatch(/hourly run limit/)
  })
})
