import { describe, expect, it } from "vitest"
import type { DiscoverySettings } from "@/lib/api"
import { validateDiscoverySettings } from "@/lib/discoverySettings"

const ok: DiscoverySettings = {
  rediscovery_time_limit_seconds: 600, rediscovery_unit_pause_seconds: 2,
  rediscovery_due_batch: 200, rediscovery_refresh_interval_days: 7, rediscovery_failed_retry_days: 1,
}
const v = (o: Partial<DiscoverySettings>) => validateDiscoverySettings({ ...ok, ...o })
const CROSS = /must not take longer than the refresh interval/

describe("validateDiscoverySettings", () => {
  it("accepts defaults", () => expect(v({})).toBeNull())
  it("checks bounds edges", () => {
    const cases: [keyof DiscoverySettings, number, number][] = [
      ["rediscovery_time_limit_seconds", 60, 3000],
      ["rediscovery_unit_pause_seconds", 1, 60],
      ["rediscovery_due_batch", 10, 1000],
      ["rediscovery_refresh_interval_days", 1, 90],
    ]
    for (const [k, lo, hi] of cases) {
      expect(v({ [k]: lo })).toBeNull()
      expect(v({ [k]: hi })).toBeNull()
      expect(v({ [k]: lo - 1 })).not.toBeNull()
      expect(v({ [k]: hi + 1 })).not.toBeNull()
      expect(v({ [k]: lo + 0.5 })).not.toBeNull()
      expect(v({ [k]: NaN })).not.toBeNull()
    }
  })
  it("checks failed retry bounds", () => {
    expect(v({ rediscovery_failed_retry_days: 1 })).toBeNull()
    expect(v({ rediscovery_failed_retry_days: 0 })).not.toBeNull()
    expect(v({ rediscovery_refresh_interval_days: 90, rediscovery_failed_retry_days: 30 })).toBeNull()
    expect(v({ rediscovery_refresh_interval_days: 90, rediscovery_failed_retry_days: 31 })).not.toBeNull()
    expect(v({ rediscovery_failed_retry_days: NaN })).not.toBeNull()
  })
  it("cross-field: failed retry must not exceed refresh interval", () => {
    expect(v({ rediscovery_refresh_interval_days: 7, rediscovery_failed_retry_days: 7 })).toBeNull()
    expect(v({ rediscovery_refresh_interval_days: 7, rediscovery_failed_retry_days: 8 })).toMatch(CROSS)
    // lowering the refresh interval below the retry is the other direction
    expect(v({ rediscovery_refresh_interval_days: 3, rediscovery_failed_retry_days: 3 })).toBeNull()
    expect(v({ rediscovery_refresh_interval_days: 2, rediscovery_failed_retry_days: 3 })).toMatch(CROSS)
  })
})
