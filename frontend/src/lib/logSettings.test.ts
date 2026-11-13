import { describe, expect, it } from "vitest"
import type { LogQueueSettings } from "@/lib/api"
import { queueRestartNote, validateLogQueueSettings, type LogQueueDraft } from "@/lib/logSettings"

const QMSG = "Lines held in memory must be a whole number from 1,000 to 100,000."
const BMSG = "Lines per write must be a whole number from 10 to 1,000."
const FMSG = "Longest wait before a write must be a number from 0.2 to 10 seconds."
const ok: LogQueueDraft = { queue_max_records: 10000, batch_max_records: 200, flush_interval_s: 1 }
const v = (over: Partial<LogQueueDraft>) => validateLogQueueSettings({ ...ok, ...over })

describe("validateLogQueueSettings", () => {
  it("accepts the defaults", () => expect(validateLogQueueSettings(ok)).toBeNull())
  it("checks queue_max_records", () => {
    expect(v({ queue_max_records: 1000 })).toBeNull()
    expect(v({ queue_max_records: 100000 })).toBeNull()
    expect(v({ queue_max_records: 999 })).toBe(QMSG)
    expect(v({ queue_max_records: 100001 })).toBe(QMSG)
    expect(v({ queue_max_records: 1500.5 })).toBe(QMSG)
    expect(v({ queue_max_records: NaN })).toBe(QMSG)
  })
  it("checks batch_max_records", () => {
    expect(v({ batch_max_records: 10 })).toBeNull()
    expect(v({ batch_max_records: 1000 })).toBeNull()
    expect(v({ batch_max_records: 9 })).toBe(BMSG)
    expect(v({ batch_max_records: 1001 })).toBe(BMSG)
    expect(v({ batch_max_records: 20.5 })).toBe(BMSG)
    expect(v({ batch_max_records: NaN })).toBe(BMSG)
  })
  it("checks flush_interval_s", () => {
    expect(v({ flush_interval_s: 0.2 })).toBeNull()
    expect(v({ flush_interval_s: 10 })).toBeNull()
    expect(v({ flush_interval_s: 0.25 })).toBeNull()
    expect(v({ flush_interval_s: 0.19 })).toBe(FMSG)
    expect(v({ flush_interval_s: 10.01 })).toBe(FMSG)
    expect(v({ flush_interval_s: NaN })).toBe(FMSG)
  })
  it("reports the first error in field order", () => {
    expect(v({ queue_max_records: 5, batch_max_records: 5, flush_interval_s: 99 })).toBe(QMSG)
    expect(v({ batch_max_records: 5, flush_interval_s: 99 })).toBe(BMSG)
  })
})

describe("queueRestartNote", () => {
  const s = (active: number, stored: number): LogQueueSettings => ({
    queue_max_records: stored, batch_max_records: 200, flush_interval_s: 1, queue_max_records_active: active,
  })
  it("is null when the running bound matches", () => expect(queueRestartNote(s(10000, 10000))).toBeNull())
  it("names the running bound when it differs", () => {
    expect(queueRestartNote(s(10000, 50000))).toBe("Running with 10,000 until the backend restarts.")
  })
})
