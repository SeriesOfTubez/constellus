import { describe, expect, it } from "vitest"
import type { CaptureSettings } from "@/lib/api"
import {
  bytesToKiB, kibToBytes, validUserAgent, validateCaptureSettings,
} from "@/lib/captureSettings"

const ok: CaptureSettings = {
  browse_revisit_days: 30, user_agent_mode: "stock", identifying_user_agent: "",
  max_image_bytes: 2097152, queue_timeout_seconds: 600,
  image_keep_count: 3, proxy_connect_timeout_seconds: 10,
  proxy_idle_timeout_seconds: 30, proxy_max_connections: 256,
}
const v = (o: Partial<CaptureSettings>) => validateCaptureSettings({ ...ok, ...o })

describe("KiB conversion", () => {
  it("converts both ways", () => {
    expect(bytesToKiB(2097152)).toBe(2048)
    expect(kibToBytes(64)).toBe(65536)
    expect(kibToBytes(8192)).toBe(8388608)
    expect(kibToBytes(bytesToKiB(123456 * 1024))).toBe(123456 * 1024)
  })
})

describe("validUserAgent", () => {
  it("enforces length and printable ASCII", () => {
    expect(validUserAgent("a".repeat(256))).toBe(true)
    expect(validUserAgent("a".repeat(257))).toBe(false)
    expect(validUserAgent(" ~")).toBe(true)
    expect(validUserAgent("a\nb")).toBe(false)
    expect(validUserAgent("café")).toBe(false)
    expect(validUserAgent("\x7f")).toBe(false)
    expect(validUserAgent("")).toBe(false)
  })
})

describe("validateCaptureSettings", () => {
  it("accepts defaults", () => expect(v({})).toBeNull())
  it("checks bounds edges", () => {
    expect(v({ browse_revisit_days: 1 })).toBeNull()
    expect(v({ browse_revisit_days: 365 })).toBeNull()
    expect(v({ browse_revisit_days: 0 })).not.toBeNull()
    expect(v({ browse_revisit_days: 366 })).not.toBeNull()
    expect(v({ browse_revisit_days: 1.5 })).not.toBeNull()
    expect(v({ browse_revisit_days: NaN })).not.toBeNull()
    expect(v({ max_image_bytes: 65536 })).toBeNull()
    expect(v({ max_image_bytes: 8388608 })).toBeNull()
    expect(v({ max_image_bytes: 65535 })).not.toBeNull()
    expect(v({ max_image_bytes: 8388609 })).not.toBeNull()
    expect(v({ queue_timeout_seconds: 60 })).toBeNull()
    expect(v({ queue_timeout_seconds: 3600 })).toBeNull()
    expect(v({ queue_timeout_seconds: 59 })).not.toBeNull()
    expect(v({ queue_timeout_seconds: 3601 })).not.toBeNull()
  })
  it("checks image_keep_count bounds", () => {
    expect(v({ image_keep_count: 1 })).toBeNull()
    expect(v({ image_keep_count: 50 })).toBeNull()
    expect(v({ image_keep_count: 0 })).toMatch(/Screenshots kept/)
    expect(v({ image_keep_count: 51 })).not.toBeNull()
    expect(v({ image_keep_count: 2.5 })).not.toBeNull()
    expect(v({ image_keep_count: NaN })).not.toBeNull()
  })
  it("checks proxy limit bounds", () => {
    expect(v({ proxy_connect_timeout_seconds: 1 })).toBeNull()
    expect(v({ proxy_connect_timeout_seconds: 60 })).toBeNull()
    expect(v({ proxy_connect_timeout_seconds: 0 })).toMatch(/connect timeout/)
    expect(v({ proxy_connect_timeout_seconds: 61 })).not.toBeNull()
    expect(v({ proxy_idle_timeout_seconds: 5 })).toBeNull()
    expect(v({ proxy_idle_timeout_seconds: 600 })).toBeNull()
    expect(v({ proxy_idle_timeout_seconds: 4 })).toMatch(/idle timeout/)
    expect(v({ proxy_idle_timeout_seconds: 601 })).not.toBeNull()
    expect(v({ proxy_max_connections: 1 })).toBeNull()
    expect(v({ proxy_max_connections: 1024 })).toBeNull()
    expect(v({ proxy_max_connections: 0 })).toMatch(/max connections/)
    expect(v({ proxy_max_connections: 1025 })).not.toBeNull()
    expect(v({ proxy_max_connections: NaN })).not.toBeNull()
  })
  it("cross-field: identifying needs a UA", () => {
    expect(v({ user_agent_mode: "identifying", identifying_user_agent: "" })).toMatch(/User-Agent/)
    expect(v({ user_agent_mode: "identifying", identifying_user_agent: "scanner/1.0" })).toBeNull()
  })
  it("a stored UA is still validated in stock mode, empty is fine", () => {
    expect(v({ user_agent_mode: "stock", identifying_user_agent: "x\ny" })).not.toBeNull()
    expect(v({ user_agent_mode: "stock", identifying_user_agent: "" })).toBeNull()
  })
})
