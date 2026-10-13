import { describe, expect, it } from "vitest"
import { digestHourWarning, validBaseUrl, validDigestHour } from "@/lib/digestSettings"

describe("digestHourWarning", () => {
  it("warns at 2 and 3 with distinct messages", () => {
    expect(digestHourWarning(2)).toContain("Monitoring scans run at 02:00 UTC")
    expect(digestHourWarning(3)).toContain("The nightly re-score runs at 03:00 UTC")
  })
  it("is null elsewhere", () => {
    for (const h of [0, 7, 23]) expect(digestHourWarning(h)).toBeNull()
  })
})

describe("validBaseUrl", () => {
  it("accepts empty and http(s) URLs", () => {
    expect(validBaseUrl("")).toBe(true)
    expect(validBaseUrl("https://easm.example.com")).toBe(true)
    expect(validBaseUrl("http://192.0.2.10:8080/app")).toBe(true)
  })
  it("rejects other schemes, bare scheme and over-long values", () => {
    expect(validBaseUrl("javascript:alert(1)")).toBe(false)
    expect(validBaseUrl("ftp://x")).toBe(false)
    expect(validBaseUrl("https://")).toBe(false)
    expect(validBaseUrl("https://" + "a".repeat(193))).toBe(false) // 201 chars
    expect(validBaseUrl("https://" + "a".repeat(192))).toBe(true) // 200 chars
  })
  it("rejects userinfo in the host", () => {
    expect(validBaseUrl("https://user@evil.example")).toBe(false)
    expect(validBaseUrl("https://user:pw@evil.example/a")).toBe(false)
    expect(validBaseUrl("http://@evil.example")).toBe(false)
  })
})

describe("validDigestHour", () => {
  it("accepts integers 0-23 only", () => {
    expect(validDigestHour(0)).toBe(true)
    expect(validDigestHour(23)).toBe(true)
    expect(validDigestHour(24)).toBe(false)
    expect(validDigestHour(-1)).toBe(false)
    expect(validDigestHour(1.5)).toBe(false)
    expect(validDigestHour(NaN)).toBe(false)
  })
})
