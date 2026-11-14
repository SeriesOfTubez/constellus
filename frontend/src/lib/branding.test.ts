import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { ACCENT_PALETTE, BRANDING_DEFAULTS, applyBranding } from "./branding"

describe("ACCENT_PALETTE", () => {
  it("is the curated four, well formed and unique", () => {
    expect(ACCENT_PALETTE).toHaveLength(4)
    for (const p of ACCENT_PALETTE) expect(p.value).toMatch(/^#[0-9a-f]{6}$/)
    expect(new Set(ACCENT_PALETTE.map((p) => p.value)).size).toBe(4)
    expect(new Set(ACCENT_PALETTE.map((p) => p.name)).size).toBe(4)
    expect(ACCENT_PALETTE.map((p) => p.value)).toContain(BRANDING_DEFAULTS.org_brand_accent)
  })
})

describe("applyBranding", () => {
  let calls: Record<string, string>

  beforeEach(() => {
    calls = {}
    globalThis.document = {
      documentElement: {
        style: {
          setProperty: (k: string, v: string) => {
            calls[k] = v
          },
        },
      },
    } as unknown as Document
  })

  afterEach(() => {
    delete (globalThis as { document?: Document }).document
  })

  it("derives every accent token from the cyan default", () => {
    applyBranding({ ...BRANDING_DEFAULTS, org_brand_accent: "#66d0df", org_name_color: null })
    expect(calls["--brand"]).toBe("#66d0df")
    expect(calls["--brand-dim"]).toBe("rgba(102, 208, 223, 0.1)")
    expect(calls["--logo-glow"]).toBe("#a3e3ec")
    expect(calls["--link"]).toBe("#7dd7e4")
    expect(calls["--primary"]).toBe("#66d0df")
    expect(calls["--ring"]).toBe("#66d0df")
    expect(calls["--org-name-color"]).toBe("#66d0df")
    expect(calls["--primary-foreground"]).toBeUndefined()
  })

  it("uses an explicit org name colour when set", () => {
    applyBranding({ ...BRANDING_DEFAULTS, org_brand_accent: "#66d0df", org_name_color: "#112233" })
    expect(calls["--org-name-color"]).toBe("#112233")
  })

  it("sets nothing for an invalid accent", () => {
    applyBranding({ ...BRANDING_DEFAULTS, org_brand_accent: "not-a-colour" })
    expect(Object.keys(calls).length).toBe(0)
  })
})
