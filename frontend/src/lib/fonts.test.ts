/// <reference types="node" />
import { describe, expect, it } from "vitest"
import fs from "node:fs"
import path from "node:path"

const css = fs.readFileSync(path.resolve(__dirname, "../index.css"), "utf8")
const html = fs.readFileSync(path.resolve(__dirname, "../../index.html"), "utf8")
const fontsDir = path.resolve(__dirname, "../../public/fonts")

const fontFamilies = [...css.matchAll(/@font-face\s*\{[^}]*?font-family:\s*["']([^"']+)["']/g)].map((m) => m[1])
const fontFiles = [...new Set([...css.matchAll(/url\(\s*["']\/fonts\/([^"')]+)["']\s*\)/g)].map((m) => m[1]))]

describe("self-hosted fonts", () => {
  it("declares Geist and Geist Mono with exactly two font files", () => {
    expect(fontFamilies).toContain("Geist")
    expect(fontFamilies).toContain("Geist Mono")
    expect(fontFiles).toHaveLength(2)
  })

  it("ships real woff2 files for each reference", () => {
    for (const name of fontFiles) {
      const file = path.join(fontsDir, name)
      expect(fs.existsSync(file), name).toBe(true)
      expect(fs.statSync(file).size, name).toBeGreaterThan(10_000)
      const magic = fs.readFileSync(file).subarray(0, 4).toString("ascii")
      expect(magic, name).toBe("wOF2")
    }
  })

  it("preloads each font in index.html", () => {
    for (const name of fontFiles) {
      const tag = [...html.matchAll(/<link\b[^>]*>/g)]
        .map((m) => m[0])
        .find((t) => t.includes(`/fonts/${name}`))
      expect(tag, name).toBeDefined()
      expect(tag).toContain('rel="preload"')
      expect(tag).toContain('as="font"')
    }
  })

  it("includes the OFL license text", () => {
    const lic = path.join(fontsDir, "LICENSE-OFL.txt")
    expect(fs.existsSync(lic)).toBe(true)
    expect(fs.readFileSync(lic, "utf8")).toContain("SIL Open Font License")
  })

  it("has no CDN or external references", () => {
    for (const src of [css, html]) {
      expect(src).not.toMatch(/https?:\/\//)
      expect(src).not.toContain("googleapis")
      expect(src).not.toContain("gstatic")
    }
  })

  it("sets the font stacks to Geist", () => {
    expect(css).toMatch(/--font-sans:\s*["']?Geist\b/)
    expect(css).toMatch(/--font-mono:\s*["']?Geist Mono\b/)
  })

  it("keeps the six locked severity values verbatim", () => {
    const locked: Record<string, string> = {
      critical: "#f04267",
      high: "#ff8a3d",
      medium: "#f5c542",
      low: "#4a9eff",
      unknown: "#7b8290",
      clean: "#34d399",
    }
    for (const [name, hex] of Object.entries(locked)) {
      expect(css, name).toMatch(new RegExp(`--sev-${name}:\\s*${hex}`, "i"))
    }
  })
})
