/// <reference types="node" />
import { describe, expect, it } from "vitest"
import fs from "node:fs"
import path from "node:path"

// planning#337 slice 3: every call site sits on the four-step type scale
// (12 / 13 / 15 / 20) plus one display token for the dashboard's hero numbers.
// This test keeps it that way: no arbitrary pixel sizes, no off-scale Tailwind
// steps, display on the dashboard only.

const SRC = path.resolve(__dirname, "..")
const ROOT = path.resolve(__dirname, "../..")
const SELF = path.resolve(__filename)

function walk(dir: string): string[] {
  const out: string[] = []
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name !== "node_modules") out.push(...walk(full))
    } else if (/\.(ts|tsx)$/.test(entry.name)) {
      out.push(full)
    }
  }
  return out
}

const files = walk(SRC).filter((f) => f !== SELF)
const sources = files.map((f) => ({ file: path.relative(SRC, f).split(path.sep).join("/"), text: fs.readFileSync(f, "utf8") }))

function hits(re: RegExp): string[] {
  return sources.flatMap((s) => [...s.text.matchAll(re)].map((m) => `${s.file}: ${m[0]}`))
}

describe("type scale (planning#337)", () => {
  it("scans the real source tree", () => {
    expect(files.length).toBeGreaterThan(100)
    expect(sources.some((s) => s.file === "pages/Findings.tsx")).toBe(true)
    expect(sources.some((s) => s.file === "components/finding-badges.tsx")).toBe(true)
  })

  it("has no arbitrary pixel text size", () => {
    expect(hits(/\btext-\[\d+px\]/g)).toEqual([])
  })

  it("uses only the four text steps plus the display token", () => {
    expect(hits(/\b(?:[a-z]+:)?text-(?:lg|2xl|3xl|4xl|5xl|6xl)\b/g)).toEqual([])
  })

  it("has no SVG or inline font size under 12px", () => {
    // The class sweep cannot see fontSize="9" on an <svg> <text> or fontSize: 10 in a
    // style object; the dashboard gauge and the EPSS sparkline had both.
    const small = sources.flatMap((s) =>
      [...s.text.matchAll(/\bfontSize\s*[:=]\s*["'{]?\s*"?(\d+)(?:px)?\b/g)]
        .filter((m) => Number(m[1]) < 12)
        .map((m) => `${s.file}: ${m[0]}`),
    )
    expect(small).toEqual([])
  })

  it("keeps the display size on the dashboard only", () => {
    const users = sources.filter((s) => /\btext-display\b/.test(s.text)).map((s) => s.file)
    expect(users).toEqual(["pages/Dashboard.tsx"])
  })

  it("declares the scale in index.css", () => {
    const css = fs.readFileSync(path.join(SRC, "index.css"), "utf8")
    expect(css).toMatch(/--text-sm:\s*13px/)
    expect(css).toMatch(/--text-base:\s*15px/)
    expect(css).toMatch(/--text-display:\s*24px/)
    expect(css).toMatch(/--text-display--line-height:\s*28px/)
  })

  it("no longer declares @radix-ui/react-toast", () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> }
    expect({ ...pkg.dependencies, ...pkg.devDependencies }).not.toHaveProperty("@radix-ui/react-toast")
  })
})
