/// <reference types="node" />
import { describe, expect, it } from "vitest"
import fs from "node:fs"
import path from "node:path"

// planning#337 slice 3: icons sit on two sizes (14px inline, 16px in a control) and
// every chip composes the one CHIP geometry. This test keeps both true: no
// hand-rolled h-N w-N pairs, no off-grid icon sizes, no old pill geometry.

const SRC = path.resolve(__dirname, "..")
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

describe("icon and chip geometry (planning#337 slice 3)", () => {
  it("scans the real source tree", () => {
    expect(files.length).toBeGreaterThan(100)
    expect(sources.some((s) => s.file === "pages/Findings.tsx")).toBe(true)
    expect(sources.some((s) => s.file === "components/finding-badges.tsx")).toBe(true)
  })

  it("has no h-N w-N or w-N h-N pair on the icon sizes (use size-N)", () => {
    expect(hits(/\b[hw]-(2\.5|3|3\.5|4) [hw]-\1\b/g)).toEqual([])
  })

  it("has no size-2.5, and size-3 only on the timeline dot", () => {
    const users = hits(/\bsize-(2\.5|3)\b(?!\.)/g).map((h) => h.split(":")[0]).sort()
    expect(users).toEqual(["components/OrgAcquisitionParts.test.tsx", "components/OrgAcquisitionParts.tsx"])
  })

  it("has no [&_svg]:h- or [&_svg]:w- (use [&_svg]:size-*)", () => {
    expect(hits(/\[&_svg\]:[hw]-/g)).toEqual([])
  })

  it("declares the chip geometry in components/ui/chip.tsx", () => {
    const text = fs.readFileSync(path.join(SRC, "components/ui/chip.tsx"), "utf8")
    const chip = /export const CHIP = "([^"]*)"/.exec(text)?.[1] ?? ""
    for (const token of ["inline-flex", "h-5", "items-center", "gap-1", "whitespace-nowrap", "px-2", "text-xs"]) {
      expect(chip.split(/\s+/)).toContain(token)
    }
    expect(chip).toMatch(/\brounded(?![-\w])/)
    expect(chip).not.toMatch(/py-/)
  })

  it("has no class string with the old chip geometry", () => {
    expect(hits(/["`][^"`\n]*\binline-flex\b[^"`\n]*\bpy-0\.5\b/g)).toEqual([])
    expect(hits(/["`][^"`\n]*\bpy-0\.5\b[^"`\n]*\binline-flex\b/g)).toEqual([])
    expect(hits(/\brounded-full\b[^"`\n]*\bpy-0\.5\b/g)).toEqual([])
    expect(hits(/\bpy-0\.5\b[^"`\n]*\brounded-full\b/g)).toEqual([])
  })

  it("composes CHIP in at least 20 files", () => {
    const users = sources.filter((s) => /\bcn\(CHIP\b/.test(s.text)).map((s) => s.file)
    expect(users.length).toBeGreaterThanOrEqual(20)
  })
})
