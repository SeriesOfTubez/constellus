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
    const chip = /export const CHIP =\s*"([^"]*)"/.exec(text)?.[1] ?? ""
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

describe("spacing on the 4px grid (planning#337 slice 3)", () => {
  const SPACING = "(?:p|px|py|pt|pb|pl|pr|m|mx|my|mt|mb|ml|mr|gap|gap-x|gap-y|space-x|space-y)"

  it("has no spacing half-step (variant prefixes and negatives included)", () => {
    expect(hits(new RegExp("(?:^|[\\s\"`':])-?" + SPACING + "-\\d+\\.5\\b", "g"))).toEqual([])
  })

  it("has no arbitrary pixel spacing", () => {
    expect(hits(new RegExp("\\b" + SPACING + "-\\[\\d+px\\]", "g"))).toEqual([])
  })

  it("keeps inline code at a flat vertical padding (py-0)", () => {
    expect(hits(/<code\b[^>]*\bpy-(?!0\b)\d+\b/g)).toEqual([])
  })
})

describe("chip colour and weight (planning#337 slice 3)", () => {
  const read = (rel: string) => fs.readFileSync(path.join(SRC, rel), "utf8")
  const HUE_CLASS = new RegExp(
    "\\b(?:bg|text|border|ring|from|to|via|fill|stroke|divide|outline|decoration)(?:-[trblxy])?-" +
      "(?:red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose|slate|gray|zinc|neutral|stone)-\\d{2,3}\\b",
    "g",
  )

  it("has no Tailwind palette hue colour class anywhere in src (tokens only)", () => {
    // The scan covers every .ts/.tsx under src, tests included; only this file is excluded.
    expect(files.length).toBeGreaterThan(100)
    expect(sources.some((s) => s.file === "components/ui/chip.tsx")).toBe(true)
    expect(sources.some((s) => s.file === "components/ScheduledJobsParts.test.tsx")).toBe(true)
    expect(hits(HUE_CLASS)).toEqual([])
  })

  it("makes CHIP neutral, weight 400, by default", () => {
    const chip = /export const CHIP =\s*"([^"]*)"/.exec(read("components/ui/chip.tsx"))?.[1] ?? ""
    for (const token of ["bg-secondary", "text-secondary-foreground", "border-border", "font-normal"]) {
      expect(chip.split(/\s+/)).toContain(token)
    }
  })

  it("defines SEV_CHIP with exactly the six tones, each on its own token and semibold", async () => {
    const { SEV_CHIP } = await import("@/components/ui/chip")
    expect(Object.keys(SEV_CHIP).sort()).toEqual(["clean", "critical", "high", "low", "medium", "unknown"])
    for (const [tone, cls] of Object.entries(SEV_CHIP)) {
      const tokens = cls.split(/\s+/)
      expect(tokens).toContain(`bg-sev-${tone}/15`)
      expect(tokens).toContain(`text-sev-${tone}`)
      expect(tokens).toContain(`border-sev-${tone}/30`)
      expect(tokens).toContain("font-semibold")
    }
  })

  it("never gives a chip font-medium or font-bold on the line that composes CHIP", () => {
    const offenders = sources.flatMap((s) =>
      s.text.split("\n")
        .map((line, i) => ({ line, n: i + 1 }))
        .filter(({ line }) => (line.includes("cn(CHIP") || line.includes("CHIP +")) && /\bfont-(medium|bold)\b/.test(line))
        .map(({ n }) => `${s.file}:${n}`),
    )
    expect(offenders).toEqual([])
  })

  it("draws the Logo from the brand tokens, not hard-coded blues", () => {
    const logo = read("components/Logo.tsx")
    for (const gone of ["#60a5fa", "#06b6d4", "blue-400", "cyan-400"]) expect(logo).not.toContain(gone)
    // Wordmark gradient and SVG stops each name both tokens.
    for (const kept of ["from-(--brand)", "to-(--logo-glow)", 'stopColor: "var(--brand)"', 'stopColor: "var(--logo-glow)"']) {
      expect(logo).toContain(kept)
    }
  })

  it("points the Badge success and warning variants at the sev tokens", () => {
    const badge = read("components/ui/badge.tsx")
    expect(/success:\s*"[^"]*sev-clean/.test(badge)).toBe(true)
    expect(/warning:\s*"[^"]*sev-medium/.test(badge)).toBe(true)
  })
})

describe("loading states and menu origin (planning#337 slice 3)", () => {
  const read = (rel: string) => fs.readFileSync(path.join(SRC, rel), "utf8")
  const nonTest = sources.filter((s) => !/\.test\.tsx?$/.test(s.file))

  it("has no JSX text node that is just a loading word (use Skeleton)", () => {
    expect(nonTest.length).toBeGreaterThan(100)
    const found = nonTest.flatMap((s) => [...s.text.matchAll(/>\s*Loading[^<{]*</g)].map((m) => `${s.file}: ${m[0]}`))
    expect(found).toEqual([])
  })

  it("keeps Skeleton as the loading idiom in at least 30 files", () => {
    expect(nonTest.filter((s) => s.text.includes("<Skeleton")).length).toBeGreaterThanOrEqual(30)
  })

  it("gives every aria-label=\"Loading\" region a Skeleton and role=status", () => {
    const labelled = nonTest.filter((s) => s.text.includes('aria-label="Loading"'))
    expect(labelled.length).toBeGreaterThan(0)
    for (const s of labelled) {
      expect(s.text, s.file).toContain("<Skeleton")
      expect(s.text, s.file).toContain('role="status"')
    }
  })

  it("makes Radix floating content scale from its trigger", () => {
    const count = (text: string, needle: string) => text.split(needle).length - 1
    expect(count(read("components/ui/dropdown-menu.tsx"), "origin-(--radix-dropdown-menu-content-transform-origin)")).toBe(2)
    expect(count(read("components/ui/select.tsx"), "origin-(--radix-select-content-transform-origin)")).toBe(1)
    expect(count(read("components/ui/tooltip.tsx"), "origin-(--radix-tooltip-content-transform-origin)")).toBe(1)
  })
})
