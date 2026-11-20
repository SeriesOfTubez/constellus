import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { TooltipProvider } from "@/components/ui/tooltip"
import { BodSlaBadge, bodSlaTooltip } from "@/components/finding-badges"
import type { Finding } from "@/lib/api"

type Sla = NonNullable<Finding["bod_sla"]>

const sla = (over: Partial<Sla> = {}): Sla => ({
  window: "3d", forensic_triage: false, due_date: "2026-11-22", days_remaining: 3, overdue: false, ...over,
})
const render = (s: Sla) =>
  renderToStaticMarkup(<TooltipProvider><BodSlaBadge finding={{ bod_sla: s } as Finding} /></TooltipProvider>)
// The chip's whole text, bounded by its tags.
const chip = (text: string) => `>${text}<`

// planning#381: the date is ours (first-seen clock, BOD 26-04 windows), so
// nothing on the badge may call it the BOD 26-04 deadline.
describe("BodSlaBadge", () => {
  it("labels the fix window, not the directive", () => {
    expect(render(sla())).not.toContain("BOD")
    expect(render(sla({ overdue: true, days_remaining: -2 }))).toContain(chip("Fix: 3d · overdue"))
    expect(render(sla({ window: "14d", days_remaining: 9 }))).toContain(chip("Fix: 14d · 9d left"))
    expect(render(sla({ window: "3d+triage", forensic_triage: true, days_remaining: 0 }))).toContain(chip("Fix: 3d · due today + triage"))
    expect(render(sla({ window: "upgrade", due_date: null, days_remaining: null }))).toContain(chip("Fix: fix on upgrade"))
  })

  it("explains the window and the clock in the tooltip", () => {
    expect(bodSlaTooltip(sla())).toBe(
      "3-day fix window (from BOD 26-04 Table 1), counted from first seen. Due: 2026-11-22")
    expect(bodSlaTooltip(sla({ window: "60d" }))).toBe(
      "60-day fix window (from BOD 26-04 Table 1), counted from first seen. Due: 2026-11-22")
    expect(bodSlaTooltip(sla({ window: "3d+triage", forensic_triage: true }))).toBe(
      "3-day fix window plus forensic triage (from BOD 26-04 Table 1), counted from first seen. Due: 2026-11-22")
    expect(bodSlaTooltip(sla({ window: "upgrade", due_date: null, days_remaining: null }))).toBe(
      "No fixed date: fix in the next upgrade cycle (BOD 26-04 Table 1).")
  })
})
