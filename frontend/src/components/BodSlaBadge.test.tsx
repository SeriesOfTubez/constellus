import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { TooltipProvider } from "@/components/ui/tooltip"
import { BodSlaBadge, bodSlaTooltip } from "@/components/finding-badges"
import type { Finding } from "@/lib/api"

type Sla = NonNullable<Finding["bod_sla"]>

const sla = (over: Partial<Sla> = {}): Sla => ({
  window: "3d", forensic_triage: false, due_date: "2026-11-22", days_remaining: 3, overdue: false, ...over,
})
const label = (s: Sla) =>
  renderToStaticMarkup(<TooltipProvider><BodSlaBadge finding={{ bod_sla: s } as Finding} /></TooltipProvider>)
    .replace(/<[^>]+>/g, "")

// planning#381: the date is ours (first-seen clock, BOD 26-04 windows), so
// nothing on the badge may call it the BOD 26-04 deadline.
describe("BodSlaBadge", () => {
  it("labels the fix window, not the directive", () => {
    expect(label(sla({ overdue: true, days_remaining: -2 }))).toBe("Fix: 3d · overdue")
    expect(label(sla({ window: "14d", days_remaining: 9 }))).toBe("Fix: 14d · 9d left")
    expect(label(sla({ window: "3d+triage", forensic_triage: true, days_remaining: 0 }))).toBe("Fix: 3d · due today + triage")
    expect(label(sla({ window: "upgrade", due_date: null, days_remaining: null }))).toBe("Fix: fix on upgrade")
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
