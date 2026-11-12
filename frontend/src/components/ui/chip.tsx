import * as React from "react"
import { cn } from "@/lib/utils"

/**
 * The one chip (planning#337 slice 3, mockup D): 20px tall, 0 8px padding, 4px gap,
 * 4px radius, 12px text. Colour and weight live here too: neutral by default
 * (raised fill, line border, secondary text, weight 400). Severity chips opt in
 * through SEV_CHIP and are weight 600. Every chip, pill, tag, badge and count bubble
 * composes CHIP; gridscale.test.ts forbids the old hand-rolled geometry and any
 * Tailwind palette hue.
 */
export const CHIP =
  "inline-flex h-5 items-center gap-1 whitespace-nowrap rounded border border-border bg-secondary px-2 text-xs font-normal text-secondary-foreground"

/** Severity/health tones for chips. Written out as literals so Tailwind sees them. */
export const SEV_CHIP = {
  critical: "border-sev-critical/30 bg-sev-critical/15 font-semibold text-sev-critical",
  high: "border-sev-high/30 bg-sev-high/15 font-semibold text-sev-high",
  medium: "border-sev-medium/30 bg-sev-medium/15 font-semibold text-sev-medium",
  low: "border-sev-low/30 bg-sev-low/15 font-semibold text-sev-low",
  unknown: "border-sev-unknown/30 bg-sev-unknown/15 font-semibold text-sev-unknown",
  clean: "border-sev-clean/30 bg-sev-clean/15 font-semibold text-sev-clean",
} as const

export type SevTone = keyof typeof SEV_CHIP

export const Chip = React.forwardRef<HTMLSpanElement, React.HTMLAttributes<HTMLSpanElement>>(
  ({ className, ...props }, ref) => <span ref={ref} className={cn(CHIP, className)} {...props} />,
)
Chip.displayName = "Chip"
