import * as React from "react"
import { cn } from "@/lib/utils"

/**
 * The one chip geometry (planning#337 slice 3, mockup D): 20px tall, 0 8px padding,
 * 4px gap, 4px radius, 12px text. Colour and weight still come from the caller until
 * the chip-colour pass moves them here. Every chip, pill, tag, badge and count bubble
 * composes CHIP; gridscale.test.ts forbids the old hand-rolled geometry.
 */
export const CHIP = "inline-flex h-5 items-center gap-1 whitespace-nowrap rounded px-2 text-xs"

export const Chip = React.forwardRef<HTMLSpanElement, React.HTMLAttributes<HTMLSpanElement>>(
  ({ className, ...props }, ref) => <span ref={ref} className={cn(CHIP, className)} {...props} />,
)
Chip.displayName = "Chip"
