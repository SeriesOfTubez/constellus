import type { ExposureHopStatus } from "@/lib/api"
import { cn } from "@/lib/utils"

const SHAPE: Record<ExposureHopStatus, string> = {
  observed: "size-2 rounded-full bg-foreground",
  derived: "size-2 rounded-full border border-foreground",
  unknown: "size-2 rounded-full border border-dashed border-muted-foreground",
  not_applicable: "h-px w-2 bg-muted-foreground",
}

export function HopMarker({ status, diamond }: { status: ExposureHopStatus; diamond?: boolean }) {
  return (
    <span
      aria-hidden="true"
      data-status={status}
      className={cn("inline-block shrink-0", diamond ? "size-2 rotate-45 rounded-none bg-foreground" : SHAPE[status])}
    />
  )
}
