import { useState, type ReactNode } from "react"
import { ChevronDown, ChevronRight } from "lucide-react"
import type { Segment } from "@/lib/trace"
import { CHIP } from "@/components/ui/chip"
import { cn } from "@/lib/utils"

export function ChainRow({ segments, chip, defaultOpen, children }: {
  segments: Segment[]
  chip?: string | null
  defaultOpen: boolean
  children: ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="rounded-lg border bg-card">
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="px-4 py-3 flex w-full items-center gap-3 rounded-lg text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {open
          ? <ChevronDown className="size-3.5 shrink-0 text-muted-foreground" />
          : <ChevronRight className="size-3.5 shrink-0 text-muted-foreground" />}
        <span className="flex min-w-0 flex-1 flex-wrap items-center gap-x-2 gap-y-1">
          {segments.map((s, i) => (
            <span key={i} className="inline-flex items-center gap-x-2">
              {i > 0 && <span aria-hidden="true" className="text-sm text-muted-foreground">→</span>}
              <span className={cn("text-sm", s.mono && "font-mono break-all", s.missing && "text-muted-foreground")}>
                {s.text}
              </span>
            </span>
          ))}
        </span>
        {chip && <span className={cn(CHIP, "ml-auto shrink-0")}>{chip}</span>}
      </button>
      {open && <div className="border-t px-4 py-4">{children}</div>}
    </div>
  )
}
