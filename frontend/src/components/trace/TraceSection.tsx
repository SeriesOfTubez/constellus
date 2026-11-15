import type { ReactNode } from "react"
import { cn } from "@/lib/utils"

export function TraceSection({ number, question, last, children }: {
  number: number
  question: string
  last?: boolean
  children: ReactNode
}) {
  return (
    <div className="grid grid-cols-[24px_minmax(0,1fr)] gap-4">
      <div className="flex flex-col items-center">
        <span className="flex size-6 items-center justify-center rounded-full border bg-secondary text-xs font-semibold text-secondary-foreground">
          {number}
        </span>
        {!last && <span className="w-px flex-1 bg-border my-2" aria-hidden="true" />}
      </div>
      <div className={cn("min-w-0 space-y-3", !last && "pb-8")}>
        <h2 className="text-base font-semibold tracking-title">{question}</h2>
        {children}
      </div>
    </div>
  )
}
