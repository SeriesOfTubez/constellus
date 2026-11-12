import { ChevronDown, ChevronRight } from "lucide-react"
import type { JobRun, JobStatus } from "@/lib/api"
import { cadenceText, cadenceUtcText, finishReasonText, formatDuration, isProblem, isSubHour, jobLabel, missedSlotsText, runCountsText, SUB_HOUR_NOTE } from "@/lib/jobRuns"
import { formatExactTime, relativeTime } from "@/lib/time"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"

const reasonClass = (reason: string) =>
  isProblem(reason) ? "text-amber-600 dark:text-amber-400" : "text-muted-foreground"

export function JobStatusRow({ status, windowHours, expanded, onToggle }: {
  status: JobStatus
  windowHours: number
  expanded: boolean
  onToggle: () => void
}) {
  const last = status.last_run
  const subHour = isSubHour(status.cadence)
  const missed = missedSlotsText(status, windowHours)
  const Chevron = expanded ? ChevronDown : ChevronRight
  return (
    <div className="space-y-1">
      <div className="flex items-baseline gap-2">
        <span className="text-sm font-medium">{jobLabel(status.job)}</span>
        <span className="text-xs text-muted-foreground" title={cadenceUtcText(status.cadence) ?? undefined}>
          {cadenceText(status.cadence)}
        </span>
        {subHour && <span className="text-xs text-muted-foreground">· {SUB_HOUR_NOTE}</span>}
      </div>
      <p className="text-xs">
        {last ? (
          <>
            <span title={formatExactTime(last.started_at)}>{relativeTime(last.started_at)}</span>
            <span className="text-muted-foreground"> · {formatDuration(last.duration_seconds)} · </span>
            <span className={reasonClass(last.finish_reason)}>{finishReasonText(last.finish_reason, last.job)}</span>
          </>
        ) : (
          <span className="text-muted-foreground">{subHour ? "No tick has done work yet." : "No runs recorded yet."}</span>
        )}
      </p>
      {subHour && (
        <p className="text-xs text-muted-foreground">
          {status.last_tick_at ? (
            <>Last tick <span title={formatExactTime(status.last_tick_at)}>{relativeTime(status.last_tick_at)}</span> in this backend process</>
          ) : (
            <>No tick yet in this backend process</>
          )}
          <span title="Kept in memory, not in the run history; it resets when the backend restarts."> · resets on restart</span>
        </p>
      )}
      {status.missed_slots.length > 0 && (
        <p className="text-xs text-muted-foreground">
          {missed.text}
          {missed.overflow.length > 0 && (
            <span className="ml-1" title={missed.overflow.join(", ")}>+{missed.overflow.length}</span>
          )}
        </p>
      )}
      <Button type="button" variant="ghost" size="sm" className="h-7 px-1 text-xs" aria-expanded={expanded} onClick={onToggle}>
        <Chevron className="h-3 w-3 mr-1" />
        {expanded ? "Hide recent runs" : "Recent runs"}
      </Button>
    </div>
  )
}

export function JobRunsList({ runs, isLoading }: { runs: JobRun[] | undefined; isLoading: boolean }) {
  if (isLoading || !runs) return <Skeleton className="h-16" />
  if (runs.length === 0)
    return <p className="text-xs text-muted-foreground">No runs recorded in the retention window.</p>
  return (
    <ul className="divide-y rounded border text-xs">
      {runs.map((r) => {
        const counts = runCountsText(r)
        return (
        <li key={r.id} className="px-3 py-2 space-y-0.5">
          <div>
            <span title={formatExactTime(r.started_at)}>{relativeTime(r.started_at)}</span>
            <span className="text-muted-foreground"> · {formatDuration(r.duration_seconds)}</span>
          </div>
          <div className={reasonClass(r.finish_reason)}>{finishReasonText(r.finish_reason, r.job)}</div>
          {counts && <div className="text-muted-foreground">{counts}</div>}
        </li>
        )
      })}
    </ul>
  )
}
