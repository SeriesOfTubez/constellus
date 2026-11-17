import type { TimelineEvent } from "@/lib/api"
import { gapText, onlyFirstSeen, sameDay, secondLines, timelineDate, timelineLabel, utcToday } from "@/lib/findingTimeline"
import { cn } from "@/lib/utils"
import { TraceSection } from "./TraceSection"

// Ours = the events that are about our own scope, so they carry the strong dot.
const OURS = new Set<TimelineEvent["kind"]>(["acquired", "claimed", "ownership_confirmed"])

function Dot({ kind }: { kind: TimelineEvent["kind"] }) {
  return (
    <span className="flex h-5 items-center" aria-hidden="true">
      <span
        className={cn(
          "size-2 rounded-full",
          kind === "due" ? "border-2 border-sev-high bg-transparent" : OURS.has(kind) ? "bg-foreground" : "bg-muted-foreground",
        )}
      />
    </span>
  )
}

// One spine cell per row: a dot (events only) and a line down to the next row.
function Spine({ kind, line }: { kind?: TimelineEvent["kind"]; line: boolean }) {
  return (
    <div className="flex flex-col items-center">
      {kind ? <Dot kind={kind} /> : null}
      {line && <span className="w-px flex-1 bg-border" aria-hidden="true" />}
    </div>
  )
}

export function TimelineQuestion({ events, today = utcToday() }: { events: TimelineEvent[] | undefined; today?: string }) {
  if (events === undefined) return null
  return (
    <TraceSection number={3} question="How long has this been open?" last>
      {events.length === 0 ? (
        <p className="text-sm text-muted-foreground">No dates are on record for this finding.</p>
      ) : (
        <ol aria-label="Timeline" className="grid grid-cols-[112px_16px_minmax(0,1fr)] gap-x-3">
          {events.map((e, i) => {
            const prev = i > 0 ? events[i - 1] : null
            const gap = prev ? gapText(prev, e) : null
            const lines = secondLines(e, today)
            const isLast = i === events.length - 1
            return (
              <li key={`${i}-${e.kind}`} className="contents">
                {gap && (
                  <>
                    <div />
                    <Spine line />
                    <p className="pb-2 font-mono text-xs text-muted-foreground">{gap}</p>
                  </>
                )}
                <p className="text-right font-mono text-xs leading-5 tabular-nums text-muted-foreground">
                  {prev && sameDay(prev, e) ? "" : timelineDate(e)}
                </p>
                <Spine kind={e.kind} line={!isLast} />
                <div className={cn("min-w-0", !isLast && "pb-2")}>
                  <p
                    className={cn(
                      "text-sm leading-5",
                      e.kind === "ownership_confirmed" && "font-semibold",
                      e.kind === "due" && "font-semibold text-sev-high",
                    )}
                  >
                    {timelineLabel(e)}
                  </p>
                  {lines.map((l, li) => (
                    <p key={li} className="text-xs text-muted-foreground">{l}</p>
                  ))}
                </div>
              </li>
            )
          })}
        </ol>
      )}
      {events.length > 0 && onlyFirstSeen(events) && (
        <p className="text-sm text-muted-foreground">
          No published, exploited, acquired, claimed or due date is on record for this finding.
        </p>
      )}
    </TraceSection>
  )
}
