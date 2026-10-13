import { Link } from "react-router-dom"
import type { AlertDelivery, AlertDispatch } from "@/lib/api"
import { SeverityBadge } from "@/components/finding-badges"
import { relativeTime } from "@/lib/time"

/** Plain-words delivery outcome. Unknown outcomes fall back to the raw string. */
export function deliveryLabel(d: { outcome: string; connector_id: string | null; recipient_count: number }): string {
  const via = d.connector_id ?? "unknown connector"
  switch (d.outcome) {
    case "sent":
      return `Sent via ${via} (${d.recipient_count} recipient${d.recipient_count === 1 ? "" : "s"})`
    case "failed":
      return `Send failed (${via})`
    case "raised":
      return `Send error (${via})`
    case "no_channel":
      return "Not sent: no notification channel enabled"
    case "no_recipients":
      return "Not sent: rule has no recipients"
    default:
      return d.outcome
  }
}

function deliveryTone(d: AlertDelivery): string {
  if (d.outcome === "failed" || d.outcome === "raised") return "text-destructive"
  return d.outcome === "sent" ? "text-foreground" : "text-muted-foreground"
}

const SHOWN_EVENTS = 2

export function AlertHistoryList({ dispatches }: { dispatches: AlertDispatch[] }) {
  if (dispatches.length === 0) {
    return <p className="text-sm text-muted-foreground">No alerts recorded yet.</p>
  }
  return (
    <div className="rounded-md border divide-y">
      {dispatches.map(d => {
        const shown = d.events.slice(0, SHOWN_EVENTS)
        const more = d.event_count - shown.length
        return (
          <div key={d.id} className="flex items-start gap-3 px-3 py-2.5 text-sm">
            <div className="w-44 shrink-0 min-w-0">
              <p className="font-medium truncate">{d.rule_name}</p>
              <p className="text-xs text-muted-foreground">
                {d.kind === "promotion" ? "Risk escalation" : "New findings"} · {relativeTime(d.created_at)}
              </p>
            </div>
            <div className="flex-1 min-w-0 space-y-1">
              {shown.map(e => (
                <div key={e.finding_id} className="flex items-center gap-2 min-w-0">
                  {e.severity && <SeverityBadge severity={e.severity} />}
                  <Link to={`/findings?id=${e.finding_id}`} className="truncate hover:underline">
                    {e.title}
                  </Link>
                  <span className="text-xs text-muted-foreground truncate">{e.asset_value}</span>
                </div>
              ))}
              {more > 0 && <span className="text-xs text-muted-foreground">+{more}</span>}
            </div>
            <div className="w-64 shrink-0 space-y-0.5 text-xs">
              {d.deliveries.map((dl, i) => (
                <p key={i} className={deliveryTone(dl)}>{deliveryLabel(dl)}</p>
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}
