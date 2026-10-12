import { Link } from "react-router-dom"
import { hopSummary, refusedReasonText, type RedirectHop } from "@/lib/redirectChain"

const TITLE_TIP = "Page title of the redirect destination, not of this endpoint"

/** planning#271 — quiet one-line-per-hop redirect chain. All text is plain text;
 *  the hop URL is attacker-controllable so it is never an href to the URL itself. */
export function RedirectChain({ chain, compact }: { chain: RedirectHop[]; compact?: boolean }) {
  if (chain.length === 0) return null
  return (
    <div className={compact ? "text-[10px] text-muted-foreground/80" : "text-xs text-muted-foreground"}>
      {chain.map((hop, i) => {
        const url = hop.hop_asset_id ? (
          <Link
            to={`/assets/${hop.hop_asset_id}`}
            className="font-mono truncate hover:text-foreground hover:underline"
            title={`${hop.url} (open the destination's asset)`}
          >
            {hop.url}
          </Link>
        ) : (
          <span className="font-mono truncate" title={hop.url}>{hop.url}</span>
        )
        const summary = hopSummary(hop)
        return (
          <div key={hop.hop_index} className="flex items-baseline gap-1 min-w-0">
            <span className="shrink-0">{i === 0 ? "Redirects to" : "then"}</span>
            {url}
            {summary && <span className="shrink-0">{" → "}</span>}
            {hop.followed ? (
              <>
                {hop.http_status != null && <span className="shrink-0">{hop.http_status}</span>}
                {hop.http_status != null && hop.http_title && <span className="shrink-0">·</span>}
                {hop.http_title && <span className="truncate" title={TITLE_TIP}>{hop.http_title}</span>}
              </>
            ) : (
              <>
                <span className="shrink-0">Not followed:</span>
                <span className="truncate" title={`Rule: ${hop.reason}`}>{refusedReasonText(hop.reason ?? "")}</span>
              </>
            )}
          </div>
        )
      })}
    </div>
  )
}
