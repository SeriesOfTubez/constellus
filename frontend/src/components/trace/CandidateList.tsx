import { useState } from "react"
import { Link } from "react-router-dom"
import type { ExposureHopCandidate } from "@/lib/api"
import { candidateMeta } from "@/lib/trace"
import { MORE_EXIST } from "./EvidenceList"

const SHOWN = 5

export function CandidateList({ candidates, truncated }: { candidates: ExposureHopCandidate[]; truncated: boolean }) {
  const [all, setAll] = useState(false)
  const rows = all ? candidates : candidates.slice(0, SHOWN)
  const hidden = candidates.length - SHOWN
  return (
    <div className="space-y-1">
      <ul className="space-y-1">
        {rows.map((c) => {
          const meta = candidateMeta(c).join(" · ")
          return (
            <li key={c.asset_id} className="text-sm">
              <Link to={`/assets/${c.asset_id}`} className="font-mono break-all text-link hover:underline">{c.value}</Link>
              {meta && <span className="ml-2 text-xs text-muted-foreground">{meta}</span>}
            </li>
          )
        })}
      </ul>
      {hidden > 0 && !all && (
        <button
          type="button"
          aria-expanded={false}
          onClick={() => setAll(true)}
          className="text-xs text-muted-foreground hover:text-foreground rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {`Show all ${candidates.length}`}
        </button>
      )}
      {/* Only once every listed candidate is on screen: beside "Show all" it would read as the whole list. */}
      {truncated && (all || hidden <= 0) && <p className="text-xs text-muted-foreground">{MORE_EXIST}</p>}
    </div>
  )
}
