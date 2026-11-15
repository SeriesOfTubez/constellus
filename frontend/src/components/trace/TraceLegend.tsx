import { TIER_LABEL } from "@/lib/organizations"
import { STATUS_LEGEND } from "@/lib/trace"
import { TierChip } from "@/components/OrgCandidateParts"
import { HopMarker } from "./HopMarker"

export function TraceLegend() {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-muted-foreground">
      {STATUS_LEGEND.map((e) => (
        <span key={e.status} title={e.meaning} className="inline-flex items-center gap-2">
          <HopMarker status={e.status} />
          {e.label}
        </span>
      ))}
      <span className="inline-flex items-center gap-2">
        Evidence tier
        {["strong", "supporting", "context"].map((t) => (
          <TierChip key={t} tier={t} label={TIER_LABEL[t]} />
        ))}
      </span>
    </div>
  )
}
