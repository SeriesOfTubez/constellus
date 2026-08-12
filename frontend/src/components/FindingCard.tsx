import { Sparkles, Clock } from "lucide-react"
import { type Finding } from "@/lib/api"
import { displayName } from "@/lib/apex"
import { relativeTime, isStale, daysSince } from "@/lib/time"
import {
  RiskBandBadge, SeverityBadge, CategoryBadge, StateBadge,
  EnrichmentBadges, ImpactClassBadge, BuildingVelocityBadge, ExposureOverrideBadge,
  findingTitle,
} from "@/components/finding-badges"
import { FindingActionsMenu } from "@/components/FindingActionsMenu"
import { TagBadge } from "@/components/ui/tag-badge"

const NEW_FINDING_DAYS = 7

/** Compact rich finding card — the card-view counterpart of a Findings table row.
 *  Clicking opens the finding flyout (same as a row click). The "more" menu sits
 *  in the header row and stops propagation so it doesn't also open the flyout. */
export function FindingCard({
  finding: f,
  onClick,
  selected,
  onAcknowledge,
  onSuppress,
  onVerify,
  onReopen,
  verifyPending,
  statePending,
}: {
  finding: Finding
  onClick: () => void
  selected?: boolean
  onAcknowledge: () => void
  onSuppress: () => void
  onVerify: () => void
  onReopen: () => void
  verifyPending?: boolean
  statePending?: boolean
}) {
  const isNew = (Date.now() - new Date(f.first_seen_at).getTime()) < NEW_FINDING_DAYS * 86_400_000
  const stale = isStale(f.last_seen_at)
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onClick}
      onKeyDown={e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onClick() } }}
      className={`text-left w-full rounded-lg border bg-card p-3.5 space-y-2 transition-colors hover:bg-accent/40 cursor-pointer ${
        selected ? "ring-2 ring-primary" : ""
      }`}
    >
      <div className="space-y-1">
        <ImpactClassBadge finding={f} />
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5 flex-wrap">
            {f.risk_band ? <RiskBandBadge band={f.risk_band} score={f.risk_score} /> : <SeverityBadge severity={f.severity} />}
            <BuildingVelocityBadge active={f.building_velocity} />
          </div>
          <div className="flex items-center gap-1 shrink-0">
            <StateBadge state={f.state} />
            <FindingActionsMenu
              finding={f}
              onAcknowledge={onAcknowledge}
              onSuppress={onSuppress}
              onVerify={onVerify}
              onReopen={onReopen}
              verifyPending={verifyPending}
              statePending={statePending}
            />
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <p className="text-sm font-medium leading-snug line-clamp-2 flex-1">{findingTitle(f)}</p>
        {f.cve_id && <span className="font-mono text-xs text-muted-foreground shrink-0">{f.cve_id}</span>}
        <ExposureOverrideBadge finding={f} />
        {isNew && (
          <span className="inline-flex items-center gap-1 rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary shrink-0">
            <Sparkles className="h-2.5 w-2.5" />New
          </span>
        )}
      </div>

      <p className="font-mono text-xs text-muted-foreground truncate">{displayName(f.asset_value)}</p>

      <div className="flex items-center gap-2 flex-wrap">
        <CategoryBadge category={f.category} />
        <EnrichmentBadges finding={f} />
      </div>

      {(f.tags?.length ?? 0) > 0 && (
        <div className="flex items-center gap-1 flex-wrap">
          {f.tags.slice(0, 4).map(t => <TagBadge key={t} tag={t} />)}
        </div>
      )}

      <p className="flex items-center gap-1 text-[11px] text-muted-foreground">
        {stale ? (
          <><Clock className="h-3 w-3 text-amber-500" /> stale {daysSince(f.last_seen_at)}d</>
        ) : (
          <>seen {relativeTime(f.last_seen_at)}</>
        )}
      </p>
    </div>
  )
}
