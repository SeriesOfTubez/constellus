import { Clock, Sparkles, Network } from "lucide-react"
import { type Asset } from "@/lib/api"
import { displayName } from "@/lib/apex"
import { relativeTime, isStale, daysSince } from "@/lib/time"
import { RecordTypeBadge, AssetTypeBadge, SourceBadges } from "@/components/asset-badges"
import { RiskBandBadge, SeverityBadge } from "@/components/finding-badges"
import { TagBadge } from "@/components/ui/tag-badge"
import { IndeterminateCheckbox } from "@/components/ui/indeterminate-checkbox"

const NEW_ASSET_DAYS = 7

/**
 * Asset-summary card — the card-view counterpart of an Assets table row. Built
 * from asset data already on the page (no extra fetch). Click opens the asset
 * flyout; the corner checkbox drives the same bulk selection as the table.
 */
export function AssetCard({
  asset,
  onOpen,
  selected,
  onSelect,
}: {
  asset: Asset
  onOpen: () => void
  selected: boolean
  onSelect: (checked: boolean) => void
}) {
  const m = asset.asset_metadata
  const content = typeof m.content === "string" ? m.content : null
  const portCount = Array.isArray(m.open_ports) ? (m.open_ports as unknown[]).length : 0
  const isNew = (Date.now() - new Date(asset.first_seen_at).getTime()) < NEW_ASSET_DAYS * 86_400_000
  const stale = isStale(asset.last_seen_at)
  const secondary = asset.asset_type === "dns_record"
    ? (content ? displayName(content) : null)
    : (asset.parent_value ? displayName(asset.parent_value) : null)

  return (
    <div
      onClick={onOpen}
      role="button"
      tabIndex={0}
      onKeyDown={e => { if (e.key === "Enter") onOpen() }}
      className={`rounded-lg border bg-card p-3.5 space-y-2.5 cursor-pointer transition-colors hover:bg-accent/40 ${
        asset.ignored ? "opacity-50" : ""
      } ${selected ? "ring-2 ring-primary" : ""}`}
    >
      {/* Type + risk + select */}
      <div className="flex items-center gap-2">
        {asset.asset_type === "dns_record" && m.record_type
          ? <RecordTypeBadge type={String(m.record_type)} />
          : <AssetTypeBadge type={asset.asset_type} />}
        {asset.risk_band
          ? <RiskBandBadge band={asset.risk_band} score={asset.risk_score} />
          : asset.worst_severity ? <SeverityBadge severity={asset.worst_severity} /> : null}
        <span className="ml-auto" onClick={e => e.stopPropagation()}>
          <IndeterminateCheckbox checked={selected} onChange={onSelect} />
        </span>
      </div>

      {/* Identity */}
      <div className="space-y-0.5">
        <div className="flex items-center gap-2 flex-wrap">
          <p className="font-mono text-sm font-medium break-all">{displayName(asset.value)}</p>
          {isNew && (
            <span className="inline-flex items-center gap-1 rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">
              <Sparkles className="h-2.5 w-2.5" />New
            </span>
          )}
          {stale && (
            <span className="inline-flex items-center gap-1 rounded bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-700 dark:text-amber-400">
              <Clock className="h-2.5 w-2.5" />stale {daysSince(asset.last_seen_at)}d
            </span>
          )}
        </div>
        {secondary && <p className="text-xs font-mono text-muted-foreground break-all">→ {secondary}</p>}
      </div>

      {/* Ports + sources */}
      <div className="flex items-center gap-2 flex-wrap">
        {portCount > 0 && (
          <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
            <Network className="h-3 w-3" />{portCount} port{portCount !== 1 ? "s" : ""}
          </span>
        )}
        <SourceBadges metadata={asset.asset_metadata} />
      </div>

      {/* Tags */}
      {(asset.tags?.length ?? 0) > 0 && (
        <div className="flex items-center gap-1 flex-wrap">
          {asset.tags.slice(0, 4).map(t => <TagBadge key={t} tag={t} />)}
        </div>
      )}

      {/* Footer */}
      <p className="text-[11px] text-muted-foreground">seen {relativeTime(asset.last_seen_at)}</p>
    </div>
  )
}
