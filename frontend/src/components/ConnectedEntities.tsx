import { useQuery } from "@tanstack/react-query"
import { useNavigate } from "react-router-dom"
import { ChevronRight, Box, Circle, ShieldAlert } from "lucide-react"

import { api, type EdgesResponse, type EdgeNode, type EdgeNodeType } from "@/lib/api"
import { displayName } from "@/lib/apex"

/**
 * Source-agnostic relationship panel driven by `asset_edges`.
 *
 * Renders every edge touching the given node, grouped by `(edge_type, direction)`.
 * The server returns the directional verb so adding a new edge type is a
 * backend-only change. Findings get a severity dot prefix; navigation rows
 * are quieter. Click a row to navigate to that node's full-detail page.
 */
export type ObservedName = {
  value: string
  source: string  // "shodan" | "tlsx" | …
}

export function ConnectedEntities({
  nodeType,
  nodeId,
  observedNames,
}: {
  nodeType: EdgeNodeType
  nodeId: string
  /**
   * Additional unmonitored names tied to this node by enrichment data, not by
   * `asset_edges`. Rendered as an extra "Other names observed" group so the
   * user sees the full neighborhood even when the names aren't tracked assets.
   */
  observedNames?: ObservedName[]
}) {
  const { data, isLoading } = useQuery({
    queryKey: ["edges", nodeType, nodeId],
    queryFn: () => api.get<EdgesResponse>(`/edges/${nodeType}/${nodeId}`),
  })

  const groups = data?.groups ?? []
  const hasObserved = observedNames && observedNames.length > 0
  const hasContent = groups.length > 0 || hasObserved

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
          Connected entities
        </p>
        <div className="flex items-center gap-1 text-[10px] text-muted-foreground">
          <span className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5">
            <Box className="h-2.5 w-2.5" />List
          </span>
          <span
            className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 opacity-50 cursor-not-allowed"
            title="Graph view coming with continuous-monitoring phase 4"
          >
            <Circle className="h-2.5 w-2.5" />Graph
          </span>
        </div>
      </div>

      {isLoading ? (
        <p className="text-xs text-muted-foreground italic">Loading…</p>
      ) : !hasContent ? (
        <p className="text-xs text-muted-foreground italic">No connected entities.</p>
      ) : (
        <div className="space-y-3">
          {groups.map(group => (
            <EdgeGroupBlock
              key={`${group.edge_type}-${group.direction}`}
              verb={group.verb}
              total={group.total}
              items={group.items}
              direction={group.direction}
              tag={group.edge_type === "shares_ip_with" ? "tracked" : undefined}
            />
          ))}
          {hasObserved && <ObservedNamesBlock names={observedNames!} />}
        </div>
      )}
    </div>
  )
}

function ObservedNamesBlock({ names }: { names: ObservedName[] }) {
  // Group by source so the per-source attribution is at the panel level rather
  // than repeated on every row.
  const bySource = new Map<string, string[]>()
  for (const n of names) {
    const list = bySource.get(n.source) ?? []
    list.push(n.value)
    bySource.set(n.source, list)
  }
  const total = names.length

  return (
    <div className="rounded-md border bg-card">
      <div className="flex items-center gap-2 px-3 py-1.5 border-b text-xs">
        <span className="text-muted-foreground font-mono">~</span>
        <span className="font-medium">Other names observed</span>
        <span className="text-muted-foreground">({total})</span>
        <span
          className="ml-auto text-[10px] text-muted-foreground"
          title="Names seen by enrichment sources that aren't tracked assets in Constellus"
        >
          unmonitored
        </span>
      </div>
      <div className="divide-y">
        {[...bySource.entries()].map(([source, values]) => (
          <div key={source} className="px-3 py-2 text-xs space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-[10px] uppercase tracking-wider text-muted-foreground">via {source}</span>
            </div>
            <div className="font-mono space-y-0.5 break-all">
              {values.map(v => <div key={v}>{v}</div>)}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function EdgeGroupBlock({
  verb, total, items, direction, tag,
}: {
  verb: string
  total: number
  items: EdgeNode[]
  direction: "in" | "out" | "lateral"
  tag?: string
}) {
  const glyph = direction === "out" ? "→" : direction === "in" ? "←" : "~"
  const overflow = total - items.length

  return (
    <div className="rounded-md border bg-card">
      <div className="flex items-center gap-2 px-3 py-1.5 border-b text-xs">
        <span className="text-muted-foreground font-mono">{glyph}</span>
        <span className="font-medium">{verb}</span>
        <span className="text-muted-foreground">({total})</span>
        {tag && (
          <span className="ml-auto text-[10px] text-muted-foreground">{tag}</span>
        )}
      </div>
      <div className="divide-y">
        {items.map(item => (
          <EdgeRow key={`${item.node_type}-${item.node_id}`} item={item} />
        ))}
        {overflow > 0 && (
          <div className="px-3 py-1.5 text-xs text-muted-foreground italic">
            +{overflow} more — open full view to see all
          </div>
        )}
      </div>
    </div>
  )
}

function EdgeRow({ item }: { item: EdgeNode }) {
  const navigate = useNavigate()

  const onClick = () => {
    if (item.node_type === "asset_canonical") navigate(`/assets/${item.node_id}`)
    else if (item.node_type === "finding_canonical") navigate(`/findings/${item.node_id}`)
    else if (item.node_type === "target") navigate(`/targets/${item.node_id}`)
  }

  const display = item.value && item.value.includes(".") ? displayName(item.value) : item.value

  return (
    <button
      type="button"
      onClick={onClick}
      className="w-full flex items-center gap-2 px-3 py-2 text-xs hover:bg-accent text-left"
    >
      <TypeChip item={item} />
      <span className="font-mono break-all flex-1 min-w-0" title={item.value}>{display}</span>
      <EdgeMetaChips item={item} />
      <ChevronRight className="h-3 w-3 text-muted-foreground shrink-0" />
    </button>
  )
}

function TypeChip({ item }: { item: EdgeNode }) {
  if (item.node_type === "finding_canonical") {
    const sev = item.severity ?? "info"
    const cls = SEV_COLOR[sev]
    return (
      <span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium ${cls}`}>
        {item.kev && <ShieldAlert className="h-2.5 w-2.5" />}
        {sev.toUpperCase()}
      </span>
    )
  }
  if (item.node_type === "target") {
    return <span className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-foreground">target</span>
  }
  // asset_canonical
  const meta = item.edge_metadata
  if (item.asset_type === "dns_record" && typeof meta.record_type === "string") {
    return <span className="inline-flex items-center rounded bg-blue-500/10 text-blue-600 dark:text-blue-400 px-1.5 py-0.5 text-[10px] font-mono font-semibold">{String(meta.record_type)}</span>
  }
  const label = (item.asset_type ?? "asset").replace(/_/g, " ")
  return <span className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">{label}</span>
}

function EdgeMetaChips({ item }: { item: EdgeNode }) {
  const chips: string[] = []
  const meta = item.edge_metadata
  if (typeof meta.record_type === "string" && item.asset_type !== "dns_record") chips.push(meta.record_type)
  if (meta.provider_mx === true) chips.push("provider")
  if (item.node_type === "asset_canonical" && item.metadata?.content) {
    chips.push(String(item.metadata.content))
  }
  if (Array.isArray(meta.via_ips)) {
    // shares_ip_with rows: show which IP(s) they share. Cap to 2 to keep the
    // row legible; remainder count rendered as a trailing chip.
    const ips = meta.via_ips as string[]
    chips.push(...ips.slice(0, 2))
    if (ips.length > 2) chips.push(`+${ips.length - 2}`)
  }
  if (item.node_type === "finding_canonical" && item.cve_id) chips.push(item.cve_id)
  if (!chips.length) return null
  return (
    <div className="flex items-center gap-1 shrink-0">
      {chips.map(c => (
        <span key={c} className="inline-flex items-center rounded bg-muted/60 px-1 py-0.5 text-[10px] font-mono text-muted-foreground">{c}</span>
      ))}
    </div>
  )
}

const SEV_COLOR: Record<string, string> = {
  critical: "bg-red-500/15 text-red-600 dark:text-red-400",
  high:     "bg-orange-500/15 text-orange-600 dark:text-orange-400",
  medium:   "bg-amber-500/15 text-amber-700 dark:text-amber-400",
  low:      "bg-yellow-500/10 text-yellow-700 dark:text-yellow-500",
  info:     "bg-blue-500/10 text-blue-600 dark:text-blue-400",
}
