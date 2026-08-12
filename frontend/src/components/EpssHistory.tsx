/**
 * EPSS history components — score row with delta indicator, and a 12-week
 * sparkline. Both share the same TanStack Query key so only one fetch fires
 * per finding even when both appear on the same page.
 *
 * EpssRow      — drop-in for the existing enrichment table row
 * EpssSparklineSection — standalone section with heading + chart
 */

import { useId } from "react"
import { useQuery } from "@tanstack/react-query"
import { TrendingUp, TrendingDown, Minus, Info } from "lucide-react"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { api, type EpssHistoryData } from "@/lib/api"
import { relativeTime } from "@/lib/time"

// ── shared query ──────────────────────────────────────────────────────────────

function useEpssHistory(findingId: string) {
  return useQuery<EpssHistoryData>({
    queryKey: ["epss-history", findingId],
    queryFn: () => api.get<EpssHistoryData>(`/findings/${findingId}/epss-history`),
    staleTime: 5 * 60 * 1000, // 5 min — FIRST.org data is daily anyway
  })
}

// ── delta indicator ───────────────────────────────────────────────────────────

function DeltaChip({ delta }: { delta: number | null }) {
  if (delta === null || delta === 0) {
    return <span className="inline-flex items-center gap-0.5 text-xs text-muted-foreground"><Minus className="h-3 w-3" />unchanged</span>
  }
  // EPSS going up = bad (higher exploitation probability)
  const isUp = delta > 0
  const pct = (Math.abs(delta) * 100).toFixed(2)
  if (isUp) {
    return (
      <span className="inline-flex items-center gap-0.5 text-xs text-orange-500 dark:text-orange-400">
        <TrendingUp className="h-3 w-3" />+{pct}%
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-0.5 text-xs text-green-600 dark:text-green-500">
      <TrendingDown className="h-3 w-3" />−{pct}%
    </span>
  )
}

// ── sparkline (raw SVG, no deps) ──────────────────────────────────────────────

function EpssSparkline({
  history,
  height = 56,
  showLabels = false,
}: {
  history: EpssHistoryData["history"]
  height?: number
  showLabels?: boolean
}) {
  const gradientId = useId()

  if (history.length === 0) {
    return (
      <p className="text-xs text-muted-foreground py-2">No trend data yet — will populate after the next enrichment cycle.</p>
    )
  }

  // history is most-recent first; reverse for left→right display
  const pts = history.slice().reverse()
  const scores = pts.map(p => p.epss_score)
  const maxS = Math.max(...scores, 0.001)
  const minS = Math.min(...scores, 0)
  const range = maxS - minS || maxS || 0.001

  const W = 300
  const H = height
  const PAD_Y = 3
  const PAD_X = 0
  const innerW = W - PAD_X * 2
  const innerH = H - PAD_Y * 2

  const toX = (i: number) => PAD_X + (pts.length > 1 ? (i / (pts.length - 1)) * innerW : innerW / 2)
  const toY = (s: number) => PAD_Y + innerH * (1 - (s - minS) / range)

  const lineD = pts.map((p, i) => `${i === 0 ? "M" : "L"}${toX(i).toFixed(1)},${toY(p.epss_score).toFixed(1)}`).join(" ")
  const areaD = `${lineD} L${toX(pts.length - 1).toFixed(1)},${H} L${toX(0).toFixed(1)},${H} Z`

  const LABEL_H = showLabels ? 16 : 0
  const totalH = H + LABEL_H

  return (
    <svg
      viewBox={`0 0 ${W} ${totalH}`}
      className="w-full overflow-visible"
      style={{ height: totalH }}
      aria-label="EPSS score trend"
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="rgb(245 158 11)" stopOpacity="0.25" />
          <stop offset="100%" stopColor="rgb(245 158 11)" stopOpacity="0.02" />
        </linearGradient>
      </defs>

      <path d={areaD} fill={`url(#${gradientId})`} />
      <path d={lineD} fill="none" stroke="rgb(245 158 11)" strokeWidth="1.5" strokeLinejoin="round" />

      {pts.map((p, i) => (
        <circle key={i} cx={toX(i)} cy={toY(p.epss_score)} r="2.5" fill="rgb(245 158 11)">
          <title>{p.week_start}: {(p.epss_score * 100).toFixed(3)}%</title>
        </circle>
      ))}

      {showLabels && pts.map((p, i) => {
        // Only show first and last label to avoid overlap
        if (i !== 0 && i !== pts.length - 1) return null
        const label = p.week_start.slice(5) // MM-DD
        return (
          <text
            key={i}
            x={toX(i)}
            y={H + LABEL_H - 2}
            textAnchor={i === 0 ? "start" : "end"}
            fontSize="9"
            fill="currentColor"
            className="text-muted-foreground"
            opacity="0.6"
          >
            {label}
          </text>
        )
      })}
    </svg>
  )
}

// ── public exports ────────────────────────────────────────────────────────────

/**
 * Replaces the plain EPSS enrichment table row. Shows score + percentile +
 * a daily delta indicator. Falls back to the raw Finding fields while loading.
 */
export function EpssRow({
  findingId,
  fallbackScore,
  fallbackPercentile,
}: {
  findingId: string
  fallbackScore: number | null
  fallbackPercentile: number | null
}) {
  const { data } = useEpssHistory(findingId)

  const score = data?.current_score ?? fallbackScore
  const pct = data?.current_percentile ?? fallbackPercentile

  if (score === null) return null

  return (
    <div className="flex items-center gap-3 px-3 py-2">
      <span className="text-muted-foreground w-24 shrink-0">EPSS</span>
      <span className="font-mono">{(score * 100).toFixed(2)}%</span>
      {pct != null && (
        <span className="text-xs text-muted-foreground">{(pct * 100).toFixed(0)}th percentile</span>
      )}
      {data && <DeltaChip delta={data.delta} />}
      {data?.score_changed_date && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Info className="h-3.5 w-3.5 text-muted-foreground/60 cursor-default shrink-0" />
          </TooltipTrigger>
          <TooltipContent side="top">
            Score last changed {relativeTime(data.score_changed_date)} ({data.score_changed_date})
          </TooltipContent>
        </Tooltip>
      )}
    </div>
  )
}

/**
 * Compact variant for the finding flyout — same data, smaller chart (no labels).
 */
export function EpssRowCompact({
  findingId,
  fallbackScore,
  fallbackPercentile,
}: {
  findingId: string
  fallbackScore: number | null
  fallbackPercentile: number | null
}) {
  const { data } = useEpssHistory(findingId)

  const score = data?.current_score ?? fallbackScore
  const pct = data?.current_percentile ?? fallbackPercentile

  if (score === null) return null

  return (
    <div className="flex items-center gap-3 text-sm">
      <span className="text-xs text-muted-foreground w-20 shrink-0">EPSS</span>
      <span className="font-mono">{(score * 100).toFixed(2)}%</span>
      {pct != null && (
        <span className="text-xs text-muted-foreground">{(pct * 100).toFixed(0)}th percentile</span>
      )}
      {data && <DeltaChip delta={data.delta} />}
      {data?.score_changed_date && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Info className="h-3 w-3 text-muted-foreground/60 cursor-default shrink-0" />
          </TooltipTrigger>
          <TooltipContent side="top">
            Score last changed {relativeTime(data.score_changed_date)} ({data.score_changed_date})
          </TooltipContent>
        </Tooltip>
      )}
    </div>
  )
}

/**
 * Headed section with the 12-week sparkline. Place below the enrichment block.
 * compact=true reduces chart height and omits date labels (for the flyout).
 */
export function EpssSparklineSection({
  findingId,
  compact = false,
}: {
  findingId: string
  compact?: boolean
}) {
  const { data, isLoading } = useEpssHistory(findingId)

  if (isLoading) return (
    <div className="space-y-1.5">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">EPSS trend</p>
      <div className="h-10 bg-muted/40 rounded animate-pulse" />
    </div>
  )

  if (!data || data.history.length === 0) return null

  return (
    <div className="space-y-1.5">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
        EPSS trend · {data.history.length}w
      </p>
      <EpssSparkline
        history={data.history}
        height={compact ? 40 : 56}
        showLabels={!compact}
      />
    </div>
  )
}
