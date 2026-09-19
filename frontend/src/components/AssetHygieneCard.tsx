import { useQuery } from "@tanstack/react-query"
import { ShieldQuestion, Clock3 } from "lucide-react"
import { api, type Asset, type HygieneBand, type HygieneDetail } from "@/lib/api"
import { relativeTime } from "@/lib/time"
import { HygieneGradeChip } from "@/components/hygiene-badges"

/**
 * Asset hygiene drill-down — the sibling of AssetRiskCard for the OPPOSITE
 * polarity axis. Risk Score (AssetRiskCard) is 0-100 where high = bad;
 * hygiene is 0-100 where high = good, so this card labels its hero
 * unambiguously ("Asset Hygiene") since both live on the same flyout/page.
 * This is the ONE place the numeric hygiene score is allowed to render —
 * everywhere else (the Assets list) shows the band word only, via
 * HygieneBandBadge (see hygiene-badges.tsx's module docstring for why).
 *
 * Fetches its own data (`GET /api/hygiene/{asset.id}`) rather than taking it
 * as a prop, mirroring how AssetDetailSheet's other flyout panels (whois,
 * domain-whois) each own their query — the parent only ever needs to pass
 * the asset. Used in the Assets flyout Overview tab (near AssetRiskCard)
 * and on AssetDetail.tsx.
 *
 * Handles three distinct non-error states, none of which is a loading
 * failure:
 *   - `scored: false, reason: "excluded_not_ours"` — third-party asset,
 *     deliberately never scored.
 *   - `scored: false, reason: "not_yet_computed"` — in scope, but the
 *     nightly job hasn't reached it yet.
 *   - `scored: true` — the normal five-dimension card. `coverage` reads
 *     `unknown` for every asset today (no producers until planning#152) —
 *     that is expected, not broken, and its own `detail` string already
 *     explains why; every dimension row always renders, `unknown` included,
 *     never hidden or dimmed (settled rule 2).
 */

const DIMENSION_ORDER = ["coverage", "health", "currency", "exposure", "ownership"] as const

const DIMENSION_LABEL: Record<(typeof DIMENSION_ORDER)[number], string> = {
  coverage:  "Coverage",
  health:    "Health",
  currency:  "Currency",
  exposure:  "Exposure",
  ownership: "Ownership",
}

// Hero styling keyed on the hygiene band — same red/orange/yellow/blue/emerald
// hue-by-meaning ramp as HYGIENE_BAND_COLOR, just expressed as gradient hero
// classes the way AssetRiskCard's BAND_HERO does for the Risk Score axis.
const HYGIENE_BAND_HERO: Record<HygieneBand, { label: string; textCls: string; bgCls: string }> = {
  critical:  { label: "Critical",  textCls: "text-red-500",     bgCls: "from-red-500/[0.07]" },
  poor:      { label: "Poor",      textCls: "text-orange-500",  bgCls: "from-orange-500/[0.07]" },
  fair:      { label: "Fair",      textCls: "text-yellow-600 dark:text-yellow-400", bgCls: "from-amber-500/[0.07]" },
  good:      { label: "Good",      textCls: "text-blue-500",    bgCls: "from-blue-500/[0.07]" },
  excellent: { label: "Excellent", textCls: "text-emerald-500", bgCls: "from-emerald-500/[0.07]" },
}

export function AssetHygieneCard({ asset }: { asset: Asset }) {
  const { data, isLoading, isError } = useQuery<HygieneDetail>({
    queryKey: ["hygiene", asset.id],
    queryFn: () => api.get<HygieneDetail>(`/hygiene/${asset.id}`),
    enabled: !!asset.id,
    staleTime: 30_000,
  })

  if (isLoading) {
    return (
      <div className="space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Asset Hygiene</p>
        <div className="rounded-lg border p-4 text-xs text-muted-foreground italic">Loading…</div>
      </div>
    )
  }

  if (isError || !data) {
    return (
      <div className="space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Asset Hygiene</p>
        <div className="rounded-lg border p-4 text-xs text-muted-foreground">Couldn't load hygiene score.</div>
      </div>
    )
  }

  if (!data.scored) {
    const excluded = data.reason === "excluded_not_ours"
    return (
      <div className="space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Asset Hygiene</p>
        <div className="rounded-lg border bg-muted/20 p-4 flex items-start gap-3">
          {excluded
            ? <ShieldQuestion className="h-4 w-4 mt-0.5 shrink-0 text-muted-foreground" />
            : <Clock3 className="h-4 w-4 mt-0.5 shrink-0 text-muted-foreground" />}
          <div className="space-y-0.5">
            <p className="text-sm font-medium">{excluded ? "Not scored — third party" : "Not yet computed"}</p>
            <p className="text-xs text-muted-foreground leading-relaxed">
              {excluded
                ? "This asset is third-party (outside your owned estate) and is deliberately excluded from hygiene scoring by design."
                : "This asset is in scope but the nightly scoring job hasn't reached it yet. Check back after the next run."}
            </p>
          </div>
        </div>
      </div>
    )
  }

  const hero = HYGIENE_BAND_HERO[data.band]

  return (
    <div className="space-y-3">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Asset Hygiene</p>

      {/* Hero — the ONE place the numeric score appears, explicitly labelled
          so it can't be mistaken for Risk Score (opposite polarity) sitting
          elsewhere on the same screen. */}
      <div className={`rounded-lg p-4 bg-gradient-to-br ${hero.bgCls} to-transparent space-y-1`}>
        <p className={`text-lg font-bold leading-none ${hero.textCls}`}>
          {hero.label}
          <span className="ml-2 font-mono text-sm opacity-70">{data.score} / 100</span>
        </p>
        <p className="text-xs text-muted-foreground">Computed {relativeTime(data.computed_at)}</p>
      </div>

      {/* Five dimension rows, fixed backend order. Always all five, `unknown`
          included — an unknown dimension is a finding, not a gap. */}
      <div className="rounded-md border divide-y">
        {DIMENSION_ORDER.map(key => {
          const dim = data.dimensions[key]
          if (!dim) return null
          return (
            <div key={key} className="px-3 py-2.5 space-y-1">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-medium">{DIMENSION_LABEL[key]}</span>
                <HygieneGradeChip grade={dim.grade} />
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">{dim.detail}</p>
            </div>
          )
        })}
      </div>
    </div>
  )
}
