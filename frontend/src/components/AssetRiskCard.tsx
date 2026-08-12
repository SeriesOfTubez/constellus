import { Link } from "react-router-dom"
import { SquareArrowOutUpRight } from "lucide-react"
import { type Asset, type Finding } from "@/lib/api"
import { relativeTime } from "@/lib/time"
import { displayName } from "@/lib/apex"
import { AssetTypeBadge } from "@/components/asset-badges"
import {
  RISK_BAND_ORDER,
  RISK_BAND_SHORT,
  RISK_BAND_COLOR,
  effectiveBand,
} from "@/components/finding-badges"

/**
 * Shared asset risk summary — verdict hero + clickable band distribution +
 * top-finding spotlight. Extracted from the Assets flyout so the same card backs
 * the flyout overview, the (forthcoming) card views on Assets/Findings, and any
 * grouped-by-asset rendering. One component, one look, everywhere.
 *
 * The band pills are the asset-scoped entry point into Findings: each links to
 * `/findings?asset=<value>&band=<band>` — the dead severity pills are now live.
 *
 * `href` (optional) renders a clickable identity header (type badge + asset
 * value) — used in the card-grid views where the card must name its asset and
 * offer "see all this asset's findings". Omitted in the flyout, where the sheet
 * header already names the asset.
 */

// Verdict hero styling, keyed directly on the Risk Score band (the verdict axis).
const BAND_HERO: Record<string, { label: string; textCls: string; bgCls: string }> = {
  imminent_compromise: { label: "Imminent Threat",     textCls: "text-red-500",     bgCls: "from-red-500/[0.07]" },
  high:                { label: "High Risk",           textCls: "text-orange-500",  bgCls: "from-orange-500/[0.07]" },
  elevated:            { label: "Elevated Risk",       textCls: "text-yellow-500",  bgCls: "from-amber-500/[0.07]" },
  low:                 { label: "Low Risk",            textCls: "text-blue-500",    bgCls: "from-blue-500/[0.07]" },
  secure:              { label: "Secure Posture",      textCls: "text-emerald-500", bgCls: "from-emerald-500/[0.07]" },
}

const SPOTLIGHT_CLS: Record<string, string> = {
  imminent_compromise: "border-l-4 border-l-red-500",
  high:                "border-l-4 border-l-orange-500",
  elevated:            "border-l-4 border-l-yellow-500",
  low:                 "border-l-4 border-l-blue-500",
  secure:              "border-l-4 border-l-border",
}

export function AssetRiskCard({ asset, findings, href }: { asset: Asset; findings: Finding[]; href?: string }) {
  const active = findings.filter(f => f.state === "open" || f.state === "acknowledged")
  const bandCounts = active.reduce<Record<string, number>>((acc, f) => {
    const b = effectiveBand(f)
    acc[b] = (acc[b] ?? 0) + 1
    return acc
  }, {})
  const topFinding = [...active].sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0))[0] ?? null

  const hero = BAND_HERO[asset.risk_band ?? "secure"] ?? BAND_HERO.secure

  return (
    <div className="space-y-5">
      {/* Identity header — names the asset and links to all its findings */}
      {href && (
        <Link
          to={href}
          className="group/title flex items-center gap-2 hover:text-primary transition-colors"
          title={`All findings for ${asset.value}`}
        >
          <AssetTypeBadge type={asset.asset_type} />
          <span className="font-mono text-sm font-medium truncate">{displayName(asset.value)}</span>
          <SquareArrowOutUpRight className="ml-auto h-3.5 w-3.5 shrink-0 text-muted-foreground group-hover/title:text-primary transition-colors" />
        </Link>
      )}

      {/* Risk verdict hero */}
      <div className={`rounded-lg p-4 bg-gradient-to-br ${hero.bgCls} to-transparent space-y-1`}>
        <p className={`text-lg font-bold leading-none ${hero.textCls}`}>
          {hero.label}
          {asset.risk_score != null && (
            <span className="ml-2 font-mono text-sm opacity-70">{asset.risk_score}</span>
          )}
        </p>
        <p className="text-xs text-muted-foreground">
          {active.length === 0
            ? `No open findings · last seen ${relativeTime(asset.last_seen_at)}`
            : `${active.length} active finding${active.length !== 1 ? "s" : ""}`}
        </p>
      </div>

      {/* Band distribution — each pill deep-links to this asset's findings in that band */}
      <div className="grid grid-cols-4 gap-2">
        {RISK_BAND_ORDER.map(b => {
          const count = bandCounts[b] ?? 0
          return (
            <Link
              key={b}
              to={`/findings?asset=${encodeURIComponent(asset.value)}&band=${b}`}
              className={`rounded-md border px-2 py-2 text-center transition-opacity ${
                count > 0 ? `${RISK_BAND_COLOR[b]} hover:opacity-80` : "border-border/40 opacity-30 pointer-events-none"
              }`}
            >
              <p className="text-base font-bold leading-none mb-0.5">{count}</p>
              <p className="text-[10px] uppercase tracking-wider">{RISK_BAND_SHORT[b]}</p>
            </Link>
          )
        })}
      </div>

      {/* Top finding spotlight */}
      {topFinding && (
        <div className={`rounded-md border bg-muted/20 p-3.5 space-y-2 ${SPOTLIGHT_CLS[effectiveBand(topFinding)] ?? ""}`}>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Top finding</span>
            {(topFinding.kev || topFinding.vulncheck_kev) && (
              <span className="inline-flex items-center rounded border px-1 py-0 text-[10px] font-bold bg-red-500 text-white border-red-600">KEV</span>
            )}
          </div>
          <p className="text-sm font-medium leading-snug">{topFinding.title}</p>
          {topFinding.description && (
            <p className="text-xs text-muted-foreground line-clamp-2">{topFinding.description}</p>
          )}
          <Link
            to={`/findings/${topFinding.id}`}
            className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
          >
            View finding <SquareArrowOutUpRight className="h-3 w-3" />
          </Link>
        </div>
      )}
    </div>
  )
}
