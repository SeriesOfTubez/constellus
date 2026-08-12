import { useQuery } from "@tanstack/react-query"
import { Link } from "react-router-dom"
import { Activity, AlertTriangle, ArrowDownRight, ArrowUpRight, Globe, Loader2, Minus, ScanLine, Target, Zap, Sparkles } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useAuthStore } from "@/lib/auth"
import { api, type Finding, type ScanRun, type SecurityScore, type Target as TargetType } from "@/lib/api"
import { displayName } from "@/lib/apex"
import { relativeTime } from "@/lib/time"
import { CATEGORY_LABEL, RISK_BAND_LABEL, RISK_BAND_SHORT, RISK_BAND_ORDER, RiskBandBadge, effectiveBand } from "@/components/finding-badges"

const NEW_DAYS = 7
const KIND_LABEL: Record<ScanRun["kind"], string> = {
  monitoring:        "Monitoring",
  initial_discovery: "Initial discovery",
  recheck:           "Recheck",
  manual:            "Manual",
}
const STATUS_VARIANT: Record<ScanRun["status"], "default" | "outline" | "success" | "warning" | "destructive"> = {
  pending:   "outline",
  running:   "warning",
  completed: "success",
  failed:    "destructive",
  cancelled: "outline",
}

// ── Risk verdict strip ──────────────────────────────────────────────────────

function SeverityStrip({ findings, loading, error }: { findings?: Finding[]; loading: boolean; error?: boolean }) {
  const counts = RISK_BAND_ORDER.reduce<Record<string, number>>((acc, b) => {
    acc[b] = (findings ?? []).filter(f => effectiveBand(f) === b).length
    return acc
  }, {})
  const total   = (findings ?? []).length
  const kev     = (findings ?? []).filter(f => f.kev || f.vulncheck_kev).length
  const exploit = (findings ?? []).filter(f => f.has_exploit).length

  return (
    <Card>
      <CardContent className="pt-5 pb-5">
        {loading ? (
          <div className="flex gap-8"><Skeleton className="h-10 w-16" /><Skeleton className="h-10 w-16" /><Skeleton className="h-10 w-16" /></div>
        ) : error ? (
          <p className="text-sm text-muted-foreground">Couldn't load findings — data may be incomplete.</p>
        ) : (
          <div className="flex flex-wrap items-end gap-x-8 gap-y-4">
            {/* Total */}
            <div className="text-center min-w-[2.5rem]">
              <p className="text-3xl font-bold tabular-nums leading-none">{total}</p>
              <p className="text-xs text-muted-foreground mt-1">Total</p>
            </div>

            <div className="h-8 w-px bg-border self-center" />

            {/* Per-verdict counts (Constellus Risk Score band, not raw CVSS severity) */}
            {RISK_BAND_ORDER.filter(b => counts[b] > 0).map(b => (
              <Link key={b} to={`/findings?band=${b}`} className="text-center min-w-[2.5rem] group">
                <p className="text-3xl font-bold tabular-nums leading-none group-hover:opacity-80 transition-opacity"
                  style={{ color: BAND_VAR[b] }}>
                  {counts[b]}
                </p>
                <p className="text-xs text-muted-foreground mt-1">{RISK_BAND_SHORT[b]}</p>
              </Link>
            ))}

            {/* Intel chips */}
            {(kev > 0 || exploit > 0) && (
              <>
                <div className="h-8 w-px bg-border self-center" />
                <div className="flex flex-wrap items-center gap-3">
                  {kev > 0 && (
                    <Link to="/findings?kev=true" className="flex items-center gap-1.5 text-sm hover:opacity-80 transition-opacity">
                      <span className="inline-block h-2 w-2 rounded-full bg-[var(--sev-critical)]" />
                      <span className="font-semibold text-foreground">{kev}</span>
                      <span className="text-muted-foreground">confirmed exploited (KEV)</span>
                    </Link>
                  )}
                  {exploit > 0 && (
                    <Link to="/findings?exploit=true" className="flex items-center gap-1.5 text-sm hover:opacity-80 transition-opacity">
                      <Zap className="h-3.5 w-3.5 text-[var(--sev-high)]" />
                      <span className="font-semibold text-foreground">{exploit}</span>
                      <span className="text-muted-foreground">with public exploit</span>
                    </Link>
                  )}
                </div>
              </>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ── SSVC posture strip ────────────────────────────────────────────────────────

/** Compact strip of the CISA SSVC structural signals (Vulnrichment or derived),
 *  clickable into the matching Findings facets. Hidden when nothing is SSVC-scored. */
function SsvcStrip({ findings, loading, error }: { findings?: Finding[]; loading: boolean; error?: boolean }) {
  const all = findings ?? []
  const scored      = all.filter(f => f.ssvc_source).length
  const automatable = all.filter(f => f.ssvc_automatable === true).length
  const total       = all.filter(f => f.ssvc_technical_impact === "total").length
  const partial     = all.filter(f => f.ssvc_technical_impact === "partial").length
  if (!loading && !error && scored === 0) return null

  const stat = (to: string, n: number, label: string) => (
    <Link to={to} className="text-center min-w-[2.5rem] group">
      <p className="text-2xl font-bold tabular-nums leading-none group-hover:opacity-80 transition-opacity">{n}</p>
      <p className="text-xs text-muted-foreground mt-1">{label}</p>
    </Link>
  )

  return (
    <Card>
      <CardContent className="py-4">
        {loading ? (
          <div className="flex gap-8"><Skeleton className="h-9 w-16" /><Skeleton className="h-9 w-16" /><Skeleton className="h-9 w-16" /></div>
        ) : error ? (
          <p className="text-sm text-muted-foreground">Couldn't load SSVC posture — data may be incomplete.</p>
        ) : (
          <div className="flex flex-wrap items-end gap-x-8 gap-y-3">
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground self-center cursor-help leading-tight">SSVC<br />posture</span>
              </TooltipTrigger>
              <TooltipContent side="bottom" className="max-w-xs">
                CISA SSVC structural signals (Vulnrichment or derived). Automatable = mass-scriptable exploitation; Technical Impact = control gained if exploited.
              </TooltipContent>
            </Tooltip>
            <div className="h-8 w-px bg-border self-center" />
            {stat("/findings?automatable=true", automatable, "Automatable")}
            {stat("/findings?tech_impact=total", total, "Total control")}
            {stat("/findings?tech_impact=partial", partial, "Partial control")}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ── Category breakdown ────────────────────────────────────────────────────────

function CategoryBreakdown({ findings, loading, error }: { findings?: Finding[]; loading: boolean; error?: boolean }) {
  const counts = (findings ?? []).reduce<Record<string, number>>((acc, f) => {
    if (f.category) acc[f.category] = (acc[f.category] ?? 0) + 1
    return acc
  }, {})
  const rows = Object.entries(counts).sort(([, a], [, b]) => b - a)
  const max  = rows[0]?.[1] ?? 1

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base">Findings by category</CardTitle>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="space-y-3">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-4 w-full" />)}</div>
        ) : error ? (
          <p className="text-sm text-muted-foreground">Couldn't load — data may be incomplete.</p>
        ) : rows.length === 0 ? (
          <p className="text-sm text-muted-foreground">No findings yet.</p>
        ) : (
          <div className="space-y-2.5">
            {rows.map(([cat, count]) => (
              <Link
                key={cat}
                to={`/findings?category=${encodeURIComponent(cat)}`}
                className="flex items-center gap-3 -mx-1 px-1 py-0.5 rounded hover:bg-accent/40 transition-colors group"
              >
                <span className="text-xs text-muted-foreground w-36 shrink-0 truncate group-hover:text-foreground transition-colors">
                  {CATEGORY_LABEL[cat] ?? cat}
                </span>
                <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                  <div
                    className="h-full bg-primary rounded-full transition-all"
                    style={{ width: `${(count / max) * 100}%` }}
                  />
                </div>
                <span className="text-xs tabular-nums text-muted-foreground w-6 text-right">{count}</span>
              </Link>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ── Security score gauge ──────────────────────────────────────────────────────

const BAND_VAR: Record<SecurityScore["band"], string> = {
  imminent_compromise: "var(--sev-critical)",
  high:                "var(--sev-high)",
  elevated:            "var(--sev-medium)",
  low:                 "var(--sev-low)",
  secure:              "var(--sev-clean)",
}

/** Semicircular arc gauge. Worst-driven Constellus Risk Score at org scope —
 *  the number is the single worst open finding; breadth lives in the count badge. */
function ScoreGauge({ score, color }: { score: number; color: string }) {
  // Top semicircle, radius 80, centre (100,100). Arc length = π·r.
  const R = 80
  const LEN = Math.PI * R
  const frac = Math.max(0, Math.min(100, score)) / 100
  return (
    <svg viewBox="0 0 200 116" className="w-full max-w-[220px]" role="img" aria-label={`Risk score ${score}`}>
      <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="var(--border)" strokeWidth="12" strokeLinecap="round" />
      <path
        d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
        strokeDasharray={LEN} strokeDashoffset={LEN * (1 - frac)}
        style={{ transition: "stroke-dashoffset 600ms ease" }}
      />
      <text x="100" y="92" textAnchor="middle" className="font-bold tabular-nums" fontSize="40" fill={color}>{score}</text>
      <text x="100" y="108" textAnchor="middle" fontSize="11" fill="var(--muted-foreground)">/ 100</text>
    </svg>
  )
}

/** Day-over-day change in the worst-band count. Labeled "since yesterday" so the
 *  number reads as a delta, not a count. Down (fewer) is good → green. */
function TrendChange({ count, prev }: { count: number; prev: number }) {
  const net = count - prev
  if (net < 0) return (
    <span className="mt-0.5 inline-flex items-center gap-0.5 text-xs font-medium text-[var(--sev-clean)]">
      <ArrowDownRight className="h-3 w-3" />{Math.abs(net)} fewer since yesterday
    </span>
  )
  if (net > 0) return (
    <span className="mt-0.5 inline-flex items-center gap-0.5 text-xs font-medium text-[var(--sev-high)]">
      <ArrowUpRight className="h-3 w-3" />{net} more since yesterday
    </span>
  )
  return (
    <span className="mt-0.5 inline-flex items-center gap-0.5 text-xs text-muted-foreground">
      <Minus className="h-3 w-3" />No change since yesterday
    </span>
  )
}

function SecurityScoreGauge({ data, loading, error }: { data?: SecurityScore; loading: boolean; error?: boolean }) {
  const band  = data?.band ?? "secure"
  const color = BAND_VAR[band]
  const label = RISK_BAND_LABEL[band]
  const isSecure = band === "secure"

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-base">Security Score</CardTitle>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="flex flex-col items-center gap-3 py-4">
            <Skeleton className="h-24 w-48 rounded-t-full" />
            <Skeleton className="h-5 w-32" />
          </div>
        ) : error ? (
          // Unknown must never render as secure — a failed fetch shows a
          // distinct neutral "Unknown" state (locked --sev-unknown, no
          // numeric gauge that could misread as a good score), not the
          // green "Secure Posture" gauge (planning#92).
          <div className="flex flex-col items-center gap-2 py-8 text-center">
            <AlertTriangle className="h-8 w-8" style={{ color: "var(--sev-unknown)" }} />
            <p className="text-base font-bold" style={{ color: "var(--sev-unknown)" }}>Unable to load</p>
            <p className="text-xs text-muted-foreground max-w-[220px]">Couldn't reach the server — security score is unknown, not secure.</p>
          </div>
        ) : (
          <div className="flex flex-col items-center">
            <ScoreGauge score={data?.score ?? 0} color={color} />

            {/* Verdict at org scope */}
            <p className="text-lg font-bold -mt-1" style={{ color }}>
              {isSecure ? "Secure Posture ✓" : label}
            </p>

            {/* Worst-band count + day-over-day trend */}
            {isSecure ? (
              <p className="text-xs text-muted-foreground mt-1">No open findings across your attack surface.</p>
            ) : data ? (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Link to="/findings" className="mt-1.5 flex flex-col items-center cursor-help hover:opacity-80 transition-opacity">
                    <span className="text-sm">
                      <span className="font-semibold tabular-nums" style={{ color }}>{data.worst_band_count}</span>{" "}
                      <span className="text-muted-foreground">{label.toLowerCase()} finding{data.worst_band_count !== 1 ? "s" : ""}</span>
                    </span>
                    <TrendChange count={data.worst_band_count} prev={data.worst_band_count_prev} />
                  </Link>
                </TooltipTrigger>
                <TooltipContent side="bottom">
                  Last 24h: <span className="text-[var(--sev-high)] font-semibold">↑{data.worst_band_new} new</span>
                  {" · "}
                  <span className="text-[var(--sev-clean)] font-semibold">↓{data.worst_band_resolved} resolved</span>
                </TooltipContent>
              </Tooltip>
            ) : null}

            {/* Top contributors */}
            {data && data.breakdown.length > 0 && (
              <div className="w-full mt-4 pt-3 border-t space-y-1.5">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Top contributors</p>
                {data.breakdown.slice(0, 3).map(f => (
                  <Link key={f.id} to={`/findings/${f.id}`}
                    className="flex items-center gap-2 -mx-1 px-1 py-1 rounded hover:bg-accent/40 transition-colors">
                    <span className="font-mono text-xs tabular-nums w-7 shrink-0 text-right" style={{ color }}>{f.risk_score ?? "—"}</span>
                    <span className="flex-1 text-xs truncate">{f.title}</span>
                    {f.building_velocity && <span className="text-amber-500 shrink-0" title="Building Velocity">⚡</span>}
                  </Link>
                ))}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ── Recently remediated ───────────────────────────────────────────────────────

function RecentlyRemediated({ findings, loading, error }: { findings?: Finding[]; loading: boolean; error?: boolean }) {
  const remediated = (findings ?? [])
    .filter(f => effectiveBand(f) === "imminent_compromise" || effectiveBand(f) === "high")
    .sort((a, b) => new Date(b.resolved_at ?? b.last_seen_at).getTime() - new Date(a.resolved_at ?? a.last_seen_at).getTime())
    .slice(0, 6)

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <span className="inline-block h-2 w-2 rounded-full bg-[var(--sev-clean)]" />
          Recently remediated · Imminent &amp; High Risk
        </CardTitle>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}</div>
        ) : error ? (
          <p className="text-sm text-muted-foreground py-4">Couldn't load — data may be incomplete.</p>
        ) : remediated.length === 0 ? (
          <div className="py-6 text-center text-muted-foreground">
            <p className="text-sm">No resolved imminent or high-risk findings yet.</p>
          </div>
        ) : (
          <div className="divide-y">
            {remediated.map(f => (
              <Link key={f.id} to={`/findings/${f.id}`}
                className="flex items-center gap-3 py-2.5 -mx-1 px-1 rounded hover:bg-accent/40 transition-colors">
                <RiskBandBadge band={f.risk_band ?? effectiveBand(f)} score={f.risk_score} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{f.title}</p>
                  <p className="text-xs text-muted-foreground truncate font-mono">{displayName(f.asset_value)}</p>
                </div>
                <span className="text-xs text-muted-foreground shrink-0">
                  {relativeTime(f.resolved_at ?? f.last_seen_at)}
                </span>
              </Link>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ── Recent activity ───────────────────────────────────────────────────────────

function RecentActivity({ scans, loading, error }: { scans?: ScanRun[]; loading: boolean; error?: boolean }) {
  const recent = (scans ?? []).slice(0, 8)
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <Activity className="h-4 w-4" />
          Recent activity
        </CardTitle>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="space-y-2">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
        ) : error ? (
          <p className="text-sm text-muted-foreground py-4">Couldn't load — data may be incomplete.</p>
        ) : recent.length === 0 ? (
          <div className="py-6 text-center text-muted-foreground">
            <ScanLine className="h-10 w-10 mx-auto mb-3 opacity-30" />
            <p className="text-sm font-medium">No scan activity yet</p>
            <p className="text-xs mt-1">Add a target to kick off the first discovery run.</p>
          </div>
        ) : (
          <div className="divide-y">
            {recent.map(r => (
              <Link key={r.id} to={`/assets?scan=${r.id}`}
                className="flex items-center gap-3 py-2.5 -mx-1 px-1 rounded hover:bg-accent/40 transition-colors">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <p className="text-sm font-medium truncate">
                      {r.name ?? (r.scope.domains?.[0] ? displayName(r.scope.domains[0]) : null) ?? "Unnamed run"}
                    </p>
                    <Badge variant={STATUS_VARIANT[r.status]}>{r.status}</Badge>
                    <Badge variant="outline" className="text-[10px]">{KIND_LABEL[r.kind]}</Badge>
                    {r.status === "running" && <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />}
                  </div>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    {r.asset_count} asset{r.asset_count !== 1 ? "s" : ""} · {r.finding_count} finding{r.finding_count !== 1 ? "s" : ""}
                    {" · "}{relativeTime(r.completed_at ?? r.started_at ?? r.created_at)}
                  </p>
                </div>
              </Link>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const { user } = useAuthStore()

  const { data: targets, isLoading: tLoading, isError: tError } = useQuery({
    queryKey: ["targets-list"],
    queryFn: () => api.get<TargetType[]>("/targets/"),
  })

  const { data: assets, isLoading: aLoading, isError: aError } = useQuery({
    queryKey: ["assets-count"],
    queryFn: () => api.get<unknown[]>("/assets/"),
  })

  const { data: openFindings, isLoading: fLoading, isError: fError } = useQuery({
    queryKey: ["findings-open"],
    queryFn: () => api.get<Finding[]>("/findings/?state=open"),
  })

  const { data: resolvedFindings, isLoading: rLoading, isError: rError } = useQuery({
    queryKey: ["findings-resolved"],
    queryFn: () => api.get<Finding[]>("/findings/?state=resolved"),
  })

  const { data: securityScore, isLoading: scoreLoading, isError: scoreError } = useQuery({
    queryKey: ["security-score"],
    queryFn: () => api.get<SecurityScore>("/findings/security-score"),
  })

  const { data: scans, isLoading: sLoading, isError: sError } = useQuery({
    queryKey: ["scans-recent"],
    queryFn: () => api.get<ScanRun[]>("/scans/"),
    refetchInterval: (query) => {
      const data = query.state.data as ScanRun[] | undefined
      return data?.some(s => s.status === "running" || s.status === "pending") ? 5_000 : false
    },
  })

  const newThisWeek = (openFindings ?? []).filter(
    f => (Date.now() - new Date(f.first_seen_at).getTime()) < NEW_DAYS * 86_400_000
  ).length

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <p className="text-sm text-muted-foreground mt-1">Welcome back, {user?.full_name}</p>
      </div>

      {/* Stat row */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Link to="/admin/targets" className="block">
          <Card className="hover:bg-accent/50 transition-colors cursor-pointer">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Targets</CardTitle>
              <Target className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              {tLoading ? <Skeleton className="h-8 w-12" /> : tError ? (
                <div className="text-2xl font-bold" style={{ color: "var(--sev-unknown)" }} title="Couldn't load — data may be incomplete">?</div>
              ) : <div className="text-2xl font-bold">{targets?.length ?? "—"}</div>}
            </CardContent>
          </Card>
        </Link>

        <Link to="/assets" className="block">
          <Card className="hover:bg-accent/50 transition-colors cursor-pointer">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Assets</CardTitle>
              <Globe className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              {aLoading ? <Skeleton className="h-8 w-12" /> : aError ? (
                <div className="text-2xl font-bold" style={{ color: "var(--sev-unknown)" }} title="Couldn't load — data may be incomplete">?</div>
              ) : <div className="text-2xl font-bold">{assets?.length ?? "—"}</div>}
            </CardContent>
          </Card>
        </Link>

        <Link to="/findings" className="block">
          <Card className="hover:bg-accent/50 transition-colors cursor-pointer">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Open Findings</CardTitle>
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              {fLoading ? <Skeleton className="h-8 w-12" /> : fError ? (
                <div className="text-2xl font-bold" style={{ color: "var(--sev-unknown)" }} title="Couldn't load — data may be incomplete">?</div>
              ) : <div className="text-2xl font-bold">{openFindings?.length ?? "—"}</div>}
            </CardContent>
          </Card>
        </Link>

        <Link to="/findings?since=7d" className="block">
          <Card className="hover:bg-accent/50 transition-colors cursor-pointer">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">New (7d)</CardTitle>
              <Sparkles className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              {fLoading ? <Skeleton className="h-8 w-12" /> : fError ? (
                <div className="text-2xl font-bold" style={{ color: "var(--sev-unknown)" }} title="Couldn't load — data may be incomplete">?</div>
              ) : <div className="text-2xl font-bold">{newThisWeek}</div>}
            </CardContent>
          </Card>
        </Link>
      </div>

      {/* Severity strip */}
      <SeverityStrip findings={openFindings} loading={fLoading} error={fError} />

      {/* SSVC posture strip (hidden until findings are SSVC-scored) */}
      <SsvcStrip findings={openFindings} loading={fLoading} error={fError} />

      {/* Category + security score */}
      <div className="grid gap-4 lg:grid-cols-2">
        <CategoryBreakdown findings={openFindings} loading={fLoading} error={fError} />
        <SecurityScoreGauge data={securityScore} loading={scoreLoading} error={scoreError} />
      </div>

      {/* Activity + recently remediated */}
      <div className="grid gap-4 lg:grid-cols-2">
        <RecentActivity scans={scans} loading={sLoading} error={sError} />
        <RecentlyRemediated findings={resolvedFindings} loading={rLoading} error={rError} />
      </div>
    </div>
  )
}
