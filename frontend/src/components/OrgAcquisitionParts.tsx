// Acquisitions tab roll-up table + timeline (planning#277 S4a table, S4b timeline). No trend column: split to planning#315.
import { type CSSProperties, useMemo, useState } from "react"
import { ChevronLeft, ChevronRight, SquareArrowOutUpRight, ZoomIn, ZoomOut } from "lucide-react"
import {
  type AcquisitionRow, SEVERITY_BAR_CLASS,
  formatClosed, formatShare, ipSpaceLabel, postureLabel, severityBar,
} from "@/lib/organizations"
import {
  assignLanes, canPan, canZoomIn, canZoomOut, currentWindow, dotKind, dotTitle, extent, offEdges, pan,
  placementMs, xFraction, yearTicks, zoomIn, zoomOut, type TimelineView, type Window,
} from "@/lib/acquisitionTimeline"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

export const SHARE_TITLE =
  "Summed risk score of this company's open findings ÷ the same sum over the estate (claimed scope only)"

function Cand({ n }: { n: number }) {
  return n > 0 ? <span className="ml-1 text-xs text-muted-foreground">+{n} cand</span> : null
}

function FindingsCell({ row }: { row: AcquisitionRow }) {
  const bar = severityBar(row.open_findings)
  if (bar.total === 0) return <span className="text-xs text-muted-foreground">none</span>
  return (
    <div className="flex items-center gap-2 text-xs">
      <span
        className="flex h-1.5 w-20 overflow-hidden rounded-full bg-muted"
        title={bar.segments.map(s => `${s.count} ${s.severity}`).join(", ")}
      >
        {bar.segments.map(s => (
          <span key={s.severity} className={SEVERITY_BAR_CLASS[s.severity]} style={{ width: `${s.pct}%` }} />
        ))}
      </span>
      <span className="tabular-nums">{bar.total}</span>
    </div>
  )
}

export function AcquisitionsTable({
  rows, onOpenCompany,
}: { rows: AcquisitionRow[]; onOpenCompany?: (entityId: string | null) => void }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Acquired company</TableHead>
          <TableHead>Closed</TableHead>
          <TableHead>Posture</TableHead>
          <TableHead>Domains</TableHead>
          <TableHead>IP space</TableHead>
          <TableHead>Assets</TableHead>
          <TableHead>Open findings</TableHead>
          <TableHead>KEV</TableHead>
          <TableHead title={SHARE_TITLE}>Share of estate risk</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map(row => (
          <TableRow key={row.entity_id ?? "organic"}>
            <TableCell className="text-sm font-medium">
              <span className="inline-flex items-center gap-1">
                {row.organic
                  ? <span className="text-muted-foreground">{row.name} (organic)</span>
                  : <span>{row.name}</span>}
                {onOpenCompany && (
                  <Button
                    variant="ghost" size="icon" className="h-6 w-6"
                    title="Open in Companies & filings" aria-label="Open in Companies & filings"
                    onClick={() => onOpenCompany(row.organic ? null : row.entity_id)}
                  >
                    <SquareArrowOutUpRight className="h-3.5 w-3.5" />
                  </Button>
                )}
              </span>
            </TableCell>
            <TableCell className="text-sm">{formatClosed(row.closed, row.closed_precision)}</TableCell>
            <TableCell className="text-sm">
              {row.postures.length ? row.postures.map(postureLabel).join(", ") : "—"}
            </TableCell>
            <TableCell className="text-sm tabular-nums">{row.domains_claimed}<Cand n={row.domains_to_review} /></TableCell>
            <TableCell className="text-sm">{ipSpaceLabel(row)}<Cand n={row.ip_to_review} /></TableCell>
            <TableCell className="text-sm tabular-nums">{row.assets}</TableCell>
            <TableCell><FindingsCell row={row} /></TableCell>
            <TableCell className={`text-sm tabular-nums ${row.kev === 0 ? "text-muted-foreground" : ""}`}>{row.kev}</TableCell>
            <TableCell className="text-sm tabular-nums" title={SHARE_TITLE}>{formatShare(row.risk_share)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

function dotStyle(row: AcquisitionRow): CSSProperties {
  const kind = dotKind(row)
  if (kind === "filled") return { backgroundColor: `var(--sev-${row.worst_severity})` }
  if (kind === "clean") return { backgroundColor: "var(--sev-clean)" }
  return { backgroundColor: "transparent", border: "2px solid var(--sev-unknown)" }
}

const RING = "ring-2 ring-foreground ring-offset-2 ring-offset-background"

export function AcquisitionTimeline({
  rows, selected, onSelect,
}: { rows: AcquisitionRow[]; selected: string | null; onSelect: (entityId: string | null) => void }) {
  const deals = useMemo(() => rows.filter(r => !r.organic && r.entity_id), [rows])
  const placed = useMemo(
    () => deals.flatMap(r => { const ms = placementMs(r.closed, r.closed_precision); return ms === null ? [] : [{ row: r, ms }] }),
    [deals],
  )
  const undated = useMemo(() => deals.filter(r => placementMs(r.closed, r.closed_precision) === null), [deals])
  const ext = useMemo(() => extent(placed.map(p => p.ms)), [placed])
  const [view, setView] = useState<TimelineView | null>(null)
  const setWin = (win: Window) => ext && setView({ ext, win })
  if (deals.length === 0) return null

  const w = currentWindow(view, ext)
  const inWin = w ? placed.filter(p => p.ms >= w.start && p.ms <= w.end) : []
  const xs = w ? inWin.map(p => xFraction(p.ms, w)) : []
  const lanes = assignLanes(xs)
  const laneCount = lanes.length ? Math.max(...lanes) + 1 : 1
  const off = w ? offEdges(placed.map(p => p.ms), w) : { before: 0, after: 0 }
  const pick = (id: string) => onSelect(selected === id ? null : id)

  return (
    <div className="space-y-2">
      {w && ext && (
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="icon" className="h-7 w-7" aria-label="Earlier"
            disabled={!canPan(w, ext, -1)} onClick={() => setWin(pan(w, ext, -1))}>
            <ChevronLeft className="h-4 w-4" />
          </Button>
          {off.before > 0 && <span className="text-xs text-muted-foreground">+{off.before}</span>}
          <Button variant="ghost" size="icon" className="h-7 w-7" aria-label="Later"
            disabled={!canPan(w, ext, 1)} onClick={() => setWin(pan(w, ext, 1))}>
            <ChevronRight className="h-4 w-4" />
          </Button>
          {off.after > 0 && <span className="text-xs text-muted-foreground">+{off.after}</span>}
          <span className="ml-2 flex items-center gap-1">
            <Button variant="outline" size="icon" className="h-7 w-7" aria-label="Zoom out"
              disabled={!canZoomOut(w, ext)} onClick={() => setWin(zoomOut(w, ext))}>
              <ZoomOut className="h-4 w-4" />
            </Button>
            <Button variant="outline" size="icon" className="h-7 w-7" aria-label="Zoom in"
              disabled={!canZoomIn(w)} onClick={() => setWin(zoomIn(w, ext))}>
              <ZoomIn className="h-4 w-4" />
            </Button>
          </span>
        </div>
      )}
      {w && (
        <div className="relative mx-3" style={{ height: 4 + laneCount * 16 + 24 }}>
          <div className="absolute left-0 right-0 h-px bg-border" style={{ top: 10 }} />
          {yearTicks(w).map(t => (
            <span key={t.year} className="absolute -translate-x-1/2 text-xs text-muted-foreground"
              style={{ left: `${t.x * 100}%`, top: 4 + laneCount * 16 + 4 }}>
              {t.year}
            </span>
          ))}
          {inWin.map((p, i) => {
            const id = p.row.entity_id as string
            const title = dotTitle(p.row)
            return (
              <button
                key={id} type="button" title={title} aria-label={title} aria-pressed={selected === id}
                className={`absolute h-3 w-3 -translate-x-1/2 rounded-full ${selected === id ? RING : ""}`}
                style={{ left: `${xs[i] * 100}%`, top: 4 + lanes[i] * 16, ...dotStyle(p.row) }}
                onClick={() => pick(id)}
              />
            )
          })}
        </div>
      )}
      {undated.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-muted-foreground">Date unknown</span>
          {undated.map(r => {
            const id = r.entity_id as string
            const title = dotTitle(r)
            return (
              <button
                key={id} type="button" title={title} aria-label={title} aria-pressed={selected === id}
                className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs ${selected === id ? RING : ""}`}
                onClick={() => pick(id)}
              >
                <span className="h-2 w-2 rounded-full" style={dotStyle(r)} />
                {r.name}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}
