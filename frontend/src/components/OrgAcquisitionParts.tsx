// Acquisitions tab roll-up table (planning#277 S4a). No trend column: split to planning#315.
import { SquareArrowOutUpRight } from "lucide-react"
import {
  type AcquisitionRow, SEVERITY_BAR_CLASS,
  formatClosed, formatShare, ipSpaceLabel, postureLabel, severityBar,
} from "@/lib/organizations"
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
