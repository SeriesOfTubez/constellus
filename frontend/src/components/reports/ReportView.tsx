import { Link } from "react-router-dom"
import { Download, Loader2, SquareArrowOutUpRight, Trash2 } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { exploreHref, isInternalHref, type QueryObject } from "@/lib/chat"
import { entityHref } from "@/lib/organizations"
import {
  KIND_LABELS, SECTIONS_BY_KIND, citationHref, formatCount, listRowText,
  type Report, type Statement,
} from "@/lib/reports"

interface Props {
  report: Report
  engagementName: string
  /** Delete is offered only when this is provided (the page passes it for permitted roles). */
  onDelete?: () => void
  onDownload?: () => void
}

function MetricsTable({ report }: { report: Report }) {
  const all = report.facts?.metrics ?? {}
  // JSONB does not keep key order: show metrics in the order the facts were built.
  const order = (report.facts?.metric_order ?? Object.keys(all)).filter(k => k in all)
  const metrics = order.map(k => [k, all[k]] as const)
  if (!metrics.length) return null
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Measure</TableHead>
          <TableHead className="text-right">Count</TableHead>
          <TableHead className="w-10" />
        </TableRow>
      </TableHeader>
      <TableBody>
        {metrics.map(([key, m]) => (
          <TableRow key={key}>
            <TableCell>{m.label}</TableCell>
            <TableCell className="text-right tabular-nums">{formatCount(m)}</TableCell>
            <TableCell>
              <Link
                to={exploreHref(m.query as QueryObject)}
                title="Open in Explore"
                aria-label={`Open ${m.label} in Explore`}
                className="text-muted-foreground hover:text-foreground"
              >
                <SquareArrowOutUpRight className="h-3.5 w-3.5" />
              </Link>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

/** `first` is the number of this statement's first citation: citations are
 *  numbered across the whole report, as in the markdown export. */
function StatementView({ statement, report, first }: { statement: Statement; report: Report; first: number }) {
  return (
    <li className="text-sm leading-relaxed">
      {statement.text}
      {statement.citations.map((c, i) => {
        const href = citationHref(c, report)
        const title = `${c.path} = ${c.value}`
        return (
          <sup key={i} className="ml-0.5 text-xs">
            {href ? (
              <Link to={href} title={title} className="text-primary hover:underline">[{first + i}]</Link>
            ) : (
              <span title={title} className="text-muted-foreground">[{first + i}]</span>
            )}
          </sup>
        )
      })}
    </li>
  )
}

function Narrative({ report }: { report: Report }) {
  const statements = report.payload?.statements ?? []
  if (!statements.length) {
    return <p className="text-sm text-muted-foreground">No statement could be tied to the data, so none is shown.</p>
  }
  let next = 1
  return (
    <div className="space-y-4">
      {SECTIONS_BY_KIND[report.kind].map(({ key: section, label }) => {
        const items = statements.filter(s => s.section === section)
        if (!items.length) return null
        return (
          <section key={section} className="space-y-1.5">
            <h3 className="text-sm font-semibold">{label}</h3>
            <ul className="list-disc pl-5 space-y-1.5">
              {items.map((s, i) => {
                const first = next
                next += s.citations.length
                return <StatementView key={i} statement={s} report={report} first={first} />
              })}
            </ul>
          </section>
        )
      })}
    </div>
  )
}

function FactLists({ report }: { report: Report }) {
  const lists = report.facts?.lists
  const order = (report.facts?.list_order ?? []).filter(k => lists && k in lists)
  if (!lists || !order.length) return null
  return (
    <>
      {order.map(key => {
        const list = lists[key]
        return (
          <section key={key} className="space-y-2">
            <h3 className="text-sm font-semibold flex items-center gap-2">
              {list.label}
              <Link
                to={exploreHref(list.query as QueryObject)}
                title="Open in Explore"
                aria-label={`Open ${list.label} in Explore`}
                className="text-muted-foreground hover:text-foreground"
              >
                <SquareArrowOutUpRight className="h-3.5 w-3.5" />
              </Link>
            </h3>
            {list.rows.length === 0 ? (
              <p className="text-sm text-muted-foreground">None recorded.</p>
            ) : (
              <ul className="list-disc pl-5 space-y-1">
                {list.rows.map((row, i) => {
                  const text = listRowText(key, row)
                  const href = row.entity_id ? entityHref(row.entity_id) : ""
                  return (
                    <li key={i} className="text-sm">
                      {row.entity_id && isInternalHref(href)
                        ? <Link to={href} className="hover:underline">{text}</Link>
                        : text}
                    </li>
                  )
                })}
              </ul>
            )}
            {list.truncated && (
              <p className="text-xs text-muted-foreground">Showing the first {list.rows.length}; more exist.</p>
            )}
          </section>
        )
      })}
    </>
  )
}

function TopFindings({ report }: { report: Report }) {
  const findings = report.facts?.top_findings ?? []
  return (
    <section className="space-y-2">
      <h3 className="text-sm font-semibold">Top findings</h3>
      {findings.length === 0 ? (
        <p className="text-sm text-muted-foreground">No open findings recorded for this engagement.</p>
      ) : (
        <ul className="space-y-1.5">
          {findings.map(f => {
            const href = `/findings/${f.id}`
            return (
              <li key={f.id} className="text-sm flex flex-wrap items-center gap-2">
                {isInternalHref(href)
                  ? <Link to={href} className="hover:underline">{f.title}</Link>
                  : <span>{f.title}</span>}
                <Badge variant="outline">{f.severity}</Badge>
                {f.risk_score != null && <span className="text-xs text-muted-foreground">risk {f.risk_score}</span>}
                {f.kev && <Badge variant="destructive">KEV</Badge>}
                <span className="text-xs text-muted-foreground">{f.asset_value}</span>
              </li>
            )
          })}
        </ul>
      )}
    </section>
  )
}

export function ReportView({ report, engagementName, onDelete, onDownload }: Props) {
  const inFlight = report.status === "queued" || report.status === "running"
  return (
    <div className="space-y-5">
      <header className="space-y-1">
        <h2 className="text-lg font-semibold">{KIND_LABELS[report.kind]}</h2>
        <p className="text-sm text-muted-foreground">{engagementName}</p>
        {report.kind === "ma_brief" && report.facts?.subject && (
          <p className="text-sm text-muted-foreground">
            Subject:{" "}
            {isInternalHref(entityHref(report.facts.subject.id))
              ? <Link to={entityHref(report.facts.subject.id)} className="hover:underline">{report.facts.subject.name}</Link>
              : report.facts.subject.name}
          </p>
        )}
        <p className="text-xs text-muted-foreground">
          As of {new Date(report.as_of).toLocaleString()}
          {report.model ? ` · ${report.model}` : ""}
          {report.cost_usd != null ? ` · $${report.cost_usd.toFixed(4)}` : ""}
        </p>
      </header>

      {inFlight && (
        <p className="text-sm text-muted-foreground flex items-center gap-2">
          <Loader2 className="h-4 w-4 animate-spin" />
          {report.status === "queued" ? "Queued…" : "Generating…"}
        </p>
      )}

      {report.status === "failed" && (
        <div className="space-y-2">
          <p className="text-sm text-destructive">{report.error ?? "The report failed."}</p>
          {report.facts && (
            <p className="text-sm text-muted-foreground">
              The numbers below were computed; the narrative could not be generated.
            </p>
          )}
        </div>
      )}

      {report.status === "done" && <Narrative report={report} />}

      {(report.status === "done" || report.status === "failed") && report.facts && (
        <>
          <MetricsTable report={report} />
          <FactLists report={report} />
          {report.status === "done" && <TopFindings report={report} />}
        </>
      )}

      {report.status === "done" && report.statements_dropped > 0 && (
        <p className="text-xs text-muted-foreground">
          {report.statements_dropped === 1
            ? "1 statement was dropped because it could not be tied to the data."
            : `${report.statements_dropped} statements were dropped because they could not be tied to the data.`}
        </p>
      )}

      <div className="flex gap-2">
        {report.status === "done" && onDownload && (
          <Button variant="outline" size="sm" onClick={onDownload}>
            <Download className="h-4 w-4 mr-1.5" />Download markdown
          </Button>
        )}
        {onDelete && !inFlight && (
          <Button variant="outline" size="sm" onClick={onDelete}>
            <Trash2 className="h-4 w-4 mr-1.5" />Delete
          </Button>
        )}
      </div>
    </div>
  )
}
