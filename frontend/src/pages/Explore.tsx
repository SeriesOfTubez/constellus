import { useState } from "react"
import { Link, useSearchParams } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"
import { Braces, Network } from "lucide-react"
import { api, ApiError } from "@/lib/api"
import {
  formatCount, parseExploreParam, summariseQuery,
  type QueryCountResponse, type QueryObject, type QueryRowsResponse,
} from "@/lib/chat"
import { relativeTime } from "@/lib/time"

/**
 * Explore. Until the #53 builder exists, `?q=<query JSON>` (from the chat
 * assistant's "Open in Explore") shows that query's results as a table and
 * its exact count. The link carries only the query, never data: the query
 * runs as whoever opens it, through the same validator and read scope as
 * any other `POST /api/query`. Without `q` this is the placeholder.
 */
export default function Explore() {
  const [params] = useSearchParams()
  const raw = params.get("q")
  if (raw === null) return <Placeholder />
  const q = parseExploreParam(raw)
  if (!q) return <Problem>This link's query could not be read.</Problem>
  return <QueryResults q={q} raw={raw} />
}

function Placeholder() {
  return (
    <div className="flex flex-col items-center justify-center h-full gap-4 text-center p-8">
      <Network className="h-12 w-12 text-muted-foreground/40" />
      <div className="space-y-1">
        <h2 className="text-lg font-semibold">Graph Explorer</h2>
        <p className="text-sm text-muted-foreground max-w-sm">
          Point-and-click query builder over the attack-surface graph — coming soon.
        </p>
      </div>
    </div>
  )
}

function Problem({ children }: { children: React.ReactNode }) {
  return (
    <div className="p-6 space-y-2">
      <h1 className="text-lg font-semibold">Explore</h1>
      <div className="text-sm text-muted-foreground">{children}</div>
    </div>
  )
}

/** Field errors from the backend validator (422 detail.errors). */
function validationErrors(err: unknown): { path: string; message: string }[] {
  if (!(err instanceof ApiError) || err.status !== 422) return []
  const d = err.detail as { errors?: unknown } | undefined
  return Array.isArray(d?.errors) ? d.errors.filter(
    (e): e is { path: string; message: string } => !!e && typeof e.path === "string" && typeof e.message === "string",
  ) : []
}

// A record column links to its page when the row carries that record's id.
const LINKED: Record<string, { idCol: string; base: string }> = {
  "asset.value": { idCol: "asset.id", base: "/assets/" },
  "finding.title": { idCol: "finding.id", base: "/findings/" },
}

function cellText(col: string, v: unknown): string {
  if (v === null || v === undefined || v === "") return "—"
  if (Array.isArray(v)) return v.length ? v.join(", ") : "—"
  if (typeof v === "boolean") return v ? "yes" : "no"
  if (col.endsWith("_at") && typeof v === "string") return relativeTime(v)
  if (typeof v === "object") return JSON.stringify(v)
  return String(v)
}

function QueryResults({ q, raw }: { q: QueryObject; raw: string }) {
  const [showJson, setShowJson] = useState(false)
  const rows = useQuery({
    queryKey: ["explore", "rows", raw],
    queryFn: () => api.post<QueryRowsResponse>("/query", q),
    retry: false,
  })
  const count = useQuery({
    queryKey: ["explore", "count", raw],
    queryFn: () => api.post<QueryCountResponse>("/query?mode=count", q),
    retry: false,
  })

  const error = rows.error ?? count.error
  const errors = validationErrors(error)
  const columns = rows.data?.columns.filter(c => !c.endsWith(".id")) ?? []

  return (
    <div className="p-6 space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-semibold">Explore</h1>
        <span className="rounded border px-1.5 py-0.5 text-xs text-muted-foreground">From chat</span>
        <span className="font-mono text-xs text-muted-foreground truncate max-w-[50ch]" title={summariseQuery(q)}>
          {summariseQuery(q)}
        </span>
        <span className="ml-auto text-xs text-muted-foreground" data-testid="explore-count">
          {count.data && <><span className="font-mono text-foreground">{formatCount(count.data.count, count.data.capped)}</span> matches</>}
          {count.data && rows.data && <> · showing {rows.data.row_count.toLocaleString("en-US")}</>}
        </span>
        <button className="flex items-center gap-1 text-xs text-primary hover:opacity-80" onClick={() => setShowJson(s => !s)}>
          <Braces className="h-3.5 w-3.5" /> Query
        </button>
      </div>

      {showJson && (
        <pre className="overflow-x-auto rounded-md border bg-muted/40 p-3 text-xs">{JSON.stringify(q, null, 2)}</pre>
      )}

      {error && (errors.length ? (
        <div className="rounded-md border p-3 text-sm space-y-1" data-testid="explore-errors">
          <p className="font-medium">This query is not valid.</p>
          <ul className="list-disc ml-5 text-xs text-muted-foreground">
            {errors.map((e, i) => <li key={i}><span className="font-mono">{e.path}</span>: {e.message}</li>)}
          </ul>
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">The query could not be run: {error.message}</p>
      ))}

      {rows.isLoading && <p className="text-sm text-muted-foreground">Running…</p>}

      {rows.data && (rows.data.rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">No records match.</p>
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full text-xs" data-testid="explore-table">
            <thead className="bg-muted/40 text-left text-muted-foreground">
              <tr>{columns.map(c => <th key={c} className="px-3 py-2 font-medium whitespace-nowrap">{c}</th>)}</tr>
            </thead>
            <tbody className="divide-y">
              {rows.data.rows.map((r, i) => (
                <tr key={i}>
                  {columns.map(c => {
                    const link = LINKED[c]
                    const id = link ? r[link.idCol] : undefined
                    const text = cellText(c, r[c])
                    return (
                      <td key={c} className="px-3 py-1.5 max-w-[40ch] truncate" title={text}>
                        {typeof id === "string"
                          ? <Link to={link.base + encodeURIComponent(id)} className="text-primary hover:underline">{text}</Link>
                          : text}
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
      {rows.data?.truncated && (
        <p className="text-xs text-muted-foreground">
          Showing the first {rows.data.row_count.toLocaleString("en-US")}, the query's own limit.
        </p>
      )}
    </div>
  )
}
