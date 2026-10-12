import { Globe } from "lucide-react"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { AiInferredBadge } from "@/components/ai/AiInferredBadge"
import {
  ENV_LABELS, effectiveLabel, endpointFlags, endpointKey,
  type WebEndpointState,
} from "@/lib/webClassification"
import { statusCell, titleCell } from "@/lib/redirectChain"

/** Web endpoints (planning#231). All text is rendered as plain React text nodes. */
export function EndpointsTable({
  groups, onOpen, filtered,
}: {
  groups: Array<{ key: string; label: string | null; rows: WebEndpointState[] }>
  onOpen: (row: WebEndpointState & { id: string }) => void
  filtered: boolean
}) {
  const total = groups.reduce((n, g) => n + g.rows.length, 0)
  if (total === 0) {
    return (
      <div className="rounded-lg border bg-card p-12 text-center text-muted-foreground">
        <Globe className="h-12 w-12 mx-auto mb-4 opacity-30" />
        <p className="font-medium">{filtered ? "No endpoints match these filters" : "No web endpoints discovered"}</p>
      </div>
    )
  }
  return (
    <div className="rounded-lg border overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead>Endpoint</TableHead>
            <TableHead>Title</TableHead>
            <TableHead className="w-20">Status</TableHead>
            <TableHead>Kind</TableHead>
            <TableHead>Environment</TableHead>
            <TableHead className="w-16">Flags</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {groups.map(g => (
            <GroupRows key={g.key} group={g} onOpen={onOpen} />
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

function GroupRows({
  group, onOpen,
}: {
  group: { key: string; label: string | null; rows: WebEndpointState[] }
  onOpen: (row: WebEndpointState & { id: string }) => void
}) {
  return (
    <>
      {group.label !== null && (
        <TableRow className="bg-muted/30 hover:bg-muted/30">
          <TableCell colSpan={6}>
            <span className="text-sm font-semibold">{group.label}</span>
            <span className="ml-2 text-xs text-muted-foreground bg-muted px-1.5 py-0.5 rounded-full">{group.rows.length}</span>
          </TableCell>
        </TableRow>
      )}
      {group.rows.map(row => {
        const id = endpointKey(row)
        const warn = endpointFlags(row).filter(f => f.tone === "warn")
        const none = row.source === "none"
        const title = titleCell(row.http_title, row.redirect_chain)
        return (
          <TableRow key={id} className="cursor-pointer" onClick={() => onOpen({ ...row, id })}>
            <TableCell className="font-mono text-sm">{row.asset_value}:{row.port}</TableCell>
            <TableCell className="max-w-xs text-xs text-muted-foreground">
              <div className={title.destination ? "truncate italic text-muted-foreground/70" : "truncate"} title={title.tooltip}>
                {title.text}
              </div>
            </TableCell>
            <TableCell className="text-xs tabular-nums whitespace-nowrap">{statusCell(row.http_status, row.redirect_chain)}</TableCell>
            <TableCell>
              <span className="inline-flex flex-wrap items-center gap-1.5 text-xs">
                <span className={none ? "text-muted-foreground" : "font-medium"}>{effectiveLabel(row)}</span>
                {!none && (
                  <AiInferredBadge
                    source={row.source as "ai" | "user"}
                    setBy={row.override?.set_by}
                    at={row.override?.updated_at}
                    model={row.ai?.model}
                  />
                )}
              </span>
            </TableCell>
            <TableCell className="text-xs text-muted-foreground">
              {none || !row.environment || row.environment === "unknown" ? "—" : ENV_LABELS[row.environment]}
            </TableCell>
            <TableCell>
              {warn.length > 0 && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span className="inline-flex items-center gap-1 cursor-help" aria-label={`${warn.length} flags`}>
                      <span className="h-2 w-2 rounded-full bg-amber-500" />
                      <span className="text-[10px] text-muted-foreground">{warn.length}</span>
                    </span>
                  </TooltipTrigger>
                  <TooltipContent side="left" className="max-w-xs">
                    <div className="space-y-0.5">
                      {warn.map(f => <p key={f.key}>{f.text}</p>)}
                    </div>
                  </TooltipContent>
                </Tooltip>
              )}
            </TableCell>
          </TableRow>
        )
      })}
    </>
  )
}
