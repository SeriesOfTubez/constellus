// "ASNs & IP space" tab pieces (planning#278 S3d).
//
// A reassignment record is a REGISTRY OBSERVATION, not a finding: it is shown
// with the neutral Info icon and muted styling only, and nothing here can
// un-claim, release or delete a claimed candidate because of one.
import { useState } from "react"
import { useMutation, useQuery } from "@tanstack/react-query"
import { Info, RefreshCw } from "lucide-react"
import { api, ApiError } from "@/lib/api"
import { useCan } from "@/lib/permissions"
import { relativeTime } from "@/lib/time"
import { cn } from "@/lib/utils"
import {
  type CandidateRow, type RecheckAccepted, type ReassignmentPage, type ReassignmentRow,
  registryChangeText, registryHolder,
} from "@/lib/organizations"
import { AssetsCell, DECIDE, SignalsCell, StateCell, errorDetail } from "@/components/OrgCandidateParts"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

export const REGISTRY_CHANGE_TITLE =
  "The registry now lists part of this prefix under another holder. This is a registry observation, not a finding."

export function RegistryChangeBadge() {
  return (
    <span
      title={REGISTRY_CHANGE_TITLE}
      className="ml-2 inline-flex items-center gap-1 rounded border bg-muted/40 px-1.5 py-0.5 align-middle font-sans text-[11px] font-medium text-muted-foreground"
    >
      <Info className="h-3 w-3" />Registry change
    </span>
  )
}

export function RegistryObservationList({ rows }: { rows: ReassignmentRow[] }) {
  return (
    <section className="space-y-2">
      <h3 className="text-sm font-semibold">Registry observations</h3>
      {rows.length === 0 ? (
        <p className="text-xs text-muted-foreground">No registry changes recorded.</p>
      ) : (
        <>
          <ul className="space-y-2">
            {rows.map(r => (
              <li key={r.id} className="flex items-start gap-2 rounded-md border bg-muted/30 p-2.5">
                <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                <div className="min-w-0 space-y-0.5">
                  <p className="text-sm">{registryChangeText(r)}</p>
                  <p className="text-xs text-muted-foreground">
                    First seen {relativeTime(r.first_detected_at)} · last seen {relativeTime(r.last_seen_at)}
                  </p>
                </div>
              </li>
            ))}
          </ul>
          <p className="text-xs text-muted-foreground">
            Your claim and its target are unchanged. Review whether this space is still yours.
          </p>
        </>
      )}
    </section>
  )
}

export function RegistryObservations({ orgId, candidateId }: { orgId: string; candidateId: string }) {
  const q = useQuery({
    queryKey: ["org-reassignments", orgId, candidateId],
    queryFn: () => api.get<ReassignmentPage>(
      `/organizations/${orgId}/reassignments?candidate_id=${candidateId}&limit=100`),
  })
  if (q.isLoading) return <Skeleton className="h-16 w-full" />
  if (q.isError) return <p className="text-xs text-muted-foreground">{errorDetail(q.error)}</p>
  return <RegistryObservationList rows={q.data?.items ?? []} />
}

export function IpSpaceTable({
  rows, kind, flagged, onOpen, activeId, labelOf,
}: {
  rows: CandidateRow[]
  kind: "asn" | "cidr"
  flagged: Set<string>
  onOpen: (r: CandidateRow) => void
  activeId?: string
  labelOf: (t: string) => string
}) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{kind === "asn" ? "ASN" : "Prefix"}</TableHead>
          <TableHead>Registry</TableHead>
          <TableHead>Signals</TableHead>
          <TableHead>State</TableHead>
          {kind === "cidr" && <TableHead>Assets</TableHead>}
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map(r => (
          <TableRow key={r.id} className={cn("cursor-pointer", r.id === activeId && "bg-accent/50")} onClick={() => onOpen(r)}>
            <TableCell className="font-mono text-sm">
              {r.value}
              {kind === "cidr" && flagged.has(r.id) && <RegistryChangeBadge />}
            </TableCell>
            <TableCell className="text-sm">{registryHolder(r)}</TableCell>
            <TableCell><SignalsCell row={r} labelOf={labelOf} /></TableCell>
            <TableCell><StateCell row={r} /></TableCell>
            {kind === "cidr" && <TableCell><AssetsCell row={r} /></TableCell>}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

export function RecheckButton({ orgId }: { orgId: string }) {
  const can = useCan()
  const [started, setStarted] = useState(false)
  const m = useMutation({
    mutationFn: () => api.post<RecheckAccepted>(`/organizations/${orgId}/recheck`),
    onMutate: () => setStarted(false),
    onSuccess: () => setStarted(true),
  })
  if (!can(DECIDE)) return null
  return (
    <div className="flex items-center gap-3">
      <Button size="sm" variant="outline" disabled={m.isPending} onClick={() => m.mutate()}>
        <RefreshCw className={cn("h-4 w-4 mr-1", m.isPending && "animate-spin")} />Re-check registries
      </Button>
      {started && (
        <span className="max-w-md text-xs text-muted-foreground">
          Re-check started. ARIN and RIPE are asked again for this organization's claimed domains and prefixes; results appear here when it finishes.
        </span>
      )}
      {m.isError && (
        m.error instanceof ApiError && m.error.status === 409
          ? <span className="text-xs text-muted-foreground">A re-check of this organization is already running.</span>
          : <span role="alert" className="text-xs text-destructive">{errorDetail(m.error)}</span>
      )}
    </div>
  )
}
