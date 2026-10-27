import { useState } from "react"
import { Plug } from "lucide-react"
import { ApiError } from "@/lib/api"
import { useCan } from "@/lib/permissions"
import { openEvidence } from "@/lib/evidence"
import { relativeTime } from "@/lib/time"
import {
  type CandidateDetail, type CandidateRow, type OrganizationSummary, type SignalDetail, type TreeNode,
  STRENGTH_LABEL, TIER_LABEL, SEVERITY_BAR_CLASS,
  anchorText, destinationText, eventText, severityBar, splitSignals, stateInfo, tierChipClass,
} from "@/lib/organizations"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Textarea } from "@/components/ui/textarea"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { OverflowCell } from "@/components/ui/overflow-cell"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"

export const DECIDE = "entities.decide_candidate"

export function errorDetail(e: unknown): string {
  if (e instanceof ApiError) return typeof e.detail === "string" ? e.detail : e.message
  return e instanceof Error ? e.message : "Request failed"
}

export function TierChip({ tier, label, title }: { tier: string; label: string; title?: string }) {
  return (
    <span title={title} className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[11px] font-medium ${tierChipClass(tier)}`}>
      {label}
    </span>
  )
}

type LabelOf = (signalType: string) => string

export function SignalsCell({ row, labelOf }: { row: CandidateRow; labelOf: LabelOf }) {
  const tip = (s: CandidateRow["signals"][number]) => `${labelOf(s.signal_type)} · ${s.family} · ${TIER_LABEL[s.tier] ?? s.tier}`
  return (
    <OverflowCell
      items={row.signals}
      limit={2}
      getLabel={tip}
      renderItem={s => <TierChip key={s.signal_type} tier={s.tier} label={labelOf(s.signal_type)} title={tip(s)} />}
      renderOverflowItem={s => <span>{tip(s)}</span>}
    />
  )
}

export function AssetsCell({ row }: { row: CandidateRow }) {
  if (row.status !== "claimed" || row.asset_count === null) return <span className="text-muted-foreground text-xs">—</span>
  if (row.asset_count === 0) return <span className="text-muted-foreground text-xs">no assets recorded</span>
  const bar = severityBar(row.open_findings)
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="tabular-nums">{row.asset_count}</span>
      {bar.total > 0 && (
        <span
          className="flex h-1.5 w-20 overflow-hidden rounded-full bg-muted"
          title={bar.segments.map(s => `${s.count} ${s.severity}`).join(", ")}
        >
          {bar.segments.map(s => (
            <span key={s.severity} className={SEVERITY_BAR_CLASS[s.severity]} style={{ width: `${s.pct}%` }} />
          ))}
        </span>
      )}
    </div>
  )
}

export function StateCell({ row }: { row: CandidateRow }) {
  const st = stateInfo(row)
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-xs">
      <span className="font-medium">{st.label}</span>
      {st.viaConnector && (
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="inline-flex items-center gap-0.5 text-muted-foreground cursor-help">
              <Plug className="h-3 w-3" />via connector
            </span>
          </TooltipTrigger>
          <TooltipContent side="top">Claimed via connector</TooltipContent>
        </Tooltip>
      )}
      {st.previouslyRejected && <span className="text-muted-foreground">previously rejected</span>}
    </div>
  )
}

export function OrganizationCell({ row }: { row: CandidateRow }) {
  return (
    <span className="text-sm">
      {row.affiliated.name ?? "—"}
      {row.affiliated_is_default && <span className="ml-1 text-xs text-muted-foreground">(default)</span>}
    </span>
  )
}

// ── flyout ──────────────────────────────────────────────────────────────────

function SignalRow({ s, labelOf }: { s: SignalDetail; labelOf: LabelOf }) {
  return (
    <li className="rounded-md border p-2.5 space-y-1" title={s.quote ?? undefined}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium">{labelOf(s.signal_type)}</span>
        <TierChip tier={s.tier} label={TIER_LABEL[s.tier] ?? s.tier} />
        <span className="text-xs text-muted-foreground">{s.family}</span>
      </div>
      {s.matched_values && s.matched_values.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {s.matched_values.map(v => (
            <code key={v} className="rounded bg-muted px-1.5 py-0.5 text-xs font-mono">{v}</code>
          ))}
        </div>
      )}
      <div className="text-xs text-muted-foreground">
        {anchorText(s.anchor)} · first seen {relativeTime(s.first_seen_at)} · last seen {relativeTime(s.last_seen_at)}
      </div>
      {s.quote && (
        <details className="text-xs">
          <summary className="cursor-pointer text-muted-foreground">Quote</summary>
          <p className="mt-1 whitespace-pre-wrap">{s.quote}</p>
        </details>
      )}
      {s.evidence_id && (
        <button type="button" className="text-xs underline text-muted-foreground hover:text-foreground"
          onClick={() => void openEvidence(s.evidence_id as string)}>
          evidence
        </button>
      )}
    </li>
  )
}

export function CandidateFlyoutContent({
  detail, org, labelOf, nodes, onClaim, onReject, extra,
}: {
  detail: CandidateDetail
  org: OrganizationSummary
  labelOf: LabelOf
  nodes: TreeNode[]
  onClaim: (affiliatedEntityId: string | null) => Promise<void>
  onReject: (reason: string) => Promise<void>
  /** Extra block rendered just before History (e.g. registry observations). */
  extra?: React.ReactNode
}) {
  const can = useCan()
  const { counting, context } = splitSignals(detail.signal_details)
  const st = stateInfo(detail)
  const root = nodes.find(n => n.parent_id === null)?.name ?? org.name
  const [dialog, setDialog] = useState<"claim" | "reject" | null>(null)
  const canDecide = can(DECIDE) && detail.status === "open"

  return (
    <div className="flex flex-col min-h-0 flex-1">
      <div className="px-6 py-4 space-y-4 overflow-y-auto flex-1">
        <p className="text-xs text-muted-foreground">
          {(detail.affiliated.name ?? "—")} → {root} · {st.label} · {STRENGTH_LABEL[detail.strength] ?? detail.strength}
        </p>

        {detail.previously_rejected && (
          <div className="rounded-md border border-dashed p-2.5 text-xs text-muted-foreground">
            previously rejected: {detail.previously_rejected.reason ?? "no reason recorded"}
          </div>
        )}

        <section className="space-y-2">
          <h3 className="text-sm font-semibold">Why we think it's theirs</h3>
          {counting.length === 0
            ? <p className="text-xs text-muted-foreground">No signals that count toward the bar.</p>
            : <ul className="space-y-2">{counting.map(s => <SignalRow key={s.id} s={s} labelOf={labelOf} />)}</ul>}
        </section>

        {context.length > 0 && (
          <section className="space-y-2 opacity-80">
            <h3 className="text-sm font-semibold text-muted-foreground">Context (does not count)</h3>
            <ul className="space-y-2">{context.map(s => <SignalRow key={s.id} s={s} labelOf={labelOf} />)}</ul>
          </section>
        )}

        <section className="space-y-1">
          <h3 className="text-sm font-semibold">{detail.status === "claimed" ? "Claimed into" : "If claimed"}</h3>
          <p className="text-sm">
            {detail.status === "claimed"
              ? (detail.accepted_into ?? "—")
              : org.relationship === "ours" ? "Lands in our estate" : `Lands in ${destinationText(org)}`}
          </p>
        </section>

        {extra}

        <section className="space-y-1">
          <h3 className="text-sm font-semibold">History</h3>
          {detail.events.length === 0
            ? <p className="text-xs text-muted-foreground">No decisions yet.</p>
            : (
              <ul className="space-y-1 text-xs">
                {detail.events.map((e, i) => (
                  <li key={i}>
                    <span className="text-muted-foreground">{relativeTime(e.at)}</span>{" "}
                    {eventText(e, detail.decided_by_connector_name)}
                  </li>
                ))}
              </ul>
            )}
        </section>
      </div>

      {canDecide && (
        <div className="px-6 py-3 border-t flex gap-2 shrink-0">
          <Button size="sm" onClick={() => setDialog("claim")}>Claim</Button>
          <Button size="sm" variant="outline" onClick={() => setDialog("reject")}>Reject</Button>
        </div>
      )}
      {dialog === "claim" && (
        <ClaimDialog value={detail.value} nodes={nodes} defaultId={detail.affiliated.id}
          description={detail.kind === "asn" ? ASN_CLAIM_NOTE : undefined}
          onClose={() => setDialog(null)} onSubmit={async id => { await onClaim(id); setDialog(null) }} />
      )}
      {dialog === "reject" && (
        <RejectDialog value={detail.value} onClose={() => setDialog(null)}
          onSubmit={async r => { await onReject(r); setDialog(null) }} />
      )}
    </div>
  )
}

const ASN_CLAIM_NOTE =
  "Claiming this ASN also claims its registry holder's open, proposable prefixes as CIDR targets. Prefixes it only announces are not claimed."

export function ClaimDialog({
  value, description, nodes, defaultId, onClose, onSubmit,
}: {
  value: string
  description?: string
  nodes: TreeNode[]
  defaultId: string | null
  onClose: () => void
  onSubmit: (affiliatedEntityId: string | null) => Promise<void>
}) {
  const [aff, setAff] = useState<string>(defaultId ?? "")
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  return (
    <Dialog open onOpenChange={o => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Claim {value}</DialogTitle>
          <DialogDescription>
            The claim is recorded with you as the decider.{description ? ` ${description}` : ""}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-1.5">
          <Label>Organization it belongs to</Label>
          <Select value={aff} onValueChange={setAff}>
            <SelectTrigger><SelectValue placeholder="Default" /></SelectTrigger>
            <SelectContent>
              {nodes.map(n => <SelectItem key={n.entity_id} value={n.entity_id}>{n.name}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        {err && <p role="alert" className="text-sm text-destructive">{err}</p>}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button disabled={busy} onClick={async () => {
            setBusy(true); setErr(null)
            try { await onSubmit(aff || null) } catch (e) { setErr(errorDetail(e)) } finally { setBusy(false) }
          }}>Claim</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export function RejectDialog({
  value, onClose, onSubmit,
}: { value: string; onClose: () => void; onSubmit: (reason: string) => Promise<void> }) {
  const [reason, setReason] = useState("")
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  return (
    <Dialog open onOpenChange={o => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Reject {value}</DialogTitle>
          <DialogDescription>A reason is required and is kept in the history.</DialogDescription>
        </DialogHeader>
        <div className="space-y-1.5">
          <Label htmlFor="reject-reason">Reason</Label>
          <Textarea id="reject-reason" value={reason} onChange={e => setReason(e.target.value)} />
        </div>
        {err && <p role="alert" className="text-sm text-destructive">{err}</p>}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button disabled={busy || !reason.trim()} onClick={async () => {
            setBusy(true); setErr(null)
            try { await onSubmit(reason.trim()) } catch (e) { setErr(errorDetail(e)) } finally { setBusy(false) }
          }}>Reject</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
