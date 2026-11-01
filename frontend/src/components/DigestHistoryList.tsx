import { useState } from "react"
import { Link } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"
import { ChevronDown, ChevronRight } from "lucide-react"
import {
  api, type DigestDetail, type DigestOutcome, type DigestSummary, type FindingDigestDetail,
  type OrgDiscoveryDigestDetail,
} from "@/lib/api"
import { SeverityBadge } from "@/components/finding-badges"

/** What is on record, no more. */
export const DIGEST_OUTCOME_LABEL: Record<DigestOutcome, string> = {
  empty: "Nothing new · not sent",
  pending: "Sending…",
  sent: "Sent",
  partial: "Partly sent",
  failed: "Send failed",
  no_channel: "Not sent · no notification channel",
  no_recipients: "Not sent · no recipients",
  abandoned: "Not sent · gave up after retries",
}

export function digestOutcomeLabel(o: string): string {
  return (DIGEST_OUTCOME_LABEL as Record<string, string>)[o] ?? o
}

function outcomeTone(o: string): string {
  if (o === "failed" || o === "abandoned") return "text-destructive"
  return o === "sent" ? "text-foreground" : "text-muted-foreground"
}

const fmt = (iso: string) => new Date(iso).toLocaleString()

const CANDIDATE_KIND_LABEL: Record<string, string> = { domain: "domain", asn: "ASN", cidr: "IP range" }

function OrgDiscoveryBodyView({ detail }: { detail: OrgDiscoveryDigestDetail }) {
  const { totals, organizations } = detail.body
  return (
    <div className="space-y-3 text-sm">
      <p className="text-xs text-muted-foreground">
        {totals.candidates} new candidate{totals.candidates === 1 ? "" : "s"} across{" "}
        {totals.organizations} organization{totals.organizations === 1 ? "" : "s"}
      </p>
      {organizations.map(o => (
        <div key={o.id} className="space-y-1">
          <div className="flex items-center gap-2 min-w-0">
            <Link
              to={`/organizations/${o.id}?tab=domains&seg=candidates`}
              className="font-medium truncate hover:underline"
            >
              {o.name}
            </Link>
            <span className="text-xs text-muted-foreground shrink-0">{o.candidate_count} new</span>
          </div>
          <div className="space-y-0.5 pl-4">
            {o.candidates.map(c => (
              <div key={c.id} className="flex items-center gap-2 min-w-0">
                <span className="text-xs text-muted-foreground shrink-0">{CANDIDATE_KIND_LABEL[c.kind] ?? c.kind}</span>
                <span className="truncate">{c.value}</span>
              </div>
            ))}
            {o.candidate_count > o.candidates.length && (
              <p className="text-xs text-muted-foreground">and {o.candidate_count - o.candidates.length} more</p>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

export function DigestBodyView({ detail }: { detail: DigestDetail }) {
  if (detail.kind === "org_discovery") return <OrgDiscoveryBodyView detail={detail} />
  return <FindingDigestBodyView detail={detail} />
}

function FindingDigestBodyView({ detail }: { detail: FindingDigestDetail }) {
  const { body, narrative } = detail
  const t = body.totals
  return (
    <div className="space-y-3 text-sm">
      {narrative && narrative.statements.length > 0 ? (
        <div className="space-y-1">
          <p className="text-xs font-medium">AI summary (each statement is tied to the records below)</p>
          <ul className="list-disc pl-5 space-y-0.5">
            {narrative.statements.map((s, i) => <li key={i}>{s.text}</li>)}
          </ul>
        </div>
      ) : detail.narrative_status && detail.narrative_status !== "succeeded" ? (
        <p className="text-xs text-muted-foreground">
          AI summary unavailable: {detail.narrative_reason ?? detail.narrative_status}
        </p>
      ) : null}
      <p className="text-xs text-muted-foreground">
        {t.findings} finding{t.findings === 1 ? "" : "s"} on {t.assets} asset{t.assets === 1 ? "" : "s"}
        {" · "}{t.new} new · {t.promotions} risk escalation{t.promotions === 1 ? "" : "s"}
        {" · "}critical {t.by_severity.critical}, high {t.by_severity.high}, medium {t.by_severity.medium},
        {" "}low {t.by_severity.low}, info {t.by_severity.info}
      </p>
      {body.groups.map(g => (
        <div key={`${g.kind}:${g.key}`} className="space-y-1">
          <div className="flex items-center gap-2 min-w-0">
            <SeverityBadge severity={g.max_severity} />
            <span className="font-medium truncate">{g.label}</span>
            <span className="text-xs text-muted-foreground shrink-0">
              {g.finding_count} finding{g.finding_count === 1 ? "" : "s"} · {g.asset_count} asset{g.asset_count === 1 ? "" : "s"}
            </span>
          </div>
          {g.writeup && g.writeup.summary && (
            <p className="pl-4 text-xs italic text-muted-foreground whitespace-pre-wrap">
              AI write-up of this issue across {g.writeup.asset_count} asset{g.writeup.asset_count === 1 ? "" : "s"}
              {" "}({new Date(g.writeup.written_at).toLocaleDateString()}
              {g.writeup.inputs_changed && ", inputs changed since"}): {g.writeup.summary}
            </p>
          )}
          <div className="space-y-0.5 pl-4">
            {g.items.map(it => (
              <div key={`${it.finding_id}:${it.asset_id}`} className="flex items-center gap-2 min-w-0">
                <SeverityBadge severity={it.severity} />
                <Link to={`/findings?id=${it.finding_id}`} className="truncate hover:underline">{it.title}</Link>
                <span className="text-xs text-muted-foreground truncate">— {it.asset}</span>
                {it.cve_id && <span className="text-xs text-muted-foreground shrink-0">{it.cve_id}</span>}
                {it.band_change && (
                  <span className="text-xs text-muted-foreground shrink-0">
                    {it.band_change.from ?? "?"} → {it.band_change.to ?? "?"}
                  </span>
                )}
                {it.state_now !== "open" && <span className="text-xs text-muted-foreground shrink-0">(now {it.state_now})</span>}
                {it.excluded_now && <span className="text-xs text-muted-foreground shrink-0">(now excluded)</span>}
              </div>
            ))}
          </div>
        </div>
      ))}
      {body.omitted_findings > 0 && (
        <p className="text-xs text-muted-foreground">… and {body.omitted_findings} more</p>
      )}
    </div>
  )
}

function DigestRow({ d }: { d: DigestSummary }) {
  const [open, setOpen] = useState(false)
  const { data, isLoading, isError } = useQuery({
    queryKey: ["notification-digest", d.id],
    queryFn: () => api.get<DigestDetail>(`/notifications/digests/${d.id}`),
    enabled: open,
  })
  const Chevron = open ? ChevronDown : ChevronRight
  return (
    <div className="px-3 py-2.5 text-sm">
      <button
        type="button"
        className="flex w-full items-start gap-3 text-left"
        aria-expanded={open}
        onClick={() => setOpen(o => !o)}
      >
        <Chevron className="h-4 w-4 mt-0.5 shrink-0" />
        <span className="block w-44 shrink-0 min-w-0">
          <span className="block font-medium truncate">{d.rule_name}</span>
          <span className="block text-xs text-muted-foreground">{fmt(d.period_start)} → {fmt(d.period_end)}</span>
        </span>
        <span className="block flex-1 min-w-0">
          {d.kind === "org_discovery"
            ? (d.event_count > 0 ? `${d.event_count} candidate${d.event_count === 1 ? "" : "s"}` : "Nothing new")
            : d.finding_count > 0 ? `${d.finding_count} finding${d.finding_count === 1 ? "" : "s"}` : "Nothing new"}
        </span>
        <span className="block w-64 shrink-0 space-y-0.5 text-xs">
          <span className={`block ${outcomeTone(d.outcome)}`}>{digestOutcomeLabel(d.outcome)}</span>
          {d.kind !== "org_discovery" && d.narrative_status === "succeeded" && <span className="block">AI summary</span>}
          {d.kind !== "org_discovery" && (d.narrative_status === "skipped" || d.narrative_status === "failed") && (
            <span className="block text-muted-foreground" title={d.narrative_reason ?? undefined}>No AI summary</span>
          )}
        </span>
      </button>
      {open && (
        <div className="mt-3 pl-7">
          {isLoading ? <p className="text-xs text-muted-foreground">Loading…</p>
            : isError || !data ? <p className="text-xs text-muted-foreground">Could not load this digest.</p>
            : <DigestBodyView detail={data} />}
        </div>
      )}
    </div>
  )
}

export function DigestHistoryList({ digests }: { digests: DigestSummary[] }) {
  if (digests.length === 0) {
    return <p className="text-sm text-muted-foreground">No digests yet.</p>
  }
  return (
    <div className="rounded-md border divide-y">
      {digests.map(d => <DigestRow key={d.id} d={d} />)}
    </div>
  )
}
