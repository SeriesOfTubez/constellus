import { useState } from "react"
import { ChevronDown, ChevronRight } from "lucide-react"
import { Link } from "react-router-dom"
import type { AttributionEvidence, AttributionTier, ExposureHopCandidate, ExposureHopStatus } from "@/lib/api"
import { TIER_LABEL } from "@/lib/organizations"
import { STATUS_LABEL, plural, type HopTitle } from "@/lib/trace"
import { TierChip } from "@/components/OrgCandidateParts"
import { cn } from "@/lib/utils"
import { CandidateList } from "./CandidateList"
import { EvidenceList } from "./EvidenceList"
import { HopMarker } from "./HopMarker"

export type HopView = {
  key: string
  status: ExposureHopStatus
  title: HopTitle
  caption: string | null
  reason: string | null
  meta: string[]
  diamond?: boolean
  link?: { text: string | null; tier: AttributionTier | null; evidence: AttributionEvidence[]; truncated: boolean } | null
  candidates?: ExposureHopCandidate[]
  candidatesTruncated?: boolean
}

function Title({ title }: { title: HopTitle }) {
  const cls = cn(
    "text-sm font-medium",
    title.mono && "font-mono break-all",
    title.missing && "text-muted-foreground font-normal",
  )
  if (title.href) {
    return <Link to={title.href} title={title.text} className={cn(cls, "text-link hover:underline")}>{title.text}</Link>
  }
  return <span title={title.mono ? title.text : undefined} className={cls}>{title.text}</span>
}

export function Hop({ hop, first, last }: { hop: HopView; first: boolean; last: boolean }) {
  const link = hop.link
  // The toggle sits in the link row; the rows open below it at full width.
  const [open, setOpen] = useState(false)
  const hasLink = !!link && (!!link.text || !!link.tier || link.evidence.length > 0)
  return (
    <div className="grid grid-cols-[16px_minmax(0,1fr)] gap-x-3">
      {!first && (
        <>
          <span className="mx-auto w-px bg-border" aria-hidden="true" />
          {hasLink && link ? (
            <div className="space-y-2 py-2">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                {link.text && <span className="text-sm text-muted-foreground">{link.text}</span>}
                {link.tier && <TierChip tier={link.tier} label={TIER_LABEL[link.tier] ?? link.tier} />}
                {link.evidence.length > 0 && (
                  <button
                    type="button"
                    aria-expanded={open}
                    onClick={() => setOpen((o) => !o)}
                    className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  >
                    {open ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}
                    {plural(link.evidence.length, "record", "records")}
                  </button>
                )}
              </div>
              {open && <EvidenceList rows={link.evidence} truncated={link.truncated} />}
            </div>
          ) : (
            <div className="h-4" />
          )}
        </>
      )}
      <div className="flex flex-col items-center">
        <span className="flex h-5 items-center">
          <HopMarker status={hop.status} diamond={hop.diamond} />
        </span>
        {!last && <span className="w-px flex-1 bg-border" aria-hidden="true" />}
      </div>
      <div className={cn("min-w-0 space-y-1", !last && "pb-2")}>
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
          <Title title={hop.title} />
          {hop.caption && <span className="text-sm text-muted-foreground">{hop.caption}</span>}
          {/* Only "derived" needs the word: a gap's title already says nothing is on record. */}
          {hop.status === "derived" && (
            <span className="text-xs text-muted-foreground">{STATUS_LABEL[hop.status]}</span>
          )}
        </div>
        {hop.reason && <p className="text-sm text-muted-foreground">{hop.reason}</p>}
        {hop.meta.map((m) => (
          <p key={m} className="text-xs text-muted-foreground">{m}</p>
        ))}
        {hop.candidates && hop.candidates.length > 0 && (
          <CandidateList candidates={hop.candidates} truncated={hop.candidatesTruncated ?? false} />
        )}
      </div>
    </div>
  )
}
