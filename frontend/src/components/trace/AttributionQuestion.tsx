import type { Attribution, AttributionHop } from "@/lib/api"
import { TIER_LABEL } from "@/lib/organizations"
import {
  attributionHopCaption, attributionHopTitle, attributionLinkText, attributionSummary,
  chainsNote, ownershipAnswer, plural, seenText,
} from "@/lib/trace"
import { TierChip } from "@/components/OrgCandidateParts"
import { ChainRow } from "./ChainRow"
import { Disclosure } from "./Disclosure"
import { EvidenceList } from "./EvidenceList"
import { Hop, type HopView } from "./Hop"
import { TraceSection } from "./TraceSection"

function toView(hop: AttributionHop, index: number): HopView {
  const seen = seenText(hop.first_seen_at, hop.last_seen_at)
  return {
    key: `${index}-${hop.kind}`,
    status: hop.status,
    title: attributionHopTitle(hop),
    caption: attributionHopCaption(hop),
    reason: hop.reason,
    meta: seen ? [seen] : [],
    link: index === 0
      ? null
      : { text: attributionLinkText(hop), tier: hop.tier, evidence: hop.evidence, truncated: hop.evidence_truncated },
    candidates: hop.kind === "host" ? hop.candidates : undefined,
    candidatesTruncated: hop.kind === "host" ? hop.candidates_truncated : undefined,
  }
}

export function AttributionQuestion({ attribution }: { attribution: Attribution | null | undefined }) {
  if (attribution === undefined) return null
  if (attribution === null) {
    return (
      <TraceSection number={1} question="Is it yours?">
        <p className="text-sm text-muted-foreground">
          This finding has no asset on record, so there is nothing to attribute.
        </p>
      </TraceSection>
    )
  }
  const { ownership, chains, chains_truncated } = attribution
  const answer = ownershipAnswer(ownership.surface)
  const note = chainsNote(chains.length, chains_truncated)
  return (
    <TraceSection number={1} question="Is it yours?">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <p className="text-sm font-medium">{answer.headline}</p>
        {ownership.tier && <TierChip tier={ownership.tier} label={TIER_LABEL[ownership.tier] ?? ownership.tier} />}
      </div>
      {ownership.reason && <p className="text-sm text-muted-foreground">{ownership.reason}</p>}
      {ownership.evidence.length > 0 && (
        <Disclosure label={plural(ownership.evidence.length, "ownership record", "ownership records")}>
          <EvidenceList rows={ownership.evidence} truncated={false} />
        </Disclosure>
      )}
      {answer.note && <p className="text-sm text-muted-foreground">{answer.note}</p>}
      {note && <p className="text-xs text-muted-foreground">{note}</p>}
      {chains.map((chain, ci) => (
        <ChainRow key={ci} defaultOpen={ci === 0} segments={attributionSummary(chain)}>
          {chain.hops.map((hop, hi) => (
            <Hop key={hi} hop={toView(hop, hi)} first={hi === 0} last={hi === chain.hops.length - 1} />
          ))}
        </ChainRow>
      ))}
    </TraceSection>
  )
}
