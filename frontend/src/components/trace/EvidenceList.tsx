import { SquareArrowOutUpRight } from "lucide-react"
import type { AttributionEvidence } from "@/lib/api"
import { openEvidence } from "@/lib/evidence"
import { TIER_LABEL } from "@/lib/organizations"
import { evidenceDocumentId, evidenceMeta, evidenceTitle } from "@/lib/trace"
import { TierChip } from "@/components/OrgCandidateParts"

export const MORE_EXIST = "More exist than are listed."

export function EvidenceList({ rows, truncated }: { rows: AttributionEvidence[]; truncated: boolean }) {
  return (
    <ul className="rounded-md border divide-y text-sm">
      {rows.map((row, i) => {
        const docId = evidenceDocumentId(row)
        const meta = evidenceMeta(row).join(" · ")
        return (
          <li key={i} className="px-3 py-2 flex items-start gap-3">
            <div className="min-w-0 flex-1">
              <p className="font-medium">{evidenceTitle(row)}</p>
              {meta && <p className="text-xs text-muted-foreground">{meta}</p>}
            </div>
            {row.tier && <TierChip tier={row.tier} label={TIER_LABEL[row.tier] ?? row.tier} />}
            {docId && (
              <button
                type="button"
                aria-label="Open source document"
                title="Open source document"
                onClick={() => void openEvidence(docId)}
                className="inline-flex items-center text-muted-foreground hover:text-primary transition-colors rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <SquareArrowOutUpRight className="size-4" />
              </button>
            )}
          </li>
        )
      })}
      {truncated && (
        <li className="px-3 py-2 text-xs text-muted-foreground">{MORE_EXIST}</li>
      )}
    </ul>
  )
}
