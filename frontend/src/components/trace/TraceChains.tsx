import type { Finding } from "@/lib/api"
import { AttributionQuestion } from "./AttributionQuestion"
import { ExposureQuestion } from "./ExposureQuestion"
import { TimelineQuestion } from "./TimelineQuestion"
import { VerdictBand } from "./VerdictBand"

export function TraceChains({ finding }: { finding: Finding }) {
  if (finding.attribution === undefined && finding.exposure_paths === undefined && finding.timeline === undefined) return null
  return (
    <section aria-label="Trace">
      <VerdictBand finding={finding} />
      <AttributionQuestion attribution={finding.attribution} />
      <ExposureQuestion paths={finding.exposure_paths} findingTitle={finding.title} last={finding.timeline === undefined} />
      <TimelineQuestion events={finding.timeline} />
    </section>
  )
}
