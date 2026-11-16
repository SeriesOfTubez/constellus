import type { Finding } from "@/lib/api"
import { AttributionQuestion } from "./AttributionQuestion"
import { ExposureQuestion } from "./ExposureQuestion"
import { VerdictBand } from "./VerdictBand"

export function TraceChains({ finding }: { finding: Finding }) {
  if (finding.attribution === undefined && finding.exposure_paths === undefined) return null
  return (
    <section aria-label="Trace">
      <VerdictBand finding={finding} />
      <AttributionQuestion attribution={finding.attribution} />
      <ExposureQuestion paths={finding.exposure_paths} findingTitle={finding.title} />
    </section>
  )
}
