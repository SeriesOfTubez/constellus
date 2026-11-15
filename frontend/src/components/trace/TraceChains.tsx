import type { Finding } from "@/lib/api"
import { AttributionQuestion } from "./AttributionQuestion"
import { ExposureQuestion } from "./ExposureQuestion"

export function TraceChains({ finding }: { finding: Finding }) {
  if (finding.attribution === undefined && finding.exposure_paths === undefined) return null
  return (
    <section aria-label="Trace">
      <AttributionQuestion attribution={finding.attribution} />
      <ExposureQuestion paths={finding.exposure_paths} findingTitle={finding.title} />
    </section>
  )
}
