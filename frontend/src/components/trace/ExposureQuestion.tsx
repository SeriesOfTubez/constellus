import type { ExposureHop, ExposurePath } from "@/lib/api"
import {
  exposureHopCaption, exposureHopTitle, exposureSummary, observationLabel, pathsAnswer, seenText, sourcesText,
} from "@/lib/trace"
import { ChainRow } from "./ChainRow"
import { Hop, type HopView } from "./Hop"
import { TraceLegend } from "./TraceLegend"
import { TraceSection } from "./TraceSection"

function toView(hop: ExposureHop, index: number, findingTitle: string | null): HopView {
  // One line per hop: six hops with two meta lines each read as clutter.
  const parts = [sourcesText(hop.sources), seenText(hop.first_seen_at, hop.last_seen_at)]
    .filter((m): m is string => m !== null)
  const meta = parts.length > 0 ? [parts.join(" · ")] : []
  const withCandidates = hop.kind === "host" || hop.kind === "address"
  return {
    key: `${index}-${hop.kind}`,
    status: hop.status,
    title: exposureHopTitle(hop, findingTitle),
    caption: exposureHopCaption(hop),
    reason: hop.reason,
    meta,
    diamond: hop.kind === "finding",
    link: null,
    candidates: withCandidates ? hop.candidates : undefined,
    candidatesTruncated: withCandidates ? hop.candidates_truncated : undefined,
  }
}

export function ExposurePathHops({ path, findingTitle }: { path: ExposurePath; findingTitle: string | null }) {
  return (
    <>
      {path.hops.map((hop, hi) => (
        <Hop key={hi} hop={toView(hop, hi, findingTitle)} first={hi === 0} last={hi === path.hops.length - 1} />
      ))}
    </>
  )
}

export function ExposureQuestion({ paths, findingTitle }: { paths: ExposurePath[] | undefined; findingTitle: string | null }) {
  if (paths === undefined) return null
  return (
    <TraceSection number={2} question="Can it be reached?" last>
      <p className="text-sm font-medium">{pathsAnswer(paths)}</p>
      {paths.map((path, pi) => (
        <ChainRow
          key={path.endpoint_id ?? pi}
          segments={exposureSummary(path, findingTitle)}
          chip={observationLabel(path)}
        >
          <ExposurePathHops path={path} findingTitle={findingTitle} />
        </ChainRow>
      ))}
      <TraceLegend />
    </TraceSection>
  )
}
