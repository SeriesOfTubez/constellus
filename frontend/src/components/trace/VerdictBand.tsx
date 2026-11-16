import type { Finding } from "@/lib/api"
import { VERDICT_HEADINGS, verdictFor } from "@/lib/trace"

export function VerdictBand({ finding }: { finding: Pick<Finding, "source" | "finding_type" | "detail"> }) {
  const v = verdictFor(finding)
  return (
    <section aria-label="What was checked" className="mb-8 rounded-lg border bg-card px-4 py-4">
      <p className="text-sm font-semibold">{v.label}</p>
      <dl className="mt-3 grid gap-x-8 gap-y-3 md:grid-cols-2">
        <div className="space-y-1">
          <dt className="text-xs font-medium text-muted-foreground">{VERDICT_HEADINGS.saw}</dt>
          <dd className="text-sm">{v.saw}</dd>
        </div>
        <div className="space-y-1">
          <dt className="text-xs font-medium text-muted-foreground">{VERDICT_HEADINGS.didNot}</dt>
          <dd className="text-sm">{v.didNot}</dd>
        </div>
      </dl>
    </section>
  )
}
