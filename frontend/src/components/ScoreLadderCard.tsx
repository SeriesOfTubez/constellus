import { Fragment } from "react"
import { useNavigate } from "react-router-dom"
import { ParentSize } from "@visx/responsive"
import { AlertTriangle } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import type { ScoreLadder } from "@/lib/api"
import { RISK_BAND_LABEL } from "@/components/finding-badges"
import { StepLadder, fixCountLabel } from "@/components/charts/StepLadder"

export function ScoreLadderCard({
  data, loading, error, width,
}: { data?: ScoreLadder; loading: boolean; error: boolean; width?: number }) {
  const navigate = useNavigate()
  const goToFix = (id: string) => navigate(`/findings/${id}`)
  const crossings = data ? data.crossings.slice(0, 2) : []

  let body
  if (loading) {
    body = <Skeleton className="h-72 w-full" />
  } else if (error || !data) {
    // Unknown must never render as secure (same convention as the score gauge).
    body = (
      <div className="flex flex-col items-center gap-2 py-8 text-center">
        <AlertTriangle className="size-4" style={{ color: "var(--sev-unknown)" }} />
        <p className="text-sm font-semibold" style={{ color: "var(--sev-unknown)" }}>Unable to load the score ladder.</p>
      </div>
    )
  } else if (data.levels.length === 0) {
    body = (
      <div className="flex flex-col gap-2">
        <p className="text-sm text-muted-foreground">No scored finding is open, so there is nothing to step down from.</p>
        {data.unscored_count > 0 && (
          <p className="text-sm text-muted-foreground">
            {data.unscored_count === 1
              ? "1 open finding has not been scored yet."
              : `${data.unscored_count} open findings have not been scored yet.`}
          </p>
        )}
      </div>
    )
  } else if (width !== undefined) {
    body = <StepLadder ladder={data} width={width} onSelectFix={goToFix} />
  } else {
    const ladder = data
    body = (
      // 288 chart + 8 gap + 40 two-line readout
      <div className="h-84 w-full">
        <ParentSize>
          {({ width: w }) => <StepLadder ladder={ladder} width={w} onSelectFix={goToFix} />}
        </ParentSize>
      </div>
    )
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-baseline justify-between gap-4">
          <CardTitle className="text-base">The way down</CardTitle>
          {crossings.length > 0 && (
            <span className="text-sm text-muted-foreground">
              {crossings.map((c, i) => (
                <Fragment key={c.band}>
                  {i > 0 && " · "}
                  <span>
                    <span className="font-semibold text-foreground">{fixCountLabel(c.fixes)}</span> to {RISK_BAND_LABEL[c.band]}
                  </span>
                </Fragment>
              ))}
            </span>
          )}
        </div>
        {data?.rule === "worst_open_finding" && (
          <p className="text-sm text-muted-foreground">
            Each fix removes your worst finding, so the score steps down to the next one.
          </p>
        )}
      </CardHeader>
      <CardContent>{body}</CardContent>
    </Card>
  )
}
