import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import type { ScoreLadder } from "@/lib/api"
import { MOCK_ROWS, makeLadder } from "@/components/charts/ladderFixture"
import { ScoreLadderCard } from "@/components/ScoreLadderCard"

const render = (props: Partial<React.ComponentProps<typeof ScoreLadderCard>> & { data?: ScoreLadder }) =>
  renderToStaticMarkup(
    <MemoryRouter><ScoreLadderCard loading={false} error={false} {...props} /></MemoryRouter>,
  )

describe("ScoreLadderCard", () => {
  it("shows the first two crossings and the rule sentence", () => {
    const html = render({ data: makeLadder(MOCK_ROWS), width: 900 })
    expect(html).toContain("The way down")
    expect(html).toContain(`<span class="font-semibold text-foreground">3 fixes</span> to High Risk`)
    expect(html).toContain(`<span class="font-semibold text-foreground">12 fixes</span> to Elevated Risk`)
    expect(html).toContain(" · ")
    expect(html).toContain("Each fix removes your worst finding, so the score steps down to the next one.")
  })

  it("handles the singular fix count", () => {
    const html = render({ data: makeLadder([[80, "imminent_compromise", 1], [60, "high", 5]]), width: 900 })
    expect(html).toContain(`<span class="font-semibold text-foreground">1 fix</span> to High Risk`)
  })

  it("renders the chart when given a width", () => {
    const html = render({ data: makeLadder(MOCK_ROWS), width: 900 })
    expect(html).toContain("<svg")
    expect(html).toContain("Step chart: risk score falls from 91")
  })

  it("shows a skeleton and no chart while loading", () => {
    const html = render({ loading: true, width: 900 })
    expect(html).toContain("animate-pulse")
    expect(html).not.toContain("<svg")
  })

  it("shows the unable-to-load state, never a chart", () => {
    const html = render({ error: true, width: 900 })
    expect(html).toContain("Unable to load the score ladder.")
    expect(html).toContain("var(--sev-unknown)")
    expect(html).not.toContain("Step chart")
  })

  it("explains an empty ladder, with singular and plural unscored counts", () => {
    const none = render({ data: makeLadder([]), width: 900 })
    expect(none).toContain("No scored finding is open, so there is nothing to step down from.")
    expect(none).not.toContain("not been scored")
    expect(render({ data: makeLadder([], { unscored_count: 1 }), width: 900 }))
      .toContain("1 open finding has not been scored yet.")
    expect(render({ data: makeLadder([], { unscored_count: 4 }), width: 900 }))
      .toContain("4 open findings have not been scored yet.")
  })

  it("wraps the chart in a measured container when no width is given", () => {
    const html = render({ data: makeLadder(MOCK_ROWS) })
    expect(html).toContain("h-84")
    expect(html).not.toContain("<svg")
  })
})
