import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { TooltipProvider } from "@/components/ui/tooltip"
import { AiInferredBadge } from "@/components/ai/AiInferredBadge"

const render = (el: React.ReactElement) => renderToStaticMarkup(<TooltipProvider>{el}</TooltipProvider>)

describe("AiInferredBadge", () => {
  it("renders Inferred by AI for source ai", () => {
    const html = render(<AiInferredBadge source="ai" model="some-model" />)
    expect(html).toContain("Inferred by AI")
    expect(html).not.toContain("Set by")
  })
  it("renders Set by <name> for source user", () => {
    const html = render(<AiInferredBadge source="user" setBy="Ada Admin" />)
    expect(html).toContain("Set by Ada Admin")
    expect(html).not.toContain("Inferred by AI")
  })
  it("falls back to an admin when no name is known", () => {
    expect(render(<AiInferredBadge source="user" setBy={null} />)).toContain("Set by an admin")
  })
})
