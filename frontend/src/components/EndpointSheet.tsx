import { Link } from "react-router-dom"
import { SquareArrowOutUpRight } from "lucide-react"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { RedirectChain } from "@/components/RedirectChain"
import { WebClassificationSummary } from "@/components/ai/WebClassificationSummary"
import { WebClassificationControls } from "@/components/ai/WebClassificationControls"
import { KIND_LABELS, type WebEndpointState } from "@/lib/webClassification"

/** Flyout for one web endpoint. All page/model text is plain text. */
export function EndpointSheet({ row, onClose }: { row: WebEndpointState; onClose: () => void }) {
  const endpoint = `${row.asset_value}:${row.port}`
  return (
    <Sheet open onOpenChange={o => !o && onClose()}>
      <SheetContent className="w-[480px] sm:max-w-[480px] flex flex-col gap-0 p-0">
        <SheetHeader className="px-6 pt-5 pb-3 border-b space-y-1.5 shrink-0">
          <div className="flex items-center gap-2">
            <Link
              to={`/assets/${row.asset_id}`}
              className="ml-auto mr-6 text-muted-foreground hover:text-foreground inline-flex items-center gap-1 text-xs"
              title="Open asset"
            >
              Open asset<SquareArrowOutUpRight className="h-3.5 w-3.5" />
            </Link>
          </div>
          <SheetTitle className="font-mono text-sm break-all leading-relaxed" title={endpoint}>{endpoint}</SheetTitle>
          <SheetDescription className="sr-only">Web endpoint classification for {endpoint}</SheetDescription>
        </SheetHeader>
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-4">
          <EndpointHttpSummary row={row} />
          <WebClassificationSummary state={row} />
          {row.ai && (
            <p className="text-[11px] text-muted-foreground">
              {row.source === "user" ? `AI's own classification: ${!row.ai.kind || row.ai.kind === "unknown" || row.ai.downgraded ? "Unclassified" : KIND_LABELS[row.ai.kind]} · ` : ""}
              {row.ai.model ? `Model: ${row.ai.model}` : "Model: unknown"}
              {row.ai.cost_usd !== null ? ` · Cost: $${row.ai.cost_usd.toFixed(4)}` : ""}
            </p>
          )}
          <WebClassificationControls assetId={row.asset_id!} state={row} />
        </div>
      </SheetContent>
    </Sheet>
  )
}

/** The endpoint's own title/status, then its redirect chain. Extracted so it
 *  can be rendered in tests (the Sheet's Radix portal renders nothing under
 *  renderToStaticMarkup). A hop title is never the endpoint's title. */
export function EndpointHttpSummary({ row }: { row: WebEndpointState }) {
  return (
    <div className="space-y-0.5 text-xs">
      <p className="break-words">{row.http_title ?? "No page title recorded"}</p>
      {row.http_status !== null && <p className="text-muted-foreground">HTTP status {row.http_status}</p>}
      <RedirectChain chain={row.redirect_chain} />
    </div>
  )
}
