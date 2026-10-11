import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { AiInferredBadge } from "@/components/ai/AiInferredBadge"
import { ENV_LABELS, KIND_LABELS, effectiveLabel, endpointFlags, type Citation, type WebEndpointState } from "@/lib/webClassification"

// Everything below is rendered as React text nodes only. Model output and page
// content (title, citation values, product, reason, errors) are untrusted:
// no markup rendering, no links.

function CitationChip({ c }: { c: Citation }) {
  return (
    <span className="text-[11px] text-muted-foreground">
      <span className="font-mono text-[10px]">{c.source_field}</span>
      {` "${c.value}"`}
    </span>
  )
}

export function WebClassificationSummary({
  state, compact = false,
}: {
  state: WebEndpointState
  compact?: boolean
}) {
  const none = state.source === "none"
  const showEnv = !none && state.environment && state.environment !== "unknown"
  const evidence = state.ai?.evidence ?? []
  const showCitations = evidence.length > 0 && (state.source === "ai" || (!compact && !!state.ai))
  const shown = compact ? evidence.slice(0, 2) : evidence
  const rest = compact ? evidence.slice(2) : []
  const flags = endpointFlags(state)

  return (
    <div className="space-y-0.5 min-w-0">
      <div className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-xs">
        <span className={none ? "text-muted-foreground" : "font-medium"}>{effectiveLabel(state)}</span>
        {showEnv && (
          <>
            <span className="text-muted-foreground">·</span>
            <span>{ENV_LABELS[state.environment!]}</span>
          </>
        )}
        {!none && (
          <AiInferredBadge
            source={state.source as "ai" | "user"}
            setBy={state.override?.set_by}
            at={state.override?.updated_at}
            model={state.ai?.model}
          />
        )}
      </div>
      {showCitations && (
        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
          {state.source !== "ai" && (
            <span className="text-[11px] text-muted-foreground">
              AI cited{state.ai?.kind ? ` (for ${KIND_LABELS[state.ai.kind]})` : ""}:
            </span>
          )}
          {shown.map((c, i) => <CitationChip key={i} c={c} />)}
          {rest.length > 0 && (
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="text-[11px] text-muted-foreground cursor-help">+{rest.length}</span>
              </TooltipTrigger>
              <TooltipContent side="top" className="max-w-xs">
                <div className="space-y-0.5">
                  {rest.map((c, i) => <CitationChip key={i} c={c} />)}
                </div>
              </TooltipContent>
            </Tooltip>
          )}
        </div>
      )}
      {state.product && (
        <p className="text-[11px] text-muted-foreground">Product (AI guess): {state.product}</p>
      )}
      {!compact && state.source === "user" && state.override?.reason && (
        <p className="text-[11px] text-muted-foreground">Reason: {state.override.reason}</p>
      )}
      {flags.map(f => (
        <p
          key={f.key}
          className={`text-[11px] ${f.tone === "warn" ? "text-amber-600 dark:text-amber-400" : "text-muted-foreground"}`}
        >
          {f.text}
        </p>
      ))}
    </div>
  )
}
