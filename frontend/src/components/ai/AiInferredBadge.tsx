import { Sparkles, UserCheck } from "lucide-react"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { CHIP } from "@/components/ui/chip"
import { cn } from "@/lib/utils"

// Shared provenance badge for AI-inferred values. Under the planning#225 rule,
// low-impact AI values (such as a web endpoint's kind) are applied
// automatically and are correctable by an admin, so the value always carries
// a badge saying where it came from: "Inferred by AI" until an admin corrects
// it, then "Set by <name>". Pure props and no hooks, so any AI feature can
// reuse it and it renders in a plain server-render test. Callers must be
// inside a TooltipProvider (the app root provides one).

export function AiInferredBadge({
  source, setBy, at, model, className = "",
}: {
  source: "ai" | "user"
  setBy?: string | null
  at?: string | null
  model?: string | null
  className?: string
}) {
  const isAi = source === "ai"
  const Icon = isAi ? Sparkles : UserCheck
  const text = isAi ? "Inferred by AI" : `Set by ${setBy || "an admin"}`
  const cls = isAi
    ? "border-violet-500/40 bg-violet-500/10 text-violet-600 dark:text-violet-400"
    : "border-sky-500/40 bg-sky-500/10 text-sky-600 dark:text-sky-400"
  const date = at ? new Date(at).toLocaleDateString() : null

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className={cn(CHIP, "border font-medium cursor-help", cls, className)}>
          <Icon className="size-3.5" />{text}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs">
        {isAi ? (
          <div className="space-y-0.5">
            <p>An AI model inferred this from the endpoint's own signals. It is applied as-is; an admin can correct it.</p>
            {model && <p className="text-muted-foreground">Model: {model}</p>}
          </div>
        ) : (
          <p>Corrected by {setBy || "an admin"}{date ? ` on ${date}` : ""}. It stays until an admin removes it.</p>
        )}
      </TooltipContent>
    </Tooltip>
  )
}
