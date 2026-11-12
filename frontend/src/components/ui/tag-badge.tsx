import { X } from "lucide-react"
import { CHIP } from "@/components/ui/chip"
import { cn } from "@/lib/utils"

// Deterministic color from tag string — maps to one of 8 palette slots
const PALETTES = [
  "bg-blue-500/15 text-blue-600 dark:text-blue-400",
  "bg-purple-500/15 text-purple-600 dark:text-purple-400",
  "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  "bg-orange-500/15 text-orange-600 dark:text-orange-400",
  "bg-cyan-500/15 text-cyan-600 dark:text-cyan-400",
  "bg-rose-500/15 text-rose-600 dark:text-rose-400",
  "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400",
  "bg-indigo-500/15 text-indigo-600 dark:text-indigo-400",
]

function tagColor(tag: string): string {
  let hash = 0
  for (let i = 0; i < tag.length; i++) hash = (hash * 31 + tag.charCodeAt(i)) >>> 0
  return PALETTES[hash % PALETTES.length]
}

export function TagBadge({
  tag,
  onRemove,
}: {
  tag: string
  onRemove?: () => void
}) {
  return (
    <span className={cn(CHIP, "font-medium", tagColor(tag))}>
      {tag}
      {onRemove && (
        <button
          type="button"
          onClick={e => { e.stopPropagation(); onRemove() }}
          className="ml-1 opacity-60 hover:opacity-100 focus:outline-none"
          aria-label={`Remove tag ${tag}`}
        >
          <X className="size-3.5" />
        </button>
      )}
    </span>
  )
}
