import { X } from "lucide-react"
import { CHIP } from "@/components/ui/chip"

export function TagBadge({
  tag,
  onRemove,
}: {
  tag: string
  onRemove?: () => void
}) {
  return (
    <span className={CHIP}>
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
