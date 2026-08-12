import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"

interface OverflowCellProps<T> {
  items: T[]
  renderItem: (item: T, index: number) => React.ReactNode
  getLabel: (item: T) => string
  /** Optional rich renderer for the hover popup. Falls back to plain `getLabel`
   *  text when omitted. Must NOT itself contain a tooltip (no nesting). */
  renderOverflowItem?: (item: T, index: number) => React.ReactNode
  limit?: number
  emptyLabel?: string
}

/** Shows the first `limit` items then a muted `+n` chip.
 *  Hovering `+n` shows a tooltip listing the remaining values (rich when
 *  `renderOverflowItem` is given, else plain text).
 *  Clicking the *row* (not this chip) opens the flyout — this is intentional. */
export function OverflowCell<T>({
  items,
  renderItem,
  getLabel,
  renderOverflowItem,
  limit = 2,
  emptyLabel = "—",
}: OverflowCellProps<T>) {
  if (items.length === 0) {
    return <span className="text-muted-foreground text-xs">{emptyLabel}</span>
  }

  const visible  = items.slice(0, limit)
  const overflow = items.slice(limit)

  return (
    <div className="flex flex-wrap items-center gap-1">
      {visible.map((item, i) => renderItem(item, i))}
      {overflow.length > 0 && (
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="text-xs text-muted-foreground cursor-help select-none">
              +{overflow.length}
            </span>
          </TooltipTrigger>
          <TooltipContent side="top" className="max-w-sm">
            <div className="space-y-1.5 text-xs">
              {overflow.map((item, i) => (
                <div key={i}>{renderOverflowItem ? renderOverflowItem(item, i) : getLabel(item)}</div>
              ))}
            </div>
          </TooltipContent>
        </Tooltip>
      )}
    </div>
  )
}
