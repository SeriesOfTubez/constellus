import { useCallback, useEffect } from "react"
import { useSearchParams } from "react-router-dom"

/**
 * Manages flyout panel state via URL query param.
 *
 * - Selected item is reflected in ?<paramName>=<id> so panels survive refresh
 *   and URLs are shareable.
 * - Opening pushes a history entry so the back button closes the panel.
 * - J/K keyboard navigation moves through the visible (filtered) item list
 *   using replace navigation so keyboard browsing doesn't pollute history.
 * - Escape is handled by the Radix Sheet component; wire onOpenChange to close().
 *
 * Usage:
 *   const { selected, open, close } = useFlyout(filteredItems)
 *   <TableRow onClick={() => open(item)} />
 *   <Sheet open={!!selected} onOpenChange={o => !o && close()} />
 */
export function useFlyout<T extends { id: string }>(
  items: T[],
  paramName = "id",
) {
  const [searchParams, setSearchParams] = useSearchParams()
  const selectedId = searchParams.get(paramName)
  const selected = items.find(item => item.id === selectedId) ?? null
  const currentIndex = selected ? items.findIndex(i => i.id === selected.id) : -1

  const open = useCallback(
    (item: T) => {
      setSearchParams(
        prev => { const n = new URLSearchParams(prev); n.set(paramName, item.id); return n },
        { replace: false },
      )
    },
    [setSearchParams, paramName],
  )

  const close = useCallback(
    () => {
      setSearchParams(
        prev => { const n = new URLSearchParams(prev); n.delete(paramName); return n },
        { replace: true },
      )
    },
    [setSearchParams, paramName],
  )

  useEffect(() => {
    if (!selected) return
    const handler = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return
      if (e.key === "j" || e.key === "J") {
        const next = items[currentIndex + 1]
        if (next) setSearchParams(
          prev => { const n = new URLSearchParams(prev); n.set(paramName, next.id); return n },
          { replace: true },
        )
      } else if (e.key === "k" || e.key === "K") {
        const prev = items[currentIndex - 1]
        if (prev) setSearchParams(
          p => { const n = new URLSearchParams(p); n.set(paramName, prev.id); return n },
          { replace: true },
        )
      }
    }
    window.addEventListener("keydown", handler)
    return () => window.removeEventListener("keydown", handler)
  }, [selected, items, currentIndex, setSearchParams, paramName])

  return { selected, open, close, isOpen: selected !== null }
}
