import { useState } from "react"
import type { KeyboardEvent } from "react"

// The hover layer for a chart with many marks along x: one transparent band per
// mark for the pointer, and ONE focusable slider for the keyboard (a tab stop
// per mark would put 30 stops in a 30-day line).

export type Band = { x: number; w: number }

// The app's focus ring is a box-shadow, which an svg <rect> does not draw. An
// outline does. The slider fills its svg and the ring sits 2px outside it, so
// the svg needs SCRUB_SVG or the ring is clipped at its edge.
// No `outline-none` here: it sets the style to none and `outline-2` only sets a width.
export const SCRUB_FOCUS = "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
export const SCRUB_SVG = "overflow-visible"

/** Split [left, right] at the midpoints between neighbouring mark centres. */
export function scrubBands(centers: number[], left: number, right: number): Band[] {
  return centers.map((c, i) => {
    const x0 = i === 0 ? left : (centers[i - 1] + c) / 2
    const x1 = i === centers.length - 1 ? right : (c + centers[i + 1]) / 2
    return { x: x0, w: Math.max(0, x1 - x0) }
  })
}

/**
 * The mark a key press moves to: an index, null to clear, or undefined when
 * the key is not ours. With nothing active, Left starts at the last mark (the
 * most recent) and Right at the first.
 */
export function scrubKey(key: string, active: number | null, count: number): number | null | undefined {
  if (count <= 0) return undefined
  const last = count - 1
  switch (key) {
    case "ArrowLeft":  return active === null ? last : Math.max(0, active - 1)
    case "ArrowRight": return active === null ? 0 : Math.min(last, active + 1)
    case "Home":       return 0
    case "End":        return last
    case "Escape":     return null
    default:           return undefined
  }
}

export function useScrub(count: number) {
  const [active, setActive] = useState<number | null>(null)
  const onKeyDown = (ev: KeyboardEvent<SVGElement>) => {
    const next = scrubKey(ev.key, active, count)
    if (next === undefined) return
    ev.preventDefault()
    setActive(next)
  }
  return { active: active !== null && active < count ? active : null, setActive, onKeyDown }
}
