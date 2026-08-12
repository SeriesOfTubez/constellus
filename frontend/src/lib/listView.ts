import { useCallback, useEffect, useState } from "react"
import { useSearchParams } from "react-router-dom"

/**
 * URL-backed list state — the single source of truth for filters, grouping, and
 * view mode on list pages (Findings, Assets). Sibling to `useFlyout`.
 *
 * Why the URL and not local state: every filtered/grouped view becomes shareable
 * and deep-linkable by construction (the locked "clickable by default" standard),
 * and there's exactly one source of truth, so inbound links and in-page controls
 * can't drift. All writes use replace-nav so filtering doesn't pollute history.
 */

/** A single URL-backed string filter. Setting the default (or empty) removes the
 *  param so URLs stay clean. */
export function useUrlState(key: string, defaultValue = "all") {
  const [searchParams, setSearchParams] = useSearchParams()
  const value = searchParams.get(key) ?? defaultValue
  const setValue = useCallback(
    (next: string) => {
      setSearchParams(
        prev => {
          const n = new URLSearchParams(prev)
          if (!next || next === defaultValue) n.delete(key)
          else n.set(key, next)
          return n
        },
        { replace: true },
      )
    },
    [key, defaultValue, setSearchParams],
  )
  return [value, setValue] as const
}

/**
 * A URL-backed string filter for free-text inputs (e.g. search boxes). Returns
 * immediately-updating local state for responsive typing, but writes to the URL
 * only after `delayMs` of no further changes — keeps filtering instant while
 * avoiding a history/URL update on every keystroke.
 */
export function useDebouncedUrlState(key: string, defaultValue = "", delayMs = 300) {
  const [urlValue, setUrlValue] = useUrlState(key, defaultValue)
  const [local, setLocal] = useState(urlValue)

  // Pick up external changes (back/forward nav, dismissed chips, deep links).
  useEffect(() => {
    setLocal(urlValue)
  }, [urlValue])

  useEffect(() => {
    if (local === urlValue) return
    const t = setTimeout(() => setUrlValue(local), delayMs)
    return () => clearTimeout(t)
  }, [local, urlValue, setUrlValue, delayMs])

  return [local, setLocal] as const
}

/** A URL-backed boolean flag (`?key=true`); absent param means false. */
export function useUrlFlag(key: string) {
  const [searchParams, setSearchParams] = useSearchParams()
  const value = searchParams.get(key) === "true"
  const setValue = useCallback(
    (next: boolean) => {
      setSearchParams(
        prev => {
          const n = new URLSearchParams(prev)
          if (next) n.set(key, "true")
          else n.delete(key)
          return n
        },
        { replace: true },
      )
    },
    [key, setSearchParams],
  )
  return [value, setValue] as const
}

export type ListViewMode = "table" | "card"
export type GroupMode = "none" | "band" | "asset" | "apex" | "impact"

/**
 * Table-vs-card and the grouping axis, both URL-backed. Grouping render (band /
 * asset sectioning) and the card view land in the next increment; the param
 * vocabulary lives here now so deep-links, the eventual toolbar controls, and
 * both list pages all speak the same language.
 *
 * `defaultGroup` lets a page opt into a non-"none" default (e.g. Assets groups
 * by apex domain unless the URL says otherwise) without polluting the URL for
 * the common case.
 */
export function useListView(defaultGroup: GroupMode = "none") {
  const [view, setView] = useUrlState("view", "table")
  const [group, setGroup] = useUrlState("group", defaultGroup)
  return {
    view: view as ListViewMode,
    setView: (v: ListViewMode) => setView(v),
    group: group as GroupMode,
    setGroup: (g: GroupMode) => setGroup(g),
  }
}
