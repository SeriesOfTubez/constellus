import { useEffect, useRef, useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { TagBadge } from "./tag-badge"

export function TagEditor({
  tags,
  entityType,
  onChange,
  disabled,
}: {
  tags: string[]
  entityType: "target" | "asset" | "finding"
  onChange: (tags: string[]) => void
  disabled?: boolean
}) {
  const [input, setInput] = useState("")
  const [showSuggestions, setShowSuggestions] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const { data: allTags = [] } = useQuery<string[]>({
    queryKey: ["tags", entityType],
    queryFn: () => api.get(`/tags/?entity_type=${entityType}`),
    staleTime: 30_000,
  })

  const suggestions = allTags.filter(
    t => t.includes(input.toLowerCase()) && !tags.includes(t) && input.length > 0
  )

  function addTag(tag: string) {
    const normalized = tag.trim().toLowerCase().replace(/\s+/g, "-")
    if (!normalized || tags.includes(normalized)) return
    onChange([...tags, normalized])
    setInput("")
    setShowSuggestions(false)
  }

  function removeTag(tag: string) {
    onChange(tags.filter(t => t !== tag))
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if ((e.key === "Enter" || e.key === ",") && input.trim()) {
      e.preventDefault()
      addTag(input)
    }
    if (e.key === "Backspace" && !input && tags.length > 0) {
      removeTag(tags[tags.length - 1])
    }
    if (e.key === "Escape") {
      setShowSuggestions(false)
    }
  }

  // Close suggestions on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (inputRef.current && !inputRef.current.closest(".tag-editor-root")?.contains(e.target as Node)) {
        setShowSuggestions(false)
      }
    }
    document.addEventListener("mousedown", handleClick)
    return () => document.removeEventListener("mousedown", handleClick)
  }, [])

  return (
    <div className="tag-editor-root relative">
      <div
        className="flex flex-wrap gap-1.5 rounded-md border border-input bg-background px-2 py-1.5 text-sm min-h-9 cursor-text"
        onClick={() => !disabled && inputRef.current?.focus()}
      >
        {tags.map(tag => (
          <TagBadge key={tag} tag={tag} onRemove={disabled ? undefined : () => removeTag(tag)} />
        ))}
        {!disabled && (
          <input
            ref={inputRef}
            value={input}
            onChange={e => { setInput(e.target.value); setShowSuggestions(true) }}
            onKeyDown={handleKeyDown}
            onFocus={() => setShowSuggestions(true)}
            placeholder={tags.length === 0 ? "Add tags…" : ""}
            className="flex-1 min-w-20 bg-transparent outline-none text-xs placeholder:text-muted-foreground"
          />
        )}
      </div>

      {showSuggestions && suggestions.length > 0 && (
        <div className="absolute z-50 top-full left-0 mt-1 w-full rounded-md border bg-popover shadow-md">
          {suggestions.slice(0, 8).map(s => (
            <button
              key={s}
              type="button"
              className="w-full text-left px-3 py-1.5 text-xs hover:bg-accent"
              onMouseDown={e => { e.preventDefault(); addTag(s) }}
            >
              {s}
            </button>
          ))}
        </div>
      )}

      {!disabled && (
        <p className="mt-1 text-xs text-muted-foreground">Enter or comma to add · Backspace to remove</p>
      )}
    </div>
  )
}
