// Trace question 3 ("How long has this been open?") as text: labels, second lines and the gaps between
// events (planning#362). Pure, no React. The API sorts the events; nothing here does.
import type { TimelineEvent } from "@/lib/api"
import { formatClosed } from "@/lib/organizations"

const DAY_MS = 86_400_000

// "YYYY-MM-DD" is split, never local-parsed: `new Date("2026-08-01")` shifts a day west of UTC.
const parts = (iso: string): [number, number, number] => {
  const [y, m, d] = iso.slice(0, 10).split("-").map(Number)
  return [y, m, d]
}
const dayNumber = (iso: string): number => {
  const [y, m, d] = parts(iso)
  return Math.round(Date.UTC(y, m - 1, d) / DAY_MS)
}
const plural = (n: number, unit: string) => `${n} ${unit}${n === 1 ? "" : "s"}`

export function timelineLabel(e: TimelineEvent): string {
  switch (e.kind) {
    case "cve_published": return "CVE published"
    case "listed_exploited_cisa": return "Listed by CISA as exploited"
    case "listed_exploited_vulncheck": return "Listed by VulnCheck as exploited"
    case "acquired": return `${e.entity_name ?? "A company"} acquired`
    case "claimed": return `${e.target_value ?? "A scope"} claimed`
    case "first_seen": return "First seen"
    case "ownership_confirmed": return "Confirmed ours"
    case "due": return "Fix due"
  }
}

export function timelineDate(e: TimelineEvent): string {
  return formatClosed(e.date, e.precision)
}

export function secondLines(e: TimelineEvent, today: string): string[] {
  if (e.kind === "acquired") {
    return e.other_dates.map((d) => `Another source says ${formatClosed(d.date, d.precision)}`)
  }
  if (e.kind === "due") {
    const n = dayNumber(e.date) - dayNumber(today)
    if (n < 0) return [`BOD 26-04 · ${plural(-n, "day")} ago`]
    if (n === 0) return ["BOD 26-04 · today"]
    return [`BOD 26-04 · in ${plural(n, "day")}`]
  }
  return []
}

const aboutMonths = (n: number) => `about ${plural(n, "month")} later`
const aboutYears = (n: number) => `about ${plural(n, "year")} later`

// Elapsed time between two consecutive events, at the coarser of their precisions.
export function gapText(prev: TimelineEvent, next: TimelineEvent): string | null {
  if (prev.precision === "year" || next.precision === "year") return null
  if (prev.precision === "month" || next.precision === "month") {
    const [y1, m1] = parts(prev.date)
    const [y2, m2] = parts(next.date)
    const months = (y2 * 12 + m2) - (y1 * 12 + m1)
    if (months <= 0) return null
    if (months < 12) return aboutMonths(months)
    return aboutYears(Math.round(months / 12))
  }
  const days = dayNumber(next.date) - dayNumber(prev.date)
  if (days <= 0) return null
  if (days === 1) return "1 day later"
  if (days <= 30) return `${days} days later`
  const months = Math.round(days / 30.4375)
  if (months < 12) return aboutMonths(Math.max(1, months))
  return aboutYears(Math.round(days / 365.25))
}

// The date cell is blank on `next` when it repeats the row above.
export function sameDay(prev: TimelineEvent, next: TimelineEvent): boolean {
  return prev.date === next.date && prev.precision === next.precision
}

export function onlyFirstSeen(events: TimelineEvent[]): boolean {
  return events.length >= 1 && events.every((e) => e.kind === "first_seen")
}

export function utcToday(): string {
  return new Date().toISOString().slice(0, 10)
}
