// planning#232 — pure helpers for the new-organization ingest progress panel:
// map the ingest run + its acquisition_read follow-up to what the step shows.
import type { EntityIngestRun } from "@/lib/api"

export type RunStatus = EntityIngestRun["status"]

export type ReadFollowup =
  | { status: "queued"; run_id?: string }
  | { status: "skipped"; reason?: string }
  | undefined

export type SeedProgressInput = {
  ingest: "queued" | "already_running"
  ingestStatus: RunStatus | undefined
  ingestError: string | null | undefined
  followup: ReadFollowup
  // Status of the acquisition read's own run, once it has been found.
  readStatus: RunStatus | undefined
  readError: string | null | undefined
}

export type SeedProgress = {
  phase: "ingest" | "read" | "done" | "failed" | "already_running"
  ingestLabel: string
  readLabel: string | null
  hint: string | null
  // True while either run may still change — drives refetchInterval.
  polling: boolean
}

export const AI_CONFIGURE_HINT =
  "Configure AI later under Admin → AI models, then run it from the company page."

export function isAiReason(reason: string | undefined | null): boolean {
  return !!reason && /\b(ai models?|openrouter)\b/i.test(reason)
}

export function isActive(status: RunStatus | undefined): boolean {
  return status === undefined || status === "queued" || status === "running"
}

export function followupOf(result: EntityIngestRun["result"] | undefined): ReadFollowup {
  const f = (result as Record<string, unknown> | null | undefined)?.acquisition_read
  if (!f || typeof f !== "object") return undefined
  const status = (f as { status?: unknown }).status
  if (status === "queued") {
    const run_id = (f as { run_id?: unknown }).run_id
    return { status: "queued", run_id: typeof run_id === "string" ? run_id : undefined }
  }
  if (status === "skipped") {
    const reason = (f as { reason?: unknown }).reason
    return { status: "skipped", reason: typeof reason === "string" ? reason : undefined }
  }
  return undefined
}

export function seedProgress(i: SeedProgressInput): SeedProgress {
  if (i.ingest === "already_running") {
    return {
      phase: "already_running",
      ingestLabel: "An import of this company is already running.",
      readLabel: null,
      hint: null,
      polling: false,
    }
  }
  if (i.ingestStatus === "failed") {
    return {
      phase: "failed",
      ingestLabel: `Couldn't read filings: ${i.ingestError || "unknown error"}`,
      readLabel: null,
      hint: null,
      polling: false,
    }
  }
  if (i.ingestStatus !== "succeeded") {
    return {
      phase: "ingest",
      ingestLabel: "Reading SEC filings…",
      readLabel: null,
      hint: null,
      polling: true,
    }
  }
  const ingestLabel = "Filings read"
  const f = i.followup
  if (!f) {
    return { phase: "done", ingestLabel, readLabel: null, hint: null, polling: false }
  }
  if (f.status === "skipped") {
    const reason = f.reason || "no reason given"
    return {
      phase: "done",
      ingestLabel,
      readLabel: `Acquisition read skipped: ${reason}`,
      hint: isAiReason(f.reason) ? AI_CONFIGURE_HINT : null,
      polling: false,
    }
  }
  if (i.readStatus === "failed") {
    return {
      phase: "done",
      ingestLabel,
      readLabel: `Acquisition read failed: ${i.readError || "unknown error"}`,
      hint: null,
      polling: false,
    }
  }
  if (i.readStatus === "succeeded") {
    return { phase: "done", ingestLabel, readLabel: "Acquisition read finished", hint: null, polling: false }
  }
  return {
    phase: "read",
    ingestLabel,
    readLabel: "Looking for acquisitions with AI…",
    hint: null,
    polling: true,
  }
}
