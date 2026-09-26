import { toast } from "sonner"
import { useAuthStore } from "@/lib/auth"

// Auth header is added manually here (not via `api.get`) because the
// response is `text/plain`, not JSON, and must never be parsed or rendered
// as HTML in our origin — the backend forces the content-type for exactly
// that reason (`app/api/entities.py`'s `get_evidence`).
export async function openEvidence(fetchId: string) {
  const { tokens } = useAuthStore.getState()
  try {
    const res = await fetch(`/api/entities/evidence/${fetchId}`, {
      headers: tokens?.access_token ? { Authorization: `Bearer ${tokens.access_token}` } : {},
    })
    if (!res.ok) {
      toast.error("Failed to load evidence")
      return
    }
    // A blob: URL is SAME-ORIGIN with the app, so its type decides whether
    // fetched third-party HTML could run here. Force it client-side rather
    // than trusting whatever content-type the response carried.
    const blob = new Blob([await res.arrayBuffer()], { type: "text/plain;charset=utf-8" })
    const url = URL.createObjectURL(blob)
    window.open(url, "_blank", "noopener,noreferrer")
    setTimeout(() => URL.revokeObjectURL(url), 60_000)
  } catch {
    toast.error("Failed to load evidence")
  }
}
