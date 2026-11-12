import type { ScoreBand } from "@/lib/api"

export const BAND_VAR: Record<ScoreBand, string> = {
  imminent_compromise: "var(--sev-critical)",
  high:                "var(--sev-high)",
  elevated:            "var(--sev-medium)",
  low:                 "var(--sev-low)",
  secure:              "var(--sev-clean)",
}
