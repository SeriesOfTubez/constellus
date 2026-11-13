import type { ScoreBand } from "@/lib/api"
import type { SevTone } from "@/components/ui/chip"

export const BAND_VAR: Record<ScoreBand, string> = {
  imminent_compromise: "var(--sev-critical)",
  high:                "var(--sev-high)",
  elevated:            "var(--sev-medium)",
  low:                 "var(--sev-low)",
  secure:              "var(--sev-clean)",
}

export const SEV_VAR: Record<SevTone, string> = {
  critical: "var(--sev-critical)",
  high:     "var(--sev-high)",
  medium:   "var(--sev-medium)",
  low:      "var(--sev-low)",
  unknown:  "var(--sev-unknown)",
  clean:    "var(--sev-clean)",
}
