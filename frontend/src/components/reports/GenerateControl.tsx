import { Button } from "@/components/ui/button"
import { canGenerateReports } from "@/lib/reports"

/** The "Generate" button, rendered only for roles allowed to generate. */
export function GenerateControl({ role, busy, onClick }: { role: string | undefined; busy: boolean; onClick: () => void }) {
  if (!canGenerateReports(role)) return null
  return <Button onClick={onClick} disabled={busy}>Generate executive summary</Button>
}
