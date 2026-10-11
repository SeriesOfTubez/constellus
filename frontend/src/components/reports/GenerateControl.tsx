import { Button } from "@/components/ui/button"
import { canGenerateReports } from "@/lib/reports"

/** The generate actions, rendered only for roles allowed to generate.
 *  `onClick` generates the executive summary; `onGenerateMa` the M&A brief,
 *  which needs an engagement with a subject entity (`noSubject` disables it). */
export function GenerateControl({ role, busy, onClick, onGenerateMa, noSubject = false }: {
  role: string | undefined
  busy: boolean
  onClick: () => void
  onGenerateMa?: () => void
  noSubject?: boolean
}) {
  if (!canGenerateReports(role)) return null
  return (
    <div className="flex items-center gap-2">
      <Button onClick={onClick} disabled={busy}>Generate executive summary</Button>
      {onGenerateMa && (
        <Button
          variant="outline"
          onClick={onGenerateMa}
          disabled={busy || noSubject}
          title={noSubject ? "This engagement has no subject entity" : undefined}
        >
          Generate M&amp;A brief
        </Button>
      )}
    </div>
  )
}
