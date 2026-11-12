import { MoreVertical, ShieldCheck, ShieldOff, RefreshCw, ChevronDown, Loader2 } from "lucide-react"
import { type Finding } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"

/** Per-finding state actions (acknowledge / suppress / re-verify / reopen),
 *  consolidated into a single "more" menu. Shared by the Findings table row
 *  and card so both views offer the same quick actions without competing
 *  with the title/CVE info for horizontal space. */
export function FindingActionsMenu({
  finding: f,
  onAcknowledge,
  onSuppress,
  onVerify,
  onReopen,
  verifyPending,
  statePending,
}: {
  finding: Finding
  onAcknowledge: () => void
  onSuppress: () => void
  onVerify: () => void
  onReopen: () => void
  verifyPending?: boolean
  statePending?: boolean
}) {
  if (f.state === "resolved") return null

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" title="More actions" onClick={e => e.stopPropagation()}>
          <MoreVertical className="size-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" onClick={e => e.stopPropagation()}>
        {f.state === "open" && (
          <>
            <DropdownMenuItem disabled={statePending} onClick={onAcknowledge}>
              <ShieldCheck className="size-4" />Acknowledge
            </DropdownMenuItem>
            <DropdownMenuItem onClick={onSuppress}>
              <ShieldOff className="size-4" />Suppress
            </DropdownMenuItem>
          </>
        )}
        {(f.state === "open" || f.state === "acknowledged") && (
          <DropdownMenuItem disabled={verifyPending} onClick={onVerify}>
            {verifyPending ? <Loader2 className="size-4 animate-spin" /> : <RefreshCw className="size-4" />}Re-verify
          </DropdownMenuItem>
        )}
        {f.state === "suppressed" && (
          <DropdownMenuItem disabled={statePending} onClick={onReopen}>
            <ChevronDown className="size-4 rotate-180" />Reopen
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
