import { useState } from "react"
import { Link } from "react-router-dom"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Briefcase, Loader2, Plus, SquareArrowOutUpRight } from "lucide-react"
import { AdminBreadcrumb } from "@/components/AdminBreadcrumb"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api, type Engagement } from "@/lib/api"
import { relativeTime } from "@/lib/time"

const POSTURE_LABEL: Record<string, string> = {
  pre_close: "Pre-close",
  day_0: "Day 0",
  integrated: "Integrated",
  abandoned: "Abandoned",
}
const POSTURE_VARIANT: Record<string, "warning" | "success" | "secondary" | "outline"> = {
  pre_close: "warning",
  day_0: "success",
  integrated: "success",
  abandoned: "secondary",
}

function PostureBadge({ posture }: { posture: string }) {
  return <Badge variant={POSTURE_VARIANT[posture] ?? "outline"}>{POSTURE_LABEL[posture] ?? posture}</Badge>
}

export default function Engagements() {
  const qc = useQueryClient()
  const [createOpen, setCreateOpen] = useState(false)
  const [newName, setNewName] = useState("")

  const { data: engagements, isLoading } = useQuery({
    queryKey: ["engagements"],
    queryFn: () => api.get<Engagement[]>("/engagements/"),
  })

  const createMutation = useMutation({
    mutationFn: (name: string) => api.post<Engagement>("/engagements/", { name }),
    onSuccess: (created) => {
      toast.success(`${created.name} created`)
      qc.invalidateQueries({ queryKey: ["engagements"] })
      setCreateOpen(false)
      setNewName("")
    },
    onError: (e: { message?: string }) => toast.error(e?.message ?? "Failed to create engagement"),
  })

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <AdminBreadcrumb page="Engagements" />
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Engagements</h1>
          <p className="text-sm text-muted-foreground mt-1">
            M&A and diligence engagements — posture, member targets, and recorded authorisation.
          </p>
        </div>
        <Button size="sm" onClick={() => setCreateOpen(true)}>
          <Plus className="h-4 w-4 mr-1.5" />New Engagement
        </Button>
      </div>

      {isLoading ? (
        <div className="space-y-2">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}</div>
      ) : !engagements?.length ? (
        <div className="rounded-lg border bg-card p-12 text-center text-muted-foreground">
          <Briefcase className="h-12 w-12 mx-auto mb-4 opacity-30" />
          <p className="font-medium">No engagements yet</p>
          <p className="text-sm mt-1">
            Create one here, or mark a target as M&A (pre-close) from its detail page.
          </p>
        </div>
      ) : (
        <div className="rounded-lg border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead>Name</TableHead>
                <TableHead className="w-32">Posture</TableHead>
                <TableHead className="hidden md:table-cell">Member targets</TableHead>
                <TableHead className="hidden lg:table-cell">Authorised by</TableHead>
                <TableHead className="hidden lg:table-cell">Created</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {engagements.map(e => (
                <TableRow key={e.id}>
                  <TableCell className="font-medium">{e.name}</TableCell>
                  <TableCell><PostureBadge posture={e.posture} /></TableCell>
                  <TableCell className="hidden md:table-cell text-sm text-muted-foreground">
                    {e.member_targets.length}
                  </TableCell>
                  <TableCell className="hidden lg:table-cell text-xs text-muted-foreground">
                    {e.authorised_by ?? "—"}
                  </TableCell>
                  <TableCell className="hidden lg:table-cell text-xs text-muted-foreground">
                    {relativeTime(e.created_at)}
                  </TableCell>
                  <TableCell>
                    <Link
                      to={`/admin/engagements/${e.id}`}
                      className="inline-flex items-center text-muted-foreground hover:text-primary transition-colors"
                      title="Open full view"
                    >
                      <SquareArrowOutUpRight className="h-3.5 w-3.5" />
                    </Link>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>New Engagement</DialogTitle>
            <DialogDescription>Starts in pre-close — traffic to member targets restricts to passive-only.</DialogDescription>
          </DialogHeader>
          <Input
            placeholder="Engagement name"
            value={newName}
            onChange={e => setNewName(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter" && newName.trim()) createMutation.mutate(newName.trim()) }}
            autoFocus
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button disabled={!newName.trim() || createMutation.isPending} onClick={() => createMutation.mutate(newName.trim())}>
              {createMutation.isPending && <Loader2 className="h-4 w-4 animate-spin mr-1.5" />}Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
