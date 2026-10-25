// planning#277 S2c — first-run "Your company" step: the same add-organization
// flow the Organizations page uses, with the relationship fixed to "Ours".
// Nothing is created until Finish; Skip leaves the step without creating anything.
import { useState } from "react"
import { Link } from "react-router-dom"
import { useQueryClient } from "@tanstack/react-query"
import { CheckCircle2, ChevronRight } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { AddOrganizationFlow } from "@/components/AddOrganizationFlow"
import { SeedProgressPanel } from "@/components/SeedProgressPanel"
import type { AddOrganizationResponse } from "@/lib/organizations"

export function SetupOrganizationStep({ onContinue }: { onContinue: () => void }) {
  const qc = useQueryClient()
  const [created, setCreated] = useState<{ resp: AddOrganizationResponse; name: string; cik: string | null } | null>(null)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Your company</CardTitle>
        <CardDescription>
          {created
            ? "Your organization is added. Everything discovered stays proposed for you to review."
            : "Add your organization from its primary domain. If it files with the SEC, you choose which filer is yours; nothing is matched automatically."}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {created ? (
          <div className="space-y-4">
            <div className="rounded-lg border p-4 text-sm space-y-1">
              <p className="flex items-center gap-2 font-medium">
                <CheckCircle2 className="h-4 w-4" />{created.name} added
              </p>
              <p className="text-muted-foreground pl-6">Seed domain claimed. Discovery is queued.</p>
            </div>
            {created.resp.ingest_run_id && created.resp.ingest !== "not_requested" && (
              <SeedProgressPanel seeded={{
                entity_id: created.resp.organization_id,
                entity_name: created.name,
                cik: created.cik,
                run_id: created.resp.ingest_run_id,
                ingest: created.resp.ingest,
              }} />
            )}
            <div className="flex items-center justify-between">
              <Button variant="outline" asChild>
                {/* Drop the cached first-run status so the setup guard re-reads it
                    instead of bouncing back to /setup. */}
                <Link to={`/organizations/${created.resp.organization_id}`}
                  onClick={() => qc.removeQueries({ queryKey: ["system-status"] })}>
                  Open organization
                </Link>
              </Button>
              <Button onClick={onContinue}>Continue <ChevronRight className="h-4 w-4" /></Button>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <AddOrganizationFlow
              presetRelationship="ours"
              onCreated={(resp, name, cik) => setCreated({ resp, name, cik })}
            />
            <div className="pt-2">
              <button
                type="button"
                onClick={onContinue}
                className="text-xs text-muted-foreground underline underline-offset-2 hover:text-foreground transition-colors"
              >
                Skip this step
              </button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
