// Resolver for `entityHref(id)` (planning#277 S2c): asks the backend which
// organization (and tree node) a company belongs to, then redirects there.
import { Link, Navigate, useParams } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"
import { api, ApiError } from "@/lib/api"
import { orgEntityTarget, type LocateResponse } from "@/lib/organizations"
import { errorDetail } from "@/components/OrgCandidateParts"
import { Skeleton } from "@/components/ui/skeleton"

export const locateKey = (id: string) => ["org-locate", id] as const

export default function OrganizationEntityRedirect() {
  const { id = "" } = useParams<{ id: string }>()
  const q = useQuery({
    queryKey: locateKey(id),
    enabled: !!id,
    queryFn: () => api.get<LocateResponse>(`/organizations/locate/${id}`),
    retry: (n, e) => !(e instanceof ApiError && e.status === 404) && n < 2,
  })

  if (q.data) return <Navigate replace to={orgEntityTarget(q.data)} />
  if (q.isError) {
    if (q.error instanceof ApiError && q.error.status === 404) {
      return (
        <div className="p-10 text-center text-sm text-muted-foreground space-y-2">
          <p>This company is not part of an organization you can see.</p>
          <Link to="/organizations" className="underline">Back to organizations</Link>
        </div>
      )
    }
    return <div className="p-6 text-sm text-destructive" role="alert">{errorDetail(q.error)}</div>
  }
  return <div className="p-6 space-y-2"><Skeleton className="h-6 w-64" /><Skeleton className="h-20 w-full" /></div>
}
