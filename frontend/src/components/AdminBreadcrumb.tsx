import { Link } from "react-router-dom"
import { ChevronRight } from "lucide-react"

export function AdminBreadcrumb({ page }: { page: string }) {
  return (
    <div className="flex items-center gap-1.5 text-sm">
      <Link to="/admin" className="text-muted-foreground hover:text-foreground transition-colors">
        Admin
      </Link>
      <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
      <span className="text-foreground font-medium">{page}</span>
    </div>
  )
}
