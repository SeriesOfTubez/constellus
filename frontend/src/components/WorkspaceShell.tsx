import { cn } from "@/lib/utils"

export interface TabDef {
  key: string
  label: string
  count?: number
}

interface WorkspaceShellProps {
  title: string
  subtitle?: string
  tabs: TabDef[]
  activeTab: string
  onTabChange: (key: string) => void
  toolbar?: React.ReactNode
  bulkBar?: React.ReactNode
  primaryAction?: React.ReactNode
  children: React.ReactNode
}

/** Reusable page chrome for every data page (Assets, Findings, Explore…).
 *  Renders: header → tab bar → toolbar → optional bulk bar → children (table).
 *  The page data, queries, and mutations stay in the consuming component. */
export function WorkspaceShell({
  title,
  subtitle,
  tabs,
  activeTab,
  onTabChange,
  toolbar,
  bulkBar,
  primaryAction,
  children,
}: WorkspaceShellProps) {
  return (
    <div className="flex flex-col min-h-full">
      {/* Header */}
      <div className="px-6 pt-6 pb-4 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">{title}</h1>
          {subtitle && <p className="text-sm text-muted-foreground mt-0.5">{subtitle}</p>}
        </div>
        {primaryAction && <div className="shrink-0">{primaryAction}</div>}
      </div>

      {/* Tab bar */}
      <div className="px-6 border-b flex items-center gap-0">
        {tabs.map(tab => (
          <button
            key={tab.key}
            onClick={() => onTabChange(tab.key)}
            className={cn(
              "relative flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px",
              activeTab === tab.key
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:text-foreground hover:border-border"
            )}
          >
            {tab.label}
            {tab.count !== undefined && (
              <span className={cn(
                "rounded-full px-1.5 py-0.5 text-[10px] font-semibold tabular-nums",
                activeTab === tab.key
                  ? "bg-primary/15 text-primary"
                  : "bg-muted text-muted-foreground"
              )}>
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Toolbar */}
      {toolbar && (
        <div className="px-6 py-3 flex flex-wrap gap-3 items-center border-b bg-card/50">
          {toolbar}
        </div>
      )}

      {/* Bulk action bar */}
      {bulkBar && (
        <div className="px-6 py-2 border-b bg-muted/30">
          {bulkBar}
        </div>
      )}

      {/* Page content */}
      <div className="flex-1 px-6 py-4">
        {children}
      </div>
    </div>
  )
}
