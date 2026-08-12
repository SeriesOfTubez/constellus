import { LayoutGrid, Rows3 } from "lucide-react"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { type ListViewMode, type GroupMode } from "@/lib/listView"

/** Table-vs-card toggle. Shared across list pages (Findings, Assets). */
export function ViewToggle({ view, onChange }: { view: ListViewMode; onChange: (v: ListViewMode) => void }) {
  const opts: Array<[ListViewMode, string, typeof Rows3]> = [
    ["table", "Table view", Rows3],
    ["card", "Card view", LayoutGrid],
  ]
  return (
    <div className="inline-flex items-center rounded-md border h-9 p-0.5">
      {opts.map(([v, label, Icon]) => (
        <button
          key={v}
          onClick={() => onChange(v)}
          title={label}
          aria-pressed={view === v}
          className={`inline-flex items-center justify-center h-8 w-8 rounded transition-colors ${
            view === v ? "bg-accent text-foreground" : "text-muted-foreground hover:text-foreground"
          }`}
        >
          <Icon className="h-4 w-4" />
        </button>
      ))}
    </div>
  )
}

const DEFAULT_GROUP_OPTIONS: Array<{ value: GroupMode; label: string }> = [
  { value: "none", label: "No grouping" },
  { value: "band", label: "Group by band" },
  { value: "impact", label: "Group by impact" },
  { value: "asset", label: "Group by asset" },
]

/** Grouping-axis picker. Defaults to the Findings vocabulary (none/band/asset);
 *  pass `options` for pages with a different axis set (e.g. Assets: apex/band/none). */
export function GroupBySelect({
  group,
  onChange,
  options = DEFAULT_GROUP_OPTIONS,
}: {
  group: GroupMode
  onChange: (g: GroupMode) => void
  options?: Array<{ value: GroupMode; label: string }>
}) {
  return (
    <Select value={group} onValueChange={v => onChange(v as GroupMode)}>
      <SelectTrigger className="w-36 h-9 text-sm"><SelectValue /></SelectTrigger>
      <SelectContent>
        {options.map(o => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}
      </SelectContent>
    </Select>
  )
}
