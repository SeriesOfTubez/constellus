import { useState } from "react"
import { Eye, EyeOff } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Skeleton } from "@/components/ui/skeleton"

export type FieldDef = { label: string; type: string; help?: string; default?: unknown; options?: string[] }

export function SecretInput({ value, onChange, placeholder, id }: { value: string; onChange: (v: string) => void; placeholder?: string; id?: string }) {
  const [show, setShow] = useState(false)
  return (
    <div className="relative">
      <Input id={id} type={show ? "text" : "password"} value={value}
        onChange={(e) => onChange(e.target.value)} className="pr-10" placeholder={placeholder} />
      <button type="button" onClick={() => setShow(s => !s)} tabIndex={-1}
        className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors">
        {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
      </button>
    </div>
  )
}

/**
 * Renders a connector's config_schema as a field list — shared between the
 * Admin → Connectors config sheet and the first-run setup wizard so both
 * surfaces stay in lockstep with the schema's field types.
 */
export function ConnectorConfigFields({
  schema,
  values,
  onChange,
  loaded = true,
}: {
  schema: Record<string, FieldDef>
  values: Record<string, string | boolean>
  onChange: (key: string, value: string | boolean) => void
  loaded?: boolean
}) {
  if (!loaded) {
    return (
      <div className="space-y-5">
        {Array.from({ length: Object.keys(schema).length || 3 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
      </div>
    )
  }

  return (
    <div className="space-y-5">
      {Object.entries(schema).map(([key, field]) => (
        <div key={key} className="space-y-1.5">
          {field.type === "boolean" ? (
            <>
              <div className="flex items-center justify-between gap-4">
                <Label htmlFor={key} className="cursor-pointer">{field.label}</Label>
                <Switch
                  id={key}
                  checked={Boolean(values[key])}
                  onCheckedChange={(v) => onChange(key, v)}
                />
              </div>
              {field.help && <p className="text-xs text-muted-foreground">{field.help}</p>}
            </>
          ) : field.type === "secret" ? (
            <>
              <Label htmlFor={key}>{field.label}</Label>
              <SecretInput id={key} value={(values[key] as string | undefined) ?? ""}
                onChange={(v) => onChange(key, v)}
                placeholder={`Enter ${field.label.toLowerCase()}`} />
              {field.help && <p className="text-xs text-muted-foreground">{field.help}</p>}
            </>
          ) : field.type === "select" ? (
            <>
              <Label htmlFor={key}>{field.label}</Label>
              <Select value={(values[key] as string | undefined) ?? String(field.default ?? "")}
                onValueChange={(v) => onChange(key, v)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {field.options?.map(o => <SelectItem key={o} value={o}>{o}</SelectItem>)}
                </SelectContent>
              </Select>
            </>
          ) : (
            <>
              <Label htmlFor={key}>{field.label}</Label>
              <Input id={key} value={(values[key] as string | undefined) ?? ""}
                onChange={(e) => onChange(key, e.target.value)}
                placeholder={field.help ?? `Enter ${field.label.toLowerCase()}`} />
              {field.help && <p className="text-xs text-muted-foreground">{field.help}</p>}
            </>
          )}
        </div>
      ))}
    </div>
  )
}

/** Builds the initial `values` map for a schema from a stored config blob. */
export function fillConfigValues(schema: Record<string, FieldDef>, stored: Record<string, unknown>): Record<string, string | boolean> {
  const filled: Record<string, string | boolean> = {}
  Object.entries(schema).forEach(([k, f]) => {
    const value = stored[k]
    if (f.type === "boolean") {
      filled[k] = typeof value === "boolean" ? value
        : typeof value === "string" ? value.toLowerCase() === "true"
        : Boolean(f.default)
    } else {
      filled[k] = value != null ? String(value) : String(f.default ?? "")
    }
  })
  return filled
}
