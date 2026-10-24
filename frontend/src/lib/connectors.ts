// Pure logic behind Admin → Connectors (planning#284): grouping, the copy for
// binding suggestions, and the plain-words reading of the API's refusals.
import type { BindingSuggestion, ConnectorInstanceSummary, ConnectorTypeSummary } from "@/lib/api"

export const PHASE_ORDER = ["discovery", "enrichment", "scanning", "notification", "inference"]

export function groupByPhase(types: ConnectorTypeSummary[]): Record<string, ConnectorTypeSummary[]> {
  return PHASE_ORDER.reduce<Record<string, ConnectorTypeSummary[]>>((acc, phase) => {
    acc[phase] = types.filter((t) => t.phase === phase)
    return acc
  }, {})
}

/** Types whose instances list zones (Zones tab, sync) and can suggest a
 * binding from them: the API's `supports_zones` (a DNS-discovery type). */
export function hasZones(type: ConnectorTypeSummary): boolean {
  return type.supports_zones
}

export const BINDING_PAUSED_COPY =
  "Syncing is paused: this organization's deal engagement re-opened, so the instance may no longer be bound to it."

export function bindingWarning(instance: ConnectorInstanceSummary): string | null {
  return instance.binding_ok ? null : BINDING_PAUSED_COPY
}

/** Sync needs: a zone-capable type, enabled, configured and a binding that still holds. */
export function canSync(type: ConnectorTypeSummary, instance: ConnectorInstanceSummary): boolean {
  return hasZones(type) && instance.enabled && instance.configured && instance.binding_ok
}

/** The line shown after "Find matching organization". */
export function suggestionCopy(s: BindingSuggestion): string {
  const total = s.zone_count
  if (s.suggested_entity_id) {
    const top = s.candidates.find((c) => c.entity_id === s.suggested_entity_id)
    if (top) {
      return total != null
        ? `${top.matches} of ${total} zones match ${top.name}`
        : `${top.matches} zones match ${top.name}`
    }
  }
  if (total === 0) {
    return "The provider returned no zones. Check the token with Test, then try again."
  }
  if (s.candidates.length > 1) {
    return `Several organizations match equally (${s.candidates
      .map((c) => `${c.name}: ${c.matches}`)
      .join(", ")}). Pick one.`
  }
  return "No organization's claimed domains match these zones. Pick one."
}

type Refusal = { status?: number; detail?: unknown; body?: unknown; message?: string }

const BINDING_REASONS: Record<string, string> = {
  unknown_entity: "that organization no longer exists",
  not_an_organization: "that is not an organization root",
  deal_engagement_ambiguous: "the deal does not have exactly one open engagement",
  deal_not_closed: "the deal has not closed yet (its engagement must be day 0 or integrated)",
  not_visible: "you do not have access to that organization",
}

/** Reads a 422/409 from create, rebind or sync into words. */
export function bindingErrorMessage(err: Refusal): string {
  const d = err.detail
  if (d && typeof d === "object") {
    const { code, reason } = d as { code?: string; reason?: string }
    if (code === "binding_required") return "Pick the organization this account belongs to."
    if (code === "binding_forbidden") return "This connector is global and cannot be bound to an organization."
    if (code === "binding_not_allowed") {
      return `This organization cannot be bound: ${BINDING_REASONS[reason ?? ""] ?? reason ?? "not allowed"}.`
    }
  }
  if (typeof d === "string" && d) return d
  return err.message || "Request failed"
}

/** The 409 from deleting an instance that targets still use. null for any other error. */
export function deleteConflictMessage(err: Refusal): string | null {
  if (err.status !== 409) return null
  const ids = (err.body as { target_ids?: unknown } | undefined)?.target_ids
  const n = Array.isArray(ids) ? ids.length : 0
  if (n === 0) return "Still used by targets — disable it instead"
  return `Used by ${n} target${n === 1 ? "" : "s"} — disable it instead`
}
