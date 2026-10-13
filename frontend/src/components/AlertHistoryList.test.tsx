import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import type { AlertDispatch } from "@/lib/api"
import { AlertHistoryList, deliveryLabel } from "@/components/AlertHistoryList"

const ev = (n: number) => ({
  finding_id: `f-${n}`, title: `CVE-2024-9000${n} on web`, severity: "high" as const,
  asset_value: n % 2 ? "app.example.com" : "203.0.113.7", detail: {},
})

function dispatch(over: Partial<AlertDispatch> = {}): AlertDispatch {
  return {
    id: "d1", rule_id: "r1", rule_name: "Fabrikam critical", kind: "new",
    created_at: new Date().toISOString(), event_count: 5,
    events: [ev(1), ev(2), ev(3)], deliveries: [], ...over,
  }
}
const render = (d: AlertDispatch[]) =>
  renderToStaticMarkup(<MemoryRouter><AlertHistoryList dispatches={d} /></MemoryRouter>)

describe("deliveryLabel", () => {
  it("maps each outcome to plain words", () => {
    expect(deliveryLabel({ outcome: "sent", connector_id: "smtp", recipient_count: 2 })).toBe("Sent via smtp (2 recipients)")
    expect(deliveryLabel({ outcome: "sent", connector_id: "smtp", recipient_count: 1 })).toBe("Sent via smtp (1 recipient)")
    expect(deliveryLabel({ outcome: "failed", connector_id: "smtp", recipient_count: 0 })).toBe("Send failed (smtp)")
    expect(deliveryLabel({ outcome: "raised", connector_id: "smtp", recipient_count: 0 })).toBe("Send error (smtp)")
    expect(deliveryLabel({ outcome: "no_channel", connector_id: null, recipient_count: 0 })).toBe("Not sent: no notification channel enabled")
    expect(deliveryLabel({ outcome: "no_recipients", connector_id: null, recipient_count: 0 })).toBe("Not sent: rule has no recipients")
    expect(deliveryLabel({ outcome: "deferred_to_digest", connector_id: null, recipient_count: 0 })).toBe("Held for the daily digest")
    expect(deliveryLabel({ outcome: "weird", connector_id: null, recipient_count: 0 })).toBe("weird")
  })
})

describe("AlertHistoryList", () => {
  it("renders rule name, kind, shown events, +n and link", () => {
    const html = render([dispatch()])
    expect(html).toContain("Fabrikam critical")
    expect(html).toContain("New findings")
    expect(html).toContain("CVE-2024-90001 on web")
    expect(html).toContain("CVE-2024-90002 on web")
    expect(html).not.toContain("CVE-2024-90003 on web")
    expect(html).toContain("+3")
    expect(html).toContain('href="/findings?id=f-1"')
    expect(html).toContain("app.example.com")
  })

  it("labels promotions as risk escalation and omits +n when all shown", () => {
    const html = render([dispatch({ kind: "promotion", event_count: 2, events: [ev(1), ev(2)] })])
    expect(html).toContain("Risk escalation")
    expect(html).not.toContain("+0")
    expect(html).not.toMatch(/>\+\d/)
  })

  it("renders every delivery outcome including unknown", () => {
    const html = render([dispatch({
      deliveries: [
        { connector_id: "smtp", outcome: "sent", recipient_count: 2 },
        { connector_id: "smtp", outcome: "failed", recipient_count: 0 },
        { connector_id: "smtp", outcome: "raised", recipient_count: 0 },
        { connector_id: null, outcome: "no_channel", recipient_count: 0 },
        { connector_id: null, outcome: "no_recipients", recipient_count: 0 },
        { connector_id: null, outcome: "mystery" as never, recipient_count: 0 },
      ],
    })])
    for (const t of ["Sent via smtp (2 recipients)", "Send failed (smtp)", "Send error (smtp)",
      "Not sent: no notification channel enabled", "Not sent: rule has no recipients", "mystery"]) {
      expect(html).toContain(t)
    }
  })

  it("shows the empty state", () => {
    expect(render([])).toContain("No alerts recorded yet.")
  })
})
