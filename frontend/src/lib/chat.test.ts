import { describe, expect, it } from "vitest"
import { ApiError } from "@/lib/api"
import {
  askErrorReason, countedQueries, exploreHref, formatCount, isInternalHref, parseExploreParam,
  STOP_NOTICES, stopNotice, summariseQuery, type QueryObject,
} from "@/lib/chat"

const ID = "3f2b8c1e-4d5a-4b6c-8d7e-9f0a1b2c3d4e"

describe("formatCount", () => {
  it("shows the exact count", () => {
    expect(formatCount(37, false)).toBe("37")
    expect(formatCount(1234, false)).toBe("1,234")
  })
  it("marks a capped count as 'more than'", () => {
    expect(formatCount(10000, true)).toBe("10,000+")
  })
})

describe("countedQueries", () => {
  const q: QueryObject = { version: 1, entity: "asset", where: { field: "asset.type", op: "eq", value: "ip" } }
  it("keeps run_query calls with a count, in order", () => {
    const out = countedQueries([
      { tool: "describe_schema" },
      { tool: "run_query", query: q, count: 37, count_capped: false, rows_shown: 25 },
      { tool: "run_query", error: "invalid_query" },
      { tool: "get_asset" },
      { tool: "run_query", query: { ...q, entity: "finding" }, count: 10000, count_capped: true, rows_shown: 25 },
    ])
    expect(out).toEqual([
      { query: q, count: 37, count_capped: false, times: 1 },
      { query: { ...q, entity: "finding" }, count: 10000, count_capped: true, times: 1 },
    ])
  })
  it("folds an identical query run again into one row, keeping first-run order", () => {
    const other: QueryObject = { ...q, entity: "finding" }
    const out = countedQueries([
      { tool: "run_query", query: q, count: 3 },
      { tool: "run_query", query: other, count: 5 },
      { tool: "run_query", query: { ...q }, count: 3 },
      { tool: "run_query", query: q, count: 3 },
    ])
    expect(out.map(c => [c.query.entity, c.count, c.times])).toEqual([["asset", 3, 3], ["finding", 5, 1]])
  })
  it("keeps the same query with a different count as its own row", () => {
    const out = countedQueries([
      { tool: "run_query", query: q, count: 3 },
      { tool: "run_query", query: q, count: 4 },
      { tool: "run_query", query: q, count: 3, count_capped: true },
    ])
    expect(out.map(c => [c.count, c.count_capped, c.times])).toEqual([[3, false, 1], [4, false, 1], [3, true, 1]])
  })
  it("tolerates a missing trace", () => {
    expect(countedQueries(undefined)).toEqual([])
  })
})

describe("summariseQuery", () => {
  it("names the entity alone without a filter", () => {
    expect(summariseQuery({ entity: "asset" })).toBe("assets")
  })
  it("shows one condition", () => {
    expect(summariseQuery({ entity: "finding", where: { field: "finding.severity", op: "eq", value: "critical" } }))
      .toBe("findings · finding.severity = critical")
  })
  it("shows the first two conditions of an all, then +n", () => {
    expect(summariseQuery({
      entity: "asset",
      where: { all: [
        { field: "asset.type", op: "eq", value: "hostname" },
        { exists: { relation: "port", where: { all: [
          { field: "port.service", op: "eq", value: "nginx" },
          { field: "port.number", op: "eq", value: 443 },
        ] } } },
        { field: "asset.tags", op: "has", value: "prod" },
        { not: { field: "asset.suppressed", op: "eq", value: true } },
      ] },
    })).toBe("assets · asset.type = hostname, port where port.service = nginx +1 +2")
  })
  it("summarises in-lists and empty checks", () => {
    expect(summariseQuery({ entity: "asset", where: { field: "asset.type", op: "in", value: ["ip", "hostname"] } }))
      .toBe("assets · asset.type in [ip, hostname]")
    expect(summariseQuery({ entity: "finding", where: { field: "finding.cve_id", op: "is_null", value: true } }))
      .toBe("findings · finding.cve_id is empty")
    expect(summariseQuery({ entity: "finding", where: { field: "finding.cve_id", op: "is_null", value: false } }))
      .toBe("findings · finding.cve_id is set")
  })
})

describe("isInternalHref", () => {
  it.each([`/assets/${ID}`, `/findings/${ID}`, `/organizations/entity/${ID.toUpperCase()}`])("accepts %s", h => {
    expect(isInternalHref(h)).toBe(true)
  })
  it.each([
    "", "https://evil.example", `https://evil.example/assets/${ID}`, `//evil.example/assets/${ID}`,
    `/assets/${ID}/`, `/assets/${ID}?x=1`, `/assets/${ID}#x`, `/targets/${ID}`, `/entities/${ID}`, `/organizations/${ID}`, "/assets/not-a-uuid",
    `/assets/${ID.replace(/-/g, "")}`, `javascript:/assets/${ID}`, ` /assets/${ID}`,
  ])("rejects %s", h => {
    expect(isInternalHref(h)).toBe(false)
  })
  it("rejects non-strings, even one that stringifies to a record path", () => {
    expect(isInternalHref(undefined)).toBe(false)
    expect(isInternalHref(null)).toBe(false)
    expect(isInternalHref({ toString: () => `/assets/${ID}` })).toBe(false)
  })
})

describe("Explore link", () => {
  it("round-trips the query object through the URL", () => {
    const q: QueryObject = { version: 1, entity: "asset", where: { field: "asset.value", op: "contains", value: "a&b=c #?" } }
    const href = exploreHref(q)
    expect(href.startsWith("/explore?q=")).toBe(true)
    const raw = new URLSearchParams(href.slice("/explore?".length)).get("q")
    expect(parseExploreParam(raw)).toEqual(q)
  })
  it.each([null, "", "not json", "[1,2]", "42", "null", '"str"'])("ignores %s", raw => {
    expect(parseExploreParam(raw)).toBeNull()
  })
})

describe("notices", () => {
  it("has none for an answered question", () => {
    expect(stopNotice("answered")).toBeNull()
    expect(stopNotice(undefined)).toBeNull()
  })
  it("has one sentence for every other stop reason", () => {
    for (const reason of Object.keys(STOP_NOTICES) as (keyof typeof STOP_NOTICES)[]) {
      expect(stopNotice(reason)).toBe(STOP_NOTICES[reason])
    }
    expect(Object.keys(STOP_NOTICES).sort())
      .toEqual(["error", "round_limit", "spend_limit", "token_limit", "tool_call_limit"])
  })
})

describe("askErrorReason", () => {
  it("passes the server's own words through for 409 and 422", () => {
    expect(askErrorReason(new ApiError(409, "This conversation reached 20 questions; start a new one.")))
      .toBe("This conversation reached 20 questions; start a new one.")
    expect(askErrorReason(new ApiError(422, "The question is empty."))).toBe("The question is empty.")
  })
  it("explains the AI-side failures in plain language", () => {
    expect(askErrorReason(new ApiError(503, "AI is not available: x"))).toMatch(/not configured/)
    expect(askErrorReason(new ApiError(429, "budget"))).toMatch(/budget or rate limit/)
    expect(askErrorReason(new ApiError(502, "The AI model failed: LLMTimeout"))).toMatch(/model failed/)
  })
  it("covers a network failure", () => {
    expect(askErrorReason(new TypeError("Failed to fetch"))).toMatch(/connection/)
  })
})
