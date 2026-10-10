/**
 * Renders an assistant answer (planning#228 slice 2).
 *
 * The server has already sanitised the markdown (images, raw HTML,
 * autolinks, external links and links to records no tool returned are
 * removed). This renderer is the second layer and assumes nothing of the
 * first: an EASM's data is hostile, and an answer quotes it.
 *  - Raw HTML is skipped, never parsed into elements.
 *  - Only the elements below render. Anything else (img, input, footnote
 *    sections) is dropped and only its text children are kept.
 *  - A link renders as a link only when it points at a record page by id
 *    (`isInternalHref`). Every other link, autolink or `www.` literal
 *    renders as its text.
 */
import Markdown, { type Components } from "react-markdown"
import remarkGfm from "remark-gfm"
import { Link } from "react-router-dom"
import { isInternalHref } from "@/lib/chat"

export const ALLOWED_ELEMENTS = [
  "p", "br", "hr", "strong", "em", "del", "code", "pre", "blockquote",
  "ul", "ol", "li", "a", "h1", "h2", "h3", "h4", "h5", "h6",
  "table", "thead", "tbody", "tr", "th", "td",
]

/** Keep a URL only when it is a record link; anything else becomes "" and
 *  the `a` component below renders plain text for it. */
export function chatUrlTransform(url: string): string {
  return isInternalHref(url) ? url : ""
}

/** A link only for a record page by id; anything else is its text. */
export function ChatLink({ href, children }: { href?: string; children?: React.ReactNode }) {
  return isInternalHref(href)
    ? <Link to={href} className="text-primary underline underline-offset-2 hover:opacity-80">{children}</Link>
    : <span>{children}</span>
}

const components: Components = {
  a: ({ href, children }) => <ChatLink href={href}>{children}</ChatLink>,
  p: ({ children }) => <p className="my-2 first:mt-0 last:mb-0">{children}</p>,
  ul: ({ children }) => <ul className="my-2 ml-5 list-disc space-y-1">{children}</ul>,
  ol: ({ children }) => <ol className="my-2 ml-5 list-decimal space-y-1">{children}</ol>,
  code: ({ children }) => <code className="rounded bg-muted px-1 py-0.5 font-mono text-[0.85em]">{children}</code>,
  pre: ({ children }) => <pre className="my-2 overflow-x-auto rounded bg-muted p-2 text-xs [&>code]:bg-transparent [&>code]:p-0">{children}</pre>,
  blockquote: ({ children }) => <blockquote className="my-2 border-l-2 border-border pl-3 text-muted-foreground">{children}</blockquote>,
  h1: ({ children }) => <p className="mt-3 mb-1 font-semibold">{children}</p>,
  h2: ({ children }) => <p className="mt-3 mb-1 font-semibold">{children}</p>,
  h3: ({ children }) => <p className="mt-3 mb-1 font-semibold">{children}</p>,
  h4: ({ children }) => <p className="mt-3 mb-1 font-semibold">{children}</p>,
  h5: ({ children }) => <p className="mt-3 mb-1 font-semibold">{children}</p>,
  h6: ({ children }) => <p className="mt-3 mb-1 font-semibold">{children}</p>,
  table: ({ children }) => <div className="my-2 overflow-x-auto"><table className="w-full text-xs">{children}</table></div>,
  th: ({ children }) => <th className="border-b border-border px-2 py-1 text-left font-medium">{children}</th>,
  td: ({ children }) => <td className="border-b border-border/50 px-2 py-1">{children}</td>,
}

export function ChatMarkdown({ content }: { content: string }) {
  return (
    <div className="text-sm leading-relaxed break-words">
      <Markdown
        remarkPlugins={[remarkGfm]}
        skipHtml
        allowedElements={ALLOWED_ELEMENTS}
        unwrapDisallowed
        urlTransform={chatUrlTransform}
        components={components}
      >
        {content}
      </Markdown>
    </div>
  )
}
