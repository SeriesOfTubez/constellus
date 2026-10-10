/**
 * The chat assistant panel (planning#228 slice 2; decisions on #228,
 * 2026-10-10): a non-modal panel docked on the right of the shell, opened
 * from the sidebar or Ctrl+/ on any page. The page narrows beside it rather
 * than sliding under it, so a question can be about what is on screen.
 *
 * Asking is synchronous (the backend answers once the answer is stored), so
 * the question shows at once with a spinner and elapsed seconds; there is no
 * streaming. Every number the panel shows next to a query comes from the
 * answer's `tool_trace`, never from its prose.
 */
import { useEffect, useRef, useState } from "react"
import { Link } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { AlertTriangle, History, Info, Loader2, Plus, SquareArrowOutUpRight, Sparkles, Trash2, X } from "lucide-react"
import { Button } from "@/components/ui/button"
import { ChatMarkdown } from "@/components/chat/ChatMarkdown"
import {
  ASSISTANT_NAME, MAX_QUESTION_CHARS, askErrorReason, chatApi, countedQueries, exploreHref, formatCount,
  stopNotice, summariseQuery, type ChatMessage, type Conversation,
} from "@/lib/chat"
import { useChatPanel } from "@/lib/chatPanel"
import { relativeTime } from "@/lib/time"
import { cn } from "@/lib/utils"

const EXAMPLES = [
  "How many hostnames have port 22 open?",
  "Which critical findings are on internet-facing assets?",
]

function UserBubble({ text, muted }: { text: string; muted?: boolean }) {
  return (
    <div className="flex justify-end">
      <div className={cn("max-w-[85%] whitespace-pre-wrap break-words rounded-lg bg-muted px-3 py-2 text-sm", muted && "opacity-70")}>
        {text}
      </div>
    </div>
  )
}

function Notice({ icon: Icon, children }: { icon: React.ElementType; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-1.5 text-xs text-muted-foreground">
      <Icon className="mt-0.5 h-3.5 w-3.5 shrink-0" />
      <span>{children}</span>
    </div>
  )
}

function AssistantMessage({ m }: { m: ChatMessage }) {
  const counted = countedQueries(m.tool_trace)
  const notice = stopNotice(m.stop_reason)
  const unverified = m.unverified_numbers ?? []
  return (
    <div className="space-y-2" data-testid="chat-answer">
      <ChatMarkdown content={m.content} />
      {counted.length > 0 && (
        <div className="space-y-1.5">
          {counted.map((c, i) => (
            <div key={i} className="flex items-center gap-2 rounded-md border bg-muted/30 px-2.5 py-1.5 text-xs" data-testid="chat-query">
              <span className="truncate font-mono text-muted-foreground" title={JSON.stringify(c.query, null, 2)}>
                {summariseQuery(c.query)}
              </span>
              <span
                className="ml-auto shrink-0 rounded bg-muted px-1.5 py-0.5 font-mono text-foreground"
                title={c.count_capped ? "More than this many match; the exact count is capped" : "Exact number of matching records"}
                data-testid="chat-count"
              >
                {formatCount(c.count, c.count_capped)}
              </span>
              {c.times > 1 && (
                <span className="shrink-0 font-mono text-muted-foreground" title={`This query ran ${c.times} times`}>×{c.times}</span>
              )}
              <Link
                to={exploreHref(c.query)}
                className="shrink-0 text-primary hover:opacity-80"
                aria-label="Open in Explore"
                title="Open in Explore"
              >
                <SquareArrowOutUpRight className="h-3.5 w-3.5" />
              </Link>
            </div>
          ))}
        </div>
      )}
      {notice && (
        <div className="rounded-md border bg-muted/40 px-2.5 py-2 text-xs" data-testid="chat-stop-notice">{notice}</div>
      )}
      {unverified.length > 0 && (
        <div className="border-t pt-2" data-testid="chat-unverified">
          <Notice icon={AlertTriangle}>
            Not traced to a query result:{" "}
            <span className="font-mono text-foreground">{unverified.join(", ")}</span>.{" "}
            {counted.length > 0 ? "Check against the counts above." : "Check before relying on it."}
          </Notice>
        </div>
      )}
    </div>
  )
}

function Elapsed({ since }: { since: number }) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(t)
  }, [])
  return <span className="font-mono">{Math.max(0, Math.floor((now - since) / 1000))}s</span>
}

function ConversationList() {
  const qc = useQueryClient()
  const { conversationId, openConversation, forgetConversation } = useChatPanel()
  const [confirming, setConfirming] = useState<string | null>(null)
  const list = useQuery({ queryKey: ["chat", "conversations"], queryFn: chatApi.list })
  const remove = useMutation({
    mutationFn: (id: string) => chatApi.remove(id),
    onSuccess: (_d, id) => {
      setConfirming(null)
      qc.removeQueries({ queryKey: ["chat", "conversation", id] })
      qc.invalidateQueries({ queryKey: ["chat", "conversations"] })
      if (id === conversationId) forgetConversation()
    },
  })

  if (list.isLoading) return <p className="p-4 text-sm text-muted-foreground">Loading…</p>
  if (list.isError) return <p className="p-4 text-sm text-muted-foreground">Could not load conversations.</p>
  if (!list.data?.length) return <p className="p-4 text-sm text-muted-foreground">No conversations yet.</p>
  return (
    <ul className="divide-y" data-testid="chat-conversation-list">
      {list.data.map(c => (
        <li key={c.id} className={cn("flex items-center gap-2 px-4 py-2.5", c.id === conversationId && "bg-muted/50")}>
          <button className="min-w-0 flex-1 text-left" onClick={() => openConversation(c.id)}>
            <p className="truncate text-sm">{c.title}</p>
            <p className="text-xs text-muted-foreground">{relativeTime(c.updated_at)}</p>
          </button>
          {confirming === c.id ? (
            <div className="flex shrink-0 items-center gap-1">
              <Button size="sm" variant="destructive" className="h-7 px-2 text-xs" disabled={remove.isPending}
                onClick={() => remove.mutate(c.id)}>Delete</Button>
              <Button size="sm" variant="ghost" className="h-7 px-2 text-xs" onClick={() => setConfirming(null)}>Cancel</Button>
            </div>
          ) : (
            <button className="shrink-0 text-muted-foreground hover:text-destructive" aria-label="Delete conversation"
              title="Delete conversation" onClick={() => setConfirming(c.id)}>
              <Trash2 className="h-4 w-4" />
            </button>
          )}
        </li>
      ))}
    </ul>
  )
}

function ConversationView() {
  const qc = useQueryClient()
  const { conversationId, openConversation } = useChatPanel()
  const [draft, setDraft] = useState("")
  const [pending, setPending] = useState<{ question: string; since: number } | null>(null)
  const [failed, setFailed] = useState<{ question: string; reason: string } | null>(null)
  const bottom = useRef<HTMLDivElement>(null)

  const conv = useQuery({
    queryKey: ["chat", "conversation", conversationId],
    queryFn: () => chatApi.get(conversationId as string),
    enabled: conversationId !== null,
  })

  // A different conversation (or a new one) starts with a clean slate.
  useEffect(() => { setFailed(null); setPending(null) }, [conversationId])

  const ask = useMutation({
    mutationFn: (question: string) => conversationId ? chatApi.ask(conversationId, question) : chatApi.start(question),
    onMutate: question => { setFailed(null); setPending({ question, since: Date.now() }) },
    onSuccess: async res => {
      // Load the stored conversation BEFORE dropping the optimistic bubble,
      // so the question never blinks out and back in.
      await qc.fetchQuery({
        queryKey: ["chat", "conversation", res.conversation_id],
        queryFn: () => chatApi.get(res.conversation_id),
        staleTime: 0,
      })
      qc.invalidateQueries({ queryKey: ["chat", "conversations"] })
      if (res.conversation_id !== conversationId) openConversation(res.conversation_id)
      setPending(null)
    },
    onError: (err, question) => {
      setPending(null)
      setFailed({ question, reason: askErrorReason(err) })
    },
  })

  const messages: ChatMessage[] = conversationId ? (conv.data as Conversation | undefined)?.messages ?? [] : []

  useEffect(() => {
    bottom.current?.scrollIntoView({ block: "end" })
  }, [messages.length, pending, failed])

  function send(question: string) {
    const q = question.trim()
    if (!q || ask.isPending) return
    setDraft("")
    ask.mutate(q)
  }

  const empty = messages.length === 0 && !pending && !failed

  return (
    <>
      <div className="flex-1 space-y-4 overflow-y-auto p-4" data-testid="chat-messages">
        {conversationId && conv.isLoading && <p className="text-sm text-muted-foreground">Loading…</p>}
        {conversationId && conv.isError && <p className="text-sm text-muted-foreground">This conversation could not be loaded.</p>}
        {empty && !conv.isLoading && (
          <div className="space-y-3 text-sm text-muted-foreground">
            <p>Ask about your attack surface: assets, open ports, findings and organisation entities.
              Answers come from read-only queries, shown with their exact counts.</p>
            <div className="space-y-1.5">
              {EXAMPLES.map(e => (
                <button key={e} className="block w-full rounded-md border px-3 py-2 text-left text-xs hover:bg-muted"
                  onClick={() => setDraft(e)}>{e}</button>
              ))}
            </div>
          </div>
        )}
        {messages.map(m => m.role === "user"
          ? <UserBubble key={m.id} text={m.content} />
          : <AssistantMessage key={m.id} m={m} />)}
        {pending && (
          <>
            <UserBubble text={pending.question} />
            <div className="flex items-center gap-2 text-xs text-muted-foreground" data-testid="chat-pending">
              <Loader2 className="h-3.5 w-3.5 animate-spin" /> Working… <Elapsed since={pending.since} />
            </div>
          </>
        )}
        {failed && (
          <>
            <UserBubble text={failed.question} muted />
            <div className="flex items-start gap-2 text-xs text-muted-foreground" data-testid="chat-failed">
              <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span className="flex-1">Not answered. {failed.reason}</span>
              <button className="shrink-0 text-primary hover:opacity-80" onClick={() => ask.mutate(failed.question)}>Retry</button>
            </div>
          </>
        )}
        <div ref={bottom} />
      </div>
      <form
        className="border-t p-3"
        onSubmit={e => { e.preventDefault(); send(draft) }}
      >
        <textarea
          value={draft}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => {
            if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) { e.preventDefault(); send(draft) }
          }}
          maxLength={MAX_QUESTION_CHARS}
          rows={2}
          disabled={ask.isPending}
          placeholder="Ask about your attack surface…"
          aria-label="Question"
          className="w-full resize-none rounded-md border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-60"
        />
        <div className="mt-1 flex items-center gap-2 text-[11px] text-muted-foreground">
          <span>Read-only · Enter to send, Shift+Enter for a new line</span>
          <span className="ml-auto font-mono">{draft.length} / {MAX_QUESTION_CHARS}</span>
        </div>
      </form>
    </>
  )
}

export function ChatPanel() {
  const { open, close, view, showList, newConversation, conversationId } = useChatPanel()
  const conv = useQuery({
    queryKey: ["chat", "conversation", conversationId],
    queryFn: () => chatApi.get(conversationId as string),
    enabled: open && conversationId !== null,
  })
  // Hidden, not unmounted, while closed: a question still being answered
  // keeps its pending bubble when the panel is closed and reopened.
  const title = view === "list" ? "Conversations" : conversationId ? conv.data?.title : "New conversation"
  return (
    <aside
      aria-label={`${ASSISTANT_NAME} chat`}
      data-testid="chat-panel"
      hidden={!open}
      className="flex h-screen w-[440px] max-w-[50vw] shrink-0 flex-col border-l bg-background [&[hidden]]:hidden"
      onKeyDown={e => { if (e.key === "Escape") close() }}
    >
      <div className="flex items-center gap-2 border-b px-4 py-3">
        <Sparkles className="h-4 w-4 shrink-0 text-primary" />
        <span className="shrink-0 text-sm font-semibold">{ASSISTANT_NAME}</span>
        {title && <span className="min-w-0 truncate text-xs text-muted-foreground">· {title}</span>}
        <div className="ml-auto flex shrink-0 items-center gap-1">
          <Button variant="ghost" size="icon" className={cn("h-8 w-8", view === "list" && "bg-muted")}
            aria-label="Conversations" title="Conversations" onClick={showList}>
            <History className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" className="h-8 w-8" aria-label="New conversation" title="New conversation"
            onClick={newConversation}>
            <Plus className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" className="h-8 w-8" aria-label="Close" title="Close (Esc)" onClick={close}>
            <X className="h-4 w-4" />
          </Button>
        </div>
      </div>
      {view === "list" && <div className="flex-1 overflow-y-auto"><ConversationList /></div>}
      <div className={cn("flex min-h-0 flex-1 flex-col", view === "list" && "hidden")}><ConversationView /></div>
    </aside>
  )
}
