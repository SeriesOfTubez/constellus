import { create } from "zustand"

/** Open/closed state of the chat panel, shared by the sidebar trigger, the
 *  keyboard shortcut and the panel. In memory only: a reload closes it. */
interface ChatPanelState {
  open: boolean
  /** null = a new, not yet asked conversation */
  conversationId: string | null
  view: "conversation" | "list"
  toggle: () => void
  close: () => void
  showList: () => void
  openConversation: (id: string) => void
  newConversation: () => void
  /** Forget the open conversation (it was deleted) without leaving the list. */
  forgetConversation: () => void
}

export const useChatPanel = create<ChatPanelState>(set => ({
  open: false,
  conversationId: null,
  view: "conversation",
  toggle: () => set(s => ({ open: !s.open })),
  close: () => set({ open: false }),
  showList: () => set(s => ({ view: s.view === "list" ? "conversation" : "list" })),
  openConversation: id => set({ conversationId: id, view: "conversation" }),
  newConversation: () => set({ conversationId: null, view: "conversation" }),
  forgetConversation: () => set({ conversationId: null }),
}))
