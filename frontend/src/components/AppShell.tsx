import { useEffect } from "react"
import { Outlet } from "react-router-dom"
import { Sidebar } from "@/components/Sidebar"
import { ChatPanel } from "@/components/chat/ChatPanel"
import { useChatPanel } from "@/lib/chatPanel"

export function AppShell() {
  const toggleChat = useChatPanel(s => s.toggle)
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === "/") { e.preventDefault(); toggleChat() }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [toggleChat])

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto bg-background">
        <Outlet />
      </main>
      <ChatPanel />
    </div>
  )
}
