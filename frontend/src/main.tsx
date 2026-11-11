import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { LucideProvider } from "lucide-react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import "./index.css"
import App from "./App"

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, staleTime: 30_000 },
  },
})

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      {/* Lucide at stroke 1.75 is an identity token (planning#337); icon SIZES are set per call site. */}
      <LucideProvider strokeWidth={1.75}>
        <App />
      </LucideProvider>
    </QueryClientProvider>
  </StrictMode>
)
