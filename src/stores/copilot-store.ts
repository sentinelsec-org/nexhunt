import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export interface CopilotMessage {
  role: 'user' | 'assistant' | 'terminal'
  content: string
  timestamp: string  // ISO — survives JSON serialization
  command?: string
  error?: boolean    // marks error responses, shows retry button
}

interface CopilotState {
  messages: CopilotMessage[]
  addMessage: (msg: Omit<CopilotMessage, 'timestamp'> & { timestamp?: string }) => void
  updateLastAssistant: (content: string) => void
  clearMessages: () => void
}

export const useCopilotStore = create<CopilotState>()(
  persist(
    (set, get) => ({
      messages: [],

      addMessage: (msg) => set(s => ({
        messages: [
          ...s.messages.slice(-199),  // cap at 200
          { ...msg, timestamp: msg.timestamp ?? new Date().toISOString() },
        ],
      })),

      updateLastAssistant: (content) => set(s => {
        const msgs = [...s.messages]
        for (let i = msgs.length - 1; i >= 0; i--) {
          if (msgs[i].role === 'assistant') {
            msgs[i] = { ...msgs[i], content }
            return { messages: msgs }
          }
        }
        return {}
      }),

      clearMessages: () => set({ messages: [] }),
    }),
    { name: 'nexhunt-copilot-chat', version: 1 }
  )
)
