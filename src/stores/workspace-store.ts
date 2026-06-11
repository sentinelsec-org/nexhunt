import { create } from 'zustand'
import type { Finding, HttpFlow } from '@/types'

// ─── Types ────────────────────────────────────────────────────────────────────

export type WorkspaceItemType = 'finding' | 'http_flow' | 'note'

export interface WorkspaceItem {
  id: string                       // unique within workspace
  type: WorkspaceItemType
  title: string                    // display name
  addedAt: string                  // ISO timestamp
  notes: string                    // user markdown notes
  aiAnalysis: string | null        // cached AI response
  aiAnalyzing: boolean
  // Only one of these will be set depending on type
  finding?: Finding
  httpFlow?: HttpFlow
}

interface WorkspaceState {
  items: WorkspaceItem[]
  selectedItemId: string | null

  addFinding: (finding: Finding) => void
  addHttpFlow: (flow: HttpFlow) => void
  addNote: (title?: string) => void
  removeItem: (id: string) => void
  selectItem: (id: string | null) => void
  updateNotes: (id: string, notes: string) => void
  updateTitle: (id: string, title: string) => void
  setAiAnalysis: (id: string, analysis: string | null) => void
  setAiAnalyzing: (id: string, analyzing: boolean) => void
  clearAll: () => void
}

// ─── Store ────────────────────────────────────────────────────────────────────

export const useWorkspaceStore = create<WorkspaceState>((set, get) => ({
  items: [],
  selectedItemId: null,

  addFinding: (finding) => {
    // Avoid duplicates
    if (get().items.some(i => i.type === 'finding' && i.finding?.id === finding.id)) {
      set({ selectedItemId: get().items.find(i => i.finding?.id === finding.id)?.id ?? null })
      return
    }
    const item: WorkspaceItem = {
      id: `finding-${finding.id}`,
      type: 'finding',
      title: finding.title,
      addedAt: new Date().toISOString(),
      notes: '',
      aiAnalysis: null,
      aiAnalyzing: false,
      finding,
    }
    set(s => ({ items: [...s.items, item], selectedItemId: item.id }))
  },

  addHttpFlow: (flow) => {
    // Avoid duplicates
    if (get().items.some(i => i.type === 'http_flow' && i.httpFlow?.id === flow.id)) {
      set({ selectedItemId: get().items.find(i => i.httpFlow?.id === flow.id)?.id ?? null })
      return
    }
    const item: WorkspaceItem = {
      id: `flow-${flow.id}`,
      type: 'http_flow',
      title: `${flow.request_method} ${flow.request_host}${flow.request_path}`,
      addedAt: new Date().toISOString(),
      notes: '',
      aiAnalysis: null,
      aiAnalyzing: false,
      httpFlow: flow,
    }
    set(s => ({ items: [...s.items, item], selectedItemId: item.id }))
  },

  addNote: (title = 'New Note') => {
    const id = `note-${Date.now()}`
    const item: WorkspaceItem = {
      id,
      type: 'note',
      title,
      addedAt: new Date().toISOString(),
      notes: '',
      aiAnalysis: null,
      aiAnalyzing: false,
    }
    set(s => ({ items: [...s.items, item], selectedItemId: id }))
  },

  updateTitle: (id, title) => set(s => ({
    items: s.items.map(i => i.id === id ? { ...i, title } : i)
  })),

  removeItem: (id) => set(s => {
    const remaining = s.items.filter(i => i.id !== id)
    const selectedId = s.selectedItemId === id
      ? (remaining[0]?.id ?? null)
      : s.selectedItemId
    return { items: remaining, selectedItemId: selectedId }
  }),

  selectItem: (id) => set({ selectedItemId: id }),

  updateNotes: (id, notes) => set(s => ({
    items: s.items.map(i => i.id === id ? { ...i, notes } : i)
  })),

  setAiAnalysis: (id, analysis) => set(s => ({
    items: s.items.map(i => i.id === id ? { ...i, aiAnalysis: analysis } : i)
  })),

  setAiAnalyzing: (id, analyzing) => set(s => ({
    items: s.items.map(i => i.id === id ? { ...i, aiAnalyzing: analyzing } : i)
  })),

  clearAll: () => set({ items: [], selectedItemId: null }),
}))
