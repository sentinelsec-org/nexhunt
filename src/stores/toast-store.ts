import { create } from 'zustand'

export type ToastKind = 'success' | 'error' | 'warning' | 'info'

export interface Toast {
  id: string
  kind: ToastKind
  title: string
  message?: string
}

interface ToastState {
  toasts: Toast[]
  push: (t: Omit<Toast, 'id'>) => void
  dismiss: (id: string) => void
}

export const useToastStore = create<ToastState>((set) => ({
  toasts: [],
  push: (t) => {
    const id = crypto.randomUUID()
    set((s) => ({ toasts: [...s.toasts, { ...t, id }] }))
    setTimeout(() => {
      set((s) => ({ toasts: s.toasts.filter((x) => x.id !== id) }))
    }, t.kind === 'error' ? 8000 : 4000)
  },
  dismiss: (id) => set((s) => ({ toasts: s.toasts.filter((x) => x.id !== id) })),
}))

function extract(e: unknown): string {
  if (!e) return ''
  if (typeof e === 'string') return e
  if (e instanceof Error) return e.message
  return String(e)
}

export const toast = {
  success: (title: string, message?: string) => useToastStore.getState().push({ kind: 'success', title, message }),
  error: (title: string, e?: unknown) => useToastStore.getState().push({ kind: 'error', title, message: extract(e) || undefined }),
  warning: (title: string, message?: string) => useToastStore.getState().push({ kind: 'warning', title, message }),
  info: (title: string, message?: string) => useToastStore.getState().push({ kind: 'info', title, message }),
}
