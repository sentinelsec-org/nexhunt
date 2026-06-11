import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { Project } from '@/types'

interface AppState {
  backendConnected: boolean
  wsConnected: boolean
  activeProject: string | null
  activeProjectData: Project | null
  sidebarCollapsed: boolean
  globalTarget: string
  sessionCookies: string
  sessionHeaders: string
  pendingCommand: string | null
  setPendingCommand: (cmd: string | null) => void
  setBackendConnected: (connected: boolean) => void
  setWsConnected: (connected: boolean) => void
  setActiveProject: (projectId: string | null) => void
  setActiveProjectData: (project: Project | null) => void
  toggleSidebar: () => void
  getActiveScope: () => string[]
  setGlobalTarget: (target: string) => void
  setSessionCookies: (v: string) => void
  setSessionHeaders: (v: string) => void
  getSessionOpts: () => { session_cookies: string; session_headers: string }
}

export const useAppStore = create<AppState>()(
  persist(
    (set, get) => ({
      backendConnected: false,
      wsConnected: false,
      activeProject: null,
      activeProjectData: null,
      sidebarCollapsed: false,
      globalTarget: '',
      sessionCookies: '',
      sessionHeaders: '',
      pendingCommand: null,
      setPendingCommand: (cmd) => set({ pendingCommand: cmd }),
      setBackendConnected: (connected) => set({ backendConnected: connected }),
      setWsConnected: (connected) => set({ wsConnected: connected }),
      setActiveProject: (projectId) => set({ activeProject: projectId }),
      setActiveProjectData: (project) => set({ activeProjectData: project }),
      toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
      getActiveScope: () => get().activeProjectData?.scope ?? [],
      setGlobalTarget: (target) => set({ globalTarget: target }),
      setSessionCookies: (v) => set({ sessionCookies: v }),
      setSessionHeaders: (v) => set({ sessionHeaders: v }),
      getSessionOpts: () => ({
        session_cookies: get().sessionCookies,
        session_headers: get().sessionHeaders,
      }),
    }),
    {
      name: 'nexhunt.app',
      partialize: (s) => ({
        activeProject: s.activeProject,
        sidebarCollapsed: s.sidebarCollapsed,
        globalTarget: s.globalTarget,
        sessionCookies: s.sessionCookies,
        sessionHeaders: s.sessionHeaders,
      }),
    }
  )
)
