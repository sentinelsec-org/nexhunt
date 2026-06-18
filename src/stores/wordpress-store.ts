import { create } from 'zustand'

export interface WpPlugin { name: string; raw?: string }
export interface WpVuln { title: string; severity: string }

interface WordPressState {
  version: { value: string; status: string } | null
  theme: string | null
  plugins: string[]
  themes: string[]
  users: string[]
  vulns: WpVuln[]
  interesting: string[]
  configBackups: string[]
  log: string[]
  running: boolean
  jobId: string | null
  apiTokenSet: boolean
  installed: boolean

  setStatus: (s: { installed: boolean; apiTokenSet: boolean }) => void
  setRunning: (running: boolean, jobId?: string | null) => void
  appendLog: (line: string) => void
  handleResult: (r: any) => void
  clear: () => void
}

export const useWordPressStore = create<WordPressState>((set) => ({
  version: null,
  theme: null,
  plugins: [],
  themes: [],
  users: [],
  vulns: [],
  interesting: [],
  configBackups: [],
  log: [],
  running: false,
  jobId: null,
  apiTokenSet: false,
  installed: false,

  setStatus: (s) => set({ installed: s.installed, apiTokenSet: s.apiTokenSet }),
  setRunning: (running, jobId) => set((st) => ({ running, jobId: jobId !== undefined ? jobId : st.jobId })),
  appendLog: (line) => set((st) => ({ log: [...st.log, line] })),

  handleResult: (r) => set((st) => {
    switch (r.kind) {
      case 'version':
        return { version: { value: r.value, status: r.status } }
      case 'theme':
        // First theme line ("theme in use") becomes the active theme;
        // any others go into the themes list.
        if (!st.theme) return { theme: r.name }
        return st.themes.includes(r.name) ? {} : { themes: [...st.themes, r.name] }
      case 'plugin':
        return st.plugins.includes(r.name) ? {} : { plugins: [...st.plugins, r.name] }
      case 'user':
        return st.users.includes(r.name) ? {} : { users: [...st.users, r.name] }
      case 'vuln':
        return { vulns: [...st.vulns, { title: r.title, severity: r.severity }] }
      case 'interesting':
        return st.interesting.includes(r.text) ? {} : { interesting: [...st.interesting, r.text] }
      case 'config_backup':
        return st.configBackups.includes(r.url) ? {} : { configBackups: [...st.configBackups, r.url] }
      default:
        return {}
    }
  }),

  clear: () => set({
    version: null, theme: null, plugins: [], themes: [], users: [], vulns: [],
    interesting: [], configBackups: [], log: [],
  }),
}))
