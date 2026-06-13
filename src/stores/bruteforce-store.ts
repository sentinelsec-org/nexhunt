import { create } from 'zustand'
import { api } from '@/api/http-client'

export interface BruteForceConfig {
  target: string
  service: string
  port: number | null
  login: string
  login_list: string
  password: string
  password_list: string
  combo_list: string
  threads: number
  stop_on_first: boolean
  form_path: string
  form_body: string
  fail_string: string
  success_string: string
  extra_args: string
}

export interface FoundCred {
  host: string
  login: string
  password: string
  port: number
  service: string
}

export interface BruteJob {
  job_id: string
  target: string
  service: string
  started_at: number
  status: string
  found: number
}

export interface Wordlist {
  name: string
  path: string
  size: number
  lines: number | null
  category: string
  custom: boolean
}

export const emptyConfig = (): BruteForceConfig => ({
  target: '',
  service: 'http-post-form',
  port: null,
  login: '',
  login_list: '',
  password: '',
  password_list: '',
  combo_list: '',
  threads: 16,
  stop_on_first: true,
  form_path: '',
  form_body: '',
  fail_string: '',
  success_string: '',
  extra_args: '',
})

interface BruteForceState {
  config: BruteForceConfig
  jobs: BruteJob[]
  wordlists: Wordlist[]
  prefill: BruteForceConfig | null

  setConfig: (patch: Partial<BruteForceConfig>) => void
  resetConfig: () => void
  setPrefill: (cfg: BruteForceConfig) => void
  consumePrefill: () => void
  startAttack: () => Promise<string>
  fetchJobs: () => Promise<void>
  killJob: (id: string) => Promise<void>
  fetchWordlists: () => Promise<void>
}

export const useBruteForceStore = create<BruteForceState>((set, get) => ({
  config: emptyConfig(),
  jobs: [],
  wordlists: [],
  prefill: null,

  setConfig: (patch) => set((s) => ({ config: { ...s.config, ...patch } })),
  resetConfig: () => set({ config: emptyConfig() }),
  setPrefill: (cfg) => set({ prefill: cfg }),
  consumePrefill: () => {
    const p = get().prefill
    if (p) set({ config: p, prefill: null })
  },

  startAttack: async () => {
    const res = await api.post<{ job_id: string }>('/api/bruteforce/start', get().config)
    await get().fetchJobs()
    return res.job_id
  },
  fetchJobs: async () => {
    const res = await api.get<{ jobs: BruteJob[] }>('/api/bruteforce/jobs')
    set({ jobs: res.jobs })
  },
  killJob: async (id) => {
    await api.delete(`/api/bruteforce/jobs/${id}`)
    await get().fetchJobs()
  },
  fetchWordlists: async () => {
    const res = await api.get<{ wordlists: Wordlist[] }>('/api/wordlists')
    set({ wordlists: res.wordlists })
  },
}))
