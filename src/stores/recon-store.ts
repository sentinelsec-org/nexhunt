import { create } from 'zustand'
import type { SubdomainResult, UrlResult, PortResult, EndpointResult, ScanJob } from '@/types'

export interface LiveHostResult {
  url: string
  host: string
  status_code: number | null
  title: string
  technologies: string[]
  content_type: string
  ip: string
}

export interface ScreenshotResult {
  url: string
  filename: string
  screenshot_url: string  // e.g. /screenshots/filename.jpeg
  path?: string
}

interface ReconState {
  subdomains: SubdomainResult[]
  urls: UrlResult[]
  ports: PortResult[]
  liveHosts: LiveHostResult[]
  screenshots: ScreenshotResult[]
  endpoints: EndpointResult[]
  cveResult: { results: any[] } | { error: string } | null
  cveRunning: boolean
  screenshotRunning: boolean
  screenshotProgress: { done: number; total: number }
  activeJobs: ScanJob[]
  activeReconTools: Set<string>
  activeReconJobIds: Record<string, string>
  addSubdomains: (results: SubdomainResult[]) => void
  addUrls: (results: UrlResult[]) => void
  addPorts: (results: PortResult[]) => void
  addLiveHosts: (results: LiveHostResult[]) => void
  addScreenshots: (results: ScreenshotResult[]) => void
  addEndpoints: (results: EndpointResult[]) => void
  setCveResult: (result: ReconState['cveResult']) => void
  setCveRunning: (running: boolean) => void
  setScreenshotRunning: (running: boolean, progress?: { done: number; total: number }) => void
  updateJob: (job: ScanJob) => void
  setReconToolRunning: (tool: string, running: boolean) => void
  setReconJobId: (tool: string, jobId: string | null) => void
  clearRecon: () => void
}

export const useReconStore = create<ReconState>((set) => ({
  subdomains: [],
  urls: [],
  ports: [],
  liveHosts: [],
  screenshots: [],
  endpoints: [],
  cveResult: null,
  cveRunning: false,
  screenshotRunning: false,
  screenshotProgress: { done: 0, total: 0 },
  activeJobs: [],
  activeReconTools: new Set<string>(),
  activeReconJobIds: {},
  addSubdomains: (results) => set((state) => ({
    subdomains: [
      ...state.subdomains,
      ...results.filter(r => !state.subdomains.some(s => s.subdomain === r.subdomain))
    ]
  })),
  addUrls: (results) => set((state) => ({ urls: [...state.urls, ...results] })),
  addPorts: (results) => set((state) => ({ ports: [...state.ports, ...results] })),
  addLiveHosts: (results) => set((state) => ({
    liveHosts: [
      ...state.liveHosts,
      ...results.filter(r => !state.liveHosts.some(h => h.url === r.url))
    ]
  })),
  addScreenshots: (results) => set((state) => ({
    screenshots: [
      ...state.screenshots,
      ...results.filter(r => !state.screenshots.some(s => s.url === r.url))
    ]
  })),
  addEndpoints: (results) => set((state) => ({
    endpoints: [
      ...state.endpoints,
      ...results.filter(r => !state.endpoints.some(e => e.url === r.url))
    ]
  })),
  setCveResult: (result) => set({ cveResult: result }),
  setCveRunning: (running) => set({ cveRunning: running }),
  setScreenshotRunning: (running, progress) => set((state) => ({
    screenshotRunning: running,
    screenshotProgress: progress ?? state.screenshotProgress,
  })),
  updateJob: (job) => set((state) => ({
    activeJobs: state.activeJobs.some(j => j.id === job.id)
      ? state.activeJobs.map(j => j.id === job.id ? job : j)
      : [...state.activeJobs, job]
  })),
  setReconToolRunning: (tool, running) => set((state) => {
    const next = new Set(state.activeReconTools)
    running ? next.add(tool) : next.delete(tool)
    return { activeReconTools: next }
  }),
  setReconJobId: (tool, jobId) => set((state) => {
    const next = { ...state.activeReconJobIds }
    if (jobId === null) delete next[tool]
    else next[tool] = jobId
    return { activeReconJobIds: next }
  }),
  clearRecon: () => set({ subdomains: [], urls: [], ports: [], liveHosts: [], screenshots: [], endpoints: [], cveResult: null, cveRunning: false, activeJobs: [], activeReconTools: new Set(), activeReconJobIds: {} })
}))
