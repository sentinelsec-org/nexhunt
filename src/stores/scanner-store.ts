import { create } from 'zustand'
import type { Finding, ScanJob } from '@/types'

const MAX_OUTPUT_LINES = 2000

interface ScannerState {
  findings: Finding[]
  scanJobs: ScanJob[]
  rawOutput: Record<string, string[]>   // tool -> lines
  activeScans: Set<string>              // tools currently running
  activeScanCounts: Record<string, number>  // supports concurrent bulk jobs per tool
  activeJobIds: Record<string, string>  // tool -> job_id (for cancellation)
  addFinding: (finding: Finding) => void
  setFindings: (findings: Finding[]) => void
  updateScanJob: (job: ScanJob) => void
  setScanJobs: (jobs: ScanJob[]) => void
  appendToolOutput: (tool: string, line: string) => void
  clearToolOutput: (tool: string) => void
  setScanRunning: (tool: string, running: boolean) => void
  setJobId: (tool: string, jobId: string | null) => void
  clearFindings: () => void
  removeFindingsByTool: (tool: string) => void
}

export const useScannerStore = create<ScannerState>((set) => ({
  findings: [],
  scanJobs: [],
  rawOutput: {},
  activeScans: new Set<string>(),
  activeScanCounts: {},
  activeJobIds: {},
  addFinding: (finding) => set((state) => ({
    findings: [finding, ...state.findings]
  })),
  setFindings: (findings) => set({ findings }),
  updateScanJob: (job) => set((state) => ({
    scanJobs: state.scanJobs.some(j => j.id === job.id)
      ? state.scanJobs.map(j => j.id === job.id ? job : j)
      : [...state.scanJobs, job]
  })),
  setScanJobs: (jobs) => set({ scanJobs: jobs }),
  appendToolOutput: (tool, line) => set((state) => {
    const prev = state.rawOutput[tool] ?? []
    const next = [...prev, line]
    return { rawOutput: { ...state.rawOutput, [tool]: next.slice(-MAX_OUTPUT_LINES) } }
  }),
  clearToolOutput: (tool) => set((state) => ({
    rawOutput: { ...state.rawOutput, [tool]: [] },
  })),
  setScanRunning: (tool, running) => set((state) => {
    const counts = { ...state.activeScanCounts }
    counts[tool] = Math.max(0, (counts[tool] ?? 0) + (running ? 1 : -1))
    const next = new Set(state.activeScans)
    if (counts[tool] > 0) next.add(tool)
    else { next.delete(tool); delete counts[tool] }
    return { activeScans: next, activeScanCounts: counts }
  }),
  setJobId: (tool, jobId) => set((state) => {
    const next = { ...state.activeJobIds }
    if (jobId === null) delete next[tool]
    else next[tool] = jobId
    return { activeJobIds: next }
  }),
  clearFindings: () => set({ findings: [], scanJobs: [], rawOutput: {}, activeScans: new Set(), activeScanCounts: {}, activeJobIds: {} }),
  removeFindingsByTool: (tool) => set((state) => ({
    findings: state.findings.filter(f => f.tool !== tool)
  }))
}))
