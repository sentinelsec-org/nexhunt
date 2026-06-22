import { create } from 'zustand'

const MAX_OUTPUT_LINES = 2000

export interface ApiParameterContract {
  name: string
  in: 'path' | 'query' | 'header' | 'cookie'
  required: boolean
  description: string
  value: unknown
  enabled: boolean
  schema: Record<string, unknown>
}

export interface ApiEndpointRow {
  method: string
  path: string
  url: string
  base_url: string
  operation_id: string
  summary: string
  tags: string[]
  parameters: ApiParameterContract[]
  body: unknown
  body_content_type: string
  body_required: boolean
  body_schema: Record<string, unknown>
  request_headers: Record<string, string>
  mutating: boolean
  status_anon: number | null
  status_auth: number | null
  content_length: number
  content_type: string
  auth_required: boolean
  probe_state: 'not_run' | 'skipped_write' | 'request_error' | 'input_rejected' | 'protected' | 'reachable' | 'not_found' | 'completed'
  note: string
}

interface ApiScannerState {
  rows: ApiEndpointRow[]
  output: string[]
  running: boolean
  jobId: string | null
  addRow: (row: ApiEndpointRow) => void
  setRows: (rows: ApiEndpointRow[]) => void
  appendOutput: (line: string) => void
  setRunning: (running: boolean, jobId?: string | null) => void
  clear: () => void
}

export const useApiScannerStore = create<ApiScannerState>((set) => ({
  rows: [],
  output: [],
  running: false,
  jobId: null,
  addRow: (row) => set((state) => ({ rows: [...state.rows, row] })),
  setRows: (rows) => set({ rows }),
  appendOutput: (line) => set((state) => ({
    output: [...state.output, line].slice(-MAX_OUTPUT_LINES),
  })),
  setRunning: (running, jobId) => set((state) => ({
    running,
    jobId: jobId !== undefined ? jobId : state.jobId,
  })),
  clear: () => set({ rows: [], output: [] }),
}))
