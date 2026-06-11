export interface NexHuntAPI {
  getBackendUrl: () => Promise<string>
  getWsUrl: () => Promise<string>
  platform: string
  versions: {
    node: string
    chrome: string
    electron: string
  }
}

declare global {
  interface Window {
    nexhunt: NexHuntAPI
  }
}

// HTTP Flow types
export interface HttpFlow {
  id: string
  request_method: string
  request_url: string
  request_host: string
  request_port: number
  request_path: string
  request_headers: Record<string, string>
  request_body: string | null
  response_status: number
  response_headers: Record<string, string>
  response_body: string | null
  content_type: string | null
  response_length: number
  duration_ms: number
  is_intercepted: boolean
  timestamp: string
  tags: string[]
}

// Project types
export interface Project {
  id: string
  name: string
  scope: string[]
  out_of_scope: string[]
  scope_mode: 'strict' | 'permissive'
  notes: string
  created_at: string
  updated_at: string
}

export interface Target {
  id: string
  project_id: string
  value: string
  type: 'domain' | 'ip' | 'cidr'
  created_at: string
}

// Finding types
export interface Finding {
  id: string
  project_id: string
  target_id: string | null
  scan_job_id: string | null
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  vuln_type: string | null
  url: string | null
  parameter: string | null
  evidence: string | null
  description: string | null
  tool: string | null
  template_id: string | null
  status: 'new' | 'confirmed' | 'reported' | 'duplicate' | 'false_positive'
  notes: string | null
  created_at: string
  updated_at: string
}

// Scan types
export interface ScanJob {
  id: string
  project_id: string
  tool: string
  target: string
  options: Record<string, unknown>
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  progress: number
  started_at: string | null
  finished_at: string | null
  error: string | null
  created_at: string
}

// Tool types
export interface ToolStatus {
  name: string
  installed: boolean
  version: string | null
  path: string | null
}

// WebSocket message
export interface WsMessage {
  channel: string
  event: string
  data: unknown
}

// Recon result types
export interface SubdomainResult {
  subdomain: string
  source: string
  ip: string | null
  status_code: number | null
}

export interface UrlResult {
  url: string
  source: string
  status_code: number | null
  content_type: string | null
}

export interface PortResult {
  ip: string
  port: number
  proto?: string
  service: string | null
  version: string | null
  scripts?: string
}

export interface EndpointResult {
  url: string
  status_code: number | null
  title: string | null
  content_type: string | null
}

export interface PipelineEvent {
  phase: 'katana' | 'dalfox' | 'sqli_probe' | 'js_scan'
  pipeline?: 'xss' | 'sqli' | 'js_scan'
  event: 'started' | 'url_found' | 'completed' | 'failed' | 'finding' | 'js_file'
  message?: string
  url?: string
  has_params?: boolean
  is_form?: boolean
  total?: number
  total_urls?: number
  xss_candidates?: number
  findings?: number
  total_findings?: number
  finding?: Record<string, any>
  error?: string
  targets?: number
  fetched?: boolean
  js_files?: number
}
