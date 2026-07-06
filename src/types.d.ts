export interface UpdateAvailableInfo {
  current: string
  latest: string
  notes: string
  mandatory: boolean
}

export interface NexHuntAPI {
  getBackendUrl: () => Promise<string>
  getWsUrl: () => Promise<string>
  platform: string
  versions: {
    node: string
    chrome: string
    electron: string
  }
  update: {
    apply: () => void
    onAvailable: (cb: (data: UpdateAvailableInfo) => void) => () => void
    onInstalling: (cb: () => void) => () => void
    onDone: (cb: (version: string) => void) => () => void
    onError: (cb: (message: string) => void) => () => void
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
  content_length?: number | null
}

export interface PortResult {
  ip: string
  hostname?: string
  addresses?: Record<string, string>
  port: number
  proto?: string
  state?: string
  reason?: string
  service: string | null
  product?: string
  version: string | null
  extra_info?: string
  service_tunnel?: string
  device_type?: string
  service_os?: string
  confidence?: number
  cpes?: string[]
  scripts?: string
  script_results?: Array<{ id: string; output: string }>
  host_scripts?: string
  host_script_results?: Array<{ id: string; output: string }>
  os_matches?: Array<{ name: string; accuracy: number; line: string }>
  trace?: Array<{ ttl: string; ip: string; host: string; rtt: string }>
  scan_profile?: string
}

export interface EndpointResult {
  url: string
  status_code: number | null
  title: string | null
  content_type: string | null
  content_length: number | null
}

export interface PipelineEvent {
  phase: 'katana' | 'dalfox' | 'sqli_probe' | 'js_scan' | 'js_parse' | 'bucket_check'
  pipeline?: 'xss' | 'sqli' | 'js_scan'
  event: 'started' | 'url_found' | 'completed' | 'failed' | 'finding' | 'js_file' | 'cached'
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
  js_endpoints?: number
}
