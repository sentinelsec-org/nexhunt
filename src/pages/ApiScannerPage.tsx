import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  AlertTriangle, Check, ChevronDown, ChevronUp, ExternalLink, FileJson2,
  Loader2, Lock, Network, Play, Plus, Repeat2, Send, ShieldCheck, Sparkles,
  Search, Square, Terminal, X,
} from 'lucide-react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { Input } from '@/components/ui/input'
import { api } from '@/api/http-client'
import { toast } from '@/stores/toast-store'
import { useAppStore } from '@/stores/app-store'
import { useApiScannerStore, type ApiEndpointRow, type ApiParameterContract } from '@/stores/api-scanner-store'
import { useProxyStore } from '@/stores/proxy-store'
import { cn } from '@/lib/utils'

type ViewMode = 'results' | 'terminal'
type StatusFilter = 'all' | '2xx' | '3xx' | '4xx' | '5xx' | 'not-run' | 'inconclusive' | 'err'

interface ProbeResult {
  loading: boolean
  status?: number
  headers?: Record<string, string>
  body?: string
  duration_ms?: number
  error?: string
}

interface RequestDraft {
  parameters: Record<string, { value: string; enabled: boolean }>
  body: string
}

interface BuiltRequest {
  method: string
  url: string
  headers: Record<string, string>
  body: string | null
  error?: string
}

interface ContractInfo {
  spec_url: string
  base_url: string
  title: string
  version: string
  openapi_version: string
  endpoint_count: number
  truncated: boolean
  endpoints: ApiEndpointRow[]
}

const FILTERS: { id: StatusFilter; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: '2xx', label: '2xx' },
  { id: '3xx', label: '3xx' },
  { id: '4xx', label: '4xx' },
  { id: '5xx', label: '5xx' },
  { id: 'not-run', label: 'Not run' },
  { id: 'inconclusive', label: 'Inconclusive' },
  { id: 'err', label: 'Errors' },
]

const METHOD_COLOR: Record<string, string> = {
  GET: 'text-green-400 border-green-900 bg-green-950/25',
  POST: 'text-yellow-400 border-yellow-900 bg-yellow-950/25',
  PUT: 'text-blue-400 border-blue-900 bg-blue-950/25',
  PATCH: 'text-cyan-400 border-cyan-900 bg-cyan-950/25',
  DELETE: 'text-red-400 border-red-900 bg-red-950/25',
  HEAD: 'text-zinc-400 border-zinc-700 bg-zinc-900',
  OPTIONS: 'text-zinc-400 border-zinc-700 bg-zinc-900',
}

function rowKey(row: ApiEndpointRow) {
  return `${row.method}:${row.path}`
}

function parameterKey(parameter: ApiParameterContract) {
  return `${parameter.in}:${parameter.name}`
}

function valueText(value: unknown) {
  if (typeof value === 'string') return value
  if (value === null || value === undefined) return ''
  return typeof value === 'object' ? JSON.stringify(value) : String(value)
}

function draftFor(row: ApiEndpointRow): RequestDraft {
  const parameters: RequestDraft['parameters'] = {}
  for (const parameter of row.parameters || []) {
    parameters[parameterKey(parameter)] = {
      value: valueText(parameter.value),
      enabled: parameter.required || parameter.enabled,
    }
  }
  return {
    parameters,
    body: row.body === null || row.body === undefined
      ? ''
      : JSON.stringify(row.body, null, 2),
  }
}

function parseAccountAuthHeaders(value: string): Record<string, string> {
  const headers: Record<string, string> = {}
  const normalized = (value || '').trim()
  if (!normalized) return headers
  const lines = normalized.replace(/\r/g, '').split('\n').map(line => line.trim()).filter(Boolean)
  if (lines.length === 1 && !lines[0].includes(':')) {
    return { Authorization: `Bearer ${lines[0]}` }
  }
  for (const line of lines) {
    const index = line.indexOf(':')
    if (index < 0) continue
    const key = line.slice(0, index).trim()
    const headerValue = line.slice(index + 1).trim()
    if (key) headers[key] = headerValue
  }
  return headers
}

function globalAccountAuth(cookies: string, headers: string): string {
  return [cookies.trim() ? `Cookie: ${cookies.trim()}` : '', headers.trim()].filter(Boolean).join('\n')
}

function isAbsoluteHttpUrl(value: string): boolean {
  try {
    const parsed = new URL(value)
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && !!parsed.hostname
  } catch {
    return false
  }
}

function buildRequest(row: ApiEndpointRow, draft: RequestDraft, authHeaders: Record<string, string> = {}): BuiltRequest {
  let path = row.path
  const query = new URLSearchParams()
  const headers: Record<string, string> = { ...(row.request_headers || {}) }
  const cookies: string[] = []

  for (const parameter of row.parameters || []) {
    const current = draft.parameters[parameterKey(parameter)] || {
      value: valueText(parameter.value),
      enabled: parameter.required || parameter.enabled,
    }
    if (!current.enabled && !parameter.required) continue
    if (parameter.in === 'path') {
      path = path.replace(`{${parameter.name}}`, encodeURIComponent(current.value))
    } else if (parameter.in === 'query') {
      query.append(parameter.name, current.value)
    } else if (parameter.in === 'header') {
      headers[parameter.name] = current.value
    } else if (parameter.in === 'cookie') {
      cookies.push(`${parameter.name}=${current.value}`)
    }
  }

  path = path.replace(/\{[^}]+\}/g, '1')
  if (cookies.length) headers.Cookie = cookies.join('; ')
  Object.assign(headers, authHeaders)

  let body: string | null = draft.body.trim() || null
  if (body && row.body_content_type?.includes('json')) {
    try {
      body = JSON.stringify(JSON.parse(body), null, 2)
    } catch {
      return {
        method: row.method,
        url: '',
        headers,
        body,
        error: 'Request body is not valid JSON.',
      }
    }
  }
  if (body && row.body_content_type && !headers['Content-Type']) {
    headers['Content-Type'] = row.body_content_type
  }

  const url = row.base_url.replace(/\/$/, '') + '/' + path.replace(/^\//, '') + (query.size ? `?${query}` : '')
  return { method: row.method, url, headers, body }
}

function buildRawRequest(request: BuiltRequest) {
  let url: URL
  try { url = new URL(request.url) } catch { return null }
  const https = url.protocol === 'https:'
  const port = url.port ? Number(url.port) : (https ? 443 : 80)
  const lines = [`${request.method} ${url.pathname}${url.search} HTTP/1.1`, `Host: ${url.host}`]
  for (const [key, value] of Object.entries(request.headers)) {
    if (key.toLowerCase() !== 'host') lines.push(`${key}: ${value}`)
  }
  lines.push('', request.body || '')
  return { raw: lines.join('\n'), host: url.hostname, port, https }
}

function usefulnessRank(row: ApiEndpointRow): number {
  const status = row.status_anon
  if (status !== null && status >= 200 && status < 300 && row.auth_required) return 0
  if (status !== null && status >= 200 && status < 300) return 1
  if (status === 401 || status === 403) return 2
  if (status !== null && status >= 300 && status < 400) return 3
  if (status === 404) return 4
  if (status === 400 || status === 415 || status === 422) return 5
  if (status !== null && status >= 500) return 6
  if (row.probe_state === 'skipped_write') return 7
  if (row.probe_state === 'not_run') return 9
  return 8
}

function statusGroup(row: ApiEndpointRow): StatusFilter {
  if (row.probe_state === 'not_run' || row.probe_state === 'skipped_write') return 'not-run'
  if (row.probe_state === 'input_rejected') return 'inconclusive'
  if (row.status_anon === null) return 'err'
  if (row.status_anon < 300) return '2xx'
  if (row.status_anon < 400) return '3xx'
  if (row.status_anon < 500) return '4xx'
  return '5xx'
}

function matchesStatusFilter(row: ApiEndpointRow, filter: StatusFilter, probe?: { anon?: ProbeResult; auth?: ProbeResult }): boolean {
  if (filter === 'all') return true

  const statuses = [row.status_anon, row.status_auth, probe?.anon?.status, probe?.auth?.status]
    .filter((status): status is number => typeof status === 'number')

  if (filter === '2xx') return statuses.some(status => status >= 200 && status < 300)
  if (filter === '3xx') return statuses.some(status => status >= 300 && status < 400)
  if (filter === '4xx') return statuses.some(status => status >= 400 && status < 500)
  if (filter === '5xx') return statuses.some(status => status >= 500 && status < 600)
  return statusGroup(row) === filter
}

function StatusPill({ row, auth = false }: { row: ApiEndpointRow; auth?: boolean }) {
  const code = auth ? row.status_auth : row.status_anon
  if (!auth && row.probe_state === 'skipped_write') {
    return <span className="inline-flex min-w-12 justify-center rounded-sm border border-amber-900/80 bg-amber-950/20 px-1.5 py-0.5 text-[9px] font-medium text-amber-400">skipped</span>
  }
  if (!auth && row.probe_state === 'not_run') {
    return <span className="inline-flex min-w-12 justify-center rounded-sm border border-zinc-800 bg-zinc-900 px-1.5 py-0.5 text-[9px] text-zinc-600">not run</span>
  }
  if (code === null) return <span className="text-zinc-700">-</span>
  const style = code < 300
    ? 'border-green-800 bg-green-950/50 text-green-400'
    : code < 400
      ? 'border-blue-800 bg-blue-950/50 text-blue-400'
      : code < 500
        ? 'border-yellow-800 bg-yellow-950/50 text-yellow-400'
        : 'border-red-800 bg-red-950/50 text-red-400'
  return <span className={cn('inline-flex min-w-10 justify-center rounded-sm border px-1.5 py-0.5 font-mono text-[10px] font-semibold tabular-nums', style)}>{code}</span>
}

function schemaType(schema: Record<string, unknown>) {
  const type = typeof schema?.type === 'string' ? schema.type : 'value'
  const format = typeof schema?.format === 'string' ? schema.format : ''
  return format ? `${type} · ${format}` : type
}

function prettyJson(raw: string): string | null {
  try { return JSON.stringify(JSON.parse(raw), null, 2) } catch { return null }
}

function JsonString({ value }: { value: string }) {
  const [exp, setExp] = useState(false)
  const long = value.length > 100
  return (
    <span>
      <span className="text-green-300">"{!long || exp ? value : value.slice(0, 80) + '…'}"</span>
      {long && <button onClick={() => setExp(v => !v)} className="ml-1 text-[9px] text-zinc-600 hover:text-zinc-400">{exp ? '▲' : `+${value.length - 80}ch`}</button>}
    </span>
  )
}

function JsonNode({ value, depth = 0 }: { value: unknown; depth?: number }) {
  const isArr = Array.isArray(value)
  const isObj = value !== null && typeof value === 'object' && !isArr
  const entries = isArr
    ? (value as unknown[]).map((v, i) => [String(i), v] as [string, unknown])
    : isObj ? Object.entries(value as Record<string, unknown>) : []
  const count = entries.length
  const [open, setOpen] = useState(depth < 2 && !(isArr && count > 15))

  if (value === null) return <span className="text-zinc-500">null</span>
  if (typeof value === 'boolean') return <span className="text-cyan-400">{String(value)}</span>
  if (typeof value === 'number') return <span className="text-yellow-300">{value}</span>
  if (typeof value === 'string') return <JsonString value={value} />
  if (!isArr && !isObj) return <span className="text-zinc-300">{String(value)}</span>

  const [o, c] = isArr ? ['[', ']'] : ['{', '}']
  if (count === 0) return <span className="text-zinc-600">{o}{c}</span>

  return (
    <>
      <button onClick={() => setOpen(v => !v)} className="text-zinc-400 hover:text-white">
        {open ? o : <><span>{o}</span><span className="text-amber-400/80 text-[10px] px-0.5">{count}</span><span>{c}</span></>}
      </button>
      {open && (
        <div className="pl-4 border-l border-zinc-800/50 ml-0.5 mt-0.5">
          {entries.map(([key, val], i) => (
            <div key={key} className="leading-5">
              {isObj && <><span className="text-teal-300">"{key}"</span><span className="text-zinc-600">: </span></>}
              <JsonNode value={val} depth={depth + 1} />
              {i < count - 1 && <span className="text-zinc-700">,</span>}
            </div>
          ))}
        </div>
      )}
      {open && <div className="text-zinc-400">{c}</div>}
    </>
  )
}

function JsonViewer({ raw }: { raw: string }) {
  const parsed = useMemo(() => { try { return { ok: true, val: JSON.parse(raw) } } catch { return { ok: false, val: null } } }, [raw])
  if (!parsed.ok) return <pre className="p-3 font-mono text-xs text-zinc-400 whitespace-pre-wrap break-words">{raw}</pre>
  return <div className="p-3 font-mono text-xs leading-5 select-text"><JsonNode value={parsed.val} /></div>
}

function ResponsePanel({ label, color, probe }: { label: string; color: string; probe?: ProbeResult }) {
  const [expanded, setExpanded] = useState(false)
  const [copied, setCopied] = useState(false)
  if (!probe) return null

  const copyText = probe.body ? (prettyJson(probe.body) ?? probe.body) : ''

  const handleCopy = () => {
    if (!copyText) return
    navigator.clipboard.writeText(copyText).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }

  return (
    <div className="space-y-2 border-t border-zinc-800/80 pt-3">
      <div className="flex items-center gap-2">
        <span className={cn('text-[9px] font-semibold uppercase tracking-[0.16em]', color)}>{label}</span>
        {probe.loading && <Loader2 size={11} className="animate-spin text-teal-400" />}
        {probe.status !== undefined && <span className="rounded-sm border border-zinc-700 bg-zinc-950 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-zinc-200">{probe.status}</span>}
        {probe.duration_ms !== undefined && <span className="text-[9px] text-zinc-600">{Math.round(probe.duration_ms)} ms</span>}
        {probe.body && (
          <div className="ml-auto flex items-center gap-3">
            <button onClick={handleCopy} className="text-[9px] text-zinc-500 hover:text-zinc-300">{copied ? 'Copied!' : 'Copy'}</button>
            <button onClick={() => setExpanded(v => !v)} className="text-[9px] text-teal-400">{expanded ? 'Collapse' : 'Expand'}</button>
          </div>
        )}
      </div>
      {probe.error && <p className="text-[10px] text-red-400">{probe.error}</p>}
      {probe.body && (
        <div className={cn('overflow-auto rounded-md border border-zinc-800 bg-[#070A0D] shadow-inner', expanded ? 'max-h-[700px]' : 'max-h-80')}>
          <JsonViewer raw={probe.body} />
        </div>
      )}
    </div>
  )
}

function ParameterEditor({ parameter, current, onChange }: {
  parameter: ApiParameterContract
  current: { value: string; enabled: boolean }
  onChange: (value: { value: string; enabled: boolean }) => void
}) {
  return (
    <div className="grid grid-cols-[18px_120px_minmax(0,1fr)] items-center gap-2 border-t border-zinc-800/60 py-2 first:border-t-0">
      <input
        type="checkbox"
        checked={current.enabled || parameter.required}
        disabled={parameter.required}
        onChange={event => onChange({ ...current, enabled: event.target.checked })}
        className="w-3 h-3 accent-teal-500"
      />
      <div className="min-w-0">
        <div className="font-mono text-[10px] text-zinc-300 truncate">{parameter.name}</div>
        <div className="text-[8px] text-zinc-600">{schemaType(parameter.schema)}{parameter.required ? ' · required' : ''}</div>
      </div>
      <input
        value={current.value}
        onChange={event => onChange({ ...current, value: event.target.value })}
        className="h-8 min-w-0 rounded-md border border-zinc-800 bg-[#090D11] px-2.5 font-mono text-[10px] text-zinc-200 outline-none transition-colors focus:border-teal-700 focus:ring-1 focus:ring-teal-900"
      />
    </div>
  )
}

function RequestBuilder({ row, draft, onDraftChange, accountAuth, probes, onSend, onRepeater }: {
  row: ApiEndpointRow
  draft: RequestDraft
  onDraftChange: (draft: RequestDraft) => void
  accountAuth: string
  probes?: { anon?: ProbeResult; auth?: ProbeResult }
  onSend: (pass: 'anon' | 'auth') => void
  onRepeater: (auth: boolean) => void
}) {
  const groups = ['path', 'query', 'header', 'cookie'] as const
  const anonymous = buildRequest(row, draft)
  const bodyProperties = (row.body_schema?.properties || {}) as Record<string, Record<string, unknown>>

  return (
    <div className="space-y-5">
      {(row.summary || row.operation_id || row.tags?.length > 0) && (
        <div>
          {row.tags?.length > 0 && <div className="text-[9px] font-semibold uppercase tracking-[0.16em] text-teal-500">{row.tags.join(' / ')}</div>}
          {row.summary && <p className="mt-1 text-[11px] leading-relaxed text-zinc-400">{row.summary}</p>}
          {row.operation_id && <code className="mt-1 block text-[9px] text-zinc-600">{row.operation_id}</code>}
        </div>
      )}

      {groups.map(location => {
        const parameters = (row.parameters || []).filter(parameter => parameter.in === location)
        if (!parameters.length) return null
        return <section key={location}>
          <div className="mb-1.5 flex items-center justify-between">
            <span className="text-[9px] font-semibold uppercase tracking-[0.14em] text-zinc-500">{location} parameters</span>
            <span className="text-[8px] text-zinc-700">{parameters.filter(parameter => parameter.required).length} required</span>
          </div>
          <div className="rounded-md border border-zinc-800 bg-zinc-950/45 px-2.5">
            {parameters.map(parameter => {
              const key = parameterKey(parameter)
              const current = draft.parameters[key] || { value: valueText(parameter.value), enabled: parameter.required || parameter.enabled }
              return <ParameterEditor key={key} parameter={parameter} current={current} onChange={value => onDraftChange({ ...draft, parameters: { ...draft.parameters, [key]: value } })} />
            })}
          </div>
        </section>
      })}

      {(row.body !== null && row.body !== undefined) && (
        <section>
          <div className="mb-1.5 flex items-center justify-between">
            <span className="text-[9px] font-semibold uppercase tracking-[0.14em] text-zinc-500">Request body</span>
            <span className="font-mono text-[8px] text-zinc-600">{row.body_content_type || 'application/json'}{row.body_required ? ' · required' : ''}</span>
          </div>
          <textarea
            value={draft.body}
            onChange={event => onDraftChange({ ...draft, body: event.target.value })}
            spellCheck={false}
            className={cn('h-44 w-full resize-y rounded-md border bg-[#070A0D] p-3 font-mono text-[10px] leading-relaxed text-zinc-200 outline-none shadow-inner', anonymous.error ? 'border-red-800' : 'border-zinc-800 focus:border-teal-700 focus:ring-1 focus:ring-teal-900')}
          />
          {anonymous.error && <p className="mt-1 text-[9px] text-red-400">{anonymous.error}</p>}
          {Object.keys(bodyProperties).length > 0 && (
            <div className="mt-1.5 flex flex-wrap gap-1">
              {Object.entries(bodyProperties).map(([name, schema]) => <span key={name} className="rounded border border-zinc-800 bg-zinc-900 px-1.5 py-0.5 font-mono text-[8px] text-zinc-500">{name}: {schemaType(schema)}</span>)}
            </div>
          )}
        </section>
      )}

      <section>
        <div className="mb-1.5 text-[9px] font-semibold uppercase tracking-[0.14em] text-zinc-500">HTTP preview</div>
        <pre className="max-h-52 overflow-auto whitespace-pre-wrap break-words rounded-md border border-zinc-800 bg-[#050709] p-3 font-mono text-[10px] leading-relaxed text-zinc-400 shadow-inner">
          {anonymous.error ? anonymous.error : [
            `${anonymous.method} ${anonymous.url}`,
            ...Object.entries(anonymous.headers).map(([key, value]) => `${key}: ${value}`),
            anonymous.body ? `\n${anonymous.body}` : '',
          ].filter(Boolean).join('\n')}
        </pre>
      </section>

      <div className="grid grid-cols-2 gap-2">
        <button onClick={() => onSend('anon')} disabled={!!anonymous.error || probes?.anon?.loading} className="flex h-9 items-center justify-center gap-1.5 rounded-md border border-zinc-700 bg-zinc-900/50 text-[10px] font-medium text-zinc-200 transition-colors hover:border-teal-700 hover:bg-teal-950/20 hover:text-teal-300 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-teal-500 disabled:opacity-40">
          {probes?.anon?.loading ? <Loader2 size={11} className="animate-spin" /> : <Send size={11} />} Send anonymous
        </button>
        <button onClick={() => onSend('auth')} disabled={!accountAuth.trim() || !!anonymous.error || probes?.auth?.loading} className="flex h-9 items-center justify-center gap-1.5 rounded-md border border-cyan-900 bg-cyan-950/15 text-[10px] font-medium text-cyan-300 transition-colors hover:border-cyan-700 hover:bg-cyan-950/30 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-500 disabled:opacity-40">
          {probes?.auth?.loading ? <Loader2 size={11} className="animate-spin" /> : <Lock size={11} />} Send authenticated
        </button>
        <button onClick={() => onRepeater(false)} disabled={!!anonymous.error} className="col-span-2 flex h-9 items-center justify-center gap-1.5 rounded-md border border-zinc-800 text-[10px] text-zinc-500 transition-colors hover:border-zinc-700 hover:bg-zinc-900/70 hover:text-zinc-300 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-zinc-600">
          <Repeat2 size={11} /> Open drafted request in Repeater
        </button>
      </div>

      <ResponsePanel label="Anonymous response" color="text-zinc-400" probe={probes?.anon} />
      <ResponsePanel label="Authenticated response" color="text-cyan-400" probe={probes?.auth} />
    </div>
  )
}

export function ApiScannerPage({ embedded }: { embedded?: boolean }) {
  const [docsUrl, setDocsUrl] = useState('')
  const [baseUrl, setBaseUrl] = useState('')
  const [accountAuth, setAccountAuth] = useState('')
  const [authOpen, setAuthOpen] = useState(false)
  const [customHeaders, setCustomHeaders] = useState('')
  const [customHeadersOpen, setCustomHeadersOpen] = useState(false)
  const [aiAssist, setAiAssist] = useState(false)
  const [probeWrites, setProbeWrites] = useState(false)
  const [loadingSpec, setLoadingSpec] = useState(false)
  const [contract, setContract] = useState<ContractInfo | null>(null)
  const [view, setView] = useState<ViewMode>('results')
  const [filter, setFilter] = useState<StatusFilter>('all')
  const [search, setSearch] = useState('')
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [drafts, setDrafts] = useState<Record<string, RequestDraft>>({})
  const [probes, setProbes] = useState<Record<string, { anon?: ProbeResult; auth?: ProbeResult }>>({})
  const termRef = useRef<HTMLPreElement>(null)
  const syncedGlobalAuth = useRef('')
  const navigate = useNavigate()

  const { activeProject, sessionCookies, sessionHeaders } = useAppStore()
  const { rows, output, running, jobId, clear, setRows } = useApiScannerStore()
  const { sendRawToRepeater } = useProxyStore()

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight
  }, [output])

  useEffect(() => {
    const nextGlobalAuth = globalAccountAuth(sessionCookies, sessionHeaders)
    setAccountAuth(current => (!current.trim() || current === syncedGlobalAuth.current) ? nextGlobalAuth : current)
    syncedGlobalAuth.current = nextGlobalAuth
  }, [sessionCookies, sessionHeaders])

  const selected = rows.find(row => rowKey(row) === selectedKey) || null
  const selectedDraft = selected ? (drafts[rowKey(selected)] || draftFor(selected)) : null

  const counts = useMemo(() => FILTERS.reduce((result, item) => {
    if (item.id !== 'all') {
      result[item.id] = rows.filter(row => matchesStatusFilter(row, item.id, probes[rowKey(row)])).length
    }
    return result
  }, {} as Record<string, number>), [rows, probes])

  const shown = rows
    .filter(row => {
      if (!matchesStatusFilter(row, filter, probes[rowKey(row)])) return false
      const needle = search.trim().toLowerCase()
      return !needle || `${row.method} ${row.path} ${row.operation_id} ${row.summary} ${(row.tags || []).join(' ')}`.toLowerCase().includes(needle)
    })
    .sort((a, b) => usefulnessRank(a) - usefulnessRank(b) || a.path.localeCompare(b.path))
  const reachable = rows.filter(row => row.status_anon !== null && row.status_anon < 300).length
  const inconclusive = rows.filter(row => row.probe_state === 'input_rejected').length
  const brokenAuth = rows.filter(row => row.auth_required && row.status_anon !== null && row.status_anon < 300).length
  const importedRouteSet = !contract && rows.length > 0

  const handleLoadSpec = async () => {
    if (!docsUrl.trim()) {
      toast.error('Enter a Swagger / OpenAPI docs URL first', null)
      return
    }
    if (baseUrl.trim() && !isAbsoluteHttpUrl(baseUrl.trim())) {
      toast.error('Base URL override must be an absolute HTTP(S) URL', 'Example: https://api.target.com')
      return
    }
    setLoadingSpec(true)
    clear()
    setContract(null)
    setSelectedKey(null)
    setDrafts({})
    setProbes({})
    setView('results')
    try {
      const result = await api.post<ContractInfo>('/api/api-scanner/spec', {
        target: docsUrl.trim(),
        options: { base_url: baseUrl.trim() },
        project_id: activeProject ?? '',
      })
      const templates = result.endpoints.map(endpoint => ({
        ...endpoint,
        status_anon: null,
        status_auth: null,
        content_length: 0,
        content_type: '',
        probe_state: 'not_run' as const,
        note: 'contract loaded - not sent',
      }))
      setContract(result)
      setRows(templates)
      if (templates[0]) setSelectedKey(rowKey(templates[0]))
      toast.success('API contract loaded', `${templates.length} operations · no endpoint requests sent`)
    } catch (error) {
      toast.error('Could not load API contract', error)
    } finally {
      setLoadingSpec(false)
    }
  }

  const handleRun = async () => {
    if (!rows.length) {
      toast.error('Load a contract or import routes first', null)
      return
    }
    const importedEndpoints = !contract
      ? rows.map(row => ({ method: row.method, path: row.path, secured: row.auth_required }))
      : null
    const requestedBaseUrl = baseUrl.trim()
    if (requestedBaseUrl && !isAbsoluteHttpUrl(requestedBaseUrl)) {
      toast.error('Base URL override must be an absolute HTTP(S) URL', 'Authorization headers belong in Account auth, not Base URL override.')
      return
    }
    const importedBaseUrl = !contract ? rows[0]?.base_url || '' : ''
    const runTarget = contract ? docsUrl.trim() : (importedBaseUrl || rows[0]?.url || '')
    const runBaseUrl = requestedBaseUrl || importedBaseUrl
    if (!runTarget) {
      toast.error('No target is available for these routes', null)
      return
    }
    if (!contract && (!isAbsoluteHttpUrl(runTarget) || !isAbsoluteHttpUrl(runBaseUrl))) {
      toast.error('The imported route set has an invalid base URL', 'Send the routes from JS API Mapper again to restore their target host.')
      return
    }
    clear()
    setSelectedKey(null)
    setProbes({})
    setView('results')
    try {
      await api.post('/api/api-scanner', {
        target: runTarget,
        options: {
          base_url: runBaseUrl,
          account_auth: accountAuth.trim(),
          ai_assist: aiAssist,
          probe_writes: probeWrites,
          ...(importedEndpoints ? { endpoints: importedEndpoints } : {}),
        },
        project_id: activeProject ?? '',
      })
    } catch (error) {
      toast.error('Failed to start API Scanner', error)
    }
  }

  const handleStop = async () => {
    if (!jobId) return
    try { await api.delete(`/api/api-scanner/jobs/${jobId}`) } catch {}
  }

  const updateDraft = (row: ApiEndpointRow, draft: RequestDraft) => {
    setDrafts(previous => ({ ...previous, [rowKey(row)]: draft }))
  }

  const sendProbe = async (row: ApiEndpointRow, pass: 'anon' | 'auth') => {
    const key = rowKey(row)
    const draft = drafts[key] || draftFor(row)
    const extra = parseAccountAuthHeaders(customHeaders)
    const authHeaders = pass === 'auth' ? parseAccountAuthHeaders(accountAuth) : {}
    const request = buildRequest(row, draft, { ...extra, ...authHeaders })
    if (request.error) {
      toast.error('Invalid request', request.error)
      return
    }
    setProbes(previous => ({ ...previous, [key]: { ...previous[key], [pass]: { loading: true } } }))
    try {
      const response = await api.post<{ status: number; headers: Record<string, string>; body: string; duration_ms: number }>(
        '/api/proxy/repeater',
        { method: request.method, url: request.url, headers: request.headers, body: request.body },
      )
      setProbes(previous => ({ ...previous, [key]: { ...previous[key], [pass]: { loading: false, ...response } } }))
    } catch (error) {
      setProbes(previous => ({
        ...previous,
        [key]: {
          ...previous[key],
          [pass]: { loading: false, error: (error as Error).message || 'Request failed' },
        },
      }))
    }
  }

  const sendToRepeater = (row: ApiEndpointRow, auth: boolean) => {
    const draft = drafts[rowKey(row)] || draftFor(row)
    const extra = parseAccountAuthHeaders(customHeaders)
    const request = buildRequest(row, draft, { ...extra, ...(auth ? parseAccountAuthHeaders(accountAuth) : {}) })
    if (request.error) {
      toast.error('Invalid request', request.error)
      return
    }
    const raw = buildRawRequest(request)
    if (!raw) {
      toast.error('Invalid URL', request.url)
      return
    }
    sendRawToRepeater(raw.raw, raw.host, raw.port, raw.https)
    navigate('/proxy?tab=repeater')
  }

  const body = (
    <div className="flex h-full min-h-0 flex-col gap-3">
      <section className="relative shrink-0 overflow-hidden rounded-lg border border-zinc-800 bg-[#0B1015] shadow-[0_16px_50px_rgba(0,0,0,0.18)]">
        <div className={cn('absolute inset-y-0 left-0 w-0.5', running ? 'bg-green-400' : contract || importedRouteSet ? 'bg-teal-500' : 'bg-zinc-700')} />
        <div className="space-y-4 p-4 pl-5">
          <div className="flex flex-wrap items-start gap-3">
            <div className="grid h-9 w-9 shrink-0 place-items-center rounded-md border border-teal-800/70 bg-teal-950/30 text-teal-300">
              <Network size={16} />
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-[9px] font-semibold uppercase tracking-[0.2em] text-teal-500">Contract-driven access control</div>
              <div className="mt-0.5 flex flex-wrap items-center gap-2">
                <h2 className="text-base font-semibold tracking-tight text-zinc-100">API Scanner</h2>
                {contract && <span className="rounded-sm border border-zinc-700 bg-zinc-950/70 px-2 py-0.5 font-mono text-[9px] text-zinc-400">{contract.title} · {contract.openapi_version}</span>}
                {importedRouteSet && <span className="rounded-sm border border-teal-900 bg-teal-950/20 px-2 py-0.5 font-mono text-[9px] text-teal-400">Imported route set · {rows.length}</span>}
              </div>
            </div>
            <div className="flex items-center gap-2 text-[9px] font-semibold uppercase tracking-[0.14em]">
              <span className={cn('rounded-sm border px-2 py-1', running ? 'border-green-800 bg-green-950/30 text-green-300' : contract || importedRouteSet ? 'border-teal-900 bg-teal-950/20 text-teal-400' : 'border-zinc-800 text-zinc-600')}>
                {running ? 'Probe active' : contract ? 'Contract ready' : importedRouteSet ? 'Routes imported' : 'Awaiting contract'}
              </span>
              <span className={cn('rounded-sm border px-2 py-1', probeWrites ? 'border-amber-800 bg-amber-950/20 text-amber-300' : 'border-zinc-800 text-zinc-500')}>
                {probeWrites ? 'Writes enabled' : 'Read only'}
              </span>
            </div>
          </div>

          <div>
            <div className="mb-1.5 flex items-center gap-2 text-[9px] font-semibold uppercase tracking-[0.18em] text-zinc-500"><span className="text-teal-500">01</span> Contract</div>
            <div className="flex flex-col gap-2 lg:flex-row">
              <Input
                value={docsUrl}
                onChange={event => { setDocsUrl(event.target.value); setContract(null) }}
                placeholder="https://api.target.com/swagger/index.html"
                className="h-10 flex-1 border-zinc-700 bg-[#070A0D] font-mono text-xs text-zinc-200 placeholder:text-zinc-700 focus-visible:ring-teal-800"
                onKeyDown={event => { if (event.key === 'Enter' && !loadingSpec && !running) handleLoadSpec() }}
              />
              <div className="flex gap-2">
                <button onClick={handleLoadSpec} disabled={!docsUrl.trim() || loadingSpec || running} className="flex h-10 shrink-0 items-center gap-2 rounded-md border border-teal-800 bg-teal-950/20 px-4 text-xs font-medium text-teal-300 transition-colors hover:bg-teal-950/40 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-teal-500 disabled:opacity-40">
                  {loadingSpec ? <Loader2 size={12} className="animate-spin" /> : <FileJson2 size={12} />} Load contract
                </button>
                {running ? (
                  <button onClick={handleStop} className="flex h-10 shrink-0 items-center gap-2 rounded-md border border-red-700 bg-red-950/15 px-4 text-xs font-medium text-red-300 transition-colors hover:bg-red-950/30 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-red-500"><Square size={11} className="fill-current" />Stop probe</button>
                ) : (
                  <button onClick={handleRun} disabled={rows.length === 0} className="flex h-10 shrink-0 items-center gap-2 rounded-md border border-green-700 bg-green-950/20 px-4 text-xs font-medium text-green-300 transition-colors hover:bg-green-950/40 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-green-500 disabled:opacity-40"><Play size={12} />{importedRouteSet ? 'Re-run routes' : 'Run probe'}</button>
                )}
              </div>
            </div>
          </div>

          <div className="grid gap-3 lg:grid-cols-[minmax(260px,0.8fr)_minmax(520px,1.2fr)]">
            <div className="rounded-md border border-zinc-800 bg-zinc-950/30 p-3">
              <div className="mb-2 flex items-center gap-2 text-[9px] font-semibold uppercase tracking-[0.18em] text-zinc-500"><span className="text-cyan-500">02</span> Request context</div>
              <Input value={baseUrl} onChange={event => { setBaseUrl(event.target.value); setContract(null) }} placeholder="Base URL override (optional)" className="h-8 border-zinc-800 bg-[#070A0D] font-mono text-[10px]" />
              <div className="mt-2 flex flex-wrap gap-x-4 gap-y-2">
                <button onClick={() => setAuthOpen(open => !open)} className="flex items-center gap-1.5 text-[10px] text-cyan-400/90 transition-colors hover:text-cyan-300 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-600">
                  <Lock size={11} /> Account auth {accountAuth.trim() && <Check size={10} className="text-green-400" />}{authOpen ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
                </button>
                <button onClick={() => setCustomHeadersOpen(open => !open)} className="flex items-center gap-1.5 text-[10px] text-amber-400/90 transition-colors hover:text-amber-300 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-amber-600">
                  <Plus size={11} /> Custom headers {customHeaders.trim() && <Check size={10} className="text-green-400" />}{customHeadersOpen ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
                </button>
              </div>
            </div>

            <div className="rounded-md border border-zinc-800 bg-zinc-950/30 p-3">
              <div className="mb-2 flex items-center gap-2 text-[9px] font-semibold uppercase tracking-[0.18em] text-zinc-500"><span className="text-green-500">03</span> Probe policy</div>
              <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
                <label className="flex cursor-pointer items-center gap-2 text-[10px] text-zinc-400">
                  <input type="checkbox" checked={aiAssist} onChange={event => setAiAssist(event.target.checked)} className="h-3 w-3 accent-teal-500" />
                  <Sparkles size={11} className="text-teal-400" /> AI triage
                </label>
                <label className={cn('flex cursor-pointer items-center gap-2 text-[10px]', probeWrites ? 'text-amber-300' : 'text-zinc-500')}>
                  <input type="checkbox" checked={probeWrites} onChange={event => setProbeWrites(event.target.checked)} className="h-3 w-3 accent-amber-500" />
                  <AlertTriangle size={11} /> Include write methods
                </label>
                {contract && <a href={contract.spec_url} target="_blank" rel="noreferrer" className="ml-auto flex items-center gap-1 text-[9px] text-zinc-600 transition-colors hover:text-teal-400">Open source contract <ExternalLink size={9} /></a>}
              </div>
              <p className="mt-2 text-[9px] leading-relaxed text-zinc-700">Anonymous and authenticated responses are kept as separate evidence lanes. Write methods remain opt-in.</p>
            </div>
          </div>

          {(authOpen || customHeadersOpen) && (
            <div className="grid gap-3 lg:grid-cols-2">
              {authOpen && (
                <div>
                  <div className="mb-1 text-[9px] font-semibold uppercase tracking-[0.14em] text-cyan-500">Authenticated lane</div>
                  <textarea value={accountAuth} onChange={event => setAccountAuth(event.target.value)} rows={2} placeholder={"Authorization: Bearer eyJ...\nCookie: session=..."} className="w-full resize-none rounded-md border border-cyan-950 bg-[#070A0D] px-3 py-2 font-mono text-[10px] text-zinc-300 outline-none focus:border-cyan-700 focus:ring-1 focus:ring-cyan-950" />
                </div>
              )}
              {customHeadersOpen && (
                <div>
                  <div className="mb-1 text-[9px] font-semibold uppercase tracking-[0.14em] text-amber-500">Shared request headers</div>
                  <textarea value={customHeaders} onChange={event => setCustomHeaders(event.target.value)} rows={2} placeholder={"X-Forwarded-For: 127.0.0.1\nX-Real-IP: 127.0.0.1"} className="w-full resize-none rounded-md border border-amber-950 bg-[#070A0D] px-3 py-2 font-mono text-[10px] text-zinc-300 outline-none focus:border-amber-700 focus:ring-1 focus:ring-amber-950" />
                </div>
              )}
            </div>
          )}

          {rows.length > 0 && (
            <div className="grid grid-cols-2 overflow-hidden rounded-md border border-zinc-800 bg-zinc-800 sm:grid-cols-4">
              <div className="bg-[#090D11] px-3 py-2.5"><div className="font-mono text-lg font-semibold tabular-nums text-zinc-100">{rows.length}</div><div className="text-[9px] uppercase tracking-[0.12em] text-zinc-600">Operations</div></div>
              <div className="bg-[#090D11] px-3 py-2.5"><div className="font-mono text-lg font-semibold tabular-nums text-green-400">{reachable}</div><div className="text-[9px] uppercase tracking-[0.12em] text-zinc-600">Anon accepted</div></div>
              <div className="bg-[#090D11] px-3 py-2.5"><div className="font-mono text-lg font-semibold tabular-nums text-amber-400">{inconclusive}</div><div className="text-[9px] uppercase tracking-[0.12em] text-zinc-600">Inconclusive</div></div>
              <div className="bg-[#090D11] px-3 py-2.5"><div className="font-mono text-lg font-semibold tabular-nums text-red-400">{brokenAuth}</div><div className="text-[9px] uppercase tracking-[0.12em] text-zinc-600">Access gaps</div></div>
            </div>
          )}
        </div>
      </section>

      <div className="flex shrink-0 items-center gap-1 border-b border-zinc-800 px-1">
        <button onClick={() => setView('results')} className={cn('relative flex h-9 items-center gap-2 px-3 text-xs transition-colors', view === 'results' ? 'text-zinc-100 after:absolute after:inset-x-2 after:bottom-[-1px] after:h-px after:bg-teal-400' : 'text-zinc-500 hover:text-zinc-300')}>Operations {rows.length > 0 && <span className="rounded-sm bg-zinc-800 px-1.5 font-mono text-[9px] text-zinc-400">{rows.length}</span>}</button>
        <button onClick={() => setView('terminal')} className={cn('relative flex h-9 items-center gap-2 px-3 text-xs transition-colors', view === 'terminal' ? 'text-zinc-100 after:absolute after:inset-x-2 after:bottom-[-1px] after:h-px after:bg-teal-400' : 'text-zinc-500 hover:text-zinc-300')}><Terminal size={11} />Raw output{running && <span className="h-1.5 w-1.5 rounded-full bg-green-400 animate-pulse" />}</button>
      </div>

      {view === 'terminal' && (
        <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-lg border border-zinc-800 bg-[#050709]">
          <div className="flex h-9 shrink-0 items-center justify-between border-b border-zinc-800 px-3 text-[9px] font-semibold uppercase tracking-[0.16em] text-zinc-600"><span>Scanner event stream</span><span>{output.length} lines</span></div>
          <pre ref={termRef} className="flex-1 overflow-auto p-4 font-mono text-[11px] leading-relaxed">
            {output.map((line, index) => <span key={index} className={cn('block', line.startsWith('$') ? 'font-bold text-green-400' : line.includes('inconclusive') ? 'text-amber-400' : line.includes('SECURED') ? 'text-red-400' : 'text-zinc-300')}>{line}</span>)}
            {running && output.length === 0 && <span className="text-zinc-600 animate-pulse">Starting probe...</span>}
            {!running && output.length === 0 && <span className="text-zinc-700">Load a contract, inspect requests, then run the probe.</span>}
          </pre>
        </div>
      )}

      {view === 'results' && (
        <div className="flex min-h-0 flex-1 flex-col gap-2">
          <div className="flex shrink-0 flex-wrap items-center gap-1.5">
            <span className="mr-1 text-[9px] font-semibold uppercase tracking-[0.16em] text-zinc-600">Response class</span>
            {FILTERS.map(item => <button key={item.id} onClick={() => setFilter(item.id)} className={cn('shrink-0 rounded-sm border px-2.5 py-1 text-[10px] transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-teal-600', filter === item.id ? 'border-teal-700 bg-teal-950/30 text-teal-300' : 'border-zinc-800 bg-zinc-950/40 text-zinc-500 hover:border-zinc-700 hover:text-zinc-300')}>{item.label}{item.id !== 'all' && counts[item.id] ? ` ${counts[item.id]}` : ''}</button>)}
            <div className="relative ml-auto min-w-60 flex-1 sm:max-w-72">
              <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-600" />
              <input value={search} onChange={event => setSearch(event.target.value)} placeholder="Filter method, path, tag" className="h-8 w-full rounded-md border border-zinc-800 bg-[#070A0D] pl-8 pr-2 font-mono text-[10px] text-zinc-300 outline-none transition-colors placeholder:text-zinc-700 focus:border-teal-800 focus:ring-1 focus:ring-teal-950" />
            </div>
          </div>

          <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 xl:grid-cols-[minmax(500px,1fr)_minmax(410px,0.82fr)]">
            <div className="min-h-72 overflow-auto rounded-lg border border-zinc-800 bg-[#090D11]">
              <table className="w-full text-xs">
                <thead className="sticky top-0 z-10 bg-[#0E151B] shadow-[0_1px_0_#1C2330]">
                  <tr className="text-left text-[9px] font-semibold uppercase tracking-[0.12em] text-zinc-600">
                    <th className="w-20 px-3 py-2.5">Method</th>
                    <th className="px-3 py-2.5">Operation</th>
                    <th className="w-20 px-3 py-2.5 text-green-500">Anon lane</th>
                    <th className="w-20 px-3 py-2.5 text-cyan-500">Auth lane</th>
                    <th className="w-36 px-3 py-2.5">Assessment</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map(row => {
                    const key = rowKey(row)
                    return <tr key={key} onClick={() => setSelectedKey(key)} className={cn('cursor-pointer border-t border-zinc-800/60 transition-colors hover:bg-zinc-800/30', selectedKey === key && 'bg-teal-950/15 shadow-[inset_2px_0_0_#00D9A6]', row.probe_state === 'input_rejected' && 'bg-amber-950/10')}>
                      <td className="px-3 py-2.5"><span className={cn('rounded-sm border px-1.5 py-0.5 font-mono text-[9px] font-bold', METHOD_COLOR[row.method] || METHOD_COLOR.HEAD)}>{row.method}</span></td>
                      <td className="min-w-0 px-3 py-2.5">
                        <div className="break-all font-mono text-[10px] text-zinc-200">{row.path}</div>
                        {(row.summary || row.operation_id) && <div className="mt-1 truncate text-[9px] text-zinc-600">{row.summary || row.operation_id}</div>}
                      </td>
                      <td className="px-3 py-2.5"><StatusPill row={row} /></td>
                      <td className="px-3 py-2.5"><StatusPill row={row} auth /></td>
                      <td className={cn('px-3 py-2.5 text-[9px] leading-snug', row.probe_state === 'input_rejected' ? 'text-amber-400' : row.note.includes('SECURED') ? 'font-medium text-red-400' : 'text-zinc-600')}>{row.note}</td>
                    </tr>
                  })}
                  {shown.length === 0 && <tr><td colSpan={5} className="py-20 text-center text-xs text-zinc-600">{running ? <span className="inline-flex items-center gap-2"><Loader2 size={12} className="animate-spin" />Probing operations...</span> : 'No operations match this view.'}</td></tr>}
                </tbody>
              </table>
            </div>

            <aside className="min-h-72 overflow-y-auto rounded-lg border border-zinc-800 bg-[#0B1015]">
              {selected && selectedDraft ? (
                <>
                  <div className="sticky top-0 z-10 border-b border-zinc-800 bg-[#0E151B]/95 px-4 py-3 backdrop-blur">
                    <div className="mb-2 flex items-center justify-between text-[9px] font-semibold uppercase tracking-[0.16em] text-zinc-600"><span>Request workbench</span><button onClick={() => setSelectedKey(null)} className="rounded p-1 text-zinc-600 transition-colors hover:bg-zinc-800 hover:text-zinc-300 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-zinc-600" aria-label="Close request workbench"><X size={13} /></button></div>
                    <div className="flex items-start gap-2.5">
                      <span className={cn('rounded-sm border px-2 py-1 font-mono text-[10px] font-bold', METHOD_COLOR[selected.method] || METHOD_COLOR.HEAD)}>{selected.method}</span>
                      <div className="min-w-0 flex-1">
                        <div className="break-all font-mono text-sm text-zinc-100">{selected.path}</div>
                        <div className="mt-1.5 flex flex-wrap items-center gap-2">
                          {selected.auth_required ? <span className="inline-flex items-center gap-1 text-[9px] text-cyan-400"><ShieldCheck size={9} />Auth declared</span> : <span className="text-[9px] text-zinc-600">No auth declared</span>}
                          {selected.mutating && <span className="inline-flex items-center gap-1 text-[9px] text-amber-400"><AlertTriangle size={9} />May change data</span>}
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="p-4">
                    <RequestBuilder
                      row={selected}
                      draft={selectedDraft}
                      onDraftChange={draft => updateDraft(selected, draft)}
                      accountAuth={accountAuth}
                      probes={probes[rowKey(selected)]}
                      onSend={pass => sendProbe(selected, pass)}
                      onRepeater={auth => sendToRepeater(selected, auth)}
                    />
                  </div>
                </>
              ) : (
                <div className="grid h-full min-h-72 place-items-center px-8 text-center">
                  <div><div className="mx-auto mb-3 grid h-10 w-10 place-items-center rounded-md border border-zinc-800 bg-zinc-950 text-zinc-600"><Network size={16} /></div><div className="text-xs font-medium text-zinc-400">Select an operation</div><p className="mt-1 max-w-56 text-[10px] leading-relaxed text-zinc-600">Inspect its generated request, edit parameters, and compare anonymous against authenticated responses.</p></div>
                </div>
              )}
            </aside>
          </div>
        </div>
      )}
    </div>
  )

  if (embedded) return body
  return <WorkspaceShell title="API Scanner" subtitle="Load the contract, inspect generated requests, then probe access control">{body}</WorkspaceShell>
}
