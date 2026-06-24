import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  AlertTriangle, Check, ChevronDown, ChevronUp, ExternalLink, FileJson2,
  Loader2, Lock, Network, Play, Repeat2, Send, ShieldCheck, Sparkles,
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

function StatusPill({ row, auth = false }: { row: ApiEndpointRow; auth?: boolean }) {
  const code = auth ? row.status_auth : row.status_anon
  if (!auth && row.probe_state === 'skipped_write') {
    return <span className="rounded border border-amber-900 bg-amber-950/20 px-1.5 py-0.5 text-[9px] text-amber-500">skipped</span>
  }
  if (!auth && row.probe_state === 'not_run') {
    return <span className="rounded border border-zinc-800 bg-zinc-900 px-1.5 py-0.5 text-[9px] text-zinc-600">not run</span>
  }
  if (code === null) return <span className="text-zinc-700">-</span>
  const style = code < 300
    ? 'border-green-800 bg-green-950/50 text-green-400'
    : code < 400
      ? 'border-blue-800 bg-blue-950/50 text-blue-400'
      : code < 500
        ? 'border-yellow-800 bg-yellow-950/50 text-yellow-400'
        : 'border-red-800 bg-red-950/50 text-red-400'
  return <span className={cn('rounded border px-1.5 py-0.5 font-mono text-[10px]', style)}>{code}</span>
}

function schemaType(schema: Record<string, unknown>) {
  const type = typeof schema?.type === 'string' ? schema.type : 'value'
  const format = typeof schema?.format === 'string' ? schema.format : ''
  return format ? `${type} · ${format}` : type
}

function ResponsePanel({ label, color, probe }: { label: string; color: string; probe?: ProbeResult }) {
  const [expanded, setExpanded] = useState(false)
  if (!probe) return null
  return (
    <div className="border-t border-zinc-800 pt-3 space-y-2">
      <div className="flex items-center gap-2">
        <span className={cn('text-[9px] font-semibold uppercase', color)}>{label}</span>
        {probe.loading && <Loader2 size={11} className="animate-spin text-teal-400" />}
        {probe.status !== undefined && <span className="font-mono text-[10px] text-zinc-300">{probe.status}</span>}
        {probe.duration_ms !== undefined && <span className="text-[9px] text-zinc-600">{Math.round(probe.duration_ms)} ms</span>}
        {probe.body && <button onClick={() => setExpanded(value => !value)} className="ml-auto text-[9px] text-teal-400">{expanded ? 'Collapse' : 'Expand'}</button>}
      </div>
      {probe.error && <p className="text-[10px] text-red-400">{probe.error}</p>}
      {probe.body && <pre className={cn('rounded bg-zinc-950 p-2 font-mono text-[10px] leading-relaxed text-zinc-400 whitespace-pre-wrap break-all overflow-auto', expanded ? 'max-h-96' : 'max-h-32')}>{probe.body}</pre>}
    </div>
  )
}

function ParameterEditor({ parameter, current, onChange }: {
  parameter: ApiParameterContract
  current: { value: string; enabled: boolean }
  onChange: (value: { value: string; enabled: boolean }) => void
}) {
  return (
    <div className="grid grid-cols-[18px_110px_minmax(0,1fr)] gap-2 items-center py-1.5 border-t border-zinc-800/60 first:border-t-0">
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
        className="h-7 min-w-0 rounded border border-zinc-800 bg-zinc-950 px-2 font-mono text-[10px] text-zinc-300 focus:outline-none focus:border-teal-800"
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
    <div className="space-y-4">
      {(row.summary || row.operation_id || row.tags?.length > 0) && (
        <div>
          {row.tags?.length > 0 && <div className="text-[9px] uppercase font-semibold text-teal-500">{row.tags.join(' / ')}</div>}
          {row.summary && <p className="mt-1 text-[11px] leading-relaxed text-zinc-400">{row.summary}</p>}
          {row.operation_id && <code className="mt-1 block text-[9px] text-zinc-600">{row.operation_id}</code>}
        </div>
      )}

      {groups.map(location => {
        const parameters = (row.parameters || []).filter(parameter => parameter.in === location)
        if (!parameters.length) return null
        return <section key={location}>
          <div className="mb-1 flex items-center justify-between">
            <span className="text-[9px] font-semibold uppercase text-zinc-600">{location} parameters</span>
            <span className="text-[8px] text-zinc-700">{parameters.filter(parameter => parameter.required).length} required</span>
          </div>
          <div className="rounded border border-zinc-800 bg-zinc-950/35 px-2">
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
          <div className="mb-1 flex items-center justify-between">
            <span className="text-[9px] font-semibold uppercase text-zinc-600">Request body</span>
            <span className="font-mono text-[8px] text-zinc-600">{row.body_content_type || 'application/json'}{row.body_required ? ' · required' : ''}</span>
          </div>
          <textarea
            value={draft.body}
            onChange={event => onDraftChange({ ...draft, body: event.target.value })}
            spellCheck={false}
            className={cn('h-40 w-full resize-y rounded border bg-zinc-950 p-2 font-mono text-[10px] leading-relaxed text-zinc-300 focus:outline-none', anonymous.error ? 'border-red-800' : 'border-zinc-800 focus:border-teal-800')}
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
        <div className="mb-1 text-[9px] font-semibold uppercase text-zinc-600">HTTP preview</div>
        <pre className="max-h-48 overflow-auto rounded border border-zinc-800 bg-black p-2 font-mono text-[9px] leading-relaxed text-zinc-400 whitespace-pre-wrap break-all">
          {anonymous.error ? anonymous.error : [
            `${anonymous.method} ${anonymous.url}`,
            ...Object.entries(anonymous.headers).map(([key, value]) => `${key}: ${value}`),
            anonymous.body ? `\n${anonymous.body}` : '',
          ].filter(Boolean).join('\n')}
        </pre>
      </section>

      <div className="grid grid-cols-2 gap-2">
        <button onClick={() => onSend('anon')} disabled={!!anonymous.error || probes?.anon?.loading} className="h-8 rounded border border-zinc-700 text-[10px] text-zinc-300 hover:border-teal-700 hover:text-teal-300 disabled:opacity-40 flex items-center justify-center gap-1.5">
          {probes?.anon?.loading ? <Loader2 size={11} className="animate-spin" /> : <Send size={11} />} Send anonymous
        </button>
        <button onClick={() => onSend('auth')} disabled={!accountAuth.trim() || !!anonymous.error || probes?.auth?.loading} className="h-8 rounded border border-cyan-900 text-[10px] text-cyan-400 hover:border-cyan-700 disabled:opacity-40 flex items-center justify-center gap-1.5">
          {probes?.auth?.loading ? <Loader2 size={11} className="animate-spin" /> : <Lock size={11} />} Send authenticated
        </button>
        <button onClick={() => onRepeater(false)} disabled={!!anonymous.error} className="col-span-2 h-8 rounded border border-zinc-800 text-[10px] text-zinc-500 hover:text-zinc-300 flex items-center justify-center gap-1.5">
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
  const navigate = useNavigate()

  const { activeProject } = useAppStore()
  const { rows, output, running, jobId, clear, setRows } = useApiScannerStore()
  const { sendRawToRepeater } = useProxyStore()

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight
  }, [output])

  const selected = rows.find(row => rowKey(row) === selectedKey) || null
  const selectedDraft = selected ? (drafts[rowKey(selected)] || draftFor(selected)) : null

  const counts = useMemo(() => rows.reduce((result, row) => {
    const group = statusGroup(row)
    result[group] = (result[group] || 0) + 1
    return result
  }, {} as Record<string, number>), [rows])

  const shown = rows
    .filter(row => {
      if (filter !== 'all' && statusGroup(row) !== filter) return false
      const needle = search.trim().toLowerCase()
      return !needle || `${row.method} ${row.path} ${row.operation_id} ${row.summary} ${(row.tags || []).join(' ')}`.toLowerCase().includes(needle)
    })
    .sort((a, b) => usefulnessRank(a) - usefulnessRank(b) || a.path.localeCompare(b.path))
  const reachable = rows.filter(row => row.status_anon !== null && row.status_anon < 300).length
  const inconclusive = rows.filter(row => row.probe_state === 'input_rejected').length
  const brokenAuth = rows.filter(row => row.auth_required && row.status_anon !== null && row.status_anon < 300).length

  const handleLoadSpec = async () => {
    if (!docsUrl.trim()) {
      toast.error('Enter a Swagger / OpenAPI docs URL first', null)
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
    if (!contract || !rows.length) {
      toast.error('Load the API contract first', null)
      return
    }
    clear()
    setSelectedKey(null)
    setProbes({})
    setView('results')
    try {
      await api.post('/api/api-scanner', {
        target: docsUrl.trim(),
        options: {
          base_url: baseUrl.trim(),
          account_auth: accountAuth.trim(),
          ai_assist: aiAssist,
          probe_writes: probeWrites,
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
    const authHeaders = pass === 'auth' ? parseAccountAuthHeaders(accountAuth) : {}
    const request = buildRequest(row, draft, authHeaders)
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
    const request = buildRequest(row, draft, auth ? parseAccountAuthHeaders(accountAuth) : {})
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
    <div className="flex flex-col gap-3 h-full min-h-0">
      <div className="rounded-lg border border-teal-500/30 bg-teal-950/15 p-3 space-y-2.5">
        <div className="flex items-center gap-2">
          <Network size={15} className="text-teal-400" />
          <span className="text-sm font-semibold text-teal-400">API Scanner</span>
          {contract && <span className="rounded border border-zinc-800 bg-zinc-950/50 px-2 py-0.5 text-[9px] text-zinc-500">{contract.title} · {contract.openapi_version}</span>}
        </div>

        <div className="flex gap-2">
          <Input
            value={docsUrl}
            onChange={event => { setDocsUrl(event.target.value); setContract(null) }}
            placeholder="https://api.target.com/swagger/index.html"
            className="bg-zinc-900/80 text-sm flex-1"
            onKeyDown={event => { if (event.key === 'Enter' && !loadingSpec && !running) handleLoadSpec() }}
          />
          <button onClick={handleLoadSpec} disabled={!docsUrl.trim() || loadingSpec || running} className="h-9 shrink-0 rounded-md border border-teal-800 px-3 text-xs text-teal-300 hover:bg-teal-950/40 disabled:opacity-40 flex items-center gap-1.5">
            {loadingSpec ? <Loader2 size={11} className="animate-spin" /> : <FileJson2 size={11} />} Load spec
          </button>
          {running ? (
            <button onClick={handleStop} className="h-9 shrink-0 rounded-md border border-red-700 px-3 text-xs text-red-400 flex items-center gap-1.5"><Square size={11} className="fill-current" />Stop</button>
          ) : (
            <button onClick={handleRun} disabled={!contract || rows.length === 0} className="h-9 shrink-0 rounded-md border border-green-700 px-3 text-xs text-green-400 hover:bg-green-950/30 disabled:opacity-40 flex items-center gap-1.5"><Play size={11} />Scan</button>
          )}
        </div>

        <Input value={baseUrl} onChange={event => { setBaseUrl(event.target.value); setContract(null) }} placeholder="Base URL override (optional)" className="bg-zinc-900/80 text-xs" />

        <div className="flex items-center gap-4">
          <button onClick={() => setAuthOpen(open => !open)} className="flex items-center gap-1.5 text-[10px] text-cyan-400/80">
            <Lock size={11} /> Account auth {accountAuth.trim() && <Check size={10} className="text-green-400" />}{authOpen ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
          </button>
          <label className="flex items-center gap-1.5 text-[10px] text-zinc-400 cursor-pointer">
            <input type="checkbox" checked={aiAssist} onChange={event => setAiAssist(event.target.checked)} className="w-3 h-3 accent-teal-500" />
            <Sparkles size={10} className="text-teal-400" /> AI triage
          </label>
          <label className={cn('flex items-center gap-1.5 text-[10px] cursor-pointer', probeWrites ? 'text-amber-400' : 'text-zinc-500')}>
            <input type="checkbox" checked={probeWrites} onChange={event => setProbeWrites(event.target.checked)} className="w-3 h-3 accent-amber-500" />
            <AlertTriangle size={10} /> Include write methods
          </label>
          {contract && <a href={contract.spec_url} target="_blank" rel="noreferrer" className="ml-auto text-[9px] text-zinc-600 hover:text-teal-400 flex items-center gap-1">Contract source <ExternalLink size={9} /></a>}
        </div>

        {authOpen && (
          <textarea value={accountAuth} onChange={event => setAccountAuth(event.target.value)} rows={2} placeholder={"Authorization: Bearer eyJ...\nCookie: session=..."} className="w-full resize-none rounded border border-zinc-800 bg-zinc-900/80 px-2 py-1.5 font-mono text-[10px] text-zinc-300 focus:outline-none focus:border-cyan-800" />
        )}

        {rows.length > 0 && (
          <div className="flex items-center gap-3 border-t border-zinc-800/60 pt-2 text-[10px] text-zinc-500">
            <span>{rows.length} operations</span>
            <span className="text-green-400">{reachable} accepted anonymous</span>
            {inconclusive > 0 && <span className="text-amber-400">{inconclusive} input rejected</span>}
            {brokenAuth > 0 && <span className="font-semibold text-red-400">{brokenAuth} potential broken access</span>}
            {!probeWrites && <span className="ml-auto text-zinc-600">Read-only scan</span>}
          </div>
        )}
      </div>

      <div className="flex gap-1 rounded-lg bg-zinc-900/50 p-1">
        <button onClick={() => setView('results')} className={cn('rounded-md px-3 py-1.5 text-xs', view === 'results' ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-400')}>Operations {rows.length > 0 && <span className="ml-1 text-[9px] text-zinc-500">{rows.length}</span>}</button>
        <button onClick={() => setView('terminal')} className={cn('rounded-md px-3 py-1.5 text-xs flex items-center gap-1.5', view === 'terminal' ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-400')}><Terminal size={11} />Raw output{running && <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />}</button>
      </div>

      {view === 'terminal' && (
        <pre ref={termRef} className="flex-1 overflow-auto rounded-lg border border-zinc-800 bg-black p-4 font-mono text-[11px] leading-relaxed">
          {output.map((line, index) => <span key={index} className={cn('block', line.startsWith('$') ? 'font-bold text-green-400' : line.includes('inconclusive') ? 'text-amber-400' : line.includes('SECURED') ? 'text-red-400' : 'text-zinc-300')}>{line}</span>)}
          {running && output.length === 0 && <span className="text-zinc-600 animate-pulse">Starting scan...</span>}
          {!running && output.length === 0 && <span className="text-zinc-700">Load a contract, inspect requests, then scan.</span>}
        </pre>
      )}

      {view === 'results' && (
        <div className="flex-1 min-h-0 flex flex-col">
          <div className="flex gap-1 pb-2 overflow-x-auto">
            {FILTERS.map(item => <button key={item.id} onClick={() => setFilter(item.id)} className={cn('shrink-0 rounded border px-2 py-1 text-[10px]', filter === item.id ? 'border-teal-600 bg-teal-950/40 text-teal-300' : 'border-zinc-800 text-zinc-500')}>{item.label}{item.id !== 'all' && counts[item.id] ? ` ${counts[item.id]}` : ''}</button>)}
            <div className="relative ml-auto min-w-56">
              <Search size={11} className="absolute left-2 top-1/2 -translate-y-1/2 text-zinc-600" />
              <input value={search} onChange={event => setSearch(event.target.value)} placeholder="Filter method, path, tag" className="h-7 w-full rounded border border-zinc-800 bg-zinc-950 pl-7 pr-2 text-[10px] text-zinc-300 focus:outline-none focus:border-teal-800" />
            </div>
          </div>

          <div className="flex-1 min-h-0 grid grid-cols-[minmax(520px,1fr)_minmax(430px,0.85fr)] gap-3">
            <div className="overflow-auto rounded-lg border border-zinc-800">
              <table className="w-full text-xs">
                <thead className="sticky top-0 z-10 bg-zinc-900">
                  <tr className="text-left text-zinc-500">
                    <th className="w-20 px-3 py-2">Method</th>
                    <th className="px-3 py-2">Operation</th>
                    <th className="w-20 px-3 py-2">Anon</th>
                    <th className="w-20 px-3 py-2">Auth</th>
                    <th className="w-32 px-3 py-2">Assessment</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map(row => {
                    const key = rowKey(row)
                    return <tr key={key} onClick={() => setSelectedKey(key)} className={cn('cursor-pointer border-t border-zinc-800/60 hover:bg-zinc-800/35', selectedKey === key && 'bg-teal-950/15', row.probe_state === 'input_rejected' && 'bg-amber-950/10')}>
                      <td className="px-3 py-2"><span className={cn('rounded border px-1.5 py-0.5 font-mono text-[9px] font-bold', METHOD_COLOR[row.method] || METHOD_COLOR.HEAD)}>{row.method}</span></td>
                      <td className="px-3 py-2 min-w-0">
                        <div className="font-mono text-[10px] text-zinc-300 break-all">{row.path}</div>
                        {(row.summary || row.operation_id) && <div className="mt-0.5 text-[9px] text-zinc-600 truncate">{row.summary || row.operation_id}</div>}
                      </td>
                      <td className="px-3 py-2"><StatusPill row={row} /></td>
                      <td className="px-3 py-2"><StatusPill row={row} auth /></td>
                      <td className={cn('px-3 py-2 text-[9px]', row.probe_state === 'input_rejected' ? 'text-amber-400' : row.note.includes('SECURED') ? 'text-red-400' : 'text-zinc-600')}>{row.note}</td>
                    </tr>
                  })}
                  {shown.length === 0 && <tr><td colSpan={5} className="py-16 text-center text-xs text-zinc-600">{running ? <span className="inline-flex items-center gap-2"><Loader2 size={12} className="animate-spin" />Probing operations...</span> : 'No operations in this view.'}</td></tr>}
                </tbody>
              </table>
            </div>

            <div className="min-h-0 overflow-y-auto rounded-lg border border-zinc-800 bg-zinc-900/35">
              {selected && selectedDraft ? (
                <div className="p-4">
                  <div className="mb-4 flex items-start gap-2">
                    <span className={cn('rounded border px-2 py-1 font-mono text-[10px] font-bold', METHOD_COLOR[selected.method] || METHOD_COLOR.HEAD)}>{selected.method}</span>
                    <div className="min-w-0 flex-1">
                      <div className="font-mono text-sm text-zinc-100 break-all">{selected.path}</div>
                      <div className="mt-1 flex items-center gap-2">
                        {selected.auth_required ? <span className="inline-flex items-center gap-1 text-[9px] text-cyan-400"><ShieldCheck size={9} />Auth declared</span> : <span className="text-[9px] text-zinc-600">No auth declared</span>}
                        {selected.mutating && <span className="text-[9px] text-amber-400">May change data</span>}
                      </div>
                    </div>
                    <button onClick={() => setSelectedKey(null)} className="text-zinc-600 hover:text-zinc-300"><X size={13} /></button>
                  </div>
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
              ) : (
                <div className="h-full min-h-64 grid place-items-center px-8 text-center text-[11px] text-zinc-600">
                  Select an operation to inspect and edit its request contract.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )

  if (embedded) return body
  return <WorkspaceShell title="API Scanner" subtitle="Load the contract, inspect generated requests, then probe access control">{body}</WorkspaceShell>
}
