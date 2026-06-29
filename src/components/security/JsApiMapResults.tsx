import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { BookOpen, Check, Copy, ExternalLink, Filter, Info, Loader2, Network, Route, Search, Send, ShieldAlert, Sparkles, X } from 'lucide-react'
import type { Finding } from '@/types'
import { cn } from '@/lib/utils'
import { useWorkspaceStore } from '@/stores/workspace-store'
import { useAppStore } from '@/stores/app-store'
import { useApiScannerStore } from '@/stores/api-scanner-store'
import { api } from '@/api/http-client'
import { toast } from '@/stores/toast-store'

type MapView = 'privileged' | 'all' | 'roles'

interface MappedRoute {
  key: string
  method: string
  path: string
  source: string
  url: string
  privileged: boolean
  severity: Finding['severity']
  finding?: Finding
}

interface ProbeResult {
  loading: boolean
  status?: number
  headers?: Record<string, string>
  body?: string
  duration_ms?: number
  error?: string
}

const METHOD_COLOR: Record<string, string> = {
  GET: 'text-cyan-300 border-cyan-800/70 bg-cyan-950/30',
  POST: 'text-green-300 border-green-800/70 bg-green-950/30',
  PUT: 'text-amber-300 border-amber-800/70 bg-amber-950/30',
  PATCH: 'text-orange-300 border-orange-800/70 bg-orange-950/30',
  DELETE: 'text-red-300 border-red-800/70 bg-red-950/30',
}

function statusColor(status?: number) {
  if (status === undefined) return 'text-zinc-400 border-zinc-700 bg-zinc-900'
  if (status < 300) return 'text-green-300 border-green-800 bg-green-950/40'
  if (status < 400) return 'text-blue-300 border-blue-800 bg-blue-950/40'
  if (status < 500) return 'text-amber-300 border-amber-800 bg-amber-950/40'
  return 'text-red-300 border-red-800 bg-red-950/40'
}

// Builds the "account_auth" string the API Scanner adapter expects (one "Header: value" per line).
function buildAccountAuthString(cookies: string, extraHeaders: string): string {
  const lines: string[] = []
  if (cookies.trim()) lines.push(`Cookie: ${cookies.trim()}`)
  if (extraHeaders.trim()) lines.push(extraHeaders.trim())
  return lines.join('\n')
}

// Builds a flat headers dict from the sidebar's session Cookies + Extra Headers fields.
function buildSessionHeaders(cookies: string, extraHeaders: string): Record<string, string> {
  const headers: Record<string, string> = {}
  if (cookies.trim()) headers['Cookie'] = cookies.trim()
  for (const line of (extraHeaders || '').replace(/\r/g, '').split('\n')) {
    const idx = line.indexOf(':')
    if (idx === -1) continue
    const k = line.slice(0, idx).trim()
    const v = line.slice(idx + 1).trim()
    if (k) headers[k] = v
  }
  return headers
}

function parseMap(findings: Finding[]) {
  const summary = findings.find(f => f.template_id?.startsWith('jsmap-fw-') || f.template_id === 'jsmap-map' || f.title.includes('[JS API Map] Auth framework:') || f.title.includes('[JS API Map] Route map:'))
  const frameworkMatch = summary?.title.match(/Auth framework:\s*(.*?)\s*[—-]\s*(\d+) routes mapped/i)
  const frameworks = frameworkMatch?.[1]?.split(',').map(v => v.trim()).filter(Boolean) ?? []
  const routeMapMatch = summary?.title.match(/Route map:\s*(\d+) routes mapped/i)
  const mappedCount = Number(frameworkMatch?.[2] || routeMapMatch?.[1] || 0)
  const evidence = summary?.evidence || ''
  const basesLine = evidence.match(/API base candidates:\s*(.+)/i)?.[1] || ''
  const bases = basesLine.split(',').map(v => v.trim()).filter(Boolean)
  const routes = new Map<string, MappedRoute>()

  for (const line of evidence.split('\n')) {
    const match = line.match(/^\s*(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\S+)\s+\[([^\]]+)]/i)
    if (!match) continue
    const method = match[1].toUpperCase()
    const path = match[2]
    const source = match[3]
    const key = `${method}:${path}`
    routes.set(key, {
      key, method, path, source,
      url: `${summary?.url || bases[0] || ''}${path}`,
      privileged: false,
      severity: 'info',
    })
  }

  const privilegedFindings = findings.filter(f => f.template_id?.startsWith('jsmap-route-') || f.title.includes('[JS API Map] Privileged route:'))
  for (const finding of privilegedFindings) {
    const match = finding.title.match(/Privileged route:\s*(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(.+)$/i)
    if (!match) continue
    const method = match[1].toUpperCase()
    const path = match[2].trim()
    const source = finding.evidence?.match(/Source:\s*([^\n]+)/i)?.[1]?.trim() || 'detected'
    const key = `${method}:${path}`
    routes.set(key, {
      key, method, path, source,
      url: finding.url || `${summary?.url || bases[0] || ''}${path}`,
      privileged: true,
      severity: finding.severity,
      finding,
    })
  }

  const roleFindings = findings.filter(f => f.template_id === 'jsmap-roles' || f.title.includes('[JS API Map] Privileged role actions'))
  return { summary, frameworks, mappedCount: mappedCount || routes.size, bases, routes: [...routes.values()], roleFindings }
}

function commandRows(finding?: Finding) {
  if (!finding?.evidence) return []
  return finding.evidence.split('\n').flatMap(line => {
    const match = line.match(/^\s*(anon|user|admin):\s*(curl .+)$/i)
    return match ? [{ identity: match[1].toLowerCase(), command: match[2] }] : []
  })
}

export function JsApiMapResults({ findings, running }: { findings: Finding[]; running: boolean }) {
  const navigate = useNavigate()
  const addFinding = useWorkspaceStore(s => s.addFinding)
  const { sessionCookies, sessionHeaders, activeProject } = useAppStore()
  const hostGroups = useMemo(() => {
    const grouped = new Map<string, Finding[]>()
    for (const finding of findings) {
      let host = 'Unknown host'
      try { host = new URL(finding.url || '').hostname || host } catch {}
      grouped.set(host, [...(grouped.get(host) || []), finding])
    }
    return [...grouped.entries()]
      .map(([host, hostFindings]) => ({ host, findings: hostFindings, parsed: parseMap(hostFindings) }))
      .sort((a, b) => a.host.localeCompare(b.host))
  }, [findings])
  const [activeHost, setActiveHost] = useState<string | null>(null)
  const activeGroup = hostGroups.find(group => group.host === activeHost) || hostGroups[0]
  const parsed = activeGroup?.parsed || parseMap([])
  const [view, setView] = useState<MapView>('all')
  const [filter, setFilter] = useState('')
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [copied, setCopied] = useState<string | null>(null)
  const [basesInfoOpen, setBasesInfoOpen] = useState(false)
  const [probes, setProbes] = useState<Record<string, ProbeResult>>({})
  const [scopeAll, setScopeAll] = useState(false)
  const [includeWriteMethods, setIncludeWriteMethods] = useState(false)
  const [scanning, setScanning] = useState(false)

  const filteredRoutes = parsed.routes.filter(route => {
    if (view === 'privileged' && !route.privileged) return false
    const needle = filter.trim().toLowerCase()
    return !needle || `${route.method} ${route.path} ${route.source}`.toLowerCase().includes(needle)
  })
  const selected = parsed.routes.find(route => route.key === selectedKey) || filteredRoutes[0]
  const declaredCount = parsed.routes.filter(route => route.source === 'declared').length
  const inferredCount = parsed.routes.filter(route => route.source.startsWith('expanded:')).length

  const copy = (value: string) => {
    navigator.clipboard.writeText(value)
    setCopied(value)
    setTimeout(() => setCopied(null), 1200)
  }

  const sendRequest = async (route: MappedRoute) => {
    setProbes(prev => ({ ...prev, [route.key]: { loading: true } }))
    try {
      const headers = buildSessionHeaders(sessionCookies, sessionHeaders)
      const res = await api.post<{ status: number; headers: Record<string, string>; body: string; duration_ms: number }>(
        '/api/proxy/repeater',
        { method: route.method, url: route.url, headers },
      )
      setProbes(prev => ({ ...prev, [route.key]: { loading: false, ...res } }))
    } catch (err) {
      setProbes(prev => ({ ...prev, [route.key]: { loading: false, error: (err as Error).message || 'Request failed' } }))
    }
  }

  const privilegedRoutes = parsed.routes.filter(r => r.privileged)
  const bulkTargets = scopeAll ? parsed.routes : privilegedRoutes
  const baseUrl = parsed.bases[0] || ''

  const probeWithApiScanner = async () => {
    if (!bulkTargets.length) {
      toast.error('No routes to probe', 'No privileged routes were detected. Try "All routes".')
      return
    }
    if (!baseUrl) {
      toast.error('No API base detected', 'Check the "API bases" section to confirm the host.')
      return
    }
    setScanning(true)
    try {
      useApiScannerStore.getState().clear()
      await api.post('/api/api-scanner', {
        target: baseUrl,
        options: {
          base_url: baseUrl,
          endpoints: bulkTargets.map(r => ({ method: r.method, path: r.path, secured: r.privileged })),
          account_auth: buildAccountAuthString(sessionCookies, sessionHeaders),
          probe_writes: includeWriteMethods,
        },
        project_id: activeProject ?? '',
      })
      navigate('/scan?tab=api')
    } catch (err) {
      toast.error('No se pudo iniciar el API Scanner', err)
    } finally {
      setScanning(false)
    }
  }

  if (!findings.length) return (
    <div className="flex-1 rounded-lg border border-zinc-800 bg-zinc-950/40 flex flex-col items-center justify-center text-center px-6">
      <Route size={28} className={cn('mb-3', running ? 'text-teal-400 animate-pulse' : 'text-zinc-700')} />
      <div className="text-base font-medium text-zinc-300">{running ? 'Mapping JavaScript routes' : 'No API map yet'}</div>
      <div className="text-sm text-zinc-600 mt-1">Run the mapper against an application host or JavaScript bundle.</div>
    </div>
  )

  return (
    <div className="flex-1 min-h-0 flex flex-col gap-3">
      <div className="shrink-0 flex items-center gap-1.5 overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-950/60 p-1.5">
        <span className="px-2 text-[10px] font-semibold uppercase text-zinc-600 whitespace-nowrap">Hosts</span>
        {hostGroups.map(group => {
          const active = group.host === activeGroup?.host
          const privileged = group.parsed.routes.filter(route => route.privileged).length
          return <button key={group.host} onClick={() => { setActiveHost(group.host); setSelectedKey(null) }} className={cn('h-9 shrink-0 rounded-md border px-3 flex items-center gap-2 text-[11px] transition-colors', active ? 'border-teal-800 bg-teal-950/30 text-teal-300' : 'border-transparent text-zinc-500 hover:border-zinc-800 hover:text-zinc-300')}>
            <span className={cn('w-1.5 h-1.5 rounded-full', group.parsed.mappedCount > 0 ? 'bg-teal-400' : 'bg-zinc-700')} />
            <span className="font-mono">{group.host}</span>
            <span className="text-[10px] text-zinc-600">{group.parsed.mappedCount} routes{privileged > 0 ? ` · ${privileged} privileged` : ''}</span>
          </button>
        })}
      </div>

      <div className="grid grid-cols-2 xl:grid-cols-4 gap-px rounded-lg border border-zinc-800 bg-zinc-800 overflow-hidden shrink-0">
        <Metric label="Framework" value={parsed.frameworks.join(', ') || 'Unknown'} accent />
        <Metric label="Routes mapped" value={String(parsed.mappedCount)} />
        <Metric label="Privileged" value={String(parsed.routes.filter(r => r.privileged).length)} danger />
        <Metric label="Origin" value={`${declaredCount} declared / ${inferredCount} inferred`} />
      </div>

      {parsed.routes.length > 0 && (
        <div className="shrink-0 rounded-lg border border-teal-900/50 bg-teal-950/10 p-3 flex items-center gap-3 flex-wrap">
          <Network size={15} className="text-teal-400 shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="text-[12px] text-teal-300 font-medium">Test these routes with the API Scanner</div>
            <div className="text-[10px] text-zinc-600 leading-relaxed">
              Sends the routes to the bulk test engine (anonymous + your sidebar Session) and takes you to Scan → API Scanner with the results.
            </div>
          </div>
          <label className="flex items-center gap-1.5 text-[10px] text-zinc-400 cursor-pointer shrink-0">
            <input type="checkbox" checked={scopeAll} onChange={e => setScopeAll(e.target.checked)} className="w-3 h-3 accent-teal-500" />
            All ({parsed.routes.length}) — otherwise only privileged ({privilegedRoutes.length})
          </label>
          <label className="flex items-center gap-1.5 text-[10px] text-amber-400 cursor-pointer shrink-0" title="May create, update, or delete data. Bodies start as editable empty JSON when no schema is available.">
            <input type="checkbox" checked={includeWriteMethods} onChange={e => setIncludeWriteMethods(e.target.checked)} className="w-3 h-3 accent-amber-500" />
            Include writes
          </label>
          <button
            onClick={probeWithApiScanner}
            disabled={scanning || bulkTargets.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-medium rounded-md border border-teal-700/70 text-teal-300 hover:bg-teal-950/40 disabled:opacity-40 disabled:cursor-not-allowed transition-colors shrink-0"
          >
            {scanning ? <Loader2 size={12} className="animate-spin" /> : <Send size={12} />}
            Test {bulkTargets.length} route{bulkTargets.length === 1 ? '' : 's'}
          </button>
        </div>
      )}

      {parsed.bases.length > 0 && (
        <div className="shrink-0 rounded-lg border border-zinc-800 bg-zinc-950/40 px-3 py-2.5 space-y-1.5">
          <div className="flex items-center gap-1.5">
            <span className="text-[11px] text-zinc-500 uppercase font-semibold tracking-wide">API bases</span>
            <button onClick={() => setBasesInfoOpen(v => !v)} className="text-zinc-600 hover:text-teal-400 transition-colors">
              <Info size={12} />
            </button>
          </div>
          {basesInfoOpen && (
            <p className="text-[11px] text-zinc-500 leading-relaxed max-w-2xl">
              These are the root addresses the mapper found inside the site's JavaScript. Each one gets the
              "route" you see in the table below appended to build the full URL that gets tested. Example: if the base is{' '}
              <code className="text-teal-400">https://api.company.com</code> and the route is <code className="text-teal-400">/admin/users</code>,
              the final URL is <code className="text-teal-400">https://api.company.com/admin/users</code>. There can be several
              because the site sometimes uses more than one backend (e.g. one for the web app and another for services). Click one
              to copy it.
            </p>
          )}
          <div className="flex items-center gap-2 overflow-x-auto text-[11px] pt-0.5">
            {parsed.bases.map(base => <button key={base} onClick={() => copy(base)} className="font-mono text-teal-300 border border-teal-900/60 bg-teal-950/20 rounded px-2.5 py-1.5 hover:border-teal-700 whitespace-nowrap flex items-center gap-1.5">{copied === base ? <Check size={11} className="text-green-400" /> : null}{base}</button>)}
          </div>
        </div>
      )}

      <div className="flex-1 min-h-0 grid grid-cols-1 xl:grid-cols-[minmax(460px,1.3fr)_minmax(420px,1fr)] gap-3">
        <div className="min-h-[420px] rounded-lg border border-zinc-800 overflow-hidden flex flex-col">
          <div className="p-2.5 border-b border-zinc-800 bg-zinc-900/70 flex items-center gap-2 shrink-0">
            <div className="flex bg-zinc-950 rounded-md p-0.5">
              <ViewButton active={view === 'privileged'} onClick={() => setView('privileged')} label="Privileged" count={parsed.routes.filter(r => r.privileged).length} />
              <ViewButton active={view === 'all'} onClick={() => setView('all')} label="All routes" count={parsed.routes.length} />
              <ViewButton active={view === 'roles'} onClick={() => setView('roles')} label="Role model" count={parsed.roleFindings.length} />
            </div>
            {view !== 'roles' && <div className="relative ml-auto w-64">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-600" />
              <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter path, method, source" className="w-full h-8 pl-8 pr-2 rounded border border-zinc-800 bg-zinc-950 text-[12px] text-zinc-300 placeholder:text-zinc-700 focus:outline-none focus:border-teal-800" />
            </div>}
          </div>

          {view === 'roles' ? (
            <div className="overflow-y-auto p-3 space-y-2.5">
              {parsed.roleFindings.map(finding => <div key={finding.id} className="border border-zinc-800 rounded-lg p-3.5 bg-zinc-950/40"><div className="flex items-center gap-2"><ShieldAlert size={15} className="text-amber-400" /><span className="text-sm text-zinc-200">{finding.title.replace('[JS API Map] ', '')}</span></div><p className="text-[12px] text-zinc-500 mt-2 leading-relaxed">{finding.description}</p></div>)}
              {!parsed.roleFindings.length && <Empty text="No privileged role arrays were identified in the bundles." />}
            </div>
          ) : (
            <div className="overflow-y-auto">
              <div className="grid grid-cols-[84px_minmax(220px,1fr)_150px_90px] gap-3 px-3.5 py-2.5 bg-zinc-950 text-[10px] uppercase font-semibold text-zinc-600 sticky top-0 z-10">
                <span>Method</span><span>Route</span><span>Source</span><span>Risk</span>
              </div>
              {filteredRoutes.map(route => <button key={route.key} onClick={() => setSelectedKey(route.key)} className={cn('w-full grid grid-cols-[84px_minmax(220px,1fr)_150px_90px] gap-3 items-center px-3.5 py-3.5 text-left border-t border-zinc-800/70 hover:bg-zinc-900/60', selected?.key === route.key && 'bg-teal-950/15')}>
                <span className={cn('w-fit rounded border px-2 py-1 font-mono text-[10px] font-bold', METHOD_COLOR[route.method] || 'text-zinc-400 border-zinc-700')}>{route.method}</span>
                <span className="font-mono text-[13px] text-zinc-200 truncate">{route.path}</span>
                <span className={cn('text-[11px] truncate', route.source === 'declared' ? 'text-cyan-400' : 'text-zinc-500')}>{route.source === 'declared' ? 'In JavaScript' : route.source.replace('expanded:', 'Inferred: ')}</span>
                <span className={cn('text-[10px] font-semibold uppercase', route.severity === 'high' ? 'text-red-400' : route.severity === 'medium' ? 'text-amber-400' : 'text-zinc-600')}>{route.privileged ? route.severity : 'mapped'}</span>
              </button>)}
              {!filteredRoutes.length && <Empty text="No routes match this filter." />}
            </div>
          )}
        </div>

        <div className="min-h-[420px] rounded-lg border border-zinc-800 bg-zinc-900/30 overflow-y-auto">
          {selected && view !== 'roles' ? (
            <RouteDetail
              route={selected}
              copied={copied}
              onCopy={copy}
              onWorkspace={() => { if (selected.finding) { addFinding(selected.finding); navigate('/workspace') } }}
              onAnalyze={() => { if (selected.finding) { addFinding(selected.finding); navigate('/copilot') } }}
              probe={probes[selected.key]}
              onSend={() => sendRequest(selected)}
            />
          ) : <Empty text="Select a route to inspect its access-control test plan." />}
        </div>
      </div>
    </div>
  )
}

function Metric({ label, value, accent, danger }: { label: string; value: string; accent?: boolean; danger?: boolean }) {
  return <div className="bg-zinc-950 px-4 py-3.5 min-w-0"><div className={cn('text-lg font-semibold truncate', accent ? 'text-teal-300' : danger ? 'text-red-300' : 'text-zinc-200')}>{value}</div><div className="text-[11px] text-zinc-600 mt-1">{label}</div></div>
}

function ViewButton({ active, onClick, label, count }: { active: boolean; onClick: () => void; label: string; count: number }) {
  return <button onClick={onClick} className={cn('h-8 px-3 rounded text-[11px] flex items-center gap-1.5', active ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-500 hover:text-zinc-300')}>{label}<span className="text-[9px] text-zinc-600">{count}</span></button>
}

function Empty({ text }: { text: string }) {
  return <div className="min-h-32 flex items-center justify-center p-6 text-center text-[12px] text-zinc-600"><Filter size={14} className="mr-2" />{text}</div>
}

function ResponseBody({ probe }: { probe: ProbeResult }) {
  const [expanded, setExpanded] = useState(false)
  if (probe.loading) return <div className="flex items-center gap-2 text-[12px] text-zinc-400 py-3"><Loader2 size={13} className="animate-spin" /> Sending request...</div>
  if (probe.error) return <div className="text-[12px] text-red-400 py-2">Error: {probe.error}</div>
  if (probe.status === undefined) return null
  const ctype = probe.headers?.['content-type'] || probe.headers?.['Content-Type'] || ''
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <span className={cn('rounded border px-2 py-1 font-mono text-[11px] font-bold', statusColor(probe.status))}>{probe.status}</span>
        {ctype && <span className="text-[10px] text-zinc-500">{ctype.split(';')[0]}</span>}
        {probe.body !== undefined && <span className="text-[10px] text-zinc-600">{probe.body.length}B</span>}
        {probe.duration_ms !== undefined && <span className="text-[10px] text-zinc-600">{Math.round(probe.duration_ms)}ms</span>}
        <button onClick={() => setExpanded(true)} className="ml-auto text-[10px] text-teal-400/80 hover:text-teal-300">Expand</button>
      </div>
      {probe.body && (
        <pre className="text-[11px] text-zinc-400 bg-zinc-950 rounded p-2.5 overflow-auto max-h-48 whitespace-pre-wrap break-all leading-relaxed">{probe.body}</pre>
      )}
      {expanded && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4" onClick={() => setExpanded(false)}>
          <div className="w-full max-w-4xl max-h-[88vh] flex flex-col rounded-xl border border-zinc-700 bg-zinc-950 shadow-2xl overflow-hidden" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-5 py-3 border-b border-zinc-800 bg-zinc-900 shrink-0">
              <span className="text-sm font-semibold text-zinc-100">Response</span>
              <button onClick={() => setExpanded(false)} className="text-zinc-600 hover:text-zinc-300"><X size={14} /></button>
            </div>
            <pre className="overflow-auto p-4 text-[12px] leading-relaxed font-mono text-zinc-300 whitespace-pre-wrap break-all">{probe.body}</pre>
          </div>
        </div>
      )}
    </div>
  )
}

function RouteDetail({ route, copied, onCopy, onWorkspace, onAnalyze, probe, onSend }: {
  route: MappedRoute
  copied: string | null
  onCopy: (v: string) => void
  onWorkspace: () => void
  onAnalyze: () => void
  probe?: ProbeResult
  onSend: () => void
}) {
  const commands = commandRows(route.finding)
  return <div className="p-5 space-y-5">
    <div>
      <div className="flex items-center gap-2"><span className={cn('rounded border px-2 py-1 font-mono text-[10px] font-bold', METHOD_COLOR[route.method] || 'text-zinc-400 border-zinc-700')}>{route.method}</span><span className="text-[11px] text-zinc-600">{route.source}</span></div>
      <div className="font-mono text-base text-zinc-100 break-all mt-2">{route.path}</div>
      {route.url && <a href={route.url} target="_blank" rel="noreferrer" className="mt-1 inline-flex items-center gap-1 text-[11px] text-teal-400 hover:text-teal-300 break-all">{route.url}<ExternalLink size={10} /></a>}
    </div>

    <div className="rounded-lg border border-teal-900/50 bg-teal-950/10 p-3 space-y-2.5">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] text-teal-300 font-medium">Test this endpoint now</span>
        <button onClick={onSend} disabled={probe?.loading} className="flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-medium rounded-md border border-teal-700/70 text-teal-300 hover:bg-teal-950/40 disabled:opacity-40 transition-colors shrink-0">
          {probe?.loading ? <Loader2 size={12} className="animate-spin" /> : <Send size={12} />}
          {probe ? 'Resend' : 'Send request'}
        </button>
      </div>
      <p className="text-[10px] text-zinc-600 leading-relaxed">
        Sends a real {route.method} to this URL using the Session (cookies/headers) configured in the sidebar.
        Without a Session configured, the request goes out anonymous.
      </p>
      {probe && <ResponseBody probe={probe} />}
    </div>

    {route.finding?.description && <div><div className="text-[10px] uppercase font-semibold text-zinc-600 mb-1.5">Why it matters</div><p className="text-[12px] text-zinc-400 leading-relaxed">{route.finding.description}</p></div>}
    <div>
      <div className="text-[10px] uppercase font-semibold text-zinc-600 mb-2.5">Access-control matrix</div>
      <div className="space-y-2.5">{commands.map(row => <div key={row.identity} className="rounded border border-zinc-800 bg-zinc-950/70 p-2.5"><div className="flex items-center justify-between gap-2 mb-1.5"><span className={cn('text-[10px] font-semibold uppercase', row.identity === 'anon' ? 'text-zinc-400' : row.identity === 'user' ? 'text-cyan-400' : 'text-amber-400')}>{row.identity}</span><button title="Copy command" onClick={() => onCopy(row.command)} className="text-zinc-600 hover:text-zinc-300">{copied === row.command ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}</button></div><code className="text-[10px] text-zinc-500 break-all leading-relaxed">{row.command}</code></div>)}</div>
      {!commands.length && <p className="text-[11px] text-zinc-600">This route is mapped but has no generated test plan.</p>}
    </div>
    {route.finding && <div className="grid grid-cols-2 gap-2"><button onClick={onWorkspace} className="h-9 rounded border border-zinc-700 text-[11px] text-zinc-400 hover:text-zinc-200 flex items-center justify-center gap-1.5"><BookOpen size={12} />Workspace</button><button onClick={onAnalyze} className="h-9 rounded border border-teal-900 text-[11px] text-teal-400 hover:text-teal-300 flex items-center justify-center gap-1.5"><Sparkles size={12} />Analyze AI</button></div>}
  </div>
}
