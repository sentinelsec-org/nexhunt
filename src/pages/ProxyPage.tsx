import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { flowToRaw, useProxyStore } from '@/stores/proxy-store'
import { useAppStore } from '@/stores/app-store'
import { useWorkspaceStore } from '@/stores/workspace-store'
import { useLicenseStore } from '@/stores/license-store'
import { ProGate } from '@/components/layout/ProGate'
import { ContextMenu, menuFromEvent, type ContextMenuState } from '@/components/ui/context-menu'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { cn, getMethodColor, getStatusColor, formatBytes, formatDuration } from '@/lib/utils'
import { api } from '@/api/http-client'
import { toast } from '@/stores/toast-store'
import { PAYLOAD_SETS, CATEGORY_ORDER, type PayloadSet } from '@/lib/intruder-payloads'
import type { HttpFlow } from '@/types'
import type { RepeaterTab, IntruderResult } from '@/stores/proxy-store'
import { OAuthAttackTab } from '@/pages/proxy/OAuthAttackTab'
import {
  Play, Square, Shield, ShieldOff, Trash2, Search, Send,
  Plus, X, Repeat2, Crosshair, Filter, ChevronDown, ChevronRight,
  AlertTriangle, CheckCircle, Loader2, RotateCcw, BookOpen, Sparkles, Globe,
  Key, Copy, Check, ChevronUp, ExternalLink, Network, KeyRound, Folder, Crown, ShieldCheck, LogIn,
} from 'lucide-react'

type Tab = 'intercept' | 'history' | 'sitemap' | 'repeater' | 'intruder' | 'jwt' | 'oauth'

type PayloadSetConfig = {
  type: 'builtin' | 'custom' | 'numbers'
  builtinId: string
  custom: string
  numberStart: number
  numberEnd: number
  numberStep: number
  numberPad: number
  prefix: string
  suffix: string
  repeat: number
}

const newPayloadSet = (builtinId = 'fuzzing'): PayloadSetConfig => ({
  type: 'builtin', builtinId, custom: '',
  numberStart: 0, numberEnd: 100, numberStep: 1, numberPad: 0,
  prefix: '', suffix: '', repeat: 1,
})

function payloadValues(config: PayloadSetConfig): string[] {
  let values: string[] = []
  if (config.type === 'builtin') {
    values = PAYLOAD_SETS.find(item => item.id === config.builtinId)?.payloads ?? []
  } else if (config.type === 'custom') {
    values = config.custom.split(/\r?\n/).map(value => value.trim()).filter(Boolean)
  } else {
    const step = config.numberStep || 1
    const direction = config.numberEnd >= config.numberStart ? Math.abs(step) : -Math.abs(step)
    for (let value = config.numberStart; direction > 0 ? value <= config.numberEnd : value >= config.numberEnd; value += direction) {
      const sign = value < 0 ? '-' : ''
      values.push(sign + String(Math.abs(value)).padStart(Math.max(0, config.numberPad), '0'))
      if (values.length >= 100000) break
    }
  }
  const processed = values.map(value => `${config.prefix}${value}${config.suffix}`)
  const repeated: string[] = []
  for (let round = 0; round < Math.max(1, Math.min(config.repeat, 1000)) && repeated.length < 100000; round++) {
    repeated.push(...processed.slice(0, 100000 - repeated.length))
  }
  return repeated
}

// ── helpers ────────────────────────────────────────────────────────────────────
function statusBg(code: number) {
  if (!code) return 'text-zinc-600'
  if (code < 300) return 'text-green-400'
  if (code < 400) return 'text-yellow-400'
  if (code < 500) return 'text-orange-400'
  return 'text-red-400'
}

// ── ProxyPage ─────────────────────────────────────────────────────────────────
export function ProxyPage() {
  const [params] = useSearchParams()
  const isPro = useLicenseStore((s) => s.isPro())
  const [activeTab, setActiveTab] = useState<Tab>(() => {
    const t = params.get('tab')
    return (t === 'intercept' || t === 'history' || t === 'sitemap' || t === 'repeater' || t === 'intruder' || t === 'jwt') ? t : 'history'
  })
  const {
    flows, selectedFlowId, selectFlow,
    interceptEnabled, setInterceptEnabled,
    interceptScopeOnly, setInterceptScopeOnly,
    interceptQueue, setInterceptQueue, removeFromInterceptQueue,
    proxyRunning, setProxyRunning,
    filter, setFilter, clearFlows, mergeFlows,
    sendToRepeater, sendToIntruder, sendToJwt, sendToOauth, sendToBruteForce, sendToLoginBypass,
  } = useProxyStore()
  const { activeProjectData } = useAppStore()
  const navigate = useNavigate()
  const historyEpoch = useRef(0)

  const selectedFlow = flows.find(f => f.id === selectedFlowId)
  const scopeDomains: string[] = activeProjectData?.scope ?? []
  const outOfScopeDomains: string[] = activeProjectData?.out_of_scope ?? []

  useEffect(() => {
    api.get<{ running: boolean; intercept_enabled: boolean; intercept_scope_only: boolean }>('/api/proxy/status')
      .then(status => {
        setProxyRunning(status.running)
        setInterceptEnabled(status.intercept_enabled)
        setInterceptScopeOnly(status.intercept_scope_only)
      })
      .catch(() => {})
    api.get<HttpFlow[]>('/api/proxy/intercept/pending')
      .then(setInterceptQueue)
      .catch(() => {})
  }, [setProxyRunning, setInterceptEnabled, setInterceptScopeOnly, setInterceptQueue])

  useEffect(() => {
    if (!interceptScopeOnly) return
    api.post('/api/proxy/intercept/config', {
      scope_only: true,
      scope: scopeDomains,
      out_of_scope: outOfScopeDomains,
    }).catch(() => {})
    // Reconfigure when the user switches projects while Scope only is active.
  }, [activeProjectData?.id])

  useEffect(() => {
    let cancelled = false
    const hydrateHistory = async () => {
      const epoch = historyEpoch.current
      try {
        const persisted = await api.get<HttpFlow[]>('/api/proxy/history', { limit: '1000' })
        if (!cancelled && epoch === historyEpoch.current) mergeFlows(persisted)
      } catch {
        // Live WebSocket capture remains available if persistence hydration fails.
      }
    }
    hydrateHistory()
    const interval = proxyRunning ? window.setInterval(hydrateHistory, 5000) : null
    return () => {
      cancelled = true
      if (interval !== null) window.clearInterval(interval)
    }
  }, [proxyRunning, mergeFlows])

  // Scope filter: check host against active project domains
  const inScope = useCallback((host: string) => {
    if (!filter.scopeOnly || scopeDomains.length === 0) return true
    return scopeDomains.some(d => host === d || host.endsWith(`.${d}`))
  }, [filter.scopeOnly, scopeDomains])

  const filteredFlows = flows.filter(f => {
    if (!inScope(f.request_host)) return false
    if (filter.host && !f.request_host.includes(filter.host)) return false
    if (filter.method && f.request_method !== filter.method) return false
    if (filter.statusCode && String(f.response_status) !== filter.statusCode) return false
    if (filter.search) {
      const s = filter.search.toLowerCase()
      return f.request_url.toLowerCase().includes(s) || f.request_host.toLowerCase().includes(s)
    }
    return true
  })

  // Ctrl+R → Repeater, Ctrl+I → Intruder
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (!e.ctrlKey) return
      if (e.key === 'r' || e.key === 'R') {
        e.preventDefault()
        if (selectedFlow) { sendToRepeater(selectedFlow); setActiveTab('repeater') }
      }
      if (e.key === 'i' || e.key === 'I') {
        e.preventDefault()
        if (selectedFlow) { sendToIntruder(selectedFlow); setActiveTab('intruder') }
      }
    }
    window.addEventListener('keydown', handler, true)
    return () => window.removeEventListener('keydown', handler, true)
  }, [selectedFlow, sendToRepeater, sendToIntruder])

  const handleStartProxy = async () => {
    try { await api.post('/api/proxy/start'); setProxyRunning(true) }
    catch (err) { toast.error('Failed to start proxy', err) }
  }
  const handleStopProxy = async () => {
    try {
      await api.post('/api/proxy/stop')
      setProxyRunning(false)
      setInterceptEnabled(false)
      setInterceptQueue([])
    }
    catch (err) { toast.error('Failed to stop proxy', err) }
  }
  const handleToggleIntercept = async () => {
    try {
      if (!interceptEnabled && !proxyRunning) {
        await api.post('/api/proxy/start')
        setProxyRunning(true)
      }
      await api.post('/api/proxy/intercept/toggle', {
        enabled: !interceptEnabled,
        scope_only: interceptScopeOnly,
        scope: scopeDomains,
        out_of_scope: outOfScopeDomains,
      })
      setInterceptEnabled(!interceptEnabled)
      if (!interceptEnabled) setActiveTab('intercept')
      else setInterceptQueue([])
    } catch (err) { toast.error('Failed to toggle intercept', err) }
  }

  const handleScopeOnly = async () => {
    const next = !interceptScopeOnly
    try {
      await api.post('/api/proxy/intercept/config', {
        scope_only: next,
        scope: scopeDomains,
        out_of_scope: outOfScopeDomains,
      })
      setInterceptScopeOnly(next)
      if (next && scopeDomains.length === 0) {
        toast.warning('Scope only has no targets', 'Add domains to the active project scope; traffic will pass through until then.')
      }
    } catch (err) {
      toast.error('Failed to update intercept scope', err)
    }
  }

  const handleOpenBrowser = async () => {
    try {
      if (!proxyRunning) {
        await api.post('/api/proxy/start')
        setProxyRunning(true)
      }
      await api.post('/api/proxy/open-browser')
    }
    catch (err) { toast.error('Failed to open browser', err) }
  }

  const handleClearHistory = async () => {
    try {
      historyEpoch.current += 1
      await api.delete('/api/proxy/history')
      clearFlows()
    } catch (err) {
      toast.error('Failed to clear proxy history', err)
    }
  }

  return (
    <WorkspaceShell title="Proxy" subtitle="HTTP/HTTPS interception — Repeater — Intruder">
      <div className="flex flex-col h-full gap-3">
        {/* Toolbar */}
        <div className="flex items-center gap-2 shrink-0">
          {proxyRunning ? (
            <Button variant="destructive" size="sm" onClick={handleStopProxy}>
              <Square size={13} className="mr-1" /> Stop
            </Button>
          ) : (
            <Button size="sm" onClick={handleStartProxy}>
              <Play size={13} className="mr-1" /> Start Proxy
            </Button>
          )}
          <Button variant={interceptEnabled ? 'default' : 'outline'} size="sm" onClick={handleToggleIntercept}>
            {interceptEnabled
              ? <><Shield size={13} className="mr-1" /> Intercept ON{interceptQueue.length > 0 && ` · ${interceptQueue.length} held`}</>
              : <><ShieldOff size={13} className="mr-1" /> Intercept OFF</>}
          </Button>
          <button
            onClick={handleScopeOnly}
            className={cn(
              'h-8 px-2.5 rounded-md border text-[11px] font-medium flex items-center gap-1.5 transition-colors',
              interceptScopeOnly
                ? 'border-blue-700/70 bg-blue-950/40 text-blue-300'
                : 'border-zinc-700 text-zinc-500 hover:text-zinc-300'
            )}
            title={scopeDomains.length > 0
              ? `Only intercept: ${scopeDomains.join(', ')}`
              : 'No targets in the active project scope'}
          >
            <Filter size={12} /> Scope only
            <span className="font-mono text-[9px] opacity-70">{scopeDomains.length}</span>
          </button>

          {proxyRunning && (
            <span className="text-[10px] text-green-500 font-mono">● 127.0.0.1:8080</span>
          )}
          {proxyRunning && (
            <Button variant="outline" size="sm" onClick={handleOpenBrowser}
              className="border-zinc-700 text-xs gap-1" title="Open Chromium with proxy configured">
              <Globe size={12} /> Open Browser
            </Button>
          )}

          <div className="flex-1" />

          <div className="flex gap-1 bg-zinc-900 rounded-lg p-1">
            {([
              { id: 'intercept', label: 'Intercept', icon: Shield },
              { id: 'history', label: 'HTTP History', icon: Search },
              { id: 'sitemap', label: 'Site Map', icon: Network },
              { id: 'repeater', label: 'Repeater', icon: Repeat2 },
              { id: 'intruder', label: 'Intruder', icon: Crosshair },
              { id: 'jwt', label: 'JWT Attacks', icon: Key },
              { id: 'oauth', label: 'OAuth Attacks', icon: ShieldCheck },
            ] as { id: Tab; label: string; icon: React.FC<any> }[]).map(t => (
              <button key={t.id} onClick={() => setActiveTab(t.id as Tab)}
                className={cn('flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors',
                  activeTab === t.id ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200')}>
                <t.icon size={12} />
                {t.label}
                {t.id === 'intercept' && interceptQueue.length > 0 && (
                  <span className="ml-0.5 min-w-4 h-4 px-1 rounded-full bg-amber-500 text-[9px] font-bold text-zinc-950 grid place-items-center">
                    {interceptQueue.length}
                  </span>
                )}
                {t.id === 'jwt' && !isPro && <Crown size={11} className="text-amber-400" />}
              </button>
            ))}
          </div>

          <Button variant="ghost" size="icon" onClick={handleClearHistory} title="Clear history">
            <Trash2 size={13} />
          </Button>
        </div>

        {/* Content */}
        {activeTab === 'intercept' && (
          <InterceptTab
            queue={interceptQueue}
            enabled={interceptEnabled}
            removeFromQueue={removeFromInterceptQueue}
          />
        )}
        {activeTab === 'history' && (
          <HistoryTab
            filteredFlows={filteredFlows}
            selectedFlow={selectedFlow}
            filter={filter}
            setFilter={setFilter}
            selectFlow={selectFlow}
            selectedFlowId={selectedFlowId}
            proxyRunning={proxyRunning}
            scopeDomains={scopeDomains}
            sendToRepeater={(f) => { sendToRepeater(f); setActiveTab('repeater') }}
            sendToIntruder={(f) => { sendToIntruder(f); setActiveTab('intruder') }}
            sendToJwt={(f) => { sendToJwt(f); setActiveTab('jwt') }}
            sendToOauth={(f) => { sendToOauth(f); setActiveTab('oauth') }}
            sendToBruteForce={(f) => { sendToBruteForce(f); navigate('/offense?tab=brute') }}
            sendToLoginBypass={(f) => { sendToLoginBypass(f); navigate('/offense?tab=injection') }}
          />
        )}
        {activeTab === 'sitemap' && (
          <SiteMapTab
            flows={flows}
            selectedFlowId={selectedFlowId}
            selectFlow={selectFlow}
            scopeDomains={scopeDomains}
            sendToBruteForce={(f) => { sendToBruteForce(f); navigate('/offense?tab=brute') }}
          />
        )}
        {activeTab === 'repeater' && <RepeaterTab onOpenIntruder={() => setActiveTab('intruder')} />}
        {activeTab === 'intruder' && <IntruderTab />}
        {activeTab === 'jwt' && <ProGate feature="JWT Attack Suite"><JwtAttackTab /></ProGate>}
        {activeTab === 'oauth' && <ProGate feature="OAuth Attack Suite"><OAuthAttackTab /></ProGate>}
      </div>
    </WorkspaceShell>
  )
}

// ── Intercept tab ─────────────────────────────────────────────────────────────
function InterceptTab({ queue, enabled, removeFromQueue }: {
  queue: HttpFlow[]
  enabled: boolean
  removeFromQueue: (id: string) => void
}) {
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [drafts, setDrafts] = useState<Record<string, string>>({})
  const [releasing, setReleasing] = useState(false)
  const selected = queue.find(flow => flow.id === selectedId) ?? queue[0]
  const rawRequest = selected ? (drafts[selected.id] ?? flowToRaw(selected)) : ''

  useEffect(() => {
    if (queue.length === 0) {
      setSelectedId(null)
    } else if (!selectedId || !queue.some(flow => flow.id === selectedId)) {
      setSelectedId(queue[0].id)
    }
  }, [queue, selectedId])

  const release = useCallback(async (action: 'forward' | 'drop') => {
    if (!selected || releasing) return
    setReleasing(true)
    try {
      await api.post('/api/proxy/intercept/action', {
        flow_id: selected.id,
        action,
        modified_request: action === 'forward' ? rawRequest : null,
      })
      removeFromQueue(selected.id)
      setDrafts(current => {
        const next = { ...current }
        delete next[selected.id]
        return next
      })
    } catch (err) {
      toast.error(`Failed to ${action} request`, err)
    } finally {
      setReleasing(false)
    }
  }, [selected, releasing, rawRequest, removeFromQueue])

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.ctrlKey && event.key === 'Enter' && selected) {
        event.preventDefault()
        void release('forward')
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [release, selected])

  if (!selected) {
    return (
      <div className="flex-1 min-h-0 rounded-lg border border-zinc-800 bg-zinc-950 grid place-items-center">
        <div className="max-w-sm text-center px-6">
          <div className={cn(
            'mx-auto mb-4 h-12 w-12 rounded-xl border grid place-items-center',
            enabled ? 'border-amber-800/70 bg-amber-950/30 text-amber-400' : 'border-zinc-800 bg-zinc-900 text-zinc-600'
          )}>
            {enabled ? <Shield size={22} /> : <ShieldOff size={22} />}
          </div>
          <p className="text-sm font-semibold text-zinc-300">
            {enabled ? 'Intercept is armed' : 'Intercept is off'}
          </p>
          <p className="mt-1.5 text-xs leading-relaxed text-zinc-600">
            {enabled
              ? 'The next HTTP or HTTPS request will stop here before it reaches the server.'
              : 'Turn Intercept ON to hold requests for editing, forwarding, or dropping.'}
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="flex-1 min-h-0 flex overflow-hidden rounded-lg border border-amber-900/60 bg-zinc-950 shadow-[inset_3px_0_0_#f59e0b]">
      <aside className="w-72 shrink-0 border-r border-zinc-800 flex flex-col min-h-0">
        <div className="h-11 px-3 border-b border-zinc-800 bg-amber-950/20 flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-amber-400 opacity-60" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-amber-400" />
          </span>
          <span className="text-[10px] font-bold uppercase tracking-[0.18em] text-amber-400">Request held</span>
          <span className="ml-auto font-mono text-[10px] text-zinc-500">{queue.length} queued</span>
        </div>
        <div className="flex-1 overflow-auto">
          {queue.map((flow, index) => (
            <button
              key={flow.id}
              onClick={() => setSelectedId(flow.id)}
              className={cn(
                'w-full px-3 py-3 border-b border-zinc-800/70 text-left transition-colors',
                selected.id === flow.id ? 'bg-amber-950/25' : 'hover:bg-zinc-900'
              )}
            >
              <div className="flex items-center gap-2">
                <span className={cn('text-[10px] font-mono font-bold', getMethodColor(flow.request_method))}>{flow.request_method}</span>
                <span className="truncate text-[11px] font-mono text-zinc-400">{flow.request_host}</span>
                <span className="ml-auto text-[9px] font-mono text-zinc-700">{String(index + 1).padStart(2, '0')}</span>
              </div>
              <p className="mt-1 truncate text-[10px] font-mono text-zinc-600">{flow.request_path}</p>
            </button>
          ))}
        </div>
      </aside>

      <section className="flex-1 min-w-0 flex flex-col">
        <div className="h-11 px-3 border-b border-zinc-800 bg-zinc-900/60 flex items-center gap-2">
          <Badge variant="outline" className="border-amber-800/60 text-amber-400 text-[9px]">HELD</Badge>
          <span className="truncate font-mono text-xs text-zinc-300">{selected.request_host}{selected.request_path}</span>
          <span className="ml-auto text-[10px] text-zinc-600">Edit the raw request before forwarding</span>
        </div>
        <textarea
          value={rawRequest}
          onChange={event => setDrafts(current => ({ ...current, [selected.id]: event.target.value }))}
          spellCheck={false}
          className="flex-1 min-h-0 resize-none bg-[#08090b] p-4 font-mono text-[11px] leading-relaxed text-zinc-300 outline-none focus:bg-zinc-950"
        />
        <div className="h-14 px-3 border-t border-zinc-800 bg-zinc-900/80 flex items-center gap-2">
          <Button onClick={() => void release('forward')} disabled={releasing} size="sm" className="bg-amber-500 text-zinc-950 hover:bg-amber-400">
            {releasing ? <Loader2 size={13} className="mr-1.5 animate-spin" /> : <Send size={13} className="mr-1.5" />}
            Forward
          </Button>
          <Button onClick={() => void release('drop')} disabled={releasing} size="sm" variant="outline" className="border-red-900/70 text-red-400 hover:bg-red-950/30">
            <X size={13} className="mr-1.5" /> Drop
          </Button>
          <span className="ml-auto text-[10px] text-zinc-600"><kbd className="font-mono text-zinc-500">Ctrl + Enter</kbd> to forward</span>
        </div>
      </section>
    </div>
  )
}

// ── History tab ───────────────────────────────────────────────────────────────
function HistoryTab({ filteredFlows, selectedFlow, filter, setFilter, selectFlow, selectedFlowId, proxyRunning, scopeDomains, sendToRepeater, sendToIntruder, sendToJwt, sendToOauth, sendToBruteForce, sendToLoginBypass }: {
  filteredFlows: HttpFlow[]
  selectedFlow: HttpFlow | undefined
  filter: any
  setFilter: (f: any) => void
  selectFlow: (id: string | null) => void
  selectedFlowId: string | null
  proxyRunning: boolean
  scopeDomains: string[]
  sendToRepeater: (f: HttpFlow) => void
  sendToIntruder: (f: HttpFlow) => void
  sendToJwt: (f: HttpFlow) => void
  sendToOauth: (f: HttpFlow) => void
  sendToBruteForce: (f: HttpFlow) => void
  sendToLoginBypass: (f: HttpFlow) => void
}) {
  const [ctxMenu, setCtxMenu] = useState<ContextMenuState>({ visible: false, x: 0, y: 0 })
  const [ctxFlow, setCtxFlow] = useState<HttpFlow | null>(null)
  const { addHttpFlow } = useWorkspaceStore()
  const navigate = useNavigate()

  return (
    <div className="flex-1 flex flex-col gap-2 min-h-0">
      {/* Filter bar */}
      <div className="flex items-center gap-2 shrink-0">
        <div className="relative flex-1">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500" />
          <Input placeholder="Filter URL / host…" className="pl-8 h-7 text-xs bg-zinc-900"
            value={filter.search} onChange={e => setFilter({ search: e.target.value })} />
        </div>
        <Input placeholder="Host" className="w-28 h-7 text-xs bg-zinc-900"
          value={filter.host} onChange={e => setFilter({ host: e.target.value })} />
        <Input placeholder="Status" className="w-16 h-7 text-xs bg-zinc-900"
          value={filter.statusCode} onChange={e => setFilter({ statusCode: e.target.value })} />
        <select className="h-7 rounded-md border border-input bg-zinc-900 px-2 text-xs text-zinc-300"
          value={filter.method} onChange={e => setFilter({ method: e.target.value })}>
          <option value="">All Methods</option>
          {['GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD'].map(m => <option key={m}>{m}</option>)}
        </select>
        <button
          onClick={() => setFilter({ scopeOnly: !filter.scopeOnly })}
          className={cn('flex items-center gap-1 px-2 h-7 rounded-md border text-xs transition-colors',
            filter.scopeOnly
              ? 'border-blue-600 bg-blue-950/50 text-blue-400'
              : 'border-zinc-700 text-zinc-500 hover:text-zinc-300')}
          title={scopeDomains.length === 0 ? 'No scope set — configure in Projects' : `Scope: ${scopeDomains.join(', ')}`}
        >
          <Filter size={11} />
          Scope{scopeDomains.length > 0 && ` (${scopeDomains.length})`}
        </button>
      </div>

      {/* Table + detail */}
      <div className="flex-1 flex gap-3 min-h-0">
        <div className="flex-1 overflow-auto rounded-lg border border-zinc-800 min-h-0">
          <table className="w-full text-xs">
            <thead className="bg-zinc-900 sticky top-0 z-10">
              <tr className="text-zinc-500 text-left">
                <th className="px-2 py-2 w-8">#</th>
                <th className="px-2 py-2 w-14">Method</th>
                <th className="px-2 py-2 w-40">Host</th>
                <th className="px-2 py-2">Path</th>
                <th className="px-2 py-2 w-14">Status</th>
                <th className="px-2 py-2 w-16">Size</th>
                <th className="px-2 py-2 w-14">Time</th>
              </tr>
            </thead>
            <tbody>
              {filteredFlows.map((flow, idx) => (
                <tr key={flow.id}
                  onClick={() => selectFlow(flow.id)}
                  onContextMenu={e => { selectFlow(flow.id); setCtxFlow(flow); setCtxMenu(menuFromEvent(e)) }}
                  className={cn('cursor-pointer border-b border-zinc-800/50 hover:bg-zinc-800/30 transition-colors',
                    selectedFlowId === flow.id && 'bg-zinc-800/60')}>
                  <td className="px-2 py-1.5 text-zinc-600">{idx + 1}</td>
                  <td className={cn('px-2 py-1.5 font-mono font-bold text-[11px]', getMethodColor(flow.request_method))}>
                    {flow.request_method}
                  </td>
                  <td className="px-2 py-1.5 text-zinc-400 truncate max-w-[160px] font-mono text-[11px]">
                    {flow.request_host}
                  </td>
                  <td className="px-2 py-1.5 text-zinc-300 truncate max-w-[280px] font-mono text-[11px]">
                    {flow.request_path}
                  </td>
                  <td className={cn('px-2 py-1.5 font-mono font-semibold', getStatusColor(flow.response_status))}>
                    {flow.response_status || '—'}
                  </td>
                  <td className="px-2 py-1.5 text-zinc-500">{formatBytes(flow.response_length)}</td>
                  <td className="px-2 py-1.5 text-zinc-500">{formatDuration(flow.duration_ms)}</td>
                </tr>
              ))}
              {filteredFlows.length === 0 && (
                <tr><td colSpan={7} className="px-3 py-10 text-center text-zinc-600">
                  {proxyRunning ? 'Waiting for traffic… browse through the proxy.' : 'Start the proxy to capture traffic.'}
                </td></tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Detail panel */}
        {selectedFlow && (
          <div className="w-[440px] shrink-0 flex flex-col gap-2 min-h-0 overflow-auto">
            {/* Actions */}
            <div className="flex gap-1.5 shrink-0 flex-wrap">
              <Button size="sm" variant="outline" className="text-xs border-zinc-700 flex-1"
                onClick={() => sendToRepeater(selectedFlow)}>
                <Repeat2 size={12} className="mr-1" /> Repeater
              </Button>
              <Button size="sm" variant="outline" className="text-xs border-zinc-700 flex-1"
                onClick={() => sendToIntruder(selectedFlow)}>
                <Crosshair size={12} className="mr-1" /> Intruder
              </Button>
              <Button size="sm" variant="outline" className="text-xs border-red-800/60 text-red-400 hover:bg-red-950/20 flex-1"
                onClick={() => sendToJwt(selectedFlow)}>
                <Key size={12} className="mr-1" /> JWT Attacks
              </Button>
              <Button size="sm" variant="outline" className="text-xs border-amber-800/60 text-amber-400 hover:bg-amber-950/20 flex-1"
                onClick={() => sendToBruteForce(selectedFlow)}>
                <KeyRound size={12} className="mr-1" /> Brute Force
              </Button>
            </div>
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3 flex-1 overflow-auto">
              <p className="text-[10px] text-zinc-500 font-semibold uppercase mb-2">Request</p>
              <pre className="text-[11px] text-zinc-300 font-mono whitespace-pre-wrap break-all">
                {`${selectedFlow.request_method} ${selectedFlow.request_path} HTTP/1.1\nHost: ${selectedFlow.request_host}\n`}
                {selectedFlow.request_headers && Object.entries(selectedFlow.request_headers)
                  .filter(([k]) => k.toLowerCase() !== 'host')
                  .map(([k, v]) => `${k}: ${v}\n`).join('')}
                {selectedFlow.request_body && `\n${selectedFlow.request_body}`}
              </pre>
            </div>
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3 flex-1 overflow-auto">
              <p className="text-[10px] text-zinc-500 font-semibold uppercase mb-2">
                Response — <span className={statusBg(selectedFlow.response_status)}>{selectedFlow.response_status}</span>
              </p>
              <pre className="text-[11px] text-zinc-300 font-mono whitespace-pre-wrap break-all">
                {selectedFlow.response_headers && Object.entries(selectedFlow.response_headers)
                  .map(([k, v]) => `${k}: ${v}\n`).join('')}
                {selectedFlow.response_body && `\n${selectedFlow.response_body.slice(0, 8000)}`}
              </pre>
            </div>
          </div>
        )}
      </div>

      {/* Flow context menu */}
      <ContextMenu
        state={ctxMenu}
        onClose={() => setCtxMenu(s => ({ ...s, visible: false }))}
        items={[
          {
            label: 'Send to Workspace',
            icon: <BookOpen size={12} />,
            onClick: () => {
              if (ctxFlow) { addHttpFlow(ctxFlow); navigate('/workspace') }
            },
          },
          {
            label: 'Analyze with AI',
            icon: <Sparkles size={12} />,
            onClick: () => {
              if (ctxFlow) { addHttpFlow(ctxFlow); navigate('/workspace') }
            },
          },
          { separator: true },
          {
            label: 'Send to Repeater',
            icon: <Repeat2 size={12} />,
            onClick: () => { if (ctxFlow) sendToRepeater(ctxFlow) },
          },
          {
            label: 'Send to Intruder',
            icon: <Crosshair size={12} />,
            onClick: () => { if (ctxFlow) sendToIntruder(ctxFlow) },
          },
          {
            label: 'Send to JWT Attacks',
            icon: <Key size={12} />,
            onClick: () => { if (ctxFlow) sendToJwt(ctxFlow) },
          },
          {
            label: 'Send to OAuth Attacks',
            icon: <ShieldCheck size={12} />,
            onClick: () => { if (ctxFlow) sendToOauth(ctxFlow) },
          },
          {
            label: 'Send to Brute Force',
            icon: <KeyRound size={12} />,
            onClick: () => { if (ctxFlow) sendToBruteForce(ctxFlow) },
          },
          {
            label: 'Send to Login SQLi Bypass',
            icon: <LogIn size={12} />,
            onClick: () => { if (ctxFlow) sendToLoginBypass(ctxFlow) },
          },
        ]}
      />
    </div>
  )
}

// ── Site Map tab ────────────────────────────────────────────────────────────────
interface TreeNode {
  name: string
  fullPath: string
  children: Map<string, TreeNode>
  flows: HttpFlow[]
}

function buildSiteTree(flows: HttpFlow[]): Map<string, TreeNode> {
  const hosts = new Map<string, TreeNode>()
  for (const f of flows) {
    if (!hosts.has(f.request_host)) {
      hosts.set(f.request_host, { name: f.request_host, fullPath: f.request_host, children: new Map(), flows: [] })
    }
    let node = hosts.get(f.request_host)!
    const path = (f.request_path || '/').split('?')[0]
    const segs = path.split('/').filter(Boolean)
    let acc = f.request_host
    for (const seg of segs) {
      acc += '/' + seg
      if (!node.children.has(seg)) {
        node.children.set(seg, { name: seg, fullPath: acc, children: new Map(), flows: [] })
      }
      node = node.children.get(seg)!
    }
    node.flows.push(f)
  }
  return hosts
}

function SiteMapTab({ flows, selectedFlowId, selectFlow, scopeDomains, sendToBruteForce }: {
  flows: HttpFlow[]
  selectedFlowId: string | null
  selectFlow: (id: string | null) => void
  scopeDomains: string[]
  sendToBruteForce: (f: HttpFlow) => void
}) {
  const hasScope = scopeDomains.length > 0
  const [scopeOnly, setScopeOnly] = useState(hasScope)

  const inScope = (host: string) => {
    if (!scopeOnly || !hasScope) return true
    return scopeDomains.some(d => host === d || host.endsWith(`.${d}`))
  }

  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const visibleFlows = flows.filter(f => inScope(f.request_host))
  const tree = buildSiteTree(visibleFlows)
  const selectedFlow = flows.find(f => f.id === selectedFlowId)

  // Live re-send state — fresh response from hitting the endpoint again
  const [liveResp, setLiveResp] = useState<{ status: number; headers: Record<string, string>; body: string; duration_ms: number; error?: string } | null>(null)
  const [sending, setSending] = useState(false)

  // Reset the live response whenever a different endpoint is selected
  useEffect(() => { setLiveResp(null) }, [selectedFlowId])

  const handleSend = async () => {
    if (!selectedFlow) return
    setSending(true); setLiveResp(null)
    try {
      const raw = [
        `${selectedFlow.request_method} ${selectedFlow.request_path} HTTP/1.1`,
        `Host: ${selectedFlow.request_host}`,
        ...Object.entries(selectedFlow.request_headers ?? {})
          .filter(([k]) => k.toLowerCase() !== 'host')
          .map(([k, v]) => `${k}: ${v}`),
        '',
        selectedFlow.request_body ?? '',
      ].join('\n')
      const data = await api.post<any>('/api/proxy/repeat-raw', {
        raw_request: raw,
        host: selectedFlow.request_host,
        port: selectedFlow.request_port || (selectedFlow.request_url.startsWith('https') ? 443 : 80),
        use_https: selectedFlow.request_url.startsWith('https'),
      })
      setLiveResp(data)
    } catch (e: any) {
      setLiveResp({ status: 0, headers: {}, body: '', duration_ms: 0, error: String(e) })
    } finally {
      setSending(false)
    }
  }

  const toggle = (key: string) => setExpanded(s => {
    const next = new Set(s)
    next.has(key) ? next.delete(key) : next.add(key)
    return next
  })

  const renderNode = (node: TreeNode, depth: number): React.ReactNode => {
    const hasChildren = node.children.size > 0
    const isOpen = expanded.has(node.fullPath)
    const leafFlow = node.flows[0]
    return (
      <div key={node.fullPath}>
        <div
          className="flex items-center gap-1 py-1 pr-2 hover:bg-zinc-800/40 cursor-pointer text-xs"
          style={{ paddingLeft: depth * 14 + 6 }}
          onClick={() => { if (hasChildren) toggle(node.fullPath); if (leafFlow) selectFlow(leafFlow.id) }}>
          {hasChildren
            ? (isOpen ? <ChevronDown size={12} className="text-zinc-500 shrink-0" /> : <ChevronRight size={12} className="text-zinc-500 shrink-0" />)
            : <span className="w-3 shrink-0" />}
          {depth === 0
            ? <Globe size={12} className="text-blue-400 shrink-0" />
            : <Folder size={12} className="text-zinc-500 shrink-0" />}
          <span className={cn('truncate font-mono', depth === 0 ? 'text-zinc-200' : 'text-zinc-300')}>
            {depth === 0 ? node.name : `/${node.name}`}
          </span>
          {node.flows.length > 0 && (
            <span className={cn('ml-auto font-mono font-semibold text-[10px]', getStatusColor(leafFlow.response_status))}>
              {leafFlow.request_method} {leafFlow.response_status || ''}
            </span>
          )}
        </div>
        {hasChildren && isOpen && (
          <div>
            {Array.from(node.children.values())
              .sort((a, b) => a.name.localeCompare(b.name))
              .map(c => renderNode(c, depth + 1))}
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="flex-1 flex gap-3 min-h-0">
      <div className="w-[420px] shrink-0 flex flex-col rounded-lg border border-zinc-800 min-h-0">
        <div className="flex items-center justify-between px-3 py-1.5 border-b border-zinc-800 shrink-0">
          <span className="text-[10px] text-zinc-500 uppercase tracking-widest">
            {visibleFlows.length} request{visibleFlows.length !== 1 ? 's' : ''}
          </span>
          <button
            onClick={() => setScopeOnly(v => !v)}
            disabled={!hasScope}
            title={hasScope ? `Scope: ${scopeDomains.join(', ')}` : 'No scope configured in project'}
            className={cn(
              'text-[10px] px-2 py-0.5 rounded border transition-colors',
              scopeOnly && hasScope
                ? 'border-green-700 bg-green-950/40 text-green-400'
                : 'border-zinc-700 text-zinc-500 hover:text-zinc-300 disabled:opacity-40 disabled:cursor-not-allowed'
            )}>
            Scope{hasScope ? ` (${scopeDomains.length})` : ''}
          </button>
        </div>
        <div className="flex-1 overflow-auto">
        {tree.size === 0
          ? <p className="px-3 py-10 text-center text-zinc-600 text-xs">{scopeOnly && hasScope ? 'No in-scope traffic yet.' : 'No traffic captured yet.'}</p>
          : Array.from(tree.values()).sort((a, b) => a.name.localeCompare(b.name)).map(h => renderNode(h, 0))}
        </div>
      </div>

      <div className="flex-1 flex flex-col gap-2 min-h-0 overflow-auto">
        {selectedFlow ? (
          <>
            <div className="flex items-center gap-2 shrink-0">
              <Badge className={cn('font-mono', getMethodColor(selectedFlow.request_method))}>{selectedFlow.request_method}</Badge>
              <span className="text-xs text-zinc-400 font-mono truncate flex-1">{selectedFlow.request_host}{selectedFlow.request_path}</span>
              <span className={cn('font-mono font-semibold text-xs', statusBg(selectedFlow.response_status))}>{selectedFlow.response_status || '—'}</span>
              <Button size="sm" className="text-xs bg-blue-700 hover:bg-blue-600 text-white" onClick={handleSend} disabled={sending}>
                {sending ? <Loader2 size={12} className="mr-1 animate-spin" /> : <Send size={12} className="mr-1" />}
                Send
              </Button>
              <Button size="sm" variant="outline" className="text-xs border-amber-800/60 text-amber-400 hover:bg-amber-950/20"
                onClick={() => sendToBruteForce(selectedFlow)}>
                <KeyRound size={12} className="mr-1" /> Brute Force
              </Button>
            </div>
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3 overflow-auto max-h-[30%] shrink-0">
              <p className="text-[10px] text-zinc-500 font-semibold uppercase mb-2">Request</p>
              <pre className="text-[11px] text-zinc-300 font-mono whitespace-pre-wrap break-all">
                {`${selectedFlow.request_method} ${selectedFlow.request_path} HTTP/1.1\nHost: ${selectedFlow.request_host}\n`}
                {selectedFlow.request_headers && Object.entries(selectedFlow.request_headers)
                  .filter(([k]) => k.toLowerCase() !== 'host')
                  .map(([k, v]) => `${k}: ${v}\n`).join('')}
                {selectedFlow.request_body && `\n${selectedFlow.request_body}`}
              </pre>
            </div>
            {/* Response — live re-send if available, otherwise the captured one */}
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3 flex-1 overflow-auto min-h-0">
              {liveResp ? (
                <>
                  <p className="text-[10px] text-zinc-500 font-semibold uppercase mb-2 flex items-center gap-2">
                    Live response — <span className={statusBg(liveResp.status)}>{liveResp.status || 'error'}</span>
                    <span className="text-zinc-600 normal-case">{liveResp.duration_ms} ms · {formatBytes(liveResp.body.length)}</span>
                    <span className="ml-auto text-[9px] text-blue-400 normal-case">freshly sent</span>
                  </p>
                  {liveResp.error
                    ? <pre className="text-[11px] text-red-400 font-mono whitespace-pre-wrap break-all">{liveResp.error}</pre>
                    : <pre className="text-[11px] text-zinc-300 font-mono whitespace-pre-wrap break-all">
                        {Object.entries(liveResp.headers).map(([k, v]) => `${k}: ${v}\n`).join('')}
                        {liveResp.body && `\n${liveResp.body.slice(0, 20000)}`}
                      </pre>}
                </>
              ) : (
                <>
                  <p className="text-[10px] text-zinc-500 font-semibold uppercase mb-2">
                    Response — <span className={statusBg(selectedFlow.response_status)}>{selectedFlow.response_status || '—'}</span>
                    <span className="ml-2 text-zinc-600 normal-case">captured · press Send to re-issue</span>
                  </p>
                  {(selectedFlow.response_headers || selectedFlow.response_body) ? (
                    <pre className="text-[11px] text-zinc-300 font-mono whitespace-pre-wrap break-all">
                      {selectedFlow.response_headers && Object.entries(selectedFlow.response_headers)
                        .map(([k, v]) => `${k}: ${v}\n`).join('')}
                      {selectedFlow.response_body && `\n${selectedFlow.response_body.slice(0, 20000)}`}
                    </pre>
                  ) : (
                    <p className="text-[11px] text-zinc-600">No captured response body. Press <span className="text-blue-400">Send</span> to fetch it live.</p>
                  )}
                </>
              )}
            </div>
          </>
        ) : (
          <div className="h-full grid place-items-center text-zinc-600 text-sm">Select an endpoint in the tree</div>
        )}
      </div>
    </div>
  )
}

// ── Repeater tab ──────────────────────────────────────────────────────────────
function RepeaterTab({ onOpenIntruder }: { onOpenIntruder: () => void }) {
  const { repeaterTabs, activeRepeaterTabId, addRepeaterTab, closeRepeaterTab,
    setActiveRepeaterTab, updateRepeaterTab, sendRawToIntruder } = useProxyStore()

  const activeTab = repeaterTabs.find(t => t.id === activeRepeaterTabId)

  const handleSend = async () => {
    if (!activeTab) return
    updateRepeaterTab(activeTab.id, { loading: true, response: null })
    try {
      const data = await api.post<any>('/api/proxy/repeat-raw', {
        raw_request: activeTab.rawRequest,
        host: activeTab.host,
        port: activeTab.port,
        use_https: activeTab.useHttps,
      })
      updateRepeaterTab(activeTab.id, { loading: false, response: data })
    } catch (e: any) {
      updateRepeaterTab(activeTab.id, { loading: false, response: { status: 0, headers: {}, body: '', duration_ms: 0, error: String(e) } })
    }
  }

  if (repeaterTabs.length === 0) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center gap-3 text-zinc-600">
        <Repeat2 size={40} className="text-zinc-700" />
        <p className="text-sm">No repeater tabs open.</p>
        <p className="text-xs">Select a request in History and press <kbd className="bg-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded text-[11px]">Ctrl+R</kbd></p>
        <Button size="sm" variant="outline" onClick={addRepeaterTab}><Plus size={12} className="mr-1" /> New tab</Button>
      </div>
    )
  }

  return (
    <div className="flex-1 flex flex-col gap-2 min-h-0">
      {/* Tab bar */}
      <div className="flex items-center gap-1 shrink-0 overflow-x-auto">
        {repeaterTabs.map(tab => (
          <div key={tab.id} onClick={() => setActiveRepeaterTab(tab.id)}
            className={cn('flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs cursor-pointer border shrink-0 max-w-[160px] transition-colors',
              activeRepeaterTabId === tab.id
                ? 'bg-zinc-700 border-zinc-600 text-zinc-100'
                : 'bg-zinc-900 border-zinc-800 text-zinc-400 hover:text-zinc-200')}>
            <span className="truncate">{tab.label}</span>
            <button onClick={e => { e.stopPropagation(); closeRepeaterTab(tab.id) }}
              className="shrink-0 text-zinc-600 hover:text-zinc-300">
              <X size={10} />
            </button>
          </div>
        ))}
        <button onClick={addRepeaterTab}
          className="shrink-0 p-1.5 rounded-md border border-zinc-800 text-zinc-600 hover:text-zinc-400 hover:border-zinc-600">
          <Plus size={12} />
        </button>
      </div>

      {activeTab && (
        <div className="flex-1 flex flex-col gap-2 min-h-0">
          {/* Target bar */}
          <div className="flex items-center gap-2 shrink-0">
            <button onClick={() => updateRepeaterTab(activeTab.id, { useHttps: !activeTab.useHttps })}
              className={cn('px-2 py-1 rounded border text-xs font-mono font-bold shrink-0',
                activeTab.useHttps ? 'border-green-700 text-green-400 bg-green-950/30' : 'border-zinc-700 text-zinc-400')}>
              {activeTab.useHttps ? 'HTTPS' : 'HTTP'}
            </button>
            <Input className="flex-1 h-7 text-xs bg-zinc-900 font-mono" placeholder="host"
              value={activeTab.host}
              onChange={e => updateRepeaterTab(activeTab.id, { host: e.target.value })} />
            <Input className="w-20 h-7 text-xs bg-zinc-900 font-mono" placeholder="port"
              value={String(activeTab.port)}
              onChange={e => updateRepeaterTab(activeTab.id, { port: parseInt(e.target.value) || 80 })} />
            <Button size="sm" variant="outline" className="shrink-0 border-orange-800/60 text-orange-400" onClick={() => { sendRawToIntruder(activeTab.rawRequest, activeTab.host, activeTab.port, activeTab.useHttps); onOpenIntruder() }} title="Send the edited request to Intruder">
              <Crosshair size={12} className="mr-1" /> Intruder
            </Button>
            <Button size="sm" onClick={handleSend} disabled={activeTab.loading} className="shrink-0">
              {activeTab.loading ? <Loader2 size={12} className="animate-spin mr-1" /> : <Send size={12} className="mr-1" />}
              Send
            </Button>
          </div>

          {/* Request | Response */}
          <div className="flex-1 flex gap-3 min-h-0">
            <div className="flex-1 flex flex-col min-h-0">
              <p className="text-[10px] text-zinc-500 font-semibold uppercase mb-1 shrink-0">Request</p>
              <textarea
                className="flex-1 bg-zinc-900 border border-zinc-800 rounded-lg p-3 text-[11px] font-mono text-zinc-200 resize-none focus:outline-none focus:border-zinc-600 min-h-0"
                value={activeTab.rawRequest}
                onChange={e => updateRepeaterTab(activeTab.id, { rawRequest: e.target.value })}
                spellCheck={false}
              />
            </div>
            <div className="flex-1 flex flex-col min-h-0">
              <div className="flex items-center gap-2 mb-1 shrink-0">
                <p className="text-[10px] text-zinc-500 font-semibold uppercase">Response</p>
                {activeTab.response && (
                  <span className={cn('text-xs font-mono font-bold', statusBg(activeTab.response.status))}>
                    {activeTab.response.status || 'ERR'}
                  </span>
                )}
                {activeTab.response?.duration_ms ? (
                  <span className="text-[10px] text-zinc-600">{activeTab.response.duration_ms.toFixed(0)}ms</span>
                ) : null}
              </div>
              <div className="flex-1 bg-zinc-900 border border-zinc-800 rounded-lg p-3 overflow-auto min-h-0">
                {activeTab.loading && (
                  <div className="flex items-center gap-2 text-zinc-500 text-xs">
                    <Loader2 size={14} className="animate-spin" /> Sending…
                  </div>
                )}
                {!activeTab.loading && activeTab.response?.error && (
                  <p className="text-red-400 text-xs">{activeTab.response.error}</p>
                )}
                {!activeTab.loading && activeTab.response && !activeTab.response.error && (
                  <pre className="text-[11px] font-mono text-zinc-300 whitespace-pre-wrap break-all">
                    {Object.entries(activeTab.response.headers).map(([k, v]) => `${k}: ${v}\n`).join('')}
                    {'\n'}
                    {activeTab.response.body}
                  </pre>
                )}
                {!activeTab.loading && !activeTab.response && (
                  <p className="text-zinc-700 text-xs">Press Send to get a response.</p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Intruder tab ──────────────────────────────────────────────────────────────
function IntruderTab() {
  const {
    intruderRequest, intruderHost, intruderPort, intruderHttps,
    intruderResults, intruderRunning, intruderJobId, intruderTotal,
    setIntruderRequest, setIntruderTarget, clearIntruderResults, sendRawToRepeater,
  } = useProxyStore()

  const [subTab, setSubTab] = useState<'positions' | 'payloads' | 'results'>('positions')
  const [attackType, setAttackType] = useState<'sniper' | 'cluster_bomb' | 'pitchfork'>('sniper')
  const [payloadSets, setPayloadSets] = useState<PayloadSetConfig[]>([newPayloadSet('sqli-error')])
  const [concurrency, setConcurrency] = useState(10)
  const [timeout, setTimeout2] = useState(10)
  const [maxRequests, setMaxRequests] = useState(10000)
  const [filterStatus, setFilterStatus] = useState('')
  const [filterPayload, setFilterPayload] = useState('')
  const [selectedResult, setSelectedResult] = useState<IntruderResult | null>(null)
  const [resultDetail, setResultDetail] = useState<'request' | 'response'>('response')
  const textRef = useRef<HTMLTextAreaElement>(null)
  const resultsEndRef = useRef<HTMLDivElement>(null)

  // Auto-scroll results
  useEffect(() => {
    if (intruderRunning) resultsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [intruderResults.length, intruderRunning])

  // Count §markers§
  const markerCount = (intruderRequest.match(/§[^§\n]*§/g) || []).length

  const wrapSelection = () => {
    const ta = textRef.current
    if (!ta) return
    const start = ta.selectionStart
    const end = ta.selectionEnd
    const sel = intruderRequest.slice(start, end)
    const next = intruderRequest.slice(0, start) + '§' + sel + '§' + intruderRequest.slice(end)
    setIntruderRequest(next)
    setTimeout(() => {
      ta.focus()
      ta.setSelectionRange(start + 1, end + 1)
    }, 0)
  }

  const clearMarkers = () => setIntruderRequest(intruderRequest.replace(/§/g, ''))

  const getPayloads = (): string[][] => {
    return payloadSets.map(payloadValues)
  }

  const payloadCounts = payloadSets.map(ps => payloadValues(ps).length)
  const effectivePayloadCounts = Array.from(
    { length: markerCount },
    (_, index) => payloadCounts[index] ?? payloadCounts[payloadCounts.length - 1] ?? 0,
  )
  const estimatedRequests = markerCount === 0 ? 0 : attackType === 'sniper'
    ? markerCount * (payloadCounts[0] || 0)
    : attackType === 'pitchfork'
      ? Math.min(...effectivePayloadCounts)
      : effectivePayloadCounts.reduce((total, count) => total * Math.max(0, count), 1)

  const handleStart = async () => {
    clearIntruderResults()
    const payloads = getPayloads()
    await api.post('/api/proxy/intruder/start', {
      raw_request: intruderRequest,
      host: intruderHost,
      port: intruderPort,
      use_https: intruderHttps,
      attack_type: attackType,
      payloads,
      concurrency,
      timeout: timeout2,
      max_requests: maxRequests,
    })
    setSubTab('results')
  }

  const handleStop = async () => {
    if (intruderJobId) await api.delete(`/api/proxy/intruder/${intruderJobId}`)
  }

  // Filtered results
  const visibleResults = intruderResults.filter(result =>
    (!filterStatus || String(result.status).startsWith(filterStatus)) &&
    (!filterPayload || result.payload.toLowerCase().includes(filterPayload.toLowerCase()))
  )

  // Baseline: most common status in results
  const baselineStatus = intruderResults.length > 0
    ? Object.entries(intruderResults.reduce((acc, r) => {
        acc[r.status] = (acc[r.status] || 0) + 1; return acc
      }, {} as Record<number, number>)).sort((a, b) => b[1] - a[1])[0]?.[0]
    : null
  const baselineLength = intruderResults.length > 0
    ? Math.round(intruderResults.reduce((s, r) => s + r.length, 0) / intruderResults.length)
    : 0

  const isInteresting = (r: IntruderResult) =>
    (baselineStatus !== null && String(r.status) !== baselineStatus) ||
    (baselineLength > 0 && Math.abs(r.length - baselineLength) > baselineLength * 0.1)

  const timeout2 = timeout

  return (
    <div className="flex-1 flex flex-col gap-2 min-h-0">
      {/* Target + controls */}
      <div className="flex items-center gap-2 shrink-0">
        <button onClick={() => setIntruderTarget(intruderHost, intruderPort, !intruderHttps)}
          className={cn('px-2 py-1 rounded border text-xs font-mono font-bold shrink-0',
            intruderHttps ? 'border-green-700 text-green-400 bg-green-950/30' : 'border-zinc-700 text-zinc-400')}>
          {intruderHttps ? 'HTTPS' : 'HTTP'}
        </button>
        <Input className="flex-1 h-7 text-xs bg-zinc-900 font-mono" placeholder="host"
          value={intruderHost}
          onChange={e => setIntruderTarget(e.target.value, intruderPort, intruderHttps)} />
        <Input className="w-16 h-7 text-xs bg-zinc-900 font-mono" placeholder="port"
          value={String(intruderPort)}
          onChange={e => setIntruderTarget(intruderHost, parseInt(e.target.value) || 80, intruderHttps)} />
        <select value={attackType} onChange={e => setAttackType(e.target.value as any)}
          className="h-7 rounded-md border border-zinc-700 bg-zinc-900 px-2 text-xs text-zinc-300">
          <option value="sniper">Sniper</option>
          <option value="pitchfork">Pitchfork</option>
          <option value="cluster_bomb">Cluster Bomb</option>
        </select>
        {intruderRunning ? (
          <Button size="sm" variant="destructive" onClick={handleStop} className="shrink-0">
            <Square size={12} className="mr-1" /> Stop
          </Button>
        ) : (
          <Button size="sm" onClick={handleStart}
            disabled={!intruderHost || markerCount === 0}
            className="shrink-0 bg-orange-600 hover:bg-orange-500 text-white">
            <Play size={12} className="mr-1" /> Attack
          </Button>
        )}
        {intruderRunning && (
          <span className="text-xs text-orange-400 font-mono shrink-0">
            {intruderResults.length}/{intruderTotal}
          </span>
        )}
      </div>

      {/* Sub-tabs */}
      <div className="flex gap-1 bg-zinc-900 rounded-md p-0.5 w-fit shrink-0">
        {([
          { id: 'positions', label: `Positions${markerCount > 0 ? ` (${markerCount})` : ''}` },
          { id: 'payloads', label: 'Payloads' },
          { id: 'results', label: `Results${intruderResults.length > 0 ? ` (${intruderResults.length})` : ''}` },
        ] as { id: string; label: string }[]).map(t => (
          <button key={t.id} onClick={() => setSubTab(t.id as any)}
            className={cn('px-3 py-1 text-xs font-medium rounded transition-colors',
              subTab === t.id ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200')}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Positions sub-tab */}
      {subTab === 'positions' && (
        <div className="flex-1 flex flex-col gap-2 min-h-0">
          <div className="flex gap-2 shrink-0">
            <Button size="sm" variant="outline" className="text-xs border-zinc-700" onClick={wrapSelection}>
              Add § § around selection
            </Button>
            <Button size="sm" variant="ghost" className="text-xs text-zinc-500" onClick={clearMarkers}>
              <RotateCcw size={11} className="mr-1" /> Clear markers
            </Button>
            {markerCount > 0 && (
              <span className="text-xs text-orange-400 self-center">{markerCount} position{markerCount !== 1 ? 's' : ''} marked</span>
            )}
          </div>
          <div className="text-[10px] text-zinc-600 shrink-0">
            Highlight text and click "Add § §" to mark a position, or type § manually. Each §value§ will be replaced by payloads.
          </div>
          <textarea
            ref={textRef}
            className="flex-1 bg-zinc-900 border border-zinc-800 rounded-lg p-3 text-[11px] font-mono text-zinc-200 resize-none focus:outline-none focus:border-orange-700 min-h-0"
            value={intruderRequest}
            onChange={e => setIntruderRequest(e.target.value)}
            placeholder={'GET /?q=§value§ HTTP/1.1\nHost: example.com\n\n'}
            spellCheck={false}
          />
        </div>
      )}

      {/* Payloads sub-tab */}
      {subTab === 'payloads' && (
        <div className="flex-1 overflow-auto space-y-3">
          <div className="flex items-center gap-3">
            <span className="text-xs text-zinc-400">Concurrency</span>
            <input type="number" min={1} max={50} value={concurrency}
              onChange={e => setConcurrency(parseInt(e.target.value) || 1)}
              className="w-16 h-7 bg-zinc-900 border border-zinc-800 rounded px-2 text-xs text-zinc-300" />
            <span className="text-xs text-zinc-400">Timeout (s)</span>
            <input type="number" min={1} max={60} value={timeout}
              onChange={e => setTimeout2(parseInt(e.target.value) || 10)}
              className="w-16 h-7 bg-zinc-900 border border-zinc-800 rounded px-2 text-xs text-zinc-300" />
            <span className="text-xs text-zinc-400">Max requests</span>
            <input type="number" min={1} max={100000} value={maxRequests}
              onChange={e => setMaxRequests(Math.max(1, Math.min(100000, parseInt(e.target.value) || 1)))}
              className="w-24 h-7 bg-zinc-900 border border-zinc-800 rounded px-2 text-xs text-zinc-300" />
            <span className={cn('text-[10px] ml-auto', estimatedRequests > maxRequests ? 'text-amber-400' : 'text-zinc-500')}>
              {estimatedRequests.toLocaleString()} planned{estimatedRequests > maxRequests ? `, capped at ${maxRequests.toLocaleString()}` : ''}
            </span>
          </div>

          {/* How payload sets map to positions — depends on the attack type */}
          <div className="rounded border border-zinc-800 bg-zinc-900/40 p-2.5 text-[11px] text-zinc-400 space-y-1">
            {markerCount === 0 ? (
              <p className="text-amber-400">Mark at least one §position§ in the Positions tab first.</p>
            ) : attackType === 'sniper' ? (
              <>
                <p><span className="text-zinc-200 font-medium">Sniper</span> uses <span className="text-zinc-200">one</span> payload list, applied to each of the {markerCount} marked position{markerCount > 1 ? 's' : ''} one at a time.</p>
                {markerCount > 1 && (
                  <p>Want a different list per position? Switch to{' '}
                    <button onClick={() => setAttackType('cluster_bomb')} className="text-orange-400 hover:underline">Cluster Bomb</button>{' or '}
                    <button onClick={() => setAttackType('pitchfork')} className="text-orange-400 hover:underline">Pitchfork</button>, then use <span className="text-zinc-200">Add payload set</span> below.
                  </p>
                )}
              </>
            ) : (
              <p><span className="text-zinc-200 font-medium">{attackType === 'cluster_bomb' ? 'Cluster Bomb' : 'Pitchfork'}</span> uses one payload list per position — {payloadSets.length}/{markerCount} configured. Use <span className="text-zinc-200">Add payload set</span> below to add one per marked position.</p>
            )}
          </div>

          {payloadSets.map((ps, idx) => (
            <PayloadSetEditor
              key={idx}
              index={idx}
              ps={ps}
              attackType={attackType}
              onChange={updated => setPayloadSets(prev => prev.map((p, i) => i === idx ? updated : p))}
              onRemove={payloadSets.length > 1 ? () => setPayloadSets(prev => prev.filter((_, i) => i !== idx)) : undefined}
            />
          ))}

          {(attackType === 'cluster_bomb' || attackType === 'pitchfork') && payloadSets.length < markerCount && (
            <Button size="sm" variant="outline" className="text-xs border-zinc-700" onClick={() =>
              setPayloadSets(prev => [...prev, newPayloadSet('fuzzing')])}>
              <Plus size={11} className="mr-1" /> Add payload set (Position {payloadSets.length + 1})
            </Button>
          )}
        </div>
      )}

      {/* Results sub-tab */}
      {subTab === 'results' && (
        <div className="flex-1 flex flex-col gap-2 min-h-0">
          <div className="flex items-center gap-2 shrink-0">
            <Input placeholder="Filter status…" className="w-24 h-7 text-xs bg-zinc-900"
              value={filterStatus} onChange={e => setFilterStatus(e.target.value)} />
            <Input placeholder="Filter payload…" className="w-48 h-7 text-xs bg-zinc-900"
              value={filterPayload} onChange={e => setFilterPayload(e.target.value)} />
            {intruderResults.length > 0 && (
              <span className="text-xs text-zinc-500">
                {intruderResults.length} results
                {baselineStatus && <> · baseline: <span className={statusBg(parseInt(baselineStatus))}>{baselineStatus}</span></>}
                {baselineLength > 0 && <> · avg length: {baselineLength}b</>}
              </span>
            )}
            <Button size="sm" variant="ghost" className="text-xs text-zinc-600 ml-auto" onClick={() => { clearIntruderResults(); setSelectedResult(null) }}>
              <Trash2 size={11} className="mr-1" /> Clear
            </Button>
          </div>
          <div className="flex-1 grid grid-cols-[minmax(410px,1fr)_minmax(360px,0.9fr)] gap-2 min-h-0">
            <div className="overflow-auto rounded-lg border border-zinc-800 min-h-0">
              <table className="w-full text-xs">
                <thead className="bg-zinc-900 sticky top-0 z-10">
                  <tr className="text-zinc-500 text-left">
                    <th className="px-2 py-2 w-10">#</th>
                    <th className="px-2 py-2">Payload</th>
                    <th className="px-2 py-2 w-16">Status</th>
                    <th className="px-2 py-2 w-16">Length</th>
                    <th className="px-2 py-2 w-16">Time</th>
                    <th className="px-2 py-2 w-8"></th>
                  </tr>
                </thead>
                <tbody>
                  {visibleResults.map((r) => {
                    const interesting = isInteresting(r)
                    return (
                      <tr key={r.index} onClick={() => setSelectedResult(r)}
                        className={cn('border-b border-zinc-800/50 hover:bg-zinc-800/40 cursor-pointer',
                          interesting && 'bg-yellow-950/20', selectedResult?.index === r.index && 'bg-orange-950/30 outline outline-1 outline-inset outline-orange-900')}>
                        <td className="px-2 py-1.5 text-zinc-600">{r.index + 1}</td>
                        <td className="px-2 py-1.5 font-mono text-[11px] text-zinc-300 truncate max-w-[240px]">{r.payload}</td>
                        <td className={cn('px-2 py-1.5 font-mono font-semibold', statusBg(r.status))}>
                          {r.error ? <span className="text-red-500">ERR</span> : r.status || '—'}
                        </td>
                        <td className="px-2 py-1.5 text-zinc-400 font-mono">{r.error ? '—' : r.length}</td>
                        <td className="px-2 py-1.5 text-zinc-500">{r.error ? '—' : `${r.duration_ms.toFixed(0)}ms`}</td>
                        <td className="px-2 py-1.5">
                          {interesting && !r.error && <AlertTriangle size={11} className="text-yellow-500" />}
                          {r.error && <span className="text-[10px] text-red-500" title={r.error}>!</span>}
                        </td>
                      </tr>
                    )
                  })}
                  {intruderResults.length === 0 && !intruderRunning && (
                    <tr><td colSpan={6} className="px-3 py-8 text-center text-zinc-600">Mark positions, configure payloads, then click Attack.</td></tr>
                  )}
                  {intruderRunning && intruderResults.length === 0 && (
                    <tr><td colSpan={6} className="px-3 py-4 text-center text-zinc-500"><Loader2 size={14} className="animate-spin inline mr-2" />Attacking…</td></tr>
                  )}
                </tbody>
              </table>
              <div ref={resultsEndRef} />
            </div>

            <div className="rounded-lg border border-zinc-800 bg-zinc-950 min-h-0 overflow-hidden flex flex-col">
              {selectedResult ? (
                <>
                  <div className="px-3 py-2 border-b border-zinc-800 bg-zinc-900/70 flex items-center gap-3 shrink-0">
                    <span className={cn('text-sm font-mono font-bold', statusBg(selectedResult.status))}>{selectedResult.error ? 'ERR' : selectedResult.status}</span>
                    <span className="text-[10px] text-zinc-500 truncate flex-1" title={selectedResult.payload}>{selectedResult.payload}</span>
                    <button className="text-[10px] text-zinc-400 hover:text-zinc-100 flex items-center gap-1" onClick={() => navigator.clipboard.writeText(resultDetail === 'request' ? selectedResult.request : `${Object.entries(selectedResult.response_headers).map(([key, value]) => `${key}: ${value}`).join('\n')}\n\n${selectedResult.response_body}`)}><Copy size={10} />Copy</button>
                    <button className="text-[10px] text-orange-400 hover:text-orange-300 flex items-center gap-1" onClick={() => { sendRawToRepeater(selectedResult.request, intruderHost, intruderPort, intruderHttps); toast.success('Request opened in Repeater') }}><Repeat2 size={10} />Repeater</button>
                  </div>
                  <div className="px-3 pt-2 flex items-center justify-between shrink-0">
                    <div className="flex rounded bg-zinc-900 p-0.5">
                      {(['request', 'response'] as const).map(detail => <button key={detail} onClick={() => setResultDetail(detail)} className={cn('px-3 py-1 rounded text-[10px] capitalize', resultDetail === detail ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-500 hover:text-zinc-300')}>{detail}</button>)}
                    </div>
                    <span className="text-[9px] text-zinc-600">{selectedResult.length} bytes · {selectedResult.duration_ms.toFixed(0)} ms</span>
                  </div>
                  <div className="flex-1 min-h-0 overflow-auto p-3">
                    {resultDetail === 'request' ? (
                      <pre className="text-[10px] leading-relaxed font-mono text-zinc-300 whitespace-pre-wrap break-all">{selectedResult.request || '(request unavailable)'}</pre>
                    ) : selectedResult.error ? (
                      <pre className="text-[10px] font-mono text-red-400 whitespace-pre-wrap">{selectedResult.error}</pre>
                    ) : (
                      <div className="space-y-3">
                        <div><p className="text-[9px] uppercase font-semibold text-zinc-600 mb-1">Headers</p><pre className="text-[10px] leading-relaxed font-mono text-sky-300 whitespace-pre-wrap break-all">{Object.entries(selectedResult.response_headers).map(([key, value]) => `${key}: ${value}`).join('\n') || '(no headers)'}</pre></div>
                        <div><p className="text-[9px] uppercase font-semibold text-zinc-600 mb-1">Body</p><pre className="text-[10px] leading-relaxed font-mono text-zinc-300 whitespace-pre-wrap break-all">{selectedResult.response_body || '(empty body)'}</pre></div>
                      </div>
                    )}
                  </div>
                </>
              ) : <div className="flex-1 grid place-items-center text-center px-8"><div><Search size={20} className="mx-auto text-zinc-700 mb-2" /><p className="text-xs text-zinc-500">Select a result to inspect the complete request and response.</p></div></div>}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── JwtAttackTab ──────────────────────────────────────────────────────────────
const SEV_BADGE: Record<string, string> = {
  critical: 'bg-red-900/60 text-red-300 border border-red-700/50',
  high:     'bg-orange-900/60 text-orange-300 border border-orange-700/50',
  medium:   'bg-yellow-900/60 text-yellow-300 border border-yellow-700/50',
  info:     'bg-zinc-800 text-zinc-400 border border-zinc-700',
}
const SEV_ROW: Record<string, string> = {
  critical: 'border-red-900/40 hover:bg-red-950/10',
  high:     'border-orange-900/40 hover:bg-orange-950/10',
  medium:   'border-yellow-900/40 hover:bg-yellow-950/10',
  info:     'border-zinc-800 hover:bg-zinc-800/30',
}

const ATTACK_DISPLAY = [
  { id: 'alg_none',        name: 'alg:none',                  severity: 'critical' },
  { id: 'empty_sig',       name: 'Empty Signature',           severity: 'critical' },
  { id: 'tampered_payload',name: 'Tampered Payload',          severity: 'high' },
  { id: 'key_confusion',   name: 'RS256 → HS256 Confusion',   severity: 'critical' },
  { id: 'weak_secret',     name: 'Weak Secret Brute Force',   severity: 'critical' },
  { id: 'kid_injection',   name: 'kid Header Injection',      severity: 'high' },
  { id: 'jku_ssrf',        name: 'jku / x5u SSRF',            severity: 'high' },
  { id: 'priv_esc',        name: 'Privilege Escalation',      severity: 'high' },
  { id: 'expired_reuse',   name: 'Expired Token Reuse',       severity: 'medium' },
  { id: 'null_token',      name: 'Null / Malformed Token',    severity: 'medium' },
]

function JwtAttackTab() {
  const [token, setToken] = useState('')
  const [targetUrl, setTargetUrl] = useState('')
  const [headerName, setHeaderName] = useState('Authorization')
  const [publicKey, setPublicKey] = useState('')
  const [wordlist, setWordlist] = useState('')
  const [decoded, setDecoded] = useState<any>(null)
  const [decodeError, setDecodeError] = useState('')
  const [selectedAttack, setSelectedAttack] = useState<string | null>(null)
  const [attackResults, setAttackResults] = useState<Record<string, any>>({})
  const [running, setRunning] = useState<Record<string, boolean>>({})
  const [copiedToken, setCopiedToken] = useState<string | null>(null)
  const [customHeader, setCustomHeader] = useState('')
  const [customPayload, setCustomPayload] = useState('')
  const [signingMode, setSigningMode] = useState<'keep_signature' | 'none' | 'hmac'>('keep_signature')
  const [hmacAlgorithm, setHmacAlgorithm] = useState<'HS256' | 'HS384' | 'HS512'>('HS256')
  const [hmacSecret, setHmacSecret] = useState('')
  const [headerValueTemplate, setHeaderValueTemplate] = useState('Bearer {token}')
  const [forgeResult, setForgeResult] = useState<any>(null)
  const [forgeRunning, setForgeRunning] = useState(false)
  // Request mode
  const [mode, setMode] = useState<'token' | 'request'>('token')
  const [requestFlow, setRequestFlow] = useState<any>(null)
  const [detectedJwts, setDetectedJwts] = useState<any[]>([])
  const [selectedJwtIdx, setSelectedJwtIdx] = useState(0)
  const [reqRunning, setReqRunning] = useState(false)
  const [reqResults, setReqResults] = useState<any[]>([])
  const { sendToRepeater, jwtFlow, clearJwtFlow } = useProxyStore()

  // Load flow when sent from history
  useEffect(() => {
    if (!jwtFlow) return
    setMode('request')
    setRequestFlow(jwtFlow)
    clearJwtFlow()
    // Auto-detect JWTs
    const headers: Record<string, string> = {}
    if (jwtFlow.request_headers) {
      Object.entries(jwtFlow.request_headers).forEach(([k, v]) => { headers[k] = String(v) })
    }
    api.post<any>('/api/jwt/detect', {
      method: jwtFlow.request_method,
      url: jwtFlow.request_url,
      headers,
      body: jwtFlow.request_body || '',
    }).then(res => {
      if (res.found?.length > 0) {
        setDetectedJwts(res.found)
        setSelectedJwtIdx(0)
        // Also populate the token field for individual attacks
        setToken(res.found[0].token)
      } else {
        setDetectedJwts([])
      }
    }).catch(() => {})
  }, [jwtFlow])

  // Auto-decode whenever token changes
  useEffect(() => {
    const t = token.trim()
    if (!t || !t.includes('.')) { setDecoded(null); setDecodeError(''); return }
    const timer = setTimeout(async () => {
      try {
        const res = await api.post<any>('/api/jwt/decode', { token: t })
        if (res.error) { setDecodeError(res.error); setDecoded(null) }
        else { setDecoded(res); setDecodeError('') }
      } catch { setDecoded(null) }
    }, 400)
    return () => clearTimeout(timer)
  }, [token])

  useEffect(() => {
    if (!decoded) return
    setCustomHeader(JSON.stringify(decoded.header || {}, null, 2))
    setCustomPayload(JSON.stringify(decoded.payload || {}, null, 2))
    setForgeResult(null)
  }, [decoded])

  const forgeCustomToken = async () => {
    if (!token.trim()) return
    let header: Record<string, unknown>
    let payload: Record<string, unknown>
    try {
      header = JSON.parse(customHeader)
      payload = JSON.parse(customPayload)
      if (Array.isArray(header) || Array.isArray(payload) || !header || !payload) throw new Error('JSON objects required')
    } catch (error) {
      setForgeResult({ error: `Invalid JSON: ${String(error)}` })
      return
    }
    setForgeRunning(true)
    try {
      const result = await api.post<any>('/api/jwt/forge-custom', {
        token: token.trim(), header, payload,
        signing_mode: signingMode,
        algorithm: hmacAlgorithm,
        secret: hmacSecret,
        target_url: targetUrl.trim(),
        header_name: headerName.trim() || 'Authorization',
        header_value_template: headerValueTemplate || '{token}',
      })
      setForgeResult(result)
    } catch (error) {
      setForgeResult({ error: String(error) })
    } finally {
      setForgeRunning(false)
    }
  }

  const runAttack = async (attackId: string) => {
    if (!token.trim()) return
    setRunning(r => ({ ...r, [attackId]: true }))
    try {
      const wl = wordlist.trim() ? wordlist.split('\n').map(s => s.trim()).filter(Boolean) : []
      const res = await api.post<any>('/api/jwt/single-attack', {
        token: token.trim(),
        attack_id: attackId,
        target_url: targetUrl.trim(),
        header_name: headerName.trim() || 'Authorization',
        wordlist: wl,
        public_key: publicKey.trim(),
      })
      setAttackResults(r => ({ ...r, [attackId]: res }))
    } catch (e) {
      setAttackResults(r => ({ ...r, [attackId]: { error: String(e) } }))
    } finally {
      setRunning(r => ({ ...r, [attackId]: false }))
    }
  }

  const runAll = async () => {
    for (const atk of ATTACK_DISPLAY) {
      await runAttack(atk.id)
    }
  }

  const copyTok = (t: string) => {
    navigator.clipboard.writeText(t)
    setCopiedToken(t)
    setTimeout(() => setCopiedToken(null), 1500)
  }

  const sendToRep = (tok: string) => {
    const value = (headerValueTemplate || 'Bearer {token}').replace('{token}', tok)
    const fakeFlow = {
      id: `jwt-${Date.now()}`,
      request_method: 'GET',
      request_host: new URL(targetUrl || 'http://target.com').host,
      request_path: new URL(targetUrl || 'http://target.com').pathname || '/',
      request_headers: { [headerName || 'Authorization']: value },
      request_body: '',
      response_status: 0,
      response_headers: {},
      response_body: '',
      response_length: 0,
      duration_ms: 0,
      timestamp: new Date().toISOString(),
    } as any
    sendToRepeater(fakeFlow)
  }

  const sel = ATTACK_DISPLAY.find(a => a.id === selectedAttack)
  const selResult = selectedAttack ? attackResults[selectedAttack] : null

  // Status indicator per attack
  const getStatus = (id: string) => {
    if (running[id]) return 'running'
    const r = attackResults[id]
    if (!r) return 'idle'
    if (r.error) return 'error'
    if (r.manual) return 'manual'
    if (r.cracked === false) return 'miss'
    if (r.cracked === true) return 'hit'
    const probes = r.probes || []
    if (probes.some((p: any) => p.probe?.interesting)) return 'hit'
    if (probes.length > 0) return 'done'
    return 'done'
  }

  const statusDot = (id: string) => {
    const s = getStatus(id)
    if (s === 'running') return <Loader2 size={9} className="animate-spin text-yellow-400 shrink-0" />
    if (s === 'hit') return <div className="w-2 h-2 rounded-full bg-green-500 shrink-0" />
    if (s === 'error') return <div className="w-2 h-2 rounded-full bg-red-500 shrink-0" />
    if (s === 'miss') return <div className="w-2 h-2 rounded-full bg-zinc-600 shrink-0" />
    if (s === 'done') return <div className="w-2 h-2 rounded-full bg-zinc-500 shrink-0" />
    if (s === 'manual') return <div className="w-2 h-2 rounded-full bg-blue-500 shrink-0" />
    return <div className="w-2 h-2 rounded-full bg-zinc-800 border border-zinc-700 shrink-0" />
  }

  const runRequestAttack = async (attackId: string) => {
    if (!requestFlow) return
    setReqRunning(true)
    const headers: Record<string, string> = {}
    if (requestFlow.request_headers) {
      Object.entries(requestFlow.request_headers).forEach(([k, v]) => { headers[k] = String(v) })
    }
    try {
      const wl = wordlist.trim() ? wordlist.split('\n').map((s: string) => s.trim()).filter(Boolean) : []
      const res = await api.post<any>('/api/jwt/attack-request', {
        method: requestFlow.request_method,
        url: requestFlow.request_url,
        headers,
        body: requestFlow.request_body || '',
        attack_id: attackId,
        wordlist: wl,
        public_key: publicKey,
      })
      setReqResults(prev => {
        const filtered = prev.filter((r: any) => r.attack_id !== attackId)
        return [...filtered, ...(res.results || [{ attack_id: attackId, error: res.error }])]
      })
    } catch (e) {
      setReqResults(prev => [...prev, { attack_id: attackId, error: String(e) }])
    } finally {
      setReqRunning(false)
    }
  }

  const runAllRequestAttacks = async () => {
    if (!requestFlow) return
    setReqRunning(true)
    setReqResults([])
    const headers: Record<string, string> = {}
    if (requestFlow.request_headers) {
      Object.entries(requestFlow.request_headers).forEach(([k, v]) => { headers[k] = String(v) })
    }
    try {
      const wl = wordlist.trim() ? wordlist.split('\n').map((s: string) => s.trim()).filter(Boolean) : []
      const res = await api.post<any>('/api/jwt/attack-request', {
        method: requestFlow.request_method,
        url: requestFlow.request_url,
        headers,
        body: requestFlow.request_body || '',
        attack_id: '',
        wordlist: wl,
        public_key: publicKey,
      })
      setReqResults(res.results || [])
    } catch (e) {
      setReqResults([{ error: String(e) }])
    } finally {
      setReqRunning(false)
    }
  }

  return (
    <div className="flex-1 flex flex-col gap-2 min-h-0">
      {/* Mode toggle */}
      <div className="flex items-center gap-2 shrink-0">
        <div className="flex gap-1 bg-zinc-900 rounded-md p-0.5">
          <button onClick={() => setMode('token')}
            className={cn('px-3 py-1 text-xs rounded transition-colors',
              mode === 'token' ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-500 hover:text-zinc-300')}>
            Token Mode
          </button>
          <button onClick={() => setMode('request')}
            className={cn('px-3 py-1 text-xs rounded transition-colors flex items-center gap-1',
              mode === 'request' ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-500 hover:text-zinc-300')}>
            Request Mode
            {requestFlow && <span className="w-1.5 h-1.5 rounded-full bg-green-500" />}
          </button>
        </div>
        {mode === 'request' && !requestFlow && (
          <p className="text-[10px] text-zinc-600">Right-click a request in HTTP History → "Send to JWT Attacks"</p>
        )}
      </div>

      {/* ── REQUEST MODE ── */}
      {mode === 'request' && (
        <div className="flex-1 flex gap-3 min-h-0">
          {/* Left: request summary + detected JWTs */}
          <div className="w-64 shrink-0 flex flex-col gap-2 overflow-y-auto">
            {!requestFlow ? (
              <div className="flex-1 flex flex-col items-center justify-center text-center gap-2 p-4">
                <Repeat2 size={28} className="text-zinc-700" />
                <p className="text-xs text-zinc-600">No request loaded.<br/>Right-click any flow → "Send to JWT Attacks"</p>
              </div>
            ) : (
              <>
                <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-2.5 space-y-1.5">
                  <div className="flex items-center gap-1.5">
                    <span className={cn('text-[9px] font-bold px-1.5 py-0.5 rounded', getMethodColor(requestFlow.request_method))}>{requestFlow.request_method}</span>
                    <span className="text-[10px] text-zinc-400 font-mono truncate flex-1">{requestFlow.request_host}</span>
                  </div>
                  <p className="text-[9px] text-zinc-600 font-mono truncate">{requestFlow.request_path}</p>
                  <button onClick={() => { setRequestFlow(null); setDetectedJwts([]); setReqResults([]) }}
                    className="text-[9px] text-zinc-700 hover:text-red-400 transition-colors">
                    Clear request
                  </button>
                </div>

                {/* Detected JWTs */}
                {detectedJwts.length === 0 && (
                  <div className="rounded-lg border border-yellow-800/40 bg-yellow-950/20 p-2.5 space-y-2">
                    <p className="text-[10px] text-yellow-400">No JWT detected in this request</p>
                    <p className="text-[9px] text-zinc-500 leading-relaxed">A JWT has three Base64URL parts separated by dots. This may be an opaque session cookie, which cannot be decoded into editable claims.</p>
                    <button onClick={() => requestFlow && sendToRepeater(requestFlow)} className="w-full h-7 rounded border border-zinc-700 text-[9px] text-zinc-300 hover:border-zinc-500 flex items-center justify-center gap-1"><Repeat2 size={9} />Send request to Repeater</button>
                  </div>
                )}
                {detectedJwts.length > 0 && (
                  <div className="rounded-lg border border-zinc-800 overflow-hidden">
                    <div className="bg-zinc-900 px-2.5 py-1.5">
                      <p className="text-[9px] font-semibold text-zinc-500 uppercase">{detectedJwts.length} JWT{detectedJwts.length > 1 ? 's' : ''} found</p>
                    </div>
                    {detectedJwts.map((jwt: any, i: number) => (
                      <button key={i} onClick={() => { setSelectedJwtIdx(i); setToken(jwt.token) }}
                        className={cn('w-full text-left px-2.5 py-2 border-t border-zinc-800 transition-colors',
                          selectedJwtIdx === i ? 'bg-zinc-800/60' : 'hover:bg-zinc-800/30')}>
                        <div className="flex items-center gap-1.5">
                          <span className={cn('text-[8px] px-1 py-0.5 rounded font-bold uppercase',
                            jwt.location === 'header' ? 'bg-blue-900/50 text-blue-300' :
                            jwt.location === 'cookie' ? 'bg-orange-900/50 text-orange-300' :
                            'bg-zinc-800 text-zinc-400'
                          )}>{jwt.location}</span>
                          <span className="text-[9px] text-zinc-400 truncate flex-1">
                            {jwt.header_name || jwt.cookie_name || jwt.param_name || 'body'}
                          </span>
                        </div>
                        {jwt.decoded && (
                          <div className="mt-1 flex items-center gap-2 text-[9px]">
                            <span className="text-yellow-400 font-mono">{jwt.decoded.algorithm}</span>
                            {jwt.decoded.is_expired && <span className="text-red-400">EXPIRED</span>}
                            {jwt.decoded.issues?.map((iss: any, j: number) => (
                              <span key={j} className="text-orange-400">⚠ {iss.msg}</span>
                            ))}
                          </div>
                        )}
                      </button>
                    ))}
                  </div>
                )}

                {/* Attack list for request mode */}
                {detectedJwts.length > 0 && (
                  <div className="rounded-lg border border-zinc-800 overflow-hidden">
                    <div className="bg-zinc-900 px-2.5 py-1.5 flex items-center justify-between">
                      <span className="text-[9px] font-semibold text-zinc-500 uppercase">Attacks</span>
                      <button onClick={runAllRequestAttacks} disabled={reqRunning}
                        className="text-[9px] text-red-400 hover:text-red-300 font-semibold disabled:opacity-40 flex items-center gap-1">
                        {reqRunning ? <><Loader2 size={8} className="animate-spin" />Running...</> : 'Run All'}
                      </button>
                    </div>
                    <div className="divide-y divide-zinc-800/50">
                      {ATTACK_DISPLAY.map(atk => {
                        const res = reqResults.find((r: any) => r.attack_id === atk.id)
                        const hasHit = res?.probes?.some((p: any) => p.probe?.interesting)
                        return (
                          <button key={atk.id}
                            onClick={() => { setSelectedAttack(atk.id); runRequestAttack(atk.id) }}
                            disabled={reqRunning}
                            className={cn('w-full flex items-center gap-2 px-2.5 py-1.5 text-left transition-colors disabled:opacity-50',
                              SEV_ROW[atk.severity])}>
                            {reqRunning && selectedAttack === atk.id
                              ? <Loader2 size={9} className="animate-spin text-yellow-400 shrink-0" />
                              : hasHit ? <div className="w-2 h-2 rounded-full bg-green-500 shrink-0" />
                              : res ? <div className="w-2 h-2 rounded-full bg-zinc-500 shrink-0" />
                              : <div className="w-2 h-2 rounded-full bg-zinc-800 border border-zinc-700 shrink-0" />
                            }
                            <span className="text-[10px] text-zinc-400 flex-1">{atk.name}</span>
                            <span className={cn('text-[8px] px-1 py-0.5 rounded font-bold uppercase', SEV_BADGE[atk.severity])}>
                              {atk.severity === 'critical' ? 'CRIT' : atk.severity.slice(0,3).toUpperCase()}
                            </span>
                          </button>
                        )
                      })}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>

          {/* Right: request attack results */}
          <div className="flex-1 min-h-0 overflow-y-auto space-y-3">
            {reqResults.length === 0 && !reqRunning && requestFlow && detectedJwts.length > 0 && (
              <div className="flex items-center justify-center h-full text-xs text-zinc-600">
                Select an attack or click "Run All"
              </div>
            )}
            {reqResults.map((res: any, i: number) => {
              const atkMeta = ATTACK_DISPLAY.find(a => a.id === res.attack_id)
              return (
                <div key={i} className="rounded-lg border border-zinc-800 bg-zinc-900/30 p-3 space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-zinc-200">{atkMeta?.name || res.attack_id}</span>
                    {atkMeta && <span className={cn('text-[8px] px-1.5 py-0.5 rounded font-bold uppercase', SEV_BADGE[atkMeta.severity])}>
                      {atkMeta.severity === 'critical' ? 'CRIT' : atkMeta.severity.slice(0,3).toUpperCase()}
                    </span>}
                    {res.cracked && <span className="text-[10px] text-green-400 font-bold">SECRET: {res.secret}</span>}
                  </div>
                  {res.manual && <p className="text-[10px] text-blue-300 whitespace-pre-wrap">{res.instructions}</p>}
                  {res.error && <p className="text-[10px] text-red-400">{res.error}</p>}
                  {res.probes?.length > 0 && (
                    <TokenList probes={res.probes} onCopy={setCopiedToken} copiedToken={copiedToken}
                      onSendToRepeater={undefined} />
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* ── TOKEN MODE ── */}
      {mode === 'token' && (
    <div className="flex-1 flex gap-3 min-h-0">

      {/* ── LEFT PANEL ── */}
      <div className="w-64 shrink-0 flex flex-col gap-2 overflow-y-auto">

        {/* Token input */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-2.5 space-y-2">
          <p className="text-[9px] font-semibold text-zinc-500 uppercase tracking-wide flex items-center gap-1">
            <Key size={9} /> JWT Token
          </p>
          <textarea
            className="w-full h-16 bg-zinc-950 border border-zinc-800 rounded p-1.5 text-[10px] font-mono text-green-300 resize-none focus:outline-none focus:border-zinc-600"
            placeholder="eyJhbGci..."
            value={token}
            onChange={e => setToken(e.target.value)}
            spellCheck={false}
          />
          {decodeError && <p className="text-[10px] text-red-400">{decodeError}</p>}
          {decoded && (
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-[10px]">
                <span className="text-zinc-500">alg:</span>
                <span className="text-yellow-400 font-mono font-bold">{decoded.algorithm}</span>
                {decoded.is_expired === true && <span className="text-red-400 font-semibold">EXPIRED</span>}
                {decoded.is_expired === false && <span className="text-green-400">valid</span>}
              </div>
              {decoded.issues?.map((iss: any, i: number) => (
                <div key={i} className={cn('text-[9px] rounded px-1.5 py-0.5',
                  iss.level === 'critical' ? 'bg-red-950/40 text-red-300' :
                  iss.level === 'high' ? 'bg-orange-950/40 text-orange-300' : 'bg-yellow-950/40 text-yellow-300'
                )}>
                  ⚠ {iss.msg}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Target URL */}
        <div className="space-y-1">
          <p className="text-[9px] text-zinc-600 uppercase font-semibold px-0.5">Target URL (optional)</p>
          <Input className="h-6 text-[10px] bg-zinc-950 font-mono" placeholder="https://api.target.com/me"
            value={targetUrl} onChange={e => setTargetUrl(e.target.value)} />
          <Input className="h-6 text-[10px] bg-zinc-950 font-mono" placeholder="Header name (Authorization)"
            value={headerName} onChange={e => setHeaderName(e.target.value)} />
        </div>

        {/* Attack list */}
        <button
          onClick={() => setSelectedAttack('custom_editor')}
          disabled={!decoded}
          className={cn('w-full h-8 rounded-md border flex items-center justify-center gap-1.5 text-[10px] font-semibold transition-colors disabled:opacity-40', selectedAttack === 'custom_editor' ? 'border-teal-700 bg-teal-950/30 text-teal-300' : 'border-teal-900/70 text-teal-400 hover:bg-teal-950/20')}
        >
          <Key size={11} /> Edit claims and re-sign
        </button>

        <div className="rounded-lg border border-zinc-800 overflow-hidden">
          <div className="bg-zinc-900 px-2.5 py-1.5 flex items-center justify-between">
            <span className="text-[9px] font-semibold text-zinc-500 uppercase">Attacks ({ATTACK_DISPLAY.length})</span>
            <button onClick={runAll} disabled={!token.trim()}
              className="text-[9px] text-red-400 hover:text-red-300 font-semibold disabled:opacity-40">
              Run All
            </button>
          </div>
          <div className="divide-y divide-zinc-800/50">
            {ATTACK_DISPLAY.map(atk => (
              <button key={atk.id}
                onClick={() => setSelectedAttack(atk.id)}
                className={cn('w-full flex items-center gap-2 px-2.5 py-1.5 text-left transition-colors border-l-2',
                  selectedAttack === atk.id
                    ? 'bg-zinc-800/60 border-l-zinc-400'
                    : cn('border-l-transparent', SEV_ROW[atk.severity])
                )}
              >
                {statusDot(atk.id)}
                <span className={cn('text-[10px] flex-1 font-medium',
                  selectedAttack === atk.id ? 'text-zinc-100' : 'text-zinc-400'
                )}>{atk.name}</span>
                <span className={cn('text-[8px] px-1 py-0.5 rounded font-bold uppercase', SEV_BADGE[atk.severity])}>
                  {atk.severity === 'critical' ? 'CRIT' : atk.severity.slice(0,3).toUpperCase()}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Legend */}
        <div className="text-[9px] text-zinc-700 space-y-0.5 px-0.5">
          <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-green-500" /> Potential bypass found</div>
          <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-zinc-500" /> Ran — no bypass</div>
          <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-blue-500" /> Manual steps required</div>
          <div className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-zinc-800 border border-zinc-700" /> Not run yet</div>
        </div>
      </div>

      {/* ── RIGHT PANEL ── */}
      <div className="flex-1 flex flex-col gap-3 min-h-0 overflow-y-auto">
        {!selectedAttack && (
          <div className="flex-1 flex flex-col items-center justify-center text-center gap-3">
            <div className="rounded-full bg-red-900/20 border border-red-800/30 p-5">
              <Key size={32} className="text-red-400" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-zinc-300">JWT Attack Suite</h3>
              <p className="text-xs text-zinc-600 mt-1 max-w-xs">
                Paste a JWT token, then select an attack from the left to see details and run it individually — or click "Run All".
              </p>
            </div>
            <div className="grid grid-cols-2 gap-2 text-[10px] text-zinc-600 max-w-xs">
              {['alg:none bypass', 'Weak secret crack', 'RS256→HS256', 'kid SQLi/traversal', 'jku SSRF', 'Priv escalation'].map(f => (
                <div key={f} className="flex items-center gap-1"><AlertTriangle size={9} className="text-red-600 shrink-0" />{f}</div>
              ))}
            </div>
          </div>
        )}

        {selectedAttack === 'custom_editor' && (
          <CustomJwtEditor
            header={customHeader} setHeader={setCustomHeader}
            payload={customPayload} setPayload={setCustomPayload}
            signingMode={signingMode} setSigningMode={setSigningMode}
            algorithm={hmacAlgorithm} setAlgorithm={setHmacAlgorithm}
            secret={hmacSecret} setSecret={setHmacSecret}
            headerName={headerName} template={headerValueTemplate} setTemplate={setHeaderValueTemplate}
            targetUrl={targetUrl} running={forgeRunning} result={forgeResult}
            onForge={forgeCustomToken} onCopy={copyTok}
            onLoadToken={value => { setToken(value); setSelectedAttack('custom_editor') }}
            onSendToRepeater={targetUrl ? sendToRep : undefined}
          />
        )}

        {selectedAttack !== 'custom_editor' && selectedAttack && sel && (
          <>
            {/* Attack header */}
            <div className="flex items-center justify-between gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-sm font-bold text-zinc-100">{sel.name}</h2>
                  <span className={cn('text-[9px] px-1.5 py-0.5 rounded font-bold uppercase', SEV_BADGE[sel.severity])}>
                    {sel.severity}
                  </span>
                </div>
              </div>
              <Button size="sm"
                className="bg-red-700 hover:bg-red-600 text-white text-xs shrink-0"
                disabled={running[sel.id] || !token.trim()}
                onClick={() => runAttack(sel.id)}>
                {running[sel.id]
                  ? <><Loader2 size={11} className="animate-spin mr-1.5" />Running...</>
                  : <><Play size={11} className="mr-1.5" />Run Attack</>}
              </Button>
            </div>

            {/* Attack info boxes */}
            <AttackInfoPanel attackId={sel.id} decoded={decoded}
              wordlist={wordlist} setWordlist={setWordlist}
              publicKey={publicKey} setPublicKey={setPublicKey} />

            {/* Results */}
            {selResult && <AttackResultPanel result={selResult} attackId={sel.id}
              targetUrl={targetUrl} headerName={headerName || 'Authorization'}
              onCopy={copyTok} copiedToken={copiedToken}
              onSendToRepeater={targetUrl ? sendToRep : undefined} />}
          </>
        )}
      </div>
    </div>
    )}
    </div>
  )
}

function CustomJwtEditor({ header, setHeader, payload, setPayload, signingMode, setSigningMode, algorithm, setAlgorithm, secret, setSecret, headerName, template, setTemplate, targetUrl, running, result, onForge, onCopy, onLoadToken, onSendToRepeater }: {
  header: string; setHeader: (v: string) => void
  payload: string; setPayload: (v: string) => void
  signingMode: 'keep_signature' | 'none' | 'hmac'; setSigningMode: (v: 'keep_signature' | 'none' | 'hmac') => void
  algorithm: 'HS256' | 'HS384' | 'HS512'; setAlgorithm: (v: 'HS256' | 'HS384' | 'HS512') => void
  secret: string; setSecret: (v: string) => void
  headerName: string; template: string; setTemplate: (v: string) => void
  targetUrl: string; running: boolean; result: any
  onForge: () => void; onCopy: (v: string) => void; onLoadToken: (v: string) => void
  onSendToRepeater?: (v: string) => void
}) {
  return <div className="space-y-3">
    <div className="flex items-center justify-between gap-3">
      <div><h2 className="text-sm font-bold text-zinc-100">JWT claim workbench</h2><p className="text-[10px] text-zinc-500 mt-0.5">Edit any claim, choose how to sign it, then probe the target or move it to Repeater.</p></div>
      <Button size="sm" onClick={onForge} disabled={running} className="bg-teal-700 hover:bg-teal-600 text-white text-xs shrink-0">{running ? <Loader2 size={11} className="animate-spin mr-1.5" /> : <Play size={11} className="mr-1.5" />}Generate{targetUrl ? ' and send' : ''}</Button>
    </div>

    <div className="grid grid-cols-2 gap-3">
      <JsonEditor label="JOSE header" value={header} onChange={setHeader} />
      <JsonEditor label="Payload claims" value={payload} onChange={setPayload} />
    </div>

    <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3 space-y-3">
      <div className="grid grid-cols-3 gap-2">
        <SignMode active={signingMode === 'keep_signature'} title="Keep signature" body="Tests missing signature verification" onClick={() => setSigningMode('keep_signature')} />
        <SignMode active={signingMode === 'none'} title="alg:none" body="Unsigned bypass plus edited claims" onClick={() => setSigningMode('none')} />
        <SignMode active={signingMode === 'hmac'} title="HMAC secret" body="Creates a valid HS token" onClick={() => setSigningMode('hmac')} />
      </div>
      {signingMode === 'hmac' && <div className="grid grid-cols-[120px_1fr] gap-2"><select value={algorithm} onChange={e => setAlgorithm(e.target.value as any)} className="h-8 rounded border border-zinc-700 bg-zinc-950 px-2 text-[11px] text-zinc-300"><option>HS256</option><option>HS384</option><option>HS512</option></select><Input type="password" value={secret} onChange={e => setSecret(e.target.value)} placeholder="HMAC secret (from weak-secret crack or authorized test config)" className="h-8 bg-zinc-950 text-[11px] font-mono" /></div>}
      <div className="grid grid-cols-[180px_1fr] gap-2 items-end"><div><label className="text-[9px] text-zinc-600 uppercase font-semibold">Injection header</label><div className="h-8 mt-1 rounded border border-zinc-800 bg-zinc-950 px-2 flex items-center text-[10px] font-mono text-zinc-400 truncate">{headerName || 'Authorization'}</div></div><div><label className="text-[9px] text-zinc-600 uppercase font-semibold">Value template</label><Input value={template} onChange={e => setTemplate(e.target.value)} placeholder="Bearer {token} or session={token}" className="h-8 mt-1 bg-zinc-950 text-[10px] font-mono" /></div></div>
      <p className="text-[9px] text-zinc-600">Use <code className="text-teal-400">{'{token}'}</code> where the generated JWT belongs. The probe uses GET; use Repeater for custom methods, bodies, or cookies.</p>
    </div>

    {result?.error && <div className="rounded-lg border border-red-800/50 bg-red-950/20 p-3 text-[11px] text-red-400">{result.error}</div>}
    {result?.token && <div className="rounded-lg border border-teal-900/70 bg-teal-950/10 overflow-hidden"><div className="px-3 py-2 border-b border-teal-900/50 flex items-center justify-between"><div><span className="text-[10px] font-semibold text-teal-300">Generated token</span>{result.warning && <span className="ml-2 text-[9px] text-amber-400">Signature intentionally invalid</span>}</div><div className="flex gap-2"><button onClick={() => onCopy(result.token)} className="text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1"><Copy size={10} />Copy</button><button onClick={() => onLoadToken(result.token)} className="text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center gap-1"><RotateCcw size={10} />Load</button>{onSendToRepeater && <button onClick={() => onSendToRepeater(result.token)} className="text-[10px] text-teal-400 hover:text-teal-300 flex items-center gap-1"><Send size={10} />Repeater</button>}</div></div><div className="p-3 font-mono text-[10px] text-green-300 break-all leading-relaxed">{result.token}</div>{result.probe && <div className="border-t border-teal-900/40 px-3 py-2 flex items-center gap-3"><span className={cn('text-xs font-bold font-mono', getStatusColor(result.probe.status))}>HTTP {result.probe.status || 'ERR'}</span><span className="text-[10px] text-zinc-500">{result.probe.length ?? 0} bytes</span><span className={cn('text-[9px] font-semibold', result.probe.interesting ? 'text-green-400' : 'text-zinc-600')}>{result.probe.interesting ? 'Review response' : 'Rejected by authorization'}</span></div>}</div>}
  </div>
}

function JsonEditor({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  return <div className="rounded-lg border border-zinc-800 overflow-hidden"><div className="h-8 px-3 bg-zinc-900 flex items-center text-[9px] uppercase font-semibold text-zinc-500">{label}</div><textarea value={value} onChange={e => onChange(e.target.value)} spellCheck={false} className="w-full h-56 resize-none bg-zinc-950 p-3 font-mono text-[11px] leading-relaxed text-zinc-300 focus:outline-none focus:ring-1 focus:ring-teal-900" /></div>
}

function SignMode({ active, title, body, onClick }: { active: boolean; title: string; body: string; onClick: () => void }) {
  return <button onClick={onClick} className={cn('text-left rounded-md border p-2.5 transition-colors', active ? 'border-teal-700 bg-teal-950/25' : 'border-zinc-800 bg-zinc-950/40 hover:border-zinc-700')}><div className={cn('text-[10px] font-semibold', active ? 'text-teal-300' : 'text-zinc-300')}>{title}</div><div className="text-[9px] text-zinc-600 mt-1 leading-relaxed">{body}</div></button>
}

// ── Attack info panel (description + steps) ───────────────────────────────────
const ATTACK_INFO: Record<string, {
  description: string
  how: string
  steps: string[]
  prereq: string
  cve?: string
  command?: string
}> = {
  alg_none: {
    description: "If the server doesn't enforce a whitelist of allowed algorithms, setting alg to 'none' makes it skip signature verification entirely. You can modify any claim.",
    how: "JWT libraries that accept 'none' treat the token as unsigned. Even case variants like 'None', 'NONE', 'nOnE' bypass naive string checks.",
    steps: ["Decode the original JWT", "Change `alg` header to 'none' (4 variants tested)", "Modify payload (role, admin, exp)", "Remove signature — token ends with a dot", "Send the modified token"],
    prereq: "None — works on any JWT regardless of original algorithm",
    cve: "CVE-2015-9235",
  },
  empty_sig: {
    description: "Some libraries distinguish between 'no signature' and 'empty signature'. Sending `header.payload.` bypasses verification in some implementations.",
    how: "Buggy implementations accept an empty string as a valid signature, especially when alg is kept as the original.",
    steps: ["Take the original header.payload parts", "Append a dot without any signature: header.payload.", "Optionally modify the payload", "Send the token"],
    prereq: "None",
  },
  tampered_payload: {
    description: "Modify payload claims (admin, role, expiry) while keeping the original signature. Tests if the server skips signature verification.",
    how: "A properly implemented server rejects this, but misconfigured or dev servers often don't validate. Also useful to confirm the server reads claims at all.",
    steps: ["Decode original token", "Modify claims: admin, role, exp, sub, user_id", "Re-encode only the payload", "Keep original header + signature unchanged", "Send: original_header.new_payload.original_signature"],
    prereq: "None — only works if server skips signature validation",
  },
  key_confusion: {
    description: "When the server uses RS256 and the public key is available, sign a HS256 token using the public key as the HMAC secret. Vulnerable libraries accept it.",
    how: "The server's public key is public. If the library uses the alg from the token header instead of enforcing expected algorithm, it verifies HS256 with the public key — which matches what the attacker signed.",
    steps: ["Obtain server's RSA public key (from /jwks.json or SSL cert)", "Change `alg` from RS256 to HS256", "Modify payload claims as desired", "Sign token with HMAC-SHA256 using the public key bytes as secret", "Send the forged token"],
    prereq: "Target uses RS256 or ES256; public key must be obtainable",
    cve: "CVE-2016-10555",
    command: "python3 -c \"import jwt; print(jwt.encode(payload, open('public.pem','rb').read(), algorithm='HS256'))\"",
  },
  weak_secret: {
    description: "HS256 JWTs are only as secure as their secret. Short or common secrets can be cracked offline without any server interaction.",
    how: "The signature is HMAC(header.payload, secret). Try candidate secrets locally — if the resulting signature matches, the secret is found and you can re-sign anything.",
    steps: ["Extract the JWT from a request", "Run offline brute force against common/weak secrets", "If cracked: re-sign any payload with the secret", "Elevate privileges, impersonate users, extend expiry"],
    prereq: "Token uses HS256, HS384, or HS512",
    command: "hashcat -a 0 -m 16500 <token> /usr/share/wordlists/rockyou.txt",
  },
  kid_injection: {
    description: "The `kid` header tells the server which key to use. If used in a file path or SQL query without sanitization, it's vulnerable to path traversal or SQLi.",
    how: "Path traversal: kid='../../dev/null', sign with empty/null secret — server reads empty file as key, accepts empty HMAC. SQL injection: kid=\\\"' OR '1'='1\\\" makes key lookup return any key.",
    steps: ["Verify token has a `kid` header", "Try path traversal: kid='../../dev/null' signed with empty secret", "Try SQL injection: kid=\\\"' OR '1'='1\\\"", "Try deeper traversal paths", "Observe server behavior"],
    prereq: "Token has `kid` header; server uses it unsafely",
  },
  jku_ssrf: {
    description: "The `jku` header tells the server where to fetch the signing key. NexHunt automates this: generates an RSA keypair, hosts the JWKS at its own endpoint, signs the token, and probes the target.",
    how: "The backend generates an RSA keypair, hosts JWKS at /api/jwt/jwks/<kid> (accessible to the target if internal), signs the JWT with the private key pointing jku there. If target fetches it and accepts the token, the attack worked.",
    steps: [
      "NexHunt generates RSA keypair automatically",
      "JWKS hosted at http://YOUR_IP:17707/api/jwt/jwks/<kid>",
      "Token signed with RS256, jku/x5u header set to JWKS URL",
      "Target server fetches the JWKS URL to verify the signature",
      "If target accepts: you get in — check for green INTERESTING response",
      "For external targets: set target URL and ensure NexHunt is reachable from target",
    ],
    prereq: "Target server must be able to reach NexHunt's JWKS endpoint. For local/internal targets: works out of the box. For external targets: add ngrok token in Settings → Ngrok Authtoken and NexHunt will start a tunnel automatically.",
    command: "# NexHunt handles this automatically — set Target URL and click Run. For external targets, add ngrok token in Settings first.",
  },
  priv_esc: {
    description: "Once signature verification is bypassed, add or modify authorization claims to gain elevated access: admin=true, role=admin, scope=admin, permissions=[*].",
    how: "Combined with alg:none — forged tokens with admin claims can access privileged endpoints. Try /admin, /api/admin, /dashboard, /users.",
    steps: ["First bypass signature verification (alg:none or cracked secret)", "Add privilege claims to payload", "Send to privileged endpoints", "Try different claim names: admin, role, isAdmin, scope, permissions, groups"],
    prereq: "Signature verification must already be bypassable",
  },
  expired_reuse: {
    description: "Some servers don't validate the `exp` claim, accepting expired tokens indefinitely. Common in internal APIs and microservices.",
    how: "Simply resend the original expired token. If you get 200 OK instead of 401, the server doesn't check expiration.",
    steps: ["Capture a JWT from any response", "Wait for it to expire (check `exp` claim)", "Resend the original token", "If 200 OK: server doesn't validate expiry — combine with other attacks"],
    prereq: "Have an expired (or soon-to-expire) token",
  },
  null_token: {
    description: "Test how the server handles null, empty, or malformed tokens. Some servers fail-open (grant access) or leak info on unexpected inputs.",
    how: "Some authentication middleware grants access on null/empty tokens or throws exceptions that reveal internal paths.",
    steps: ["Try: Authorization: Bearer null", "Try: Authorization: Bearer undefined", "Try: Authorization: Bearer []", "Try: omit the Authorization header entirely", "Observe: 401/403 = correct | 200 = fail-open | 500 = exception"],
    prereq: "None",
  },
}

function AttackInfoPanel({ attackId, decoded, wordlist, setWordlist, publicKey, setPublicKey }: {
  attackId: string; decoded: any
  wordlist: string; setWordlist: (v: string) => void
  publicKey: string; setPublicKey: (v: string) => void
}) {
  const info = ATTACK_INFO[attackId]
  if (!info) return null

  return (
    <div className="space-y-3">
      {info.cve && (
        <span className="text-[9px] bg-red-950/40 text-red-400 border border-red-800/40 px-2 py-0.5 rounded font-mono">
          {info.cve}
        </span>
      )}

      <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3 space-y-2">
        <p className="text-xs text-zinc-300 leading-relaxed">{info.description}</p>
        <div className="border-t border-zinc-800 pt-2">
          <p className="text-[10px] text-zinc-500 font-semibold mb-1">How it works</p>
          <p className="text-[11px] text-zinc-400 leading-relaxed">{info.how}</p>
        </div>
        <div className="border-t border-zinc-800 pt-2">
          <p className="text-[10px] text-zinc-500 font-semibold mb-1 flex items-center gap-1">
            <ChevronRight size={10} /> Prerequisites
          </p>
          <p className="text-[11px] text-zinc-400">{info.prereq}</p>
        </div>
      </div>

      <div className="rounded-lg border border-zinc-700/50 bg-zinc-900/30 p-3">
        <p className="text-[10px] font-semibold text-zinc-400 mb-2 uppercase tracking-wide">Step-by-Step</p>
        <ol className="space-y-1.5">
          {info.steps.map((step, i) => (
            <li key={i} className="flex gap-2.5 text-[11px] text-zinc-300">
              <span className="shrink-0 w-4 h-4 rounded-full bg-zinc-800 border border-zinc-600 text-[9px] font-bold text-zinc-400 flex items-center justify-center mt-0.5">
                {i + 1}
              </span>
              {step}
            </li>
          ))}
        </ol>
      </div>

      {info.command && (
        <div className="rounded-lg border border-zinc-700 overflow-hidden">
          <div className="bg-zinc-800 px-3 py-1 text-[9px] text-zinc-500 font-semibold uppercase">Command</div>
          <pre className="bg-zinc-950 px-3 py-2 text-[11px] font-mono text-green-300 overflow-x-auto">
            {info.command}
          </pre>
        </div>
      )}

      {/* Extra inputs per attack */}
      {attackId === 'weak_secret' && (
        <div className="space-y-1">
          <p className="text-[10px] text-zinc-500 font-semibold">Custom wordlist (one secret per line):</p>
          <textarea
            className="w-full h-20 bg-zinc-950 border border-zinc-800 rounded p-2 text-[11px] font-mono text-zinc-400 resize-none focus:outline-none focus:border-zinc-600"
            placeholder={"secret\npassword\n123456\nadmin\njwt_secret\n..."}
            value={wordlist}
            onChange={e => setWordlist(e.target.value)}
            spellCheck={false}
          />
          <p className="text-[9px] text-zinc-600">Leave empty to use built-in list of 30+ common secrets</p>
        </div>
      )}

      {attackId === 'key_confusion' && (
        <div className="space-y-1">
          <p className="text-[10px] text-zinc-500 font-semibold">Server public key (PEM format):</p>
          <textarea
            className="w-full h-24 bg-zinc-950 border border-zinc-800 rounded p-2 text-[11px] font-mono text-zinc-400 resize-none focus:outline-none focus:border-zinc-600"
            placeholder={"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----"}
            value={publicKey}
            onChange={e => setPublicKey(e.target.value)}
            spellCheck={false}
          />
          <p className="text-[9px] text-zinc-600">Get from: /jwks.json · /.well-known/openid-configuration · SSL cert · source code</p>
        </div>
      )}

      {decoded && attackId === 'priv_esc' && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/30 p-2.5">
          <p className="text-[9px] text-zinc-500 font-semibold mb-1.5">Detected payload claims to escalate:</p>
          <div className="flex flex-wrap gap-1">
            {Object.keys(decoded.payload || {}).map(k => (
              <span key={k} className="text-[9px] bg-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded font-mono">{k}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Attack result panel ────────────────────────────────────────────────────────
function AttackResultPanel({ result, attackId, targetUrl, headerName, onCopy, copiedToken, onSendToRepeater }: {
  result: any; attackId: string; targetUrl: string; headerName: string
  onCopy: (t: string) => void; copiedToken: string | null
  onSendToRepeater?: (t: string) => void
}) {
  if (result.error) {
    return <div className="rounded-lg border border-red-800/40 bg-red-950/20 p-3 text-xs text-red-400">{result.error}</div>
  }

  if (result.manual) {
    return (
      <div className="rounded-lg border border-blue-800/40 bg-blue-950/20 p-3 space-y-2">
        <p className="text-[10px] font-semibold text-blue-300 uppercase">Manual Steps Required</p>
        <pre className="text-[11px] text-zinc-300 whitespace-pre-wrap font-mono leading-relaxed">{result.instructions}</pre>
      </div>
    )
  }

  // jku attack result
  if (result.jwks_url) {
    const hits = (result.probes || []).filter((p: any) => p.probe?.interesting)
    return (
      <div className="rounded-lg border border-zinc-700/50 bg-zinc-900/30 p-3 space-y-2">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[10px] font-semibold text-zinc-300 uppercase">jku/x5u Automated Attack</span>
          {hits.length > 0 && (
            <span className="text-[9px] px-1.5 py-0.5 rounded bg-green-900/50 text-green-300 font-bold">
              {hits.length} POTENTIAL HIT{hits.length > 1 ? 'S' : ''}
            </span>
          )}
          {result.ngrok_url && (
            <span className="text-[9px] px-1.5 py-0.5 rounded bg-orange-900/50 text-orange-300 font-mono">
              ngrok: {result.ngrok_url}
            </span>
          )}
          {result.tunnel_needed && !result.ngrok_url && (
            <span className="text-[9px] px-1.5 py-0.5 rounded bg-yellow-900/40 text-yellow-400">
              External target — configure ngrok in Settings
            </span>
          )}
        </div>
        {result.ngrok_error && (
          <div className="rounded border border-yellow-800/40 bg-yellow-950/20 p-2 text-[10px] text-yellow-300 space-y-1">
            <p className="font-semibold">Ngrok not configured for external target</p>
            <p className="text-zinc-400">Go to <strong className="text-zinc-200">Settings → Ngrok Authtoken</strong> to enable auto-tunneling.</p>
            <p className="text-zinc-600">Get token free at dashboard.ngrok.com/get-started/your-authtoken</p>
          </div>
        )}
        {result.note && <p className="text-[10px] text-zinc-500 whitespace-pre-line">{result.note}</p>}
        <TokenList probes={result.probes || []} onCopy={onCopy} copiedToken={copiedToken}
          onSendToRepeater={onSendToRepeater} jwksUrl={result.jwks_url} />
      </div>
    )
  }

  if (attackId === 'weak_secret') {
    if (result.cracked === false) {
      return (
        <div className="rounded-lg border border-zinc-700 bg-zinc-900/30 p-3 space-y-1.5">
          <p className="text-xs font-semibold text-zinc-400">No weak secret found in built-in list</p>
          <p className="text-[10px] text-zinc-500">{result.message}</p>
          {result.next && (
            <div className="rounded border border-zinc-700 bg-zinc-950 p-2 mt-1">
              <pre className="text-[10px] font-mono text-green-300">{result.next}</pre>
            </div>
          )}
        </div>
      )
    }
    if (result.cracked === true) {
      return (
        <div className="rounded-lg border border-green-700/50 bg-green-950/20 p-3 space-y-2">
          <div className="flex items-center gap-2">
            <CheckCircle size={14} className="text-green-400" />
            <p className="text-xs font-bold text-green-300">SECRET CRACKED: <span className="font-mono bg-zinc-800 px-1.5 rounded">{result.secret}</span></p>
          </div>
          <TokenList probes={result.probes} onCopy={onCopy} copiedToken={copiedToken} onSendToRepeater={onSendToRepeater} />
        </div>
      )
    }
  }

  const probes = result.probes || []
  if (probes.length === 0) return null

  const hits = probes.filter((p: any) => p.probe?.interesting)

  return (
    <div className="rounded-lg border border-zinc-700/50 bg-zinc-900/30 p-3 space-y-2">
      <div className="flex items-center gap-2">
        <p className="text-[10px] font-semibold text-zinc-400 uppercase flex-1">
          {probes.length} token{probes.length > 1 ? 's' : ''} generated
          {targetUrl && (() => { try { return <span className="text-zinc-600 font-normal ml-1">— probed {new URL(targetUrl).host}</span> } catch { return null } })()}
        </p>
        {hits.length > 0 && (
          <span className="text-[9px] px-1.5 py-0.5 rounded bg-green-900/50 text-green-300 font-bold">
            {hits.length} INTERESTING
          </span>
        )}
      </div>
      <TokenList probes={probes} onCopy={onCopy} copiedToken={copiedToken} onSendToRepeater={onSendToRepeater} />
    </div>
  )
}

function TokenList({ probes, onCopy, copiedToken, onSendToRepeater, jwksUrl }: {
  probes: any[]; onCopy: (t: string) => void; copiedToken: string | null
  onSendToRepeater?: (t: string) => void
  jwksUrl?: string
}) {
  const [expandedReqResp, setExpandedReqResp] = useState<Set<number>>(new Set())

  const toggleReqResp = (i: number) => {
    setExpandedReqResp(prev => {
      const n = new Set(prev); n.has(i) ? n.delete(i) : n.add(i); return n
    })
  }

  return (
    <div className="space-y-2">
      {jwksUrl && (
        <div className="rounded border border-blue-800/40 bg-blue-950/20 p-2 text-[10px] space-y-1">
          <p className="text-blue-300 font-semibold">JWKS endpoint auto-generated and hosted:</p>
          <code className="text-blue-200 font-mono break-all">{jwksUrl}</code>
          <p className="text-zinc-500">If target fetches this URL, the attack succeeded. Check backend logs.</p>
        </div>
      )}
      {probes.map((p: any, i: number) => (
        <div key={i} className={cn('rounded border space-y-1.5',
          p.probe?.interesting ? 'border-green-700/50 bg-green-950/10' : 'border-zinc-800 bg-zinc-950/50'
        )}>
          {/* Header row */}
          <div className="flex items-center gap-2 p-2.5">
            <span className="text-[10px] text-zinc-400 flex-1 truncate">{p.label}</span>
            {p.probe && !p.probe.error && (
              <span className={cn('text-[10px] font-mono font-bold shrink-0',
                p.probe.interesting ? 'text-green-400' : 'text-zinc-500'
              )}>
                {p.probe.status}
                {p.probe.length != null && <span className="text-zinc-600 ml-1">{p.probe.length}b</span>}
                {p.probe.interesting && <span className="text-green-400 ml-1 font-semibold">INTERESTING</span>}
              </span>
            )}
            {p.probe?.error && <span className="text-[10px] text-red-400 shrink-0">ERR: {p.probe.error}</span>}
            {(p.probe?.raw_request || p.probe?.raw_response) && (
              <button onClick={() => toggleReqResp(i)}
                className={cn('text-[9px] px-1.5 py-0.5 rounded border transition-colors shrink-0',
                  expandedReqResp.has(i) ? 'border-zinc-600 text-zinc-300' : 'border-zinc-700 text-zinc-500 hover:text-zinc-300'
                )}>
                {expandedReqResp.has(i) ? 'Hide' : 'Request/Response'}
              </button>
            )}
          </div>

          {/* Request / Response viewer */}
          {expandedReqResp.has(i) && p.probe && (
            <div className="border-t border-zinc-800 grid grid-cols-2 gap-0 divide-x divide-zinc-800">
              <div className="p-2">
                <p className="text-[9px] text-zinc-600 font-semibold uppercase mb-1">Request sent</p>
                <pre className="text-[9px] font-mono text-zinc-400 whitespace-pre-wrap break-all overflow-auto max-h-40">
                  {p.probe.raw_request || '(no request data)'}
                </pre>
              </div>
              <div className="p-2">
                <p className="text-[9px] text-zinc-600 font-semibold uppercase mb-1 flex items-center gap-1">
                  Response
                  {p.probe.status && (
                    <span className={cn('font-mono font-bold',
                      p.probe.interesting ? 'text-green-400' : 'text-zinc-500'
                    )}>{p.probe.status}</span>
                  )}
                </p>
                <pre className="text-[9px] font-mono text-zinc-400 whitespace-pre-wrap break-all overflow-auto max-h-40">
                  {p.probe.raw_response || p.probe.error || '(no response)'}
                </pre>
              </div>
            </div>
          )}

          {/* Token + actions */}
          {p.token && (
            <div className="px-2.5 pb-2.5">
              <pre className="text-[9px] font-mono text-zinc-400 bg-zinc-900 rounded p-1.5 overflow-x-auto whitespace-pre-wrap break-all max-h-12">
                {p.token}
              </pre>
              <div className="flex gap-1 mt-1">
                <button onClick={() => onCopy(p.token)}
                  className="flex items-center gap-1 text-[9px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 hover:text-zinc-200">
                  {copiedToken === p.token ? <><Check size={9} className="text-green-400" /> Copied</> : <><Copy size={9} /> Copy</>}
                </button>
                {onSendToRepeater && (
                  <button onClick={() => onSendToRepeater(p.token)}
                    className="flex items-center gap-1 text-[9px] px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 hover:text-blue-300">
                    <Repeat2 size={9} /> Repeater
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

// ── PayloadSetEditor ──────────────────────────────────────────────────────────
function PayloadSetEditor({ index, ps, attackType, onChange, onRemove }: {
  index: number
  ps: PayloadSetConfig
  attackType: string
  onChange: (ps: PayloadSetConfig) => void
  onRemove?: () => void
}) {
  const [expanded, setExpanded] = useState(true)
  const selectedSet = PAYLOAD_SETS.find(p => p.id === ps.builtinId)
  const preview = payloadValues(ps)
  const count = preview.length

  // Group by category
  const grouped = CATEGORY_ORDER.reduce((acc, cat) => {
    const sets = PAYLOAD_SETS.filter(p => p.category === cat)
    if (sets.length) acc[cat] = sets
    return acc
  }, {} as Record<string, PayloadSet[]>)

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/40">
      <button onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-2 px-3 py-2 text-xs text-zinc-300 hover:text-zinc-100">
        {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        <span className="font-medium">
          Payload Set {index + 1}
          {attackType !== 'sniper' && ` — Position ${index + 1}`}
        </span>
        <Badge variant="secondary" className="h-4 px-1 text-[10px] ml-1">{count} payloads</Badge>
        {onRemove && (
          <button onClick={e => { e.stopPropagation(); onRemove() }}
            className="ml-auto text-zinc-700 hover:text-red-400"><X size={11} /></button>
        )}
      </button>

      {expanded && (
        <div className="px-3 pb-3 space-y-2 border-t border-zinc-800">
          <div className="flex gap-2 mt-2">
            <button onClick={() => onChange({ ...ps, type: 'builtin' })}
              className={cn('px-2 py-1 rounded text-[11px] border', ps.type === 'builtin' ? 'border-orange-600 text-orange-400 bg-orange-950/30' : 'border-zinc-700 text-zinc-500')}>
              Built-in
            </button>
            <button onClick={() => onChange({ ...ps, type: 'custom' })}
              className={cn('px-2 py-1 rounded text-[11px] border', ps.type === 'custom' ? 'border-orange-600 text-orange-400 bg-orange-950/30' : 'border-zinc-700 text-zinc-500')}>
              Custom list
            </button>
            <button onClick={() => onChange({ ...ps, type: 'numbers' })}
              className={cn('px-2 py-1 rounded text-[11px] border', ps.type === 'numbers' ? 'border-orange-600 text-orange-400 bg-orange-950/30' : 'border-zinc-700 text-zinc-500')}>
              Numbers
            </button>
          </div>

          {ps.type === 'builtin' && (
            <div className="space-y-1.5">
              <select value={ps.builtinId} onChange={e => onChange({ ...ps, builtinId: e.target.value })}
                className="w-full h-7 rounded-md border border-zinc-700 bg-zinc-900 px-2 text-xs text-zinc-300">
                {Object.entries(grouped).map(([cat, sets]) => (
                  <optgroup key={cat} label={`── ${cat} ──`}>
                    {sets.map(s => (
                      <option key={s.id} value={s.id}>{s.name} ({s.payloads.length})</option>
                    ))}
                  </optgroup>
                ))}
              </select>
              {selectedSet && (
                <p className="text-[10px] text-zinc-600">{selectedSet.description}</p>
              )}
              {selectedSet && (
                <div className="bg-zinc-900 border border-zinc-800 rounded p-2 max-h-32 overflow-auto">
                  {selectedSet.payloads.slice(0, 10).map((p, i) => (
                    <div key={i} className="text-[10px] font-mono text-zinc-500 truncate">{p}</div>
                  ))}
                  {selectedSet.payloads.length > 10 && (
                    <div className="text-[10px] text-zinc-700">…{selectedSet.payloads.length - 10} more</div>
                  )}
                </div>
              )}
            </div>
          )}

          {ps.type === 'custom' && (
            <textarea
              className="w-full h-40 bg-zinc-900 border border-zinc-800 rounded p-2 text-[11px] font-mono text-zinc-300 resize-none focus:outline-none focus:border-zinc-600"
              placeholder={"one payload per line\npayload1\npayload2\n..."}
              value={ps.custom}
              onChange={e => onChange({ ...ps, custom: e.target.value })}
              spellCheck={false}
            />
          )}

          {ps.type === 'numbers' && (
            <div className="grid grid-cols-4 gap-2">
              {[
                ['Start', 'numberStart', ps.numberStart], ['End', 'numberEnd', ps.numberEnd],
                ['Step', 'numberStep', ps.numberStep], ['Zero padding', 'numberPad', ps.numberPad],
              ].map(([label, key, value]) => <label key={String(key)} className="text-[9px] text-zinc-500 space-y-1"><span>{label}</span><input type="number" value={Number(value)} min={key === 'numberPad' ? 0 : undefined} onChange={e => onChange({ ...ps, [key]: Number(e.target.value) } as PayloadSetConfig)} className="w-full h-8 bg-zinc-900 border border-zinc-800 rounded px-2 text-xs text-zinc-300" /></label>)}
            </div>
          )}

          <div className="grid grid-cols-[1fr_1fr_120px] gap-2 pt-2 border-t border-zinc-800">
            <label className="text-[9px] text-zinc-500 space-y-1"><span>Prefix</span><input value={ps.prefix} onChange={e => onChange({ ...ps, prefix: e.target.value })} placeholder="Optional" className="w-full h-8 bg-zinc-900 border border-zinc-800 rounded px-2 text-xs font-mono text-zinc-300" /></label>
            <label className="text-[9px] text-zinc-500 space-y-1"><span>Suffix</span><input value={ps.suffix} onChange={e => onChange({ ...ps, suffix: e.target.value })} placeholder="Optional" className="w-full h-8 bg-zinc-900 border border-zinc-800 rounded px-2 text-xs font-mono text-zinc-300" /></label>
            <label className="text-[9px] text-zinc-500 space-y-1"><span>Repeat list</span><input type="number" min={1} max={1000} value={ps.repeat} onChange={e => onChange({ ...ps, repeat: Math.max(1, Math.min(1000, Number(e.target.value) || 1)) })} className="w-full h-8 bg-zinc-900 border border-zinc-800 rounded px-2 text-xs text-zinc-300" /></label>
          </div>

          <div className="bg-zinc-950 border border-zinc-800 rounded p-2">
            <div className="flex items-center justify-between mb-1"><span className="text-[9px] uppercase font-semibold text-zinc-600">Generated preview</span><span className="text-[9px] text-zinc-600">{count.toLocaleString()} total</span></div>
            <div className="flex flex-wrap gap-1">{preview.slice(0, 12).map((value, i) => <code key={`${value}-${i}`} className="max-w-40 truncate rounded bg-zinc-900 px-1.5 py-0.5 text-[9px] text-orange-300" title={value}>{value}</code>)}{count > 12 && <span className="text-[9px] text-zinc-600 self-center">+{count - 12} more</span>}</div>
          </div>
        </div>
      )}
    </div>
  )
}
