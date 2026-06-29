import { useState, useRef, useEffect } from 'react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { Input } from '@/components/ui/input'
import { api, HttpError } from '@/api/http-client'
import { toast } from '@/stores/toast-store'
import { useScannerStore } from '@/stores/scanner-store'
import { useAppStore } from '@/stores/app-store'
import { useWorkspaceStore } from '@/stores/workspace-store'
import { cn } from '@/lib/utils'
import {
  useGraphqlStore, AUDIT_PHASES,
  type SchemaField, type OpKind, type QueryResponse, type ProbeState,
} from '@/stores/graphql-store'
import {
  Play, Square, Loader2, Search, Lock, Unlock, ShieldAlert, ShieldCheck,
  Share2, Send, UserX, Info, X, Copy, Check, Terminal, Sparkles, BookOpen,
  ChevronDown, Zap, ListTree, FlaskConical, Trash2,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import type { Finding } from '@/types'

const TOOL = 'graphql_audit'
type WorkView = 'console' | 'findings' | 'log'

const PHASE_LABELS: Record<string, string> = {
  unauth: 'No-auth probe',
  idor: 'IDOR / BOLA',
  error_leak: 'Error leaks',
  mutations: 'Mutation inventory',
  name_discovery: 'Name discovery',
}

const SEV_COLORS: Record<string, string> = {
  critical: 'bg-red-950/60 text-red-400 border-red-800',
  high:     'bg-orange-950/60 text-orange-400 border-orange-800',
  medium:   'bg-yellow-950/60 text-yellow-400 border-yellow-800',
  low:      'bg-blue-950/60 text-blue-400 border-blue-800',
  info:     'bg-zinc-800 text-zinc-400 border-zinc-700',
}

const SCALARS = new Set(['String', 'Int', 'Float', 'Boolean', 'ID'])

function SevBadge({ severity }: { severity: string }) {
  return (
    <span className={cn('text-[10px] px-1.5 py-0.5 rounded border font-medium capitalize shrink-0', SEV_COLORS[severity] ?? SEV_COLORS.info)}>
      {severity}
    </span>
  )
}

function linkify(text: string): React.ReactNode[] {
  return text.split(/(https?:\/\/[^\s)<>"']+)/g).map((part, i) =>
    /^https?:\/\//.test(part)
      ? <a key={i} href={part} target="_blank" rel="noreferrer" className="text-cyan-400 underline hover:text-cyan-300 break-all">{part}</a>
      : <span key={i}>{part}</span>
  )
}

// A minimal valid query/mutation for a root field, with required args stubbed.
function buildQuery(field: SchemaField, kind: OpKind): string {
  const argStr = field.args
    .filter(a => a.required)
    .map(a => `${a.name}: ${/id$|uuid|guid/i.test(a.name) || a.type === 'ID' ? '"REPLACE_ID"' : a.type === 'Int' || a.type === 'Float' ? '0' : a.type === 'Boolean' ? 'false' : '""'}`)
    .join(', ')
  const head = argStr ? `${field.name}(${argStr})` : field.name
  const sel = SCALARS.has(field.type) ? '' : ` { ${field.selection || '__typename'} }`
  return `${kind} {\n  ${head}${sel}\n}`
}

function curlFor(endpoint: string, query: string, useAuth: boolean, headers: Record<string, string>): string {
  const h = useAuth
    ? Object.entries(headers).filter(([k]) => ['authorization', 'cookie'].includes(k.toLowerCase()))
    : []
  const authFlags = h.map(([k, v]) => ` -H '${k}: ${v.length > 40 ? v.slice(0, 40) + '...' : v}'`).join('')
  const body = JSON.stringify({ query }).replace(/'/g, "'\\''")
  return `curl -ks -X POST '${endpoint}' -H 'content-type: application/json'${authFlags} -d '${body}'`
}

export function GraphQLAuditPage({ embedded }: { embedded?: boolean }) {
  const {
    endpoint, schema, introspecting, introspectError,
    selectedOp, queryDraft, variablesDraft, sending, authResp, anonResp, probeStatus,
    phases, sampleIds, extraQueries,
    setEndpoint, setSchema, setIntrospecting, setIntrospectError,
    selectOp, setQueryDraft, setVariablesDraft, setSending, setResponses, setProbe,
    togglePhase, setSampleIds, setExtraQueries,
  } = useGraphqlStore()

  const [view, setView] = useState<WorkView>('console')
  const [filter, setFilter] = useState('')
  const [configOpen, setConfigOpen] = useState(false)
  const [guideOpen, setGuideOpen] = useState(false)
  const [selected, setSelected] = useState<Finding | null>(null)
  const termRef = useRef<HTMLPreElement>(null)

  const { activeProject, globalTarget, getSessionOpts } = useAppStore()
  const { findings, rawOutput, activeScans, activeJobIds, clearToolOutput, removeFindingsByTool } = useScannerStore()
  const { addFinding: addToWorkspace } = useWorkspaceStore()
  const navigate = useNavigate()

  const tabFindings = findings.filter(f => f.tool === TOOL)
  const tabOutput = rawOutput[TOOL] ?? []
  const isRunning = activeScans.has(TOOL)
  const jobId = activeJobIds[TOOL]

  useEffect(() => {
    if (!endpoint && globalTarget) setEndpoint(globalTarget)
  }, [globalTarget])

  useEffect(() => {
    if (view === 'log' && termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight
  }, [tabOutput, view])

  const optsFor = () => ({
    ...getSessionOpts(),
    sample_ids: sampleIds,
    extra_queries: extraQueries,
    phases,
  })

  const handleIntrospect = async () => {
    if (!endpoint.trim()) { toast.error('Enter a GraphQL endpoint first', null); return }
    setIntrospecting(true)
    setIntrospectError(null)
    try {
      const res = await api.post<typeof schema>('/api/tools/graphql/introspect', {
        target: endpoint.trim(), options: getSessionOpts(),
      })
      setSchema(res)
      if (res && !res.introspection) {
        setIntrospectError('Introspection is disabled on this endpoint. Run a full audit to discover names, or send queries by hand in the Console.')
      } else if (res && res.queries[0]) {
        selectOp({ name: res.queries[0].name, kind: 'query' }, buildQuery(res.queries[0], 'query'))
      }
    } catch (err) {
      const msg = err instanceof HttpError ? err.message : String(err)
      setSchema(null)
      setIntrospectError(msg)
      toast.error('Introspection failed', msg)
    } finally {
      setIntrospecting(false)
    }
  }

  const handleRunAudit = async () => {
    if (!endpoint.trim()) { toast.error('Enter a GraphQL endpoint first', null); return }
    clearToolOutput(TOOL)
    setView('log')
    try {
      await api.post('/api/tools/graphql', { target: endpoint.trim(), options: optsFor(), project_id: activeProject ?? '' })
    } catch (err) {
      toast.error('Failed to start GraphQL audit', err)
    }
  }

  const handleStop = async () => {
    if (!jobId) return
    try { await api.delete(`/api/tools/jobs/${jobId}`) } catch {}
  }

  const handleClearFindings = async () => {
    removeFindingsByTool(TOOL)
    setSelected(null)
    const qs = new URLSearchParams({ tool: TOOL, ...(activeProject ? { project_id: activeProject } : {}) })
    try { await api.delete(`/api/scanner/findings?${qs}`) } catch {}
  }

  const pickOp = (field: SchemaField, kind: OpKind) => {
    selectOp({ name: field.name, kind }, buildQuery(field, kind))
    setView('console')
  }

  const parseVars = (): Record<string, unknown> | null => {
    if (!variablesDraft.trim()) return {}
    try { return JSON.parse(variablesDraft) } catch { toast.error('Variables are not valid JSON', null); return null }
  }

  const sendOne = async (useAuth: boolean): Promise<QueryResponse | null> => {
    const vars = parseVars()
    if (vars === null) return null
    try {
      return await api.post<QueryResponse>('/api/tools/graphql/query', {
        target: endpoint.trim(), query: queryDraft, options: getSessionOpts(), use_auth: useAuth, variables: vars,
      })
    } catch (err) {
      toast.error('Query failed', err instanceof HttpError ? err.message : String(err))
      return null
    }
  }

  const hasData = (r: QueryResponse | null, opName?: string): boolean => {
    if (!r || !r.json || typeof r.json !== 'object') return false
    if ((r.errors?.length ?? 0) > 0) return false
    const data = (r.json as { data?: Record<string, unknown> }).data
    if (!data) return false
    if (opName) return data[opName] != null
    return Object.values(data).some(v => v != null)
  }

  const handleSend = async (mode: 'auth' | 'anon' | 'both') => {
    if (!queryDraft.trim()) { toast.error('Write a query first', null); return }
    if (!endpoint.trim()) { toast.error('Enter a GraphQL endpoint first', null); return }
    setSending(true)
    try {
      if (mode === 'auth') {
        const r = await sendOne(true)
        if (r) setResponses(r, anonResp)
      } else if (mode === 'anon') {
        const r = await sendOne(false)
        if (r) setResponses(authResp, r)
      } else {
        const [a, n] = await Promise.all([sendOne(true), sendOne(false)])
        setResponses(a, n)
        if (n && selectedOp) {
          const open = hasData(n, selectedOp.name)
          setProbe(selectedOp.name, open ? 'open' : 'secured')
          if (open) toast.error('Reachable without auth', `'${selectedOp.name}' returned data anonymously`)
        }
      }
    } finally {
      setSending(false)
    }
  }

  const leakCount = Object.values(probeStatus).filter(s => s === 'open').length
    + tabFindings.filter(f => f.severity === 'high' && f.vuln_type === 'broken-access-control').length

  return (
    <WorkspaceShell title="GraphQL Auditor" subtitle="Introspect, explore and drive any GraphQL operation — authed vs anonymous" embedded={embedded}>
      <div className="flex flex-col h-full min-h-0 gap-3">

        {/* Endpoint bar */}
        <div className="rounded-lg border border-fuchsia-500/30 bg-fuchsia-950/15 p-3 space-y-2.5 shrink-0">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Share2 size={15} className="text-fuchsia-400" />
              <span className="text-sm font-semibold text-fuchsia-400">GraphQL Auditor</span>
            </div>
            <button onClick={() => setGuideOpen(true)} className="flex items-center gap-1 text-[10px] text-zinc-600 hover:text-zinc-400 transition-colors shrink-0">
              <Info size={11} /> Guide
            </button>
          </div>

          <div className="flex gap-2">
            <Input
              value={endpoint}
              onChange={e => setEndpoint(e.target.value)}
              placeholder="https://api.target.com/graphql"
              className="bg-zinc-900/80 text-sm flex-1 font-mono"
              onKeyDown={e => { if (e.key === 'Enter' && !introspecting) handleIntrospect() }}
            />
            <button
              onClick={handleIntrospect}
              disabled={introspecting || !endpoint.trim()}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-fuchsia-700/70 text-fuchsia-300 hover:bg-fuchsia-950/40 disabled:opacity-40 disabled:cursor-not-allowed transition-colors shrink-0"
            >
              {introspecting ? <Loader2 size={11} className="animate-spin" /> : <ListTree size={11} />} Introspect
            </button>
            {isRunning ? (
              <button onClick={handleStop} className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-red-700 text-red-400 hover:bg-red-950/30 transition-colors shrink-0">
                <Square size={11} className="fill-current" /> Stop
              </button>
            ) : (
              <button
                onClick={handleRunAudit}
                disabled={!endpoint.trim()}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-green-700/70 text-green-400 hover:bg-green-950/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors shrink-0"
              >
                <Play size={11} /> Run full audit
              </button>
            )}
          </div>

          {/* Status chips */}
          <div className="flex items-center gap-2 flex-wrap">
            <Chip label="Introspection" value={schema ? (schema.introspection ? 'ENABLED' : 'disabled') : '—'} tone={schema ? (schema.introspection ? 'red' : 'zinc') : 'zinc'} />
            <Chip label="Queries" value={schema ? String(schema.queries.length) : '—'} tone="fuchsia" />
            <Chip label="Mutations" value={schema ? String(schema.mutations.length) : '—'} tone="amber" />
            <Chip label="Types" value={schema ? String(schema.types_count) : '—'} tone="zinc" />
            <Chip label="Leaks" value={String(leakCount)} tone={leakCount > 0 ? 'red' : 'zinc'} />
            {isRunning && <span className="flex items-center gap-1.5 text-[10px] text-green-400"><span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" /> auditing…</span>}
            <button onClick={() => setConfigOpen(o => !o)} className="ml-auto flex items-center gap-1 text-[10px] text-zinc-500 hover:text-zinc-300 transition-colors">
              <Zap size={11} /> Audit config <ChevronDown size={10} className={cn('transition-transform', configOpen && 'rotate-180')} />
            </button>
          </div>

          {configOpen && (
            <div className="space-y-2 rounded-md border border-zinc-800 bg-zinc-900/40 p-2.5">
              <div className="flex flex-wrap gap-1.5">
                {AUDIT_PHASES.map(p => {
                  const on = phases.includes(p)
                  return (
                    <button
                      key={p}
                      onClick={() => togglePhase(p)}
                      className={cn('text-[10px] px-2 py-1 rounded border transition-colors',
                        on ? 'border-fuchsia-700/60 bg-fuchsia-950/30 text-fuchsia-300' : 'border-zinc-800 text-zinc-600 hover:text-zinc-400')}
                    >
                      {on ? '✓ ' : ''}{PHASE_LABELS[p]}
                    </button>
                  )
                })}
                <span className="text-[9px] text-zinc-600 self-center ml-1">Introspection always runs</span>
              </div>
              <Input value={sampleIds} onChange={e => setSampleIds(e.target.value)} placeholder="Sample IDs for IDOR test (your loyaltyId, userId...)" className="bg-zinc-900/80 text-xs" />
              <Input value={extraQueries} onChange={e => setExtraQueries(e.target.value)} placeholder="Extra query names if introspection is off (me, orders...)" className="bg-zinc-900/80 text-xs" />
            </div>
          )}

          {introspectError && (
            <div className="text-[10px] text-amber-400/90 leading-relaxed border-l-2 border-amber-700/50 pl-2">{introspectError}</div>
          )}
        </div>

        {/* Body: schema rail + work area */}
        <div className="flex gap-3 flex-1 min-h-0">
          <SchemaRail
            schema={schema}
            filter={filter}
            setFilter={setFilter}
            selectedName={selectedOp?.name ?? null}
            probeStatus={probeStatus}
            onPick={pickOp}
          />

          <div className="flex-1 flex flex-col min-w-0 min-h-0">
            {/* Inner tabs */}
            <div className="flex items-center gap-1 mb-2 shrink-0">
              <div className="flex gap-1 bg-zinc-900/50 rounded-lg p-1">
                <ViewTab active={view === 'console'} onClick={() => setView('console')} icon={FlaskConical} label="Console" />
                <ViewTab active={view === 'findings'} onClick={() => setView('findings')} icon={ShieldAlert} label="Findings" count={tabFindings.length} />
                <ViewTab active={view === 'log'} onClick={() => setView('log')} icon={Terminal} label="Log" running={isRunning} />
              </div>
              {view === 'findings' && tabFindings.length > 0 && (
                <button onClick={handleClearFindings} className="ml-auto flex items-center gap-1.5 px-2.5 py-1.5 text-[10px] text-zinc-500 hover:text-red-400 rounded-md hover:bg-red-950/20 transition-colors">
                  <Trash2 size={12} /> Clear all
                </button>
              )}
            </div>

            {view === 'console' && (
              <Console
                endpoint={endpoint}
                selectedOpName={selectedOp?.name ?? null}
                queryDraft={queryDraft}
                setQueryDraft={setQueryDraft}
                variablesDraft={variablesDraft}
                setVariablesDraft={setVariablesDraft}
                sending={sending}
                authResp={authResp}
                anonResp={anonResp}
                sessionHeaders={getSessionOpts().session_headers}
                onSend={handleSend}
              />
            )}

            {view === 'findings' && (
              <FindingsView
                findings={tabFindings}
                running={isRunning}
                selected={selected}
                setSelected={setSelected}
                onWorkspace={f => { addToWorkspace(f); navigate('/workspace') }}
                onAnalyze={f => { addToWorkspace(f); navigate('/copilot') }}
              />
            )}

            {view === 'log' && (
              <pre ref={termRef} className="flex-1 rounded-lg border border-zinc-800 bg-black p-4 overflow-auto text-[11px] font-mono leading-relaxed min-h-0">
                {isRunning && tabOutput.length === 0 && <span className="text-zinc-600 animate-pulse block">Starting GraphQL audit…</span>}
                {tabOutput.map((line, i) => (
                  <span key={i} className={cn('block',
                    line.startsWith('$') ? 'text-green-400 font-bold' :
                    line.includes('[unauth-ok]') || line.includes('[IDOR]') ? 'text-red-400 font-semibold' :
                    line.includes('[+]') ? 'text-fuchsia-300' :
                    line.includes('error') || line.includes('Error') ? 'text-red-400' :
                    'text-zinc-300')}>{line}</span>
                ))}
                {!isRunning && tabOutput.length === 0 && <span className="text-zinc-700">No output yet — run a full audit above.</span>}
              </pre>
            )}
          </div>
        </div>
      </div>

      {guideOpen && <GuideModal onClose={() => setGuideOpen(false)} />}
    </WorkspaceShell>
  )
}

function Chip({ label, value, tone }: { label: string; value: string; tone: 'red' | 'fuchsia' | 'amber' | 'zinc' }) {
  const tones = {
    red: 'border-red-800/60 text-red-400',
    fuchsia: 'border-fuchsia-800/50 text-fuchsia-300',
    amber: 'border-amber-800/50 text-amber-300',
    zinc: 'border-zinc-800 text-zinc-500',
  }
  return (
    <span className={cn('text-[10px] px-2 py-0.5 rounded border bg-zinc-900/40', tones[tone])}>
      {label} <span className="font-mono font-semibold">{value}</span>
    </span>
  )
}

function ViewTab({ active, onClick, icon: Icon, label, count, running }: {
  active: boolean; onClick: () => void; icon: React.ComponentType<{ size?: number; className?: string }>; label: string; count?: number; running?: boolean
}) {
  return (
    <button onClick={onClick} className={cn('flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors',
      active ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200')}>
      <Icon size={11} /> {label}
      {count != null && count > 0 && <span className="text-[9px] px-1 rounded bg-zinc-600 text-zinc-200">{count}</span>}
      {running && <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse shrink-0" />}
    </button>
  )
}

function LockGlyph({ state, sensitive }: { state: ProbeState; sensitive: boolean }) {
  if (state === 'open') return <Unlock size={12} className="text-red-500 shrink-0" />
  if (state === 'secured') return <ShieldCheck size={12} className="text-emerald-500 shrink-0" />
  return <Lock size={12} className={cn('shrink-0', sensitive ? 'text-orange-500/70' : 'text-zinc-700')} />
}

function SchemaRail({ schema, filter, setFilter, selectedName, probeStatus, onPick }: {
  schema: ReturnType<typeof useGraphqlStore.getState>['schema']
  filter: string; setFilter: (v: string) => void
  selectedName: string | null
  probeStatus: Record<string, ProbeState>
  onPick: (field: SchemaField, kind: OpKind) => void
}) {
  const match = (f: SchemaField) => !filter || f.name.toLowerCase().includes(filter.toLowerCase())
  const queries = (schema?.queries ?? []).filter(match)
  const mutations = (schema?.mutations ?? []).filter(match)

  return (
    <div className="w-64 shrink-0 flex flex-col rounded-lg border border-zinc-800 bg-zinc-900/30 min-h-0">
      <div className="p-2 border-b border-zinc-800 shrink-0">
        <div className="relative">
          <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2 text-zinc-600" />
          <input
            value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter operations…"
            className="w-full text-[11px] bg-zinc-950 border border-zinc-800 rounded pl-7 pr-2 py-1.5 text-zinc-300 placeholder:text-zinc-700 focus:outline-none focus:border-fuchsia-800"
          />
        </div>
      </div>
      <div className="flex-1 overflow-y-auto p-1.5 space-y-3 min-h-0">
        {!schema && <div className="px-2 py-8 text-center text-[10px] text-zinc-600 leading-relaxed">Introspect an endpoint to map its schema, or run a full audit to discover operations.</div>}
        {schema && !schema.introspection && (queries.length + mutations.length === 0) && (
          <div className="px-2 py-8 text-center text-[10px] text-zinc-600 leading-relaxed">Introspection is off. Use the Console to send queries by hand, or run a full audit for name discovery.</div>
        )}
        {queries.length > 0 && <OpGroup title="Queries" kind="query" fields={queries} selectedName={selectedName} probeStatus={probeStatus} onPick={onPick} />}
        {mutations.length > 0 && <OpGroup title="Mutations" kind="mutation" fields={mutations} selectedName={selectedName} probeStatus={probeStatus} onPick={onPick} />}
      </div>
    </div>
  )
}

function OpGroup({ title, kind, fields, selectedName, probeStatus, onPick }: {
  title: string; kind: OpKind; fields: SchemaField[]
  selectedName: string | null; probeStatus: Record<string, ProbeState>
  onPick: (field: SchemaField, kind: OpKind) => void
}) {
  const accent = kind === 'query' ? 'text-fuchsia-400' : 'text-amber-400'
  return (
    <div>
      <div className={cn('text-[9px] uppercase tracking-widest px-2 pb-1 font-semibold', accent)}>{title} · {fields.length}</div>
      <div className="space-y-0.5">
        {fields.map(f => {
          const state = probeStatus[f.name] ?? 'unknown'
          const active = selectedName === f.name
          return (
            <button
              key={f.name}
              onClick={() => onPick(f, kind)}
              className={cn('w-full flex items-center gap-2 px-2 py-1.5 rounded text-left transition-colors',
                active ? 'bg-zinc-800' : 'hover:bg-zinc-800/50',
                state === 'open' && 'bg-red-950/20')}
              title={f.args.length ? `${f.name}(${f.args.map(a => a.name + (a.required ? '!' : '')).join(', ')}): ${f.type}` : `${f.name}: ${f.type}`}
            >
              <LockGlyph state={state} sensitive={f.sensitive} />
              <span className={cn('text-[11px] font-mono truncate flex-1', active ? 'text-zinc-100' : 'text-zinc-400')}>{f.name}</span>
              {f.sensitive && <span className="text-[8px] px-1 rounded bg-orange-950/50 text-orange-400/80 shrink-0">sens</span>}
            </button>
          )
        })}
      </div>
    </div>
  )
}

function Console({ endpoint, selectedOpName, queryDraft, setQueryDraft, variablesDraft, setVariablesDraft, sending, authResp, anonResp, sessionHeaders, onSend }: {
  endpoint: string; selectedOpName: string | null
  queryDraft: string; setQueryDraft: (v: string) => void
  variablesDraft: string; setVariablesDraft: (v: string) => void
  sending: boolean
  authResp: QueryResponse | null; anonResp: QueryResponse | null
  sessionHeaders: string
  onSend: (mode: 'auth' | 'anon' | 'both') => void
}) {
  const headersObj = Object.fromEntries(
    sessionHeaders.replace(/\n/g, ',').split(',').map(p => p.split(/:(.*)/).map(s => s.trim())).filter(p => p[0] && p[1]).map(p => [p[0], p[1]])
  )
  const verdict = anonResp ? verdictFor(anonResp, selectedOpName) : null

  return (
    <div className="flex-1 flex flex-col min-h-0 gap-2">
      {/* Query editor */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900/30 p-2.5 shrink-0">
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-[10px] text-zinc-500 uppercase tracking-wide">Query {selectedOpName && <span className="text-fuchsia-400 font-mono normal-case">· {selectedOpName}</span>}</span>
          <div className="flex items-center gap-1.5">
            <button onClick={() => onSend('auth')} disabled={sending} className="flex items-center gap-1 px-2 py-1 text-[10px] rounded border border-zinc-700 text-zinc-300 hover:border-zinc-500 disabled:opacity-50 transition-colors">
              <Send size={10} /> As You
            </button>
            <button onClick={() => onSend('anon')} disabled={sending} className="flex items-center gap-1 px-2 py-1 text-[10px] rounded border border-zinc-700 text-zinc-300 hover:border-zinc-500 disabled:opacity-50 transition-colors">
              <UserX size={10} /> As Anon
            </button>
            <button onClick={() => onSend('both')} disabled={sending} className="flex items-center gap-1 px-2 py-1 text-[10px] rounded border border-fuchsia-700 text-fuchsia-300 hover:bg-fuchsia-950/40 disabled:opacity-50 transition-colors">
              {sending ? <Loader2 size={10} className="animate-spin" /> : <ShieldAlert size={10} />} Compare
            </button>
          </div>
        </div>
        <textarea
          value={queryDraft}
          onChange={e => setQueryDraft(e.target.value)}
          spellCheck={false}
          placeholder={'query {\n  me { id email }\n}'}
          className="w-full h-28 text-[11px] bg-zinc-950 border border-zinc-800 rounded p-2 text-fuchsia-200 font-mono resize-none focus:outline-none focus:border-fuchsia-800 leading-relaxed"
        />
        <details className="mt-1.5">
          <summary className="text-[9px] text-zinc-600 cursor-pointer hover:text-zinc-400">Variables (JSON, optional)</summary>
          <textarea
            value={variablesDraft}
            onChange={e => setVariablesDraft(e.target.value)}
            spellCheck={false}
            placeholder='{ "id": "123" }'
            className="mt-1 w-full h-14 text-[10px] bg-zinc-950 border border-zinc-800 rounded p-2 text-zinc-300 font-mono resize-none focus:outline-none focus:border-zinc-700"
          />
        </details>
      </div>

      {verdict && (
        <div className={cn('flex items-center gap-2 rounded-md px-3 py-1.5 text-[11px] shrink-0 border',
          verdict.open ? 'border-red-800/60 bg-red-950/20 text-red-300' : 'border-emerald-800/50 bg-emerald-950/15 text-emerald-300')}>
          {verdict.open ? <Unlock size={13} /> : <ShieldCheck size={13} />}
          <span>{verdict.text}</span>
        </div>
      )}

      {/* Response lanes */}
      <div className="flex-1 grid grid-cols-2 gap-2 min-h-0">
        <ResponseLane title="Authenticated" subtitle="with your session" tone="zinc" resp={authResp} endpoint={endpoint} query={queryDraft} useAuth headers={headersObj} />
        <ResponseLane title="Anonymous" subtitle="token stripped" tone="fuchsia" resp={anonResp} endpoint={endpoint} query={queryDraft} useAuth={false} headers={headersObj} />
      </div>
    </div>
  )
}

function verdictFor(anon: QueryResponse, opName: string | null): { open: boolean; text: string } {
  const j = anon.json as { data?: Record<string, unknown> } | null
  const errs = anon.errors?.length ?? 0
  const data = j?.data
  const got = data && (opName ? data[opName] != null : Object.values(data).some(v => v != null))
  if (got) return { open: true, text: 'Broken access control — the anonymous request returned data. Build the full selection and pull it.' }
  if (errs > 0) return { open: false, text: 'Anonymous request was rejected (auth error). Access control looks enforced for this operation.' }
  return { open: false, text: 'Anonymous request returned no data. Likely enforced — verify by hand.' }
}

function StatusPill({ status }: { status: number }) {
  const tone = status === 0 ? 'text-zinc-500' : status < 300 ? 'text-green-400' : status < 400 ? 'text-blue-400' : status < 500 ? 'text-amber-400' : 'text-red-400'
  return <span className={cn('font-mono font-bold text-[11px]', tone)}>{status || 'ERR'}</span>
}

function ResponseLane({ title, subtitle, tone, resp, endpoint, query, useAuth, headers }: {
  title: string; subtitle: string; tone: 'zinc' | 'fuchsia'
  resp: QueryResponse | null; endpoint: string; query: string; useAuth: boolean; headers: Record<string, string>
}) {
  const [copied, setCopied] = useState<'json' | 'curl' | null>(null)
  const copy = (what: 'json' | 'curl', text: string) => {
    navigator.clipboard.writeText(text).then(() => { setCopied(what); setTimeout(() => setCopied(null), 1500) })
  }
  const pretty = resp ? (() => { try { return JSON.stringify(resp.json ?? resp.body, null, 2) } catch { return resp.body } })() : ''
  const accent = tone === 'fuchsia' ? 'text-fuchsia-400' : 'text-zinc-400'

  return (
    <div className="flex flex-col rounded-lg border border-zinc-800 bg-zinc-950/60 min-h-0">
      <div className="flex items-center justify-between gap-2 px-2.5 py-1.5 border-b border-zinc-800 shrink-0">
        <div className="flex items-center gap-2 min-w-0">
          <span className={cn('text-[10px] font-semibold uppercase tracking-wide', accent)}>{title}</span>
          <span className="text-[9px] text-zinc-600 truncate">{subtitle}</span>
        </div>
        {resp && (
          <div className="flex items-center gap-2 shrink-0">
            <StatusPill status={resp.status} />
            <span className="text-[9px] text-zinc-600">{resp.time_ms}ms</span>
            <button onClick={() => copy('curl', curlFor(endpoint, query, useAuth, headers))} title="Copy as curl" className="text-zinc-600 hover:text-zinc-300">
              {copied === 'curl' ? <Check size={11} className="text-green-400" /> : <Terminal size={11} />}
            </button>
            <button onClick={() => copy('json', pretty)} title="Copy response" className="text-zinc-600 hover:text-zinc-300">
              {copied === 'json' ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
            </button>
          </div>
        )}
      </div>
      <div className="flex-1 overflow-auto min-h-0">
        {!resp ? (
          <div className="h-full grid place-items-center text-[10px] text-zinc-700 p-4 text-center">No response yet.</div>
        ) : (
          <>
            {resp.leaked_urls.length > 0 && (
              <div className="px-2.5 py-1.5 border-b border-orange-900/40 bg-orange-950/15 text-[10px] text-orange-300">
                Leaked internal URL(s): {resp.leaked_urls.map((u, i) => <span key={i} className="block break-all">{linkify(u)}</span>)}
              </div>
            )}
            <pre className="p-2.5 text-[10px] font-mono text-zinc-300 whitespace-pre-wrap break-all leading-relaxed">{linkify(pretty)}</pre>
          </>
        )}
      </div>
    </div>
  )
}

function FindingsView({ findings, running, selected, setSelected, onWorkspace, onAnalyze }: {
  findings: Finding[]; running: boolean
  selected: Finding | null; setSelected: (f: Finding | null) => void
  onWorkspace: (f: Finding) => void; onAnalyze: (f: Finding) => void
}) {
  const hostFor = (url: string | null) => {
    if (!url) return '-'
    try { return new URL(url.startsWith('http') ? url : `https://${url}`).hostname } catch { return url.slice(0, 30) }
  }
  return (
    <div className="flex-1 flex gap-3 min-h-0">
      <div className="flex-1 overflow-auto rounded-lg border border-zinc-800 min-h-0">
        <table className="w-full text-xs">
          <thead className="bg-zinc-900 sticky top-0 z-10">
            <tr className="text-zinc-500 text-left">
              <th className="px-3 py-2 w-20">Severity</th>
              <th className="px-3 py-2">Title</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f, i) => (
              <tr key={f.id ?? i} onClick={() => setSelected(selected?.id === f.id ? null : f)}
                className={cn('border-b border-zinc-800/50 cursor-pointer transition-colors', selected?.id === f.id ? 'bg-zinc-800' : 'hover:bg-zinc-800/40')}>
                <td className="px-3 py-1.5"><SevBadge severity={f.severity} /></td>
                <td className="px-3 py-1.5 text-zinc-300">{f.title}</td>
              </tr>
            ))}
            {findings.length === 0 && (
              <tr><td colSpan={2} className="px-3 py-16 text-center text-zinc-600 text-xs">
                {running ? <span className="flex items-center justify-center gap-2"><Loader2 size={13} className="animate-spin" /> Auditing…</span> : 'No findings yet. Run a full audit.'}
              </td></tr>
            )}
          </tbody>
        </table>
      </div>

      {selected && (
        <div className="w-96 shrink-0 rounded-lg border border-zinc-800 bg-zinc-900/50 p-4 overflow-y-auto text-xs space-y-3 min-h-0">
          <div className="flex items-start justify-between gap-2">
            <h3 className="font-semibold text-zinc-200 leading-tight flex-1">{selected.title}</h3>
            <button onClick={() => setSelected(null)} className="text-zinc-600 hover:text-zinc-400 shrink-0"><X size={13} /></button>
          </div>
          <SevBadge severity={selected.severity} />
          {selected.url && <div><div className="text-zinc-600 mb-0.5 text-[10px]">URL</div><div className="font-mono text-blue-400 text-[10px] break-all">{selected.url}</div></div>}
          {selected.parameter && <div><div className="text-zinc-600 mb-0.5 text-[10px]">Operation</div><div className="font-mono text-yellow-400">{selected.parameter}</div></div>}
          {selected.description && <div><div className="text-zinc-600 mb-0.5 text-[10px]">Description</div><div className="text-zinc-400 leading-relaxed">{selected.description}</div></div>}
          {selected.evidence && (
            <div>
              <div className="text-zinc-600 mb-0.5 text-[10px]">Evidence</div>
              <pre className="text-[10px] bg-zinc-950 rounded p-2 overflow-auto text-zinc-400 whitespace-pre-wrap break-all leading-relaxed max-h-80">{linkify(selected.evidence)}</pre>
            </div>
          )}
          <div className="flex gap-2 pt-1">
            <button onClick={() => onWorkspace(selected)} className="flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 text-[10px] rounded border border-zinc-700 text-zinc-400 hover:text-zinc-200 hover:border-zinc-500 transition-colors">
              <BookOpen size={10} /> Workspace
            </button>
            <button onClick={() => onAnalyze(selected)} className="flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 text-[10px] rounded border border-purple-800/50 text-purple-400 hover:text-purple-300 hover:border-purple-700 transition-colors">
              <Sparkles size={10} /> Analyze AI
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function GuideModal({ onClose }: { onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4" onClick={onClose}>
      <div className="w-full max-w-2xl max-h-[85vh] flex flex-col rounded-xl border border-zinc-700 bg-zinc-950 shadow-2xl overflow-hidden" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3 border-b border-zinc-800 bg-zinc-900 shrink-0">
          <div className="flex items-center gap-2"><Share2 size={14} className="text-fuchsia-400" /><span className="text-sm font-semibold text-zinc-100">GraphQL Auditor</span></div>
          <button onClick={onClose} className="text-zinc-600 hover:text-zinc-300"><X size={14} /></button>
        </div>
        <div className="overflow-y-auto p-5 text-xs text-zinc-300 space-y-4">
          <Section title="How to use it">
            <ol className="space-y-1.5 text-[11px] text-zinc-400 list-decimal pl-4 leading-relaxed">
              <li>Paste the GraphQL endpoint (e.g. <code className="text-fuchsia-400">https://api.target.com/graphql</code>) and hit <span className="text-fuchsia-300">Introspect</span> to map the schema.</li>
              <li>Click any operation in the left rail — a query is generated into the <span className="text-zinc-200">Console</span>.</li>
              <li>Hit <span className="text-fuchsia-300">Compare</span> to send it with your session and with the token stripped, side by side. If the anonymous lane returns data, that is broken access control.</li>
              <li>The lock next to each operation flips to <span className="text-red-400">open</span> (reachable anonymously) or <span className="text-emerald-400">secured</span> as you test.</li>
              <li><span className="text-green-300">Run full audit</span> automates all of it — introspection, no-auth probing, IDOR, error leaks and a mutation inventory — into the Findings tab.</li>
            </ol>
          </Section>
          <Section title="The three bug classes">
            <div className="space-y-1 text-[11px] text-zinc-400 leading-relaxed">
              <p><span className="text-amber-400">1. Introspection left on</span> — hands attackers the whole API map.</p>
              <p><span className="text-amber-400">2. Missing per-operation auth</span> — operations that should need login return data while logged out.</p>
              <p><span className="text-amber-400">3. IDOR</span> — an object-by-id query that does not check the id is yours. Paste a sample id in Audit config to auto-test.</p>
            </div>
          </Section>
          <Section title="Set your Session first">
            <p className="text-[11px] text-zinc-400 leading-relaxed">
              Paste your <code className="text-fuchsia-400">Authorization: Bearer …</code> and any context headers (x-region…) in the sidebar Session panel.
              The console sends the authed lane with them and strips them for the anonymous lane, so you compare what a real user sees vs an anonymous client.
            </p>
          </Section>
          <Section title="Is it safe?">
            <p className="text-[11px] text-zinc-400 leading-relaxed">
              The audit and the console are read-only — they send queries and introspection, never mutations. The IDOR test only uses IDs you paste. Only run it against targets you are authorized to test.
            </p>
          </Section>
        </div>
        <div className="shrink-0 px-5 py-3 border-t border-zinc-800 bg-zinc-900 flex justify-end">
          <button onClick={onClose} className="px-4 py-1.5 rounded text-xs border border-zinc-700 text-zinc-400 hover:text-zinc-200 hover:border-zinc-500 transition-colors">Close</button>
        </div>
      </div>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return <div className="space-y-1.5"><h3 className="text-xs font-semibold text-zinc-200">{title}</h3>{children}</div>
}
