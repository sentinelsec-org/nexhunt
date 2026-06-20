import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { BookOpen, Check, Copy, ExternalLink, Filter, Route, Search, ShieldAlert, Sparkles } from 'lucide-react'
import type { Finding } from '@/types'
import { cn } from '@/lib/utils'
import { useWorkspaceStore } from '@/stores/workspace-store'

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

const METHOD_COLOR: Record<string, string> = {
  GET: 'text-cyan-300 border-cyan-800/70 bg-cyan-950/30',
  POST: 'text-green-300 border-green-800/70 bg-green-950/30',
  PUT: 'text-amber-300 border-amber-800/70 bg-amber-950/30',
  PATCH: 'text-orange-300 border-orange-800/70 bg-orange-950/30',
  DELETE: 'text-red-300 border-red-800/70 bg-red-950/30',
}

function parseMap(findings: Finding[]) {
  const summary = findings.find(f => f.template_id?.startsWith('jsmap-fw-') || f.title.includes('[JS API Map] Auth framework:'))
  const frameworkMatch = summary?.title.match(/Auth framework:\s*(.*?)\s*[—-]\s*(\d+) routes mapped/i)
  const frameworks = frameworkMatch?.[1]?.split(',').map(v => v.trim()).filter(Boolean) ?? []
  const mappedCount = Number(frameworkMatch?.[2] || 0)
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
  const parsed = useMemo(() => parseMap(findings), [findings])
  const [view, setView] = useState<MapView>('privileged')
  const [filter, setFilter] = useState('')
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [copied, setCopied] = useState<string | null>(null)

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

  if (!findings.length) return (
    <div className="flex-1 rounded-lg border border-zinc-800 bg-zinc-950/40 flex flex-col items-center justify-center text-center px-6">
      <Route size={25} className={cn('mb-3', running ? 'text-teal-400 animate-pulse' : 'text-zinc-700')} />
      <div className="text-sm font-medium text-zinc-300">{running ? 'Mapping JavaScript routes' : 'No API map yet'}</div>
      <div className="text-xs text-zinc-600 mt-1">Run the mapper against an application host or JavaScript bundle.</div>
    </div>
  )

  return (
    <div className="flex-1 min-h-0 flex flex-col gap-3">
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-px rounded-lg border border-zinc-800 bg-zinc-800 overflow-hidden shrink-0">
        <Metric label="Framework" value={parsed.frameworks.join(', ') || 'Unknown'} accent />
        <Metric label="Routes mapped" value={String(parsed.mappedCount)} />
        <Metric label="Privileged" value={String(parsed.routes.filter(r => r.privileged).length)} danger />
        <Metric label="Origin" value={`${declaredCount} declared / ${inferredCount} inferred`} />
      </div>

      {parsed.bases.length > 0 && (
        <div className="flex items-center gap-2 overflow-x-auto text-[10px] shrink-0">
          <span className="text-zinc-600 uppercase font-semibold">API bases</span>
          {parsed.bases.map(base => <button key={base} onClick={() => copy(base)} className="font-mono text-teal-300 border border-teal-900/60 bg-teal-950/20 rounded px-2 py-1 hover:border-teal-700 whitespace-nowrap">{base}</button>)}
        </div>
      )}

      <div className="flex-1 min-h-0 grid grid-cols-[minmax(420px,1.25fr)_minmax(330px,.75fr)] gap-3">
        <div className="min-h-0 rounded-lg border border-zinc-800 overflow-hidden flex flex-col">
          <div className="p-2 border-b border-zinc-800 bg-zinc-900/70 flex items-center gap-2 shrink-0">
            <div className="flex bg-zinc-950 rounded-md p-0.5">
              <ViewButton active={view === 'privileged'} onClick={() => setView('privileged')} label="Privileged" count={parsed.routes.filter(r => r.privileged).length} />
              <ViewButton active={view === 'all'} onClick={() => setView('all')} label="All routes" count={parsed.routes.length} />
              <ViewButton active={view === 'roles'} onClick={() => setView('roles')} label="Role model" count={parsed.roleFindings.length} />
            </div>
            {view !== 'roles' && <div className="relative ml-auto w-56">
              <Search size={11} className="absolute left-2 top-1/2 -translate-y-1/2 text-zinc-600" />
              <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter path, method, source" className="w-full h-7 pl-7 pr-2 rounded border border-zinc-800 bg-zinc-950 text-[10px] text-zinc-300 placeholder:text-zinc-700 focus:outline-none focus:border-teal-800" />
            </div>}
          </div>

          {view === 'roles' ? (
            <div className="overflow-y-auto p-3 space-y-2">
              {parsed.roleFindings.map(finding => <div key={finding.id} className="border border-zinc-800 rounded-lg p-3 bg-zinc-950/40"><div className="flex items-center gap-2"><ShieldAlert size={13} className="text-amber-400" /><span className="text-xs text-zinc-200">{finding.title.replace('[JS API Map] ', '')}</span></div><p className="text-[10px] text-zinc-500 mt-2 leading-relaxed">{finding.description}</p></div>)}
              {!parsed.roleFindings.length && <Empty text="No privileged role arrays were identified in the bundles." />}
            </div>
          ) : (
            <div className="overflow-y-auto">
              <div className="grid grid-cols-[68px_minmax(180px,1fr)_120px_72px] gap-3 px-3 py-2 bg-zinc-950 text-[9px] uppercase font-semibold text-zinc-600 sticky top-0 z-10">
                <span>Method</span><span>Route</span><span>Source</span><span>Risk</span>
              </div>
              {filteredRoutes.map(route => <button key={route.key} onClick={() => setSelectedKey(route.key)} className={cn('w-full grid grid-cols-[68px_minmax(180px,1fr)_120px_72px] gap-3 items-center px-3 py-2.5 text-left border-t border-zinc-800/70 hover:bg-zinc-900/60', selected?.key === route.key && 'bg-teal-950/15')}>
                <span className={cn('w-fit rounded border px-1.5 py-0.5 font-mono text-[9px] font-bold', METHOD_COLOR[route.method] || 'text-zinc-400 border-zinc-700')}>{route.method}</span>
                <span className="font-mono text-[11px] text-zinc-200 truncate">{route.path}</span>
                <span className={cn('text-[9px] truncate', route.source === 'declared' ? 'text-cyan-400' : 'text-zinc-500')}>{route.source === 'declared' ? 'In JavaScript' : route.source.replace('expanded:', 'Inferred: ')}</span>
                <span className={cn('text-[9px] font-semibold uppercase', route.severity === 'high' ? 'text-red-400' : route.severity === 'medium' ? 'text-amber-400' : 'text-zinc-600')}>{route.privileged ? route.severity : 'mapped'}</span>
              </button>)}
              {!filteredRoutes.length && <Empty text="No routes match this filter." />}
            </div>
          )}
        </div>

        <div className="min-h-0 rounded-lg border border-zinc-800 bg-zinc-900/30 overflow-y-auto">
          {selected && view !== 'roles' ? <RouteDetail route={selected} copied={copied} onCopy={copy} onWorkspace={() => { if (selected.finding) { addFinding(selected.finding); navigate('/workspace') } }} onAnalyze={() => { if (selected.finding) { addFinding(selected.finding); navigate('/copilot') } }} /> : <Empty text="Select a route to inspect its access-control test plan." />}
        </div>
      </div>
    </div>
  )
}

function Metric({ label, value, accent, danger }: { label: string; value: string; accent?: boolean; danger?: boolean }) {
  return <div className="bg-zinc-950 px-3 py-2.5 min-w-0"><div className={cn('text-sm font-semibold truncate', accent ? 'text-teal-300' : danger ? 'text-red-300' : 'text-zinc-200')}>{value}</div><div className="text-[9px] text-zinc-600 mt-0.5">{label}</div></div>
}

function ViewButton({ active, onClick, label, count }: { active: boolean; onClick: () => void; label: string; count: number }) {
  return <button onClick={onClick} className={cn('h-7 px-2.5 rounded text-[10px] flex items-center gap-1.5', active ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-500 hover:text-zinc-300')}>{label}<span className="text-[8px] text-zinc-600">{count}</span></button>
}

function Empty({ text }: { text: string }) {
  return <div className="min-h-32 flex items-center justify-center p-6 text-center text-[11px] text-zinc-600"><Filter size={13} className="mr-2" />{text}</div>
}

function RouteDetail({ route, copied, onCopy, onWorkspace, onAnalyze }: { route: MappedRoute; copied: string | null; onCopy: (v: string) => void; onWorkspace: () => void; onAnalyze: () => void }) {
  const commands = commandRows(route.finding)
  return <div className="p-4 space-y-4">
    <div><div className="flex items-center gap-2"><span className={cn('rounded border px-1.5 py-0.5 font-mono text-[9px] font-bold', METHOD_COLOR[route.method] || 'text-zinc-400 border-zinc-700')}>{route.method}</span><span className="text-[9px] text-zinc-600">{route.source}</span></div><div className="font-mono text-sm text-zinc-100 break-all mt-2">{route.path}</div>{route.url && <a href={route.url} target="_blank" rel="noreferrer" className="mt-1 inline-flex items-center gap-1 text-[10px] text-teal-400 hover:text-teal-300 break-all">{route.url}<ExternalLink size={9} /></a>}</div>
    {route.finding?.description && <div><div className="text-[9px] uppercase font-semibold text-zinc-600 mb-1">Why it matters</div><p className="text-[11px] text-zinc-400 leading-relaxed">{route.finding.description}</p></div>}
    <div><div className="text-[9px] uppercase font-semibold text-zinc-600 mb-2">Access-control matrix</div><div className="space-y-2">{commands.map(row => <div key={row.identity} className="rounded border border-zinc-800 bg-zinc-950/70 p-2"><div className="flex items-center justify-between gap-2 mb-1"><span className={cn('text-[9px] font-semibold uppercase', row.identity === 'anon' ? 'text-zinc-400' : row.identity === 'user' ? 'text-cyan-400' : 'text-amber-400')}>{row.identity}</span><button title="Copy command" onClick={() => onCopy(row.command)} className="text-zinc-600 hover:text-zinc-300">{copied === row.command ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}</button></div><code className="text-[9px] text-zinc-500 break-all leading-relaxed">{row.command}</code></div>)}</div>{!commands.length && <p className="text-[10px] text-zinc-600">This route is mapped but has no generated test plan.</p>}</div>
    {route.finding && <div className="grid grid-cols-2 gap-2"><button onClick={onWorkspace} className="h-8 rounded border border-zinc-700 text-[10px] text-zinc-400 hover:text-zinc-200 flex items-center justify-center gap-1.5"><BookOpen size={11} />Workspace</button><button onClick={onAnalyze} className="h-8 rounded border border-teal-900 text-[10px] text-teal-400 hover:text-teal-300 flex items-center justify-center gap-1.5"><Sparkles size={11} />Analyze AI</button></div>}
  </div>
}
