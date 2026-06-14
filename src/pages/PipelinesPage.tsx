import { useState, useEffect, useRef } from 'react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ScopeSelector } from '@/components/ui/scope-selector'
import { api } from '@/api/http-client'
import { toast } from '@/stores/toast-store'
import { cn } from '@/lib/utils'
import { usePipelineStore } from '@/stores/pipeline-store'
import { useScannerStore } from '@/stores/scanner-store'
import { useReconStore } from '@/stores/recon-store'
import { useAppStore } from '@/stores/app-store'
import {
  Play, Loader2, Database, Zap, Bug, Trash2, FileCode,
  ChevronDown, Server, Settings2,
} from 'lucide-react'

const ACCENTS = {
  xss: {
    border: 'border-orange-500/30', bg: 'bg-orange-950/15', text: 'text-orange-400',
    iconBg: 'bg-orange-500/15 text-orange-400', btn: 'bg-orange-700 hover:bg-orange-600',
    accentInput: 'accent-orange-500',
  },
  sqli: {
    border: 'border-red-500/30', bg: 'bg-red-950/15', text: 'text-red-400',
    iconBg: 'bg-red-500/15 text-red-400', btn: 'bg-red-700 hover:bg-red-600',
    accentInput: 'accent-red-500',
  },
  js_scan: {
    border: 'border-blue-500/30', bg: 'bg-blue-950/15', text: 'text-blue-400',
    iconBg: 'bg-blue-500/15 text-blue-400', btn: 'bg-blue-700 hover:bg-blue-600',
    accentInput: 'accent-blue-500',
  },
}

export function PipelinesPage() {
  const { globalTarget, setGlobalTarget, getSessionOpts } = useAppStore()
  const [pipelineTarget, setPipelineTargetLocal] = useState(globalTarget)

  useEffect(() => {
    if (globalTarget && !pipelineTarget) setPipelineTargetLocal(globalTarget)
  }, [globalTarget])

  const setPipelineTarget = (v: string) => {
    setPipelineTargetLocal(v)
    setGlobalTarget(v)
  }

  const { runs, activeRunId, startRun, clearRuns } = usePipelineStore()
  const { findings } = useScannerStore()
  const logRef = useRef<HTMLPreElement>(null)
  const activeRun = runs.find(r => r.id === activeRunId)

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [activeRun?.log.length])

  const xssFindings = findings.filter(f => f.tool === 'dalfox')

  // ── XSS ──
  const [xssRunning, setXssRunning] = useState(false)
  const [xssOpts, setXssOpts] = useState({
    depth: '3', concurrency: '10', rate_limit: '150',
    js_crawl: true, crawl_forms: true, restrict_scope: true, headless: false,
    workers: '10', blind: '', cookie: '', parse_js: true,
  })

  const handleXss = async () => {
    if (!pipelineTarget.trim()) return
    setXssRunning(true)
    startRun('xss', pipelineTarget.trim())
    try {
      const sess = getSessionOpts()
      await api.post('/api/pipeline/xss', {
        target: pipelineTarget.trim(),
        options: {
          depth: parseInt(xssOpts.depth) || 3,
          concurrency: parseInt(xssOpts.concurrency) || 10,
          rate_limit: parseInt(xssOpts.rate_limit) || 150,
          js_crawl: xssOpts.js_crawl, crawl_forms: xssOpts.crawl_forms,
          restrict_scope: xssOpts.restrict_scope, headless: xssOpts.headless,
          parse_js: xssOpts.parse_js, blind: xssOpts.blind || undefined,
          cookie: xssOpts.cookie || sess.session_cookies || undefined,
          workers: parseInt(xssOpts.workers) || 10,
          ...sess,
        },
      }, 0)
    } catch (err) { toast.error('XSS pipeline failed', err) }
    finally { setXssRunning(false) }
  }

  // ── SQLi ──
  const [sqliRunning, setSqliRunning] = useState(false)
  const [sqliOpts, setSqliOpts] = useState({
    depth: '3', concurrency: '10', rate_limit: '150',
    js_crawl: true, crawl_forms: true, restrict_scope: true, headless: false,
    workers: '5', cookie: '', parse_js: true,
  })

  const handleSqli = async () => {
    if (!pipelineTarget.trim()) return
    setSqliRunning(true)
    startRun('sqli', pipelineTarget.trim())
    try {
      const sess = getSessionOpts()
      await api.post('/api/pipeline/sqli_probe', {
        target: pipelineTarget.trim(),
        options: {
          depth: parseInt(sqliOpts.depth) || 3,
          concurrency: parseInt(sqliOpts.concurrency) || 10,
          rate_limit: parseInt(sqliOpts.rate_limit) || 150,
          js_crawl: sqliOpts.js_crawl, crawl_forms: sqliOpts.crawl_forms,
          restrict_scope: sqliOpts.restrict_scope, headless: sqliOpts.headless,
          parse_js: sqliOpts.parse_js,
          cookie: sqliOpts.cookie || sess.session_cookies || undefined,
          workers: parseInt(sqliOpts.workers) || 5,
          ...sess,
        },
      }, 0)
    } catch (err) { toast.error('SQLi pipeline failed', err) }
    finally { setSqliRunning(false) }
  }

  // ── JS Secrets ──
  const [jsRunning, setJsRunning] = useState(false)
  const [jsOpts, setJsOpts] = useState({
    depth: '3', concurrency: '10', rate_limit: '150',
    js_crawl: true, crawl_forms: true, restrict_scope: true, headless: false,
    workers: '5', cookie: '',
  })

  const handleJs = async () => {
    if (!pipelineTarget.trim()) return
    setJsRunning(true)
    startRun('js_scan', pipelineTarget.trim())
    try {
      const sess = getSessionOpts()
      await api.post('/api/pipeline/js_scan', {
        target: pipelineTarget.trim(),
        options: {
          depth: parseInt(jsOpts.depth) || 3,
          concurrency: parseInt(jsOpts.concurrency) || 10,
          rate_limit: parseInt(jsOpts.rate_limit) || 150,
          js_crawl: jsOpts.js_crawl, crawl_forms: jsOpts.crawl_forms,
          restrict_scope: jsOpts.restrict_scope, headless: jsOpts.headless,
          cookie: jsOpts.cookie || sess.session_cookies || undefined,
          workers: parseInt(jsOpts.workers) || 5,
          ...sess,
        },
      }, 0)
    } catch (err) { toast.error('JS scan pipeline failed', err) }
    finally { setJsRunning(false) }
  }

  const anyRunning = xssRunning || sqliRunning || jsRunning
  const noTarget = !pipelineTarget.trim()

  return (
    <WorkspaceShell title="Pipelines" subtitle="Automated bug bounty chains — crawl, mine and probe in one run">
      <div className="flex flex-col gap-4 max-w-[1400px]">
        {/* Target bar */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
          <div className="text-[10px] font-semibold tracking-wider text-zinc-500 uppercase mb-2">Target</div>
          <div className="flex flex-col sm:flex-row gap-2">
            <div className="sm:w-56 shrink-0"><ScopeSelector onSelect={setPipelineTarget} selectedTarget={pipelineTarget} /></div>
            <div className="sm:w-56 shrink-0"><LiveHostPicker selected={pipelineTarget} onSelect={setPipelineTarget} /></div>
            <Input
              placeholder="https://target.com"
              className="flex-1 bg-zinc-950 text-sm font-mono"
              value={pipelineTarget}
              onChange={e => setPipelineTarget(e.target.value)}
            />
          </div>
        </div>

        {/* Pipeline gallery */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <PipelineCard
            accent={ACCENTS.xss}
            icon={<Zap size={18} />}
            title="XSS"
            chain="Katana → mine JS → Dalfox"
            desc="Crawls the target, mines endpoints from JS and inline scripts, then runs Dalfox on every parameterized URL. Deduplicates by endpoint so the same path is not scanned twice."
            running={xssRunning}
            runLabel="Run XSS Pipeline"
            disabled={noTarget}
            onRun={handleXss}
          >
            <CrawlOpts opts={xssOpts} set={setXssOpts} accent={ACCENTS.xss.accentInput} />
            <div className="space-y-1.5 border border-zinc-800 rounded-lg p-3">
              <div className="text-[10px] font-semibold text-zinc-400 mb-1">Dalfox</div>
              <OptRow label="Workers" placeholder="10" value={xssOpts.workers} onChange={v => setXssOpts(p => ({ ...p, workers: v }))} />
              <OptRow label="Blind XSS" placeholder="https://callback/" value={xssOpts.blind} onChange={v => setXssOpts(p => ({ ...p, blind: v }))} />
              <OptRow label="Cookie" placeholder="(usa Session del sidebar)" value={xssOpts.cookie} onChange={v => setXssOpts(p => ({ ...p, cookie: v }))} />
              <Check label="Minar endpoints de JS" checked={xssOpts.parse_js} onChange={v => setXssOpts(p => ({ ...p, parse_js: v }))} accent={ACCENTS.xss.accentInput} />
            </div>
          </PipelineCard>

          <PipelineCard
            accent={ACCENTS.sqli}
            icon={<Database size={18} />}
            title="SQLi Probe"
            chain="Katana → mine JS → 3-layer probe"
            desc="Probes every parameter with error-based, boolean-based and time-based detection (MySQL, PostgreSQL, MSSQL). Numeric params first. Detection only — confirma con SQLMap antes de reportar."
            running={sqliRunning}
            runLabel="Run SQLi Probe"
            disabled={noTarget}
            onRun={handleSqli}
          >
            <CrawlOpts opts={sqliOpts} set={setSqliOpts} accent={ACCENTS.sqli.accentInput} />
            <div className="space-y-1.5 border border-zinc-800 rounded-lg p-3">
              <div className="text-[10px] font-semibold text-zinc-400 mb-1">Probe</div>
              <OptRow label="Workers" placeholder="5" value={sqliOpts.workers} onChange={v => setSqliOpts(p => ({ ...p, workers: v }))} />
              <OptRow label="Cookie" placeholder="(usa Session del sidebar)" value={sqliOpts.cookie} onChange={v => setSqliOpts(p => ({ ...p, cookie: v }))} />
              <Check label="Parsear .js (fetch/axios/XHR/$.ajax)" checked={sqliOpts.parse_js} onChange={v => setSqliOpts(p => ({ ...p, parse_js: v }))} accent={ACCENTS.sqli.accentInput} />
            </div>
          </PipelineCard>

          <PipelineCard
            accent={ACCENTS.js_scan}
            icon={<FileCode size={18} />}
            title="JS Secrets"
            chain="Katana → fetch .js → grep secrets"
            desc="Downloads every .js file and inline script, then greps for API keys, JWTs, AWS creds, GraphQL and internal endpoints. Handles minified bundles and filters low-entropy placeholders."
            running={jsRunning}
            runLabel="Run JS Scanner"
            disabled={noTarget}
            onRun={handleJs}
          >
            <CrawlOpts opts={jsOpts} set={setJsOpts} accent={ACCENTS.js_scan.accentInput} />
            <div className="space-y-1.5 border border-zinc-800 rounded-lg p-3">
              <div className="text-[10px] font-semibold text-zinc-400 mb-1">Scanner</div>
              <OptRow label="Workers" placeholder="5" value={jsOpts.workers} onChange={v => setJsOpts(p => ({ ...p, workers: v }))} />
              <OptRow label="Cookie" placeholder="(usa Session del sidebar)" value={jsOpts.cookie} onChange={v => setJsOpts(p => ({ ...p, cookie: v }))} />
            </div>
          </PipelineCard>
        </div>

        {/* Run console */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="text-[10px] font-semibold tracking-wider text-zinc-500 uppercase">Live run</div>
            <Button variant="ghost" size="sm" className="text-zinc-600 hover:text-red-400 text-xs" onClick={clearRuns} disabled={anyRunning}>
              <Trash2 size={12} className="mr-1" /> Clear history
            </Button>
          </div>

          {activeRun && (
            <div className="flex items-center gap-2 bg-zinc-950 rounded-lg px-4 py-2 text-xs flex-wrap">
              <PhaseStep label="Katana" active={activeRun.phase === 'katana'} done={activeRun.phase !== 'katana' && activeRun.phase !== 'idle'} />
              <span className="text-zinc-700">→</span>
              {activeRun.type === 'xss' && <>
                <PhaseStep label="Filter + mine" active={activeRun.phase === 'js_parse'} done={activeRun.candidates.length > 0 && activeRun.phase !== 'js_parse'} />
                <span className="text-zinc-700">→</span>
                <PhaseStep label="Dalfox" active={activeRun.phase === 'dalfox'} done={activeRun.phase === 'completed'} />
              </>}
              {activeRun.type === 'sqli' && <>
                <PhaseStep label="Filter + mine" active={activeRun.phase === 'js_parse'} done={activeRun.candidates.length > 0 && activeRun.phase !== 'js_parse'} />
                <span className="text-zinc-700">→</span>
                <PhaseStep label="SQLi Probe" active={activeRun.phase === 'sqli_probe'} done={activeRun.phase === 'completed'} />
              </>}
              {activeRun.type === 'js_scan' && <>
                <PhaseStep label="Filter .js" active={false} done={activeRun.candidates.length > 0} />
                <span className="text-zinc-700">→</span>
                <PhaseStep label="Grep secrets" active={activeRun.phase === 'js_scan'} done={activeRun.phase === 'completed'} />
              </>}
              {activeRun.phase === 'completed' && <span className="ml-auto text-green-400 font-medium">✓ Done</span>}
              {activeRun.phase === 'failed' && <span className="ml-auto text-red-400 font-medium">✗ Failed</span>}
            </div>
          )}

          {activeRun && (
            <div className="flex gap-3">
              <StatCard label="URLs found" value={activeRun.katanaUrls.length} color="text-blue-400" />
              <StatCard label={activeRun.type === 'js_scan' ? 'JS files' : 'Candidates'} value={activeRun.candidates.length} color="text-yellow-400" />
              <StatCard
                label={activeRun.type === 'xss' ? 'XSS findings' : activeRun.type === 'sqli' ? 'SQLi hints' : 'Secrets found'}
                value={activeRun.findingsCount}
                color="text-red-400"
              />
            </div>
          )}

          <div className="rounded-lg border border-zinc-800 bg-black p-4 overflow-auto h-72">
            <pre ref={logRef} className="text-xs font-mono whitespace-pre-wrap leading-relaxed">
              {activeRun
                ? activeRun.log.map((line, i) => (
                    <span key={i} className={cn('block',
                      line.includes('[XSS FOUND]') || line.includes('[SQL ERROR]') ? 'text-red-400 font-bold' :
                      line.includes('[BOOLEAN]') || line.includes('[TIME-BASED]') ? 'text-red-400 font-bold' :
                      line.includes('[SECRET]') ? 'text-yellow-400 font-bold' :
                      line.includes('[Katana]') || line.includes('[JS]') ? 'text-blue-400 font-semibold' :
                      line.includes('[✓]') ? 'text-green-400 font-semibold' :
                      line.includes('ERROR') ? 'text-red-400' : 'text-zinc-400'
                    )}>{line}</span>
                  ))
                : <span className="text-zinc-700">No pipeline running. Pick a pipeline above and hit Run.</span>}
            </pre>
          </div>

          {xssFindings.length > 0 && (
            <div className="rounded-lg border border-red-500/30 bg-red-950/20 p-3 space-y-2">
              <div className="text-xs font-semibold text-red-400 flex items-center gap-1.5">
                <Bug size={12} /> XSS Findings ({xssFindings.length})
              </div>
              {xssFindings.slice(0, 6).map((f, i) => (
                <div key={i} className="text-[10px] space-y-0.5">
                  <div className="text-red-300 font-mono truncate">{f.url}</div>
                  {f.parameter && <div className="text-zinc-500">param: <span className="text-yellow-400">{f.parameter}</span></div>}
                </div>
              ))}
              {xssFindings.length > 6 && <div className="text-[10px] text-zinc-600">+ {xssFindings.length - 6} more → Scanner → Findings</div>}
            </div>
          )}
        </div>
      </div>
    </WorkspaceShell>
  )
}

// ─── Card shell ───────────────────────────────────────────────────────────────

function PipelineCard({ accent, icon, title, chain, desc, running, runLabel, disabled, onRun, children }: {
  accent: typeof ACCENTS.xss
  icon: React.ReactNode
  title: string
  chain: string
  desc: string
  running: boolean
  runLabel: string
  disabled: boolean
  onRun: () => void
  children: React.ReactNode
}) {
  const [showAdv, setShowAdv] = useState(false)
  return (
    <div className={cn('rounded-xl border p-5 flex flex-col gap-3.5', accent.border, accent.bg)}>
      <div className="flex items-center gap-3">
        <div className={cn('w-10 h-10 rounded-lg flex items-center justify-center shrink-0', accent.iconBg)}>{icon}</div>
        <div className="min-w-0">
          <div className={cn('text-sm font-bold', accent.text)}>{title}</div>
          <div className="text-[10px] text-zinc-500 font-mono truncate">{chain}</div>
        </div>
      </div>

      <p className="text-[11px] text-zinc-400 leading-relaxed flex-1">{desc}</p>

      <Button className={cn('w-full text-white text-xs font-semibold', accent.btn)} disabled={running || disabled} onClick={onRun}>
        {running
          ? <><Loader2 size={13} className="mr-1.5 animate-spin" />Running...</>
          : <><Play size={13} className="mr-1.5" />{runLabel}</>}
      </Button>

      <button
        onClick={() => setShowAdv(v => !v)}
        className="flex items-center justify-center gap-1 text-[10px] text-zinc-500 hover:text-zinc-300 transition-colors"
      >
        <Settings2 size={11} /> Advanced
        <ChevronDown size={11} className={cn('transition-transform', showAdv && 'rotate-180')} />
      </button>

      {showAdv && <div className="space-y-2 pt-1">{children}</div>}
    </div>
  )
}

function CrawlOpts({ opts, set, accent }: {
  opts: any; set: (fn: (p: any) => any) => void; accent: string
}) {
  return (
    <div className="space-y-1.5 border border-zinc-800 rounded-lg p-3">
      <div className="text-[10px] font-semibold text-zinc-400 mb-1">Katana (crawl)</div>
      <div className="grid grid-cols-3 gap-1.5">
        <OptRow label="Depth" placeholder="3" value={opts.depth} onChange={v => set(p => ({ ...p, depth: v }))} />
        <OptRow label="Conc." placeholder="10" value={opts.concurrency} onChange={v => set(p => ({ ...p, concurrency: v }))} />
        <OptRow label="Rate" placeholder="150" value={opts.rate_limit} onChange={v => set(p => ({ ...p, rate_limit: v }))} />
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-1 pt-1">
        <Check label="-jc (JS crawl)" checked={opts.js_crawl} onChange={v => set(p => ({ ...p, js_crawl: v }))} accent={accent} />
        <Check label="-aff (forms)" checked={opts.crawl_forms} onChange={v => set(p => ({ ...p, crawl_forms: v }))} accent={accent} />
        <Check label="scope restrict" checked={opts.restrict_scope} onChange={v => set(p => ({ ...p, restrict_scope: v }))} accent={accent} />
        <Check label="-hl (headless)" checked={opts.headless} onChange={v => set(p => ({ ...p, headless: v }))} accent={accent} />
      </div>
    </div>
  )
}

function Check({ label, checked, onChange, accent }: {
  label: string; checked: boolean; onChange: (v: boolean) => void; accent: string
}) {
  return (
    <label className="flex items-center gap-1.5 cursor-pointer">
      <input type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)} className={cn('w-3 h-3', accent)} />
      <span className="text-[10px] text-zinc-400">{label}</span>
    </label>
  )
}

function OptRow({ label, placeholder, value, onChange }: {
  label: string; placeholder: string; value: string; onChange: (v: string) => void
}) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-[10px] text-zinc-600 w-12 shrink-0 text-right">{label}:</span>
      <input
        type="text" placeholder={placeholder} value={value} onChange={e => onChange(e.target.value)}
        className="flex-1 min-w-0 text-[10px] bg-zinc-950 border border-zinc-800 rounded px-2 py-0.5 text-zinc-400 placeholder:text-zinc-700 focus:outline-none focus:border-zinc-600"
      />
    </div>
  )
}

function PhaseStep({ label, active, done }: { label: string; active: boolean; done: boolean }) {
  return (
    <span className={cn(
      'px-2 py-0.5 rounded text-[10px] font-medium border',
      done ? 'border-green-700 bg-green-950/30 text-green-400' :
      active ? 'border-blue-600 bg-blue-950/30 text-blue-300 animate-pulse' :
      'border-zinc-800 text-zinc-600'
    )}>
      {done ? '✓ ' : active ? '● ' : ''}{label}
    </span>
  )
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="flex-1 rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2 text-center">
      <div className={cn('text-lg font-bold font-mono', color)}>{value}</div>
      <div className="text-[10px] text-zinc-600">{label}</div>
    </div>
  )
}

function LiveHostPicker({ selected, onSelect }: { selected: string; onSelect: (url: string) => void }) {
  const { liveHosts } = useReconStore()
  const [open, setOpen] = useState(false)
  const [filter, setFilter] = useState('')
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  if (liveHosts.length === 0) return null

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between gap-1.5 px-2.5 py-1.5 rounded-lg border border-green-700/50 bg-green-950/20 text-xs text-green-400 hover:border-green-600 hover:bg-green-950/30 transition-colors"
      >
        <div className="flex items-center gap-1.5">
          <Server size={11} />
          <span>{liveHosts.length} live hosts</span>
          {selected && liveHosts.some(h => h.url === selected) && (
            <span className="text-[9px] text-green-600">· selected</span>
          )}
        </div>
        <ChevronDown size={11} className={cn('transition-transform', open && 'rotate-180')} />
      </button>

      {open && (
        <div className="absolute top-full left-0 right-0 mt-1 z-50 rounded-lg border border-zinc-700 bg-zinc-900 shadow-xl shadow-black/50 overflow-hidden">
          <div className="p-1.5 border-b border-zinc-800">
            <input
              autoFocus type="text" placeholder="Filter hosts..."
              value={filter} onChange={e => setFilter(e.target.value)}
              className="w-full text-[10px] bg-zinc-950 border border-zinc-800 rounded px-2 py-1 text-zinc-300 placeholder:text-zinc-700 focus:outline-none"
            />
          </div>
          <div className="max-h-48 overflow-y-auto">
            {liveHosts
              .filter(h => !filter || h.url.toLowerCase().includes(filter.toLowerCase()))
              .map((h, i) => (
                <button
                  key={i}
                  onClick={() => { onSelect(h.url); setOpen(false); setFilter('') }}
                  className={cn(
                    'w-full flex items-center gap-2 px-2.5 py-1.5 text-left hover:bg-zinc-800 transition-colors',
                    selected === h.url && 'bg-zinc-800'
                  )}
                >
                  <span className={cn('text-[10px] font-mono font-bold shrink-0',
                    h.status_code && h.status_code < 300 ? 'text-green-400' :
                    h.status_code && h.status_code < 400 ? 'text-yellow-400' : 'text-orange-400'
                  )}>
                    {h.status_code}
                  </span>
                  <span className="text-[10px] text-zinc-300 font-mono truncate flex-1">{h.url}</span>
                  {h.title && <span className="text-[9px] text-zinc-600 truncate max-w-[80px] shrink-0">{h.title}</span>}
                </button>
              ))}
          </div>
        </div>
      )}
    </div>
  )
}
