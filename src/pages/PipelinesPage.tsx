import { useState, useEffect, useRef } from 'react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ScopeSelector } from '@/components/ui/scope-selector'
import { api } from '@/api/http-client'
import { toast } from '@/stores/toast-store'
import { cn } from '@/lib/utils'
import { usePipelineStore, type PipelineRun } from '@/stores/pipeline-store'

import { useReconStore } from '@/stores/recon-store'
import { useAppStore } from '@/stores/app-store'
import { useScannerStore } from '@/stores/scanner-store'
import { useLicenseStore } from '@/stores/license-store'
import {
  Play, Loader2, Database, Zap, Bug, Trash2, FileCode, FileSearch,
  ChevronDown, Server, Settings2, CheckSquare, Square as SquareIcon,
  Sparkles, X, History, Crown, Copy,
} from 'lucide-react'

// Tools tagged by the pipelines themselves — used to show persisted results after a restart.
const PIPELINE_TOOLS = ['dalfox', 'sqli_pipeline', 'lfi_pipeline', 'js_scan_pipeline', 'viewstate_audit', 'cloud_buckets']

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
  lfi: {
    border: 'border-amber-500/30', bg: 'bg-amber-950/15', text: 'text-amber-400',
    iconBg: 'bg-amber-500/15 text-amber-400', btn: 'bg-amber-700 hover:bg-amber-600',
    accentInput: 'accent-amber-500',
  },
  js_scan: {
    border: 'border-blue-500/30', bg: 'bg-blue-950/15', text: 'text-blue-400',
    iconBg: 'bg-blue-500/15 text-blue-400', btn: 'bg-blue-700 hover:bg-blue-600',
    accentInput: 'accent-blue-500',
  },
}

export function PipelinesPage({ embedded }: { embedded?: boolean }) {
  const { globalTarget, setGlobalTarget, getSessionOpts, activeProject } = useAppStore()
  const isPro = useLicenseStore((s) => s.isPro())
  const { findings } = useScannerStore()
  const [pipelineTarget, setPipelineTargetLocal] = useState(globalTarget)
  const [selectedHosts, setSelectedHosts] = useState<string[]>([])
  const [multiProgress, setMultiProgress] = useState<{ current: number; total: number } | null>(null)
  const previousFindings = findings.filter(f => f.tool && PIPELINE_TOOLS.includes(f.tool))

  useEffect(() => {
    if (globalTarget && !pipelineTarget) setPipelineTargetLocal(globalTarget)
  }, [globalTarget])

  const setPipelineTarget = (v: string) => {
    setPipelineTargetLocal(v)
    setGlobalTarget(v)
  }

  const { runs, activeRunId, startRun, clearRuns } = usePipelineStore()
  const { liveHosts } = useReconStore()
  const logRef = useRef<HTMLPreElement>(null)
  const [viewRunId, setViewRunId] = useState<string | null>(null)

  // AI secret analysis modal state
  const [secretAi, setSecretAi] = useState<{ title: string; loading: boolean; result: string } | null>(null)

  // AI sqlmap command generator modal state
  const [sqlmapAi, setSqlmapAi] = useState<{ title: string; loading: boolean; command: string } | null>(null)

  const generateSqlmap = async (f: { label: string; url?: string; param?: string; text?: string }, extraHeaders: string[] = []) => {
    setSqlmapAi({ title: `${f.label} — ${f.param ?? '?'}`, loading: true, command: '' })
    try {
      const res = await api.post<{ command: string }>('/api/copilot/generate-sqlmap', {
        url: f.url ?? '',
        param: f.param ?? '',
        method: f.label === 'BOOLEAN' ? 'boolean-based' : f.label === 'TIME-BASED' ? 'time-based' : 'error-based',
        evidence: f.text ?? '',
        extra_headers: extraHeaders,
      })
      setSqlmapAi({ title: `${f.label} — ${f.param ?? '?'}`, loading: false, command: res.command })
    } catch (err) {
      setSqlmapAi({ title: `${f.label} — ${f.param ?? '?'}`, loading: false, command: `# Error: ${err}` })
    }
  }

  const analyzeSecret = async (f: { label: string; url?: string; match?: string; context?: string; line?: number }) => {
    setSecretAi({ title: f.label, loading: true, result: '' })
    try {
      const res = await api.post<{ response: string }>('/api/copilot/analyze-secret', {
        js_url: f.url ?? '',
        label: f.label,
        match: f.match ?? f.label,
        context: f.context ?? '',
        line: f.line,
        live_hosts: liveHosts.slice(0, 25),
      })
      setSecretAi({ title: f.label, loading: false, result: res.response })
    } catch (err) {
      setSecretAi({ title: f.label, loading: false, result: `Error: ${err}` })
    }
  }

  // Auto-follow the newest run when it starts, but don't override manual selection
  useEffect(() => {
    if (activeRunId) setViewRunId(activeRunId)
  }, [activeRunId])

  const viewRun = runs.find(r => r.id === (viewRunId ?? activeRunId)) ?? runs[0] ?? null

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [viewRun?.log.length])

  // Returns the list of targets to scan — selected hosts if any, otherwise the manual input
  const getTargets = () =>
    selectedHosts.length > 0 ? selectedHosts : pipelineTarget.trim() ? [pipelineTarget.trim()] : []

  // Run a pipeline fn sequentially over all targets, tracking progress
  const runOnTargets = async (
    setRunning: (v: boolean) => void,
    runFn: (target: string) => Promise<void>,
  ) => {
    const targets = getTargets()
    if (targets.length === 0) return
    setRunning(true)
    if (targets.length > 1) setMultiProgress({ current: 1, total: targets.length })
    try {
      for (let i = 0; i < targets.length; i++) {
        if (targets.length > 1) setMultiProgress({ current: i + 1, total: targets.length })
        await runFn(targets[i])
      }
    } finally {
      setRunning(false)
      setMultiProgress(null)
    }
  }

  // ── XSS ──
  const [xssRunning, setXssRunning] = useState(false)
  const [xssOpts, setXssOpts] = useState({
    depth: '3', concurrency: '10', rate_limit: '150',
    js_crawl: true, crawl_forms: true, restrict_scope: true, headless: false, force_recrawl: false,
    workers: '10', blind: '', cookie: '', parse_js: true,
  })

  const handleXss = () => runOnTargets(setXssRunning, async (target) => {
    startRun('xss', target)
    try {
      const sess = getSessionOpts()
      await api.post('/api/pipeline/xss', {
        target,
        project_id: activeProject ?? '',
        options: {
          depth: parseInt(xssOpts.depth) || 3,
          concurrency: parseInt(xssOpts.concurrency) || 10,
          rate_limit: parseInt(xssOpts.rate_limit) || 150,
          js_crawl: xssOpts.js_crawl, crawl_forms: xssOpts.crawl_forms,
          restrict_scope: xssOpts.restrict_scope, headless: xssOpts.headless, force_recrawl: xssOpts.force_recrawl,
          parse_js: xssOpts.parse_js, blind: xssOpts.blind || undefined,
          cookie: xssOpts.cookie || sess.session_cookies || undefined,
          workers: parseInt(xssOpts.workers) || 10,
          ...sess,
        },
      }, 0)
    } catch (err) { toast.error('XSS pipeline failed', err) }
  })

  // ── SQLi ──
  const [sqliRunning, setSqliRunning] = useState(false)
  const [sqliOpts, setSqliOpts] = useState({
    depth: '3', concurrency: '10', rate_limit: '150',
    js_crawl: true, crawl_forms: true, restrict_scope: true, headless: false, force_recrawl: false,
    workers: '5', cookie: '', parse_js: true,
  })

  const handleSqli = () => runOnTargets(setSqliRunning, async (target) => {
    startRun('sqli', target)
    try {
      const sess = getSessionOpts()
      await api.post('/api/pipeline/sqli_probe', {
        target,
        project_id: activeProject ?? '',
        options: {
          depth: parseInt(sqliOpts.depth) || 3,
          concurrency: parseInt(sqliOpts.concurrency) || 10,
          rate_limit: parseInt(sqliOpts.rate_limit) || 150,
          js_crawl: sqliOpts.js_crawl, crawl_forms: sqliOpts.crawl_forms,
          restrict_scope: sqliOpts.restrict_scope, headless: sqliOpts.headless, force_recrawl: sqliOpts.force_recrawl,
          parse_js: sqliOpts.parse_js,
          cookie: sqliOpts.cookie || sess.session_cookies || undefined,
          workers: parseInt(sqliOpts.workers) || 5,
          ...sess,
        },
      }, 0)
    } catch (err) { toast.error('SQLi pipeline failed', err) }
  })

  // ── LFI ──
  const [lfiRunning, setLfiRunning] = useState(false)
  const [lfiOpts, setLfiOpts] = useState({
    depth: '3', concurrency: '10', rate_limit: '150',
    js_crawl: true, crawl_forms: true, restrict_scope: true, headless: false, force_recrawl: false,
    workers: '5', cookie: '', parse_js: true,
  })

  const handleLfi = () => runOnTargets(setLfiRunning, async (target) => {
    startRun('lfi', target)
    try {
      const sess = getSessionOpts()
      await api.post('/api/pipeline/lfi', {
        target,
        project_id: activeProject ?? '',
        options: {
          depth: parseInt(lfiOpts.depth) || 3,
          concurrency: parseInt(lfiOpts.concurrency) || 10,
          rate_limit: parseInt(lfiOpts.rate_limit) || 150,
          js_crawl: lfiOpts.js_crawl, crawl_forms: lfiOpts.crawl_forms,
          restrict_scope: lfiOpts.restrict_scope, headless: lfiOpts.headless, force_recrawl: lfiOpts.force_recrawl,
          parse_js: lfiOpts.parse_js,
          cookie: lfiOpts.cookie || sess.session_cookies || undefined,
          workers: parseInt(lfiOpts.workers) || 5,
          ...sess,
        },
      }, 0)
    } catch (err) { toast.error('LFI pipeline failed', err) }
  })

  // ── JS Secrets ──
  const [jsRunning, setJsRunning] = useState(false)
  const [jsOpts, setJsOpts] = useState({
    depth: '3', concurrency: '10', rate_limit: '150',
    js_crawl: true, crawl_forms: true, restrict_scope: true, headless: false, force_recrawl: false,
    workers: '5', cookie: '',
  })

  const handleJs = () => runOnTargets(setJsRunning, async (target) => {
    startRun('js_scan', target)
    try {
      const sess = getSessionOpts()
      await api.post('/api/pipeline/js_scan', {
        target,
        project_id: activeProject ?? '',
        options: {
          depth: parseInt(jsOpts.depth) || 3,
          concurrency: parseInt(jsOpts.concurrency) || 10,
          rate_limit: parseInt(jsOpts.rate_limit) || 150,
          js_crawl: jsOpts.js_crawl, crawl_forms: jsOpts.crawl_forms,
          restrict_scope: jsOpts.restrict_scope, headless: jsOpts.headless, force_recrawl: jsOpts.force_recrawl,
          cookie: jsOpts.cookie || sess.session_cookies || undefined,
          workers: parseInt(jsOpts.workers) || 5,
          ...sess,
        },
      }, 0)
    } catch (err) { toast.error('JS scan pipeline failed', err) }
  })

  const anyRunning = xssRunning || sqliRunning || lfiRunning || jsRunning
  const targets = getTargets()
  const noTarget = targets.length === 0

  const runLabel = (base: string) => {
    if (selectedHosts.length > 1) return `${base} — ${selectedHosts.length} hosts`
    if (selectedHosts.length === 1) return `${base} — 1 host`
    return base
  }

  return (
    <WorkspaceShell title="Pipelines" subtitle="Automated bug bounty chains — crawl, mine and probe in one run" embedded={embedded}>
      <div className="flex flex-col gap-4 max-w-[1400px]">
        {/* Target bar */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
          <div className="text-[10px] font-semibold tracking-wider text-zinc-500 uppercase mb-2">Target</div>
          <div className="flex flex-col sm:flex-row gap-2">
            <div className="sm:w-56 shrink-0"><ScopeSelector onSelect={setPipelineTarget} selectedTarget={pipelineTarget} /></div>
            <div className="sm:w-64 shrink-0">
              <LiveHostPicker
                selectedHosts={selectedHosts}
                onToggle={(url) => setSelectedHosts(prev =>
                  prev.includes(url) ? prev.filter(h => h !== url) : [...prev, url]
                )}
                onSelectAll={(all) => setSelectedHosts(all)}
                onClear={() => setSelectedHosts([])}
              />
            </div>
            <Input
              placeholder="https://target.com"
              className={cn('flex-1 bg-zinc-950 text-sm font-mono', selectedHosts.length > 0 && 'opacity-40')}
              value={pipelineTarget}
              onChange={e => setPipelineTarget(e.target.value)}
              disabled={selectedHosts.length > 0}
            />
          </div>
          {/* Progress indicator when running multi-host */}
          {multiProgress && (
            <div className="mt-2 flex items-center gap-2">
              <div className="flex-1 bg-zinc-800 rounded-full h-1">
                <div
                  className="bg-cyan-500 h-1 rounded-full transition-all duration-500"
                  style={{ width: `${(multiProgress.current / multiProgress.total) * 100}%` }}
                />
              </div>
              <span className="text-[10px] text-zinc-400 shrink-0">
                Host {multiProgress.current} / {multiProgress.total}
              </span>
            </div>
          )}
        </div>

        {/* Pipeline gallery */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <PipelineCard
            accent={ACCENTS.xss}
            icon={<Zap size={18} />}
            title="XSS"
            chain="Katana → mine JS → Dalfox"
            desc="Crawls the target, mines endpoints from JS and inline scripts, then runs Dalfox on every parameterized URL. Deduplicates by endpoint so the same path is not scanned twice."
            running={xssRunning}
            runLabel={runLabel('Run XSS Pipeline')}
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
            runLabel={runLabel('Run SQLi Probe')}
            disabled={noTarget}
            onRun={handleSqli}
            locked={!isPro}
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
            accent={ACCENTS.lfi}
            icon={<FileSearch size={18} />}
            title="LFI Probe"
            chain="Katana → mine JS → traversal + wrappers"
            desc="Prueba cada parámetro tipo archivo con una matriz generada (no un diccionario plano): traversal a varias profundidades, encodings (%2e, doble, ....//, overlong UTF-8), backslash Windows, null-byte, y wrappers PHP (php://filter, data://, expect://). Confirma por firma de contenido, no por longitud."
            running={lfiRunning}
            runLabel={runLabel('Run LFI Probe')}
            disabled={noTarget}
            onRun={handleLfi}
            locked={!isPro}
          >
            <CrawlOpts opts={lfiOpts} set={setLfiOpts} accent={ACCENTS.lfi.accentInput} />
            <div className="space-y-1.5 border border-zinc-800 rounded-lg p-3">
              <div className="text-[10px] font-semibold text-zinc-400 mb-1">Probe</div>
              <OptRow label="Workers" placeholder="5" value={lfiOpts.workers} onChange={v => setLfiOpts(p => ({ ...p, workers: v }))} />
              <OptRow label="Cookie" placeholder="(usa Session del sidebar)" value={lfiOpts.cookie} onChange={v => setLfiOpts(p => ({ ...p, cookie: v }))} />
              <Check label="Parsear .js (fetch/axios/XHR/$.ajax)" checked={lfiOpts.parse_js} onChange={v => setLfiOpts(p => ({ ...p, parse_js: v }))} accent={ACCENTS.lfi.accentInput} />
            </div>
          </PipelineCard>

          <PipelineCard
            accent={ACCENTS.js_scan}
            icon={<FileCode size={18} />}
            title="JS Secrets"
            chain="Katana → fetch .js → grep secrets"
            desc="Downloads every .js file and inline script, then greps for API keys, JWTs, AWS creds, GraphQL and internal endpoints. Handles minified bundles and filters low-entropy placeholders."
            running={jsRunning}
            runLabel={runLabel('Run JS Scanner')}
            disabled={noTarget}
            onRun={handleJs}
            locked={!isPro}
          >
            <CrawlOpts opts={jsOpts} set={setJsOpts} accent={ACCENTS.js_scan.accentInput} />
            <div className="space-y-1.5 border border-zinc-800 rounded-lg p-3">
              <div className="text-[10px] font-semibold text-zinc-400 mb-1">Scanner</div>
              <OptRow label="Workers" placeholder="5" value={jsOpts.workers} onChange={v => setJsOpts(p => ({ ...p, workers: v }))} />
              <OptRow label="Cookie" placeholder="(usa Session del sidebar)" value={jsOpts.cookie} onChange={v => setJsOpts(p => ({ ...p, cookie: v }))} />
            </div>
          </PipelineCard>
        </div>

        {/* Persisted results — survive an app restart, unlike the run console below */}
        {previousFindings.length > 0 && (
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-zinc-800">
              <History size={14} className="text-zinc-500" />
              <span className="text-[10px] font-semibold tracking-wider text-zinc-400 uppercase">Resultados guardados</span>
              <span className="bg-zinc-700 text-zinc-200 rounded-full px-1.5 text-[9px] font-bold">{previousFindings.length}</span>
              <span className="text-[10px] text-zinc-600 ml-1">— de corridas anteriores de este proyecto, no se pierden al reiniciar</span>
            </div>
            <div className="divide-y divide-zinc-800/60 max-h-56 overflow-y-auto">
              {previousFindings.map(f => (
                <div key={f.id} className="flex items-start gap-2.5 px-4 py-2 hover:bg-zinc-900 transition-colors">
                  <span className={cn('text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border shrink-0 mt-0.5',
                    f.severity === 'critical' ? 'text-red-400 bg-red-950/50 border-red-800' :
                    f.severity === 'high'     ? 'text-orange-400 bg-orange-950/50 border-orange-800' :
                    f.severity === 'medium'   ? 'text-yellow-400 bg-yellow-950/50 border-yellow-800' :
                    f.severity === 'low'      ? 'text-zinc-400 bg-zinc-900 border-zinc-700' :
                                                'text-zinc-500 bg-zinc-900 border-zinc-800'
                  )}>{f.severity}</span>
                  <div className="min-w-0 flex-1">
                    <div className="text-[11px] text-zinc-200 truncate">{f.title}</div>
                    {f.url && <div className="text-[9px] text-zinc-500 font-mono truncate mt-0.5">{f.url}</div>}
                  </div>
                  <span className="text-[9px] text-zinc-600 shrink-0 mt-0.5">{f.tool}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Run console */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="text-[10px] font-semibold tracking-wider text-zinc-500 uppercase">Run console</div>
            <Button variant="ghost" size="sm" className="text-zinc-600 hover:text-red-400 text-xs" onClick={() => { clearRuns(); setViewRunId(null) }} disabled={anyRunning}>
              <Trash2 size={12} className="mr-1" /> Clear history
            </Button>
          </div>

          {/* Run tabs — one per host, persisted across runs */}
          {runs.length > 0 && (
            <div className="flex gap-1 flex-wrap">
              {[...runs].reverse().map(run => {
                const isActive = run.id === activeRunId
                const isViewing = run.id === viewRun?.id
                const hostShort = run.target.replace(/^https?:\/\//, '').split('/')[0]
                const typeLabel = run.type === 'xss' ? 'XSS' : run.type === 'sqli' ? 'SQLi' : run.type === 'lfi' ? 'LFI' : 'JS'
                return (
                  <button
                    key={run.id}
                    onClick={() => setViewRunId(run.id)}
                    className={cn(
                      'flex items-center gap-1.5 px-2.5 py-1 rounded text-[10px] border transition-colors shrink-0',
                      isViewing
                        ? 'bg-zinc-800 border-zinc-600 text-zinc-200'
                        : 'bg-zinc-900 border-zinc-800 text-zinc-500 hover:border-zinc-600 hover:text-zinc-300'
                    )}
                  >
                    <span className={cn('font-mono font-bold text-[9px]',
                      typeLabel === 'XSS' ? 'text-orange-400' :
                      typeLabel === 'SQLi' ? 'text-red-400' :
                      typeLabel === 'LFI' ? 'text-amber-400' : 'text-blue-400'
                    )}>{typeLabel}</span>
                    <span className="truncate max-w-[120px]">{hostShort}</span>
                    {run.findingsCount > 0 && (
                      <span className="bg-red-600 text-white rounded-full px-1 text-[8px] font-bold shrink-0">{run.findingsCount}</span>
                    )}
                    {run.phase === 'completed' && run.findingsCount === 0 && <span className="text-green-500 text-[9px]">✓</span>}
                    {run.phase === 'failed' && <span className="text-red-400 text-[9px]">✗</span>}
                    {isActive && run.phase !== 'completed' && run.phase !== 'failed' && (
                      <Loader2 size={8} className="animate-spin text-zinc-400 shrink-0" />
                    )}
                  </button>
                )
              })}
            </div>
          )}

          {/* Phase pipeline for viewed run */}
          {viewRun && (
            <div className="flex items-center gap-2 bg-zinc-950 rounded-lg px-4 py-2 text-xs flex-wrap">
              <PhaseStep label="Katana" active={viewRun.phase === 'katana'} done={viewRun.phase !== 'katana' && viewRun.phase !== 'idle'} />
              <span className="text-zinc-700">→</span>
              {viewRun.type === 'xss' && <>
                <PhaseStep label="Filter + mine" active={viewRun.phase === 'js_parse'} done={Math.max(viewRun.candidates.length, viewRun.candidateCount) > 0 && viewRun.phase !== 'js_parse'} />
                <span className="text-zinc-700">→</span>
                <PhaseStep label="Dalfox" active={viewRun.phase === 'dalfox'} done={viewRun.phase === 'completed'} />
              </>}
              {viewRun.type === 'sqli' && <>
                <PhaseStep label="Filter + mine" active={viewRun.phase === 'js_parse'} done={Math.max(viewRun.candidates.length, viewRun.candidateCount) > 0 && viewRun.phase !== 'js_parse'} />
                <span className="text-zinc-700">→</span>
                <PhaseStep label="SQLi Probe" active={viewRun.phase === 'sqli_probe'} done={viewRun.phase === 'completed'} />
              </>}
              {viewRun.type === 'lfi' && <>
                <PhaseStep label="Filter + mine" active={viewRun.phase === 'js_parse'} done={Math.max(viewRun.candidates.length, viewRun.candidateCount) > 0 && viewRun.phase !== 'js_parse'} />
                <span className="text-zinc-700">→</span>
                <PhaseStep label="LFI Probe" active={viewRun.phase === 'lfi_probe'} done={viewRun.phase === 'completed'} />
              </>}
              {viewRun.type === 'js_scan' && <>
                <PhaseStep label="fetch .js" active={false} done={Math.max(viewRun.candidates.length, viewRun.candidateCount) > 0} />
                <span className="text-zinc-700">→</span>
                <PhaseStep label="Grep secrets" active={viewRun.phase === 'js_scan'} done={viewRun.phase === 'completed'} />
              </>}
              <div className="ml-auto flex items-center gap-3">
                <span className="text-[9px] text-zinc-600">{Math.max(viewRun.katanaUrls.length, viewRun.stats.totalUrls)} URLs</span>
                <span className="text-[9px] text-zinc-600">{Math.max(viewRun.candidates.length, viewRun.candidateCount)} {viewRun.type === 'js_scan' ? 'JS files' : 'candidates'}</span>
                {viewRun.phase === 'completed' && <span className="text-green-400 font-medium text-[10px]">✓ Done</span>}
                {viewRun.phase === 'failed' && <span className="text-red-400 font-medium text-[10px]">✗ Failed</span>}
              </div>
            </div>
          )}

          {/* Log terminal */}
          <div className="rounded-lg border border-zinc-800 bg-black overflow-auto h-64">
            <pre ref={logRef} className="text-xs font-mono whitespace-pre-wrap leading-relaxed p-4">
              {viewRun
                ? viewRun.log.map((line, i) => (
                    <span key={i} className={cn('block',
                      // XSS / SQLi findings
                      line.includes('[XSS FOUND]') ? 'text-orange-300 font-bold' :
                      line.includes('[SQL ERROR]') || line.includes('[BOOLEAN]') || line.includes('[TIME-BASED]') ? 'text-red-300 font-bold' :
                      // JS scan severity levels
                      line.includes('[CRITICAL]') ? 'text-red-400 font-bold' :
                      line.includes('[HIGH]') ? 'text-orange-400 font-semibold' :
                      line.includes('[MEDIUM]') ? 'text-yellow-400' :
                      line.includes('[LOW]') ? 'text-zinc-400' :
                      line.includes('[INFO]') ? 'text-zinc-500' :
                      // Structural lines
                      line.includes('[Katana]') ? 'text-blue-400 font-semibold' :
                      line.includes('[JS]') || line.includes('[Buckets]') ? 'text-cyan-400 font-semibold' :
                      line.includes('[SQLi]') || line.includes('[Dalfox]') ? 'text-purple-400 font-semibold' :
                      line.includes('[✓]') ? 'text-green-400 font-semibold' :
                      line.includes('[•]') ? 'text-zinc-300 font-semibold' :
                      line.includes('ERROR') || line.includes('failed') ? 'text-red-400' :
                      line.includes('  [param]') ? 'text-zinc-600' :
                      line.includes('  [•]') ? 'text-zinc-600' :
                      'text-zinc-400'
                    )}>{line}</span>
                  ))
                : <span className="text-zinc-700">No pipeline running. Pick a pipeline above and hit Run.</span>}
            </pre>
          </div>

          {/* Findings panel for viewed run */}
          {viewRun && viewRun.findings.length > 0 && (
            <div className="rounded-lg border border-zinc-700 bg-zinc-950 overflow-hidden">
              <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800">
                <span className="text-[10px] font-semibold text-zinc-300 flex items-center gap-1.5">
                  <Bug size={11} />
                  Findings — {viewRun.target.replace(/^https?:\/\//, '').split('/')[0]}
                  <span className="bg-red-600 text-white rounded-full px-1.5 text-[9px] font-bold ml-1">{viewRun.findings.length}</span>
                </span>
              </div>
              <div className="divide-y divide-zinc-800/60 max-h-48 overflow-y-auto">
                {viewRun.findings.map((f, i) => (
                  <div key={i} className="flex items-start gap-2.5 px-3 py-2 hover:bg-zinc-900 transition-colors">
                    <span className={cn('text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border shrink-0 mt-0.5',
                      f.severity === 'critical' ? 'text-red-400 bg-red-950/50 border-red-800' :
                      f.severity === 'high'     ? 'text-orange-400 bg-orange-950/50 border-orange-800' :
                      f.severity === 'medium'   ? 'text-yellow-400 bg-yellow-950/50 border-yellow-800' :
                      f.severity === 'low'      ? 'text-zinc-400 bg-zinc-900 border-zinc-700' :
                                                  'text-zinc-500 bg-zinc-900 border-zinc-800'
                    )}>{f.severity}</span>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5">
                        <span className="text-[10px] font-semibold text-zinc-200">{f.label}</span>
                        {f.param && <span className="text-[9px] text-zinc-500">param: <span className="text-yellow-400 font-mono">{f.param}</span></span>}
                      </div>
                      {f.url && <div className="text-[9px] text-zinc-500 font-mono truncate mt-0.5">{f.url}</div>}
                      {f.text && <div className="text-[9px] text-zinc-400 font-mono truncate mt-0.5">{f.text}</div>}
                    </div>
                    {/* sqlmap command generator — only for SQLi findings */}
                    {f.param && viewRun.type === 'sqli' && (
                      <button
                        onClick={() => generateSqlmap(f)}
                        title="Generate optimal sqlmap command with AI"
                        className="shrink-0 flex items-center gap-1 px-1.5 py-1 rounded border border-red-800/60 text-red-300 hover:bg-red-950/40 text-[9px] transition-colors mt-0.5"
                      >
                        <Sparkles size={10} /> sqlmap
                      </button>
                    )}
                    {/* AI analysis for JS secrets — explains what the secret is + what to test */}
                    {f.match && (
                      <button
                        onClick={() => analyzeSecret(f)}
                        title="Ask AI what this secret is and what to test"
                        className="shrink-0 flex items-center gap-1 px-1.5 py-1 rounded border border-purple-800/60 text-purple-300 hover:bg-purple-950/40 text-[9px] transition-colors mt-0.5"
                      >
                        <Sparkles size={10} /> AI
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* AI secret analysis modal */}
      {secretAi && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
          onClick={() => setSecretAi(null)}
        >
          <div
            className="w-full max-w-3xl max-h-[85vh] flex flex-col rounded-xl border border-purple-800/50 bg-zinc-950 shadow-2xl overflow-hidden"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-5 py-3 border-b border-zinc-800 bg-zinc-900 shrink-0">
              <div className="flex items-center gap-2 min-w-0">
                <Sparkles size={14} className="text-purple-400 shrink-0" />
                <span className="text-sm font-semibold text-zinc-100 truncate">AI analysis — {secretAi.title}</span>
              </div>
              <button onClick={() => setSecretAi(null)} className="text-zinc-600 hover:text-zinc-300 shrink-0"><X size={14} /></button>
            </div>
            <div className="overflow-auto p-5 text-[12px] leading-relaxed text-zinc-300 whitespace-pre-wrap">
              {secretAi.loading
                ? <span className="flex items-center gap-2 text-zinc-500"><Loader2 size={13} className="animate-spin" /> Analyzing the secret, its file and host context...</span>
                : secretAi.result}
            </div>
          </div>
        </div>
      )}

      {/* sqlmap command generator modal */}
      {sqlmapAi && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
          onClick={() => setSqlmapAi(null)}
        >
          <div
            className="w-full max-w-2xl flex flex-col rounded-xl border border-red-800/50 bg-zinc-950 shadow-2xl overflow-hidden"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-5 py-3 border-b border-zinc-800 bg-zinc-900 shrink-0">
              <div className="flex items-center gap-2 min-w-0">
                <Sparkles size={14} className="text-red-400 shrink-0" />
                <span className="text-sm font-semibold text-zinc-100 truncate">sqlmap — {sqlmapAi.title}</span>
              </div>
              <button onClick={() => setSqlmapAi(null)} className="text-zinc-600 hover:text-zinc-300 shrink-0"><X size={14} /></button>
            </div>
            <div className="p-5">
              {sqlmapAi.loading
                ? <span className="flex items-center gap-2 text-[12px] text-zinc-500"><Loader2 size={13} className="animate-spin" /> Generating optimal command...</span>
                : (
                  <div className="relative group">
                    <pre className="text-[12px] font-mono text-green-300 bg-black rounded-lg p-4 whitespace-pre-wrap break-all leading-relaxed border border-zinc-800">
                      {sqlmapAi.command}
                    </pre>
                    <button
                      onClick={() => { navigator.clipboard.writeText(sqlmapAi.command); toast.success('Copied') }}
                      className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity p-1.5 rounded border border-zinc-700 bg-zinc-900 text-zinc-400 hover:text-zinc-200"
                      title="Copy command"
                    >
                      <Copy size={11} />
                    </button>
                  </div>
                )}
            </div>
          </div>
        </div>
      )}
    </WorkspaceShell>
  )
}

// ─── Card shell ───────────────────────────────────────────────────────────────

function PipelineCard({ accent, icon, title, chain, desc, running, runLabel, disabled, onRun, locked, children }: {
  accent: typeof ACCENTS.xss
  icon: React.ReactNode
  title: string
  chain: string
  desc: string
  running: boolean
  runLabel: string
  disabled: boolean
  onRun: () => void
  locked?: boolean
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

      {locked && (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-950/20 px-3 py-2">
          <Crown size={14} className="text-amber-400 shrink-0 mt-0.5" />
          <div className="text-[11px] leading-relaxed">
            <span className="text-amber-300 font-semibold">{title} is a PRO feature.</span>
            <span className="text-zinc-400"> Upgrade to run it. </span>
            <a href="https://nexhunt.myshopify.com/products/nexhunt-pro" target="_blank" rel="noreferrer" className="text-amber-400 underline">Get PRO</a>
          </div>
        </div>
      )}

      <Button className={cn('w-full text-white text-xs font-semibold', accent.btn)} disabled={running || disabled || locked} onClick={onRun}>
        {locked
          ? <><Crown size={13} className="mr-1.5" />PRO</>
          : running
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

// ─── Live host multi-picker ───────────────────────────────────────────────────

function LiveHostPicker({ selectedHosts, onToggle, onSelectAll, onClear }: {
  selectedHosts: string[]
  onToggle: (url: string) => void
  onSelectAll: (all: string[]) => void
  onClear: () => void
}) {
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

  const visible = liveHosts.filter(h => !filter || h.url.toLowerCase().includes(filter.toLowerCase()))
  const allVisibleSelected = visible.length > 0 && visible.every(h => selectedHosts.includes(h.url))

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(v => !v)}
        className={cn(
          'w-full flex items-center justify-between gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs transition-colors',
          selectedHosts.length > 0
            ? 'border-cyan-600 bg-cyan-950/30 text-cyan-300 hover:border-cyan-500'
            : 'border-green-700/50 bg-green-950/20 text-green-400 hover:border-green-600 hover:bg-green-950/30'
        )}
      >
        <div className="flex items-center gap-1.5">
          <Server size={11} />
          {selectedHosts.length > 0
            ? <span>{selectedHosts.length} host{selectedHosts.length > 1 ? 's' : ''} selected</span>
            : <span>{liveHosts.length} live hosts</span>}
        </div>
        <ChevronDown size={11} className={cn('transition-transform', open && 'rotate-180')} />
      </button>

      {open && (
        <div className="absolute top-full left-0 right-0 mt-1 z-50 rounded-lg border border-zinc-700 bg-zinc-900 shadow-xl shadow-black/50 overflow-hidden" style={{ minWidth: '280px' }}>
          {/* Header: search + select all / clear */}
          <div className="p-1.5 border-b border-zinc-800 space-y-1.5">
            <input
              autoFocus type="text" placeholder="Filter hosts..."
              value={filter} onChange={e => setFilter(e.target.value)}
              className="w-full text-[10px] bg-zinc-950 border border-zinc-800 rounded px-2 py-1 text-zinc-300 placeholder:text-zinc-700 focus:outline-none"
            />
            <div className="flex gap-1.5">
              <button
                onClick={() => allVisibleSelected ? onClear() : onSelectAll(visible.map(h => h.url))}
                className="flex items-center gap-1 px-2 py-0.5 rounded text-[9px] border border-zinc-700 text-zinc-400 hover:border-zinc-500 hover:text-zinc-300 transition-colors"
              >
                {allVisibleSelected
                  ? <><SquareIcon size={9} /> Deselect all</>
                  : <><CheckSquare size={9} /> Select all ({visible.length})</>}
              </button>
              {selectedHosts.length > 0 && (
                <button
                  onClick={onClear}
                  className="px-2 py-0.5 rounded text-[9px] border border-zinc-700 text-red-400 hover:border-red-600 transition-colors"
                >
                  Clear ({selectedHosts.length})
                </button>
              )}
            </div>
          </div>
          {/* Host list */}
          <div className="max-h-52 overflow-y-auto">
            {visible.map((h, i) => {
              const checked = selectedHosts.includes(h.url)
              return (
                <button
                  key={i}
                  onClick={() => onToggle(h.url)}
                  className={cn(
                    'w-full flex items-center gap-2 px-2.5 py-1.5 text-left hover:bg-zinc-800 transition-colors',
                    checked && 'bg-cyan-950/20'
                  )}
                >
                  <input
                    type="checkbox" checked={checked} readOnly
                    className="w-3 h-3 accent-cyan-500 shrink-0 pointer-events-none"
                  />
                  <span className={cn('text-[10px] font-mono font-bold shrink-0',
                    h.status_code && h.status_code < 300 ? 'text-green-400' :
                    h.status_code && h.status_code < 400 ? 'text-yellow-400' : 'text-orange-400'
                  )}>
                    {h.status_code ?? '?'}
                  </span>
                  <span className="text-[10px] text-zinc-300 font-mono truncate flex-1">{h.url}</span>
                  {h.title && <span className="text-[9px] text-zinc-600 truncate max-w-[80px] shrink-0">{h.title}</span>}
                </button>
              )
            })}
            {visible.length === 0 && (
              <div className="px-3 py-4 text-center text-[10px] text-zinc-600">No hosts match</div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

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
        <Check label="force re-crawl" checked={opts.force_recrawl} onChange={v => set(p => ({ ...p, force_recrawl: v }))} accent={accent} />
      </div>
      <p className="text-[9px] text-zinc-600">Crawls are cached ~30 min per target+config and reused across pipelines. Tick force re-crawl to bypass.</p>
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
