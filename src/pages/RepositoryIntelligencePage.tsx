import { useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle, Boxes, Check, ChevronDown, ChevronRight, Circle, CloudCog, Copy, Database,
  FileCode2, GitBranch, GitCommitHorizontal, GitFork, KeyRound, Loader2, Network,
  Play, RefreshCw, SearchCode, Send, Server, ShieldAlert, Square, TerminalSquare,
} from 'lucide-react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { Input } from '@/components/ui/input'
import { api } from '@/api/http-client'
import { wsClient } from '@/api/ws-client'
import { cn } from '@/lib/utils'
import { useAppStore } from '@/stores/app-store'
import { useReconStore } from '@/stores/recon-store'
import { toast } from '@/stores/toast-store'

type EvidenceView = 'overview' | 'secrets' | 'history' | 'providers' | 'architecture'

interface SecretEvidence {
  detector: string
  raw: string
  source: string
  line: number
  commit: string
  evidence: string
  historical: boolean
}

interface ProviderEvidence {
  provider: 'github' | 'gitlab' | 'bitbucket'
  source: string
  kind: string
  evidence: string
}

interface ServiceEvidence {
  scheme: string
  host: string
  port: number | null
  source: string
  evidence: string
  credentials_exposed: boolean
}

interface RepositoryReport {
  target: string
  git_url: string
  project_id: string
  created_at: string
  exposure: {
    exposed: boolean
    checks: Array<{ name: string; url: string; status: number; size: number; signature: boolean; evidence: string }>
  }
  repository: {
    path: string
    commits: number
    files: number
    branch: string
    remotes: string[]
    log: string
    recent_commits: Array<{ hash: string; author: string; date: string; subject: string }>
  }
  history: { commits_scanned: number; truncated: boolean }
  secrets: SecretEvidence[]
  providers: ProviderEvidence[]
  architecture: {
    files_scanned: number
    hosts: string[]
    services: ServiceEvidence[]
    urls: Array<{ url: string; host: string; port: number | null; scheme: string; source: string }>
  }
  summary: {
    commits: number
    files: number
    secrets: number
    historical_secrets: number
    providers: number
    hosts: number
    services: number
  }
}

interface ProviderResult {
  valid: boolean
  provider: string
  identity: string
  repositories: Array<{ name: string; private: boolean; url: string; clone_url: string }>
}

const STAGES = [
  { id: 'exposure', label: 'Exposure', detail: 'Validate .git metadata', icon: ShieldAlert },
  { id: 'recovery', label: 'Recovery', detail: 'Reconstruct repository', icon: GitFork },
  { id: 'history', label: 'History', detail: 'Files, commits & secrets', icon: GitCommitHorizontal },
  { id: 'providers', label: 'Providers', detail: 'GitHub, GitLab, Bitbucket', icon: CloudCog },
  { id: 'architecture', label: 'Architecture', detail: 'Hosts, services & paths', icon: Network },
] as const

const VIEWS: Array<{ id: EvidenceView; label: string; icon: typeof Boxes }> = [
  { id: 'overview', label: 'Case file', icon: Boxes },
  { id: 'secrets', label: 'Secrets', icon: KeyRound },
  { id: 'history', label: 'History', icon: GitCommitHorizontal },
  { id: 'providers', label: 'Providers', icon: CloudCog },
  { id: 'architecture', label: 'Architecture', icon: Network },
]

function projectTarget(scope?: string[]) {
  return scope?.find(Boolean) || ''
}

function cleanError(error: unknown) {
  const message = error instanceof Error ? error.message : String(error)
  try {
    const parsed = JSON.parse(message.slice(message.indexOf('{')))
    return parsed.detail || message
  } catch {
    return message
  }
}

function copy(value: string, label = 'Evidence') {
  navigator.clipboard.writeText(value)
    .then(() => toast.success(`${label} copied`))
    .catch(() => toast.error('Could not copy to clipboard'))
}

function StageRail({ active, complete, running }: { active: string; complete: boolean; running: boolean }) {
  const current = STAGES.findIndex(stage => stage.id === active)
  return (
    <aside className="border border-zinc-800/80 bg-zinc-950/70 rounded-lg overflow-hidden">
      <div className="px-3 py-2.5 border-b border-zinc-800/80 bg-zinc-900/35">
        <div className="text-[9px] font-semibold uppercase tracking-[0.18em] text-zinc-600">Evidence chain</div>
      </div>
      <div className="p-2">
        {STAGES.map((stage, index) => {
          const Icon = stage.icon
          const done = complete || index < current
          const isActive = running && stage.id === active
          return (
            <div key={stage.id} className="relative flex gap-2.5 px-2 py-2.5">
              {index < STAGES.length - 1 && (
                <div className={cn('absolute left-[18px] top-8 h-[22px] w-px', done ? 'bg-green-800' : 'bg-zinc-800')} />
              )}
              <div className={cn(
                'relative z-10 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border transition-colors',
                done ? 'border-green-700 bg-green-950 text-green-400'
                  : isActive ? 'border-amber-600 bg-amber-950/50 text-amber-400'
                    : 'border-zinc-800 bg-zinc-950 text-zinc-700'
              )}>
                {done ? <Check size={10} /> : isActive ? <Loader2 size={10} className="animate-spin motion-reduce:animate-none" /> : <Icon size={10} />}
              </div>
              <div className="min-w-0">
                <div className={cn('text-[12px] font-medium', done ? 'text-green-400' : isActive ? 'text-amber-300' : 'text-zinc-500')}>
                  {stage.label}
                </div>
                <div className="text-[9px] text-zinc-700 mt-0.5 truncate">{stage.detail}</div>
              </div>
            </div>
          )
        })}
      </div>
    </aside>
  )
}

function EmptyCase() {
  return (
    <div className="min-h-[360px] flex flex-col items-center justify-center border border-dashed border-zinc-800 rounded-lg bg-zinc-950/30 px-8 text-center">
      <div className="relative mb-5">
        <div className="absolute inset-0 border border-green-900/50 rounded-full scale-[1.7]" />
        <SearchCode size={28} className="text-green-500" />
      </div>
      <h2 className="text-[15px] font-semibold text-zinc-200">No repository case opened</h2>
      <p className="mt-2 max-w-md text-[12px] leading-relaxed text-zinc-600">
        Point NexHunt at an authorized web target. It will verify exposed Git metadata, reconstruct the source,
        inspect current and deleted history, and map the infrastructure referenced by the code.
      </p>
      <div className="mt-5 flex items-center gap-2 text-[9px] uppercase tracking-[0.16em] text-zinc-700">
        <span>/.git</span><ChevronRight size={10} /><span>commits</span><ChevronRight size={10} /><span>secrets</span><ChevronRight size={10} /><span>assets</span>
      </div>
    </div>
  )
}

function SummaryLedger({ report, setView }: { report: RepositoryReport; setView: (view: EvidenceView) => void }) {
  const rows: Array<[string, number, EvidenceView, string]> = [
    ['commits', report.summary.commits, 'history', 'text-zinc-200'],
    ['files', report.summary.files, 'overview', 'text-zinc-200'],
    ['secrets', report.summary.secrets, 'secrets', report.summary.secrets ? 'text-amber-400' : 'text-zinc-500'],
    ['historical', report.summary.historical_secrets, 'secrets', report.summary.historical_secrets ? 'text-red-400' : 'text-zinc-500'],
    ['providers', report.summary.providers, 'providers', 'text-violet-400'],
    ['hosts', report.summary.hosts, 'architecture', 'text-cyan-400'],
    ['services', report.summary.services, 'architecture', 'text-cyan-400'],
  ]
  return (
    <div className="flex flex-wrap items-stretch border border-zinc-800/80 rounded-lg bg-zinc-950/65 overflow-hidden">
      {rows.map(([label, value, view, color], index) => (
        <button key={label} onClick={() => setView(view)} className={cn(
          'min-w-[88px] flex-1 px-3 py-2.5 text-left hover:bg-zinc-900/50 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-green-700 transition-colors',
          index > 0 && 'border-l border-zinc-800/70'
        )}>
          <div className={cn('font-mono text-[17px] leading-none', color)}>{value}</div>
          <div className="mt-1 text-[8px] uppercase tracking-[0.16em] text-zinc-600">{label}</div>
        </button>
      ))}
    </div>
  )
}

function Overview({ report }: { report: RepositoryReport }) {
  return (
    <div className="grid gap-3 xl:grid-cols-[1.15fr_0.85fr]">
      <section className="border border-zinc-800 rounded-lg overflow-hidden">
        <header className="flex items-center justify-between px-3 py-2 border-b border-zinc-800 bg-zinc-900/30">
          <div className="flex items-center gap-2 text-[11px] font-medium text-zinc-300"><ShieldAlert size={13} className="text-amber-400" /> Exposure proof</div>
          <span className={cn('text-[9px] uppercase tracking-wider', report.exposure.exposed ? 'text-amber-400' : 'text-zinc-600')}>
            {report.exposure.exposed ? 'confirmed' : 'not confirmed'}
          </span>
        </header>
        <div className="divide-y divide-zinc-900">
          {report.exposure.checks.map(check => (
            <div key={check.name} className="grid grid-cols-[60px_48px_1fr] items-start gap-2 px-3 py-2.5 text-[10px]">
              <span className={cn('font-mono font-semibold', check.signature ? 'text-green-400' : 'text-zinc-600')}>{check.name}</span>
              <span className={cn('font-mono', check.status === 200 ? 'text-amber-400' : 'text-zinc-600')}>{check.status || 'ERR'}</span>
              <code className="text-zinc-500 break-all line-clamp-2">{check.evidence || 'No response signature'}</code>
            </div>
          ))}
        </div>
      </section>
      <section className="border border-zinc-800 rounded-lg overflow-hidden">
        <header className="flex items-center gap-2 px-3 py-2 border-b border-zinc-800 bg-zinc-900/30 text-[11px] font-medium text-zinc-300">
          <GitBranch size={13} className="text-green-400" /> Repository identity
        </header>
        <dl className="p-3 space-y-2.5 text-[10px]">
          <div><dt className="text-zinc-700 uppercase tracking-wider">Target</dt><dd className="mt-0.5 font-mono text-zinc-300 break-all">{report.target}</dd></div>
          <div><dt className="text-zinc-700 uppercase tracking-wider">Branch</dt><dd className="mt-0.5 font-mono text-zinc-300">{report.repository.branch || 'detached'}</dd></div>
          <div><dt className="text-zinc-700 uppercase tracking-wider">Local evidence</dt><dd className="mt-0.5 font-mono text-zinc-500 break-all">{report.repository.path}</dd></div>
          <div><dt className="text-zinc-700 uppercase tracking-wider">Remotes</dt>{report.repository.remotes.length ? report.repository.remotes.map(remote => <dd key={remote} className="mt-0.5 font-mono text-violet-400 break-all">{remote}</dd>) : <dd className="mt-0.5 text-zinc-600">None recovered</dd>}</div>
        </dl>
      </section>
    </div>
  )
}

function SecretsView({ secrets }: { secrets: SecretEvidence[] }) {
  const [historicalOnly, setHistoricalOnly] = useState(false)
  const [query, setQuery] = useState('')
  const filtered = useMemo(() => secrets.filter(secret => {
    if (historicalOnly && !secret.historical) return false
    const haystack = `${secret.detector} ${secret.source} ${secret.raw} ${secret.commit}`.toLowerCase()
    return haystack.includes(query.toLowerCase())
  }), [secrets, historicalOnly, query])
  return (
    <div>
      <div className="flex flex-col sm:flex-row gap-2 mb-3">
        <div className="relative flex-1"><SearchCode size={13} className="absolute left-2.5 top-2.5 text-zinc-600" /><Input value={query} onChange={event => setQuery(event.target.value)} placeholder="Filter detector, file, value or commit" className="h-8 pl-8 text-[11px] font-mono" /></div>
        <button onClick={() => setHistoricalOnly(value => !value)} className={cn('h-8 px-3 rounded border text-[10px] transition-colors', historicalOnly ? 'border-red-800 bg-red-950/30 text-red-400' : 'border-zinc-800 text-zinc-500 hover:text-zinc-300')}>Historical only</button>
      </div>
      <div className="mb-3 flex items-center gap-2 rounded border border-amber-900/50 bg-amber-950/15 px-3 py-2 text-[10px] text-amber-500/90">
        <AlertTriangle size={12} className="shrink-0" /> Evidence is intentionally shown in cleartext. Handle exports and screenshots as sensitive material.
      </div>
      <div className="space-y-2">
        {filtered.length === 0 && <div className="py-16 text-center text-[11px] text-zinc-700">No matching secret evidence.</div>}
        {filtered.map((secret, index) => (
          <article key={`${secret.commit}-${secret.source}-${secret.line}-${index}`} className="border border-zinc-800 rounded-lg overflow-hidden bg-zinc-950/55">
            <header className="flex flex-wrap items-center gap-2 px-3 py-2 border-b border-zinc-800/80 bg-zinc-900/30">
              <KeyRound size={12} className={secret.historical ? 'text-red-400' : 'text-amber-400'} />
              <span className="text-[11px] font-medium text-zinc-200">{secret.detector}</span>
              <span className={cn('rounded px-1.5 py-0.5 text-[8px] uppercase tracking-wider', secret.historical ? 'bg-red-950/50 text-red-400' : 'bg-amber-950/50 text-amber-400')}>{secret.historical ? 'history' : 'current'}</span>
              <span className="ml-auto font-mono text-[9px] text-zinc-600">{secret.source}:{secret.line}</span>
            </header>
            <div className="p-3">
              <div className="flex items-start gap-2 rounded border border-zinc-800 bg-black/30 p-2.5">
                <code className="flex-1 break-all text-[11px] leading-relaxed text-amber-200 selection:bg-amber-700/50">{secret.raw}</code>
                <button onClick={() => copy(secret.raw, 'Secret')} className="shrink-0 text-zinc-600 hover:text-zinc-300" title="Copy secret"><Copy size={12} /></button>
              </div>
              <div className="mt-2 font-mono text-[9px] leading-relaxed text-zinc-600 break-all">{secret.evidence}</div>
              {secret.historical && <div className="mt-2 flex items-center gap-1.5 font-mono text-[9px] text-red-500/70"><GitCommitHorizontal size={10} /> {secret.commit}</div>}
            </div>
          </article>
        ))}
      </div>
    </div>
  )
}

function HistoryView({ report }: { report: RepositoryReport }) {
  return (
    <div className="border border-zinc-800 rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800 bg-zinc-900/30">
        <span className="text-[10px] text-zinc-400">Recent commit ledger</span>
        <span className="font-mono text-[9px] text-zinc-600">{report.history.commits_scanned} commits inspected</span>
      </div>
      <div className="divide-y divide-zinc-900">
        {report.repository.recent_commits.map(commit => (
          <div key={commit.hash} className="grid gap-1 px-3 py-2.5 sm:grid-cols-[88px_1fr_130px] sm:items-center">
            <button onClick={() => copy(commit.hash, 'Commit hash')} className="font-mono text-left text-[10px] text-green-500 hover:text-green-300">{commit.hash.slice(0, 10)}</button>
            <div className="min-w-0"><div className="truncate text-[11px] text-zinc-300">{commit.subject}</div><div className="text-[9px] text-zinc-600">{commit.author}</div></div>
            <time className="font-mono text-[9px] text-zinc-600 sm:text-right">{commit.date.slice(0, 19).replace('T', ' ')}</time>
          </div>
        ))}
      </div>
    </div>
  )
}

function ProvidersView({ report }: { report: RepositoryReport }) {
  const detected = Array.from(new Set(report.providers.map(item => item.provider)))
  const [provider, setProvider] = useState<'github' | 'gitlab' | 'bitbucket'>(detected[0] || 'github')
  const [token, setToken] = useState('')
  const [workspace, setWorkspace] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<ProviderResult | null>(null)

  const validate = async () => {
    if (!token.trim()) return toast.error('Paste a token to validate')
    setLoading(true)
    setResult(null)
    try {
      const response = await api.post<ProviderResult>('/api/repository-intelligence/provider/validate', { provider, token, workspace })
      setResult(response)
      toast.success(`${provider} token accepted`, `${response.repositories.length} repositories visible`)
    } catch (error) {
      toast.error('Provider validation failed', cleanError(error))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="grid gap-3 xl:grid-cols-[0.8fr_1.2fr]">
      <section className="border border-zinc-800 rounded-lg overflow-hidden">
        <header className="px-3 py-2 border-b border-zinc-800 bg-zinc-900/30 text-[10px] font-medium text-zinc-300">Detected provider evidence</header>
        <div className="divide-y divide-zinc-900">
          {report.providers.length === 0 && <div className="p-6 text-center text-[10px] text-zinc-700">No provider markers recovered.</div>}
          {report.providers.map((item, index) => (
            <div key={`${item.provider}-${index}`} className="p-3">
              <div className="flex items-center gap-2"><CloudCog size={12} className="text-violet-400" /><span className="text-[11px] font-medium capitalize text-violet-300">{item.provider}</span><span className="text-[8px] uppercase text-zinc-700">{item.kind}</span></div>
              <code className="mt-2 block break-all text-[9px] leading-relaxed text-zinc-500">{item.evidence}</code>
              <div className="mt-1 text-[8px] text-zinc-700">{item.source}</div>
            </div>
          ))}
        </div>
      </section>
      <section className="border border-zinc-800 rounded-lg p-3 bg-zinc-950/50">
        <div className="flex items-start gap-2 mb-3"><KeyRound size={13} className="mt-0.5 text-violet-400" /><div><h3 className="text-[11px] font-medium text-zinc-200">Explicit token validation</h3><p className="mt-0.5 text-[9px] text-zinc-600">The token is sent directly to the selected provider and is never stored in the case file.</p></div></div>
        <div className="grid gap-2 sm:grid-cols-[130px_1fr]">
          <select value={provider} onChange={event => { setProvider(event.target.value as typeof provider); setResult(null) }} className="h-8 rounded border border-zinc-800 bg-zinc-950 px-2 text-[11px] text-zinc-300 focus:outline-none focus:border-violet-700">
            <option value="github">GitHub</option><option value="gitlab">GitLab</option><option value="bitbucket">Bitbucket</option>
          </select>
          <Input type="password" value={token} onChange={event => setToken(event.target.value)} placeholder="Token recovered during the authorized assessment" className="h-8 font-mono text-[10px]" />
        </div>
        {provider === 'bitbucket' && <Input value={workspace} onChange={event => setWorkspace(event.target.value)} placeholder="Bitbucket workspace (optional)" className="h-8 mt-2 text-[10px]" />}
        <button onClick={validate} disabled={loading || !token.trim()} className="mt-2 inline-flex h-8 items-center gap-2 rounded border border-violet-800 bg-violet-950/30 px-3 text-[10px] font-medium text-violet-300 hover:bg-violet-950/60 disabled:opacity-40">
          {loading ? <Loader2 size={12} className="animate-spin motion-reduce:animate-none" /> : <CloudCog size={12} />} Validate & enumerate
        </button>
        {result && <div className="mt-3 border-t border-zinc-800 pt-3"><div className="mb-2 flex items-center gap-2 text-[10px] text-green-400"><Check size={11} /> Authenticated as {result.identity || 'unknown identity'}</div><div className="max-h-60 overflow-auto divide-y divide-zinc-900 border border-zinc-800 rounded">{result.repositories.map(repo => <div key={`${repo.name}-${repo.url}`} className="flex items-center gap-2 p-2 text-[9px]"><GitBranch size={10} className="text-violet-400" /><span className="flex-1 truncate text-zinc-300">{repo.name}</span><span className={repo.private ? 'text-amber-500' : 'text-zinc-700'}>{repo.private ? 'private' : 'public'}</span></div>)}</div></div>}
      </section>
    </div>
  )
}

function ArchitectureView({ report, onImport, importing }: { report: RepositoryReport; onImport: () => void; importing: boolean }) {
  const nodes = report.architecture.hosts.slice(0, 24)
  return (
    <div className="space-y-3">
      <section className="border border-zinc-800 rounded-lg overflow-hidden">
        <header className="flex items-center justify-between gap-3 px-3 py-2 border-b border-zinc-800 bg-zinc-900/30">
          <div className="flex items-center gap-2 text-[10px] text-zinc-300"><Network size={12} className="text-cyan-400" /> Source-to-service map</div>
          <button onClick={onImport} disabled={importing || report.architecture.hosts.length === 0} className="inline-flex items-center gap-1.5 rounded border border-cyan-900 bg-cyan-950/25 px-2.5 py-1 text-[9px] text-cyan-400 hover:bg-cyan-950/50 disabled:opacity-40">{importing ? <Loader2 size={10} className="animate-spin" /> : <Send size={10} />} Send assets to Recon</button>
        </header>
        <div className="relative min-h-44 overflow-hidden p-5 bg-[radial-gradient(circle_at_center,rgba(34,211,238,0.04),transparent_55%)]">
          <div className="relative z-10 mx-auto flex max-w-3xl flex-col items-center gap-5">
            <div className="flex items-center gap-2 rounded border border-green-900/70 bg-green-950/30 px-3 py-2 text-[10px] text-green-300"><FileCode2 size={12} /> recovered source</div>
            <div className="h-5 w-px bg-cyan-900" />
            <div className="flex flex-wrap justify-center gap-2">
              {nodes.map(host => <div key={host} className="flex items-center gap-1.5 rounded border border-cyan-900/70 bg-cyan-950/20 px-2.5 py-1.5 font-mono text-[9px] text-cyan-300"><Server size={10} />{host}</div>)}
              {report.architecture.hosts.length > nodes.length && <div className="rounded border border-zinc-800 px-2.5 py-1.5 text-[9px] text-zinc-600">+{report.architecture.hosts.length - nodes.length} more</div>}
            </div>
          </div>
        </div>
      </section>
      <div className="grid gap-3 xl:grid-cols-2">
        <section className="border border-zinc-800 rounded-lg overflow-hidden"><header className="px-3 py-2 border-b border-zinc-800 bg-zinc-900/30 text-[10px] text-zinc-300">Services & connection strings</header><div className="max-h-80 overflow-auto divide-y divide-zinc-900">{report.architecture.services.map((service, index) => <div key={`${service.host}-${service.port}-${index}`} className="p-3"><div className="flex items-center gap-2"><Database size={11} className={service.credentials_exposed ? 'text-amber-400' : 'text-cyan-400'} /><span className="font-mono text-[10px] text-cyan-300">{service.scheme}://{service.host}{service.port ? `:${service.port}` : ''}</span>{service.credentials_exposed && <span className="ml-auto text-[8px] uppercase text-amber-500">credentials</span>}</div><code className="mt-1.5 block break-all text-[8px] text-zinc-600">{service.evidence}</code><div className="mt-1 text-[8px] text-zinc-700">{service.source}</div></div>)}</div></section>
        <section className="border border-zinc-800 rounded-lg overflow-hidden"><header className="px-3 py-2 border-b border-zinc-800 bg-zinc-900/30 text-[10px] text-zinc-300">Referenced URLs</header><div className="max-h-80 overflow-auto divide-y divide-zinc-900">{report.architecture.urls.map((item, index) => <div key={`${item.url}-${index}`} className="p-3"><code className="block break-all text-[9px] text-cyan-300">{item.url}</code><div className="mt-1 text-[8px] text-zinc-700">{item.source}</div></div>)}</div></section>
      </div>
    </div>
  )
}

function HostSelect({ hosts, selected, onChange, disabled }: {
  hosts: { url: string; status_code: number | null; title?: string }[]
  selected: string[]
  onChange: (urls: string[]) => void
  disabled?: boolean
}) {
  const [open, setOpen] = useState(false)
  const [filter, setFilter] = useState('')
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onClick = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [open])

  const visible = filter
    ? hosts.filter(h => (h.url + (h.title || '')).toLowerCase().includes(filter.toLowerCase()))
    : hosts
  const toggle = (url: string) => onChange(selected.includes(url) ? selected.filter(u => u !== url) : [...selected, url])

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen(v => !v)}
        disabled={disabled || hosts.length === 0}
        className="h-8 flex items-center gap-2 rounded border border-green-900/70 bg-green-950/20 px-3 text-[10px] text-green-300 hover:border-green-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
      >
        <Server size={12} />
        <span>{selected.length ? `${selected.length} selected` : hosts.length ? 'Pick hosts' : 'No live hosts'}</span>
        <ChevronDown size={11} className={cn('transition-transform', open && 'rotate-180')} />
      </button>
      {open && (
        <div className="absolute z-50 top-full left-0 mt-1 w-[420px] max-w-[80vw] rounded-lg border border-zinc-700 bg-zinc-900 shadow-xl shadow-black/50 overflow-hidden">
          <div className="flex items-center gap-2 p-2 border-b border-zinc-800">
            <input autoFocus value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter hostname or title" className="flex-1 h-7 rounded border border-zinc-800 bg-zinc-950 px-2 text-[10px] text-zinc-300 focus:outline-none focus:border-green-800" />
            <button type="button" onClick={() => onChange(hosts.map(h => h.url))} className="text-[10px] text-green-400 hover:text-green-300">Select all</button>
            <button type="button" onClick={() => onChange([])} className="text-[10px] text-zinc-500 hover:text-zinc-300">Clear</button>
          </div>
          <div className="max-h-56 overflow-y-auto p-1">
            {visible.map(host => {
              const checked = selected.includes(host.url)
              return (
                <button type="button" key={host.url} onClick={() => toggle(host.url)} className={cn('w-full grid grid-cols-[20px_44px_minmax(0,1fr)] items-center gap-2 rounded px-2 py-1.5 text-left hover:bg-zinc-800/70', checked && 'bg-green-950/20')}>
                  <span className={cn('w-3.5 h-3.5 rounded border grid place-items-center', checked ? 'border-green-600 bg-green-600 text-zinc-950' : 'border-zinc-700')}>{checked && <Check size={10} />}</span>
                  <span className={cn('text-[9px] font-mono font-semibold', host.status_code && host.status_code < 300 ? 'text-green-400' : 'text-amber-400')}>{host.status_code || '---'}</span>
                  <span className="font-mono text-[10px] text-zinc-300 truncate">{host.url}</span>
                </button>
              )
            })}
            {visible.length === 0 && <div className="px-3 py-5 text-center text-[10px] text-zinc-600">No hosts match this filter.</div>}
          </div>
        </div>
      )}
    </div>
  )
}

export function RepositoryIntelligencePage({ embedded = false }: { embedded?: boolean }) {
  const activeProject = useAppStore(state => state.activeProject)
  const activeProjectData = useAppStore(state => state.activeProjectData)
  const [target, setTarget] = useState(() => projectTarget(activeProjectData?.scope))
  const [report, setReport] = useState<RepositoryReport | null>(null)
  const [view, setView] = useState<EvidenceView>('overview')
  const [running, setRunning] = useState(false)
  const [jobId, setJobId] = useState<string | null>(null)
  const [stage, setStage] = useState('')
  const [status, setStatus] = useState('Ready to inspect target')
  const [scanHistory, setScanHistory] = useState(true)
  const [importing, setImporting] = useState(false)
  const liveHosts = useReconStore(state => state.liveHosts)
  const [selectedHosts, setSelectedHosts] = useState<string[]>([])
  const [bulkProgress, setBulkProgress] = useState<{ done: number; total: number } | null>(null)

  useEffect(() => {
    if (!target && activeProjectData?.scope?.length) setTarget(projectTarget(activeProjectData.scope))
  }, [activeProjectData, target])

  useEffect(() => {
    setReport(null)
    setTarget(activeProjectData?.id === activeProject ? projectTarget(activeProjectData.scope) : '')
    setStage('')
    setStatus('Ready to inspect target')
  }, [activeProject])

  useEffect(() => {
    return wsClient.subscribe('repository_intelligence', data => {
      const event = data as { event: string; job_id: string; project_id: string; stage?: string; message?: string; report?: RepositoryReport; error?: string; host_index?: number; host_total?: number }
      if (event.project_id !== activeProject) return
      if (event.event === 'progress') {
        setRunning(true)
        setStage(event.stage || '')
        setStatus(event.message || 'Working…')
      } else if (event.event === 'completed' && event.report) {
        setReport(event.report)
        if (event.host_index && event.host_total) {
          // One host of a bulk sweep finished; keep the job running for the rest.
          setBulkProgress({ done: event.host_index, total: event.host_total })
          setStatus(`Host ${event.host_index} of ${event.host_total} complete`)
        } else {
          setRunning(false)
          setJobId(null)
          setStage('complete')
          setStatus('Repository intelligence report ready')
          toast.success('Repository case completed', `${event.report.summary.secrets} secrets and ${event.report.summary.hosts} hosts extracted`)
        }
      } else if (event.event === 'bulk_completed') {
        setRunning(false)
        setJobId(null)
        setStage('complete')
        setBulkProgress(null)
        setStatus(`Sweep complete — ${event.host_total ?? 0} host(s) analyzed`)
        toast.success('Repository sweep completed', `${event.host_total ?? 0} host(s) analyzed`)
      } else if (event.event === 'failed') {
        setRunning(false)
        setJobId(null)
        setStatus(event.error || 'Analysis failed')
        toast.error('Repository analysis failed', event.error)
      } else if (event.event === 'cancelled') {
        setRunning(false)
        setJobId(null)
        setStatus('Analysis cancelled')
      }
    })
  }, [activeProject])

  const start = async () => {
    if (!activeProject) return toast.error('An active project is required')
    if (!selectedHosts.length && !target.trim()) return toast.error('Pick hosts or enter a target')
    setReport(null)
    setView('overview')
    setRunning(true)
    setStage('exposure')
    try {
      if (selectedHosts.length) {
        setBulkProgress({ done: 0, total: selectedHosts.length })
        setStatus(`Opening ${selectedHosts.length} repository cases…`)
        const response = await api.post<{ job_id: string }>('/api/repository-intelligence/analyze-bulk', {
          targets: selectedHosts, project_id: activeProject, recover: true, scan_history: scanHistory,
        })
        setJobId(response.job_id)
      } else {
        setBulkProgress(null)
        setStatus('Opening repository case…')
        const response = await api.post<{ job_id: string }>('/api/repository-intelligence/analyze', {
          target, project_id: activeProject, recover: true, scan_history: scanHistory,
        })
        setJobId(response.job_id)
      }
    } catch (error) {
      setRunning(false)
      setStage('')
      setBulkProgress(null)
      setStatus(cleanError(error))
      toast.error('Could not start analysis', cleanError(error))
    }
  }

  const cancel = async () => {
    if (!jobId) return
    try { await api.delete(`/api/repository-intelligence/jobs/${jobId}`) } catch (error) { toast.error('Could not cancel job', cleanError(error)) }
  }

  const loadLatest = async () => {
    if (!activeProject || !target.trim()) return
    try {
      const response = await api.get<{ report: RepositoryReport | null }>('/api/repository-intelligence/latest', { project_id: activeProject, target })
      if (response.report) {
        setReport(response.report)
        setStage('complete')
        setStatus('Stored case loaded')
      } else toast.error('No stored case for this target')
    } catch (error) { toast.error('Could not load stored case', cleanError(error)) }
  }

  const importAssets = async () => {
    if (!report || !activeProject) return
    setImporting(true)
    const assets = [
      ...report.architecture.hosts.map(value => ({ type: 'host', value })),
      ...report.architecture.urls.map(item => ({ type: 'url', value: item.url })),
    ].slice(0, 500)
    try {
      const response = await api.post<{ imported: number; skipped_out_of_scope: number }>('/api/repository-intelligence/assets/import', { project_id: activeProject, assets })
      const skipped = response.skipped_out_of_scope ? `; ${response.skipped_out_of_scope} out of scope skipped` : ''
      toast.success('Assets sent to Recon', `${response.imported} assets imported${skipped}`)
    } catch (error) { toast.error('Asset import failed', cleanError(error)) } finally { setImporting(false) }
  }

  return (
    <WorkspaceShell embedded={embedded} title="Repository Intelligence" subtitle="Recover exposed source, inspect Git history and map infrastructure">
      <div className="space-y-3">
        <section className="border border-zinc-800/80 rounded-lg bg-zinc-950/55 overflow-hidden">
          <div className="flex flex-col gap-3 p-3 lg:flex-row lg:items-end">
            <div className="flex-1"><label className="mb-1.5 block text-[9px] font-semibold uppercase tracking-[0.16em] text-zinc-600">Authorized target</label><div className="relative"><TerminalSquare size={13} className="absolute left-3 top-2.5 text-green-500" /><Input value={target} onChange={event => setTarget(event.target.value)} disabled={running || selectedHosts.length > 0} placeholder={selectedHosts.length ? `${selectedHosts.length} live host(s) selected` : 'https://target.example'} className="h-8 pl-8 font-mono text-[11px] disabled:opacity-50" /></div></div>
            <div><label className="mb-1.5 block text-[9px] font-semibold uppercase tracking-[0.16em] text-zinc-600">Live hosts</label><HostSelect hosts={liveHosts} selected={selectedHosts} onChange={setSelectedHosts} disabled={running} /></div>
            <label className="flex h-8 cursor-pointer items-center gap-2 rounded border border-zinc-800 px-2.5 text-[9px] text-zinc-500 hover:text-zinc-300"><input type="checkbox" checked={scanHistory} onChange={event => setScanHistory(event.target.checked)} disabled={running} className="accent-green-600" /> Scan deleted history</label>
            <button onClick={loadLatest} disabled={running || selectedHosts.length > 0 || !target.trim()} className="inline-flex h-8 items-center justify-center gap-1.5 rounded border border-zinc-800 px-3 text-[10px] text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200 disabled:opacity-40"><RefreshCw size={11} /> Load last</button>
            {running ? <button onClick={cancel} disabled={!jobId} className="inline-flex h-8 items-center justify-center gap-1.5 rounded border border-red-900 bg-red-950/20 px-3 text-[10px] text-red-400 hover:bg-red-950/40 disabled:opacity-40"><Square size={10} /> Stop</button> : <button onClick={start} disabled={!selectedHosts.length && !target.trim()} className="inline-flex h-8 items-center justify-center gap-1.5 rounded border border-green-800 bg-green-950/40 px-4 text-[10px] font-medium text-green-300 hover:bg-green-950/70 disabled:opacity-40"><Play size={11} fill="currentColor" /> {selectedHosts.length ? `Analyze ${selectedHosts.length} host${selectedHosts.length > 1 ? 's' : ''}` : 'Recover & analyze'}</button>}
          </div>
          <div className="flex items-center gap-2 border-t border-zinc-800/70 bg-black/20 px-3 py-1.5 font-mono text-[9px]"><Circle size={6} fill="currentColor" className={running ? 'text-amber-400 animate-pulse motion-reduce:animate-none' : report ? 'text-green-500' : 'text-zinc-700'} /><span className={running ? 'text-amber-400' : 'text-zinc-600'}>{status}</span>{bulkProgress && <span className="text-green-500">· {bulkProgress.done}/{bulkProgress.total} hosts</span>}{jobId && <span className="ml-auto text-zinc-800">job {jobId.slice(0, 8)}</span>}</div>
        </section>

        <div className="grid gap-3 lg:grid-cols-[190px_minmax(0,1fr)]">
          <StageRail active={stage} complete={stage === 'complete'} running={running} />
          <div className="min-w-0 space-y-3">
            {report && <SummaryLedger report={report} setView={setView} />}
            {report && <nav className="flex overflow-x-auto border-b border-zinc-800" aria-label="Repository evidence views">{VIEWS.map(item => { const Icon = item.icon; return <button key={item.id} onClick={() => setView(item.id)} className={cn('flex shrink-0 items-center gap-1.5 border-b-2 px-3 py-2 text-[10px] transition-colors', view === item.id ? 'border-green-500 text-green-400' : 'border-transparent text-zinc-600 hover:text-zinc-300')}><Icon size={11} />{item.label}{item.id === 'secrets' && report.summary.secrets > 0 && <span className="rounded bg-amber-950/50 px-1 text-[8px] text-amber-400">{report.summary.secrets}</span>}</button> })}</nav>}
            {!report && <EmptyCase />}
            {report && view === 'overview' && <Overview report={report} />}
            {report && view === 'secrets' && <SecretsView secrets={report.secrets} />}
            {report && view === 'history' && <HistoryView report={report} />}
            {report && view === 'providers' && <ProvidersView report={report} />}
            {report && view === 'architecture' && <ArchitectureView report={report} onImport={importAssets} importing={importing} />}
          </div>
        </div>
      </div>
    </WorkspaceShell>
  )
}
