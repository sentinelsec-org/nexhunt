import { useEffect, useMemo, useState } from 'react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { api } from '@/api/http-client'
import { useAppStore } from '@/stores/app-store'
import { useReconStore } from '@/stores/recon-store'
import { toast } from '@/stores/toast-store'
import { cn } from '@/lib/utils'
import {
  Search, Radar, Globe2, Database, Braces, ShieldAlert, Bug, KeyRound,
  ExternalLink, Loader2, Server, MapPin, Copy, Check, FolderSearch,
  SlidersHorizontal, AlertTriangle, ChevronRight,
} from 'lucide-react'

type Mode = 'global' | 'project'
type Category = 'api_docs' | 'sql_errors' | 'known_vuln' | 'default_logins' | 'admin_panels' | 'debug' | 'secrets' | 'custom'
type ResultView = 'web' | 'shodan' | 'dorks' | 'project'

interface DorkResult { query: string; google_url: string; bing_url: string }
interface ShodanResult {
  ip: string; port: number; transport: string; hostnames: string[]; domains: string[]
  org: string; product: string; version: string; title: string; server: string
  country: string; city: string; vulns: string[]; timestamp: string
}
interface WebResult {
  url: string; title: string; description: string; hostname: string
  signals: string[]; source_query: string
}
interface ProjectResult {
  url: string; source_host: string; category: string; severity: string
  status_code: number; content_type: string; technologies: string[]; signals: string[]
}

const CATEGORIES: { id: Category; label: string; short: string; icon: typeof Search; tone: string }[] = [
  { id: 'api_docs', label: 'Exposed APIs', short: 'Swagger, OpenAPI, GraphQL', icon: Braces, tone: 'text-cyan-400 border-cyan-900/70 bg-cyan-950/20' },
  { id: 'sql_errors', label: 'SQL errors', short: 'Database error disclosure', icon: Database, tone: 'text-red-400 border-red-900/70 bg-red-950/20' },
  { id: 'known_vuln', label: 'Known CVEs', short: 'Search by CVE identifier', icon: ShieldAlert, tone: 'text-rose-400 border-rose-900/70 bg-rose-950/20' },
  { id: 'default_logins', label: 'Default-login risks', short: 'Initial setup and admin surfaces', icon: KeyRound, tone: 'text-amber-400 border-amber-900/70 bg-amber-950/20' },
  { id: 'admin_panels', label: 'Admin panels', short: 'Jenkins, Grafana, phpMyAdmin', icon: KeyRound, tone: 'text-amber-400 border-amber-900/70 bg-amber-950/20' },
  { id: 'debug', label: 'Debug surfaces', short: 'Actuator, phpinfo, profiler', icon: Bug, tone: 'text-violet-400 border-violet-900/70 bg-violet-950/20' },
  { id: 'secrets', label: 'Exposed secrets', short: '.env, .git, config backups', icon: ShieldAlert, tone: 'text-orange-400 border-orange-900/70 bg-orange-950/20' },
]

const TECHNOLOGIES = ['', 'wordpress', 'nginx', 'apache', 'iis', 'jenkins', 'grafana', 'elasticsearch', 'kubernetes', 'django', 'laravel']

export function ExposureIntelPage() {
  const activeProject = useAppStore(s => s.activeProject)
  const activeProjectData = useAppStore(s => s.activeProjectData)
  const liveHosts = useReconStore(s => s.liveHosts)
  const [mode, setMode] = useState<Mode>('global')
  const [category, setCategory] = useState<Category>('api_docs')
  const [query, setQuery] = useState('')
  const [technology, setTechnology] = useState('')
  const [domain, setDomain] = useState('')
  const [shodanConfigured, setShodanConfigured] = useState(false)
  const [braveConfigured, setBraveConfigured] = useState(false)
  const [loading, setLoading] = useState(false)
  const [resultView, setResultView] = useState<ResultView>('shodan')
  const [dorks, setDorks] = useState<DorkResult[]>([])
  const [shodanResults, setShodanResults] = useState<ShodanResult[]>([])
  const [shodanTotal, setShodanTotal] = useState(0)
  const [shodanQuery, setShodanQuery] = useState('')
  const [shodanQueries, setShodanQueries] = useState<string[]>([])
  const [shodanError, setShodanError] = useState('')
  const [webResults, setWebResults] = useState<WebResult[]>([])
  const [webQueries, setWebQueries] = useState<string[]>([])
  const [webError, setWebError] = useState('')
  const [projectResults, setProjectResults] = useState<ProjectResult[]>([])
  const [projectStats, setProjectStats] = useState({ hosts: 0, tested: 0 })
  const [copied, setCopied] = useState<string | null>(null)

  useEffect(() => {
    api.get<any>('/api/exposure-intel/presets')
      .then(data => {
        setShodanConfigured(!!data.shodan_configured)
        setBraveConfigured(!!data.brave_configured)
      })
      .catch(() => {})
  }, [])

  const projectDomains = useMemo(() => liveHosts.map(host => host.host || host.url).filter(Boolean), [liveHosts])
  const projectTech = useMemo(() => Array.from(new Set(liveHosts.flatMap(host => host.technologies || []))).sort(), [liveHosts])

  const payload = () => ({
    category,
    technology,
    domain: mode === 'global' ? domain : '',
    custom_query: query,
    project_hosts: mode === 'project' ? projectDomains : [],
  })

  const runGlobalSearch = async () => {
    setLoading(true); setShodanError(''); setWebError(''); setProjectResults([])
    try {
      const dorkPromise = api.post<DorkResult[]>('/api/exposure-intel/dorks', payload())
      const shodanPromise = api.post<any>('/api/exposure-intel/shodan/search', payload())
      const webPromise = api.post<any>('/api/exposure-intel/web/search', payload())
      const [dorkData, shodanData, webData] = await Promise.all([dorkPromise, shodanPromise, webPromise])
      setDorks(dorkData)
      setShodanResults(shodanData.results || [])
      setShodanTotal(shodanData.total || 0)
      setShodanQuery(shodanData.query || '')
      setShodanQueries(shodanData.queries || [])
      setShodanError(shodanData.error || '')
      setWebResults(webData.results || [])
      setWebQueries(webData.queries || [])
      setWebError(webData.error || '')
      setResultView(webData.results?.length ? 'web' : shodanData.results?.length ? 'shodan' : 'dorks')
    } catch (error) {
      toast.error('Exposure search failed', error)
    } finally { setLoading(false) }
  }

  const runProjectScan = async () => {
    if (!activeProject) return
    setLoading(true); setProjectResults([])
    try {
      const [scan, dorkData] = await Promise.all([
        api.post<any>('/api/exposure-intel/project-scan', {
          project_id: activeProject,
          categories: category === 'sql_errors' ? ['api_docs', 'admin_panels', 'debug'] : [category],
          technology,
          max_hosts: 50,
        }),
        api.post<DorkResult[]>('/api/exposure-intel/dorks', payload()),
      ])
      setProjectResults(scan.results || [])
      setProjectStats({ hosts: scan.hosts || 0, tested: scan.tested || 0 })
      setDorks(dorkData)
      setResultView('project')
      if (!scan.results?.length) toast.info('No exposed endpoints matched', scan.message || `${scan.tested || 0} candidates checked`)
    } catch (error) {
      toast.error('Project endpoint scan failed', error)
    } finally { setLoading(false) }
  }

  const copyText = (value: string) => {
    navigator.clipboard.writeText(value)
    setCopied(value)
    setTimeout(() => setCopied(null), 1200)
  }

  const openExternal = (url: string) => window.open(url, '_blank', 'noopener,noreferrer')

  return (
    <WorkspaceShell title="Exposure Intel" subtitle="Search public exposure signals across Shodan, search engines, and your live hosts">
      <div className="flex flex-col gap-4 max-w-[1450px]">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="inline-flex rounded-lg border border-zinc-800 bg-zinc-950 p-1">
            <ModeButton active={mode === 'global'} icon={<Globe2 size={14} />} label="Global Search" onClick={() => setMode('global')} />
            <ModeButton active={mode === 'project'} icon={<FolderSearch size={14} />} label="Project Hosts" onClick={() => setMode('project')} />
          </div>
          <div className="flex items-center gap-3 text-[11px]">
            <SourceStatus label="Brave URLs" configured={braveConfigured} />
            <SourceStatus label="Shodan" configured={shodanConfigured} />
            {(!shodanConfigured || !braveConfigured) && <button className="text-blue-400 hover:underline" onClick={() => location.hash = '#/settings'}>Open Settings</button>}
          </div>
        </div>

        <section className="rounded-xl border border-zinc-800 bg-zinc-900/45 overflow-hidden">
          <div className="p-4 border-b border-zinc-800 bg-gradient-to-r from-green-950/20 via-transparent to-cyan-950/10">
            <div className="flex items-center gap-2 mb-3">
              <Search size={18} className="text-green-400" />
              <div>
                <h2 className="text-sm font-semibold text-zinc-100">{mode === 'global' ? 'Global vulnerability search' : 'Search your discovered attack surface'}</h2>
                <p className="text-[11px] text-zinc-500">{mode === 'global' ? 'Passive intelligence only. Choose a signal, add filters, and search public indexes.' : `${activeProjectData?.name || 'No project selected'} · ${liveHosts.length} live hosts available`}</p>
              </div>
            </div>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-600" />
                <Input
                  value={query}
                  onChange={event => setQuery(event.target.value)}
                  onKeyDown={event => { if (event.key === 'Enter' && !loading) mode === 'global' ? runGlobalSearch() : runProjectScan() }}
                  placeholder={category === 'custom' ? 'Shodan query or search dork…' : 'Optional keyword or Shodan filter, e.g. country:US port:443'}
                  className="h-11 pl-9 bg-black/60 border-zinc-700 font-mono text-sm"
                />
              </div>
              <Button
                onClick={mode === 'global' ? runGlobalSearch : runProjectScan}
                disabled={loading || (mode === 'project' && (!activeProject || !liveHosts.length))}
                className="h-11 px-5 bg-green-700 hover:bg-green-600 text-white"
              >
                {loading ? <Loader2 size={15} className="mr-2 animate-spin" /> : <Radar size={15} className="mr-2" />}
                {mode === 'global' ? 'Search exposures' : 'Scan project hosts'}
              </Button>
            </div>
          </div>

          <div className="p-4 space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-7 gap-2">
              {CATEGORIES.map(item => {
                const Icon = item.icon
                return <button key={item.id} onClick={() => setCategory(item.id)} className={cn('text-left border rounded-lg p-3 transition-colors', category === item.id ? item.tone : 'border-zinc-800 bg-zinc-950/60 hover:border-zinc-700')}>
                  <Icon size={15} className={category === item.id ? '' : 'text-zinc-600'} />
                  <div className={cn('text-xs font-semibold mt-2', category === item.id ? '' : 'text-zinc-300')}>{item.label}</div>
                  <div className="text-[10px] text-zinc-600 mt-0.5 leading-tight">{item.short}</div>
                </button>
              })}
            </div>

            <div className="flex items-end gap-3 flex-wrap border-t border-zinc-800 pt-3">
              <div className="min-w-48">
                <label className="flex items-center gap-1 text-[10px] text-zinc-600 uppercase tracking-wider mb-1"><SlidersHorizontal size={10} /> Technology</label>
                <Input list="exposure-technologies" value={technology} onChange={event => setTechnology(event.target.value)} placeholder="Any technology" className="h-9 bg-zinc-950 text-xs" />
                <datalist id="exposure-technologies">
                  {(mode === 'project' && projectTech.length ? projectTech : TECHNOLOGIES.filter(Boolean)).map(value => <option key={value} value={value} />)}
                </datalist>
              </div>
              {mode === 'global' && <div className="min-w-64 flex-1 max-w-md">
                <label className="text-[10px] text-zinc-600 uppercase tracking-wider mb-1 block">Domain / organization scope (optional)</label>
                <Input value={domain} onChange={event => setDomain(event.target.value)} placeholder="example.com" className="h-9 bg-zinc-950 font-mono text-xs" />
              </div>}
              {mode === 'project' && <div className="text-[11px] text-zinc-500 pb-2">
                HTTP probing is restricted to live hosts saved under the active project.
              </div>}
            </div>
          </div>
        </section>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-px rounded-lg border border-zinc-800 bg-zinc-800 overflow-hidden">
          <Stat value={webResults.length.toString()} label="Direct URLs" />
          <Stat value={shodanResults.length.toString()} label="Shodan results" />
          <Stat value={dorks.length.toString()} label="Search dorks" />
          <Stat value={mode === 'project' ? projectStats.tested.toString() : liveHosts.length.toString()} label={mode === 'project' ? 'Endpoints tested' : 'Project live hosts'} />
        </div>

        <section className="rounded-xl border border-zinc-800 bg-zinc-900/40 overflow-hidden min-h-[360px]">
          <div className="flex items-center gap-1 px-3 border-b border-zinc-800 bg-zinc-950/60 overflow-x-auto">
            <ResultTab active={resultView === 'web'} label="Direct URLs" count={webResults.length} onClick={() => setResultView('web')} />
            <ResultTab active={resultView === 'shodan'} label="Shodan" count={shodanResults.length} onClick={() => setResultView('shodan')} />
            <ResultTab active={resultView === 'dorks'} label="Google / Bing dorks" count={dorks.length} onClick={() => setResultView('dorks')} />
            {mode === 'project' && <ResultTab active={resultView === 'project'} label="Project endpoints" count={projectResults.length} onClick={() => setResultView('project')} />}
          </div>

          {resultView === 'web' && <WebResults results={webResults} queries={webQueries} error={webError} configured={braveConfigured} openExternal={openExternal} />}
          {resultView === 'shodan' && <ShodanResults results={shodanResults} query={shodanQuery} queries={shodanQueries} error={shodanError} configured={shodanConfigured} openExternal={openExternal} copyText={copyText} copied={copied} />}
          {resultView === 'dorks' && <DorkResults results={dorks} openExternal={openExternal} copyText={copyText} copied={copied} />}
          {resultView === 'project' && <ProjectResults results={projectResults} openExternal={openExternal} />}
        </section>

        <div className="flex items-start gap-2 text-[10px] text-zinc-600 px-1">
          <AlertTriangle size={12} className="shrink-0 mt-0.5" />
          <span>Global results are passive intelligence and may include unrelated third-party systems. Validate authorization before any active testing. NexHunt does not attempt default credentials or exploit discovered services.</span>
        </div>
      </div>
    </WorkspaceShell>
  )
}

function ModeButton({ active, icon, label, onClick }: { active: boolean; icon: React.ReactNode; label: string; onClick: () => void }) {
  return <button onClick={onClick} className={cn('flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium', active ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-500 hover:text-zinc-300')}>{icon}{label}</button>
}
function SourceStatus({ label, configured }: { label: string; configured: boolean }) {
  return <span className="flex items-center gap-1.5 text-zinc-500"><span className={cn('w-1.5 h-1.5 rounded-full', configured ? 'bg-green-500' : 'bg-amber-500')} />{label}</span>
}
function Stat({ value, label }: { value: string; label: string }) {
  return <div className="bg-zinc-950 px-4 py-3"><div className="font-mono text-lg font-semibold text-zinc-200">{value}</div><div className="text-[10px] text-zinc-600">{label}</div></div>
}
function ResultTab({ active, label, count, onClick }: { active: boolean; label: string; count: number; onClick: () => void }) {
  return <button onClick={onClick} className={cn('flex items-center gap-2 px-3 py-2.5 border-b-2 text-xs whitespace-nowrap', active ? 'border-green-500 text-green-400' : 'border-transparent text-zinc-500 hover:text-zinc-300')}><span>{label}</span>{count > 0 && <span className="rounded bg-zinc-800 px-1.5 py-0.5 text-[9px] text-zinc-400">{count}</span>}</button>
}

function ShodanResults({ results, query, queries, error, configured, openExternal, copyText, copied }: { results: ShodanResult[]; query: string; queries: string[]; error: string; configured: boolean; openExternal: (url: string) => void; copyText: (v: string) => void; copied: string | null }) {
  if (error) return <div className="min-h-[310px] flex flex-col items-center justify-center text-center px-6">
    <div className="text-zinc-700 mb-3"><Radar size={24} /></div>
    <div className="text-sm font-medium text-zinc-300">{configured ? 'Shodan API could not complete the search' : 'Connect Shodan for API results'}</div>
    <div className="text-xs text-zinc-600 mt-1 max-w-md">{error}</div>
    {!!queries.length && <div className="mt-4 w-full max-w-2xl space-y-2">
      {queries.map((item, index) => <div key={item} className="flex items-center gap-2 rounded border border-zinc-800 bg-black/40 px-3 py-2 text-left">
        <code className="flex-1 min-w-0 text-[10px] text-green-400 break-all">{item}</code>
        <button title="Copy query" onClick={() => copyText(item)} className="p-1 text-zinc-500 hover:text-zinc-200">{copied === item ? <Check size={12} /> : <Copy size={12} />}</button>
        <Button size="sm" variant="outline" className="h-7 shrink-0 text-[10px]" onClick={() => openExternal(`https://www.shodan.io/search?query=${encodeURIComponent(item)}`)}>Open {index + 1}<ExternalLink size={10} className="ml-1" /></Button>
      </div>)}
    </div>}
  </div>
  if (!results.length) return <EmptyState icon={<Radar size={24} />} title="No Shodan results loaded" body="Choose a vulnerability signal and run a global search." />
  return <div>
    {query && <div className="flex items-center gap-2 px-4 py-2 border-b border-zinc-800 bg-black/20"><code className="flex-1 text-[10px] text-green-400 font-mono truncate">{query}</code><button onClick={() => copyText(query)} className="text-zinc-500 hover:text-zinc-200">{copied === query ? <Check size={12} /> : <Copy size={12} />}</button></div>}
    <div className="divide-y divide-zinc-800/70">
      {results.map((result, index) => {
        const host = result.hostnames[0] || result.ip
        return <div key={`${result.ip}:${result.port}:${index}`} className="grid grid-cols-[minmax(180px,.8fr)_minmax(220px,1.4fr)_minmax(160px,.8fr)_auto] gap-4 items-center px-4 py-3 hover:bg-zinc-900/60">
          <div className="min-w-0"><div className="font-mono text-xs text-zinc-200 truncate">{host}:{result.port}</div><div className="text-[10px] text-zinc-600 truncate mt-0.5">{result.ip} · {result.transport}</div></div>
          <div className="min-w-0"><div className="text-xs text-zinc-300 truncate">{result.title || result.product || 'Untitled service'}</div><div className="text-[10px] text-zinc-600 truncate mt-0.5">{[result.product, result.version, result.server].filter(Boolean).join(' · ') || result.org}</div></div>
          <div className="min-w-0"><div className="flex items-center gap-1 text-[10px] text-zinc-500 truncate"><MapPin size={10} />{[result.city, result.country].filter(Boolean).join(', ') || 'Unknown location'}</div>{result.vulns.length > 0 && <div className="text-[10px] text-red-400 mt-1 truncate">{result.vulns.slice(0, 3).join(', ')}</div>}</div>
          <button title="Open on Shodan" onClick={() => openExternal(`https://www.shodan.io/host/${result.ip}`)} className="p-2 text-zinc-500 hover:text-green-400"><ExternalLink size={14} /></button>
        </div>
      })}
    </div>
  </div>
}

function WebResults({ results, queries, error, configured, openExternal }: { results: WebResult[]; queries: string[]; error: string; configured: boolean; openExternal: (url: string) => void }) {
  if (error && !results.length) return <div className="min-h-[310px] flex flex-col items-center justify-center text-center px-6">
    <div className="text-zinc-700 mb-3"><Server size={24} /></div>
    <div className="text-sm font-medium text-zinc-300">{configured ? 'Web search could not load direct URLs' : 'Connect Brave Search for direct URLs'}</div>
    <div className="text-xs text-zinc-600 mt-1 max-w-lg">{error}</div>
    {!!queries.length && <code className="mt-4 max-w-2xl text-[10px] text-zinc-500 bg-black/50 border border-zinc-800 rounded px-3 py-2 break-all">{queries[0]}</code>}
  </div>
  if (!results.length) return <EmptyState icon={<Server size={24} />} title="No direct URLs matched" body="The search engine results were filtered to remove articles, tutorials, and documentation pages." />
  return <div className="divide-y divide-zinc-800/70">
    {results.map((result, index) => <button key={`${result.url}:${index}`} onClick={() => openExternal(result.url)} className="w-full text-left grid grid-cols-[minmax(150px,.45fr)_minmax(260px,1.3fr)_minmax(130px,.45fr)_auto] gap-4 items-center px-4 py-3 hover:bg-zinc-900/60">
      <div className="font-mono text-[11px] text-green-400 truncate">{result.hostname}</div>
      <div className="min-w-0"><div className="text-xs text-zinc-200 truncate">{result.title || result.url}</div><div className="text-[10px] text-zinc-600 truncate mt-0.5">{result.url}</div></div>
      <div className="flex gap-1 flex-wrap">{result.signals.slice(0, 3).map(signal => <span key={signal} className="rounded border border-zinc-700 bg-zinc-900 px-1.5 py-0.5 text-[9px] text-zinc-500">{signal}</span>)}</div>
      <ExternalLink size={13} className="text-zinc-600" />
    </button>)}
  </div>
}

function DorkResults({ results, openExternal, copyText, copied }: { results: DorkResult[]; openExternal: (url: string) => void; copyText: (v: string) => void; copied: string | null }) {
  if (!results.length) return <EmptyState icon={<Search size={24} />} title="No dorks generated" body="Run a search to generate Google and Bing queries for the selected signal." />
  return <div className="divide-y divide-zinc-800/70">{results.map((result, index) => <div key={`${result.query}:${index}`} className="flex items-center gap-3 px-4 py-3 hover:bg-zinc-900/60"><code className="flex-1 min-w-0 text-[11px] font-mono text-zinc-300 break-all">{result.query}</code><button title="Copy query" onClick={() => copyText(result.query)} className="p-2 text-zinc-500 hover:text-zinc-200">{copied === result.query ? <Check size={13} className="text-green-400" /> : <Copy size={13} />}</button><Button size="sm" variant="outline" className="h-7 text-[10px]" onClick={() => openExternal(result.google_url)}>Google <ExternalLink size={10} className="ml-1" /></Button><Button size="sm" variant="outline" className="h-7 text-[10px]" onClick={() => openExternal(result.bing_url)}>Bing <ExternalLink size={10} className="ml-1" /></Button></div>)}</div>
}

function ProjectResults({ results, openExternal }: { results: ProjectResult[]; openExternal: (url: string) => void }) {
  if (!results.length) return <EmptyState icon={<FolderSearch size={24} />} title="No project endpoint results" body="Select an active project with live hosts and run the scoped endpoint scan." />
  return <div className="divide-y divide-zinc-800/70">{results.map((result, index) => <button key={`${result.url}:${index}`} onClick={() => openExternal(result.url)} className="w-full text-left grid grid-cols-[70px_70px_minmax(220px,1fr)_minmax(140px,.5fr)_auto] gap-3 items-center px-4 py-3 hover:bg-zinc-900/60"><span className={cn('text-[9px] font-bold uppercase rounded border px-1.5 py-0.5 w-fit', result.severity === 'high' ? 'text-red-400 border-red-900 bg-red-950/30' : result.severity === 'medium' ? 'text-amber-400 border-amber-900 bg-amber-950/30' : 'text-zinc-500 border-zinc-700')}>{result.severity}</span><span className="font-mono text-[11px] text-zinc-400">HTTP {result.status_code}</span><span className="font-mono text-[11px] text-zinc-200 truncate">{result.url}</span><span className="text-[10px] text-zinc-500 truncate">{result.category.replace('_', ' ')}{result.signals.length ? ` · ${result.signals.join(', ')}` : ''}</span><ChevronRight size={13} className="text-zinc-600" /></button>)}</div>
}

function EmptyState({ icon, title, body }: { icon: React.ReactNode; title: string; body: string }) {
  return <div className="min-h-[310px] flex flex-col items-center justify-center text-center px-6"><div className="text-zinc-700 mb-3">{icon}</div><div className="text-sm font-medium text-zinc-300">{title}</div><div className="text-xs text-zinc-600 mt-1 max-w-md">{body}</div></div>
}
