import { useState, useCallback, useEffect, useRef } from 'react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { ScopeSelector } from '@/components/ui/scope-selector'
import { useReconStore } from '@/stores/recon-store'
import { useScannerStore } from '@/stores/scanner-store'
import { useAppStore } from '@/stores/app-store'
import { api } from '@/api/http-client'
import { toast } from '@/stores/toast-store'
import { API_BASE } from '@/lib/constants'
import { cn } from '@/lib/utils'
import {
  Radar,
  Play,
  Square,
  Globe,
  Network,
  Link,
  Loader2,
  Wifi,
  Settings2,
  Trash2,
  Zap,
  Camera,
  ExternalLink,
  Download,
  ChevronDown,
  Server,
  ShieldAlert,
  Sparkles,
  X,
  Plus,
  Route,
} from 'lucide-react'

// ─── Export helper ─────────────────────────────────────────────────────────────
function downloadText(content: string, filename: string) {
  const blob = new Blob([content], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

type ReconTab = 'subdomains' | 'live_hosts' | 'urls' | 'ports' | 'screenshots' | 'cve' | 'endpoints'

const ENDPOINT_CATEGORIES = [
  { id: 'api',       label: 'API / Swagger',   desc: 'Swagger, OpenAPI, GraphQL, REST discovery' },
  { id: 'sensitive', label: 'Sensitive Files',  desc: '.env, .git, .svn, configs, keys' },
  { id: 'backups',   label: 'Backups / Dumps',  desc: '.zip, .sql, .bak, old archives' },
  { id: 'admin',     label: 'Admin Panels',     desc: '/admin, /panel, /dashboard, /console' },
  { id: 'spring',    label: 'Spring / Actuator',desc: '/actuator endpoints — high value for Java apps' },
  { id: 'wordpress', label: 'WordPress',        desc: 'wp-admin, wp-json, xmlrpc, common WP paths' },
  { id: 'php',       label: 'PHP / Laravel',    desc: 'phpinfo, phpmyadmin, artisan, debug endpoints' },
  { id: 'devops',    label: 'DevOps / CI',      desc: 'Dockerfile, CI configs, terraform state, k8s' },
  { id: 'debug',     label: 'Debug / Metrics',  desc: 'pprof, metrics, elmah/trace.axd, dev paths' },
  { id: 'login',     label: 'Login Pages',      desc: '/login, /auth, /signin, /sso' },
]

// Bug Bounty stages with their tools
const BB_STAGES = [
  {
    id: 'asset-discovery',
    label: 'Stage 1 — Asset Discovery',
    description: 'Subdomain enumeration via passive/active DNS',
    color: 'text-blue-400',
    borderColor: 'border-blue-500/30',
    bgColor: 'bg-blue-950/20',
    tools: [
      { id: 'subfinder', label: 'Subfinder', desc: 'Passive enumeration via APIs (fast)', installed: true },
      { id: 'amass', label: 'Amass', desc: 'Deep passive + active OSINT enumeration', installed: true },
      { id: 'crtsh', label: 'crt.sh', desc: 'Certificate transparency logs — passive, no binary needed', installed: true },
      { id: 'gobuster-dns', label: 'Gobuster DNS', desc: 'Active DNS brute-force — ideal for internal/.local domains, set custom resolver for private DNS', installed: true },
      { id: 'vhost-fuzzer', label: 'Vhost Fuzzer', desc: 'Virtual host brute-force via Host header (ffuf) — finds subdomains behind wildcard DNS like .local', installed: true },
    ],
  },
  {
    id: 'live-probing',
    label: 'Stage 2 — Live Host Probing',
    description: 'Verify which subdomains are alive, get status codes, titles & tech stack',
    color: 'text-green-400',
    borderColor: 'border-green-500/30',
    bgColor: 'bg-green-950/20',
    tools: [
      { id: 'httpx', label: 'HTTPX (single)', desc: 'Probe one target URL/domain', installed: true },
      { id: 'httpx-probe-all', label: 'HTTPX (probe all)', desc: 'Probe all subdomains found in Stage 1', installed: true, special: true },
    ],
  },
  {
    id: 'url-discovery',
    label: 'Stage 3 — URL & Endpoint Discovery',
    description: 'Find historical and current endpoints, JS links, parameters',
    color: 'text-purple-400',
    borderColor: 'border-purple-500/30',
    bgColor: 'bg-purple-950/20',
    tools: [
      { id: 'waybackurls', label: 'Waybackurls', desc: 'Historical URLs from Wayback Machine', installed: true },
      { id: 'gau', label: 'GAU', desc: 'Get All URLs — Wayback + Common Crawl + OTX', installed: true },
      { id: 'katana', label: 'Katana', desc: 'Active web crawler — crawls links and forms', installed: true },
      { id: 'katana-headless', label: 'Katana Headless', desc: 'Crawl with real browser (Chromium) — discovers SPA/React/Vue routes that the standard crawler misses', installed: true },
      { id: 'linkfinder', label: 'LinkFinder', desc: 'Extracts endpoints from JS files — ideal for SPAs. Pass the JS bundle URL (e.g. /static/js/main.js)', installed: true },
    ],
  },
  {
    id: 'port-scanning',
    label: 'Stage 4 — Port & Service Scanning',
    description: 'Identify open ports and running services',
    color: 'text-orange-400',
    borderColor: 'border-orange-500/30',
    bgColor: 'bg-orange-950/20',
    tools: [
      { id: 'nmap', label: 'Nmap', desc: 'Port scan + service/version detection', installed: true },
    ],
  },
  {
    id: 'param-discovery',
    label: 'Stage 5 — Parameter Discovery',
    description: 'Find URL parameters for fuzzing and injection testing',
    color: 'text-yellow-400',
    borderColor: 'border-yellow-500/30',
    bgColor: 'bg-yellow-950/20',
    tools: [
      { id: 'paramspider', label: 'ParamSpider', desc: 'Parameters from Wayback Machine', installed: false },
      { id: 'arjun', label: 'Arjun', desc: 'HTTP parameter discovery brute-force', installed: true },
    ],
  },
]

interface ToolOptions {
  [toolId: string]: Record<string, string>
}

export function ReconPage() {
  const [activeTab, setActiveTab] = useState<ReconTab>('subdomains')
  const { globalTarget, setGlobalTarget, activeProject } = useAppStore()
  const [target, setTargetLocal] = useState(globalTarget)
  const [expandedOptions, setExpandedOptions] = useState<Set<string>>(new Set())
  const [toolOptions, setToolOptions] = useState<ToolOptions>({})
  const [liveHostPickerOpen, setLiveHostPickerOpen] = useState(false)
  const [liveHostFilter, setLiveHostFilter] = useState('')
  const liveHostPickerRef = useRef<HTMLDivElement>(null)
  const [endpointStatusFilter, setEndpointStatusFilter] = useState<string>('all')
  const [selectedEndpointCats, setSelectedEndpointCats] = useState<Set<string>>(new Set())
  const [endpointSearch, setEndpointSearch] = useState('')
  const [endpointCodeFilter, setEndpointCodeFilter] = useState('')
  const [endpointMinSize, setEndpointMinSize] = useState('')
  const [endpointMaxSize, setEndpointMaxSize] = useState('')
  const [endpointHideSizes, setEndpointHideSizes] = useState('')
  const [selectedEndpointHosts, setSelectedEndpointHosts] = useState<Set<string>>(new Set())
  const [endpointHostFilter, setEndpointHostFilter] = useState('')
  const [manualHost, setManualHost] = useState('')
  const [urlSearch, setUrlSearch] = useState('')
  const [urlCategoryFilter, setUrlCategoryFilter] = useState<'all' | 'interesting' | 'api' | 'config' | 'backup' | 'scripts' | 'media'>('all')

  // Close live host picker on outside click
  useEffect(() => {
    if (!liveHostPickerOpen) return
    const handler = (e: MouseEvent) => {
      if (liveHostPickerRef.current && !liveHostPickerRef.current.contains(e.target as Node)) {
        setLiveHostPickerOpen(false)
        setLiveHostFilter('')
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [liveHostPickerOpen])

  const setTarget = (v: string) => { setTargetLocal(v); setGlobalTarget(v) }
  const { activeScans: scannerActiveScans } = useScannerStore()
  const nucleiRunning = scannerActiveScans.has('nuclei')
  const [endpointMenuOpen, setEndpointMenuOpen] = useState(false)
  const endpointMenuRef = useRef<HTMLDivElement>(null)
  const { subdomains, urls, ports, liveHosts, endpoints, cveResult, cveRunning, setCveResult, setCveRunning, clearRecon, activeReconTools, activeReconJobIds, addLiveHosts, removeLiveHost } = useReconStore()

  // Close endpoint menu on outside click
  useEffect(() => {
    if (!endpointMenuOpen) return
    const handler = (e: MouseEvent) => {
      if (endpointMenuRef.current && !endpointMenuRef.current.contains(e.target as Node)) {
        setEndpointMenuOpen(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [endpointMenuOpen])
  const { getSessionOpts } = useAppStore()  // activeProject already from line above

  // URL classification for wayback/crawl results
  function classifyUrl(url: string): 'sensitive' | 'api' | 'config' | 'backup' | 'scripts' | 'media' | 'other' {
    const u = url.toLowerCase()
    const ext = u.split('?')[0].split('#')[0].split('.').pop() ?? ''
    if (/\.(env|bak|backup|sql|key|pem|p12|pfx|cer|der|dump|shadow|passwd|htpasswd)$/.test(u) ||
        /[?&](token|api_key|apikey|auth|secret|password|pass|pwd|key|access_token)=/i.test(url))
      return 'sensitive'
    if (/\/(api|v\d+|graphql|rest|swagger|openapi|internal|admin|dashboard|panel|console|debug)\b/.test(u))
      return 'api'
    if (/\.(zip|tar|gz|tgz|rar|7z|old|orig|copy|bk)$/.test(u))
      return 'backup'
    if (/\.(json|xml|yaml|yml|toml|config|cfg|ini|conf)$/.test(u))
      return 'config'
    if (/\.(js|php|asp|aspx|jsp|cgi|pl|py|rb)$/.test(u))
      return 'scripts'
    if (/\.(jpg|jpeg|png|gif|svg|webp|ico|woff|woff2|ttf|eot|css|mp4|mp3|pdf)$/.test(u))
      return 'media'
    return 'other'
  }

  const urlCategoryColors: Record<string, string> = {
    sensitive: 'text-red-400 bg-red-950/40 border-red-800/50',
    api:       'text-blue-400 bg-blue-950/40 border-blue-800/50',
    backup:    'text-orange-400 bg-orange-950/40 border-orange-800/50',
    config:    'text-yellow-400 bg-yellow-950/40 border-yellow-800/50',
    scripts:   'text-purple-400 bg-purple-950/40 border-purple-800/50',
    media:     'text-zinc-500 bg-zinc-900/40 border-zinc-800/30',
    other:     '',
  }

  const filteredUrls = urls.filter(u => {
    if (urlSearch && !u.url.toLowerCase().includes(urlSearch.toLowerCase())) return false
    if (urlCategoryFilter === 'all') return true
    if (urlCategoryFilter === 'interesting') return ['sensitive', 'api', 'backup', 'config'].includes(classifyUrl(u.url))
    return classifyUrl(u.url) === urlCategoryFilter
  })

  const interestingCount = urls.filter(u => ['sensitive', 'api', 'backup', 'config'].includes(classifyUrl(u.url))).length

  // Stop a running recon job
  const cancelReconTool = async (toolId: string) => {
    const jobId = activeReconJobIds[toolId]
    if (!jobId) return
    try { await api.delete(`/api/recon/jobs/${jobId}`) } catch {}
  }

  // Tool is running if WS reported it as started (source of truth)
  const isToolRunning = (toolId: string) => activeReconTools.has(toolId)

  const handleNucleiBulkScan = async () => {
    if (liveHosts.length === 0) {
      toast.error('No live hosts', 'Run HTTPX probe first to discover live hosts.')
      return
    }
    try {
      const targets = liveHosts.map(h => h.url).filter(Boolean)
      await api.post('/api/scanner/nuclei-bulk', {
        targets,
        project_id: activeProject ?? '',
        options: getSessionOpts(),
      })
      toast.success('Nuclei scan started', `Running default templates on ${targets.length} live hosts. Results appear in Scanner page.`)
    } catch (err) {
      toast.error('Failed to start nuclei scan', err)
    }
  }

  const handleTakeoverScan = async () => {
    const allTargets = [
      ...liveHosts.map(h => h.url),
      ...subdomains.map(s => s.subdomain),
    ].filter(Boolean)
    if (allTargets.length === 0) {
      toast.error('No targets', 'Run subdomain enumeration or HTTPX first.')
      return
    }
    try {
      await api.post('/api/scanner/nuclei-bulk', {
        targets: allTargets,
        project_id: activeProject ?? '',
        options: { ...getSessionOpts(), scan_type: 'takeover' },
      })
      toast.success('Takeover scan started', `Checking ${allTargets.length} targets for CNAME takeovers. Results appear in Scanner page.`)
    } catch (err) {
      toast.error('Failed to start takeover scan', err)
    }
  }

  const handleAddLiveHost = async () => {
    let v = manualHost.trim()
    if (!v) return
    if (!/^https?:\/\//i.test(v)) v = 'https://' + v
    let host = v
    try { host = new URL(v).host } catch {}
    addLiveHosts([{ url: v, host, status_code: null, title: '', technologies: [], content_type: '', ip: '' }])
    setManualHost('')
    setActiveTab('live_hosts')
    try {
      await api.post('/api/recon/live-host', { url: v, project_id: activeProject ?? '' })
      toast.success('Live host added', host)
    } catch (err) {
      toast.error('Saved locally but not persisted', err)
    }
  }

  const handleCheckEndpoints = async (categories: string[]) => {
    // Use the chosen host subset, or all live hosts when none are explicitly selected
    const allUrls = liveHosts.map(h => h.url).filter(Boolean)
    const targets = selectedEndpointHosts.size > 0
      ? allUrls.filter(u => selectedEndpointHosts.has(u))
      : allUrls
    if (targets.length === 0) {
      toast.error('No target hosts', selectedEndpointHosts.size > 0 ? 'No selected host is live.' : 'Run HTTPX probe first.')
      return
    }
    setEndpointMenuOpen(false)
    setActiveTab('endpoints')
    try {
      const res = await api.post<{ url_count: number }>('/api/recon/check-endpoints', {
        targets,
        categories,
        project_id: activeProject ?? '',
      })
      toast.success('Endpoint scan started', `Checking ~${res.url_count} URLs across ${targets.length} hosts`)
    } catch (err) {
      toast.error('Failed to start endpoint scan', err)
    }
  }

  const handleCveCorrelate = async () => {
    const allTech = [...new Set(liveHosts.flatMap(h => h.technologies ?? []))]
    if (allTech.length === 0) return
    setCveRunning(true)
    setCveResult(null)
    setActiveTab('cve')
    try {
      const res = await api.post<any>('/api/cve/correlate', { technologies: allTech })
      setCveResult(res)
    } catch (e) {
      setCveResult({ error: String(e) })
    } finally {
      setCveRunning(false)
    }
  }

  const handleRunTool = async (toolId: string) => {
    if (!target.trim()) return
    try {
      const opts: Record<string, string> = { ...(toolOptions[toolId] || {}), ...getSessionOpts() }

      // crt.sh — direct API call, no binary
      if (toolId === 'crtsh') {
        await api.post('/api/recon/crtsh', { target: target.trim(), project_id: activeProject ?? '' })
        return
      }

      // Waybackurls CDX mode — call CDX API directly instead of binary
      if (toolId === 'waybackurls' && opts.cdx_mode === 'true') {
        const statusRaw = opts.cdx_status || 'all'
        const statusCodes = statusRaw === 'all' ? [] : statusRaw.split(',').map((s: string) => s.trim()).filter(Boolean)
        const methodRaw = opts.cdx_method || 'all'
        const methods = methodRaw === 'all' ? [] : [methodRaw]
        const extRaw = opts.cdx_extensions || ''
        const extensions = extRaw ? extRaw.split(',').map((s: string) => s.trim()).filter(Boolean) : []
        await api.post('/api/recon/wayback-cdx', {
          target: target.trim(),
          status_codes: statusCodes,
          methods,
          extensions,
          limit: parseInt(opts.cdx_limit || '500', 10),
          project_id: activeProject ?? '',
        })
        return
      }

      await api.post(`/api/recon/${toolId}`, { target: target.trim(), options: opts, project_id: activeProject ?? '' })
    } catch (err) {
      toast.error(`Failed to start ${toolId}`, err)
    }
  }

  const handleProbeAll = async () => {
    if (subdomains.length === 0) return
    try {
      const targets = subdomains.map(s => s.subdomain)
      await api.post('/api/recon/httpx-probe', { targets, options: getSessionOpts(), project_id: activeProject ?? '' })
    } catch (err) {
      toast.error('Failed to probe subdomains', err)
    }
  }

  const handleFullRecon = async () => {
    if (!target.trim()) return
    try {
      await api.post('/api/recon/full', { target: target.trim(), project_id: activeProject ?? '' })
    } catch (err) {
      toast.error('Failed to start full recon', err)
    }
  }

  const toggleOptions = (toolId: string) => {
    setExpandedOptions(prev => {
      const n = new Set(prev)
      n.has(toolId) ? n.delete(toolId) : n.add(toolId)
      return n
    })
  }

  const setOption = (toolId: string, key: string, value: string) => {
    setToolOptions(prev => ({ ...prev, [toolId]: { ...(prev[toolId] || {}), [key]: value } }))
  }

  const [expandedPort, setExpandedPort] = useState<string | null>(null)
  const [screenshotLoading, setScreenshotLoading] = useState(false)
  const [lightboxSrc, setLightboxSrc] = useState<string | null>(null)
  const [lightboxUrl, setLightboxUrl] = useState<string | null>(null)
  const [hostsAiAnalysis, setHostsAiAnalysis] = useState<string | null>(null)
  const [hostsAiRunning, setHostsAiRunning] = useState(false)
  const { screenshots, screenshotRunning, screenshotProgress } = useReconStore()
  const probingAll = isToolRunning('httpx-probe')

  const handleScreenshotAll = async () => {
    if (liveHosts.length === 0) return
    setScreenshotLoading(true)
    try {
      const urls = liveHosts.map(h => h.url).filter(Boolean)
      await api.post('/api/recon/screenshots-bulk', { urls, project_id: activeProject ?? '' })
    } catch (err) {
      console.error('Failed to start bulk screenshots:', err)
    } finally {
      setScreenshotLoading(false)
    }
  }

  const handleAnalyzeHostsAI = async () => {
    if (liveHosts.length === 0) return
    setHostsAiRunning(true)
    setHostsAiAnalysis(null)
    try {
      const res = await api.post<{ response: string }>('/api/copilot/analyze-hosts', {
        live_hosts: liveHosts,
        subdomains,
        ports,
      })
      setHostsAiAnalysis(res.response)
    } catch (err) {
      setHostsAiAnalysis('AI analysis failed.')
    } finally {
      setHostsAiRunning(false)
    }
  }

  const tabs = [
    { id: 'subdomains' as ReconTab, icon: Globe, label: 'Subdomains', count: subdomains.length, color: 'text-blue-400' },
    { id: 'live_hosts' as ReconTab, icon: Wifi, label: 'Live Hosts', count: liveHosts.length, color: 'text-green-400' },
    { id: 'urls' as ReconTab, icon: Link, label: 'URLs', count: urls.length, color: 'text-purple-400' },
    { id: 'ports' as ReconTab, icon: Network, label: 'Ports', count: ports.length, color: 'text-orange-400' },
    { id: 'screenshots' as ReconTab, icon: Camera, label: 'Screenshots', count: screenshots.length, color: 'text-pink-400' },
    { id: 'cve' as ReconTab, icon: ShieldAlert, label: 'CVE', count: (cveResult && 'results' in cveResult ? cveResult.results.length : 0), color: 'text-red-400' },
    { id: 'endpoints' as ReconTab, icon: Route, label: 'Endpoints', count: endpoints.length, color: 'text-cyan-400' },
  ]

  return (
    <WorkspaceShell title="Recon" subtitle="Bug Bounty reconnaissance pipeline — stages 1 to 5">
      <div className="flex gap-4 h-full min-h-0">

        {/* LEFT PANEL — Stages & Tools */}
        <div className="w-72 shrink-0 flex flex-col gap-3 overflow-y-auto pr-1">

          {/* Target input */}
          <div className="space-y-2">
            <ScopeSelector onSelect={setTarget} selectedTarget={target} />
            <div className="flex gap-2">
              <Input
                placeholder="domain.com"
                className="flex-1 bg-zinc-900 text-sm"
                value={target}
                onChange={e => setTarget(e.target.value)}
              />
              <Button
                size="sm"
                onClick={handleFullRecon}
                disabled={!target.trim() || isToolRunning('full_recon')}
                title="Full automated recon pipeline"
              >
                {isToolRunning('full_recon') ? <Loader2 size={14} className="animate-spin" /> : <Radar size={14} />}
              </Button>
            </div>
            {target && (
              <div className="text-[10px] text-zinc-600 font-mono truncate">Target: {target}</div>
            )}

            {/* Live host quick-select — visible once httpx finds hosts */}
            {liveHosts.length > 0 && (
              <div className="relative" ref={liveHostPickerRef}>
                <button
                  onClick={() => setLiveHostPickerOpen(v => !v)}
                  className="w-full flex items-center justify-between gap-1.5 px-2.5 py-1.5 rounded-lg border border-green-700/50 bg-green-950/20 text-xs text-green-400 hover:border-green-600 hover:bg-green-950/30 transition-colors"
                >
                  <div className="flex items-center gap-1.5">
                    <Server size={11} />
                    <span>{liveHosts.length} live hosts</span>
                    {target && liveHosts.some(h => h.url === target) && (
                      <span className="text-[9px] text-green-600">· selected</span>
                    )}
                  </div>
                  <ChevronDown size={11} className={cn('transition-transform', liveHostPickerOpen && 'rotate-180')} />
                </button>

                {liveHostPickerOpen && (
                  <div className="absolute top-full left-0 right-0 mt-1 z-50 rounded-lg border border-zinc-700 bg-zinc-900 shadow-xl shadow-black/50 overflow-hidden">
                    <div className="p-1.5 border-b border-zinc-800">
                      <input
                        autoFocus
                        type="text"
                        placeholder="Filter hosts..."
                        value={liveHostFilter}
                        onChange={e => setLiveHostFilter(e.target.value)}
                        className="w-full text-[10px] bg-zinc-950 border border-zinc-800 rounded px-2 py-1 text-zinc-300 placeholder:text-zinc-700 focus:outline-none"
                      />
                    </div>
                    <div className="max-h-48 overflow-y-auto">
                      {liveHosts
                        .filter(h => !liveHostFilter || h.url.toLowerCase().includes(liveHostFilter.toLowerCase()))
                        .map((h, i) => (
                          <button
                            key={i}
                            onClick={() => { setTarget(h.url); setLiveHostPickerOpen(false); setLiveHostFilter('') }}
                            className={cn(
                              'w-full flex items-center gap-2 px-2.5 py-1.5 text-left hover:bg-zinc-800 transition-colors',
                              target === h.url && 'bg-zinc-800'
                            )}
                          >
                            <span className={cn('text-[10px] font-mono font-bold shrink-0',
                              h.status_code && h.status_code < 300 ? 'text-green-400' :
                              h.status_code && h.status_code < 400 ? 'text-yellow-400' : 'text-orange-400'
                            )}>
                              {h.status_code}
                            </span>
                            <span className="text-[10px] text-zinc-300 font-mono truncate flex-1">{h.url}</span>
                            {h.title && (
                              <span className="text-[9px] text-zinc-600 truncate max-w-[80px] shrink-0">{h.title}</span>
                            )}
                          </button>
                        ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Stages */}
          {BB_STAGES.map(stage => (
            <div key={stage.id} className={cn("rounded-lg border p-3 space-y-2", stage.borderColor, stage.bgColor)}>
              <div>
                <div className={cn("text-xs font-semibold", stage.color)}>{stage.label}</div>
                <div className="text-[10px] text-zinc-500 mt-0.5">{stage.description}</div>
              </div>

              <div className="space-y-1.5">
                {stage.tools.map(tool => {
                  const isRunning = isToolRunning(tool.id) || (tool.id === 'httpx-probe-all' && probingAll)
                  const hasOpts = expandedOptions.has(tool.id)
                  const opts = toolOptions[tool.id] || {}
                  const isSpecial = (tool as any).special

                  return (
                    <div key={tool.id} className="space-y-1">
                      <div className="flex items-center gap-1">
                        {/* Stop button when running */}
                        {isRunning && (
                          <button
                            onClick={() => cancelReconTool(isSpecial ? 'httpx-probe' : tool.id)}
                            className="p-1 rounded border border-red-700 text-red-400 hover:bg-red-950/30 transition-colors"
                            title="Stop"
                          >
                            <Square size={10} className="fill-current" />
                          </button>
                        )}
                        {/* Run button */}
                        <button
                          disabled={
                            isRunning ||
                            (!isSpecial && !target.trim()) ||
                            (isSpecial && subdomains.length === 0) ||
                            !tool.installed
                          }
                          onClick={() => isSpecial ? handleProbeAll() : handleRunTool(tool.id)}
                          className={cn(
                            "flex items-center gap-1.5 flex-1 px-2 py-1 rounded text-xs font-medium transition-colors",
                            "border text-left",
                            !tool.installed
                              ? "border-zinc-800 text-zinc-700 cursor-not-allowed"
                              : isRunning
                                ? "border-zinc-600 bg-zinc-800 text-zinc-300"
                                : "border-zinc-700 bg-zinc-900 text-zinc-300 hover:border-zinc-500 hover:bg-zinc-800"
                          )}
                        >
                          {isRunning ? (
                            <Loader2 size={11} className="animate-spin shrink-0" />
                          ) : (
                            <Play size={11} className="shrink-0" />
                          )}
                          <span className="truncate">{tool.label}</span>
                          {!tool.installed && (
                            <span className="ml-auto text-[9px] text-zinc-700 shrink-0">not installed</span>
                          )}
                          {isSpecial && subdomains.length > 0 && (
                            <span className="ml-auto text-[9px] text-zinc-500 shrink-0">{subdomains.length}</span>
                          )}
                        </button>

                        {/* Options toggle (only for tools that have options) */}
                        {tool.installed && !isSpecial && (
                          <button
                            onClick={() => toggleOptions(tool.id)}
                            className="p-1 rounded border border-zinc-800 text-zinc-600 hover:text-zinc-400 hover:border-zinc-600 transition-colors"
                          >
                            <Settings2 size={10} />
                          </button>
                        )}
                      </div>

                      {/* Tool description */}
                      <div className="text-[10px] text-zinc-600 pl-1">{tool.desc}</div>

                      {/* Options panel */}
                      {hasOpts && tool.installed && (
                        <div className="pl-1 space-y-1 border-l border-zinc-800 ml-1">
                          {tool.id === 'nmap' && (
                            <>
                              <OptionInput label="Ports" placeholder="-p 80,443,8080 or -p-" value={opts.ports || ''} onChange={v => setOption(tool.id, 'ports', v)} />
                              <OptionInput label="Flags" placeholder="-sV -sC -A" value={opts.flags || ''} onChange={v => setOption(tool.id, 'flags', v)} />
                            </>
                          )}
                          {tool.id === 'subfinder' && (
                            <OptionInput label="Sources" placeholder="shodan,virustotal" value={opts.sources || ''} onChange={v => setOption(tool.id, 'sources', v)} />
                          )}
                          {tool.id === 'waybackurls' && (() => {
                            const cdxMode = opts.cdx_mode === 'true'
                            return (
                              <div className="space-y-2 pt-1">
                                {/* CDX mode toggle */}
                                <label className="flex items-center gap-2 cursor-pointer">
                                  <input type="checkbox" checked={cdxMode}
                                    onChange={e => setOption(tool.id, 'cdx_mode', e.target.checked ? 'true' : '')}
                                    className="w-3 h-3 accent-cyan-500" />
                                  <span className="text-[10px] text-zinc-400 font-medium">CDX API mode</span>
                                  <span className="text-[9px] text-zinc-600">— faster, no binary, deduplicated</span>
                                </label>
                                {cdxMode && (
                                  <div className="space-y-2 border-l border-zinc-700 pl-2">
                                    {/* Status codes */}
                                    <div>
                                      <div className="text-[9px] text-zinc-500 mb-1">Status</div>
                                      <div className="flex gap-1 flex-wrap">
                                        {[
                                          { v: '200', label: '200 only' },
                                          { v: '200,301,302', label: '2xx+3xx' },
                                          { v: 'all', label: 'All' },
                                        ].map(o => (
                                          <button key={o.v}
                                            onClick={() => setOption(tool.id, 'cdx_status', o.v)}
                                            className={cn('px-2 py-0.5 rounded text-[9px] border transition-colors',
                                              (opts.cdx_status || 'all') === o.v
                                                ? 'bg-cyan-900/50 border-cyan-700 text-cyan-300'
                                                : 'bg-zinc-900 border-zinc-700 text-zinc-400 hover:border-zinc-500'
                                            )}
                                          >{o.label}</button>
                                        ))}
                                      </div>
                                    </div>
                                    {/* Methods */}
                                    <div>
                                      <div className="text-[9px] text-zinc-500 mb-1">Method</div>
                                      <div className="flex gap-1">
                                        {['all', 'GET', 'POST'].map(m => (
                                          <button key={m}
                                            onClick={() => setOption(tool.id, 'cdx_method', m)}
                                            className={cn('px-2 py-0.5 rounded text-[9px] border transition-colors',
                                              (opts.cdx_method || 'all') === m
                                                ? 'bg-cyan-900/50 border-cyan-700 text-cyan-300'
                                                : 'bg-zinc-900 border-zinc-700 text-zinc-400 hover:border-zinc-500'
                                            )}
                                          >{m}</button>
                                        ))}
                                      </div>
                                    </div>
                                    {/* Extension presets */}
                                    <div>
                                      <div className="text-[9px] text-zinc-500 mb-1">Extension filter</div>
                                      <div className="flex gap-1 flex-wrap">
                                        {[
                                          { label: 'All', v: '' },
                                          { label: 'Sensitive', v: '.env,.bak,.backup,.sql,.key,.pem,.dump,.shadow,.htpasswd,.db' },
                                          { label: 'Config', v: '.json,.xml,.yaml,.yml,.toml,.config,.cfg,.ini,.conf' },
                                          { label: 'Scripts', v: '.js,.php,.asp,.aspx,.jsp' },
                                        ].map(o => (
                                          <button key={o.label}
                                            onClick={() => setOption(tool.id, 'cdx_extensions', o.v)}
                                            className={cn('px-2 py-0.5 rounded text-[9px] border transition-colors',
                                              (opts.cdx_extensions ?? '') === o.v
                                                ? 'bg-cyan-900/50 border-cyan-700 text-cyan-300'
                                                : 'bg-zinc-900 border-zinc-700 text-zinc-400 hover:border-zinc-500'
                                            )}
                                          >{o.label}</button>
                                        ))}
                                      </div>
                                    </div>
                                    {/* Limit */}
                                    <div>
                                      <div className="text-[9px] text-zinc-500 mb-1">Limit</div>
                                      <div className="flex gap-1">
                                        {['200', '500', '1000', '5000', '20000'].map(l => (
                                          <button key={l}
                                            onClick={() => setOption(tool.id, 'cdx_limit', l)}
                                            className={cn('px-2 py-0.5 rounded text-[9px] border transition-colors',
                                              (opts.cdx_limit || '500') === l
                                                ? 'bg-cyan-900/50 border-cyan-700 text-cyan-300'
                                                : 'bg-zinc-900 border-zinc-700 text-zinc-400 hover:border-zinc-500'
                                            )}
                                          >{l}</button>
                                        ))}
                                      </div>
                                    </div>
                                  </div>
                                )}
                              </div>
                            )
                          })()}
                          {tool.id === 'amass' && (
                            <label className="flex items-center gap-2 cursor-pointer pt-1">
                              <input type="checkbox"
                                checked={opts.active === 'true'}
                                onChange={e => setOption(tool.id, 'active', e.target.checked ? 'true' : '')}
                                className="w-3 h-3 accent-blue-500"
                              />
                              <span className="text-[10px] text-zinc-500">Active brute (-active -brute) — finds wildcard-hidden hosts, slower &amp; noisier</span>
                            </label>
                          )}
                          {tool.id === 'gobuster-dns' && (
                            <>
                              <OptionInput label="Resolver" placeholder="192.168.1.1 (internal DNS server)" value={opts.resolver || ''} onChange={v => setOption(tool.id, 'resolver', v)} />
                              <OptionInput label="Wordlist" placeholder="(default: subdomains-top1m-5000)" value={opts.wordlist || ''} onChange={v => setOption(tool.id, 'wordlist', v)} />
                              <OptionInput label="Threads" placeholder="50" value={opts.threads || ''} onChange={v => setOption(tool.id, 'threads', v)} />
                              <div className="text-[9px] text-zinc-600 pt-0.5">
                                Set Resolver to the internal DNS IP when targeting .local or private domains. Leave blank for public.
                              </div>
                            </>
                          )}
                          {tool.id === 'vhost-fuzzer' && (
                            <>
                              <OptionInput label="Port" placeholder="80" value={opts.port || ''} onChange={v => setOption(tool.id, 'port', v)} />
                              <OptionInput label="Wordlist" placeholder="(default: subdomains-top1m-5000)" value={opts.wordlist || ''} onChange={v => setOption(tool.id, 'wordlist', v)} />
                              <OptionInput label="Threads" placeholder="50" value={opts.threads || ''} onChange={v => setOption(tool.id, 'threads', v)} />
                              <div className="text-[9px] text-zinc-600 pt-0.5">
                                Auto-detects baseline response size and filters it. Use Port 443 for HTTPS targets.
                                Results go to Subdomains tab with HTTP status code.
                              </div>
                            </>
                          )}
                          {tool.id === 'httpx' && (
                            <OptionInput label="Threads" placeholder="50" value={opts.threads || ''} onChange={v => setOption(tool.id, 'threads', v)} />
                          )}
                          {(tool.id === 'paramspider' || tool.id === 'arjun') && (
                            <OptionInput label="Method" placeholder="GET" value={opts.method || ''} onChange={v => setOption(tool.id, 'method', v)} />
                          )}
                          {(tool.id === 'katana' || tool.id === 'katana-headless') && (
                            <>
                              <OptionInput label="Depth" placeholder="3" value={opts.depth || ''} onChange={v => setOption(tool.id, 'depth', v)} />
                              <OptionInput label="Scope" placeholder="domain.com (restrict crawl)" value={opts.scope || ''} onChange={v => setOption(tool.id, 'scope', v)} />
                            </>
                          )}
                          {tool.id === 'linkfinder' && (
                            <>
                              <div className="text-[9px] text-zinc-600 pt-0.5">
                                Target: JS bundle URL<br/>
                                <span className="text-zinc-500">e.g. https://site.com/static/js/main.abc123.js</span><br/>
                                or full domain with -d mode
                              </div>
                              <label className="flex items-center gap-2 cursor-pointer pt-1">
                                <input type="checkbox"
                                  checked={opts.domain_mode === 'true'}
                                  onChange={e => setOption(tool.id, 'domain_mode', e.target.checked ? 'true' : '')}
                                  className="w-3 h-3 accent-purple-500"
                                />
                                <span className="text-[10px] text-zinc-500">Domain mode (-d) — scans all JS files on the site</span>
                              </label>
                            </>
                          )}
                          <OptionInput label="Extra flags" placeholder="-timeout 30 -rl 50" value={opts.extra_args || ''} onChange={v => setOption(tool.id, 'extra_args', v)} />
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          ))}

          {/* Clear results */}
          <Button
            variant="ghost"
            size="sm"
            className="text-zinc-600 hover:text-red-400 text-xs"
            onClick={async () => {
              clearRecon()
              try { await api.delete(`/api/recon/results?project_id=${activeProject ?? ''}`) } catch {}
            }}
          >
            <Trash2 size={12} className="mr-1" /> Clear all
          </Button>
        </div>

        {/* RIGHT PANEL — Results */}
        <div className="flex-1 flex flex-col gap-3 min-h-0 min-w-0">

          {/* Tabs + Export button */}
          <div className="flex items-center gap-2">
            <div className="flex gap-1 bg-zinc-900 rounded-lg p-1">
              {tabs.map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={cn(
                    'flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-colors',
                    activeTab === tab.id
                      ? 'bg-zinc-700 text-zinc-100'
                      : 'text-zinc-400 hover:text-zinc-200'
                  )}
                >
                  <tab.icon size={12} className={activeTab === tab.id ? tab.color : ''} />
                  {tab.label}
                  {tab.count > 0 && (
                    <Badge variant="secondary" className="h-4 px-1 text-[10px]">{tab.count}</Badge>
                  )}
                </button>
              ))}
            </div>

            {/* Import button for subdomains */}
            {(activeTab === 'subdomains' || activeTab === 'live_hosts' || activeTab === 'urls') && (
              <label
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-zinc-700 text-zinc-400 hover:text-zinc-200 hover:border-zinc-600 text-[10px] font-medium transition-colors cursor-pointer"
                title="Import from .txt (one per line)"
              >
                <input type="file" accept=".txt" className="hidden" onChange={async e => {
                  const file = e.target.files?.[0]
                  if (!file) return
                  const text = await file.text()
                  const lines = text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'))
                  if (activeTab === 'subdomains') {
                    const { addSubdomains } = useReconStore.getState()
                    addSubdomains(lines.map(s => ({ subdomain: s, source: 'import', ip: null, status_code: null })))
                  } else if (activeTab === 'live_hosts') {
                    const { addLiveHosts } = useReconStore.getState()
                    addLiveHosts(lines.map(u => {
                      let host = u
                      try { host = new URL(u).host } catch {}
                      return { url: u, host, status_code: null, title: '', technologies: [], content_type: '', ip: '' }
                    }))
                  } else if (activeTab === 'urls') {
                    const { addUrls } = useReconStore.getState()
                    addUrls(lines.map(u => ({ url: u, source: 'import', status_code: null, content_type: null })))
                  }
                  e.target.value = ''
                }} />
                <Download size={11} className="rotate-180" /> Import
              </label>
            )}

            {/* Export button — only when there's data */}
            {(activeTab === 'subdomains' && subdomains.length > 0) ||
             (activeTab === 'live_hosts' && liveHosts.length > 0) ||
             (activeTab === 'urls' && urls.length > 0) ||
             (activeTab === 'ports' && ports.length > 0) ? (
              <button
                onClick={() => {
                  if (activeTab === 'subdomains') {
                    downloadText(subdomains.map(s => s.subdomain).join('\n'), 'subdomains.txt')
                  } else if (activeTab === 'live_hosts') {
                    const lines = liveHosts.map(h =>
                      `${h.url}\t${h.status_code ?? ''}\t${h.title ?? ''}\t${(h.technologies ?? []).join(',')}`
                    )
                    downloadText(['URL\tStatus\tTitle\tTechnologies', ...lines].join('\n'), 'live_hosts.txt')
                  } else if (activeTab === 'urls') {
                    downloadText(urls.map(u => u.url).join('\n'), 'urls.txt')
                  } else if (activeTab === 'ports') {
                    const lines = ports.map(p => `${p.ip}\t${p.port}\t${p.proto ?? 'tcp'}\t${p.service ?? ''}\t${p.version ?? ''}`)
                    downloadText(['IP\tPort\tProto\tService\tVersion', ...lines].join('\n'), 'ports.txt')
                  }
                }}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-zinc-700 text-zinc-400 hover:text-zinc-200 hover:border-zinc-600 text-[10px] font-medium transition-colors"
                title="Export to text file"
              >
                <Download size={11} /> Export
              </button>
            ) : null}
          </div>

          {/* Live Hosts — manual add */}
          {activeTab === 'live_hosts' && (
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={manualHost}
                onChange={e => setManualHost(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') handleAddLiveHost() }}
                placeholder="Add a host manually, e.g. api-ar.redremax.com"
                className="flex-1 max-w-md text-xs bg-zinc-900 border border-zinc-800 rounded px-2.5 py-1.5 text-zinc-300 placeholder:text-zinc-700 focus:outline-none focus:border-zinc-600 font-mono"
              />
              <Button
                size="sm"
                variant="outline"
                className="border-green-700 text-green-400 hover:bg-green-950/40 text-xs"
                onClick={handleAddLiveHost}
                disabled={!manualHost.trim()}
              >
                <Plus size={12} className="mr-1.5" />Add host
              </Button>
            </div>
          )}

          {/* Live Hosts — action bar */}
          {activeTab === 'live_hosts' && liveHosts.length > 0 && (
            <div className="flex items-center gap-2 flex-wrap">
              <Button
                size="sm"
                variant="outline"
                className="border-yellow-700 text-yellow-400 hover:bg-yellow-950/40 text-xs"
                onClick={handleNucleiBulkScan}
                disabled={nucleiRunning}
              >
                {nucleiRunning
                  ? <><Loader2 size={12} className="animate-spin mr-1.5" />Starting...</>
                  : <><Zap size={12} className="mr-1.5" />Scan all with Nuclei ({liveHosts.length} hosts)</>}
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="border-pink-700 text-pink-400 hover:bg-pink-950/40 text-xs"
                onClick={handleScreenshotAll}
                disabled={screenshotLoading || screenshotRunning}
              >
                {(screenshotLoading || screenshotRunning)
                  ? <><Loader2 size={12} className="animate-spin mr-1.5" />
                    {screenshotRunning && screenshotProgress.total > 0
                      ? `${screenshotProgress.done}/${screenshotProgress.total}`
                      : 'Starting...'}</>
                  : <><Camera size={12} className="mr-1.5" />Screenshot all ({liveHosts.length})</>}
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="border-red-700 text-red-400 hover:bg-red-950/40 text-xs"
                onClick={handleCveCorrelate}
                disabled={cveRunning || liveHosts.every(h => !h.technologies?.length)}
              >
                {cveRunning
                  ? <><Loader2 size={12} className="animate-spin mr-1.5" />Correlating...</>
                  : <><ShieldAlert size={12} className="mr-1.5" />Correlate CVEs</>}
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="border-violet-700 text-violet-400 hover:bg-violet-950/40 text-xs"
                onClick={handleAnalyzeHostsAI}
                disabled={hostsAiRunning || liveHosts.length === 0}
              >
                {hostsAiRunning
                  ? <><Loader2 size={12} className="animate-spin mr-1.5" />Analyzing...</>
                  : <><Sparkles size={12} className="mr-1.5" />AI Analysis</>}
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="border-purple-700 text-purple-400 hover:bg-purple-950/40 text-xs"
                onClick={handleTakeoverScan}
                disabled={nucleiRunning || (liveHosts.length === 0 && subdomains.length === 0)}
              >
                {nucleiRunning
                  ? <><Loader2 size={12} className="animate-spin mr-1.5" />Scanning...</>
                  : <><ShieldAlert size={12} className="mr-1.5" />Check Takeovers ({liveHosts.length + subdomains.length})</>}
              </Button>

              {/* Endpoint discovery dropdown — hosts + categories in one menu */}
              <div className="relative" ref={endpointMenuRef}>
                <Button
                  size="sm"
                  variant="outline"
                  className="border-cyan-700 text-cyan-400 hover:bg-cyan-950/40 text-xs"
                  onClick={() => setEndpointMenuOpen(v => !v)}
                  disabled={isToolRunning('endpoint_check') || liveHosts.length === 0}
                >
                  {isToolRunning('endpoint_check')
                    ? <><Loader2 size={12} className="animate-spin mr-1.5" />Scanning endpoints...</>
                    : <><Route size={12} className="mr-1.5" />Check Endpoints <ChevronDown size={10} className="ml-1" /></>}
                </Button>
                {endpointMenuOpen && (
                  <div className="absolute top-full left-0 mt-1 z-50 w-[760px] max-w-[calc(100vw-2rem)] rounded-lg border border-zinc-700 bg-zinc-900 shadow-xl shadow-black/50">
                    <div className="grid grid-cols-2 divide-x divide-zinc-800">
                      {/* Target hosts */}
                      <div className="flex flex-col min-h-0">
                        <div className="flex items-center justify-between px-3.5 py-3 border-b border-zinc-800">
                          <p className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wide">
                            Target hosts ({selectedEndpointHosts.size > 0 ? selectedEndpointHosts.size : liveHosts.length})
                          </p>
                          <div className="flex gap-1.5">
                            <button
                              onClick={() => setSelectedEndpointHosts(new Set())}
                              className="text-[10px] px-2 py-1 rounded border border-zinc-700 text-zinc-400 hover:border-zinc-500 transition-colors"
                            >All</button>
                            <button
                              onClick={() => setSelectedEndpointHosts(new Set(['__none__']))}
                              className="text-[10px] px-2 py-1 rounded border border-zinc-700 text-zinc-400 hover:border-zinc-500 transition-colors"
                            >None</button>
                          </div>
                        </div>
                        <div className="px-2 py-2 border-b border-zinc-800">
                          <input
                            type="text" placeholder="Filter hosts..."
                            value={endpointHostFilter}
                            onChange={e => setEndpointHostFilter(e.target.value)}
                            className="w-full text-[11px] bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-zinc-300 placeholder:text-zinc-700 focus:outline-none"
                          />
                        </div>
                        <div className="max-h-[22rem] overflow-auto flex-1 p-1">
                          {liveHosts
                            .filter(h => !endpointHostFilter || h.url.toLowerCase().includes(endpointHostFilter.toLowerCase()))
                            .map((h, i) => {
                              // empty selection = all hosts implicitly checked
                              const checked = selectedEndpointHosts.size === 0 || selectedEndpointHosts.has(h.url)
                              return (
                                <label key={i} className="w-full flex items-center gap-2.5 px-2.5 py-2 hover:bg-zinc-800 transition-colors cursor-pointer rounded">
                                  <input
                                    type="checkbox"
                                    checked={checked}
                                    onChange={() => setSelectedEndpointHosts(prev => {
                                      // Materialize implicit "all" (or the "none" sentinel) into a concrete set before toggling
                                      const base = prev.size === 0
                                        ? new Set(liveHosts.map(x => x.url))
                                        : new Set([...prev].filter(u => u !== '__none__'))
                                      if (base.has(h.url)) base.delete(h.url); else base.add(h.url)
                                      return base.size === 0 ? new Set(['__none__']) : base
                                    })}
                                    className="shrink-0 accent-cyan-500 w-3.5 h-3.5"
                                  />
                                  <span className={cn('text-[11px] font-mono font-bold shrink-0',
                                    h.status_code && h.status_code < 300 ? 'text-green-400' :
                                    h.status_code && h.status_code < 400 ? 'text-yellow-400' : 'text-orange-400'
                                  )}>{h.status_code ?? '?'}</span>
                                  <span className="text-[11px] text-zinc-300 font-mono truncate flex-1">{h.url}</span>
                                </label>
                              )
                            })}
                        </div>
                      </div>

                      {/* Categories */}
                      <div className="flex flex-col min-h-0">
                        <div className="flex items-center justify-between px-3.5 py-3 border-b border-zinc-800">
                          <p className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wide">
                            Wordlist categories ({selectedEndpointCats.size})
                          </p>
                          <div className="flex gap-1.5">
                            <button
                              onClick={() => setSelectedEndpointCats(new Set(ENDPOINT_CATEGORIES.map(c => c.id)))}
                              className="text-[10px] px-2 py-1 rounded border border-zinc-700 text-zinc-400 hover:border-zinc-500 transition-colors"
                            >All</button>
                            <button
                              onClick={() => setSelectedEndpointCats(new Set())}
                              className="text-[10px] px-2 py-1 rounded border border-zinc-700 text-zinc-400 hover:border-zinc-500 transition-colors"
                            >None</button>
                          </div>
                        </div>
                        <div className="max-h-[22rem] overflow-auto flex-1 p-1">
                          {ENDPOINT_CATEGORIES.map(cat => {
                            const checked = selectedEndpointCats.has(cat.id)
                            return (
                              <label
                                key={cat.id}
                                className="w-full flex items-start gap-2.5 px-2.5 py-2.5 hover:bg-zinc-800 transition-colors text-left cursor-pointer rounded"
                              >
                                <input
                                  type="checkbox"
                                  checked={checked}
                                  onChange={() => setSelectedEndpointCats(prev => {
                                    const next = new Set(prev)
                                    if (next.has(cat.id)) next.delete(cat.id); else next.add(cat.id)
                                    return next
                                  })}
                                  className="mt-0.5 shrink-0 accent-cyan-500 w-3.5 h-3.5"
                                />
                                <div className="min-w-0">
                                  <div className="text-[13px] font-medium text-zinc-200">{cat.label}</div>
                                  <div className="text-[11px] text-zinc-500 leading-snug mt-0.5">{cat.desc}</div>
                                </div>
                              </label>
                            )
                          })}
                        </div>
                      </div>
                    </div>
                    {/* Scan actions */}
                    <div className="flex items-center gap-2 px-3.5 py-3 border-t border-zinc-800">
                      <button
                        onClick={() => handleCheckEndpoints([...selectedEndpointCats])}
                        disabled={selectedEndpointCats.size === 0}
                        className="flex-1 text-[11px] font-semibold px-3 py-2 rounded border border-cyan-700 text-cyan-400 hover:bg-cyan-950/40 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                      >
                        Scan {selectedEndpointCats.size} cats → {selectedEndpointHosts.has('__none__') ? 0 : selectedEndpointHosts.size > 0 ? selectedEndpointHosts.size : liveHosts.length} hosts
                      </button>
                      <button
                        onClick={() => handleCheckEndpoints(ENDPOINT_CATEGORIES.map(c => c.id))}
                        className="text-[11px] px-3 py-2 rounded border border-zinc-700 text-zinc-300 hover:bg-zinc-800 transition-colors"
                      >
                        All cats
                      </button>
                    </div>
                  </div>
                )}
              </div>

              <span className="text-[10px] text-zinc-600">Screenshots → Screenshots tab | Nuclei/Takeover results → Scanner page</span>
            </div>
          )}

          {/* Table area */}
          <div className="flex-1 overflow-auto rounded-lg border border-zinc-800 min-h-0">

            {/* Subdomains tab */}
            {activeTab === 'subdomains' && (
              <table className="w-full text-xs">
                <thead className="bg-zinc-900 sticky top-0 z-10">
                  <tr className="text-zinc-500 text-left">
                    <th className="px-3 py-2 w-8">#</th>
                    <th className="px-3 py-2">Subdomain</th>
                    <th className="px-3 py-2 w-24">Source</th>
                    <th className="px-3 py-2 w-32">IP</th>
                    <th className="px-3 py-2 w-20">Live?</th>
                  </tr>
                </thead>
                <tbody>
                  {subdomains.map((s, i) => {
                    const liveEntry = liveHosts.find(h => h.url?.includes(s.subdomain) || h.host === s.subdomain)
                    return (
                      <tr key={i} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
                        <td className="px-3 py-1.5 text-zinc-600">{i + 1}</td>
                        <td className="px-3 py-1.5 text-zinc-300 font-mono">{s.subdomain}</td>
                        <td className="px-3 py-1.5 text-zinc-500">{s.source}</td>
                        <td className="px-3 py-1.5 text-zinc-500 font-mono">{s.ip || '-'}</td>
                        <td className="px-3 py-1.5">
                          {liveEntry ? (
                            <Badge variant="default" className="text-[10px] bg-green-900/50 text-green-400 border-green-700">
                              {liveEntry.status_code}
                            </Badge>
                          ) : (
                            <span className="text-zinc-700">—</span>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                  {subdomains.length === 0 && (
                    <tr>
                      <td colSpan={5} className="px-3 py-12 text-center text-zinc-600">
                        No subdomains found yet. Enter a target and run Stage 1.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}

            {/* Live Hosts tab */}
            {activeTab === 'live_hosts' && (
              <table className="w-full text-xs">
                <thead className="bg-zinc-900 sticky top-0 z-10">
                  <tr className="text-zinc-500 text-left">
                    <th className="px-3 py-2 w-8">#</th>
                    <th className="px-3 py-2">URL</th>
                    <th className="px-3 py-2 w-16">Status</th>
                    <th className="px-3 py-2">Title</th>
                    <th className="px-3 py-2">Technologies</th>
                    <th className="px-3 py-2 w-8"></th>
                  </tr>
                </thead>
                <tbody>
                  {liveHosts.map((h, i) => (
                    <tr key={i} className="border-b border-zinc-800/50 hover:bg-zinc-800/30 group">
                      <td className="px-3 py-1.5 text-zinc-600">{i + 1}</td>
                      <td className="px-3 py-1.5 text-green-400 font-mono truncate max-w-[240px]">{h.url}</td>
                      <td className="px-3 py-1.5">
                        <span className={cn(
                          "font-mono font-semibold",
                          h.status_code && h.status_code < 300 ? "text-green-500" :
                          h.status_code && h.status_code < 400 ? "text-yellow-500" :
                          h.status_code && h.status_code < 500 ? "text-orange-500" : "text-red-500"
                        )}>
                          {h.status_code ?? '?'}
                        </span>
                      </td>
                      <td className="px-3 py-1.5 text-zinc-300 truncate max-w-[200px]">{h.title || '—'}</td>
                      <td className="px-3 py-1.5">
                        <div className="flex flex-wrap gap-1">
                          {h.technologies?.slice(0, 4).map((t, ti) => (
                            <span key={ti} className="text-[9px] px-1 py-0.5 rounded bg-zinc-800 text-zinc-400 font-mono">{t}</span>
                          ))}
                        </div>
                      </td>
                      <td className="px-3 py-1.5">
                        <button
                          onClick={async () => {
                            removeLiveHost(h.url)
                            try { await api.delete(`/api/recon/live-host?url=${encodeURIComponent(h.url)}`) } catch {}
                          }}
                          title="Remove this host (permanent)"
                          className="text-zinc-700 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-all"
                        >
                          <Trash2 size={12} />
                        </button>
                      </td>
                    </tr>
                  ))}
                  {liveHosts.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-3 py-12 text-center text-zinc-600">
                        No live hosts yet. Run Stage 1 first, then &quot;HTTPX (probe all)&quot; in Stage 2.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}

            {/* AI host analysis panel */}
            {activeTab === 'live_hosts' && (hostsAiAnalysis || hostsAiRunning) && (
              <div className="border-t border-zinc-800 p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Sparkles size={13} className="text-violet-400" />
                    <span className="text-xs font-semibold text-violet-300">AI Host Analysis</span>
                  </div>
                  {hostsAiAnalysis && (
                    <button onClick={() => setHostsAiAnalysis(null)}
                      className="text-zinc-600 hover:text-zinc-400"><X size={12} /></button>
                  )}
                </div>
                {hostsAiRunning && (
                  <div className="flex items-center gap-2 text-zinc-500 text-xs">
                    <Loader2 size={12} className="animate-spin" /> Analyzing {liveHosts.length} hosts...
                  </div>
                )}
                {hostsAiAnalysis && (
                  <div className="prose prose-invert prose-xs max-w-none text-[12px] leading-relaxed text-zinc-300 whitespace-pre-wrap">
                    {hostsAiAnalysis}
                  </div>
                )}
              </div>
            )}

            {/* URLs tab */}
            {activeTab === 'urls' && (
              <div className="flex flex-col h-full">
                {/* Filter bar */}
                <div className="flex flex-wrap items-center gap-2 px-3 py-2 border-b border-zinc-800 bg-zinc-950 sticky top-0 z-10">
                  <input
                    type="text"
                    placeholder="Search URLs..."
                    value={urlSearch}
                    onChange={e => setUrlSearch(e.target.value)}
                    className="text-xs bg-zinc-900 border border-zinc-800 rounded px-2.5 py-1 text-zinc-300 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-600 font-mono w-64"
                  />
                  <div className="flex items-center gap-1 flex-wrap">
                    {([
                      { id: 'all', label: 'All' },
                      { id: 'interesting', label: `Interesting (${interestingCount})`, hot: interestingCount > 0 },
                      { id: 'api',      label: 'API / Admin' },
                      { id: 'sensitive',label: 'Sensitive' },
                      { id: 'backup',   label: 'Backups' },
                      { id: 'config',   label: 'Config' },
                      { id: 'scripts',  label: 'Scripts' },
                      { id: 'media',    label: 'Media' },
                    ] as { id: string; label: string; hot?: boolean }[]).map(chip => (
                      <button
                        key={chip.id}
                        onClick={() => setUrlCategoryFilter(chip.id as typeof urlCategoryFilter)}
                        className={cn(
                          'px-2 py-0.5 rounded text-[10px] border transition-colors',
                          urlCategoryFilter === chip.id
                            ? 'bg-cyan-900/50 border-cyan-700 text-cyan-300'
                            : chip.hot
                              ? 'bg-red-950/40 border-red-800/60 text-red-400 hover:border-red-600'
                              : 'bg-zinc-900 border-zinc-700 text-zinc-400 hover:border-zinc-500'
                        )}
                      >{chip.label}</button>
                    ))}
                  </div>
                  <span className="ml-auto text-[10px] text-zinc-600">
                    {filteredUrls.length} / {urls.length}
                  </span>
                </div>
                {/* Table */}
                <table className="w-full text-xs">
                  <thead className="bg-zinc-900 sticky top-[41px] z-10">
                    <tr className="text-zinc-500 text-left">
                      <th className="px-3 py-2 w-8">#</th>
                      <th className="px-3 py-2">URL</th>
                      <th className="px-3 py-2 w-20">Type</th>
                      <th className="px-3 py-2 w-24">Source</th>
                      <th className="px-3 py-2 w-16">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredUrls.map((u, i) => {
                      const cat = classifyUrl(u.url)
                      const colorClass = urlCategoryColors[cat]
                      return (
                        <tr key={i} className={cn('border-b border-zinc-800/50 hover:bg-zinc-800/30', cat === 'sensitive' && 'bg-red-950/10')}>
                          <td className="px-3 py-1.5 text-zinc-600">{i + 1}</td>
                          <td className="px-3 py-1.5 font-mono truncate max-w-[500px]">
                            <a href={u.url} target="_blank" rel="noreferrer" className="text-zinc-300 hover:text-cyan-400 hover:underline">{u.url}</a>
                          </td>
                          <td className="px-3 py-1.5">
                            {cat !== 'other' && (
                              <span className={cn('px-1.5 py-0.5 rounded text-[9px] border font-medium', colorClass)}>
                                {cat}
                              </span>
                            )}
                          </td>
                          <td className="px-3 py-1.5 text-zinc-500">{u.source}</td>
                          <td className="px-3 py-1.5 text-zinc-500">{u.status_code ?? '—'}</td>
                        </tr>
                      )
                    })}
                    {filteredUrls.length === 0 && (
                      <tr>
                        <td colSpan={5} className="px-3 py-12 text-center text-zinc-600">
                          {urls.length === 0 ? 'No URLs discovered yet. Run Stage 3.' : 'No URLs match the current filter.'}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {/* Screenshots tab */}
            {activeTab === 'screenshots' && (
              <div className="p-3">
                {screenshots.length === 0 ? (
                  <div className="py-12 text-center text-zinc-600 text-xs">
                    No screenshots yet. Go to Live Hosts tab and click &quot;Screenshot all&quot;.
                  </div>
                ) : (
                  <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                    {screenshots.map((s, i) => (
                      <div key={i} className="rounded-lg border border-zinc-800 bg-zinc-900 overflow-hidden group flex flex-col">
                        {/* Clickable image — opens lightbox */}
                        <div
                          className="relative aspect-video bg-zinc-950 cursor-zoom-in"
                          onClick={() => { setLightboxSrc(`${API_BASE}${s.screenshot_url}`); setLightboxUrl(s.url) }}
                        >
                          <img
                            src={`${API_BASE}${s.screenshot_url}`}
                            alt={s.url}
                            className="w-full h-full object-cover group-hover:opacity-90 transition-opacity"
                            loading="lazy"
                          />
                          <div className="absolute inset-0 flex items-center justify-center bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity">
                            <Camera size={18} className="text-white" />
                          </div>
                        </div>
                        {/* URL row with open button */}
                        <div className="px-2 py-1.5 flex items-center gap-1 min-w-0">
                          <div className="text-[10px] text-zinc-400 font-mono truncate flex-1" title={s.url}>{s.url}</div>
                          <a
                            href={s.url}
                            target="_blank"
                            rel="noreferrer"
                            onClick={e => e.stopPropagation()}
                            className="shrink-0 text-zinc-600 hover:text-blue-400 transition-colors"
                            title="Open in browser"
                          >
                            <ExternalLink size={10} />
                          </a>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Ports tab */}
            {activeTab === 'ports' && (
              <table className="w-full text-xs">
                <thead className="bg-zinc-900 sticky top-0 z-10">
                  <tr className="text-zinc-500 text-left">
                    <th className="px-3 py-2 w-8">#</th>
                    <th className="px-3 py-2 w-32">IP/Host</th>
                    <th className="px-3 py-2 w-20">Port</th>
                    <th className="px-3 py-2 w-24">Service</th>
                    <th className="px-3 py-2">Version / Scripts</th>
                  </tr>
                </thead>
                <tbody>
                  {ports.map((p, i) => {
                    const portKey = `${p.ip}:${p.port}`
                    const isExpanded = expandedPort === portKey
                    return (
                      <>
                        <tr
                          key={i}
                          onClick={() => setExpandedPort(isExpanded ? null : portKey)}
                          className="border-b border-zinc-800/50 hover:bg-zinc-800/30 cursor-pointer"
                        >
                          <td className="px-3 py-1.5 text-zinc-600">{i + 1}</td>
                          <td className="px-3 py-1.5 text-zinc-300 font-mono">{p.ip}</td>
                          <td className="px-3 py-1.5">
                            <span className="text-green-500 font-mono font-bold">{p.port}</span>
                            {p.proto && <span className="text-zinc-600 font-mono text-[9px] ml-1">/{p.proto}</span>}
                          </td>
                          <td className="px-3 py-1.5 text-zinc-400">{p.service ?? '—'}</td>
                          <td className="px-3 py-1.5 text-zinc-500 truncate max-w-[260px]">
                            {p.version ?? '—'}
                            {p.scripts && <span className="ml-2 text-[9px] text-blue-400">▶ scripts</span>}
                          </td>
                        </tr>
                        {isExpanded && p.scripts && (
                          <tr key={`${i}-detail`} className="border-b border-zinc-800/50 bg-zinc-900/60">
                            <td colSpan={5} className="px-4 py-2">
                              <pre className="text-[10px] font-mono text-blue-300 whitespace-pre-wrap break-words leading-relaxed">
                                {p.scripts}
                              </pre>
                            </td>
                          </tr>
                        )}
                      </>
                    )
                  })}
                  {ports.length === 0 && (
                    <tr>
                      <td colSpan={5} className="px-3 py-12 text-center text-zinc-600">
                        No port scan results yet. Run Nmap in Stage 4.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}
            {/* CVE Correlation tab */}
            {activeTab === 'cve' && (
              <div className="p-4 space-y-4">
                {cveRunning && (
                  <div className="flex items-center gap-2 text-sm text-zinc-400">
                    <Loader2 size={14} className="animate-spin" /> Searching nuclei templates...
                  </div>
                )}
                {!cveRunning && !cveResult && (
                  <div className="py-12 text-center text-zinc-600 text-xs">
                    Go to Live Hosts tab and click &quot;Correlate CVEs&quot; after running httpx.
                  </div>
                )}
                {cveResult && 'error' in cveResult && (
                  <div className="text-red-400 text-xs">{cveResult.error}</div>
                )}
                {cveResult && 'results' in cveResult && cveResult.results.map((r: any, i: number) => (
                  <div key={i} className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4 space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-xs font-semibold text-zinc-200 font-mono">{r.technology}</div>
                      <span className={cn(
                        'text-[10px] px-2 py-0.5 rounded border font-medium',
                        r.template_count > 0 ? 'border-red-700 bg-red-950/30 text-red-400' : 'border-zinc-700 text-zinc-600'
                      )}>
                        {r.template_count} templates
                      </span>
                    </div>
                    {r.nuclei_cmd && (
                      <div className="rounded border border-zinc-800 overflow-hidden">
                        <div className="flex items-center justify-between px-3 py-1 bg-zinc-900 border-b border-zinc-800">
                          <span className="text-[9px] text-zinc-600 font-mono">nuclei command</span>
                          <button
                            onClick={async () => {
                              // Extract template IDs from -id "..." flag
                              const idMatch = r.nuclei_cmd.match(/-id\s+"([^"]+)"/)
                              const templateIds = idMatch ? idMatch[1] : ''
                              const opts = {
                                ...(templateIds ? { extra_args: `-id "${templateIds}"` } : {}),
                                severity: 'critical,high,medium',
                                ...getSessionOpts(),
                              }
                              // Find live hosts that actually have this technology
                              const techName = (r.technology?.split(' ')[0] ?? '').toLowerCase()
                              const matchingHosts = techName
                                ? liveHosts.filter(h => h.technologies?.some(t => t.toLowerCase().includes(techName)))
                                : []
                              try {
                                if (matchingHosts.length > 1) {
                                  await api.post('/api/scanner/nuclei-bulk', {
                                    targets: matchingHosts.map(h => h.url),
                                    options: opts,
                                    project_id: activeProject ?? '',
                                  })
                                  toast.success('Nuclei started', `${r.technology} templates on ${matchingHosts.length} hosts — Scanner page`)
                                } else {
                                  const tgt = matchingHosts[0]?.url || target.trim() || liveHosts[0]?.url || ''
                                  if (!tgt) { toast.error('No target', 'Run HTTPX first.'); return }
                                  await api.post('/api/scanner/nuclei', {
                                    target: tgt,
                                    options: opts,
                                    project_id: activeProject ?? '',
                                  })
                                  toast.success('Nuclei started', `${r.technology} templates on ${tgt} — Scanner page`)
                                }
                              } catch (e) {
                                toast.error('Failed to start nuclei', e)
                              }
                            }}
                            className="flex items-center gap-1 text-[10px] text-green-400 hover:text-green-300 font-semibold"
                          >
                            <Play size={9} /> Run
                          </button>
                        </div>
                        <div className="text-[10px] font-mono bg-black px-3 py-2 text-green-400 break-all">
                          {r.nuclei_cmd}
                        </div>
                        {r.template_count > 0 && (
                          <div className="px-3 py-1.5 bg-zinc-950/50 text-[9px] text-zinc-500">
                            {r.technology} — {r.template_count} templates available.
                            {r.templates?.[0]?.severity === 'critical' || r.templates?.[0]?.severity === 'high'
                              ? ' High-priority: run immediately.'
                              : ' Run to check for known vulnerabilities in this version.'}
                          </div>
                        )}
                      </div>
                    )}
                    {r.templates?.length > 0 && (
                      <div className="space-y-1">
                        {r.templates.slice(0, 8).map((t: any, j: number) => (
                          <div key={j} className="flex items-start gap-2 text-[10px]">
                            <span className={cn(
                              'shrink-0 px-1 py-0.5 rounded font-bold uppercase',
                              t.severity === 'critical' ? 'bg-red-900/50 text-red-400' :
                              t.severity === 'high' ? 'bg-orange-900/50 text-orange-400' :
                              t.severity === 'medium' ? 'bg-yellow-900/50 text-yellow-400' :
                              t.severity === 'low' ? 'bg-blue-900/50 text-blue-400' :
                              'bg-zinc-800 text-zinc-500'
                            )}>{t.severity ?? '?'}</span>
                            <span className="text-zinc-300 font-mono">{t.id}</span>
                            {t.cve && <span className="text-blue-400">{t.cve}</span>}
                            {t.cvss && <span className="text-zinc-600">CVSS {t.cvss}</span>}
                          </div>
                        ))}
                        {r.templates.length > 8 && (
                          <div className="text-[10px] text-zinc-600">+ {r.templates.length - 8} more templates</div>
                        )}
                      </div>
                    )}
                    {r.template_count === 0 && (
                      <div className="text-[10px] text-zinc-600">No matching nuclei templates found for this technology.</div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* Endpoints tab */}
            {activeTab === 'endpoints' && (
              <div className="p-2 space-y-1">
                {isToolRunning('endpoint_check') && (
                  <div className="flex items-center gap-2 text-xs text-zinc-400 px-2 py-2">
                    <Loader2 size={13} className="animate-spin" /> Scanning endpoints...
                  </div>
                )}
                {!isToolRunning('endpoint_check') && endpoints.length === 0 && (
                  <div className="py-12 text-center text-zinc-600 text-xs">
                    Go to Live Hosts and click <span className="text-cyan-400 font-semibold">Check Endpoints</span> to scan for known paths.
                  </div>
                )}
                {endpoints.length > 0 && (() => {
                  const statusClass = (code: number | null | undefined) =>
                    code === 200 || code === 201 ? 'bg-green-900/50 text-green-400' :
                    code === 401 || code === 403 ? 'bg-orange-900/50 text-orange-400' :
                    code === 301 || code === 302 ? 'bg-blue-900/50 text-blue-400' :
                    code === 500 ? 'bg-red-900/50 text-red-400' :
                    'bg-zinc-800 text-zinc-500'
                  const bucket = (code: number | null | undefined) =>
                    code == null ? 'other' :
                    code < 300 ? '2xx' : code < 400 ? '3xx' : code < 500 ? '4xx' : code < 600 ? '5xx' : 'other'
                  const buckets = ['2xx', '3xx', '4xx', '5xx']
                  const counts = endpoints.reduce<Record<string, number>>((acc, ep) => {
                    const b = bucket(ep.status_code); acc[b] = (acc[b] || 0) + 1; return acc
                  }, {})
                  const q = endpointSearch.trim().toLowerCase()
                  const codeQ = endpointCodeFilter.trim()
                  const minS = endpointMinSize.trim() === '' ? null : Number(endpointMinSize)
                  const maxS = endpointMaxSize.trim() === '' ? null : Number(endpointMaxSize)
                  const hideSizes = new Set(
                    endpointHideSizes.split(',').map(s => s.trim()).filter(Boolean).map(Number).filter(n => !isNaN(n))
                  )
                  const filtered = endpoints.filter(ep => {
                    if (endpointStatusFilter !== 'all' && bucket(ep.status_code) !== endpointStatusFilter) return false
                    if (codeQ && String(ep.status_code ?? '') !== codeQ) return false
                    if (q && !(ep.url?.toLowerCase().includes(q) || ep.title?.toLowerCase().includes(q))) return false
                    const len = ep.content_length
                    if (minS != null && (len == null || len < minS)) return false
                    if (maxS != null && (len == null || len > maxS)) return false
                    if (len != null && hideSizes.has(len)) return false
                    return true
                  })
                  return (
                    <>
                      <div className="flex items-center gap-1.5 px-2 pb-1.5 flex-wrap">
                        <span className="text-[10px] text-zinc-600 mr-1">{filtered.length} / {endpoints.length}</span>
                        <button
                          onClick={() => setEndpointStatusFilter('all')}
                          className={cn('text-[10px] font-mono px-1.5 py-0.5 rounded border transition-colors',
                            endpointStatusFilter === 'all' ? 'border-cyan-500/60 bg-cyan-950/40 text-cyan-400' : 'border-zinc-800 text-zinc-500 hover:border-zinc-600')}
                        >all</button>
                        {buckets.filter(b => counts[b]).map(b => (
                          <button
                            key={b}
                            onClick={() => setEndpointStatusFilter(b)}
                            className={cn('text-[10px] font-mono px-1.5 py-0.5 rounded border transition-colors',
                              endpointStatusFilter === b ? 'border-cyan-500/60 bg-cyan-950/40 text-cyan-400' : 'border-zinc-800 text-zinc-500 hover:border-zinc-600')}
                          >{b} <span className="text-zinc-600">{counts[b]}</span></button>
                        ))}
                        <input
                          value={endpointSearch}
                          onChange={e => setEndpointSearch(e.target.value)}
                          placeholder="filter url / title"
                          className="text-[10px] bg-zinc-900 border border-zinc-800 rounded px-1.5 py-0.5 text-zinc-300 placeholder:text-zinc-700 focus:outline-none focus:border-zinc-600 w-36 font-mono"
                        />
                        <input
                          value={endpointCodeFilter}
                          onChange={e => setEndpointCodeFilter(e.target.value.replace(/[^0-9]/g, ''))}
                          placeholder="code"
                          className="text-[10px] bg-zinc-900 border border-zinc-800 rounded px-1.5 py-0.5 text-zinc-300 placeholder:text-zinc-700 focus:outline-none focus:border-zinc-600 w-14 font-mono"
                        />
                        <input
                          value={endpointMinSize}
                          onChange={e => setEndpointMinSize(e.target.value.replace(/[^0-9]/g, ''))}
                          placeholder="min B"
                          className="text-[10px] bg-zinc-900 border border-zinc-800 rounded px-1.5 py-0.5 text-zinc-300 placeholder:text-zinc-700 focus:outline-none focus:border-zinc-600 w-16 font-mono"
                        />
                        <input
                          value={endpointMaxSize}
                          onChange={e => setEndpointMaxSize(e.target.value.replace(/[^0-9]/g, ''))}
                          placeholder="max B"
                          className="text-[10px] bg-zinc-900 border border-zinc-800 rounded px-1.5 py-0.5 text-zinc-300 placeholder:text-zinc-700 focus:outline-none focus:border-zinc-600 w-16 font-mono"
                        />
                        <input
                          value={endpointHideSizes}
                          onChange={e => setEndpointHideSizes(e.target.value.replace(/[^0-9,]/g, ''))}
                          placeholder="hide B (2000,3000)"
                          title="Hide responses with these exact byte sizes (comma-separated)"
                          className="text-[10px] bg-zinc-900 border border-zinc-800 rounded px-1.5 py-0.5 text-zinc-300 placeholder:text-zinc-700 focus:outline-none focus:border-red-700/60 w-28 font-mono"
                        />
                      </div>
                      {filtered.map((ep, i) => (
                        <div key={i} className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-zinc-800/50 transition-colors group">
                          <span className={cn('text-[10px] font-mono font-bold shrink-0 w-8 text-center rounded px-1', statusClass(ep.status_code))}>{ep.status_code ?? '?'}</span>
                          <span className="text-xs text-zinc-200 font-mono flex-1 truncate">{ep.url}</span>
                          {ep.title && <span className="text-[10px] text-zinc-500 truncate max-w-32 shrink-0">{ep.title}</span>}
                          {ep.content_length != null && (
                            <span className="text-[9px] text-zinc-600 font-mono shrink-0 w-16 text-right">{ep.content_length} B</span>
                          )}
                          {ep.content_type && (
                            <span className="text-[9px] text-zinc-700 shrink-0 hidden group-hover:block">{ep.content_type.split(';')[0]}</span>
                          )}
                          <a href={ep.url} target="_blank" rel="noopener noreferrer" className="text-zinc-700 hover:text-zinc-400 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                            <ExternalLink size={10} />
                          </a>
                        </div>
                      ))}
                    </>
                  )
                })()}
              </div>
            )}

          </div>
        </div>
      </div>
      {/* Lightbox modal */}
      {lightboxSrc && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-sm"
          onClick={() => { setLightboxSrc(null); setLightboxUrl(null) }}
        >
          <div
            className="max-w-5xl w-full mx-4 rounded-xl overflow-hidden shadow-2xl border border-zinc-700"
            onClick={e => e.stopPropagation()}
          >
            <img
              src={lightboxSrc}
              alt={lightboxUrl ?? ''}
              className="w-full max-h-[75vh] object-contain bg-zinc-950"
            />
            <div className="bg-zinc-900 px-4 py-3 flex items-center justify-between gap-3">
              <span className="text-xs font-mono text-zinc-400 truncate">{lightboxUrl}</span>
              <div className="flex items-center gap-2 shrink-0">
                <a
                  href={lightboxUrl ?? '#'}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1.5 px-3 py-1 rounded text-[10px] border border-blue-700 text-blue-400 hover:bg-blue-950/40 transition-colors"
                >
                  <ExternalLink size={10} /> Open in browser
                </a>
                <button
                  onClick={() => { setLightboxSrc(null); setLightboxUrl(null) }}
                  className="text-zinc-600 hover:text-zinc-300 transition-colors text-xs"
                >
                  ✕ Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </WorkspaceShell>
  )
}

// Small helper component for option inputs
function OptionInput({
  label, placeholder, value, onChange
}: { label: string; placeholder: string; value: string; onChange: (v: string) => void }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-[10px] text-zinc-600 w-14 shrink-0">{label}:</span>
      <input
        type="text"
        placeholder={placeholder}
        value={value}
        onChange={e => onChange(e.target.value)}
        className="flex-1 text-[10px] bg-zinc-900 border border-zinc-800 rounded px-2 py-0.5 text-zinc-400 placeholder:text-zinc-700 focus:outline-none focus:border-zinc-600"
      />
    </div>
  )
}
