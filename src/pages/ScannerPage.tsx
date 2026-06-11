import { useState, useEffect, useRef } from 'react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { ScopeSelector } from '@/components/ui/scope-selector'
import { ContextMenu, menuFromEvent, type ContextMenuState } from '@/components/ui/context-menu'
import { useScannerStore } from '@/stores/scanner-store'
import { useAppStore } from '@/stores/app-store'
import { useWorkspaceStore } from '@/stores/workspace-store'
import { useReconStore } from '@/stores/recon-store'
import { api } from '@/api/http-client'
import { toast } from '@/stores/toast-store'
import { cn } from '@/lib/utils'
import { useNavigate } from 'react-router-dom'
import {
  Play,
  Square,
  Loader2,
  Settings2,
  Trash2,
  Bug,
  FolderSearch,
  Shield,
  Server,
  Terminal,
  BookOpen,
  Sparkles,
  ChevronDown,
  Info,
  X,
  AlertTriangle,
  CheckCircle2,
  Zap,
} from 'lucide-react'
import type { Finding } from '@/types'

interface NucleiScanType { id: string; label: string; desc: string; speed: string; color: string }
interface NucleiScanGroup { label: string; types: NucleiScanType[] }

// Nuclei scan type groups
const NUCLEI_SCAN_GROUPS: NucleiScanGroup[] = [
  {
    label: 'General',
    types: [
      { id: '', label: 'Default', desc: 'Tech + Exposures + Misconfigs', speed: 'fast', color: 'text-zinc-300' },
      { id: 'cves', label: 'CVEs', desc: 'Known CVE templates', speed: 'slow', color: 'text-red-400' },
      { id: 'exposure', label: 'Exposures', desc: 'Sensitive files & data', speed: 'medium', color: 'text-orange-400' },
      { id: 'misconfig', label: 'Misconfigs', desc: 'Server misconfigurations', speed: 'medium', color: 'text-yellow-400' },
      { id: 'default-logins', label: 'Default Logins', desc: 'Default credentials', speed: 'medium', color: 'text-amber-400' },
      { id: 'takeover', label: 'Takeover', desc: 'Subdomain takeover', speed: 'fast', color: 'text-purple-400' },
    ],
  },
  {
    label: 'Injection',
    types: [
      { id: 'xss', label: 'XSS', desc: 'Cross-site scripting templates', speed: 'medium', color: 'text-pink-400' },
      { id: 'sqli', label: 'SQL Injection', desc: 'SQL injection detection', speed: 'medium', color: 'text-red-400' },
      { id: 'ssti', label: 'SSTI', desc: 'Server-side template injection', speed: 'fast', color: 'text-orange-400' },
      { id: 'xxe', label: 'XXE', desc: 'XML external entity', speed: 'fast', color: 'text-yellow-400' },
      { id: 'lfi', label: 'LFI/Path Traversal', desc: 'Local file inclusion', speed: 'medium', color: 'text-amber-400' },
      { id: 'rce', label: 'RCE', desc: 'Remote code execution', speed: 'medium', color: 'text-red-500' },
    ],
  },
  {
    label: 'Access & Auth',
    types: [
      { id: 'ssrf', label: 'SSRF', desc: 'SSRF + open redirect', speed: 'fast', color: 'text-blue-400' },
      { id: 'idor', label: 'IDOR', desc: 'Insecure direct object reference', speed: 'medium', color: 'text-cyan-400' },
      { id: 'auth-bypass', label: 'Auth Bypass', desc: 'Authentication bypass', speed: 'medium', color: 'text-orange-400' },
      { id: 'jwt', label: 'JWT', desc: 'JWT vulnerabilities', speed: 'fast', color: 'text-yellow-400' },
      { id: 'cors', label: 'CORS', desc: 'CORS misconfigurations', speed: 'fast', color: 'text-green-400' },
      { id: 'oast', label: 'OAST', desc: 'Out-of-band detection', speed: 'fast', color: 'text-purple-400' },
    ],
  },
  {
    label: 'OWASP Top 10',
    types: [
      { id: 'full-owasp', label: 'Full OWASP', desc: 'All OWASP Top 10 categories', speed: 'slow', color: 'text-red-400' },
      { id: 'owasp-a01', label: 'A01 - Broken Access', desc: 'IDOR, BAC, privilege escalation', speed: 'medium', color: 'text-orange-400' },
      { id: 'owasp-a02', label: 'A02 - Auth Failures', desc: 'JWT, session, broken auth', speed: 'medium', color: 'text-yellow-400' },
      { id: 'owasp-a03', label: 'A03 - Injection', desc: 'SQLi, XSS, SSTI, XXE, RCE', speed: 'slow', color: 'text-red-400' },
      { id: 'owasp-a05', label: 'A05 - Misconfig', desc: 'CORS, headers, misconfigs', speed: 'medium', color: 'text-blue-400' },
      { id: 'owasp-a06', label: 'A06 - Vulns/CVEs', desc: 'Known vulnerabilities & CVEs', speed: 'slow', color: 'text-orange-400' },
      { id: 'owasp-a07', label: 'A07 - Auth & Identity', desc: 'Broken auth, default logins', speed: 'medium', color: 'text-yellow-400' },
    ],
  },
  {
    label: 'Specialized',
    types: [
      { id: 'api', label: 'API Security', desc: 'REST/GraphQL endpoints', speed: 'medium', color: 'text-cyan-400' },
      { id: 'cloud', label: 'Cloud', desc: 'AWS, GCP, Azure misconfigs', speed: 'fast', color: 'text-blue-400' },
    ],
  },
]

// Scanner tool categories by BB purpose
const SCANNER_STAGES = [
  {
    id: 'vuln-scan',
    label: 'Vulnerability Detection',
    color: 'text-red-400',
    borderColor: 'border-red-500/30',
    bgColor: 'bg-red-950/20',
    tools: [
      {
        id: 'nuclei',
        label: 'Nuclei',
        desc: 'Template-based vulnerability scanner',
        installed: true,
        options: [
          { key: 'severity', label: 'Severity', placeholder: 'info,low,medium,high,critical' },
          { key: 'tags', label: 'Extra tags', placeholder: 'cves,xss,sqli,misconfig' },
          { key: 'exclude_tags', label: 'Exclude tags', placeholder: 'dos,fuzz' },
          { key: 'templates', label: 'Custom template', placeholder: '/root/nuclei-templates/http/...' },
          { key: 'rate_limit', label: 'Rate limit', placeholder: '100' },
          { key: 'concurrency', label: 'Concurrency', placeholder: '25' },
          { key: 'request_timeout', label: 'Req timeout', placeholder: '10' },
          { key: 'proxy', label: 'Proxy', placeholder: 'http://127.0.0.1:8080' },
          { key: 'headers', label: 'Headers', placeholder: 'Authorization: Bearer TOKEN' },
        ],
        scanTypes: [],
      },
    ],
  },
  {
    id: 'web-analysis',
    label: 'Web Server Analysis',
    color: 'text-yellow-400',
    borderColor: 'border-yellow-500/30',
    bgColor: 'bg-yellow-950/20',
    tools: [
      {
        id: 'nikto',
        label: 'Nikto',
        desc: 'Web server scanner — misconfigs, outdated software, headers',
        installed: true,
        options: [
          { key: 'extra', label: 'Extra flags', placeholder: '-Tuning 123456' },
        ],
        scanTypes: [],
      },
    ],
  },
  {
    id: 'dir-discovery',
    label: 'Directory & File Discovery',
    color: 'text-blue-400',
    borderColor: 'border-blue-500/30',
    bgColor: 'bg-blue-950/20',
    tools: [
      {
        id: 'gobuster',
        label: 'Gobuster',
        desc: 'Fast directory brute-force (Go)',
        installed: true,
        options: [
          { key: 'wordlist', label: 'Wordlist', type: 'wordlist-select' as const },
          { key: 'extensions', label: 'Extensions', placeholder: 'php,html,js,txt,bak' },
          { key: 'threads', label: 'Threads', placeholder: '10' },
          { key: 'match_codes', label: 'Status codes', placeholder: '200,204,301,302,307,401,403' },
          { key: 'exclude_length', label: 'Exclude size', placeholder: '0 (hide empty responses)' },
        ],
        scanTypes: [],
      },
      {
        id: 'ffuf',
        label: 'FFUF',
        desc: 'Web fuzzer — add FUZZ keyword to URL or auto-appended',
        installed: true,
        options: [
          { key: 'wordlist', label: 'Wordlist', type: 'wordlist-select' as const },
          { key: 'extensions', label: 'Extensions', placeholder: '.php,.html,.txt' },
          { key: 'match_codes', label: 'Match codes', placeholder: '200,301,302,403' },
          { key: 'filter_size', label: 'Filter size', placeholder: '0' },
        ],
        scanTypes: [],
      },
      {
        id: 'dirsearch',
        label: 'Dirsearch',
        desc: 'Directory scanner with built-in wordlists',
        installed: true,
        options: [
          { key: 'extensions', label: 'Extensions', placeholder: 'php,html,js,txt' },
          { key: 'threads', label: 'Threads', placeholder: '20' },
          { key: 'wordlist', label: 'Wordlist', type: 'wordlist-select' as const },
        ],
        scanTypes: [],
      },
    ],
  },
]

interface ToolOpts { [key: string]: string }
type ToolOptionsMap = Record<string, ToolOpts>

// View modes: all findings or per-tool view
type ViewMode = 'all' | string  // string = specific tool id

export function ScannerPage() {
  const { globalTarget, setGlobalTarget, activeProject, getSessionOpts } = useAppStore()
  const [target, setTargetLocal] = useState(globalTarget)
  // Always sync with global target (allows Recon live-host picker to propagate here)
  useEffect(() => { setTargetLocal(globalTarget) }, [globalTarget])
  const setTarget = (v: string) => { setTargetLocal(v); setGlobalTarget(v) }
  const [expandedOpts, setExpandedOpts] = useState<Set<string>>(new Set())
  const [nucleiPreset, setNucleiPreset] = useState<string>('')
  const [nucleiGuideOpen, setNucleiGuideOpen] = useState(false)
  const [nucleiTemplateOpen, setNucleiTemplateOpen] = useState(false)
  const [nucleiTemplates, setNucleiTemplates] = useState<Array<{name: string; path: string; count: number}>>([])
  const [nucleiTemplatesLoaded, setNucleiTemplatesLoaded] = useState(false)
  const [toolOptions, setToolOptions] = useState<ToolOptionsMap>({})
  const [viewMode, setViewMode] = useState<ViewMode>('all')
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const [terminalTool, setTerminalTool] = useState<string>('')
  const terminalRef = useRef<HTMLPreElement>(null)
  const { findings, rawOutput, activeScans, activeJobIds, clearFindings } = useScannerStore()

  // Live host picker (mirrors Recon's discovered hosts)
  const { liveHosts } = useReconStore()
  const [liveHostPickerOpen, setLiveHostPickerOpen] = useState(false)
  const [liveHostFilter, setLiveHostFilter] = useState('')
  const liveHostPickerRef = useRef<HTMLDivElement>(null)
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

  // Context menu for findings
  const [ctxMenu, setCtxMenu] = useState<ContextMenuState>({ visible: false, x: 0, y: 0 })
  const [ctxFinding, setCtxFinding] = useState<Finding | null>(null)
  const { addFinding: addToWorkspace } = useWorkspaceStore()
  const navigate = useNavigate()

  const cancelScan = async (toolId: string) => {
    const jobId = activeJobIds[toolId]
    if (!jobId) return
    try { await api.delete(`/api/scanner/jobs/${jobId}`) } catch {}
  }

  // Auto-scroll terminal
  useEffect(() => {
    if (viewMode === 'terminal' && terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight
    }
  }, [rawOutput, viewMode])

  // When a dir-discovery tool starts running, auto-select it in the terminal
  const dirTools = ['gobuster', 'ffuf', 'dirsearch']
  useEffect(() => {
    const running = dirTools.find(t => activeScans.has(t))
    if (running) {
      setTerminalTool(running)
    }
  }, [activeScans])

  const jumpToTerminal = (toolId: string) => {
    setTerminalTool(toolId)
    setViewMode('terminal')
  }

  const handleRunTool = async (toolId: string, extraOpts?: Record<string, any>) => {
    if (!target.trim()) return
    try {
      const opts: Record<string, any> = { ...(toolOptions[toolId] || {}), ...extraOpts, ...getSessionOpts() }
      // If wordlist-using tools have no wordlist set, default to SecLists common
      if (['gobuster', 'ffuf', 'dirsearch'].includes(toolId) && !opts.wordlist) {
        opts.wordlist = WORDLIST_PRESETS[0].value
      }
      await api.post(`/api/scanner/${toolId}`, { target: target.trim(), options: opts, project_id: activeProject ?? '' })
    } catch (err) {
      toast.error(`Failed to start ${toolId}`, err)
    }
  }

  const toggleOpts = (toolId: string) => {
    setExpandedOpts(prev => { const n = new Set(prev); n.has(toolId) ? n.delete(toolId) : n.add(toolId); return n })
  }

  const setOption = (toolId: string, key: string, value: string) => {
    setToolOptions(prev => ({ ...prev, [toolId]: { ...(prev[toolId] || {}), [key]: value } }))
  }

  // Findings filtered by tool when in per-tool view
  const displayedFindings = viewMode === 'all'
    ? findings
    : findings.filter(f => f.tool === viewMode)

  // Count per tool for the view tabs
  const toolCounts = findings.reduce<Record<string, number>>((acc, f) => {
    if (f.tool) acc[f.tool] = (acc[f.tool] || 0) + 1
    return acc
  }, {})

  // All unique tools that produced results
  const activeTools = [...new Set(findings.map(f => f.tool).filter(Boolean))] as string[]

  // Severity summary counts
  const severityCounts = findings.reduce<Record<string, number>>((acc, f) => {
    const s = (f.severity || 'info').toLowerCase()
    acc[s] = (acc[s] || 0) + 1
    return acc
  }, {})

  return (
    <WorkspaceShell title="Scanner" subtitle="Vulnerability scanning and directory discovery — per-tool output">
      <div className="flex gap-4 h-full min-h-0">

        {/* LEFT PANEL — Tool launcher */}
        <div className="w-72 shrink-0 flex flex-col gap-3 overflow-y-auto pr-1">

          {/* Target */}
          <div className="space-y-2">
            <ScopeSelector onSelect={setTarget} selectedTarget={target} />
            <Input
              placeholder="https://target.com"
              className="bg-zinc-900 text-sm"
              value={target}
              onChange={e => setTarget(e.target.value)}
            />

            {/* Live host picker — populated from Recon page */}
            {liveHosts.length > 0 && (
              <div className="relative" ref={liveHostPickerRef}>
                <button
                  onClick={() => setLiveHostPickerOpen(v => !v)}
                  className="w-full flex items-center justify-between gap-1.5 px-2.5 py-1.5 rounded-lg border border-green-700/50 bg-green-950/20 text-xs text-green-400 hover:border-green-600 hover:bg-green-950/30 transition-colors"
                >
                  <span className="truncate">{liveHosts.length} live hosts from Recon</span>
                  <ChevronDown size={11} className={cn('shrink-0 transition-transform', liveHostPickerOpen && 'rotate-180')} />
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
          {SCANNER_STAGES.map(stage => (
            <div key={stage.id} className={cn("rounded-lg border p-3 space-y-2", stage.borderColor, stage.bgColor)}>
              <div className={cn("text-xs font-semibold", stage.color)}>{stage.label}</div>

              {stage.tools.map(tool => {
                const isRunning = activeScans.has(tool.id)
                const hasOpts = expandedOpts.has(tool.id)
                const opts = toolOptions[tool.id] || {}

                return (
                  <div key={tool.id} className="space-y-1">
                    {/* Nuclei uses its own run button inside the preset selector — hide generic one */}
                    <div className={cn("flex items-center gap-1", tool.id === 'nuclei' && "hidden")}>
                      {isRunning && (
                        <button
                          onClick={() => cancelScan(tool.id)}
                          className="p-1 rounded border border-red-700 text-red-400 hover:bg-red-950/30 transition-colors"
                          title="Stop"
                        >
                          <Square size={10} className="fill-current" />
                        </button>
                      )}
                      <button
                        disabled={isRunning || !target.trim() || !tool.installed}
                        onClick={() => handleRunTool(tool.id)}
                        className={cn(
                          "flex items-center gap-1.5 flex-1 px-2 py-1.5 rounded text-xs font-medium transition-colors border text-left",
                          !tool.installed
                            ? "border-zinc-800 text-zinc-700 cursor-not-allowed"
                            : isRunning
                              ? "border-zinc-600 bg-zinc-800 text-zinc-300"
                              : "border-zinc-700 bg-zinc-900 text-zinc-300 hover:border-zinc-500 hover:bg-zinc-800"
                        )}
                      >
                        {isRunning
                          ? <Loader2 size={11} className="animate-spin shrink-0" />
                          : <Play size={11} className="shrink-0" />}
                        <span className="flex-1">{tool.label}</span>
                        {toolCounts[tool.id] ? (
                          <Badge variant="secondary" className="h-3.5 px-1 text-[9px]">{toolCounts[tool.id]}</Badge>
                        ) : null}
                      </button>
                      <button
                        onClick={() => toggleOpts(tool.id)}
                        className={cn(
                          "p-1 rounded border transition-colors",
                          hasOpts ? "border-zinc-600 text-zinc-400" : "border-zinc-800 text-zinc-600 hover:text-zinc-400 hover:border-zinc-600"
                        )}
                        title="Options"
                      >
                        <Settings2 size={10} />
                      </button>
                    </div>

                    <div className="text-[10px] text-zinc-600 pl-1">{tool.desc}</div>

                    {/* Dir-discovery tools: show output button */}
                    {dirTools.includes(tool.id) && (
                      <button
                        onClick={() => jumpToTerminal(tool.id)}
                        className={cn(
                          "w-full flex items-center gap-1.5 px-2 py-1 rounded text-[10px] border transition-colors",
                          isRunning
                            ? "border-green-700/60 text-green-400 bg-green-950/20 animate-pulse"
                            : rawOutput[tool.id]?.length
                              ? "border-zinc-600 text-zinc-400 hover:border-zinc-500 hover:text-zinc-200"
                              : "border-zinc-800 text-zinc-600 hover:border-zinc-700 hover:text-zinc-500"
                        )}
                      >
                        <Terminal size={9} />
                        {isRunning
                          ? `Live output (${rawOutput[tool.id]?.length ?? 0} lines)`
                          : rawOutput[tool.id]?.length
                            ? `View output (${rawOutput[tool.id].length} lines)`
                            : 'View output'}
                      </button>
                    )}

                    {/* Nuclei grouped preset selector */}
                    {tool.id === 'nuclei' && (
                      <div className="space-y-2 pl-1">
                        <div className="flex gap-1">
                          <button
                            onClick={() => setNucleiGuideOpen(true)}
                            className="flex-1 flex items-center gap-1.5 px-2 py-1 rounded text-[10px] border border-blue-800/50 text-blue-400/70 hover:text-blue-400 hover:border-blue-700 transition-colors bg-blue-950/10"
                          >
                            <Info size={10} /> Guide
                          </button>
                          <button
                            onClick={async () => {
                              setNucleiTemplateOpen(true)
                              if (!nucleiTemplatesLoaded) {
                                try {
                                  const res = await api.get<{available: boolean; categories: typeof nucleiTemplates}>('/api/tools/nuclei-templates')
                                  if (res.available) setNucleiTemplates(res.categories)
                                  setNucleiTemplatesLoaded(true)
                                } catch {}
                              }
                            }}
                            className="flex-1 flex items-center gap-1.5 px-2 py-1 rounded text-[10px] border border-zinc-700 text-zinc-500 hover:text-zinc-300 hover:border-zinc-600 transition-colors"
                          >
                            <BookOpen size={10} /> Templates
                          </button>
                        </div>
                        {NUCLEI_SCAN_GROUPS.map(group => (
                          <div key={group.label}>
                            <div className="text-[9px] text-zinc-600 uppercase tracking-wider mb-1 font-semibold">{group.label}</div>
                            <div className="grid grid-cols-2 gap-1">
                              {group.types.map(st => (
                                <button
                                  key={st.id}
                                  onClick={() => {
                                    setNucleiPreset(st.id)
                                    setOption('nuclei', 'templates', '')
                                  }}
                                  className={cn(
                                    "text-left px-2 py-1.5 rounded border text-[10px] transition-colors",
                                    nucleiPreset === st.id
                                      ? "border-red-500/60 bg-red-950/30 text-red-300"
                                      : "border-zinc-800 text-zinc-500 hover:border-zinc-600 hover:text-zinc-300"
                                  )}
                                >
                                  <div className={cn("font-medium", nucleiPreset === st.id ? "text-red-300" : st.color)}>{st.label}</div>
                                  <div className="text-[9px] mt-0.5 text-zinc-600 leading-tight">{st.desc}</div>
                                </button>
                              ))}
                            </div>
                          </div>
                        ))}
                        {nucleiPreset && (
                          <div className="text-[9px] text-zinc-500 flex items-center gap-1">
                            Preset: <span className="text-red-400 font-mono">{nucleiPreset}</span>
                            <button onClick={() => setNucleiPreset('')} className="text-zinc-700 hover:text-zinc-400 ml-1">✕</button>
                          </div>
                        )}
                        {opts.templates && (
                          <div className="text-[9px] text-zinc-500 flex items-center gap-1">
                            Template: <span className="text-green-400 font-mono">{opts.templates.split('/').pop()}</span>
                            <button onClick={() => setOption('nuclei', 'templates', '')} className="text-zinc-700 hover:text-zinc-400 ml-1">✕</button>
                          </div>
                        )}
                        <button
                          disabled={isRunning || !target.trim()}
                          onClick={() => handleRunTool('nuclei', nucleiPreset ? { scan_type: nucleiPreset } : {})}
                          className={cn(
                            "w-full flex items-center justify-center gap-1.5 px-2 py-2 rounded text-xs font-medium transition-colors border",
                            isRunning
                              ? "border-zinc-600 bg-zinc-800 text-zinc-300"
                              : "border-red-600/50 bg-red-950/20 text-red-300 hover:bg-red-950/40 hover:border-red-500"
                          )}
                        >
                          {isRunning
                            ? <><Loader2 size={11} className="animate-spin" />Running nuclei...</>
                            : <><Play size={11} />Run Nuclei {opts.templates ? `— ${opts.templates.split('/').pop()}` : nucleiPreset ? `— ${nucleiPreset}` : '— default'}</>}
                        </button>
                        {isRunning && (
                          <div className="text-[10px] text-zinc-500 text-center animate-pulse">
                            Loading templates (~25s) — output visible in Raw Output tab
                          </div>
                        )}
                        {isRunning && (
                          <button
                            onClick={() => cancelScan('nuclei')}
                            className="w-full flex items-center justify-center gap-1.5 px-2 py-1 rounded text-xs border border-red-700 text-red-400 hover:bg-red-950/30 transition-colors"
                          >
                            <Square size={10} className="fill-current" /> Stop Nuclei
                          </button>
                        )}
                      </div>
                    )}

                    {/* Options panel */}
                    {hasOpts && (
                      <div className="pl-1 space-y-1 border-l border-zinc-800 ml-1 pt-1">
                        {tool.options.map(opt => (
                          (opt as any).type === 'wordlist-select'
                            ? <WordlistSelect
                                key={opt.key}
                                label={opt.label}
                                value={opts[opt.key] || ''}
                                onChange={v => setOption(tool.id, opt.key, v)}
                              />
                            : <OptionInput
                                key={opt.key}
                                label={opt.label}
                                placeholder={(opt as any).placeholder}
                                value={opts[opt.key] || ''}
                                onChange={v => setOption(tool.id, opt.key, v)}
                              />
                        ))}
                        <OptionInput
                          label="Extra flags"
                          placeholder="-rate 50 --timeout 15"
                          value={opts.extra_args || ''}
                          onChange={v => setOption(tool.id, 'extra_args', v)}
                        />
                        <div className="text-[9px] text-zinc-600 leading-tight">
                          Appended verbatim to the command. The exact command appears as <span className="font-mono text-zinc-500">$ ...</span> in the output.
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          ))}

          <Button
            variant="ghost"
            size="sm"
            className="text-zinc-600 hover:text-red-400 text-xs"
            onClick={async () => {
              clearFindings()
              setSelectedFinding(null)
              const qs = activeProject ? `?project_id=${activeProject}` : ''
              try { await api.delete(`/api/scanner/findings${qs}`) } catch {}
            }}
          >
            <Trash2 size={12} className="mr-1" /> Clear findings
          </Button>
        </div>

        {/* RIGHT PANEL — Results */}
        <div className="flex-1 flex flex-col gap-3 min-h-0 min-w-0">

          {/* View mode tabs — All + per-tool */}
          <div className="flex gap-1 bg-zinc-900 rounded-lg p-1 flex-wrap">
            <button
              onClick={() => setViewMode('all')}
              className={cn(
                'flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors',
                viewMode === 'all' ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200'
              )}
            >
              <Bug size={11} />
              All findings
              {findings.length > 0 && (
                <Badge variant="secondary" className="h-4 px-1 text-[10px]">{findings.length}</Badge>
              )}
            </button>

            {activeTools.map(toolId => (
              <button
                key={toolId}
                onClick={() => setViewMode(toolId)}
                className={cn(
                  'flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors capitalize',
                  viewMode === toolId ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200'
                )}
              >
                {toolId === 'nuclei' && <Shield size={11} />}
                {toolId === 'nikto' && <Server size={11} />}
                {(toolId === 'gobuster' || toolId === 'ffuf' || toolId === 'dirsearch') && <FolderSearch size={11} />}
                {toolId}
                <Badge variant="secondary" className="h-4 px-1 text-[10px]">{toolCounts[toolId]}</Badge>
              </button>
            ))}

            {/* Terminal tab — always shown when there's raw output */}
            <button
              onClick={() => {
                setViewMode('terminal')
                // default to first tool with output
                if (!terminalTool || !rawOutput[terminalTool]) {
                  const first = Object.keys(rawOutput)[0]
                  if (first) setTerminalTool(first)
                }
              }}
              className={cn(
                'flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ml-auto',
                viewMode === 'terminal' ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200'
              )}
            >
              <Terminal size={11} />
              Raw Output
              {Object.values(rawOutput).some(l => l.length > 0) && (
                <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
              )}
            </button>
          </div>

          {/* Terminal view */}
          {viewMode === 'terminal' && (
            <div className="flex-1 flex flex-col gap-2 min-h-0">
              {/* Tool selector — shows all tools with output + currently running tools */}
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[10px] text-zinc-600 shrink-0">Tool:</span>
                <div className="flex gap-1 flex-wrap flex-1">
                  {/* All tools that have output OR are currently running */}
                  {[...new Set([...Object.keys(rawOutput), ...[...activeScans]])].map(tool => {
                    const isActive = activeScans.has(tool)
                    const lines = rawOutput[tool]?.length ?? 0
                    return (
                      <button
                        key={tool}
                        onClick={() => setTerminalTool(tool)}
                        className={cn(
                          "text-[10px] px-2 py-0.5 rounded border transition-colors font-mono flex items-center gap-1",
                          terminalTool === tool
                            ? "border-green-600 text-green-400 bg-green-950/30"
                            : "border-zinc-700 text-zinc-500 hover:border-zinc-500 hover:text-zinc-300"
                        )}
                      >
                        {isActive && <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse shrink-0" />}
                        {tool}
                        <span className="text-zinc-600">({lines})</span>
                      </button>
                    )
                  })}
                  {Object.keys(rawOutput).length === 0 && activeScans.size === 0 && (
                    <span className="text-[10px] text-zinc-700">Run gobuster, nuclei or another tool to see output here</span>
                  )}
                </div>
                {/* Clear output for selected tool */}
                {terminalTool && rawOutput[terminalTool]?.length > 0 && (
                  <button
                    onClick={() => {
                      // clear by overwriting — use store directly
                      const { rawOutput: ro } = useScannerStore.getState()
                      useScannerStore.setState({ rawOutput: { ...ro, [terminalTool]: [] } })
                    }}
                    className="text-[10px] text-zinc-700 hover:text-red-400 transition-colors shrink-0"
                    title="Clear output"
                  >
                    <Trash2 size={11} />
                  </button>
                )}
              </div>

              {/* Terminal */}
              <pre
                ref={terminalRef}
                className="flex-1 rounded-lg border border-zinc-800 bg-black p-4 overflow-auto text-[11px] font-mono leading-relaxed"
              >
                {terminalTool && activeScans.has(terminalTool) && (!rawOutput[terminalTool] || rawOutput[terminalTool].length === 0) && (
                  <span className="text-zinc-600 animate-pulse block">Starting {terminalTool}, waiting for first output...</span>
                )}
                {terminalTool && rawOutput[terminalTool]?.length > 0
                  ? rawOutput[terminalTool].map((line, i) => (
                      <span key={i} className={cn(
                        "block",
                        // Gobuster findings
                        line.match(/Status:\s*200/) ? 'text-green-400 font-semibold' :
                        line.match(/Status:\s*20[1-9]/) ? 'text-green-300' :
                        line.match(/Status:\s*301|Status:\s*302/) ? 'text-yellow-400' :
                        line.match(/Status:\s*401|Status:\s*403/) ? 'text-orange-400' :
                        line.match(/Status:\s*[45]\d\d/) ? 'text-red-400' :
                        // Error patterns
                        line.toLowerCase().includes('error') || line.includes('[ERR]') ? 'text-red-400' :
                        line.toLowerCase().includes('warning') || line.includes('[WRN]') || line.includes('Failed') ? 'text-yellow-400' :
                        // Info / progress
                        line.includes('[INF]') || line.startsWith('===============') ? 'text-zinc-500' :
                        // Nmap
                        line.match(/\d+\/tcp\s+open/) ? 'text-green-400 font-semibold' :
                        line.includes('Nmap scan report') ? 'text-blue-400 font-semibold' :
                        // JSON (nuclei)
                        line.startsWith('{') ? 'text-cyan-400' :
                        'text-zinc-300'
                      )}>{line}</span>
                    ))
                  : !activeScans.has(terminalTool) && (
                    <span className="text-zinc-700">
                      {terminalTool
                        ? `No output from ${terminalTool}. If the tool failed to start, the issue may be an incorrect parameter — check the wordlist and options.`
                        : 'Select a tool above to view its output.'}
                    </span>
                  )
                }
              </pre>
            </div>
          )}

          {/* Severity summary bar */}
          {viewMode !== 'terminal' && findings.length > 0 && (
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800">
              <span className="text-[10px] text-zinc-600 shrink-0">Findings:</span>
              {[
                { key: 'critical', label: 'Critical', color: 'bg-red-950/70 text-red-400 border-red-800' },
                { key: 'high', label: 'High', color: 'bg-orange-950/70 text-orange-400 border-orange-800' },
                { key: 'medium', label: 'Medium', color: 'bg-yellow-950/70 text-yellow-400 border-yellow-800' },
                { key: 'low', label: 'Low', color: 'bg-blue-950/70 text-blue-400 border-blue-800' },
                { key: 'info', label: 'Info', color: 'bg-zinc-800 text-zinc-400 border-zinc-700' },
              ].map(({ key, label, color }) => severityCounts[key] ? (
                <span key={key} className={cn("text-[10px] px-2 py-0.5 rounded border font-medium", color)}>
                  {severityCounts[key]} {label}
                </span>
              ) : null)}
              <span className="ml-auto text-[10px] text-zinc-600">{findings.length} total</span>
            </div>
          )}

          {/* Finding detail panel + table split */}
          {viewMode !== 'terminal' && <div className="flex-1 flex gap-3 min-h-0">
            {/* Findings table */}
            <div className={cn("overflow-auto rounded-lg border border-zinc-800", selectedFinding ? "flex-1" : "flex-1")}>
              <table className="w-full text-xs">
                <thead className="bg-zinc-900 sticky top-0 z-10">
                  <tr className="text-zinc-500 text-left">
                    <th className="px-3 py-2 w-8">#</th>
                    <th className="px-3 py-2 w-20">Severity</th>
                    <th className="px-3 py-2">Title</th>
                    <th className="px-3 py-2 w-24">Tool</th>
                    <th className="px-3 py-2 w-24">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {displayedFindings.map((f, i) => (
                    <tr
                      key={f.id ?? i}
                      onClick={() => setSelectedFinding(selectedFinding?.id === f.id ? null : f)}
                      onContextMenu={e => { setCtxFinding(f); setCtxMenu(menuFromEvent(e)) }}
                      className={cn(
                        "border-b border-zinc-800/50 cursor-pointer transition-colors",
                        selectedFinding?.id === f.id ? "bg-zinc-800" : "hover:bg-zinc-800/40"
                      )}
                    >
                      <td className="px-3 py-1.5 text-zinc-600">{i + 1}</td>
                      <td className="px-3 py-1.5">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="px-3 py-1.5 text-zinc-300 truncate max-w-[280px]">{f.title}</td>
                      <td className="px-3 py-1.5">
                        <span className="text-[10px] text-zinc-500 font-mono bg-zinc-900 px-1.5 py-0.5 rounded border border-zinc-800">
                          {f.tool}
                        </span>
                      </td>
                      <td className="px-3 py-1.5">
                        <Badge variant="outline" className="text-[10px]">{f.status}</Badge>
                      </td>
                    </tr>
                  ))}
                  {displayedFindings.length === 0 && (
                    <tr>
                      <td colSpan={5} className="px-3 py-12 text-center text-zinc-600">
                        {viewMode === 'all'
                          ? 'No findings yet. Select a target and run a scan.'
                          : `No findings from ${viewMode} yet.`}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Finding detail side panel */}
            {selectedFinding && (
              <div className="w-72 shrink-0 rounded-lg border border-zinc-800 bg-zinc-900/50 p-4 overflow-y-auto text-xs space-y-3">
                <div className="flex items-start justify-between gap-2">
                  <h3 className="font-semibold text-zinc-200 leading-tight">{selectedFinding.title}</h3>
                  <button onClick={() => setSelectedFinding(null)} className="text-zinc-600 hover:text-zinc-400 shrink-0">✕</button>
                </div>

                <div className="space-y-2">
                  <DetailRow label="Severity"><SeverityBadge severity={selectedFinding.severity} /></DetailRow>
                  <DetailRow label="Tool"><span className="font-mono text-zinc-400">{selectedFinding.tool}</span></DetailRow>
                  {selectedFinding.url && (
                    <DetailRow label="URL">
                      <span className="font-mono text-blue-400 break-all">{selectedFinding.url}</span>
                    </DetailRow>
                  )}
                  {selectedFinding.parameter && (
                    <DetailRow label="Param"><span className="font-mono text-yellow-400">{selectedFinding.parameter}</span></DetailRow>
                  )}
                  {selectedFinding.template_id && (
                    <DetailRow label="Template"><span className="font-mono text-zinc-400">{selectedFinding.template_id}</span></DetailRow>
                  )}
                  {selectedFinding.description && (
                    <div>
                      <div className="text-zinc-600 mb-1">Description</div>
                      <div className="text-zinc-400 leading-relaxed">{selectedFinding.description}</div>
                    </div>
                  )}
                  {selectedFinding.evidence && (
                    <div>
                      <div className="text-zinc-600 mb-1">Evidence</div>
                      <pre className="text-zinc-400 bg-zinc-950 rounded p-2 overflow-auto text-[10px] leading-relaxed whitespace-pre-wrap break-all">
                        {selectedFinding.evidence}
                      </pre>
                    </div>
                  )}
                  <DetailRow label="Status">
                    <Badge variant="outline" className="text-[10px]">{selectedFinding.status}</Badge>
                  </DetailRow>
                </div>
              </div>
            )}
          </div>}
        </div>
      </div>

      {/* Finding context menu */}
      <ContextMenu
        state={ctxMenu}
        onClose={() => setCtxMenu(s => ({ ...s, visible: false }))}
        items={[
          {
            label: 'Send to Workspace',
            icon: <BookOpen size={12} />,
            onClick: () => {
              if (ctxFinding) {
                addToWorkspace(ctxFinding)
                navigate('/workspace')
              }
            },
          },
          {
            label: 'Analyze with AI',
            icon: <Sparkles size={12} />,
            onClick: () => {
              if (ctxFinding) {
                addToWorkspace(ctxFinding)
                navigate('/workspace')
              }
            },
          },
          { separator: true },
          {
            label: 'Select finding',
            onClick: () => { if (ctxFinding) setSelectedFinding(ctxFinding) },
          },
        ]}
      />

      {/* Nuclei Template Browser Modal */}
      {nucleiTemplateOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
          onClick={() => setNucleiTemplateOpen(false)}
        >
          <div
            className="w-full max-w-lg max-h-[80vh] flex flex-col rounded-xl border border-zinc-700 bg-zinc-950 shadow-2xl overflow-hidden"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-5 py-3 border-b border-zinc-800 bg-zinc-900 shrink-0">
              <span className="text-sm font-semibold text-zinc-100">Nuclei Template Browser</span>
              <button onClick={() => setNucleiTemplateOpen(false)} className="text-zinc-600 hover:text-zinc-300">
                <X size={14} />
              </button>
            </div>
            <div className="overflow-y-auto p-4">
              {!nucleiTemplatesLoaded ? (
                <div className="flex items-center gap-2 text-xs text-zinc-500 py-4">
                  <Loader2 size={13} className="animate-spin" /> Loading templates...
                </div>
              ) : nucleiTemplates.length === 0 ? (
                <p className="text-xs text-zinc-600 py-4">
                  Templates not found at ~/nuclei-templates/http/. Run <code className="text-green-400">nuclei -update-templates</code> first.
                </p>
              ) : (
                <div className="space-y-1">
                  <p className="text-[10px] text-zinc-600 mb-3">Click a category to use it as a custom template path in the options panel.</p>
                  {nucleiTemplates.map(t => (
                    <button
                      key={t.name}
                      onClick={() => {
                        setOption('nuclei', 'templates', t.path)
                        setNucleiPreset('')
                        setNucleiTemplateOpen(false)
                      }}
                      className="w-full flex items-center justify-between px-3 py-2 rounded border border-zinc-800 hover:border-zinc-600 hover:bg-zinc-800/50 transition-colors text-left"
                    >
                      <span className="text-xs text-zinc-300 font-mono">{t.name}</span>
                      <span className="text-[10px] text-zinc-600">{t.count} templates</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Nuclei Guide Modal */}
      {nucleiGuideOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
          onClick={() => setNucleiGuideOpen(false)}
        >
          <div
            className="w-full max-w-3xl max-h-[90vh] flex flex-col rounded-xl border border-zinc-700 bg-zinc-950 shadow-2xl overflow-hidden"
            onClick={e => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex items-center justify-between px-5 py-3 border-b border-zinc-800 bg-zinc-900 shrink-0">
              <div className="flex items-center gap-2">
                <Shield size={15} className="text-red-400" />
                <span className="text-sm font-semibold text-zinc-100">Nuclei — Usage Guide & Tips</span>
                <span className="text-[10px] text-zinc-600 ml-1">Bug Bounty Edition</span>
              </div>
              <button onClick={() => setNucleiGuideOpen(false)} className="text-zinc-600 hover:text-zinc-300 transition-colors">
                <X size={15} />
              </button>
            </div>

            <div className="overflow-y-auto p-5 space-y-6 text-xs text-zinc-300">

              {/* What is Nuclei */}
              <section className="space-y-2">
                <h2 className="text-sm font-bold text-zinc-100 flex items-center gap-2"><Zap size={13} className="text-yellow-400" />What is Nuclei?</h2>
                <p className="text-zinc-400 leading-relaxed">
                  Nuclei is a YAML template-based vulnerability scanner. Each template defines how to detect a specific vulnerability: which request to send, what response to expect, and how to classify the result. The official repository has over 9,000 templates.
                </p>
                <div className="grid grid-cols-3 gap-2 mt-2">
                  {[
                    { label: 'Templates', value: '9,000+', color: 'text-green-400' },
                    { label: 'Speed', value: 'High (Go)', color: 'text-blue-400' },
                    { label: 'Output format', value: 'JSONL', color: 'text-purple-400' },
                  ].map(s => (
                    <div key={s.label} className="rounded-lg border border-zinc-800 bg-zinc-900 p-2.5 text-center">
                      <div className={`text-base font-bold ${s.color}`}>{s.value}</div>
                      <div className="text-[10px] text-zinc-600 mt-0.5">{s.label}</div>
                    </div>
                  ))}
                </div>
              </section>

              {/* Recommended workflow */}
              <section className="space-y-2">
                <h2 className="text-sm font-bold text-zinc-100 flex items-center gap-2"><CheckCircle2 size={13} className="text-green-400" />Recommended Bug Bounty Workflow</h2>
                <ol className="space-y-1.5">
                  {[
                    { n: '1', text: 'Complete recon first (Recon page) — get all live subdomains with HTTPX' },
                    { n: '2', text: 'Use "Scan all with Nuclei" from the Live Hosts tab in Recon for a Default scan across all hosts' },
                    { n: '3', text: 'Review findings — click high/critical severity items first' },
                    { n: '4', text: 'For specific interesting hosts: run targeted scans (CORS, SSRF, XSS) with the selected target' },
                    { n: '5', text: 'Send interesting findings to Workspace (right-click) and analyze with AI' },
                  ].map(s => (
                    <li key={s.n} className="flex gap-2.5">
                      <span className="shrink-0 w-5 h-5 rounded-full bg-zinc-800 text-zinc-400 text-[10px] flex items-center justify-center font-bold">{s.n}</span>
                      <span className="text-zinc-400 leading-relaxed">{s.text}</span>
                    </li>
                  ))}
                </ol>
              </section>

              {/* Scan types */}
              <section className="space-y-2">
                <h2 className="text-sm font-bold text-zinc-100 flex items-center gap-2"><Shield size={13} className="text-red-400" />Scan Types Guide</h2>
                <div className="space-y-3">
                  {[
                    {
                      label: '🔍 Default', color: 'border-zinc-700',
                      desc: 'Detects technologies, exposed files, and common misconfigs. Ideal as the first scan on any target. Fast and low-noise.',
                      tip: 'Always start here. In bug bounty ~30% of findings come from exposures (.env files, backups, .git, etc.)',
                    },
                    {
                      label: '💥 CVEs', color: 'border-red-900',
                      desc: 'Checks if the target is vulnerable to known CVEs. Very valuable when you identify specific technologies (WordPress, Apache, etc.).',
                      tip: 'Run Default first to detect technologies, then CVEs on hosts with an identified tech stack. Can be slow.',
                    },
                    {
                      label: '🔓 CORS', color: 'border-yellow-900',
                      desc: 'Tests 29 Origin header variations (arbitrary domains, null, subdomain bypass, regex abuse). Detects CORS misconfiguration with credentials.',
                      tip: 'CORS + cookies = P2/P3. If you see Access-Control-Allow-Origin: [your origin] + Allow-Credentials: true → critical. Verify manually in the browser.',
                    },
                    {
                      label: '🎯 SSRF', color: 'border-orange-900',
                      desc: 'Detects Server-Side Request Forgery and open redirects. Uses interactsh for out-of-band detection.',
                      tip: 'Cloud SSRF can reach the metadata service (169.254.169.254) → AWS credentials. Always try to escalate to RCE or IMDS.',
                    },
                    {
                      label: '⚡ XSS', color: 'border-pink-900',
                      desc: 'Templates for detecting reflected and stored XSS. Limited compared to dedicated tools like Dalfox.',
                      tip: 'For deep XSS use Dalfox. Nuclei is good for quick detection. XSS findings require manual verification in the browser.',
                    },
                    {
                      label: '🗄️ SQL Injection', color: 'border-red-900',
                      desc: 'Detects error-based SQLi and some blind patterns. Limited — use SQLMap for full analysis.',
                      tip: 'If Nuclei finds SQLi, run SQLMap on that endpoint. Nuclei gives the lead, SQLMap exploits it.',
                    },
                    {
                      label: '🔑 JWT', color: 'border-yellow-900',
                      desc: 'Detects JWT tokens with alg:none, weak secrets (HS256 with "secret"), and common misconfigs.',
                      tip: 'If you see JWTs in proxy requests, send them to Workspace and ask AI for JWT analysis.',
                    },
                    {
                      label: '🌐 Full OWASP', color: 'border-purple-900',
                      desc: 'Combines tags from all OWASP Top 10 categories. Complete but slow scan. Ideal for programs with wide scope.',
                      tip: 'Reserve for targets with good scope. Can take 10-30 minutes per host. Reduce rate limit if the target is sensitive.',
                    },
                    {
                      label: '☁️ Cloud', color: 'border-blue-900',
                      desc: 'Detects misconfigs in AWS S3, GCP Storage, Azure. Public buckets, exposed keys, SSRF toward metadata.',
                      tip: 'In large company programs always look for exposed cloud infrastructure. A public S3 bucket can be P1.',
                    },
                  ].map(s => (
                    <div key={s.label} className={`rounded-lg border ${s.color} bg-zinc-900/50 p-3 space-y-1.5`}>
                      <div className="font-semibold text-zinc-200">{s.label}</div>
                      <div className="text-zinc-400 leading-relaxed">{s.desc}</div>
                      <div className="flex gap-1.5 items-start">
                        <span className="text-yellow-500 text-[10px] shrink-0 mt-0.5">💡 Tip:</span>
                        <span className="text-zinc-500 text-[10px] leading-relaxed">{s.tip}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              {/* Advanced options */}
              <section className="space-y-2">
                <h2 className="text-sm font-bold text-zinc-100 flex items-center gap-2"><Settings2 size={13} className="text-zinc-400" />Advanced Options</h2>
                <div className="space-y-2">
                  {[
                    { opt: 'Proxy', val: 'http://127.0.0.1:8080', desc: 'Route all Nuclei traffic through BurpSuite. Useful for seeing exactly which requests it sends and modifying them.' },
                    { opt: 'Headers', val: 'Authorization: Bearer TOKEN', desc: 'Custom headers. Use when the target requires authentication. Format: "Header: Value" (one per line or comma-separated).' },
                    { opt: 'Rate limit', val: '50 (default: 100)', desc: 'Requests per second. Lower for sensitive targets or aggressive WAFs. Raise on private networks for speed.' },
                    { opt: 'Concurrency', val: '10 (default: 25)', desc: 'Templates running in parallel. Reduce if there are timeouts or false negatives due to saturation.' },
                    { opt: 'Req timeout', val: '30', desc: 'Seconds to wait per request. Increase for slow targets or when using OAST (OOB).' },
                    { opt: 'Severity', val: 'high,critical', desc: 'Filter by severity. For quick high-impact recon: "high,critical". For full coverage: empty (all).' },
                    { opt: 'Exclude tags', val: 'dos,fuzz', desc: 'Always exclude "dos" to avoid sending destructive payloads. "fuzz" avoids high-load requests.' },
                  ].map(o => (
                    <div key={o.opt} className="flex gap-3 items-start rounded-lg border border-zinc-800 bg-zinc-900/50 px-3 py-2">
                      <div className="shrink-0 w-24">
                        <div className="text-zinc-200 font-medium text-[11px]">{o.opt}</div>
                        <code className="text-[9px] text-green-400 font-mono">{o.val}</code>
                      </div>
                      <div className="text-zinc-500 text-[10px] leading-relaxed">{o.desc}</div>
                    </div>
                  ))}
                </div>
              </section>

              {/* Interpreting results */}
              <section className="space-y-2">
                <h2 className="text-sm font-bold text-zinc-100 flex items-center gap-2"><Bug size={13} className="text-orange-400" />Interpreting Results</h2>
                <div className="space-y-1.5">
                  {[
                    { sev: 'critical', color: 'bg-red-950/60 text-red-400 border-red-800', msg: 'Confirmed RCE, SQLi, exposed credentials. Report immediately. Verify manually before reporting.' },
                    { sev: 'high', color: 'bg-orange-950/60 text-orange-400 border-orange-800', msg: 'Exploitable CVEs, SSRF, IDOR with impact. Always verify — some are false positives.' },
                    { sev: 'medium', color: 'bg-yellow-950/60 text-yellow-400 border-yellow-800', msg: 'CORS, weak JWT, XSS without context. Check if there is a way to escalate impact before reporting.' },
                    { sev: 'low', color: 'bg-blue-950/60 text-blue-400 border-blue-800', msg: 'Missing headers, minor info disclosure. Useful for report completion but rarely paid on their own.' },
                    { sev: 'info', color: 'bg-zinc-800 text-zinc-400 border-zinc-700', msg: 'Detected technologies, found endpoints. Use as a map for targeted attacks, not as a standalone finding.' },
                  ].map(r => (
                    <div key={r.sev} className="flex gap-3 items-start">
                      <span className={`shrink-0 text-[10px] px-1.5 py-0.5 rounded border font-medium capitalize ${r.color}`}>{r.sev}</span>
                      <span className="text-zinc-500 text-[10px] leading-relaxed">{r.msg}</span>
                    </div>
                  ))}
                </div>
              </section>

              {/* Key tips */}
              <section className="space-y-2">
                <h2 className="text-sm font-bold text-zinc-100 flex items-center gap-2"><AlertTriangle size={13} className="text-yellow-400" />Key Tips</h2>
                <div className="space-y-1.5">
                  {[
                    '⚡ Nuclei does not replace manual review — it is a first filter. Many findings need confirmation.',
                    '🔍 "info" technology findings are gold: use them to look for CVEs specific to that version.',
                    '📡 For OAST (out-of-band) you need an interactsh server or Burp Collaborator. Enable interactsh by removing -ni from options.',
                    '⚠️ Rate limit: never exceed 150 req/s on production targets. A WAF may block your IP.',
                    '🔑 If the target requires login, configure cookies/tokens in the Headers field before running.',
                    '📋 CVE templates are most reliable — they have exact matchers. Injection templates (XSS, SQLi) have more false positives.',
                    '🎯 For Bug Bounty: Default scan first on all hosts, then targeted scans on the most interesting ones.',
                    '💾 Always send findings to Workspace and analyze with AI to find ways to escalate impact.',
                  ].map((tip, i) => (
                    <div key={i} className="text-zinc-400 text-[10px] leading-relaxed pl-2 border-l border-zinc-800">
                      {tip}
                    </div>
                  ))}
                </div>
              </section>

            </div>

            <div className="shrink-0 px-5 py-3 border-t border-zinc-800 bg-zinc-900 flex justify-end">
              <button
                onClick={() => setNucleiGuideOpen(false)}
                className="px-4 py-1.5 rounded text-xs border border-zinc-700 text-zinc-400 hover:text-zinc-200 hover:border-zinc-500 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </WorkspaceShell>
  )
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-950/60 text-red-400 border-red-800',
    high: 'bg-orange-950/60 text-orange-400 border-orange-800',
    medium: 'bg-yellow-950/60 text-yellow-400 border-yellow-800',
    low: 'bg-blue-950/60 text-blue-400 border-blue-800',
    info: 'bg-zinc-800 text-zinc-400 border-zinc-700',
  }
  return (
    <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-medium capitalize", colors[severity] ?? colors.info)}>
      {severity}
    </span>
  )
}

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2">
      <span className="text-zinc-600 w-16 shrink-0">{label}</span>
      <div className="flex-1">{children}</div>
    </div>
  )
}

const WORDLIST_PRESETS = [
  { label: 'DirBuster medium (220k) ★', value: '/home/kali/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt' },
  { label: 'SecLists common (4.7k)', value: '/usr/share/seclists/Discovery/Web-Content/common.txt' },
  { label: 'SecLists big (20k)', value: '/usr/share/seclists/Discovery/Web-Content/big.txt' },
  { label: 'SecLists raft-medium dirs (30k)', value: '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt' },
  { label: 'SecLists raft-large dirs (62k)', value: '/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt' },
  { label: 'dirb common (4.6k)', value: '/usr/share/wordlists/dirb/common.txt' },
  { label: 'dirbuster medium (220k)', value: '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt' },
]

function WordlistSelect({ label, value, onChange }: {
  label: string; value: string; onChange: (v: string) => void
}) {
  const isPreset = WORDLIST_PRESETS.some(p => p.value === value)
  const [showCustom, setShowCustom] = useState(!isPreset)

  return (
    <div className="flex items-start gap-2">
      <span className="text-[10px] text-zinc-600 w-14 shrink-0 text-right mt-1">{label}:</span>
      <div className="flex-1 space-y-1">
        <select
          value={showCustom ? '__custom__' : (value || WORDLIST_PRESETS[0].value)}
          onChange={e => {
            if (e.target.value === '__custom__') {
              setShowCustom(true)
              onChange('')
            } else {
              setShowCustom(false)
              onChange(e.target.value)
            }
          }}
          className="w-full text-[10px] bg-zinc-900 border border-zinc-800 rounded px-2 py-0.5 text-zinc-400 focus:outline-none focus:border-zinc-600"
        >
          {WORDLIST_PRESETS.map(p => (
            <option key={p.value} value={p.value}>{p.label}</option>
          ))}
          <option value="__custom__">Custom path...</option>
        </select>
        {showCustom && (
          <input
            type="text"
            placeholder="/path/to/wordlist.txt"
            value={value}
            onChange={e => onChange(e.target.value)}
            className="w-full text-[10px] bg-zinc-900 border border-zinc-800 rounded px-2 py-0.5 text-zinc-400 placeholder:text-zinc-700 focus:outline-none focus:border-zinc-600"
          />
        )}
      </div>
    </div>
  )
}

function OptionInput({ label, placeholder, value, onChange }: {
  label: string; placeholder?: string; value: string; onChange: (v: string) => void
}) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-[10px] text-zinc-600 w-14 shrink-0 text-right">{label}:</span>
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
