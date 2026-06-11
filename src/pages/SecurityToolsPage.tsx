import { useState, useRef, useEffect } from 'react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { Input } from '@/components/ui/input'
import { api } from '@/api/http-client'
import { toast } from '@/stores/toast-store'
import { useScannerStore } from '@/stores/scanner-store'
import { useReconStore } from '@/stores/recon-store'
import { useAppStore } from '@/stores/app-store'
import { cn } from '@/lib/utils'
import {
  Play, Square, Loader2, Terminal, Copy, Check,
  Globe, Lock, Cloud, GitBranch, Radio, Info, X, BookOpen, Sparkles,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useWorkspaceStore } from '@/stores/workspace-store'
import type { Finding } from '@/types'

type ToolId = 'cors' | 'bypass_403' | 'cloud_buckets' | 'github_scanner' | 'interactsh'
type ViewMode = 'findings' | 'terminal'

interface ToolDef {
  id: ToolId
  label: string
  icon: React.ComponentType<{ size?: number; className?: string }>
  tagline: string
  desc: string
  inputLabel: string
  placeholder: string
  color: string
  border: string
  bg: string
  endpoint: string
}

const TOOLS: ToolDef[] = [
  {
    id: 'cors',
    label: 'CORS Scanner',
    icon: Globe,
    tagline: '6 origin bypass tests per target',
    desc: 'Tests cross-origin resource sharing misconfigurations. Sends 6 probes per target: arbitrary origin reflection, null origin, trusted subdomain bypass, prefix bypass (evil.target.com), and HTTP downgrade. A critical finding means any website can read credentialed API responses from this origin.',
    inputLabel: 'Target URL',
    placeholder: 'https://api.target.com',
    color: 'text-yellow-400',
    border: 'border-yellow-500/30',
    bg: 'bg-yellow-950/15',
    endpoint: '/api/tools/cors',
  },
  {
    id: 'bypass_403',
    label: '403/401 Bypass',
    icon: Lock,
    tagline: '19 bypass techniques — path tricks + header injections',
    desc: 'Attempts to reach a 403/401-protected endpoint using path encoding tricks (/%2f, /;/, /..;/) and HTTP header injections (X-Forwarded-For: 127.0.0.1, X-Original-URL, X-Rewrite-URL, Referer, X-Host). Reports any probe that returns a 200 or 302 as a potential bypass.',
    inputLabel: 'Protected URL (returns 403/401)',
    placeholder: 'https://target.com/admin',
    color: 'text-orange-400',
    border: 'border-orange-500/30',
    bg: 'bg-orange-950/15',
    endpoint: '/api/tools/bypass-403',
  },
  {
    id: 'cloud_buckets',
    label: 'Cloud Buckets',
    icon: Cloud,
    tagline: '~40 name variants across AWS S3, GCS, Azure',
    desc: 'Brute-forces cloud storage bucket names derived from a company name or domain. Tests ~40 variations (acme, acme-prod, acme-backup, acme-data...) across AWS S3, Google Cloud Storage, and Azure Blob Storage. A 200 means the bucket is publicly readable — list its contents with "aws s3 ls s3://BUCKET --no-sign-request".',
    inputLabel: 'Company name or domain',
    placeholder: 'acme-corp or acme.com',
    color: 'text-blue-400',
    border: 'border-blue-500/30',
    bg: 'bg-blue-950/15',
    endpoint: '/api/tools/cloud-buckets',
  },
  {
    id: 'github_scanner',
    label: 'GitHub Secrets',
    icon: GitBranch,
    tagline: 'TruffleHog secret scanner for orgs and repos',
    desc: 'Scans GitHub organizations or repositories for leaked secrets using TruffleHog. Detects API keys, tokens, passwords, and private keys in commit history, branches, and PRs. Enter a GitHub org name (e.g. "acme-corp") or a full repo URL (e.g. "https://github.com/acme/api"). Verified secrets are confirmed active via the issuing API. Requires trufflehog.',
    inputLabel: 'GitHub org name or repo URL',
    placeholder: 'acme-corp  or  https://github.com/acme/repo',
    color: 'text-purple-400',
    border: 'border-purple-500/30',
    bg: 'bg-purple-950/15',
    endpoint: '/api/tools/github',
  },
  {
    id: 'interactsh',
    label: 'OOB / Interactsh',
    icon: Radio,
    tagline: 'Out-of-band listener for blind SSRF, XSS, XXE',
    desc: 'Starts an out-of-band interaction server via interactsh-client. Generates a unique hostname you can embed in SSRF payloads (http://HOST/), blind XSS (<img src="http://HOST">), XXE (<!ENTITY e SYSTEM "http://HOST">), and command injection ($(nslookup HOST)). Any DNS or HTTP callback appears here in real time. Requires interactsh-client installed.',
    inputLabel: 'Target context (optional)',
    placeholder: 'https://target.com (optional, for context)',
    color: 'text-green-400',
    border: 'border-green-500/30',
    bg: 'bg-green-950/15',
    endpoint: '/api/tools/interactsh',
  },
]

const SEV_COLORS: Record<string, string> = {
  critical: 'bg-red-950/60 text-red-400 border-red-800',
  high:     'bg-orange-950/60 text-orange-400 border-orange-800',
  medium:   'bg-yellow-950/60 text-yellow-400 border-yellow-800',
  low:      'bg-blue-950/60 text-blue-400 border-blue-800',
  info:     'bg-zinc-800 text-zinc-400 border-zinc-700',
}

function SevBadge({ severity }: { severity: string }) {
  return (
    <span className={cn('text-[10px] px-1.5 py-0.5 rounded border font-medium capitalize shrink-0', SEV_COLORS[severity] ?? SEV_COLORS.info)}>
      {severity}
    </span>
  )
}

// binary name → ToolId (for install checking)
const TOOL_BINARY: Partial<Record<ToolId, string>> = {
  github_scanner: 'trufflehog',
  interactsh: 'interactsh-client',
}

export function SecurityToolsPage() {
  const [activeTab, setActiveTab] = useState<ToolId>('cors')
  const [targets, setTargets] = useState<Record<ToolId, string>>({
    cors: '', bypass_403: '', cloud_buckets: '', github_scanner: '', interactsh: '',
  })
  const [view, setView] = useState<ViewMode>('findings')
  const [selected, setSelected] = useState<Finding | null>(null)
  const [copied, setCopied] = useState(false)
  const [guideOpen, setGuideOpen] = useState(false)
  const [notInstalled, setNotInstalled] = useState<Set<string>>(new Set())
  const termRef = useRef<HTMLPreElement>(null)
  const navigate = useNavigate()

  const { activeProject, globalTarget, getSessionOpts } = useAppStore()
  const { findings, rawOutput, activeScans, activeJobIds } = useScannerStore()
  const { liveHosts } = useReconStore()
  const { addFinding: addToWorkspace } = useWorkspaceStore()

  // Check which tools are installed once on mount
  useEffect(() => {
    api.get<{ installed: Record<string, boolean> }>('/api/tools/check-installed')
      .then(res => {
        const missing = new Set<string>()
        Object.entries(res.installed).forEach(([bin, ok]) => {
          if (!ok) missing.add(bin)
        })
        setNotInstalled(missing)
      })
      .catch(() => {})
  }, [])

  // Auto-fill target from global store when tab changes
  useEffect(() => {
    if (globalTarget && !targets[activeTab]) {
      setTargets(prev => ({ ...prev, [activeTab]: globalTarget }))
    }
  }, [activeTab, globalTarget])

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight
  }, [rawOutput[activeTab]])

  const tabFindings = findings.filter(f => f.tool === activeTab)
  const tabOutput = rawOutput[activeTab] ?? []
  const isRunning = activeScans.has(activeTab)
  const jobId = activeJobIds[activeTab]

  // OOB host extracted from interactsh findings
  const oobHost = findings.find(f => f.tool === 'interactsh' && f.template_id === 'interactsh-host')?.url?.replace('http://', '') ?? ''

  const tool = TOOLS.find(t => t.id === activeTab)!

  const handleRun = async () => {
    const target = targets[activeTab].trim()
    if (!target && activeTab !== 'interactsh') {
      toast.error('Enter a target first', null)
      return
    }
    try {
      await api.post(tool.endpoint, { target, options: getSessionOpts(), project_id: activeProject ?? '' })
    } catch (err) {
      toast.error(`Failed to start ${tool.label}`, err)
    }
  }

  const handleStop = async () => {
    if (!jobId) return
    try { await api.delete(`/api/tools/jobs/${jobId}`) } catch {}
  }

  const handleCorsBulk = async () => {
    const targets = liveHosts.map(h => h.url).filter(Boolean)
    if (targets.length === 0) {
      toast.error('No live hosts', 'Run HTTPX on the Recon page first to populate live hosts.')
      return
    }
    try {
      const res = await api.post<{ count: number }>('/api/tools/cors-bulk', {
        targets,
        options: getSessionOpts(),
        project_id: activeProject ?? '',
      })
      toast.success(`CORS scan started`, `Running on ${res.count} live hosts`)
    } catch (err) {
      toast.error('Failed to start bulk CORS scan', err)
    }
  }

  const copy = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  const hostForUrl = (url: string | null | undefined) => {
    if (!url) return '-'
    try { return new URL(url.startsWith('http') ? url : `https://${url}`).hostname }
    catch { return url.slice(0, 30) }
  }

  return (
    <WorkspaceShell title="Security Tools" subtitle="CORS, 403 bypass, cloud buckets, GitHub secrets, OOB testing">
      <div className="flex gap-4 h-full min-h-0">

        {/* LEFT: Tool selector */}
        <div className="w-52 shrink-0 flex flex-col gap-1.5 overflow-y-auto pr-1">
          <div className="text-[9px] text-zinc-700 uppercase tracking-widest px-1 pb-1">Tools</div>
          {TOOLS.map(t => {
            const Icon = t.icon
            const running = activeScans.has(t.id)
            const count = findings.filter(f => f.tool === t.id).length
            const active = activeTab === t.id
            return (
              <button
                key={t.id}
                onClick={() => { setActiveTab(t.id); setSelected(null) }}
                className={cn(
                  'text-left px-3 py-2.5 rounded-lg border transition-colors',
                  active ? `${t.border} ${t.bg}` : 'border-zinc-800 hover:border-zinc-700 hover:bg-zinc-800/30'
                )}
              >
                <div className="flex items-center gap-2">
                  <Icon size={13} className={active ? t.color : 'text-zinc-600'} />
                  <span className={cn('text-xs font-medium flex-1', active ? t.color : 'text-zinc-400')}>
                    {t.label}
                  </span>
                  {running && <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse shrink-0" />}
                  {count > 0 && !running && (
                    <span className="text-[9px] px-1 rounded bg-zinc-800 text-zinc-500">{count}</span>
                  )}
                </div>
                {active && (
                  <p className="text-[10px] text-zinc-600 mt-1 leading-relaxed">{t.tagline}</p>
                )}
              </button>
            )
          })}
        </div>

        {/* RIGHT: Main panel */}
        <div className="flex-1 flex flex-col gap-3 min-h-0 min-w-0">

          {/* Tool header */}
          <div className={cn('rounded-lg border p-3 space-y-2.5', tool.border, tool.bg)}>
            {TOOL_BINARY[activeTab] && notInstalled.has(TOOL_BINARY[activeTab]!) && (
              <div className="flex items-start gap-2 rounded border border-orange-700/50 bg-orange-950/20 px-3 py-2 text-[11px] text-orange-300">
                <span className="shrink-0 font-bold">!</span>
                <span>
                  <span className="font-semibold font-mono">{TOOL_BINARY[activeTab]}</span> is not installed.
                  Running will fail until it is. Install:
                  {activeTab === 'github_scanner' && <code className="block mt-1 text-zinc-400 font-mono">curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin</code>}
                  {activeTab === 'interactsh' && <code className="block mt-1 text-zinc-400 font-mono">go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest</code>}
                </span>
              </div>
            )}
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <tool.icon size={15} className={tool.color} />
                <span className={cn('text-sm font-semibold', tool.color)}>{tool.label}</span>
              </div>
              <button
                onClick={() => setGuideOpen(true)}
                className="flex items-center gap-1 text-[10px] text-zinc-600 hover:text-zinc-400 transition-colors shrink-0"
              >
                <Info size={11} /> Guide
              </button>
            </div>
            <p className="text-[11px] text-zinc-500 leading-relaxed">{tool.desc}</p>

            {/* Input + buttons */}
            <div className="flex gap-2">
              <Input
                value={targets[activeTab]}
                onChange={e => setTargets(prev => ({ ...prev, [activeTab]: e.target.value }))}
                placeholder={tool.placeholder}
                className="bg-zinc-900/80 text-sm flex-1"
                onKeyDown={e => { if (e.key === 'Enter' && !isRunning) handleRun() }}
              />
              {isRunning ? (
                <button
                  onClick={handleStop}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-red-700 text-red-400 hover:bg-red-950/30 transition-colors shrink-0"
                >
                  <Square size={11} className="fill-current" /> Stop
                </button>
              ) : (
                <button
                  onClick={handleRun}
                  disabled={!targets[activeTab].trim() && activeTab !== 'interactsh'}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-green-700/70 text-green-400 hover:bg-green-950/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors shrink-0"
                >
                  <Play size={11} /> Run
                </button>
              )}
            </div>

            {/* CORS: bulk scan all live hosts */}
            {activeTab === 'cors' && (
              <button
                onClick={handleCorsBulk}
                disabled={isRunning || liveHosts.length === 0}
                className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 text-[11px] font-medium rounded-md border border-yellow-700/50 text-yellow-400/80 hover:bg-yellow-950/20 hover:text-yellow-300 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                <Globe size={11} />
                Scan all live hosts ({liveHosts.length})
              </button>
            )}

            {/* OOB host display */}
            {activeTab === 'interactsh' && oobHost && (
              <div className="flex items-center gap-2 p-2 rounded-md bg-green-950/30 border border-green-700/40">
                <span className="text-[10px] text-green-300 font-mono flex-1 truncate">{oobHost}</span>
                <button
                  onClick={() => copy(oobHost)}
                  className="flex items-center gap-1 text-[10px] text-green-400 hover:text-green-200 shrink-0"
                >
                  {copied ? <Check size={11} /> : <Copy size={11} />}
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
            )}

            {/* Cloud: provider tags */}
            {activeTab === 'cloud_buckets' && (
              <div className="flex gap-1.5 items-center">
                <span className="text-[9px] text-zinc-600">Providers:</span>
                {['AWS S3', 'GCS', 'Azure'].map(p => (
                  <span key={p} className="text-[9px] px-1.5 py-0.5 rounded border border-blue-700/50 text-blue-400/80">{p}</span>
                ))}
              </div>
            )}
          </div>

          {/* View tabs */}
          <div className="flex gap-1 bg-zinc-900/50 rounded-lg p-1">
            <button
              onClick={() => setView('findings')}
              className={cn(
                'flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors',
                view === 'findings' ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200'
              )}
            >
              Findings
              {tabFindings.length > 0 && (
                <span className="text-[9px] px-1 rounded bg-zinc-600 text-zinc-200">{tabFindings.length}</span>
              )}
            </button>
            <button
              onClick={() => setView('terminal')}
              className={cn(
                'flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors',
                view === 'terminal' ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200'
              )}
            >
              <Terminal size={11} />
              Raw Output
              {isRunning && <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse shrink-0" />}
            </button>
          </div>

          {/* Terminal view */}
          {view === 'terminal' && (
            <pre
              ref={termRef}
              className="flex-1 rounded-lg border border-zinc-800 bg-black p-4 overflow-auto text-[11px] font-mono leading-relaxed"
            >
              {isRunning && tabOutput.length === 0 && (
                <span className="text-zinc-600 animate-pulse block">Starting {tool.label}...</span>
              )}
              {tabOutput.map((line, i) => (
                <span key={i} className={cn(
                  'block',
                  line.startsWith('$') ? 'text-green-400 font-bold' :
                  line.includes('VULN') || line.includes('BYPASS') || line.includes('CALLBACK') ? 'text-red-400 font-semibold' :
                  line.includes('Host ready') || line.includes('Host:') ? 'text-green-300' :
                  line.includes('error') || line.includes('Error') ? 'text-red-400' :
                  line.includes('Baseline') ? 'text-zinc-500' :
                  'text-zinc-300'
                )}>{line}</span>
              ))}
              {!isRunning && tabOutput.length === 0 && (
                <span className="text-zinc-700">No output yet — run the tool above.</span>
              )}
            </pre>
          )}

          {/* Findings view */}
          {view === 'findings' && (
            <div className="flex-1 flex gap-3 min-h-0">
              {/* Findings table */}
              <div className="flex-1 overflow-auto rounded-lg border border-zinc-800">
                <table className="w-full text-xs">
                  <thead className="bg-zinc-900 sticky top-0 z-10">
                    <tr className="text-zinc-500 text-left">
                      <th className="px-3 py-2 w-20">Severity</th>
                      <th className="px-3 py-2">Title</th>
                      <th className="px-3 py-2 w-28 hidden lg:table-cell">Host</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tabFindings.map((f, i) => (
                      <tr
                        key={f.id ?? i}
                        onClick={() => setSelected(selected?.id === f.id ? null : f)}
                        className={cn(
                          'border-b border-zinc-800/50 cursor-pointer transition-colors',
                          selected?.id === f.id ? 'bg-zinc-800' : 'hover:bg-zinc-800/40'
                        )}
                      >
                        <td className="px-3 py-1.5"><SevBadge severity={f.severity} /></td>
                        <td className="px-3 py-1.5 text-zinc-300">{f.title}</td>
                        <td className="px-3 py-1.5 text-zinc-600 font-mono text-[10px] hidden lg:table-cell truncate max-w-[110px]">
                          {hostForUrl(f.url)}
                        </td>
                      </tr>
                    ))}
                    {tabFindings.length === 0 && (
                      <tr>
                        <td colSpan={3} className="px-3 py-16 text-center text-zinc-600 text-xs">
                          {isRunning ? (
                            <span className="flex items-center justify-center gap-2">
                              <Loader2 size={13} className="animate-spin" />
                              Running {tool.label}...
                            </span>
                          ) : (
                            <span>No findings yet. Enter a target and click Run.</span>
                          )}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              {/* Detail panel */}
              {selected && (
                <div className="w-72 shrink-0 rounded-lg border border-zinc-800 bg-zinc-900/50 p-4 overflow-y-auto text-xs space-y-3">
                  <div className="flex items-start justify-between gap-2">
                    <h3 className="font-semibold text-zinc-200 leading-tight flex-1">{selected.title}</h3>
                    <button onClick={() => setSelected(null)} className="text-zinc-600 hover:text-zinc-400 shrink-0"><X size={13} /></button>
                  </div>
                  <SevBadge severity={selected.severity} />
                  {selected.url && (
                    <div>
                      <div className="text-zinc-600 mb-0.5 text-[10px]">URL</div>
                      <div className="font-mono text-blue-400 text-[10px] break-all leading-relaxed">{selected.url}</div>
                    </div>
                  )}
                  {selected.parameter && (
                    <div>
                      <div className="text-zinc-600 mb-0.5 text-[10px]">Parameter / Header</div>
                      <div className="font-mono text-yellow-400">{selected.parameter}</div>
                    </div>
                  )}
                  {selected.description && (
                    <div>
                      <div className="text-zinc-600 mb-0.5 text-[10px]">Description</div>
                      <div className="text-zinc-400 leading-relaxed">{selected.description}</div>
                    </div>
                  )}
                  {selected.evidence && (
                    <div>
                      <div className="text-zinc-600 mb-0.5 text-[10px]">Evidence</div>
                      <pre className="text-[10px] bg-zinc-950 rounded p-2 overflow-auto text-zinc-400 whitespace-pre-wrap break-all leading-relaxed max-h-48">
                        {selected.evidence}
                      </pre>
                    </div>
                  )}
                  <div className="flex gap-2 pt-1">
                    <button
                      onClick={() => { addToWorkspace(selected); navigate('/workspace') }}
                      className="flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 text-[10px] rounded border border-zinc-700 text-zinc-400 hover:text-zinc-200 hover:border-zinc-500 transition-colors"
                    >
                      <BookOpen size={10} /> Workspace
                    </button>
                    <button
                      onClick={() => { addToWorkspace(selected); navigate('/copilot') }}
                      className="flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 text-[10px] rounded border border-purple-800/50 text-purple-400 hover:text-purple-300 hover:border-purple-700 transition-colors"
                    >
                      <Sparkles size={10} /> Analyze AI
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Guide modal */}
      {guideOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
          onClick={() => setGuideOpen(false)}
        >
          <div
            className="w-full max-w-2xl max-h-[85vh] flex flex-col rounded-xl border border-zinc-700 bg-zinc-950 shadow-2xl overflow-hidden"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-5 py-3 border-b border-zinc-800 bg-zinc-900 shrink-0">
              <div className="flex items-center gap-2">
                <tool.icon size={14} className={tool.color} />
                <span className="text-sm font-semibold text-zinc-100">{tool.label}</span>
              </div>
              <button onClick={() => setGuideOpen(false)} className="text-zinc-600 hover:text-zinc-300">
                <X size={14} />
              </button>
            </div>
            <div className="overflow-y-auto p-5 text-xs text-zinc-300 space-y-4">
              <p className="text-zinc-400 leading-relaxed">{tool.desc}</p>
              {activeTab === 'cors' && <CorsGuide />}
              {activeTab === 'bypass_403' && <Bypass403Guide />}
              {activeTab === 'cloud_buckets' && <CloudGuide />}
              {activeTab === 'github_scanner' && <GithubGuide />}
              {activeTab === 'interactsh' && <InteractshGuide />}
            </div>
            <div className="shrink-0 px-5 py-3 border-t border-zinc-800 bg-zinc-900 flex justify-end">
              <button
                onClick={() => setGuideOpen(false)}
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

function GuideSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <h3 className="text-xs font-semibold text-zinc-200">{title}</h3>
      {children}
    </div>
  )
}

function Tip({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex gap-2 items-start text-[10px] text-zinc-500 pl-2 border-l border-zinc-800 leading-relaxed">
      <span className="text-yellow-500 shrink-0">Tip:</span>
      <span>{children}</span>
    </div>
  )
}

function CorsGuide() {
  return (
    <>
      <GuideSection title="What to look for">
        <ul className="space-y-1 text-zinc-400 text-[11px] list-disc pl-4">
          <li><span className="text-red-400 font-medium">Critical</span>: Arbitrary origin reflected + ACAC: true. Any origin can read credentialed responses. P1/P2.</li>
          <li><span className="text-orange-400 font-medium">High</span>: Subdomain/prefix bypass + ACAC: true. Attacker on a subdomain can steal data.</li>
          <li><span className="text-yellow-400 font-medium">Medium</span>: Origin reflected without credentials. Lower impact but still worth reporting if sensitive data is in the response.</li>
        </ul>
      </GuideSection>
      <GuideSection title="Manual verification">
        <p className="text-zinc-500 text-[10px] leading-relaxed">
          Send a cross-origin fetch from a browser console on attacker.com — check if response is readable. With ACAC: true, try with <code className="text-green-400">credentials: 'include'</code>.
        </p>
      </GuideSection>
      <Tip>CORS issues without credentials rarely pay out alone — escalate by showing what sensitive data is exposed in the API response.</Tip>
    </>
  )
}

function Bypass403Guide() {
  return (
    <>
      <GuideSection title="Techniques tested">
        <div className="grid grid-cols-2 gap-1 text-[10px]">
          {[
            ['Path: /%2f', 'URL-encoded slash'],
            ['Path: /;/', 'Semicolon bypass'],
            ['Path: /..;/', 'Dotdot-semicolon'],
            ['Path: /./', 'Dot-slash trick'],
            ['Header: X-Forwarded-For', '127.0.0.1 spoof'],
            ['Header: X-Original-URL', 'Path override'],
            ['Header: X-Rewrite-URL', 'Path override 2'],
            ['Header: Referer', 'Trusted referer'],
          ].map(([a, b]) => (
            <div key={a} className="flex flex-col rounded border border-zinc-800 px-2 py-1">
              <span className="font-mono text-zinc-300">{a}</span>
              <span className="text-zinc-600">{b}</span>
            </div>
          ))}
        </div>
      </GuideSection>
      <Tip>403 bypass on /admin or /api/internal endpoints is a high-impact finding. Always verify manually — check if the 200 response has actual sensitive content, not just a different error page.</Tip>
    </>
  )
}

function CloudGuide() {
  return (
    <>
      <GuideSection title="Status codes">
        <div className="space-y-1 text-[10px]">
          {[
            ['200', 'text-green-400', 'Public read. High severity. List the bucket contents and check for sensitive files.'],
            ['403', 'text-orange-400', 'Bucket exists but private. Info severity. Check if you own it — if not, document for completeness.'],
            ['404 / DNS fail', 'text-zinc-500', 'Bucket does not exist. Skip.'],
          ].map(([code, color, desc]) => (
            <div key={code} className="flex gap-2 items-start">
              <span className={`font-mono font-bold shrink-0 ${color}`}>{code}</span>
              <span className="text-zinc-500 leading-relaxed">{desc}</span>
            </div>
          ))}
        </div>
      </GuideSection>
      <Tip>A public S3 bucket with sensitive data (backups, keys, user data) is a P1 in most programs. Use <code className="text-green-400">aws s3 ls s3://BUCKET --no-sign-request</code> to list contents without credentials.</Tip>
    </>
  )
}

function GithubGuide() {
  return (
    <>
      <GuideSection title="Requires: trufflehog">
        <code className="block text-[10px] text-green-400 bg-zinc-900 rounded px-2 py-1 font-mono">
          curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
        </code>
      </GuideSection>
      <GuideSection title="Input formats">
        <div className="space-y-1 text-[10px] text-zinc-500">
          <div><span className="font-mono text-zinc-300">acme-corp</span> — scan entire org (all repos)</div>
          <div><span className="font-mono text-zinc-300">https://github.com/acme/repo</span> — single repo</div>
        </div>
      </GuideSection>
      <Tip>Verified secrets (active credentials confirmed via API) are critical. Even unverified secrets should be checked manually — old API keys in commit history are often still valid.</Tip>
    </>
  )
}

function InteractshGuide() {
  return (
    <>
      <GuideSection title="Requires: interactsh-client">
        <code className="block text-[10px] text-green-400 bg-zinc-900 rounded px-2 py-1 font-mono">
          go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
        </code>
      </GuideSection>
      <GuideSection title="Use the host in payloads">
        <div className="space-y-1 text-[10px]">
          {[
            ['SSRF',       'http://HOST/'],
            ['Blind XSS',  "<img src='http://HOST'>"],
            ['XXE',        "<!ENTITY e SYSTEM 'http://HOST'>"],
            ['DNS probe',  '$(nslookup HOST)'],
          ].map(([type, payload]) => (
            <div key={type} className="flex gap-2">
              <span className="text-zinc-500 w-20 shrink-0">{type}</span>
              <code className="font-mono text-green-400 text-[10px]">{payload}</code>
            </div>
          ))}
        </div>
      </GuideSection>
      <Tip>SSRF to cloud metadata (169.254.169.254) via the OOB host is a P1. If you get a DNS callback but not HTTP, check for SSRF+DNS-only. Still worth reporting.</Tip>
    </>
  )
}
