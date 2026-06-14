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
  FolderGit2, Server, ChevronDown,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useWorkspaceStore } from '@/stores/workspace-store'
import type { Finding } from '@/types'

type ToolId = 'cors' | 'bypass_403' | 'cloud_buckets' | 'exposed_files' | 'github_scanner' | 'interactsh'
type ViewMode = 'findings' | 'terminal'

// Tools that take a live-host URL — get the host picker + bulk scan.
const HOST_TOOLS: ToolId[] = ['cors', 'bypass_403', 'exposed_files']
const BULK_ENDPOINT: Partial<Record<ToolId, string>> = {
  cors: '/api/tools/cors-bulk',
  bypass_403: '/api/tools/bypass-403-bulk',
  exposed_files: '/api/tools/exposed-files-bulk',
  cloud_buckets: '/api/tools/cloud-buckets-bulk',
}

interface ToolDef {
  id: ToolId
  label: string
  icon: React.ComponentType<{ size?: number; className?: string }>
  tagline: string
  what: string      // what this attack is, in one line
  impact: string    // what happens when it lands
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
    tagline: '8 origin bypass tests + wildcard detection',
    what: 'Checks whether the server reflects an attacker-controlled Origin in its CORS headers (Access-Control-Allow-Origin).',
    impact: 'If ACAO reflects your origin AND Access-Control-Allow-Credentials is true, any malicious page can read this site\'s authenticated responses (session data, tokens, PII) from a logged-in victim\'s browser.',
    desc: 'Sends 8 crafted Origin headers per target: arbitrary reflection, null origin, subdomain (evil.target.com), prefix/suffix tricks, unanchored-regex bypass and HTTP downgrade. Also flags a bare wildcard ACAO. Severity is critical when reflection is paired with credentials.',
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
    tagline: '18 path tricks + 15 header injections + 6 verbs',
    what: 'Tries to reach an endpoint that returns 403/401 by tricking the proxy/WAF that enforces the block while the backend still serves the content.',
    impact: 'A working bypass reaches admin panels, internal APIs or restricted files that were supposed to be access-controlled — often a direct path to sensitive functionality.',
    desc: 'Probes the protected path with encoding/path tricks (/%2f, /..;/, /%2e/, overlong UTF-8), IP-spoofing and URL-override headers (X-Forwarded-For, X-Original-URL, X-Rewrite-URL...), and HTTP verb tampering (POST/PUT/HEAD/OPTIONS/TRACE). Any probe returning 2xx where the baseline returned 403 is flagged, with a curl to reproduce.',
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
    tagline: '~66 name variants across S3, GCS, Azure, DO',
    what: 'Finds the target\'s cloud storage buckets two ways — reading real references out of its HTML/JS, and guessing names from the company/domain — then checks each across S3, GCS, Azure and DigitalOcean for public access.',
    impact: 'A public-read bucket exposes whatever the company stored there — backups, source, customer data, credentials. A public-write bucket is worse: you can overwrite assets the site serves (defacement / supply-chain). The finding includes the command to list and pull it.',
    desc: 'If you give it a domain/URL it first fetches the homepage and its linked JS and extracts buckets referenced directly in the code (s3.amazonaws.com, storage.googleapis.com, *.blob.core.windows.net, *.digitaloceanspaces.com) — these are real, in-use buckets. Then it also derives ~66 likely names (acme-prod, acme-backup, acme-data...). All are checked in parallel; 200 = public (listing parsed in + "aws s3 ls" repro), 403 = private. Use "Derive buckets from N domains" to sweep every host from Recon.',
    inputLabel: 'Company name or domain',
    placeholder: 'acme-corp or acme.com',
    color: 'text-blue-400',
    border: 'border-blue-500/30',
    bg: 'bg-blue-950/15',
    endpoint: '/api/tools/cloud-buckets',
  },
  {
    id: 'exposed_files',
    label: 'Exposed Files',
    icon: FolderGit2,
    tagline: '.git, .env, .svn, .htpasswd, WEB-INF exposure',
    what: 'Checks a live host for sensitive files and version-control directories left reachable in the web root.',
    impact: 'An exposed /.git/ or /.env hands over source code, commit history and cleartext secrets (DB creds, API keys). The finding tells you exactly how to dump it (git-dumper) and where to look.',
    desc: 'Requests /.git/HEAD, /.git/config, /.env, /.svn metadata, /.htpasswd and WEB-INF/web.xml, validating each by content signature so it survives servers that answer 200 to everything. Run it on a single URL or sweep every live host from Recon.',
    inputLabel: 'Target URL',
    placeholder: 'https://target.com',
    color: 'text-red-400',
    border: 'border-red-500/30',
    bg: 'bg-red-950/15',
    endpoint: '/api/tools/exposed-files',
  },
  {
    id: 'github_scanner',
    label: 'GitHub Secrets',
    icon: GitBranch,
    tagline: 'TruffleHog secret scanner for orgs and repos',
    what: 'Scans a GitHub org or repo\'s full history for committed secrets using TruffleHog.',
    impact: 'Developers leak API keys, tokens and passwords in commits and never rotate them. Verified hits are confirmed still-active against the issuing API — instant valid credentials.',
    desc: 'Runs TruffleHog over a GitHub org or repo, scanning commit history, branches and PRs for API keys, tokens, passwords and private keys. Enter an org name ("acme-corp"), a domain ("acme.com" -> org "acme") or a repo URL. Secrets are verified live against the issuing API. Requires trufflehog.',
    inputLabel: 'GitHub org, domain or repo URL',
    placeholder: 'acme-corp,  acme.com  or  https://github.com/acme/repo',
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
    what: 'Spins up an out-of-band server with a unique hostname you embed in payloads to catch blind, no-response vulnerabilities.',
    impact: 'Confirms blind bugs that have no visible output: blind SSRF, blind XSS, XXE and command injection all prove out via a DNS/HTTP callback to your host.',
    desc: 'Starts interactsh-client and generates a unique hostname. Embed it in SSRF payloads (http://HOST/), blind XSS (<img src="http://HOST">), XXE (<!ENTITY e SYSTEM "http://HOST">) or command injection ($(nslookup HOST)). Any DNS or HTTP callback appears here in real time. Requires interactsh-client.',
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
    cors: '', bypass_403: '', cloud_buckets: '', exposed_files: '', github_scanner: '', interactsh: '',
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

  const handleBulkScan = async () => {
    const endpoint = BULK_ENDPOINT[activeTab]
    if (!endpoint) return
    if (bulkTargets.length === 0) {
      toast.error('No live hosts', 'Run HTTPX on the Recon page first to populate live hosts.')
      return
    }
    try {
      const res = await api.post<{ count: number }>(endpoint, {
        targets: bulkTargets,
        options: getSessionOpts(),
        project_id: activeProject ?? '',
      })
      const unit = activeTab === 'cloud_buckets' ? 'domains' : 'live hosts'
      toast.success(`${tool.label} started`, `Running on ${res.count} ${unit}`)
    } catch (err) {
      toast.error(`Failed to start bulk ${tool.label} scan`, err)
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

  // Cloud buckets derives names from domains, not URLs — send unique hostnames.
  const bulkTargets =
    activeTab === 'cloud_buckets'
      ? [...new Set(liveHosts.map(h => hostForUrl(h.url)).filter(d => d && d !== '-'))]
      : liveHosts.map(h => h.url).filter(Boolean)

  return (
    <WorkspaceShell title="Attacks" subtitle="Targeted attacks — CORS, 403 bypass, cloud buckets, exposed files, secrets, OOB">
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
            {/* What it is / what happens */}
            <div className="space-y-1.5 rounded-md border border-zinc-800 bg-zinc-900/40 p-2.5">
              <div className="flex gap-2">
                <span className="text-[9px] font-semibold uppercase tracking-wide text-zinc-500 w-14 shrink-0 pt-0.5">Attack</span>
                <span className="text-[11px] text-zinc-300 leading-relaxed flex-1">{tool.what}</span>
              </div>
              <div className="flex gap-2">
                <span className={cn('text-[9px] font-semibold uppercase tracking-wide w-14 shrink-0 pt-0.5', tool.color)}>Impact</span>
                <span className="text-[11px] text-zinc-400 leading-relaxed flex-1">{tool.impact}</span>
              </div>
            </div>
            <p className="text-[10px] text-zinc-600 leading-relaxed">{tool.desc}</p>

            {/* Host picker for URL-based tools */}
            {HOST_TOOLS.includes(activeTab) && (
              <LiveHostPicker
                color={tool.color}
                selected={targets[activeTab]}
                onSelect={url => setTargets(prev => ({ ...prev, [activeTab]: url }))}
              />
            )}

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

            {/* Bulk scan all live hosts (tools that support it) */}
            {BULK_ENDPOINT[activeTab] && (
              <button
                onClick={handleBulkScan}
                disabled={isRunning || bulkTargets.length === 0}
                className={cn(
                  'w-full flex items-center justify-center gap-1.5 px-3 py-1.5 text-[11px] font-medium rounded-md border transition-colors disabled:opacity-40 disabled:cursor-not-allowed',
                  tool.border, tool.color, 'hover:bg-zinc-800/40'
                )}
              >
                <Server size={11} />
                {activeTab === 'cloud_buckets'
                  ? `Derive buckets from ${bulkTargets.length} domains`
                  : `Scan all live hosts (${bulkTargets.length})`}
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
              {activeTab === 'exposed_files' && <ExposedFilesGuide />}
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
      <GuideSection title="What is a bucket">
        <p className="text-[10px] text-zinc-500 leading-relaxed">
          A bucket is a top-level container in cloud object storage (AWS S3, Google Cloud Storage,
          Azure Blob, DigitalOcean Spaces). Companies dump assets, backups, logs and exports there.
          Names are globally unique, and a single misconfigured ACL makes the whole bucket
          world-readable — or world-writable.
        </p>
      </GuideSection>
      <GuideSection title="How it finds buckets">
        <div className="space-y-1.5 text-[10px] text-zinc-500 leading-relaxed">
          <p>
            <span className="text-green-400 font-semibold">Referenced (real):</span> if the target is a
            domain/URL it fetches the homepage + linked JS and pulls out buckets the app actually uses
            (s3.amazonaws.com, storage.googleapis.com, *.blob.core.windows.net, *.digitaloceanspaces.com).
            These are probed first and flagged as referenced.
          </p>
          <p>
            <span className="text-blue-400 font-semibold">Guessed:</span> derives ~66 candidate names by
            appending common suffixes (<code className="text-blue-400">-backup -prod -dev -data -assets -uploads -logs</code> ...).
          </p>
          <p>Everything is checked against the 4 providers in parallel. The bulk button repeats this for every unique domain from Recon.</p>
        </div>
      </GuideSection>
      <GuideSection title="Status codes">
        <div className="space-y-1 text-[10px]">
          {[
            ['200', 'text-green-400', 'Public read. High severity. The object listing is parsed into the finding; download and triage.'],
            ['403', 'text-orange-400', 'Bucket exists but private. Info severity. Confirm ownership; try region/auth tricks.'],
            ['404 / DNS fail', 'text-zinc-500', 'Bucket does not exist. Skipped.'],
          ].map(([code, color, desc]) => (
            <div key={code} className="flex gap-2 items-start">
              <span className={`font-mono font-bold shrink-0 ${color}`}>{code}</span>
              <span className="text-zinc-500 leading-relaxed">{desc}</span>
            </div>
          ))}
        </div>
      </GuideSection>
      <GuideSection title="When you find a public bucket">
        <div className="space-y-1 text-[10px] text-zinc-500 leading-relaxed">
          <p>1. List it: <code className="text-green-400">aws s3 ls s3://BUCKET --no-sign-request</code> (GCS: <code className="text-green-400">gsutil ls gs://BUCKET</code>).</p>
          <p>2. Pull it: <code className="text-green-400">aws s3 sync s3://BUCKET . --no-sign-request</code> and grep for keys, .env, dumps, PII.</p>
          <p>3. Test write: <code className="text-green-400">aws s3 cp poc.txt s3://BUCKET --no-sign-request</code> — a writable bucket can mean defacement or supply-chain (overwriting served JS).</p>
        </div>
      </GuideSection>
      <Tip>A public bucket with backups, keys or user data is usually a P1. A world-writable bucket that serves the site's assets can be even worse — you control what visitors load.</Tip>
    </>
  )
}

function ExposedFilesGuide() {
  return (
    <>
      <GuideSection title="What gets checked">
        <div className="space-y-1 text-[10px]">
          {[
            ['/.git/HEAD + config', 'text-red-400', 'Whole repo + history. Dump with git-dumper, then grep git log for secrets.'],
            ['/.env', 'text-red-400', 'App secrets in cleartext: DB creds, API keys, APP_KEY. Read and pivot.'],
            ['/.svn metadata', 'text-orange-400', 'Reconstruct source paths and pristine files from the working copy.'],
            ['/.htpasswd', 'text-orange-400', 'Basic-auth hashes. Crack offline with hashcat/john.'],
            ['WEB-INF/web.xml', 'text-orange-400', 'Java deployment descriptor: servlet maps, params, internal endpoints.'],
          ].map(([f, color, desc]) => (
            <div key={f} className="flex gap-2 items-start">
              <span className={`font-mono font-bold shrink-0 ${color}`}>{f}</span>
              <span className="text-zinc-500 leading-relaxed">{desc}</span>
            </div>
          ))}
        </div>
      </GuideSection>
      <GuideSection title="Why content signatures">
        <p className="text-[10px] text-zinc-500 leading-relaxed">
          Many servers answer 200 to every path (SPA fallbacks). Each check validates the body against a
          per-type signature (e.g. <code className="text-green-400">ref:</code> for .git/HEAD,
          <code className="text-green-400"> KEY=value</code> for .env), so a soft-404 HTML page is not flagged.
        </p>
      </GuideSection>
      <Tip>Use <code className="text-green-400">Scan all live hosts</code> to sweep every host from Recon at once. An exposed .git is usually a P1 — dump it: <code className="text-green-400">git-dumper http://HOST/.git/ ./loot</code>.</Tip>
    </>
  )
}

function LiveHostPicker({ selected, onSelect, color }: {
  selected: string
  onSelect: (url: string) => void
  color: string
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

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(v => !v)}
        className={cn('w-full flex items-center justify-between gap-1.5 px-2.5 py-1.5 rounded-md border border-zinc-700 bg-zinc-900/60 text-xs hover:border-zinc-500 transition-colors', color)}
      >
        <div className="flex items-center gap-1.5">
          <Server size={11} />
          <span>{liveHosts.length} live hosts</span>
          {selected && liveHosts.some(h => h.url === selected) && (
            <span className="text-[9px] text-zinc-500">· selected</span>
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
