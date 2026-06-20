import { useState, useRef, useEffect } from 'react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { Input } from '@/components/ui/input'
import { api } from '@/api/http-client'
import { toast } from '@/stores/toast-store'
import { useScannerStore } from '@/stores/scanner-store'
import { useReconStore } from '@/stores/recon-store'
import { useAppStore } from '@/stores/app-store'
import { useLicenseStore } from '@/stores/license-store'
import { cn } from '@/lib/utils'
import {
  Play, Square, Loader2, Terminal, Copy, Check,
  Globe, Lock, Cloud, GitBranch, Radio, Info, X, BookOpen, Sparkles,
  FolderGit2, Server, ChevronDown, Share2, FileCode2, Crown, Maximize2, Crosshair, Rocket, Waypoints,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useWorkspaceStore } from '@/stores/workspace-store'
import type { Finding } from '@/types'
import { JsApiMapResults } from '@/components/security/JsApiMapResults'

type ToolId = 'cors' | 'bypass_403' | 'cloud_buckets' | 'exposed_files' | 'graphql_audit' | 'viewstate_audit' | 'github_scanner' | 'interactsh' | 'exploit_intel' | 'js_api_mapper'
type ViewMode = 'findings' | 'terminal'

// PRO-only tools in prod.
const PRO_TOOLS: ToolId[] = ['graphql_audit', 'viewstate_audit']

// Tools that take a live-host URL — get the host picker + bulk scan.
const HOST_TOOLS: ToolId[] = ['cors', 'bypass_403', 'exposed_files', 'viewstate_audit']
const BULK_ENDPOINT: Partial<Record<ToolId, string>> = {
  cors: '/api/tools/cors-bulk',
  bypass_403: '/api/tools/bypass-403-bulk',
  exposed_files: '/api/tools/exposed-files-bulk',
  cloud_buckets: '/api/tools/cloud-buckets-bulk',
  viewstate_audit: '/api/tools/viewstate-bulk',
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
    what: 'Finds the target\'s cloud storage buckets two ways — reading real references out of its HTML/JS, and guessing names from the company/domain — then checks each across S3, GCS, Azure and DigitalOcean for public access, paginates the full listing, flags sensitive files, and probes ACL/policy documents.',
    impact: 'A public-read bucket exposes whatever the company stored there — backups, source, customer data, credentials. A public-write bucket is worse: you can overwrite assets the site serves (defacement / supply-chain). Findings are split by severity: public listing, sensitive files found inside it, exposed ACL/policy grants, and (opt-in) a proven write takeover.',
    desc: 'If you give it a domain/URL it first fetches the homepage and its linked JS and extracts buckets referenced directly in the code (s3.amazonaws.com, storage.googleapis.com, *.blob.core.windows.net, *.digitaloceanspaces.com) — these are real, in-use buckets. Then it also derives ~66 likely names (acme-prod, acme-backup, acme-data...). All are checked in parallel; 200 = public (full paginated listing, flags .env/.sql/.pem/credential-looking filenames as a separate critical finding), 403 = private. It also fetches ?acl/?policy directly (S3/GCS/DO) since those can be public even when listing is blocked. Enable "Test write access" to actively prove a write takeover (PUT+delete a marker object) on buckets referenced by the target. Use "Derive buckets from N domains" to sweep every host from Recon.',
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
    id: 'graphql_audit',
    label: 'GraphQL Auditor',
    icon: Share2,
    tagline: 'Introspection dump + no-auth access check + error leaks',
    what: 'Audits a GraphQL API endpoint: dumps its whole schema via introspection, then re-runs each query WITHOUT your token to see which ones still return data, and harvests internal URLs leaked in error messages.',
    impact: 'GraphQL APIs routinely ship with introspection enabled and per-query authorization missing. This surfaces operations that hand user / payment / loyalty data to anyone unauthenticated, plus internal microservice URLs you can pivot to.',
    desc: 'Point it at a GraphQL endpoint (e.g. https://api.target.com/graphql). It sends the introspection query to recover every query, mutation and type; then for each root query with no required arguments it sends the request with the Authorization header stripped and flags any that return data (broken access control). It also fires a malformed query to trigger verbose errors and extracts leaked internal/infra URLs, and inventories sensitive-looking mutations. Set your Session token first so it can compare authed vs anonymous.',
    inputLabel: 'GraphQL endpoint URL',
    placeholder: 'https://api.target.com/graphql',
    color: 'text-fuchsia-400',
    border: 'border-fuchsia-500/30',
    bg: 'bg-fuchsia-950/15',
    endpoint: '/api/tools/graphql',
  },
  {
    id: 'viewstate_audit',
    label: 'VIEWSTATE Auditor',
    icon: FileCode2,
    tagline: 'Decode ASP.NET __VIEWSTATE + secrets + SOAP enum',
    what: 'Decodes the hidden __VIEWSTATE field on ASP.NET WebForms pages and reads what developers embedded in it — and flags when the blob is unencrypted (a deserialization-RCE candidate).',
    impact: 'Unencrypted VIEWSTATE leaks whatever was stored in it: credentials, connection strings, private keys, internal service URLs and IPs — in cleartext. If its MAC is also disabled it is a ViewState deserialization RCE sink (ysoserial.net). It also surfaces internal .asmx/.svc SOAP services and lists their methods.',
    desc: 'Fetches the URL (and common ASP.NET entry points: /, /default.aspx, /login.aspx), extracts __VIEWSTATE + __VIEWSTATEGENERATOR, Base64-decodes the blob and confirms whether it is encrypted (encrypted blobs do not start with the ObjectStateFormatter 0xFF01 marker). When cleartext, it runs strings-style extraction and mines for embedded credentials, keys, connection strings, AWS keys, private IPs and internal/SOAP URLs. Any .asmx/.svc referenced on the page or inside the blob has its WSDL pulled and its operations listed. Run on one URL or sweep every live host from Recon. Honors your Session cookie/token.',
    inputLabel: 'Target URL (ASP.NET page)',
    placeholder: 'https://target.com/Login.aspx',
    color: 'text-cyan-400',
    border: 'border-cyan-500/30',
    bg: 'bg-cyan-950/15',
    endpoint: '/api/tools/viewstate',
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
    id: 'js_api_mapper',
    label: 'JS API Mapper',
    icon: Waypoints,
    tagline: 'JS bundles -> API route map + auth framework + access-control plan',
    what: 'Parses the site\'s JavaScript to recover the API route map, fingerprints the auth/backend framework (better-auth, NextAuth, Supabase, Firebase...), expands it to that library\'s full known privileged routes, and builds an access-control test plan for each.',
    impact: 'Turns "I found a path string in a JS file" into "here is the whole admin API surface (impersonate, set-role, set-password, delete-user...) and exactly how to test each for broken access control / IDOR / account takeover".',
    desc: 'Give it a host (it fetches the homepage + linked bundles) or a single .js URL. It extracts quoted route strings, path->method maps, and role/permission arrays; identifies the auth framework from route signatures and adds its documented admin endpoints even if the client only shipped a few; flags privileged routes (admin/impersonate/set-role/set-password/delete) and dangerous role actions; and emits a per-route anon/user/admin test plan. Pairs with the Proxy: register a normal account, grab its JWT, and replay each privileged route to see what the backend actually enforces. Auto-uses JS URLs from Recon.',
    inputLabel: 'Host or JS bundle URL',
    placeholder: 'https://app.target.com  or  https://app.target.com/assets/index.js',
    color: 'text-teal-400',
    border: 'border-teal-500/30',
    bg: 'bg-teal-950/15',
    endpoint: '/api/tools/js-api-mapper',
  },
  {
    id: 'exploit_intel',
    label: 'Exploit Intel',
    icon: Crosshair,
    tagline: 'Tech versions -> Exploit-DB + Metasploit + auto MSF setup',
    what: 'Takes the technologies fingerprinted on your live hosts (or a product/CVE you type) and looks up known public exploits in Exploit-DB (searchsploit) and Metasploit, then prepares a ready-to-run MSF resource script for each matched module.',
    impact: 'Turns "Apache 2.4.49 / Log4j / Confluence 7.13" into a shortlist of real, downloadable exploits and one-click Metasploit setups. Closes the gap between "I know the version" and "here is the exploit and the msfconsole session".',
    desc: 'Auto-collects the tech stack from your Recon live hosts (httpx tech-detect), or take a single product string / CVE you type. For each, it runs searchsploit (local Exploit-DB) and searches the Metasploit module DB by product name and by CVE. Each hit is a finding: Exploit-DB entries include the EDB-ID and the searchsploit -m / -x commands; Metasploit modules get a "Run in Metasploit" button that writes a resource script (RHOSTS/RPORT/LHOST pre-set) and opens msfconsole with it. Version matching is a lead, not a confirmation - verify before firing. Requires searchsploit + metasploit-framework.',
    inputLabel: 'Product + version or CVE (optional - auto-uses live host tech)',
    placeholder: 'Apache 2.4.49  /  CVE-2021-44228  /  Confluence 7.13',
    color: 'text-rose-400',
    border: 'border-rose-500/30',
    bg: 'bg-rose-950/15',
    endpoint: '/api/tools/exploit-intel',
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

// Render plain evidence text with clickable http(s) links (e.g. bucket object URLs).
function linkify(text: string): React.ReactNode[] {
  const parts = text.split(/(https?:\/\/[^\s)<>"']+)/g)
  return parts.map((part, i) =>
    /^https?:\/\//.test(part)
      ? <a key={i} href={part} target="_blank" rel="noreferrer" className="text-cyan-400 underline hover:text-cyan-300 break-all">{part}</a>
      : <span key={i}>{part}</span>
  )
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
    cors: '', bypass_403: '', cloud_buckets: '', exposed_files: '', graphql_audit: '', viewstate_audit: '', github_scanner: '', interactsh: '', exploit_intel: '', js_api_mapper: '',
  })
  const [graphqlSampleIds, setGraphqlSampleIds] = useState('')
  const [graphqlExtraQueries, setGraphqlExtraQueries] = useState('')
  const [cloudTestWrite, setCloudTestWrite] = useState(false)
  const [msfRhosts, setMsfRhosts] = useState('')
  const [msfLhost, setMsfLhost] = useState('')
  const [msfLaunching, setMsfLaunching] = useState(false)
  const [view, setView] = useState<ViewMode>('findings')
  const [selected, setSelected] = useState<Finding | null>(null)
  const [copied, setCopied] = useState(false)
  const [evidenceOpen, setEvidenceOpen] = useState(false)
  const [guideOpen, setGuideOpen] = useState(false)
  const [notInstalled, setNotInstalled] = useState<Set<string>>(new Set())
  const termRef = useRef<HTMLPreElement>(null)
  const navigate = useNavigate()

  const { activeProject, globalTarget, getSessionOpts } = useAppStore()
  const { isPro } = useLicenseStore()
  const { findings, rawOutput, activeScans, activeJobIds } = useScannerStore()
  const { liveHosts, urls } = useReconStore()
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
  const proGated = PRO_TOOLS.includes(activeTab) && !isPro()  // PRO-only in prod

  // Per-tool extra options on top of the session (cookies/headers).
  const optsFor = (id: ToolId) => {
    if (id === 'cloud_buckets')
      return { ...getSessionOpts(), seed_urls: urls.map(u => u.url).filter(Boolean).slice(0, 800), test_write: cloudTestWrite }
    if (id === 'exploit_intel')
      return { ...getSessionOpts(), techs: [...new Set(liveHosts.flatMap(h => h.technologies ?? []).filter(Boolean))].slice(0, 100) }
    if (id === 'js_api_mapper')
      return { ...getSessionOpts(), seed_urls: urls.map(u => u.url).filter(Boolean).slice(0, 800) }
    if (id === 'graphql_audit')
      return { ...getSessionOpts(), sample_ids: graphqlSampleIds, extra_queries: graphqlExtraQueries }
    return getSessionOpts()
  }

  const exploitIntelTechCount = [...new Set(liveHosts.flatMap(h => h.technologies ?? []).filter(Boolean))].length

  const handleRun = async () => {
    const target = targets[activeTab].trim()
    // exploit_intel can run with no typed target if live hosts have detected tech.
    if (activeTab === 'exploit_intel' && !target && exploitIntelTechCount === 0) {
      toast.error('Nothing to look up', 'Type a product/CVE, or probe live hosts in Recon first so tech is detected.')
      return
    }
    if (!target && activeTab !== 'interactsh' && activeTab !== 'exploit_intel') {
      toast.error('Enter a target first', null)
      return
    }
    try {
      await api.post(tool.endpoint, { target, options: optsFor(activeTab), project_id: activeProject ?? '' })
    } catch (err) {
      toast.error(`Failed to start ${tool.label}`, err)
    }
  }

  const handleStop = async () => {
    if (!jobId) return
    try { await api.delete(`/api/tools/jobs/${jobId}`) } catch {}
  }

  const handleMsfLaunch = async (module: string) => {
    if (!msfRhosts.trim()) {
      toast.error('Set a target host (RHOSTS)', 'Enter the IP/host to exploit before launching.')
      return
    }
    setMsfLaunching(true)
    try {
      const res = await api.post<{ status: string; command?: string; rc_path?: string; note?: string }>(
        '/api/tools/exploit-intel/msf-launch',
        { module, rhosts: msfRhosts.trim(), lhost: msfLhost.trim() },
      )
      if (res.status === 'launched') {
        toast.success('Metasploit launched', `${module} in a new terminal (${res.rc_path})`)
      } else if (res.status === 'manual') {
        navigator.clipboard.writeText(res.command || '').catch(() => {})
        toast.success('Resource script ready', `${res.note} Command copied: ${res.command}`)
      } else {
        toast.error('Launch failed', (res as any).error || 'Unknown error')
      }
    } catch (err) {
      toast.error('Failed to launch Metasploit', err)
    } finally {
      setMsfLaunching(false)
    }
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
        options: optsFor(activeTab),
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
                  {PRO_TOOLS.includes(t.id) && !isPro() && <Crown size={11} className="text-amber-400 shrink-0" />}
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

            {proGated && (
              <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-950/20 px-3 py-2">
                <Crown size={14} className="text-amber-400 shrink-0 mt-0.5" />
                <div className="text-[11px] leading-relaxed">
                  <span className="text-amber-300 font-semibold">{tool.label} is a PRO feature.</span>
                  <span className="text-zinc-400"> Upgrade to run it. </span>
                  <a href="https://nexhunt.myshopify.com/products/nexhunt-pro" target="_blank" rel="noreferrer" className="text-amber-400 underline">Get PRO</a>
                </div>
              </div>
            )}

            {activeTab === 'graphql_audit' && (
              <button
                onClick={() => setGuideOpen(true)}
                className="flex items-center gap-1.5 text-[10px] text-fuchsia-400/80 hover:text-fuchsia-300 transition-colors"
              >
                <Info size={11} /> New to GraphQL? Open the Guide for a plain-English primer
              </button>
            )}

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
                  disabled={(!targets[activeTab].trim() && activeTab !== 'interactsh' && !(activeTab === 'exploit_intel' && exploitIntelTechCount > 0)) || proGated}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-green-700/70 text-green-400 hover:bg-green-950/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors shrink-0"
                >
                  {proGated ? <Crown size={11} /> : <Play size={11} />} {proGated ? 'PRO' : 'Run'}
                </button>
              )}
            </div>

            {/* Bulk scan all live hosts (tools that support it) */}
            {BULK_ENDPOINT[activeTab] && (
              <button
                onClick={handleBulkScan}
                disabled={isRunning || bulkTargets.length === 0 || proGated}
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

            {/* GraphQL: optional sample IDs for IDOR auto-test */}
            {activeTab === 'graphql_audit' && (
              <div className="space-y-1">
                <Input
                  value={graphqlSampleIds}
                  onChange={e => setGraphqlSampleIds(e.target.value)}
                  placeholder="Sample IDs for IDOR test (optional): your loyaltyId, userId..."
                  className="bg-zinc-900/80 text-xs"
                />
                <p className="text-[9px] text-zinc-600 leading-relaxed">
                  Paste a known ID/UUID (e.g. your own account's) to auto-test object-by-ID queries for IDOR. Separate multiple with spaces or commas.
                </p>
                <Input
                  value={graphqlExtraQueries}
                  onChange={e => setGraphqlExtraQueries(e.target.value)}
                  placeholder="Extra query names (optional): loyaltyServiceAnonymousOffers, me, orders..."
                  className="bg-zinc-900/80 text-xs"
                />
                <p className="text-[9px] text-zinc-600 leading-relaxed">
                  If introspection is disabled, the auditor probes a built-in name wordlist + server field suggestions. Add any query names you already know here to test them too.
                </p>
              </div>
            )}

            {/* Cloud: provider tags + write-test toggle */}
            {activeTab === 'cloud_buckets' && (
              <div className="space-y-1.5">
                <div className="flex gap-1.5 items-center">
                  <span className="text-[9px] text-zinc-600">Providers:</span>
                  {['AWS S3', 'GCS', 'Azure'].map(p => (
                    <span key={p} className="text-[9px] px-1.5 py-0.5 rounded border border-blue-700/50 text-blue-400/80">{p}</span>
                  ))}
                </div>
                <label className="flex items-start gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={cloudTestWrite}
                    onChange={e => setCloudTestWrite(e.target.checked)}
                    className="w-3 h-3 mt-0.5 accent-red-500"
                  />
                  <span className="text-[10px] text-zinc-400">
                    <span className="text-red-400 font-medium">Test write access</span> — attempts to PUT (then delete) a
                    harmless marker file on buckets actually referenced by the target, to prove a write takeover instead
                    of just reporting "exists". Active probe against real infra; only runs on referenced buckets, never
                    on guessed names.
                  </span>
                </label>
              </div>
            )}

            {/* Exploit Intel: show how many techs will be auto-looked-up */}
            {activeTab === 'exploit_intel' && (
              <div className="text-[10px] text-zinc-500 leading-relaxed">
                {exploitIntelTechCount > 0
                  ? <>Will look up <span className="text-rose-400 font-medium">{exploitIntelTechCount}</span> technolog{exploitIntelTechCount === 1 ? 'y' : 'ies'} detected on your live hosts{targets.exploit_intel.trim() ? ', plus what you typed' : ''}.</>
                  : <>No tech detected yet — probe live hosts in Recon (HTTPX), or just type a product/CVE above.</>}
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
          {view === 'findings' && activeTab === 'js_api_mapper' && (
            <JsApiMapResults findings={tabFindings} running={isRunning} />
          )}
          {view === 'findings' && activeTab !== 'js_api_mapper' && (
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
                <div className="w-96 xl:w-[480px] shrink-0 rounded-lg border border-zinc-800 bg-zinc-900/50 p-4 overflow-y-auto text-xs space-y-3">
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
                      <div className="flex items-center justify-between mb-0.5">
                        <div className="text-zinc-600 text-[10px]">Evidence</div>
                        <button
                          onClick={() => setEvidenceOpen(true)}
                          className="flex items-center gap-1 text-[10px] text-cyan-400/80 hover:text-cyan-300 transition-colors"
                        >
                          <Maximize2 size={10} /> Expand
                        </button>
                      </div>
                      <pre className="text-[10px] bg-zinc-950 rounded p-2 overflow-auto text-zinc-400 whitespace-pre-wrap break-all leading-relaxed max-h-80">
                        {selected.evidence}
                      </pre>
                    </div>
                  )}
                  {selected.tool === 'exploit_intel' && selected.template_id?.startsWith('msf:') && (
                    <div className="space-y-1.5 rounded-md border border-rose-800/50 bg-rose-950/20 p-2">
                      <div className="text-[10px] text-rose-300 font-medium flex items-center gap-1.5">
                        <Rocket size={11} /> Run in Metasploit
                      </div>
                      <div className="text-[9px] text-zinc-500 font-mono break-all">{selected.template_id.slice(4)}</div>
                      <input
                        value={msfRhosts}
                        onChange={e => setMsfRhosts(e.target.value)}
                        placeholder="RHOSTS — target IP/host"
                        className="w-full text-[10px] bg-zinc-950 border border-zinc-800 rounded px-2 py-1 text-zinc-300 placeholder:text-zinc-700 focus:outline-none focus:border-rose-700"
                      />
                      <input
                        value={msfLhost}
                        onChange={e => setMsfLhost(e.target.value)}
                        placeholder="LHOST — your IP (for reverse shells, optional)"
                        className="w-full text-[10px] bg-zinc-950 border border-zinc-800 rounded px-2 py-1 text-zinc-300 placeholder:text-zinc-700 focus:outline-none focus:border-rose-700"
                      />
                      <button
                        onClick={() => handleMsfLaunch(selected.template_id!.slice(4))}
                        disabled={msfLaunching}
                        className="w-full flex items-center justify-center gap-1.5 px-2 py-1.5 text-[10px] rounded border border-rose-700 text-rose-300 hover:bg-rose-950/40 disabled:opacity-50 transition-colors"
                      >
                        {msfLaunching ? <Loader2 size={10} className="animate-spin" /> : <Rocket size={10} />}
                        Launch msfconsole with this module
                      </button>
                      <div className="text-[9px] text-zinc-600 leading-relaxed">
                        Opens msfconsole with the module + options pre-set and stops at "show options". Review, then type "exploit". Active testing only on authorized targets.
                      </div>
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

      {/* Evidence reader modal */}
      {evidenceOpen && selected?.evidence && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
          onClick={() => setEvidenceOpen(false)}
        >
          <div
            className="w-full max-w-4xl max-h-[88vh] flex flex-col rounded-xl border border-zinc-700 bg-zinc-950 shadow-2xl overflow-hidden"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-5 py-3 border-b border-zinc-800 bg-zinc-900 shrink-0">
              <div className="flex items-center gap-2 min-w-0">
                <FileCode2 size={14} className="text-cyan-400 shrink-0" />
                <span className="text-sm font-semibold text-zinc-100 truncate">{selected.title}</span>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <button
                  onClick={() => { navigator.clipboard.writeText(selected.evidence || ''); setCopied(true); setTimeout(() => setCopied(false), 1200) }}
                  className="flex items-center gap-1 text-[11px] text-zinc-400 hover:text-zinc-200 transition-colors"
                >
                  {copied ? <Check size={12} className="text-green-400" /> : <Copy size={12} />} {copied ? 'Copied' : 'Copy all'}
                </button>
                <button onClick={() => setEvidenceOpen(false)} className="text-zinc-600 hover:text-zinc-300">
                  <X size={14} />
                </button>
              </div>
            </div>
            <pre className="overflow-auto p-4 text-[11px] leading-relaxed font-mono text-zinc-300 whitespace-pre-wrap break-all">
              {linkify(selected.evidence)}
            </pre>
          </div>
        </div>
      )}

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
              {activeTab === 'graphql_audit' && <GraphqlGuide />}
              {activeTab === 'viewstate_audit' && <ViewStateGuide />}
              {activeTab === 'github_scanner' && <GithubGuide />}
              {activeTab === 'interactsh' && <InteractshGuide />}
              {activeTab === 'exploit_intel' && <ExploitIntelGuide />}
              {activeTab === 'js_api_mapper' && <JsApiMapperGuide />}
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
            ['200', 'text-green-400', 'Public read. High severity. Full listing is paginated (not just the first page) and parsed into the finding; download and triage.'],
            ['403', 'text-orange-400', 'Bucket exists but private. Info/low severity. Confirm ownership; try region/auth tricks.'],
            ['404 / DNS fail', 'text-zinc-500', 'Bucket does not exist. Skipped.'],
          ].map(([code, color, desc]) => (
            <div key={code} className="flex gap-2 items-start">
              <span className={`font-mono font-bold shrink-0 ${color}`}>{code}</span>
              <span className="text-zinc-500 leading-relaxed">{desc}</span>
            </div>
          ))}
        </div>
      </GuideSection>
      <GuideSection title="Beyond public/private">
        <div className="space-y-1.5 text-[10px] text-zinc-500 leading-relaxed">
          <p><span className="text-red-400 font-semibold">Sensitive files (critical):</span> any listed object name matching .env, .sql/.sqlite, .zip/.tar, .pem/.key, id_rsa, credential/secret/password, wp-config.php, .git, dumps... gets its own finding so you don't have to scroll the whole listing.</p>
          <p><span className="text-orange-400 font-semibold">ACL/policy exposure (high/critical):</span> ?acl and ?policy are fetched directly on S3/GCS/DO — these can be public even when plain listing returns 403, and a WRITE/FULL_CONTROL grant or a wildcard policy Principal is flagged on its own.</p>
          <p><span className="text-red-400 font-semibold">Write-test (opt-in, critical):</span> tick "Test write access" before running to actually PUT (then delete) a marker file on buckets referenced by the target — proves takeover instead of guessing from the ACL. Active probe against real infra, so it only runs on referenced buckets, never on guessed names.</p>
        </div>
      </GuideSection>
      <GuideSection title="Manual follow-up">
        <div className="space-y-1 text-[10px] text-zinc-500 leading-relaxed">
          <p>List it: <code className="text-green-400">aws s3 ls s3://BUCKET --no-sign-request</code> (GCS: <code className="text-green-400">gsutil ls gs://BUCKET</code>).</p>
          <p>Pull it: <code className="text-green-400">aws s3 sync s3://BUCKET . --no-sign-request</code> and grep for keys, .env, dumps, PII.</p>
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

function GraphqlGuide() {
  return (
    <>
      <GuideSection title="New to GraphQL? Read this first">
        <div className="space-y-1.5 text-[10px] text-zinc-500 leading-relaxed">
          <p>
            A normal (REST) API has one URL per thing: <code className="text-zinc-400">/user/123</code>, <code className="text-zinc-400">/menu</code>...
            GraphQL is different: there is <span className="text-zinc-300">one single URL</span> (usually <code className="text-fuchsia-400">/graphql</code>),
            always hit with <span className="text-zinc-300">POST</span>, and you send a query describing exactly what you want:
          </p>
          <pre className="text-[10px] bg-zinc-950 rounded p-2 text-fuchsia-300 overflow-x-auto">{`POST /graphql
{ me { name email orders { id total } } }`}</pre>
          <p>That one request returns your name, email and orders together. Modern apps (Burger King, GitHub, Instagram) use it.</p>
        </div>
      </GuideSection>
      <GuideSection title="4 words you need">
        <div className="space-y-1 text-[10px] text-zinc-500 leading-relaxed">
          <p><span className="text-fuchsia-400 font-semibold">Schema</span> — the full catalog of everything the API can do (its "menu").</p>
          <p><span className="text-fuchsia-400 font-semibold">Query</span> — a read operation (ask for data): <code className="text-zinc-400">me</code>, <code className="text-zinc-400">order</code>.</p>
          <p><span className="text-fuchsia-400 font-semibold">Mutation</span> — a write/action: <code className="text-zinc-400">login</code>, <code className="text-zinc-400">pay</code>, <code className="text-zinc-400">updateProfile</code>.</p>
          <p><span className="text-fuchsia-400 font-semibold">Introspection</span> — a built-in feature that asks the API for its own schema. Meant for developers; if left on in production, <span className="text-zinc-300">anyone gets the full map.</span></p>
        </div>
      </GuideSection>
      <GuideSection title="Why GraphQL leaks (the bug classes)">
        <div className="space-y-1 text-[10px] text-zinc-500 leading-relaxed">
          <p><span className="text-amber-400">1. Introspection left on</span> — hands attackers the whole API map.</p>
          <p><span className="text-amber-400">2. Missing per-operation auth</span> — with one endpoint and many operations, devs forget the lock on some. Queries that should need login return data while logged out.</p>
          <p><span className="text-amber-400">3. IDOR</span> — a query like <code className="text-zinc-400">user(id: X)</code> that does not check the id is yours: swap the id, read someone else's data.</p>
          <p className="text-zinc-600">This tool hunts all three. In short: GraphQL bugs are almost always "they forgot the lock."</p>
        </div>
      </GuideSection>
      <GuideSection title="What this tool does, step by step">
        <div className="space-y-1 text-[10px] text-zinc-500 leading-relaxed">
          <p><span className="text-fuchsia-400 font-semibold">1. Introspection</span> — asks the API for its schema. If it answers, that is already a finding.</p>
          <p><span className="text-fuchsia-400 font-semibold">2. No-auth access check</span> — re-runs each simple query <span className="text-zinc-300">with your token removed</span>. Anything that still returns data is broken access control.</p>
          <p><span className="text-fuchsia-400 font-semibold">3. IDOR test</span> — fills object-by-ID queries with the Sample IDs you provide and probes them without auth.</p>
          <p><span className="text-fuchsia-400 font-semibold">4. Error leaks</span> — sends a broken query; verbose errors often leak internal microservice URLs to pivot to.</p>
          <p><span className="text-fuchsia-400 font-semibold">5. Mutation inventory</span> — lists mutations, flagging auth/payment/OTP ones for manual review.</p>
        </div>
      </GuideSection>
      <GuideSection title="If introspection is disabled">
        <p className="text-[10px] text-zinc-500 leading-relaxed">
          Good targets turn introspection off, so there is no schema to read. The auditor then falls back to
          <span className="text-zinc-300"> name discovery</span>: it probes a built-in wordlist of common query names,
          harvests real names from the server's own <code className="text-fuchsia-400">"Did you mean ..."</code> error hints,
          and tests anything you typed in <span className="text-zinc-300">Extra query names</span> — all without auth.
          If you already know an operation exists (from the app's JS or prior recon), paste it there.
        </p>
      </GuideSection>
      <GuideSection title="Which URL goes here">
        <p className="text-[10px] text-zinc-500 leading-relaxed">
          The <span className="text-zinc-300">GraphQL endpoint</span>, not the website. It is the URL that receives
          POST requests with a JSON <code className="text-fuchsia-400">{'{ "query": ... }'}</code> body. Typical paths:
          <code className="text-fuchsia-400"> /graphql</code>, <code className="text-fuchsia-400">/api/graphql</code>,
          <code className="text-fuchsia-400"> /v1/graphql</code>, <code className="text-fuchsia-400">/query</code>.
          Example: <code className="text-green-400">https://api.target.com/graphql</code>.
        </p>
      </GuideSection>
      <GuideSection title="How to find the endpoint">
        <div className="space-y-1 text-[10px] text-zinc-500 leading-relaxed">
          <p>• Run the <span className="text-blue-400">JS Secrets</span> pipeline — it flags <code className="text-blue-400">graphql_endpoint</code> references.</p>
          <p>• Or DevTools (F12) → Network → filter <span className="text-zinc-300">Fetch/XHR</span> → look for POST requests to a <code className="text-fuchsia-400">/graphql</code> path. The host is often a separate API domain (e.g. <code className="text-zinc-400">api.*</code>, <code className="text-zinc-400">*-gateway.*</code>).</p>
        </div>
      </GuideSection>
      <GuideSection title="Set your Session first">
        <p className="text-[10px] text-zinc-500 leading-relaxed">
          Paste your <code className="text-fuchsia-400">Authorization: Bearer ...</code> (and any required context headers like
          <code className="text-fuchsia-400"> x-ui-region</code>) in the <span className="text-zinc-300">Session</span> panel.
          The auditor uses it for introspection, then strips it for the no-auth check — so it compares what an
          authenticated user sees vs an anonymous one. It still runs without a token, just with less coverage.
        </p>
      </GuideSection>
      <GuideSection title="What each finding means">
        <div className="space-y-1 text-[10px]">
          {[
            ['Introspection enabled', 'text-yellow-400', 'The schema is public. Low/medium on its own, but it powers everything else.'],
            ['Returns data without authentication', 'text-red-400', 'A sensitive query answers with no token = broken access control. Usually high impact.'],
            ['IDOR — reads object by ID', 'text-red-400', 'An object is readable by id with no auth. Swap the id to read other users (BOLA).'],
            ['Internal endpoint leaked', 'text-orange-400', 'A response/error exposed an internal microservice URL. Probe it directly.'],
            ['Mutations exposed', 'text-blue-400', 'Inventory of write operations (info). Review payment/OTP/auth ones by hand.'],
          ].map(([t, color, desc]) => (
            <div key={t} className="flex gap-2 items-start">
              <span className={`font-semibold shrink-0 ${color}`}>{t}:</span>
              <span className="text-zinc-500 leading-relaxed">{desc}</span>
            </div>
          ))}
        </div>
      </GuideSection>
      <GuideSection title="Is it safe to run?">
        <p className="text-[10px] text-zinc-500 leading-relaxed">
          Yes — it is <span className="text-green-300">read-only</span>. It only sends queries (reads) and introspection; it never
          executes mutations, so it does not change, delete or buy anything. The IDOR test only uses IDs <span className="text-zinc-300">you</span> paste —
          it does not enumerate other users' IDs. Still, only run it against targets you are authorized to test.
        </p>
      </GuideSection>
      <Tip>A "returns data without authentication" hit on a query like <code className="text-fuchsia-400">me</code>, <code className="text-fuchsia-400">order</code> or <code className="text-fuchsia-400">loyaltyUser</code> is usually a high-impact broken-access-control bug. Verify with the curl in the finding, then build the full query by hand to pull the actual data.</Tip>
    </>
  )
}

function ViewStateGuide() {
  return (
    <>
      <GuideSection title="New to this? Read this first">
        <div className="space-y-1.5 text-[10px] text-zinc-500 leading-relaxed">
          <p>
            Sites built on <span className="text-zinc-300">ASP.NET WebForms</span> (Microsoft, very common in
            enterprise/legacy apps — pages ending in <code className="text-cyan-400">.aspx</code>) carry a giant hidden field
            called <code className="text-cyan-400">__VIEWSTATE</code> in every form:
          </p>
          <pre className="text-[10px] bg-zinc-950 rounded p-2 text-cyan-300 overflow-x-auto">{`<input type="hidden" name="__VIEWSTATE"
       value="/wEPDwUJNjgzNDM1ODU3DxYE..." />`}</pre>
          <p>
            That long value is just <span className="text-zinc-300">Base64</span>, not encryption. It stores the page's state
            between clicks. Developers sometimes dump config into it ("it's encoded, nobody reads it") — so it leaks.
          </p>
        </div>
      </GuideSection>
      <GuideSection title="The two bugs this finds">
        <div className="space-y-1 text-[10px] text-zinc-500 leading-relaxed">
          <p><span className="text-amber-400">1. Secret leakage</span> — decode the blob and read embedded credentials, DB connection strings, private/API keys, internal service URLs and IPs in cleartext.</p>
          <p><span className="text-amber-400">2. Deserialization RCE</span> — if the VIEWSTATE is not encrypted <span className="text-zinc-300">and</span> its MAC is disabled, you can forge a malicious blob the server deserializes into code execution (the classic <code className="text-zinc-400">ysoserial.net -p ViewState</code> attack).</p>
        </div>
      </GuideSection>
      <GuideSection title="What this tool does, step by step">
        <div className="space-y-1 text-[10px] text-zinc-500 leading-relaxed">
          <p><span className="text-cyan-400 font-semibold">1. Find it</span> — fetches the URL plus common entry points (<code className="text-zinc-400">/</code>, <code className="text-zinc-400">/default.aspx</code>, <code className="text-zinc-400">/login.aspx</code>) and pulls __VIEWSTATE + __VIEWSTATEGENERATOR.</p>
          <p><span className="text-cyan-400 font-semibold">2. Decode</span> — Base64-decodes and checks if it is encrypted (encrypted blobs lack the <code className="text-zinc-400">0xFF01</code> ObjectStateFormatter marker).</p>
          <p><span className="text-cyan-400 font-semibold">3. Mine</span> — on cleartext blobs, runs strings extraction and flags credentials, keys, connection strings, AWS keys, private IPs and internal/SOAP URLs.</p>
          <p><span className="text-cyan-400 font-semibold">4. RCE flag</span> — an unencrypted blob with a generator value is reported as an RCE candidate (verify the MAC by hand with ysoserial.net).</p>
          <p><span className="text-cyan-400 font-semibold">5. SOAP enum</span> — any <code className="text-zinc-400">.asmx</code>/<code className="text-zinc-400">.svc</code> referenced on the page or inside the blob gets its WSDL pulled and its methods listed.</p>
        </div>
      </GuideSection>
      <GuideSection title="Which URL goes here">
        <p className="text-[10px] text-zinc-500 leading-relaxed">
          Any ASP.NET page that renders a form — login pages and search/listing pages are the richest.
          Look for URLs ending in <code className="text-cyan-400">.aspx</code>, or "View source" and search for
          <code className="text-cyan-400"> __VIEWSTATE</code>. If it is there, this tool has something to chew on.
          You can also sweep every live host from Recon with the bulk button.
        </p>
      </GuideSection>
      <GuideSection title="Runs inside JS Secrets too">
        <p className="text-[10px] text-zinc-500 leading-relaxed">
          The <span className="text-blue-400">JS Secrets</span> pipeline now auto-decodes any __VIEWSTATE it crawls, so you
          get these findings for free across a whole site without picking pages by hand.
        </p>
      </GuideSection>
      <GuideSection title="Is it safe to run?">
        <p className="text-[10px] text-zinc-500 leading-relaxed">
          Yes — <span className="text-green-300">read-only</span>. It only GETs pages and decodes a field that was already
          sent to your browser; it never forges or replays a VIEWSTATE. The RCE finding is a <span className="text-zinc-300">candidate</span>
          flag — actual exploitation (ysoserial.net) is a manual step you run only with authorization.
        </p>
      </GuideSection>
      <Tip>An unencrypted VIEWSTATE that leaks an internal URL with a non-standard port (like <code className="text-cyan-400">http://10.0.0.5:8083/...asmx</code>) is gold: it usually points at an internal SOAP backend. Let the tool pull its WSDL, then review the methods for unauthenticated, state-changing operations.</Tip>
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

function JsApiMapperGuide() {
  return (
    <>
      <GuideSection title="What it does">
        <div className="space-y-1.5 text-[10px] text-zinc-500 leading-relaxed">
          <p>Recovers the API from the client JS: <span className="text-teal-400">route strings</span>, <span className="text-teal-400">path→method maps</span>, and <span className="text-teal-400">role/permission arrays</span>.</p>
          <p>Fingerprints the auth framework (better-auth, NextAuth, Supabase, Firebase, Laravel Sanctum) by its route signatures and <span className="text-teal-400">expands</span> to the library's full admin endpoint set — even the ones the client never calls.</p>
          <p>Flags privileged routes (admin / impersonate / set-role / set-password / delete) and emits an access-control test plan per route.</p>
        </div>
      </GuideSection>
      <GuideSection title="How to use the output">
        <div className="space-y-1 text-[10px] text-zinc-500 leading-relaxed">
          <p>1. Register a normal account on the target and grab its JWT/session (via the Proxy or DevTools).</p>
          <p>2. Replay each privileged route as <code className="text-teal-400">anonymous</code> and as that <code className="text-teal-400">normal user</code>.</p>
          <p>3. A <code className="text-green-400">2xx</code> where you expected <code className="text-orange-400">401/403</code> = broken access control. Routes with an id/param = test IDOR too.</p>
        </div>
      </GuideSection>
      <Tip>The biggest wins live here: an <code className="text-red-400">impersonate-user</code> or <code className="text-red-400">set-role</code> route reachable by a normal user is account takeover / privilege escalation — usually P1.</Tip>
    </>
  )
}

function ExploitIntelGuide() {
  return (
    <>
      <GuideSection title="Requires: searchsploit + metasploit-framework">
        <code className="block text-[10px] text-green-400 bg-zinc-900 rounded px-2 py-1 font-mono">
          sudo apt install exploitdb metasploit-framework
        </code>
        <p className="text-[10px] text-zinc-500 leading-relaxed mt-1">
          Run <code className="text-green-400">msfconsole</code> once so it builds its module cache (the first run is slow).
        </p>
      </GuideSection>
      <GuideSection title="How it works">
        <div className="space-y-1.5 text-[10px] text-zinc-500 leading-relaxed">
          <p><span className="text-rose-400 font-semibold">Input:</span> leave the box empty to auto-use every technology fingerprinted on your Recon live hosts, or type a product + version ("Apache 2.4.49") or a CVE ("CVE-2021-44228").</p>
          <p><span className="text-rose-400 font-semibold">Exploit-DB:</span> runs searchsploit per tech. Each hit shows the EDB-ID, type and the commands to pull (<code className="text-green-400">searchsploit -m ID</code>) and read (<code className="text-green-400">searchsploit -x ID</code>) it.</p>
          <p><span className="text-rose-400 font-semibold">Metasploit:</span> searches the module DB by product name and by CVE. Exploit modules rank highest. Each one gets a "Run in Metasploit" button.</p>
        </div>
      </GuideSection>
      <GuideSection title="Run in Metasploit">
        <div className="space-y-1 text-[10px] text-zinc-500 leading-relaxed">
          <p>Open a Metasploit finding, set RHOSTS (target) and optionally LHOST (your IP for reverse shells), then Launch. It writes a resource script with everything pre-set and opens msfconsole stopped at <code className="text-green-400">show options</code> — review, then type <code className="text-green-400">exploit</code>.</p>
        </div>
      </GuideSection>
      <Tip>Version matching is a LEAD, not proof. A banner version can be patched/backported and still report old. Confirm the module's check (<code className="text-green-400">check</code> in msf) or verify manually before firing — and only against authorized targets.</Tip>
    </>
  )
}
