import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ScopeSelector } from '@/components/ui/scope-selector'
import { api } from '@/api/http-client'
import { toast } from '@/stores/toast-store'
import { cn } from '@/lib/utils'
import { useAppStore } from '@/stores/app-store'
import { useWordPressStore } from '@/stores/wordpress-store'
import { buildAttackPlan, type WpAction, type ActionPriority } from '@/lib/wordpress-playbook'
import {
  Play, Loader2, Square, Trash2, ChevronDown, Settings2, KeyRound,
  ShieldAlert, Package, Palette, Users, AlertTriangle, FileWarning,
  Eye, Globe, CheckCircle2, XCircle, Swords, Copy, TerminalSquare, Check as CheckIcon,
} from 'lucide-react'

const PROFILES = [
  { id: 'quick',    label: 'Quick',    desc: 'Version + interesting findings. Passive, fast, low noise.' },
  { id: 'standard', label: 'Standard', desc: 'Vuln plugins/themes, config backups, db exports, users, media. Recommended.' },
  { id: 'thorough', label: 'Thorough', desc: 'All plugins/themes aggressively + wider user range. Slow & noisy.' },
]

const SEV_ORDER: Record<string, number> = { high: 0, medium: 1, low: 2, info: 3 }

const PRIO_STYLE: Record<ActionPriority, string> = {
  critical: 'text-red-400 bg-red-950/50 border-red-800',
  high:     'text-orange-400 bg-orange-950/50 border-orange-800',
  medium:   'text-yellow-400 bg-yellow-950/40 border-yellow-800',
  low:      'text-zinc-400 bg-zinc-900 border-zinc-700',
  info:     'text-zinc-500 bg-zinc-900 border-zinc-800',
}

export function WordPressPage() {
  const navigate = useNavigate()
  const { globalTarget, setGlobalTarget, activeProject, getSessionOpts, setPendingCommand } = useAppStore()
  const [target, setTargetLocal] = useState(globalTarget)
  const [profile, setProfile] = useState('standard')
  const [showAdv, setShowAdv] = useState(false)
  const [opts, setOpts] = useState({
    random_user_agent: true, stealthy: false, disable_tls_checks: false, force: false,
    passwords: '', usernames: '', password_attack: '',
  })
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const logRef = useRef<HTMLPreElement>(null)
  const advRef = useRef<HTMLDivElement>(null)

  const {
    version, theme, plugins, themes, users, vulns, interesting, configBackups,
    log, running, jobId, apiTokenSet, installed, setStatus, setRunning, clear,
  } = useWordPressStore()

  const setTarget = (v: string) => { setTargetLocal(v); setGlobalTarget(v) }

  useEffect(() => {
    api.get<{ installed: boolean; api_token_set: boolean }>('/api/wordpress/status')
      .then(s => setStatus({ installed: s.installed, apiTokenSet: s.api_token_set }))
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [log.length])

  const handleScan = async () => {
    if (!target.trim()) return
    clear()
    try {
      const sess = getSessionOpts()
      const res = await api.post<{ job_id: string }>('/api/wordpress/scan', {
        target: target.trim(),
        profile,
        project_id: activeProject ?? '',
        options: {
          random_user_agent: opts.random_user_agent,
          stealthy: opts.stealthy,
          disable_tls_checks: opts.disable_tls_checks,
          force: opts.force,
          passwords: opts.passwords || undefined,
          usernames: opts.usernames || undefined,
          password_attack: opts.password_attack || undefined,
          ...sess,
        },
      })
      setRunning(true, res.job_id)
    } catch (err) {
      toast.error('Scan failed to start', err)
    }
  }

  const handleStop = async () => {
    if (!jobId) return
    try { await api.delete(`/api/wordpress/jobs/${jobId}`) } catch {}
  }

  const sortedVulns = [...vulns].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9))

  const hasFindings = !!(version || theme || plugins.length || users.length || vulns.length || interesting.length || configBackups.length)
  const attackPlan = hasFindings
    ? buildAttackPlan(target, { version, theme, plugins, users, vulns, interesting, configBackups })
    : []

  const copyCommand = (a: WpAction) => {
    if (!a.command) return
    navigator.clipboard.writeText(a.command)
    setCopiedId(a.id)
    setTimeout(() => setCopiedId(null), 1500)
  }

  const runInTerminal = (a: WpAction) => {
    if (!a.command) return
    setPendingCommand(a.command)
    navigate('/terminal')
  }

  const configurePasswordAttack = () => {
    setOpts(p => ({
      ...p,
      usernames: users.join(','),
      passwords: p.passwords || '/usr/share/wordlists/rockyou.txt',
      password_attack: 'xmlrpc-multicall',
    }))
    setShowAdv(true)
    setTimeout(() => advRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 100)
  }

  return (
    <WorkspaceShell title="WordPress" subtitle="Black-box WordPress pentest powered by WPScan">
      <div className="flex flex-col gap-4 max-w-[1400px]">
        {/* Status banner */}
        <div className="flex flex-wrap items-center gap-3 rounded-xl border border-zinc-800 bg-zinc-900/50 px-4 py-2.5">
          <div className="flex items-center gap-1.5 text-xs">
            {installed
              ? <CheckCircle2 size={13} className="text-green-500" />
              : <XCircle size={13} className="text-red-500" />}
            <span className={installed ? 'text-zinc-400' : 'text-red-400'}>
              wpscan {installed ? 'installed' : 'not installed (gem install wpscan)'}
            </span>
          </div>
          <div className="w-px h-4 bg-zinc-800" />
          <button
            onClick={() => navigate('/settings')}
            className="flex items-center gap-1.5 text-xs group"
            title="Configure in Settings"
          >
            <KeyRound size={13} className={apiTokenSet ? 'text-green-500' : 'text-amber-500'} />
            <span className={cn('group-hover:underline', apiTokenSet ? 'text-zinc-400' : 'text-amber-400')}>
              WPScan API token {apiTokenSet ? 'configured' : 'not set — vuln data disabled'}
            </span>
          </button>
          {!apiTokenSet && (
            <span className="text-[10px] text-zinc-600">
              Free token (25 req/day) at wpscan.com/profile → Settings
            </span>
          )}
        </div>

        {/* Target + profile */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4 space-y-3">
          <div className="text-[10px] font-semibold tracking-wider text-zinc-500 uppercase">Target</div>
          <div className="flex flex-col sm:flex-row gap-2">
            <div className="sm:w-56 shrink-0"><ScopeSelector onSelect={setTarget} selectedTarget={target} /></div>
            <Input
              placeholder="https://wordpress-site.com"
              className="flex-1 bg-zinc-950 text-sm font-mono"
              value={target}
              onChange={e => setTarget(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && !running) handleScan() }}
            />
          </div>

          {/* Profile cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            {PROFILES.map(p => (
              <button
                key={p.id}
                onClick={() => setProfile(p.id)}
                className={cn(
                  'text-left rounded-lg border p-3 transition-colors',
                  profile === p.id
                    ? 'border-blue-600 bg-blue-950/30'
                    : 'border-zinc-800 bg-zinc-950 hover:border-zinc-600'
                )}
              >
                <div className={cn('text-xs font-bold', profile === p.id ? 'text-blue-400' : 'text-zinc-300')}>{p.label}</div>
                <div className="text-[10px] text-zinc-500 mt-1 leading-relaxed">{p.desc}</div>
              </button>
            ))}
          </div>

          {/* Advanced options */}
          <button
            onClick={() => setShowAdv(v => !v)}
            className="flex items-center gap-1 text-[10px] text-zinc-500 hover:text-zinc-300 transition-colors"
          >
            <Settings2 size={11} /> Advanced options
            <ChevronDown size={11} className={cn('transition-transform', showAdv && 'rotate-180')} />
          </button>
          {showAdv && (
            <div ref={advRef} className="space-y-3 border-l border-zinc-800 pl-3">
              <div className="flex flex-wrap gap-x-4 gap-y-1.5">
                <Check label="Random user-agent" checked={opts.random_user_agent} onChange={v => setOpts(p => ({ ...p, random_user_agent: v }))} />
                <Check label="Stealthy (passive)" checked={opts.stealthy} onChange={v => setOpts(p => ({ ...p, stealthy: v }))} />
                <Check label="Disable TLS checks" checked={opts.disable_tls_checks} onChange={v => setOpts(p => ({ ...p, disable_tls_checks: v }))} />
                <Check label="Force (skip WP check / 403)" checked={opts.force} onChange={v => setOpts(p => ({ ...p, force: v }))} />
              </div>
              {/* Password attack */}
              <div className="rounded-lg border border-red-900/40 bg-red-950/10 p-3 space-y-2">
                <div className="flex items-center gap-1.5 text-[10px] font-semibold text-red-400">
                  <ShieldAlert size={11} /> Password attack (optional — noisy, authorized targets only)
                </div>
                <OptRow label="Wordlist path" placeholder="/usr/share/wordlists/rockyou.txt" value={opts.passwords} onChange={v => setOpts(p => ({ ...p, passwords: v }))} />
                <OptRow label="Usernames" placeholder="admin,editor (blank = enumerated users)" value={opts.usernames} onChange={v => setOpts(p => ({ ...p, usernames: v }))} />
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-zinc-600 w-24 shrink-0 text-right">Attack:</span>
                  <select
                    value={opts.password_attack}
                    onChange={e => setOpts(p => ({ ...p, password_attack: e.target.value }))}
                    className="text-[10px] bg-zinc-950 border border-zinc-800 rounded px-2 py-1 text-zinc-300 focus:outline-none focus:border-zinc-600"
                  >
                    <option value="">auto</option>
                    <option value="wp-login">wp-login</option>
                    <option value="xmlrpc">xmlrpc</option>
                    <option value="xmlrpc-multicall">xmlrpc-multicall</option>
                  </select>
                </div>
              </div>
            </div>
          )}

          {/* Run / Stop */}
          <div className="flex items-center gap-2">
            {running ? (
              <Button variant="outline" size="sm" className="border-red-700 text-red-400 hover:bg-red-950/40" onClick={handleStop}>
                <Square size={12} className="mr-1.5 fill-current" /> Stop scan
              </Button>
            ) : (
              <Button size="sm" className="bg-blue-700 hover:bg-blue-600 text-white" disabled={!target.trim() || !installed} onClick={handleScan}>
                <Play size={12} className="mr-1.5" /> Run WordPress scan
              </Button>
            )}
            {running && <span className="text-xs text-zinc-500 flex items-center gap-1.5"><Loader2 size={12} className="animate-spin" /> scanning {target}</span>}
          </div>
        </div>

        {/* Attack plan */}
        {attackPlan.length > 0 && (
          <div className="rounded-xl border border-blue-900/40 bg-blue-950/10 overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-2.5 border-b border-zinc-800 bg-zinc-900/50">
              <Swords size={15} className="text-blue-400" />
              <span className="text-sm font-semibold text-zinc-200">Attack Plan</span>
              <span className="text-[10px] text-zinc-500">— prioritized next steps from the findings</span>
              <span className="ml-auto text-[10px] text-zinc-500">{attackPlan.length} actions</span>
            </div>
            <div className="divide-y divide-zinc-800/60">
              {attackPlan.map(a => (
                <div key={a.id} className="p-3 hover:bg-zinc-900/30 transition-colors">
                  <div className="flex items-start gap-2.5">
                    <span className={cn('text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border shrink-0 mt-0.5', PRIO_STYLE[a.priority])}>
                      {a.priority}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="text-[12px] font-semibold text-zinc-200">{a.title}</div>
                      <div className="text-[11px] text-zinc-500 leading-relaxed mt-0.5">{a.why}</div>
                      <div className="text-[9px] text-zinc-600 mt-1 font-mono">from: {a.source}</div>
                      {a.command && (
                        <div className="mt-2 flex items-stretch gap-1.5">
                          <code className="flex-1 min-w-0 text-[10px] font-mono bg-black border border-zinc-800 rounded px-2 py-1.5 text-green-300 overflow-x-auto whitespace-nowrap">
                            {a.command}
                          </code>
                          <button
                            onClick={() => copyCommand(a)}
                            title="Copy command"
                            className="shrink-0 px-2 rounded border border-zinc-700 text-zinc-400 hover:border-zinc-500 hover:text-zinc-200 transition-colors"
                          >
                            {copiedId === a.id ? <CheckIcon size={12} className="text-green-400" /> : <Copy size={12} />}
                          </button>
                          <button
                            onClick={() => runInTerminal(a)}
                            title="Run in NexHunt terminal"
                            className="shrink-0 px-2 rounded border border-blue-700 text-blue-400 hover:bg-blue-950/40 transition-colors flex items-center gap-1"
                          >
                            <TerminalSquare size={12} />
                            <span className="text-[10px] font-medium">Run</span>
                          </button>
                        </div>
                      )}
                      {a.inApp === 'password-attack' && (
                        <button
                          onClick={configurePasswordAttack}
                          className="mt-2 text-[10px] font-medium px-2 py-1 rounded border border-red-800 text-red-400 hover:bg-red-950/40 transition-colors flex items-center gap-1.5 w-fit"
                        >
                          <ShieldAlert size={11} /> Configure this attack in-app
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Results grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Left: terminal */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4 space-y-2 flex flex-col">
            <div className="flex items-center justify-between">
              <div className="text-[10px] font-semibold tracking-wider text-zinc-500 uppercase">Live output</div>
              <Button variant="ghost" size="sm" className="text-zinc-600 hover:text-red-400 text-xs h-6" onClick={clear} disabled={running}>
                <Trash2 size={11} className="mr-1" /> Clear
              </Button>
            </div>
            <div className="rounded-lg border border-zinc-800 bg-black overflow-auto h-[420px]">
              <pre ref={logRef} className="text-[11px] font-mono whitespace-pre-wrap leading-relaxed p-3">
                {log.length > 0
                  ? log.map((line, i) => (
                      <span key={i} className={cn('block',
                        /\[!\]/.test(line) ? 'text-red-400 font-semibold' :
                        /\[\+\]/.test(line) ? 'text-green-400' :
                        /\[i\]/.test(line) ? 'text-blue-400' :
                        line.startsWith('$ ') ? 'text-zinc-500' :
                        line.includes('|') ? 'text-zinc-600' :
                        'text-zinc-400'
                      )}>{line}</span>
                    ))
                  : <span className="text-zinc-700">No scan yet. Set a target and run a scan.</span>}
              </pre>
            </div>
          </div>

          {/* Right: structured findings */}
          <div className="space-y-4">
            {/* Version + theme */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4">
              <div className="flex items-center gap-2 mb-2">
                <Globe size={14} className="text-blue-400" />
                <span className="text-xs font-semibold text-zinc-300">Core</span>
              </div>
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <div className="text-[10px] text-zinc-600 uppercase tracking-widest mb-0.5">Version</div>
                  {version
                    ? <div className="font-mono text-zinc-200">{version.value}
                        <span className={cn('ml-1.5 text-[10px]', /insecure|out of date/i.test(version.status) ? 'text-red-400' : 'text-green-400')}>
                          ({version.status})
                        </span>
                      </div>
                    : <div className="text-zinc-600">—</div>}
                </div>
                <div>
                  <div className="text-[10px] text-zinc-600 uppercase tracking-widest mb-0.5">Active theme</div>
                  <div className="font-mono text-zinc-200">{theme ?? <span className="text-zinc-600">—</span>}</div>
                </div>
              </div>
            </div>

            {/* Vulnerabilities */}
            <ResultPanel icon={<AlertTriangle size={14} className="text-red-400" />} title="Vulnerabilities" count={vulns.length} accent="red">
              {sortedVulns.map((v, i) => (
                <div key={i} className="flex items-start gap-2 px-3 py-2 border-b border-zinc-800/60 last:border-0">
                  <span className={cn('text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border shrink-0 mt-0.5',
                    v.severity === 'high' ? 'text-red-400 bg-red-950/50 border-red-800' :
                    v.severity === 'medium' ? 'text-orange-400 bg-orange-950/50 border-orange-800' :
                    'text-yellow-400 bg-yellow-950/40 border-yellow-800'
                  )}>{v.severity}</span>
                  <span className="text-[11px] text-zinc-300 leading-snug">{v.title}</span>
                </div>
              ))}
              {vulns.length === 0 && <EmptyHint text={apiTokenSet ? 'No vulnerabilities reported yet.' : 'Set a WPScan API token to get vulnerability data.'} />}
            </ResultPanel>

            {/* Plugins */}
            <ResultPanel icon={<Package size={14} className="text-purple-400" />} title="Plugins" count={plugins.length} accent="purple">
              <ChipList items={plugins} />
            </ResultPanel>

            {/* Users */}
            <ResultPanel icon={<Users size={14} className="text-cyan-400" />} title="Users" count={users.length} accent="cyan">
              <ChipList items={users} mono />
            </ResultPanel>

            {/* Themes (other than active) */}
            {themes.length > 0 && (
              <ResultPanel icon={<Palette size={14} className="text-pink-400" />} title="Other themes" count={themes.length} accent="pink">
                <ChipList items={themes} />
              </ResultPanel>
            )}

            {/* Interesting findings */}
            {interesting.length > 0 && (
              <ResultPanel icon={<Eye size={14} className="text-amber-400" />} title="Interesting findings" count={interesting.length} accent="amber">
                {interesting.map((t, i) => (
                  <div key={i} className="px-3 py-1.5 text-[11px] text-zinc-400 border-b border-zinc-800/60 last:border-0">{t}</div>
                ))}
              </ResultPanel>
            )}

            {/* Config backups */}
            {configBackups.length > 0 && (
              <ResultPanel icon={<FileWarning size={14} className="text-red-400" />} title="Config / DB backups" count={configBackups.length} accent="red">
                {configBackups.map((u, i) => (
                  <div key={i} className="px-3 py-1.5 text-[11px] font-mono text-red-300 truncate border-b border-zinc-800/60 last:border-0">{u}</div>
                ))}
              </ResultPanel>
            )}
          </div>
        </div>
      </div>
    </WorkspaceShell>
  )
}

function ResultPanel({ icon, title, count, accent, children }: {
  icon: React.ReactNode; title: string; count: number; accent: string; children: React.ReactNode
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-zinc-800">
        {icon}
        <span className="text-xs font-semibold text-zinc-300">{title}</span>
        {count > 0 && (
          <span className={cn('ml-auto text-[10px] font-bold rounded-full px-1.5 py-0.5',
            accent === 'red' ? 'bg-red-600 text-white' : 'bg-zinc-700 text-zinc-200'
          )}>{count}</span>
        )}
      </div>
      <div className="max-h-56 overflow-y-auto">{children}</div>
    </div>
  )
}

function ChipList({ items, mono }: { items: string[]; mono?: boolean }) {
  if (items.length === 0) return <EmptyHint text="Nothing found yet." />
  return (
    <div className="flex flex-wrap gap-1.5 p-3">
      {items.map((it, i) => (
        <span key={i} className={cn('text-[11px] px-2 py-0.5 rounded border border-zinc-700 bg-zinc-950 text-zinc-300', mono && 'font-mono')}>{it}</span>
      ))}
    </div>
  )
}

function EmptyHint({ text }: { text: string }) {
  return <div className="px-3 py-4 text-center text-[11px] text-zinc-600">{text}</div>
}

function Check({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center gap-1.5 cursor-pointer">
      <input type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)} className="w-3 h-3 accent-blue-500" />
      <span className="text-[10px] text-zinc-400">{label}</span>
    </label>
  )
}

function OptRow({ label, placeholder, value, onChange }: {
  label: string; placeholder: string; value: string; onChange: (v: string) => void
}) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-[10px] text-zinc-600 w-24 shrink-0 text-right">{label}:</span>
      <input
        type="text" placeholder={placeholder} value={value} onChange={e => onChange(e.target.value)}
        className="flex-1 min-w-0 text-[10px] bg-zinc-950 border border-zinc-800 rounded px-2 py-1 text-zinc-400 placeholder:text-zinc-700 focus:outline-none focus:border-zinc-600 font-mono"
      />
    </div>
  )
}
