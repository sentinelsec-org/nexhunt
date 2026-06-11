import { useState, useEffect } from 'react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { api } from '@/api/http-client'
import { useLicenseStore } from '@/stores/license-store'
import type { ToolStatus } from '@/types'
import { TOOL_CATEGORIES, API_BASE } from '@/lib/constants'
import {
  Wrench,
  CheckCircle,
  XCircle,
  Download,
  Key,
  Globe,
  Check,
  Crown,
  KeyRound,
  RefreshCw,
  Loader2,
  ExternalLink,
  Cpu,
  ArrowUpCircle,
} from 'lucide-react'

const GROQ_MODELS = [
  { id: 'llama-3.3-70b-versatile', label: 'Llama 3.3 70B Versatile (recommended)' },
  { id: 'llama-3.1-8b-instant', label: 'Llama 3.1 8B Instant (fastest)' },
  { id: 'mixtral-8x7b-32768', label: 'Mixtral 8x7B (32k context)' },
  { id: 'gemma2-9b-it', label: 'Gemma 2 9B (Google)' },
]

export function SettingsPage() {
  const [tools, setTools] = useState<ToolStatus[]>([])
  const [proxyPort, setProxyPort] = useState('8080')
  const [aiProvider, setAiProvider] = useState('groq')
  const [aiModel, setAiModel] = useState('llama-3.3-70b-versatile')
  const [groqKey, setGroqKey] = useState('')
  const [groqKeySet, setGroqKeySet] = useState(false)
  const [aiApiKey, setAiApiKey] = useState('')
  const [language, setLanguage] = useState('en')
  const [ngrokToken, setNgrokToken] = useState('')
  const [saved, setSaved] = useState(false)

  const fetchTools = async () => {
    try {
      const data = await api.get<ToolStatus[]>('/api/tools/status')
      setTools(data)
    } catch (err) {
      console.error('Failed to fetch tool status:', err)
    }
  }

  useEffect(() => {
    fetchTools()
    api.get<any>('/api/settings').then(s => {
      if (s.proxy_port) setProxyPort(String(s.proxy_port))
      if (s.ai_provider) setAiProvider(s.ai_provider)
      if (s.ai_model) setAiModel(s.ai_model)
      if (s.ai_groq_key_set) setGroqKeySet(true)
      if (s.language) setLanguage(s.language)
      if (s.ngrok_authtoken_set) setNgrokToken('')
    }).catch(() => {})
    useLicenseStore.getState().fetchStatus()
  }, [])

  const handleSaveSettings = async () => {
    try {
      await api.post('/api/settings', {
        proxy_port: parseInt(proxyPort),
        ai_provider: aiProvider,
        ai_model: aiModel,
        ai_groq_key: groqKey,
        ai_api_key: aiApiKey || undefined,
        language,
        ngrok_authtoken: ngrokToken || undefined,
      })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (err) {
      console.error('Failed to save settings:', err)
    }
  }

  return (
    <WorkspaceShell title="Settings" subtitle="Configure NexHunt">
      <div className="space-y-6 max-w-3xl">
        {/* License */}
        <LicenseSection />

        {/* Updates */}
        <UpdatesSection />

        {/* Proxy settings */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-5">
          <h3 className="font-semibold text-zinc-200 mb-4 flex items-center gap-2">
            <Globe size={16} /> Proxy Settings
          </h3>
          <div className="space-y-4">
            <div className="flex gap-4 flex-wrap">
              <div>
                <label className="text-xs text-zinc-500 mb-1 block">Proxy Port</label>
                <Input
                  className="w-32 bg-zinc-900"
                  value={proxyPort}
                  onChange={e => setProxyPort(e.target.value)}
                />
              </div>
              <div>
                <label className="text-xs text-zinc-500 mb-1 block">CA Certificate</label>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => window.open(`${API_BASE}/api/proxy/cert`, '_blank')}
                >
                  <Download size={12} className="mr-1" /> Download CA Cert
                </Button>
              </div>
            </div>

            {/* Setup guide */}
            <div className="rounded-lg border border-zinc-700 bg-zinc-900 p-4 space-y-3">
              <div className="text-xs font-semibold text-zinc-300">FoxyProxy Setup — step by step</div>
              <ol className="space-y-2">
                {[
                  { n: 1, title: 'Start the proxy', desc: 'Go to the Proxy tab and click Start. The proxy listens on port 8080.' },
                  { n: 2, title: 'Configure FoxyProxy', desc: 'Add a new proxy: Type = HTTP, Host = 127.0.0.1, Port = 8080. Enable it.' },
                  { n: 3, title: 'HTTP sites', desc: 'Already works. Browse any http:// site — traffic appears in the Proxy tab.' },
                  { n: 4, title: 'HTTPS sites (CA cert required)', desc: 'Download the cert above. In Firefox: Settings → Privacy & Security → View Certificates → AUTHORITIES tab → Import. Tick "Trust this CA to identify websites". Do NOT use the "Your Certificates" tab — that gives a private key error.' },
                  { n: 5, title: 'Verify', desc: 'Browse any https:// site. It should load normally and flows appear in NexHunt.' },
                ].map(step => (
                  <li key={step.n} className="flex gap-3 text-xs">
                    <span className="shrink-0 w-5 h-5 rounded-full bg-zinc-700 text-zinc-300 flex items-center justify-center text-[10px] font-bold mt-0.5">
                      {step.n}
                    </span>
                    <div>
                      <span className="font-medium text-zinc-300">{step.title} — </span>
                      <span className="text-zinc-500">{step.desc}</span>
                    </div>
                  </li>
                ))}
              </ol>
              <div className="text-[11px] text-zinc-600 border-t border-zinc-800 pt-2">
                Chrome/Chromium: import the cert via chrome://settings/certificates → Authorities → Import
              </div>
            </div>
          </div>
        </div>

        {/* AI settings */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-5">
          <h3 className="font-semibold text-zinc-200 mb-4 flex items-center gap-2">
            <Key size={16} /> AI Copilot Settings
          </h3>
          <div className="space-y-3">
            <div>
              <label className="text-xs text-zinc-500 mb-1 block">AI Provider</label>
              <select
                className="h-9 rounded-md border border-input bg-zinc-900 px-3 text-sm text-zinc-300 w-48"
                value={aiProvider}
                onChange={e => setAiProvider(e.target.value)}
              >
                <option value="groq">Groq (fast + free tier)</option>
                <option value="openai">OpenAI</option>
                <option value="claude">Claude (Anthropic)</option>
              </select>
            </div>

            {aiProvider === 'groq' && (
              <>
                <div>
                  <label className="text-xs text-zinc-500 mb-1 block">Groq API Key</label>
                  <Input
                    type="password"
                    className="bg-zinc-900 font-mono text-sm"
                    placeholder={groqKeySet ? 'configured — leave blank to keep' : 'gsk_...'}
                    value={groqKey}
                    onChange={e => setGroqKey(e.target.value)}
                  />
                  <p className="text-[11px] text-zinc-600 mt-1">
                    PRO Copilot is hosted by Sentinel and needs no key. A local key is only for self-hosting. Free key at console.groq.com
                  </p>
                </div>
                <div>
                  <label className="text-xs text-zinc-500 mb-1 block">Model</label>
                  <select
                    className="h-9 rounded-md border border-input bg-zinc-900 px-3 text-sm text-zinc-300 w-full max-w-sm"
                    value={aiModel}
                    onChange={e => setAiModel(e.target.value)}
                  >
                    {GROQ_MODELS.map(m => (
                      <option key={m.id} value={m.id}>{m.label}</option>
                    ))}
                  </select>
                </div>
              </>
            )}

            {(aiProvider === 'openai' || aiProvider === 'claude') && (
              <div>
                <label className="text-xs text-zinc-500 mb-1 block">API Key</label>
                <Input
                  type="password"
                  className="bg-zinc-900"
                  placeholder="sk-..."
                  value={aiApiKey}
                  onChange={e => setAiApiKey(e.target.value)}
                />
              </div>
            )}

            <div>
              <label className="text-xs text-zinc-500 mb-1 block">Interface &amp; AI Language</label>
              <select
                className="h-9 rounded-md border border-input bg-zinc-900 px-3 text-sm text-zinc-300 w-48"
                value={language}
                onChange={e => setLanguage(e.target.value)}
              >
                <option value="en">English</option>
                <option value="es">Español</option>
              </select>
              <p className="text-[11px] text-zinc-600 mt-1">AI Copilot will respond in this language</p>
            </div>

            {/* Ngrok */}
            <div className="border-t border-zinc-800 pt-4 space-y-2">
              <label className="text-xs text-zinc-400 font-semibold flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-orange-500" /> Ngrok Authtoken
              </label>
              <p className="text-[11px] text-zinc-600">
                Required for <strong className="text-zinc-400">jku/x5u JWT attacks</strong> against external targets.
                NexHunt auto-starts a tunnel so the target server can fetch your JWKS.
                Get your token at <span className="text-blue-400">dashboard.ngrok.com/get-started/your-authtoken</span>
              </p>
              <Input
                type="password"
                className="bg-zinc-900 font-mono text-sm"
                placeholder="2abc123xyz_XXXXXXXXXXXXXXXXXXXX"
                value={ngrokToken}
                onChange={e => setNgrokToken(e.target.value)}
              />
              {ngrokToken && <p className="text-[10px] text-green-500">Ngrok token configured — jku attacks against external targets will work automatically.</p>}
            </div>

            <Button onClick={handleSaveSettings} size="sm" className="flex items-center gap-2">
              {saved ? <><Check size={13} /> Saved!</> : 'Save Settings'}
            </Button>
          </div>
        </div>

        {/* Installed tools */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-5">
          <h3 className="font-semibold text-zinc-200 mb-4 flex items-center gap-2">
            <Wrench size={16} /> External Tools
          </h3>
          <div className="space-y-4">
            {Object.entries(TOOL_CATEGORIES).map(([category, toolNames]) => (
              <div key={category}>
                <h4 className="text-xs font-medium text-zinc-500 uppercase mb-2">{category}</h4>
                <div className="grid grid-cols-2 gap-2">
                  {toolNames.map(name => {
                    const tool = tools.find(t => t.name === name)
                    const installed = tool?.installed ?? false
                    return (
                      <div
                        key={name}
                        className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2"
                      >
                        <div className="flex items-center gap-2">
                          {installed ? (
                            <CheckCircle size={14} className="text-green-500" />
                          ) : (
                            <XCircle size={14} className="text-red-500" />
                          )}
                          <span className="text-sm text-zinc-300">{name}</span>
                        </div>
                        {tool?.version && (
                          <Badge variant="secondary" className="text-[10px]">
                            {tool.version}
                          </Badge>
                        )}
                      </div>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>
          <Button variant="outline" size="sm" className="mt-4" onClick={fetchTools}>
            Refresh Status
          </Button>
        </div>
      </div>
    </WorkspaceShell>
  )
}

function LicenseSection() {
  const { status, fetchStatus, activate, deactivate, refresh } = useLicenseStore()
  const [keyInput, setKeyInput] = useState('')
  const [busy, setBusy] = useState<'activate' | 'deactivate' | 'refresh' | null>(null)
  const [error, setError] = useState('')

  const isPro = status?.tier === 'pro'

  const handleActivate = async () => {
    if (!keyInput.trim()) return
    setBusy('activate'); setError('')
    try {
      await activate(keyInput.trim())
      setKeyInput('')
    } catch (e: any) {
      setError(typeof e?.message === 'string' ? e.message : 'Activation failed')
    } finally {
      setBusy(null)
    }
  }

  const handleDeactivate = async () => {
    setBusy('deactivate'); setError('')
    try { await deactivate() } catch (e: any) { setError(e?.message ?? 'Failed') } finally { setBusy(null) }
  }

  const handleRefresh = async () => {
    setBusy('refresh'); setError('')
    try { await refresh() } catch { /* keep current */ } finally { setBusy(null); fetchStatus() }
  }

  return (
    <div className="rounded-xl border border-amber-500/20 bg-gradient-to-br from-amber-500/[0.04] to-zinc-900/50 p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-semibold text-zinc-200 flex items-center gap-2">
          <Crown size={16} className={isPro ? 'text-amber-400' : 'text-zinc-500'} /> License
        </h3>
        <span className={`text-[10px] font-bold uppercase tracking-wide px-2 py-0.5 rounded border ${
          isPro
            ? 'bg-amber-500/15 text-amber-400 border-amber-500/40'
            : 'bg-zinc-800 text-zinc-400 border-zinc-700'
        }`}>
          {isPro ? 'PRO' : 'Free'}
        </span>
      </div>

      {isPro ? (
        <div className="space-y-3 text-sm">
          <div className="grid grid-cols-2 gap-3">
            <Field label="License key" value={status?.key_masked || '-'} mono />
            <Field label="Account" value={status?.customer_email || '-'} />
            <Field label="Expires" value={status?.expires_at ? new Date(status.expires_at).toLocaleDateString() : 'Never'} />
            <Field label="Machine ID" value={status?.machine_id?.slice(0, 16) + '...'} mono />
          </div>
          {status?.offline_grace && (
            <p className="text-[11px] text-amber-500/80">Running on cached license (offline). It will re-validate when back online.</p>
          )}
          <div className="flex gap-2 pt-1">
            <Button size="sm" variant="outline" onClick={handleRefresh} disabled={busy !== null}>
              {busy === 'refresh' ? <Loader2 size={13} className="mr-1 animate-spin" /> : <RefreshCw size={13} className="mr-1" />}
              Re-validate
            </Button>
            <Button size="sm" variant="outline" onClick={handleDeactivate} disabled={busy !== null}
              className="border-red-800/60 text-red-400 hover:bg-red-950/30">
              {busy === 'deactivate' ? <Loader2 size={13} className="mr-1 animate-spin" /> : null}
              Deactivate (move machine)
            </Button>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-sm text-zinc-400">
            Activate a license key to unlock NexHunt PRO: AI Copilot, automated pipelines, bulk scanning, JWT and business-logic suites, and professional reports.
          </p>
          <div className="flex gap-2">
            <Input
              className="bg-zinc-900 font-mono text-sm flex-1"
              placeholder="NEXHUNT-XXXX-XXXX-XXXX"
              value={keyInput}
              onChange={e => setKeyInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') handleActivate() }}
            />
            <Button size="sm" onClick={handleActivate} disabled={busy !== null || !keyInput.trim()}
              className="bg-amber-500 text-zinc-950 hover:bg-amber-400">
              {busy === 'activate' ? <Loader2 size={13} className="mr-1 animate-spin" /> : <KeyRound size={13} className="mr-1" />}
              Activate
            </Button>
          </div>
          {error && <p className="text-[11px] text-red-400">{error}</p>}
          <div className="flex items-center gap-3 text-[11px] pt-1">
            <a href={status?.upgrade_url || 'https://sentinelsec.online/pricing'} target="_blank" rel="noreferrer"
              className="inline-flex items-center gap-1 text-amber-400 hover:text-amber-300">
              Get a PRO license <ExternalLink size={11} />
            </a>
            <span className="text-zinc-700">·</span>
            <span className="text-zinc-600 font-mono">Machine: {status?.machine_id?.slice(0, 12) ?? '...'}</span>
          </div>
        </div>
      )}
    </div>
  )
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-[10px] text-zinc-600 uppercase tracking-widest mb-0.5">{label}</div>
      <div className={`text-zinc-300 text-[13px] truncate ${mono ? 'font-mono' : ''}`}>{value}</div>
    </div>
  )
}

function UpdatesSection() {
  const [info, setInfo] = useState<{ current: string; latest: string; update_available: boolean; notes: string; url: string } | null>(null)
  const [busy, setBusy] = useState<'check' | 'apply' | null>(null)
  const [msg, setMsg] = useState('')

  const check = async () => {
    setBusy('check'); setMsg('')
    try {
      const data = await api.get<any>('/api/update/check')
      setInfo(data)
      if (!data.update_available) setMsg('You are on the latest version.')
    } catch (e: any) {
      setMsg(e?.status === 404 ? 'No releases published yet.' : 'Could not reach the update server.')
    } finally { setBusy(null) }
  }

  const apply = async () => {
    setBusy('apply'); setMsg('')
    try {
      const data = await api.post<any>('/api/update/apply', {})
      setMsg(data.staged ? `Update ${data.version} downloaded. Restart NexHunt to apply.` : (data.message || 'Up to date.'))
    } catch {
      setMsg('Update failed. Try again later.')
    } finally { setBusy(null) }
  }

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-5">
      <h3 className="font-semibold text-zinc-200 mb-3 flex items-center gap-2">
        <ArrowUpCircle size={16} /> Updates
      </h3>
      <div className="flex items-center gap-2">
        <Button size="sm" variant="outline" onClick={check} disabled={busy !== null}>
          {busy === 'check' ? <Loader2 size={13} className="mr-1 animate-spin" /> : <RefreshCw size={13} className="mr-1" />}
          Check for updates
        </Button>
        {info?.update_available && (
          <Button size="sm" onClick={apply} disabled={busy !== null} className="bg-green-700 hover:bg-green-600">
            {busy === 'apply' ? <Loader2 size={13} className="mr-1 animate-spin" /> : <Download size={13} className="mr-1" />}
            Download {info.latest}
          </Button>
        )}
      </div>
      {info && (
        <p className="text-[11px] text-zinc-500 mt-2 flex items-center gap-1.5">
          <Cpu size={11} /> Installed {info.current}
          {info.update_available && <span className="text-green-400">· {info.latest} available</span>}
        </p>
      )}
      {msg && <p className="text-[11px] text-zinc-400 mt-2">{msg}</p>}
    </div>
  )
}
