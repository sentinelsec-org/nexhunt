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
  ShieldCheck,
  ShieldOff,
  Route,
  Gauge,
} from 'lucide-react'

type PrivacyMode = 'direct' | 'system' | 'tor' | 'custom'

interface PrivacyStatus {
  mode: PrivacyMode
  state: 'direct' | 'connecting' | 'connected' | 'error'
  proxy_url: string
  tor_installed: boolean
  proxychains_installed: boolean
  system_vpn_detected: boolean
  system_vpn_provider: string
  raw_socket_warning: boolean
  error?: string
}

interface EgressTest {
  ok: boolean
  direct_ip: string
  exit_ip: string
  changed?: boolean
  tor_verified?: boolean
  routed: boolean
  system_managed?: boolean
  error?: string
}

const GROQ_MODELS = [
  { id: 'openai/gpt-oss-120b', label: 'GPT-OSS 120B (recommended — best for pentesting, free)' },
  { id: 'qwen/qwen3-32b', label: 'Qwen3 32B (strong reasoning, Chinese, free)' },
  { id: 'openai/gpt-oss-20b', label: 'GPT-OSS 20B (lighter, higher rate limit)' },
  { id: 'meta-llama/llama-4-scout-17b-16e-instruct', label: 'Llama 4 Scout (fast)' },
  { id: 'llama-3.3-70b-versatile', label: 'Llama 3.3 70B Versatile' },
  { id: 'llama-3.1-8b-instant', label: 'Llama 3.1 8B Instant (fastest)' },
]

// Suggested models per OpenAI-compatible provider (free or near-free)
const PROVIDER_MODEL_HINTS: Record<string, string> = {
  gemini: 'gemini-2.0-flash',
  cerebras: 'llama-3.3-70b',
  openrouter: 'deepseek/deepseek-chat-v3-0324:free',
  deepseek: 'deepseek-chat',
  openai: 'gpt-4o',
  custom: '',
}

export function SettingsPage() {
  const [tools, setTools] = useState<ToolStatus[]>([])
  const [proxyPort, setProxyPort] = useState('8080')
  const [aiProvider, setAiProvider] = useState('groq')
  const [aiModel, setAiModel] = useState('llama-3.3-70b-versatile')
  const [groqKey, setGroqKey] = useState('')
  const [groqKeySet, setGroqKeySet] = useState(false)
  const [aiApiKey, setAiApiKey] = useState('')
  const [aiBaseUrl, setAiBaseUrl] = useState('')
  const [language, setLanguage] = useState('en')
  const [ngrokToken, setNgrokToken] = useState('')
  const [wpscanToken, setWpscanToken] = useState('')
  const [wpscanTokenSet, setWpscanTokenSet] = useState(false)
  const [shodanKey, setShodanKey] = useState('')
  const [shodanKeySet, setShodanKeySet] = useState(false)
  const [braveSearchKey, setBraveSearchKey] = useState('')
  const [braveSearchKeySet, setBraveSearchKeySet] = useState(false)
  const [saved, setSaved] = useState(false)
  const [privacyMode, setPrivacyMode] = useState<PrivacyMode>('direct')
  const [privacyProxyUrl, setPrivacyProxyUrl] = useState('')
  const [privacyProxySet, setPrivacyProxySet] = useState(false)
  const [privacyStatus, setPrivacyStatus] = useState<PrivacyStatus | null>(null)
  const [privacyBusy, setPrivacyBusy] = useState<'apply' | 'test' | null>(null)
  const [privacyError, setPrivacyError] = useState('')
  const [egressTest, setEgressTest] = useState<EgressTest | null>(null)

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
      if (s.privacy_mode) setPrivacyMode(s.privacy_mode)
      if (s.privacy_proxy_url_set) setPrivacyProxySet(true)
      if (s.ai_provider) setAiProvider(s.ai_provider)
      if (s.ai_model) setAiModel(s.ai_model)
      if (s.ai_base_url) setAiBaseUrl(s.ai_base_url)
      if (s.ai_groq_key_set) setGroqKeySet(true)
      if (s.language) setLanguage(s.language)
      if (s.ngrok_authtoken_set) setNgrokToken('')
      if (s.wpscan_api_token_set) setWpscanTokenSet(true)
      if (s.shodan_api_key_set) setShodanKeySet(true)
      if (s.brave_search_api_key_set) setBraveSearchKeySet(true)
    }).catch(() => {})
    api.get<PrivacyStatus>('/api/settings/privacy/status').then(setPrivacyStatus).catch(() => {})
    useLicenseStore.getState().fetchStatus()
  }, [])

  const applyPrivacyRoute = async () => {
    setPrivacyBusy('apply'); setPrivacyError(''); setEgressTest(null)
    try {
      await api.post('/api/settings', {
        privacy_mode: privacyMode,
        privacy_proxy_url: privacyMode === 'custom' && privacyProxyUrl ? privacyProxyUrl : undefined,
      }, 50000)
      const status = await api.get<PrivacyStatus>('/api/settings/privacy/status')
      setPrivacyStatus(status)
      if (privacyProxyUrl) setPrivacyProxySet(true)
    } catch (err: any) {
      setPrivacyError(err?.message || 'Could not activate the privacy route')
    } finally {
      setPrivacyBusy(null)
    }
  }

  const testPrivacyRoute = async () => {
    setPrivacyBusy('test'); setPrivacyError(''); setEgressTest(null)
    try {
      const result = await api.post<EgressTest>('/api/settings/privacy/test', {}, 45000)
      setEgressTest(result)
      if (!result.ok) setPrivacyError(result.error || 'The route did not reach the IP check service')
    } catch (err: any) {
      setPrivacyError(err?.message || 'Could not test the privacy route')
    } finally {
      setPrivacyBusy(null)
    }
  }

  const handleSaveSettings = async () => {
    try {
      await api.post('/api/settings', {
        proxy_port: parseInt(proxyPort),
        ai_provider: aiProvider,
        ai_model: aiModel,
        ai_groq_key: groqKey || undefined,
        ai_api_key: aiApiKey || undefined,
        ai_base_url: aiBaseUrl || undefined,
        language,
        ngrok_authtoken: ngrokToken || undefined,
        wpscan_api_token: wpscanToken || undefined,
        shodan_api_key: shodanKey || undefined,
        brave_search_api_key: braveSearchKey || undefined,
      })
      if (wpscanToken) setWpscanTokenSet(true)
      if (shodanKey) setShodanKeySet(true)
      if (braveSearchKey) setBraveSearchKeySet(true)
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

        {/* Privacy Route */}
        <div className="overflow-hidden rounded-xl border border-cyan-950/80 bg-[linear-gradient(145deg,rgba(8,47,73,0.24),rgba(9,9,11,0.88)_48%)]">
          <div className="flex items-start justify-between gap-4 border-b border-cyan-950/70 px-5 py-4">
            <div>
              <h3 className="flex items-center gap-2 font-semibold text-zinc-100">
                <Route size={16} className="text-cyan-400" /> Privacy Route
              </h3>
              <p className="mt-1 text-[11px] text-zinc-500">Choose the path used by outbound HTTP and compatible TCP tools.</p>
            </div>
            <div className={`flex items-center gap-2 rounded-full border px-2.5 py-1 text-[10px] font-medium uppercase tracking-[0.12em] ${
              privacyStatus?.state === 'connected'
                ? 'border-emerald-800/70 bg-emerald-950/40 text-emerald-400'
                : privacyStatus?.state === 'error'
                  ? 'border-red-900/70 bg-red-950/40 text-red-400'
                  : 'border-zinc-700 bg-zinc-900/70 text-zinc-500'
            }`}>
              <span className={`h-1.5 w-1.5 rounded-full ${privacyStatus?.state === 'connected' ? 'bg-emerald-400' : privacyStatus?.state === 'error' ? 'bg-red-400' : 'bg-zinc-500'}`} />
              {privacyStatus?.state || 'direct'}
            </div>
          </div>

          <div className="space-y-4 p-5">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4" role="radiogroup" aria-label="Outbound privacy route">
              {([
                { mode: 'direct', label: 'Direct', hint: 'Fastest', icon: ShieldOff },
                { mode: 'system', label: 'System VPN', hint: 'Proton · WARP', icon: Globe },
                { mode: 'tor', label: 'Tor', hint: 'Free · slower', icon: ShieldCheck },
                { mode: 'custom', label: 'Custom', hint: 'Fast SOCKS/HTTP', icon: Gauge },
              ] as const).map(option => {
                const Icon = option.icon
                const active = privacyMode === option.mode
                return (
                  <button
                    key={option.mode}
                    type="button"
                    role="radio"
                    aria-checked={active}
                    onClick={() => { setPrivacyMode(option.mode); setEgressTest(null); setPrivacyError('') }}
                    className={`group rounded-lg border p-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cyan-400 ${
                      active
                        ? 'border-cyan-700/80 bg-cyan-950/40 text-zinc-100'
                        : 'border-zinc-800 bg-zinc-950/45 text-zinc-500 hover:border-zinc-700 hover:text-zinc-300'
                    }`}
                  >
                    <Icon size={15} className={active ? 'text-cyan-400' : 'text-zinc-600 group-hover:text-zinc-400'} />
                    <span className="mt-2 block text-xs font-semibold">{option.label}</span>
                    <span className="mt-0.5 block text-[10px]">{option.hint}</span>
                  </button>
                )
              })}
            </div>

            {privacyMode === 'custom' && (
              <div>
                <label className="mb-1 block text-xs text-zinc-500">SOCKS5 or HTTP proxy URL</label>
                <Input
                  className="bg-zinc-950 font-mono text-xs"
                  type="password"
                  value={privacyProxyUrl}
                  onChange={event => setPrivacyProxyUrl(event.target.value)}
                  placeholder={privacyProxySet ? 'configured — leave blank to keep' : 'socks5://user:password@host:port'}
                />
              </div>
            )}

            <div className="flex flex-wrap items-center gap-2">
              <Button size="sm" onClick={applyPrivacyRoute} disabled={privacyBusy !== null}>
                {privacyBusy === 'apply' && <Loader2 size={12} className="mr-1.5 animate-spin" />}
                Apply route
              </Button>
              <Button variant="outline" size="sm" onClick={testPrivacyRoute} disabled={privacyBusy !== null}>
                {privacyBusy === 'test' && <Loader2 size={12} className="mr-1.5 animate-spin" />}
                Test exit IP
              </Button>
              <span className="text-[10px] text-zinc-600">
                Tor {privacyStatus?.tor_installed ? 'ready' : 'not installed'} · CLI routing {privacyStatus?.proxychains_installed ? 'ready' : 'limited'}
                {privacyStatus?.system_vpn_detected && ` · ${privacyStatus.system_vpn_provider} detected`}
              </span>
            </div>

            {egressTest?.ok && (
              <div className={`grid gap-3 rounded-lg border p-3 sm:grid-cols-[1fr_auto_1fr] ${egressTest.routed ? 'border-emerald-900/70 bg-emerald-950/20' : 'border-zinc-800 bg-zinc-950/50'}`}>
                <div>
                  <div className="text-[9px] uppercase tracking-[0.15em] text-zinc-600">{privacyMode === 'system' ? 'Original IP' : 'Direct IP'}</div>
                  <code className="mt-1 block text-xs text-zinc-400">{egressTest.direct_ip || (privacyMode === 'system' ? 'hidden by OS tunnel' : 'unavailable')}</code>
                </div>
                <div className="hidden self-center text-zinc-700 sm:block">→</div>
                <div>
                  <div className="text-[9px] uppercase tracking-[0.15em] text-zinc-600">Exit IP</div>
                  <code className={`mt-1 block text-xs ${egressTest.routed ? 'text-emerald-400' : 'text-zinc-400'}`}>{egressTest.exit_ip}</code>
                  {privacyMode === 'tor' && <span className={`text-[10px] ${egressTest.tor_verified ? 'text-emerald-500' : 'text-amber-500'}`}>{egressTest.tor_verified ? 'Tor network verified' : 'Not verified as Tor'}</span>}
                  {privacyMode === 'system' && <span className={`text-[10px] ${egressTest.routed ? 'text-emerald-500' : 'text-amber-500'}`}>{egressTest.routed ? 'System VPN interface detected' : 'No VPN interface detected — connect Proton first'}</span>}
                </div>
              </div>
            )}

            {privacyError && <p className="rounded-md border border-red-900/60 bg-red-950/30 px-3 py-2 text-[11px] text-red-400">{privacyError}</p>}

            <div className="border-t border-zinc-800/80 pt-3 text-[10px] leading-relaxed text-zinc-600">
              <strong className="text-amber-500/90">Boundary:</strong> localhost bypasses the route, so NexHunt Proxy keeps working. Tor/custom route HTTP and normal TCP; SYN/UDP, ICMP and raw sockets can reveal your IP. A connected system VPN covers more protocols and is the faster choice.
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
                className="h-9 rounded-md border border-input bg-zinc-900 px-3 text-sm text-zinc-300 w-full max-w-sm"
                value={aiProvider}
                onChange={e => {
                  const p = e.target.value
                  setAiProvider(p)
                  // Prefill a sensible default model when switching provider
                  if (p === 'groq') setAiModel('openai/gpt-oss-120b')
                  else if (PROVIDER_MODEL_HINTS[p]) setAiModel(PROVIDER_MODEL_HINTS[p])
                }}
              >
                <option value="groq">Groq (free — recommended, hosts GPT-OSS/Qwen/Llama4)</option>
                <option value="gemini">Google Gemini (free tier, powerful)</option>
                <option value="cerebras">Cerebras (free, fastest)</option>
                <option value="openrouter">OpenRouter (free models: DeepSeek/Qwen/Llama)</option>
                <option value="deepseek">DeepSeek (Chinese, cheap)</option>
                <option value="openai">OpenAI</option>
                <option value="claude">Claude (Anthropic)</option>
                <option value="custom">Custom (OpenAI-compatible)</option>
              </select>
            </div>

            {/* Groq: dedicated key + curated model dropdown */}
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
                  <p className="text-[11px] text-zinc-600 mt-1">Free key at console.groq.com — all listed models are free.</p>
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

            {/* Any other OpenAI-compatible provider: key + free-text model (+ base URL for custom) */}
            {(['gemini', 'cerebras', 'openrouter', 'deepseek', 'openai', 'custom'].includes(aiProvider)) && (
              <>
                <div>
                  <label className="text-xs text-zinc-500 mb-1 block">API Key</label>
                  <Input
                    type="password"
                    className="bg-zinc-900 font-mono text-sm"
                    placeholder="provider API key"
                    value={aiApiKey}
                    onChange={e => setAiApiKey(e.target.value)}
                  />
                </div>
                {aiProvider === 'custom' && (
                  <div>
                    <label className="text-xs text-zinc-500 mb-1 block">Base URL (OpenAI-compatible)</label>
                    <Input
                      className="bg-zinc-900 font-mono text-sm"
                      placeholder="https://host/v1"
                      value={aiBaseUrl}
                      onChange={e => setAiBaseUrl(e.target.value)}
                    />
                  </div>
                )}
                <div>
                  <label className="text-xs text-zinc-500 mb-1 block">Model</label>
                  <Input
                    className="bg-zinc-900 font-mono text-sm"
                    placeholder={PROVIDER_MODEL_HINTS[aiProvider] || 'model id'}
                    value={aiModel}
                    onChange={e => setAiModel(e.target.value)}
                  />
                  {PROVIDER_MODEL_HINTS[aiProvider] && (
                    <p className="text-[11px] text-zinc-600 mt-1">Suggested: <code className="text-zinc-400">{PROVIDER_MODEL_HINTS[aiProvider]}</code></p>
                  )}
                </div>
              </>
            )}

            {aiProvider === 'claude' && (
              <div>
                <label className="text-xs text-zinc-500 mb-1 block">Anthropic API Key</label>
                <Input
                  type="password"
                  className="bg-zinc-900 font-mono text-sm"
                  placeholder="sk-ant-..."
                  value={aiApiKey}
                  onChange={e => setAiApiKey(e.target.value)}
                />
              </div>
            )}

            <div>
              <label className="text-xs text-zinc-500 mb-1 block">AI Language</label>
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

            {/* WPScan */}
            <div className="border-t border-zinc-800 pt-4 space-y-2">
              <label className="text-xs text-zinc-400 font-semibold flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-blue-500" /> WPScan API Token
                {wpscanTokenSet && <span className="text-[10px] text-green-500 font-normal">· configured</span>}
              </label>
              <p className="text-[11px] text-zinc-600">
                Unlocks <strong className="text-zinc-400">WordPress vulnerability data</strong> in the WordPress pentest module.
                Free token (25 requests/day) at <span className="text-blue-400">wpscan.com/profile</span>
              </p>
              <Input
                type="password"
                className="bg-zinc-900 font-mono text-sm"
                placeholder={wpscanTokenSet ? 'configured — leave blank to keep' : 'your WPScan API token'}
                value={wpscanToken}
                onChange={e => setWpscanToken(e.target.value)}
              />
            </div>

            {/* Shodan */}
            <div className="border-t border-zinc-800 pt-4 space-y-2">
              <label className="text-xs text-zinc-400 font-semibold flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-green-500" /> Shodan API Key
                {shodanKeySet && <span className="text-[10px] text-green-500 font-normal">· configured</span>}
              </label>
              <p className="text-[11px] text-zinc-600">
                Enables passive global exposure searches in <strong className="text-zinc-400">Exposure Intel</strong>.
                Create a key at <span className="text-blue-400">account.shodan.io</span>.
              </p>
              <Input
                type="password"
                className="bg-zinc-900 font-mono text-sm"
                placeholder={shodanKeySet ? 'configured — leave blank to keep' : 'your Shodan API key'}
                value={shodanKey}
                onChange={e => setShodanKey(e.target.value)}
              />
            </div>

            {/* Brave Search */}
            <div className="border-t border-zinc-800 pt-4 space-y-2">
              <label className="text-xs text-zinc-400 font-semibold flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-green-500" /> Brave Search API Key
                {braveSearchKeySet && <span className="text-[10px] text-green-500 font-normal">· configured</span>}
              </label>
              <p className="text-[11px] text-zinc-600">
                Loads filtered, direct web URLs inside <strong className="text-zinc-400">Exposure Intel</strong>.
                Create a key at <span className="text-blue-400">api-dashboard.search.brave.com</span>.
              </p>
              <Input
                type="password"
                className="bg-zinc-900 font-mono text-sm"
                placeholder={braveSearchKeySet ? 'configured — leave blank to keep' : 'your Brave Search API key'}
                value={braveSearchKey}
                onChange={e => setBraveSearchKey(e.target.value)}
              />
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
            <a href={status?.upgrade_url || 'https://nexhunt.myshopify.com/products/nexhunt-pro'} target="_blank" rel="noreferrer"
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
