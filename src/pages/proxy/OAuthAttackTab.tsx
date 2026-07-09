import { useEffect, useMemo, useState } from 'react'
import { api } from '@/api/http-client'
import { cn } from '@/lib/utils'
import { useProxyStore } from '@/stores/proxy-store'
import {
  Loader2, Play, ShieldCheck, ChevronDown, ChevronRight, Radio, Copy, Check,
} from 'lucide-react'

// Client-side mirror of the backend ATTACK_META registry (keep in sync).
const OAUTH_ATTACKS = [
  { id: 'redirect_uri_bypass', name: 'redirect_uri Bypass', severity: 'critical' },
  { id: 'response_type_manip', name: 'response_type / Implicit', severity: 'high' },
  { id: 'csrf_state',          name: 'Missing state (CSRF)', severity: 'high' },
  { id: 'pkce_downgrade',      name: 'PKCE Downgrade', severity: 'high' },
  { id: 'request_uri_ssrf',    name: 'request_uri SSRF', severity: 'high' },
  { id: 'scope_escalation',    name: 'Scope Escalation', severity: 'high' },
  { id: 'code_replay',         name: 'Code Replay', severity: 'high' },
]

const OAUTH_INFO: Record<string, { what: string; how: string; needs: string }> = {
  redirect_uri_bypass: {
    what: 'The authorization server should only redirect to a pre-registered redirect_uri. Weak matchers accept attacker-controlled hosts, delivering the code/token off-domain (account takeover).',
    how: 'Mutates the registered redirect_uri across ~16 bypass shapes (subdomain, @/backslash userinfo, path traversal, encoded slash, query/fragment append) and checks whether the AS still 3xx-redirects to the attacker host with a code/token.',
    needs: 'A valid /authorize request. For a proven code leak, send the victim’s AS session cookie.',
  },
  response_type_manip: {
    what: 'Forcing response_type=token (implicit) returns the access token directly in the URL fragment, far more exposed than an authorization code.',
    how: 'Resends /authorize with token / id_token token / code token / none and looks for a token in the fragment.',
    needs: 'A valid /authorize request.',
  },
  csrf_state: {
    what: 'Without an unguessable, session-bound state, an attacker can force-link accounts or CSRF the OAuth login.',
    how: 'Resends /authorize with state removed and with a static state, comparing behaviour against the baseline.',
    needs: 'A valid /authorize request.',
  },
  pkce_downgrade: {
    what: 'Public clients must use PKCE. If the AS issues a code without code_challenge, a stolen code is exchangeable without the verifier.',
    how: 'Strips code_challenge and checks whether the AS still proceeds. Absence of PKCE altogether is itself flagged.',
    needs: 'A valid /authorize request (ideally one using PKCE).',
  },
  request_uri_ssrf: {
    what: 'OIDC request_uri makes the AS fetch a request object server-side. Unrestricted, it is an SSRF primitive.',
    how: 'Sets request_uri to the NexHunt collector and watches for a server-side callback.',
    needs: 'A collector URL (generate one below; ngrok recommended for external targets).',
  },
  scope_escalation: {
    what: 'If the token endpoint does not validate the requested scope against what was approved, extra scopes can be granted.',
    how: 'Exchanges the code adding admin/offline_access and compares the granted scope.',
    needs: 'token_url + a fresh code + client credentials.',
  },
  code_replay: {
    what: 'Authorization codes must be single-use. If the same code exchanges twice, a leaked code stays valid.',
    how: 'Exchanges the supplied code twice; a second success means codes are replayable.',
    needs: 'token_url + a fresh code + client credentials.',
  },
}

const SEV_BADGE: Record<string, string> = {
  critical: 'bg-red-900/60 text-red-300 border border-red-700/50',
  high: 'bg-orange-900/60 text-orange-300 border border-orange-700/50',
  medium: 'bg-yellow-900/60 text-yellow-300 border border-yellow-700/50',
}
const SEV_ROW: Record<string, string> = {
  critical: 'border-red-900/40 hover:bg-red-950/10',
  high: 'border-orange-900/40 hover:bg-orange-950/10',
  medium: 'border-yellow-900/40 hover:bg-yellow-950/10',
}

// The verdict vocabulary is the heart of the results view — one glance tells you
// safe (green) vs suspicious (amber) vs confirmed-broken (red).
const VERDICT: Record<string, { label: string; badge: string; dot: string }> = {
  leaked:        { label: 'LEAKED',        badge: 'bg-red-900/70 text-red-200 border border-red-600/60', dot: 'bg-red-500' },
  vulnerable:    { label: 'VULNERABLE',    badge: 'bg-red-900/70 text-red-200 border border-red-600/60', dot: 'bg-red-500' },
  open_redirect: { label: 'OPEN REDIRECT', badge: 'bg-orange-900/60 text-orange-300 border border-orange-700/50', dot: 'bg-orange-500' },
  accepted:      { label: 'ACCEPTED',      badge: 'bg-orange-900/60 text-orange-300 border border-orange-700/50', dot: 'bg-orange-500' },
  reflected:     { label: 'REFLECTED',     badge: 'bg-yellow-900/60 text-yellow-300 border border-yellow-700/50', dot: 'bg-yellow-500' },
  review:        { label: 'REVIEW',        badge: 'bg-yellow-900/60 text-yellow-300 border border-yellow-700/50', dot: 'bg-yellow-500' },
  rejected:      { label: 'REJECTED',      badge: 'bg-green-900/50 text-green-300 border border-green-700/40', dot: 'bg-green-500' },
  inconclusive:  { label: 'INCONCLUSIVE',  badge: 'bg-zinc-800 text-zinc-400 border border-zinc-700', dot: 'bg-zinc-600' },
  info:          { label: 'INFO',          badge: 'bg-zinc-800 text-zinc-400 border border-zinc-700', dot: 'bg-zinc-600' },
}
const BAD_VERDICTS = new Set(['leaked', 'vulnerable', 'open_redirect', 'accepted'])

function paramsToText(p: Record<string, string>): string {
  return Object.entries(p).map(([k, v]) => `${k}=${v}`).join('\n')
}
function textToParams(t: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of t.split('\n')) {
    const s = line.trim()
    if (!s) continue
    const i = s.indexOf('=')
    if (i === -1) { out[s] = ''; continue }
    out[s.slice(0, i).trim()] = s.slice(i + 1).trim()
  }
  return out
}
function parseHeaderLines(t: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of t.split('\n')) {
    const i = line.indexOf(':')
    if (i === -1) continue
    const k = line.slice(0, i).trim()
    if (k) out[k] = line.slice(i + 1).trim()
  }
  return out
}

export function OAuthAttackTab() {
  const { oauthFlow, clearOauthFlow } = useProxyStore()

  const [authorizeUrl, setAuthorizeUrl] = useState('')
  const [paramsText, setParamsText] = useState('')
  const [collaborator, setCollaborator] = useState('')
  const [advanced, setAdvanced] = useState(false)
  const [cookies, setCookies] = useState('')
  const [headers, setHeaders] = useState('')
  const [tokenUrl, setTokenUrl] = useState('')
  const [code, setCode] = useState('')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [redirectUri, setRedirectUri] = useState('')

  const [selected, setSelected] = useState<string | null>('redirect_uri_bypass')
  const [results, setResults] = useState<Record<string, any>>({})
  const [running, setRunning] = useState<Record<string, boolean>>({})
  const [collector, setCollector] = useState<{ id: string; url: string; public_url: string | null } | null>(null)
  const [hits, setHits] = useState<any[]>([])

  // Load an /authorize request captured from HTTP History.
  useEffect(() => {
    if (!oauthFlow) return
    const url = oauthFlow.request_url || ''
    setAuthorizeUrl(url)
    api.post<any>('/api/oauth/parse', { url }).then(res => {
      if (res.authorize_url) setAuthorizeUrl(res.authorize_url)
      if (res.params) setParamsText(paramsToText(res.params))
      if (res.params?.redirect_uri) setRedirectUri(res.params.redirect_uri)
    }).catch(() => {})
    if (oauthFlow.request_headers?.Cookie) setCookies(String(oauthFlow.request_headers.Cookie))
    clearOauthFlow()
  }, [oauthFlow])

  // Poll the collector for server-side callbacks while one is live.
  useEffect(() => {
    if (!collector) return
    const t = setInterval(() => {
      api.get<any>(`/api/oauth/collector/${collector.id}/hits`).then(r => setHits(r.hits || [])).catch(() => {})
    }, 3000)
    return () => clearInterval(t)
  }, [collector])

  const params = useMemo(() => textToParams(paramsText), [paramsText])

  const parseUrl = async () => {
    if (!authorizeUrl.trim()) return
    try {
      const res = await api.post<any>('/api/oauth/parse', { url: authorizeUrl.trim() })
      if (res.authorize_url) setAuthorizeUrl(res.authorize_url)
      if (res.params) setParamsText(paramsToText(res.params))
      if (res.params?.redirect_uri) setRedirectUri(res.params.redirect_uri)
    } catch { /* ignore */ }
  }

  const genCollector = async () => {
    try {
      const res = await api.post<any>('/api/oauth/generate-collector', {})
      setCollector({ id: res.id, url: res.url, public_url: res.public_url })
      setCollaborator(res.url)
      setHits([])
    } catch { /* ignore */ }
  }

  const runAttack = async (attackId: string) => {
    setSelected(attackId)
    setRunning(r => ({ ...r, [attackId]: true }))
    try {
      const res = await api.post<any>('/api/oauth/single-attack', {
        authorize_url: authorizeUrl.trim(),
        params,
        attack_id: attackId,
        collaborator_url: collaborator.trim(),
        cookies: cookies.trim() ? { Cookie: cookies.trim() } : {},
        extra_headers: parseHeaderLines(headers),
        token_url: tokenUrl.trim(),
        code: code.trim(),
        client_id: clientId.trim(),
        client_secret: clientSecret.trim(),
        redirect_uri: redirectUri.trim(),
      })
      setResults(r => ({ ...r, [attackId]: res }))
    } catch (e: any) {
      setResults(r => ({ ...r, [attackId]: { error: e?.message || 'request failed' } }))
    } finally {
      setRunning(r => ({ ...r, [attackId]: false }))
    }
  }

  const runAll = async () => {
    for (const a of OAUTH_ATTACKS) await runAttack(a.id)
  }

  const worstVerdict = (attackId: string): string | null => {
    const tests = results[attackId]?.tests
    if (!tests) return null
    for (const v of ['leaked', 'vulnerable', 'open_redirect', 'accepted', 'reflected', 'review']) {
      if (tests.some((t: any) => t.verdict === v)) return v
    }
    return 'rejected'
  }

  const ready = authorizeUrl.trim().length > 0

  return (
    <div className="flex-1 flex flex-col gap-3 min-h-0">
      {/* Header */}
      <div className="flex items-start gap-2">
        <ShieldCheck size={18} className="text-cyan-400 mt-0.5 shrink-0" />
        <div>
          <h2 className="text-sm font-semibold text-zinc-200">OAuth 2.0 Attacks</h2>
          <p className="text-[11px] text-zinc-500">
            Paste an <span className="font-mono text-zinc-400">/authorize</span> URL (or right-click a flow → &ldquo;Send to OAuth Attacks&rdquo;), then run the automated checks.
          </p>
        </div>
      </div>

      {/* Config */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3 space-y-2.5">
        <div className="flex gap-2">
          <input
            value={authorizeUrl}
            onChange={e => setAuthorizeUrl(e.target.value)}
            placeholder="https://as.example.com/authorize?client_id=..&redirect_uri=..&response_type=code&state=.."
            className="flex-1 h-8 rounded border border-zinc-700 bg-zinc-950 px-2 text-[11px] font-mono text-zinc-300 placeholder:text-zinc-600 focus:border-cyan-600 outline-none"
          />
          <button onClick={parseUrl}
            className="h-8 px-3 rounded bg-zinc-800 hover:bg-zinc-700 text-[11px] text-zinc-200 border border-zinc-700 shrink-0">
            Parse
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
          <label className="block">
            <span className="text-[9px] font-semibold text-zinc-500 uppercase tracking-wider">Authorization params</span>
            <textarea
              value={paramsText}
              onChange={e => setParamsText(e.target.value)}
              placeholder={'client_id=...\nredirect_uri=https://client/callback\nresponse_type=code\nscope=openid\nstate=...'}
              rows={5}
              className="mt-1 w-full rounded border border-zinc-800 bg-zinc-950 p-2 text-[11px] font-mono text-zinc-300 placeholder:text-zinc-600 focus:border-cyan-700 outline-none resize-none"
            />
          </label>
          <label className="block">
            <span className="text-[9px] font-semibold text-zinc-500 uppercase tracking-wider">Attacker host / collector</span>
            <div className="mt-1 flex gap-2">
              <input
                value={collaborator}
                onChange={e => setCollaborator(e.target.value)}
                placeholder="https://evil.attacker.test  (or generate a collector)"
                className="flex-1 h-8 rounded border border-zinc-800 bg-zinc-950 px-2 text-[11px] font-mono text-zinc-300 placeholder:text-zinc-600 focus:border-cyan-700 outline-none"
              />
              <button onClick={genCollector}
                className="h-8 px-2 rounded bg-zinc-800 hover:bg-zinc-700 text-[10px] text-zinc-200 border border-zinc-700 shrink-0 flex items-center gap-1">
                <Radio size={11} /> Collector
              </button>
            </div>
            {collector && (
              <div className="mt-1.5 rounded border border-cyan-900/40 bg-cyan-950/20 p-2 text-[10px] space-y-0.5">
                <div className="text-cyan-300 font-mono break-all">{collector.public_url || collector.url}</div>
                <div className="text-zinc-500">
                  {collector.public_url ? 'Public (ngrok) — reachable by external targets.' : 'Local only — start ngrok for external targets.'}
                  {' '}Callbacks: <span className={hits.length ? 'text-red-400 font-semibold' : 'text-zinc-400'}>{hits.length}</span>
                </div>
              </div>
            )}
            <button onClick={() => setAdvanced(a => !a)}
              className="mt-1.5 flex items-center gap-1 text-[10px] text-zinc-500 hover:text-zinc-300">
              {advanced ? <ChevronDown size={11} /> : <ChevronRight size={11} />} Advanced (session cookie, token endpoint)
            </button>
          </label>
        </div>

        {advanced && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 border-t border-zinc-800 pt-2.5">
            <TextArea label="AS session cookie" value={cookies} onChange={setCookies} placeholder="session=...; other=..." rows={2} />
            <TextArea label="Extra headers (Name: value)" value={headers} onChange={setHeaders} placeholder="Authorization: Bearer ..." rows={2} />
            <Field label="token_url (for scope / replay)" value={tokenUrl} onChange={setTokenUrl} placeholder="https://as.example.com/token" />
            <Field label="Authorization code" value={code} onChange={setCode} placeholder="fresh code to exchange" />
            <Field label="client_id" value={clientId} onChange={setClientId} placeholder="client id" />
            <Field label="client_secret" value={clientSecret} onChange={setClientSecret} placeholder="(if confidential)" />
            <Field label="redirect_uri (for /token)" value={redirectUri} onChange={setRedirectUri} placeholder="https://client/callback" />
          </div>
        )}
      </div>

      {/* Attacks + results */}
      <div className="flex-1 flex gap-3 min-h-0">
        {/* Attack list */}
        <div className="w-56 shrink-0 rounded-lg border border-zinc-800 overflow-hidden flex flex-col">
          <div className="bg-zinc-900 px-2.5 py-1.5 flex items-center justify-between">
            <span className="text-[9px] font-semibold text-zinc-500 uppercase">Attacks</span>
            <button onClick={runAll} disabled={!ready || Object.values(running).some(Boolean)}
              className="text-[9px] text-cyan-400 hover:text-cyan-300 font-semibold disabled:opacity-40 flex items-center gap-1">
              <Play size={8} /> Run all
            </button>
          </div>
          <div className="divide-y divide-zinc-800/50 overflow-y-auto">
            {OAUTH_ATTACKS.map(atk => {
              const worst = worstVerdict(atk.id)
              return (
                <button key={atk.id} onClick={() => runAttack(atk.id)} disabled={!ready || running[atk.id]}
                  className={cn('w-full flex items-center gap-2 px-2.5 py-2 text-left transition-colors disabled:opacity-50',
                    SEV_ROW[atk.severity], selected === atk.id && 'bg-zinc-800/50')}>
                  {running[atk.id]
                    ? <Loader2 size={9} className="animate-spin text-cyan-400 shrink-0" />
                    : worst ? <div className={cn('w-2 h-2 rounded-full shrink-0', VERDICT[worst]?.dot || 'bg-zinc-600')} />
                    : <div className="w-2 h-2 rounded-full bg-zinc-800 border border-zinc-700 shrink-0" />}
                  <span className="text-[10px] text-zinc-300 flex-1 leading-tight">{atk.name}</span>
                  <span className={cn('text-[8px] px-1 py-0.5 rounded font-bold uppercase', SEV_BADGE[atk.severity])}>
                    {atk.severity === 'critical' ? 'CRIT' : 'HIGH'}
                  </span>
                </button>
              )
            })}
          </div>
        </div>

        {/* Results */}
        <div className="flex-1 min-h-0 overflow-y-auto">
          {selected && <ResultPanel attackId={selected} result={results[selected]} running={!!running[selected]} onRun={() => runAttack(selected)} ready={ready} />}
        </div>
      </div>
    </div>
  )
}

function ResultPanel({ attackId, result, running, onRun, ready }: {
  attackId: string; result: any; running: boolean; onRun: () => void; ready: boolean
}) {
  const info = OAUTH_INFO[attackId]
  const meta = OAUTH_ATTACKS.find(a => a.id === attackId)
  const tests: any[] = result?.tests || []
  const badCount = tests.filter(t => BAD_VERDICTS.has(t.verdict)).length

  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold text-zinc-200">{meta?.name}</h3>
          <button onClick={onRun} disabled={!ready || running}
            className="h-7 px-3 rounded bg-cyan-800/70 hover:bg-cyan-700 text-[11px] text-cyan-100 border border-cyan-700/50 disabled:opacity-40 flex items-center gap-1.5">
            {running ? <Loader2 size={11} className="animate-spin" /> : <Play size={11} />} Run
          </button>
        </div>
        {info && (
          <div className="mt-2 space-y-1.5 text-[11px] leading-relaxed">
            <p className="text-zinc-400">{info.what}</p>
            <p className="text-zinc-500"><span className="text-zinc-400 font-medium">How:</span> {info.how}</p>
            <p className="text-zinc-600"><span className="text-zinc-500 font-medium">Needs:</span> {info.needs}</p>
          </div>
        )}
      </div>

      {result?.error && (
        <div className="rounded-lg border border-orange-800/40 bg-orange-950/20 p-3 text-[11px] text-orange-300">{result.error}</div>
      )}

      {tests.length > 0 && (
        <>
          <div className={cn('rounded-lg border p-2.5 text-[11px] font-medium',
            badCount > 0 ? 'border-red-800/50 bg-red-950/20 text-red-300' : 'border-green-800/40 bg-green-950/15 text-green-300')}>
            {badCount > 0
              ? `${badCount} of ${tests.length} test${tests.length > 1 ? 's' : ''} flagged — review the highlighted rows.`
              : `No bypass found across ${tests.length} test${tests.length > 1 ? 's' : ''}. The AS rejected the malicious variants.`}
            {result?.evil_host && <span className="text-zinc-500 font-normal"> (attacker host: {result.evil_host})</span>}
          </div>
          <div className="rounded-lg border border-zinc-800 divide-y divide-zinc-800/60">
            {tests.map((t, i) => <TestRow key={i} test={t} />)}
          </div>
        </>
      )}

      {!result && !running && (
        <div className="flex items-center justify-center h-32 text-[11px] text-zinc-600">
          {ready ? 'Click Run to launch this check.' : 'Paste an /authorize URL above to begin.'}
        </div>
      )}
    </div>
  )
}

function TestRow({ test }: { test: any }) {
  const [open, setOpen] = useState(false)
  const v = VERDICT[test.verdict] || VERDICT.info
  const bad = BAD_VERDICTS.has(test.verdict)
  const hasRaw = test.raw_request || test.raw_response
  return (
    <div className={cn('px-2.5 py-2', bad && 'bg-red-950/10')}>
      <div className="flex items-center gap-2">
        <span className={cn('text-[8px] px-1.5 py-0.5 rounded font-bold uppercase shrink-0 w-24 text-center', v.badge)}>{v.label}</span>
        <span className="text-[10px] text-zinc-300 shrink-0">{test.label}</span>
        {test.status ? <span className="text-[9px] text-zinc-600 font-mono shrink-0">HTTP {test.status}</span> : null}
        {hasRaw && (
          <button onClick={() => setOpen(o => !o)} className="ml-auto text-[9px] text-zinc-500 hover:text-zinc-300 flex items-center gap-0.5 shrink-0">
            {open ? <ChevronDown size={10} /> : <ChevronRight size={10} />} raw
          </button>
        )}
      </div>
      {test.payload && <p className="mt-1 text-[10px] font-mono text-zinc-500 break-all">{test.payload}</p>}
      {test.evidence && <p className={cn('mt-1 text-[10px] leading-relaxed', bad ? 'text-red-300/80' : 'text-zinc-500')}>{test.evidence}</p>}
      {open && hasRaw && (
        <div className="mt-2 grid grid-cols-1 lg:grid-cols-2 gap-2">
          <RawBox title="Request" text={test.raw_request} />
          <RawBox title="Response" text={test.raw_response} />
        </div>
      )}
    </div>
  )
}

function RawBox({ title, text }: { title: string; text?: string }) {
  const [copied, setCopied] = useState(false)
  if (!text) return null
  return (
    <div className="rounded border border-zinc-800 bg-zinc-950 overflow-hidden">
      <div className="flex items-center justify-between px-2 py-1 bg-zinc-900/60">
        <span className="text-[8px] font-semibold text-zinc-500 uppercase">{title}</span>
        <button onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1200) }}
          className="text-zinc-600 hover:text-zinc-300">{copied ? <Check size={10} /> : <Copy size={10} />}</button>
      </div>
      <pre className="p-2 text-[9px] font-mono text-zinc-400 whitespace-pre-wrap break-all max-h-48 overflow-y-auto">{text}</pre>
    </div>
  )
}

function Field({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <label className="block">
      <span className="text-[9px] font-semibold text-zinc-500 uppercase tracking-wider">{label}</span>
      <input value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
        className="mt-1 w-full h-8 rounded border border-zinc-800 bg-zinc-950 px-2 text-[11px] font-mono text-zinc-300 placeholder:text-zinc-600 focus:border-cyan-700 outline-none" />
    </label>
  )
}

function TextArea({ label, value, onChange, placeholder, rows }: { label: string; value: string; onChange: (v: string) => void; placeholder?: string; rows?: number }) {
  return (
    <label className="block">
      <span className="text-[9px] font-semibold text-zinc-500 uppercase tracking-wider">{label}</span>
      <textarea value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} rows={rows || 2}
        className="mt-1 w-full rounded border border-zinc-800 bg-zinc-950 p-2 text-[11px] font-mono text-zinc-300 placeholder:text-zinc-600 focus:border-cyan-700 outline-none resize-none" />
    </label>
  )
}
