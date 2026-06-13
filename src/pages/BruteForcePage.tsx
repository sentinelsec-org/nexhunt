import { useState, useEffect, useCallback } from 'react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { api } from '@/api/http-client'
import { toast } from '@/stores/toast-store'
import { useBruteForceStore, type FoundCred } from '@/stores/bruteforce-store'
import { cn } from '@/lib/utils'
import {
  KeyRound, Play, Square, Loader2, ExternalLink, Trash2, FolderOpen,
  Save, X, ShieldCheck, FileText, Globe, Shuffle, Pencil, Wand2, UserRound,
} from 'lucide-react'

const SERVICES = [
  'http-post-form', 'https-post-form', 'http-get',
  'ssh', 'ftp', 'mysql', 'postgres', 'rdp', 'smb', 'vnc', 'telnet',
]
const HTTP_SERVICES = ['http-post-form', 'https-post-form', 'http-get']

function humanSize(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

const labelCls = 'text-[10px] text-zinc-500 uppercase tracking-widest mb-1 block'
const selectCls = 'w-full h-8 rounded-md bg-zinc-900 border border-zinc-700 text-xs text-zinc-200 px-2 focus:outline-none focus:border-zinc-500'

export function BruteForcePage() {
  const { config, setConfig, jobs, wordlists, startAttack, fetchJobs, killJob, fetchWordlists, prefill, consumePrefill } = useBruteForceStore()
  const [launching, setLaunching] = useState(false)
  const [selectedJob, setSelectedJob] = useState<string | null>(null)
  const [detail, setDetail] = useState<{ found: FoundCred[]; log_tail: string; status: string; command: string } | null>(null)
  const [wlOpen, setWlOpen] = useState(false)

  const [loginMode, setLoginMode] = useState<'single' | 'list' | 'combo'>('single')
  const [passMode, setPassMode] = useState<'single' | 'list'>('list')

  useEffect(() => { fetchJobs(); fetchWordlists() }, [fetchJobs, fetchWordlists])

  useEffect(() => {
    if (prefill) {
      consumePrefill()
      if (prefill.combo_list) setLoginMode('combo')
      else if (prefill.login_list) setLoginMode('list')
      else setLoginMode('single')
      toast.success('Loaded request from Proxy')
    }
  }, [prefill, consumePrefill])

  useEffect(() => {
    const t = setInterval(fetchJobs, 3000)
    return () => clearInterval(t)
  }, [fetchJobs])

  const loadDetail = useCallback(async (id: string) => {
    try {
      const d = await api.get<{ found: FoundCred[]; log_tail: string; status: string; command: string }>(`/api/bruteforce/jobs/${id}`)
      setDetail(d)
    } catch { /* job gone */ }
  }, [])

  useEffect(() => {
    if (!selectedJob) return
    loadDetail(selectedJob)
    const t = setInterval(() => loadDetail(selectedJob), 2500)
    return () => clearInterval(t)
  }, [selectedJob, loadDetail])

  const isHttp = HTTP_SERVICES.includes(config.service)

  const launch = async () => {
    if (!config.target.trim()) { toast.error('Target is required'); return }
    setLaunching(true)
    try {
      // reconcile credential mode -> only send the active fields
      const patch: Partial<typeof config> = {}
      if (loginMode === 'combo') { patch.login = ''; patch.login_list = ''; patch.password = ''; patch.password_list = '' }
      else {
        patch.combo_list = ''
        if (loginMode === 'single') patch.login_list = ''; else patch.login = ''
        if (passMode === 'single') patch.password_list = ''; else patch.password = ''
      }
      useBruteForceStore.getState().setConfig(patch)
      const id = await startAttack()
      setSelectedJob(id)
      toast.success('Attack launched in external terminal')
    } catch (e: any) {
      toast.error(e?.message || 'Failed to launch')
    } finally {
      setLaunching(false)
    }
  }

  return (
    <WorkspaceShell title="Brute Force" subtitle="Hydra credential attacks — runs in a separate terminal window">
      <div className="flex h-full">
        {/* ── Config ── */}
        <div className="w-[380px] shrink-0 border-r border-zinc-800 overflow-y-auto p-4 space-y-3">
          <div className="flex items-center gap-2 text-zinc-300 text-sm font-medium mb-1">
            <KeyRound size={15} className="text-red-400" /> Attack configuration
          </div>

          <div className="grid grid-cols-3 gap-2">
            <div className="col-span-2">
              <label className={labelCls}>Target host / IP</label>
              <Input value={config.target} onChange={(e) => setConfig({ target: e.target.value })} placeholder="10.0.0.5 or target.com" className="h-8 text-xs" />
            </div>
            <div>
              <label className={labelCls}>Port</label>
              <Input type="number" value={config.port ?? ''} onChange={(e) => setConfig({ port: e.target.value ? Number(e.target.value) : null })} placeholder="auto" className="h-8 text-xs" />
            </div>
          </div>

          <div>
            <label className={labelCls}>Service</label>
            <select className={selectCls} value={config.service} onChange={(e) => setConfig({ service: e.target.value })}>
              {SERVICES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>

          {isHttp && (
            <div className="space-y-2 rounded-md border border-zinc-800 bg-zinc-900/40 p-2.5">
              <div>
                <label className={labelCls}>Path</label>
                <Input value={config.form_path} onChange={(e) => setConfig({ form_path: e.target.value })} placeholder="/login.php" className="h-8 text-xs" />
              </div>
              {config.service !== 'http-get' && (
                <>
                  <div>
                    <label className={labelCls}>POST body (use ^USER^ and ^PASS^)</label>
                    <Input value={config.form_body} onChange={(e) => setConfig({ form_body: e.target.value })} placeholder="user=^USER^&pass=^PASS^" className="h-8 text-xs font-mono" />
                  </div>
                  <div>
                    <label className={labelCls}>Failure string (F=)</label>
                    <Input value={config.fail_string} onChange={(e) => setConfig({ fail_string: e.target.value })} placeholder="F=Invalid credentials" className="h-8 text-xs font-mono" />
                  </div>
                </>
              )}
            </div>
          )}

          {/* Login */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className={labelCls + ' mb-0'}>Username</label>
              <ModeTabs value={loginMode} onChange={(v) => setLoginMode(v as any)} options={['single', 'list', 'combo']} />
            </div>
            {loginMode === 'single' && (
              <Input value={config.login} onChange={(e) => setConfig({ login: e.target.value })} placeholder="admin" className="h-8 text-xs" />
            )}
            {loginMode === 'list' && (
              <WordlistSelect value={config.login_list} onChange={(v) => setConfig({ login_list: v })} wordlists={wordlists} onManage={() => setWlOpen(true)} />
            )}
            {loginMode === 'combo' && (
              <WordlistSelect value={config.combo_list} onChange={(v) => setConfig({ combo_list: v })} wordlists={wordlists} onManage={() => setWlOpen(true)} hint="user:pass combo file" />
            )}
          </div>

          {/* Password */}
          {loginMode !== 'combo' && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className={labelCls + ' mb-0'}>Password</label>
                <ModeTabs value={passMode} onChange={(v) => setPassMode(v as any)} options={['single', 'list']} />
              </div>
              {passMode === 'single'
                ? <Input value={config.password} onChange={(e) => setConfig({ password: e.target.value })} placeholder="password123" className="h-8 text-xs" />
                : <WordlistSelect value={config.password_list} onChange={(v) => setConfig({ password_list: v })} wordlists={wordlists} onManage={() => setWlOpen(true)} />}
            </div>
          )}

          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className={labelCls}>Threads</label>
              <Input type="number" value={config.threads} onChange={(e) => setConfig({ threads: Number(e.target.value) })} className="h-8 text-xs" />
            </div>
            <label className="flex items-end gap-2 pb-1.5 text-xs text-zinc-400 cursor-pointer select-none">
              <input type="checkbox" checked={config.stop_on_first} onChange={(e) => setConfig({ stop_on_first: e.target.checked })} className="accent-red-500" />
              Stop on first hit
            </label>
          </div>

          <div>
            <label className={labelCls}>Extra hydra args</label>
            <Input value={config.extra_args} onChange={(e) => setConfig({ extra_args: e.target.value })} placeholder="-V -w 30" className="h-8 text-xs font-mono" />
          </div>

          <Button onClick={launch} disabled={launching} className="w-full bg-red-600 hover:bg-red-500 text-white">
            {launching ? <><Loader2 size={14} className="animate-spin mr-1.5" />Launching...</> : <><Play size={14} className="mr-1.5" />Launch attack</>}
          </Button>
          <p className="text-[10px] text-zinc-600 leading-relaxed flex items-start gap-1.5">
            <ExternalLink size={11} className="mt-0.5 shrink-0" />
            Hydra opens in its own terminal window so it does not slow down NexHunt. Results stream back here.
          </p>
        </div>

        {/* ── Jobs ── */}
        <div className="flex-1 flex min-w-0">
          <div className="w-[300px] shrink-0 border-r border-zinc-800 overflow-y-auto">
            <div className="px-3 py-2 text-[10px] text-zinc-500 uppercase tracking-widest border-b border-zinc-800 sticky top-0 bg-zinc-950">Attacks</div>
            {jobs.length === 0 && <p className="text-xs text-zinc-600 p-4 text-center">No attacks yet</p>}
            {jobs.map(j => (
              <button key={j.job_id} onClick={() => setSelectedJob(j.job_id)}
                className={cn('w-full text-left px-3 py-2 border-b border-zinc-800/60 hover:bg-zinc-900', selectedJob === j.job_id && 'bg-zinc-900')}>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-zinc-200 truncate">{j.target}</span>
                  <StatusDot status={j.status} />
                </div>
                <div className="flex items-center justify-between mt-0.5">
                  <span className="text-[10px] text-zinc-500">{j.service}</span>
                  {j.found > 0 && <span className="text-[10px] text-emerald-400 font-medium">{j.found} cred{j.found > 1 ? 's' : ''}</span>}
                </div>
              </button>
            ))}
          </div>

          <div className="flex-1 overflow-y-auto p-4 min-w-0">
            {!selectedJob || !detail ? (
              <div className="h-full flex items-center justify-center text-zinc-600 text-sm">Select an attack to see results</div>
            ) : (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <StatusDot status={detail.status} />
                    <span className="text-xs text-zinc-400 capitalize">{detail.status}</span>
                  </div>
                  {detail.status === 'running' && (
                    <Button size="sm" variant="outline" className="border-red-800 text-red-400 hover:bg-red-950/40" onClick={() => killJob(selectedJob)}>
                      <Square size={12} className="mr-1.5" />Stop
                    </Button>
                  )}
                </div>

                {detail.found.length > 0 && (
                  <div className="rounded-md border border-emerald-700/50 bg-emerald-950/20 p-3">
                    <div className="flex items-center gap-1.5 text-emerald-400 text-xs font-medium mb-2">
                      <ShieldCheck size={14} /> Credentials found
                    </div>
                    <table className="w-full text-xs">
                      <thead><tr className="text-zinc-500 text-[10px] uppercase">
                        <th className="text-left font-medium pb-1">Login</th>
                        <th className="text-left font-medium pb-1">Password</th>
                      </tr></thead>
                      <tbody>
                        {detail.found.map((c, i) => (
                          <tr key={i} className="text-zinc-200 font-mono">
                            <td className="py-0.5 pr-3">{c.login || '(empty)'}</td>
                            <td className="py-0.5">{c.password || '(empty)'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                <div>
                  <label className={labelCls}>Command</label>
                  <pre className="text-[10px] text-zinc-400 font-mono bg-zinc-900 border border-zinc-800 rounded p-2 whitespace-pre-wrap break-all">{detail.command}</pre>
                </div>

                <div>
                  <label className={labelCls}>Output</label>
                  <pre className="text-[10px] text-zinc-400 font-mono bg-black border border-zinc-800 rounded p-2 whitespace-pre-wrap max-h-[40vh] overflow-y-auto">{detail.log_tail || 'Waiting for output...'}</pre>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {wlOpen && <WordlistManager onClose={() => { setWlOpen(false); fetchWordlists() }} targetHint={config.target} />}
    </WorkspaceShell>
  )
}

function ModeTabs({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: string[] }) {
  return (
    <div className="flex gap-0.5">
      {options.map(o => (
        <button key={o} onClick={() => onChange(o)}
          className={cn('text-[10px] px-2 py-0.5 rounded capitalize', value === o ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-500 hover:text-zinc-300')}>
          {o}
        </button>
      ))}
    </div>
  )
}

function WordlistSelect({ value, onChange, wordlists, onManage, hint }: {
  value: string; onChange: (v: string) => void; wordlists: any[]; onManage: () => void; hint?: string
}) {
  return (
    <div className="flex gap-1.5">
      <select className={selectCls} value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">{hint || 'Select a wordlist...'}</option>
        {wordlists.map(w => (
          <option key={w.path} value={w.path}>
            {w.custom ? '★ ' : ''}{w.name}{w.lines != null ? ` (${w.lines.toLocaleString()})` : ''}
          </option>
        ))}
      </select>
      <button onClick={onManage} title="Generate / manage wordlists"
        className="shrink-0 h-8 px-2 flex items-center gap-1.5 rounded-md border border-zinc-700 text-zinc-400 hover:text-green-400 hover:border-green-700 transition-colors text-[10px] whitespace-nowrap">
        <FolderOpen size={13} />Generate
      </button>
    </div>
  )
}

function StatusDot({ status }: { status: string }) {
  const color = status === 'running' ? 'bg-amber-400 animate-pulse' : status === 'finished' ? 'bg-zinc-500' : 'bg-blue-400'
  return <span className={cn('inline-block w-2 h-2 rounded-full', color)} />
}

const COMBO_MUTATIONS: { id: string; label: string; fn: (w: string) => string[] }[] = [
  { id: 'original', label: 'Original',                fn: w => [w] },
  { id: 'capital',  label: 'Capitalizada',            fn: w => [w.length ? w[0].toUpperCase() + w.slice(1) : w] },
  { id: 'upper',    label: 'MAYUSCULAS',              fn: w => [w.toUpperCase()] },
  { id: 'years',    label: '+ año (2022-2026)',       fn: w => ['2022','2023','2024','2025','2026'].map(y => w+y) },
  { id: 'capyears', label: 'Capitalizada + año',      fn: w => { const c=w[0]?.toUpperCase()+w.slice(1); return ['2024','2025','2026'].map(y=>c+y) } },
  { id: 'specials', label: '+ ! / 123 / @',           fn: w => ['!','!!','123','1234','@','!123','@123'].map(s=>w+s) },
  { id: 'capspec',  label: 'Capitalizada + !/ año',   fn: w => { const c=w[0]?.toUpperCase()+w.slice(1); return [c+'!',c+'!!',c+'123',c+'2024',c+'2025',c+'@123'] } },
  { id: 'l33t',     label: 'L33t (a→@ e→3 i→1 o→0)', fn: w => [w.replace(/a/gi,'@').replace(/e/gi,'3').replace(/i/gi,'1').replace(/o/gi,'0').replace(/s/gi,'$')] },
  { id: 'nums',     label: '+ números 1-50',          fn: w => Array.from({length:50},(_,i)=>`${w}${i+1}`) },
]

function buildWordlist(
  rawWords: string[],
  useSingle: boolean,
  usePairs: boolean,
  useTriples: boolean,
  separators: string[],
  mutations: Set<string>
): string[] {
  const words = rawWords.map(w => w.trim()).filter(Boolean)
  if (!words.length) return []
  const seps = separators.length ? separators : ['']
  const combos = new Set<string>()

  if (useSingle) words.forEach(w => combos.add(w))

  if (usePairs) {
    for (let i = 0; i < words.length; i++)
      for (let j = 0; j < words.length; j++)
        if (i !== j) seps.forEach(s => combos.add(words[i] + s + words[j]))
  }

  if (useTriples) {
    for (let i = 0; i < words.length; i++)
      for (let j = 0; j < words.length; j++)
        for (let k = 0; k < words.length; k++)
          if (i !== j && j !== k && i !== k)
            seps.forEach(s => combos.add(words[i] + s + words[j] + s + words[k]))
  }

  const out = new Set<string>()
  for (const combo of combos)
    for (const rule of COMBO_MUTATIONS)
      if (mutations.has(rule.id)) rule.fn(combo).forEach(v => v && out.add(v))

  return [...out]
}

const CHARSETS: Record<string, string> = {
  'Lowercase letters':         'abcdefghijklmnopqrstuvwxyz',
  'Lowercase + digits':        'abcdefghijklmnopqrstuvwxyz0123456789',
  'Alphanumeric':              'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
  'Digits only':               '0123456789',
  'Lowercase + common special':'abcdefghijklmnopqrstuvwxyz0123456789!@#$%',
}

function crunchEstimate(minLen: number, maxLen: number, charset: string): number {
  let total = 0
  for (let i = minLen; i <= maxLen; i++) total += Math.pow(charset.length, i)
  return total
}

function WordlistManager({ onClose, targetHint }: { onClose: () => void; targetHint?: string }) {
  const { wordlists, fetchWordlists } = useBruteForceStore()
  const [tab, setTab] = useState<'cewl' | 'crunch' | 'cupp' | 'mutate' | 'manual'>('cewl')
  const [busy, setBusy] = useState(false)

  // CeWL state
  const [cewlUrl, setCewlUrl] = useState(() => {
    if (!targetHint) return ''
    return targetHint.startsWith('http') ? targetHint : `http://${targetHint}`
  })
  const [cewlDepth, setCewlDepth] = useState(2)
  const [cewlMinLen, setCewlMinLen] = useState(5)
  const [cewlNumbers, setCewlNumbers] = useState(false)
  const [cewlLower, setCewlLower] = useState(false)
  const [cewlName, setCewlName] = useState('')

  // Crunch state
  const [crunchMin, setCrunchMin] = useState(4)
  const [crunchMax, setCrunchMax] = useState(6)
  const [charsetKey, setCharsetKey] = useState('Lowercase + digits')
  const [customCharset, setCustomCharset] = useState('')
  const [crunchPattern, setCrunchPattern] = useState('')
  const [crunchName, setCrunchName] = useState('')

  // CUPP state
  const [cupp, setCupp] = useState({
    first_name: '', last_name: '', nickname: '', birthdate: '',
    partner: '', partner_nick: '', partner_birth: '',
    pet: '', company: '', keywords: '',
    cupp_leet: true, cupp_specials: true, cupp_numbers: true,
  })
  const [cuppName, setCuppName] = useState('')
  const [cuppBusy, setCuppBusy] = useState(false)

  // Manual state
  const [manualName, setManualName] = useState('')
  const [manualContent, setManualContent] = useState('')

  // Mutate/combine state
  const [mutateWords, setMutateWords] = useState('')
  const [useSingle, setUseSingle] = useState(true)
  const [usePairs, setUsePairs] = useState(true)
  const [useTriples, setUseTriples] = useState(false)
  const [combSeps, setCombSeps] = useState<Set<string>>(new Set(['', '_']))
  const [mutateActive, setMutateActive] = useState<Set<string>>(new Set(['original','capital','years','capyears','specials','capspec']))
  const [mutateName, setMutateName] = useState('')

  const remove = async (n: string) => {
    try { await api.delete(`/api/wordlists/${encodeURIComponent(n)}`); await fetchWordlists(); toast.success('Deleted') }
    catch (e: any) { toast.error(e?.message || 'Delete failed') }
  }

  const runCewl = async () => {
    if (!cewlUrl.trim()) { toast.error('URL is required'); return }
    if (!cewlName.trim()) { toast.error('Name is required'); return }
    setBusy(true)
    try {
      const r = await api.post<{ lines: number; name: string }>('/api/wordlists/generate', {
        tool: 'cewl', name: cewlName, url: cewlUrl,
        depth: cewlDepth, min_word_len: cewlMinLen,
        include_numbers: cewlNumbers, lowercase: cewlLower,
      }, 150_000)
      await fetchWordlists()
      toast.success(`CeWL done - ${r.lines ?? '?'} words saved to ${r.name}`)
      setCewlName('')
    } catch (e: any) { toast.error(e?.message || 'CeWL failed') }
    finally { setBusy(false) }
  }

  const resolvedCharset = charsetKey === 'Custom' ? customCharset : (CHARSETS[charsetKey] || '')
  const estimate = crunchMin > 0 && crunchMax >= crunchMin && resolvedCharset.length > 0
    ? crunchEstimate(crunchMin, crunchMax, resolvedCharset) : 0
  const estimateTooLarge = estimate > 10_000_000

  const runCrunch = async () => {
    if (!crunchName.trim()) { toast.error('Name is required'); return }
    if (estimateTooLarge) { toast.error('Too many entries - reduce length or charset'); return }
    setBusy(true)
    try {
      const r = await api.post<{ lines: number; name: string }>('/api/wordlists/generate', {
        tool: 'crunch', name: crunchName,
        min_len: crunchMin, max_len: crunchMax,
        charset: resolvedCharset,
        pattern: crunchPattern.trim() || undefined,
      }, 150_000)
      await fetchWordlists()
      toast.success(`Crunch done - ${r.lines ?? '?'} words saved to ${r.name}`)
      setCrunchName('')
    } catch (e: any) { toast.error(e?.message || 'Crunch failed') }
    finally { setBusy(false) }
  }

  const saveManual = async () => {
    if (!manualName.trim() || !manualContent.trim()) { toast.error('Name and content required'); return }
    setBusy(true)
    try {
      await api.post('/api/wordlists', { name: manualName, content: manualContent })
      await fetchWordlists()
      setManualName(''); setManualContent('')
      toast.success('Wordlist saved')
    } catch (e: any) { toast.error(e?.message || 'Save failed') }
    finally { setBusy(false) }
  }

  const runCupp = async () => {
    if (!cuppName.trim()) { toast.error('Name is required'); return }
    const hasData = Object.entries(cupp).some(([k, v]) => !k.startsWith('cupp_') && typeof v === 'string' && v.trim())
    if (!hasData) { toast.error('Fill in at least one profile field'); return }
    setCuppBusy(true)
    try {
      const r = await api.post<{ lines: number; name: string }>('/api/wordlists/generate', {
        tool: 'cupp', name: cuppName, ...cupp,
      })
      await fetchWordlists()
      toast.success(`CUPP: ${r.lines?.toLocaleString() ?? '?'} passwords guardados en ${r.name}`)
      setCuppName('')
    } catch (e: any) { toast.error(e?.message || 'CUPP failed') }
    finally { setCuppBusy(false) }
  }

  const mutateResult = buildWordlist(mutateWords.split('\n'), useSingle, usePairs, useTriples, [...combSeps], mutateActive)

  const saveMutate = async () => {
    if (!mutateName.trim()) { toast.error('Name is required'); return }
    if (mutateResult.length === 0) { toast.error('No words to save'); return }
    setBusy(true)
    try {
      await api.post('/api/wordlists', { name: mutateName, content: mutateResult.join('\n') })
      await fetchWordlists()
      setMutateName('')
      toast.success(`Saved ${mutateResult.length} words to ${mutateName}`)
    } catch (e: any) { toast.error(e?.message || 'Save failed') }
    finally { setBusy(false) }
  }

  const custom = wordlists.filter(w => w.custom)

  return (
    <div className="fixed inset-0 z-50 bg-black/70 grid place-items-center" onClick={onClose}>
      <div className="bg-zinc-900 border border-zinc-700 rounded-lg w-[700px] max-h-[85vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
          <div className="flex items-center gap-2 text-zinc-200 text-sm font-semibold">
            <FileText size={15} className="text-green-400" /> Wordlist Generator
          </div>
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-200"><X size={16} /></button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-zinc-800 overflow-x-auto">
          {([
            { id: 'cewl',   label: 'CeWL',     icon: Globe      },
            { id: 'crunch', label: 'Crunch',    icon: Shuffle    },
            { id: 'cupp',   label: 'CUPP',      icon: UserRound  },
            { id: 'mutate', label: 'Combinar',  icon: Wand2      },
            { id: 'manual', label: 'Manual',    icon: Pencil     },
          ] as const).map(({ id, label, icon: Icon }) => (
            <button key={id} onClick={() => setTab(id)}
              className={cn(
                'flex items-center gap-1.5 px-5 py-2.5 text-xs font-medium border-b-2 whitespace-nowrap transition-colors shrink-0',
                tab === id
                  ? 'border-green-500 text-green-400'
                  : 'border-transparent text-zinc-500 hover:text-zinc-300'
              )}>
              <Icon size={13} />
              {label}
            </button>
          ))}
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {/* CeWL tab */}
          {tab === 'cewl' && (
            <div className="space-y-3">
              <p className="text-[11px] text-zinc-500 leading-relaxed">
                CeWL crawls the target website and extracts words to build a target-specific wordlist — great for guessing passwords that use company or product terminology.
              </p>
              <div>
                <label className={labelCls}>Target URL</label>
                <Input value={cewlUrl} onChange={(e) => setCewlUrl(e.target.value)} placeholder="https://target.com" className="h-8 text-xs font-mono" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={labelCls}>Crawl depth (1-5)</label>
                  <input type="range" min={1} max={5} value={cewlDepth} onChange={(e) => setCewlDepth(Number(e.target.value))}
                    className="w-full accent-green-500" />
                  <div className="text-[10px] text-zinc-400 mt-0.5">Depth: {cewlDepth}</div>
                </div>
                <div>
                  <label className={labelCls}>Min word length (1-20)</label>
                  <input type="range" min={1} max={20} value={cewlMinLen} onChange={(e) => setCewlMinLen(Number(e.target.value))}
                    className="w-full accent-green-500" />
                  <div className="text-[10px] text-zinc-400 mt-0.5">Min: {cewlMinLen} chars</div>
                </div>
              </div>
              <div className="flex gap-4">
                <label className="flex items-center gap-2 text-xs text-zinc-400 cursor-pointer">
                  <input type="checkbox" checked={cewlNumbers} onChange={(e) => setCewlNumbers(e.target.checked)} className="accent-green-500" />
                  Include words with numbers
                </label>
                <label className="flex items-center gap-2 text-xs text-zinc-400 cursor-pointer">
                  <input type="checkbox" checked={cewlLower} onChange={(e) => setCewlLower(e.target.checked)} className="accent-green-500" />
                  Lowercase all
                </label>
              </div>
              <div>
                <label className={labelCls}>Save as</label>
                <Input value={cewlName} onChange={(e) => setCewlName(e.target.value)} placeholder="acme-cewl" className="h-8 text-xs" />
              </div>
              <Button onClick={runCewl} disabled={busy} className="w-full bg-green-700 hover:bg-green-600 text-white">
                {busy ? <><Loader2 size={13} className="animate-spin mr-1.5" />Crawling... (puede tardar 1-2 min)</> : <><Globe size={13} className="mr-1.5" />Run CeWL</>}
              </Button>
            </div>
          )}

          {/* Crunch tab */}
          {tab === 'crunch' && (
            <div className="space-y-3">
              <p className="text-[11px] text-zinc-500 leading-relaxed">
                Crunch generates every combination from a charset between a min/max length. Use a pattern (-t) for structured passwords like <span className="font-mono text-zinc-400">@@@@%%</span> (4 letters + 2 digits).
              </p>
              <div>
                <label className={labelCls}>Charset</label>
                <select className={selectCls} value={charsetKey} onChange={(e) => setCharsetKey(e.target.value)}>
                  {Object.keys(CHARSETS).map(k => <option key={k} value={k}>{k}</option>)}
                  <option value="Custom">Custom...</option>
                </select>
                {charsetKey === 'Custom' && (
                  <Input value={customCharset} onChange={(e) => setCustomCharset(e.target.value)}
                    placeholder="abc123!@#" className="h-8 text-xs font-mono mt-1.5" />
                )}
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={labelCls}>Min length</label>
                  <input type="number" min={1} max={12} value={crunchMin}
                    onChange={(e) => setCrunchMin(Math.max(1, Math.min(12, Number(e.target.value))))}
                    className="w-full h-8 rounded-md bg-zinc-900 border border-zinc-700 text-xs text-zinc-200 px-2 focus:outline-none focus:border-zinc-500" />
                </div>
                <div>
                  <label className={labelCls}>Max length</label>
                  <input type="number" min={1} max={12} value={crunchMax}
                    onChange={(e) => setCrunchMax(Math.max(1, Math.min(12, Number(e.target.value))))}
                    className="w-full h-8 rounded-md bg-zinc-900 border border-zinc-700 text-xs text-zinc-200 px-2 focus:outline-none focus:border-zinc-500" />
                </div>
              </div>
              <div>
                <label className={labelCls}>Pattern (optional) <span className="text-zinc-600 normal-case tracking-normal">@ = lowercase, % = digit, , = uppercase, ^ = special</span></label>
                <Input value={crunchPattern} onChange={(e) => setCrunchPattern(e.target.value)}
                  placeholder="@@@@%%" className="h-8 text-xs font-mono" />
              </div>
              {/* Live estimate */}
              {estimate > 0 && (
                <div className={cn('rounded-md border px-3 py-2 text-xs flex items-center gap-2',
                  estimateTooLarge ? 'border-red-800 bg-red-950/20 text-red-400' : 'border-zinc-700 bg-zinc-800/40 text-zinc-400')}>
                  <Shuffle size={12} className="shrink-0" />
                  {estimateTooLarge
                    ? `~${estimate.toLocaleString()} entries - too large (max 10M). Reduce length or charset.`
                    : `~${estimate.toLocaleString()} entries`}
                </div>
              )}
              <div>
                <label className={labelCls}>Save as</label>
                <Input value={crunchName} onChange={(e) => setCrunchName(e.target.value)} placeholder="crunch-alpha-4-6" className="h-8 text-xs" />
              </div>
              <Button onClick={runCrunch} disabled={busy || estimateTooLarge || !resolvedCharset} className="w-full bg-green-700 hover:bg-green-600 text-white disabled:opacity-40">
                {busy ? <><Loader2 size={13} className="animate-spin mr-1.5" />Generating...</> : <><Shuffle size={13} className="mr-1.5" />Run Crunch</>}
              </Button>
            </div>
          )}

          {/* CUPP tab */}
          {tab === 'cupp' && (
            <div className="space-y-3">
              <p className="text-[11px] text-zinc-500 leading-relaxed">
                Perfil del objetivo. Rellena los campos que conozcas - CUPP genera combinaciones de todos con años, fechas, l33t, sufijos especiales, y pares de palabras.
              </p>

              <div className="rounded-md border border-zinc-800 bg-zinc-900/40 p-3 space-y-2">
                <label className={labelCls + ' mb-1'}>Objetivo</label>
                <div className="grid grid-cols-3 gap-2">
                  {([['Nombre', 'first_name'], ['Apellido', 'last_name'], ['Apodo/nick', 'nickname']] as const).map(([lbl, key]) => (
                    <div key={key}>
                      <label className={labelCls}>{lbl}</label>
                      <Input value={cupp[key]} onChange={e => setCupp(p => ({...p, [key]: e.target.value}))} placeholder={lbl.toLowerCase()} className="h-8 text-xs" />
                    </div>
                  ))}
                </div>
                <div>
                  <label className={labelCls}>Fecha de nacimiento (DD/MM/AAAA)</label>
                  <Input value={cupp.birthdate} onChange={e => setCupp(p => ({...p, birthdate: e.target.value}))} placeholder="15/06/1990" className="h-8 text-xs font-mono" />
                </div>
              </div>

              <div className="rounded-md border border-zinc-800 bg-zinc-900/40 p-3 space-y-2">
                <label className={labelCls + ' mb-1'}>Pareja / familia</label>
                <div className="grid grid-cols-3 gap-2">
                  {([['Nombre', 'partner'], ['Apodo', 'partner_nick'], ['Nacimiento', 'partner_birth']] as const).map(([lbl, key]) => (
                    <div key={key}>
                      <label className={labelCls}>{lbl}</label>
                      <Input value={cupp[key]} onChange={e => setCupp(p => ({...p, [key]: e.target.value}))} placeholder={lbl.toLowerCase()} className="h-8 text-xs" />
                    </div>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className={labelCls}>Mascota</label>
                  <Input value={cupp.pet} onChange={e => setCupp(p => ({...p, pet: e.target.value}))} placeholder="firulais" className="h-8 text-xs" />
                </div>
                <div>
                  <label className={labelCls}>Empresa / empresa</label>
                  <Input value={cupp.company} onChange={e => setCupp(p => ({...p, company: e.target.value}))} placeholder="acmecorp" className="h-8 text-xs" />
                </div>
              </div>

              <div>
                <label className={labelCls}>Palabras clave extra (una por linea)</label>
                <textarea value={cupp.keywords} onChange={e => setCupp(p => ({...p, keywords: e.target.value}))}
                  placeholder={'futbol\nriver\nboca'}
                  className="w-full h-16 rounded-md bg-black border border-zinc-700 text-xs text-zinc-200 font-mono p-2 focus:outline-none focus:border-zinc-500" />
              </div>

              <div className="flex gap-4">
                {([['cupp_leet', 'L33t (a→@ e→3...)'], ['cupp_specials', '+ ! 123 @'], ['cupp_numbers', '+ numeros']] as const).map(([key, lbl]) => (
                  <label key={key} className="flex items-center gap-2 text-[11px] text-zinc-400 cursor-pointer">
                    <input type="checkbox" checked={cupp[key] as boolean} onChange={e => setCupp(p => ({...p, [key]: e.target.checked}))} className="accent-green-500" />
                    {lbl}
                  </label>
                ))}
              </div>

              <div>
                <label className={labelCls}>Guardar como</label>
                <Input value={cuppName} onChange={e => setCuppName(e.target.value)} placeholder="perfil-objetivo" className="h-8 text-xs" />
              </div>
              <Button onClick={runCupp} disabled={cuppBusy} className="w-full bg-green-700 hover:bg-green-600 text-white">
                {cuppBusy
                  ? <><Loader2 size={13} className="animate-spin mr-1.5" />Generando...</>
                  : <><UserRound size={13} className="mr-1.5" />Generar wordlist CUPP</>}
              </Button>
            </div>
          )}

          {/* Mutate tab */}
          {tab === 'mutate' && (
            <div className="space-y-3">
              <div>
                <label className={labelCls}>Palabras base (una por linea)</label>
                <textarea value={mutateWords} onChange={(e) => setMutateWords(e.target.value)}
                  placeholder={'mcdonalds\nargentina\n2026\nhamburguesas'}
                  className="w-full h-24 rounded-md bg-black border border-zinc-700 text-xs text-zinc-200 font-mono p-2 focus:outline-none focus:border-zinc-500" />
              </div>

              {/* Combination mode */}
              <div className="rounded-md border border-zinc-800 bg-zinc-900/40 p-3 space-y-2">
                <label className={labelCls + ' mb-1'}>Como combinarlas</label>
                <div className="space-y-1.5">
                  <label className="flex items-center gap-2 text-[11px] text-zinc-400 cursor-pointer">
                    <input type="checkbox" checked={useSingle} onChange={e => setUseSingle(e.target.checked)} className="accent-green-500" />
                    Palabras solas (mcdonalds, argentina...)
                  </label>
                  <label className="flex items-center gap-2 text-[11px] text-zinc-400 cursor-pointer">
                    <input type="checkbox" checked={usePairs} onChange={e => setUsePairs(e.target.checked)} className="accent-green-500" />
                    Pares (mcdonalds+argentina, argentina+2026...)
                  </label>
                  <label className="flex items-center gap-2 text-[11px] text-zinc-400 cursor-pointer">
                    <input type="checkbox" checked={useTriples} onChange={e => setUseTriples(e.target.checked)} className="accent-green-500" />
                    Trios (mcdonalds+argentina+2026...)
                  </label>
                </div>
                <div className="border-t border-zinc-800 pt-2 mt-1">
                  <label className={labelCls + ' mb-1.5'}>Separador entre palabras</label>
                  <div className="flex flex-wrap gap-2">
                    {[['(ninguno)', ''], ['_', '_'], ['-', '-'], ['.', '.'], ['@', '@']].map(([label, val]) => (
                      <label key={val} className="flex items-center gap-1.5 text-[11px] text-zinc-400 cursor-pointer bg-zinc-800 rounded px-2 py-1">
                        <input type="checkbox"
                          checked={combSeps.has(val)}
                          onChange={e => {
                            const next = new Set(combSeps)
                            e.target.checked ? next.add(val) : next.delete(val)
                            setCombSeps(next)
                          }}
                          className="accent-green-500" />
                        <span className="font-mono">{label}</span>
                      </label>
                    ))}
                  </div>
                </div>
              </div>

              {/* Mutations */}
              <div className="rounded-md border border-zinc-800 bg-zinc-900/40 p-3 space-y-2">
                <label className={labelCls + ' mb-1'}>Mutaciones a aplicar a cada resultado</label>
                <div className="grid grid-cols-2 gap-y-1.5 gap-x-3">
                  {COMBO_MUTATIONS.map(rule => (
                    <label key={rule.id} className="flex items-start gap-2 text-[11px] text-zinc-400 cursor-pointer hover:text-zinc-200">
                      <input type="checkbox"
                        checked={mutateActive.has(rule.id)}
                        onChange={e => {
                          const next = new Set(mutateActive)
                          e.target.checked ? next.add(rule.id) : next.delete(rule.id)
                          setMutateActive(next)
                        }}
                        className="mt-0.5 accent-green-500 shrink-0" />
                      <span className="leading-tight">{rule.label}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Live count */}
              {mutateResult.length > 0 && (
                <div className={cn('rounded-md border px-3 py-2 text-xs flex items-center gap-2',
                  mutateResult.length > 500_000
                    ? 'border-red-800 bg-red-950/20 text-red-400'
                    : 'border-zinc-700 bg-zinc-800/40 text-zinc-400')}>
                  <Wand2 size={12} className="text-green-400 shrink-0" />
                  <span><span className="text-green-400 font-medium">{mutateResult.length.toLocaleString()}</span> entradas unicas</span>
                </div>
              )}

              <div>
                <label className={labelCls}>Guardar como</label>
                <Input value={mutateName} onChange={(e) => setMutateName(e.target.value)} placeholder="mcdonalds-combo" className="h-8 text-xs" />
              </div>
              <Button onClick={saveMutate} disabled={busy || mutateResult.length === 0} className="w-full bg-green-700 hover:bg-green-600 text-white disabled:opacity-40">
                {busy
                  ? <><Loader2 size={13} className="animate-spin mr-1.5" />Guardando...</>
                  : <><Wand2 size={13} className="mr-1.5" />Guardar {mutateResult.length > 0 ? `${mutateResult.length.toLocaleString()} palabras` : ''}</>}
              </Button>
            </div>
          )}

          {/* Manual tab */}
          {tab === 'manual' && (
            <div className="space-y-2">
              <p className="text-[11px] text-zinc-500">One entry per line.</p>
              <Input value={manualName} onChange={(e) => setManualName(e.target.value)} placeholder="my-custom-list" className="h-8 text-xs" />
              <textarea value={manualContent} onChange={(e) => setManualContent(e.target.value)}
                placeholder={'admin\npassword123\nSummer2024!\nCompanyName@2024'}
                className="w-full h-44 rounded-md bg-black border border-zinc-700 text-xs text-zinc-200 font-mono p-2 focus:outline-none focus:border-zinc-500" />
              <Button onClick={saveManual} disabled={busy} size="sm" className="bg-zinc-700 hover:bg-zinc-600">
                {busy ? <Loader2 size={13} className="animate-spin mr-1.5" /> : <Save size={13} className="mr-1.5" />}Save
              </Button>
            </div>
          )}

          {/* Saved custom wordlists */}
          {custom.length > 0 && (
            <div className="border-t border-zinc-800 pt-3">
              <label className={labelCls}>Saved custom wordlists ({custom.length})</label>
              {custom.map(w => (
                <div key={w.path} className="flex items-center justify-between py-1.5 border-b border-zinc-800/50">
                  <span className="text-xs text-zinc-300">
                    <span className="text-green-500 mr-1.5">★</span>{w.name}
                    <span className="text-zinc-600 ml-2">{w.lines != null ? `${w.lines.toLocaleString()} words` : humanSize(w.size)}</span>
                  </span>
                  <button onClick={() => remove(w.name)} className="text-zinc-500 hover:text-red-400"><Trash2 size={13} /></button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
