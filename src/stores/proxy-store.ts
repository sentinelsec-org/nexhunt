import { create } from 'zustand'
import type { HttpFlow } from '@/types'
import { useBruteForceStore, emptyConfig } from '@/stores/bruteforce-store'
import { useExploitStore } from '@/stores/exploit-store'

function buildBruteForceConfig(flow: HttpFlow) {
  const https = flow.request_url.startsWith('https')
  const cfg = emptyConfig()
  cfg.target = flow.request_host
  cfg.service = https ? 'https-post-form' : 'http-post-form'
  cfg.port = flow.request_port || (https ? 443 : 80)
  cfg.form_path = flow.request_path || '/'
  // Rewrite the captured body: replace the value of the likely user/pass fields
  // with hydra placeholders, keep everything else as-is.
  const body = flow.request_body || ''
  const parts = body.split('&').map(p => {
    const eq = p.indexOf('=')
    const key = eq === -1 ? p : p.slice(0, eq)
    const lk = key.toLowerCase()
    if (/user|email|login|uname|^id$/.test(lk)) return `${key}=^USER^`
    if (/pass|pwd|passwd/.test(lk)) return `${key}=^PASS^`
    return p
  })
  cfg.form_body = parts.join('&')
  return cfg
}

export interface RepeaterTab {
  id: string
  label: string
  rawRequest: string
  host: string
  port: number
  useHttps: boolean
  response: {
    status: number
    headers: Record<string, string>
    body: string
    duration_ms: number
    error?: string
  } | null
  loading: boolean
}

export interface IntruderResult {
  index: number
  payload: string
  status: number
  length: number
  duration_ms: number
  error: string | null
  request: string
  response_headers: Record<string, string>
  response_body: string
  content_type: string
}

export function flowToRaw(flow: HttpFlow): string {
  const lines: string[] = []
  lines.push(`${flow.request_method} ${flow.request_path} HTTP/1.1`)
  lines.push(`Host: ${flow.request_host}`)
  if (flow.request_headers) {
    for (const [k, v] of Object.entries(flow.request_headers)) {
      if (k.toLowerCase() !== 'host') lines.push(`${k}: ${v}`)
    }
  }
  lines.push('')
  if (flow.request_body) lines.push(flow.request_body)
  return lines.join('\n')
}

interface ProxyState {
  flows: HttpFlow[]
  selectedFlowId: string | null
  interceptEnabled: boolean
  interceptScopeOnly: boolean
  interceptQueue: HttpFlow[]
  proxyPort: number
  proxyRunning: boolean
  filter: { host: string; method: string; statusCode: string; search: string; scopeOnly: boolean }

  // Repeater
  repeaterTabs: RepeaterTab[]
  activeRepeaterTabId: string | null

  // Intruder
  intruderRequest: string
  intruderHost: string
  intruderPort: number
  intruderHttps: boolean
  intruderResults: IntruderResult[]
  intruderRunning: boolean
  intruderJobId: string | null
  intruderTotal: number

  addFlow: (flow: HttpFlow) => void
  setFlows: (flows: HttpFlow[]) => void
  mergeFlows: (flows: HttpFlow[]) => void
  selectFlow: (id: string | null) => void
  setInterceptEnabled: (enabled: boolean) => void
  setInterceptScopeOnly: (enabled: boolean) => void
  setInterceptQueue: (flows: HttpFlow[]) => void
  addToInterceptQueue: (flow: HttpFlow) => void
  removeFromInterceptQueue: (id: string) => void
  setProxyPort: (port: number) => void
  setProxyRunning: (running: boolean) => void
  setFilter: (filter: Partial<ProxyState['filter']>) => void
  clearFlows: () => void

  // Repeater actions
  sendToRepeater: (flow: HttpFlow) => void
  sendRawToRepeater: (raw: string, host: string, port: number, https: boolean) => void
  addRepeaterTab: () => void
  closeRepeaterTab: (id: string) => void
  setActiveRepeaterTab: (id: string) => void
  updateRepeaterTab: (id: string, patch: Partial<RepeaterTab>) => void

  // JWT
  jwtFlow: HttpFlow | null
  sendToJwt: (flow: HttpFlow) => void
  clearJwtFlow: () => void

  // OAuth
  oauthFlow: HttpFlow | null
  sendToOauth: (flow: HttpFlow) => void
  clearOauthFlow: () => void

  // Brute force
  sendToBruteForce: (flow: HttpFlow) => void

  // Login SQLi bypass
  sendToLoginBypass: (flow: HttpFlow) => void

  // Intruder actions
  sendToIntruder: (flow: HttpFlow) => void
  sendRawToIntruder: (raw: string, host: string, port: number, https: boolean) => void
  setIntruderRequest: (raw: string) => void
  setIntruderTarget: (host: string, port: number, https: boolean) => void
  addIntruderResult: (result: IntruderResult) => void
  clearIntruderResults: () => void
  setIntruderRunning: (running: boolean, jobId?: string | null, total?: number) => void
}

let _tabCounter = 1

export const useProxyStore = create<ProxyState>((set) => ({
  flows: [],
  selectedFlowId: null,
  interceptEnabled: false,
  interceptScopeOnly: false,
  interceptQueue: [],
  proxyPort: 8080,
  proxyRunning: false,
  filter: { host: '', method: '', statusCode: '', search: '', scopeOnly: false },

  repeaterTabs: [],
  activeRepeaterTabId: null,

  intruderRequest: '',
  intruderHost: '',
  intruderPort: 80,
  intruderHttps: false,
  intruderResults: [],
  intruderRunning: false,
  intruderJobId: null,
  intruderTotal: 0,

  jwtFlow: null,
  sendToJwt: (flow) => set({ jwtFlow: flow }),
  clearJwtFlow: () => set({ jwtFlow: null }),

  oauthFlow: null,
  sendToOauth: (flow) => set({ oauthFlow: flow }),
  clearOauthFlow: () => set({ oauthFlow: null }),

  sendToBruteForce: (flow) => {
    useBruteForceStore.getState().setPrefill(buildBruteForceConfig(flow))
  },

  sendToLoginBypass: (flow) => {
    const https = flow.request_url.startsWith('https')
    useExploitStore.getState().prefillLoginBypass(
      flowToRaw(flow),
      flow.request_host,
      flow.request_port || (https ? 443 : 80),
      https,
    )
  },

  addFlow: (flow) => set((s) => ({
    flows: [flow, ...s.flows.filter(existing => existing.id !== flow.id)].slice(0, 10000),
  })),
  setFlows: (flows) => set({ flows }),
  mergeFlows: (flows) => set((s) => {
    const known = new Set(s.flows.map(flow => flow.id))
    const merged = [...s.flows, ...flows.filter(flow => !known.has(flow.id))]
    merged.sort((a, b) => String(b.timestamp || '').localeCompare(String(a.timestamp || '')))
    return { flows: merged.slice(0, 10000) }
  }),
  selectFlow: (id) => set({ selectedFlowId: id }),
  setInterceptEnabled: (enabled) => set({ interceptEnabled: enabled }),
  setInterceptScopeOnly: (enabled) => set({ interceptScopeOnly: enabled }),
  setInterceptQueue: (flows) => set({ interceptQueue: flows }),
  addToInterceptQueue: (flow) => set((s) => ({
    interceptQueue: [...s.interceptQueue.filter(existing => existing.id !== flow.id), flow],
  })),
  removeFromInterceptQueue: (id) => set((s) => ({ interceptQueue: s.interceptQueue.filter(f => f.id !== id) })),
  setProxyPort: (port) => set({ proxyPort: port }),
  setProxyRunning: (running) => set({ proxyRunning: running }),
  setFilter: (filter) => set((s) => ({ filter: { ...s.filter, ...filter } })),
  clearFlows: () => set({ flows: [], selectedFlowId: null }),

  // Repeater
  sendToRepeater: (flow) => {
    const id = `tab-${_tabCounter++}`
    const tab: RepeaterTab = {
      id,
      label: `${flow.request_method} ${flow.request_path.slice(0, 20)}`,
      rawRequest: flowToRaw(flow),
      host: flow.request_host,
      port: flow.request_port || (flow.request_url.startsWith('https') ? 443 : 80),
      useHttps: flow.request_url.startsWith('https'),
      response: null,
      loading: false,
    }
    set((s) => ({ repeaterTabs: [...s.repeaterTabs.slice(-9), tab], activeRepeaterTabId: id }))
  },
  sendRawToRepeater: (raw, host, port, https) => {
    const id = `tab-${_tabCounter++}`
    const first = raw.split(/\r?\n/, 1)[0] || 'Request'
    const tab: RepeaterTab = {
      id, label: first.slice(0, 28), rawRequest: raw,
      host, port, useHttps: https, response: null, loading: false,
    }
    set((s) => ({ repeaterTabs: [...s.repeaterTabs.slice(-9), tab], activeRepeaterTabId: id }))
  },
  addRepeaterTab: () => {
    const id = `tab-${_tabCounter++}`
    const tab: RepeaterTab = {
      id, label: `Tab ${_tabCounter - 1}`,
      rawRequest: 'GET / HTTP/1.1\nHost: example.com\n\n',
      host: 'example.com', port: 80, useHttps: false,
      response: null, loading: false,
    }
    set((s) => ({ repeaterTabs: [...s.repeaterTabs, tab], activeRepeaterTabId: id }))
  },
  closeRepeaterTab: (id) => set((s) => {
    const tabs = s.repeaterTabs.filter(t => t.id !== id)
    const active = s.activeRepeaterTabId === id ? (tabs[tabs.length - 1]?.id ?? null) : s.activeRepeaterTabId
    return { repeaterTabs: tabs, activeRepeaterTabId: active }
  }),
  setActiveRepeaterTab: (id) => set({ activeRepeaterTabId: id }),
  updateRepeaterTab: (id, patch) => set((s) => ({
    repeaterTabs: s.repeaterTabs.map(t => t.id === id ? { ...t, ...patch } : t)
  })),

  // Intruder
  sendToIntruder: (flow) => set({
    intruderRequest: flowToRaw(flow),
    intruderHost: flow.request_host,
    intruderPort: flow.request_port || (flow.request_url.startsWith('https') ? 443 : 80),
    intruderHttps: flow.request_url.startsWith('https'),
    intruderResults: [],
  }),
  sendRawToIntruder: (raw, host, port, https) => set({
    intruderRequest: raw,
    intruderHost: host,
    intruderPort: port,
    intruderHttps: https,
    intruderResults: [],
  }),
  setIntruderRequest: (raw) => set({ intruderRequest: raw }),
  setIntruderTarget: (host, port, https) => set({ intruderHost: host, intruderPort: port, intruderHttps: https }),
  addIntruderResult: (result) => set((s) => ({ intruderResults: [...s.intruderResults, result].slice(-20000) })),
  clearIntruderResults: () => set({ intruderResults: [], intruderTotal: 0 }),
  setIntruderRunning: (running, jobId, total) => set((s) => ({
    intruderRunning: running,
    intruderJobId: jobId !== undefined ? jobId : s.intruderJobId,
    intruderTotal: total !== undefined ? total : s.intruderTotal,
  })),
}))
