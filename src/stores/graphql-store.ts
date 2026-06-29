import { create } from 'zustand'

export type OpKind = 'query' | 'mutation'
export type ProbeState = 'unknown' | 'open' | 'secured'

export interface SchemaArg {
  name: string
  required: boolean
  type: string
}

export interface SchemaField {
  name: string
  args: SchemaArg[]
  type: string
  selection?: string
  sensitive: boolean
  no_required_args: boolean
}

export interface Schema {
  endpoint: string
  introspection: boolean
  query_type: string | null
  mutation_type: string | null
  types_count: number
  queries: SchemaField[]
  mutations: SchemaField[]
}

export interface QueryResponse {
  status: number
  time_ms: number
  use_auth: boolean
  headers: Record<string, string>
  body: string
  json: unknown
  errors: unknown[]
  leaked_urls: string[]
}

// Audit phases that can be toggled off (introspection always runs server-side).
export const AUDIT_PHASES = ['unauth', 'idor', 'error_leak', 'mutations', 'name_discovery'] as const
export type AuditPhase = (typeof AUDIT_PHASES)[number]

interface GraphqlState {
  endpoint: string
  schema: Schema | null
  introspecting: boolean
  introspectError: string | null

  selectedOp: { name: string; kind: OpKind } | null
  queryDraft: string
  variablesDraft: string
  sending: boolean
  authResp: QueryResponse | null
  anonResp: QueryResponse | null

  probeStatus: Record<string, ProbeState>

  phases: AuditPhase[]
  sampleIds: string
  extraQueries: string

  setEndpoint: (v: string) => void
  setSchema: (s: Schema | null) => void
  setIntrospecting: (v: boolean) => void
  setIntrospectError: (v: string | null) => void
  selectOp: (op: { name: string; kind: OpKind } | null, query: string) => void
  setQueryDraft: (v: string) => void
  setVariablesDraft: (v: string) => void
  setSending: (v: boolean) => void
  setResponses: (auth: QueryResponse | null, anon: QueryResponse | null) => void
  setProbe: (name: string, state: ProbeState) => void
  togglePhase: (p: AuditPhase) => void
  setSampleIds: (v: string) => void
  setExtraQueries: (v: string) => void
  reset: () => void
}

export const useGraphqlStore = create<GraphqlState>((set) => ({
  endpoint: '',
  schema: null,
  introspecting: false,
  introspectError: null,

  selectedOp: null,
  queryDraft: '',
  variablesDraft: '',
  sending: false,
  authResp: null,
  anonResp: null,

  probeStatus: {},

  phases: [...AUDIT_PHASES],
  sampleIds: '',
  extraQueries: '',

  setEndpoint: (v) => set({ endpoint: v }),
  setSchema: (schema) => set({ schema }),
  setIntrospecting: (introspecting) => set({ introspecting }),
  setIntrospectError: (introspectError) => set({ introspectError }),
  selectOp: (selectedOp, query) => set({ selectedOp, queryDraft: query, authResp: null, anonResp: null }),
  setQueryDraft: (queryDraft) => set({ queryDraft }),
  setVariablesDraft: (variablesDraft) => set({ variablesDraft }),
  setSending: (sending) => set({ sending }),
  setResponses: (authResp, anonResp) => set({ authResp, anonResp }),
  setProbe: (name, state) => set((s) => ({ probeStatus: { ...s.probeStatus, [name]: state } })),
  togglePhase: (p) => set((s) => ({
    phases: s.phases.includes(p) ? s.phases.filter((x) => x !== p) : [...s.phases, p],
  })),
  setSampleIds: (sampleIds) => set({ sampleIds }),
  setExtraQueries: (extraQueries) => set({ extraQueries }),
  reset: () => set({
    schema: null, introspectError: null, selectedOp: null, queryDraft: '',
    variablesDraft: '', authResp: null, anonResp: null, probeStatus: {},
  }),
}))
