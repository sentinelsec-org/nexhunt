import { create } from 'zustand'
import type { PipelineEvent } from '@/types'

export type PipelineType = 'xss' | 'sqli' | 'js_scan'

export interface PipelineRun {
  id: string
  type: PipelineType
  target: string
  phase: string
  katanaUrls: string[]
  candidates: string[]      // XSS param URLs / SQLi param URLs / JS file URLs
  findingsCount: number
  log: string[]
  startedAt: number
  stats: {
    totalUrls: number
    jsFiles?: number
  }
}

interface PipelineState {
  runs: PipelineRun[]
  activeRunId: string | null
  handleEvent: (event: PipelineEvent) => void
  startRun: (type: PipelineType, target: string) => string
  clearRuns: () => void
}

let runCounter = 0

const PIPELINE_LABELS: Record<PipelineType, string> = {
  xss: 'XSS Pipeline',
  sqli: 'SQLi Probe',
  js_scan: 'JS Scanner',
}

export const usePipelineStore = create<PipelineState>((set, get) => ({
  runs: [],
  activeRunId: null,

  startRun: (type: PipelineType, target: string) => {
    const id = `run-${++runCounter}-${Date.now()}`
    const run: PipelineRun = {
      id,
      type,
      target,
      phase: 'idle',
      katanaUrls: [],
      candidates: [],
      findingsCount: 0,
      log: [`[•] ${PIPELINE_LABELS[type]} started for ${target}`],
      startedAt: Date.now(),
      stats: { totalUrls: 0 },
    }
    set(state => ({ runs: [run, ...state.runs], activeRunId: id }))
    return id
  },

  handleEvent: (event: PipelineEvent) => {
    const { runs, activeRunId } = get()
    if (!activeRunId) return

    set({
      runs: runs.map(run => {
        if (run.id !== activeRunId) return run
        const updated = { ...run, log: [...run.log] }

        // ── Katana phase (shared by all pipelines) ──
        if (event.phase === 'katana') {
          updated.phase = 'katana'
          if (event.event === 'started') {
            updated.log.push(`[Katana] Crawling ${run.target}...`)
          } else if (event.event === 'url_found' && event.url) {
            updated.katanaUrls = [...updated.katanaUrls, event.url]
            updated.stats = { ...updated.stats, totalUrls: updated.katanaUrls.length }
            if (event.has_params || event.is_form) {
              updated.candidates = [...updated.candidates, event.url]
              updated.log.push(`  [param] ${event.url}`)
            }
            // Skip logging plain URLs — too noisy. Stats panel shows the count.
            // Log a progress ping every 50 URLs to show crawl is alive
            else if (updated.katanaUrls.length % 50 === 0) {
              updated.log.push(`  [•] ${updated.katanaUrls.length} URLs crawled so far...`)
            }
          } else if (event.event === 'completed') {
            const cLabel = run.type === 'js_scan' ? 'JS files' : 'param URLs'
            updated.log.push(
              `[Katana] Done — ${event.total_urls ?? updated.katanaUrls.length} URLs crawled, ${updated.candidates.length} ${cLabel} found`
            )
          } else if (event.event === 'failed') {
            updated.phase = 'failed'
            updated.log.push(`[Katana] ERROR: ${event.error}`)
          }
        }

        // ── Dalfox phase (XSS) ──
        if (event.phase === 'dalfox') {
          updated.phase = 'dalfox'
          if (event.event === 'started') {
            updated.log.push(`[Dalfox] Scanning ${event.targets ?? 0} endpoints...`)
          } else if (event.event === 'finding' && event.finding) {
            updated.findingsCount += 1
            updated.log.push(
              `  [XSS FOUND] ${event.finding.url ?? ''} — param: ${event.finding.parameter ?? '?'}`
            )
          } else if (event.event === 'completed') {
            updated.phase = 'completed'
            updated.log.push(`[Dalfox] Done — ${event.findings ?? 0} XSS finding(s)`)
            updated.log.push(`[✓] Pipeline completed`)
          } else if (event.event === 'failed') {
            updated.phase = 'failed'
            updated.log.push(`[Dalfox] ERROR: ${event.error}`)
          }
        }

        // ── SQLi probe phase ──
        if (event.phase === 'sqli_probe') {
          updated.phase = 'sqli_probe'
          if (event.event === 'started') {
            updated.log.push(`[SQLi] Probing ${event.targets ?? 0} URLs with ' payload...`)
          } else if (event.event === 'finding' && event.finding) {
            updated.findingsCount += 1
            const f = event.finding
            updated.log.push(
              `  [SQL ERROR] ${f.original_url ?? f.url} — param: ${f.parameter} — ${f.evidence?.slice(0, 80)}`
            )
          } else if (event.event === 'completed') {
            updated.phase = 'completed'
            updated.log.push(`[SQLi] Done — ${event.findings ?? 0} potential finding(s)`)
            updated.log.push(`[✓] Pipeline completed`)
          } else if (event.event === 'failed') {
            updated.phase = 'failed'
            updated.log.push(`[SQLi] ERROR: ${event.error}`)
          }
        }

        // ── JS scan phase ──
        if (event.phase === 'js_scan') {
          updated.phase = 'js_scan'
          if (event.event === 'started') {
            updated.log.push(`[JS] Fetching and analyzing ${event.targets ?? 0} JS files...`)
          } else if (event.event === 'js_file' && event.url) {
            // Only log failed fetches — successes are too noisy
            if (!event.fetched) updated.log.push(`  [js]  ${event.url} — failed`)
          } else if (event.event === 'finding' && event.finding) {
            updated.findingsCount += 1
            const f = event.finding
            updated.log.push(
              `  [${f.severity?.toUpperCase()}] ${f.label} in ${f.js_url} :${f.line} — ${f.match?.slice(0, 60)}`
            )
          } else if (event.event === 'completed') {
            updated.phase = 'completed'
            updated.log.push(`[JS] Done — ${event.findings ?? 0} finding(s) in ${event.js_files ?? 0} files`)
            updated.log.push(`[✓] Pipeline completed`)
          } else if (event.event === 'failed') {
            updated.phase = 'failed'
            updated.log.push(`[JS] ERROR: ${event.error}`)
          }
        }

        return updated
      }),
    })
  },

  clearRuns: () => set({ runs: [], activeRunId: null }),
}))
