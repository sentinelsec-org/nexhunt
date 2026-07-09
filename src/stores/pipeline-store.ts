import { create } from 'zustand'
import type { PipelineEvent } from '@/types'

export type PipelineType = 'xss' | 'sqli' | 'lfi' | 'js_scan'

export interface PipelineFinding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  label: string
  text: string
  url?: string
  param?: string
  // Raw fields kept for JS-secret AI analysis (full value, surrounding code, line).
  match?: string
  context?: string
  line?: number
}

export interface PipelineRun {
  id: string
  type: PipelineType
  target: string
  phase: string
  katanaUrls: string[]
  candidates: string[]      // XSS param URLs / SQLi param URLs / JS file URLs
  findingsCount: number
  findings: PipelineFinding[]
  log: string[]
  startedAt: number
  // Count of param/JS candidates. On a cache-hit run the per-URL stream is not
  // replayed, so `candidates` (the URL list) stays empty; this carries the count
  // reported by the 'cached'/'completed' events so the UI still shows it.
  candidateCount: number
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
  lfi: 'LFI Probe',
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
      findings: [],
      log: [`[•] ${PIPELINE_LABELS[type]} started for ${target}`],
      startedAt: Date.now(),
      candidateCount: 0,
      stats: { totalUrls: 0 },
    }
    set(state => ({ runs: [run, ...state.runs], activeRunId: id }))
    return id
  },

  handleEvent: (event: PipelineEvent) => {
    const { runs, activeRunId } = get()

    // Route each event to the run that owns it by pipeline type, so concurrent
    // pipelines (e.g. JS Secrets + SQLi on the same targets) don't dump each
    // other's URLs/findings into one run. `runs` is newest-first, so this picks
    // the most recent still-running run of that type. Events with no pipeline
    // tag fall back to the active (last-started) run.
    let targetId = activeRunId
    if (event.pipeline) {
      const match = runs.find(r => r.type === event.pipeline && r.phase !== 'completed' && r.phase !== 'failed')
      if (match) targetId = match.id
    }
    if (!targetId) return

    set({
      runs: runs.map(run => {
        if (run.id !== targetId) return run
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
              updated.candidateCount = updated.candidates.length
              updated.log.push(`  [param] ${event.url}`)
            }
            // Skip logging plain URLs — too noisy. Stats panel shows the count.
            // Log a progress ping every 50 URLs to show crawl is alive
            else if (updated.katanaUrls.length % 50 === 0) {
              updated.log.push(`  [•] ${updated.katanaUrls.length} URLs crawled so far...`)
            }
          } else if (event.event === 'cached') {
            // Cache hit: the per-URL stream is skipped, so pull the counts off the
            // event itself, otherwise the panel would show 0 URLs / 0 candidates.
            updated.stats = { ...updated.stats, totalUrls: event.total ?? updated.stats.totalUrls }
            updated.candidateCount = event.xss_candidates ?? updated.candidateCount
            updated.log.push(`[Katana] ♻ ${event.message ?? 'reused cached crawl'}`)
          } else if (event.event === 'skipped') {
            updated.log.push(`[→] ${event.message ?? 'Crawl skipped — continuing with URLs found so far'}`)
          } else if (event.event === 'completed') {
            const cLabel = run.type === 'js_scan' ? 'JS files' : 'param URLs'
            updated.stats = { ...updated.stats, totalUrls: Math.max(updated.stats.totalUrls, event.total_urls ?? 0) }
            updated.candidateCount = Math.max(updated.candidateCount, event.xss_candidates ?? 0)
            updated.log.push(
              `[Katana] Done — ${event.total_urls ?? updated.katanaUrls.length} URLs crawled, ${event.xss_candidates ?? updated.candidates.length} ${cLabel} found`
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
            updated.findings = [...updated.findings, {
              severity: 'high', label: 'XSS',
              text: `param: ${event.finding.parameter ?? '?'}`,
              url: event.finding.url,
              param: event.finding.parameter,
            }]
            updated.log.push(
              `  [XSS FOUND] ${event.finding.url ?? ''} — param: ${event.finding.parameter ?? '?'}`
            )
          } else if (event.event === 'skipped') {
            updated.log.push(`[→] ${event.message ?? 'Dalfox scan stopped'}`)
          } else if (event.event === 'completed') {
            updated.phase = 'completed'
            updated.log.push(`[Dalfox] Done — ${event.findings ?? 0} XSS finding(s)`)
            updated.log.push(`[✓] Pipeline completed`)
          } else if (event.event === 'failed') {
            updated.phase = 'failed'
            updated.log.push(`[Dalfox] ERROR: ${event.error}`)
          }
        }

        // ── JS endpoint parsing phase (XSS + SQLi pipelines) ──
        if (event.phase === 'js_parse') {
          updated.phase = 'js_parse'
          if (event.event === 'started') {
            updated.log.push(`[JS] Parsing ${event.targets ?? 0} JS files for hidden endpoints...`)
          } else if (event.event === 'skipped') {
            updated.log.push(`[→] ${event.message ?? 'JS parse skipped'}`)
          } else if (event.event === 'completed') {
            const n = event.js_endpoints ?? 0
            updated.log.push(`[JS] Added ${n} new parameterized endpoint(s) from JS`)
            if (n > 0) updated.candidates = [...updated.candidates]
          }
        }

        // ── SQLi probe phase ──
        if (event.phase === 'sqli_probe') {
          updated.phase = 'sqli_probe'
          if (event.event === 'started') {
            updated.log.push(`[SQLi] Probing ${event.targets ?? 0} URLs (error + boolean + time-based)...`)
          } else if (event.event === 'skipped') {
            updated.log.push(`[→] ${event.message ?? 'SQLi probe stopped'}`)
          } else if (event.event === 'finding' && event.finding) {
            updated.findingsCount += 1
            const f = event.finding
            const tag = f.method === 'boolean-based' ? 'BOOLEAN'
              : f.method === 'time-based' ? 'TIME-BASED'
              : 'SQL ERROR'
            updated.findings = [...updated.findings, {
              severity: 'critical', label: tag,
              text: `param: ${f.parameter} — ${f.evidence?.slice(0, 80) ?? ''}`,
              url: f.original_url ?? f.url,
              param: f.parameter,
            }]
            updated.log.push(
              `  [${tag}] ${f.original_url ?? f.url} — param: ${f.parameter} — ${f.evidence?.slice(0, 80)}`
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

        // ── LFI probe phase ──
        if (event.phase === 'lfi_probe') {
          updated.phase = 'lfi_probe'
          if (event.event === 'started') {
            updated.log.push(`[LFI] Probing ${event.targets ?? 0} URLs (traversal + wrappers + bypasses)...`)
          } else if (event.event === 'skipped') {
            updated.log.push(`[→] ${event.message ?? 'LFI probe stopped'}`)
          } else if (event.event === 'finding' && event.finding) {
            updated.findingsCount += 1
            const f = event.finding
            const conf = (f as { confidence?: string }).confidence === 'tentative' ? 'medium' : 'high'
            updated.findings = [...updated.findings, {
              severity: conf as PipelineFinding['severity'], label: 'LFI',
              text: `param: ${f.parameter} — ${(f as { technique?: string }).technique ?? ''} — ${f.evidence?.slice(0, 60) ?? ''}`,
              url: f.original_url ?? f.url,
              param: f.parameter,
            }]
            updated.log.push(
              `  [LFI] ${f.original_url ?? f.url} — param: ${f.parameter} — ${(f as { payload?: string }).payload ?? ''}`
            )
          } else if (event.event === 'completed') {
            updated.phase = 'completed'
            updated.log.push(`[LFI] Done — ${event.findings ?? 0} potential finding(s)`)
            updated.log.push(`[✓] Pipeline completed`)
          } else if (event.event === 'failed') {
            updated.phase = 'failed'
            updated.log.push(`[LFI] ERROR: ${event.error}`)
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
            const sev = (f.severity ?? 'info') as PipelineFinding['severity']
            updated.findings = [...updated.findings, {
              severity: sev, label: f.label ?? 'secret',
              text: `${f.match?.slice(0, 80) ?? ''}`,
              url: f.js_url,
              match: f.match, context: f.context, line: f.line,
            }]
            updated.log.push(
              `  [${f.severity?.toUpperCase()}] ${f.label} in ${f.js_url} :${f.line} — ${f.match?.slice(0, 60)}`
            )
          } else if (event.event === 'skipped') {
            updated.log.push(`[→] ${event.message ?? 'JS scan stopped'}`)
          } else if (event.event === 'completed') {
            updated.phase = 'completed'
            updated.log.push(`[JS] Done — ${event.findings ?? 0} finding(s) in ${event.js_files ?? 0} files`)
            updated.log.push(`[✓] Pipeline completed`)
          } else if (event.event === 'failed') {
            updated.phase = 'failed'
            updated.log.push(`[JS] ERROR: ${event.error}`)
          }
        }

        // ── Cloud bucket check (buckets referenced in scanned JS) ──
        if (event.phase === 'bucket_check') {
          updated.phase = 'bucket_check'
          if (event.event === 'started') {
            updated.log.push(`[Buckets] Testing ${event.targets ?? 0} bucket(s) referenced in JS...`)
          } else if (event.event === 'finding' && event.finding) {
            updated.findingsCount += 1
            const f = event.finding
            const bsev = (f.severity ?? 'high') as PipelineFinding['severity']
            updated.findings = [...updated.findings, {
              severity: bsev, label: 'Cloud bucket',
              text: f.title ?? '', url: f.url,
            }]
            updated.log.push(`  [${f.severity?.toUpperCase()}] [Cloud] ${f.title} — ${f.url}`)
          } else if (event.event === 'skipped') {
            updated.log.push(`[→] ${event.message ?? 'Bucket check stopped'}`)
          } else if (event.event === 'completed') {
            updated.log.push(`[Buckets] ${event.message ?? 'done'}`)
          }
        }

        return updated
      }),
    })
  },

  clearRuns: () => set({ runs: [], activeRunId: null }),
}))
