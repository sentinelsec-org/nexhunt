import { useState, useEffect, useRef, useCallback } from 'react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { useWorkspaceStore, type WorkspaceItem } from '@/stores/workspace-store'
import { api } from '@/api/http-client'
import { cn } from '@/lib/utils'
import type { HttpFlow } from '@/types'
import {
  Bug, Globe, Trash2, Sparkles, Loader2, Copy, Check,
  FileText, Send, ChevronRight, AlertTriangle, Shield,
  Crosshair, RotateCcw, BookOpen, Lightbulb, Code, Plus, StickyNote,
} from 'lucide-react'

// ─── Bug-hunter AI prompt builder ────────────────────────────────────────────

function buildFindingPrompt(item: WorkspaceItem): string {
  const f = item.finding!
  return `You are an expert bug bounty hunter. Analyze this vulnerability finding and provide actionable guidance.

## Finding
- **Title**: ${f.title}
- **Severity**: ${f.severity.toUpperCase()}
- **Type**: ${f.vuln_type ?? 'unknown'}
- **URL**: ${f.url ?? 'N/A'}
- **Parameter**: ${f.parameter ?? 'N/A'}
- **Tool**: ${f.tool ?? 'manual'}
- **Status**: ${f.status}
- **Description**: ${f.description ?? 'none'}
- **Evidence**: ${f.evidence ?? 'none'}

Provide your analysis in this structure:

### Severity Calibration
Is the reported severity accurate? Should it be higher or lower based on the evidence? Justify.

### Exploitation Path
How would you actually exploit this? Step-by-step if applicable. Include any payloads or techniques.

### Impact Analysis
What's the real-world business impact? What can an attacker do? What data is at risk?

### Chaining Opportunities
Can this be combined with other vulnerability classes to escalate impact? What to look for.

### Next Tests
What 3–5 specific follow-up tests should the hunter do right now to confirm, escalate, or expand?

### Report Notes
Key technical details to include in a bug bounty report for this finding. What makes it a quality report.

Be precise, use specific payloads and techniques. Think like you're hunting on a real program.`
}

function buildRequestPrompt(item: WorkspaceItem): string {
  const f = item.httpFlow!

  const requestHeaders = Object.entries(f.request_headers ?? {})
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n')

  const responseHeaders = Object.entries(f.response_headers ?? {})
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n')

  const body = f.request_body ? `\n\n${f.request_body.slice(0, 2000)}` : ''
  const respBody = f.response_body ? f.response_body.slice(0, 1000) : '(empty)'

  return `You are an expert bug bounty hunter reviewing an intercepted HTTP request. Analyze it deeply.

## HTTP Request
\`\`\`http
${f.request_method} ${f.request_path} HTTP/1.1
Host: ${f.request_host}
${requestHeaders}${body}
\`\`\`

## HTTP Response
\`\`\`
HTTP/1.1 ${f.response_status}
${responseHeaders}

${respBody}
\`\`\`

Provide analysis in this structure:

### Attack Surface Assessment
What's interesting about this request? Which parameters, headers, cookies, or endpoints stand out as potentially vulnerable?

### Vulnerability Hypotheses
For each interesting parameter or behavior, what vulnerability class could be present? Be specific:
- Parameter X → looks like SQLi because...
- Header Y → SSRF candidate because...
- Endpoint Z → IDOR pattern because...

### Modified Requests to Try
Show me specific modified versions of this request to test each hypothesis. Use \`\`\`http blocks:
\`\`\`http
[modified request]
\`\`\`
Explain what each modification tests and what response to look for.

### Payloads by Category
If there are injectable parameters, list specific payloads for:
- SQLi (error-based, blind, time-based as applicable)
- XSS (context-appropriate)
- Path traversal / LFI
- SSRF / open redirect
- Any other relevant class

### Response Indicators
What specific things in the response would confirm a vulnerability? Error messages, status code changes, timing differences, content differences.

### Automated Follow-up
Which tools from the toolkit (SQLMap, Dalfox, Commix, Nuclei) should be run against this endpoint and with what options?

Be specific, actionable, and treat this like a real bug hunt. If nothing looks interesting, say so and explain why.`
}

// ─── Markdown renderer ────────────────────────────────────────────────────────

function inlineFormat(text: string): React.ReactNode {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*)/g)
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**'))
      return <strong key={i} className="text-zinc-100 font-semibold">{part.slice(2, -2)}</strong>
    if (part.startsWith('*') && part.endsWith('*'))
      return <em key={i} className="text-zinc-300 italic">{part.slice(1, -1)}</em>
    if (part.startsWith('`') && part.endsWith('`'))
      return <code key={i} className="text-green-300 bg-zinc-800 px-1 rounded text-[10px] font-mono">{part.slice(1, -1)}</code>
    return part
  })
}

function Markdown({ text }: { text: string }) {
  const lines = text.split('\n')
  const elements: React.ReactNode[] = []
  let i = 0

  while (i < lines.length) {
    const line = lines[i]
    if (line.startsWith('```')) {
      const lang = line.slice(3).trim()
      const codeLines: string[] = []
      i++
      while (i < lines.length && !lines[i].startsWith('```')) { codeLines.push(lines[i]); i++ }
      elements.push(
        <div key={i} className="my-2 rounded-lg overflow-hidden border border-zinc-700">
          {lang && <div className="px-3 py-1 text-[10px] text-zinc-500 bg-zinc-800 border-b border-zinc-700 font-mono">{lang}</div>}
          <pre className="bg-zinc-950 p-3 overflow-x-auto text-[11px] font-mono text-green-300 leading-relaxed whitespace-pre-wrap break-all">
            <code>{codeLines.join('\n')}</code>
          </pre>
        </div>
      )
    } else if (line.startsWith('### ')) {
      elements.push(<h3 key={i} className="text-xs font-bold text-zinc-200 mt-4 mb-1 flex items-center gap-1.5"><ChevronRight size={10} className="text-green-500" />{inlineFormat(line.slice(4))}</h3>)
    } else if (line.startsWith('## ')) {
      elements.push(<h2 key={i} className="text-sm font-bold text-zinc-100 mt-4 mb-2 border-b border-zinc-800 pb-1">{inlineFormat(line.slice(3))}</h2>)
    } else if (line.startsWith('# ')) {
      elements.push(<h1 key={i} className="text-base font-bold text-white mt-4 mb-2">{inlineFormat(line.slice(2))}</h1>)
    } else if (line.match(/^[-*+] /)) {
      elements.push(
        <div key={i} className="flex gap-2 text-xs text-zinc-300 leading-relaxed my-0.5">
          <span className="text-zinc-600 shrink-0 mt-0.5">•</span>
          <span>{inlineFormat(line.slice(2))}</span>
        </div>
      )
    } else if (line.match(/^\d+\. /)) {
      const m = line.match(/^(\d+)\. (.*)/)
      if (m) elements.push(
        <div key={i} className="flex gap-2 text-xs text-zinc-300 leading-relaxed my-0.5">
          <span className="text-zinc-500 shrink-0 font-mono text-[10px] mt-0.5 w-4 text-right">{m[1]}.</span>
          <span>{inlineFormat(m[2])}</span>
        </div>
      )
    } else if (line.startsWith('> ')) {
      elements.push(
        <blockquote key={i} className="border-l-2 border-zinc-600 pl-3 my-1 text-zinc-400 italic text-xs">
          {inlineFormat(line.slice(2))}
        </blockquote>
      )
    } else if (line.match(/^[-*]{3,}$/)) {
      elements.push(<hr key={i} className="border-zinc-800 my-2" />)
    } else if (line.trim()) {
      elements.push(<p key={i} className="text-xs text-zinc-300 leading-relaxed">{inlineFormat(line)}</p>)
    } else {
      elements.push(<div key={i} className="h-1.5" />)
    }
    i++
  }
  return <div className="space-y-0.5">{elements}</div>
}

// ─── Severity badge ───────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-950/60 text-red-400 border-red-800',
    high: 'bg-orange-950/60 text-orange-400 border-orange-800',
    medium: 'bg-yellow-950/60 text-yellow-400 border-yellow-800',
    low: 'bg-blue-950/60 text-blue-400 border-blue-800',
    info: 'bg-zinc-800 text-zinc-400 border-zinc-700',
  }
  return (
    <span className={cn('text-[10px] px-1.5 py-0.5 rounded border font-medium capitalize', colors[severity] ?? colors.info)}>
      {severity}
    </span>
  )
}

// ─── Item list entry ──────────────────────────────────────────────────────────

function ItemEntry({ item, selected, onSelect, onRemove, onAnalyze }: {
  item: WorkspaceItem
  selected: boolean
  onSelect: () => void
  onRemove: () => void
  onAnalyze: () => void
}) {
  return (
    <div
      onClick={onSelect}
      className={cn(
        'group rounded-lg border px-3 py-2.5 cursor-pointer transition-colors space-y-1',
        selected
          ? 'border-green-700 bg-green-950/20'
          : 'border-zinc-800 bg-zinc-900/50 hover:border-zinc-700 hover:bg-zinc-900'
      )}
    >
      <div className="flex items-start gap-2">
        <div className="shrink-0 mt-0.5">
          {item.type === 'finding'
            ? <Bug size={12} className={selected ? 'text-green-400' : 'text-zinc-500'} />
            : item.type === 'note'
              ? <StickyNote size={12} className={selected ? 'text-yellow-400' : 'text-zinc-500'} />
              : <Globe size={12} className={selected ? 'text-green-400' : 'text-zinc-500'} />}
        </div>
        <div className="flex-1 min-w-0">
          <div className={cn('text-xs font-medium truncate leading-tight', selected ? 'text-zinc-100' : 'text-zinc-300')}>
            {item.title}
          </div>
          <div className="flex items-center gap-1.5 mt-1">
            {item.type === 'finding' && item.finding && (
              <SeverityBadge severity={item.finding.severity} />
            )}
            {item.type === 'http_flow' && item.httpFlow && (
              <span className={cn('text-[10px] font-mono font-bold',
                item.httpFlow.request_method === 'POST' ? 'text-orange-400' :
                item.httpFlow.request_method === 'PUT' ? 'text-yellow-400' :
                'text-blue-400'
              )}>
                {item.httpFlow.request_method}
              </span>
            )}
            {item.aiAnalysis && (
              <span className="text-[9px] text-purple-400 flex items-center gap-0.5">
                <Sparkles size={8} /> AI
              </span>
            )}
            {item.aiAnalyzing && (
              <span className="text-[9px] text-purple-400 flex items-center gap-0.5 animate-pulse">
                <Loader2 size={8} className="animate-spin" /> analyzing…
              </span>
            )}
            {item.notes && (
              <span className="text-[9px] text-zinc-600 flex items-center gap-0.5">
                <FileText size={8} /> notes
              </span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-all shrink-0">
          {item.type !== 'note' && (
            <button
              onClick={e => { e.stopPropagation(); onAnalyze() }}
              className="text-zinc-700 hover:text-purple-400 transition-colors"
              title="Analyze with AI"
            >
              <Sparkles size={11} />
            </button>
          )}
          <button
            onClick={e => { e.stopPropagation(); onRemove() }}
            className="text-zinc-700 hover:text-red-400 transition-colors"
          >
            <Trash2 size={11} />
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Detail panel — Finding ───────────────────────────────────────────────────

function FindingDetail({ item }: { item: WorkspaceItem }) {
  const f = item.finding!
  return (
    <div className="space-y-3">
      <div className="flex items-start gap-2">
        <Bug size={16} className="text-red-400 shrink-0 mt-0.5" />
        <div>
          <h2 className="text-sm font-semibold text-zinc-100">{f.title}</h2>
          <div className="flex items-center gap-2 mt-1">
            <SeverityBadge severity={f.severity} />
            <span className="text-[10px] text-zinc-600">{f.tool ?? 'manual'}</span>
            <span className="text-[10px] text-zinc-700">|</span>
            <span className="text-[10px] text-zinc-600 capitalize">{f.status}</span>
          </div>
        </div>
      </div>

      {f.url && (
        <div>
          <div className="text-[10px] text-zinc-600 mb-0.5 uppercase tracking-wider">URL</div>
          <div className="text-xs text-blue-400 font-mono break-all bg-zinc-900 rounded px-2 py-1.5 border border-zinc-800">{f.url}</div>
        </div>
      )}

      {f.parameter && (
        <div>
          <div className="text-[10px] text-zinc-600 mb-0.5 uppercase tracking-wider">Parameter</div>
          <div className="text-xs text-yellow-400 font-mono bg-zinc-900 rounded px-2 py-1.5 border border-zinc-800">{f.parameter}</div>
        </div>
      )}

      {f.description && (
        <div>
          <div className="text-[10px] text-zinc-600 mb-0.5 uppercase tracking-wider">Description</div>
          <div className="text-xs text-zinc-400 leading-relaxed">{f.description}</div>
        </div>
      )}

      {f.evidence && (
        <div>
          <div className="text-[10px] text-zinc-600 mb-0.5 uppercase tracking-wider">Evidence</div>
          <pre className="text-[10px] text-zinc-400 font-mono bg-zinc-950 rounded border border-zinc-800 p-2 overflow-auto whitespace-pre-wrap break-all leading-relaxed max-h-40">
            {f.evidence}
          </pre>
        </div>
      )}

      {f.template_id && (
        <div>
          <div className="text-[10px] text-zinc-600 mb-0.5 uppercase tracking-wider">Template</div>
          <div className="text-[10px] text-zinc-500 font-mono">{f.template_id}</div>
        </div>
      )}
    </div>
  )
}

// ─── Detail panel — HTTP Flow ─────────────────────────────────────────────────

function FlowDetail({ flow }: { flow: HttpFlow }) {
  const reqHeaders = Object.entries(flow.request_headers ?? {})
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n')

  const respHeaders = Object.entries(flow.response_headers ?? {})
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n')

  const statusColor = flow.response_status < 300 ? 'text-green-400'
    : flow.response_status < 400 ? 'text-yellow-400'
    : flow.response_status < 500 ? 'text-orange-400'
    : 'text-red-400'

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Globe size={16} className="text-blue-400 shrink-0" />
        <div>
          <h2 className="text-sm font-semibold text-zinc-100 font-mono break-all">
            <span className={cn('mr-2', flow.request_method === 'POST' ? 'text-orange-400' : 'text-blue-400')}>
              {flow.request_method}
            </span>
            {flow.request_host}{flow.request_path}
          </h2>
          <div className="flex items-center gap-2 mt-1">
            <span className={cn('text-xs font-mono font-semibold', statusColor)}>{flow.response_status}</span>
            <span className="text-[10px] text-zinc-600">{(flow.response_length / 1024).toFixed(1)} KB</span>
            <span className="text-[10px] text-zinc-600">{flow.duration_ms}ms</span>
          </div>
        </div>
      </div>

      <div>
        <div className="text-[10px] text-zinc-600 mb-0.5 uppercase tracking-wider">Request</div>
        <pre className="text-[10px] text-zinc-300 font-mono bg-zinc-950 rounded border border-zinc-800 p-2 overflow-auto whitespace-pre-wrap break-all leading-relaxed max-h-48">
          {`${flow.request_method} ${flow.request_path} HTTP/1.1\nHost: ${flow.request_host}\n${reqHeaders}${flow.request_body ? '\n\n' + flow.request_body.slice(0, 1500) : ''}`}
        </pre>
      </div>

      {flow.response_body && (
        <div>
          <div className="text-[10px] text-zinc-600 mb-0.5 uppercase tracking-wider">Response</div>
          <pre className="text-[10px] text-zinc-400 font-mono bg-zinc-950 rounded border border-zinc-800 p-2 overflow-auto whitespace-pre-wrap break-all leading-relaxed max-h-32">
            {`HTTP/1.1 ${flow.response_status}\n${respHeaders}\n\n${flow.response_body.slice(0, 800)}`}
          </pre>
        </div>
      )}
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function WorkspacePage() {
  const {
    items, selectedItemId,
    addFinding, addNote, removeItem, selectItem, updateNotes, updateTitle,
    setAiAnalysis, setAiAnalyzing, clearAll,
  } = useWorkspaceStore()

  const selectedItem = items.find(i => i.id === selectedItemId) ?? null

  const [activeTab, setActiveTab] = useState<'detail' | 'notes' | 'ai'>('detail')
  const [copiedAi, setCopiedAi] = useState(false)
  const aiPanelRef = useRef<HTMLDivElement>(null)

  // Scroll AI panel to bottom when analysis updates
  useEffect(() => {
    if (aiPanelRef.current && activeTab === 'ai') {
      aiPanelRef.current.scrollTop = aiPanelRef.current.scrollHeight
    }
  }, [selectedItem?.aiAnalysis, activeTab])

  // Switch to detail tab when item changes
  useEffect(() => {
    setActiveTab('detail')
  }, [selectedItemId])

  const runAiAnalysisForItem = useCallback(async (item: WorkspaceItem) => {
    if (item.type === 'note') return
    setAiAnalyzing(item.id, true)
    setAiAnalysis(item.id, null)
    setActiveTab('ai')
    try {
      const prompt = item.type === 'finding'
        ? buildFindingPrompt(item)
        : buildRequestPrompt(item)
      const res = await api.post<{ response: string }>('/api/copilot/chat', {
        message: prompt,
        context: { mode: 'bug_hunter_analysis' },
      })
      setAiAnalysis(item.id, res.response)
    } catch (err) {
      setAiAnalysis(item.id, `Error calling AI: ${err}\n\nMake sure an AI provider is configured in Settings.`)
    } finally {
      setAiAnalyzing(item.id, false)
    }
  }, [setAiAnalysis, setAiAnalyzing])

  const runAiAnalysis = useCallback(async () => {
    if (!selectedItem) return
    runAiAnalysisForItem(selectedItem)
  }, [selectedItem, runAiAnalysisForItem])

  const copyAiAnalysis = () => {
    if (selectedItem?.aiAnalysis) {
      navigator.clipboard.writeText(selectedItem.aiAnalysis)
      setCopiedAi(true)
      setTimeout(() => setCopiedAi(false), 1500)
    }
  }

  return (
    <WorkspaceShell
      title="Workspace"
      subtitle="Collected evidence — notes — AI bug hunter analysis"
    >
      <div className="flex h-full min-h-0 gap-0">

        {/* ── LEFT: Item list ── */}
        <div className="w-56 shrink-0 flex flex-col border-r border-zinc-800 min-h-0">
          <div className="flex items-center justify-between px-3 py-2 border-b border-zinc-800">
            <div className="text-[10px] text-zinc-600 uppercase tracking-wider font-semibold">
              Evidence ({items.length})
            </div>
            <div className="flex items-center gap-1">
              <button
                onClick={() => addNote()}
                className="text-zinc-600 hover:text-green-400 transition-colors"
                title="New note"
              >
                <Plus size={12} />
              </button>
              {items.length > 0 && (
                <button
                  onClick={clearAll}
                  className="text-zinc-700 hover:text-red-400 transition-colors"
                  title="Clear all"
                >
                  <Trash2 size={11} />
                </button>
              )}
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-2 space-y-1.5">
            {items.length === 0 ? (
              <div className="text-center py-12 space-y-3">
                <div className="text-zinc-700">
                  <BookOpen size={28} className="mx-auto mb-2" />
                </div>
                <div className="text-[11px] text-zinc-600 leading-relaxed px-2">
                  Right-click any finding or request to send it here, or add a note manually.
                </div>
              </div>
            ) : (
              items.map(item => (
                <ItemEntry
                  key={item.id}
                  item={item}
                  selected={item.id === selectedItemId}
                  onSelect={() => selectItem(item.id)}
                  onRemove={() => removeItem(item.id)}
                  onAnalyze={() => {
                    selectItem(item.id)
                    runAiAnalysisForItem(item)
                  }}
                />
              ))
            )}
          </div>
        </div>

        {/* ── CENTER + RIGHT: Detail / Notes / AI ── */}
        {selectedItem ? (
          <div className="flex flex-1 min-h-0 min-w-0">

            {/* Center: Detail + Notes */}
            <div className="flex-1 flex flex-col min-h-0 min-w-0 border-r border-zinc-800">

              {/* Tab bar */}
              <div className="flex items-center gap-1 border-b border-zinc-800 px-3 py-1.5 shrink-0">
                <TabBtn active={activeTab === 'detail'} onClick={() => setActiveTab('detail')} icon={<Shield size={11} />} label="Details" />
                <TabBtn active={activeTab === 'notes'} onClick={() => setActiveTab('notes')} icon={<FileText size={11} />} label="Notes" />
                <TabBtn active={activeTab === 'ai'} onClick={() => setActiveTab('ai')} icon={<Sparkles size={11} />} label="AI Analysis"
                  badge={selectedItem.aiAnalyzing ? 'loading' : selectedItem.aiAnalysis ? 'done' : undefined}
                />

                {/* Analyze button — hidden for plain notes */}
                {selectedItem.type !== 'note' && (
                  <button
                    onClick={runAiAnalysis}
                    disabled={selectedItem.aiAnalyzing}
                    className={cn(
                      'ml-auto flex items-center gap-1.5 px-3 py-1 rounded text-[10px] font-medium transition-colors border',
                      selectedItem.aiAnalyzing
                        ? 'border-zinc-700 text-zinc-500 cursor-not-allowed'
                        : 'border-purple-700 bg-purple-950/30 text-purple-300 hover:bg-purple-950/50 hover:border-purple-600'
                    )}
                  >
                    {selectedItem.aiAnalyzing
                      ? <><Loader2 size={10} className="animate-spin" /> Analyzing...</>
                      : <><Sparkles size={10} /> {selectedItem.aiAnalysis ? 'Re-analyze' : 'Analyze with AI'}</>
                    }
                  </button>
                )}
              </div>

              {/* Detail view */}
              {activeTab === 'detail' && (
                <div className="flex-1 overflow-y-auto p-4">
                  {selectedItem.type === 'finding' && selectedItem.finding && (
                    <FindingDetail item={selectedItem} />
                  )}
                  {selectedItem.type === 'http_flow' && selectedItem.httpFlow && (
                    <FlowDetail flow={selectedItem.httpFlow} />
                  )}
                  {selectedItem.type === 'note' && (
                    <div className="space-y-4">
                      <div className="space-y-1">
                        <div className="text-[10px] text-zinc-600 uppercase tracking-wider">Note title</div>
                        <input
                          className="w-full bg-zinc-900 border border-zinc-700 rounded px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-zinc-500"
                          value={selectedItem.title}
                          onChange={e => updateTitle(selectedItem.id, e.target.value)}
                          placeholder="Note title..."
                        />
                      </div>
                      <div className="text-xs text-zinc-500 flex items-center gap-2">
                        <StickyNote size={12} className="text-yellow-400" />
                        Switch to the <span className="text-zinc-300 font-medium">Notes</span> tab to write your content.
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Notes editor */}
              {activeTab === 'notes' && (
                <div className="flex-1 flex flex-col min-h-0 p-3 gap-2">
                  <div className="text-[10px] text-zinc-600">
                    Markdown supported · notes are saved automatically
                  </div>
                  <textarea
                    className="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg p-3 text-xs text-zinc-300 font-mono resize-none focus:outline-none focus:border-zinc-600 leading-relaxed placeholder:text-zinc-700"
                    placeholder={`# Notes for: ${selectedItem.title}\n\n## Summary\n\n## Steps to Reproduce\n\n## Impact\n\n## References\n`}
                    value={selectedItem.notes}
                    onChange={e => updateNotes(selectedItem.id, e.target.value)}
                    spellCheck={false}
                  />
                </div>
              )}

              {/* AI Analysis */}
              {activeTab === 'ai' && (
                <div ref={aiPanelRef} className="flex-1 overflow-y-auto p-4">
                  {selectedItem.aiAnalyzing && (
                    <div className="flex items-center gap-2 text-sm text-purple-400 mb-4">
                      <Loader2 size={14} className="animate-spin" />
                      Analyzing as bug hunter...
                    </div>
                  )}

                  {selectedItem.aiAnalysis ? (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center gap-1.5 text-[10px] text-zinc-600">
                          <Sparkles size={10} className="text-purple-400" />
                          AI Bug Hunter Analysis
                        </div>
                        <button
                          onClick={copyAiAnalysis}
                          className="text-zinc-600 hover:text-zinc-400 transition-colors"
                          title="Copy analysis"
                        >
                          {copiedAi ? <Check size={12} /> : <Copy size={12} />}
                        </button>
                      </div>
                      <Markdown text={selectedItem.aiAnalysis} />
                    </div>
                  ) : !selectedItem.aiAnalyzing && (
                    <div className="text-center py-16 space-y-3 text-zinc-700">
                      <Lightbulb size={28} className="mx-auto" />
                      <div className="text-sm">Click "Analyze with AI" above</div>
                      <div className="text-xs text-zinc-600 max-w-xs mx-auto leading-relaxed">
                        The AI will act as a bug hunter and suggest what vulnerabilities to test, how to modify the request, and what payloads to try.
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Right: Quick AI chat for follow-up questions */}
            <WorkspaceChatPanel item={selectedItem} />
          </div>
        ) : (
          /* Empty state */
          <div className="flex-1 flex items-center justify-center text-center">
            <div className="space-y-3 max-w-sm">
              <div className="text-zinc-700">
                <Crosshair size={36} className="mx-auto mb-3" />
              </div>
              <h3 className="text-sm font-semibold text-zinc-500">Select an item to analyze</h3>
              <div className="text-xs text-zinc-700 leading-relaxed">
                Right-click any finding in <strong className="text-zinc-600">Scanner</strong> or any request in <strong className="text-zinc-600">Proxy → History</strong> and choose <em className="text-zinc-500">Send to Workspace</em>.
              </div>
              <div className="text-[10px] text-zinc-700 pt-2">
                The AI will analyze the item from a bug hunter's perspective — suggesting what vulnerabilities to test, how to modify requests, and what payloads to try.
              </div>
            </div>
          </div>
        )}
      </div>
    </WorkspaceShell>
  )
}

// ─── Follow-up chat panel ─────────────────────────────────────────────────────

function WorkspaceChatPanel({ item }: { item: WorkspaceItem }) {
  const [messages, setMessages] = useState<Array<{ role: 'user' | 'ai'; text: string }>>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  // Reset chat when item changes
  useEffect(() => {
    setMessages([])
    setInput('')
  }, [item.id])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const send = async () => {
    const text = input.trim()
    if (!text || loading) return
    setInput('')
    setMessages(prev => [...prev, { role: 'user', text }])
    setLoading(true)
    try {
      const contextSummary = item.type === 'finding'
        ? `Currently analyzing finding: "${item.title}" (${item.finding?.severity} severity, tool: ${item.finding?.tool}, URL: ${item.finding?.url})`
        : `Currently analyzing HTTP request: ${item.httpFlow?.request_method} ${item.httpFlow?.request_host}${item.httpFlow?.request_path} → ${item.httpFlow?.response_status}`

      const aiContext = item.aiAnalysis
        ? `\n\nPrevious AI analysis summary:\n${item.aiAnalysis.slice(0, 800)}`
        : ''

      const fullMessage = `${contextSummary}${aiContext}\n\nFollow-up question from bug hunter: ${text}`

      const res = await api.post<{ response: string }>('/api/copilot/chat', {
        message: fullMessage,
        context: { mode: 'bug_hunter_followup' },
      })
      setMessages(prev => [...prev, { role: 'ai', text: res.response }])
    } catch (err) {
      setMessages(prev => [...prev, { role: 'ai', text: `Error: ${err}` }])
    } finally {
      setLoading(false)
      inputRef.current?.focus()
    }
  }

  return (
    <div className="w-72 shrink-0 flex flex-col border-l border-zinc-800 min-h-0">
      <div className="px-3 py-2 border-b border-zinc-800 shrink-0">
        <div className="text-[10px] text-zinc-600 uppercase tracking-wider font-semibold flex items-center gap-1.5">
          <Send size={10} /> Follow-up chat
        </div>
        <div className="text-[9px] text-zinc-700 mt-0.5">Ask the AI follow-up questions about this item</div>
      </div>

      <div className="flex-1 overflow-y-auto p-3 space-y-3 min-h-0">
        {messages.length === 0 && (
          <div className="text-center py-8 space-y-2 text-zinc-700">
            <Code size={20} className="mx-auto" />
            <div className="text-[10px] leading-relaxed">
              Ask anything about this {item.type === 'finding' ? 'finding' : 'request'}:
              <div className="mt-2 space-y-1 text-left">
                {item.type === 'http_flow' ? (
                  <>
                    <div className="text-[9px] text-zinc-700">"How do I test for IDOR here?"</div>
                    <div className="text-[9px] text-zinc-700">"Write a curl command to test SQLi"</div>
                    <div className="text-[9px] text-zinc-700">"Is the JWT algorithm safe?"</div>
                  </>
                ) : (
                  <>
                    <div className="text-[9px] text-zinc-700">"How do I escalate this?"</div>
                    <div className="text-[9px] text-zinc-700">"Write the report description"</div>
                    <div className="text-[9px] text-zinc-700">"What's the CVSS score?"</div>
                  </>
                )}
              </div>
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} className={cn('text-xs', msg.role === 'user' ? 'text-right' : 'text-left')}>
            {msg.role === 'user' ? (
              <div className="inline-block bg-zinc-800 rounded-lg px-3 py-2 text-zinc-200 max-w-[90%] text-left">
                {msg.text}
              </div>
            ) : (
              <div className="text-zinc-400 leading-relaxed">
                <Markdown text={msg.text} />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex items-center gap-1.5 text-xs text-zinc-600">
            <Loader2 size={11} className="animate-spin" /> Thinking...
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="p-2 border-t border-zinc-800 shrink-0">
        <div className="flex gap-1.5">
          <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }}
            placeholder="Ask the AI..."
            className="flex-1 text-xs bg-zinc-900 border border-zinc-800 rounded-lg px-2.5 py-1.5 text-zinc-300 placeholder:text-zinc-700 focus:outline-none focus:border-zinc-600"
          />
          <button
            onClick={send}
            disabled={!input.trim() || loading}
            className="p-1.5 rounded-lg bg-purple-800 hover:bg-purple-700 text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <Send size={12} />
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Shared small components ──────────────────────────────────────────────────

function TabBtn({ active, onClick, icon, label, badge }: {
  active: boolean; onClick: () => void; icon: React.ReactNode
  label: string; badge?: 'loading' | 'done'
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-medium rounded-md transition-colors',
        active ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-500 hover:text-zinc-300'
      )}
    >
      {icon} {label}
      {badge === 'loading' && <Loader2 size={8} className="animate-spin text-purple-400" />}
      {badge === 'done' && <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />}
    </button>
  )
}
