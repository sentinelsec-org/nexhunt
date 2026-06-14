import { useState, useRef, useEffect, useCallback } from 'react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { api } from '@/api/http-client'
import { cn } from '@/lib/utils'
import { useScannerStore } from '@/stores/scanner-store'
import { useReconStore } from '@/stores/recon-store'
import { useAppStore } from '@/stores/app-store'
import { useCopilotStore, type CopilotMessage } from '@/stores/copilot-store'
import { WS_BASE } from '@/lib/constants'
import {
  Bot, Send, User, Loader2, Sparkles, FileText,
  Target, Lightbulb, ChevronRight, AlertTriangle,
  Shield, Globe, Network, RefreshCw, Copy, Check,
  Play, Terminal, Zap, Cpu,
} from 'lucide-react'

type RunToolFn = (tool: string, target: string, options: Record<string, string>) => void

// ── Simple markdown renderer with run button ──────────────────────────────────
function Markdown({ text, onRunCommand, onRunTool }: {
  text: string
  onRunCommand?: (cmd: string) => void
  onRunTool?: RunToolFn
}) {
  const lines = text.split('\n')
  const elements: React.ReactNode[] = []
  let i = 0

  while (i < lines.length) {
    const line = lines[i]

    if (line.startsWith('```')) {
      const lang = line.slice(3).trim().toLowerCase()
      const codeLines: string[] = []
      i++
      while (i < lines.length && !lines[i].startsWith('```')) {
        codeLines.push(lines[i])
        i++
      }
      const code = codeLines.join('\n')

      // nexhunt-tool block — render as a tool card with Execute button
      if (lang === 'nexhunt-tool' && onRunTool) {
        const parsed: Record<string, string> = {}
        for (const cl of codeLines) {
          const m = cl.match(/^([\w-]+):\s*(.+)$/)
          if (m) parsed[m[1]] = m[2].trim()
        }
        const { tool, target, ...options } = parsed
        if (tool) {
          elements.push(
            <div key={i} className="my-2 rounded-lg border border-green-800/50 bg-green-950/15 overflow-hidden">
              <div className="flex items-center justify-between px-3 py-1.5 bg-green-950/30 border-b border-green-800/40">
                <div className="flex items-center gap-2">
                  <Cpu size={11} className="text-green-400" />
                  <span className="text-[11px] font-semibold text-green-400 font-mono">{tool}</span>
                  {target && <span className="text-[10px] text-zinc-500 font-mono">{target}</span>}
                  {Object.entries(options).map(([k, v]) => (
                    <span key={k} className="text-[10px] text-zinc-600 font-mono">{k}={v}</span>
                  ))}
                </div>
                <button
                  onClick={() => onRunTool(tool, target || '', options)}
                  className="flex items-center gap-1 text-[10px] text-green-300 hover:text-green-200 font-semibold transition-colors bg-green-900/40 hover:bg-green-900/70 px-2 py-0.5 rounded"
                >
                  <Play size={9} /> Execute
                </button>
              </div>
            </div>
          )
          i++
          continue
        }
      }

      const isRunnable = onRunCommand && (lang === 'bash' || lang === 'sh' || lang === 'shell' || lang === '')
      elements.push(
        <div key={i} className="my-2 rounded-lg overflow-hidden border border-zinc-700">
          <div className="flex items-center justify-between px-3 py-1 bg-zinc-800 border-b border-zinc-700">
            <span className="text-[10px] text-zinc-500 font-mono">{lang || 'code'}</span>
            {isRunnable && (
              <button
                onClick={() => onRunCommand(code.trim())}
                className="flex items-center gap-1 text-[10px] text-green-400 hover:text-green-300 font-semibold transition-colors"
              >
                <Play size={10} /> Run
              </button>
            )}
          </div>
          <pre className="bg-zinc-950 p-3 overflow-x-auto text-[11px] font-mono text-green-300 leading-relaxed">
            <code>{code}</code>
          </pre>
        </div>
      )
      i++
      continue
    }

    if (line.startsWith('### ')) {
      elements.push(<h3 key={i} className="text-sm font-bold text-zinc-200 mt-4 mb-1">{inlineFormat(line.slice(4))}</h3>)
    } else if (line.startsWith('## ')) {
      elements.push(<h2 key={i} className="text-base font-bold text-zinc-100 mt-5 mb-2 border-b border-zinc-700 pb-1">{inlineFormat(line.slice(3))}</h2>)
    } else if (line.startsWith('# ')) {
      elements.push(<h1 key={i} className="text-lg font-bold text-white mt-5 mb-2">{inlineFormat(line.slice(2))}</h1>)
    } else if (line.match(/^[-*]{3,}$/)) {
      elements.push(<hr key={i} className="border-zinc-700 my-3" />)
    } else if (line.startsWith('> ')) {
      elements.push(
        <blockquote key={i} className="border-l-2 border-zinc-600 pl-3 my-1 text-zinc-400 italic text-sm">
          {inlineFormat(line.slice(2))}
        </blockquote>
      )
    } else if (line.match(/^[-*+] /)) {
      elements.push(
        <div key={i} className="flex gap-2 text-sm text-zinc-300 leading-relaxed">
          <span className="text-zinc-600 shrink-0 mt-0.5">•</span>
          <span>{inlineFormat(line.slice(2))}</span>
        </div>
      )
    } else if (line.match(/^\d+\. /)) {
      const match = line.match(/^(\d+)\. (.*)/)
      if (match) {
        elements.push(
          <div key={i} className="flex gap-2 text-sm text-zinc-300 leading-relaxed">
            <span className="text-zinc-500 shrink-0 font-mono text-xs mt-0.5 w-5 text-right">{match[1]}.</span>
            <span>{inlineFormat(match[2])}</span>
          </div>
        )
      }
    } else if (line.trim() === '') {
      elements.push(<div key={i} className="h-2" />)
    } else {
      elements.push(<p key={i} className="text-sm text-zinc-300 leading-relaxed">{inlineFormat(line)}</p>)
    }

    i++
  }

  return <div className="space-y-0.5">{elements}</div>
}

function inlineFormat(text: string): React.ReactNode {
  const parts: React.ReactNode[] = []
  const regex = /(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g
  let last = 0
  let match: RegExpExecArray | null

  while ((match = regex.exec(text)) !== null) {
    if (match.index > last) parts.push(text.slice(last, match.index))
    const raw = match[0]
    if (raw.startsWith('**')) {
      parts.push(<strong key={match.index} className="font-bold text-zinc-100">{raw.slice(2, -2)}</strong>)
    } else if (raw.startsWith('*')) {
      parts.push(<em key={match.index} className="italic text-zinc-300">{raw.slice(1, -1)}</em>)
    } else if (raw.startsWith('`')) {
      parts.push(<code key={match.index} className="bg-zinc-800 text-green-400 px-1 py-0.5 rounded text-[11px] font-mono">{raw.slice(1, -1)}</code>)
    }
    last = match.index + raw.length
  }
  if (last < text.length) parts.push(text.slice(last))
  return parts.length > 0 ? parts : text
}


// ── Quick actions ─────────────────────────────────────────────────────────────
const QUICK_ACTIONS = [
  {
    icon: Sparkles, label: 'Full Analysis', color: 'text-yellow-400',
    action: 'analyze', prompt: '',
  },
  {
    icon: Target, label: 'Attack Surface', color: 'text-orange-400',
    action: 'chat',
    prompt: 'Based on the session data, map the full attack surface. List every endpoint, parameter, and technology that could be vulnerable. For each, suggest the highest-potential attack type.',
  },
  {
    icon: Lightbulb, label: 'Next Steps', color: 'text-blue-400',
    action: 'chat',
    prompt: 'Given the current findings and recon data, what should I test next? Prioritize by bounty potential. Include exact tool commands.',
  },
  {
    icon: FileText, label: 'Generate Reports', color: 'text-green-400',
    action: 'report', prompt: '',
  },
  {
    icon: AlertTriangle, label: 'Find Attack Chains', color: 'text-red-400',
    action: 'chat',
    prompt: 'Analyze the findings and live hosts for potential attack chains. Look for: SSRF → internal access, XSS → account takeover, IDOR → data exposure, open redirect → phishing. Describe each chain with exploitation steps.',
  },
  {
    icon: Shield, label: 'Check False Positives', color: 'text-purple-400',
    action: 'chat',
    prompt: 'Review all findings and identify which ones are likely false positives. For each potential FP, explain why and how to verify it manually.',
  },
]

// ── Tool → API endpoint map ───────────────────────────────────────────────────
const TOOL_ENDPOINTS: Record<string, string> = {
  subfinder: '/api/recon/subfinder',
  amass: '/api/recon/amass',
  httpx: '/api/recon/httpx',
  'httpx-probe': '/api/recon/httpx-probe',
  nmap: '/api/recon/nmap',
  waybackurls: '/api/recon/waybackurls',
  gau: '/api/recon/gau',
  katana: '/api/recon/katana',
  'katana-headless': '/api/recon/katana-headless',
  linkfinder: '/api/recon/linkfinder',
  arjun: '/api/recon/arjun',
  nuclei: '/api/scanner/nuclei',
  ffuf: '/api/scanner/ffuf',
  gobuster: '/api/scanner/gobuster',
  dirsearch: '/api/scanner/dirsearch',
  nikto: '/api/scanner/nikto',
  cors: '/api/tools/cors',
  'bypass-403': '/api/tools/bypass-403',
}

// ── Main component ─────────────────────────────────────────────────────────────
export function CopilotPage() {
  const { messages, addMessage, clearMessages } = useCopilotStore()
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState<number | null>(null)
  const [terminalRunning, setTerminalRunning] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const terminalOutputRef = useRef<string[]>([])
  const terminalJobRef = useRef<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)

  const { findings } = useScannerStore()
  const { subdomains, liveHosts, ports, urls } = useReconStore()
  const { globalTarget, activeProject } = useAppStore()

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // WebSocket for terminal output
  useEffect(() => {
    const ws = new WebSocket(`${WS_BASE}/ws`)
    wsRef.current = ws

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        if (msg.channel !== 'terminal') return
        const data = msg.data
        if (data.job_id !== terminalJobRef.current) return

        if (data.event === 'output') {
          terminalOutputRef.current.push(data.line)
        } else if (data.event === 'completed' || data.event === 'killed') {
          const output = terminalOutputRef.current.join('')
          terminalOutputRef.current = []
          terminalJobRef.current = null
          setTerminalRunning(false)
          handleCommandDone(output)
        }
      } catch {}
    }

    return () => { ws.close() }
  }, [])

  const buildContext = useCallback(() => ({
    target: globalTarget,
    subdomains,
    live_hosts: liveHosts,
    ports,
    urls: urls.slice(0, 100),
  }), [globalTarget, subdomains, liveHosts, ports, urls])

  const sevCounts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1; return acc
  }, {})

  const appendAssistant = (content: string, isError = false) => {
    addMessage({ role: 'assistant', content, error: isError })
  }

  const handleCommandDone = async (output: string) => {
    addMessage({ role: 'terminal', content: output || '(no output)' })
    if (!output.trim()) return
    setLoading(true)
    const history = messages
      .filter(m => m.role === 'user' || m.role === 'assistant')
      .slice(-20)
      .map(m => ({ role: m.role, content: m.content }))
    try {
      const res = await api.post<{ response: string }>('/api/copilot/agent', {
        message: 'Analyze this command output and suggest next steps.',
        context: buildContext(),
        command_output: output.slice(0, 6000),
        history,
      })
      appendAssistant(res.response || 'No response.')
    } catch (e) {
      appendAssistant(`Error analyzing output: ${e}`, true)
    } finally {
      setLoading(false)
    }
  }

  const runCommand = async (cmd: string) => {
    if (terminalRunning) return
    const jobId = `copilot-${Date.now()}`
    terminalJobRef.current = jobId
    terminalOutputRef.current = []
    setTerminalRunning(true)
    addMessage({ role: 'user', content: cmd, command: cmd })
    try {
      await api.post('/api/terminal/exec', { command: cmd, job_id: jobId })
    } catch (e) {
      setTerminalRunning(false)
      addMessage({ role: 'terminal', content: `Failed to start: ${e}` })
    }
  }

  const runNexHuntTool = async (toolName: string, target: string, options: Record<string, string>) => {
    const endpoint = TOOL_ENDPOINTS[toolName]
    if (!endpoint) {
      appendAssistant(`Unknown tool: \`${toolName}\`. Check the tool name and try again.`, true)
      return
    }
    const resolvedTarget = target || globalTarget || ''
    if (!resolvedTarget) {
      appendAssistant('No target set. Set a target in the top bar first, then execute again.', true)
      return
    }
    addMessage({ role: 'user', content: `Execute ${toolName} on ${resolvedTarget}` })
    try {
      await api.post(endpoint, {
        target: resolvedTarget,
        options,
        project_id: activeProject ?? '',
      })
      appendAssistant(`**${toolName}** started on \`${resolvedTarget}\`. Output streams to the Recon/Scanner page. Findings save automatically.`)
    } catch (e) {
      appendAssistant(`Failed to start **${toolName}**: ${e}`, true)
    }
  }

  const sendChat = async (content: string) => {
    if (!content.trim() || loading) return
    const history = messages
      .filter(m => m.role === 'user' || m.role === 'assistant')
      .slice(-20)
      .map(m => ({ role: m.role, content: m.content }))
    addMessage({ role: 'user', content })
    setInput('')
    setLoading(true)
    try {
      const res = await api.post<{ response: string }>('/api/copilot/agent', {
        message: content,
        context: buildContext(),
        history,
      })
      appendAssistant(res.response || 'No response.')
    } catch (e) {
      appendAssistant(`${e}`, true)
    } finally {
      setLoading(false)
    }
  }

  const sendAnalyze = async () => {
    addMessage({ role: 'user', content: 'Full session analysis...' })
    setLoading(true)
    try {
      const res = await api.post<{ response: string }>('/api/copilot/analyze', { context: buildContext() })
      appendAssistant(res.response || 'No response.')
    } catch (e) {
      appendAssistant(`${e}`, true)
    } finally {
      setLoading(false)
    }
  }

  const sendReport = async () => {
    addMessage({ role: 'user', content: 'Generate bug bounty reports...' })
    setLoading(true)
    try {
      const res = await api.post<{ response: string }>('/api/copilot/report', { context: buildContext() })
      appendAssistant(res.response || 'No response.')
    } catch (e) {
      appendAssistant(`${e}`, true)
    } finally {
      setLoading(false)
    }
  }

  const sendTips = async () => {
    addMessage({ role: 'user', content: 'Quick tips based on current data?' })
    setLoading(true)
    try {
      const res = await api.post<{ response: string }>('/api/copilot/tips', { context: buildContext() })
      appendAssistant(res.response || 'No tips.')
    } catch (e) {
      appendAssistant(`${e}`, true)
    } finally {
      setLoading(false)
    }
  }

  const handleQuickAction = (action: typeof QUICK_ACTIONS[0]) => {
    if (action.action === 'analyze') sendAnalyze()
    else if (action.action === 'report') sendReport()
    else sendChat(action.prompt)
  }

  const copyMessage = (content: string, idx: number) => {
    navigator.clipboard.writeText(content)
    setCopied(idx)
    setTimeout(() => setCopied(null), 1500)
  }

  const clearChat = () => clearMessages()

  return (
    <WorkspaceShell title="AI Copilot" subtitle="Chat + terminal execution">
      <div className="flex gap-4 h-full min-h-0">

        {/* LEFT: Context sidebar */}
        <div className="w-52 shrink-0 flex flex-col gap-3 overflow-y-auto">

          <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-3 space-y-2">
            <p className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wide">Session Context</p>
            {globalTarget && (
              <div className="flex items-center gap-1.5 text-[11px]">
                <Target size={11} className="text-zinc-500 shrink-0" />
                <span className="text-zinc-300 font-mono truncate">{globalTarget}</span>
              </div>
            )}
            <div className="space-y-1">
              <ContextStat icon={Shield} label="Findings" value={findings.length} color="text-red-400" />
              <ContextStat icon={Globe} label="Live hosts" value={liveHosts.length} color="text-green-400" />
              <ContextStat icon={Globe} label="Subdomains" value={subdomains.length} color="text-blue-400" />
              <ContextStat icon={Network} label="Open ports" value={ports.length} color="text-orange-400" />
              <ContextStat icon={ChevronRight} label="URLs found" value={urls.length} color="text-purple-400" />
            </div>
          </div>

          {findings.length > 0 && (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-3 space-y-1.5">
              <p className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wide">Findings by Severity</p>
              {[
                { sev: 'critical', color: 'bg-red-500', label: 'Critical' },
                { sev: 'high', color: 'bg-orange-500', label: 'High' },
                { sev: 'medium', color: 'bg-yellow-500', label: 'Medium' },
                { sev: 'low', color: 'bg-blue-500', label: 'Low' },
                { sev: 'info', color: 'bg-zinc-500', label: 'Info' },
              ].filter(s => sevCounts[s.sev]).map(s => (
                <div key={s.sev} className="flex items-center gap-2">
                  <div className={cn("w-2 h-2 rounded-full shrink-0", s.color)} />
                  <span className="text-[11px] text-zinc-400 flex-1">{s.label}</span>
                  <span className="text-[11px] font-mono font-bold text-zinc-300">{sevCounts[s.sev]}</span>
                </div>
              ))}
            </div>
          )}

          <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-3 space-y-1">
            <p className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wide mb-2">Quick Actions</p>
            <button
              disabled={loading}
              onClick={sendTips}
              className="w-full flex items-center gap-2 rounded-lg px-2 py-1.5 text-left text-xs text-zinc-300 hover:bg-zinc-800 transition-colors disabled:opacity-50 border border-violet-800/50 bg-violet-950/20"
            >
              <Zap size={12} className="shrink-0 text-violet-400" />
              Quick Tips
            </button>
            {QUICK_ACTIONS.map(action => (
              <button
                key={action.label}
                disabled={loading}
                onClick={() => handleQuickAction(action)}
                className="w-full flex items-center gap-2 rounded-lg px-2 py-1.5 text-left text-xs text-zinc-300 hover:bg-zinc-800 transition-colors disabled:opacity-50"
              >
                <action.icon size={12} className={cn("shrink-0", action.color)} />
                {action.label}
              </button>
            ))}
          </div>

          <div className="rounded-xl border border-zinc-700/50 bg-zinc-900/30 p-3 space-y-1.5">
            <p className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wide flex items-center gap-1">
              <Terminal size={10} /> Terminal
            </p>
            <p className="text-[10px] text-zinc-600">
              Click <span className="text-green-400 font-semibold">Run</span> on any bash code block to execute it. Output is auto-analyzed by AI.
            </p>
            {terminalRunning && (
              <div className="flex items-center gap-1.5 text-[11px] text-yellow-400">
                <Loader2 size={10} className="animate-spin" /> Running...
              </div>
            )}
          </div>

          <Button variant="ghost" size="sm" className="text-xs text-zinc-600 hover:text-zinc-400" onClick={clearChat}>
            <RefreshCw size={11} className="mr-1" /> Clear chat
          </Button>
        </div>

        {/* RIGHT: Chat */}
        <div className="flex-1 flex flex-col min-h-0">
          <div className="flex-1 overflow-y-auto space-y-4 pb-4 pr-1">
            {messages.length === 0 && (
              <div className="flex flex-col items-center justify-center h-full text-center gap-4">
                <div className="rounded-full bg-green-500/10 border border-green-500/20 p-5">
                  <Bot size={40} className="text-green-500" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-zinc-200">NexHunt AI Copilot</h2>
                  <p className="text-sm text-zinc-500 mt-1 max-w-md">
                    All findings and recon data loaded automatically.
                    Click <span className="text-green-400 font-mono">Run</span> on any bash block to execute and analyze.
                  </p>
                </div>
                <div className="grid grid-cols-2 gap-2 max-w-md w-full">
                  <button
                    disabled={loading}
                    onClick={sendTips}
                    className="flex items-center gap-2 rounded-xl border border-violet-700/50 bg-violet-950/20 px-3 py-2.5 text-left text-xs text-zinc-300 hover:bg-violet-950/40 transition-colors col-span-2"
                  >
                    <Zap size={14} className="shrink-0 text-violet-400" />
                    <span>Quick Tips - what should I focus on?</span>
                  </button>
                  {QUICK_ACTIONS.map(action => (
                    <button
                      key={action.label}
                      disabled={loading}
                      onClick={() => handleQuickAction(action)}
                      className="flex items-center gap-2 rounded-xl border border-zinc-800 bg-zinc-900/60 px-3 py-2.5 text-left text-xs text-zinc-300 hover:bg-zinc-800/80 hover:border-zinc-600 transition-colors"
                    >
                      <action.icon size={14} className={cn("shrink-0", action.color)} />
                      <span>{action.label}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {messages.map((msg, i) => (
              <div key={i} className={cn('flex gap-3', msg.role === 'user' ? 'flex-row-reverse' : '')}>
                <div className={cn(
                  'flex h-7 w-7 shrink-0 items-center justify-center rounded-lg mt-0.5',
                  msg.role === 'user' ? 'bg-blue-500/15 text-blue-400' :
                  msg.role === 'terminal' ? 'bg-zinc-800 text-zinc-400' :
                  'bg-green-500/15 text-green-400'
                )}>
                  {msg.role === 'user' ? <User size={14} /> :
                   msg.role === 'terminal' ? <Terminal size={14} /> :
                   <Bot size={14} />}
                </div>

                <div className={cn(
                  'relative group rounded-xl px-4 py-3 max-w-[85%]',
                  msg.role === 'user' ? 'bg-blue-600/15 border border-blue-500/20 text-zinc-200' :
                  msg.role === 'terminal' ? 'bg-zinc-900 border border-zinc-700/50 font-mono text-[11px]' :
                  'bg-zinc-800/60 border border-zinc-700/50'
                )}>
                  {msg.role === 'user' && !msg.command && (
                    <p className="text-sm text-zinc-200">{msg.content}</p>
                  )}
                  {msg.role === 'user' && msg.command && (
                    <div>
                      <p className="text-[10px] text-zinc-500 mb-1">Executing command:</p>
                      <code className="text-xs text-green-400 font-mono">{msg.content}</code>
                    </div>
                  )}
                  {msg.role === 'terminal' && (
                    <pre className="text-[11px] text-zinc-400 whitespace-pre-wrap max-h-64 overflow-auto">
                      {msg.content}
                    </pre>
                  )}
                  {msg.role === 'assistant' && (
                    <>
                      <Markdown
                        text={msg.content}
                        onRunCommand={terminalRunning ? undefined : runCommand}
                        onRunTool={runNexHuntTool}
                      />
                      {msg.error && (
                        <button
                          onClick={() => {
                            // find the last user message before this one and resend it
                            for (let j = i - 1; j >= 0; j--) {
                              if (messages[j].role === 'user') {
                                sendChat(messages[j].content)
                                break
                              }
                            }
                          }}
                          disabled={loading}
                          className="mt-2 flex items-center gap-1 text-[10px] text-orange-400 hover:text-orange-300 border border-orange-800/50 rounded px-2 py-0.5 transition-colors disabled:opacity-40"
                        >
                          <RefreshCw size={9} /> Retry
                        </button>
                      )}
                    </>
                  )}

                  <button
                    onClick={() => copyMessage(msg.content, i)}
                    className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity p-1 rounded text-zinc-600 hover:text-zinc-300"
                    title="Copy"
                  >
                    {copied === i ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
                  </button>
                  <p className="text-[10px] text-zinc-700 mt-2">
                    {new Date(msg.timestamp).toLocaleTimeString()}
                  </p>
                </div>
              </div>
            ))}

            {loading && (
              <div className="flex gap-3">
                <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-green-500/15 text-green-400">
                  <Bot size={14} />
                </div>
                <div className="rounded-xl bg-zinc-800/60 border border-zinc-700/50 px-4 py-3 flex items-center gap-2">
                  <Loader2 size={14} className="animate-spin text-green-400" />
                  <span className="text-xs text-zinc-500">Analyzing...</span>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Input */}
          <div className="flex items-center gap-2 pt-3 border-t border-zinc-800">
            <Input
              placeholder="Ask anything — findings are loaded automatically..."
              className="flex-1 bg-zinc-900 text-sm"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(input) } }}
              disabled={loading || terminalRunning}
            />
            <Button onClick={() => sendChat(input)} disabled={loading || !input.trim() || terminalRunning}>
              {loading ? <Loader2 size={14} className="animate-spin" /> : <Send size={14} />}
            </Button>
          </div>
        </div>
      </div>
    </WorkspaceShell>
  )
}

function ContextStat({ icon: Icon, label, value, color }: { icon: any; label: string; value: number; color: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <Icon size={10} className={cn("shrink-0", color)} />
      <span className="text-[11px] text-zinc-500 flex-1">{label}</span>
      <span className={cn("text-[11px] font-mono font-bold", value > 0 ? color : 'text-zinc-700')}>{value}</span>
    </div>
  )
}
