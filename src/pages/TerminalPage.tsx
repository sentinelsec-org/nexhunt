import { useState, useRef, useEffect, useCallback } from 'react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { api } from '@/api/http-client'
import { useAppStore } from '@/stores/app-store'
import { API_BASE, WS_BASE } from '@/lib/constants'
import { cn } from '@/lib/utils'
import { Play, Square, Trash2, ChevronUp, ChevronDown } from 'lucide-react'

interface OutputLine {
  text: string
  type: 'cmd' | 'stdout' | 'error' | 'meta'
}

const QUICK_COMMANDS = [
  { label: 'nmap -sV -sC', cmd: 'nmap -sV -sC -p 80,443,8080,8443 ' },
  { label: 'gobuster', cmd: 'gobuster dir -u  -w /usr/share/wordlists/dirb/common.txt -t 20 --no-color --no-progress' },
  { label: 'sqlmap', cmd: 'sqlmap -u  --batch --level 3 --risk 2' },
  { label: 'subfinder', cmd: 'subfinder -d  -silent' },
  { label: 'httpx', cmd: 'httpx -u  -title -tech-detect -status-code' },
  { label: 'nuclei', cmd: 'nuclei -u  -severity medium,high,critical' },
  { label: 'ffuf', cmd: 'ffuf -u FUZZ -w /usr/share/wordlists/dirb/common.txt' },
  { label: 'katana', cmd: 'katana -u  -depth 3 -js-crawl' },
  { label: 'dalfox', cmd: 'dalfox url  --skip-bav' },
  { label: 'whatweb', cmd: 'whatweb  --log-json=-' },
]

export function TerminalPage() {
  const [input, setInput] = useState('')
  const [output, setOutput] = useState<OutputLine[]>([
    { text: '# NexHunt Terminal — run any tool directly', type: 'meta' },
    { text: '# Commands run on the local machine as the current user', type: 'meta' },
    { text: '', type: 'meta' },
  ])
  const [running, setRunning] = useState(false)
  const [jobId, setJobId] = useState<string | null>(null)
  const [history, setHistory] = useState<string[]>([])
  const [historyIdx, setHistoryIdx] = useState(-1)
  const outputRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const { backendConnected, pendingCommand, setPendingCommand } = useAppStore()

  // Pick up a command sent from another page (e.g. Methodology)
  useEffect(() => {
    if (pendingCommand) {
      setInput(pendingCommand)
      setPendingCommand(null)
      inputRef.current?.focus()
    }
  }, [pendingCommand])

  // Auto-scroll output
  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [output])

  // Setup WebSocket listener for terminal output
  useEffect(() => {
    const ws = new WebSocket(`${WS_BASE}/ws`)
    wsRef.current = ws

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data)
        if (msg.channel !== 'terminal') return

        const data = msg.data
        if (data.event === 'output') {
          const lines = data.line.split('\n')
          setOutput(prev => [
            ...prev,
            ...lines
              .filter((l: string) => l !== '')
              .map((l: string) => ({ text: l, type: 'stdout' as const })),
          ])
        } else if (data.event === 'completed') {
          setOutput(prev => [
            ...prev,
            { text: `\n[exit code: ${data.exit_code}]`, type: 'meta' },
          ])
          setRunning(false)
          setJobId(null)
        } else if (data.event === 'killed') {
          setOutput(prev => [...prev, { text: '[process killed]', type: 'meta' }])
          setRunning(false)
          setJobId(null)
        } else if (data.event === 'error') {
          setOutput(prev => [...prev, { text: `[error: ${data.message}]`, type: 'error' }])
          setRunning(false)
          setJobId(null)
        }
      } catch {}
    }

    ws.onerror = () => {}
    ws.onclose = () => {}

    return () => {
      ws.close()
    }
  }, [])

  const runCommand = useCallback(async (cmd: string) => {
    if (!cmd.trim() || running) return
    const trimmed = cmd.trim()

    // Add to history
    setHistory(prev => [trimmed, ...prev.filter(h => h !== trimmed)].slice(0, 100))
    setHistoryIdx(-1)

    setOutput(prev => [
      ...prev,
      { text: `$ ${trimmed}`, type: 'cmd' },
    ])
    setInput('')
    setRunning(true)

    try {
      const jid = `term-${Date.now()}`
      setJobId(jid)
      await api.post('/api/terminal/exec', { command: trimmed, job_id: jid })
    } catch (err) {
      setOutput(prev => [...prev, { text: `[failed to start: ${err}]`, type: 'error' }])
      setRunning(false)
      setJobId(null)
    }
  }, [running])

  const killJob = async () => {
    if (!jobId) return
    try {
      await fetch(`${API_BASE}/api/terminal/jobs/${jobId}`, { method: 'DELETE' })
    } catch {}
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      runCommand(input)
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      const idx = Math.min(historyIdx + 1, history.length - 1)
      setHistoryIdx(idx)
      setInput(history[idx] ?? '')
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      const idx = Math.max(historyIdx - 1, -1)
      setHistoryIdx(idx)
      setInput(idx === -1 ? '' : (history[idx] ?? ''))
    } else if (e.key === 'c' && e.ctrlKey) {
      killJob()
    }
  }

  const clearOutput = () => {
    setOutput([{ text: '# Output cleared', type: 'meta' }])
  }

  const lineColor = (type: OutputLine['type']) => {
    switch (type) {
      case 'cmd': return 'text-green-400 font-bold'
      case 'error': return 'text-red-400'
      case 'meta': return 'text-zinc-600'
      default: return 'text-zinc-300'
    }
  }

  return (
    <WorkspaceShell title="Terminal" subtitle="Run any command — output streams in real-time">
      <div className="flex gap-3 h-full min-h-0">

        {/* Left: quick commands */}
        <div className="w-44 shrink-0 flex flex-col gap-1 overflow-y-auto">
          <div className="text-[10px] text-zinc-600 uppercase tracking-wide px-1 mb-1">Quick commands</div>
          {QUICK_COMMANDS.map(({ label, cmd }) => (
            <button
              key={label}
              onClick={() => setInput(cmd)}
              className="text-left px-2 py-1.5 text-xs text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 rounded-md transition-colors border border-zinc-800 hover:border-zinc-600 font-mono"
            >
              {label}
            </button>
          ))}
        </div>

        {/* Right: terminal */}
        <div className="flex-1 flex flex-col gap-2 min-h-0">

          {/* Toolbar */}
          <div className="flex items-center gap-2">
            {running && (
              <button
                onClick={killJob}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-red-700 text-red-400 hover:bg-red-950/30 transition-colors"
                title="Kill process (Ctrl+C)"
              >
                <Square size={11} className="fill-current" /> Stop
              </button>
            )}
            <button
              onClick={clearOutput}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-zinc-700 text-zinc-400 hover:bg-zinc-800 transition-colors ml-auto"
            >
              <Trash2 size={11} /> Clear
            </button>
          </div>

          {/* Output */}
          <div
            ref={outputRef}
            className="flex-1 rounded-lg border border-zinc-800 bg-zinc-950 p-3 overflow-auto font-mono text-xs leading-relaxed cursor-text"
            onClick={() => inputRef.current?.focus()}
          >
            {output.map((line, i) => (
              <div key={i} className={lineColor(line.type)}>
                {line.text || '\u00A0'}
              </div>
            ))}
            {running && (
              <span className="inline-block w-2 h-3.5 bg-green-500 animate-pulse ml-0.5" />
            )}
          </div>

          {/* Input */}
          <div className={cn(
            "flex items-center gap-2 rounded-lg border px-3 py-2 bg-zinc-900 transition-colors",
            running ? "border-yellow-700/50" : "border-zinc-700 focus-within:border-green-600"
          )}>
            <span className="text-green-500 font-mono text-xs shrink-0 select-none">
              {running ? '▶' : '$'}
            </span>
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              disabled={!backendConnected}
              placeholder={running ? 'Command running… (Ctrl+C to kill)' : 'Type a command and press Enter'}
              className="flex-1 bg-transparent text-xs text-zinc-200 placeholder:text-zinc-700 font-mono outline-none"
              autoComplete="off"
              spellCheck={false}
            />
            <div className="flex items-center gap-1 shrink-0">
              <button
                onClick={() => {
                  const idx = Math.min(historyIdx + 1, history.length - 1)
                  setHistoryIdx(idx)
                  setInput(history[idx] ?? '')
                }}
                disabled={history.length === 0}
                className="p-0.5 text-zinc-700 hover:text-zinc-400 disabled:opacity-30"
              >
                <ChevronUp size={12} />
              </button>
              <button
                onClick={() => {
                  const idx = Math.max(historyIdx - 1, -1)
                  setHistoryIdx(idx)
                  setInput(idx === -1 ? '' : (history[idx] ?? ''))
                }}
                disabled={historyIdx <= 0}
                className="p-0.5 text-zinc-700 hover:text-zinc-400 disabled:opacity-30"
              >
                <ChevronDown size={12} />
              </button>
              <button
                onClick={() => runCommand(input)}
                disabled={!input.trim() || running || !backendConnected}
                className="ml-1 px-2 py-0.5 rounded text-[10px] font-medium border border-green-700 text-green-400 hover:bg-green-950/30 disabled:opacity-30 transition-colors"
              >
                <Play size={10} />
              </button>
            </div>
          </div>

          <div className="text-[10px] text-zinc-700">
            ↑↓ history · Ctrl+C kill · Enter run
          </div>
        </div>
      </div>
    </WorkspaceShell>
  )
}
