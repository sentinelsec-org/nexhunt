import { Play } from 'lucide-react'
import { Cpu } from 'lucide-react'

type RunToolFn = (tool: string, target: string, options: Record<string, string>) => void

export function Markdown({ text, onRunCommand, onRunTool }: {
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

export function inlineFormat(text: string): React.ReactNode {
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
