import { useNavigate } from 'react-router-dom'
import { useAppStore } from '@/stores/app-store'
import { useProxyStore } from '@/stores/proxy-store'
import { useReconStore } from '@/stores/recon-store'
import { useScannerStore } from '@/stores/scanner-store'
import { Sparkles } from 'lucide-react'

interface TopBarProps {
  title: string
  subtitle?: string
}

export function TopBar({ title, subtitle }: TopBarProps) {
  const { backendConnected } = useAppStore()
  const { proxyRunning, flows } = useProxyStore()
  const { liveHosts, subdomains } = useReconStore()
  const { findings } = useScannerStore()
  const navigate = useNavigate()

  const hasData = liveHosts.length > 0 || subdomains.length > 0 || findings.length > 0

  return (
    <header className="flex h-12 shrink-0 items-center justify-between border-b border-zinc-800/80 bg-zinc-950/70 px-5">
      <div className="flex items-baseline gap-2.5">
        <h1 className="text-[15px] font-semibold text-zinc-100 tracking-tight">{title}</h1>
        {subtitle && (
          <span className="text-[11px] text-zinc-600 font-normal">{subtitle}</span>
        )}
      </div>

      <div className="flex items-center gap-2">
        {hasData && (
          <button
            onClick={() => navigate('/copilot')}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium border border-violet-800/40 bg-violet-950/20 text-violet-400 hover:bg-violet-950/40 hover:border-violet-700/50 transition-colors"
            title="AI Copilot - get tips based on current data"
          >
            <Sparkles size={10} />
            AI Tips
          </button>
        )}
        {proxyRunning && (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium border border-green-900/50 bg-green-950/25 text-green-400">
            <span className="w-1.5 h-1.5 rounded-full bg-green-500 shadow-[0_0_4px_1px_rgba(0,217,166,0.5)] animate-pulse" />
            Proxy · {flows.length} flows
          </div>
        )}
        <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium border transition-colors ${
          backendConnected
            ? 'border-zinc-800/60 bg-zinc-900/40 text-zinc-500'
            : 'border-red-900/50 bg-red-950/20 text-red-400'
        }`}>
          <span className={`w-1.5 h-1.5 rounded-full ${
            backendConnected
              ? 'bg-green-500 shadow-[0_0_4px_1px_rgba(0,217,166,0.45)]'
              : 'bg-red-500'
          }`} />
          {backendConnected ? 'Online' : 'Offline'}
        </div>
      </div>
    </header>
  )
}
