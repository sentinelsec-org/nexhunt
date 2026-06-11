import { useAppStore } from '@/stores/app-store'
import { cn } from '@/lib/utils'
import { Target, AlertCircle } from 'lucide-react'

interface ScopeSelectorProps {
  onSelect: (domain: string) => void
  selectedTarget?: string
  className?: string
}

export function ScopeSelector({ onSelect, selectedTarget, className }: ScopeSelectorProps) {
  const { activeProjectData, setGlobalTarget } = useAppStore()

  if (!activeProjectData) {
    return (
      <div className={cn("flex items-center gap-2 text-xs text-zinc-600", className)}>
        <AlertCircle size={12} />
        No active project — go to Projects and activate one to use scope.
      </div>
    )
  }

  if (activeProjectData.scope.length === 0) {
    return (
      <div className={cn("flex items-center gap-2 text-xs text-zinc-600", className)}>
        <AlertCircle size={12} />
        Project &quot;{activeProjectData.name}&quot; has no domains in scope.
      </div>
    )
  }

  // Strip wildcard prefix when setting target (*.example.com → example.com)
  const handleClick = (domain: string) => {
    const clean = domain.startsWith('*.') ? domain.slice(2) : domain
    onSelect(clean)
    setGlobalTarget(clean)
  }

  const isSelected = (domain: string) => {
    const clean = domain.startsWith('*.') ? domain.slice(2) : domain
    return selectedTarget === clean
  }

  return (
    <div className={cn("flex items-center gap-2 flex-wrap", className)}>
      <span className="flex items-center gap-1 text-xs text-zinc-500 shrink-0">
        <Target size={11} />
        <span className="text-zinc-600">{activeProjectData.name}:</span>
      </span>
      {activeProjectData.scope.map((domain, i) => (
        <button
          key={i}
          onClick={() => handleClick(domain)}
          title={`Set ${domain} as target`}
          className={cn(
            "text-xs px-2 py-0.5 rounded font-mono border transition-colors",
            isSelected(domain)
              ? "bg-green-900/40 border-green-500/60 text-green-400"
              : "bg-zinc-800/60 border-zinc-700 text-zinc-400 hover:border-zinc-500 hover:text-zinc-200 hover:bg-zinc-700/60"
          )}
        >
          {domain}
        </button>
      ))}
    </div>
  )
}
