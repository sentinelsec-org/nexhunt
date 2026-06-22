import { cn } from '@/lib/utils'

export interface SectionTab {
  id: string
  label: string
  icon: React.ComponentType<{ size?: number; className?: string }>
  locked?: boolean
}

export function SectionTabs({ tabs, active, onChange }: {
  tabs: SectionTab[]
  active: string
  onChange: (id: string) => void
}) {
  return (
    <div className="flex gap-1 border-b border-zinc-800 mb-3 -mt-1">
      {tabs.map(t => {
        const Icon = t.icon
        const isActive = t.id === active
        return (
          <button
            key={t.id}
            onClick={() => onChange(t.id)}
            className={cn(
              'flex items-center gap-1.5 px-3 py-2 text-[13px] font-medium border-b-2 -mb-px transition-colors',
              isActive
                ? 'border-green-500 text-green-400'
                : 'border-transparent text-zinc-500 hover:text-zinc-300'
            )}
          >
            <Icon size={14} className="shrink-0" />
            {t.label}
            {t.locked && <span className="text-[8px] px-1 rounded bg-amber-900/40 text-amber-500 uppercase tracking-wide">Pro</span>}
          </button>
        )
      })}
    </div>
  )
}
