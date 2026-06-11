import { Lock } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useLicenseStore } from '@/stores/license-store'

interface ProBadgeProps {
  feature?: string
  className?: string
  // When true, renders a small inline lock pill that opens the upgrade modal on click.
  // When false (default) it only renders the static "PRO" tag.
  interactive?: boolean
}

/**
 * Gold "PRO" tag. On free tier + interactive, clicking opens the upgrade modal.
 * Renders nothing for PRO users.
 */
export function ProBadge({ feature, className, interactive = true }: ProBadgeProps) {
  const { isPro, openUpgrade } = useLicenseStore()
  if (isPro()) return null

  const content = (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide',
        'bg-gradient-to-r from-amber-500/20 to-yellow-500/20 text-amber-400 border border-amber-500/40',
        className,
      )}
    >
      <Lock size={9} className="shrink-0" />
      PRO
    </span>
  )

  if (!interactive) return content

  return (
    <button
      type="button"
      onClick={(e) => { e.stopPropagation(); e.preventDefault(); openUpgrade(feature) }}
      className="cursor-pointer hover:opacity-80 transition-opacity"
      title={`${feature ?? 'This'} is a NexHunt PRO feature`}
    >
      {content}
    </button>
  )
}
