import { useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { cn } from '@/lib/utils'

export interface ContextMenuItem {
  label: string
  icon?: React.ReactNode
  onClick: () => void
  danger?: boolean
  separator?: false
}

export interface ContextMenuSeparator {
  separator: true
}

export type ContextMenuEntry = ContextMenuItem | ContextMenuSeparator

export interface ContextMenuState {
  visible: boolean
  x: number
  y: number
}

interface ContextMenuProps {
  state: ContextMenuState
  items: ContextMenuEntry[]
  onClose: () => void
}

/**
 * Portal-based context menu. Renders at cursor position.
 * Usage:
 *   const [menu, setMenu] = useState<ContextMenuState>({ visible: false, x: 0, y: 0 })
 *   onContextMenu={(e) => { e.preventDefault(); setMenu({ visible: true, x: e.clientX, y: e.clientY }) }}
 */
export function ContextMenu({ state, items, onClose }: ContextMenuProps) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!state.visible) return
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent && e.key !== 'Escape') return
      onClose()
    }
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', close)
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('keydown', close)
    }
  }, [state.visible, onClose])

  if (!state.visible) return null

  // Adjust position to stay within viewport
  const menuWidth = 200
  const menuHeight = items.length * 32 + 8
  const x = state.x + menuWidth > window.innerWidth ? state.x - menuWidth : state.x
  const y = state.y + menuHeight > window.innerHeight ? state.y - menuHeight : state.y

  return createPortal(
    <div
      ref={ref}
      style={{ position: 'fixed', left: x, top: y, zIndex: 9999 }}
      className="min-w-[180px] rounded-lg border border-zinc-700 bg-zinc-900 shadow-xl shadow-black/50 py-1 text-xs"
      onMouseDown={e => e.stopPropagation()}
    >
      {items.map((entry, i) => {
        if ('separator' in entry && entry.separator) {
          return <div key={i} className="my-1 border-t border-zinc-800" />
        }
        const item = entry as ContextMenuItem
        return (
          <button
            key={i}
            onClick={() => { item.onClick(); onClose() }}
            className={cn(
              'flex items-center gap-2 w-full px-3 py-1.5 text-left transition-colors',
              item.danger
                ? 'text-red-400 hover:bg-red-950/40'
                : 'text-zinc-300 hover:bg-zinc-800'
            )}
          >
            {item.icon && <span className="text-zinc-500 shrink-0">{item.icon}</span>}
            {item.label}
          </button>
        )
      })}
    </div>,
    document.body
  )
}

/** Helper: builds ContextMenuState from a MouseEvent */
export function menuFromEvent(e: React.MouseEvent): ContextMenuState {
  e.preventDefault()
  e.stopPropagation()
  return { visible: true, x: e.clientX, y: e.clientY }
}
