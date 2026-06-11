import { CheckCircle2, XCircle, AlertTriangle, Info, X } from 'lucide-react'
import { useToastStore, type ToastKind } from '@/stores/toast-store'
import { cn } from '@/lib/utils'

const ICONS: Record<ToastKind, typeof Info> = {
  success: CheckCircle2,
  error: XCircle,
  warning: AlertTriangle,
  info: Info,
}

const STYLES: Record<ToastKind, string> = {
  success: 'border-green-700 bg-green-950/90 text-green-200',
  error: 'border-red-700 bg-red-950/90 text-red-200',
  warning: 'border-amber-700 bg-amber-950/90 text-amber-200',
  info: 'border-zinc-700 bg-zinc-900/90 text-zinc-200',
}

export function Toaster() {
  const { toasts, dismiss } = useToastStore()
  return (
    <div className="fixed bottom-4 right-4 z-[9999] flex flex-col gap-2 w-80 max-w-[90vw]">
      {toasts.map((t) => {
        const Icon = ICONS[t.kind]
        return (
          <div
            key={t.id}
            className={cn('flex items-start gap-2 rounded-md border px-3 py-2 shadow-lg backdrop-blur', STYLES[t.kind])}
          >
            <Icon size={16} className="mt-0.5 shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium break-words">{t.title}</div>
              {t.message && <div className="text-xs opacity-80 break-words mt-0.5">{t.message}</div>}
            </div>
            <button onClick={() => dismiss(t.id)} className="opacity-60 hover:opacity-100 shrink-0">
              <X size={14} />
            </button>
          </div>
        )
      })}
    </div>
  )
}
