import { useEffect, useState } from 'react'
import { Sparkles, Loader2, X, AlertTriangle } from 'lucide-react'
import type { UpdateAvailableInfo } from '@/types'

type Phase = 'hidden' | 'available' | 'installing' | 'error'

export function UpdateBanner() {
  const [phase, setPhase] = useState<Phase>('hidden')
  const [info, setInfo] = useState<UpdateAvailableInfo | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!window.nexhunt?.update) return
    const offAvailable = window.nexhunt.update.onAvailable((data) => {
      setInfo(data)
      setPhase('available')
    })
    const offInstalling = window.nexhunt.update.onInstalling(() => setPhase('installing'))
    const offDone = window.nexhunt.update.onDone(() => setPhase('installing'))
    const offError = window.nexhunt.update.onError((message) => {
      setError(message)
      setPhase('error')
    })
    return () => {
      offAvailable()
      offInstalling()
      offDone()
      offError()
    }
  }, [])

  if (phase === 'hidden') return null

  return (
    <div className="absolute top-3 left-1/2 -translate-x-1/2 z-50 w-full max-w-lg px-4">
      <div className="rounded-xl border border-amber-500/30 bg-zinc-900/95 backdrop-blur shadow-xl shadow-black/40 px-4 py-3">
        {phase === 'available' && info && (
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 rounded-lg bg-amber-500/15 border border-amber-500/40 flex items-center justify-center shrink-0">
              <Sparkles size={15} className="text-amber-400" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-sm font-semibold text-zinc-100">NexHunt {info.latest} is ready</div>
              <p className="text-[12.5px] text-zinc-400 mt-0.5 leading-snug">
                It only takes a few seconds to update, and you'll be on a better, faster NexHunt.
              </p>
              <div className="flex items-center gap-2 mt-2.5">
                <button
                  onClick={() => window.nexhunt.update.apply()}
                  className="px-3 py-1.5 rounded-md bg-gradient-to-r from-amber-500 to-yellow-500 text-zinc-950 text-xs font-semibold hover:opacity-90 transition-opacity"
                >
                  Update now
                </button>
                {!info.mandatory && (
                  <button
                    onClick={() => setPhase('hidden')}
                    className="px-3 py-1.5 rounded-md text-zinc-400 text-xs font-medium hover:text-zinc-200 transition-colors"
                  >
                    Later
                  </button>
                )}
              </div>
            </div>
            {!info.mandatory && (
              <button onClick={() => setPhase('hidden')} className="text-zinc-500 hover:text-zinc-300 shrink-0">
                <X size={14} />
              </button>
            )}
          </div>
        )}

        {phase === 'installing' && (
          <div className="flex items-center gap-3">
            <Loader2 size={16} className="text-amber-400 animate-spin shrink-0" />
            <div className="text-sm text-zinc-200">
              Installing the update — you may be asked for your system password.
            </div>
          </div>
        )}

        {phase === 'error' && (
          <div className="flex items-start gap-3">
            <AlertTriangle size={16} className="text-red-400 shrink-0 mt-0.5" />
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium text-zinc-100">Update failed</div>
              <p className="text-[12.5px] text-zinc-400 mt-0.5">{error}</p>
            </div>
            <button onClick={() => setPhase('hidden')} className="text-zinc-500 hover:text-zinc-300 shrink-0">
              <X size={14} />
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
