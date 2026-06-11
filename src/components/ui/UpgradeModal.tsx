import { useNavigate } from 'react-router-dom'
import { X, Crown, Check, KeyRound, ExternalLink } from 'lucide-react'
import { useLicenseStore } from '@/stores/license-store'

const PRO_BENEFITS = [
  'AI Copilot: analysis, attack-surface profiling, and report generation',
  'Automated pipelines: XSS, SQLi, and JS secret scanning',
  'Bulk and parallel scanning across all live hosts',
  'JWT attack suite and business-logic testing',
  'Proxy Intruder (cluster bomb, pitchfork)',
  'Professional report export and priority updates',
]

const UPGRADE_FALLBACK = 'https://sentinelsec.online/pricing'

export function UpgradeModal() {
  const { upgradeOpen, upgradeFeature, closeUpgrade, status } = useLicenseStore()
  const navigate = useNavigate()
  if (!upgradeOpen) return null

  const upgradeUrl = status?.upgrade_url || UPGRADE_FALLBACK

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
      onClick={closeUpgrade}
    >
      <div
        className="w-full max-w-md rounded-2xl border border-amber-500/30 bg-zinc-950 shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="relative bg-gradient-to-br from-amber-500/15 via-zinc-900 to-zinc-950 px-6 pt-6 pb-5 border-b border-zinc-800">
          <button onClick={closeUpgrade} className="absolute top-4 right-4 text-zinc-600 hover:text-zinc-300">
            <X size={16} />
          </button>
          <div className="flex items-center gap-2 mb-3">
            <div className="w-9 h-9 rounded-xl bg-amber-500/20 border border-amber-500/40 flex items-center justify-center">
              <Crown size={18} className="text-amber-400" />
            </div>
            <div className="text-[10px] uppercase tracking-widest text-amber-400/80 font-semibold">NexHunt PRO</div>
          </div>
          <h2 className="text-xl font-bold text-zinc-100 leading-tight">
            {upgradeFeature ? `${upgradeFeature} is a PRO feature` : 'Unlock NexHunt PRO'}
          </h2>
          <p className="text-xs text-zinc-500 mt-1.5">
            by Sentinel Security
          </p>
        </div>

        <div className="px-6 py-5 space-y-2.5">
          {PRO_BENEFITS.map((b) => (
            <div key={b} className="flex items-start gap-2.5 text-[13px] text-zinc-300 leading-snug">
              <Check size={15} className="text-amber-400 shrink-0 mt-0.5" />
              <span>{b}</span>
            </div>
          ))}
        </div>

        <div className="px-6 pb-6 space-y-2.5">
          <a
            href={upgradeUrl}
            target="_blank"
            rel="noreferrer"
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-gradient-to-r from-amber-500 to-yellow-500 text-zinc-950 text-sm font-semibold hover:opacity-90 transition-opacity"
          >
            Get PRO
            <ExternalLink size={14} />
          </a>
          <button
            onClick={() => { closeUpgrade(); navigate('/settings?tab=license') }}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg border border-zinc-700 text-zinc-300 text-sm font-medium hover:border-zinc-500 hover:text-zinc-100 transition-colors"
          >
            <KeyRound size={14} />
            I already have a license key
          </button>
        </div>
      </div>
    </div>
  )
}
