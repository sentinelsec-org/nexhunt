import { useState, useEffect } from 'react'
import { X, Crown, Zap, Shield, Bot, Layers, ExternalLink, KeyRound } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useLicenseStore } from '@/stores/license-store'

const BENEFITS = [
  { icon: Bot,     text: 'AI Copilot — attack surface analysis, JS secret mining, report generation' },
  { icon: Zap,     text: 'Automated pipelines — XSS, SQLi, and full recon chains in one click' },
  { icon: Layers,  text: 'Bulk scanning — nuclei, screenshots and CORS across all live hosts at once' },
  { icon: Shield,  text: 'Proxy Intruder, JWT attack suite, brute force module' },
]

const UPGRADE_URL = 'https://sentinelsec.online/pricing'

export function ProSplash() {
  const [visible, setVisible] = useState(false)
  const status = useLicenseStore((s) => s.status)
  const navigate = useNavigate()

  useEffect(() => {
    // Wait for status to load; show splash only for free/non-PRO users
    if (status === null) return
    if (status.tier === 'pro') return
    // Small delay so the app renders first
    const t = setTimeout(() => setVisible(true), 600)
    return () => clearTimeout(t)
  }, [status])

  if (!visible) return null

  const upgradeUrl = status?.upgrade_url || UPGRADE_URL

  return (
    <div
      className="fixed inset-0 z-[110] flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
      onClick={() => setVisible(false)}
    >
      <div
        className="w-full max-w-lg rounded-2xl border border-amber-500/25 bg-zinc-950 shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="relative px-7 pt-7 pb-6 bg-gradient-to-br from-amber-500/10 via-zinc-900/80 to-zinc-950 border-b border-zinc-800/70">
          <button
            onClick={() => setVisible(false)}
            className="absolute top-4 right-4 text-zinc-600 hover:text-zinc-300 transition-colors"
          >
            <X size={16} />
          </button>

          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-xl bg-amber-500/15 border border-amber-500/35 flex items-center justify-center">
              <Crown size={20} className="text-amber-400" />
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-[0.18em] text-amber-400/80 font-semibold">
                NexHunt PRO
              </div>
              <div className="text-[11px] text-zinc-600 mt-0.5">by Sentinel Security</div>
            </div>
          </div>

          <h2 className="text-[22px] font-bold text-zinc-100 leading-tight">
            Take your recon to the next level
          </h2>
          <p className="text-sm text-zinc-500 mt-1.5 leading-relaxed">
            Unlock automation, AI assistance, and advanced attack modules.
          </p>
        </div>

        {/* Benefits */}
        <div className="px-7 py-5 space-y-4">
          {BENEFITS.map(({ icon: Icon, text }) => (
            <div key={text} className="flex items-start gap-3">
              <div className="mt-0.5 w-6 h-6 rounded-md bg-amber-500/10 border border-amber-500/20 flex items-center justify-center shrink-0">
                <Icon size={12} className="text-amber-400" />
              </div>
              <span className="text-[13px] text-zinc-300 leading-snug">{text}</span>
            </div>
          ))}
        </div>

        {/* Actions */}
        <div className="px-7 pb-7 space-y-2.5">
          <a
            href={upgradeUrl}
            target="_blank"
            rel="noreferrer"
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-gradient-to-r from-amber-500 to-yellow-400 text-zinc-950 text-sm font-bold hover:opacity-90 transition-opacity"
          >
            Get PRO
            <ExternalLink size={13} />
          </a>
          <button
            onClick={() => { setVisible(false); navigate('/settings?tab=license') }}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg border border-zinc-800 text-zinc-400 text-sm font-medium hover:border-zinc-600 hover:text-zinc-200 transition-colors"
          >
            <KeyRound size={13} />
            I have a license key
          </button>
          <button
            onClick={() => setVisible(false)}
            className="w-full text-[11px] text-zinc-700 hover:text-zinc-500 transition-colors pt-1"
          >
            Continue with free plan
          </button>
        </div>
      </div>
    </div>
  )
}
