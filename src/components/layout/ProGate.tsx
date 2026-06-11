import { useNavigate } from 'react-router-dom'
import { Crown, Check, KeyRound, ExternalLink } from 'lucide-react'
import { useLicenseStore } from '@/stores/license-store'

interface ProGateProps {
  feature: string
  children: React.ReactNode
}

const BENEFITS = [
  'AI-driven analysis, host profiling, and report generation',
  'Automated XSS / SQLi / JS pipelines',
  'Bulk scanning, JWT and business-logic suites',
]

const UPGRADE_FALLBACK = 'https://sentinelsec.online/pricing'

/**
 * Full-page gate for PRO-only routes. Renders an upsell instead of the page on free tier.
 */
export function ProGate({ feature, children }: ProGateProps) {
  const { isPro, status } = useLicenseStore()
  const navigate = useNavigate()

  if (isPro()) return <>{children}</>

  const upgradeUrl = status?.upgrade_url || UPGRADE_FALLBACK

  return (
    <div className="flex flex-1 items-center justify-center bg-zinc-950 p-6">
      <div className="text-center space-y-6 max-w-md">
        <div className="flex justify-center">
          <div className="w-16 h-16 rounded-2xl bg-amber-500/15 border border-amber-500/40 flex items-center justify-center">
            <Crown size={28} className="text-amber-400" />
          </div>
        </div>

        <div>
          <div className="text-[10px] uppercase tracking-widest text-amber-400/80 font-semibold mb-2">NexHunt PRO</div>
          <h2 className="text-xl font-bold text-zinc-100 mb-1">{feature} is a PRO feature</h2>
          <p className="text-sm text-zinc-500">by Sentinel Security</p>
        </div>

        <div className="space-y-2 text-left inline-block">
          {BENEFITS.map((b) => (
            <div key={b} className="flex items-start gap-2.5 text-[13px] text-zinc-300 leading-snug">
              <Check size={15} className="text-amber-400 shrink-0 mt-0.5" />
              <span>{b}</span>
            </div>
          ))}
        </div>

        <div className="flex flex-col gap-2.5 max-w-xs mx-auto">
          <a
            href={upgradeUrl}
            target="_blank"
            rel="noreferrer"
            className="w-full flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-gradient-to-r from-amber-500 to-yellow-500 text-zinc-950 text-sm font-semibold hover:opacity-90 transition-opacity"
          >
            Get PRO
            <ExternalLink size={14} />
          </a>
          <button
            onClick={() => navigate('/settings?tab=license')}
            className="w-full flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg border border-zinc-700 text-zinc-300 text-sm font-medium hover:border-zinc-500 hover:text-zinc-100 transition-colors"
          >
            <KeyRound size={14} />
            Enter license key
          </button>
        </div>
      </div>
    </div>
  )
}
