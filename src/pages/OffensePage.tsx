import { useSearchParams } from 'react-router-dom'
import { ShieldCheck, Swords, KeyRound } from 'lucide-react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { SectionTabs } from '@/components/layout/SectionTabs'
import { SecurityToolsPage } from '@/pages/SecurityToolsPage'
import { ExploitPage } from '@/pages/ExploitPage'
import { BruteForcePage } from '@/pages/BruteForcePage'

export function OffensePage() {
  const [params, setParams] = useSearchParams()
  const tabs = [
    { id: 'attacks', label: 'Attacks', icon: ShieldCheck },
    { id: 'injection', label: 'Injection', icon: Swords },
    { id: 'brute', label: 'Brute Force', icon: KeyRound },
  ]
  const active = tabs.some(t => t.id === params.get('tab')) ? params.get('tab')! : 'attacks'

  return (
    <WorkspaceShell title="Exploit" subtitle="Active exploitation — targeted attacks, injection (SQLi/XSS/CMDi) and credential brute force">
      <SectionTabs tabs={tabs} active={active} onChange={id => setParams({ tab: id }, { replace: true })} />
      {active === 'attacks' && <SecurityToolsPage embedded />}
      {active === 'injection' && <ExploitPage embedded />}
      {active === 'brute' && <BruteForcePage embedded />}
    </WorkspaceShell>
  )
}
