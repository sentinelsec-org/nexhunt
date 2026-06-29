import { useSearchParams } from 'react-router-dom'
import { ShieldCheck, Swords, KeyRound, Share2 } from 'lucide-react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { SectionTabs } from '@/components/layout/SectionTabs'
import { ProGate } from '@/components/layout/ProGate'
import { useLicenseStore } from '@/stores/license-store'
import { SecurityToolsPage } from '@/pages/SecurityToolsPage'
import { GraphQLAuditPage } from '@/pages/GraphQLAuditPage'
import { ExploitPage } from '@/pages/ExploitPage'
import { BruteForcePage } from '@/pages/BruteForcePage'

export function OffensePage() {
  const [params, setParams] = useSearchParams()
  const isPro = useLicenseStore((s) => s.isPro())
  const tabs = [
    { id: 'attacks', label: 'Attacks', icon: ShieldCheck },
    { id: 'graphql', label: 'GraphQL', icon: Share2, locked: !isPro },
    { id: 'injection', label: 'Injection', icon: Swords },
    { id: 'brute', label: 'Brute Force', icon: KeyRound },
  ]
  const active = tabs.some(t => t.id === params.get('tab')) ? params.get('tab')! : 'attacks'

  return (
    <WorkspaceShell title="Exploit" subtitle="Active exploitation — targeted attacks, GraphQL, injection (SQLi/XSS/CMDi) and credential brute force">
      <SectionTabs tabs={tabs} active={active} onChange={id => setParams({ tab: id }, { replace: true })} />
      {active === 'attacks' && <SecurityToolsPage embedded />}
      {active === 'graphql' && <ProGate feature="GraphQL Auditor"><GraphQLAuditPage embedded /></ProGate>}
      {active === 'injection' && <ExploitPage embedded />}
      {active === 'brute' && <BruteForcePage embedded />}
    </WorkspaceShell>
  )
}
