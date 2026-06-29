import { useSearchParams } from 'react-router-dom'
import { ScanSearch, Network, Newspaper, Zap, GitFork } from 'lucide-react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { SectionTabs } from '@/components/layout/SectionTabs'
import { ProGate } from '@/components/layout/ProGate'
import { useLicenseStore } from '@/stores/license-store'
import { ScannerPage } from '@/pages/ScannerPage'
import { ApiScannerPage } from '@/pages/ApiScannerPage'
import { WordPressPage } from '@/pages/WordPressPage'
import { PipelinesPage } from '@/pages/PipelinesPage'
import { RepositoryIntelligencePage } from '@/pages/RepositoryIntelligencePage'

export function ScanPage() {
  const [params, setParams] = useSearchParams()
  const isPro = useLicenseStore((s) => s.isPro())
  const tabs = [
    { id: 'scanner', label: 'Vuln Scanner', icon: ScanSearch },
    { id: 'api', label: 'API Scanner', icon: Network, locked: !isPro },
    { id: 'repository', label: 'Repository Intel', icon: GitFork, locked: !isPro },
    { id: 'wordpress', label: 'WordPress', icon: Newspaper },
    { id: 'pipelines', label: 'Pipelines', icon: Zap },
  ]
  const active = tabs.some(t => t.id === params.get('tab')) ? params.get('tab')! : 'scanner'

  return (
    <WorkspaceShell title="Scan" subtitle="Vulnerability scanning — Nuclei, dirs, API spec probing, WordPress and pipelines">
      <SectionTabs tabs={tabs} active={active} onChange={id => setParams({ tab: id }, { replace: true })} />
      {active === 'scanner' && <ScannerPage embedded />}
      {active === 'api' && <ProGate feature="API Scanner"><ApiScannerPage embedded /></ProGate>}
      {active === 'repository' && <ProGate feature="Repository Intelligence"><RepositoryIntelligencePage embedded /></ProGate>}
      {active === 'wordpress' && <WordPressPage embedded />}
      {active === 'pipelines' && <PipelinesPage embedded />}
    </WorkspaceShell>
  )
}
