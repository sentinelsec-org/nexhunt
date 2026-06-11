import { useNavigate } from 'react-router-dom'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { useProxyStore } from '@/stores/proxy-store'
import { useScannerStore } from '@/stores/scanner-store'
import { useReconStore } from '@/stores/recon-store'
import { useAppStore } from '@/stores/app-store'
import { Badge } from '@/components/ui/badge'
import {
  Globe,
  Radar,
  ScanSearch,
  Swords,
  Bug,
  Shield,
  Activity,
  FolderOpen,
  ArrowRight,
} from 'lucide-react'

function StatCard({ icon: Icon, label, value, color, dimmed }: {
  icon: typeof Globe
  label: string
  value: string | number
  color: string
  dimmed?: boolean
}) {
  return (
    <div className={`rounded-xl border bg-zinc-900/50 p-5 transition-opacity ${dimmed ? 'border-zinc-800/50 opacity-40' : 'border-zinc-800'}`}>
      <div className="flex items-center gap-3">
        <div className={`rounded-lg p-2 ${color}`}>
          <Icon size={20} />
        </div>
        <div>
          <p className="text-2xl font-bold text-zinc-100">{value}</p>
          <p className="text-xs text-zinc-500">{label}</p>
        </div>
      </div>
    </div>
  )
}

export function DashboardPage() {
  const { flows, proxyRunning } = useProxyStore()
  const { findings } = useScannerStore()
  const { subdomains } = useReconStore()
  const { activeProject, activeProjectData } = useAppStore()
  const navigate = useNavigate()

  const hasProject = !!activeProject
  const criticalCount = findings.filter(f => f.severity === 'critical').length
  const highCount = findings.filter(f => f.severity === 'high').length

  return (
    <WorkspaceShell
      title="Dashboard"
      subtitle={hasProject ? `Project: ${activeProjectData?.name ?? '...'}` : 'No project selected'}
    >
      <div className="space-y-6">

        {/* No-project banner */}
        {!hasProject && (
          <div className="flex items-center justify-between rounded-xl border border-zinc-800 bg-zinc-900/60 px-5 py-4">
            <div className="flex items-center gap-3">
              <FolderOpen size={18} className="text-zinc-600" />
              <div>
                <div className="text-sm font-medium text-zinc-300">No project selected</div>
                <div className="text-xs text-zinc-600">Findings and scan data are scoped to a project. Select one to get started.</div>
              </div>
            </div>
            <button
              onClick={() => navigate('/projects')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-green-700 hover:bg-green-600 text-white text-xs font-medium transition-colors"
            >
              <FolderOpen size={12} /> Select project <ArrowRight size={12} />
            </button>
          </div>
        )}

        {/* Stats grid */}
        <div className="grid grid-cols-4 gap-4">
          <StatCard
            icon={Globe}
            label="HTTP Flows"
            value={hasProject ? flows.length : 0}
            color="bg-blue-500/10 text-blue-500"
            dimmed={!hasProject}
          />
          <StatCard
            icon={Radar}
            label="Subdomains"
            value={hasProject ? subdomains.length : 0}
            color="bg-cyan-500/10 text-cyan-500"
            dimmed={!hasProject}
          />
          <StatCard
            icon={Bug}
            label="Findings"
            value={findings.length}
            color="bg-amber-500/10 text-amber-500"
            dimmed={!hasProject}
          />
          <StatCard
            icon={Shield}
            label="Critical / High"
            value={hasProject ? `${criticalCount} / ${highCount}` : '0 / 0'}
            color="bg-red-500/10 text-red-500"
            dimmed={!hasProject}
          />
        </div>

        {/* Quick status */}
        <div className="grid grid-cols-2 gap-4">
          {/* Proxy status */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-5">
            <div className="flex items-center gap-2 mb-4">
              <Activity size={16} className="text-green-500" />
              <h3 className="font-semibold text-zinc-200">Proxy Status</h3>
            </div>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-zinc-500">Status</span>
                <Badge variant={proxyRunning ? 'default' : 'secondary'}>
                  {proxyRunning ? 'Running' : 'Stopped'}
                </Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-zinc-500">Total flows</span>
                <span className="text-zinc-300">{hasProject ? flows.length : 0}</span>
              </div>
            </div>
          </div>

          {/* Recent findings */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-5">
            <div className="flex items-center gap-2 mb-4">
              <ScanSearch size={16} className="text-amber-500" />
              <h3 className="font-semibold text-zinc-200">Recent Findings</h3>
              {hasProject && activeProjectData && (
                <span className="ml-auto text-[10px] text-zinc-600 truncate max-w-[120px]">{activeProjectData.name}</span>
              )}
            </div>
            {!hasProject ? (
              <p className="text-sm text-zinc-600">Select a project to see findings.</p>
            ) : findings.length === 0 ? (
              <p className="text-sm text-zinc-500">No findings yet. Run a scan.</p>
            ) : (
              <div className="space-y-2">
                {findings.slice(0, 5).map((f) => (
                  <div key={f.id} className="flex items-center justify-between text-sm gap-2">
                    <span className="text-zinc-300 truncate">{f.title}</span>
                    <Badge variant={f.severity as 'critical' | 'high' | 'medium' | 'low' | 'info'} className="shrink-0">
                      {f.severity}
                    </Badge>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Welcome when truly empty */}
        {!hasProject && (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <div className="rounded-full bg-green-500/10 p-6 mb-4">
              <Swords size={40} className="text-green-500" />
            </div>
            <h2 className="text-xl font-bold text-zinc-200 mb-2">Welcome to NexHunt</h2>
            <p className="text-zinc-500 max-w-md text-sm">
              Create or select a project to start hunting. All findings, scans and history are stored per-project.
            </p>
          </div>
        )}
      </div>
    </WorkspaceShell>
  )
}
