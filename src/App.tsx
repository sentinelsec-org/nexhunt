import { HashRouter, Routes, Route } from 'react-router-dom'
import { useEffect } from 'react'
import { Sidebar } from '@/components/layout/Sidebar'
import { ProjectGate } from '@/components/layout/ProjectGate'
import { ProGate } from '@/components/layout/ProGate'
import { ErrorBoundary } from '@/components/layout/ErrorBoundary'
import { Toaster } from '@/components/ui/toast'
import { UpgradeModal } from '@/components/ui/UpgradeModal'
import { ProSplash } from '@/components/ui/ProSplash'
import { DashboardPage } from '@/pages/DashboardPage'
import { ProxyPage } from '@/pages/ProxyPage'
import { ReconPage } from '@/pages/ReconPage'
import { ScannerPage } from '@/pages/ScannerPage'
import { ExploitPage } from '@/pages/ExploitPage'
import { CopilotPage } from '@/pages/CopilotPage'
import { ProjectsPage } from '@/pages/ProjectsPage'
import { SettingsPage } from '@/pages/SettingsPage'
import { TerminalPage } from '@/pages/TerminalPage'
import { MethodologyPage } from '@/pages/MethodologyPage'
import { WorkspacePage } from '@/pages/WorkspacePage'
import { SecurityToolsPage } from '@/pages/SecurityToolsPage'
import { BruteForcePage } from '@/pages/BruteForcePage'
import { useAppStore } from '@/stores/app-store'
import { useProxyStore } from '@/stores/proxy-store'
import { useScannerStore } from '@/stores/scanner-store'
import { useReconStore } from '@/stores/recon-store'
import type { LiveHostResult } from '@/stores/recon-store'
import { usePipelineStore } from '@/stores/pipeline-store'
import { useLicenseStore } from '@/stores/license-store'
import { wsClient } from '@/api/ws-client'
import { api } from '@/api/http-client'
import { toast } from '@/stores/toast-store'
import { API_BASE } from '@/lib/constants'
import type { HttpFlow, Finding, SubdomainResult, Project, PipelineEvent } from '@/types'

function App() {
  const { setBackendConnected, activeProject, setActiveProjectData } = useAppStore()
  const { addFlow, setProxyRunning, addIntruderResult, setIntruderRunning } = useProxyStore()
  const { addFinding, appendToolOutput, setScanRunning, setJobId } = useScannerStore()
  const { addSubdomains, addUrls, addLiveHosts, addPorts, addScreenshots, addEndpoints, setScreenshotRunning, setReconToolRunning, setReconJobId } = useReconStore()
  const { handleEvent: handlePipelineEvent } = usePipelineStore()

  // Load findings from DB — only when a project is active
  const loadFindings = async (projectId: string | null) => {
    if (!projectId) {
      useScannerStore.getState().setFindings([])
      return
    }
    try {
      const findings = await api.get<Finding[]>(`/api/scanner/findings?project_id=${projectId}`)
      useScannerStore.getState().setFindings(findings)
    } catch {}
  }

  // Load persisted data from DB on startup
  useEffect(() => {
    const loadPersistedData = async () => {
      await loadFindings(useAppStore.getState().activeProject)
      useLicenseStore.getState().fetchStatus()
      try {
        const recon = await api.get<Record<string, any[]>>('/api/recon/results')
        if (recon.subdomain) addSubdomains(recon.subdomain)
        if (recon.live_host) addLiveHosts(recon.live_host)
        if (recon.url) addUrls(recon.url)
        if (recon.port) addPorts(recon.port)
        if (recon.screenshot) addScreenshots(recon.screenshot)
      } catch {}
    }
    // Small delay to let backend start
    setTimeout(loadPersistedData, 2000)
  }, [])

  // Reload findings when active project changes
  useEffect(() => {
    useScannerStore.getState().clearFindings()
    loadFindings(activeProject)
  }, [activeProject])

  // Fetch active project data whenever activeProject changes
  useEffect(() => {
    if (!activeProject) {
      setActiveProjectData(null)
      return
    }
    api.get<Project>(`/api/projects/${activeProject}`)
      .then(data => setActiveProjectData(data))
      .catch(() => setActiveProjectData(null))
  }, [activeProject])

  useEffect(() => {
    let wasConnected = true
    const checkHealth = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/health`)
        setBackendConnected(res.ok)
        if (res.ok && !wasConnected) toast.success('Backend reconnected')
        wasConnected = res.ok
      } catch {
        setBackendConnected(false)
        if (wasConnected) toast.error('Backend disconnected', 'Cannot reach the NexHunt backend')
        wasConnected = false
      }
    }

    checkHealth()
    const healthInterval = setInterval(checkHealth, 5000)

    wsClient.connect()

    const unsubProxy = wsClient.subscribe('proxy_feed', (data) => {
      addFlow(data as HttpFlow)
    })

    const unsubFindings = wsClient.subscribe('findings', (data) => {
      const f = data as Finding & { project_id?: string }
      const currentProject = useAppStore.getState().activeProject
      // Only add finding if it belongs to the active project (or no project filter)
      if (!currentProject || !f.project_id || f.project_id === currentProject) {
        addFinding(f)
      }
    })

    const unsubRecon = wsClient.subscribe('recon_results', (data) => {
      const result = data as { tool: string; type: string; results: any[] }

      if (result.type === 'subdomain') {
        addSubdomains(result.results as SubdomainResult[])
      } else if (result.type === 'live_host') {
        addLiveHosts(result.results as LiveHostResult[])
      } else if (result.type === 'url') {
        addUrls(result.results)
      } else if (result.type === 'port') {
        addPorts(result.results)
      } else if (result.type === 'screenshot') {
        addScreenshots(result.results)
      } else if (result.type === 'endpoint') {
        addEndpoints(result.results)
      }
    })

    const unsubStatus = wsClient.subscribe('tool_status', (data) => {
      const status = data as { tool: string; event: string; done?: number; total?: number; error?: string }
      if (status.event === 'failed') {
        toast.error(`${status.tool} failed`, status.error)
      }
      if (status.tool === 'proxy') {
        setProxyRunning(status.event === 'started')
      }
      if (status.tool === 'gowitness') {
        if (status.event === 'started') setScreenshotRunning(true, { done: 0, total: status.total ?? 0 })
        else if (status.event === 'progress') setScreenshotRunning(true, { done: status.done ?? 0, total: status.total ?? 0 })
        else if (status.event === 'completed' || status.event === 'failed') setScreenshotRunning(false)
      }
      // Track scanner + exploit tool running state + job IDs via WS
      const scannerTools = ['nuclei', 'ffuf', 'nikto', 'gobuster', 'dirsearch', 'sqlmap', 'dalfox', 'xsstrike', 'commix', 'cors', 'bypass_403', 'cloud_buckets', 'github_scanner', 'interactsh']
      if (scannerTools.includes(status.tool)) {
        const s = data as { tool: string; event: string; job_id?: string }
        setScanRunning(s.tool, s.event === 'started')
        if (s.event === 'started' && s.job_id) setJobId(s.tool, s.job_id)
        if (s.event === 'completed' || s.event === 'failed' || s.event === 'cancelled') setJobId(s.tool, null)
      }

      // Track recon tool running state + job IDs via WS
      const reconTools = ['subfinder', 'amass', 'httpx', 'httpx-probe', 'httpx-probe-all', 'nmap', 'waybackurls', 'gau', 'katana', 'katana-headless', 'linkfinder', 'paramspider', 'arjun', 'full_recon', 'endpoint_check']
      if (reconTools.includes(status.tool)) {
        const s = data as { tool: string; event: string; job_id?: string }
        setReconToolRunning(s.tool, s.event === 'started')
        if (s.event === 'started' && s.job_id) setReconJobId(s.tool, s.job_id)
        if (s.event === 'completed' || s.event === 'failed' || s.event === 'cancelled') setReconJobId(s.tool, null)
      }
    })

    const unsubPipeline = wsClient.subscribe('pipeline', (data) => {
      handlePipelineEvent(data as PipelineEvent)
    })

    const unsubToolOutput = wsClient.subscribe('tool_output', (data) => {
      const d = data as { tool: string; line: string }
      if (d.tool && d.line) appendToolOutput(d.tool, d.line)
    })

    const unsubIntruder = wsClient.subscribe('intruder', (data) => {
      const d = data as { event: string; job_id: string; total?: number; index?: number; payload?: string; status?: number; length?: number; duration_ms?: number; error?: string | null }
      if (d.event === 'started') {
        setIntruderRunning(true, d.job_id, d.total)
      } else if (d.event === 'result') {
        addIntruderResult({ index: d.index!, payload: d.payload!, status: d.status!, length: d.length!, duration_ms: d.duration_ms!, error: d.error ?? null })
      } else if (d.event === 'completed' || d.event === 'cancelled' || d.event === 'error') {
        setIntruderRunning(false, null)
      }
    })

    return () => {
      clearInterval(healthInterval)
      unsubProxy()
      unsubFindings()
      unsubRecon()
      unsubStatus()
      unsubPipeline()
      unsubToolOutput()
      unsubIntruder()
      wsClient.disconnect()
    }
  }, [])

  return (
    <HashRouter>
      <div className="flex h-screen w-screen overflow-hidden bg-zinc-950">
        <Sidebar />
        <ErrorBoundary>
          <Routes>
            {/* Always accessible */}
            <Route path="/" element={<ProjectsPage />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/projects" element={<ProjectsPage />} />
            <Route path="/settings" element={<SettingsPage />} />

            {/* Project-required pages — blocked by ProjectGate when no project is active */}
            <Route path="/proxy" element={<ProjectGate><ProxyPage /></ProjectGate>} />
            <Route path="/recon" element={<ProjectGate><ReconPage /></ProjectGate>} />
            <Route path="/scanner" element={<ProjectGate><ScannerPage /></ProjectGate>} />
            <Route path="/security-tools" element={<ProjectGate><SecurityToolsPage /></ProjectGate>} />
            <Route path="/exploit" element={<ProjectGate><ExploitPage /></ProjectGate>} />
            <Route path="/brute-force" element={<ProjectGate><ProGate feature="Brute force"><BruteForcePage /></ProGate></ProjectGate>} />
            <Route path="/workspace" element={<ProjectGate><WorkspacePage /></ProjectGate>} />
            <Route path="/copilot" element={<ProGate feature="AI Copilot"><CopilotPage /></ProGate>} />
            <Route path="/terminal" element={<TerminalPage />} />
            <Route path="/methodology" element={<MethodologyPage />} />
          </Routes>
        </ErrorBoundary>
        <Toaster />
        <UpgradeModal />
        <ProSplash />
      </div>
    </HashRouter>
  )
}

export default App
