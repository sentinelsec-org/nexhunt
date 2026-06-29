import { HashRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useEffect } from 'react'
import { Sidebar } from '@/components/layout/Sidebar'
import { ProjectGate } from '@/components/layout/ProjectGate'
import { ProGate } from '@/components/layout/ProGate'
import { ErrorBoundary } from '@/components/layout/ErrorBoundary'
import { Toaster } from '@/components/ui/toast'
import { UpgradeModal } from '@/components/ui/UpgradeModal'
import { ProSplash } from '@/components/ui/ProSplash'
import { UpdateBanner } from '@/components/layout/UpdateBanner'
import { DashboardPage } from '@/pages/DashboardPage'
import { ProxyPage } from '@/pages/ProxyPage'
import { ReconPage } from '@/pages/ReconPage'
import { ScanPage } from '@/pages/ScanPage'
import { OffensePage } from '@/pages/OffensePage'
import { CopilotPage } from '@/pages/CopilotPage'
import { ProjectsPage } from '@/pages/ProjectsPage'
import { SettingsPage } from '@/pages/SettingsPage'
import { TerminalPage } from '@/pages/TerminalPage'
import { MethodologyPage } from '@/pages/MethodologyPage'
import { WorkspacePage } from '@/pages/WorkspacePage'
import { ExposureIntelPage } from '@/pages/ExposureIntelPage'
import { useAppStore } from '@/stores/app-store'
import { useProxyStore } from '@/stores/proxy-store'
import { useScannerStore } from '@/stores/scanner-store'
import { useReconStore } from '@/stores/recon-store'
import type { LiveHostResult } from '@/stores/recon-store'
import { usePipelineStore } from '@/stores/pipeline-store'
import { useWordPressStore } from '@/stores/wordpress-store'
import { useApiScannerStore } from '@/stores/api-scanner-store'
import type { ApiEndpointRow } from '@/stores/api-scanner-store'
import { useLicenseStore } from '@/stores/license-store'
import { wsClient } from '@/api/ws-client'
import { api } from '@/api/http-client'
import { toast } from '@/stores/toast-store'
import { API_BASE } from '@/lib/constants'
import type { HttpFlow, Finding, SubdomainResult, Project, PipelineEvent } from '@/types'

function App() {
  const { setBackendConnected, activeProject, setActiveProjectData } = useAppStore()
  const {
    addFlow, setProxyRunning, addIntruderResult, setIntruderRunning,
    addToInterceptQueue, removeFromInterceptQueue,
  } = useProxyStore()
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

  // Load recon results from DB — scoped to the active project
  const loadReconResults = async (projectId: string | null) => {
    useReconStore.getState().clearRecon()
    if (!projectId) return
    try {
      const recon = await api.get<Record<string, any[]>>(`/api/recon/results?project_id=${projectId}`)
      if (recon.subdomain) addSubdomains(recon.subdomain)
      if (recon.live_host) addLiveHosts(recon.live_host)
      if (recon.url) addUrls(recon.url)
      if (recon.port) addPorts(recon.port)
      if (recon.screenshot) addScreenshots(recon.screenshot)
      if (recon.endpoint) addEndpoints(recon.endpoint)
    } catch {}
  }

  useEffect(() => {
    useLicenseStore.getState().fetchStatus()
  }, [])

  // Reload findings + recon results when active project changes (and on initial mount)
  useEffect(() => {
    useScannerStore.getState().clearFindings()
    loadFindings(activeProject)
    loadReconResults(activeProject)
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

    const unsubProxyIntercept = wsClient.subscribe('proxy_intercept', (data) => {
      addToInterceptQueue(data as HttpFlow)
    })

    const unsubProxyInterceptResolved = wsClient.subscribe('proxy_intercept_resolved', (data) => {
      removeFromInterceptQueue((data as { id: string }).id)
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
      const result = data as { tool: string; type: string; results: any[]; project_id?: string }
      const currentProject = useAppStore.getState().activeProject
      // Only add recon results that belong to the active project (or have no project filter)
      if (currentProject && result.project_id && result.project_id !== currentProject) return

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
      const scannerTools = ['nuclei', 'ffuf', 'nikto', 'gobuster', 'dirsearch', 'sqlmap', 'dalfox', 'xsstrike', 'commix', 'cors', 'bypass_403', 'cloud_buckets', 'github_scanner', 'interactsh', 'exploit_intel', 'js_api_mapper', 'graphql_audit']
      if (scannerTools.includes(status.tool)) {
        const s = data as { tool: string; event: string; job_id?: string }
        setScanRunning(s.tool, s.event === 'started')
        if (s.event === 'started' && s.job_id) setJobId(s.tool, s.job_id)
        if (s.event === 'completed' || s.event === 'failed' || s.event === 'cancelled') setJobId(s.tool, null)
      }

      // Track API Scanner running state + job ID via WS
      if (status.tool === 'api_scanner') {
        const s = data as { tool: string; event: string; job_id?: string }
        if (s.event === 'started') useApiScannerStore.getState().setRunning(true, s.job_id ?? null)
        if (s.event === 'completed' || s.event === 'failed' || s.event === 'cancelled') {
          useApiScannerStore.getState().setRunning(false, null)
        }
      }

      // Track WordPress (wpscan) running state + job ID via WS
      if (status.tool === 'wpscan') {
        const s = data as { tool: string; event: string; job_id?: string }
        if (s.event === 'started') useWordPressStore.getState().setRunning(true, s.job_id ?? null)
        if (s.event === 'completed' || s.event === 'failed' || s.event === 'cancelled') {
          useWordPressStore.getState().setRunning(false, null)
        }
      }

      // Track recon tool running state + job IDs via WS
      const reconTools = ['subfinder', 'amass', 'crtsh', 'httpx', 'httpx-probe', 'httpx-probe-all', 'nmap', 'waybackurls', 'gau', 'katana', 'katana-headless', 'linkfinder', 'paramspider', 'arjun', 'full_recon', 'endpoint_check']
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

    const unsubWordpress = wsClient.subscribe('wordpress', (data) => {
      useWordPressStore.getState().handleResult(data)
    })

    const unsubApiScan = wsClient.subscribe('api_scan', (data) => {
      useApiScannerStore.getState().addRow(data as ApiEndpointRow)
    })

    const unsubToolOutput = wsClient.subscribe('tool_output', (data) => {
      const d = data as { tool: string; line: string }
      if (d.tool === 'wpscan') {
        useWordPressStore.getState().appendLog(d.line)
        return
      }
      if (d.tool === 'api_scanner') {
        useApiScannerStore.getState().appendOutput(d.line)
        return
      }
      if (d.tool && d.line) appendToolOutput(d.tool, d.line)
    })

    const unsubIntruder = wsClient.subscribe('intruder', (data) => {
      const d = data as { event: string; job_id: string; total?: number; index?: number; payload?: string; status?: number; length?: number; duration_ms?: number; error?: string | null; request?: string; response_headers?: Record<string, string>; response_body?: string; content_type?: string }
      if (d.event === 'started') {
        setIntruderRunning(true, d.job_id, d.total)
      } else if (d.event === 'result') {
        addIntruderResult({ index: d.index!, payload: d.payload!, status: d.status!, length: d.length!, duration_ms: d.duration_ms!, error: d.error ?? null, request: d.request ?? '', response_headers: d.response_headers ?? {}, response_body: d.response_body ?? '', content_type: d.content_type ?? '' })
      } else if (d.event === 'completed' || d.event === 'cancelled' || d.event === 'error') {
        setIntruderRunning(false, null)
      }
    })

    return () => {
      clearInterval(healthInterval)
      unsubProxy()
      unsubProxyIntercept()
      unsubProxyInterceptResolved()
      unsubFindings()
      unsubRecon()
      unsubStatus()
      unsubPipeline()
      unsubWordpress()
      unsubApiScan()
      unsubToolOutput()
      unsubIntruder()
      wsClient.disconnect()
    }
  }, [])

  return (
    <HashRouter>
      <div className="relative flex h-screen w-screen overflow-hidden bg-zinc-950">
        <UpdateBanner />
        <Sidebar />
        <ErrorBoundary>
          <Routes>
            {/* Always accessible */}
            <Route path="/" element={<ProjectsPage />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/projects" element={<ProjectsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/exposure-intel" element={<ExposureIntelPage />} />

            {/* Project-required pages — blocked by ProjectGate when no project is active */}
            <Route path="/proxy" element={<ProjectGate><ProxyPage /></ProjectGate>} />
            <Route path="/recon" element={<ProjectGate><ReconPage /></ProjectGate>} />
            <Route path="/scan" element={<ProjectGate><ScanPage /></ProjectGate>} />
            <Route path="/offense" element={<ProjectGate><OffensePage /></ProjectGate>} />
            <Route path="/workspace" element={<ProjectGate><WorkspacePage /></ProjectGate>} />

            {/* Back-compat redirects for the old flat routes */}
            <Route path="/scanner" element={<Navigate to="/scan?tab=scanner" replace />} />
            <Route path="/api-scanner" element={<Navigate to="/scan?tab=api" replace />} />
            <Route path="/repository-intelligence" element={<Navigate to="/scan?tab=repository" replace />} />
            <Route path="/wordpress" element={<Navigate to="/scan?tab=wordpress" replace />} />
            <Route path="/pipelines" element={<Navigate to="/scan?tab=pipelines" replace />} />
            <Route path="/security-tools" element={<Navigate to="/offense?tab=attacks" replace />} />
            <Route path="/graphql" element={<Navigate to="/offense?tab=graphql" replace />} />
            <Route path="/exploit" element={<Navigate to="/offense?tab=injection" replace />} />
            <Route path="/brute-force" element={<Navigate to="/offense?tab=brute" replace />} />
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
