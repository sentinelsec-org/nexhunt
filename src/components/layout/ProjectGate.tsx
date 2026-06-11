import { useNavigate } from 'react-router-dom'
import { useAppStore } from '@/stores/app-store'
import { FolderOpen, ArrowRight } from 'lucide-react'

interface ProjectGateProps {
  children: React.ReactNode
}

/**
 * Blocks access to any page that requires an active project.
 * Shows a full-page prompt to select or create a project.
 */
export function ProjectGate({ children }: ProjectGateProps) {
  const { activeProject, activeProjectData } = useAppStore()
  const navigate = useNavigate()

  if (!activeProject) {
    return (
      <div className="flex flex-1 items-center justify-center bg-zinc-950">
        <div className="text-center space-y-6 max-w-sm">
          <div className="flex justify-center">
            <div className="w-16 h-16 rounded-2xl bg-zinc-900 border border-zinc-800 flex items-center justify-center">
              <FolderOpen size={28} className="text-zinc-600" />
            </div>
          </div>

          <div>
            <h2 className="text-lg font-semibold text-zinc-200 mb-2">No project selected</h2>
            <p className="text-sm text-zinc-500 leading-relaxed">
              All findings, history, and scan results are scoped to a project.
              Select or create a project to get started.
            </p>
          </div>

          <button
            onClick={() => navigate('/projects')}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-green-700 hover:bg-green-600 text-white text-sm font-medium transition-colors"
          >
            <FolderOpen size={15} />
            Go to Projects
            <ArrowRight size={15} />
          </button>
        </div>
      </div>
    )
  }

  return <>{children}</>
}
