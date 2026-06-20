import type { ReactNode } from 'react'
import { TopBar } from './TopBar'

interface WorkspaceShellProps {
  title: string
  subtitle?: string
  children: ReactNode
}

export function WorkspaceShell({ title, subtitle, children }: WorkspaceShellProps) {
  return (
    <div className="workspace-shell flex flex-1 flex-col overflow-hidden">
      <TopBar title={title} subtitle={subtitle} />
      <main className="workspace-main flex-1 overflow-auto p-4">
        {children}
      </main>
    </div>
  )
}
