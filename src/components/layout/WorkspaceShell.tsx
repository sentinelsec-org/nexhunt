import type { ReactNode } from 'react'
import { TopBar } from './TopBar'

interface WorkspaceShellProps {
  title: string
  subtitle?: string
  children: ReactNode
}

export function WorkspaceShell({ title, subtitle, children }: WorkspaceShellProps) {
  return (
    <div className="flex flex-1 flex-col overflow-hidden">
      <TopBar title={title} subtitle={subtitle} />
      <main className="flex-1 overflow-auto p-4">
        {children}
      </main>
    </div>
  )
}
