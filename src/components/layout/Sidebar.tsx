import { useState } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { useAppStore } from '@/stores/app-store'
import { useLicenseStore } from '@/stores/license-store'
import {
  LayoutDashboard,
  Globe,
  Radar,
  ScanSearch,
  Swords,
  Bot,
  FolderOpen,
  Settings,
  ChevronLeft,
  ChevronRight,
  TerminalSquare,
  BookOpen,
  FlaskConical,
  KeyRound,
  ChevronDown,
  ChevronUp,
  ShieldCheck,
  Lock,
  Crown,
} from 'lucide-react'

const navSections = [
  {
    title: 'Workflow',
    items: [
      { path: '/recon',          icon: Radar,        label: 'Recon',           requiresProject: true  },
      { path: '/proxy',          icon: Globe,         label: 'Proxy',           requiresProject: true  },
      { path: '/scanner',        icon: ScanSearch,    label: 'Scanner',         requiresProject: true  },
      { path: '/security-tools', icon: ShieldCheck,   label: 'Security Tools',  requiresProject: true  },
      { path: '/exploit',        icon: Swords,        label: 'Exploit',         requiresProject: true  },
      { path: '/workspace',      icon: BookOpen,      label: 'Workspace',       requiresProject: true  },
    ],
  },
  {
    title: 'Assist',
    items: [
      { path: '/methodology', icon: FlaskConical,  label: 'Methodology', requiresProject: false },
      { path: '/copilot',     icon: Bot,           label: 'AI Copilot',  requiresProject: false, pro: true },
      { path: '/terminal',    icon: TerminalSquare, label: 'Terminal',   requiresProject: false },
    ],
  },
]

function NHLogo({ size = 32 }: { size?: number }) {
  return (
    <svg
      viewBox="0 0 36 36"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      className="shrink-0 text-green-500"
    >
      <circle cx="18" cy="18" r="11" stroke="currentColor" strokeWidth="1.5"/>
      <line x1="18" y1="3"  x2="18" y2="8"  stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
      <line x1="18" y1="28" x2="18" y2="33" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
      <line x1="3"  y1="18" x2="8"  y2="18" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
      <line x1="28" y1="18" x2="33" y2="18" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
      <text
        x="18" y="22.5"
        textAnchor="middle"
        fill="currentColor"
        fontSize="10"
        fontWeight="700"
        fontFamily="'Space Grotesk Variable', monospace"
        letterSpacing="0.5"
      >NH</text>
    </svg>
  )
}

function SectionLabel({ title, collapsed }: { title: string; collapsed: boolean }) {
  if (collapsed) return null
  return (
    <div className="flex items-center gap-2 px-3 pt-3 pb-1">
      <span className="text-[9px] font-semibold tracking-[0.16em] text-zinc-600 uppercase whitespace-nowrap">
        {title}
      </span>
      <div className="flex-1 h-px bg-zinc-800/70" />
    </div>
  )
}

function NavItem({
  path,
  icon: Icon,
  label,
  locked,
  collapsed,
  proLocked,
}: {
  path: string
  icon: typeof Globe
  label: string
  locked: boolean
  collapsed: boolean
  proLocked?: boolean
}) {
  return (
    <NavLink
      to={path}
      className={({ isActive }) =>
        cn(
          'flex items-center gap-2.5 rounded-md px-2.5 py-[7px] text-[13px] font-medium transition-colors',
          locked
            ? 'text-zinc-700 cursor-default pointer-events-none'
            : isActive
              ? 'bg-green-950/35 text-green-400 ring-1 ring-inset ring-green-900/50'
              : 'text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800/40'
        )
      }
      title={locked ? 'Select a project first' : label}
    >
      <Icon size={15} className="shrink-0" />
      {!collapsed && <span className="truncate flex-1">{label}</span>}
      {!collapsed && proLocked && (
        <Lock size={11} className="shrink-0 text-amber-500/70" />
      )}
    </NavLink>
  )
}

export function Sidebar() {
  const {
    sidebarCollapsed, toggleSidebar, backendConnected, activeProject, activeProjectData,
    sessionCookies, sessionHeaders, setSessionCookies, setSessionHeaders,
  } = useAppStore()
  const navigate = useNavigate()
  const isPro = useLicenseStore((s) => s.status?.tier === 'pro')
  const [sessionOpen, setSessionOpen] = useState(false)
  const hasSession = !!(sessionCookies.trim() || sessionHeaders.trim())
  const hasProject = !!activeProject

  return (
    <aside
      className={cn(
        'flex flex-col border-r border-zinc-800/80 bg-zinc-950 transition-all duration-200',
        sidebarCollapsed ? 'w-[52px]' : 'w-52'
      )}
    >
      {/* Brand */}
      <div className={cn(
        'flex h-12 items-center border-b border-zinc-800/80',
        sidebarCollapsed ? 'justify-center px-2' : 'gap-2.5 px-3'
      )}>
        <NHLogo size={30} />
        {!sidebarCollapsed && (
          <div className="flex flex-col leading-none">
            <span className="text-[15px] font-semibold tracking-tight text-zinc-100">
              Nex<span className="text-green-500">Hunt</span>
            </span>
            <span className="text-[9px] text-zinc-600 tracking-widest uppercase mt-0.5">
              by Sentinel Security
            </span>
          </div>
        )}
      </div>

      {/* Active project */}
      <div
        className={cn(
          'border-b border-zinc-800/80 cursor-pointer transition-colors hover:bg-zinc-900/50',
          sidebarCollapsed ? 'flex justify-center px-2 py-2.5' : 'px-3 py-2.5'
        )}
        onClick={() => navigate('/projects')}
        title={hasProject ? `Project: ${activeProjectData?.name}` : 'Select a project'}
      >
        {sidebarCollapsed ? (
          <div className={cn(
            'flex items-center justify-center w-7 h-7 rounded-md',
            hasProject ? 'bg-green-900/30 text-green-400' : 'bg-zinc-900/60 text-zinc-600'
          )}>
            <FolderOpen size={13} />
          </div>
        ) : (
          <div className="flex items-center gap-2 min-w-0">
            <FolderOpen size={12} className={cn('shrink-0', hasProject ? 'text-green-500' : 'text-zinc-600')} />
            <div className="flex-1 min-w-0">
              {hasProject ? (
                <>
                  <div className="text-[8px] text-zinc-600 uppercase tracking-widest">Active project</div>
                  <div className="text-[12px] font-medium text-green-400 truncate leading-tight mt-0.5">
                    {activeProjectData?.name ?? '...'}
                  </div>
                </>
              ) : (
                <>
                  <div className="text-[8px] text-zinc-600 uppercase tracking-widest">No project</div>
                  <div className="text-[12px] text-zinc-600 leading-tight mt-0.5">Select one →</div>
                </>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Session */}
      <div className={cn('border-b border-zinc-800/80', sidebarCollapsed ? 'px-2 py-2' : 'px-3 py-2')}>
        {sidebarCollapsed ? (
          <button
            onClick={() => { toggleSidebar(); setSessionOpen(true) }}
            className={cn(
              'flex items-center justify-center w-7 h-7 rounded-md transition-colors',
              hasSession ? 'bg-green-900/30 text-green-400' : 'bg-zinc-900/40 text-zinc-600 hover:text-zinc-400'
            )}
            title={hasSession ? 'Session active' : 'Set session'}
          >
            <KeyRound size={12} />
          </button>
        ) : (
          <>
            <button
              onClick={() => setSessionOpen(o => !o)}
              className="w-full flex items-center justify-between gap-2 group"
            >
              <div className="flex items-center gap-1.5">
                <KeyRound size={10} className={hasSession ? 'text-green-500' : 'text-zinc-600'} />
                <span className={cn(
                  'text-[9px] uppercase tracking-[0.14em] font-semibold',
                  hasSession ? 'text-green-500' : 'text-zinc-600'
                )}>
                  Session
                </span>
                {hasSession && <span className="w-1 h-1 rounded-full bg-green-500 shrink-0" />}
              </div>
              {sessionOpen
                ? <ChevronUp size={9} className="text-zinc-600" />
                : <ChevronDown size={9} className="text-zinc-600" />}
            </button>

            {sessionOpen && (
              <div className="mt-2 space-y-2">
                <div className="space-y-1">
                  <label className="text-[8px] text-zinc-600 uppercase tracking-widest">Cookies</label>
                  <input
                    type="text"
                    placeholder="PHPSESSID=abc; token=xyz"
                    value={sessionCookies}
                    onChange={e => setSessionCookies(e.target.value)}
                    className="w-full text-[10px] bg-zinc-900/60 border border-zinc-800 rounded px-2 py-1 text-zinc-300 placeholder:text-zinc-700 focus:outline-none focus:border-zinc-600 font-mono"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-[8px] text-zinc-600 uppercase tracking-widest">Extra Headers</label>
                  <textarea
                    placeholder={"Authorization: Bearer eyJ...\nX-API-Key: secret"}
                    value={sessionHeaders}
                    onChange={e => setSessionHeaders(e.target.value)}
                    rows={2}
                    className="w-full text-[10px] bg-zinc-900/60 border border-zinc-800 rounded px-2 py-1 text-zinc-300 placeholder:text-zinc-700 focus:outline-none focus:border-zinc-600 font-mono resize-none"
                  />
                </div>
                {hasSession && (
                  <button
                    onClick={() => { setSessionCookies(''); setSessionHeaders('') }}
                    className="text-[9px] text-zinc-700 hover:text-red-400 transition-colors"
                  >
                    Clear session
                  </button>
                )}
              </div>
            )}
          </>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto p-1.5 space-y-0.5">
        <NavLink
          to="/"
          className={({ isActive }) =>
            cn(
              'flex items-center gap-2.5 rounded-md px-2.5 py-[7px] text-[13px] font-medium transition-colors',
              isActive
                ? 'bg-green-950/35 text-green-400 ring-1 ring-inset ring-green-900/50'
                : 'text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800/40'
            )
          }
        >
          <LayoutDashboard size={15} className="shrink-0" />
          {!sidebarCollapsed && <span>Dashboard</span>}
        </NavLink>

        {navSections.map((section, si) => (
          <div key={section.title} className={si > 0 ? 'pt-1' : ''}>
            <SectionLabel
              title={section.title === 'Workflow' && !hasProject ? 'Workflow — select project' : section.title}
              collapsed={sidebarCollapsed}
            />
            {section.items.map((item) => (
              <NavItem
                key={item.path}
                path={item.path}
                icon={item.icon}
                label={item.label}
                locked={item.requiresProject && !hasProject}
                collapsed={sidebarCollapsed}
                proLocked={'pro' in item && item.pro && !isPro}
              />
            ))}
          </div>
        ))}
      </nav>

      {/* Bottom */}
      <div className="border-t border-zinc-800/80 p-1.5 space-y-0.5">
        {/* License tier */}
        <button
          onClick={() => navigate('/settings?tab=license')}
          className={cn(
            'flex w-full items-center rounded-md px-2.5 py-[7px] transition-colors hover:bg-zinc-800/40',
            sidebarCollapsed ? 'justify-center' : 'gap-2.5'
          )}
          title={isPro ? 'NexHunt PRO — manage license' : 'Free plan — upgrade to PRO'}
        >
          <Crown size={15} className={cn('shrink-0', isPro ? 'text-amber-400' : 'text-zinc-600')} />
          {!sidebarCollapsed && (
            isPro ? (
              <span className="text-[11px] font-semibold text-amber-400">PRO</span>
            ) : (
              <span className="text-[11px] font-medium text-zinc-500">Free <span className="text-amber-500/70">· Upgrade</span></span>
            )
          )}
        </button>

        {/* Connection status */}
        <div className={cn(
          'flex items-center gap-2.5 px-2.5 py-[7px] text-[11px]',
          sidebarCollapsed ? 'justify-center' : ''
        )}>
          <span className={cn(
            'w-1.5 h-1.5 rounded-full shrink-0',
            backendConnected
              ? 'bg-green-500 shadow-[0_0_5px_1px_rgba(0,217,166,0.55)]'
              : 'bg-red-500'
          )} />
          {!sidebarCollapsed && (
            <span className={backendConnected ? 'text-zinc-600' : 'text-red-500'}>
              {backendConnected ? 'Backend online' : 'Backend offline'}
            </span>
          )}
        </div>

        <NavLink
          to="/settings"
          className={({ isActive }) =>
            cn(
              'flex items-center gap-2.5 rounded-md px-2.5 py-[7px] text-[13px] font-medium transition-colors',
              isActive
                ? 'bg-green-950/35 text-green-400 ring-1 ring-inset ring-green-900/50'
                : 'text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800/40'
            )
          }
        >
          <Settings size={15} className="shrink-0" />
          {!sidebarCollapsed && <span>Settings</span>}
        </NavLink>

        <NavLink
          to="/projects"
          className={({ isActive }) =>
            cn(
              'flex items-center gap-2.5 rounded-md px-2.5 py-[7px] text-[13px] font-medium transition-colors',
              isActive
                ? 'bg-green-950/35 text-green-400 ring-1 ring-inset ring-green-900/50'
                : 'text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800/40'
            )
          }
        >
          <FolderOpen size={15} className="shrink-0" />
          {!sidebarCollapsed && <span>Projects</span>}
        </NavLink>

        <button
          onClick={toggleSidebar}
          className="flex w-full items-center gap-2.5 rounded-md px-2.5 py-[7px] text-[13px] font-medium text-zinc-600 hover:text-zinc-300 hover:bg-zinc-800/40 transition-colors"
        >
          {sidebarCollapsed ? <ChevronRight size={15} className="shrink-0" /> : <ChevronLeft size={15} className="shrink-0" />}
          {!sidebarCollapsed && <span>Collapse</span>}
        </button>
      </div>
    </aside>
  )
}
