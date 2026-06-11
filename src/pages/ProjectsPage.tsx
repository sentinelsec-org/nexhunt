import { useState, useEffect } from 'react'
import { WorkspaceShell } from '@/components/layout/WorkspaceShell'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { useAppStore } from '@/stores/app-store'
import { api } from '@/api/http-client'
import type { Project } from '@/types'
import {
  FolderOpen,
  Plus,
  Check,
  Trash2,
  X,
  Globe,
  StickyNote,
  Target,
  ShieldOff,
  ShieldCheck,
} from 'lucide-react'
import { cn } from '@/lib/utils'

export function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([])
  const [newName, setNewName] = useState('')
  const [newScopeInput, setNewScopeInput] = useState('')
  const [newScopeList, setNewScopeList] = useState<string[]>([])
  const [newOutScopeInput, setNewOutScopeInput] = useState('')
  const [newOutScopeList, setNewOutScopeList] = useState<string[]>([])
  const [newScopeMode, setNewScopeMode] = useState<'strict' | 'permissive'>('strict')
  const [newNotes, setNewNotes] = useState('')
  const [creating, setCreating] = useState(false)
  const [editingScope, setEditingScope] = useState<string | null>(null)
  const [editingOutScope, setEditingOutScope] = useState<string | null>(null)
  const [scopeInput, setScopeInput] = useState('')
  const [outScopeInput, setOutScopeInput] = useState('')
  const { activeProject, setActiveProject, setActiveProjectData } = useAppStore()

  const fetchProjects = async () => {
    try {
      const data = await api.get<Project[]>('/api/projects')
      setProjects(data)
      if (activeProject) {
        const active = data.find(p => p.id === activeProject)
        if (active) setActiveProjectData(active)
      }
    } catch {}
  }

  useEffect(() => { fetchProjects() }, [])

  const handleCreate = async () => {
    if (!newName.trim()) return
    setCreating(true)
    try {
      await api.post('/api/projects', {
        name: newName.trim(),
        scope: newScopeList,
        out_of_scope: newOutScopeList,
        scope_mode: newScopeMode,
        notes: newNotes.trim() || undefined,
      })
      setNewName(''); setNewScopeList([]); setNewScopeInput('')
      setNewOutScopeList([]); setNewOutScopeInput(''); setNewNotes('')
      await fetchProjects()
    } finally { setCreating(false) }
  }

  const handleDelete = async (id: string) => {
    try {
      await api.delete(`/api/projects/${id}`)
      if (activeProject === id) { setActiveProject(null); setActiveProjectData(null) }
      await fetchProjects()
    } catch {}
  }

  const handleSetActive = (project: Project) => {
    setActiveProject(project.id)
    setActiveProjectData(project)
  }

  const addScopeDomain = async (project: Project, domain: string, type: 'in' | 'out') => {
    const update = type === 'in'
      ? { scope: [...project.scope, domain] }
      : { out_of_scope: [...(project.out_of_scope || []), domain] }
    try {
      await api.put(`/api/projects/${project.id}`, update)
      await fetchProjects()
      if (type === 'in') { setScopeInput(''); setEditingScope(null) }
      else { setOutScopeInput(''); setEditingOutScope(null) }
    } catch {}
  }

  const removeScopeDomain = async (project: Project, domain: string, type: 'in' | 'out') => {
    const update = type === 'in'
      ? { scope: project.scope.filter(d => d !== domain) }
      : { out_of_scope: (project.out_of_scope || []).filter(d => d !== domain) }
    try {
      await api.put(`/api/projects/${project.id}`, update)
      await fetchProjects()
    } catch {}
  }

  const toggleScopeMode = async (project: Project) => {
    const newMode = project.scope_mode === 'strict' ? 'permissive' : 'strict'
    try {
      await api.put(`/api/projects/${project.id}`, { scope_mode: newMode })
      await fetchProjects()
    } catch {}
  }

  return (
    <WorkspaceShell title="Projects" subtitle="Manage bug bounty targets and scope">
      <div className="space-y-6 max-w-3xl">

        {/* Create */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-5">
          <h3 className="font-semibold text-zinc-200 mb-4 flex items-center gap-2 text-sm">
            <Plus size={15} /> New Project
          </h3>
          <div className="space-y-3">
            <Input
              placeholder="Project name (e.g., HackerOne — Example Corp)"
              className="bg-zinc-900"
              value={newName}
              onChange={e => setNewName(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleCreate()}
            />

            <ScopeInputRow
              label="In-scope" icon={<Globe size={11} />} color="text-green-400"
              placeholder="*.example.com" input={newScopeInput}
              list={newScopeList}
              onInputChange={setNewScopeInput}
              onAdd={() => { const v = newScopeInput.trim(); if (v && !newScopeList.includes(v)) { setNewScopeList(p => [...p, v]); setNewScopeInput('') } }}
              onRemove={d => setNewScopeList(p => p.filter(x => x !== d))}
              tagClass="border-green-800 text-green-300"
            />

            <ScopeInputRow
              label="Out-of-scope" icon={<ShieldOff size={11} />} color="text-red-400"
              placeholder="staging.example.com" input={newOutScopeInput}
              list={newOutScopeList}
              onInputChange={setNewOutScopeInput}
              onAdd={() => { const v = newOutScopeInput.trim(); if (v && !newOutScopeList.includes(v)) { setNewOutScopeList(p => [...p, v]); setNewOutScopeInput('') } }}
              onRemove={d => setNewOutScopeList(p => p.filter(x => x !== d))}
              tagClass="border-red-900 text-red-400"
            />

            <div className="flex items-center gap-3">
              <span className="text-xs text-zinc-500">Scope mode:</span>
              <button
                onClick={() => setNewScopeMode(m => m === 'strict' ? 'permissive' : 'strict')}
                className={cn('flex items-center gap-1.5 text-xs px-3 py-1 rounded border transition-colors',
                  newScopeMode === 'strict'
                    ? 'border-orange-700 bg-orange-950/30 text-orange-300'
                    : 'border-zinc-700 text-zinc-400 hover:border-zinc-600'
                )}
              >
                <ShieldCheck size={11} />
                {newScopeMode === 'strict' ? 'Strict — block out-of-scope tools' : 'Permissive — warn only'}
              </button>
            </div>

            <Input
              placeholder="Notes (platform, program URL, rules...)"
              className="bg-zinc-900 text-sm"
              value={newNotes}
              onChange={e => setNewNotes(e.target.value)}
            />

            <Button onClick={handleCreate} disabled={!newName.trim() || creating} size="sm">
              <Plus size={13} className="mr-1" /> Create Project
            </Button>
          </div>
        </div>

        {/* List */}
        <div className="space-y-3">
          {projects.map(project => (
            <div
              key={project.id}
              className={cn(
                'rounded-xl border bg-zinc-900/50 p-5 transition-colors',
                activeProject === project.id ? 'border-green-500/40 bg-green-950/10' : 'border-zinc-800 hover:border-zinc-700'
              )}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0 space-y-3">
                  <h3 className="font-semibold text-zinc-200 flex items-center gap-2 text-sm">
                    <FolderOpen size={14} className={activeProject === project.id ? 'text-green-500' : 'text-zinc-500'} />
                    {project.name}
                    {activeProject === project.id && (
                      <Badge className="text-[10px] bg-green-900/50 text-green-400 border-green-700">Active</Badge>
                    )}
                    <button
                      onClick={() => toggleScopeMode(project)}
                      title={`Scope mode: ${project.scope_mode ?? 'strict'} — click to toggle`}
                      className={cn('ml-1 flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border transition-colors',
                        (project.scope_mode ?? 'strict') === 'strict'
                          ? 'border-orange-800/50 bg-orange-950/20 text-orange-400'
                          : 'border-zinc-700 text-zinc-600 hover:border-zinc-600'
                      )}
                    >
                      <ShieldCheck size={9} />
                      {project.scope_mode ?? 'strict'}
                    </button>
                  </h3>

                  {/* In-scope */}
                  <ProjectScopeRow
                    label="In-scope" icon={<Target size={10} />}
                    domains={project.scope}
                    tagClass="border-green-900/50 text-green-300"
                    editing={editingScope === project.id}
                    inputValue={scopeInput}
                    placeholder="*.new-domain.com"
                    onInputChange={setScopeInput}
                    onStartEdit={() => { setEditingScope(project.id); setEditingOutScope(null); setScopeInput('') }}
                    onConfirm={() => scopeInput.trim() && addScopeDomain(project, scopeInput.trim(), 'in')}
                    onCancel={() => setEditingScope(null)}
                    onRemove={d => removeScopeDomain(project, d, 'in')}
                  />

                  {/* Out-of-scope */}
                  <ProjectScopeRow
                    label="Out-of-scope" icon={<ShieldOff size={10} />}
                    domains={project.out_of_scope || []}
                    tagClass="border-red-900/50 text-red-400"
                    editing={editingOutScope === project.id}
                    inputValue={outScopeInput}
                    placeholder="staging.example.com"
                    onInputChange={setOutScopeInput}
                    onStartEdit={() => { setEditingOutScope(project.id); setEditingScope(null); setOutScopeInput('') }}
                    onConfirm={() => outScopeInput.trim() && addScopeDomain(project, outScopeInput.trim(), 'out')}
                    onCancel={() => setEditingOutScope(null)}
                    onRemove={d => removeScopeDomain(project, d, 'out')}
                  />

                  {project.notes && (
                    <div className="flex items-start gap-1.5 text-[11px] text-zinc-500">
                      <StickyNote size={10} className="mt-0.5 shrink-0" />
                      <span className="line-clamp-2">{project.notes}</span>
                    </div>
                  )}
                  <div className="text-[10px] text-zinc-700">
                    Creado {new Date(project.created_at).toLocaleDateString('es-AR')}
                  </div>
                </div>

                <div className="flex flex-col gap-2 shrink-0">
                  {activeProject !== project.id && (
                    <Button variant="outline" size="sm" onClick={() => handleSetActive(project)} className="text-xs">
                      <Check size={11} className="mr-1" /> Activar
                    </Button>
                  )}
                  <Button variant="ghost" size="icon" className="text-zinc-600 hover:text-red-500 h-8 w-8" onClick={() => handleDelete(project.id)}>
                    <Trash2 size={13} />
                  </Button>
                </div>
              </div>
            </div>
          ))}

          {projects.length === 0 && (
            <div className="text-center py-16 text-zinc-600">
              <FolderOpen size={40} className="mx-auto mb-3 opacity-40" />
              <p className="text-sm">No hay proyectos. Crea uno para empezar.</p>
            </div>
          )}
        </div>
      </div>
    </WorkspaceShell>
  )
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function ScopeInputRow({ label, icon, color, placeholder, input, list, onInputChange, onAdd, onRemove, tagClass }: {
  label: string; icon: React.ReactNode; color: string; placeholder: string
  input: string; list: string[]
  onInputChange: (v: string) => void; onAdd: () => void; onRemove: (d: string) => void
  tagClass: string
}) {
  return (
    <div className="space-y-1.5">
      <label className={`text-xs flex items-center gap-1.5 ${color}`}>{icon} {label}</label>
      <div className="flex gap-2">
        <Input placeholder={placeholder} className="bg-zinc-900 text-sm flex-1" value={input}
          onChange={e => onInputChange(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && onAdd()} />
        <Button variant="outline" size="sm" onClick={onAdd} disabled={!input.trim()}><Plus size={12} /></Button>
      </div>
      {list.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {list.map((d, i) => (
            <span key={i} className={`flex items-center gap-1 text-xs bg-zinc-800 font-mono px-2 py-0.5 rounded border ${tagClass}`}>
              {d}
              <button onClick={() => onRemove(d)} className="text-zinc-600 hover:text-red-400"><X size={10} /></button>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

function ProjectScopeRow({ label, icon, domains, tagClass, editing, inputValue, placeholder, onInputChange, onStartEdit, onConfirm, onCancel, onRemove }: {
  label: string; icon: React.ReactNode; domains: string[]; tagClass: string
  editing: boolean; inputValue: string; placeholder: string
  onInputChange: (v: string) => void; onStartEdit: () => void
  onConfirm: () => void; onCancel: () => void; onRemove: (d: string) => void
}) {
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-1 text-[11px] text-zinc-600">{icon} {label}</div>
      <div className="flex flex-wrap gap-1.5">
        {domains.map((d, i) => (
          <span key={i} className={`flex items-center gap-1 text-[11px] bg-zinc-800/80 font-mono px-2 py-0.5 rounded border ${tagClass}`}>
            {d}
            <button onClick={() => onRemove(d)} className="text-zinc-700 hover:text-red-400"><X size={9} /></button>
          </span>
        ))}
        {editing ? (
          <div className="flex items-center gap-1">
            <input autoFocus type="text" placeholder={placeholder} value={inputValue}
              onChange={e => onInputChange(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') onConfirm(); if (e.key === 'Escape') onCancel() }}
              className="text-[11px] bg-zinc-900 border border-zinc-700 rounded px-2 py-0.5 text-zinc-300 font-mono focus:outline-none focus:border-zinc-500 w-44" />
            <button onClick={onConfirm} className="text-green-500 hover:text-green-400"><Check size={12} /></button>
            <button onClick={onCancel} className="text-zinc-600 hover:text-zinc-400"><X size={12} /></button>
          </div>
        ) : (
          <button onClick={onStartEdit}
            className="flex items-center gap-1 text-[11px] text-zinc-700 hover:text-zinc-400 border border-dashed border-zinc-800 hover:border-zinc-600 rounded px-2 py-0.5 transition-colors">
            <Plus size={9} /> add
          </button>
        )}
      </div>
    </div>
  )
}
