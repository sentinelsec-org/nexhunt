import json
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from nexhunt.database import get_session
from nexhunt.models.project import Project
from nexhunt.schemas.project import ProjectCreate, ProjectUpdate
from nexhunt.services.scope import is_in_scope, filter_urls

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.get("")
async def list_projects(session: AsyncSession = Depends(get_session)):
    """List all projects."""
    result = await session.execute(select(Project).order_by(Project.created_at.desc()))
    projects = result.scalars().all()
    return [_serialize(p) for p in projects]


@router.post("")
async def create_project(data: ProjectCreate, session: AsyncSession = Depends(get_session)):
    project = Project(
        name=data.name,
        scope=json.dumps(data.scope),
        out_of_scope=json.dumps(data.out_of_scope),
        scope_mode=data.scope_mode,
        notes=data.notes,
    )
    session.add(project)
    await session.commit()
    return {"id": project.id, "name": project.name}


@router.get("/{project_id}")
async def get_project(project_id: str, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        return {"error": "Project not found"}
    return _serialize(project)


@router.put("/{project_id}")
async def update_project(
    project_id: str, data: ProjectUpdate, session: AsyncSession = Depends(get_session)
):
    result = await session.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        return {"error": "Project not found"}

    if data.name is not None:
        project.name = data.name
    if data.scope is not None:
        project.scope = json.dumps(data.scope)
    if data.out_of_scope is not None:
        project.out_of_scope = json.dumps(data.out_of_scope)
    if data.scope_mode is not None:
        project.scope_mode = data.scope_mode
    if data.notes is not None:
        project.notes = data.notes

    await session.commit()
    return {"status": "updated"}


# ── Scope check endpoints ──────────────────────────────────────────────────────

class ScopeCheckRequest(BaseModel):
    urls: list[str]


@router.post("/{project_id}/scope-check")
async def scope_check(
    project_id: str,
    data: ScopeCheckRequest,
    session: AsyncSession = Depends(get_session),
):
    """Check which URLs are in/out of scope for a project."""
    result = await session.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        return {"error": "Project not found"}

    in_s = json.loads(project.scope) if project.scope else []
    out_s = json.loads(project.out_of_scope) if project.out_of_scope else []
    ins, outs = filter_urls(data.urls, in_s, out_s)
    return {"in_scope": ins, "out_of_scope": outs, "mode": project.scope_mode}


def _serialize(p: Project) -> dict:
    return {
        "id": p.id,
        "name": p.name,
        "scope": json.loads(p.scope) if p.scope else [],
        "out_of_scope": json.loads(p.out_of_scope) if getattr(p, 'out_of_scope', None) else [],
        "scope_mode": getattr(p, 'scope_mode', 'strict'),
        "notes": p.notes,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }


@router.delete("/{project_id}")
async def delete_project(project_id: str, session: AsyncSession = Depends(get_session)):
    """Delete a project."""
    result = await session.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        return {"error": "Project not found"}

    await session.delete(project)
    await session.commit()
    return {"status": "deleted"}
