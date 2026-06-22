import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from nexhunt.database import get_session
from nexhunt.models.project import Project
from nexhunt.models.finding import Finding
from nexhunt.models.recon_result import ReconResult
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


@router.get("/{project_id}/briefing")
async def get_briefing(project_id: str, session: AsyncSession = Depends(get_session)):
    """General, AI-readable summary of the pentest so far — for handing off to an assistant to
    continue the work. Deliberately high-level: counts and the critical/high findings list, not
    full evidence dumps or exhaustive URL lists."""
    result = await session.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        return {"error": "Project not found"}

    findings_result = await session.execute(
        select(Finding).where(Finding.project_id == project_id).order_by(Finding.created_at.desc())
    )
    findings = findings_result.scalars().all()

    recon_result = await session.execute(
        select(ReconResult).where(ReconResult.project_id == project_id)
    )
    recon_rows = recon_result.scalars().all()

    return {"content": _build_briefing(project, findings, recon_rows)}


def _build_briefing(project: Project, findings: list[Finding], recon_rows: list[ReconResult]) -> str:
    in_scope = json.loads(project.scope) if project.scope else []
    targets = in_scope or sorted({r.target for r in recon_rows if r.target})

    by_sev: dict[str, list[Finding]] = {}
    for f in findings:
        by_sev.setdefault(f.severity or "info", []).append(f)
    sev_order = ["critical", "high", "medium", "low", "info"]
    sev_counts = ", ".join(f"{s}: {len(by_sev[s])}" for s in sev_order if by_sev.get(s))

    recon_counts: dict[str, int] = {}
    for r in recon_rows:
        recon_counts[r.type] = recon_counts.get(r.type, 0) + 1

    tools_used = sorted({f.tool for f in findings if f.tool})

    lines = [
        f"# NexHunt Pentest Briefing — {project.name}",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Scope",
        f"Target(s): {', '.join(targets) if targets else 'not set'}",
        f"Scope mode: {project.scope_mode}",
    ]
    if project.notes:
        lines += ["", "## Notes", project.notes]

    lines += [
        "",
        "## Status so far",
        f"- {len(findings)} findings total ({sev_counts or 'none'})",
        "- Recon: " + (", ".join(f"{v} {k.replace('_', ' ')}" for k, v in recon_counts.items()) if recon_counts else "nothing run yet"),
        f"- Tools that produced findings: {', '.join(tools_used) if tools_used else 'none yet'}",
    ]

    live_hosts = []
    for r in recon_rows:
        if r.type != "live_host":
            continue
        try:
            live_hosts.append(json.loads(r.data))
        except Exception:
            continue
    lines += ["", f"## Live Hosts ({len(live_hosts)})"]
    if live_hosts:
        for h in live_hosts[:150]:
            status = h.get("status_code")
            url = h.get("url", "")
            title = h.get("title") or ""
            techs = ", ".join(h.get("technologies") or [])
            line = f"- [{status}] {url}"
            if title:
                line += f" — \"{title}\""
            if techs:
                line += f" — {techs}"
            lines.append(line)
        if len(live_hosts) > 150:
            lines.append(f"- ...and {len(live_hosts) - 150} more (open NexHunt → Recon → Live Hosts for the full list)")
    else:
        lines.append("- None yet.")

    important = [f for f in findings if f.severity in ("critical", "high")][:25]
    lines += ["", "## Most important findings (critical / high)"]
    if important:
        for f in important:
            line = f"- [{f.severity.upper()}] {f.title}"
            if f.tool:
                line += f" — {f.tool}"
            if f.url:
                line += f" — {f.url}"
            lines.append(line)
        if len(by_sev.get("critical", [])) + len(by_sev.get("high", [])) > len(important):
            lines.append(f"- ...and more (open NexHunt → Workspace for the full list)")
    else:
        lines.append("- None yet.")

    lines += [
        "",
        "---",
        "Instructions for the AI: this is a GENERAL summary of the pentest done so far on the scope "
        "indicated above. It is intentionally brief — it does not include full evidence or exhaustive "
        "URL listings. Use it as context to continue the work: prioritize confirming/exploiting the "
        "critical/high findings listed, propose next recon or exploitation steps that are missing based "
        "on what has already been run, and ask for the specific details of a particular finding if you need them.",
    ]
    return "\n".join(lines)


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
