import json
from datetime import datetime, timezone
from urllib.parse import urlparse
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from nexhunt.database import get_session
from nexhunt.models.project import Project
from nexhunt.models.finding import Finding
from nexhunt.models.recon_result import ReconResult
from nexhunt.models.http_flow import HttpFlow
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


class BriefingRequest(BaseModel):
    observed_endpoints: list[dict] = []


async def _briefing_content(
    project_id: str,
    session: AsyncSession,
    observed_endpoints: list[dict] | None = None,
):
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

    flows_result = await session.execute(
        select(HttpFlow).where(
            HttpFlow.project_id == project_id,
            HttpFlow.response_status == 200,
        )
    )
    http_flows = flows_result.scalars().all()

    return {"content": _build_briefing(
        project, findings, recon_rows, http_flows, observed_endpoints or []
    )}


@router.get("/{project_id}/briefing")
async def get_briefing(project_id: str, session: AsyncSession = Depends(get_session)):
    """Generate an AI-readable handoff from persisted project data."""
    return await _briefing_content(project_id, session)


@router.post("/{project_id}/briefing")
async def create_briefing(
    project_id: str,
    data: BriefingRequest,
    session: AsyncSession = Depends(get_session),
):
    """Generate a handoff and merge live workspace endpoints not persisted yet."""
    return await _briefing_content(project_id, session, data.observed_endpoints)


def _handoff_url(value: str) -> str:
    """Preserve the full observed URL, including sensitive query values, for the AI handoff."""
    return value or ""


def _json_data(row: ReconResult) -> dict:
    try:
        value = json.loads(row.data)
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _status_is_200(value) -> bool:
    try:
        return int(value) == 200
    except (TypeError, ValueError):
        return False


def _successful_endpoints(
    recon_rows: list[ReconResult],
    http_flows: list[HttpFlow],
    in_scope: list[str],
    out_of_scope: list[str],
    observed_endpoints: list[dict] | None = None,
) -> list[dict]:
    endpoints: dict[tuple[str, str], dict] = {}

    def add(method, url, source, lane="", content_type="", title=""):
        if not url or not is_in_scope(url, in_scope, out_of_scope):
            return
        method = str(method or "GET").upper()
        safe_url = _handoff_url(str(url))
        key = (method, safe_url)
        item = endpoints.setdefault(key, {
            "method": method,
            "url": safe_url,
            "sources": set(),
            "lanes": set(),
            "content_type": "",
            "title": "",
        })
        item["sources"].add(source)
        if lane:
            item["lanes"].add(lane)
        if content_type and not item["content_type"]:
            item["content_type"] = str(content_type)
        if title and not item["title"]:
            item["title"] = str(title).replace("\n", " ")[:160]

    for row in recon_rows:
        data = _json_data(row)
        url = data.get("url") or row.target or ""
        method = data.get("method") or "GET"
        if row.type == "api_endpoint":
            if _status_is_200(data.get("status_anon")):
                add(method, url, "API Scanner", "anonymous", data.get("content_type"), data.get("summary"))
            if _status_is_200(data.get("status_auth")):
                add(method, url, "API Scanner", "authenticated", data.get("content_type"), data.get("summary"))
        elif row.type in ("live_host", "endpoint", "url") and _status_is_200(data.get("status_code")):
            source = {"live_host": "HTTP probe", "endpoint": "Endpoint check", "url": "URL discovery"}[row.type]
            add(method, url, source, "", data.get("content_type"), data.get("title"))

    for flow in http_flows:
        if _status_is_200(flow.response_status):
            add(
                flow.request_method,
                flow.request_url,
                "Proxy history",
                "",
                flow.content_type or "",
            )

    for data in observed_endpoints or []:
        if not isinstance(data, dict):
            continue
        method = data.get("method") or "GET"
        url = data.get("url") or ""
        source = str(data.get("source") or "Current workspace")
        if _status_is_200(data.get("status_anon")):
            add(method, url, source, "anonymous", data.get("content_type"), data.get("summary") or data.get("title"))
        if _status_is_200(data.get("status_auth")):
            add(method, url, source, "authenticated", data.get("content_type"), data.get("summary") or data.get("title"))
        if _status_is_200(data.get("status_code")):
            add(method, url, source, "", data.get("content_type"), data.get("summary") or data.get("title"))

    return sorted(endpoints.values(), key=lambda item: (urlparse(item["url"]).netloc, item["url"], item["method"]))


def _build_briefing(
    project: Project,
    findings: list[Finding],
    recon_rows: list[ReconResult],
    http_flows: list[HttpFlow] | None = None,
    observed_endpoints: list[dict] | None = None,
) -> str:
    in_scope = json.loads(project.scope) if project.scope else []
    out_of_scope = json.loads(project.out_of_scope) if getattr(project, "out_of_scope", None) else []
    targets = in_scope or sorted({r.target for r in recon_rows if r.target})
    successful_endpoints = _successful_endpoints(
        recon_rows, http_flows or [], in_scope, out_of_scope, observed_endpoints or []
    )

    by_sev: dict[str, list[Finding]] = {}
    for f in findings:
        by_sev.setdefault(f.severity or "info", []).append(f)
    sev_order = ["critical", "high", "medium", "low", "info"]
    sev_counts = ", ".join(f"{s}: {len(by_sev[s])}" for s in sev_order if by_sev.get(s))
    status_counts: dict[str, int] = {}
    for finding in findings:
        status_counts[finding.status or "new"] = status_counts.get(finding.status or "new", 0) + 1

    recon_counts: dict[str, int] = {}
    for r in recon_rows:
        recon_counts[r.type] = recon_counts.get(r.type, 0) + 1

    tools_used = {f.tool for f in findings if f.tool}
    tools_used.update(
        str(_json_data(row).get("_tool")) for row in recon_rows if _json_data(row).get("_tool")
    )
    if any(row.type == "api_endpoint" for row in recon_rows):
        tools_used.add("api_scanner")
    tools_used = sorted(tools_used)

    lines = [
        f"# NexHunt AI Handoff - {project.name}",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Engagement context",
        "This file is a concise operational handoff generated by NexHunt. It summarizes current scope, work completed,",
        "important findings and every recorded in-scope endpoint that returned HTTP 200.",
        "CONFIDENTIAL: observed parameters, tokens, session values and other sensitive query data are preserved in clear text by operator request.",
        "",
        "## Scope",
        f"- Scope mode: {project.scope_mode}",
        "- In scope:",
    ]
    lines.extend(f"  - `{target}`" for target in targets)
    if not targets:
        lines.append("  - Not set")
    lines.append("- Explicitly out of scope:")
    lines.extend(f"  - `{target}`" for target in out_of_scope)
    if not out_of_scope:
        lines.append("  - None recorded")
    if project.notes:
        lines += ["", "## Operator notes", project.notes]

    lines += [
        "",
        "## Status so far",
        f"- {len(findings)} findings total ({sev_counts or 'none'})",
        "- Finding workflow: " + (", ".join(f"{status}: {count}" for status, count in sorted(status_counts.items())) if status_counts else "none"),
        f"- Recorded HTTP 200 endpoints: {len(successful_endpoints)}",
        f"- Tools observed: {', '.join(tools_used) if tools_used else 'none recorded'}",
    ]

    lines += ["", "## Work completed"]
    if recon_counts:
        for result_type, count in sorted(recon_counts.items()):
            lines.append(f"- {result_type.replace('_', ' ')}: {count} stored results")
    else:
        lines.append("- No recon activity is stored for this project yet.")

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
                line += f" - \"{title}\""
            if techs:
                line += f" - {techs}"
            lines.append(line)
        if len(live_hosts) > 150:
            lines.append(f"- ...and {len(live_hosts) - 150} more (open NexHunt → Recon → Live Hosts for the full list)")
    else:
        lines.append("- None yet.")

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    important = [f for f in findings if f.status not in ("false_positive", "duplicate")]
    important.sort(key=lambda f: (severity_rank.get(f.severity, 5), 0 if f.status == "confirmed" else 1, str(f.created_at)))
    important = [f for f in important if f.severity in ("critical", "high") or f.status == "confirmed"][:40]
    lines += ["", "## Most important findings"]
    if important:
        for f in important:
            line = f"- [{f.severity.upper()}] [{(f.status or 'new').upper()}] {f.title}"
            if f.tool:
                line += f" - {f.tool}"
            if f.url:
                line += f" - `{_handoff_url(f.url)}`"
            lines.append(line)
    else:
        lines.append("- None yet.")

    lines += ["", f"## In-scope endpoints returning HTTP 200 ({len(successful_endpoints)})"]
    lines.append("These are deduplicated by HTTP method and URL. A lane identifies whether API Scanner received 200 anonymously or with supplied authentication.")
    if successful_endpoints:
        current_host = None
        for endpoint in successful_endpoints:
            host = urlparse(endpoint["url"]).netloc or "unknown host"
            if host != current_host:
                lines += ["", f"### {host}"]
                current_host = host
            details = [f"source: {', '.join(sorted(endpoint['sources']))}"]
            if endpoint["lanes"]:
                details.append(f"200 lane: {', '.join(sorted(endpoint['lanes']))}")
            if endpoint["content_type"]:
                details.append(f"type: {endpoint['content_type']}")
            if endpoint["title"]:
                details.append(f"label: {endpoint['title']}")
            lines.append(f"- `{endpoint['method']} {endpoint['url']}` ({'; '.join(details)})")
    else:
        lines.append("- None recorded yet.")

    lines += [
        "",
        "---",
        "## Instructions for the next AI",
        "Continue this authorized pentest strictly within the scope above. Treat findings as hypotheses unless their status is confirmed. "
        "Prioritize the critical and high items, identify meaningful gaps in the recorded work, and propose the next safest validation steps. "
        "Use the HTTP 200 endpoint inventory to avoid repeating discovery. Ask the operator for raw evidence, credentials or request/response "
        "details only when needed. Never infer authorization to test an out-of-scope host.",
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
