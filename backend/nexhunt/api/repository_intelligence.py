"""API for exposed repository recovery and source intelligence."""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from urllib.parse import quote, urlparse

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from nexhunt.config import settings
from nexhunt.database import DefaultSession
from nexhunt.models.project import Project
from nexhunt.models.recon_result import ReconResult
from nexhunt.services.repository_intelligence import analyze_repository, normalize_target, workspace_for
from nexhunt.services.scope import is_in_scope
from nexhunt.ws.manager import ws_manager

router = APIRouter(prefix="/api/repository-intelligence", tags=["repository-intelligence"])
logger = logging.getLogger(__name__)
_JOBS: dict[str, asyncio.Task] = {}


class AnalyzeRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    project_id: str = Field(min_length=1, max_length=80)
    recover: bool = True
    scan_history: bool = True


class AnalyzeBulkRequest(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=200)
    project_id: str = Field(min_length=1, max_length=80)
    recover: bool = True
    scan_history: bool = True


class ProviderRequest(BaseModel):
    provider: str
    token: str = Field(min_length=1, max_length=4096)
    workspace: str = Field(default="", max_length=255)


class ImportAssetsRequest(BaseModel):
    project_id: str = Field(min_length=1, max_length=80)
    assets: list[dict] = Field(default_factory=list, max_length=500)


async def _project(project_id: str) -> Project:
    async with DefaultSession() as session:
        result = await session.execute(select(Project).where(Project.id == project_id))
        project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


async def _check_scope(project_id: str, target: str) -> tuple[Project, str]:
    project = await _project(project_id)
    try:
        base, _ = normalize_target(target)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    in_scope = json.loads(project.scope) if project.scope else []
    out_of_scope = json.loads(project.out_of_scope) if project.out_of_scope else []
    if not is_in_scope(base, in_scope, out_of_scope):
        raise HTTPException(status_code=403, detail="Target is outside the active project's scope")
    return project, base


async def _run(job_id: str, request: AnalyzeRequest) -> None:
    async def progress(stage: str, message: str, data: dict | None) -> None:
        await ws_manager.broadcast("repository_intelligence", {
            "event": "progress", "job_id": job_id, "project_id": request.project_id,
            "stage": stage, "message": message, "data": data or {},
        })

    await ws_manager.broadcast("tool_status", {
        "tool": "repository_intelligence", "event": "started", "job_id": job_id,
    })
    try:
        report = await analyze_repository(
            request.target, request.project_id, settings.db_dir,
            request.recover, request.scan_history, progress,
        )
        await ws_manager.broadcast("repository_intelligence", {
            "event": "completed", "job_id": job_id, "project_id": request.project_id,
            "report": report,
        })
        await ws_manager.broadcast("tool_status", {
            "tool": "repository_intelligence", "event": "completed", "job_id": job_id,
        })
    except asyncio.CancelledError:
        await ws_manager.broadcast("repository_intelligence", {
            "event": "cancelled", "job_id": job_id, "project_id": request.project_id,
        })
        await ws_manager.broadcast("tool_status", {
            "tool": "repository_intelligence", "event": "cancelled", "job_id": job_id,
        })
    except Exception as error:
        logger.exception("Repository intelligence failed")
        await ws_manager.broadcast("repository_intelligence", {
            "event": "failed", "job_id": job_id, "project_id": request.project_id,
            "error": str(error),
        })
        await ws_manager.broadcast("tool_status", {
            "tool": "repository_intelligence", "event": "failed", "job_id": job_id,
            "error": str(error),
        })
    finally:
        _JOBS.pop(job_id, None)


@router.post("/analyze")
async def start_analysis(request: AnalyzeRequest):
    await _check_scope(request.project_id, request.target)
    job_id = str(uuid.uuid4())
    _JOBS[job_id] = asyncio.create_task(_run(job_id, request))
    return {"status": "started", "job_id": job_id, "tool": "repository_intelligence"}


async def _run_bulk(job_id: str, request: AnalyzeBulkRequest) -> None:
    project = await _project(request.project_id)
    in_scope = json.loads(project.scope) if project.scope else []
    out_of_scope = json.loads(project.out_of_scope) if project.out_of_scope else []
    targets = []
    for raw in dict.fromkeys(request.targets):
        try:
            base, _ = normalize_target(raw)
        except ValueError:
            continue
        if is_in_scope(base, in_scope, out_of_scope):
            targets.append(raw)
    total = len(targets)

    await ws_manager.broadcast("tool_status", {
        "tool": "repository_intelligence", "event": "started", "job_id": job_id,
    })
    try:
        for index, target in enumerate(targets, 1):
            async def progress(stage: str, message: str, data: dict | None, _i=index, _t=target) -> None:
                await ws_manager.broadcast("repository_intelligence", {
                    "event": "progress", "job_id": job_id, "project_id": request.project_id,
                    "stage": stage, "message": f"[{_i}/{total}] {_t} — {message}", "data": data or {},
                })
            try:
                report = await analyze_repository(
                    target, request.project_id, settings.db_dir,
                    request.recover, request.scan_history, progress,
                )
                await ws_manager.broadcast("repository_intelligence", {
                    "event": "completed", "job_id": job_id, "project_id": request.project_id,
                    "report": report, "host_index": index, "host_total": total,
                })
            except asyncio.CancelledError:
                raise
            except Exception as error:
                logger.warning("Repository intelligence host failed: %s", error)
                await ws_manager.broadcast("repository_intelligence", {
                    "event": "progress", "job_id": job_id, "project_id": request.project_id,
                    "stage": "exposure",
                    "message": f"[{index}/{total}] {target} — failed: {error}", "data": {},
                })
        await ws_manager.broadcast("repository_intelligence", {
            "event": "bulk_completed", "job_id": job_id, "project_id": request.project_id,
            "host_total": total,
        })
        await ws_manager.broadcast("tool_status", {
            "tool": "repository_intelligence", "event": "completed", "job_id": job_id,
        })
    except asyncio.CancelledError:
        await ws_manager.broadcast("repository_intelligence", {
            "event": "cancelled", "job_id": job_id, "project_id": request.project_id,
        })
        await ws_manager.broadcast("tool_status", {
            "tool": "repository_intelligence", "event": "cancelled", "job_id": job_id,
        })
    finally:
        _JOBS.pop(job_id, None)


@router.post("/analyze-bulk")
async def start_bulk_analysis(request: AnalyzeBulkRequest):
    await _project(request.project_id)
    job_id = str(uuid.uuid4())
    _JOBS[job_id] = asyncio.create_task(_run_bulk(job_id, request))
    return {"status": "started", "job_id": job_id, "tool": "repository_intelligence"}


@router.delete("/jobs/{job_id}")
async def cancel_analysis(job_id: str):
    task = _JOBS.get(job_id)
    if not task:
        raise HTTPException(status_code=404, detail="Job not found")
    task.cancel()
    return {"status": "cancelled", "job_id": job_id}


@router.get("/latest")
async def latest_report(project_id: str, target: str):
    await _check_scope(project_id, target)
    try:
        base, _ = normalize_target(target)
        report_path = workspace_for(project_id, base, settings.db_dir) / "report.json"
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    if not report_path.is_file():
        return {"report": None}
    try:
        return {"report": json.loads(report_path.read_text(encoding="utf-8"))}
    except (OSError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=500, detail=f"Stored report cannot be read: {error}") from error


def _provider_urls(request: ProviderRequest) -> tuple[str, str, dict[str, str]]:
    provider = request.provider.strip().lower()
    if provider == "github":
        base = "https://api.github.com"
        return f"{base}/user", f"{base}/user/repos?per_page=100&affiliation=owner,collaborator,organization_member", {
            "Authorization": f"Bearer {request.token}", "Accept": "application/vnd.github+json",
        }
    if provider == "gitlab":
        base = "https://gitlab.com/api/v4"
        return f"{base}/user", f"{base}/projects?membership=true&per_page=100", {"PRIVATE-TOKEN": request.token}
    if provider == "bitbucket":
        base = "https://api.bitbucket.org/2.0"
        workspace = quote(request.workspace.strip(), safe="")
        repos = f"{base}/repositories/{workspace}?pagelen=100" if workspace else f"{base}/user/permissions/repositories?pagelen=100"
        return f"{base}/user", repos, {"Authorization": f"Bearer {request.token}"}
    raise HTTPException(status_code=400, detail="Provider must be github, gitlab or bitbucket")


@router.post("/provider/validate")
async def validate_provider(request: ProviderRequest):
    user_url, repositories_url, headers = _provider_urls(request)
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
            user_response = await client.get(user_url, headers=headers)
            if user_response.status_code >= 400:
                raise HTTPException(status_code=400, detail=f"Token rejected by {request.provider}: HTTP {user_response.status_code}")
            repositories_response = await client.get(repositories_url, headers=headers)
            repositories_response.raise_for_status()
        user = user_response.json()
        payload = repositories_response.json()
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(status_code=502, detail=f"Provider request failed: {error}") from error

    rows = payload.get("values", []) if isinstance(payload, dict) else payload
    repositories = []
    for row in rows[:100]:
        repo = row.get("repository", row) if isinstance(row, dict) else {}
        links = repo.get("links", {}) if isinstance(repo, dict) else {}
        clone_links = links.get("clone", []) if isinstance(links, dict) else []
        clone_url = next((item.get("href") for item in clone_links if item.get("name") == "https"), "")
        repositories.append({
            "name": repo.get("full_name") or repo.get("path_with_namespace") or repo.get("name", ""),
            "private": bool(repo.get("private", repo.get("visibility") == "private")),
            "url": repo.get("html_url") or repo.get("web_url") or links.get("html", {}).get("href", ""),
            "clone_url": repo.get("clone_url") or repo.get("http_url_to_repo") or clone_url,
        })
    identity = user.get("login") or user.get("username") or user.get("nickname") or user.get("name") or user.get("display_name")
    return {"valid": True, "provider": request.provider.lower(), "identity": identity, "repositories": repositories}


@router.post("/assets/import")
async def import_assets(request: ImportAssetsRequest):
    project = await _project(request.project_id)
    in_scope = json.loads(project.scope) if project.scope else []
    out_of_scope = json.loads(project.out_of_scope) if project.out_of_scope else []
    saved: list[dict] = []
    skipped_out_of_scope = 0
    seen: set[tuple[str, str]] = set()
    async with DefaultSession() as session:
        for asset in request.assets:
            kind = str(asset.get("type", "host"))
            value = str(asset.get("value", "")).strip()
            if not value or kind not in {"host", "url"}:
                continue
            if kind == "url":
                parsed = urlparse(value)
                if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                    continue
                if not is_in_scope(value, in_scope, out_of_scope):
                    skipped_out_of_scope += 1
                    continue
                result_type = "url"
                data = {
                    "url": value, "source": "repository_intelligence",
                    "status_code": None, "content_type": None,
                }
            else:
                if not re_full_host(value):
                    continue
                if not is_in_scope(value, in_scope, out_of_scope):
                    skipped_out_of_scope += 1
                    continue
                result_type = "live_host"
                data = {
                    "host": value, "url": f"https://{value}", "source": "repository_intelligence",
                    "status_code": None, "title": "", "technologies": [], "content_type": "", "ip": "",
                }
            key = (result_type, value)
            if key in seen:
                continue
            seen.add(key)
            session.add(ReconResult(
                type=result_type, target=value, project_id=request.project_id, data=json.dumps(data),
            ))
            saved.append(data)
        await session.commit()
    if saved:
        grouped: dict[str, list] = {}
        for item in saved:
            result_type = "url" if "host" not in item else "live_host"
            grouped.setdefault(result_type, []).append(item)
        for result_type, results in grouped.items():
            await ws_manager.broadcast("recon_results", {
                "tool": "repository_intelligence", "type": result_type,
                "results": results, "project_id": request.project_id,
            })
    return {"imported": len(saved), "skipped_out_of_scope": skipped_out_of_scope}


def re_full_host(value: str) -> bool:
    if len(value) > 253 or any(char in value for char in "/?#@ "):
        return False
    host = value.strip("[]").lower()
    if host == "localhost":
        return True
    try:
        import ipaddress
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(host and all(part and len(part) <= 63 for part in host.split(".")))
