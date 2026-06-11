import asyncio
import os
import glob
import logging
import uuid
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from nexhunt.adapters.base import get_adapter
from nexhunt.ws.manager import ws_manager
from nexhunt.database import DefaultSession
from nexhunt.models.finding import Finding
from nexhunt.licensing.guard import require_pro

router = APIRouter(prefix="/api/tools", tags=["security-tools"])
logger = logging.getLogger(__name__)
_TOOL_JOBS: dict[str, asyncio.Task] = {}


class ToolRequest(BaseModel):
    target: str = ""
    options: dict = {}
    project_id: str = ""


class BulkToolRequest(BaseModel):
    targets: list[str]
    options: dict = {}
    project_id: str = ""


async def _run_tool_bg(job_id: str, tool_name: str, target: str, options: dict, project_id: str | None):
    adapter = get_adapter(tool_name)
    if not adapter:
        await ws_manager.broadcast("tool_status", {
            "tool": tool_name, "event": "failed", "job_id": job_id, "error": "adapter not found"
        })
        return
    if not await adapter.check_installed():
        await ws_manager.broadcast("tool_status", {
            "tool": tool_name, "event": "failed", "job_id": job_id,
            "error": f"'{tool_name}' not installed — install it and restart the backend"
        })
        return

    await ws_manager.broadcast("tool_status", {"tool": tool_name, "event": "started", "job_id": job_id})
    findings = []
    try:
        async for result in adapter.run(target, options):
            if result.get("_raw"):
                await ws_manager.broadcast("tool_output", {"tool": tool_name, "line": result["line"]})
                continue
            finding_id = str(uuid.uuid4())
            try:
                async with DefaultSession() as session:
                    session.add(Finding(
                        id=finding_id,
                        project_id=project_id or None,
                        title=result.get("title", ""),
                        severity=result.get("severity", "info"),
                        vuln_type=result.get("vuln_type"),
                        url=result.get("url"),
                        parameter=result.get("parameter"),
                        evidence=(result.get("evidence") or "")[:2000],
                        description=result.get("description"),
                        tool=tool_name,
                        template_id=result.get("template_id"),
                        status=result.get("status", "new"),
                    ))
                    await session.commit()
                result["id"] = finding_id
            except Exception as db_err:
                logger.warning(f"DB save failed [{tool_name}]: {db_err}")
            findings.append(result)
            await ws_manager.broadcast("findings", {**result, "tool": tool_name, "project_id": project_id or ""})
    except asyncio.CancelledError:
        await ws_manager.broadcast("tool_status", {"tool": tool_name, "event": "cancelled", "job_id": job_id})
        return
    except Exception as e:
        logger.error(f"Tool error [{tool_name}]: {e}")
        await ws_manager.broadcast("tool_status", {"tool": tool_name, "event": "failed", "job_id": job_id, "error": str(e)})
        return
    finally:
        _TOOL_JOBS.pop(job_id, None)

    await ws_manager.broadcast("tool_status", {
        "tool": tool_name, "event": "completed", "job_id": job_id, "count": len(findings)
    })


def _start_tool(tool_name: str, target: str, options: dict, project_id: str | None) -> dict:
    job_id = str(uuid.uuid4())
    task = asyncio.create_task(_run_tool_bg(job_id, tool_name, target, options, project_id))
    _TOOL_JOBS[job_id] = task
    return {"status": "started", "job_id": job_id, "tool": tool_name}


@router.post("/cors")
async def run_cors(req: ToolRequest):
    return _start_tool("cors", req.target, req.options, req.project_id or None)


@router.post("/cors-bulk", dependencies=[Depends(require_pro("Bulk CORS scanning"))])
async def run_cors_bulk(req: BulkToolRequest):
    targets = [t.strip() for t in req.targets if t.strip()][:50]
    job_ids = [_start_tool("cors", t, req.options, req.project_id or None)["job_id"] for t in targets]
    return {"status": "started", "count": len(job_ids), "job_ids": job_ids}


@router.post("/bypass-403")
async def run_bypass_403(req: ToolRequest):
    return _start_tool("bypass_403", req.target, req.options, req.project_id or None)


@router.post("/cloud-buckets")
async def run_cloud_buckets(req: ToolRequest):
    return _start_tool("cloud_buckets", req.target, req.options, req.project_id or None)


@router.post("/github")
async def run_github(req: ToolRequest):
    return _start_tool("github_scanner", req.target, req.options, req.project_id or None)


@router.post("/interactsh")
async def run_interactsh(req: ToolRequest):
    return _start_tool("interactsh", req.target, req.options, req.project_id or None)


@router.delete("/jobs/{job_id}")
async def cancel_tool_job(job_id: str):
    task = _TOOL_JOBS.get(job_id)
    if not task:
        return {"error": "Job not found"}
    task.cancel()
    return {"status": "cancelled", "job_id": job_id}


@router.get("/check-installed")
async def check_tools_installed():
    """Return which optional security tools are installed."""
    import shutil
    tools = {
        "trufflehog": shutil.which("trufflehog") is not None,
        "interactsh-client": shutil.which("interactsh-client") is not None,
        "nuclei": shutil.which("nuclei") is not None,
        "gobuster": shutil.which("gobuster") is not None,
        "ffuf": shutil.which("ffuf") is not None,
        "dirsearch": shutil.which("dirsearch") is not None,
        "nikto": shutil.which("nikto") is not None,
    }
    return {"installed": tools}


@router.get("/nuclei-templates")
async def list_nuclei_templates():
    templates_dir = os.path.expanduser("~/nuclei-templates/http")
    if not os.path.isdir(templates_dir):
        return {"available": False, "categories": []}
    categories = []
    for entry in sorted(os.listdir(templates_dir)):
        path = os.path.join(templates_dir, entry)
        if os.path.isdir(path):
            count = len(glob.glob(f"{path}/**/*.yaml", recursive=True))
            categories.append({"name": entry, "path": f"http/{entry}", "count": count})
    return {"available": True, "templates_dir": templates_dir, "categories": categories}
