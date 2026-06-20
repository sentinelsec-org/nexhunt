import asyncio
import os
import glob
import logging
import uuid
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from nexhunt.licensing.guard import require_pro
from nexhunt.adapters.base import get_adapter
from nexhunt.ws.manager import ws_manager
from nexhunt.database import DefaultSession
from nexhunt.models.finding import Finding

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
                        evidence=(result.get("evidence") or "")[:20000],
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


@router.post("/cors-bulk")
async def run_cors_bulk(req: BulkToolRequest):
    targets = [t.strip() for t in req.targets if t.strip()][:50]
    job_ids = [_start_tool("cors", t, req.options, req.project_id or None)["job_id"] for t in targets]
    return {"status": "started", "count": len(job_ids), "job_ids": job_ids}


@router.post("/bypass-403")
async def run_bypass_403(req: ToolRequest):
    return _start_tool("bypass_403", req.target, req.options, req.project_id or None)


@router.post("/bypass-403-bulk")
async def run_bypass_403_bulk(req: BulkToolRequest):
    targets = [t.strip() for t in req.targets if t.strip()][:50]
    job_ids = [_start_tool("bypass_403", t, req.options, req.project_id or None)["job_id"] for t in targets]
    return {"status": "started", "count": len(job_ids), "job_ids": job_ids}


@router.post("/cloud-buckets")
async def run_cloud_buckets(req: ToolRequest):
    return _start_tool("cloud_buckets", req.target, req.options, req.project_id or None)


@router.post("/cloud-buckets-bulk")
async def run_cloud_buckets_bulk(req: BulkToolRequest):
    # targets here are domains/company names derived from live hosts
    targets = [t.strip() for t in req.targets if t.strip()][:50]
    job_ids = [_start_tool("cloud_buckets", t, req.options, req.project_id or None)["job_id"] for t in targets]
    return {"status": "started", "count": len(job_ids), "job_ids": job_ids}


@router.post("/github")
async def run_github(req: ToolRequest):
    return _start_tool("github_scanner", req.target, req.options, req.project_id or None)


@router.post("/exposed-files")
async def run_exposed_files(req: ToolRequest):
    return _start_tool("exposed_files", req.target, req.options, req.project_id or None)


@router.post("/graphql", dependencies=[Depends(require_pro("GraphQL Auditor"))])
async def run_graphql_audit(req: ToolRequest):
    return _start_tool("graphql_audit", req.target, req.options, req.project_id or None)


@router.post("/viewstate", dependencies=[Depends(require_pro("VIEWSTATE Auditor"))])
async def run_viewstate_audit(req: ToolRequest):
    return _start_tool("viewstate_audit", req.target, req.options, req.project_id or None)


@router.post("/viewstate-bulk", dependencies=[Depends(require_pro("VIEWSTATE Auditor"))])
async def run_viewstate_audit_bulk(req: BulkToolRequest):
    targets = [t.strip() for t in req.targets if t.strip()][:50]
    job_ids = [_start_tool("viewstate_audit", t, req.options, req.project_id or None)["job_id"] for t in targets]
    return {"status": "started", "count": len(job_ids), "job_ids": job_ids}


@router.post("/exposed-files-bulk")
async def run_exposed_files_bulk(req: BulkToolRequest):
    targets = [t.strip() for t in req.targets if t.strip()][:50]
    job_ids = [_start_tool("exposed_files", t, req.options, req.project_id or None)["job_id"] for t in targets]
    return {"status": "started", "count": len(job_ids), "job_ids": job_ids}


@router.post("/interactsh")
async def run_interactsh(req: ToolRequest):
    return _start_tool("interactsh", req.target, req.options, req.project_id or None)


@router.post("/exploit-intel")
async def run_exploit_intel(req: ToolRequest):
    return _start_tool("exploit_intel", req.target, req.options, req.project_id or None)


@router.post("/js-api-mapper")
async def run_js_api_mapper(req: ToolRequest):
    return _start_tool("js_api_mapper", req.target, req.options, req.project_id or None)


@router.post("/js-api-mapper-bulk")
async def run_js_api_mapper_bulk(req: BulkToolRequest):
    targets = list(dict.fromkeys(t.strip() for t in req.targets if t.strip()))[:50]
    job_ids = [
        _start_tool("js_api_mapper", target, req.options, req.project_id or None)["job_id"]
        for target in targets
    ]
    return {"status": "started", "count": len(job_ids), "job_ids": job_ids}


class MsfLaunchRequest(BaseModel):
    module: str
    rhosts: str = ""
    rport: str = ""
    lhost: str = ""
    lport: str = "4444"


@router.post("/exploit-intel/msf-launch")
async def msf_launch(req: MsfLaunchRequest):
    """Write a Metasploit resource script for a module and open msfconsole with it."""
    import shutil, tempfile, subprocess
    from nexhunt.adapters.exploit_intel import build_rc

    if not req.module:
        return {"error": "No module specified"}
    if not shutil.which("msfconsole"):
        return {"error": "msfconsole not installed"}

    rc = build_rc(req.module, req.rhosts or "TARGET_HOST", req.rport, req.lhost, req.lport)
    fd, rc_path = tempfile.mkstemp(suffix=".rc", prefix="nexhunt_msf_")
    with os.fdopen(fd, "w") as f:
        f.write(rc)

    launch_cmd = f"msfconsole -r {rc_path}"
    term = shutil.which("x-terminal-emulator") or shutil.which("qterminal") or shutil.which("xterm")
    if term and os.environ.get("DISPLAY"):
        try:
            subprocess.Popen(
                [term, "-e", "bash", "-c", f"{launch_cmd}; exec bash"],
                start_new_session=True,
            )
            return {"status": "launched", "module": req.module, "rc_path": rc_path, "command": launch_cmd}
        except Exception as e:
            logger.warning(f"msf terminal launch failed: {e}")

    # No GUI terminal available — hand back the script + command to run manually.
    return {
        "status": "manual",
        "module": req.module,
        "rc_path": rc_path,
        "command": launch_cmd,
        "rc": rc,
        "note": "No GUI terminal detected. Run the command above in your terminal.",
    }


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
        "searchsploit": shutil.which("searchsploit") is not None,
        "msfconsole": shutil.which("msfconsole") is not None,
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
