"""
WordPress pentest module — drives wpscan and streams structured results.

  POST   /api/wordpress/scan        start a scan (profile + options)
  DELETE /api/wordpress/jobs/{id}   cancel a running scan
  GET    /api/wordpress/status      whether wpscan is installed + API token set

Raw scanner lines stream on the `tool_output` channel (tool="wpscan").
Structured results (version/plugin/theme/user/vuln/...) stream on the
`wordpress` channel. Vulnerabilities are also saved as findings.
"""
import asyncio
import uuid
import logging
from fastapi import APIRouter
from pydantic import BaseModel
from nexhunt.adapters.base import get_adapter
from nexhunt.ws.manager import ws_manager
from nexhunt.config import settings

router = APIRouter(prefix="/api/wordpress", tags=["wordpress"])
logger = logging.getLogger(__name__)

_WP_JOBS: dict[str, asyncio.Task] = {}


class WordPressScanRequest(BaseModel):
    target: str
    profile: str = "standard"      # quick | standard | thorough
    options: dict = {}
    project_id: str = ""


async def _save_vuln_finding(target: str, title: str, severity: str, project_id: str | None):
    try:
        import uuid as _uuid, datetime
        from nexhunt.database import DefaultSession
        from nexhunt.models.finding import Finding
        fid = str(_uuid.uuid4())
        async with DefaultSession() as session:
            session.add(Finding(
                id=fid,
                project_id=project_id or None,
                title=f"WordPress: {title}"[:300],
                severity=severity,
                vuln_type="wordpress",
                url=target,
                tool="wpscan",
                evidence=title[:2000],
                status="new",
                created_at=datetime.datetime.utcnow(),
            ))
            await session.commit()
        await ws_manager.broadcast("findings", {
            "id": fid, "title": f"WordPress: {title}", "severity": severity,
            "url": target, "tool": "wpscan", "vuln_type": "wordpress",
            "status": "new", "project_id": project_id or "",
        })
    except Exception as e:
        logger.warning(f"Failed to save WP finding: {e}")


async def _run_scan_bg(job_id: str, req: WordPressScanRequest):
    adapter = get_adapter("wpscan")
    if not adapter:
        await ws_manager.broadcast("tool_status", {
            "tool": "wpscan", "event": "failed", "job_id": job_id, "error": "adapter not found"})
        return
    if not await adapter.check_installed():
        await ws_manager.broadcast("tool_status", {
            "tool": "wpscan", "event": "failed", "job_id": job_id,
            "error": "wpscan not installed — run: gem install wpscan"})
        return

    opts = dict(req.options or {})
    opts["profile"] = req.profile
    # Inject the persisted WPScan API token unless the request overrides it
    if not opts.get("api_token") and settings.wpscan_api_token:
        opts["api_token"] = settings.wpscan_api_token

    await ws_manager.broadcast("tool_status", {
        "tool": "wpscan", "event": "started", "job_id": job_id, "target": req.target})

    counts = {"plugin": 0, "theme": 0, "user": 0, "vuln": 0,
              "interesting": 0, "config_backup": 0, "version": 0}
    try:
        async for result in adapter.run(req.target, opts):
            if result.get("_raw"):
                await ws_manager.broadcast("tool_output", {"tool": "wpscan", "line": result["line"]})
                continue

            kind = result.get("kind")
            if kind in counts:
                counts[kind] += 1

            # Stream structured result to the WordPress panel
            await ws_manager.broadcast("wordpress", {**result, "job_id": job_id})

            # Persist vulnerabilities as findings
            if kind == "vuln":
                await _save_vuln_finding(
                    req.target, result.get("title", ""),
                    result.get("severity", "low"), req.project_id or None)

    except asyncio.CancelledError:
        await ws_manager.broadcast("tool_status", {
            "tool": "wpscan", "event": "cancelled", "job_id": job_id})
        return
    except Exception as e:
        logger.error(f"wpscan error: {e}")
        await ws_manager.broadcast("tool_status", {
            "tool": "wpscan", "event": "failed", "job_id": job_id, "error": str(e)})
        return
    finally:
        _WP_JOBS.pop(job_id, None)

    await ws_manager.broadcast("tool_status", {
        "tool": "wpscan", "event": "completed", "job_id": job_id, "counts": counts})


@router.post("/scan")
async def start_scan(req: WordPressScanRequest):
    target = req.target.strip()
    if not target:
        return {"error": "No target"}
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    req.target = target
    job_id = str(uuid.uuid4())
    task = asyncio.create_task(_run_scan_bg(job_id, req))
    _WP_JOBS[job_id] = task
    return {"status": "started", "job_id": job_id, "target": target}


@router.delete("/jobs/{job_id}")
async def cancel_scan(job_id: str):
    task = _WP_JOBS.get(job_id)
    if not task:
        return {"error": "Job not found"}
    task.cancel()
    return {"status": "cancelled", "job_id": job_id}


@router.get("/status")
async def wp_status():
    import shutil
    return {
        "installed": shutil.which("wpscan") is not None,
        "api_token_set": bool(settings.wpscan_api_token),
    }
