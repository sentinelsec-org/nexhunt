import asyncio
import json
import uuid
import logging
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from nexhunt.adapters.base import get_adapter
from nexhunt.ws.manager import ws_manager
from nexhunt.database import DefaultSession
from nexhunt.models.finding import Finding
from nexhunt.models.recon_result import ReconResult
from nexhunt.licensing.guard import require_pro

router = APIRouter(prefix="/api/api-scanner", tags=["api-scanner"])
logger = logging.getLogger(__name__)
_JOBS: dict[str, asyncio.Task] = {}


class ApiScanRequest(BaseModel):
    target: str = ""
    options: dict = {}
    project_id: str = ""


async def _run_bg(job_id: str, target: str, options: dict, project_id: str | None):
    adapter = get_adapter("api_scanner")
    if not adapter:
        await ws_manager.broadcast("tool_status", {
            "tool": "api_scanner", "event": "failed", "job_id": job_id, "error": "adapter not found"
        })
        return

    await ws_manager.broadcast("tool_status", {"tool": "api_scanner", "event": "started", "job_id": job_id})
    endpoints = 0
    findings = 0
    try:
        async for result in adapter.run(target, options):
            if result.get("_raw"):
                await ws_manager.broadcast("tool_output", {"tool": "api_scanner", "line": result["line"]})
                continue
            if result.get("kind") == "endpoint":
                endpoints += 1
                try:
                    async with DefaultSession() as session:
                        session.add(ReconResult(
                            type="api_endpoint",
                            target=result.get("url", target),
                            project_id=project_id or None,
                            data=json.dumps(result, default=str),
                        ))
                        await session.commit()
                except Exception as db_err:
                    logger.warning(f"API endpoint save failed [api_scanner]: {db_err}")
                await ws_manager.broadcast("api_scan", {**result, "project_id": project_id or ""})
                continue
            # genuine finding (broken access control / AI triage) — persist + broadcast
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
                        tool="api_scanner",
                        template_id=result.get("template_id"),
                        status=result.get("status", "new"),
                    ))
                    await session.commit()
                result["id"] = finding_id
            except Exception as db_err:
                logger.warning(f"DB save failed [api_scanner]: {db_err}")
            findings += 1
            await ws_manager.broadcast("findings", {**result, "tool": "api_scanner", "project_id": project_id or ""})
    except asyncio.CancelledError:
        await ws_manager.broadcast("tool_status", {"tool": "api_scanner", "event": "cancelled", "job_id": job_id})
        return
    except Exception as e:
        logger.error(f"api_scanner error: {e}")
        await ws_manager.broadcast("tool_status", {"tool": "api_scanner", "event": "failed", "job_id": job_id, "error": str(e)})
        return
    finally:
        _JOBS.pop(job_id, None)

    await ws_manager.broadcast("tool_status", {
        "tool": "api_scanner", "event": "completed", "job_id": job_id,
        "count": endpoints, "findings": findings,
    })


@router.post("/spec", dependencies=[Depends(require_pro("API Scanner"))])
async def load_spec(req: ApiScanRequest):
    """Load and normalize an API contract without calling its operations."""
    adapter = get_adapter("api_scanner")
    if not adapter:
        raise HTTPException(status_code=500, detail="API Scanner adapter not found")
    try:
        options = req.options or {}
        return await adapter.inspect(
            req.target,
            options.get("base_url", ""),
            bool(options.get("ai_assist")),
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@router.post("", dependencies=[Depends(require_pro("API Scanner"))])
async def start_scan(req: ApiScanRequest):
    job_id = str(uuid.uuid4())
    task = asyncio.create_task(_run_bg(job_id, req.target, req.options, req.project_id or None))
    _JOBS[job_id] = task
    return {"status": "started", "job_id": job_id, "tool": "api_scanner"}


@router.delete("/jobs/{job_id}")
async def cancel_scan(job_id: str):
    task = _JOBS.get(job_id)
    if not task:
        return {"error": "Job not found"}
    task.cancel()
    return {"status": "cancelled", "job_id": job_id}
