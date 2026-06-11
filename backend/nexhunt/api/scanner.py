import asyncio
import uuid
import re
import logging
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from nexhunt.database import get_session, DefaultSession
from nexhunt.models.finding import Finding
from nexhunt.schemas.scanner import ScanRequest, FindingUpdate
from nexhunt.adapters.base import get_adapter
from nexhunt.ws.manager import ws_manager
from nexhunt.licensing.guard import require_pro

router = APIRouter(prefix="/api/scanner", tags=["scanner"])
logger = logging.getLogger(__name__)

# Background job registry — keeps tasks alive even after HTTP connection closes
_SCAN_JOBS: dict[str, asyncio.Task] = {}


async def _run_scan_background(job_id: str, tool_name: str, target: str, options: dict, project_id: str | None = None):
    """Run a scan tool in a background task, independent of the HTTP connection."""
    adapter = get_adapter(tool_name)
    if not adapter:
        await ws_manager.broadcast("tool_status", {
            "tool": tool_name, "event": "failed", "job_id": job_id,
            "error": f"Adapter for '{tool_name}' not found",
        })
        return

    if not await adapter.check_installed():
        await ws_manager.broadcast("tool_status", {
            "tool": tool_name, "event": "failed", "job_id": job_id,
            "error": f"'{tool_name}' is not installed",
        })
        return

    await ws_manager.broadcast("tool_status", {
        "tool": tool_name, "event": "started", "job_id": job_id,
    })

    findings = []
    try:
        async for result in adapter.run(target, options):
            if result.get("_raw"):
                # Raw output line — stream to terminal, don't add to findings
                await ws_manager.broadcast("tool_output", {
                    "tool": tool_name, "line": result["line"],
                })
                continue

            # For gobuster/dirsearch: save 200, 204, 401, 403 as findings.
            # 301/302 redirects are terminal-only (noisy, rarely actionable).
            if tool_name in ("gobuster", "dirsearch"):
                title = result.get("title", "")
                m = re.search(r'\((\d+)\)', title)
                if m:
                    code = int(m.group(1))
                    if code in (301, 302):
                        await ws_manager.broadcast("tool_output", {
                            "tool": tool_name,
                            "line": f"→ {result.get('url', '')} ({code})",
                        })
                        continue  # Don't save 301/302 to DB — too noisy

            # Save to DB before broadcasting so we have an ID to include
            finding_id = str(uuid.uuid4())
            try:
                async with DefaultSession() as session:
                    db_finding = Finding(
                        id=finding_id,
                        project_id=project_id or None,
                        title=result.get("title", ""),
                        severity=result.get("severity", "info"),
                        vuln_type=result.get("vuln_type"),
                        url=result.get("url"),
                        parameter=result.get("parameter"),
                        evidence=result.get("evidence", "")[:2000] if result.get("evidence") else None,
                        description=result.get("description"),
                        tool=tool_name,
                        template_id=result.get("template_id"),
                        status=result.get("status", "new"),
                    )
                    session.add(db_finding)
                    await session.commit()
                result["id"] = finding_id
            except Exception as db_err:
                logger.warning(f"Failed to save finding to DB: {db_err}")

            findings.append(result)
            await ws_manager.broadcast("findings", {**result, "tool": tool_name, "project_id": project_id or ""})
    except asyncio.CancelledError:
        logger.info(f"Scan job {job_id} ({tool_name}) was cancelled")
        await ws_manager.broadcast("tool_status", {
            "tool": tool_name, "event": "cancelled", "job_id": job_id,
        })
        return
    except Exception as e:
        logger.error(f"Scan error [{tool_name}]: {e}")
        await ws_manager.broadcast("tool_status", {
            "tool": tool_name, "event": "failed", "job_id": job_id, "error": str(e),
        })
        return
    finally:
        _SCAN_JOBS.pop(job_id, None)

    await ws_manager.broadcast("tool_status", {
        "tool": tool_name, "event": "completed", "job_id": job_id, "count": len(findings),
    })
    logger.info(f"[{tool_name}] completed — {len(findings)} findings")


def _start_scan(tool_name: str, target: str, options: dict, project_id: str | None = None) -> dict:
    """Kick off a background scan task and return immediately."""
    job_id = str(uuid.uuid4())
    task = asyncio.create_task(
        _run_scan_background(job_id, tool_name, target, options, project_id)
    )
    _SCAN_JOBS[job_id] = task
    return {"status": "started", "job_id": job_id, "tool": tool_name, "target": target}


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("/nuclei")
async def run_nuclei(req: ScanRequest):
    return _start_scan("nuclei", req.target, req.options, req.project_id or None)


class NucleiBulkRequest(BaseModel):
    targets: list[str]
    options: dict = {}
    project_id: str = ""


@router.post("/nuclei-bulk", dependencies=[Depends(require_pro("Bulk Nuclei scanning"))])
async def run_nuclei_bulk(req: NucleiBulkRequest):
    """Run nuclei against a list of targets (e.g. all live hosts from httpx)."""
    if not req.targets:
        return {"error": "No targets provided"}
    opts = {**req.options, "targets": req.targets}
    label = req.targets[0] if len(req.targets) == 1 else f"{len(req.targets)} hosts"
    return _start_scan("nuclei", label, opts, req.project_id or None)


@router.post("/ffuf")
async def run_ffuf(req: ScanRequest):
    return _start_scan("ffuf", req.target, req.options, req.project_id or None)


@router.post("/nikto")
async def run_nikto(req: ScanRequest):
    return _start_scan("nikto", req.target, req.options, req.project_id or None)


@router.post("/gobuster")
async def run_gobuster(req: ScanRequest):
    return _start_scan("gobuster", req.target, req.options, req.project_id or None)


@router.post("/dirsearch")
async def run_dirsearch(req: ScanRequest):
    return _start_scan("dirsearch", req.target, req.options, req.project_id or None)


@router.get("/jobs")
async def list_jobs():
    """List currently running scan jobs."""
    return {
        job_id: {"done": task.done(), "cancelled": task.cancelled()}
        for job_id, task in _SCAN_JOBS.items()
    }


@router.delete("/jobs/{job_id}")
async def cancel_job(job_id: str):
    """Cancel a running scan job."""
    task = _SCAN_JOBS.get(job_id)
    if not task:
        return {"error": "Job not found"}
    task.cancel()
    return {"status": "cancelled", "job_id": job_id}


# ── Findings CRUD ──────────────────────────────────────────────────────────────

@router.delete("/findings")
async def delete_all_findings(project_id: str | None = None, session: AsyncSession = Depends(get_session)):
    """Delete findings — optionally filtered by project_id."""
    from sqlalchemy import delete as sa_delete
    q = sa_delete(Finding)
    if project_id:
        q = q.where(Finding.project_id == project_id)
    await session.execute(q)
    await session.commit()
    return {"status": "cleared"}


@router.get("/findings")
async def get_findings(project_id: str | None = None, session: AsyncSession = Depends(get_session)):
    query = select(Finding).order_by(Finding.created_at.desc())
    if project_id:
        query = query.where(Finding.project_id == project_id)
    result = await session.execute(query)
    findings = result.scalars().all()
    return [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "vuln_type": f.vuln_type,
            "url": f.url,
            "parameter": f.parameter,
            "evidence": f.evidence,
            "tool": f.tool,
            "status": f.status,
            "notes": f.notes,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in findings
    ]


@router.put("/findings/{finding_id}")
async def update_finding(
    finding_id: str,
    data: FindingUpdate,
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        return {"error": "Finding not found"}
    if data.status:
        finding.status = data.status
    if data.notes is not None:
        finding.notes = data.notes
    await session.commit()
    return {"status": "updated"}
