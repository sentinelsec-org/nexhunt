"""
Built-in terminal — run any shell command from within NexHunt.
Commands stream output in real-time via WebSocket channel "terminal".
"""
import asyncio
import logging
import uuid
import os
from fastapi import APIRouter
from pydantic import BaseModel
from nexhunt.ws.manager import ws_manager

router = APIRouter(prefix="/api/terminal", tags=["terminal"])
logger = logging.getLogger(__name__)

_JOBS: dict[str, asyncio.Task] = {}


class ExecRequest(BaseModel):
    command: str
    job_id: str | None = None


class KillRequest(BaseModel):
    job_id: str


@router.post("/exec")
async def exec_command(req: ExecRequest):
    """Start a shell command. Output streams via WS channel 'terminal'."""
    if not req.command.strip():
        return {"error": "Empty command"}

    job_id = req.job_id or str(uuid.uuid4())

    # Cancel any existing job with same id
    if job_id in _JOBS and not _JOBS[job_id].done():
        _JOBS[job_id].cancel()

    task = asyncio.create_task(_run(job_id, req.command.strip()))
    _JOBS[job_id] = task
    return {"status": "started", "job_id": job_id}


@router.delete("/jobs/{job_id}")
async def kill_job(job_id: str):
    """Kill a running terminal command."""
    task = _JOBS.get(job_id)
    if not task:
        return {"error": "Job not found"}
    if not task.done():
        task.cancel()
    return {"status": "killed", "job_id": job_id}


@router.get("/jobs")
async def list_jobs():
    return {
        jid: {"done": task.done()}
        for jid, task in _JOBS.items()
    }


async def _run(job_id: str, command: str):
    await ws_manager.broadcast("terminal", {
        "job_id": job_id,
        "event": "started",
        "command": command,
    })

    proc = None
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,  # merge stderr into stdout
            env={**os.environ, "TERM": "xterm-256color"},
        )

        assert proc.stdout is not None
        while True:
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=0.5)
            except asyncio.TimeoutError:
                if proc.returncode is not None:
                    break
                continue

            if not line:
                break

            decoded = line.decode("utf-8", errors="replace")
            await ws_manager.broadcast("terminal", {
                "job_id": job_id,
                "event": "output",
                "line": decoded,
            })

        await proc.wait()
        exit_code = proc.returncode

    except asyncio.CancelledError:
        if proc and proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        await ws_manager.broadcast("terminal", {
            "job_id": job_id,
            "event": "killed",
        })
        _JOBS.pop(job_id, None)
        return
    except Exception as e:
        await ws_manager.broadcast("terminal", {
            "job_id": job_id,
            "event": "error",
            "message": str(e),
        })
        _JOBS.pop(job_id, None)
        return

    await ws_manager.broadcast("terminal", {
        "job_id": job_id,
        "event": "completed",
        "exit_code": exit_code,
    })
    _JOBS.pop(job_id, None)
