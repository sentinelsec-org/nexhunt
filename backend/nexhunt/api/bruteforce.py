"""
Brute force via Hydra. Each attack runs in a separate external terminal window
(not the in-app terminal) so heavy CPU/IO does not fight the app and the user can
keep working in parallel. Output is tee'd to a log file that the API polls for
found credentials and run status.
"""
import os
import re
import shlex
import signal
import logging
import subprocess
import time
import uuid
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from nexhunt.config import settings
from nexhunt.licensing.guard import require_pro

router = APIRouter(prefix="/api/bruteforce", tags=["bruteforce"])
logger = logging.getLogger(__name__)

_DIR = os.path.join(settings.db_dir, "bruteforce")
os.makedirs(_DIR, exist_ok=True)

SERVICES = [
    "ssh", "ftp", "http-get", "http-post-form", "https-post-form",
    "mysql", "postgres", "rdp", "smb", "vnc", "telnet",
]

_DEFAULT_PORTS = {
    "ssh": 22, "ftp": 21, "http-get": 80, "http-post-form": 80,
    "https-post-form": 443, "mysql": 3306, "postgres": 5432,
    "rdp": 3389, "smb": 445, "vnc": 5900, "telnet": 23,
}

# In-memory job registry. {job_id: {"target", "service", "command", "started_at", "popen"}}
_JOBS: dict[str, dict] = {}

_SUCCESS_RE = re.compile(
    r"\[(\d+)\]\[([^\]]+)\]\s+host:\s+(\S+)\s+login:\s+(\S*)\s+password:\s+(.*)"
)


class BruteForceRequest(BaseModel):
    target: str
    service: str
    port: int | None = None
    login: str | None = None
    login_list: str | None = None
    password: str | None = None
    password_list: str | None = None
    combo_list: str | None = None
    threads: int = 16
    stop_on_first: bool = True
    # http-get / http-post-form
    form_path: str | None = None
    form_body: str | None = None
    fail_string: str | None = None
    success_string: str | None = None
    extra_args: str | None = None


def _build_command(req: BruteForceRequest, out_file: str) -> list[str]:
    if req.service not in SERVICES:
        raise ValueError(f"Unsupported service: {req.service}")

    cmd = ["hydra"]

    if req.combo_list:
        cmd += ["-C", req.combo_list]
    else:
        if req.login_list:
            cmd += ["-L", req.login_list]
        elif req.login:
            cmd += ["-l", req.login]
        else:
            raise ValueError("Provide a login or a login list")

        if req.password_list:
            cmd += ["-P", req.password_list]
        elif req.password:
            cmd += ["-p", req.password]
        else:
            raise ValueError("Provide a password or a password list")

    cmd += ["-t", str(max(1, min(req.threads, 64)))]
    if req.stop_on_first:
        cmd.append("-f")

    port = req.port or _DEFAULT_PORTS.get(req.service)
    if port:
        cmd += ["-s", str(port)]

    cmd += ["-o", out_file]

    if req.service in ("http-post-form", "https-post-form", "http-get"):
        if not req.form_path:
            raise ValueError("form_path is required for HTTP services")
        cmd.append(req.target)
        cmd.append(req.service)
        if req.service == "http-get":
            cmd.append(req.form_path)
        else:
            cond = req.fail_string or req.success_string or ""
            module = f"{req.form_path}:{req.form_body or ''}:{cond}"
            cmd.append(module)
    else:
        cmd.append(f"{req.service}://{req.target}")

    if req.extra_args:
        try:
            cmd += shlex.split(req.extra_args)
        except ValueError:
            pass

    return cmd


def _detect_terminal(script: str) -> list[str] | None:
    """Return the argv to launch `script` in an external terminal, or None."""
    from shutil import which
    if which("x-terminal-emulator"):
        return ["x-terminal-emulator", "-e", "bash", script]
    if which("gnome-terminal"):
        return ["gnome-terminal", "--", "bash", script]
    if which("konsole"):
        return ["konsole", "-e", "bash", script]
    if which("xfce4-terminal"):
        return ["xfce4-terminal", "-e", f"bash {shlex.quote(script)}"]
    if which("qterminal"):
        return ["qterminal", "-e", f"bash {script}"]
    if which("xterm"):
        return ["xterm", "-e", "bash", script]
    return None


def _write_wrapper(job_id: str, cmd: list[str]) -> str:
    script = os.path.join(_DIR, f"{job_id}.sh")
    log = os.path.join(_DIR, f"{job_id}.log")
    pid = os.path.join(_DIR, f"{job_id}.pid")
    quoted = " ".join(shlex.quote(c) for c in cmd)
    content = f"""#!/usr/bin/env bash
echo "==================================================="
echo " NexHunt Brute Force"
echo " Command: {quoted}"
echo "==================================================="
echo
{quoted} 2>&1 | tee {shlex.quote(log)} &
HPID=$!
echo $HPID > {shlex.quote(pid)}
wait $HPID
rm -f {shlex.quote(pid)}
echo
echo "=== Finished. Press Enter to close ==="
read _
"""
    with open(script, "w") as f:
        f.write(content)
    os.chmod(script, 0o755)
    return script


def _job_status(job_id: str) -> str:
    pid_file = os.path.join(_DIR, f"{job_id}.pid")
    if os.path.exists(pid_file):
        try:
            with open(pid_file) as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            return "running"
        except (OSError, ValueError):
            return "finished"
    log = os.path.join(_DIR, f"{job_id}.log")
    return "finished" if os.path.exists(log) else "starting"


def _parse_found(job_id: str) -> list[dict]:
    log = os.path.join(_DIR, f"{job_id}.log")
    found = []
    try:
        with open(log, errors="replace") as f:
            for line in f:
                m = _SUCCESS_RE.search(line)
                if m:
                    found.append({
                        "port": int(m.group(1)),
                        "service": m.group(2),
                        "host": m.group(3),
                        "login": m.group(4),
                        "password": m.group(5).strip(),
                    })
    except OSError:
        pass
    return found


def _log_tail(job_id: str, lines: int = 40) -> str:
    log = os.path.join(_DIR, f"{job_id}.log")
    try:
        with open(log, errors="replace") as f:
            return "".join(f.readlines()[-lines:])
    except OSError:
        return ""


@router.get("/services")
async def list_services():
    return {"services": SERVICES, "default_ports": _DEFAULT_PORTS}


@router.post("/start", dependencies=[Depends(require_pro("Brute force"))])
async def start(req: BruteForceRequest):
    if not req.target.strip():
        raise HTTPException(400, "Target is required")
    job_id = str(uuid.uuid4())
    out_file = os.path.join(_DIR, f"{job_id}.out")
    try:
        cmd = _build_command(req, out_file)
    except ValueError as e:
        raise HTTPException(400, str(e))

    script = _write_wrapper(job_id, cmd)
    argv = _detect_terminal(script)
    if not argv:
        raise HTTPException(500, "No terminal emulator found. Install xterm.")

    try:
        popen = subprocess.Popen(
            argv, start_new_session=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        logger.error(f"Failed to launch terminal: {e}")
        raise HTTPException(500, f"Could not open terminal: {e}")

    _JOBS[job_id] = {
        "target": req.target,
        "service": req.service,
        "command": " ".join(shlex.quote(c) for c in cmd),
        "started_at": int(time.time()),
        "popen": popen,
    }
    return {"job_id": job_id, "status": "started"}


@router.get("/jobs")
async def list_jobs():
    return {
        "jobs": [
            {
                "job_id": jid,
                "target": j["target"],
                "service": j["service"],
                "started_at": j["started_at"],
                "status": _job_status(jid),
                "found": len(_parse_found(jid)),
            }
            for jid, j in sorted(_JOBS.items(), key=lambda kv: kv[1]["started_at"], reverse=True)
        ]
    }


@router.get("/jobs/{job_id}")
async def job_detail(job_id: str):
    j = _JOBS.get(job_id)
    if not j:
        raise HTTPException(404, "Job not found")
    return {
        "job_id": job_id,
        "target": j["target"],
        "service": j["service"],
        "command": j["command"],
        "started_at": j["started_at"],
        "status": _job_status(job_id),
        "found": _parse_found(job_id),
        "log_tail": _log_tail(job_id),
    }


@router.delete("/jobs/{job_id}")
async def kill_job(job_id: str):
    if job_id not in _JOBS:
        raise HTTPException(404, "Job not found")
    pid_file = os.path.join(_DIR, f"{job_id}.pid")
    try:
        with open(pid_file) as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
    except (OSError, ValueError):
        pass
    return {"status": "killed", "job_id": job_id}
