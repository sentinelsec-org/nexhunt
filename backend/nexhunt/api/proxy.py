import asyncio
import json
import logging
import os
import re
import time
import uuid
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from nexhunt.database import get_session
from nexhunt.models.http_flow import HttpFlow
from nexhunt.schemas.proxy import (
    ProxySettings, InterceptToggle, RepeaterRequest,
    RawRepeaterRequest, IntruderConfig,
)
from nexhunt.proxy.engine import proxy_engine
from nexhunt.licensing.guard import require_pro

router = APIRouter(prefix="/api/proxy", tags=["proxy"])
logger = logging.getLogger(__name__)

# ── Intruder job registry ──────────────────────────────────────────────────────
_INTRUDER_JOBS: dict[str, asyncio.Task] = {}


def _parse_raw_request(raw: str, host: str, port: int, use_https: bool):
    """Return (method, url, headers, body) from a raw HTTP request string."""
    lines = raw.replace('\r\n', '\n').split('\n')
    first = lines[0].strip().split(' ', 2)
    method = first[0] if first else 'GET'
    path = first[1] if len(first) > 1 else '/'

    headers: dict[str, str] = {}
    body_start: int | None = None
    for i, line in enumerate(lines[1:], 1):
        if line.strip() == '':
            body_start = i + 1
            break
        if ':' in line:
            k, v = line.split(':', 1)
            k = k.strip()
            if k.lower() != 'host':   # httpx sets Host from URL
                headers[k] = v.strip()

    body: str | None = None
    if body_start and body_start < len(lines):
        body = '\n'.join(lines[body_start:]).strip() or None

    scheme = 'https' if use_https else 'http'
    url = f"{scheme}://{host}:{port}{path}"
    return method, url, headers, body


async def _run_intruder(job_id: str, config: IntruderConfig):
    """Background task that runs the intruder attack and streams results via WS."""
    from nexhunt.ws.manager import ws_manager
    import httpx
    import itertools

    # Find all §marker§ positions
    markers = list(re.finditer(r'§([^§\n]*)§', config.raw_request))
    if not markers:
        await ws_manager.broadcast("intruder", {
            "job_id": job_id, "event": "error", "message": "No §positions§ found in request"
        })
        return

    n_positions = len(markers)
    defaults = [m.group(1) for m in markers]

    # Build attack combinations
    if config.attack_type == "sniper":
        pl = config.payloads[0] if config.payloads else []
        combos: list[list[str]] = []
        for pos_idx in range(n_positions):
            for payload in pl:
                subs = list(defaults)
                subs[pos_idx] = payload
                combos.append(subs)
    elif config.attack_type == "cluster_bomb":
        pl_lists = list(config.payloads[:n_positions])
        while len(pl_lists) < n_positions:
            pl_lists.append(pl_lists[-1] if pl_lists else [''])
        combos = [list(c) for c in itertools.product(*pl_lists)]
    elif config.attack_type == "pitchfork":
        pl_lists = list(config.payloads[:n_positions])
        while len(pl_lists) < n_positions:
            pl_lists.append(pl_lists[-1] if pl_lists else [''])
        min_len = min(len(p) for p in pl_lists)
        combos = [[pl_lists[pi][i] for pi in range(n_positions)] for i in range(min_len)]
    else:
        combos = []

    total = len(combos)
    await ws_manager.broadcast("intruder", {
        "job_id": job_id, "event": "started", "total": total
    })

    sem = asyncio.Semaphore(config.concurrency)

    async def send_one(idx: int, subs: list[str]):
        async with sem:
            # Substitute markers in order
            req_text = config.raw_request
            for i, m in enumerate(markers):
                req_text = req_text.replace(f"§{defaults[i]}§", subs[i], 1)

            method, url, headers, body = _parse_raw_request(
                req_text, config.host, config.port, config.use_https
            )
            payload_display = subs[0] if len(subs) == 1 else ' | '.join(subs)

            try:
                t0 = time.monotonic()
                async with httpx.AsyncClient(verify=False, timeout=config.timeout, follow_redirects=False) as client:
                    resp = await client.request(
                        method, url, headers=headers,
                        content=body.encode() if body else None
                    )
                duration = (time.monotonic() - t0) * 1000
                result = {
                    "job_id": job_id, "event": "result",
                    "index": idx, "payload": payload_display,
                    "status": resp.status_code,
                    "length": len(resp.content),
                    "duration_ms": round(duration, 1),
                    "error": None,
                }
            except Exception as e:
                result = {
                    "job_id": job_id, "event": "result",
                    "index": idx, "payload": payload_display,
                    "status": 0, "length": 0, "duration_ms": 0,
                    "error": str(e)[:120],
                }
            await ws_manager.broadcast("intruder", result)

    try:
        await asyncio.gather(*[send_one(i, subs) for i, subs in enumerate(combos)])
    except asyncio.CancelledError:
        await ws_manager.broadcast("intruder", {"job_id": job_id, "event": "cancelled"})
        return
    finally:
        _INTRUDER_JOBS.pop(job_id, None)

    await ws_manager.broadcast("intruder", {
        "job_id": job_id, "event": "completed", "total": total
    })


@router.post("/start")
async def start_proxy():
    """Start the intercepting proxy."""
    await proxy_engine.start()
    return {"status": "started", "port": proxy_engine.port}


@router.post("/stop")
async def stop_proxy():
    """Stop the intercepting proxy."""
    await proxy_engine.stop()
    return {"status": "stopped"}


@router.post("/open-browser")
async def open_browser():
    """Launch Chromium configured to use the proxy."""
    import subprocess, shutil
    port = proxy_engine.port or 8080
    chromium = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
    if not chromium:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Chromium not found")

    cert_path = proxy_engine.get_cert_path()
    nss_dir = os.path.expanduser("~/.pki/nssdb")

    # Install mitmproxy CA into the NSS db once so Chromium trusts HTTPS
    if cert_path and os.path.isdir(nss_dir):
        try:
            subprocess.run(
                ["certutil", "-A", "-n", "mitmproxy-nexhunt", "-t", "CT,,",
                 "-i", cert_path, "-d", nss_dir],
                capture_output=True
            )
        except FileNotFoundError:
            pass  # certutil not available

    env = {**os.environ}
    if "DISPLAY" not in env:
        env["DISPLAY"] = ":0"

    subprocess.Popen(
        [chromium,
         f"--proxy-server=127.0.0.1:{port}",
         "--ignore-certificate-errors",
         "--no-first-run",
         "--no-default-browser-check",
         "--no-sandbox"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    return {"status": "launched", "proxy": f"127.0.0.1:{port}"}


@router.get("/status")
async def proxy_status():
    """Get proxy status."""
    return {
        "running": proxy_engine.running,
        "port": proxy_engine.port,
        "intercept_enabled": proxy_engine.intercept_enabled
    }


@router.get("/history")
async def get_history(
    page: int = Query(1, ge=1),
    limit: int = Query(100, ge=1, le=1000),
    host: str | None = None,
    method: str | None = None,
    status_code: int | None = None,
    search: str | None = None,
    session: AsyncSession = Depends(get_session)
):
    """Get paginated HTTP history."""
    query = select(HttpFlow).order_by(desc(HttpFlow.timestamp))

    if host:
        query = query.where(HttpFlow.request_host.contains(host))
    if method:
        query = query.where(HttpFlow.request_method == method)
    if status_code:
        query = query.where(HttpFlow.response_status == status_code)
    if search:
        query = query.where(HttpFlow.request_url.contains(search))

    query = query.offset((page - 1) * limit).limit(limit)
    result = await session.execute(query)
    flows = result.scalars().all()

    return [_flow_to_dict(f) for f in flows]


@router.get("/flow/{flow_id}")
async def get_flow(flow_id: str, session: AsyncSession = Depends(get_session)):
    """Get full details of a specific flow."""
    result = await session.execute(select(HttpFlow).where(HttpFlow.id == flow_id))
    flow = result.scalar_one_or_none()
    if not flow:
        return {"error": "Flow not found"}
    return _flow_to_dict(flow, include_bodies=True)


@router.post("/intercept/toggle")
async def toggle_intercept(data: InterceptToggle):
    """Toggle intercept mode."""
    proxy_engine.intercept_enabled = data.enabled
    return {"intercept_enabled": data.enabled}


@router.post("/repeater")
async def repeater_send(req: RepeaterRequest):
    """Send a request via the repeater."""
    import httpx
    async with httpx.AsyncClient(verify=False) as client:
        response = await client.request(
            method=req.method,
            url=req.url,
            headers=req.headers,
            content=req.body
        )
        return {
            "status": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:10000],  # Limit response size
            "duration_ms": response.elapsed.total_seconds() * 1000
        }


@router.post("/repeat-raw")
async def repeat_raw(req: RawRepeaterRequest):
    """Send a raw HTTP request (with editable headers/body) and return the response."""
    import httpx
    method, url, headers, body = _parse_raw_request(
        req.raw_request, req.host, req.port, req.use_https
    )
    try:
        t0 = time.monotonic()
        async with httpx.AsyncClient(verify=False, timeout=30, follow_redirects=False) as client:
            resp = await client.request(
                method, url, headers=headers,
                content=body.encode() if body else None
            )
        duration = (time.monotonic() - t0) * 1000
        return {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:100_000],
            "duration_ms": round(duration, 1),
        }
    except Exception as e:
        return {"error": str(e), "status": 0, "headers": {}, "body": "", "duration_ms": 0}


@router.post("/intruder/start", dependencies=[Depends(require_pro("Proxy Intruder"))])
async def intruder_start(config: IntruderConfig):
    """Start an intruder attack. Results stream via WebSocket channel 'intruder'."""
    job_id = str(uuid.uuid4())
    task = asyncio.create_task(_run_intruder(job_id, config))
    _INTRUDER_JOBS[job_id] = task
    return {"job_id": job_id, "status": "started"}


@router.delete("/intruder/{job_id}")
async def intruder_stop(job_id: str):
    """Cancel a running intruder job."""
    task = _INTRUDER_JOBS.get(job_id)
    if not task:
        return {"error": "Job not found"}
    task.cancel()
    return {"status": "cancelled", "job_id": job_id}


@router.post("/flow")
async def receive_flow(data: dict, session: AsyncSession = Depends(get_session)):
    """Called by mitm_addon.py for every completed flow."""
    from nexhunt.ws.manager import ws_manager
    await ws_manager.broadcast("proxy_feed", data)
    try:
        flow = HttpFlow(
            id=data["id"],
            request_method=data["request_method"],
            request_url=data["request_url"],
            request_host=data["request_host"],
            request_port=data["request_port"],
            request_path=data["request_path"],
            request_headers=json.dumps(data["request_headers"]),
            request_body=data["request_body"].encode() if data.get("request_body") else None,
            response_status=data.get("response_status", 0),
            response_headers=json.dumps(data.get("response_headers", {})),
            response_body=data["response_body"].encode() if data.get("response_body") else None,
            content_type=data.get("content_type"),
            response_length=data.get("response_length", 0),
            duration_ms=data.get("duration_ms", 0),
            is_intercepted=data.get("is_intercepted", False),
            tags=json.dumps(data.get("tags", [])),
        )
        session.add(flow)
        await session.commit()
    except Exception as e:
        logger.error(f"Failed to save flow: {e}")
    return {"ok": True}


@router.get("/cert")
async def download_cert():
    """Download CA certificate for HTTPS interception."""
    from fastapi.responses import FileResponse
    cert_path = proxy_engine.get_cert_path()
    if cert_path:
        return FileResponse(cert_path, filename="nexhunt-ca-cert.crt", media_type="application/x-x509-ca-cert")
    return {"error": "Certificate not found. Start the proxy first."}


def _flow_to_dict(flow: HttpFlow, include_bodies: bool = False) -> dict:
    d = {
        "id": flow.id,
        "request_method": flow.request_method,
        "request_url": flow.request_url,
        "request_host": flow.request_host,
        "request_port": flow.request_port,
        "request_path": flow.request_path,
        "request_headers": json.loads(flow.request_headers) if flow.request_headers else {},
        "response_status": flow.response_status,
        "response_headers": json.loads(flow.response_headers) if flow.response_headers else {},
        "content_type": flow.content_type,
        "response_length": flow.response_length,
        "duration_ms": flow.duration_ms,
        "is_intercepted": flow.is_intercepted,
        "timestamp": flow.timestamp.isoformat() if flow.timestamp else None,
        "tags": json.loads(flow.tags) if flow.tags else [],
    }
    if include_bodies:
        d["request_body"] = flow.request_body.decode("utf-8", errors="replace") if flow.request_body else None
        d["response_body"] = flow.response_body.decode("utf-8", errors="replace") if flow.response_body else None
    return d
