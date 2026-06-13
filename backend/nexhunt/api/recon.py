import asyncio
import uuid
import json
import logging
from fastapi import APIRouter, Depends
from nexhunt.schemas.recon import ReconRequest, HttpxProbeRequest
from nexhunt.adapters.base import get_adapter
from nexhunt.ws.manager import ws_manager
from nexhunt.licensing.guard import require_pro

router = APIRouter(prefix="/api/recon", tags=["recon"])
logger = logging.getLogger(__name__)


# ── Persistence helper ──────────────────────────────────────────────────────────

async def _save_recon_result(result_type: str, target: str, data: dict):
    """Persist a single recon result to the database."""
    from nexhunt.database import DefaultSession
    from nexhunt.models.recon_result import ReconResult
    try:
        async with DefaultSession() as session:
            r = ReconResult(type=result_type, target=target, data=json.dumps(data))
            session.add(r)
            await session.commit()
    except Exception as e:
        logger.warning(f"Failed to save recon result: {e}")


# ── Screenshot endpoints ────────────────────────────────────────────────────────

from pydantic import BaseModel as _BaseModel

class ScreenshotRequest(_BaseModel):
    url: str

class BulkScreenshotRequest(_BaseModel):
    urls: list[str]


@router.post("/screenshot")
async def take_screenshot(req: ScreenshotRequest):
    """Take a single screenshot of a URL using gowitness."""
    from nexhunt.config import settings as _settings
    job_id = str(uuid.uuid4())
    task = asyncio.create_task(_run_screenshot(job_id, req.url, _settings.screenshots_dir))
    _RECON_JOBS[job_id] = task
    return {"status": "started", "job_id": job_id, "url": req.url}


@router.post("/screenshots-bulk")
async def take_screenshots_bulk(req: BulkScreenshotRequest):
    """Take screenshots of multiple URLs."""
    from nexhunt.config import settings as _settings
    if not req.urls:
        return {"error": "No URLs provided"}
    job_id = str(uuid.uuid4())
    task = asyncio.create_task(_run_screenshots_bulk(job_id, req.urls, _settings.screenshots_dir))
    _RECON_JOBS[job_id] = task
    return {"status": "started", "job_id": job_id, "total": len(req.urls)}


@router.get("/screenshots")
async def list_screenshots():
    """List all taken screenshots."""
    import glob as _glob
    from nexhunt.config import settings as _settings
    files = sorted(
        _glob.glob(f"{_settings.screenshots_dir}/*.jpeg") +
        _glob.glob(f"{_settings.screenshots_dir}/*.jpg") +
        _glob.glob(f"{_settings.screenshots_dir}/*.png"),
        key=lambda f: __import__("os").path.getmtime(f),
        reverse=True,
    )
    return [
        {
            "filename": __import__("os").path.basename(f),
            "url": f"/screenshots/{__import__('os').path.basename(f)}",
            "size": __import__("os").path.getsize(f),
            "mtime": __import__("os").path.getmtime(f),
        }
        for f in files
    ]


@router.delete("/jobs/{job_id}")
async def cancel_recon_job(job_id: str):
    """Cancel a running recon job."""
    task = _RECON_JOBS.get(job_id)
    if not task:
        return {"error": "Job not found"}
    task.cancel()
    return {"status": "cancelled", "job_id": job_id}


@router.delete("/results")
async def clear_recon_results():
    """Delete all stored recon results from the database."""
    from nexhunt.database import DefaultSession
    from nexhunt.models.recon_result import ReconResult
    from sqlalchemy import delete as sa_delete
    async with DefaultSession() as session:
        await session.execute(sa_delete(ReconResult))
        await session.commit()
    return {"status": "cleared"}


@router.get("/results")
async def get_recon_results():
    """Return all stored recon results grouped by type."""
    from nexhunt.database import DefaultSession
    from nexhunt.models.recon_result import ReconResult
    from sqlalchemy import select
    async with DefaultSession() as session:
        rows = await session.execute(select(ReconResult).order_by(ReconResult.created_at))
        results = rows.scalars().all()
    grouped: dict[str, list] = {}
    for r in results:
        try:
            data = json.loads(r.data)
        except Exception:
            data = {"raw": r.data}
        grouped.setdefault(r.type, []).append(data)
    return grouped


async def _run_screenshot(job_id: str, url: str, screenshots_dir: str):
    from nexhunt.adapters.gowitness import GowitnessAdapter
    adapter = GowitnessAdapter()
    if not await adapter.check_installed():
        await ws_manager.broadcast("tool_status", {"tool": "gowitness", "event": "failed", "error": "gowitness not installed"})
        return
    await ws_manager.broadcast("tool_status", {"tool": "gowitness", "event": "started", "job_id": job_id})
    async for result in adapter.run(url, {"screenshots_dir": screenshots_dir}):
        if result.get("_raw"):
            await ws_manager.broadcast("tool_output", {"tool": "gowitness", "line": result["line"]})
        else:
            await ws_manager.broadcast("recon_results", {"tool": "gowitness", "type": "screenshot", "results": [result]})
            await _save_recon_result("screenshot", url, result)
    await ws_manager.broadcast("tool_status", {"tool": "gowitness", "event": "completed", "job_id": job_id})
    _RECON_JOBS.pop(job_id, None)


async def _run_screenshots_bulk(job_id: str, urls: list[str], screenshots_dir: str):
    from nexhunt.adapters.gowitness import GowitnessAdapter
    adapter = GowitnessAdapter()
    if not await adapter.check_installed():
        await ws_manager.broadcast("tool_status", {"tool": "gowitness", "event": "failed", "error": "gowitness not installed"})
        return
    await ws_manager.broadcast("tool_status", {"tool": "gowitness", "event": "started", "job_id": job_id, "total": len(urls)})
    done = 0
    for url in urls:
        async for result in adapter.run(url, {"screenshots_dir": screenshots_dir}):
            if result.get("_raw"):
                await ws_manager.broadcast("tool_output", {"tool": "gowitness", "line": result["line"]})
            else:
                await ws_manager.broadcast("recon_results", {"tool": "gowitness", "type": "screenshot", "results": [result]})
                await _save_recon_result("screenshot", url, result)
        done += 1
        await ws_manager.broadcast("tool_status", {"tool": "gowitness", "event": "progress", "done": done, "total": len(urls)})
    await ws_manager.broadcast("tool_status", {"tool": "gowitness", "event": "completed", "job_id": job_id, "total": done})
    _RECON_JOBS.pop(job_id, None)

# Background job registry
_RECON_JOBS: dict[str, asyncio.Task] = {}


async def _run_recon_background(job_id: str, tool_name: str, target: str, options: dict):
    """Run a recon tool in a background task, independent of HTTP connection lifecycle."""
    # katana-headless reuses the katana adapter with headless=True in options
    adapter_name = "katana" if tool_name == "katana-headless" else tool_name
    adapter = get_adapter(adapter_name)
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

    results = []
    try:
        async for result in adapter.run(target, options):
            if result.get("_raw"):
                await ws_manager.broadcast("tool_output", {
                    "tool": tool_name, "line": result["line"],
                })
                continue
            results.append(result)
            await ws_manager.broadcast("recon_results", {
                "tool": tool_name,
                "type": adapter.result_type,
                "results": [result],
            })
            await _save_recon_result(adapter.result_type, target, result)
    except asyncio.CancelledError:
        logger.info(f"Recon job {job_id} ({tool_name}) was cancelled")
        await ws_manager.broadcast("tool_status", {
            "tool": tool_name, "event": "cancelled", "job_id": job_id,
        })
        return
    except Exception as e:
        logger.error(f"Recon error [{tool_name}]: {e}")
        await ws_manager.broadcast("tool_status", {
            "tool": tool_name, "event": "failed", "job_id": job_id, "error": str(e),
        })
        return
    finally:
        _RECON_JOBS.pop(job_id, None)

    await ws_manager.broadcast("tool_status", {
        "tool": tool_name, "event": "completed", "job_id": job_id, "result_count": len(results),
    })
    logger.info(f"[{tool_name}] completed — {len(results)} results")


def _start_recon(tool_name: str, target: str, options: dict) -> dict:
    job_id = str(uuid.uuid4())
    task = asyncio.create_task(
        _run_recon_background(job_id, tool_name, target, options)
    )
    _RECON_JOBS[job_id] = task
    return {"status": "started", "job_id": job_id, "tool": tool_name, "target": target}


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("/subfinder")
async def run_subfinder(req: ReconRequest):
    return _start_recon("subfinder", req.target, req.options)


@router.post("/amass")
async def run_amass(req: ReconRequest):
    return _start_recon("amass", req.target, req.options)


@router.post("/httpx")
async def run_httpx(req: ReconRequest):
    return _start_recon("httpx", req.target, req.options)


@router.post("/httpx-probe")
async def run_httpx_probe(req: HttpxProbeRequest):
    """Probe a list of discovered subdomains with httpx to find live hosts."""
    if not req.targets:
        return {"error": "No targets provided"}

    job_id = str(uuid.uuid4())
    options = {**req.options, "targets": req.targets}

    async def _probe_background():
        adapter = get_adapter("httpx")
        if not adapter or not await adapter.check_installed():
            await ws_manager.broadcast("tool_status", {"tool": "httpx-probe", "event": "failed", "error": "httpx not installed"})
            return

        await ws_manager.broadcast("tool_status", {
            "tool": "httpx-probe", "event": "started", "total": len(req.targets),
        })
        results = []
        try:
            async for result in adapter.run("", options):
                if result.get("_raw"):
                    await ws_manager.broadcast("tool_output", {"tool": "httpx-probe", "line": result["line"]})
                    continue
                results.append(result)
                await ws_manager.broadcast("recon_results", {
                    "tool": "httpx", "type": "live_host", "results": [result],
                })
                await _save_recon_result("live_host", "", result)
        except Exception as e:
            logger.error(f"httpx-probe error: {e}")
            await ws_manager.broadcast("tool_status", {"tool": "httpx-probe", "event": "failed", "error": str(e)})
            return
        finally:
            _RECON_JOBS.pop(job_id, None)

        await ws_manager.broadcast("tool_status", {
            "tool": "httpx-probe", "event": "completed", "result_count": len(results),
        })

    task = asyncio.create_task(_probe_background())
    _RECON_JOBS[job_id] = task
    return {"status": "started", "job_id": job_id, "tool": "httpx-probe", "targets": len(req.targets)}


@router.post("/nmap")
async def run_nmap(req: ReconRequest):
    return _start_recon("nmap", req.target, req.options)


@router.post("/waybackurls")
async def run_waybackurls(req: ReconRequest):
    return _start_recon("waybackurls", req.target, req.options)


@router.post("/gau")
async def run_gau(req: ReconRequest):
    return _start_recon("gau", req.target, req.options)


@router.post("/katana")
async def run_katana(req: ReconRequest):
    return _start_recon("katana", req.target, req.options)


@router.post("/katana-headless")
async def run_katana_headless(req: ReconRequest):
    return _start_recon("katana-headless", req.target, {**req.options, "headless": True})


@router.post("/linkfinder")
async def run_linkfinder(req: ReconRequest):
    return _start_recon("linkfinder", req.target, req.options)


@router.post("/paramspider")
async def run_paramspider(req: ReconRequest):
    return _start_recon("paramspider", req.target, req.options)


@router.post("/arjun")
async def run_arjun(req: ReconRequest):
    return _start_recon("arjun", req.target, req.options)


@router.post("/full", dependencies=[Depends(require_pro("Full automated recon"))])
async def run_full_recon(req: ReconRequest):
    """Start a full recon pipeline in the background."""
    job_id = str(uuid.uuid4())

    async def _full_pipeline():
        await ws_manager.broadcast("tool_status", {"tool": "full_recon", "event": "started"})

        # Step 1: Subfinder + Amass in parallel
        subfinder_results: list = []
        amass_results: list = []

        async def _collect(tool_name: str, out: list):
            """Collect subdomain-type results (subfinder, amass)."""
            adapter = get_adapter(tool_name)
            if adapter and await adapter.check_installed():
                await ws_manager.broadcast("tool_status", {"tool": tool_name, "event": "started"})
                async for r in adapter.run(req.target, {}):
                    if r.get("_raw"):
                        await ws_manager.broadcast("tool_output", {"tool": tool_name, "line": r["line"]})
                        continue
                    out.append(r)
                    await ws_manager.broadcast("recon_results", {"tool": tool_name, "type": "subdomain", "results": [r]})
                    await _save_recon_result("subdomain", req.target, r)
                await ws_manager.broadcast("tool_status", {"tool": tool_name, "event": "completed", "result_count": len(out)})

        async def _collect_typed(tool_name: str):
            """Collect results using the adapter's own result_type (url, port, etc.)."""
            adapter = get_adapter(tool_name)
            if not adapter or not await adapter.check_installed():
                return
            await ws_manager.broadcast("tool_status", {"tool": tool_name, "event": "started"})
            count = 0
            async for r in adapter.run(req.target, {}):
                if r.get("_raw"):
                    await ws_manager.broadcast("tool_output", {"tool": tool_name, "line": r["line"]})
                    continue
                count += 1
                await ws_manager.broadcast("recon_results", {
                    "tool": tool_name,
                    "type": adapter.result_type,  # "url" for gau/waybackurls
                    "results": [r],
                })
                await _save_recon_result(adapter.result_type, req.target, r)
            await ws_manager.broadcast("tool_status", {"tool": tool_name, "event": "completed", "result_count": count})

        await asyncio.gather(
            _collect("subfinder", subfinder_results),
            _collect("amass", amass_results),
            return_exceptions=True,
        )

        # Deduplicate subdomains
        seen = set()
        subdomains = []
        for r in subfinder_results + amass_results:
            sub = r.get("subdomain", "")
            if sub and sub not in seen:
                seen.add(sub)
                subdomains.append(sub)

        # Step 2: httpx probe on all found subdomains
        if subdomains:
            httpx = get_adapter("httpx")
            if httpx and await httpx.check_installed():
                await ws_manager.broadcast("tool_status", {"tool": "httpx-probe", "event": "started", "total": len(subdomains)})
                live_count = 0
                try:
                    async for result in httpx.run("", {"targets": subdomains}):
                        if result.get("_raw"):
                            await ws_manager.broadcast("tool_output", {"tool": "httpx-probe", "line": result["line"]})
                            continue
                        live_count += 1
                        await ws_manager.broadcast("recon_results", {"tool": "httpx", "type": "live_host", "results": [result]})
                        await _save_recon_result("live_host", req.target, result)
                except Exception as e:
                    logger.error(f"httpx probe error in full recon: {e}")
                await ws_manager.broadcast("tool_status", {"tool": "httpx-probe", "event": "completed", "result_count": live_count})

        # Step 3: URL discovery in parallel
        await asyncio.gather(
            _collect_typed("waybackurls"),
            _collect_typed("gau"),
            return_exceptions=True,
        )

        await ws_manager.broadcast("tool_status", {"tool": "full_recon", "event": "completed"})
        _RECON_JOBS.pop(job_id, None)

    task = asyncio.create_task(_full_pipeline())
    _RECON_JOBS[job_id] = task
    return {"status": "started", "job_id": job_id, "tool": "full_recon"}


# ── Endpoint discovery ──────────────────────────────────────────────────────────

ENDPOINT_WORDLISTS: dict[str, list[str]] = {
    "api": [
        "/swagger", "/swagger-ui.html", "/swagger-ui/", "/swagger-ui/index.html",
        "/api/swagger", "/api/swagger-ui.html", "/api/docs", "/api/doc",
        "/api/v1/docs", "/api/v2/docs", "/api/v3/docs",
        "/openapi.json", "/openapi.yaml", "/api/openapi.json",
        "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
        "/docs", "/redoc",
        "/graphql", "/graphiql", "/playground", "/api/graphql",
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/api/health", "/health", "/healthz", "/ping", "/status",
        "/api/endpoints", "/api/routes", "/api/users", "/api/me",
    ],
    "wordpress": [
        "/wp-admin", "/wp-admin/", "/wp-login.php",
        "/wp-json/", "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
        "/wp-content/uploads/", "/wp-includes/",
        "/xmlrpc.php", "/wp-admin/admin-ajax.php",
        "/wp-cron.php", "/wp-content/debug.log",
        "/wp-sitemap.xml", "/wp-config.php.bak",
    ],
    "admin": [
        "/admin", "/admin/", "/admin/login", "/admin/dashboard",
        "/administrator", "/administrator/index.php",
        "/panel", "/control", "/cpanel", "/manage",
        "/manager", "/management", "/backend", "/backend/",
        "/superadmin", "/cms", "/console", "/dashboard",
        "/portal", "/secure", "/staff", "/maintenance",
    ],
    "sensitive": [
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/.git/HEAD", "/.git/config", "/.gitignore",
        "/config.json", "/config.yaml", "/config.yml",
        "/.aws/credentials", "/secrets.json",
        "/backup.zip", "/backup.tar.gz", "/dump.sql", "/database.sql",
        "/.DS_Store", "/web.config", "/.htaccess",
        "/robots.txt", "/sitemap.xml",
        "/server-status", "/.well-known/security.txt",
    ],
    "spring": [
        "/actuator", "/actuator/health", "/actuator/env",
        "/actuator/mappings", "/actuator/beans", "/actuator/info",
        "/actuator/logfile", "/actuator/httptrace", "/actuator/sessions",
        "/heapdump", "/jolokia", "/jolokia/list",
        "/api/actuator", "/management/health",
    ],
    "php": [
        "/info.php", "/phpinfo.php", "/test.php",
        "/phpmyadmin", "/phpmyadmin/", "/pma", "/pma/", "/myadmin",
        "/.env.example", "/artisan",
        "/storage/logs/laravel.log", "/index.php?debug=true",
    ],
    "login": [
        "/login", "/login/", "/signin", "/sign-in", "/sign_in",
        "/auth", "/auth/login", "/oauth", "/sso",
        "/user/login", "/account/login", "/accounts/login",
        "/session/new", "/users/sign_in",
    ],
}

# Combined "all" is the union, deduplicated and capped at 100
_ALL_PATHS = list(dict.fromkeys(p for paths in ENDPOINT_WORDLISTS.values() for p in paths))[:100]


class EndpointCheckRequest(_BaseModel):
    targets: list[str]
    categories: list[str] = []   # empty = all
    project_id: str = ""


@router.post("/check-endpoints", dependencies=[Depends(require_pro("Bulk endpoint discovery"))])
async def check_endpoints(req: EndpointCheckRequest):
    if not req.targets:
        return {"error": "No targets provided"}

    categories = req.categories or list(ENDPOINT_WORDLISTS.keys())
    paths: list[str] = []
    for cat in categories:
        paths.extend(ENDPOINT_WORDLISTS.get(cat, []))
    paths = list(dict.fromkeys(paths))[:100]  # deduplicate, cap at 100

    job_id = str(uuid.uuid4())
    task = asyncio.create_task(
        _run_endpoint_check(job_id, req.targets, paths, req.project_id or None)
    )
    _RECON_JOBS[job_id] = task
    return {"status": "started", "job_id": job_id, "tool": "endpoint_check", "url_count": len(req.targets) * len(paths)}


async def _run_endpoint_check(job_id: str, targets: list[str], paths: list[str], project_id: str | None):
    import shutil, tempfile, os
    httpx_bin = shutil.which("httpx")
    if not httpx_bin:
        await ws_manager.broadcast("tool_status", {
            "tool": "endpoint_check", "event": "failed", "job_id": job_id,
            "error": "httpx not installed",
        })
        return

    # Build full URL list: strip trailing slash from targets, prepend paths
    urls: list[str] = []
    for t in targets[:50]:  # max 50 live hosts
        base = t.rstrip("/")
        for p in paths:
            urls.append(base + p)

    fd, tmpfile = tempfile.mkstemp(suffix=".txt", prefix="nexhunt_ep_")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(urls))

        cmd = [
            httpx_bin,
            "-l", tmpfile,
            "-json", "-silent",
            "-follow-redirects",
            "-mc", "200,201,204,301,302,401,403,405,500",
            "-title",
            "-status-code",
            "-content-type",
            "-timeout", "8",
            "-threads", "50",
            "-no-color",
        ]

        await ws_manager.broadcast("tool_status", {
            "tool": "endpoint_check", "event": "started", "job_id": job_id,
            "total": len(urls),
        })
        await ws_manager.broadcast("tool_output", {
            "tool": "endpoint_check", "line": f"$ {' '.join(cmd)}",
        })

        count = 0
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )

        assert proc.stdout
        async for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                status = data.get("status-code") or data.get("status_code")
                result = {
                    "url": data.get("url", ""),
                    "status_code": status,
                    "title": data.get("title", ""),
                    "content_type": data.get("content-type", data.get("content_type", "")),
                }
                await ws_manager.broadcast("recon_results", {
                    "tool": "endpoint_check",
                    "type": "endpoint",
                    "results": [result],
                })
                await _save_recon_result("endpoint", project_id or "global", result)
                count += 1
            except (json.JSONDecodeError, KeyError):
                if line.strip():
                    await ws_manager.broadcast("tool_output", {
                        "tool": "endpoint_check", "line": line,
                    })
    except asyncio.CancelledError:
        await ws_manager.broadcast("tool_status", {
            "tool": "endpoint_check", "event": "cancelled", "job_id": job_id,
        })
        return
    except Exception as e:
        logger.error(f"Endpoint check error: {e}")
        await ws_manager.broadcast("tool_status", {
            "tool": "endpoint_check", "event": "failed", "job_id": job_id, "error": str(e),
        })
        return
    finally:
        if os.path.exists(tmpfile):
            try:
                os.unlink(tmpfile)
            except OSError:
                pass
        _RECON_JOBS.pop(job_id, None)

    await ws_manager.broadcast("tool_status", {
        "tool": "endpoint_check", "event": "completed", "job_id": job_id, "result_count": count,
    })
