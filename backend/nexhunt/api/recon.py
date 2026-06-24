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

async def _save_recon_result(result_type: str, target: str, data: dict, project_id: str | None = None):
    """Persist a single recon result to the database."""
    from nexhunt.database import DefaultSession
    from nexhunt.models.recon_result import ReconResult
    try:
        async with DefaultSession() as session:
            r = ReconResult(type=result_type, target=target, project_id=project_id, data=json.dumps(data))
            session.add(r)
            await session.commit()
    except Exception as e:
        logger.warning(f"Failed to save recon result: {e}")


# ── Screenshot endpoints ────────────────────────────────────────────────────────

from pydantic import BaseModel as _BaseModel

class ScreenshotRequest(_BaseModel):
    url: str
    project_id: str = ""

class BulkScreenshotRequest(_BaseModel):
    urls: list[str]
    project_id: str = ""


@router.post("/screenshot")
async def take_screenshot(req: ScreenshotRequest):
    """Take a single screenshot of a URL using gowitness."""
    from nexhunt.config import settings as _settings
    job_id = str(uuid.uuid4())
    task = asyncio.create_task(_run_screenshot(job_id, req.url, _settings.screenshots_dir, req.project_id or None))
    _RECON_JOBS[job_id] = task
    return {"status": "started", "job_id": job_id, "url": req.url}


@router.post("/screenshots-bulk")
async def take_screenshots_bulk(req: BulkScreenshotRequest):
    """Take screenshots of multiple URLs."""
    from nexhunt.config import settings as _settings
    if not req.urls:
        return {"error": "No URLs provided"}
    job_id = str(uuid.uuid4())
    task = asyncio.create_task(_run_screenshots_bulk(job_id, req.urls, _settings.screenshots_dir, req.project_id or None))
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
async def clear_recon_results(project_id: str | None = None):
    """Delete stored recon results — optionally scoped to a single project."""
    from nexhunt.database import DefaultSession
    from nexhunt.models.recon_result import ReconResult
    from sqlalchemy import delete as sa_delete
    async with DefaultSession() as session:
        q = sa_delete(ReconResult)
        if project_id:
            q = q.where(ReconResult.project_id == project_id)
        await session.execute(q)
        await session.commit()
    return {"status": "cleared"}


@router.get("/results")
async def get_recon_results(project_id: str | None = None):
    """Return stored recon results grouped by type, scoped to a project."""
    from nexhunt.database import DefaultSession
    from nexhunt.models.recon_result import ReconResult
    from sqlalchemy import select
    async with DefaultSession() as session:
        query = select(ReconResult).order_by(ReconResult.created_at)
        if project_id:
            query = query.where(ReconResult.project_id == project_id)
        rows = await session.execute(query)
        results = rows.scalars().all()
    grouped: dict[str, list] = {}
    for r in results:
        try:
            data = json.loads(r.data)
        except Exception:
            data = {"raw": r.data}
        grouped.setdefault(r.type, []).append(data)
    return grouped


async def _run_screenshot(job_id: str, url: str, screenshots_dir: str, project_id: str | None = None):
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
            await ws_manager.broadcast("recon_results", {"tool": "gowitness", "type": "screenshot", "results": [result], "project_id": project_id or ""})
            await _save_recon_result("screenshot", url, result, project_id)
    await ws_manager.broadcast("tool_status", {"tool": "gowitness", "event": "completed", "job_id": job_id})
    _RECON_JOBS.pop(job_id, None)


async def _run_screenshots_bulk(job_id: str, urls: list[str], screenshots_dir: str, project_id: str | None = None):
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
                await ws_manager.broadcast("recon_results", {"tool": "gowitness", "type": "screenshot", "results": [result], "project_id": project_id or ""})
                await _save_recon_result("screenshot", url, result, project_id)
        done += 1
        await ws_manager.broadcast("tool_status", {"tool": "gowitness", "event": "progress", "done": done, "total": len(urls)})
    await ws_manager.broadcast("tool_status", {"tool": "gowitness", "event": "completed", "job_id": job_id, "total": done})
    _RECON_JOBS.pop(job_id, None)

# Background job registry
_RECON_JOBS: dict[str, asyncio.Task] = {}


async def _run_recon_background(job_id: str, tool_name: str, target: str, options: dict, project_id: str | None = None):
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
                "project_id": project_id or "",
            })
            await _save_recon_result(adapter.result_type, target, result, project_id)
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


def _start_recon(tool_name: str, target: str, options: dict, project_id: str | None = None) -> dict:
    job_id = str(uuid.uuid4())
    task = asyncio.create_task(
        _run_recon_background(job_id, tool_name, target, options, project_id)
    )
    _RECON_JOBS[job_id] = task
    return {"status": "started", "job_id": job_id, "tool": tool_name, "target": target}


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("/subfinder")
async def run_subfinder(req: ReconRequest):
    return _start_recon("subfinder", req.target, req.options, req.project_id or None)


@router.post("/amass")
async def run_amass(req: ReconRequest):
    return _start_recon("amass", req.target, req.options, req.project_id or None)


@router.post("/gobuster-dns")
async def run_gobuster_dns(req: ReconRequest):
    return _start_recon("gobuster-dns", req.target, req.options, req.project_id or None)


@router.post("/httpx")
async def run_httpx(req: ReconRequest):
    return _start_recon("httpx", req.target, req.options, req.project_id or None)


class LiveHostAddRequest(_BaseModel):
    url: str
    project_id: str = ""


@router.post("/live-host")
async def add_live_host(req: LiveHostAddRequest):
    """Manually add a live host (e.g. one found in a captured request)."""
    from urllib.parse import urlparse
    url = req.url.strip()
    if not url:
        return {"error": "No URL provided"}
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    host = urlparse(url).netloc or url
    result = {
        "url": url, "host": host, "status_code": None, "title": "",
        "technologies": [], "content_type": "", "ip": "",
    }
    await _save_recon_result("live_host", host, result, req.project_id or None)
    await ws_manager.broadcast("recon_results", {"tool": "manual", "type": "live_host", "results": [result], "project_id": req.project_id or ""})
    return {"status": "added", "url": url}


@router.delete("/live-host")
async def delete_live_host(url: str):
    """Permanently delete a stored live host by its URL (data is a JSON blob, so filter in Python)."""
    from nexhunt.database import DefaultSession
    from nexhunt.models.recon_result import ReconResult
    from sqlalchemy import select, delete as sa_delete
    deleted = 0
    async with DefaultSession() as session:
        rows = await session.execute(
            select(ReconResult).where(ReconResult.type == "live_host")
        )
        for r in rows.scalars().all():
            try:
                if json.loads(r.data).get("url") == url:
                    await session.execute(sa_delete(ReconResult).where(ReconResult.id == r.id))
                    deleted += 1
            except Exception:
                continue
        await session.commit()
    return {"status": "deleted", "url": url, "count": deleted}


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
                    "project_id": req.project_id or "",
                })
                await _save_recon_result("live_host", "", result, req.project_id or None)
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
    return _start_recon("nmap", req.target, req.options, req.project_id or None)


@router.post("/waybackurls")
async def run_waybackurls(req: ReconRequest):
    return _start_recon("waybackurls", req.target, req.options, req.project_id or None)


@router.post("/gau")
async def run_gau(req: ReconRequest):
    return _start_recon("gau", req.target, req.options, req.project_id or None)


@router.post("/katana")
async def run_katana(req: ReconRequest):
    return _start_recon("katana", req.target, req.options, req.project_id or None)


@router.post("/katana-headless")
async def run_katana_headless(req: ReconRequest):
    return _start_recon("katana-headless", req.target, {**req.options, "headless": True}, req.project_id or None)


@router.post("/linkfinder")
async def run_linkfinder(req: ReconRequest):
    return _start_recon("linkfinder", req.target, req.options, req.project_id or None)


@router.post("/paramspider")
async def run_paramspider(req: ReconRequest):
    return _start_recon("paramspider", req.target, req.options, req.project_id or None)


@router.post("/arjun")
async def run_arjun(req: ReconRequest):
    return _start_recon("arjun", req.target, req.options, req.project_id or None)


@router.post("/full", dependencies=[Depends(require_pro("Full automated recon"))])
async def run_full_recon(req: ReconRequest):
    """Start a full recon pipeline in the background."""
    job_id = str(uuid.uuid4())

    project_id = req.project_id or None

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
                    await ws_manager.broadcast("recon_results", {"tool": tool_name, "type": "subdomain", "results": [r], "project_id": project_id or ""})
                    await _save_recon_result("subdomain", req.target, r, project_id)
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
                    "project_id": project_id or "",
                })
                await _save_recon_result(adapter.result_type, req.target, r, project_id)
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
                        await ws_manager.broadcast("recon_results", {"tool": "httpx", "type": "live_host", "results": [result], "project_id": project_id or ""})
                        await _save_recon_result("live_host", req.target, result, project_id)
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
        "/swagger/index.html", "/swagger-resources", "/swagger.json", "/swagger.yaml",
        "/api/swagger", "/api/swagger-ui.html", "/api/swagger.json",
        "/api/docs", "/api/doc", "/api-docs", "/api-docs/", "/v2/api-docs", "/v3/api-docs",
        "/api/v1/docs", "/api/v2/docs", "/api/v3/docs",
        "/openapi.json", "/openapi.yaml", "/api/openapi.json", "/openapi/v3",
        "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
        "/docs", "/redoc", "/rapidoc", "/api/explorer",
        "/graphql", "/graphiql", "/playground", "/api/graphql", "/graphql/console", "/v1/graphql",
        "/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/rest/v1",
        "/api/health", "/health", "/healthz", "/livez", "/readyz", "/ping", "/status", "/api/status",
        "/api/endpoints", "/api/routes", "/api/users", "/api/me", "/api/version", "/version",
        "/wsdl", "/services", "/soap",
    ],
    "wordpress": [
        "/wp-admin", "/wp-admin/", "/wp-login.php", "/wp-admin/install.php",
        "/wp-json/", "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts", "/wp-json/wp/v2/pages",
        "/wp-json/oembed/1.0/embed",
        "/wp-content/uploads/", "/wp-content/plugins/", "/wp-content/themes/", "/wp-includes/",
        "/xmlrpc.php", "/wp-admin/admin-ajax.php", "/wp-trackback.php",
        "/wp-cron.php", "/wp-content/debug.log", "/wp-content/uploads/dump.sql",
        "/wp-sitemap.xml", "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.save",
        "/wp-config-sample.php", "/readme.html", "/license.txt",
    ],
    "admin": [
        "/admin", "/admin/", "/admin/login", "/admin/dashboard", "/admin/index.php",
        "/admin.php", "/admin/admin.php", "/adminer.php", "/adminer",
        "/administrator", "/administrator/index.php",
        "/panel", "/control", "/cpanel", "/manage", "/admin/config",
        "/manager", "/manager/html", "/management", "/backend", "/backend/",
        "/superadmin", "/cms", "/console", "/dashboard", "/admin-console",
        "/portal", "/secure", "/staff", "/maintenance", "/webadmin", "/sysadmin",
        "/admin/users", "/admin/settings",
    ],
    "sensitive": [
        "/.env", "/.env.local", "/.env.dev", "/.env.development", "/.env.production",
        "/.env.staging", "/.env.test", "/.env.backup", "/.env.bak", "/.env.save",
        "/.git/HEAD", "/.git/config", "/.git/index", "/.git/logs/HEAD", "/.gitignore",
        "/.svn/entries", "/.svn/wc.db", "/.hg/", "/.bzr/",
        "/config.json", "/config.yaml", "/config.yml", "/config.php", "/configuration.php",
        "/settings.py", "/settings.json", "/appsettings.json", "/application.properties", "/application.yml",
        "/.aws/credentials", "/.aws/config", "/secrets.json", "/credentials.json",
        "/.npmrc", "/.dockercfg", "/.docker/config.json",
        "/.DS_Store", "/web.config", "/.htaccess", "/.htpasswd",
        "/server-status", "/server-info", "/.well-known/security.txt",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/.well-known/openid-configuration",
        "/id_rsa", "/.ssh/id_rsa",
    ],
    "backups": [
        "/backup", "/backup/", "/backups/", "/backup.zip", "/backup.tar.gz", "/backup.tar",
        "/backup.sql", "/backup.bak", "/site-backup.zip", "/www.zip", "/web.zip", "/html.zip",
        "/dump.sql", "/database.sql", "/db.sql", "/db_backup.sql", "/mysql.sql",
        "/old/", "/old.zip", "/bak/", "/_old/",
        "/index.php.bak", "/index.html.bak", "/index.bak",
        "/archive.zip", "/release.zip", "/app.zip", "/source.zip", "/data.zip",
    ],
    "spring": [
        "/actuator", "/actuator/health", "/actuator/env", "/actuator/configprops",
        "/actuator/mappings", "/actuator/beans", "/actuator/info", "/actuator/metrics",
        "/actuator/logfile", "/actuator/httptrace", "/actuator/threaddump", "/actuator/sessions",
        "/actuator/heapdump", "/actuator/loggers", "/actuator/gateway/routes", "/actuator/scheduledtasks",
        "/heapdump", "/threaddump", "/env", "/trace", "/dump", "/beans", "/mappings",
        "/jolokia", "/jolokia/list", "/jolokia/read",
        "/api/actuator", "/management/health", "/management", "/management/env",
    ],
    "php": [
        "/info.php", "/phpinfo.php", "/test.php", "/i.php", "/php.php", "/x.php",
        "/phpmyadmin", "/phpmyadmin/", "/phpMyAdmin/", "/pma", "/pma/", "/myadmin", "/dbadmin",
        "/.env.example", "/artisan", "/composer.json", "/composer.lock",
        "/storage/logs/laravel.log", "/index.php?debug=true",
        "/telescope", "/telescope/requests", "/_ignition/health-check", "/_debugbar",
    ],
    "login": [
        "/login", "/login/", "/login.php", "/signin", "/sign-in", "/sign_in",
        "/auth", "/auth/login", "/oauth", "/oauth/authorize", "/sso", "/saml/login",
        "/user/login", "/account/login", "/accounts/login", "/users/login",
        "/session/new", "/users/sign_in", "/api/login", "/api/auth/login",
        "/register", "/signup", "/sign-up", "/password/reset", "/forgot-password",
        "/logout", "/2fa", "/mfa",
    ],
    "devops": [
        "/.dockerignore", "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
        "/.gitlab-ci.yml", "/.travis.yml", "/.circleci/config.yml", "/Jenkinsfile",
        "/azure-pipelines.yml", "/bitbucket-pipelines.yml",
        "/kubernetes/", "/k8s/", "/.kube/config", "/helm/",
        "/terraform.tfstate", "/.terraform/", "/ansible.cfg", "/playbook.yml",
        "/Makefile", "/package.json", "/yarn.lock", "/package-lock.json",
    ],
    "debug": [
        "/debug", "/debug/", "/debug/vars", "/debug/pprof/", "/debug/pprof/goroutine",
        "/__debug__/", "/_debug", "/_profiler",
        "/elmah.axd", "/trace.axd", "/glimpse.axd",
        "/test", "/test/", "/testing", "/dev", "/dev/", "/staging",
        "/metrics", "/prometheus", "/grafana", "/status.php", "/phpinfo",
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
    paths = list(dict.fromkeys(paths))[:500]  # deduplicate, cap at 500

    job_id = str(uuid.uuid4())
    task = asyncio.create_task(
        _run_endpoint_check(job_id, req.targets, paths, req.project_id or None)
    )
    _RECON_JOBS[job_id] = task
    return {"status": "started", "job_id": job_id, "tool": "endpoint_check", "url_count": len(req.targets) * len(paths)}


async def _probe_soft404_baselines(httpx_bin: str, bases: list[str]) -> dict:
    """Learn each host's catch-all (soft-404) signature by requesting random
    non-existent paths. Returns {netloc: {status, title, lengths:[...]}}.

    SPAs and catch-all servers answer 200 with the app shell for ANY path, so a
    plain status-code match flags everything. We fingerprint that shell (status +
    title, with length as fallback) so real endpoints can be told apart."""
    import tempfile, os
    from urllib.parse import urlparse
    sentinels: list[str] = []
    for b in bases:
        for _ in range(2):
            sentinels.append(f"{b.rstrip('/')}/nexhunt404-{uuid.uuid4().hex[:14]}")
    if not sentinels:
        return {}

    fd, tf = tempfile.mkstemp(suffix=".txt", prefix="nexhunt_b404_")
    baselines: dict = {}
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(sentinels))
        cmd = [
            httpx_bin, "-l", tf, "-json", "-silent", "-follow-redirects",
            "-mc", "200,201,204,301,302,401,403,405,500",
            "-title", "-status-code", "-cl", "-timeout", "8", "-threads", "50", "-no-color",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        assert proc.stdout
        async for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = urlparse(d.get("url", "")).netloc
            if not host:
                continue
            status = d.get("status-code") or d.get("status_code")
            title = d.get("title", "") or ""
            clen = d.get("content_length", d.get("content-length"))
            b = baselines.setdefault(host, {"status": status, "title": title, "lengths": []})
            if isinstance(clen, int):
                b["lengths"].append(clen)
        await proc.wait()
    finally:
        if os.path.exists(tf):
            try:
                os.unlink(tf)
            except OSError:
                pass
    return baselines


def _is_soft404(result: dict, baselines: dict) -> bool:
    """True if a result matches its host's catch-all signature (false positive)."""
    from urllib.parse import urlparse
    b = baselines.get(urlparse(result.get("url", "")).netloc)
    if not b:
        return False
    if result.get("status_code") != b.get("status"):
        return False
    # A non-empty shared title is the strongest catch-all signal (SPAs keep one
    # title for every route even when the body length varies).
    btitle = (b.get("title") or "").strip()
    if btitle:
        return (result.get("title") or "").strip() == btitle
    # No title to key on — fall back to a body-length match within tolerance.
    clen = result.get("content_length")
    lengths = b.get("lengths") or []
    if not isinstance(clen, int) or not lengths:
        return False
    tol = max(64, int(max(lengths) * 0.05))
    return (min(lengths) - tol) <= clen <= (max(lengths) + tol)


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
    bases = [t.rstrip("/") for t in targets[:50]]  # max 50 live hosts
    urls: list[str] = []
    for base in bases:
        for p in paths:
            urls.append(base + p)

    # Learn each host's catch-all (soft-404) signature up front so SPA/catch-all
    # hosts that answer 200 to everything don't flood the results with junk.
    await ws_manager.broadcast("tool_output", {
        "tool": "endpoint_check", "line": "  Calibrating soft-404 baseline (random paths per host)...",
    })
    baselines = await _probe_soft404_baselines(httpx_bin, bases)
    catch_all = [h for h, b in baselines.items() if (b.get("title") or "").strip() or b.get("lengths")]
    if catch_all:
        await ws_manager.broadcast("tool_output", {
            "tool": "endpoint_check",
            "line": f"  Catch-all detected on {len(catch_all)} host(s) — filtering responses that match the app shell.",
        })
    filtered = 0

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
            "-cl",
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
                    "content_length": data.get("content_length", data.get("content-length")),
                }
                # Drop responses that just echo the host's catch-all app shell.
                if _is_soft404(result, baselines):
                    filtered += 1
                    continue
                await ws_manager.broadcast("recon_results", {
                    "tool": "endpoint_check",
                    "type": "endpoint",
                    "results": [result],
                    "project_id": project_id or "",
                })
                await _save_recon_result("endpoint", "", result, project_id)
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

    if filtered:
        await ws_manager.broadcast("tool_output", {
            "tool": "endpoint_check",
            "line": f"  Filtered {filtered} catch-all/soft-404 response(s); {count} real endpoint(s) kept.",
        })
    await ws_manager.broadcast("tool_status", {
        "tool": "endpoint_check", "event": "completed", "job_id": job_id, "result_count": count,
    })


# ── crt.sh certificate transparency search ──────────────────────────────────────

class CrtshRequest(_BaseModel):
    target: str
    project_id: str = ""


@router.post("/crtsh")
async def crtsh_scan(req: CrtshRequest):
    """
    Query crt.sh (certificate transparency logs) for subdomains found in
    issued TLS certificates — no binary required, passive, free.
    """
    import httpx

    target = req.target.strip().lower()
    if not target:
        return {"error": "No target"}

    await ws_manager.broadcast("tool_status", {"tool": "crtsh", "event": "started"})

    results = []
    try:
        # crt.sh is a free, overloaded service — 502s and empty/non-JSON
        # responses under load are routine, not a real failure. Retry before
        # giving up.
        rows = None
        last_error: Exception | None = None
        for attempt in range(4):
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.get("https://crt.sh/", params={"q": f"%.{target}", "output": "json"})
                    resp.raise_for_status()
                    rows = resp.json()
                break
            except Exception as e:
                last_error = e
                if attempt < 3:
                    await asyncio.sleep(3 * (attempt + 1))
        if rows is None:
            raise last_error

        seen = set()
        for row in rows:
            for sub in row.get("name_value", "").split("\n"):
                sub = sub.strip().lower().lstrip("*.")
                if not sub or sub in seen:
                    continue
                if sub != target and not sub.endswith("." + target):
                    continue  # cert SANs can include unrelated domains
                seen.add(sub)
                result = {"subdomain": sub, "source": "crt.sh", "ip": None, "status_code": None}
                results.append(result)
                await _save_recon_result("subdomain", target, result, req.project_id or None)
    except Exception as e:
        logger.error(f"crt.sh scan error: {e}")
        await ws_manager.broadcast("tool_status", {"tool": "crtsh", "event": "failed", "error": str(e)})
        return {"error": str(e)}

    await ws_manager.broadcast("recon_results", {
        "tool": "crtsh", "type": "subdomain", "results": results, "project_id": req.project_id or "",
    })
    await ws_manager.broadcast("tool_status", {
        "tool": "crtsh", "event": "completed", "result_count": len(results),
    })
    return {"count": len(results), "results": results}


# ── Wayback CDX API scan ────────────────────────────────────────────────────────

class WaybackCdxRequest(_BaseModel):
    target: str
    status_codes: list[str] = []       # e.g. ["200"] or ["200","301"] or [] = all
    methods: list[str] = []            # e.g. ["POST"] or [] = all
    extensions: list[str] = []         # e.g. [".env",".bak"] or [] = all
    limit: int = 500
    project_id: str = ""


@router.post("/wayback-cdx")
async def wayback_cdx_scan(req: WaybackCdxRequest):
    """
    Query the Wayback Machine CDX API directly — no binary required.
    Deduplicates via collapse=urlkey and applies optional filters.
    Results streamed via WebSocket channel 'recon_results' type 'url'.
    """
    import httpx

    target = req.target.strip()
    if not target:
        return {"error": "No target"}

    # Build CDX params
    params: dict = {
        "url": f"{target}/*",
        "output": "json",
        "fl": "original,statuscode,mimetype,timestamp",
        "collapse": "urlkey",
        "limit": str(min(req.limit, 20000)),
    }
    filters = []
    if req.status_codes:
        filters.append("statuscode:" + "|".join(req.status_codes))
    if req.methods:
        filters.append("requestmethod:" + "|".join(m.upper() for m in req.methods))
    if filters:
        params["filter"] = filters  # httpx sends multiple values as repeated keys

    cdx_url = "https://web.archive.org/cdx/search/cdx"

    await ws_manager.broadcast("tool_status", {
        "tool": "waybackurls", "event": "started",
        "message": f"Querying CDX API for {target} (limit {req.limit})...",
    })

    results = []
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.get(cdx_url, params=params)
            resp.raise_for_status()
            rows = resp.json()

        # First row is the header ["original","statuscode","mimetype","timestamp"]
        header = rows[0] if rows and isinstance(rows[0], list) and rows[0][0] == "original" else None
        data_rows = rows[1:] if header else rows

        for row in data_rows:
            if not row:
                continue
            url = row[0] if len(row) > 0 else ""
            status = row[1] if len(row) > 1 else None
            mime = row[2] if len(row) > 2 else ""
            if not url.startswith("http"):
                continue

            # Extension filter (client-side, CDX doesn't support it natively)
            if req.extensions:
                path = url.split("?")[0].split("#")[0].lower()
                if not any(path.endswith(ext.lower()) for ext in req.extensions):
                    continue

            result = {
                "url": url,
                "source": "wayback-cdx",
                "status_code": int(status) if status and status.isdigit() else None,
                "content_type": mime or None,
            }
            results.append(result)
            await _save_recon_result("url", target, result, req.project_id or None)

        # Broadcast all at once
        await ws_manager.broadcast("recon_results", {
            "tool": "waybackurls",
            "type": "url",
            "results": results,
            "project_id": req.project_id or "",
        })

    except Exception as e:
        logger.error(f"CDX scan error: {e}")
        await ws_manager.broadcast("tool_status", {
            "tool": "waybackurls", "event": "failed", "error": str(e),
        })
        return {"error": str(e)}

    await ws_manager.broadcast("tool_status", {
        "tool": "waybackurls", "event": "completed",
        "result_count": len(results),
        "message": f"CDX scan done — {len(results)} unique URLs",
    })
    return {"count": len(results), "results": results}
