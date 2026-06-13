"""
NexHunt FastAPI backend entry point.
Run with: uvicorn nexhunt.main:app --host 127.0.0.1 --port 17707
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from nexhunt.licensing.guard import require_pro

from nexhunt.database import init_db
from nexhunt.version import __version__
from nexhunt.api import proxy, recon, scanner, exploit, copilot, project, tools, settings, websocket, pipeline, js_scanner, terminal, bizlogic, cve, jwt_attacks, security_tools, license, update, bruteforce, wordlists

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    logger.info("NexHunt backend starting...")
    await init_db()
    logger.info("Database initialized")
    from nexhunt.licensing.manager import license_manager
    await license_manager.start()
    logger.info("License manager started (tier=%s)", license_manager.tier())
    yield
    # Cleanup
    from nexhunt.licensing.manager import license_manager as _lm
    await _lm.stop()
    from nexhunt.proxy.engine import proxy_engine
    if proxy_engine.running:
        await proxy_engine.stop()
    logger.info("NexHunt backend stopped")


app = FastAPI(
    title="NexHunt API",
    description="Bug bounty automation platform backend",
    version=__version__,
    lifespan=lifespan
)

# CORS - only allow Electron renderer (localhost)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:*", "http://127.0.0.1:*", "null"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register all routers
app.include_router(proxy.router)
app.include_router(recon.router)
app.include_router(scanner.router)
app.include_router(exploit.router)
app.include_router(project.router)
app.include_router(tools.router)
app.include_router(settings.router)
app.include_router(websocket.router)
app.include_router(js_scanner.router)
app.include_router(terminal.router)
app.include_router(cve.router)
app.include_router(security_tools.router)
app.include_router(license.router)
app.include_router(update.router)
app.include_router(bruteforce.router)  # /start is PRO-gated per-route
app.include_router(wordlists.router)   # POST/DELETE are PRO-gated per-route

# PRO-only routers (whole feature gated behind a valid license)
app.include_router(copilot.router, dependencies=[Depends(require_pro("AI Copilot"))])
app.include_router(pipeline.router, dependencies=[Depends(require_pro("Automated pipelines"))])
app.include_router(jwt_attacks.router, dependencies=[Depends(require_pro("JWT attack suite"))])
app.include_router(bizlogic.router, dependencies=[Depends(require_pro("Business logic suite"))])


# Serve screenshots as static files
from nexhunt.config import settings as _cfg
app.mount("/screenshots", StaticFiles(directory=_cfg.screenshots_dir), name="screenshots")


@app.get("/api/health")
async def health():
    """Health check endpoint used by Electron to verify backend is ready."""
    return {"status": "ok", "version": __version__}
