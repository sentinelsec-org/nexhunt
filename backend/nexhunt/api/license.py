import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from nexhunt.licensing.manager import license_manager
from nexhunt.licensing.lemonsqueezy import LemonError

router = APIRouter(prefix="/api/license", tags=["license"])
logger = logging.getLogger(__name__)


class ActivateRequest(BaseModel):
    key: str


@router.get("/status")
async def status():
    return license_manager.status()


@router.post("/activate")
async def activate(req: ActivateRequest):
    try:
        return await license_manager.activate(req.key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except LemonError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/deactivate")
async def deactivate():
    return await license_manager.deactivate()


@router.post("/refresh")
async def refresh():
    return await license_manager.refresh()
