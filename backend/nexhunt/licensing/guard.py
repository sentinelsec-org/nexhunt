"""FastAPI dependency to gate PRO-only endpoints."""
from fastapi import HTTPException

from nexhunt.config import settings
from nexhunt.licensing.manager import license_manager


def require_pro(feature: str = "this feature"):
    """Return a dependency that 402s when the current tier is not PRO."""
    def _dep():
        if not license_manager.is_pro():
            raise HTTPException(
                status_code=402,
                detail={
                    "error": "pro_required",
                    "feature": feature,
                    "message": f"{feature} is a NexHunt PRO feature.",
                    "upgrade_url": settings.upgrade_url,
                },
            )
    return _dep
