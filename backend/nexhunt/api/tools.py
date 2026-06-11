from fastapi import APIRouter
from nexhunt.tools.checker import check_all_tools

router = APIRouter(prefix="/api/tools", tags=["tools"])


@router.get("/status")
async def get_tools_status():
    """Check installation status of all external tools."""
    return await check_all_tools()
