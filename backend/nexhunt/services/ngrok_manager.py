"""
Ngrok tunnel manager for exposing local endpoints externally.
Used by jku/x5u JWT attacks when target is not on localhost.
"""
import asyncio
import logging

logger = logging.getLogger(__name__)

_tunnel = None          # active ngrok Listener
_tunnel_url: str = ""   # cached public URL
_lock = asyncio.Lock()


def _is_external(url: str) -> bool:
    """Return True if the URL points to an external (non-local) host."""
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        local = ("localhost", "127.0.0.1", "0.0.0.0", "::1")
        return host not in local and not host.startswith("192.168.") and not host.startswith("10.")
    except Exception:
        return False


async def get_tunnel_url(local_port: int = 17707) -> tuple[str, str | None]:
    """
    Return (public_url, error).
    If a tunnel is already running, reuse it.
    If not, try to start one using the configured ngrok authtoken.
    """
    global _tunnel, _tunnel_url

    if _tunnel_url:
        return _tunnel_url, None

    async with _lock:
        if _tunnel_url:
            return _tunnel_url, None

        from nexhunt.config import settings
        if not settings.ngrok_authtoken:
            return "", "No ngrok authtoken configured. Go to Settings → Ngrok and add your token from https://dashboard.ngrok.com/get-started/your-authtoken"

        try:
            import ngrok
            _tunnel = await ngrok.forward(
                local_port,
                authtoken=settings.ngrok_authtoken,
                domain=None,
            )
            _tunnel_url = _tunnel.url()
            logger.info(f"[ngrok] Tunnel started: {_tunnel_url} → localhost:{local_port}")
            return _tunnel_url, None
        except Exception as e:
            err = str(e)
            logger.error(f"[ngrok] Failed to start tunnel: {err}")
            return "", err


async def stop_tunnel():
    global _tunnel, _tunnel_url
    if _tunnel:
        try:
            await _tunnel.close()
        except Exception:
            pass
        _tunnel = None
        _tunnel_url = ""
        logger.info("[ngrok] Tunnel stopped")


def get_cached_url() -> str:
    return _tunnel_url
