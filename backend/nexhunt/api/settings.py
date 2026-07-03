import json
import os
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from nexhunt.config import settings

router = APIRouter(prefix="/api/settings", tags=["settings"])

_SETTINGS_FILE = os.path.expanduser("~/.nexhunt/settings.json")


def _load_persisted():
    """Load persisted settings from JSON file and apply to runtime settings object."""
    try:
        if os.path.exists(_SETTINGS_FILE):
            with open(_SETTINGS_FILE) as f:
                data = json.load(f)
            if data.get("proxy_port"):
                settings.proxy_port = int(data["proxy_port"])
            if data.get("privacy_mode") in {"direct", "system", "tor", "custom"}:
                settings.privacy_mode = data["privacy_mode"]
            if data.get("privacy_proxy_url"):
                settings.privacy_proxy_url = data["privacy_proxy_url"]
            if data.get("ai_provider"):
                settings.ai_provider = data["ai_provider"]
            if data.get("ai_model"):
                settings.ai_model = data["ai_model"]
            if data.get("ai_groq_key"):
                settings.ai_groq_key = data["ai_groq_key"]
            if data.get("ai_api_key"):
                settings.ai_api_key = data["ai_api_key"]
            if data.get("ai_base_url"):
                settings.ai_base_url = data["ai_base_url"]
            if data.get("language"):
                settings.language = data["language"]
            if data.get("ngrok_authtoken"):
                settings.ngrok_authtoken = data["ngrok_authtoken"]
            if data.get("wpscan_api_token"):
                settings.wpscan_api_token = data["wpscan_api_token"]
            if data.get("shodan_api_key"):
                settings.shodan_api_key = data["shodan_api_key"]
            if data.get("brave_search_api_key"):
                settings.brave_search_api_key = data["brave_search_api_key"]
    except Exception:
        pass


def _persist():
    """Write current settings to JSON file."""
    os.makedirs(os.path.dirname(_SETTINGS_FILE), exist_ok=True)
    with open(_SETTINGS_FILE, "w") as f:
        json.dump({
            "proxy_port": settings.proxy_port,
            "privacy_mode": settings.privacy_mode,
            "privacy_proxy_url": settings.privacy_proxy_url,
            "ai_provider": settings.ai_provider,
            "ai_model": settings.ai_model,
            "ai_groq_key": settings.ai_groq_key,
            "ai_api_key": settings.ai_api_key,
            "ai_base_url": settings.ai_base_url,
            "language": settings.language,
            "ngrok_authtoken": settings.ngrok_authtoken,
            "wpscan_api_token": settings.wpscan_api_token,
            "shodan_api_key": settings.shodan_api_key,
            "brave_search_api_key": settings.brave_search_api_key,
        }, f, indent=2)
    os.chmod(_SETTINGS_FILE, 0o600)


# Load persisted settings at import time (called on app startup)
_load_persisted()


class SettingsUpdate(BaseModel):
    proxy_port: int | None = None
    privacy_mode: str | None = None
    privacy_proxy_url: str | None = None
    ai_provider: str | None = None
    ai_model: str | None = None
    ai_base_url: str | None = None
    ai_groq_key: str | None = None
    ai_api_key: str | None = None
    language: str | None = None
    ngrok_authtoken: str | None = None
    wpscan_api_token: str | None = None
    shodan_api_key: str | None = None
    brave_search_api_key: str | None = None


def _mask(secret: str) -> str:
    if not secret:
        return ""
    return f"{'*' * max(0, len(secret) - 4)}{secret[-4:]}" if len(secret) > 4 else "*" * len(secret)


def _mask_proxy_url(value: str) -> str:
    if not value or "@" not in value:
        return value
    prefix, host = value.rsplit("@", 1)
    scheme = prefix.split("://", 1)[0]
    username = prefix.split("://", 1)[-1].split(":", 1)[0]
    return f"{scheme}://{username}:***@{host}"


@router.get("")
async def get_settings():
    # Never return secrets in plaintext — only a masked hint + a boolean.
    return {
        "proxy_port": settings.proxy_port,
        "privacy_mode": settings.privacy_mode,
        "privacy_proxy_url_masked": _mask_proxy_url(settings.privacy_proxy_url),
        "privacy_proxy_url_set": bool(settings.privacy_proxy_url),
        "ai_provider": settings.ai_provider,
        "ai_model": settings.ai_model,
        "ai_base_url": settings.ai_base_url,
        "ai_groq_key_masked": _mask(settings.ai_groq_key),
        "ai_groq_key_set": bool(settings.ai_groq_key),
        "ai_api_key_set": bool(settings.ai_api_key),
        "language": settings.language,
        "ngrok_authtoken_masked": _mask(settings.ngrok_authtoken),
        "ngrok_authtoken_set": bool(settings.ngrok_authtoken),
        "wpscan_api_token_masked": _mask(settings.wpscan_api_token),
        "wpscan_api_token_set": bool(settings.wpscan_api_token),
        "shodan_api_key_masked": _mask(settings.shodan_api_key),
        "shodan_api_key_set": bool(settings.shodan_api_key),
        "brave_search_api_key_masked": _mask(settings.brave_search_api_key),
        "brave_search_api_key_set": bool(settings.brave_search_api_key),
    }


@router.post("")
async def update_settings(data: SettingsUpdate):
    privacy_changed = data.privacy_mode is not None or data.privacy_proxy_url is not None
    if privacy_changed:
        from nexhunt.services.privacy_route import PrivacyRouteError, privacy_route
        next_mode = data.privacy_mode if data.privacy_mode is not None else settings.privacy_mode
        next_url = data.privacy_proxy_url if data.privacy_proxy_url is not None else settings.privacy_proxy_url
        try:
            await privacy_route.apply(next_mode, next_url)
        except PrivacyRouteError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        settings.privacy_mode = next_mode
        settings.privacy_proxy_url = next_url
        _persist()
        # mitmdump and CLI children inherit routing at process start.
        from nexhunt.proxy.engine import proxy_engine
        if proxy_engine.running:
            port = proxy_engine.port
            await proxy_engine.stop()
            await proxy_engine.start(port)
    if data.proxy_port is not None:
        settings.proxy_port = data.proxy_port
    if data.ai_provider is not None:
        settings.ai_provider = data.ai_provider
    if data.ai_model is not None:
        settings.ai_model = data.ai_model
    if data.ai_groq_key is not None:
        settings.ai_groq_key = data.ai_groq_key
    if data.ai_api_key is not None:
        settings.ai_api_key = data.ai_api_key
    if data.ai_base_url is not None:
        settings.ai_base_url = data.ai_base_url
    if data.language is not None:
        settings.language = data.language
    if data.ngrok_authtoken is not None:
        settings.ngrok_authtoken = data.ngrok_authtoken
    if data.wpscan_api_token is not None:
        settings.wpscan_api_token = data.wpscan_api_token
    if data.shodan_api_key is not None:
        settings.shodan_api_key = data.shodan_api_key
    if data.brave_search_api_key is not None:
        settings.brave_search_api_key = data.brave_search_api_key
    _persist()
    return {"status": "updated"}


@router.get("/privacy/status")
async def privacy_status():
    from nexhunt.services.privacy_route import privacy_route
    return privacy_route.status()


@router.post("/privacy/test")
async def privacy_test():
    from nexhunt.services.privacy_route import privacy_route
    return await privacy_route.test_egress()
