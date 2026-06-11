import json
import os
from fastapi import APIRouter
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
            if data.get("ai_provider"):
                settings.ai_provider = data["ai_provider"]
            if data.get("ai_model"):
                settings.ai_model = data["ai_model"]
            if data.get("ai_groq_key"):
                settings.ai_groq_key = data["ai_groq_key"]
            if data.get("ai_api_key"):
                settings.ai_api_key = data["ai_api_key"]
            if data.get("language"):
                settings.language = data["language"]
            if data.get("ngrok_authtoken"):
                settings.ngrok_authtoken = data["ngrok_authtoken"]
    except Exception:
        pass


def _persist():
    """Write current settings to JSON file."""
    os.makedirs(os.path.dirname(_SETTINGS_FILE), exist_ok=True)
    with open(_SETTINGS_FILE, "w") as f:
        json.dump({
            "proxy_port": settings.proxy_port,
            "ai_provider": settings.ai_provider,
            "ai_model": settings.ai_model,
            "ai_groq_key": settings.ai_groq_key,
            "ai_api_key": settings.ai_api_key,
            "language": settings.language,
            "ngrok_authtoken": settings.ngrok_authtoken,
        }, f, indent=2)


# Load persisted settings at import time (called on app startup)
_load_persisted()


class SettingsUpdate(BaseModel):
    proxy_port: int | None = None
    ai_provider: str | None = None
    ai_model: str | None = None
    ai_groq_key: str | None = None
    ai_api_key: str | None = None
    language: str | None = None
    ngrok_authtoken: str | None = None


def _mask(secret: str) -> str:
    if not secret:
        return ""
    return f"{'*' * max(0, len(secret) - 4)}{secret[-4:]}" if len(secret) > 4 else "*" * len(secret)


@router.get("")
async def get_settings():
    # Never return secrets in plaintext — only a masked hint + a boolean.
    return {
        "proxy_port": settings.proxy_port,
        "ai_provider": settings.ai_provider,
        "ai_model": settings.ai_model,
        "ai_groq_key_masked": _mask(settings.ai_groq_key),
        "ai_groq_key_set": bool(settings.ai_groq_key),
        "ai_api_key_set": bool(settings.ai_api_key),
        "language": settings.language,
        "ngrok_authtoken_masked": _mask(settings.ngrok_authtoken),
        "ngrok_authtoken_set": bool(settings.ngrok_authtoken),
    }


@router.post("")
async def update_settings(data: SettingsUpdate):
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
    if data.language is not None:
        settings.language = data.language
    if data.ngrok_authtoken is not None:
        settings.ngrok_authtoken = data.ngrok_authtoken
    _persist()
    return {"status": "updated"}
