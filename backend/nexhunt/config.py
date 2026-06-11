import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Server
    host: str = "127.0.0.1"
    port: int = int(os.environ.get("NEXHUNT_PORT", "17707"))

    # Proxy
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080

    # Database
    db_dir: str = os.path.expanduser("~/.nexhunt")

    # AI — Groq (primary, cheap + fast)
    ai_provider: str = "groq"
    ai_model: str = "llama-3.3-70b-versatile"
    ai_groq_key: str = ""

    # AI — fallbacks
    ai_api_key: str = ""           # Anthropic / OpenAI key

    # AI — hosted Copilot (PRO). When set, PRO routes the Copilot through Sentinel's
    # proxy using the user's license key instead of a local AI key.
    sentinel_ai_proxy_url: str = "https://sentinel-ai-proxy.joaquinsilvagni.workers.dev"

    # Licensing (Sentinel Security / LemonSqueezy)
    license_recheck_hours: int = 24            # how often to re-validate online
    license_offline_grace_days: int = 7        # keep PRO this long without a successful check
    license_product_id: str = "1135593"        # LemonSqueezy product ID for NexHunt PRO
    upgrade_url: str = "https://sentinelsec.online/pricing"
    update_repo: str = "sentinelsec/nexhunt"   # GitHub owner/repo for release updates

    # UI language
    language: str = "en"  # "en" | "es"

    # Screenshots
    screenshots_dir: str = os.path.expanduser("~/.nexhunt/screenshots")

    # Ngrok — for jku/x5u attacks against external targets
    ngrok_authtoken: str = ""

    class Config:
        env_prefix = "NEXHUNT_"


settings = Settings()

# Ensure data directories exist
os.makedirs(settings.db_dir, exist_ok=True)
os.makedirs(os.path.join(settings.db_dir, "projects"), exist_ok=True)
os.makedirs(settings.screenshots_dir, exist_ok=True)
