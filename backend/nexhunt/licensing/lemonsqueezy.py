"""
LemonSqueezy License API client.
Docs: https://docs.lemonsqueezy.com/help/licensing/license-api
These endpoints are keyed by the license key itself — no store API token needed client-side.
"""
import logging
import httpx

logger = logging.getLogger(__name__)

_BASE = "https://api.lemonsqueezy.com/v1/licenses"
_HEADERS = {"Accept": "application/json"}
_TIMEOUT = 12.0


class LemonError(Exception):
    pass


async def activate(license_key: str, instance_name: str) -> dict:
    """Bind the key to this machine. Returns the raw LemonSqueezy payload."""
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(
            f"{_BASE}/activate",
            headers=_HEADERS,
            data={"license_key": license_key, "instance_name": instance_name},
        )
    return _parse(resp, "activated")


async def validate(license_key: str, instance_id: str | None = None) -> dict:
    """Check the key (and optionally this machine's instance) is still valid/active."""
    data = {"license_key": license_key}
    if instance_id:
        data["instance_id"] = instance_id
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(f"{_BASE}/validate", headers=_HEADERS, data=data)
    return _parse(resp, "valid")


async def deactivate(license_key: str, instance_id: str) -> dict:
    """Release this machine's seat so the key can be moved elsewhere."""
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(
            f"{_BASE}/deactivate",
            headers=_HEADERS,
            data={"license_key": license_key, "instance_id": instance_id},
        )
    return _parse(resp, "deactivated")


def _parse(resp: httpx.Response, ok_flag: str) -> dict:
    # LemonSqueezy returns 400 with a JSON {error:...} body for invalid keys — surface that text.
    try:
        body = resp.json()
    except Exception:
        raise LemonError(f"Unexpected response ({resp.status_code})")
    if resp.status_code >= 500:
        raise LemonError("License server unavailable")
    if body.get("error"):
        raise LemonError(body["error"])
    if not body.get(ok_flag):
        raise LemonError(body.get("error") or "License operation failed")
    return body
