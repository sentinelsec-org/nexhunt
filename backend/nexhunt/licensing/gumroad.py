"""
Gumroad License API client.
Docs: https://help.gumroad.com/article/76-license-keys

The verify endpoint is public (keyed by product_id + license_key) — no seller token
needed client-side, mirroring LemonSqueezy's license endpoints. Gumroad has no
per-instance binding: it tracks a `uses` counter. We enforce the activation limit
ourselves and use this machine's fingerprint as the instance id.
"""
import logging
import httpx

from nexhunt.config import settings

logger = logging.getLogger(__name__)

_VERIFY = "https://api.gumroad.com/v2/licenses/verify"
_DECREMENT = "https://api.gumroad.com/v2/licenses/decrement_uses_count"
_TIMEOUT = 12.0


class GumroadError(Exception):
    pass


def _product_params() -> dict:
    if settings.gumroad_product_id:
        return {"product_id": settings.gumroad_product_id}
    if settings.gumroad_product_permalink:
        return {"product_permalink": settings.gumroad_product_permalink}
    raise GumroadError("Gumroad product not configured")


async def _verify(key: str, increment: bool) -> dict:
    data = {
        **_product_params(),
        "license_key": key,
        "increment_uses_count": "true" if increment else "false",
    }
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(_VERIFY, data=data, headers={"Accept": "application/json"})
    if resp.status_code >= 500:
        raise GumroadError("License server unavailable")
    try:
        body = resp.json()
    except Exception:
        raise GumroadError(f"Unexpected response ({resp.status_code})")
    if not body.get("success"):
        raise GumroadError(body.get("message") or "Invalid license key")
    return body


def _normalize(body: dict, machine_id: str) -> dict:
    purchase = body.get("purchase", {}) or {}
    disabled = purchase.get("refunded") or purchase.get("disputed") or purchase.get("chargebacked")
    ended = purchase.get("subscription_ended_at") or purchase.get("subscription_failed_at")
    if disabled:
        status = "disabled"
    elif ended:
        status = "expired"
    else:
        status = "active"
    return {
        "instance_id": machine_id,
        "status": status,
        "expires_at": purchase.get("subscription_ended_at"),
        "customer_email": purchase.get("email"),
        "product_id": str(purchase.get("product_id", "")),
        "uses": body.get("uses", 0),
    }


async def activate(key: str, machine_id: str) -> dict:
    # Read the current seat count without burning one, then claim a seat.
    pre = await _verify(key, increment=False)
    limit = settings.gumroad_activation_limit
    if limit and pre.get("uses", 0) >= limit:
        raise GumroadError(
            f"Activation limit reached ({limit} machines). Deactivate another machine first."
        )
    body = await _verify(key, increment=True)
    return _normalize(body, machine_id)


async def validate(key: str, machine_id: str) -> dict:
    body = await _verify(key, increment=False)
    return _normalize(body, machine_id)


async def deactivate(key: str, machine_id: str) -> None:
    # Releasing a seat needs the seller access token (decrement_uses_count). Without it
    # we clear locally only; Gumroad's counter is unaffected.
    token = settings.gumroad_access_token
    if not token:
        logger.info("Gumroad deactivate: no access token, clearing locally only")
        return
    data = {**_product_params(), "license_key": key, "access_token": token}
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        await client.post(_DECREMENT, data=data, headers={"Accept": "application/json"})
