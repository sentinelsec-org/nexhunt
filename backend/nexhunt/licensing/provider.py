"""
License provider dispatch. Selects LemonSqueezy, Gumroad, or Keygen based on
settings.license_provider and returns a normalized result the manager consumes:

    {instance_id, status, expires_at, customer_email, product_id}

Switch providers with NEXHUNT_LICENSE_PROVIDER env var (no code change).
"""
from nexhunt.config import settings
from nexhunt.licensing import lemonsqueezy, gumroad, keygen


class LicenseError(Exception):
    pass


def _provider() -> str:
    return (settings.license_provider or "keygen").lower()


async def activate(key: str, instance_name: str, machine_id: str) -> dict:
    p = _provider()
    if p == "keygen":
        try:
            return await keygen.activate(key, machine_id, instance_name)
        except keygen.KeygenError as e:
            raise LicenseError(str(e))
    if p == "gumroad":
        try:
            return await gumroad.activate(key, machine_id)
        except gumroad.GumroadError as e:
            raise LicenseError(str(e))
    # lemonsqueezy
    try:
        payload = await lemonsqueezy.activate(key, instance_name)
    except lemonsqueezy.LemonError as e:
        raise LicenseError(str(e))
    want = settings.license_product_id
    got = str(payload.get("meta", {}).get("product_id", ""))
    if want and got != str(want):
        raise LicenseError("This license key is not valid for NexHunt")
    lic = payload.get("license_key", {})
    inst = payload.get("instance", {})
    meta = payload.get("meta", {})
    return {
        "instance_id": inst.get("id", ""),
        "status": lic.get("status", "active"),
        "expires_at": lic.get("expires_at"),
        "customer_email": meta.get("customer_email"),
        "product_id": str(meta.get("product_id", "")),
    }


async def validate(key: str, instance_id: str | None, machine_id: str) -> dict:
    p = _provider()
    if p == "keygen":
        try:
            return await keygen.validate(key, machine_id)
        except keygen.KeygenError as e:
            raise LicenseError(str(e))
    if p == "gumroad":
        try:
            return await gumroad.validate(key, machine_id)
        except gumroad.GumroadError as e:
            raise LicenseError(str(e))
    # lemonsqueezy
    try:
        payload = await lemonsqueezy.validate(key, instance_id)
    except lemonsqueezy.LemonError as e:
        raise LicenseError(str(e))
    lic = payload.get("license_key", {})
    meta = payload.get("meta", {})
    return {
        "instance_id": instance_id or "",
        "status": lic.get("status", "active"),
        "expires_at": lic.get("expires_at"),
        "customer_email": meta.get("customer_email"),
        "product_id": str(meta.get("product_id", "")),
    }


async def deactivate(key: str, instance_id: str, machine_id: str) -> None:
    p = _provider()
    if p == "keygen":
        try:
            await keygen.deactivate(key, machine_id)
        except keygen.KeygenError as e:
            raise LicenseError(str(e))
        return
    if p == "gumroad":
        try:
            await gumroad.deactivate(key, machine_id)
        except gumroad.GumroadError as e:
            raise LicenseError(str(e))
        return
    # lemonsqueezy
    try:
        await lemonsqueezy.deactivate(key, instance_id)
    except lemonsqueezy.LemonError as e:
        raise LicenseError(str(e))
