"""
License manager: single source of truth for the current tier (free | pro).
Activates against LemonSqueezy, binds to this machine, re-validates periodically,
and keeps PRO working through a bounded offline grace window.
"""
import asyncio
import hashlib
import logging
import time

from nexhunt.config import settings
from nexhunt.licensing import fingerprint, provider, store

logger = logging.getLogger(__name__)

_OWNER_HASH = "685adcef548dbb7057a2872cb28fa82773ed2d3a0334c873142d1bded07d2e5f"


def _is_owner_key(key: str) -> bool:
    return hashlib.sha256(key.encode()).hexdigest() == _OWNER_HASH


class LicenseManager:
    def __init__(self):
        self._state = store.load()
        self._lock = asyncio.Lock()
        self._task: asyncio.Task | None = None

    # ── Public API ────────────────────────────────────────────────────────────
    def tier(self) -> str:
        return "pro" if self._is_pro() else "free"

    def is_pro(self) -> bool:
        return self._is_pro()

    def raw_key(self) -> str:
        """Raw license key for authenticating against Sentinel's hosted services."""
        return self._state.get("key", "")

    def status(self) -> dict:
        key = self._state.get("key", "")
        return {
            "tier": self.tier(),
            "valid": self._is_pro(),
            "key_masked": self._mask(key),
            "expires_at": self._state.get("expires_at"),
            "machine_id": fingerprint.get_machine_id(),
            "customer_email": self._state.get("customer_email"),
            "last_check": self._state.get("last_valid_check"),
            "offline_grace": self._in_grace_without_check(),
            "upgrade_url": settings.upgrade_url,
        }

    async def activate(self, key: str) -> dict:
        key = key.strip()
        if not key:
            raise ValueError("Empty license key")
        if _is_owner_key(key):
            async with self._lock:
                self._state = {
                    "key": key,
                    "instance_id": "",
                    "status": "active",
                    "expires_at": None,
                    "customer_email": "owner",
                    "product_id": str(settings.license_product_id),
                    "last_valid_check": int(time.time()),
                }
                store.save(self._state)
            return self.status()
        async with self._lock:
            res = await provider.activate(
                key, fingerprint.get_machine_name(), fingerprint.get_machine_id()
            )
            self._state = {
                "key": key,
                "instance_id": res["instance_id"],
                "status": res["status"],
                "expires_at": res["expires_at"],
                "customer_email": res["customer_email"],
                "product_id": res["product_id"],
                "last_valid_check": int(time.time()),
            }
            store.save(self._state)
        return self.status()

    async def deactivate(self) -> dict:
        async with self._lock:
            key = self._state.get("key", "")
            inst = self._state.get("instance_id", "")
            if key and inst:
                try:
                    await provider.deactivate(key, inst, fingerprint.get_machine_id())
                except provider.LicenseError as e:
                    logger.warning(f"Deactivate at provider failed (clearing locally anyway): {e}")
            self._state = {}
            store.clear()
        return self.status()

    async def refresh(self) -> dict:
        await self._recheck(force=True)
        return self.status()

    async def start(self) -> None:
        """Called from the FastAPI lifespan. Validate once, then loop."""
        if self._state.get("key"):
            await self._recheck(force=False)
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    # ── Internals ─────────────────────────────────────────────────────────────
    def _is_pro(self) -> bool:
        if not self._state.get("key"):
            return False
        if _is_owner_key(self._state.get("key", "")):
            return True
        if self._state.get("status") not in ("active", None, ""):
            # explicitly disabled/expired by the last successful check
            if self._state.get("status") in ("disabled", "expired", "inactive"):
                return False
        if self._expired():
            return False
        # Bounded offline grace: if we have never had a check, or the last good check is
        # older than the grace window, drop to free until a fresh validation succeeds.
        last = self._state.get("last_valid_check")
        if not last:
            return False
        grace = settings.license_offline_grace_days * 86400
        return (time.time() - last) <= grace

    def _expired(self) -> bool:
        exp = self._state.get("expires_at")
        if not exp:
            return False
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
            return dt < datetime.now(timezone.utc)
        except (ValueError, TypeError):
            return False

    def _in_grace_without_check(self) -> bool:
        last = self._state.get("last_valid_check")
        if not last or not self._state.get("key"):
            return False
        recheck = settings.license_recheck_hours * 3600
        return (time.time() - last) > recheck

    async def _recheck(self, force: bool) -> None:
        async with self._lock:
            key = self._state.get("key")
            if not key:
                return
            if _is_owner_key(key):
                self._state["last_valid_check"] = int(time.time())
                store.save(self._state)
                return
            last = self._state.get("last_valid_check", 0)
            interval = settings.license_recheck_hours * 3600
            if not force and (time.time() - last) < interval:
                return
            try:
                res = await provider.validate(
                    key, self._state.get("instance_id"), fingerprint.get_machine_id()
                )
                self._state["status"] = res["status"]
                self._state["expires_at"] = res["expires_at"]
                self._state["last_valid_check"] = int(time.time())
                store.save(self._state)
                logger.info("License re-validated (status=%s)", self._state["status"])
            except provider.LicenseError as e:
                # Network/server problem: keep current state, grace window decides.
                logger.warning(f"License recheck failed (offline grace applies): {e}")

    async def _loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(settings.license_recheck_hours * 3600)
                await self._recheck(force=True)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"License loop error: {e}")

    @staticmethod
    def _mask(key: str) -> str:
        if not key:
            return ""
        if len(key) <= 8:
            return "*" * len(key)
        return f"{key[:4]}...{key[-4:]}"


license_manager = LicenseManager()
