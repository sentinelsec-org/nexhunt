"""
License manager: single source of truth for the current tier (free | pro).
Activates against LemonSqueezy, binds to this machine, re-validates periodically,
and keeps PRO working through a bounded offline grace window.
"""
import asyncio
import logging
import time

from nexhunt.config import settings
from nexhunt.licensing import fingerprint, lemonsqueezy, store

logger = logging.getLogger(__name__)


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
        async with self._lock:
            payload = await lemonsqueezy.activate(key, fingerprint.get_machine_name())
            self._guard_product(payload)
            lic = payload.get("license_key", {})
            inst = payload.get("instance", {})
            meta = payload.get("meta", {})
            self._state = {
                "key": key,
                "instance_id": inst.get("id", ""),
                "status": lic.get("status", "active"),
                "expires_at": lic.get("expires_at"),
                "customer_email": meta.get("customer_email"),
                "product_id": meta.get("product_id"),
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
                    await lemonsqueezy.deactivate(key, inst)
                except lemonsqueezy.LemonError as e:
                    logger.warning(f"Deactivate at LemonSqueezy failed (clearing locally anyway): {e}")
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

    def _guard_product(self, payload: dict) -> None:
        want = settings.license_product_id
        if not want:
            return
        got = str(payload.get("meta", {}).get("product_id", ""))
        if got != str(want):
            raise lemonsqueezy.LemonError("This license key is not valid for NexHunt")

    async def _recheck(self, force: bool) -> None:
        async with self._lock:
            key = self._state.get("key")
            if not key:
                return
            last = self._state.get("last_valid_check", 0)
            interval = settings.license_recheck_hours * 3600
            if not force and (time.time() - last) < interval:
                return
            try:
                payload = await lemonsqueezy.validate(key, self._state.get("instance_id"))
                lic = payload.get("license_key", {})
                self._state["status"] = lic.get("status", "active")
                self._state["expires_at"] = lic.get("expires_at")
                self._state["last_valid_check"] = int(time.time())
                store.save(self._state)
                logger.info("License re-validated (status=%s)", self._state["status"])
            except lemonsqueezy.LemonError as e:
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
