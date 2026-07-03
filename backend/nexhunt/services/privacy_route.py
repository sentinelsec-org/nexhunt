"""Optional outbound privacy routing for NexHunt.

HTTP clients use standard proxy environment variables. Child security tools
also inherit proxychains-ng through LD_PRELOAD, which covers ordinary TCP
connect() calls while bypassing NexHunt's localhost control plane.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import socket
from pathlib import Path
from urllib.parse import unquote, urlparse

import httpx

from nexhunt.config import settings

logger = logging.getLogger(__name__)

_TOR_HOST = "127.0.0.1"
_TOR_PORT = 19050
_MANAGED_TOR_URL = f"socks5://{_TOR_HOST}:{_TOR_PORT}"
_PROXY_ENV = (
    "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy",
    "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy",
    "LD_PRELOAD", "PROXYCHAINS_CONF_FILE", "PROXYCHAINS_QUIET_MODE",
)


class PrivacyRouteError(RuntimeError):
    pass


class PrivacyRouteManager:
    def __init__(self) -> None:
        self.mode = "direct"
        self.proxy_url = ""
        self.state = "direct"
        self.error = ""
        self._tor: asyncio.subprocess.Process | None = None
        self._original_env = {key: os.environ.get(key) for key in _PROXY_ENV}
        self._config_path = Path(settings.db_dir) / "proxychains-nexhunt.conf"

    @staticmethod
    def _parse_proxy(url: str) -> tuple[str, str, int, str, str]:
        parsed = urlparse(url.strip())
        scheme = parsed.scheme.lower()
        if scheme not in {"socks5", "socks5h", "socks4", "http"}:
            raise PrivacyRouteError("Use socks5://, socks4:// or http://")
        try:
            port = parsed.port
        except ValueError as exc:
            raise PrivacyRouteError("Proxy port is invalid") from exc
        if not parsed.hostname or not port:
            raise PrivacyRouteError("Proxy URL must include host and port")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise PrivacyRouteError("Proxy URL cannot include a path, query or fragment")
        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        if any(char.isspace() for char in username + password):
            raise PrivacyRouteError("Proxy credentials cannot contain whitespace")
        pc_scheme = "socks5" if scheme == "socks5h" else scheme
        return (
            pc_scheme,
            parsed.hostname,
            port,
            username,
            password,
        )

    @staticmethod
    def _proxychains_library() -> str:
        candidates = (
            "/usr/lib/x86_64-linux-gnu/libproxychains.so.4",
            "/usr/lib/aarch64-linux-gnu/libproxychains.so.4",
            "/usr/lib/libproxychains.so.4",
            "/usr/local/lib/libproxychains.so.4",
            "/lib64/libproxychains.so.4",
        )
        return next((path for path in candidates if os.path.isfile(path)), "")

    @staticmethod
    def _system_vpn() -> tuple[bool, str]:
        try:
            interfaces = {name.lower() for _, name in socket.if_nameindex()}
        except OSError:
            return False, ""
        signatures = (
            ("proton", "Proton VPN"),
            ("cloudflarewarp", "Cloudflare WARP"),
            ("warp", "Cloudflare WARP"),
            ("wg", "WireGuard"),
            ("tun", "VPN tunnel"),
            ("tap", "VPN tunnel"),
        )
        for prefix, provider in signatures:
            if any(name.startswith(prefix) for name in interfaces):
                return True, provider
        return False, ""

    def _restore_environment(self) -> None:
        for key, value in self._original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _write_proxychains_config(self, proxy_url: str) -> None:
        scheme, host, port, username, password = self._parse_proxy(proxy_url)
        auth = ""
        if username:
            auth = f" {username} {password}" if password else f" {username}"
        content = (
            "strict_chain\n"
            "quiet_mode\n"
            "proxy_dns\n"
            "remote_dns_subnet 224\n"
            "tcp_read_time_out 30000\n"
            "tcp_connect_time_out 12000\n"
            "localnet 127.0.0.0/255.0.0.0\n"
            "localnet ::1/128\n"
            "[ProxyList]\n"
            f"{scheme} {host} {port}{auth}\n"
        )
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        self._config_path.write_text(content)
        self._config_path.chmod(0o600)

    def _apply_environment(self, proxy_url: str) -> None:
        self._restore_environment()
        no_proxy = "localhost,127.0.0.1,::1"
        for key in ("ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
            os.environ[key] = proxy_url
        os.environ["NO_PROXY"] = no_proxy
        os.environ["no_proxy"] = no_proxy

        library = self._proxychains_library()
        if library and shutil.which("proxychains4"):
            self._write_proxychains_config(proxy_url)
            existing = self._original_env.get("LD_PRELOAD") or ""
            os.environ["LD_PRELOAD"] = f"{library}{(':' + existing) if existing else ''}"
            os.environ["PROXYCHAINS_CONF_FILE"] = str(self._config_path)
            os.environ["PROXYCHAINS_QUIET_MODE"] = "1"

    async def _wait_for_port(self, timeout: float = 35.0) -> None:
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            if self._tor and self._tor.returncode is not None:
                stderr = ""
                if self._tor.stderr:
                    stderr = (await self._tor.stderr.read()).decode(errors="replace")[-500:]
                raise PrivacyRouteError(stderr.strip() or "Tor exited before bootstrap completed")
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(_TOR_HOST, _TOR_PORT), timeout=0.5
                )
                writer.close()
                await writer.wait_closed()
                return
            except (OSError, asyncio.TimeoutError):
                await asyncio.sleep(0.35)
        raise PrivacyRouteError("Tor did not open its SOCKS port within 35 seconds")

    async def _start_tor(self) -> None:
        if self._tor and self._tor.returncode is None:
            return
        tor = shutil.which("tor")
        if not tor:
            raise PrivacyRouteError("Tor is not installed. Run the NexHunt installer again.")

        # Do not let proxy variables or proxychains wrap Tor itself.
        tor_env = dict(os.environ)
        for key in _PROXY_ENV:
            if self._original_env.get(key) is None:
                tor_env.pop(key, None)
            else:
                tor_env[key] = self._original_env[key] or ""

        data_dir = Path(settings.db_dir) / "tor"
        data_dir.mkdir(parents=True, exist_ok=True)
        self._tor = await asyncio.create_subprocess_exec(
            tor,
            "--SocksPort", f"{_TOR_HOST}:{_TOR_PORT}",
            "--DataDirectory", str(data_dir),
            "--ClientOnly", "1",
            "--AvoidDiskWrites", "1",
            "--Log", "notice stderr",
            env=tor_env,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        await self._wait_for_port()
        asyncio.create_task(self._drain_tor_logs(self._tor))

    async def _drain_tor_logs(self, process: asyncio.subprocess.Process) -> None:
        if not process.stderr:
            return
        async for raw in process.stderr:
            line = raw.decode(errors="replace").strip()
            if line:
                logger.debug("[tor] %s", line)

    async def _stop_tor(self) -> None:
        if self._tor and self._tor.returncode is None:
            self._tor.terminate()
            try:
                await asyncio.wait_for(self._tor.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._tor.kill()
                await self._tor.wait()
        self._tor = None

    async def apply(self, mode: str, custom_proxy_url: str = "") -> dict:
        mode = (mode or "direct").lower().strip()
        if mode not in {"direct", "system", "tor", "custom"}:
            raise PrivacyRouteError("Unknown privacy route mode")

        self.state = "connecting" if mode != "direct" else "direct"
        self.error = ""
        try:
            if mode == "direct":
                await self._stop_tor()
                self._restore_environment()
                self.mode, self.proxy_url, self.state = "direct", "", "direct"
            elif mode == "system":
                # Proton VPN, WARP, WireGuard and OpenVPN route at OS level.
                # NexHunt must not stack proxychains on top of that tunnel.
                await self._stop_tor()
                self._restore_environment()
                self.mode, self.proxy_url, self.state = "system", "", "connected"
            elif mode == "tor":
                await self._start_tor()
                self._apply_environment(_MANAGED_TOR_URL)
                self.mode, self.proxy_url, self.state = "tor", _MANAGED_TOR_URL, "connected"
            else:
                self._parse_proxy(custom_proxy_url)
                await self._stop_tor()
                self._apply_environment(custom_proxy_url.strip())
                self.mode, self.proxy_url, self.state = "custom", custom_proxy_url.strip(), "connected"
        except Exception as exc:
            self._restore_environment()
            self.mode, self.proxy_url, self.state = "direct", "", "error"
            self.error = str(exc)
            raise
        return self.status()

    async def start_from_settings(self) -> None:
        try:
            # Keep Electron's backend readiness window responsive. A manual
            # Apply from Settings can still use the full Tor bootstrap timeout.
            await asyncio.wait_for(
                self.apply(settings.privacy_mode, settings.privacy_proxy_url),
                timeout=15,
            )
        except Exception as exc:
            await self._stop_tor()
            self._restore_environment()
            self.mode, self.proxy_url, self.state = "direct", "", "error"
            self.error = str(exc) or "Privacy Route startup timed out"
            logger.warning("Privacy Route could not start: %s", exc)

    async def stop(self) -> None:
        self._restore_environment()
        await self._stop_tor()

    def status(self) -> dict:
        vpn_detected, vpn_provider = self._system_vpn()
        return {
            "mode": self.mode,
            "state": self.state,
            "proxy_url": self.proxy_url if self.mode != "custom" else _mask_proxy(self.proxy_url),
            "tor_installed": bool(shutil.which("tor")),
            "proxychains_installed": bool(shutil.which("proxychains4") and self._proxychains_library()),
            "system_vpn_detected": vpn_detected,
            "system_vpn_provider": vpn_provider,
            "raw_socket_warning": self.mode in {"tor", "custom"},
            "error": self.error,
        }

    async def test_egress(self) -> dict:
        proxy = self.proxy_url or None
        try:
            if self.mode == "system":
                vpn_detected, vpn_provider = self._system_vpn()
                async with httpx.AsyncClient(trust_env=False, timeout=15) as client:
                    response = await client.get("https://api.ipify.org?format=json")
                    response.raise_for_status()
                    exit_ip = str(response.json().get("ip", ""))
                return {
                    "ok": bool(exit_ip), "direct_ip": "", "exit_ip": exit_ip,
                    "changed": None, "tor_verified": False, "mode": self.mode,
                    "routed": vpn_detected, "system_managed": True,
                    "system_vpn_provider": vpn_provider,
                }
            async with httpx.AsyncClient(trust_env=False, timeout=15) as direct_client:
                direct_response = await direct_client.get("https://api.ipify.org?format=json")
                direct_response.raise_for_status()
                direct_ip = str(direct_response.json().get("ip", ""))
            async with httpx.AsyncClient(proxy=proxy, trust_env=False, timeout=20) as routed_client:
                routed_response = await routed_client.get("https://check.torproject.org/api/ip")
                routed_response.raise_for_status()
                routed_data = routed_response.json()
                exit_ip = str(routed_data.get("IP", ""))
                tor_verified = bool(routed_data.get("IsTor", False))
            changed = bool(direct_ip and exit_ip and direct_ip != exit_ip)
            return {
                "ok": bool(exit_ip),
                "direct_ip": direct_ip,
                "exit_ip": exit_ip,
                "changed": changed,
                "tor_verified": tor_verified,
                "mode": self.mode,
                "routed": (self.mode in {"tor", "custom"} and changed) or self.mode == "system",
                "system_managed": self.mode == "system",
            }
        except Exception as exc:
            return {
                "ok": False, "direct_ip": "", "exit_ip": "", "mode": self.mode,
                "routed": False, "error": str(exc)[:240],
            }


def _mask_proxy(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.password:
        return url
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    user = f"{parsed.username}:***@" if parsed.username else ""
    return f"{parsed.scheme}://{user}{host}{port}"


privacy_route = PrivacyRouteManager()
