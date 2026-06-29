"""
Proxy engine: runs mitmdump as a subprocess with a custom addon.
The addon (mitm_addon.py) POSTs each flow to /api/proxy/flow, which
broadcasts it via WebSocket and saves it to SQLite.
"""
import asyncio
import json
import logging
import os
import signal
import subprocess
import tempfile
from pathlib import Path

from nexhunt.proxy.cert_manager import get_cert_path

logger = logging.getLogger(__name__)

_ADDON_PATH = Path(__file__).parent / "mitm_addon.py"


class ProxyEngine:
    def __init__(self):
        self.port: int = 8080
        self.running: bool = False
        self._proc: asyncio.subprocess.Process | None = None
        self._intercept_flag = [False]
        self._intercept_scope_only = False
        self._intercept_scope: list[str] = []
        self._intercept_out_of_scope: list[str] = []
        self._intercept_state_path = Path(tempfile.gettempdir()) / f"nexhunt-proxy-{os.getpid()}.intercept"
        self._write_intercept_state()

    def _write_intercept_state(self):
        """Publish intercept state for the standalone mitmdump process."""
        try:
            state = {
                "enabled": self._intercept_flag[0],
                "scope_only": self._intercept_scope_only,
                "scope": self._intercept_scope,
                "out_of_scope": self._intercept_out_of_scope,
            }
            temp_path = self._intercept_state_path.with_suffix(".tmp")
            temp_path.write_text(json.dumps(state))
            temp_path.replace(self._intercept_state_path)
        except OSError as exc:
            logger.warning(f"Could not write proxy intercept state: {exc}")

    def configure_intercept(self, scope_only: bool, scope: list[str], out_of_scope: list[str]):
        self._intercept_scope_only = scope_only
        self._intercept_scope = scope
        self._intercept_out_of_scope = out_of_scope
        self._write_intercept_state()

    def _kill_existing(self, port: int):
        """Kill any mitmdump process already listening on this port."""
        try:
            result = subprocess.run(
                ["fuser", f"{port}/tcp"],
                capture_output=True, text=True
            )
            pids = result.stdout.strip().split()
            for pid_str in pids:
                try:
                    pid = int(pid_str)
                    os.kill(pid, signal.SIGTERM)
                    logger.info(f"Killed stale mitmdump (pid={pid}) on port {port}")
                except (ValueError, ProcessLookupError, PermissionError):
                    pass
        except FileNotFoundError:
            pass  # fuser not available

    async def start(self, port: int = 8080):
        if self.running:
            logger.info("Proxy already running")
            return

        self.port = port
        self._kill_existing(port)
        await asyncio.sleep(0.3)  # let the port free up

        self._write_intercept_state()
        env = {
            **os.environ,
            "NEXHUNT_PORT": "17707",
            "NEXHUNT_INTERCEPT_STATE": str(self._intercept_state_path),
        }

        self._proc = await asyncio.create_subprocess_exec(
            "mitmdump",
            "-s", str(_ADDON_PATH),
            "--listen-host", "127.0.0.1",
            "--listen-port", str(self.port),
            "--ssl-insecure",
            "--quiet",
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        self.running = True
        logger.info(f"Proxy started (mitmdump pid={self._proc.pid}) on 127.0.0.1:{self.port}")

        asyncio.create_task(self._watch_stderr())
        asyncio.create_task(self._drain_stdout())

        from nexhunt.ws.manager import ws_manager
        await ws_manager.broadcast("tool_status", {
            "tool": "proxy", "event": "started", "port": self.port
        })

    async def _drain_stdout(self):
        if not self._proc or not self._proc.stdout:
            return
        async for _ in self._proc.stdout:
            pass

    async def _watch_stderr(self):
        """Log mitmdump stderr and detect unexpected exits."""
        if not self._proc or not self._proc.stderr:
            return
        lines = []
        async for raw in self._proc.stderr:
            line = raw.decode(errors="replace").rstrip()
            if line:
                logger.debug(f"[mitmdump] {line}")
                lines.append(line)
        # stderr closed → process ended
        if self.running:
            self.running = False
            error_hint = " | ".join(lines[-3:]) if lines else "no output"
            logger.warning(f"mitmdump exited unexpectedly: {error_hint}")
            from nexhunt.ws.manager import ws_manager
            await ws_manager.broadcast("tool_status", {
                "tool": "proxy", "event": "stopped"
            })

    async def stop(self):
        if not self.running:
            return
        self.running = False
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._proc.kill()
        logger.info("Proxy stopped")
        from nexhunt.ws.manager import ws_manager
        await ws_manager.broadcast("tool_status", {
            "tool": "proxy", "event": "stopped"
        })

    def get_cert_path(self) -> str | None:
        return get_cert_path()

    @property
    def intercept_enabled(self) -> bool:
        return self._intercept_flag[0]

    @intercept_enabled.setter
    def intercept_enabled(self, value: bool):
        self._intercept_flag[0] = value
        self._write_intercept_state()

    @property
    def intercept_scope_only(self) -> bool:
        return self._intercept_scope_only

    @property
    def intercept_scope(self) -> list[str]:
        return self._intercept_scope

    @property
    def intercept_out_of_scope(self) -> list[str]:
        return self._intercept_out_of_scope


# Global singleton
proxy_engine = ProxyEngine()
