"""
Abstract base class for all external tool adapters.
Each adapter wraps one CLI tool, runs it as a subprocess,
parses its output, and yields normalized result dicts.
"""
import asyncio
import shlex
import shutil
import logging
from abc import ABC, abstractmethod
from asyncio import StreamReader
from typing import AsyncIterator

logger = logging.getLogger(__name__)


class ToolAdapter(ABC):
    name: str = ""
    binary_name: str = ""
    result_type: str = "generic"  # subdomain | url | port | finding | output

    def __init__(self):
        self._procs: list[asyncio.subprocess.Process] = []

    @abstractmethod
    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        """Yield normalized result dicts as they arrive."""
        ...

    @staticmethod
    def _with_extra_args(cmd: list[str], options: dict) -> list[str]:
        """Append user-provided extra CLI flags (per-tool customization).

        Parsed with shlex so quoting works. Args go to create_subprocess_exec
        (no shell), so this cannot inject shell commands, only tool flags.
        """
        extra = options.get("extra_args", "")
        if not extra:
            return cmd
        try:
            return cmd + shlex.split(extra)
        except ValueError:
            return cmd

    async def check_installed(self) -> bool:
        return shutil.which(self.binary_name) is not None

    async def get_version(self) -> str | None:
        if not await self.check_installed():
            return None
        try:
            proc = await asyncio.create_subprocess_exec(
                self.binary_name, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
            output = (stdout or stderr).decode().strip()
            return output.split("\n")[0][:50] if output else None
        except Exception:
            return None

    async def cancel(self):
        for proc in list(self._procs):
            if proc.returncode is None:
                try:
                    proc.terminate()
                    await asyncio.sleep(0.3)
                    if proc.returncode is None:
                        proc.kill()
                except ProcessLookupError:
                    pass

    async def _run_subprocess(
        self, cmd: list[str], timeout: int = 300, merge_stderr: bool = False
    ) -> AsyncIterator[str]:
        """
        Run a command and yield stdout lines as they arrive.

        stderr is always drained concurrently to prevent pipe-buffer deadlocks
        (e.g. gobuster writing many error lines to stderr while results go to stdout).

        If merge_stderr=True, stderr lines are also yielded (prefixed with [STDERR]).
        """
        logger.debug(f"Running: {' '.join(cmd)}")
        queue: asyncio.Queue[str | None] = asyncio.Queue()

        async def _drain(stream: StreamReader, prefix: str = ""):
            try:
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="replace").strip()
                    if decoded:
                        if merge_stderr and prefix:
                            await queue.put(f"{prefix}{decoded}")
                        elif not prefix:
                            await queue.put(decoded)
                        else:
                            # stderr — just log it, don't yield
                            logger.debug(f"[{self.binary_name} stderr] {decoded}")
            finally:
                await queue.put(None)  # sentinel

        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._procs.append(proc)
            assert proc.stdout is not None
            assert proc.stderr is not None

            # Drain stdout and stderr concurrently
            stdout_task = asyncio.create_task(_drain(proc.stdout, prefix=""))
            stderr_task = asyncio.create_task(_drain(proc.stderr, prefix="[STDERR] "))

            sentinels_received = 0
            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout

            while sentinels_received < 2:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    if proc.returncode is None:
                        try:
                            proc.terminate()
                        except ProcessLookupError:
                            pass
                    logger.warning(f"{self.binary_name} timed out after {timeout}s")
                    break
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=min(remaining, 5))
                    if item is None:
                        sentinels_received += 1
                    else:
                        yield item
                except asyncio.TimeoutError:
                    # Check if process has exited
                    if proc.returncode is not None:
                        break

            # Make sure both drain tasks are done
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            if proc.returncode is None:
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass

        except FileNotFoundError:
            logger.error(f"{self.binary_name} not found in PATH")
        except asyncio.CancelledError:
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            raise
        except Exception as e:
            logger.error(f"Subprocess error for {self.binary_name}: {e}")
        finally:
            if proc is not None and proc in self._procs:
                self._procs.remove(proc)


# ── Registry ──────────────────────────────────────────────────────────────────

def _build_registry() -> dict[str, "ToolAdapter"]:
    from nexhunt.adapters.subfinder import SubfinderAdapter
    from nexhunt.adapters.amass import AmassAdapter
    from nexhunt.adapters.httpx_adapter import HttpxAdapter
    from nexhunt.adapters.nmap import NmapAdapter
    from nexhunt.adapters.waybackurls import WaybackurlsAdapter
    from nexhunt.adapters.gau import GauAdapter
    from nexhunt.adapters.katana import KatanaAdapter
    from nexhunt.adapters.paramspider import ParamspiderAdapter
    from nexhunt.adapters.arjun import ArjunAdapter
    from nexhunt.adapters.nuclei import NucleiAdapter
    from nexhunt.adapters.ffuf import FfufAdapter
    from nexhunt.adapters.nikto import NiktoAdapter
    from nexhunt.adapters.gobuster import GobusterAdapter
    from nexhunt.adapters.dirsearch import DirsearchAdapter
    from nexhunt.adapters.sqlmap import SqlmapAdapter
    from nexhunt.adapters.dalfox import DalfoxAdapter
    from nexhunt.adapters.xsstrike import XsstrikeAdapter
    from nexhunt.adapters.commix import CommixAdapter
    from nexhunt.adapters.gowitness import GowitnessAdapter
    from nexhunt.adapters.linkfinder import LinkFinderAdapter
    from nexhunt.adapters.cors_scanner import CorsScannerAdapter
    from nexhunt.adapters.bypass_403 import Bypass403Adapter
    from nexhunt.adapters.cloud_buckets import CloudBucketsAdapter
    from nexhunt.adapters.interactsh import InteractshAdapter
    from nexhunt.adapters.github_scanner import GithubScannerAdapter

    adapters = [
        SubfinderAdapter(), AmassAdapter(), HttpxAdapter(), NmapAdapter(),
        WaybackurlsAdapter(), GauAdapter(), KatanaAdapter(),
        ParamspiderAdapter(), ArjunAdapter(),
        NucleiAdapter(), FfufAdapter(), NiktoAdapter(), GobusterAdapter(), DirsearchAdapter(),
        SqlmapAdapter(), DalfoxAdapter(), XsstrikeAdapter(), CommixAdapter(),
        GowitnessAdapter(), LinkFinderAdapter(),
        CorsScannerAdapter(), Bypass403Adapter(), CloudBucketsAdapter(),
        InteractshAdapter(), GithubScannerAdapter(),
    ]
    return {a.name: a for a in adapters}


ADAPTERS: dict[str, ToolAdapter] = {}


def get_adapter(name: str) -> ToolAdapter | None:
    global ADAPTERS
    if not ADAPTERS:
        ADAPTERS = _build_registry()
    return ADAPTERS.get(name)
