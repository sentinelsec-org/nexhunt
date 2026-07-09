import os
import re
import sys
import shutil
import subprocess
from urllib.parse import urlparse
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter

DEFAULT_WORDLIST = "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt"

# Resolved once: how to actually invoke dirsearch on this box.
_ARGV_CACHE: list[str] | None = None

_DIRSEARCH_PY_PATHS = (
    "/usr/lib/python3/dist-packages/dirsearch/dirsearch.py",
    "/usr/share/dirsearch/dirsearch.py",
    "/usr/local/lib/dirsearch/dirsearch.py",
)


def _shebang_ok(path: str) -> bool:
    """True if the file is a real binary or a script whose interpreter exists."""
    try:
        with open(path, "rb") as f:
            first = f.readline()
    except Exception:
        return False
    if not first.startswith(b"#!"):
        return True
    interp = first[2:].strip().split(b" ")[0].decode(errors="ignore")
    # os.path.exists follows symlinks and returns False for a dangling one,
    # which is exactly the broken-wrapper case (interpreter symlink is dead).
    return bool(interp) and os.path.exists(interp)


def _resolve_argv() -> list[str]:
    """
    Pick a working way to run dirsearch. The packaged console-script wrapper can
    have a dead interpreter (e.g. an /opt/... python that isn't installed in dev),
    in which case we fall back to running dirsearch.py with a system python that
    can import the module.
    """
    global _ARGV_CACHE
    if _ARGV_CACHE is not None:
        return _ARGV_CACHE

    exe = shutil.which("dirsearch")
    if exe and _shebang_ok(exe):
        _ARGV_CACHE = [exe]
        return _ARGV_CACHE

    dpy = next((p for p in _DIRSEARCH_PY_PATHS if os.path.exists(p)), None)
    pythons = [p for p in ("/usr/bin/python3", "/usr/local/bin/python3", sys.executable) if p and os.path.exists(p)]

    if not dpy:
        for py in pythons:
            try:
                out = subprocess.run(
                    [py, "-c", "import dirsearch,os;print(os.path.join(os.path.dirname(dirsearch.__file__),'dirsearch.py'))"],
                    capture_output=True, text=True, timeout=10,
                )
                cand = (out.stdout.strip().splitlines() or [""])[-1].strip()
                if cand and os.path.exists(cand):
                    _ARGV_CACHE = [py, cand]
                    return _ARGV_CACHE
            except Exception:
                continue

    if dpy and pythons:
        _ARGV_CACHE = [pythons[0], dpy]
        return _ARGV_CACHE

    _ARGV_CACHE = [exe or "dirsearch"]
    return _ARGV_CACHE


class DirsearchAdapter(ToolAdapter):
    name = "dirsearch"
    binary_name = "dirsearch"
    result_type = "finding"

    async def check_installed(self) -> bool:
        argv = _resolve_argv()
        return bool(argv) and (len(argv) > 1 or bool(shutil.which(argv[0])) or os.path.exists(argv[0]))

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        extensions = options.get("extensions", "php,asp,aspx,jsp,html,js,txt,json,xml,bak")
        threads = str(options.get("threads", 20))
        wordlist = options.get("wordlist", "")

        cmd = _resolve_argv() + [
            "-u", target,
            "--full-url",          # always emit absolute URLs so parsing is unambiguous
            "--no-color", "-q",
            "-e", extensions,
            "-t", threads,
        ]

        if wordlist:
            cmd.extend(["-w", wordlist])

        # ── Recursive mode ──
        depth = str(options.get("recursion_depth", "")).strip()
        recursive = bool(options.get("recursive")) or (depth.isdigit() and int(depth) > 0)
        if recursive:
            cmd.append("-r")
            if depth.isdigit() and int(depth) > 0:
                cmd.extend(["-R", depth])
            if options.get("deep_recursive"):
                cmd.append("--deep-recursive")
            if options.get("force_recursive"):
                cmd.append("--force-recursive")
            rs = str(options.get("recursion_status", "")).strip()
            if rs:
                cmd.extend(["--recursion-status", rs])

        cookie = options.get("cookie", "") or options.get("session_cookies", "")
        if cookie:
            cmd.extend(["--cookie", cookie])
        session_headers = options.get("session_headers", "")
        if session_headers:
            for h in session_headers.replace("\r", "").split("\n"):
                h = h.strip()
                if h and ":" in h:
                    cmd.extend(["-H", h])

        # dirsearch v0.4+ with --full-url:  "[HH:MM:SS] 200 -    4KB - http://target/path"
        # older output:                     "  200  1234B  /path"
        pattern_new = re.compile(r"\[\d{2}:\d{2}:\d{2}\]\s+(\d{3})\s+-\s+\S+\s+-\s+(https?://\S+)")
        pattern_old = re.compile(r"\s+(\d{3})\s+[\d.]+\w+\s+(/\S+)")

        cmd = self._with_extra_args(cmd, options)
        yield {"_raw": True, "line": "$ " + " ".join(cmd)}
        async for line in self._run_subprocess(cmd, timeout=1800):
            url_found = None
            status = None
            path = "/"

            m = pattern_new.match(line)
            if m:
                status, url_found = m.groups()
                # Trim any "-> redirect" suffix and derive the path.
                url_found = url_found.split()[0]
                try:
                    path = urlparse(url_found).path or "/"
                except Exception:
                    path = "/"
            else:
                m = pattern_old.match(line)
                if m:
                    status, path = m.groups()
                    url_found = f"{target.rstrip('/')}{path}"

            if status and url_found:
                status_int = int(status)
                severity = "low" if status_int == 200 else "info"
                yield {
                    "id": None,
                    "title": f"[Dirsearch] {path} ({status})",
                    "severity": severity,
                    "vuln_type": "directory-listing",
                    "url": url_found,
                    "parameter": None,
                    "evidence": f"Status: {status}",
                    "description": "Path found via directory scan",
                    "tool": "dirsearch",
                    "template_id": None,
                    "status": "new",
                    "notes": None,
                }
