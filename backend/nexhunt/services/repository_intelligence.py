"""Repository recovery, secret history analysis and architecture extraction."""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable
from urllib.parse import urlparse

import httpx


Progress = Callable[[str, str, dict | None], Awaitable[None]]

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "out", ".next", ".cache",
    "coverage", "__pycache__", ".venv", "venv", "target", "Pods",
}
TEXT_EXTENSIONS = {
    ".env", ".ini", ".conf", ".config", ".properties", ".toml", ".yaml", ".yml",
    ".json", ".jsonc", ".xml", ".txt", ".md", ".py", ".rb", ".php", ".go",
    ".java", ".kt", ".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".sh",
    ".ps1", ".cs", ".gradle", ".tf", ".tfvars",
}
CONFIG_NAMES = {
    "dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
    "gemfile", "procfile", "makefile", "wp-config.php", "settings.py", "application.properties",
}
SENSITIVE_FILE_EXTENSIONS = {
    ".p12", ".pfx", ".pem", ".key", ".keystore", ".jks", ".kdbx", ".ovpn",
}

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("GitHub Token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b")),
    ("GitLab Token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,255}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe Secret Key", re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("SendGrid API Key", re.compile(r"\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{20,}\b")),
    ("Twilio API Key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b")),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("Connection String", re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps)://[^\s'\"<>]{6,}",
        re.IGNORECASE,
    )),
    ("Authenticated URL", re.compile(r"\bhttps?://[^\s/'\"<>@]+(?::[^\s/'\"<>@]+)?@[^\s'\"<>]+", re.IGNORECASE)),
    ("Assigned Secret", re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|"
        r"smtp[_-]?(?:pass|password)|oauth[_-]?(?:secret|token)|consumer[_-]?secret|private[_-]?key|"
        r"database[_-]?url|db[_-]?password|password|passwd|pwd)\b\s*[:=]\s*['\"]?([^\s'\"`,;}{]{6,})"
    )),
]

URL_RE = re.compile(r"\bhttps?://[^\s'\"`<>)}\]]+", re.IGNORECASE)
CONNECTION_RE = re.compile(
    r"\b(?P<scheme>postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|"
    r"ftp|sftp|ssh)://(?:(?P<credentials>[^@\s/]+)@)?(?P<host>\[[^\]]+\]|[^:/\s?#]+)"
    r"(?::(?P<port>\d{1,5}))?[^\s'\"`<>]*",
    re.IGNORECASE,
)
HOST_PORT_RE = re.compile(
    r"(?i)\b(?:host|hostname|server|endpoint|base[_-]?url|api[_-]?url)\b\s*[:=]\s*['\"]?"
    r"(?P<host>(?:[a-z0-9-]+\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3}|localhost)"
    r"(?::(?P<port>\d{1,5}))?"
)
REMOTE_RE = re.compile(r"^\s*url\s*=\s*(.+?)\s*$", re.MULTILINE)

PLACEHOLDERS = {
    "password", "secret", "changeme", "change_me", "example", "sample", "dummy", "test",
    "your_token_here", "your-secret", "your-client-secret", "your-access-token", "access-token",
    "replace_me", "replace-me", "undefined", "null", "none", "notasecret", "n/a", "key", "token",
    "apikey", "api_key",
}

# "Assigned Secret" is a loose keyword+value regex; most of its hits in real codebases are PHP/JS
# code fragments (variable references, method calls) rather than literal values. Reject those.
_CODE_FRAGMENT_RE = re.compile(r"[$()]|->")

# Evidence coming from vendored/test/example code is much more likely to be a fixture or library
# internal than an application secret. Flag it as low-confidence instead of dropping it, so the
# UI and the AI briefing can deprioritize without hiding it outright.
_LOW_CONFIDENCE_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:tests?|vendor|mock|samples?)(?:/|$)|\.env-example|-example(?:\.|/|$)"
)


def _looks_like_code_fragment(value: str) -> bool:
    return bool(_CODE_FRAGMENT_RE.search(value)) or value in {"true", "false", "null"}


def normalize_target(value: str) -> tuple[str, str]:
    raw = value.strip()
    if not raw:
        raise ValueError("Target URL is required")
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Target must be a valid HTTP(S) URL")
    base_path = parsed.path or "/"
    for suffix in ("/.git/HEAD", "/.git/config", "/.git/index", "/.git/"):
        if base_path.endswith(suffix):
            base_path = base_path[: -len(suffix)] or "/"
            break
    base = f"{parsed.scheme}://{parsed.netloc}{base_path.rstrip('/')}"
    return base, f"{base}/.git/"


def workspace_for(project_id: str, target: str, db_dir: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9-]{1,80}", project_id):
        raise ValueError("Invalid project id")
    host = (urlparse(target).hostname or "target").lower()
    slug = re.sub(r"[^a-z0-9.-]+", "-", host).strip("-.")[:80] or "target"
    return Path(db_dir) / "projects" / project_id / "repository-intelligence" / slug


def _safe_git_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    return {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_PAGER": "cat",
        "PAGER": "cat",
        "LC_ALL": "C",
        # Never execute hooks or filesystem monitors recovered from an untrusted repository.
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "core.hooksPath",
        "GIT_CONFIG_VALUE_0": os.devnull,
        "GIT_CONFIG_KEY_1": "core.fsmonitor",
        "GIT_CONFIG_VALUE_1": "false",
        **(extra or {}),
    }


async def _command(
    *args: str,
    cwd: Path | None = None,
    timeout: int = 120,
    env_extra: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    env = _safe_git_environment(env_extra)
    proc = await asyncio.create_subprocess_exec(
        *args,
        cwd=str(cwd) if cwd else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise RuntimeError(f"Command timed out after {timeout}s: {args[0]}")
    return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")


async def _git_archive(repo: Path) -> bytes:
    proc = await asyncio.create_subprocess_exec(
        "git", "archive", "--format=tar", "HEAD",
        cwd=str(repo), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env=_safe_git_environment(),
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"Could not materialize recovered HEAD: {stderr.decode(errors='replace')[-2000:]}")
    if len(stdout) > 750_000_000:
        raise RuntimeError("Recovered working tree exceeds the 750 MB safety limit")
    return stdout


async def materialize_working_tree(repo: Path) -> int:
    """Export HEAD without invoking checkout, filters, hooks, or repository commands."""
    archive = await _git_archive(repo)
    for child in repo.iterdir():
        if child.name == ".git":
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink(missing_ok=True)

    total_size = 0
    file_count = 0
    root = repo.resolve()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as handle:
        members = handle.getmembers()
        if len(members) > 50_000:
            raise RuntimeError("Recovered working tree exceeds the 50,000-file safety limit")
        for member in members:
            relative = Path(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                raise RuntimeError(f"Unsafe path in recovered repository: {member.name}")
            destination = (repo / relative).resolve()
            if destination != root and root not in destination.parents:
                raise RuntimeError(f"Path escapes repository workspace: {member.name}")
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            if member.isfile():
                total_size += member.size
                if total_size > 750_000_000:
                    raise RuntimeError("Recovered working tree exceeds the 750 MB safety limit")
                source = handle.extractfile(member)
                if source is None:
                    continue
                with destination.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                destination.chmod(0o600)
                file_count += 1
            elif member.issym() or member.islnk():
                # Preserve the link target as evidence, but never create a link that could point
                # the scanner outside the isolated repository workspace.
                destination.write_text(member.linkname, encoding="utf-8")
                destination.chmod(0o600)
                file_count += 1
    return file_count


async def inspect_exposure(git_url: str) -> dict:
    checks: list[dict] = []
    async with httpx.AsyncClient(timeout=12, follow_redirects=False, verify=False) as client:
        for name in ("HEAD", "config", "index"):
            url = f"{git_url}{name}"
            try:
                response = await client.get(url, headers={"User-Agent": "NexHunt/Repository-Intelligence"})
                body = response.content[:4096]
                text = body.decode(errors="replace")
                signature = (
                    (name == "HEAD" and (text.startswith("ref:") or re.fullmatch(r"[0-9a-f]{40}\s*", text) is not None))
                    or (name == "config" and "[core]" in text and "repositoryformatversion" in text)
                    or (name == "index" and body.startswith(b"DIRC"))
                )
                checks.append({
                    "name": name,
                    "url": url,
                    "status": response.status_code,
                    "size": len(response.content),
                    "signature": bool(signature),
                    "evidence": text[:500] if name != "index" else body[:24].hex(),
                })
            except Exception as error:
                checks.append({"name": name, "url": url, "status": 0, "size": 0, "signature": False, "evidence": str(error)})
    exposed = any(item["signature"] for item in checks)
    return {"exposed": exposed, "checks": checks}


async def recover_repository(git_url: str, destination: Path) -> dict:
    binary = shutil.which("git-dumper")
    if not binary:
        raise RuntimeError("git-dumper is not installed. Re-run the NexHunt installer to add it.")
    root = destination.parent.resolve()
    resolved = destination.resolve()
    if root not in resolved.parents:
        raise RuntimeError("Unsafe repository destination")
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)

    # git-dumper normally ends with `git checkout .`. Its own documentation warns that a
    # hostile repository can execute code at that point (e.g. post-checkout hooks). Put a
    # controlled git shim first in PATH so only that checkout is skipped; NexHunt exports HEAD
    # itself below without hooks, filters, or symlinks.
    real_git = shutil.which("git")
    if not real_git:
        raise RuntimeError("git is not installed")
    shim_dir = destination.parent / ".git-shim"
    shim_dir.mkdir(mode=0o700, exist_ok=True)
    shim = shim_dir / "git"
    shim.write_text(
        "#!/bin/sh\n"
        "if [ \"${1:-}\" = \"checkout\" ]; then exit 0; fi\n"
        f"exec {shlex.quote(real_git)} \"$@\"\n",
        encoding="utf-8",
    )
    shim.chmod(0o700)
    try:
        code, stdout, stderr = await _command(
            binary, git_url, str(destination), timeout=900,
            env_extra={"PATH": f"{shim_dir}{os.pathsep}{os.environ.get('PATH', '')}"},
        )
    finally:
        shutil.rmtree(shim_dir, ignore_errors=True)
    if code != 0 or not (destination / ".git").is_dir():
        detail = (stderr or stdout or "git-dumper did not reconstruct a repository")[-3000:]
        raise RuntimeError(detail)
    config = destination / ".git" / "config"
    recovered_config = destination / ".git" / "config-recovered"
    if config.exists():
        if recovered_config.exists():
            recovered_config.unlink()
        config.rename(recovered_config)
    config.write_text(
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "\tbare = false\n"
        "\tlogallrefupdates = true\n",
        encoding="utf-8",
    )
    config.chmod(0o600)
    hooks = destination / ".git" / "hooks"
    if hooks.exists():
        quarantine = destination / ".git" / "hooks-quarantined"
        if quarantine.exists():
            shutil.rmtree(quarantine)
        hooks.rename(quarantine)
    file_count = await materialize_working_tree(destination)
    commit_code, commit_out, _ = await _command("git", "rev-list", "--all", "--count", cwd=destination, timeout=60)
    return {
        "path": str(destination),
        "commits": int(commit_out.strip()) if commit_code == 0 and commit_out.strip().isdigit() else 0,
        "files": file_count,
        "log": (stdout + "\n" + stderr).strip()[-5000:],
    }


def _text_files(repo: Path, limit: int = 3000) -> list[Path]:
    files: list[Path] = []
    for root, dirs, names in os.walk(repo):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
        for name in names:
            path = Path(root) / name
            if name.lower() in CONFIG_NAMES or path.suffix.lower() in TEXT_EXTENSIONS or name.startswith(".env"):
                try:
                    if path.stat().st_size <= 2_000_000:
                        files.append(path)
                except OSError:
                    continue
                if len(files) >= limit:
                    return files
    return files


def _secret_matches(text: str, source: str, commit: str = "working-tree") -> list[dict]:
    found: list[dict] = []
    seen: set[tuple[str, str, int]] = set()
    for detector, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(1) if detector == "Assigned Secret" and match.lastindex else match.group(0)
            raw = raw.strip().rstrip(".,)")
            if raw.lower() in PLACEHOLDERS or len(raw) < 6:
                continue
            if detector == "Assigned Secret" and _looks_like_code_fragment(raw):
                continue
            line = text.count("\n", 0, match.start()) + 1
            key = (detector, raw, line)
            if key in seen:
                continue
            seen.add(key)
            start = text.rfind("\n", 0, match.start()) + 1
            end = text.find("\n", match.end())
            evidence = text[start:(end if end >= 0 else len(text))].strip()[:1200]
            found.append({
                "detector": detector,
                "raw": raw,
                "source": source,
                "line": line,
                "commit": commit,
                "evidence": evidence,
                "historical": commit != "working-tree",
                "low_confidence": bool(_LOW_CONFIDENCE_PATH_RE.search(source)),
            })
    return found


async def _history_secret_matches(repo: Path, max_bytes: int = 300_000_000) -> tuple[list[dict], dict]:
    """Scan each unique historical text blob once instead of replaying every commit diff."""
    code, objects_out, _ = await _command("git", "rev-list", "--objects", "--all", cwd=repo, timeout=120)
    if code != 0:
        return [], {"objects_scanned": 0, "history_bytes": 0, "truncated": False}
    candidates: list[tuple[str, str]] = []
    seen_hashes: set[str] = set()
    for row in objects_out.splitlines():
        sha, separator, source = row.partition(" ")
        if not separator or sha in seen_hashes:
            continue
        name = Path(source).name.lower()
        suffix = Path(source).suffix.lower()
        if suffix not in TEXT_EXTENSIONS and name not in CONFIG_NAMES and not name.startswith(".env"):
            continue
        seen_hashes.add(sha)
        candidates.append((sha, source))
        if len(candidates) >= 25_000:
            break
    if not candidates:
        return [], {"objects_scanned": 0, "history_bytes": 0, "truncated": False}

    proc = await asyncio.create_subprocess_exec(
        "git", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        cwd=str(repo), stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, env=_safe_git_environment(),
    )
    query = ("\n".join(sha for sha, _ in candidates) + "\n").encode()
    checked, _ = await asyncio.wait_for(proc.communicate(query), timeout=120)
    path_by_hash = dict(candidates)
    selected: list[tuple[str, str, int]] = []
    total = 0
    truncated = len(candidates) >= 25_000
    for row in checked.decode(errors="replace").splitlines():
        parts = row.split()
        if len(parts) != 3 or parts[1] != "blob" or not parts[2].isdigit():
            continue
        size = int(parts[2])
        if size > 2_000_000 or total + size > max_bytes:
            truncated = True
            continue
        selected.append((parts[0], path_by_hash.get(parts[0], "history"), size))
        total += size

    proc = await asyncio.create_subprocess_exec(
        "git", "cat-file", "--batch", cwd=str(repo), stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env=_safe_git_environment(),
    )
    payload, _ = await asyncio.wait_for(
        proc.communicate(("\n".join(sha for sha, _, _ in selected) + "\n").encode()), timeout=300,
    )
    matches: list[dict] = []
    cursor = 0
    for expected_sha, source, _ in selected:
        header_end = payload.find(b"\n", cursor)
        if header_end < 0:
            truncated = True
            break
        header = payload[cursor:header_end].decode(errors="replace").split()
        if len(header) < 3 or not header[2].isdigit():
            truncated = True
            break
        size = int(header[2])
        start = header_end + 1
        blob = payload[start:start + size]
        cursor = start + size + 1
        matches.extend(_secret_matches(blob.decode(errors="replace"), source, f"object:{expected_sha}"))
    return matches, {"objects_scanned": len(selected), "history_bytes": total, "truncated": truncated}


async def scan_secrets(repo: Path, max_commits: int = 300) -> tuple[list[dict], dict]:
    results: list[dict] = []
    for path in _text_files(repo):
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        results.extend(_secret_matches(text, str(path.relative_to(repo))))
    recovered_config = repo / ".git" / "config-recovered"
    if recovered_config.exists():
        try:
            results.extend(_secret_matches(recovered_config.read_text(errors="replace"), ".git/config"))
        except OSError:
            pass

    _, commit_count, _ = await _command("git", "rev-list", "--all", "--count", cwd=repo, timeout=60)
    history_detail = {"objects_scanned": 0, "history_bytes": 0, "truncated": False}
    if max_commits > 0:
        historical, history_detail = await _history_secret_matches(repo)
        results.extend(historical)

    unique: list[dict] = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in results:
        key = (item["detector"], item["raw"], item["source"], item["commit"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
        if len(unique) >= 1500:
            break
    commits_scanned = int(commit_count.strip()) if commit_count.strip().isdigit() and max_commits > 0 else 0
    return unique, {
        "commits_scanned": commits_scanned,
        **history_detail,
        "truncated": history_detail["truncated"] or len(results) > len(unique),
    }


async def repository_metadata(repo: Path) -> dict:
    recovered_config = repo / ".git" / "config-recovered"
    config_path = recovered_config if recovered_config.exists() else repo / ".git" / "config"
    config = config_path.read_text(errors="replace") if config_path.exists() else ""
    remotes = REMOTE_RE.findall(config)
    _, branch, _ = await _command("git", "branch", "--show-current", cwd=repo, timeout=30)
    _, recent, _ = await _command("git", "log", "-n", "25", "--date=iso-strict", "--pretty=format:%H%x09%an%x09%ad%x09%s", cwd=repo, timeout=30)
    commits = []
    for line in recent.splitlines():
        parts = line.split("\t", 3)
        if len(parts) == 4:
            commits.append({"hash": parts[0], "author": parts[1], "date": parts[2], "subject": parts[3]})
    return {"branch": branch.strip(), "remotes": remotes, "config": config[:5000], "recent_commits": commits}


def detect_providers(remotes: list[str], secrets: list[dict]) -> list[dict]:
    candidates: list[dict] = []
    values = [(remote, ".git/config", "remote") for remote in remotes]
    values.extend((item["raw"], item["source"], "secret") for item in secrets)
    for value, source, kind in values:
        lower = value.lower()
        provider = None
        if "github" in lower or value.startswith(("ghp_", "github_pat_")):
            provider = "github"
        elif "gitlab" in lower or value.startswith("glpat-"):
            provider = "gitlab"
        elif "bitbucket" in lower:
            provider = "bitbucket"
        if provider:
            candidates.append({"provider": provider, "source": source, "kind": kind, "evidence": value})
    unique: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in candidates:
        key = (item["provider"], item["evidence"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def extract_architecture(repo: Path) -> dict:
    services: list[dict] = []
    urls: list[dict] = []
    files_scanned = 0
    for path in _text_files(repo):
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        files_scanned += 1
        relative = str(path.relative_to(repo))
        for match in CONNECTION_RE.finditer(text):
            scheme = match.group("scheme").lower()
            host = match.group("host").strip("[]")
            port = int(match.group("port")) if match.group("port") else None
            services.append({
                "scheme": scheme, "host": host, "port": port, "source": relative,
                "evidence": match.group(0)[:1000], "credentials_exposed": bool(match.group("credentials")),
            })
        for match in URL_RE.finditer(text):
            raw = match.group(0).rstrip(".,;")
            parsed = urlparse(raw)
            if parsed.hostname:
                urls.append({
                    "url": raw[:2000], "host": parsed.hostname, "port": parsed.port,
                    "scheme": parsed.scheme, "source": relative,
                })
        for match in HOST_PORT_RE.finditer(text):
            services.append({
                "scheme": "service", "host": match.group("host"),
                "port": int(match.group("port")) if match.group("port") else None,
                "source": relative, "evidence": match.group(0)[:1000], "credentials_exposed": False,
            })

    unique_services: list[dict] = []
    service_keys: set[tuple] = set()
    for item in services:
        key = (item["scheme"], item["host"], item["port"], item["source"])
        if key not in service_keys:
            service_keys.add(key)
            unique_services.append(item)
        if len(unique_services) >= 1000:
            break
    unique_urls: list[dict] = []
    url_keys: set[str] = set()
    for item in urls:
        if item["url"] not in url_keys:
            url_keys.add(item["url"])
            unique_urls.append(item)
        if len(unique_urls) >= 1000:
            break

    hosts = sorted({item["host"] for item in unique_services + unique_urls if item.get("host")})
    nodes = [{"id": "repository", "label": repo.name, "kind": "repository"}]
    nodes.extend({"id": f"host:{host}", "label": host, "kind": "host"} for host in hosts)
    edges = [{"source": "repository", "target": f"host:{host}", "kind": "references"} for host in hosts]
    return {
        "files_scanned": files_scanned,
        "hosts": hosts,
        "services": unique_services,
        "urls": unique_urls,
        "graph": {"nodes": nodes, "edges": edges},
    }


def _line_evidence(text: str, offset: int) -> tuple[int, str]:
    line = text.count("\n", 0, offset) + 1
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    return line, text[start:(end if end >= 0 else len(text))].strip()[:800]


def analyze_code_risks(repo: Path) -> dict:
    """Build a plain-text, source-linked risk ledger without executing recovered code."""
    findings: list[dict] = []
    routes: list[dict] = []
    technologies: set[str] = set()
    sensitive_files: list[dict] = []
    paths = {str(path.relative_to(repo)).replace(os.sep, "/") for path in _text_files(repo, 8000)}

    technology_markers = {
        "CodeIgniter": ("application/config/config.php", "system/core/CodeIgniter.php", "application/controllers/"),
        "Laravel": ("artisan", "app/Http/Controllers/", "config/app.php"),
        "WordPress": ("wp-config.php", "wp-content/"),
        "Symfony": ("bin/console", "config/bundles.php"),
        "Node.js": ("package.json",),
        "Django": ("manage.py", "settings.py"),
    }
    for technology, markers in technology_markers.items():
        if any(any(path == marker or path.startswith(marker) for path in paths) for marker in markers):
            technologies.add(technology)

    for root, dirs, names in os.walk(repo):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
        for name in names:
            path = Path(root) / name
            relative = str(path.relative_to(repo)).replace(os.sep, "/")
            suffix = path.suffix.lower()
            if suffix in SENSITIVE_FILE_EXTENSIONS:
                try:
                    payload = path.read_bytes()
                except OSError:
                    continue
                if suffix == ".pem":
                    text_guess = payload.decode(errors="replace")
                    if "PRIVATE KEY" not in text_guess and "BEGIN CERTIFICATE" in text_guess:
                        # A CA/certificate bundle with no private key is public material (e.g. a
                        # library vendoring Mozilla's cacert.pem for TLS verification), not a secret.
                        continue
                digest = hashlib.sha256(payload).hexdigest()
                size = len(payload)
                sensitive_files.append({"source": relative, "size": size, "sha256": digest, "extension": suffix})
                findings.append({
                    "severity": "critical" if suffix in {".p12", ".pfx", ".key", ".pem"} else "high",
                    "category": "sensitive-file",
                    "title": f"Sensitive cryptographic material: {name}",
                    "source": relative, "line": 1, "symbol": "", 
                    "evidence": f"{relative} ({size} bytes, SHA-256 {digest})",
                    "rationale": "Private keys, certificate bundles and keystores can grant service or signing access even when no text secret is visible.",
                    "remediation": "Revoke or rotate the material, remove it from every Git object and store replacements in a managed secret store.",
                })
            if suffix not in TEXT_EXTENSIONS and name.lower() not in CONFIG_NAMES:
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue

            if suffix == ".php" and ("application/controllers/" in relative or "/controllers/" in relative.lower()):
                class_match = re.search(r"\bclass\s+(\w+)\s+extends\s+(\w+)", text, re.IGNORECASE)
                class_name = class_match.group(1) if class_match else path.stem
                base_class = class_match.group(2) if class_match else "unknown"
                for method in re.finditer(r"(?im)^\s*(?:public\s+)?function\s+(\w+)\s*\(", text):
                    method_name = method.group(1)
                    if method_name.startswith("_"):
                        continue
                    line, evidence = _line_evidence(text, method.start())
                    route = f"/{path.stem.lower()}" + ("" if method_name == "index" else f"/{method_name}")
                    routes.append({
                        "route": route, "controller": class_name, "method": method_name,
                        "base_class": base_class, "source": relative, "line": line,
                    })
                if base_class.lower() == "ci_controller":
                    line, evidence = _line_evidence(text, class_match.start() if class_match else 0)
                    findings.append({
                        "severity": "high", "category": "authorization",
                        "title": f"Controller bypasses the application base controller: {class_name}",
                        "source": relative, "line": line, "symbol": class_name, "evidence": evidence,
                        "rationale": "Direct CI_Controller inheritance can bypass authentication, authorization or audit controls implemented in MY_Controller.",
                        "remediation": "Verify every public method and inherit from the guarded base controller or apply equivalent authorization explicitly.",
                    })

            rules: list[tuple[str, str, str, re.Pattern[str], str, str]] = [
                ("critical", "command-execution", "User-controlled command execution sink", re.compile(r"(?i)\b(?:shell_exec|exec|system|passthru|popen|proc_open)\s*\([^\n]*(?:\$_(?:GET|POST|REQUEST)|\$this->input)"), "Input appears to reach an operating-system command primitive.", "Remove the shell call or enforce a strict allowlist and argument-safe API."),
                ("high", "ssrf", "Variable URL reaches an outbound request", re.compile(r"(?i)\b(?:file_get_contents|fopen|curl_init)\s*\(\s*\$(?:url|uri|endpoint|remote|link|host)\w*|CURLOPT_URL\s*,\s*\$"), "A caller-influenced URL may let the server request internal or cloud-metadata addresses.", "Allowlist scheme, host and port; resolve DNS safely and block private, loopback and link-local ranges."),
                ("high", "file-upload", "File upload reaches server storage", re.compile(r"(?i)\b(?:move_uploaded_file|do_upload\s*\(|\$_FILES\b)"), "Uploaded content can become code execution or stored XSS when extension, MIME, path and serving origin are not constrained.", "Validate content server-side, generate names, store outside the web root and serve from a non-executable origin."),
                ("high", "file-write", "Caller-influenced filesystem operation", re.compile(r"(?i)\b(?:unlink|rename|copy|file_put_contents|mkdir|rmdir)\s*\([^\n]*(?:\$_(?:GET|POST|REQUEST)|\$this->input)"), "Request data appears in a filesystem operation and may allow traversal or destructive writes.", "Resolve against a fixed base directory and reject paths that escape it."),
                ("high", "cloud-action", "Cloud or cache mutation endpoint", re.compile(r"(?i)\b(?:deleteObject|putObject|copyObject|purge_all|purge_cache|invalidate)\s*\("), "This code performs a high-impact external mutation that needs explicit authorization and tightly scoped credentials.", "Require authorization, CSRF protection where relevant, audit logging and least-privilege service credentials."),
                ("medium", "debug-exposure", "PHP environment disclosure", re.compile(r"(?i)\bphpinfo\s*\("), "PHP environment output can reveal paths, configuration, tokens and personal data.", "Remove the endpoint or make it inaccessible outside a controlled development environment."),
                ("high", "dynamic-sql", "Request data appears in a SQL query", re.compile(r"(?i)(?:query|mysqli_query|mysql_query)\s*\([^\n]*(?:\$_(?:GET|POST|REQUEST)|\$this->input)"), "Untrusted input appears to reach a raw SQL query.", "Use parameterized queries and validate the expected data type."),
            ]
            for severity, category, title, pattern, rationale, remediation in rules:
                for match in pattern.finditer(text):
                    line, evidence = _line_evidence(text, match.start())
                    findings.append({
                        "severity": severity, "category": category, "title": title,
                        "source": relative, "line": line, "symbol": "", "evidence": evidence,
                        "rationale": rationale, "remediation": remediation,
                    })

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    unique: list[dict] = []
    seen: set[tuple[str, str, int, str]] = set()
    for finding in sorted(findings, key=lambda item: (severity_rank.get(item["severity"], 9), item["source"], item["line"])):
        key = (finding["category"], finding["source"], finding["line"], finding["title"])
        if key not in seen:
            seen.add(key)
            finding["command"] = f"git -C {shlex.quote(str(repo))} blame -L {finding['line']},{finding['line']} -- {shlex.quote(finding['source'])}"
            unique.append(finding)
        if len(unique) >= 2000:
            break
    return {
        "technologies": sorted(technologies), "routes": routes[:2000],
        "sensitive_files": sensitive_files[:500], "findings": unique,
    }


def build_next_steps(repo: Path, analysis: dict) -> list[dict]:
    steps: list[dict] = []
    if analysis["sensitive_files"]:
        steps.append({
            "priority": "immediate", "title": "Inventory and rotate cryptographic material",
            "reason": f"{len(analysis['sensitive_files'])} sensitive key or certificate files were found.",
            "command": f"find {shlex.quote(str(repo))} -type f \\( -name '*.p12' -o -name '*.pfx' -o -name '*.pem' -o -name '*.key' -o -name '*.jks' \\) -print",
        })
    if analysis["routes"]:
        steps.append({
            "priority": "high", "title": "Review controller exposure and authorization",
            "reason": f"{len(analysis['routes'])} controller methods were mapped from source.",
            "command": f"rg -n \"class .* extends|public function|function \" {shlex.quote(str(repo / 'application' / 'controllers'))}",
        })
    steps.append({
        "priority": "high", "title": "Inspect every high-risk line with Git attribution",
        "reason": "The Findings view includes a safe, local git blame command for each result.",
        "command": f"git -C {shlex.quote(str(repo))} log --all --oneline --decorate -- application/config application/controllers",
    })
    steps.append({
        "priority": "normal", "title": "Confirm that secrets were removed from history",
        "reason": "Deleting a value from HEAD does not remove it from historical Git objects.",
        "command": f"git -C {shlex.quote(str(repo))} rev-list --objects --all",
    })
    return steps


def build_ai_digest(report: dict) -> str:
    """Condense a repository intelligence report into a compact, high-signal digest for the AI
    briefing. Raw reports can hold thousands of low-value regex hits (400+ secrets is common) that
    would blow past a free-tier LLM's context budget, so this keeps only what a triage pass needs:
    top findings, high-confidence secrets first, and counts for everything else."""
    lines: list[str] = [f"Target: {report.get('target', '')}"]
    technologies = report.get("technologies") or []
    lines.append(f"Detected framework/stack: {', '.join(technologies) or 'unknown'}")

    summary = report.get("summary") or {}
    lines.append(
        f"Scan summary: {summary.get('commits', 0)} commits, {summary.get('files', 0)} files, "
        f"{summary.get('secrets', 0)} secret matches ({summary.get('historical_secrets', 0)} only in "
        f"deleted history), {summary.get('findings', 0)} code findings "
        f"({summary.get('critical_findings', 0)} flagged critical), {summary.get('hosts', 0)} referenced "
        f"hosts, {summary.get('routes', 0)} controller routes mapped."
    )

    findings = report.get("findings") or []
    if findings:
        lines.append(f"\n## Code findings (top {min(30, len(findings))} of {len(findings)}, most severe first)")
        for item in findings[:30]:
            lines.append(f"- [{item['severity'].upper()}] {item['title']} — {item['source']}:{item['line']}")
            lines.append(f"  evidence: {item['evidence'][:220]}")

    secrets = report.get("secrets") or []
    if secrets:
        high_conf = [s for s in secrets if not s.get("low_confidence") and s["detector"] != "Assigned Secret"]
        assigned = [s for s in secrets if s["detector"] == "Assigned Secret" and not s.get("low_confidence")]
        low_conf_count = sum(1 for s in secrets if s.get("low_confidence"))
        shown = (high_conf + assigned)[:40]
        lines.append(
            f"\n## Secret matches — high-confidence detectors first, {len(shown)} of {len(secrets)} shown "
            f"({low_conf_count} more auto-flagged as low-confidence vendor/test noise, omitted here)"
        )
        for item in shown:
            scope = "historical only (deleted, but still in Git objects)" if item["historical"] else "in current working tree"
            lines.append(f"- {item['detector']} in {item['source']}:{item['line']} ({scope}): {item['raw'][:120]}")

    sensitive_files = report.get("sensitive_files") or []
    if sensitive_files:
        lines.append(f"\n## Sensitive key/certificate files ({len(sensitive_files)})")
        for item in sensitive_files[:20]:
            lines.append(f"- {item['source']} ({item['extension']}, {item['size']} bytes, sha256 {item['sha256'][:16]}...)")

    providers = report.get("providers") or []
    if providers:
        lines.append("\n## Source-control provider evidence")
        for item in providers[:10]:
            lines.append(f"- {item['provider']} ({item['kind']}): {item['evidence'][:150]} — {item['source']}")

    architecture = report.get("architecture") or {}
    hosts = architecture.get("hosts") or []
    if hosts:
        lines.append(f"\n## Referenced hosts ({len(hosts)}, showing up to 40)")
        lines.append(", ".join(hosts[:40]))

    services = architecture.get("services") or []
    exposed = [item for item in services if item.get("credentials_exposed")]
    if exposed:
        lines.append(f"\n## Connection strings with embedded credentials ({len(exposed)})")
        for item in exposed[:15]:
            port_part = f":{item['port']}" if item.get("port") else ""
            lines.append(f"- {item['scheme']}://{item['host']}{port_part} — {item['source']}")

    return "\n".join(lines)


async def analyze_repository(
    target: str,
    project_id: str,
    db_dir: str,
    recover: bool,
    scan_history: bool,
    progress: Progress,
) -> dict:
    base_url, git_url = normalize_target(target)
    workspace = workspace_for(project_id, base_url, db_dir)
    repo = workspace / "repository"
    workspace.mkdir(parents=True, exist_ok=True)
    workspace.chmod(0o700)

    await progress("exposure", "Checking exposed Git metadata", None)
    exposure = await inspect_exposure(git_url)
    if recover and not exposure["exposed"]:
        raise RuntimeError("No valid exposed Git metadata was found at the target")

    repository: dict = {"path": str(repo), "commits": 0, "files": 0, "log": ""}
    if recover:
        await progress("recovery", "Reconstructing repository with git-dumper", None)
        repository = await recover_repository(git_url, repo)
    elif not (repo / ".git").is_dir():
        raise RuntimeError("No recovered repository exists for this target")

    await progress("history", "Scanning current files and Git history", {"path": str(repo)})
    metadata = await repository_metadata(repo)
    secrets, history = await scan_secrets(repo, 300 if scan_history else 0)

    await progress("providers", "Identifying source-control providers", {"secrets": len(secrets)})
    providers = detect_providers(metadata["remotes"], secrets)

    await progress("architecture", "Extracting hosts, services and connection paths", None)
    architecture = extract_architecture(repo)
    await progress("code-analysis", "Mapping frameworks, routes and dangerous data flows", None)
    code_analysis = analyze_code_risks(repo)
    next_steps = build_next_steps(repo, code_analysis)
    now = datetime.now(timezone.utc).isoformat()
    report = {
        "target": base_url,
        "git_url": git_url,
        "project_id": project_id,
        "created_at": now,
        "exposure": exposure,
        "repository": {**repository, **metadata},
        "history": history,
        "secrets": secrets,
        "providers": providers,
        "architecture": architecture,
        "technologies": code_analysis["technologies"],
        "routes": code_analysis["routes"],
        "sensitive_files": code_analysis["sensitive_files"],
        "findings": code_analysis["findings"],
        "next_steps": next_steps,
        "ai_brief": None,
        "ai_brief_generated_at": None,
        "summary": {
            "commits": repository.get("commits", 0),
            "files": repository.get("files", 0),
            "secrets": len(secrets),
            "historical_secrets": sum(1 for item in secrets if item["historical"]),
            "providers": len({item["provider"] for item in providers}),
            "hosts": len(architecture["hosts"]),
            "services": len(architecture["services"]),
            "findings": len(code_analysis["findings"]),
            "critical_findings": sum(1 for item in code_analysis["findings"] if item["severity"] == "critical"),
            "routes": len(code_analysis["routes"]),
        },
    }
    report_path = workspace / "report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report_path.chmod(0o600)
    await progress("complete", "Repository intelligence report ready", report["summary"])
    return report
