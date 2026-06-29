"""Repository recovery, secret history analysis and architecture extraction."""
from __future__ import annotations

import asyncio
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

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("GitHub Token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b")),
    ("GitLab Token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,255}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b")),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("Connection String", re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps)://[^\s'\"<>]{6,}",
        re.IGNORECASE,
    )),
    ("Authenticated URL", re.compile(r"\bhttps?://[^\s/'\"<>@]+(?::[^\s/'\"<>@]+)?@[^\s'\"<>]+", re.IGNORECASE)),
    ("Assigned Secret", re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|"
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
    "your_token_here", "your-secret", "replace_me", "replace-me", "undefined", "null", "none",
}


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
            })
    return found


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

    code, stdout, _ = await _command("git", "rev-list", "--all", "--max-count", str(max_commits), cwd=repo, timeout=60)
    commits = stdout.splitlines() if code == 0 else []
    for commit in commits:
        code, diff, _ = await _command(
            "git", "show", "--no-ext-diff", "--no-textconv", "--format=", "--find-renames", "--find-copies", "--unified=0", commit,
            cwd=repo, timeout=30,
        )
        if code != 0:
            continue
        if len(diff) > 5_000_000:
            diff = diff[:5_000_000]
        current_file = "history"
        chunks: dict[str, list[str]] = {}
        for line in diff.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:]
                continue
            if line.startswith("+") and not line.startswith("+++"):
                chunks.setdefault(current_file, []).append(line[1:])
        for source, lines in chunks.items():
            results.extend(_secret_matches("\n".join(lines), source, commit))

    unique: list[dict] = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in results:
        key = (item["detector"], item["raw"], item["source"], item["commit"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
        if len(unique) >= 1500:
            break
    return unique, {"commits_scanned": len(commits), "truncated": len(results) > len(unique)}


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
        "summary": {
            "commits": repository.get("commits", 0),
            "files": repository.get("files", 0),
            "secrets": len(secrets),
            "historical_secrets": sum(1 for item in secrets if item["historical"]),
            "providers": len({item["provider"] for item in providers}),
            "hosts": len(architecture["hosts"]),
            "services": len(architecture["services"]),
        },
    }
    report_path = workspace / "report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report_path.chmod(0o600)
    await progress("complete", "Repository intelligence report ready", report["summary"])
    return report
