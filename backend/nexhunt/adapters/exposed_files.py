import re
import httpx
from urllib.parse import urlparse
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


def _looks_git_head(t: str) -> bool:
    t = t.strip()
    return t.startswith("ref:") or bool(re.fullmatch(r"[0-9a-f]{40}", t))


def _looks_env(t: str) -> bool:
    # At least one UPPER_SNAKE=value line, and not HTML
    if "<html" in t.lower() or "<!doctype" in t.lower():
        return False
    return bool(re.search(r"(?m)^[A-Z][A-Z0-9_]{2,}=", t))


def _looks_git_config(t: str) -> bool:
    return "[core]" in t or "[remote " in t or "repositoryformatversion" in t


def _looks_svn(t: str) -> bool:
    return "svn://" in t or "dir\n" in t or t.strip().isdigit() or "SQLite format 3" in t


def _looks_dsstore(t: str) -> bool:
    return t.startswith("\x00\x00\x00\x01Bud1") or "Bud1" in t[:8]


def _looks_htpasswd(t: str) -> bool:
    return bool(re.search(r"(?m)^[^:\s]+:\$?(apr1|2y|1|6)?\$?", t)) and ":" in t and "<html" not in t.lower()


def _looks_webxml(t: str) -> bool:
    return "<web-app" in t or "<servlet" in t


# (path, label, severity, signature_fn, repro/impact note)
_CHECKS = [
    (".git/HEAD", "Exposed .git repository", "critical", _looks_git_head,
     "Dump the full source + history:  git-dumper http://HOST/.git/ ./loot  (then grep for secrets in git log)."),
    (".git/config", "Exposed .git/config", "high", _looks_git_config,
     "Reveals remote URLs (often with embedded creds). Pair with git-dumper to reconstruct the repo."),
    (".env", "Exposed .env file", "critical", _looks_env,
     "Application secrets in cleartext (DB creds, API keys, APP_KEY). Read it directly and pivot."),
    (".svn/wc.db", "Exposed .svn metadata", "high", _looks_svn,
     "SVN working copy DB — extract original source paths and pristine files."),
    (".svn/entries", "Exposed .svn/entries", "high", _looks_svn,
     "Older SVN layout — enumerate tracked files and reconstruct source."),
    (".DS_Store", "Exposed .DS_Store", "medium", _looks_dsstore,
     "macOS directory index — parse it to enumerate hidden filenames in this folder."),
    (".htpasswd", "Exposed .htpasswd", "high", _looks_htpasswd,
     "Apache basic-auth hashes — crack offline with hashcat/john to recover credentials."),
    ("WEB-INF/web.xml", "Exposed WEB-INF/web.xml", "high", _looks_webxml,
     "Java app deployment descriptor — maps servlets, params and often internal endpoints/creds."),
]


class ExposedFilesAdapter(ToolAdapter):
    """Probe a host for exposed VCS dirs, env files and other sensitive artifacts."""
    name = "exposed_files"
    binary_name = ""
    result_type = "finding"

    async def check_installed(self) -> bool:
        return True

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        url = target if "://" in target else f"https://{target}"
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        yield {"_raw": True, "line": f"$ exposed-files {base} ({len(_CHECKS)} checks)"}

        headers = {"User-Agent": "Mozilla/5.0 NexHunt ExposedFiles"}
        cookie = options.get("session_cookies", "")
        if cookie:
            headers["Cookie"] = cookie

        async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=False) as client:
            # Catch-all detection: a random path that should 404
            catch_all = False
            try:
                rnd = await client.get(f"{base}/nexhunt-404-{hash(base) & 0xffff}.zzz", headers=headers)
                catch_all = rnd.status_code in (200, 201)
                yield {"_raw": True, "line": f"  Baseline random path -> {rnd.status_code}"
                       + (" (server answers 200 to everything — relying on content signatures)" if catch_all else "")}
            except Exception as e:
                yield {"_raw": True, "line": f"  Baseline error: {e}"}

            for path, label, severity, sig_fn, note in _CHECKS:
                full = f"{base}/{path}"
                try:
                    resp = await client.get(full, headers=headers)
                    code = resp.status_code
                    body = resp.text[:4096]
                    matched = sig_fn(body)
                    yield {"_raw": True, "line": f"  [{path}] -> {code} ({len(resp.content)}b) sig={matched}"}

                    # Only flag when content matches the signature. This survives catch-all
                    # 200 pages and avoids flagging soft-404 HTML.
                    if code in (200, 206) and matched:
                        yield {
                            "_raw": False, "id": None,
                            "title": f"[Exposed] {label} — {base}",
                            "severity": severity, "vuln_type": "information-disclosure",
                            "url": full, "parameter": path,
                            "evidence": (
                                f"Path: /{path}\nStatus: {code}\n"
                                f"Signature matched: yes\n"
                                f"First bytes:\n{body[:300]}"
                            ),
                            "description": f"{label}. {note}",
                            "tool": "exposed_files", "template_id": f"exposed-{path.replace('/', '-').replace('.', '')}",
                            "status": "new",
                        }
                except Exception as e:
                    yield {"_raw": True, "line": f"  [{path}] error: {e}"}
