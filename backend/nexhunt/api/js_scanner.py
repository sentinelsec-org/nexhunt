"""
JS Secret Scanner — downloads JavaScript files found during recon and
scans them for hardcoded secrets, API keys, internal endpoints, and more.

This is one of the highest-ROI techniques in bug bounty:
JS files often contain tokens, internal API paths, cloud credentials, etc.
"""
import re
import logging
import asyncio
import urllib.parse
from fastapi import APIRouter
from pydantic import BaseModel
from nexhunt.ws.manager import ws_manager

router = APIRouter(prefix="/api/js-scanner", tags=["js-scanner"])
logger = logging.getLogger(__name__)

# ── Secret patterns ─────────────────────────────────────────────────────────

SECRET_PATTERNS = [
    # AWS
    {"name": "AWS Access Key", "severity": "critical",
     "pattern": r"(?:AKIA|AGPA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}"},
    {"name": "AWS Secret Key", "severity": "critical",
     "pattern": r"(?:aws[_\-\s]?secret|aws[_\-\s]?key)[^\n]{0,30}['\"][0-9A-Za-z/+=]{40}['\"]"},
    # Google
    {"name": "Google API Key", "severity": "high",
     "pattern": r"AIza[0-9A-Za-z\\-_]{35}"},
    {"name": "Google OAuth", "severity": "high",
     "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"},
    # Generic tokens/keys
    {"name": "Bearer Token", "severity": "high",
     "pattern": r"[Bb]earer\s+[A-Za-z0-9\-._~+/]{20,}"},
    {"name": "API Key (generic)", "severity": "medium",
     "pattern": r"(?:api[_\-]?key|apikey|api[_\-]?secret|client[_\-]?secret)['\"\s:=]+[A-Za-z0-9\-_]{16,64}"},
    {"name": "Authorization Header", "severity": "medium",
     "pattern": r"[Aa]uthorization['\"\s:]+['\"][A-Za-z0-9\-._~+/=]{20,}['\"]"},
    # Private keys
    {"name": "RSA Private Key", "severity": "critical",
     "pattern": r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"},
    # JWT
    {"name": "JWT Token", "severity": "high",
     "pattern": r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"},
    # Stripe
    {"name": "Stripe Key", "severity": "critical",
     "pattern": r"(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{24,}"},
    # GitHub
    {"name": "GitHub Token", "severity": "critical",
     "pattern": r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"},
    # Slack
    {"name": "Slack Token", "severity": "high",
     "pattern": r"xox[baprs]-[A-Za-z0-9\-]{10,48}"},
    # Firebase
    {"name": "Firebase URL", "severity": "medium",
     "pattern": r"https://[a-z0-9\-]+\.firebaseio\.com"},
    {"name": "Firebase API Key", "severity": "high",
     "pattern": r"firebase['\"\s:=]+['\"][A-Za-z0-9\-_]{30,}['\"]"},
    # S3
    {"name": "S3 Bucket URL", "severity": "medium",
     "pattern": r"https?://[a-z0-9\-]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com"},
    # Internal endpoints
    {"name": "Internal API Endpoint", "severity": "low",
     "pattern": r"(?:fetch|axios|http\.get|http\.post|ajax)\s*\(['\"](?:/api/[^\s'\"]+)['\"]"},
    {"name": "GraphQL Endpoint", "severity": "low",
     "pattern": r"(?:graphql|gql)['\"\s]*:['\"\s]*['\"](?:https?://[^\s'\"]+|/[^\s'\"]+)['\"]"},
    # Passwords
    {"name": "Hardcoded Password", "severity": "high",
     "pattern": r"(?:password|passwd|pwd)['\"\s]*[=:]['\"\s]*['\"][^'\"]{6,}['\"]"},
    # Twilio
    {"name": "Twilio Account SID", "severity": "high",
     "pattern": r"AC[a-z0-9]{32}"},
    # Mailgun
    {"name": "Mailgun API Key", "severity": "high",
     "pattern": r"key-[0-9a-zA-Z]{32}"},
    # SendGrid
    {"name": "SendGrid API Key", "severity": "high",
     "pattern": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"},
]

# Compile all patterns
_COMPILED = [
    {**p, "re": re.compile(p["pattern"], re.IGNORECASE | re.MULTILINE)}
    for p in SECRET_PATTERNS
]


async def _scan_js_content(url: str, content: str) -> list[dict]:
    """Scan JS file content for secrets. Returns list of findings."""
    findings = []
    seen = set()

    for pat in _COMPILED:
        for match in pat["re"].finditer(content):
            value = match.group(0)[:120]  # Truncate long matches
            key = (pat["name"], value[:30])
            if key in seen:
                continue
            seen.add(key)

            # Get line number and context
            line_start = content.rfind("\n", 0, match.start()) + 1
            line_end = content.find("\n", match.end())
            context_line = content[line_start:line_end if line_end != -1 else line_start + 200].strip()

            findings.append({
                "secret_type": pat["name"],
                "severity": pat["severity"],
                "url": url,
                "value": value,
                "context": context_line[:200],
            })

    return findings


async def _save_finding(title: str, severity: str, url: str, description: str, evidence: str, project_id: str | None = None):
    try:
        import uuid, datetime
        from nexhunt.database import DefaultSession
        from nexhunt.models.finding import Finding
        async with DefaultSession() as session:
            f = Finding(
                id=str(uuid.uuid4()),
                project_id=project_id or None,
                title=title,
                severity=severity,
                url=url,
                tool="js-scanner",
                description=description,
                evidence=evidence[:2000],
                status="open",
                created_at=datetime.datetime.utcnow(),
            )
            session.add(f)
            await session.commit()
            d = {
                "id": f.id, "title": f.title, "severity": f.severity,
                "url": f.url, "tool": f.tool, "description": f.description,
                "evidence": f.evidence, "status": f.status,
            }
        await ws_manager.broadcast("findings", d)
        return d
    except Exception as e:
        logger.error(f"Failed to save JS scanner finding: {e}")
        return None


class JsScanRequest(BaseModel):
    urls: list[str]  # URLs to scan — backend filters for JS
    cookie: str = ""
    max_size_kb: int = 2000  # Skip files larger than this
    project_id: str = ""


@router.post("/scan")
async def scan_js_files(req: JsScanRequest):
    """Scan JavaScript files for secrets and sensitive data."""
    import httpx

    if not req.urls:
        return {"message": "No URLs provided", "scanned": 0, "findings": []}

    # Filter to JS-looking URLs — generous matching to catch bundles, chunks, etc.
    js_urls = [u for u in req.urls if (
        u.endswith(".js") or ".js?" in u or ".js#" in u or
        "/js/" in u or "/javascript/" in u or
        ".chunk." in u or ".bundle." in u or "webpack" in u.lower()
    )]
    if not js_urls:
        # Fallback: scan all provided URLs (some JS served without recognizable extension)
        js_urls = req.urls[:100]

    all_findings = []
    scanned = 0
    errors = 0

    headers = {"User-Agent": "Mozilla/5.0 (compatible; NexHunt/1.0)"}
    if req.cookie:
        headers["Cookie"] = req.cookie

    sem = asyncio.Semaphore(8)

    async def process_url(url: str):
        nonlocal scanned, errors
        async with sem:
            try:
                async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as client:
                    resp = await client.get(url, headers=headers)
                    if resp.status_code != 200:
                        return []
                    content_len = len(resp.content)
                    if content_len > req.max_size_kb * 1024:
                        return []
                    text = resp.text
                    scanned += 1

                    await ws_manager.broadcast("tool_output", {
                        "tool": "js-scanner",
                        "line": f"[{scanned}/{len(js_urls)}] Scanning {url} ({content_len // 1024}KB)",
                    })

                    file_findings = await _scan_js_content(url, text)
                    return file_findings
            except Exception as e:
                errors += 1
                logger.debug(f"JS scan error {url}: {e}")
                return []

    await ws_manager.broadcast("tool_status", {"tool": "js-scanner", "event": "started", "total": len(js_urls)})

    results = await asyncio.gather(*[process_url(u) for u in js_urls])

    # Flatten, deduplicate by (type, value[:30], url)
    seen_global = set()
    for file_findings in results:
        for f in file_findings:
            key = (f["secret_type"], f["value"][:30], f["url"])
            if key not in seen_global:
                seen_global.add(key)
                all_findings.append(f)
                # Save to DB and broadcast
                await _save_finding(
                    title=f"{f['secret_type']} found in JS — {urllib.parse.urlparse(f['url']).netloc}",
                    severity=f["severity"],
                    url=f["url"],
                    description=f"Potential {f['secret_type']} detected in JavaScript file.\n\nContext:\n{f['context']}",
                    evidence=f"Value: {f['value']}\nContext: {f['context']}",
                    project_id=req.project_id or None,
                )

    await ws_manager.broadcast("tool_status", {
        "tool": "js-scanner", "event": "completed",
        "scanned": scanned, "findings_count": len(all_findings),
    })

    return {
        "scanned": scanned,
        "errors": errors,
        "findings_count": len(all_findings),
        "findings": all_findings,
        "message": f"Scanned {scanned} JS files — found {len(all_findings)} potential secrets",
    }
