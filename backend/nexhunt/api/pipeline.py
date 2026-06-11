"""
Automated Bug Bounty pipelines — chain tools together.

Pipelines:
  POST /api/pipeline/xss        — Katana crawl → filter params → Dalfox XSS scan
  POST /api/pipeline/sqli_probe — Katana crawl → inject ' → detect SQL errors
  POST /api/pipeline/js_scan    — Katana crawl → fetch .js files → grep secrets
"""
import re
import logging
import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from pydantic import BaseModel
from fastapi import APIRouter
from nexhunt.adapters.base import get_adapter
from nexhunt.ws.manager import ws_manager

router = APIRouter(prefix="/api/pipeline", tags=["pipeline"])
logger = logging.getLogger(__name__)


class PipelineRequest(BaseModel):
    target: str
    options: dict = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _base_domain(target: str) -> str:
    """Extract base hostname from a URL or plain domain."""
    if not target.startswith("http"):
        target = f"https://{target}"
    return urlparse(target).netloc or target


async def _katana_crawl(
    target: str,
    opts: dict,
    *,
    scope: str | None = None,
) -> tuple[list[dict], list[dict]]:
    """
    Run Katana and return (all_results, param_results).
    Filters out URLs outside the base domain.
    """
    katana = get_adapter("katana")
    if not katana or not await katana.check_installed():
        raise RuntimeError("katana is not installed")

    base = scope or _base_domain(target)
    katana_opts = {
        "depth": int(opts.get("depth", 3)),
        "js_crawl": opts.get("js_crawl", True),
        "crawl_forms": opts.get("crawl_forms", True),
        "cookie": opts.get("cookie", "") or opts.get("session_cookies", ""),
        "session_headers": opts.get("session_headers", ""),
        "headless": opts.get("headless", False),
        "concurrency": int(opts.get("concurrency", 10)),
        "rate_limit": int(opts.get("rate_limit", 150)),
        "scope": base,  # restrict crawl to target domain
    }

    all_results: list[dict] = []
    param_results: list[dict] = []

    async for result in katana.run(target, katana_opts):
        url = result.get("url", "")
        if not url:
            continue
        # Drop off-scope URLs
        parsed = urlparse(url)
        if base and base not in parsed.netloc:
            continue
        all_results.append(result)
        if result.get("has_params") or result.get("is_form"):
            param_results.append(result)

    return all_results, param_results


# ── Pipeline 1: XSS ───────────────────────────────────────────────────────────

@router.post("/xss")
async def run_xss_pipeline(req: PipelineRequest):
    """
    XSS pipeline: Katana crawl → filter parameterized URLs → Dalfox bulk scan.
    Streams progress via WebSocket channel 'pipeline'.
    """
    target = req.target.strip()
    opts = req.options

    dalfox = get_adapter("dalfox")
    dalfox_ok = dalfox and await dalfox.check_installed()
    if not dalfox_ok:
        return {"error": "dalfox is not installed"}

    # Phase 1: Katana
    await ws_manager.broadcast("pipeline", {
        "phase": "katana", "event": "started",
        "pipeline": "xss",
        "message": f"Crawling {target} with Katana...",
    })

    try:
        all_results, param_results = await _katana_crawl_streaming(
            target, opts, pipeline="xss"
        )
    except RuntimeError as e:
        return {"error": str(e)}

    param_urls = [r["url"] for r in param_results]

    await ws_manager.broadcast("pipeline", {
        "phase": "katana", "event": "completed",
        "pipeline": "xss",
        "total_urls": len(all_results),
        "xss_candidates": len(param_urls),
        "message": f"Found {len(all_results)} URLs — {len(param_urls)} XSS candidates",
    })

    if not param_urls:
        return {"status": "completed", "total_urls": len(all_results), "xss_candidates": 0, "findings": 0}

    # Phase 2: Dalfox
    await ws_manager.broadcast("pipeline", {
        "phase": "dalfox", "event": "started",
        "pipeline": "xss",
        "targets": len(param_urls),
        "message": f"Scanning {len(param_urls)} endpoints with Dalfox...",
    })

    dalfox_opts = {
        "targets": param_urls,
        "blind": opts.get("blind", ""),
        "cookie": opts.get("cookie", ""),
        "header": opts.get("header", ""),
        "workers": opts.get("workers", 10),
    }

    findings = []
    async for finding in dalfox.run(target, dalfox_opts):
        findings.append(finding)
        await ws_manager.broadcast("findings", finding)
        await ws_manager.broadcast("pipeline", {
            "phase": "dalfox", "event": "finding",
            "pipeline": "xss",
            "finding": finding,
            "total_findings": len(findings),
        })

    await ws_manager.broadcast("pipeline", {
        "phase": "dalfox", "event": "completed",
        "pipeline": "xss",
        "findings": len(findings),
        "message": f"Dalfox done — {len(findings)} XSS finding(s)",
    })

    return {
        "status": "completed",
        "total_urls": len(all_results),
        "xss_candidates": len(param_urls),
        "findings": len(findings),
    }


async def _katana_crawl_streaming(target: str, opts: dict, *, pipeline: str):
    """Katana crawl with streaming WebSocket updates."""
    katana = get_adapter("katana")
    if not katana or not await katana.check_installed():
        raise RuntimeError("katana is not installed")

    base = _base_domain(target)
    restrict_scope = opts.get("restrict_scope", True)  # default: stay in scope

    katana_opts = {
        "depth": int(opts.get("depth", 3)),
        "js_crawl": opts.get("js_crawl", True),
        "crawl_forms": opts.get("crawl_forms", True),
        "cookie": opts.get("cookie", "") or opts.get("session_cookies", ""),
        "session_headers": opts.get("session_headers", ""),
        "headless": opts.get("headless", False),
        "concurrency": int(opts.get("concurrency", 10)),
        "rate_limit": int(opts.get("rate_limit", 150)),
        # Only pass scope restriction to katana when enabled
        "scope": base if restrict_scope else "",
    }

    all_results: list[dict] = []
    param_results: list[dict] = []

    async for result in katana.run(target, katana_opts):
        url = result.get("url", "")
        if not url:
            continue
        # Post-filter: drop off-scope URLs when restrict_scope is on
        if restrict_scope:
            parsed = urlparse(url)
            if base and base not in parsed.netloc:
                continue
        all_results.append(result)
        has_p = result.get("has_params") or result.get("is_form")
        if has_p:
            param_results.append(result)

        await ws_manager.broadcast("pipeline", {
            "phase": "katana", "event": "url_found",
            "pipeline": pipeline,
            "url": url,
            "has_params": result.get("has_params", False),
            "is_form": result.get("is_form", False),
            "total": len(all_results),
            "xss_candidates": len(param_results),
        })

    return all_results, param_results


# ── Pipeline 2: SQLi Probe ────────────────────────────────────────────────────

# SQL error signatures (case-insensitive)
_SQL_ERRORS = re.compile(
    r"you have an error in your sql syntax"
    r"|warning: mysql_"
    r"|mysql_fetch_array\(\)"
    r"|mysql_num_rows\(\)"
    r"|unclosed quotation mark after the character string"
    r"|microsoft ole db provider for sql server"
    r"|odbc sql server driver"
    r"|sqlserverjdbc"
    r"|ora-\d{4,5}"
    r"|quoted string not properly terminated"
    r"|pg_query\(\)"
    r"|unterminated quoted string at or near"
    r"|syntax error at or near"
    r"|sqlite3::query\(\)"
    r"|near \".+\": syntax error"
    r"|sql syntax.*mysql"
    r"|warning.*sqlite_"
    r"|warning.*pg_"
    r"|sql error"
    r"|sql_error",
    re.IGNORECASE,
)


async def _probe_sqli(url: str, cookie: str | None) -> list[dict]:
    """Inject ' into each parameter and look for SQL errors."""
    import httpx

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []

    findings = []
    headers = {"User-Agent": "Mozilla/5.0 NexHunt SQLi-Probe"}
    if cookie:
        headers["Cookie"] = cookie

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
        for param_name in params:
            # Build URL with ' injected into this param only
            test_params = {k: v[0] for k, v in params.items()}
            original_val = test_params[param_name]
            test_params[param_name] = original_val + "'"
            new_query = urlencode(test_params)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = await client.get(test_url, headers=headers)
                body = resp.text
                if _SQL_ERRORS.search(body):
                    # Extract the matched error snippet
                    match = _SQL_ERRORS.search(body)
                    snippet = body[max(0, match.start()-40):match.end()+80].strip()
                    findings.append({
                        "url": test_url,
                        "original_url": url,
                        "parameter": param_name,
                        "payload": "'",
                        "status_code": resp.status_code,
                        "evidence": snippet[:300],
                        "type": "sqli_error",
                    })
            except Exception as e:
                logger.debug(f"SQLi probe error for {test_url}: {e}")

    return findings


@router.post("/sqli_probe")
async def run_sqli_probe_pipeline(req: PipelineRequest):
    """
    SQLi probe pipeline:
    1. Katana crawl → collect parameterized URLs
    2. For each URL + param, inject ' and check response for SQL error signatures
    3. Stream results via WebSocket channel 'pipeline' (phase='sqli_probe')
    """
    target = req.target.strip()
    opts = req.options

    await ws_manager.broadcast("pipeline", {
        "phase": "katana", "event": "started",
        "pipeline": "sqli",
        "message": f"Crawling {target} for injectable parameters...",
    })

    try:
        all_results, param_results = await _katana_crawl_streaming(target, opts, pipeline="sqli")
    except RuntimeError as e:
        return {"error": str(e)}

    param_urls = list({r["url"] for r in param_results})

    await ws_manager.broadcast("pipeline", {
        "phase": "katana", "event": "completed",
        "pipeline": "sqli",
        "total_urls": len(all_results),
        "xss_candidates": len(param_urls),
        "message": f"Found {len(all_results)} URLs — {len(param_urls)} with parameters",
    })

    if not param_urls:
        return {"status": "completed", "total_urls": len(all_results), "candidates": 0, "findings": 0}

    # Phase 2: SQLi probe
    await ws_manager.broadcast("pipeline", {
        "phase": "sqli_probe", "event": "started",
        "pipeline": "sqli",
        "targets": len(param_urls),
        "message": f"Probing {len(param_urls)} URLs for SQL errors...",
    })

    cookie = opts.get("cookie", "") or None
    all_findings = []
    workers = int(opts.get("workers", 5))

    # Process in chunks to limit concurrency
    for i in range(0, len(param_urls), workers):
        chunk = param_urls[i:i + workers]
        results = await asyncio.gather(*[_probe_sqli(url, cookie) for url in chunk])
        for findings in results:
            for finding in findings:
                all_findings.append(finding)
                await ws_manager.broadcast("pipeline", {
                    "phase": "sqli_probe", "event": "finding",
                    "pipeline": "sqli",
                    "finding": finding,
                    "total_findings": len(all_findings),
                })
                logger.info(f"[SQLi probe] Potential finding: {finding['url']} param={finding['parameter']}")

    await ws_manager.broadcast("pipeline", {
        "phase": "sqli_probe", "event": "completed",
        "pipeline": "sqli",
        "findings": len(all_findings),
        "message": f"SQLi probe done — {len(all_findings)} potential finding(s)",
    })

    return {
        "status": "completed",
        "total_urls": len(all_results),
        "candidates": len(param_urls),
        "findings": len(all_findings),
        "results": all_findings,
    }


# ── Pipeline 3: JS Scanner ────────────────────────────────────────────────────

# Patterns to search in JS files: (regex, label, severity)
_JS_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r'(?i)(api[_\-]?key|apikey|api_secret)\s*[:=]\s*["\']([a-zA-Z0-9\-_]{16,})["\']'), "api_key", "high"),
    (re.compile(r'(?i)(access[_\-]?token|auth[_\-]?token|bearer[_\-]?token)\s*[:=]\s*["\']([a-zA-Z0-9\-_.]{20,})["\']'), "token", "high"),
    (re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,64})["\']'), "password", "critical"),
    (re.compile(r'(?i)(secret[_\-]?key|client[_\-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9\-_]{8,})["\']'), "secret", "high"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "aws_access_key", "critical"),
    (re.compile(r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']'), "aws_secret", "critical"),
    (re.compile(r'eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}'), "jwt_token", "medium"),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "google_api_key", "high"),
    (re.compile(r'hooks\.slack\.com/services/[a-zA-Z0-9/]{40,}'), "slack_webhook", "high"),
    (re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'), "private_key", "critical"),
    (re.compile(r'(?i)["\']/(api|v\d+|internal|admin|graphql|rest|backend|swagger|debug)[/a-zA-Z0-9\-_?=&]{2,50}["\']'), "internal_endpoint", "info"),
    (re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'), "email", "info"),
    (re.compile(r's3\.amazonaws\.com/([a-zA-Z0-9\-_\.]+)'), "s3_bucket", "medium"),
]


async def _fetch_js(url: str, cookie: str | None) -> str | None:
    """Fetch a JS file and return its content."""
    import httpx
    headers = {"User-Agent": "Mozilla/5.0 NexHunt JS-Scanner"}
    if cookie:
        headers["Cookie"] = cookie
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.text
    except Exception as e:
        logger.debug(f"Failed to fetch {url}: {e}")
    return None


def _grep_js(url: str, content: str) -> list[dict]:
    """Run all secret patterns against JS content."""
    findings = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, 1):
        for pattern, label, severity in _JS_PATTERNS:
            match = pattern.search(line)
            if match:
                findings.append({
                    "js_url": url,
                    "line": lineno,
                    "label": label,
                    "severity": severity,
                    "match": match.group(0)[:200],
                    "context": line.strip()[:300],
                })
    return findings


@router.post("/js_scan")
async def run_js_scan_pipeline(req: PipelineRequest):
    """
    JS scan pipeline:
    1. Katana crawl → collect all URLs, filter .js files
    2. Fetch each JS file
    3. Grep for secrets, API keys, internal endpoints, etc.
    4. Stream findings via WebSocket channel 'pipeline' (phase='js_scan')
    """
    target = req.target.strip()
    opts = req.options

    await ws_manager.broadcast("pipeline", {
        "phase": "katana", "event": "started",
        "pipeline": "js_scan",
        "message": f"Crawling {target} to discover JS files...",
    })

    try:
        all_results, _ = await _katana_crawl_streaming(target, opts, pipeline="js_scan")
    except RuntimeError as e:
        return {"error": str(e)}

    # Filter JS files
    js_urls = list({
        r["url"] for r in all_results
        if r["url"].split("?")[0].endswith(".js")
    })

    await ws_manager.broadcast("pipeline", {
        "phase": "katana", "event": "completed",
        "pipeline": "js_scan",
        "total_urls": len(all_results),
        "xss_candidates": len(js_urls),
        "message": f"Found {len(all_results)} URLs — {len(js_urls)} JS files to scan",
    })

    if not js_urls:
        return {"status": "completed", "total_urls": len(all_results), "js_files": 0, "findings": 0}

    # Phase 2: Fetch + grep
    await ws_manager.broadcast("pipeline", {
        "phase": "js_scan", "event": "started",
        "pipeline": "js_scan",
        "targets": len(js_urls),
        "message": f"Fetching and analyzing {len(js_urls)} JS files...",
    })

    cookie = opts.get("cookie", "") or None
    all_findings = []
    workers = int(opts.get("workers", 5))

    for i in range(0, len(js_urls), workers):
        chunk = js_urls[i:i + workers]
        contents = await asyncio.gather(*[_fetch_js(url, cookie) for url in chunk])

        for url, content in zip(chunk, contents):
            await ws_manager.broadcast("pipeline", {
                "phase": "js_scan", "event": "js_file",
                "pipeline": "js_scan",
                "url": url,
                "fetched": content is not None,
            })

            if content:
                findings = _grep_js(url, content)
                for f in findings:
                    all_findings.append(f)
                    await ws_manager.broadcast("pipeline", {
                        "phase": "js_scan", "event": "finding",
                        "pipeline": "js_scan",
                        "finding": f,
                        "total_findings": len(all_findings),
                    })

    await ws_manager.broadcast("pipeline", {
        "phase": "js_scan", "event": "completed",
        "pipeline": "js_scan",
        "findings": len(all_findings),
        "js_files": len(js_urls),
        "message": f"JS scan done — {len(all_findings)} finding(s) in {len(js_urls)} files",
    })

    return {
        "status": "completed",
        "total_urls": len(all_results),
        "js_files": len(js_urls),
        "findings": len(all_findings),
        "results": all_findings,
    }
