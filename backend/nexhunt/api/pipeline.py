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


def _classify_params(params: dict) -> list[str]:
    """Order param names by injection likelihood: numeric first, then string, then rest."""
    def rank(name: str) -> int:
        val = params[name][0] if params[name] else ""
        if val.strip() and val.strip().lstrip("-").isdigit():
            return 0  # numeric — most likely injectable
        if val.strip():
            return 1  # has a string value
        return 2      # empty / blank

    return sorted(params.keys(), key=rank)


# Endpoint extraction patterns for JS bodies
_JS_ENDPOINT_PATTERNS = [
    re.compile(r"""XMLHttpRequest\(\)[\s\S]{0,80}?\.open\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]"""),
    re.compile(r"""\.open\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]"""),
    re.compile(r"""fetch\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""axios\.(?:get|post|put|delete|patch)\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""axios\(\s*\{[^}]*?url\s*:\s*['"]([^'"]+)['"]"""),
    re.compile(r"""\$\.ajax\(\s*\{[^}]*?url\s*:\s*['"]([^'"]+)['"]"""),
    re.compile(r"""\$\.(?:get|post)\(\s*['"]([^'"]+)['"]"""),
]


def _extract_js_endpoints(js_content: str, base_url: str) -> list[str]:
    """Pull endpoints referenced by AJAX/fetch/axios/jQuery calls in a JS file."""
    from urllib.parse import urljoin

    found: set[str] = set()
    for pat in _JS_ENDPOINT_PATTERNS:
        for ref in pat.findall(js_content):
            ref = ref.strip()
            if not ref or ref.startswith(("data:", "blob:", "javascript:", "mailto:", "#")):
                continue
            # Skip template literals we can't resolve (e.g. `/api/${id}`)
            if "${" in ref or "{{" in ref:
                continue
            if ref.startswith(("http://", "https://", "/")) or "?" in ref:
                found.add(urljoin(base_url, ref))
    return list(found)


async def _probe_sqli(url: str, cookie: str | None) -> list[dict]:
    """
    3-layer SQLi detection per parameter, params probed in priority order:
      1. Error-based: inject ' and match DB error signatures
      2. Boolean-based: AND 1=1 vs AND 1=2, flag when response sizes diverge
      3. Time-based: AND SLEEP(7), flag when it stalls but SLEEP(0) baseline is fast
    """
    import httpx
    import time

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []

    findings = []
    headers = {"User-Agent": "Mozilla/5.0 NexHunt SQLi-Probe"}
    if cookie:
        headers["Cookie"] = cookie

    def build(param_name: str, payload: str) -> str:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[param_name] = test_params[param_name] + payload
        return urlunparse(parsed._replace(query=urlencode(test_params)))

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=12) as client:
        # Baseline response for the unmodified URL (boolean comparison)
        try:
            base_resp = await client.get(url, headers=headers)
            base_len = len(base_resp.text)
        except Exception as e:
            logger.debug(f"SQLi baseline failed for {url}: {e}")
            base_len = None

        for param_name in _classify_params(params):
            found_for_param = False

            # ── Layer 1: error-based ──
            try:
                test_url = build(param_name, "'")
                resp = await client.get(test_url, headers=headers)
                m = _SQL_ERRORS.search(resp.text)
                if m:
                    snippet = resp.text[max(0, m.start() - 40):m.end() + 80].strip()
                    findings.append({
                        "url": test_url, "original_url": url, "parameter": param_name,
                        "payload": "'", "status_code": resp.status_code,
                        "evidence": snippet[:300], "type": "sqli_error", "method": "error-based",
                    })
                    found_for_param = True
            except Exception as e:
                logger.debug(f"SQLi error-probe failed for {param_name}: {e}")

            # ── Layer 2: boolean-based ──
            if not found_for_param and base_len is not None:
                try:
                    true_url = build(param_name, " AND 1=1-- -")
                    false_url = build(param_name, " AND 1=2-- -")
                    r_true = await client.get(true_url, headers=headers)
                    r_false = await client.get(false_url, headers=headers)
                    lt, lf = len(r_true.text), len(r_false.text)
                    # TRUE close to baseline, FALSE clearly different → boolean injection
                    if abs(lt - base_len) < 50 and abs(lt - lf) > max(60, base_len * 0.05):
                        findings.append({
                            "url": true_url, "original_url": url, "parameter": param_name,
                            "payload": "AND 1=1 / AND 1=2", "status_code": r_true.status_code,
                            "evidence": f"baseline={base_len}B  true(1=1)={lt}B  false(1=2)={lf}B",
                            "type": "sqli_boolean", "method": "boolean-based",
                        })
                        found_for_param = True
                except Exception as e:
                    logger.debug(f"SQLi boolean-probe failed for {param_name}: {e}")

            # ── Layer 3: time-based (expensive — only if nothing found yet) ──
            if not found_for_param:
                try:
                    sleep_url = build(param_name, "/**/AND/**/SLEEP(7)-- -")
                    t0 = time.monotonic()
                    r_sleep = await client.get(sleep_url, headers=headers)
                    elapsed = time.monotonic() - t0
                    if elapsed > 6:
                        # Confirm with SLEEP(0) — baseline must come back fast
                        base_url2 = build(param_name, "/**/AND/**/SLEEP(0)-- -")
                        t1 = time.monotonic()
                        await client.get(base_url2, headers=headers)
                        base_elapsed = time.monotonic() - t1
                        if base_elapsed < 3:
                            findings.append({
                                "url": sleep_url, "original_url": url, "parameter": param_name,
                                "payload": "AND SLEEP(7)", "status_code": r_sleep.status_code,
                                "evidence": f"SLEEP(7)={elapsed:.1f}s  SLEEP(0)={base_elapsed:.1f}s",
                                "type": "sqli_time", "method": "time-based",
                            })
                except httpx.TimeoutException:
                    logger.debug(f"SQLi time-probe timed out for {param_name} (possible injection)")
                except Exception as e:
                    logger.debug(f"SQLi time-probe failed for {param_name}: {e}")

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

    param_urls = {r["url"] for r in param_results}
    crawl_param_count = len(param_urls)

    await ws_manager.broadcast("pipeline", {
        "phase": "katana", "event": "completed",
        "pipeline": "sqli",
        "total_urls": len(all_results),
        "xss_candidates": crawl_param_count,
        "message": f"Found {len(all_results)} URLs — {crawl_param_count} with parameters",
    })

    cookie = opts.get("cookie", "") or None

    # Phase 1b: mine .js files for endpoints the crawler never linked to
    if opts.get("parse_js", True):
        js_urls = [r["url"] for r in all_results if r["url"].split("?")[0].endswith(".js")]
        if js_urls:
            await ws_manager.broadcast("pipeline", {
                "phase": "js_parse", "event": "started", "pipeline": "sqli",
                "targets": len(js_urls),
                "message": f"Parsing {len(js_urls)} JS files for hidden endpoints...",
            })
            js_endpoints: set[str] = set()
            workers = int(opts.get("workers", 5))
            for i in range(0, len(js_urls), workers):
                chunk = js_urls[i:i + workers]
                contents = await asyncio.gather(*[_fetch_js(u, cookie) for u in chunk])
                for u, content in zip(chunk, contents):
                    if not content:
                        continue
                    for ep in _extract_js_endpoints(content, u):
                        if "?" in ep and parse_qs(urlparse(ep).query) and ep not in param_urls:
                            js_endpoints.add(ep)
            param_urls |= js_endpoints
            await ws_manager.broadcast("pipeline", {
                "phase": "js_parse", "event": "completed", "pipeline": "sqli",
                "js_endpoints": len(js_endpoints),
                "message": f"JS parsing added {len(js_endpoints)} new parameterized endpoint(s)",
            })

    param_urls = list(param_urls)

    if not param_urls:
        return {"status": "completed", "total_urls": len(all_results), "candidates": 0, "findings": 0}

    # Phase 2: SQLi probe
    await ws_manager.broadcast("pipeline", {
        "phase": "sqli_probe", "event": "started",
        "pipeline": "sqli",
        "targets": len(param_urls),
        "message": f"Probing {len(param_urls)} URLs for SQL errors...",
    })

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
