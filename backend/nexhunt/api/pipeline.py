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

    # Phase 1b: mine endpoints from JS files and inline <script> tags
    if opts.get("parse_js", True):
        cookie_xss = opts.get("cookie", "") or None
        js_files_xss = [r["url"] for r in all_results if r["url"].split("?")[0].endswith(".js")]
        _SKIP_XSS = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                     ".webp", ".ico", ".woff", ".woff2", ".ttf", ".pdf", ".zip", ".mp4")
        html_pages_xss = list({r["url"] for r in all_results
                                if not r["url"].split("?")[0].lower().endswith(_SKIP_XSS)})[:120]
        if js_files_xss or html_pages_xss:
            await ws_manager.broadcast("pipeline", {
                "phase": "js_parse", "event": "started", "pipeline": "xss",
                "message": f"Mining {len(js_files_xss)} JS + {len(html_pages_xss)} pages for hidden XSS candidates...",
            })
            existing_xss = {r["url"] for r in param_results}
            extra_xss: set[str] = set()
            workers_xss = int(opts.get("workers", 5))

            def _collect_xss(content: str, src: str):
                for ep in _extract_js_endpoints(content, src):
                    if "?" in ep and parse_qs(urlparse(ep).query) and ep not in existing_xss:
                        extra_xss.add(ep)

            for i in range(0, len(js_files_xss), workers_xss):
                chunk = js_files_xss[i:i + workers_xss]
                contents = await asyncio.gather(*[_fetch_js(u, cookie_xss) for u in chunk])
                for u, c in zip(chunk, contents):
                    if c:
                        _collect_xss(c, u)

            for i in range(0, len(html_pages_xss), workers_xss):
                chunk = html_pages_xss[i:i + workers_xss]
                contents = await asyncio.gather(*[_fetch_js(u, cookie_xss) for u in chunk])
                for u, c in zip(chunk, contents):
                    if c:
                        inline = _extract_inline_scripts(c)
                        if inline:
                            _collect_xss(inline, u)

            param_urls = param_urls + list(extra_xss)
            await ws_manager.broadcast("pipeline", {
                "phase": "js_parse", "event": "completed", "pipeline": "xss",
                "js_endpoints": len(extra_xss),
                "message": f"JS mining added {len(extra_xss)} more XSS candidate(s)",
            })

    # Dedup by path + sorted param names — avoids scanning ?id=1 and ?id=2 as separate targets
    def _ep_sig(u: str) -> str:
        p = urlparse(u)
        return f"{p.scheme}://{p.netloc}{p.path}?{'&'.join(sorted(parse_qs(p.query).keys()))}"

    seen_sigs: set[str] = set()
    deduped_xss: list[str] = []
    for u in param_urls:
        sig = _ep_sig(u)
        if sig not in seen_sigs:
            seen_sigs.add(sig)
            deduped_xss.append(u)
    param_urls = deduped_xss

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


# Endpoint extraction patterns for JS bodies. Each captures the full URL
# *argument expression* (which may be a "str"+var+"str" concatenation), so we
# can recover params whose values are JS variables.
# The arg group stops at a top-level ',' or ')', tolerating one nested call like
# encodeURIComponent(x).
_ARG = r"""((?:['"][^'"]*['"]|[^,)('"]|\([^)]*\))+)"""
_JS_ENDPOINT_PATTERNS = [
    re.compile(r"""\.open\(\s*['"][A-Z]+['"]\s*,\s*""" + _ARG),
    re.compile(r"""fetch\(\s*""" + _ARG),
    re.compile(r"""axios\.(?:get|post|put|delete|patch)\(\s*""" + _ARG),
    re.compile(r"""axios\(\s*\{[^}]*?url\s*:\s*""" + _ARG),
    re.compile(r"""\$\.ajax\(\s*\{[^}]*?url\s*:\s*""" + _ARG),
    re.compile(r"""\$\.(?:get|post)\(\s*""" + _ARG),
]

_JS_STR_LITERAL = re.compile(r"""(['"])((?:\\.|(?!\1).)*)\1""")


def _resolve_js_concat(expr: str) -> str | None:
    """
    Turn a JS URL expression into a concrete URL, filling any concatenated
    variable with '1' so dynamic params become testable.
      'getCupoNuevo.php?q="+str+"&prod="+prod'  ->  getCupoNuevo.php?q=1&prod=1
    Returns None if there is no string literal to anchor on.
    """
    matches = list(_JS_STR_LITERAL.finditer(expr))
    if not matches:
        return None

    result = ""
    last_end = 0
    for i, m in enumerate(matches):
        gap = expr[last_end:m.start()]
        # A '+' between two string literals means a variable was inserted here.
        if i > 0 and "+" in gap:
            result += "1"
        result += m.group(2)
        last_end = m.end()

    # Trailing "...="+var  -> dynamic value at the end
    trailing = expr[last_end:]
    if re.search(r"\+\s*\S", trailing):
        result += "1"

    return result


_SCRIPT_TAG = re.compile(r"<script\b[^>]*>([\s\S]*?)</script>", re.IGNORECASE)


def _extract_inline_scripts(html: str) -> str:
    """Concatenate the bodies of all inline <script> tags in an HTML page."""
    bodies = [m.group(1) for m in _SCRIPT_TAG.finditer(html) if m.group(1).strip()]
    return "\n".join(bodies)


def _extract_js_endpoints(js_content: str, base_url: str) -> list[str]:
    """Pull endpoints from AJAX/fetch/axios/jQuery calls in JS (file or inline)."""
    from urllib.parse import urljoin

    found: set[str] = set()
    for pat in _JS_ENDPOINT_PATTERNS:
        for expr in pat.findall(js_content):
            ref = _resolve_js_concat(expr.strip())
            if not ref:
                continue
            ref = ref.strip()
            if ref.startswith(("data:", "blob:", "javascript:", "mailto:", "tel:", "#")):
                continue
            if "${" in ref or "{{" in ref:  # unresolved template literal
                continue
            if ref.startswith(("http://", "https://", "/")) or "?" in ref:
                found.add(urljoin(base_url, ref))
    return list(found)


# DB-specific time payloads: (db_name, sleep_payload, zero_payload)
_TIME_PAYLOADS = [
    ("MySQL",      "/**/AND/**/SLEEP(7)-- -",                              "/**/AND/**/SLEEP(0)-- -"),
    ("PostgreSQL", "/**/AND/**/(SELECT(1)FROM/**/pg_sleep(7))-- -",        "/**/AND/**/(SELECT(1)FROM/**/pg_sleep(0))-- -"),
    ("MSSQL",      ";WAITFOR DELAY '0:0:7'-- -",                           ";WAITFOR DELAY '0:0:0'-- -"),
]


async def _probe_sqli(url: str, cookie: str | None) -> list[dict]:
    """
    3-layer SQLi detection per parameter, params probed in priority order:
      1. Error-based: inject ' and match DB error signatures
      2. Boolean-based: AND 1=1 vs AND 1=2, flag when responses diverge
      3. Time-based: multi-DB sleep payloads vs measured URL baseline time
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
        # Baseline: content length + response time for this specific URL
        try:
            t_base = time.monotonic()
            base_resp = await client.get(url, headers=headers)
            url_base_time = time.monotonic() - t_base
            base_len = len(base_resp.text)
        except Exception as e:
            logger.debug(f"SQLi baseline failed for {url}: {e}")
            base_len = None
            url_base_time = 0.5

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
                    # TRUE within 3% of baseline; FALSE diverges from TRUE by 5%+
                    if abs(lt - base_len) < max(50, base_len * 0.03) and abs(lt - lf) > max(60, max(lt, lf) * 0.05):
                        findings.append({
                            "url": true_url, "original_url": url, "parameter": param_name,
                            "payload": "AND 1=1 / AND 1=2", "status_code": r_true.status_code,
                            "evidence": f"baseline={base_len}B  true={lt}B  false={lf}B  delta={abs(lt - lf)}B",
                            "type": "sqli_boolean", "method": "boolean-based",
                        })
                        found_for_param = True
                except Exception as e:
                    logger.debug(f"SQLi boolean-probe failed for {param_name}: {e}")

            # ── Layer 3: time-based — MySQL / PostgreSQL / MSSQL ──
            if not found_for_param:
                # Require at least 5s more than the baseline response time to avoid false positives on slow servers
                min_delta = max(6.0, url_base_time + 5.0)
                for db_name, sleep_pay, zero_pay in _TIME_PAYLOADS:
                    if found_for_param:
                        break
                    try:
                        t0 = time.monotonic()
                        r_sleep = await client.get(build(param_name, sleep_pay), headers=headers)
                        elapsed = time.monotonic() - t0
                        if elapsed > min_delta:
                            t1 = time.monotonic()
                            await client.get(build(param_name, zero_pay), headers=headers)
                            zero_t = time.monotonic() - t1
                            if zero_t < url_base_time + 2:
                                findings.append({
                                    "url": build(param_name, sleep_pay), "original_url": url,
                                    "parameter": param_name,
                                    "payload": sleep_pay.strip(), "status_code": r_sleep.status_code,
                                    "evidence": f"sleep={elapsed:.1f}s  zero={zero_t:.1f}s  baseline={url_base_time:.1f}s  db={db_name}",
                                    "type": "sqli_time", "method": "time-based", "db_hint": db_name,
                                })
                                found_for_param = True
                    except httpx.TimeoutException:
                        logger.debug(f"SQLi time-probe timed out for {param_name} ({db_name})")
                    except Exception as e:
                        logger.debug(f"SQLi time-probe failed for {param_name} ({db_name}): {e}")

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

    # Phase 1b: mine endpoints from external .js files AND inline <script> tags
    if opts.get("parse_js", True):
        js_urls = [r["url"] for r in all_results if r["url"].split("?")[0].endswith(".js")]
        # HTML pages to scrape for inline <script> (skip static assets)
        _SKIP_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                     ".webp", ".ico", ".woff", ".woff2", ".ttf", ".pdf", ".zip", ".mp4")
        html_urls = list({
            r["url"] for r in all_results
            if not r["url"].split("?")[0].lower().endswith(_SKIP_EXT)
        })[:120]

        if js_urls or html_urls:
            await ws_manager.broadcast("pipeline", {
                "phase": "js_parse", "event": "started", "pipeline": "sqli",
                "targets": len(js_urls) + len(html_urls),
                "message": f"Parsing {len(js_urls)} JS files + {len(html_urls)} pages (inline <script>) for hidden endpoints...",
            })
            js_endpoints: set[str] = set()
            workers = int(opts.get("workers", 5))

            def _collect(content: str, source_url: str):
                for ep in _extract_js_endpoints(content, source_url):
                    if "?" in ep and parse_qs(urlparse(ep).query) and ep not in param_urls:
                        js_endpoints.add(ep)

            # External .js: parse the whole file body
            for i in range(0, len(js_urls), workers):
                chunk = js_urls[i:i + workers]
                contents = await asyncio.gather(*[_fetch_js(u, cookie) for u in chunk])
                for u, content in zip(chunk, contents):
                    if content:
                        _collect(content, u)

            # HTML pages: parse only the inline <script> bodies
            for i in range(0, len(html_urls), workers):
                chunk = html_urls[i:i + workers]
                contents = await asyncio.gather(*[_fetch_js(u, cookie) for u in chunk])
                for u, content in zip(chunk, contents):
                    if not content:
                        continue
                    inline = _extract_inline_scripts(content)
                    if inline:
                        _collect(inline, u)

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
    (re.compile(r'(?i)["\']/?graphql[/?\"\']'), "graphql_endpoint", "info"),
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
    """Scan whole content at once (handles minified single-line bundles), with entropy filter."""
    import bisect, math

    # Build line-start index for O(log n) byte-position -> line number
    line_starts = [0]
    for lm in re.finditer(r'\n', content):
        line_starts.append(lm.end())

    _SECRET_LABELS = {"api_key", "token", "secret", "password"}
    findings = []
    seen: set[tuple] = set()

    for pattern, label, severity in _JS_PATTERNS:
        for m in pattern.finditer(content):
            val = m.group(0)
            # Skip low-entropy matches for secret-type labels (filters placeholders like "your_api_key")
            if label in _SECRET_LABELS and severity in ("high", "critical") and len(val) >= 8:
                n = len(val)
                ent = -sum((val.count(c) / n) * math.log2(val.count(c) / n) for c in set(val))
                if ent < 3.5:
                    continue
            key = (label, val[:80])
            if key in seen:
                continue
            seen.add(key)
            lineno = bisect.bisect_right(line_starts, m.start())
            start, end = max(0, m.start() - 60), min(len(content), m.end() + 60)
            findings.append({
                "js_url": url,
                "line": lineno,
                "label": label,
                "severity": severity,
                "match": val[:200],
                "context": content[start:end].replace('\n', ' ').strip()[:300],
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

    # Phase 2b: inline <script> tags from HTML pages
    _SKIP_HTML = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                  ".webp", ".ico", ".woff", ".woff2", ".ttf", ".pdf", ".zip", ".mp4")
    html_scan_urls = list({
        r["url"] for r in all_results
        if not r["url"].split("?")[0].lower().endswith(_SKIP_HTML)
    })[:80]

    if html_scan_urls:
        await ws_manager.broadcast("pipeline", {
            "phase": "js_scan", "event": "started",
            "pipeline": "js_scan",
            "message": f"Scanning inline <script> in {len(html_scan_urls)} pages...",
        })
        for i in range(0, len(html_scan_urls), workers):
            chunk = html_scan_urls[i:i + workers]
            contents = await asyncio.gather(*[_fetch_js(u, cookie) for u in chunk])
            for page_url, content in zip(chunk, contents):
                if not content:
                    continue
                inline = _extract_inline_scripts(content)
                if not inline:
                    continue
                for f in _grep_js(page_url, inline):
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
