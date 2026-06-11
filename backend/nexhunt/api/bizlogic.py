"""
Business Logic vulnerability testing:
- IDOR Scanner: enumerate IDs, flag unexpected access
- Param Fuzzer: mutate numeric/string params with edge-case payloads
- Race Condition: parallel requests, detect inconsistent responses
- 403 Bypass Tester: try common header/path bypass techniques
- Param Miner: discover hidden parameters via arjun
"""
import asyncio
import json
import logging
import os
import re
import tempfile
import time
from fastapi import APIRouter
from pydantic import BaseModel
import httpx

router = APIRouter(prefix="/api/bizlogic", tags=["bizlogic"])
logger = logging.getLogger(__name__)

# ── Shared helpers ─────────────────────────────────────────────────────────────

def _headers(cookie: str, ua: str = "") -> dict:
    h = {"User-Agent": ua or "Mozilla/5.0 (NexHunt BizLogic Scanner)"}
    if cookie:
        h["Cookie"] = cookie
    return h


# ── IDOR Scanner ───────────────────────────────────────────────────────────────

class IDORRequest(BaseModel):
    url: str                      # e.g. https://example.com/api/users/5
    param: str = ""               # query param name if not in path, e.g. "id"
    id_start: int = 1
    id_end: int = 50
    method: str = "GET"
    cookie: str = ""
    baseline_id: int = 0          # current user's ID for baseline (0 = auto-detect from URL)
    threads: int = 10
    project_id: str = ""


@router.post("/idor")
async def idor_scan(req: IDORRequest):
    """
    Fuzz numeric IDs in a URL path or query parameter.
    Returns findings: responses that differ from the expected 403/404.
    """
    results = []

    # Detect ID in URL path automatically
    path_id_match = re.search(r'/(\d+)(/|$|\?)', req.url)
    baseline_id = req.baseline_id or (int(path_id_match.group(1)) if path_id_match else 0)

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=10,
        verify=False,
    ) as client:
        # Get baseline response (current user's own resource)
        baseline_status = None
        if baseline_id:
            try:
                base_url = _make_url(req.url, req.param, baseline_id)
                r = await client.request(req.method, base_url, headers=_headers(req.cookie))
                baseline_status = r.status_code
            except Exception:
                pass

        sem = asyncio.Semaphore(req.threads)

        async def probe(id_val: int):
            async with sem:
                try:
                    url = _make_url(req.url, req.param, id_val)
                    r = await client.request(req.method, url, headers=_headers(req.cookie))
                    return {
                        "id": id_val,
                        "url": url,
                        "status": r.status_code,
                        "size": len(r.content),
                        "flagged": r.status_code in (200, 201) and id_val != baseline_id,
                    }
                except Exception as e:
                    return {"id": id_val, "url": _make_url(req.url, req.param, id_val), "status": 0, "size": 0, "flagged": False, "error": str(e)}

        tasks = [probe(i) for i in range(req.id_start, req.id_end + 1)]
        results = await asyncio.gather(*tasks)

    findings = [r for r in results if r.get("flagged")]
    all_results = sorted(results, key=lambda r: r["id"])

    return {
        "baseline_id": baseline_id,
        "baseline_status": baseline_status,
        "total_probed": len(results),
        "findings_count": len(findings),
        "findings": findings,
        "all": all_results,
    }


def _make_url(url: str, param: str, id_val: int) -> str:
    """Replace numeric ID in URL path, or append/replace query param."""
    if param:
        # Query param mode
        if f"{param}=" in url:
            return re.sub(rf'{re.escape(param)}=\d+', f'{param}={id_val}', url)
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{param}={id_val}"
    # Path mode: replace last numeric segment
    return re.sub(r'/(\d+)(/|$|\?)', lambda m: f'/{id_val}{m.group(2)}', url, count=1)


# ── Param Fuzzer ───────────────────────────────────────────────────────────────

class ParamFuzzRequest(BaseModel):
    url: str
    method: str = "POST"
    params: dict = {}             # {"price": "10.00", "qty": "1"}
    headers_extra: dict = {}
    cookie: str = ""
    project_id: str = ""


# Edge-case payloads per category
NUMERIC_PAYLOADS = [
    ("zero",         "0"),
    ("negative",     "-1"),
    ("large",        "999999999"),
    ("float",        "0.001"),
    ("neg-float",    "-0.01"),
    ("overflow",     "99999999999999999999"),
    ("empty",        ""),
    ("null-str",     "null"),
    ("array",        "[]"),
    ("negative-max", "-999999999"),
]

STRING_PAYLOADS = [
    ("empty",        ""),
    ("space",        " "),
    ("null-str",     "null"),
    ("true",         "true"),
    ("false",        "false"),
    ("long",         "A" * 5000),
    ("singlequote",  "'"),
    ("template",     "${7*7}"),
]


@router.post("/param-fuzz")
async def param_fuzz(req: ParamFuzzRequest):
    """
    Fuzz each parameter with numeric/string edge-case payloads.
    Flags responses with unexpected 2xx status or significant body change.
    """
    if not req.params:
        return {"error": "No params provided"}

    headers = {**_headers(req.cookie), **req.headers_extra}
    results = []

    async with httpx.AsyncClient(follow_redirects=True, timeout=10, verify=False) as client:
        # Baseline request with original params
        try:
            baseline = await client.request(
                req.method, req.url,
                headers=headers,
                data=req.params if req.method.upper() in ("POST", "PUT", "PATCH") else None,
                params=req.params if req.method.upper() == "GET" else None,
            )
            baseline_status = baseline.status_code
            baseline_size = len(baseline.content)
        except Exception as e:
            return {"error": f"Baseline request failed: {e}"}

        for param_name, original_value in req.params.items():
            # Choose payload set: numeric if value looks numeric
            payloads = NUMERIC_PAYLOADS if re.match(r'^-?\d+(\.\d+)?$', str(original_value)) else STRING_PAYLOADS

            for label, payload in payloads:
                mutated = {**req.params, param_name: payload}
                try:
                    r = await client.request(
                        req.method, req.url,
                        headers=headers,
                        data=mutated if req.method.upper() in ("POST", "PUT", "PATCH") else None,
                        params=mutated if req.method.upper() == "GET" else None,
                    )
                    size_diff = abs(len(r.content) - baseline_size)
                    flagged = (
                        r.status_code in (200, 201, 202) and baseline_status not in (200, 201, 202)
                    ) or (
                        r.status_code in (200, 201, 202) and size_diff > 50 and label not in ("empty", "long")
                    ) or (
                        r.status_code == 500
                    )
                    results.append({
                        "param": param_name,
                        "payload_label": label,
                        "payload": payload,
                        "status": r.status_code,
                        "size": len(r.content),
                        "size_diff": size_diff,
                        "flagged": flagged,
                        "note": _fuzz_note(r.status_code, size_diff, label, baseline_status),
                    })
                except Exception as e:
                    results.append({
                        "param": param_name, "payload_label": label, "payload": payload,
                        "status": 0, "size": 0, "size_diff": 0, "flagged": False, "error": str(e),
                    })

    findings = [r for r in results if r.get("flagged")]
    return {
        "baseline_status": baseline_status,
        "baseline_size": baseline_size,
        "total_tests": len(results),
        "findings_count": len(findings),
        "findings": findings,
        "all": results,
    }


def _fuzz_note(status: int, size_diff: int, label: str, baseline_status: int) -> str:
    if status == 500:
        return "Server error — possible unhandled edge case"
    if status in (200, 201) and baseline_status not in (200, 201):
        return "Unexpected success — logic bypass possible"
    if size_diff > 200:
        return f"Response size changed by {size_diff}b — different behavior"
    return ""


# ── Race Condition ─────────────────────────────────────────────────────────────

class RaceRequest(BaseModel):
    url: str
    method: str = "POST"
    body: str = ""                # raw body string (form-encoded or JSON)
    content_type: str = "application/x-www-form-urlencoded"
    cookie: str = ""
    threads: int = 20             # simultaneous requests
    project_id: str = ""


@router.post("/race")
async def race_condition(req: RaceRequest):
    """
    Fire N requests simultaneously to detect race conditions.
    Flags if responses are inconsistent (different status codes or body sizes).
    """
    headers = {**_headers(req.cookie), "Content-Type": req.content_type}
    results = []

    async with httpx.AsyncClient(follow_redirects=True, timeout=15, verify=False) as client:
        async def fire(i: int):
            t0 = time.monotonic()
            try:
                r = await client.request(
                    req.method, req.url,
                    headers=headers,
                    content=req.body.encode() if req.body else None,
                )
                return {
                    "index": i,
                    "status": r.status_code,
                    "size": len(r.content),
                    "ms": round((time.monotonic() - t0) * 1000),
                    "body_preview": r.text[:120],
                }
            except Exception as e:
                return {"index": i, "status": 0, "size": 0, "ms": 0, "error": str(e)}

        # Launch all simultaneously
        results = await asyncio.gather(*[fire(i) for i in range(req.threads)])

    statuses = [r["status"] for r in results if r["status"] != 0]
    sizes = [r["size"] for r in results if r["status"] != 0]

    status_counts: dict[int, int] = {}
    for s in statuses:
        status_counts[s] = status_counts.get(s, 0) + 1

    unique_statuses = len(set(statuses))
    unique_sizes = len(set(sizes))
    race_detected = unique_statuses > 1 or (unique_sizes > 3 and len(sizes) > 5)

    return {
        "threads": req.threads,
        "race_detected": race_detected,
        "status_distribution": status_counts,
        "size_min": min(sizes) if sizes else 0,
        "size_max": max(sizes) if sizes else 0,
        "unique_sizes": unique_sizes,
        "verdict": _race_verdict(race_detected, status_counts, unique_sizes),
        "results": sorted(results, key=lambda r: r["index"]),
    }


def _race_verdict(detected: bool, status_dist: dict, unique_sizes: int) -> str:
    if not detected:
        return "No race condition detected — all responses consistent"
    parts = []
    if len(status_dist) > 1:
        dist_str = ", ".join(f"{s}: {c}x" for s, c in sorted(status_dist.items()))
        parts.append(f"Mixed status codes ({dist_str})")
    if unique_sizes > 3:
        parts.append(f"{unique_sizes} different response sizes")
    return " | ".join(parts) + " — possible race condition"


# ── Param Miner ───────────────────────────────────────────────────────────────

class ParamMineRequest(BaseModel):
    url: str
    method: str = "GET"
    cookie: str = ""
    project_id: str = ""


@router.post("/param-mine")
async def param_mine(req: ParamMineRequest):
    """
    Run arjun to discover hidden parameters on a URL.
    Returns discovered params + ready-to-use ffuf commands.
    """
    import shutil
    if not shutil.which("arjun"):
        return {"error": "arjun not installed"}

    fd, outfile = tempfile.mkstemp(suffix=".json", prefix="nexhunt_arjun_")
    os.close(fd)

    cmd = ["arjun", "-u", req.url, "--stable", "-oJ", outfile, "-m", req.method.upper()]
    if req.cookie:
        cmd.extend(["-H", f"Cookie: {req.cookie}"])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        log = stdout.decode(errors="replace") if stdout else ""
    except asyncio.TimeoutError:
        return {"error": "arjun timed out after 300s"}
    except Exception as e:
        return {"error": str(e)}
    finally:
        pass

    params: list[str] = []
    try:
        if os.path.exists(outfile) and os.path.getsize(outfile) > 0:
            with open(outfile) as f:
                data = json.load(f)
            if isinstance(data, dict):
                for _url, ps in data.items():
                    params.extend(ps if isinstance(ps, list) else [])
            elif isinstance(data, list):
                for entry in data:
                    params.extend(entry.get("params", []))
    except Exception:
        pass
    finally:
        if os.path.exists(outfile):
            os.unlink(outfile)

    # Build ffuf commands for discovered params
    ffuf_cmds = []
    for p in params[:20]:
        if req.method.upper() == "GET":
            ffuf_cmds.append(
                f'ffuf -u "{req.url}?{p}=FUZZ" -w /usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt -mc 200,201,302,403'
            )
        else:
            ffuf_cmds.append(
                f'ffuf -u "{req.url}" -X POST -d "{p}=FUZZ" -w /usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt -mc 200,201'
            )

    return {
        "url": req.url,
        "params_found": len(params),
        "params": params,
        "ffuf_commands": ffuf_cmds,
        "arjun_log": log[-2000:] if log else "",
    }


# ── 403 Bypass Tester ─────────────────────────────────────────────────────────

class Bypass403Request(BaseModel):
    url: str
    cookie: str = ""
    project_id: str = ""


# Each technique: (label, header_dict, path_variant)
# path_variant replaces the URL path with the variant (None = use original)
_403_TECHNIQUES: list[tuple[str, dict, str | None]] = [
    # Header-based bypasses
    ("X-Original-URL header",      {"X-Original-URL": "{path}"},          None),
    ("X-Rewrite-URL header",       {"X-Rewrite-URL": "{path}"},           None),
    ("X-Custom-IP-Authorization",  {"X-Custom-IP-Authorization": "127.0.0.1"}, None),
    ("X-Forwarded-For: 127.0.0.1", {"X-Forwarded-For": "127.0.0.1"},     None),
    ("X-Forwarded-For: localhost", {"X-Forwarded-For": "localhost"},      None),
    ("X-Real-IP: 127.0.0.1",       {"X-Real-IP": "127.0.0.1"},           None),
    ("X-Host: 127.0.0.1",          {"X-Host": "127.0.0.1"},              None),
    ("X-ProxyUser-Ip: 127.0.0.1",  {"X-ProxyUser-Ip": "127.0.0.1"},     None),
    ("Referer: same URL",          {},                                     None),   # handled below
    # Path-based bypasses (path_variant is appended to base)
    ("Trailing slash (/admin/)",   {},  "/"),
    ("Double slash (//admin)",     {},  "//"),
    ("Dot-slash (/./admin)",       {},  "/./"),
    ("../ prefix (/../admin)",     {},  "/../"),
    ("Uppercase (/ADMIN)",         {},  "UPPER"),
    ("Semicolon (/admin;/)",       {},  ";/"),
    ("URL encode %2f",             {},  "%2f"),
    (".json suffix",               {},  ".json"),
    (".html suffix",               {},  ".html"),
    ("?anyparam=1",                {},  "?anyparam=1"),
]


@router.post("/bypass403")
async def bypass403(req: Bypass403Request):
    """
    Try common 403/401 bypass techniques against a URL.
    Returns which techniques returned a non-403/401 response.
    """
    from urllib.parse import urlparse, urlunparse

    parsed = urlparse(req.url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"
    base_headers = _headers(req.cookie)

    results = []

    async with httpx.AsyncClient(follow_redirects=False, timeout=8, verify=False) as client:
        for label, extra_headers, path_variant in _403_TECHNIQUES:
            try:
                # Build URL
                if path_variant is None:
                    test_url = req.url
                elif path_variant == "UPPER":
                    test_url = base + path.upper()
                elif path_variant.startswith("?"):
                    test_url = req.url + path_variant
                elif path_variant in ("//", "/./", "/../"):
                    test_url = base + path_variant + path.lstrip("/")
                elif path_variant == "/":
                    test_url = req.url.rstrip("/") + "/"
                elif path_variant == ";/":
                    test_url = base + path + ";/"
                elif path_variant == "%2f":
                    test_url = base + "%2f" + path.lstrip("/")
                elif path_variant in (".json", ".html"):
                    test_url = req.url.rstrip("/") + path_variant
                else:
                    test_url = base + path_variant + path.lstrip("/")

                # Build headers
                headers = {**base_headers, **extra_headers}
                if label == "Referer: same URL":
                    headers["Referer"] = req.url

                # Replace {path} placeholder in header values
                headers = {k: v.replace("{path}", path) for k, v in headers.items()}

                r = await client.get(test_url, headers=headers)
                bypassed = r.status_code not in (403, 401, 404)
                results.append({
                    "technique": label,
                    "url": test_url,
                    "status": r.status_code,
                    "size": len(r.content),
                    "bypassed": bypassed,
                })
            except Exception as e:
                results.append({
                    "technique": label, "url": req.url,
                    "status": 0, "size": 0, "bypassed": False, "error": str(e),
                })

    bypasses = [r for r in results if r["bypassed"]]
    return {
        "total_techniques": len(results),
        "bypasses_found": len(bypasses),
        "bypasses": bypasses,
        "all": results,
    }
