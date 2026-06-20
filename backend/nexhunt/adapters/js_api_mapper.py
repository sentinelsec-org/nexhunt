"""
JS API Mapper — turns a site's JavaScript bundles into an API attack map.

Beyond LinkFinder's raw endpoint strings, this:
  1. Extracts route strings, path->method maps, and role/permission arrays.
  2. Fingerprints the auth/backend framework from route signatures and EXPANDS
     to that library's full known sensitive route set (the client only ships the
     handful it uses).
  3. Classifies privileged routes (admin, impersonate, set-role, delete...).
  4. Emits a ready access-control test plan (anon / low-priv / admin) per route.

All static — it only fetches the JS, never touches the API.
"""
import re
import httpx
from urllib.parse import urljoin, urlparse
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


# ── Framework fingerprints ───────────────────────────────────────────────────
# signatures: substrings whose presence identifies the framework.
# routes: (path, method) the library exposes — added even if the JS only shipped a few.
# base_hint: the mount path the routes hang off (combined with the API base URL).
_FRAMEWORKS = {
    "better-auth": {
        "signatures": ["stop-impersonating", "revoke-other-sessions", "/api/auth", "better-auth"],
        "base_hint": "/api/auth",
        "routes": [
            ("/admin/list-users", "GET"), ("/admin/create-user", "POST"),
            ("/admin/set-role", "POST"), ("/admin/set-user-password", "POST"),
            ("/admin/ban-user", "POST"), ("/admin/unban-user", "POST"),
            ("/admin/impersonate-user", "POST"), ("/admin/stop-impersonating", "POST"),
            ("/admin/remove-user", "POST"), ("/admin/list-user-sessions", "POST"),
            ("/admin/revoke-user-session", "POST"), ("/admin/revoke-user-sessions", "POST"),
            ("/get-session", "GET"), ("/update-user", "POST"),
            ("/change-password", "POST"), ("/change-email", "POST"), ("/delete-user", "POST"),
        ],
    },
    "next-auth": {
        "signatures": ["/api/auth/csrf", "/api/auth/providers", "next-auth"],
        "base_hint": "",
        "routes": [
            ("/api/auth/session", "GET"), ("/api/auth/csrf", "GET"),
            ("/api/auth/providers", "GET"), ("/api/auth/signout", "POST"),
        ],
    },
    "supabase": {
        "signatures": ["/auth/v1/token", "supabase", "/rest/v1/"],
        "base_hint": "",
        "routes": [
            ("/auth/v1/signup", "POST"), ("/auth/v1/token", "POST"),
            ("/auth/v1/user", "GET"), ("/auth/v1/admin/users", "GET"),
            ("/rest/v1/", "GET"),
        ],
    },
    "firebase-auth": {
        "signatures": ["identitytoolkit", "securetoken.googleapis"],
        "base_hint": "",
        "routes": [
            ("/v1/accounts:signUp", "POST"), ("/v1/accounts:signInWithPassword", "POST"),
            ("/v1/accounts:lookup", "POST"),
        ],
    },
    "laravel-sanctum": {
        "signatures": ["/sanctum/csrf-cookie", "XSRF-TOKEN"],
        "base_hint": "",
        "routes": [("/sanctum/csrf-cookie", "GET")],
    },
}

# Quoted absolute path:  "/something/here"
_PATH_RE = re.compile(r'["\'`](/[a-zA-Z0-9/_.:{}$-]{2,70})["\'`]')
# path -> method map:  "/admin/list-users":"GET"
_METHOD_MAP_RE = re.compile(r'["\'`](/[a-zA-Z0-9/_.:{}$-]{2,70})["\'`]\s*:\s*["\'`](GET|POST|PUT|PATCH|DELETE)["\'`]', re.I)
# array of lowercase action strings (role/permission definitions)
_ROLE_RE = re.compile(r'\[((?:\s*["\'][a-z][a-z0-9_-]{1,20}["\']\s*,){2,}\s*["\'][a-z][a-z0-9_-]{1,20}["\']\s*)\]')
# absolute API URLs referenced in the bundle
_URL_RE = re.compile(r'https?://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9/_.-]*)?')

# Keywords that make a route privileged / worth an access-control test.
_PRIV_KW = ("admin", "impersonate", "set-role", "setrole", "set-password", "setpassword",
            "ban-", "/ban", "delete", "remove", "export", "billing", "invoice", "payment",
            "/users", "permission", "/role", "sudo", "superuser", "internal")
# Role actions that mean escalation/takeover if a low-priv user can call them.
_DANGER_ACTIONS = {"set-role", "impersonate", "set-password", "ban", "delete", "remove", "create"}

# Noise paths to ignore (static assets, mime types, etc.)
_IGNORE_RE = re.compile(r'\.(js|css|png|jpe?g|svg|gif|woff2?|ttf|ico|map|webp|mp4)(\?|$)', re.I)


def _kw_match(path: str, kws) -> bool:
    """Keyword match with a left word-boundary so 'set-password' doesn't fire
    inside 'reset-password', etc."""
    pl = path.lower()
    return any(re.search(r'(?<![a-z])' + re.escape(k), pl) for k in kws)


def _is_privileged(path: str) -> bool:
    return _kw_match(path, _PRIV_KW)


def _looks_like_route(path: str) -> bool:
    if _IGNORE_RE.search(path):
        return False
    if path in ("/", "//") or path.startswith("//"):
        return False
    # require at least one letter (drop "/2", "/1.0" version-ish noise unless it has words)
    return bool(re.search(r'[a-zA-Z]{2,}', path))


def _same_site_url(url: str, target: str) -> bool:
    """Keep Recon seeds on the target host or one of its subdomains."""
    target_host = (urlparse(target if target.startswith("http") else f"https://{target}").hostname or "").lower()
    seed_host = (urlparse(url if url.startswith("http") else f"https://{url}").hostname or "").lower()
    target_host = target_host.removeprefix("www.")
    seed_host = seed_host.removeprefix("www.")
    return bool(target_host and seed_host and (
        seed_host == target_host
        or seed_host.endswith(f".{target_host}")
        or target_host.endswith(f".{seed_host}")
    ))


def _fingerprint(blob: str) -> list[str]:
    found = []
    low = blob.lower()
    for name, fw in _FRAMEWORKS.items():
        hits = sum(1 for s in fw["signatures"] if s.lower() in low)
        if hits >= 1 and (hits >= 2 or any(s.lower() in low for s in fw["signatures"][:2])):
            found.append(name)
    return found


def _api_bases(blob: str, target: str) -> list[str]:
    """Candidate API base URLs referenced in the JS, same registrable domain as target."""
    host = urlparse(target if target.startswith("http") else f"https://{target}").netloc
    root = ".".join(host.split(".")[-2:]) if host else ""
    bases: list[str] = []
    seen = set()
    for m in _URL_RE.finditer(blob):
        u = m.group(0).rstrip("/")
        pu = urlparse(u)
        if root and root not in pu.netloc:
            continue
        # keep scheme://host(/path-prefix) — prefer ones that look like API roots
        base = f"{pu.scheme}://{pu.netloc}{pu.path}".rstrip("/")
        if base and base not in seen and ("api" in pu.netloc or "api" in pu.path or pu.path in ("", "/cronos")):
            seen.add(base)
            bases.append(base)
    # always include the target host itself as a fallback base
    fb = (target if target.startswith("http") else f"https://{target}").rstrip("/")
    if fb not in bases:
        bases.append(fb)
    return bases[:6]


def _test_plan(base: str, path: str, method: str) -> str:
    has_id = bool(re.search(r'[:{]|/\d+', path))
    lines = [
        "Access-control test (run via NexHunt proxy or curl):",
        f"  anon:  curl -i -X {method} {base}{path}",
        f"  user:  curl -i -X {method} {base}{path} -H 'Authorization: Bearer <USER_JWT>'",
        f"  admin: curl -i -X {method} {base}{path} -H 'Authorization: Bearer <ADMIN_JWT>'",
        "Expected: 401/403 for anon and a normal user. A 2xx as anon or normal user = broken access control.",
    ]
    if has_id:
        lines.append("Has an ID/param: also test IDOR — swap the id for another user's to read/modify their data.")
    return "\n".join(lines)


class JsApiMapperAdapter(ToolAdapter):
    name = "js_api_mapper"
    binary_name = ""
    result_type = "finding"

    async def check_installed(self) -> bool:
        return True

    async def _collect_js(self, client, target: str, seed_urls: list[str]) -> list[tuple]:
        """Return [(url, content)] for JS bundles to analyze."""
        out: list[tuple] = []
        js_urls: list[str] = []

        if target.split("?")[0].lower().endswith(".js"):
            js_urls.append(target if target.startswith("http") else f"https://{target}")
        elif target:
            base_url = target if target.startswith("http") else f"https://{target}"
            try:
                home = await client.get(base_url, timeout=12)
                srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', home.text, re.I)
                js_urls += [urljoin(base_url, s) for s in srcs if ".js" in s.lower()]
            except Exception:
                pass

        # JS among recon seed URLs
        js_urls += [u for u in seed_urls if u.split("?")[0].lower().endswith(".js")]

        # Treat root/www variants of the same asset as one bundle.
        unique_urls: dict[tuple[str, str, str], str] = {}
        for url in js_urls:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower().removeprefix("www.")
            key = (host, parsed.path, parsed.query)
            unique_urls.setdefault(key, url)
        js_urls = list(unique_urls.values())[:25]

        for u in js_urls:
            try:
                r = await client.get(u, timeout=12)
                if r.status_code == 200 and r.text:
                    out.append((u, r.text[:2_000_000]))
            except Exception:
                continue
        return out

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        seed_urls = [
            u for u in (options.get("seed_urls") or [])
            if isinstance(u, str) and u and _same_site_url(u, target)
        ]

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=12) as client:
            js_files = await self._collect_js(client, target, seed_urls)
            if not js_files:
                yield {"_raw": True, "line": f"  No JS files found for {target}. Give a .js URL or a host with linked bundles, or run Recon first."}
                return

            yield {"_raw": True, "line": f"$ js-api-mapper {target} — analyzing {len(js_files)} JS file(s)"}

            blob = "\n".join(c for _, c in js_files)

            # 1. Declared routes + method maps
            method_map: dict[str, str] = {}
            for m in _METHOD_MAP_RE.finditer(blob):
                p, meth = m.group(1), m.group(2).upper()
                if _looks_like_route(p):
                    method_map[p] = meth
            declared_paths = {p for m in _PATH_RE.finditer(blob) for p in [m.group(1)] if _looks_like_route(p)}

            # 2. Framework fingerprint + route expansion
            frameworks = _fingerprint(blob)
            bases = _api_bases(blob, target)
            primary_base = bases[0]

            expanded: dict[tuple, str] = {}  # (path, method) -> source
            for p, meth in method_map.items():
                expanded[(p, meth)] = "declared"
            for p in declared_paths:
                if not any(p == ep for ep, _ in expanded):
                    expanded[(p, method_map.get(p, "GET"))] = "declared"

            for fw_name in frameworks:
                fw = _FRAMEWORKS[fw_name]
                hint = fw["base_hint"]
                for rp, rm in fw["routes"]:
                    full = (hint + rp) if hint and not rp.startswith(hint) else rp
                    key = (full, rm)
                    if key not in expanded:
                        expanded[key] = f"expanded:{fw_name}"

            # 3. Role / permission arrays
            _INTERESTING_ACTIONS = _DANGER_ACTIONS | {"export", "unban", "manage", "write", "update"}
            _VERB_NOISE = {"get", "post", "put", "patch", "head", "options", "list", "read", "revoke"}
            role_actions: set[str] = set()
            for m in _ROLE_RE.finditer(blob):
                acts = re.findall(r'["\']([a-z][a-z0-9_-]{1,20})["\']', m.group(1))
                if any(a in _DANGER_ACTIONS for a in acts):
                    # keep the meaningful actions, drop generic HTTP-verb noise
                    role_actions.update(a for a in acts if a in _INTERESTING_ACTIONS or (a not in _VERB_NOISE and "-" in a))

            # ── Emit: map summary (also when no framework/routes were found) ──
            route_list = "\n".join(
                f"  {meth:6} {p}  [{src}]" for (p, meth), src in sorted(expanded.items())
            ) or "  (no API-like routes found)"
            summary_title = (
                f"[JS API Map] Auth framework: {', '.join(frameworks)} — {len(expanded)} routes mapped"
                if frameworks else f"[JS API Map] Route map: {len(expanded)} routes mapped"
            )
            yield {
                "_raw": False, "id": None,
                "title": summary_title,
                "severity": "info", "vuln_type": "info-disclosure",
                "url": primary_base, "parameter": None,
                "evidence": (
                    f"Frameworks: {', '.join(frameworks) or 'none detected'}\n"
                    f"Bundles analyzed: {len(js_files)}\n"
                    f"API base candidates: {', '.join(bases)}\n\n"
                    f"Route map (declared in JS + expanded from the library's known API):\n{route_list}"
                ),
                "description": (
                    "Recovered the API route map from the site's JavaScript and expanded it using the detected "
                    "auth framework's documented endpoints. Use these for access-control testing."
                    if frameworks else
                    "Analyzed the site's JavaScript bundles for API-like paths. Zero routes means the loaded "
                    "scripts appear static/vendor-oriented or construct endpoints dynamically at runtime."
                ),
                "tool": "js_api_mapper",
                "template_id": f"jsmap-fw-{frameworks[0]}" if frameworks else "jsmap-map",
                "status": "new",
            }

            # ── Emit: privileged routes (one finding each, with test plan) ──
            priv = sorted({(p, meth) for (p, meth) in expanded if _is_privileged(p)})
            for p, meth in priv:
                takeover = _kw_match(p, ("impersonate", "set-role", "set-password", "set-user-password"))
                sev = "high" if takeover else "medium"
                yield {
                    "_raw": False, "id": None,
                    "title": f"[JS API Map] Privileged route: {meth} {p}",
                    "severity": sev, "vuln_type": "broken-access-control",
                    "url": f"{primary_base}{p}", "parameter": None,
                    "evidence": (
                        f"Route: {meth} {primary_base}{p}\nSource: {expanded[(p, meth)]}\n\n"
                        + _test_plan(primary_base, p, meth)
                    ),
                    "description": (
                        "A privileged API route referenced/implied by the client. Confirm the server enforces "
                        "authorization — if a normal user or anonymous request reaches it, that's broken access "
                        "control"
                        + (" and likely account takeover (impersonation / role / password change)." if takeover else ".")
                    ),
                    "tool": "js_api_mapper", "template_id": f"jsmap-route-{meth}-{p}", "status": "new",
                }

            # ── Emit: dangerous role actions ──
            if role_actions:
                yield {
                    "_raw": False, "id": None,
                    "title": f"[JS API Map] Privileged role actions in client: {', '.join(sorted(role_actions))}",
                    "severity": "medium", "vuln_type": "info-disclosure",
                    "url": primary_base, "parameter": None,
                    "evidence": (
                        "Role/permission definition found in the JS bundle granting: "
                        + ", ".join(sorted(role_actions))
                        + "\n\nMap each to its route and verify a low-privilege user cannot invoke it "
                          "(set-role -> self-escalation, impersonate -> takeover, set-password -> takeover)."
                    ),
                    "description": (
                        "The client ships a role/permission model exposing high-impact actions. These are the "
                        "actions to prioritize for authorization testing."
                    ),
                    "tool": "js_api_mapper", "template_id": "jsmap-roles", "status": "new",
                }

            total_routes = len(expanded)
            yield {"_raw": True, "line": f"  Done — {total_routes} routes, {len(priv)} privileged, frameworks: {', '.join(frameworks) or 'none detected'}"}
