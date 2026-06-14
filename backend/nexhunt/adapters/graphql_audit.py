import re
import json
import httpx
from urllib.parse import urlparse
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter

_INTROSPECTION = (
    "query{__schema{queryType{name}mutationType{name}types{name kind "
    "fields(includeDeprecated:true){name "
    "args{name type{kind name ofType{kind name}}} "
    "type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"
)

# Query/mutation names that should normally require authentication.
_SENSITIVE = re.compile(
    r"(?i)(user|account|profile|customer|\bme\b|order|payment|\bpay\b|card|"
    r"loyalty|reward|points|address|email|phone|otp|token|secret|admin|"
    r"internal|transaction|invoice|cart|wallet|credential|password|ssn)"
)

# Internal/infra hosts worth surfacing when leaked in an error.
_INFRA_HINT = re.compile(r"(?i)(internal|middleware|gateway|svc|service|admin|prod|staging|"
                         r"amazonaws\.com|googleapis\.com|\.local|\.internal|\d+\.\d+\.\d+\.\d+)")
_AUTH_ERR = re.compile(r"(?i)(unautheniticated|unauthenticated|unauthorized|not authorized|"
                       r"permission|forbidden|must be logged in|access denied|invalid token|"
                       r"authentication required|UNAUTHENTICATED|FORBIDDEN)")
_URL_RE = re.compile(r"https?://[a-zA-Z0-9.\-]+(?::\d+)?(?:/[^\s\"'<>)]*)?")


def _unwrap(t: dict) -> tuple[str, str]:
    """Follow ofType to the base (kind, name)."""
    kind, name = t.get("kind"), t.get("name")
    inner = t.get("ofType")
    while inner:
        kind, name = inner.get("kind"), inner.get("name")
        inner = inner.get("ofType")
    return kind, name


def _arg_required(arg: dict) -> bool:
    return (arg.get("type") or {}).get("kind") == "NON_NULL"


def _build_query(field: dict) -> str | None:
    """Minimal valid query for a root field with no required args."""
    if any(_arg_required(a) for a in (field.get("args") or [])):
        return None
    name = field["name"]
    base_kind, _ = _unwrap(field.get("type") or {})
    if base_kind in ("SCALAR", "ENUM"):
        return "query{%s}" % name
    return "query{%s{__typename}}" % name  # object/interface/union


_ID_ARG = re.compile(r"(?i)(^id$|id$|uuid|guid)")


def _build_idor_query(field: dict, sample_id: str) -> str | None:
    """Query for a field whose required args are all ID-like scalars, filled with sample_id."""
    req = [a for a in (field.get("args") or []) if _arg_required(a)]
    if not req:
        return None
    for a in req:
        kind, name = _unwrap(a.get("type") or {})
        if kind != "SCALAR" or not (_ID_ARG.search(a["name"]) or name in ("ID", "UUID", "String")):
            return None
    args = ", ".join(f'{a["name"]}: "{sample_id}"' for a in req)
    base_kind, _ = _unwrap(field.get("type") or {})
    sel = "" if base_kind in ("SCALAR", "ENUM") else "{__typename}"
    return "query{%s(%s)%s}" % (field["name"], args, sel)


class GraphqlAuditAdapter(ToolAdapter):
    name = "graphql_audit"
    binary_name = ""
    result_type = "finding"

    async def check_installed(self) -> bool:
        return True

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        import asyncio

        url = target if "://" in target else f"https://{target}"
        target_host = urlparse(url).hostname or ""
        yield {"_raw": True, "line": f"$ graphql-audit {url}"}

        # Split session headers into auth (stripped for unauth probes) and context (kept).
        raw_headers = options.get("session_headers", "") or ""
        ctx_headers = {"Content-Type": "application/json"}
        auth_headers = {}
        for part in raw_headers.replace("\n", ",").split(","):
            if ":" not in part:
                continue
            k, _, v = part.partition(":")
            k, v = k.strip(), v.strip()
            if not k or not v:
                continue
            if k.lower() in ("authorization", "cookie"):
                auth_headers[k] = v
            else:
                ctx_headers[k] = v
        if options.get("session_cookies"):
            auth_headers["Cookie"] = options["session_cookies"]
        full_headers = {**ctx_headers, **auth_headers}

        leaked: set[str] = set()

        def _collect_urls(text: str):
            for m in _URL_RE.finditer(text or ""):
                u = m.group(0).rstrip(".,")
                h = urlparse(u).hostname or ""
                if h and h != target_host and _INFRA_HINT.search(u):
                    leaked.add(u)

        async with httpx.AsyncClient(verify=False, timeout=12, follow_redirects=True) as client:

            async def _post(query: str, headers: dict):
                return await client.post(url, headers=headers, json={"query": query})

            # 1) Introspection
            queries: list[dict] = []
            mutations: list[dict] = []
            try:
                r = await _post(_INTROSPECTION, full_headers)
                _collect_urls(r.text)
                data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
                schema = (data.get("data") or {}).get("__schema")
                if schema:
                    yield {"_raw": True, "line": "  [+] Introspection ENABLED"}
                    qname = (schema.get("queryType") or {}).get("name")
                    mname = (schema.get("mutationType") or {}).get("name")
                    by_name = {t["name"]: t for t in schema.get("types", []) if t.get("name")}
                    queries = (by_name.get(qname, {}) or {}).get("fields") or []
                    mutations = (by_name.get(mname, {}) or {}).get("fields") or []
                    yield {
                        "_raw": False, "id": None,
                        "title": f"[GraphQL] Introspection enabled — {url}",
                        "severity": "medium", "vuln_type": "information-disclosure",
                        "url": url, "parameter": "__schema",
                        "evidence": (f"Introspection query succeeded.\n"
                                     f"Queries: {len(queries)}  Mutations: {len(mutations)}\n"
                                     f"Reproduce:\n  curl -ks -X POST '{url}' -H 'content-type: application/json' "
                                     f"-d '{{\"query\":\"{{__schema{{queryType{{name}}}}}}\"}}'"),
                        "description": "GraphQL introspection is enabled in production, exposing the full schema "
                                       "(every query, mutation, type and argument) to any unauthenticated client.",
                        "tool": "graphql_audit", "template_id": "graphql-introspection", "status": "new",
                    }
                else:
                    yield {"_raw": True, "line": "  [-] Introspection disabled or not GraphQL"}
            except Exception as e:
                yield {"_raw": True, "line": f"  Introspection error: {e}"}

            # 2) Error-leak probe (invalid field -> verbose error may leak internal URLs)
            try:
                r = await _post("query{__nexhunt_invalid_field_zz}", ctx_headers)
                _collect_urls(r.text)
            except Exception:
                pass

            # 3) Unauthenticated access check on no-required-arg root queries
            probes = []
            for f in queries:
                q = _build_query(f)
                if q:
                    probes.append((f["name"], q))
            probes = probes[:80]
            if probes:
                yield {"_raw": True, "line": f"  Probing {len(probes)} root queries WITHOUT auth..."}

            async def _probe_unauth(fname: str, query: str):
                try:
                    r = await _post(query, ctx_headers)  # no Authorization / Cookie
                except Exception:
                    return None
                _collect_urls(r.text)
                try:
                    j = r.json()
                except Exception:
                    return None
                errs = j.get("errors") or []
                if any(_AUTH_ERR.search(json.dumps(e)) for e in errs):
                    return None
                d = j.get("data") or {}
                if fname in d and d[fname] is not None:
                    return (fname, r.status_code)
                return None

            for i in range(0, len(probes), 10):
                batch = probes[i:i + 10]
                results = await asyncio.gather(*[_probe_unauth(n, q) for n, q in batch])
                for res in results:
                    if not res:
                        continue
                    fname, code = res
                    sensitive = bool(_SENSITIVE.search(fname))
                    yield {"_raw": True, "line": f"  [unauth-ok] {fname}{' (SENSITIVE)' if sensitive else ''}"}
                    if sensitive:
                        yield {
                            "_raw": False, "id": None,
                            "title": f"[GraphQL] '{fname}' returns data without authentication — {url}",
                            "severity": "high", "vuln_type": "broken-access-control",
                            "url": url, "parameter": fname,
                            "evidence": (f"Query '{fname}' returned data with no Authorization header (HTTP {code}).\n"
                                         f"Reproduce:\n  curl -ks -X POST '{url}' -H 'content-type: application/json' "
                                         f"-d '{{\"query\":\"query{{{fname}{{__typename}}}}\"}}'"),
                            "description": f"The query '{fname}' looks auth-sensitive but is accessible to "
                                           f"unauthenticated clients (broken access control / excessive data exposure).",
                            "tool": "graphql_audit", "template_id": f"graphql-unauth-{fname.lower()}", "status": "new",
                        }

            # 3b) IDOR / BOLA: object-by-ID queries reachable without auth
            raw_ids = options.get("sample_ids") or ""
            if isinstance(raw_ids, (list, tuple)):
                sample_ids = [str(x).strip() for x in raw_ids if str(x).strip()]
            else:
                sample_ids = [s.strip() for s in re.split(r"[,\s]+", str(raw_ids)) if s.strip()]
            sample_ids = sample_ids[:5]

            id_fields = [f for f in queries
                         if any(_arg_required(a) for a in (f.get("args") or []))
                         and _SENSITIVE.search(f["name"])]

            if id_fields and not sample_ids:
                names = ", ".join(f["name"] for f in id_fields[:20])
                yield {
                    "_raw": False, "id": None,
                    "title": f"[GraphQL] {len(id_fields)} object-by-ID queries (potential IDOR) — {url}",
                    "severity": "info", "vuln_type": "broken-access-control",
                    "url": url, "parameter": None,
                    "evidence": (f"Sensitive queries that take an ID/UUID argument: {names}\n"
                                 "Paste a known ID (e.g. your own loyaltyId/userId) in 'Sample IDs' to auto-test "
                                 "whether the object is readable without authentication."),
                    "description": "These queries fetch an object by ID. If they lack per-object authorization, "
                                   "any ID can be read (IDOR/BOLA). Provide a sample ID to test automatically.",
                    "tool": "graphql_audit", "template_id": "graphql-idor-candidates", "status": "new",
                }

            for sid in sample_ids:
                idor_probes = [(f["name"], _build_idor_query(f, sid)) for f in id_fields]
                idor_probes = [(n, q) for n, q in idor_probes if q][:40]
                if idor_probes:
                    yield {"_raw": True, "line": f"  Testing {len(idor_probes)} ID queries with '{sid}' WITHOUT auth..."}
                for i in range(0, len(idor_probes), 10):
                    batch = idor_probes[i:i + 10]
                    results = await asyncio.gather(*[_probe_unauth(n, q) for n, q in batch])
                    for res in results:
                        if not res:
                            continue
                        fname, code = res
                        yield {"_raw": True, "line": f"  [IDOR] {fname}(id={sid}) -> data without auth"}
                        yield {
                            "_raw": False, "id": None,
                            "title": f"[GraphQL] IDOR — '{fname}' reads object by ID without auth — {url}",
                            "severity": "high", "vuln_type": "broken-access-control",
                            "url": url, "parameter": fname,
                            "evidence": (f"'{fname}' returned data for ID '{sid}' with no Authorization header (HTTP {code}).\n"
                                         f"Swap the ID to read other users' objects.\n"
                                         f"Reproduce:\n  curl -ks -X POST '{url}' -H 'content-type: application/json' "
                                         f"-d '{{\"query\":\"{_build_idor_query(next(f for f in id_fields if f['name']==fname), sid)}\"}}'"),
                            "description": f"Query '{fname}' fetches an object by ID and is readable unauthenticated "
                                           f"(IDOR/BOLA). With a valid ID anyone can read arbitrary objects.",
                            "tool": "graphql_audit", "template_id": f"graphql-idor-{fname.lower()}", "status": "new",
                        }

            # 4) Leaked internal endpoints
            for u in sorted(leaked):
                yield {
                    "_raw": False, "id": None,
                    "title": f"[GraphQL] Internal endpoint leaked: {urlparse(u).hostname}",
                    "severity": "medium", "vuln_type": "information-disclosure",
                    "url": u, "parameter": None,
                    "evidence": f"Internal URL surfaced in a GraphQL response/error:\n{u}\nSeen while auditing {url}",
                    "description": "A GraphQL response leaked an internal/infrastructure URL. Probe it directly — "
                                   "internal microservices are often reachable and unauthenticated.",
                    "tool": "graphql_audit", "template_id": "graphql-internal-url", "status": "new",
                }

            # 5) Mutations inventory (info, highlights sensitive ones)
            if mutations:
                sens = [m["name"] for m in mutations if _SENSITIVE.search(m["name"])]
                yield {
                    "_raw": False, "id": None,
                    "title": f"[GraphQL] {len(mutations)} mutations exposed via introspection — {url}",
                    "severity": "info", "vuln_type": "information-disclosure",
                    "url": url, "parameter": None,
                    "evidence": (f"Total mutations: {len(mutations)}\n"
                                 f"Auth/payment-sensitive ({len(sens)}): " + ", ".join(sens[:30])),
                    "description": "Mutations recovered from introspection. Review the sensitive ones manually for "
                                   "missing authorization, IDOR and input validation.",
                    "tool": "graphql_audit", "template_id": "graphql-mutations", "status": "new",
                }

            yield {"_raw": True, "line": "  done"}
