"""Passive exposure search plus scoped endpoint discovery for project hosts."""
import asyncio
import json
from typing import Literal
from urllib.parse import quote_plus, urljoin

import httpx
from fastapi import APIRouter
from pydantic import BaseModel, Field
from sqlalchemy import select

from nexhunt.config import settings
from nexhunt.database import DefaultSession
from nexhunt.models.recon_result import ReconResult

router = APIRouter(prefix="/api/exposure-intel", tags=["exposure-intel"])

Category = Literal["api_docs", "sql_errors", "known_vuln", "default_logins", "admin_panels", "debug", "secrets", "custom"]

_CATEGORIES = {
    "api_docs": {
        "label": "Exposed API documentation",
        "shodan": '(http.title:"Swagger UI" OR http.html:"swagger-ui" OR http.html:"openapi.json" OR http.html:"/v3/api-docs")',
        "dorks": [
            'inurl:swagger OR inurl:swagger-ui OR inurl:api-docs',
            'inurl:openapi.json OR inurl:openapi.yaml',
            'inurl:graphql OR inurl:graphiql',
        ],
    },
    "sql_errors": {
        "label": "SQL error disclosure",
        "shodan": '(http.html:"SQL syntax" OR http.html:"mysql_fetch" OR http.html:"Unclosed quotation mark" OR http.html:"PG::SyntaxError")',
        "dorks": [
            '"SQL syntax" OR "mysql_fetch" OR "mysqli_query"',
            '"Unclosed quotation mark" OR "Microsoft OLE DB Provider for SQL Server"',
            '"PG::SyntaxError" OR "SQLiteException" OR "ORA-00933"',
        ],
    },
    "known_vuln": {
        "label": "Known CVEs",
        "shodan": "has_vuln:true",
        "dorks": ['"CVE" "vulnerability"', 'inurl:security-advisories "CVE"'],
    },
    "default_logins": {
        "label": "Default-login risk surfaces",
        "shodan": '(http.title:"Jenkins" OR http.title:"Grafana" OR http.title:"phpMyAdmin" OR http.title:"Kibana" OR http.title:"RouterOS")',
        "dorks": [
            'intitle:"Jenkins" "Manage Jenkins"',
            'intitle:"Grafana" inurl:login',
            'intitle:"phpMyAdmin" inurl:index.php',
            'intitle:"RouterOS" OR intitle:"Kibana" inurl:login',
        ],
    },
    "admin_panels": {
        "label": "Exposed administration panels",
        "shodan": '(http.title:"phpMyAdmin" OR http.title:"Grafana" OR http.title:"Jenkins" OR http.title:"Kibana" OR http.title:"Admin")',
        "dorks": [
            'intitle:"phpMyAdmin" inurl:index.php',
            'intitle:"Jenkins" "Manage Jenkins"',
            'intitle:"Grafana" inurl:login OR intitle:"Kibana" inurl:app',
            'inurl:admin intitle:"login"',
        ],
    },
    "debug": {
        "label": "Debug and diagnostics surfaces",
        "shodan": '(http.html:"Spring Boot" OR http.html:"Whitelabel Error Page" OR http.title:"Dashboard [Jenkins]" OR http.html:"phpinfo()")',
        "dorks": [
            'inurl:actuator OR inurl:actuator/env OR inurl:actuator/health',
            'inurl:server-status OR inurl:phpinfo.php',
            'inurl:_profiler OR inurl:debug intitle:"debug"',
        ],
    },
    "secrets": {
        "label": "Exposed configuration and secrets",
        "shodan": '(http.html:"DB_PASSWORD" OR http.html:"AWS_SECRET_ACCESS_KEY" OR http.html:"[core] repositoryformatversion")',
        "dorks": [
            'inurl:.env "DB_PASSWORD" OR "APP_KEY"',
            'inurl:.git/config "repositoryformatversion"',
            'ext:log "password" OR "api_key" OR "secret"',
        ],
    },
    "custom": {"label": "Custom query", "shodan": "", "dorks": []},
}

_TECH_SHODAN = {
    "wordpress": 'http.html:"wp-content"',
    "nginx": 'product:"nginx"',
    "apache": 'product:"Apache httpd"',
    "iis": 'product:"Microsoft IIS httpd"',
    "jenkins": 'http.title:"Jenkins"',
    "grafana": 'http.title:"Grafana"',
    "elasticsearch": 'product:"Elasticsearch"',
    "kubernetes": 'product:"Kubernetes"',
    "django": 'http.html:"csrfmiddlewaretoken"',
    "laravel": 'http.html:"laravel_session"',
}

_PATHS = {
    "api_docs": [
        "/swagger/", "/swagger-ui/", "/swagger-ui.html", "/api-docs", "/v2/api-docs",
        "/v3/api-docs", "/openapi.json", "/openapi.yaml", "/graphql", "/graphiql",
    ],
    "default_logins": [
        "/admin", "/login", "/administrator", "/phpmyadmin/", "/jenkins/", "/grafana/", "/console/",
    ],
    "admin_panels": [
        "/admin", "/login", "/administrator", "/phpmyadmin/", "/jenkins/", "/grafana/", "/console/",
    ],
    "debug": [
        "/debug", "/actuator", "/actuator/health", "/actuator/env", "/server-status", "/phpinfo.php", "/_profiler/",
    ],
    "secrets": ["/.env", "/.git/config", "/config.json", "/wp-config.php.bak", "/backup.zip"],
}

_SIGNATURES = {
    "api_docs": ("swagger ui", "openapi", "api documentation", "graphiql", "graphql playground"),
    "default_logins": ("phpmyadmin", "jenkins", "grafana", "kibana", "routeros", "sign in", "log in"),
    "admin_panels": ("phpmyadmin", "jenkins", "grafana", "kibana", "administrator", "sign in", "log in"),
    "debug": ("spring boot", "actuator", "phpinfo()", "debug toolbar", "stack trace", "server-status"),
    "secrets": ("db_password", "app_key=", "aws_secret_access_key", "repositoryformatversion", "database_url"),
}

_SQL_SIGNATURES = (
    "sql syntax", "mysql_fetch", "mysqli_query", "unclosed quotation mark", "ole db provider",
    "pg::syntaxerror", "sqliteexception", "ora-00933", "sqlstate[", "pdoexception",
)


class SearchRequest(BaseModel):
    category: Category = "api_docs"
    technology: str = ""
    domain: str = ""
    custom_query: str = ""
    project_hosts: list[str] = Field(default_factory=list, max_length=100)
    page: int = Field(default=1, ge=1, le=20)


class ProjectScanRequest(BaseModel):
    project_id: str
    categories: list[str] = Field(default_factory=lambda: ["api_docs", "admin_panels", "debug", "secrets"])
    technology: str = ""
    max_hosts: int = Field(default=30, ge=1, le=100)


def _clean_domain(value: str) -> str:
    value = value.strip().lower()
    value = value.removeprefix("https://").removeprefix("http://").split("/")[0]
    return value


def _build_shodan_query(req: SearchRequest) -> str:
    query = req.custom_query.strip() if req.category == "custom" else _CATEGORIES[req.category]["shodan"]
    if req.category == "known_vuln" and req.custom_query.strip().upper().startswith("CVE-"):
        cve = req.custom_query.strip().split()[0].upper()
        query = f"vuln:{cve}"
    elif req.custom_query.strip() and req.category != "custom":
        query = f"{query} {req.custom_query.strip()}".strip()
    technology = req.technology.strip().lower()
    if technology:
        tech_query = _TECH_SHODAN.get(technology) or f'product:"{req.technology.strip()}"'
        query = f"{query} {tech_query}".strip()
    if req.domain.strip():
        query = f'{query} hostname:"{_clean_domain(req.domain)}"'.strip()
    return query


@router.get("/presets")
async def presets():
    return {
        "categories": [{"id": key, "label": value["label"]} for key, value in _CATEGORIES.items()],
        "technologies": list(_TECH_SHODAN.keys()),
        "shodan_configured": bool(settings.shodan_api_key),
    }


@router.post("/dorks")
async def generate_dorks(req: SearchRequest):
    base = [req.custom_query.strip()] if req.category == "custom" and req.custom_query.strip() else list(_CATEGORIES[req.category]["dorks"])
    if req.custom_query.strip() and req.category != "custom":
        base = [f"{dork} {req.custom_query.strip()}" for dork in base]
    technology = req.technology.strip()
    domains = [_clean_domain(req.domain)] if req.domain.strip() else []
    domains.extend(_clean_domain(h) for h in req.project_hosts if _clean_domain(h))
    domains = list(dict.fromkeys(domains))[:30]

    queries: list[str] = []
    for dork in base:
        scoped = f'{dork} "{technology}"'.strip() if technology else dork
        if domains:
            queries.extend(f"site:{domain} {scoped}" for domain in domains)
        else:
            queries.append(scoped)

    return [{
        "query": query,
        "google_url": f"https://www.google.com/search?q={quote_plus(query)}",
        "bing_url": f"https://www.bing.com/search?q={quote_plus(query)}",
    } for query in list(dict.fromkeys(queries))[:100]]


@router.post("/shodan/search")
async def shodan_search(req: SearchRequest):
    if not settings.shodan_api_key:
        return {"error": "Shodan API key is not configured in Settings", "query": _build_shodan_query(req)}
    query = _build_shodan_query(req)
    if not query:
        return {"error": "Enter a Shodan query", "query": ""}
    try:
        async with httpx.AsyncClient(timeout=25) as client:
            response = await client.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": settings.shodan_api_key, "query": query, "page": req.page},
            )
        if response.status_code != 200:
            detail = response.json().get("error", response.text[:200]) if response.content else "Shodan request failed"
            return {"error": str(detail), "status_code": response.status_code, "query": query}
        payload = response.json()
    except Exception as exc:
        return {"error": str(exc), "query": query}

    results = []
    for match in payload.get("matches", [])[:100]:
        http = match.get("http") or {}
        location = match.get("location") or {}
        results.append({
            "ip": match.get("ip_str", ""),
            "port": match.get("port"),
            "transport": match.get("transport", ""),
            "hostnames": match.get("hostnames") or [],
            "domains": match.get("domains") or [],
            "org": match.get("org") or "",
            "product": match.get("product") or "",
            "version": match.get("version") or "",
            "title": http.get("title") or "",
            "server": http.get("server") or "",
            "country": location.get("country_name") or "",
            "city": location.get("city") or "",
            "vulns": sorted((match.get("vulns") or {}).keys()) if isinstance(match.get("vulns"), dict) else (match.get("vulns") or []),
            "timestamp": match.get("timestamp") or "",
        })
    return {"query": query, "total": payload.get("total", 0), "results": results}


async def _project_live_hosts(project_id: str, technology: str, limit: int) -> list[dict]:
    async with DefaultSession() as session:
        rows = await session.execute(
            select(ReconResult).where(ReconResult.project_id == project_id, ReconResult.type == "live_host")
        )
        saved = rows.scalars().all()
    hosts = []
    needle = technology.strip().lower()
    for row in saved:
        try:
            data = json.loads(row.data)
        except Exception:
            continue
        url = str(data.get("url") or "").strip()
        technologies = [str(x) for x in (data.get("technologies") or [])]
        if not url or (needle and not any(needle in item.lower() for item in technologies)):
            continue
        hosts.append({"url": url.rstrip("/") + "/", "technologies": technologies})
    unique = {host["url"]: host for host in hosts}
    return list(unique.values())[:limit]


async def _probe(client: httpx.AsyncClient, semaphore: asyncio.Semaphore, host: dict, path: str, category: str):
    url = urljoin(host["url"], path.lstrip("/"))
    try:
        async with semaphore:
            response = await client.get(url, follow_redirects=True)
        body = response.text[:200_000].lower()
        signatures = [sig for sig in _SIGNATURES.get(category, ()) if sig in body]
        sql_signatures = [sig for sig in _SQL_SIGNATURES if sig in body]
        interesting_status = response.status_code in (200, 401, 403)
        if not signatures and not sql_signatures and not interesting_status:
            return None
        if category == "secrets" and response.status_code == 200:
            severity = "high"
        elif sql_signatures:
            severity = "high"
        elif category in ("api_docs", "debug") and response.status_code == 200:
            severity = "medium"
        else:
            severity = "low"
        return {
            "url": str(response.url),
            "source_host": host["url"],
            "category": "sql_errors" if sql_signatures else category,
            "severity": severity,
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type", "").split(";")[0],
            "technologies": host["technologies"],
            "signals": (signatures + sql_signatures)[:8],
        }
    except Exception:
        return None


@router.post("/project-scan")
async def project_scan(req: ProjectScanRequest):
    hosts = await _project_live_hosts(req.project_id, req.technology, req.max_hosts)
    if not hosts:
        return {"hosts": 0, "tested": 0, "results": [], "message": "No matching live hosts in this project"}
    categories = [category for category in req.categories if category in _PATHS]
    candidates = [(host, path, category) for host in hosts for category in categories for path in _PATHS[category]]
    semaphore = asyncio.Semaphore(12)
    timeout = httpx.Timeout(8, connect=5)
    async with httpx.AsyncClient(timeout=timeout, verify=False, headers={"User-Agent": "NexHunt Exposure Intelligence/1.0"}) as client:
        rows = await asyncio.gather(*(_probe(client, semaphore, host, path, category) for host, path, category in candidates))
    results = [row for row in rows if row]
    deduped = list({row["url"]: row for row in results}.values())
    deduped.sort(key=lambda row: ({"high": 0, "medium": 1, "low": 2}.get(row["severity"], 9), row["url"]))
    return {"hosts": len(hosts), "tested": len(candidates), "results": deduped}
