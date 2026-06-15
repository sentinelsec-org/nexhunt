"""
ASP.NET VIEWSTATE auditor.

ASP.NET WebForms pages carry a hidden __VIEWSTATE field: a Base64-encoded blob
that persists page state across postbacks. When it is not encrypted
(ViewStateEncryptionMode off) the blob is a readable .NET ObjectStateFormatter
stream, so developers occasionally embed config there assuming "it's encoded so
nobody reads it". Two payoffs:

  1. Secret leakage — credentials, connection strings, private keys, internal
     URLs and IPs decoded straight out of the blob.
  2. Deserialization RCE — an unencrypted VIEWSTATE whose MAC is disabled is the
     classic ViewState gadget sink (ysoserial.net -p ViewState).

Also enumerates any .asmx / .svc SOAP service referenced on the page or inside
the decoded VIEWSTATE, dumping its WSDL operation names.
"""
import re
import base64
import httpx
from urllib.parse import urlparse, urljoin
from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


# ── VIEWSTATE field extraction ──────────────────────────────────────────────

_HIDDEN_RE = re.compile(
    r'<input[^>]*\bname="(__VIEWSTATE|__VIEWSTATEGENERATOR|__EVENTVALIDATION)"'
    r'[^>]*\bvalue="([^"]*)"',
    re.IGNORECASE,
)


def _extract_fields(html: str) -> dict:
    out = {}
    for m in _HIDDEN_RE.finditer(html):
        # Handle value before name ordering too
        out[m.group(1)] = m.group(2)
    # value="" can appear before name="" — second pass with swapped order
    for m in re.finditer(
        r'<input[^>]*\bvalue="([^"]*)"[^>]*\bname="(__VIEWSTATE|__VIEWSTATEGENERATOR|__EVENTVALIDATION)"',
        html, re.IGNORECASE,
    ):
        out.setdefault(m.group(2), m.group(1))
    return out


def _b64decode(s: str) -> bytes:
    s = re.sub(r"\s+", "", s)
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _strings(data: bytes, minlen: int = 4) -> str:
    """`strings`-style extraction of printable runs from the decoded blob."""
    return "\n".join(
        m.decode("latin-1") for m in re.findall(rb"[\x20-\x7e]{%d,}" % minlen, data)
    )


# ── secret signatures (run over the recovered cleartext) ────────────────────

_SECRET_PATTERNS = [
    ("Embedded credential", "critical",
     re.compile(r'(?i)\b(pass(?:word|wd)?|pwd|secret|consumerid|user\s*id|userid|username)\b["\'>:=\s]{1,4}([^\s"\'<&]{3,60})')),
    ("Private/API key", "critical",
     re.compile(r'(?i)\b(privatekey|secretkey|api[_-]?key|access[_-]?key|merchantid|publickey)\b["\'>:=\s]{1,4}([A-Za-z0-9/+=_\-]{6,80})')),
    ("DB connection string", "high",
     re.compile(r'(?i)\b(data source|initial catalog|user id)\s*=\s*[^;<"\']{2,60}')),
    ("DB/queue URI", "high",
     re.compile(r'(?i)\b(?:mongodb|postgres(?:ql)?|mysql|redis|amqp)://[^\s"\'<]{4,120}')),
    ("AWS access key", "critical",
     re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ("Private IP", "medium",
     re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b')),
]

# Internal/SOAP endpoints: URLs with an IP literal, a non-standard port, or .asmx/.svc
_ENDPOINT_RE = re.compile(
    r'https?://(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9.\-]+)(?::\d{2,5})?(?:/[^\s"\'<]*)?',
    re.IGNORECASE,
)
_ASMX_RE = re.compile(r'https?://[^\s"\'<]+?\.(?:asmx|svc)\b', re.IGNORECASE)


def _interesting_endpoint(u: str) -> bool:
    low = u.lower()
    if ".asmx" in low or ".svc" in low:
        return True
    host = urlparse(u).netloc
    if re.match(r"\d{1,3}(\.\d{1,3}){3}", host):  # IP literal
        return True
    port = host.split(":")[-1] if ":" in host else ""
    return port.isdigit() and port not in ("80", "443")


def _scan_cleartext(cleartext: str) -> list[dict]:
    """Return de-duplicated secret hits from recovered VIEWSTATE cleartext."""
    hits: dict[str, dict] = {}
    for label, severity, rx in _SECRET_PATTERNS:
        for m in rx.finditer(cleartext):
            snippet = m.group(0).strip()[:120]
            key = f"{label}:{snippet}"
            hits.setdefault(key, {"label": label, "severity": severity, "snippet": snippet})
    for m in _ENDPOINT_RE.finditer(cleartext):
        u = m.group(0)
        if _interesting_endpoint(u):
            key = f"endpoint:{u[:120]}"
            hits.setdefault(key, {"label": "Internal/SOAP endpoint", "severity": "high", "snippet": u[:120]})
    return list(hits.values())


# ── public helper for the JS Secrets pipeline (no network) ──────────────────

def viewstate_findings_from_html(page_url: str, html: str) -> list[dict]:
    """Decode + mine any __VIEWSTATE present in `html`. Returns finding dicts."""
    fields = _extract_fields(html)
    vs = fields.get("__VIEWSTATE")
    if not vs:
        return []
    try:
        raw = _b64decode(vs)
    except Exception:
        return []
    encrypted = raw[:2] != b"\xff\x01"
    if encrypted:
        return []  # encrypted blob — nothing readable to mine
    cleartext = _strings(raw)
    out = []
    for h in _scan_cleartext(cleartext):
        out.append({
            "_raw": False, "id": None,
            "title": f"[VIEWSTATE leak] {h['label']} — {page_url}",
            "severity": h["severity"], "vuln_type": "information-disclosure",
            "url": page_url, "parameter": "__VIEWSTATE",
            "evidence": f"Recovered from decoded __VIEWSTATE:\n{h['snippet']}",
            "description": (
                "Sensitive value embedded in an unencrypted ASP.NET __VIEWSTATE. "
                "Decode the field (Base64 -> ObjectStateFormatter) to read it directly."
            ),
            "tool": "viewstate_audit",
            "template_id": "viewstate-leak",
            "status": "new",
        })
    return out


# ── adapter ─────────────────────────────────────────────────────────────────

_CANDIDATE_PATHS = ["", "/", "/default.aspx", "/login.aspx", "/Login.aspx"]


class ViewStateAuditAdapter(ToolAdapter):
    """Decode ASP.NET __VIEWSTATE, mine it for secrets, enumerate SOAP services."""
    name = "viewstate_audit"
    binary_name = ""
    result_type = "finding"

    async def check_installed(self) -> bool:
        return True

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        url = target if "://" in target else f"https://{target}"
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        yield {"_raw": True, "line": f"$ viewstate-audit {url}"}

        headers = {
            "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
        }
        cookie = options.get("session_cookies", "")
        if cookie:
            headers["Cookie"] = cookie
        for line in options.get("session_headers", "").replace("\n", ",").split(","):
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        async with httpx.AsyncClient(verify=False, timeout=12, follow_redirects=True) as client:
            html = None
            found_url = None
            # The target URL first, then a few common ASP.NET entry points.
            tried = []
            for path in ([url] if "://" in target else []) + [urljoin(base, p) for p in _CANDIDATE_PATHS]:
                if path in tried:
                    continue
                tried.append(path)
                try:
                    resp = await client.get(path, headers=headers)
                    has_vs = "__VIEWSTATE" in resp.text
                    yield {"_raw": True, "line": f"  GET {path} -> {resp.status_code} "
                           f"({len(resp.content)}b) viewstate={'yes' if has_vs else 'no'}"}
                    if has_vs:
                        html = resp.text
                        found_url = str(resp.url)
                        break
                except Exception as e:
                    yield {"_raw": True, "line": f"  GET {path} error: {e}"}

            if not html:
                yield {"_raw": True, "line": "  No __VIEWSTATE found — target is probably not ASP.NET WebForms."}
                return

            fields = _extract_fields(html)
            vs = fields.get("__VIEWSTATE", "")
            generator = fields.get("__VIEWSTATEGENERATOR", "")
            yield {"_raw": True, "line": f"  __VIEWSTATE: {len(vs)} chars"
                   f"  generator={generator or 'none'}"}

            try:
                raw = _b64decode(vs)
            except Exception as e:
                yield {"_raw": True, "line": f"  Base64 decode failed: {e}"}
                return

            encrypted = raw[:2] != b"\xff\x01"
            size_kb = len(raw) / 1024
            yield {"_raw": True, "line": f"  Decoded {len(raw)}b ({size_kb:.0f}KB) "
                   f"encrypted={'yes' if encrypted else 'no'}"}

            if encrypted:
                yield {"_raw": True, "line": "  VIEWSTATE is encrypted — no cleartext to mine."}
            else:
                cleartext = _strings(raw)
                hits = _scan_cleartext(cleartext)

                # Unencrypted VIEWSTATE + generator present = ViewState deserialization candidate.
                if generator:
                    yield {
                        "_raw": False, "id": None,
                        "title": f"[VIEWSTATE] Unencrypted ViewState — RCE candidate — {found_url}",
                        "severity": "high", "vuln_type": "deserialization",
                        "url": found_url, "parameter": "__VIEWSTATE",
                        "evidence": (
                            f"__VIEWSTATE decodes to cleartext ObjectStateFormatter "
                            f"({len(raw)} bytes), __VIEWSTATEGENERATOR={generator}.\n"
                            "Not encrypted -> if the MAC is also disabled this is a "
                            "deserialization RCE sink."
                        ),
                        "description": (
                            "ASP.NET __VIEWSTATE is not encrypted. If ViewStateMAC is disabled "
                            "(or the machineKey leaks), it is exploitable for remote code "
                            "execution. Verify with: "
                            f"ysoserial.net -p ViewState -g <gadget> --generator={generator} "
                            "-c \"<cmd>\"  and replay against the page."
                        ),
                        "tool": "viewstate_audit",
                        "template_id": "viewstate-unencrypted",
                        "status": "new",
                    }

                if hits:
                    yield {"_raw": True, "line": f"  {len(hits)} sensitive value(s) recovered from VIEWSTATE"}
                for h in hits:
                    yield {
                        "_raw": False, "id": None,
                        "title": f"[VIEWSTATE leak] {h['label']} — {found_url}",
                        "severity": h["severity"], "vuln_type": "information-disclosure",
                        "url": found_url, "parameter": "__VIEWSTATE",
                        "evidence": f"Recovered from decoded __VIEWSTATE:\n{h['snippet']}",
                        "description": (
                            "Sensitive value embedded in an unencrypted ASP.NET __VIEWSTATE. "
                            "Decode the field (Base64 -> ObjectStateFormatter) to read it directly."
                        ),
                        "tool": "viewstate_audit",
                        "template_id": "viewstate-leak",
                        "status": "new",
                    }
                if not hits:
                    yield {"_raw": True, "line": "  No embedded secrets matched in the cleartext."}

            # ── SOAP service enumeration (page HTML + decoded cleartext) ──
            search_space = html
            if not encrypted:
                search_space += "\n" + _strings(raw)
            asmx_urls = {m.group(0) for m in _ASMX_RE.finditer(search_space)}
            for au in list(asmx_urls)[:5]:
                async for item in self._enum_soap(client, au, headers):
                    yield item

    async def _enum_soap(self, client, asmx_url: str, headers: dict) -> AsyncIterator[dict]:
        wsdl_url = asmx_url.split("?")[0] + "?WSDL"
        yield {"_raw": True, "line": f"  SOAP service: {asmx_url} — fetching WSDL"}
        try:
            resp = await client.get(wsdl_url, headers=headers)
        except Exception as e:
            yield {"_raw": True, "line": f"    WSDL fetch error: {e}"}
            return
        if resp.status_code != 200 or "definitions" not in resp.text.lower():
            yield {"_raw": True, "line": f"    WSDL -> {resp.status_code} (not a WSDL)"}
            return
        ops = sorted(set(re.findall(r'<(?:\w+:)?operation\s+name="([^"]+)"', resp.text)))
        yield {"_raw": True, "line": f"    {len(ops)} operation(s): {', '.join(ops[:20])}"}
        yield {
            "_raw": False, "id": None,
            "title": f"[SOAP] Exposed service with {len(ops)} method(s) — {asmx_url}",
            "severity": "medium", "vuln_type": "information-disclosure",
            "url": asmx_url, "parameter": None,
            "evidence": f"WSDL: {wsdl_url}\nOperations:\n" + "\n".join(ops[:40]),
            "description": (
                "Internet-reachable ASMX/SVC SOAP service discovered from the page. "
                "Its WSDL lists every callable method. Review for unauthenticated, "
                "state-changing or data-exposing operations."
            ),
            "tool": "viewstate_audit",
            "template_id": "soap-service-exposed",
            "status": "new",
        }
