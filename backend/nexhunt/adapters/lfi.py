from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter
from nexhunt.services import lfi_engine


def _to_finding(f: dict, url: str) -> dict:
    conf = f.get("confidence", "confirmed")
    severity = "high" if conf == "confirmed" else "medium"
    return {
        "_raw": False, "id": None,
        "title": f"[LFI] {f.get('technique')} — param: {f.get('parameter')}",
        "severity": severity, "vuln_type": "lfi",
        "url": f.get("original_url") or url, "parameter": f.get("parameter"),
        "evidence": (
            f"Technique: {f.get('technique')}\n"
            f"Payload: {f.get('payload')}\n"
            f"Status: {f.get('status_code')}  Confidence: {conf}\n"
            f"Evidence:\n{f.get('evidence')}\n\n"
            f"PoC: {f.get('url')}"
        ),
        "description": (
            "Local File Inclusion / path traversal: the parameter reflects file "
            "content from the server filesystem. "
            + ("Confirmed by file-content signature." if conf == "confirmed"
               else "Tentative (baseline differential) — confirm manually.")
        ),
        "tool": "lfi", "template_id": f"lfi-{f.get('technique')}", "status": "new",
    }


class LfiAdapter(ToolAdapter):
    name = "lfi"
    binary_name = ""
    result_type = "finding"

    async def check_installed(self) -> bool:
        return True

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        url = target.strip()
        if "://" not in url:
            url = f"http://{url}"
        yield {"_raw": True, "line": f"$ lfi-scan {url}"}

        if "?" not in url or "=" not in url:
            yield {"_raw": True, "line": "  [!] no query parameters to test — pass a URL like https://host/page?file=x"}
            return

        extra = options.get("wordlist") or options.get("extra_paths")
        if isinstance(extra, str):
            extra = [p for p in extra.splitlines() if p.strip()]

        try:
            findings = await lfi_engine.probe_url(url, extra_wordlist=extra, thorough=True)
        except Exception as e:
            yield {"_raw": True, "line": f"  [!] error: {e}"}
            return

        if not findings:
            yield {"_raw": True, "line": "  no LFI detected"}
            return

        for f in findings:
            yield {"_raw": True, "line": f"  [+] {f['parameter']} via {f['technique']} — {f['payload']}"}
            yield _to_finding(f, url)
