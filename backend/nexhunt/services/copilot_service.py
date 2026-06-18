"""
AI Copilot service — powered by Groq (llama-3.3-70b-versatile).
Falls back to Claude or OpenAI if configured.
Automatically pulls full session context from the database on every call.
"""
import re
import logging
from nexhunt.config import settings
from nexhunt.licensing.manager import license_manager
from nexhunt.licensing import fingerprint

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are NexHunt AI Copilot, an elite bug bounty hunter and penetration tester built into a security research platform.

You have deep expertise in:
- Web application security (XSS, SQLi, SSRF, IDOR, XXE, RCE, LFI, SSTI, Open Redirect, CORS, OAuth flaws)
- Bug bounty methodologies (HackerOne, Bugcrowd, Intigriti, Synack)
- Recon techniques: subdomain enumeration, tech fingerprinting, attack surface mapping
- Exploitation: PoC development, chained attacks, bypass techniques
- Tools: Nuclei, Burp Suite, ffuf, sqlmap, amass, httpx, gowitness, dalfox, nmap
- Report writing: CVSS scoring, impact analysis, professional disclosure format

When given session data (findings, subdomains, live hosts, ports), think like a senior pentester:
1. Identify the most impactful vulnerabilities and their bounty potential
2. Spot attack chains (e.g., SSRF → internal access → RCE)
3. Flag likely false positives with reasoning
4. Suggest specific follow-up tests with exact commands/payloads
5. Prioritize by real exploitability, not just severity label

**Response formatting rules:**
- Use markdown: ## for sections, **bold** for critical info, `code` for commands/payloads
- Use code blocks (```) for multi-line commands, HTTP requests, or payloads
- Keep responses concise but complete — bullet points over long paragraphs
- Always end analysis with concrete "Next Steps" section

**Bug bounty report format when asked:**
```
## [Vulnerability Type] in [Feature/Endpoint]
**Severity:** Critical/High/Medium/Low
**CVSS:** X.X (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

### Description
[Technical explanation]

### Steps to Reproduce
1. [Step]
2. [Step]

### Impact
[What an attacker can do with this]

### Remediation
[How to fix it]

### References
- CWE-XXX
- https://...
```

**Native tool execution:**
When the user asks you to run a NexHunt tool (or when you recommend running one), output a `nexhunt-tool` code block. The UI renders it with an Execute button that fires the tool directly — no terminal needed.

Format:
```nexhunt-tool
tool: <name>
target: <domain or URL>
scan_type: <optional>
severity: <optional>
extra_args: <optional>
```

Available tools by category:
- Recon: subfinder, amass, httpx, httpx-probe, nmap, waybackurls, gau, katana, katana-headless, linkfinder, arjun
- Scanner: nuclei, ffuf, gobuster, dirsearch, nikto
- Security checks: cors, bypass-403

Common options:
- nuclei: scan_type (cves/xss/sqli/ssrf/misconfig/cors/lfi/rce/full-owasp/jwt), severity (critical/high/medium)
- nmap: ports (e.g. 80,443,8080), extra_args (-sV -O)
- gobuster/ffuf/dirsearch: wordlist path
- any tool: extra_args for raw flags

Use `nexhunt-tool` blocks proactively when analyzing an attack surface. You can suggest multiple tools in sequence."""


# Investigation protocol — lets the AI actively pull real evidence before answering.
INVESTIGATION_PROTOCOL = """

---

# INVESTIGATION MODE (use this — do not give blind answers)

Before answering, you can investigate to ground your analysis in REAL data instead of guessing.
To look at something, output a fenced block (and STOP — wait for the result):

```nexhunt-investigate
action: fetch_url
url: https://target.com/path
```

```nexhunt-investigate
action: read_finding
id: <finding id from the context above>
```

Actions available:
- `fetch_url` — performs an authenticated GET (uses the session cookies/headers if set) and returns status, key headers and the response body. Use it to CONFIRM a finding, read a page, inspect an endpoint, check a redirect, or see what a parameter does.
- `read_finding` — returns the full untruncated evidence/description of a finding by its id.

Rules:
- You may emit several investigate blocks at once (they run in parallel) — but only investigate what you actually need.
- After I return results, either investigate more OR give your FINAL assessment.
- An answer with NO investigate block is treated as final.
- Investigate when judging exploitability, confirming/dismissing a finding, or when the context lacks the actual response. Do NOT investigate for trivial questions.
- Keep it to 1-3 rounds. Be decisive.

When you finish, give a grounded verdict: what is real, what is a false positive (with the evidence that proves it), and the exact next exploitation step."""


# OpenAI-compatible providers — base URLs. All free or near-free; the user picks one in Settings.
PROVIDER_BASE_URLS = {
    "groq":       "https://api.groq.com/openai/v1",
    "gemini":     "https://generativelanguage.googleapis.com/v1beta/openai/",
    "cerebras":   "https://api.cerebras.ai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "deepseek":   "https://api.deepseek.com",
    "openai":     "https://api.openai.com/v1",
}


class CopilotService:
    def _lang_instruction(self) -> str:
        if settings.language == "es":
            return "\n\nIMPORTANTE: Responde siempre en español. Usa terminología técnica en inglés cuando sea estándar (nombres de vulnerabilidades, herramientas, comandos), pero explica todo en español."
        return ""

    async def chat(self, message: str, context: dict = {}) -> str:
        """Send a message with full auto-context to the AI."""
        ctx_str = await self._build_full_context(context)
        full_message = f"{ctx_str}\n\n---\n\n{message}" if ctx_str else message
        return await self._dispatch(full_message)

    # ── Agentic investigation loop ────────────────────────────────────────────
    _MAX_STEPS = 4
    _MAX_ACTIONS = 6
    _INVESTIGATE_RE = re.compile(r"```nexhunt-investigate\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)

    def _parse_investigations(self, text: str) -> list[dict]:
        actions = []
        for body in self._INVESTIGATE_RE.findall(text):
            d = {}
            for line in body.strip().splitlines():
                m = re.match(r"^([\w-]+):\s*(.+)$", line.strip())
                if m:
                    d[m.group(1).strip().lower()] = m.group(2).strip()
            if d.get("action"):
                actions.append(d)
        return actions

    def _strip_investigations(self, text: str) -> str:
        return self._INVESTIGATE_RE.sub("", text).strip()

    async def agent_investigate(self, message: str, context: dict, history: list[dict] | None = None) -> str:
        """
        Run the AI as an active investigator: it can request read-only actions
        (fetch_url / read_finding), we execute them and feed results back, until
        it produces a grounded final assessment. Works over any provider since
        the protocol is plain text.
        """
        ctx = await self._build_full_context(context)
        lang = self._lang_instruction()
        directive = (
            "# USER REQUEST — answer THIS, specifically\n\n"
            f"{message}\n\n"
            "How to respond:\n"
            "- Address the user's actual request above. Do NOT default to summarizing the findings list "
            "unless they explicitly ask for a session/findings overview.\n"
            "- If the request mentions a specific URL, host, domain or endpoint, you MUST `fetch_url` it "
            "and base your answer on the REAL response — never guess from the name alone.\n"
            "- Ground every claim in data you can see in the context or fetch yourself.\n"
        )
        ctx_block = f"\n\n---\n## Reference: current session data (use only if relevant to the request)\n{ctx}" if ctx else ""
        pending = directive + ctx_block + INVESTIGATION_PROTOCOL + lang

        local_history = [h for h in (history or []) if h.get("role") in ("user", "assistant")][-20:]
        trail: list[str] = []
        actions_used = 0

        for step in range(self._MAX_STEPS):
            resp = await self._dispatch(pending, local_history)
            actions = self._parse_investigations(resp)
            narrative = self._strip_investigations(resp)

            if not actions or actions_used >= self._MAX_ACTIONS:
                if narrative:
                    trail.append(narrative)
                break

            if narrative:
                trail.append(narrative)

            results = []
            log_lines = []
            for a in actions[: self._MAX_ACTIONS - actions_used]:
                actions_used += 1
                model_text, display = await self._exec_investigation(a, context)
                results.append(model_text)
                log_lines.append(display)
            trail.append("🔍 " + "\n🔍 ".join(log_lines))

            results_text = "\n\n".join(results)
            local_history = local_history + [
                {"role": "user", "content": pending[:3000]},
                {"role": "assistant", "content": resp[:3000]},
            ]
            pending = (
                "Results of your investigation:\n\n" + results_text +
                "\n\nContinue investigating only if needed, otherwise give your final grounded assessment now."
                + lang
            )
        else:
            # Loop exhausted — force a final answer from what we gathered.
            final = await self._dispatch(
                "You have investigated enough. Give your final grounded assessment now, no more investigation blocks." + lang,
                local_history,
            )
            trail.append(self._strip_investigations(final))

        return "\n\n".join(p for p in trail if p.strip())

    async def _exec_investigation(self, action: dict, context: dict) -> tuple[str, str]:
        """Execute one read-only investigation action. Returns (text_for_model, short_display)."""
        kind = action.get("action", "").lower()

        if kind == "fetch_url":
            url = action.get("url", "").strip()
            if not url.startswith(("http://", "https://")):
                return (f"fetch_url error: invalid url '{url}'", f"fetch_url skipped (bad url: {url})")
            import httpx
            headers = {"User-Agent": "Mozilla/5.0 (NexHunt Copilot)"}
            if context.get("session_cookies"):
                headers["Cookie"] = context["session_cookies"]
            for h in (context.get("session_headers", "") or "").replace("\n", ",").split(","):
                h = h.strip()
                if h and ":" in h:
                    k, _, v = h.partition(":")
                    headers[k.strip()] = v.strip()
            try:
                async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=15) as client:
                    r = await client.get(url, headers=headers)
                ctype = r.headers.get("content-type", "")
                interesting = {k: v for k, v in r.headers.items()
                               if k.lower() in ("server", "x-powered-by", "location", "content-type",
                                                "content-length", "www-authenticate", "set-cookie",
                                                "access-control-allow-origin", "x-frame-options")}
                hdr_str = "\n".join(f"{k}: {v}" for k, v in interesting.items())
                body = r.text[:3500]
                model_text = (f"### fetch_url {url}\nStatus: {r.status_code}\nHeaders:\n{hdr_str}\n\n"
                              f"Body (first 3500 chars):\n{body}")
                display = f"GET {url} -> {r.status_code} ({len(r.content)}B, {ctype.split(';')[0]})"
                return (model_text, display)
            except Exception as e:
                return (f"### fetch_url {url}\nERROR: {e}", f"GET {url} -> error: {e}")

        if kind == "read_finding":
            fid = action.get("id", "").strip()
            try:
                from nexhunt.database import DefaultSession
                from nexhunt.models.finding import Finding
                from sqlalchemy import select
                async with DefaultSession() as session:
                    row = await session.execute(select(Finding).where(Finding.id == fid))
                    f = row.scalar_one_or_none()
                if not f:
                    return (f"read_finding: no finding with id {fid}", f"read_finding {fid} -> not found")
                model_text = (f"### Finding {fid}\nTitle: {f.title}\nSeverity: {f.severity}\n"
                              f"URL: {f.url}\nTool: {f.tool}\nTemplate: {f.template_id}\n"
                              f"Description: {f.description or ''}\n\nEvidence:\n{str(f.evidence or '')[:6000]}")
                return (model_text, f"read finding {fid} ({f.title})")
            except Exception as e:
                return (f"read_finding error: {e}", f"read_finding {fid} -> error")

        return (f"Unknown investigation action: {kind}", f"unknown action: {kind}")

    async def analyze_all(self) -> str:
        """Full auto-analysis: pull everything from DB and ask for comprehensive analysis."""
        ctx = await self._build_full_context({})
        if not ctx:
            return "No data to analyze yet. Run some recon and scans first."

        prompt = (
            f"{ctx}\n\n---\n\n"
            "Perform a comprehensive security analysis of the session data above. Structure your response as:\n\n"
            "## Executive Summary\n"
            "## Critical & High Findings (prioritized by bounty potential)\n"
            "## Attack Surface Assessment\n"
            "## Detected Technologies & Known Vulnerabilities\n"
            "## Recommended Attack Vectors (with specific commands)\n"
            "## Immediate Next Steps\n\n"
            "Be specific, technical, and actionable. Include exact nuclei templates, tool commands, or payloads where relevant."
        )
        return await self._dispatch(prompt)

    async def generate_report(self, finding_id: str | None = None) -> str:
        """Generate a professional bug bounty report for a finding (or all critical/high)."""
        ctx = await self._build_full_context({})
        if finding_id:
            prompt = f"{ctx}\n\n---\n\nGenerate a professional bug bounty report for finding ID: {finding_id}. Use the standard format with CVSS score, steps to reproduce, impact, and remediation."
        else:
            prompt = f"{ctx}\n\n---\n\nGenerate professional bug bounty reports for all critical and high severity findings. For each finding, include: severity, CVSS, description, steps to reproduce, impact, and remediation."
        return await self._dispatch(prompt)

    def _build_messages(self, history: list[dict] | None, message: str) -> list[dict]:
        msgs = []
        for h in (history or [])[-20:]:
            role = h.get("role", "user")
            if role not in ("user", "assistant"):
                continue
            msgs.append({"role": role, "content": str(h.get("content", ""))[:2000]})
        msgs.append({"role": "user", "content": message})
        return msgs

    def _resolve_provider(self) -> tuple[str | None, str | None]:
        """Return (base_url, api_key) for the configured OpenAI-compatible provider, or (None, None)."""
        p = settings.ai_provider
        if p == "custom":
            return (settings.ai_base_url.rstrip("/") if settings.ai_base_url else None, settings.ai_api_key)
        base = PROVIDER_BASE_URLS.get(p)
        if not base:
            return (None, None)
        # groq keeps its own dedicated key for backward compat; everything else uses ai_api_key
        key = (settings.ai_groq_key or settings.ai_api_key) if p == "groq" else settings.ai_api_key
        return (base, key)

    async def _dispatch(self, message: str, history: list[dict] | None = None) -> str:
        # Anthropic uses its own SDK.
        if settings.ai_provider == "claude" and settings.ai_api_key:
            return await self._chat_claude(message, history)
        # Any OpenAI-compatible provider (groq/gemini/cerebras/openrouter/deepseek/openai/custom).
        base_url, key = self._resolve_provider()
        if base_url and key:
            return await self._chat_openai_compatible(base_url, key, message, history)
        # Otherwise use Sentinel's hosted PRO Copilot, authorized by the license key.
        if settings.sentinel_ai_proxy_url:
            return await self._chat_hosted(message, history)
        return "No AI provider configured. Set a provider + API key in Settings."

    async def _chat_hosted(self, message: str, history: list[dict] | None = None) -> str:
        """Call Sentinel's hosted Copilot proxy, authenticated by the license key."""
        import asyncio
        import httpx
        key = license_manager.raw_key()
        if not key:
            return "AI Copilot is a NexHunt PRO feature. Activate your license in Settings to use it."
        url = settings.sentinel_ai_proxy_url.rstrip("/") + "/v1/chat"
        payload = {
            "license_key": key,
            "machine_id": fingerprint.get_machine_id(),
            "system": SYSTEM_PROMPT + self._lang_instruction(),
            "message": message[:16000],
            "history": [h for h in (history or [])[-20:] if h.get("role") in ("user", "assistant")],
            "max_tokens": 4096,
        }
        try:
            async with httpx.AsyncClient(timeout=95.0) as client:
                resp = await client.post(url, json=payload)
            if resp.status_code in (401, 402, 403):
                return "Your NexHunt PRO license could not be verified for AI Copilot. Re-activate it in Settings."
            if resp.status_code == 429:
                return "AI Copilot rate limit reached. Wait a moment and try again."
            if resp.status_code >= 400:
                return f"AI Copilot service error ({resp.status_code}). Try again shortly."
            data = resp.json()
            return data.get("response") or data.get("error") or ""
        except (httpx.TimeoutException, asyncio.TimeoutError):
            return "AI Copilot timed out. Try again in a moment."
        except Exception as e:
            logger.error(f"Hosted Copilot error: {e}")
            return "AI Copilot is temporarily unavailable. Try again shortly."

    async def _chat_openai_compatible(self, base_url: str, key: str, message: str, history: list[dict] | None = None) -> str:
        """Chat via any OpenAI-compatible API (Groq, Gemini, Cerebras, OpenRouter, DeepSeek, OpenAI, custom)."""
        import asyncio
        try:
            from openai import AsyncOpenAI
            client = AsyncOpenAI(api_key=key, base_url=base_url, timeout=90.0)
            system = SYSTEM_PROMPT + self._lang_instruction()
            trimmed = message[:16000] if len(message) > 16000 else message
            resp = await asyncio.wait_for(
                client.chat.completions.create(
                    model=settings.ai_model,
                    messages=[{"role": "system", "content": system}] + self._build_messages(history, trimmed),
                    max_tokens=4096,
                    temperature=0.3,
                ),
                timeout=90.0,
            )
            return resp.choices[0].message.content or ""
        except (TimeoutError, asyncio.TimeoutError):
            return "Request timed out. The provider is slow right now — try again or switch provider in Settings."
        except Exception as e:
            logger.error(f"AI provider ({settings.ai_provider}) error: {e}")
            return f"AI provider error ({settings.ai_provider}, model {settings.ai_model}): {e}"

    async def _chat_claude(self, message: str, history: list[dict] | None = None) -> str:
        try:
            import anthropic
            client = anthropic.AsyncAnthropic(api_key=settings.ai_api_key)
            resp = await client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=8096,
                system=SYSTEM_PROMPT,
                messages=self._build_messages(history, message),
            )
            return resp.content[0].text
        except Exception as e:
            logger.error(f"Claude error: {e}")
            return f"Claude API error: {e}"


    async def _build_full_context(self, user_context: dict) -> str:
        """Pull ALL session data: findings from DB + recon from frontend context."""
        parts: list[str] = []

        # ── Active target ──────────────────────────────────────────────────────
        if user_context.get("target"):
            parts.append(f"## Active Target\n{user_context['target']}")

        # ── Findings from DB (full history) ───────────────────────────────────
        try:
            from nexhunt.database import DefaultSession
            from nexhunt.models.finding import Finding
            from sqlalchemy import select

            async with DefaultSession() as session:
                result = await session.execute(
                    select(Finding).order_by(Finding.created_at.desc()).limit(80)
                )
                db_findings = result.scalars().all()

            if db_findings:
                by_sev: dict[str, list] = {}
                for f in db_findings:
                    by_sev.setdefault(f.severity or "info", []).append(f)

                counts = {s: len(v) for s, v in by_sev.items()}
                summary = ", ".join(f"{s.upper()}: {c}" for s, c in counts.items())
                parts.append(f"\n## Security Findings ({len(db_findings)} total — {summary})")

                # Compact list only — the AI pulls full evidence on demand via read_finding.
                for sev in ["critical", "high", "medium", "low", "info"]:
                    if sev not in by_sev:
                        continue
                    parts.append(f"\n### {sev.upper()} ({len(by_sev[sev])})")
                    for f in by_sev[sev][:12]:
                        line = f"- {f.title} (id:{f.id})"
                        if f.url:
                            line += f" | {f.url}"
                        if f.tool:
                            line += f" | {f.tool}"
                        parts.append(line)
                parts.append("\n_(Use `read_finding <id>` to pull the full evidence/description of any finding.)_")
        except Exception as e:
            logger.warning(f"Could not fetch findings from DB: {e}")

        # ── Live hosts (from frontend context) ────────────────────────────────
        if user_context.get("live_hosts"):
            hosts = user_context["live_hosts"]
            parts.append(f"\n## Live Hosts ({len(hosts)})")
            for h in hosts[:40]:
                url = h.get("url", "")
                sc = h.get("status_code", "?")
                techs = ", ".join(h.get("technologies", [])[:6])
                title = h.get("title", "")
                line = f"- `{url}` [{sc}]"
                if title:
                    line += f" — {title}"
                if techs:
                    line += f" — *{techs}*"
                parts.append(line)

        # ── Subdomains ─────────────────────────────────────────────────────────
        if user_context.get("subdomains"):
            subs = user_context["subdomains"]
            parts.append(f"\n## Subdomains ({len(subs)})")
            parts.append(", ".join(f"`{s.get('subdomain', '')}`" for s in subs[:60]))

        # ── Open ports ────────────────────────────────────────────────────────
        if user_context.get("ports"):
            ports = user_context["ports"]
            parts.append(f"\n## Open Ports ({len(ports)})")
            for p in ports[:30]:
                svc = p.get("service", "")
                ver = p.get("version", "")
                parts.append(f"- `{p.get('ip', '')}:{p.get('port', '')}` {svc} {ver}".strip())

        # ── Discovered URLs ───────────────────────────────────────────────────
        if user_context.get("urls"):
            urls = user_context["urls"]
            parts.append(f"\n## Discovered URLs ({len(urls)} total, showing 20)")
            for u in urls[:20]:
                parts.append(f"- `{u.get('url', '')}`")

        # ── Discovered endpoints (from endpoint-discovery) ────────────────────
        if user_context.get("endpoints"):
            eps = user_context["endpoints"]
            parts.append(f"\n## Discovered Endpoints ({len(eps)} total, showing 40)")
            for e in eps[:40]:
                sc = e.get("status_code", "?")
                cl = e.get("content_length")
                line = f"- `{e.get('url', '')}` [{sc}]"
                if e.get("title"):
                    line += f" — {e['title']}"
                if cl is not None:
                    line += f" ({cl}B)"
                parts.append(line)

        # ── Captured proxy traffic (request/response pairs) ───────────────────
        if user_context.get("flows"):
            flows = user_context["flows"]
            parts.append(f"\n## Captured Proxy Traffic ({len(flows)} requests, showing 30)")
            parts.append("Use `fetch_url` to re-issue any of these and inspect the live response.")
            for fl in flows[:30]:
                m = fl.get("request_method", "GET")
                host = fl.get("request_host", "")
                path = fl.get("request_path", "")
                sc = fl.get("response_status", "?")
                ln = fl.get("response_length", "")
                parts.append(f"- `{m} {host}{path}` -> {sc} ({ln}B)")

        return "\n".join(parts)


copilot_service = CopilotService()
