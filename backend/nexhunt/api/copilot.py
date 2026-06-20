import logging
from fastapi import APIRouter
from pydantic import BaseModel
from nexhunt.services.copilot_service import copilot_service

router = APIRouter(prefix="/api/copilot", tags=["copilot"])
logger = logging.getLogger(__name__)


class ChatRequest(BaseModel):
    message: str
    context: dict = {}   # live recon data from the frontend stores


class AnalyzeRequest(BaseModel):
    context: dict = {}


class ReportRequest(BaseModel):
    finding_id: str | None = None
    context: dict = {}


class HostsAnalysisRequest(BaseModel):
    live_hosts: list[dict] = []
    subdomains: list[dict] = []
    ports: list[dict] = []


class SecretAnalysisRequest(BaseModel):
    js_url: str = ""
    label: str = ""
    match: str = ""
    context: str = ""
    line: int | None = None
    live_hosts: list[dict] = []   # for host/tech context


class AgentChatRequest(BaseModel):
    message: str
    context: dict = {}
    command_output: str = ""
    history: list[dict] = []   # [{role, content}] previous turns


@router.post("/chat")
async def chat(req: ChatRequest):
    """Chat with the AI. Context is merged with DB findings automatically."""
    try:
        response = await copilot_service.chat(req.message, req.context)
        return {"response": response}
    except Exception as e:
        logger.error(f"Copilot chat error: {e}")
        return {"response": f"Error: {e}"}


@router.post("/analyze")
async def analyze(req: AnalyzeRequest):
    """Full auto-analysis: AI reads ALL findings from DB + recon context and produces a full report."""
    try:
        # Merge DB data in the service — just pass live recon context from frontend
        response = await copilot_service.analyze_all()
        return {"response": response}
    except Exception as e:
        logger.error(f"Copilot analyze error: {e}")
        return {"response": f"Error: {e}"}


@router.post("/analyze-hosts")
async def analyze_hosts(req: HostsAnalysisRequest):
    """Analyze live hosts and return AI-generated profile + priority attack list."""
    if not req.live_hosts:
        return {"response": "No live hosts to analyze."}
    try:
        lang = copilot_service._lang_instruction()
        hosts_lines = []
        for h in req.live_hosts[:60]:
            techs = ", ".join(h.get("technologies", [])[:8])
            line = f"- {h.get('url','')} [{h.get('status_code','?')}] title=\"{h.get('title','')}\" techs=[{techs}]"
            hosts_lines.append(line)
        subs_preview = ", ".join(s.get("subdomain","") for s in req.subdomains[:30]) if req.subdomains else "none"
        ports_preview = "; ".join(f"{p.get('ip','')}:{p.get('port','')} {p.get('service','')}" for p in req.ports[:20]) if req.ports else "none"

        prompt = f"""You are analyzing an attack surface for a bug bounty engagement.

## Live Hosts ({len(req.live_hosts)} total)
{chr(10).join(hosts_lines)}

## Subdomains discovered: {subs_preview}

## Open ports: {ports_preview}

For each live host, provide a 1-2 sentence profile: what is this service, what does it likely do, and what is its attack surface potential.

Then create a **Prioritized Attack List** ranking the top 10 hosts by bug bounty potential, explaining why each is interesting (login panels, APIs, admin interfaces, legacy tech, unusual ports, etc.).

Finally add a **Quick Wins** section: 3-5 specific things to try immediately (exact tool commands).{lang}"""

        response = await copilot_service._dispatch(prompt)
        return {"response": response}
    except Exception as e:
        logger.error(f"Copilot analyze-hosts error: {e}")
        return {"response": f"Error: {e}"}


@router.post("/analyze-secret")
async def analyze_secret(req: SecretAnalysisRequest):
    """Contextualize a secret found in a JS file: fetch the whole file, add host
    context, and ask the AI what it is, the impact, and concrete next steps."""
    if not req.match:
        return {"response": "No secret provided."}
    try:
        # Pull the full JS file so the AI sees how the secret is used, not just the line.
        file_excerpt = ""
        if req.js_url:
            import httpx
            try:
                async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=12) as client:
                    r = await client.get(req.js_url)
                    body = r.text
                # Keep it within model limits: head + the region around the match.
                if len(body) > 16000:
                    idx = body.find(req.match[:40]) if req.match else -1
                    if idx >= 0:
                        s, e = max(0, idx - 4000), min(len(body), idx + 4000)
                        file_excerpt = body[:4000] + "\n...\n[region around the secret]\n" + body[s:e]
                    else:
                        file_excerpt = body[:16000]
                else:
                    file_excerpt = body
            except Exception as fe:
                file_excerpt = f"(could not fetch the file: {fe})"

        host_lines = []
        for h in req.live_hosts[:25]:
            techs = ", ".join(h.get("technologies", [])[:8])
            host_lines.append(f"- {h.get('url','')} [{h.get('status_code','?')}] techs=[{techs}]")
        hosts_block = "\n".join(host_lines) or "(no live-host context provided)"

        lang = copilot_service._lang_instruction()
        prompt = f"""A secret was flagged in a JavaScript file during a bug bounty recon.

## The match
- Type label: {req.label or 'unknown'}
- Found in: {req.js_url or 'unknown'} (line {req.line if req.line is not None else '?'})
- Value: {req.match}
- Surrounding code: {req.context or 'n/a'}

## Live hosts / tech in this engagement
{hosts_block}

## Full JS file (or the relevant region)
```
{file_excerpt or '(no file content)'}
```

Analyze this concretely and practically. Answer:
1. **What is it?** Identify the secret/key type and the exact service/provider it belongs to (from its format/prefix and how it's used in the file).
2. **Is it likely live and sensitive, or a false positive / public client-side identifier?** Many keys in JS are meant to be public (e.g. Google Maps browser keys, Stripe publishable keys, Firebase config). Be honest about which this looks like.
3. **Impact if valid:** what could an attacker actually do with it.
4. **What to test next — concrete steps:** exact API calls / curl commands / tools to validate the key and probe what it unlocks (scopes, accessible data, billing). Reference the specific host(s) above where relevant.
5. **Severity** and whether it's likely in-scope/worth reporting.

Be specific to THIS key and file. No generic advice.{lang}"""

        response = await copilot_service._dispatch(prompt)
        return {"response": response}
    except Exception as e:
        logger.error(f"Copilot analyze-secret error: {e}")
        return {"response": f"Error: {e}"}


@router.post("/agent")
async def agent_chat(req: AgentChatRequest):
    """Agent chat: active investigation loop (fetch_url / read_finding) + full context."""
    try:
        message = req.message or ""
        if req.command_output:
            message = (
                f"## Last Command Output\n```\n{req.command_output[:4000]}\n```\n\n"
                "Analyze this output and suggest next steps. "
                "If you suggest a command, put it in a ```bash code block so the user can run it with one click.\n\n"
                + message
            )
        response = await copilot_service.agent_investigate(message, req.context, history=req.history)
        return {"response": response}
    except Exception as e:
        logger.error(f"Copilot agent error: {e}")
        return {"response": f"Error: {e}"}


@router.post("/tips")
async def get_tips(req: AnalyzeRequest):
    """Get quick contextual tips based on current data."""
    try:
        ctx = await copilot_service._build_full_context(req.context)
        if not ctx:
            return {"response": ""}
        lang = copilot_service._lang_instruction()
        prompt = (
            f"{ctx}\n\n---\n\n"
            "Based on the current recon data, give me 3-5 quick actionable tips or observations. "
            "Keep it brief — one line per tip. Focus on what stands out (interesting tech, potential vulns, "
            "attack vectors). Use bullet points. No long explanations."
            f"{lang}"
        )
        response = await copilot_service._dispatch(prompt)
        return {"response": response}
    except Exception as e:
        logger.error(f"Copilot tips error: {e}")
        return {"response": f"Error: {e}"}


@router.post("/report")
async def generate_report(req: ReportRequest):
    """Generate professional bug bounty report(s)."""
    try:
        response = await copilot_service.generate_report(req.finding_id)
        return {"response": response}
    except Exception as e:
        logger.error(f"Copilot report error: {e}")
        return {"response": f"Error: {e}"}
