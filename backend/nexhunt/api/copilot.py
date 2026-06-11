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


class AgentChatRequest(BaseModel):
    message: str
    context: dict = {}
    command_output: str = ""   # last terminal output to include


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


@router.post("/agent")
async def agent_chat(req: AgentChatRequest):
    """Agent chat: full context + optional last terminal output."""
    try:
        parts = []

        if req.command_output:
            parts.append(
                f"## Last Command Output\n```\n{req.command_output[:4000]}\n```\n\n"
                "Analyze this output and suggest next steps. "
                "If you suggest a command, put it in a ```bash code block so the user can run it with one click."
            )

        lang = copilot_service._lang_instruction()
        if req.message:
            parts.append(req.message)

        full_msg = "\n\n".join(parts) if parts else req.message

        ctx = await copilot_service._build_full_context(req.context)
        if ctx:
            full_msg = f"{ctx}\n\n---\n\n{full_msg}"

        if lang:
            full_msg += lang

        response = await copilot_service._dispatch(full_msg)
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
