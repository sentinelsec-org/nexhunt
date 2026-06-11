"""
CVE Correlation: given detected technologies from httpx,
find relevant nuclei templates and known CVEs.
"""
import os
import re
import logging
from pathlib import Path
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/cve", tags=["cve"])
logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(os.path.expanduser("~/nuclei-templates"))


class CorrelateRequest(BaseModel):
    technologies: list[str]   # e.g. ["Apache 2.4.49", "WordPress 5.8", "PHP 7.4"]
    project_id: str = ""


@router.post("/correlate")
async def correlate(req: CorrelateRequest):
    """
    For each detected technology, find matching nuclei templates (CVEs + vulns).
    Returns grouped suggestions ready to run.
    """
    if not req.technologies:
        return {"results": []}

    results = []
    for tech_raw in req.technologies:
        tech = tech_raw.strip()
        if not tech:
            continue

        name, version = _parse_tech(tech)
        matches = _find_templates(name, version)

        results.append({
            "technology": tech,
            "name": name,
            "version": version,
            "template_count": len(matches),
            "templates": matches[:20],  # cap at 20 per tech
            "nuclei_cmd": _build_cmd(matches) if matches else None,
        })

    return {"results": results}


@router.get("/templates/search")
async def search_templates(q: str = ""):
    """Quick template search by keyword."""
    if not q or len(q) < 2:
        return {"templates": []}
    matches = _find_templates(q, "")
    return {"templates": matches[:30]}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_tech(tech: str) -> tuple[str, str]:
    """Split 'Apache 2.4.49' into ('apache', '2.4.49')."""
    parts = tech.strip().split()
    name = parts[0].lower() if parts else tech.lower()
    version = parts[1] if len(parts) > 1 else ""
    return name, version


def _find_templates(name: str, version: str) -> list[dict]:
    """Walk nuclei templates dir and find templates matching the tech name."""
    if not TEMPLATES_DIR.exists():
        return []

    name_lower = name.lower()
    version_parts = version.split(".")[:2] if version else []
    matches = []

    # Directories most likely to have tech-specific CVEs
    search_dirs = [
        TEMPLATES_DIR / "http" / "cves",
        TEMPLATES_DIR / "http" / "vulnerabilities",
        TEMPLATES_DIR / "http" / "exposed-panels",
        TEMPLATES_DIR / "http" / "misconfiguration",
        TEMPLATES_DIR / "http" / "default-logins",
    ]

    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        for yaml_file in search_dir.rglob("*.yaml"):
            file_lower = yaml_file.name.lower()
            # Match by filename containing the tech name
            if name_lower not in file_lower:
                continue
            meta = _read_template_meta(yaml_file)
            if not meta:
                continue
            # If version specified, filter by version range heuristic
            if version_parts and meta.get("affected_versions"):
                if not _version_matches(version_parts, meta["affected_versions"]):
                    continue
            matches.append({
                "id": meta.get("id", yaml_file.stem),
                "name": meta.get("name", yaml_file.stem),
                "severity": meta.get("severity", "unknown"),
                "description": meta.get("description", "")[:120],
                "path": str(yaml_file),
                "cve": meta.get("cve"),
                "cvss": meta.get("cvss"),
            })

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    matches.sort(key=lambda t: sev_order.get(t["severity"], 5))
    return matches


def _read_template_meta(path: Path) -> dict | None:
    """Extract id, name, severity, description from nuclei template YAML (no full parse)."""
    try:
        content = path.read_text(errors="replace")
        result: dict = {}

        m = re.search(r'^id:\s*(.+)$', content, re.MULTILINE)
        if m:
            result["id"] = m.group(1).strip()

        m = re.search(r'^\s+name:\s*(.+)$', content, re.MULTILINE)
        if m:
            result["name"] = m.group(1).strip()

        m = re.search(r'severity:\s*(\w+)', content)
        if m:
            result["severity"] = m.group(1).strip().lower()

        m = re.search(r'description:\s*[|\-]?\s*(.+)', content)
        if m:
            result["description"] = m.group(1).strip()

        # CVE reference
        m = re.search(r'CVE-(\d{4}-\d+)', content, re.IGNORECASE)
        if m:
            result["cve"] = f"CVE-{m.group(1)}"

        m = re.search(r'cvss-score:\s*([\d.]+)', content, re.IGNORECASE)
        if m:
            result["cvss"] = m.group(1)

        return result if result else None
    except Exception:
        return None


def _version_matches(version_parts: list[str], affected: str) -> bool:
    """Very rough version check — just checks major.minor presence in affected string."""
    return any(v in affected for v in version_parts)


def _build_cmd(templates: list[dict]) -> str:
    """Build a nuclei command to run all matched templates."""
    if not templates:
        return ""
    template_ids = [t["id"] for t in templates[:10] if t.get("id")]
    if not template_ids:
        return ""
    ids_flag = ",".join(template_ids)
    return f'nuclei -u TARGET -id "{ids_flag}" -severity critical,high,medium'
