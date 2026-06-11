from typing import List
from pydantic import BaseModel


class ReconRequest(BaseModel):
    target: str
    options: dict = {}


class HttpxProbeRequest(BaseModel):
    """Probe a list of subdomains/hosts with httpx to find live ones."""
    targets: List[str]
    options: dict = {}
