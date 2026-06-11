from pydantic import BaseModel


class ScanRequest(BaseModel):
    target: str
    options: dict = {}
    project_id: str = ""


class FindingUpdate(BaseModel):
    status: str | None = None
    notes: str | None = None
