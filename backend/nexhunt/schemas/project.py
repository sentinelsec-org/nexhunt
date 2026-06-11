from pydantic import BaseModel


class ProjectCreate(BaseModel):
    name: str
    scope: list[str] = []
    out_of_scope: list[str] = []
    scope_mode: str = "strict"
    notes: str = ""


class ProjectUpdate(BaseModel):
    name: str | None = None
    scope: list[str] | None = None
    out_of_scope: list[str] | None = None
    scope_mode: str | None = None
    notes: str | None = None


class TargetCreate(BaseModel):
    value: str
    type: str = "domain"
