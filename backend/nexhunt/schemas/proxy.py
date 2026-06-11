from pydantic import BaseModel


class ProxySettings(BaseModel):
    port: int = 8080
    intercept_enabled: bool = False


class InterceptToggle(BaseModel):
    enabled: bool


class InterceptAction(BaseModel):
    flow_id: str
    action: str  # "forward" or "drop"
    modified_request: str | None = None


class RepeaterRequest(BaseModel):
    method: str
    url: str
    headers: dict[str, str] = {}
    body: str | None = None


class RawRepeaterRequest(BaseModel):
    raw_request: str
    host: str
    port: int = 80
    use_https: bool = False


class IntruderConfig(BaseModel):
    raw_request: str    # raw HTTP request with §markers§ around positions
    host: str
    port: int = 80
    use_https: bool = False
    attack_type: str = "sniper"   # sniper | cluster_bomb
    payloads: list[list[str]]     # one list per position
    concurrency: int = 10
    timeout: int = 10
