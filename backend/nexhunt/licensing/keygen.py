"""
Keygen.sh License API client.
Docs: https://keygen.sh/docs/api/

Activation flow:
  activate()  -> validate key, create machine binding if needed, return state
  validate()  -> validate key + machine fingerprint scope
  deactivate() -> delete machine binding

All client-side ops use `Authorization: License {key}` (no seller token needed).
License creation (webhook only) uses `Authorization: Bearer {product_token}`.
"""
import logging
import httpx
from nexhunt.config import settings

logger = logging.getLogger(__name__)
_TIMEOUT = 12.0

# Codes returned in meta.code from validate-key
_OK_CODES = {"VALID"}
_DEAD_CODES = {"SUSPENDED", "BANNED", "REVOKED"}
_EXPIRED_CODES = {"EXPIRED"}
_NO_MACHINE_CODES = {"NO_MACHINES", "FINGERPRINT_SCOPE_MISMATCH"}
_LIMIT_CODES = {"TOO_MANY_MACHINES", "TOO_MANY_CORES"}


class KeygenError(Exception):
    pass


def _base() -> str:
    aid = settings.keygen_account_id
    if not aid:
        raise KeygenError("Keygen account not configured (set NEXHUNT_KEYGEN_ACCOUNT_ID)")
    return f"https://api.keygen.sh/v1/accounts/{aid}"


def _license_headers(key: str) -> dict:
    return {
        "Authorization": f"License {key}",
        "Accept": "application/vnd.api+json",
        "Content-Type": "application/vnd.api+json",
    }


def _token_headers() -> dict:
    token = settings.keygen_product_token
    if not token:
        raise KeygenError("Keygen product token not configured")
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.api+json",
        "Content-Type": "application/vnd.api+json",
    }


def _parse_errors(body: dict) -> str:
    errs = body.get("errors", [])
    if errs:
        return errs[0].get("detail") or errs[0].get("title") or "Unknown error"
    return "Unknown error"


def _normalize_validation(body: dict, machine_id: str) -> dict:
    code = body.get("meta", {}).get("code", "")
    lic = (body.get("data") or {}).get("attributes", {})
    if code in _DEAD_CODES:
        status = "disabled"
    elif code in _EXPIRED_CODES:
        status = "expired"
    else:
        status = "active"
    return {
        "instance_id": machine_id,
        "status": status,
        "expires_at": lic.get("expiry"),
        "customer_email": None,
        "product_id": settings.keygen_account_id,
        "keygen_code": code,
    }


async def _validate_key(key: str, fingerprint: str) -> dict:
    body = {
        "meta": {
            "key": key,
            "scope": {"fingerprint": fingerprint},
        }
    }
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(
            f"{_base()}/licenses/actions/validate-key",
            json=body,
            headers={"Accept": "application/vnd.api+json", "Content-Type": "application/vnd.api+json"},
        )
    if resp.status_code >= 500:
        raise KeygenError("License server unavailable")
    try:
        data = resp.json()
    except Exception:
        raise KeygenError(f"Unexpected response ({resp.status_code})")
    if resp.status_code == 404:
        raise KeygenError("Invalid license key")
    return data


async def _create_machine(key: str, fingerprint: str, name: str, license_id: str) -> str:
    body = {
        "data": {
            "type": "machines",
            "attributes": {"fingerprint": fingerprint, "name": name},
            "relationships": {
                "license": {"data": {"type": "licenses", "id": license_id}},
            },
        }
    }
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(
            f"{_base()}/machines",
            json=body,
            headers=_license_headers(key),
        )
    if resp.status_code >= 500:
        raise KeygenError("License server unavailable")
    data = resp.json()
    if resp.status_code == 422:
        # Machine already activated (concurrent request / previous run) — not an error
        errs = data.get("errors", [])
        code = errs[0].get("code", "") if errs else ""
        if code == "FINGERPRINT_TAKEN":
            return fingerprint  # machine_id = fingerprint
    if not resp.is_success:
        raise KeygenError(_parse_errors(data))
    return data["data"]["id"]


async def activate(key: str, machine_fingerprint: str, machine_name: str) -> dict:
    data = await _validate_key(key, machine_fingerprint)
    code = data.get("meta", {}).get("code", "")

    if code == "NOT_FOUND":
        raise KeygenError("Invalid license key")
    if code in _DEAD_CODES:
        raise KeygenError("License is suspended or revoked")
    if code in _EXPIRED_CODES:
        raise KeygenError("License has expired")
    if code in _LIMIT_CODES:
        raise KeygenError(
            "Machine activation limit reached. Deactivate another machine first "
            "(Settings → License → Deactivate)."
        )

    machine_id = machine_fingerprint
    if code in _NO_MACHINE_CODES:
        license_id = (data.get("data") or {}).get("id", "")
        machine_id = await _create_machine(key, machine_fingerprint, machine_name, license_id)

    return _normalize_validation(data, machine_id)


async def validate(key: str, machine_fingerprint: str) -> dict:
    data = await _validate_key(key, machine_fingerprint)
    code = data.get("meta", {}).get("code", "")
    if code == "NOT_FOUND":
        raise KeygenError("Invalid license key")
    return _normalize_validation(data, machine_fingerprint)


async def deactivate(key: str, machine_fingerprint: str) -> None:
    # Find the machine by fingerprint and delete it
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(
            f"{_base()}/machines",
            params={"fingerprint": machine_fingerprint},
            headers=_license_headers(key),
        )
    if not resp.is_success:
        return  # best-effort
    machines = resp.json().get("data", [])
    if not machines:
        return
    machine_id = machines[0]["id"]
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        await client.delete(
            f"{_base()}/machines/{machine_id}",
            headers=_license_headers(key),
        )


async def create_license(customer_email: str) -> str:
    """Create a new license via the product token. Used by the Stripe webhook."""
    policy_id = settings.keygen_policy_id
    if not policy_id:
        raise KeygenError("Keygen policy not configured (set NEXHUNT_KEYGEN_POLICY_ID)")
    body = {
        "data": {
            "type": "licenses",
            "attributes": {"name": f"NexHunt PRO - {customer_email}"},
            "relationships": {
                "policy": {"data": {"type": "policies", "id": policy_id}},
                "user": {
                    "data": {
                        "type": "users",
                        "attributes": {"email": customer_email},
                    }
                },
            },
        }
    }
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(
            f"{_base()}/licenses",
            json=body,
            headers=_token_headers(),
        )
    if resp.status_code >= 500:
        raise KeygenError("License server unavailable")
    data = resp.json()
    if not resp.is_success:
        raise KeygenError(_parse_errors(data))
    return data["data"]["attributes"]["key"]
