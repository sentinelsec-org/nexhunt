"""
Wordlist management for brute force. Lists system wordlists (rockyou, seclists,
etc.) and lets the user create/edit custom lists scoped to a target.
"""
import os
import logging
import subprocess
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from nexhunt.config import settings
from nexhunt.licensing.guard import require_pro

router = APIRouter(prefix="/api/wordlists", tags=["wordlists"])
logger = logging.getLogger(__name__)

_CUSTOM_DIR = os.path.join(settings.db_dir, "wordlists", "custom")
os.makedirs(_CUSTOM_DIR, exist_ok=True)

_SYSTEM_DIRS = ["/usr/share/wordlists", "/usr/share/seclists"]
_MAX_EDIT_BYTES = 2 * 1024 * 1024
_line_cache: dict[str, int] = {}


def _count_lines(path: str, size: int) -> int | None:
    if path in _line_cache:
        return _line_cache[path]
    if size > 50 * 1024 * 1024:
        return None  # too big to count cheaply, leave unknown
    try:
        with open(path, "rb") as f:
            n = sum(1 for _ in f)
        _line_cache[path] = n
        return n
    except OSError:
        return None


def _scan_dir(base: str, category: str, custom: bool) -> list[dict]:
    out = []
    if not os.path.isdir(base):
        return out
    for root, _, files in os.walk(base):
        for fn in files:
            if not (fn.endswith(".txt") or fn.endswith(".lst") or "." not in fn):
                continue
            path = os.path.join(root, fn)
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size == 0:
                continue
            rel = os.path.relpath(path, base)
            out.append({
                "name": rel if custom else f"{category}/{rel}",
                "path": path,
                "size": size,
                "lines": _count_lines(path, size),
                "category": category,
                "custom": custom,
            })
    return out


class WordlistBody(BaseModel):
    name: str
    content: str


@router.get("")
async def list_wordlists():
    items: list[dict] = []
    for d in _SYSTEM_DIRS:
        cat = os.path.basename(d)
        items += _scan_dir(d, cat, custom=False)
    items += _scan_dir(_CUSTOM_DIR, "custom", custom=True)
    items.sort(key=lambda x: (not x["custom"], x["name"].lower()))
    return {"wordlists": items}


@router.post("", dependencies=[Depends(require_pro("Custom wordlists"))])
async def save_wordlist(body: WordlistBody):
    name = os.path.basename(body.name.strip())
    if not name:
        raise HTTPException(400, "Name is required")
    if not name.endswith(".txt"):
        name += ".txt"
    path = os.path.join(_CUSTOM_DIR, name)
    with open(path, "w") as f:
        f.write(body.content)
    _line_cache.pop(path, None)
    return {"status": "saved", "name": name, "path": path}


@router.get("/content")
async def get_content(name: str):
    path = os.path.join(_CUSTOM_DIR, os.path.basename(name))
    if not os.path.isfile(path):
        raise HTTPException(404, "Not found")
    if os.path.getsize(path) > _MAX_EDIT_BYTES:
        raise HTTPException(413, "File too large to edit")
    with open(path, errors="replace") as f:
        return {"name": os.path.basename(name), "content": f.read()}


@router.delete("/{name}", dependencies=[Depends(require_pro("Custom wordlists"))])
async def delete_wordlist(name: str):
    path = os.path.join(_CUSTOM_DIR, os.path.basename(name))
    if not os.path.isfile(path):
        raise HTTPException(404, "Not found")
    os.remove(path)
    _line_cache.pop(path, None)
    return {"status": "deleted"}


class GenerateRequest(BaseModel):
    tool: str  # "cewl" | "crunch" | "cupp"
    name: str
    # CeWL
    url: str | None = None
    depth: int = 2
    min_word_len: int = 5
    include_numbers: bool = False
    lowercase: bool = False
    # Crunch
    min_len: int | None = None
    max_len: int | None = None
    charset: str | None = None
    pattern: str | None = None
    # CUPP profile
    first_name: str | None = None
    last_name: str | None = None
    nickname: str | None = None
    birthdate: str | None = None
    partner: str | None = None
    partner_nick: str | None = None
    partner_birth: str | None = None
    pet: str | None = None
    company: str | None = None
    keywords: str | None = None
    cupp_leet: bool = True
    cupp_specials: bool = True
    cupp_numbers: bool = True


def _cupp_generate(body: GenerateRequest) -> list[str]:
    words = [w for w in [
        body.first_name, body.last_name, body.nickname,
        body.partner, body.partner_nick, body.pet, body.company,
    ] if w and w.strip()]
    for kw in (body.keywords or "").split("\n"):
        if kw.strip():
            words.append(kw.strip())

    nums: set[str] = set()
    for bdate in [body.birthdate, body.partner_birth]:
        if bdate:
            for part in bdate.replace("-", "/").replace(".", "/").split("/"):
                p = part.strip()
                if p:
                    nums.add(p)
                    nums.add(p.zfill(2))

    specials = ["!", "@", "!!", "123", "1234", "12345", "!@#", "!123"] if body.cupp_specials else []
    num_sfx  = ["1", "12", "123", "1234", "12345", "123456"]          if body.cupp_numbers  else []
    years    = ["2020", "2021", "2022", "2023", "2024", "2025", "2026"]

    out: set[str] = set()

    for word in words:
        w = word.strip()
        if not w:
            continue
        variants = [w, w.lower(), w.upper(), w.capitalize()]
        if body.cupp_leet:
            l = w.lower().replace("a","@").replace("e","3").replace("i","1").replace("o","0").replace("s","$")
            variants += [l, l.capitalize()]
        variants.append(w[::-1])

        for v in variants:
            out.add(v)
            for s in specials:
                out.add(v + s)
            for n in num_sfx:
                out.add(v + n)
            for n in nums:
                out.add(v + n)
                out.add(v + n + "!")
            for y in years:
                out.add(v + y)
                out.add(v + y + "!")

    for i, w1 in enumerate(words):
        for j, w2 in enumerate(words):
            if i == j:
                continue
            for sep in ["", "_", "-"]:
                combo = w1.lower() + sep + w2.lower()
                out.add(combo)
                out.add(combo.capitalize())
                for s in ["!", "123", "2024", "2025", "2026"]:
                    out.add(combo + s)
                for n in nums:
                    out.add(combo + n)

    return sorted(v for v in out if len(v) >= 4)


@router.post("/generate", dependencies=[Depends(require_pro("Custom wordlists"))])
async def generate_wordlist(body: GenerateRequest):
    name = os.path.basename(body.name.strip())
    if not name:
        raise HTTPException(400, "Name is required")
    if not name.endswith(".txt"):
        name += ".txt"
    path = os.path.join(_CUSTOM_DIR, name)

    if body.tool == "cewl":
        if not body.url or not body.url.strip():
            raise HTTPException(400, "URL is required for CeWL")
        url = body.url.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url
        base_cmd = [
            "cewl", url,
            "-d", str(max(1, min(body.depth, 5))),
            "-m", str(max(1, min(body.min_word_len, 20))),
            "-w", path,
        ]
        if body.include_numbers:
            base_cmd.append("--with-numbers")
        if body.lowercase:
            base_cmd.append("--lowercase")

        try:
            subprocess.run(base_cmd, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            raise HTTPException(504, "CeWL timed out after 120s")
        except FileNotFoundError:
            raise HTTPException(500, "cewl is not installed")

        if not os.path.exists(path) or os.path.getsize(path) == 0:
            alt_url = url.replace("https://", "http://", 1) if url.startswith("https://") else url.replace("http://", "https://", 1)
            alt_cmd = base_cmd.copy()
            alt_cmd[1] = alt_url
            try:
                subprocess.run(alt_cmd, capture_output=True, text=True, timeout=120)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        _line_cache.pop(path, None)
        size = os.path.getsize(path) if os.path.exists(path) else 0
        lines = _count_lines(path, size)
        return {"status": "done", "name": name, "path": path, "size": size, "lines": lines or 0}

    elif body.tool == "crunch":
        if body.min_len is None or body.max_len is None:
            raise HTTPException(400, "min_len and max_len are required for Crunch")
        min_l = max(1, min(int(body.min_len), 12))
        max_l = max(min_l, min(int(body.max_len), 12))
        charset = body.charset or "abcdefghijklmnopqrstuvwxyz0123456789"
        estimated = sum(len(charset) ** i for i in range(min_l, max_l + 1))
        if estimated > 10_000_000:
            raise HTTPException(400, f"Would generate ~{estimated:,} entries. Reduce length or charset.")
        cmd = ["crunch", str(min_l), str(max_l), charset, "-o", path]
        if body.pattern:
            cmd += ["-t", body.pattern]

    elif body.tool == "cupp":
        entries = _cupp_generate(body)
        if not entries:
            raise HTTPException(400, "No profile data provided")
        with open(path, "w") as f:
            f.write("\n".join(entries))
        _line_cache.pop(path, None)
        size = os.path.getsize(path)
        lines = len(entries)
        return {"status": "done", "name": name, "path": path, "size": size, "lines": lines}

    else:
        raise HTTPException(400, f"Unknown tool: {body.tool}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0 and not os.path.exists(path):
            raise HTTPException(500, f"{body.tool} error: {result.stderr[:400]}")
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "Generation timed out after 120s")
    except FileNotFoundError:
        raise HTTPException(500, f"{body.tool} is not installed")

    _line_cache.pop(path, None)
    size = os.path.getsize(path) if os.path.exists(path) else 0
    lines = _count_lines(path, size)
    return {"status": "done", "name": name, "path": path, "size": size, "lines": lines}
