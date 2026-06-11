"""
Update checker/applier. Updates are published as GitHub Releases by Sentinel.
check  -> compares local version against the latest release tag.
apply  -> downloads + verifies the release tarball, stages it, and asks Electron to
          relaunch; the actual swap is done outside the running process by apply-update.sh.
"""
import hashlib
import json
import logging
import os
import tarfile

import httpx
from fastapi import APIRouter, HTTPException

from nexhunt.config import settings
from nexhunt.version import __version__

router = APIRouter(prefix="/api/update", tags=["update"])
logger = logging.getLogger(__name__)

_STAGING = os.path.join(settings.db_dir, "updates")


def _parse(v: str) -> tuple:
    v = v.strip().lstrip("vV")
    parts = []
    for p in v.split(".")[:3]:
        num = "".join(c for c in p if c.isdigit())
        parts.append(int(num) if num else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


async def _latest_release() -> dict:
    url = f"https://api.github.com/repos/{settings.update_repo}/releases/latest"
    async with httpx.AsyncClient(timeout=12.0) as client:
        resp = await client.get(url, headers={"Accept": "application/vnd.github+json"})
    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail="No releases published yet")
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail="Could not reach update server")
    return resp.json()


@router.get("/check")
async def check():
    rel = await _latest_release()
    latest = rel.get("tag_name", "0.0.0")
    update_available = _parse(latest) > _parse(__version__)
    return {
        "current": __version__,
        "latest": latest.lstrip("vV"),
        "update_available": update_available,
        "notes": rel.get("body", ""),
        "url": rel.get("html_url", ""),
        "mandatory": "[mandatory]" in (rel.get("body", "").lower()),
    }


@router.post("/apply")
async def apply():
    rel = await _latest_release()
    latest = rel.get("tag_name", "0.0.0")
    if _parse(latest) <= _parse(__version__):
        return {"staged": False, "message": "Already up to date"}

    assets = {a["name"]: a["browser_download_url"] for a in rel.get("assets", [])}
    tar_name = next((n for n in assets if n.endswith(".tar.gz")), None)
    if not tar_name:
        raise HTTPException(status_code=502, detail="Release has no tarball asset")

    os.makedirs(_STAGING, exist_ok=True)
    tar_path = os.path.join(_STAGING, tar_name)
    await _download(assets[tar_name], tar_path)

    if "SHA256SUMS" in assets:
        sums_path = os.path.join(_STAGING, "SHA256SUMS")
        await _download(assets["SHA256SUMS"], sums_path)
        if not _verify_checksum(tar_path, sums_path, tar_name):
            os.remove(tar_path)
            raise HTTPException(status_code=502, detail="Checksum verification failed")

    extract_dir = os.path.join(_STAGING, "staged")
    _safe_extract(tar_path, extract_dir)

    marker = os.path.join(_STAGING, "pending.json")
    with open(marker, "w") as f:
        json.dump({"version": latest.lstrip("vV"), "dir": extract_dir}, f)

    return {"staged": True, "restart_required": True, "version": latest.lstrip("vV")}


async def _download(url: str, dest: str) -> None:
    async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
        async with client.stream("GET", url) as resp:
            if resp.status_code >= 400:
                raise HTTPException(status_code=502, detail=f"Download failed: {url}")
            with open(dest, "wb") as f:
                async for chunk in resp.aiter_bytes(65536):
                    f.write(chunk)


def _verify_checksum(tar_path: str, sums_path: str, name: str) -> bool:
    h = hashlib.sha256()
    with open(tar_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    digest = h.hexdigest()
    with open(sums_path) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 2 and parts[1].lstrip("*").endswith(name):
                return parts[0] == digest
    return False


def _safe_extract(tar_path: str, dest: str) -> None:
    with tarfile.open(tar_path) as tar:
        base = os.path.abspath(dest)
        for member in tar.getmembers():
            target = os.path.abspath(os.path.join(dest, member.name))
            if not target.startswith(base + os.sep) and target != base:
                raise HTTPException(status_code=502, detail="Unsafe path in archive")
        tar.extractall(dest)
