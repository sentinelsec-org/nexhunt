"""Stable per-machine fingerprint used to bind a license to one device."""
import hashlib
import os
import platform
import subprocess
import uuid


def _machine_id() -> str:
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(path) as f:
                v = f.read().strip()
                if v:
                    return v
        except OSError:
            continue
    return ""


def _mac() -> str:
    n = uuid.getnode()
    # getnode() sets the multicast bit when it had to invent a random MAC
    if (n >> 40) & 0x01:
        return ""
    return f"{n:012x}"


def _hostname() -> str:
    try:
        return platform.node() or ""
    except Exception:
        return ""


def get_machine_id() -> str:
    """Deterministic ID for this machine. Hashed so the raw identifiers never leave the box."""
    raw = "|".join([_machine_id(), _mac(), _hostname(), platform.system()])
    if not raw.strip("|"):
        # Last-resort fallback so activation still works on locked-down systems
        raw = os.path.expanduser("~") + platform.platform()
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def get_machine_name() -> str:
    """Human-friendly label sent to LemonSqueezy as the activation instance name."""
    host = _hostname() or "nexhunt"
    return f"{host}-{platform.system().lower()}"
