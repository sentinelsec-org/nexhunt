"""
Standalone mitmproxy addon loaded by mitmdump at runtime.
Serializes each completed HTTP flow and POSTs it to the NexHunt FastAPI
server over localhost.  Runs inside the mitmdump process (separate from FastAPI).

Usage:
    NEXHUNT_PORT=17707 mitmdump -s /path/to/mitm_addon.py -p 8080
"""
import json
import os
import threading
import time
import urllib.request
import urllib.error
import uuid

_NEXHUNT_PORT = os.environ.get("NEXHUNT_PORT", "17707")
_FLOW_URL = f"http://127.0.0.1:{_NEXHUNT_PORT}/api/proxy/flow"
_POOL_SIZE = 4

# Thread pool: avoid spawning a thread per flow
_semaphore = threading.BoundedSemaphore(_POOL_SIZE)


def _post_flow(data: dict) -> None:
    """POST flow JSON to the FastAPI endpoint (runs in a worker thread)."""
    try:
        body = json.dumps(data).encode()
        req = urllib.request.Request(
            _FLOW_URL,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3):
            pass
    except (urllib.error.URLError, OSError):
        pass  # FastAPI not ready yet or NexHunt was closed
    finally:
        _semaphore.release()


class NexHuntAddon:
    def response(self, flow):
        """Called for every completed HTTP(S) flow."""
        req = flow.request
        resp = flow.response
        if resp is None:
            return

        duration_ms = 0.0
        if hasattr(req, "timestamp_start") and hasattr(resp, "timestamp_end") and resp.timestamp_end:
            duration_ms = (resp.timestamp_end - req.timestamp_start) * 1000

        resp_body_str = None
        if resp.content:
            resp_body_str = resp.content[:1_000_000].decode("utf-8", errors="replace")

        data = {
            "id": str(uuid.uuid4()),
            "request_method": req.method,
            "request_url": req.pretty_url,
            "request_host": req.pretty_host,
            "request_port": req.port,
            "request_path": req.path,
            "request_headers": dict(req.headers),
            "request_body": req.content.decode("utf-8", errors="replace") if req.content else None,
            "response_status": resp.status_code,
            "response_headers": dict(resp.headers),
            "response_body": resp_body_str,
            "content_type": resp.headers.get("content-type", ""),
            "response_length": len(resp.content) if resp.content else 0,
            "duration_ms": duration_ms,
            "is_intercepted": False,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tags": [],
        }

        # Fire-and-forget in a background thread so the proxy isn't blocked
        if _semaphore.acquire(blocking=False):
            t = threading.Thread(target=_post_flow, args=(data,), daemon=True)
            t.start()
        # If all worker slots are busy, drop the flow rather than block


addons = [NexHuntAddon()]
