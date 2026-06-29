"""
Standalone mitmproxy addon loaded by mitmdump at runtime.
Serializes each completed HTTP flow and POSTs it to the NexHunt FastAPI
server over localhost.  Runs inside the mitmdump process (separate from FastAPI).

Usage:
    NEXHUNT_PORT=17707 mitmdump -s /path/to/mitm_addon.py -p 8080
"""
import json
import os
import asyncio
import ipaddress
import threading
import time
import urllib.request
import urllib.error
import urllib.parse

_NEXHUNT_PORT = os.environ.get("NEXHUNT_PORT", "17707")
_FLOW_URL = f"http://127.0.0.1:{_NEXHUNT_PORT}/api/proxy/flow"
_CAPTURE_URL = f"http://127.0.0.1:{_NEXHUNT_PORT}/api/proxy/intercept/capture"
_WAIT_URL = f"http://127.0.0.1:{_NEXHUNT_PORT}/api/proxy/intercept/wait"
_STATE_PATH = os.environ.get("NEXHUNT_INTERCEPT_STATE", "")
_POOL_SIZE = 4

# Thread pool: avoid spawning a thread per flow
_semaphore = threading.BoundedSemaphore(_POOL_SIZE)
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _request_json(url: str, data: dict | None = None, timeout: float = 3) -> dict:
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"} if body is not None else {},
        method="POST" if body is not None else "GET",
    )
    with _opener.open(req, timeout=timeout) as response:
        return json.loads(response.read().decode() or "{}")


def _matches_scope(host: str, entry: str) -> bool:
    host = host.lower().rstrip(".").strip("[]")
    raw = entry.strip().lower()
    if not raw:
        return False

    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(raw, strict=False)
    except ValueError:
        pass

    if "://" in raw:
        candidate = urllib.parse.urlsplit(raw).hostname or ""
    else:
        candidate = urllib.parse.urlsplit(f"//{raw.split('/', 1)[0]}").hostname or raw
    candidate = candidate.removeprefix("*.").lstrip(".").rstrip(".")
    return bool(candidate) and (host == candidate or host.endswith(f".{candidate}"))


def _should_intercept(host: str) -> bool:
    if not _STATE_PATH:
        return False
    try:
        with open(_STATE_PATH, encoding="utf-8") as state_file:
            raw = state_file.read()
        # Backward compatibility with state files from older running backends.
        if raw.strip() in {"0", "1"}:
            return raw.strip() == "1"
        state = json.loads(raw)
        if not state.get("enabled", False):
            return False
        if not state.get("scope_only", False):
            return True
        scope = state.get("scope", [])
        out_of_scope = state.get("out_of_scope", [])
        return (
            any(_matches_scope(host, entry) for entry in scope)
            and not any(_matches_scope(host, entry) for entry in out_of_scope)
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False


def _post_flow(data: dict) -> None:
    """POST flow JSON to the FastAPI endpoint (runs in a worker thread)."""
    try:
        _request_json(_FLOW_URL, data, timeout=3)
    except (urllib.error.URLError, OSError):
        pass  # FastAPI not ready yet or NexHunt was closed
    finally:
        _semaphore.release()


class NexHuntAddon:
    def running(self):
        self._loop = asyncio.get_running_loop()

    def request(self, flow):
        """Pause requests while Intercept is ON and wait for Forward or Drop."""
        if not _should_intercept(flow.request.pretty_host):
            return

        flow.intercept()
        data = self._serialize_request(flow)
        thread = threading.Thread(
            target=self._hold_flow,
            args=(flow, data),
            daemon=True,
        )
        thread.start()

    def _hold_flow(self, flow, data: dict) -> None:
        """Register a held request and long-poll FastAPI for the user's action."""
        try:
            _request_json(_CAPTURE_URL, data, timeout=3)
        except (urllib.error.URLError, OSError, ValueError):
            self._schedule_release(flow, "forward", None)
            return

        failures = 0
        flow_id = urllib.parse.quote(flow.id, safe="")
        while flow.intercepted:
            try:
                command = _request_json(f"{_WAIT_URL}/{flow_id}", timeout=27)
                failures = 0
                action = command.get("action")
                if action in {"forward", "drop"}:
                    modified_request = command.get("modified_request")
                    if action == "drop":
                        # Use the exact same resume path as Forward, but point it
                        # at NexHunt's local sink. The upstream target is untouched.
                        action = "forward"
                        modified_request = (
                            "GET /api/proxy/intercept/dropped HTTP/1.1\n"
                            f"Host: 127.0.0.1:{_NEXHUNT_PORT}\n"
                            "X-NexHunt-Internal: intercept-drop\n\n"
                        )
                    self._schedule_release(flow, action, modified_request)
                    return
            except (urllib.error.URLError, OSError, ValueError):
                failures += 1
                if failures >= 3:
                    # Never leave the browser permanently hung if NexHunt closes.
                    self._schedule_release(flow, "forward", None)
                    return
                time.sleep(0.5)

    def _schedule_release(self, flow, action: str, modified_request: str | None) -> None:
        loop = getattr(self, "_loop", None)
        if loop and not loop.is_closed():
            loop.call_soon_threadsafe(self._release_flow, flow, action, modified_request)

    def _release_flow(self, flow, action: str, modified_request: str | None) -> None:
        if not flow.intercepted:
            return
        if modified_request:
            try:
                self._apply_raw_request(flow, modified_request)
            except (ValueError, UnicodeError):
                # Invalid edits must not strand a request; forward the original.
                pass
        flow.resume()

    @staticmethod
    def _apply_raw_request(flow, raw: str) -> None:
        normalized = raw.replace("\r\n", "\n")
        head, separator, body = normalized.partition("\n\n")
        lines = head.split("\n")
        if not lines or len(lines[0].split()) < 2:
            raise ValueError("Invalid HTTP request line")

        method, target = lines[0].split()[:2]
        headers: list[tuple[str, str]] = []
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers.append((name.strip(), value.lstrip()))

        request = flow.request
        request.method = method
        if target.startswith(("http://", "https://")):
            request.url = target
        else:
            request.path = target

        request.headers.clear()
        for name, value in headers:
            request.headers.add(name, value)

        host_header = next((value for name, value in headers if name.lower() == "host"), None)
        if host_header and not target.startswith(("http://", "https://")):
            parsed = urllib.parse.urlsplit(f"//{host_header}")
            if parsed.hostname:
                request.host = parsed.hostname
                if parsed.port:
                    request.port = parsed.port
                request.host_header = host_header

        request.content = body.encode("utf-8") if separator else b""
        if not body and not any(name.lower() == "content-length" for name, _ in headers):
            request.headers.pop("content-length", None)

    @staticmethod
    def _serialize_request(flow) -> dict:
        req = flow.request
        return {
            "id": flow.id,
            "request_method": req.method,
            "request_url": req.pretty_url,
            "request_host": req.pretty_host,
            "request_port": req.port,
            "request_path": req.path,
            "request_headers": dict(req.headers),
            "request_body": req.content.decode("utf-8", errors="replace") if req.content else None,
            "response_status": 0,
            "response_headers": {},
            "response_body": None,
            "content_type": None,
            "response_length": 0,
            "duration_ms": 0,
            "is_intercepted": True,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tags": [],
        }

    def response(self, flow):
        """Called for every completed HTTP(S) flow."""
        req = flow.request
        resp = flow.response
        if resp is None:
            return
        if req.headers.get("X-NexHunt-Internal") == "intercept-drop":
            return

        duration_ms = 0.0
        if hasattr(req, "timestamp_start") and hasattr(resp, "timestamp_end") and resp.timestamp_end:
            duration_ms = (resp.timestamp_end - req.timestamp_start) * 1000

        resp_body_str = None
        if resp.content:
            resp_body_str = resp.content[:1_000_000].decode("utf-8", errors="replace")

        data = {
            "id": flow.id,
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
