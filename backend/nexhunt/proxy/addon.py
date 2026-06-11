"""
Custom mitmproxy addon that captures HTTP flows and streams them
to the FastAPI WebSocket hub in real-time.
"""
import json
import asyncio
import logging
import time
import uuid
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)


class NexHuntAddon:
    """
    mitmproxy addon that:
    1. Captures every completed HTTP flow
    2. Stores it in SQLite via an async queue
    3. Broadcasts it to connected WebSocket clients
    """

    def __init__(self, ws_manager, db_queue: asyncio.Queue, fastapi_loop: asyncio.AbstractEventLoop, intercept_flag: list):
        self._ws_manager = ws_manager
        self._db_queue = db_queue
        self._fastapi_loop = fastapi_loop
        self._intercept_flag = intercept_flag  # mutable list[bool] so we can toggle without recreating addon

    def request(self, flow):
        """Called when a request is received. Handle intercept mode."""
        if self._intercept_flag[0]:
            flow.intercept()
            flow_data = self._serialize_flow_request(flow)
            self._schedule_broadcast("proxy_intercept", flow_data, "intercepted")

    def response(self, flow):
        """Called when a complete response is received."""
        flow_data = self._serialize_flow(flow)

        # Push to DB queue (non-blocking)
        try:
            self._db_queue.put_nowait(flow_data)
        except asyncio.QueueFull:
            pass  # Drop if queue is full to avoid backpressure

        # Broadcast to frontend
        self._schedule_broadcast("proxy_feed", flow_data, "new_flow")

    def _serialize_flow(self, flow) -> dict:
        """Serialize a complete mitmproxy flow to a dict."""
        req = flow.request
        resp = flow.response

        # Duration
        duration_ms = 0.0
        if hasattr(flow, "request") and hasattr(flow.request, "timestamp_start"):
            if resp and hasattr(resp, "timestamp_end") and resp.timestamp_end:
                duration_ms = (resp.timestamp_end - req.timestamp_start) * 1000

        # Response body (limit to 1MB)
        resp_body = None
        if resp and resp.content:
            resp_body = resp.content[:1_000_000]

        return {
            "id": str(uuid.uuid4()),
            "request_method": req.method,
            "request_url": req.pretty_url,
            "request_host": req.pretty_host,
            "request_port": req.port,
            "request_path": req.path,
            "request_headers": dict(req.headers),
            "request_body": req.content.decode("utf-8", errors="replace") if req.content else None,
            "response_status": resp.status_code if resp else 0,
            "response_headers": dict(resp.headers) if resp else {},
            "response_body": resp_body.decode("utf-8", errors="replace") if resp_body else None,
            "content_type": resp.headers.get("content-type", "") if resp else "",
            "response_length": len(resp_body) if resp_body else 0,
            "duration_ms": duration_ms,
            "is_intercepted": False,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tags": [],
        }

    def _serialize_flow_request(self, flow) -> dict:
        """Serialize only the request part (for intercept)."""
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

    def _schedule_broadcast(self, channel: str, data: dict, event: str):
        """Thread-safe: schedule a coroutine on the FastAPI event loop."""
        try:
            asyncio.run_coroutine_threadsafe(
                self._ws_manager.broadcast(channel, data, event),
                self._fastapi_loop
            )
        except RuntimeError:
            pass  # Loop may be closing
