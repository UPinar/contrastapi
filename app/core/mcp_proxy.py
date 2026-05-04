"""MCP Streamable HTTP endpoint wrapper.

Wraps the MCP server's Starlette app in `_MCPIPForwardMiddleware`, which:
- Sets the real client IP in contextvars so MCP tool calls forward it
- Gates POST requests through `authenticate_sync` (Free 100/hr, Pro 1000/hr)
- Caps body buffering at 1MB to defeat memory DoS via chunked uploads
- Logs only `params.name` from JSON-RPC `tools/call` (no arguments)

Call `init_mcp(app)` from main.py AFTER all routes are registered. On import
failure (mcp package missing), it logs a warning and leaves `session_mgr=None`
so lifespan skips the MCP session manager wrap.
"""

import importlib.util
import json as _json
import logging
from datetime import UTC, datetime
from typing import Any

from auth import authenticate_sync as _mcp_authenticate
from config import BASE_DIR, MCP_TOOL_COUNT, VERSION
from fastapi import FastAPI, HTTPException
from starlette.requests import Request as _MCPStarletteRequest

logger = logging.getLogger("contrastapi")

session_mgr: Any = None  # set by init_mcp; consumed by lifespan factory in main.py
_mcp_mod: Any = None  # set by init_mcp; raw mcp_server module — read via mcp_module()


def mcp_module() -> Any:
    """Return the loaded MCP server module (raw mcp_server.py), or None if MCP failed to load."""
    return _mcp_mod


_MCP_TOOL_LOG = "/var/log/contrastapi/mcp_tools.jsonl"
_MCP_TOOL_BODY_LIMIT = 256 * 1024  # 256KB cap — larger body = skip (log gate)
_MCP_BUFFER_HARD_LIMIT = 1024 * 1024  # 1MB hard cap on POST body buffering — protects RAM


def _extract_tool_name(body_bytes: bytes) -> "str | None":
    """Parse JSON-RPC body, return tool name if method=tools/call, else None.

    Privacy: NEVER logs params.arguments — only params.name (tool identifier).
    Silent on any error.
    """
    if not body_bytes or len(body_bytes) > _MCP_TOOL_BODY_LIMIT:
        return None
    try:
        obj = _json.loads(body_bytes)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(obj, dict):
        return None
    if obj.get("method") != "tools/call":
        return None
    params = obj.get("params")
    if not isinstance(params, dict):
        return None
    name = params.get("name")
    if not isinstance(name, str) or not name:
        return None
    if len(name) > 64 or not name.replace("_", "").isalnum():
        return None
    return name


def _log_mcp_tool(name: str) -> None:
    """Append one JSON line to the tool usage log. Silent on any error."""
    try:
        now = datetime.now(UTC)
        line = (
            _json.dumps(
                {
                    "date": now.strftime("%Y-%m-%d"),
                    "ts": now.strftime("%H:%M"),
                    "tool": name,
                },
                separators=(",", ":"),
            )
            + "\n"
        )
        with open(_MCP_TOOL_LOG, "a") as f:
            f.write(line)
    except Exception:
        # Tool-usage logging is best-effort; never block the request path on a log write.
        pass


class _MCPIPForwardMiddleware:
    """ASGI wrapper around the MCP Starlette app: rate-limit gate + IP forwarding."""

    def __init__(self, asgi_app, client_ip_var, safe_ip_fn):
        self.app = asgi_app
        self._client_ip_var = client_ip_var
        self._safe_ip = safe_ip_fn

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            raw_headers = scope.get("headers", [])
            headers_map = dict(raw_headers)
            # Priority: CF-Connecting-IP (Cloudflare) > X-Real-IP (nginx) > XFF
            ip = (headers_map.get(b"cf-connecting-ip") or b"").decode().strip()
            if not ip:
                ip = (headers_map.get(b"x-real-ip") or b"").decode().strip()
            if not ip:
                xff = (headers_map.get(b"x-forwarded-for") or b"").decode()
                ip = xff.split(",")[0].strip() if xff else ""
            # App-layer rate-limit gate — POST only. POST carries the
            # JSON-RPC tool-call payload; that is what consumes Free
            # 100/hr or Pro 1000/hr. GET /mcp/ is the SSE listen loop
            # and the discovery info endpoint — both return a fixed
            # 14-byte "retry: 15000" or a small JSON blob, no DB / no
            # tool execution. Gating GET would 429 a normal MCP client
            # within ~25 minutes (240 reconnects/hr at 15s retry) before
            # it ever invokes a tool. nginx mcp_get zone (3,600 req/hr/IP)
            # still caps GET-flood abuse at the edge.
            if scope.get("method") == "POST":
                _gate_req = _MCPStarletteRequest(scope)
                try:
                    _mcp_authenticate(_gate_req, "/mcp/", cost=1)
                except HTTPException as _gate_exc:
                    _err_payload = {
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32000 if _gate_exc.status_code == 429 else -32001,
                            "message": _gate_exc.detail if isinstance(_gate_exc.detail, str) else "Rate limit exceeded",
                        },
                        "id": None,
                    }
                    _err_body = _json.dumps(_err_payload).encode()
                    _err_headers = [
                        [b"content-type", b"application/json"],
                        [b"content-length", str(len(_err_body)).encode()],
                    ]
                    if _gate_exc.status_code == 429:
                        # Faz 3: authenticate_sync stashes AuthCtx on
                        # request.state.auth BEFORE the 429 raise.
                        # ratelimit_reset is a DELTA in seconds (from
                        # ratelimit.get_reset_time), so it goes straight
                        # into Retry-After. Pre-Faz-3 code subtracted
                        # time.time() treating it as epoch — that always
                        # clamped to 1s. Fall back to 60s only if no
                        # AuthCtx (defensive — should never happen on the
                        # 429 path post-Faz-3).
                        _auth_mcp = getattr(_gate_req.state, "auth", None)
                        _retry_after = _auth_mcp.ratelimit_reset if _auth_mcp and _auth_mcp.ratelimit_reset > 0 else 60
                        _err_headers.append([b"retry-after", str(_retry_after).encode()])
                    await send(
                        {
                            "type": "http.response.start",
                            "status": _gate_exc.status_code,
                            "headers": _err_headers,
                        }
                    )
                    await send({"type": "http.response.body", "body": _err_body})
                    return
            # GET/HEAD → branch on Accept header
            if scope.get("method") in ("GET", "HEAD"):
                accept = headers_map.get(b"accept", b"").decode("latin-1").lower()
                if "text/event-stream" in accept:
                    # SSE-expecting client (undici, EventSource): send retry directive only.
                    # Sets reconnect window to 15s (default 3s), cutting per-agent GET surge ~80%.
                    sse_body = b"retry: 15000\n\n"
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 200,
                            "headers": [
                                [b"content-type", b"text/event-stream"],
                                [b"cache-control", b"no-cache"],
                                [b"content-length", str(len(sse_body)).encode()],
                                [b"vary", b"Accept"],
                                [b"x-mcp-keepalive-interval", b"15"],
                            ],
                        }
                    )
                    await send(
                        {"type": "http.response.body", "body": sse_body if scope.get("method") == "GET" else b""}
                    )
                    return

                body = _json.dumps(
                    {
                        "name": "ContrastAPI MCP Server",
                        "version": VERSION,
                        "transport": "streamable-http",
                        "method": "POST",
                        "tools": MCP_TOOL_COUNT,
                        "docs": "https://api.contrastcyber.com/mcp-setup",
                    }
                ).encode()
                await send(
                    {
                        "type": "http.response.start",
                        "status": 200,
                        "headers": [
                            [b"content-type", b"application/json"],
                            [b"content-length", str(len(body)).encode()],
                            [b"vary", b"Accept"],
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body if scope.get("method") == "GET" else b""})
                return
            # Normalize Accept header for POST only — tolerant probes
            # (Chiark, etc.) may omit it on initialize.
            if scope.get("method") == "POST":
                new_headers = list(raw_headers)
                accept_idx = next(
                    (i for i, (k, _) in enumerate(new_headers) if k.lower() == b"accept"),
                    None,
                )
                current = new_headers[accept_idx][1].decode("latin-1").lower() if accept_idx is not None else ""
                if "application/json" not in current or "text/event-stream" not in current:
                    canonical = (b"accept", b"application/json, text/event-stream")
                    if accept_idx is not None:
                        new_headers[accept_idx] = canonical
                    else:
                        new_headers.append(canonical)
                    scope = dict(scope)
                    scope["headers"] = new_headers
                # Buffer full body for tool-name extraction + replay to downstream app.
                # Hard cap protects against memory DoS via chunked uploads — MCP requests
                # are normally <10KB, so 1MB is generous.
                body_chunks = []
                cumulative = 0
                oversized = False
                more = True
                while more:
                    msg = await receive()
                    if msg["type"] == "http.request":
                        chunk = msg.get("body", b"")
                        if chunk and not oversized:
                            cumulative += len(chunk)
                            if cumulative > _MCP_BUFFER_HARD_LIMIT:
                                oversized = True
                                body_chunks = []  # drop already-buffered chunks
                            else:
                                body_chunks.append(chunk)
                        more = msg.get("more_body", False)
                    else:
                        break
                if oversized:
                    err = b'{"jsonrpc":"2.0","error":{"code":-32600,"message":"Request body too large"},"id":null}'
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 413,
                            "headers": [
                                [b"content-type", b"application/json"],
                                [b"content-length", str(len(err)).encode()],
                            ],
                        }
                    )
                    await send({"type": "http.response.body", "body": err})
                    return
                full_body = b"".join(body_chunks)
                # Extract + log tool name — best-effort, never raises
                tool_name = _extract_tool_name(full_body)
                if tool_name:
                    _log_mcp_tool(tool_name)
                # Replay receive: yield cached body once, then disconnect
                _sent = {"done": False}

                async def _replay_receive():
                    if not _sent["done"]:
                        _sent["done"] = True
                        return {"type": "http.request", "body": full_body, "more_body": False}
                    return {"type": "http.disconnect"}

                receive = _replay_receive
            # Validate IP before storing — reject spoofed/malformed values
            token = self._client_ip_var.set(self._safe_ip(ip))
            try:
                await self.app(scope, receive, send)
            finally:
                self._client_ip_var.reset(token)
        else:
            await self.app(scope, receive, send)


def init_mcp(app: FastAPI) -> None:
    """Load the MCP server module, mount its Starlette app at /mcp.

    Sets module-level `session_mgr` so the lifespan factory in main.py can
    pick it up via `lambda: mcp_proxy.session_mgr`.
    """
    global session_mgr, _mcp_mod
    try:
        spec = importlib.util.spec_from_file_location("mcp_server", str(BASE_DIR.parent / "mcp_server.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _mcp_mod = mod
        instance = mod.mcp
        client_ip_var = mod._client_ip_var
        safe_ip = mod._safe_ip
        starlette_app = instance.streamable_http_app()
        session_mgr = instance.session_manager
        app.mount("/mcp", _MCPIPForwardMiddleware(starlette_app, client_ip_var, safe_ip))
    except ImportError:
        logger.warning("MCP server not available (mcp package not installed)")
