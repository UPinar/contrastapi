"""MCP Streamable HTTP endpoint wrapper.

Wraps the MCP server's Starlette app in `_MCPIPForwardMiddleware`, which:
- Sets the real client IP in contextvars so MCP tool calls forward it
- Gates POST requests through `authenticate_sync` (Free FREE_HOURLY_LIMIT, Pro PRO_HOURLY_LIMIT — see config.py)
- Caps body buffering at 1MB to defeat memory DoS via chunked uploads
- Logs `tools/call` name + a metadata-only subset of arguments (filter /
  pagination / sort flags). PII (email/phone/username/domain/ip/cve_id/
  query/...) is dropped at extraction time per privacy.html.

Call `init_mcp(app)` from main.py AFTER all routes are registered. On import
failure (mcp package missing), it logs a warning and leaves `session_mgr=None`
so lifespan skips the MCP session manager wrap.
"""

import importlib.util
import json as _json
import logging
import re as _re
from datetime import UTC, datetime
from typing import Any

from auth import authenticate_sync as _mcp_authenticate
from config import BASE_DIR, FREE_HOURLY_LIMIT, MCP_TOOL_COUNT, PRO_HOURLY_LIMIT, UPGRADE_URL, VERSION, settings
from fastapi import FastAPI, HTTPException
from starlette.requests import Request as _MCPStarletteRequest

logger = logging.getLogger("contrastapi")

session_mgr: Any = None  # set by init_mcp; consumed by lifespan factory in main.py
_mcp_mod: Any = None  # set by init_mcp; raw mcp_server module — read via mcp_module()


def mcp_module() -> Any:
    """Return the loaded MCP server module (raw mcp_server.py), or None if MCP failed to load."""
    return _mcp_mod


def mcp_session_mgr() -> Any:
    """Return the MCP session manager set by init_mcp, or None if MCP failed to load."""
    return session_mgr


_MCP_TOOL_LOG = str(settings.mcp_tool_log_path)
_MCP_TOOL_BODY_LIMIT = 256 * 1024  # 256KB cap — larger body = skip (log gate)
_MCP_BUFFER_HARD_LIMIT = 1024 * 1024  # 1MB hard cap on POST body buffering — protects RAM

# v1.30.1 — metadata-only allowlist. v1.30.0 (commit e88aeec) shipped a wider
# allowlist that included PII keys (email/phone/username/domain/ip/cve_id/
# query/...), contradicting privacy.html which states query inputs are NOT
# stored. This narrowed set keeps only result-filter, pagination, sort, and
# variant flags so usage analytics still work but no user query content
# reaches disk. Auth surface (Authorization/api_key/token/secret/password)
# is also dropped because it is not in this set.
#
# Adding any PII / query-content key here will fail tests/test_mcp_privacy.py.
_ALLOWED_TOOL_PARAM_KEYS = frozenset(
    {
        # Result filtering thresholds
        "severity",
        "kev",
        "epss_min",
        "cvss_min",
        "cvss_max",
        # Date range
        "published_after",
        "published_before",
        # Pagination / sort / variants
        "sort",
        "limit",
        "offset",
        "include",
        "tagged",
        "page",
        "max_results",
        "lite",
        "method",
    }
)
_TOOL_PARAM_VALUE_MAX_LEN = 64

# Shape filter for string metadata values. Legitimate values are short
# alphanumeric tokens (severity=HIGH, sort=epss, published_after=2024-01-01,
# include=full,refs). Anything containing whitespace, control chars, `@`,
# or punctuation outside `._-:,` is rejected — closes the PII-embedding
# bypass where an attacker hides PII inside a metadata string value
# (e.g. {"severity": "HIGH\nalice@acme.com"} would otherwise pass the
# key-allowlist and land on disk).
_METADATA_VALUE_SHAPE = _re.compile(r"^[A-Za-z0-9._\-:,]+$")


def _sanitize_tool_params(args: object) -> dict:
    """Filter MCP tool arguments to the allowlist + shape-check values.

    Two layers of defense:
    1. Key-allowlist — non-`_ALLOWED_TOOL_PARAM_KEYS` keys are dropped
       (closes the secret/auth-key leak path).
    2. Value-shape — string values must match `_METADATA_VALUE_SHAPE`
       (alphanumeric + `._-:,`, ≤64 chars after truncation). This closes
       the PII-embedding bypass: `{"severity": "HIGH\\nalice@acme.com"}`
       would otherwise pass the key-allowlist and land on disk.

    Scalar-only: non-scalar values (lists, dicts, tuples) are silently
    dropped. Empty/None values are also dropped to keep log lines compact.
    """
    if not isinstance(args, dict):
        return {}
    out: dict = {}
    for k, v in args.items():
        if k not in _ALLOWED_TOOL_PARAM_KEYS:
            continue
        if v is None or v == "":
            continue
        if isinstance(v, (bool, int, float)):
            out[k] = v
        elif isinstance(v, str):
            truncated = v[:_TOOL_PARAM_VALUE_MAX_LEN]
            if _METADATA_VALUE_SHAPE.match(truncated):
                out[k] = truncated
            # Else: shape mismatch (whitespace, @, control char, ...) → drop.
        # Non-scalar values silently dropped — see docstring.
    return out


def _extract_tool_call(body_bytes: bytes) -> "tuple[str, dict] | None":
    """Parse JSON-RPC body for method=tools/call. Returns (tool_name, sanitized_args) or None.

    Privacy: arguments are passed through `_sanitize_tool_params` which keeps
    only the metadata allowlist (filter / pagination / sort flags). PII keys
    (email, phone, username, domain, ip, cve_id, query, ...) and auth surface
    (Authorization, api_key, token, secret, password) are dropped before they
    reach disk. Silent on any error.
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
    return name, _sanitize_tool_params(params.get("arguments"))


def _extract_tool_name(body_bytes: bytes) -> "str | None":
    """Backward-compat wrapper — returns just the tool name."""
    extracted = _extract_tool_call(body_bytes)
    return extracted[0] if extracted else None


def _log_mcp_tool(name: str, params: "dict | None" = None) -> None:
    """Append one JSON line to the tool usage log. Silent on any error.

    Shape: `{ts, tool, params}` where ts is ISO 8601 with millisecond
    precision and params is the metadata-only subset (filter / pagination /
    sort keys; see `_ALLOWED_TOOL_PARAM_KEYS`). Status + duration_ms
    intentionally deferred — capturing them requires wrapping the SSE-streamed
    response, more invasive than fits this batch.
    """
    try:
        now = datetime.now(UTC)
        # Millisecond-precision ISO 8601 with explicit Z. .isoformat() emits
        # microseconds + offset which is fine but verbose for log scanning.
        ts = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
        record: dict = {"ts": ts, "tool": name}
        if params:
            record["params"] = params
        line = _json.dumps(record, separators=(",", ":")) + "\n"
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
                # Parse JSON-RPC method to decide whether this request
                # consumes a credit. Only `tools/call` runs a tool and
                # therefore costs CPU/DB/external-API — metadata methods
                # (initialize, tools/list, resources/list, prompts/list,
                # ping, notifications/*, completion/complete) just return
                # server-info / catalogs and are free. nginx
                # mcp_post_keyless edge zone (2r/m burst=50) still gates
                # abusive flood at the perimeter. Malformed body → method
                # is None → not gated; the downstream MCP app returns
                # -32700 (parse error) without running any tool.
                try:
                    _rpc = _json.loads(full_body)
                except (ValueError, UnicodeDecodeError):
                    _rpc = None
                # JSON-RPC 2.0 supports batch requests (array of objects).
                # FastMCP does not handle them; treating a batch as
                # "no method" would skip the gate while the downstream
                # app might still attempt per-entry dispatch. Reject
                # explicitly to close the bypass: a single billable
                # tools/call hidden in a batch of listing methods would
                # otherwise pass our gate untaxed.
                if isinstance(_rpc, list):
                    _batch_err = (
                        b'{"jsonrpc":"2.0","error":{"code":-32600,"message":"Batch requests not supported"},"id":null}'
                    )
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 400,
                            "headers": [
                                [b"content-type", b"application/json"],
                                [b"content-length", str(len(_batch_err)).encode()],
                            ],
                        }
                    )
                    await send({"type": "http.response.body", "body": _batch_err})
                    return
                _method = _rpc.get("method") if isinstance(_rpc, dict) else None
                if _method == "tools/call":
                    _gate_req = _MCPStarletteRequest(scope)
                    try:
                        _mcp_authenticate(_gate_req, "/mcp/", cost=1)
                    except HTTPException as _gate_exc:
                        _err_payload = {
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32000 if _gate_exc.status_code == 429 else -32001,
                                "message": _gate_exc.detail
                                if isinstance(_gate_exc.detail, str)
                                else "Rate limit exceeded",
                            },
                            "id": None,
                        }
                        _err_headers = [[b"content-type", b"application/json"]]
                        if _gate_exc.status_code == 429:
                            _auth_mcp = getattr(_gate_req.state, "auth", None)
                            _retry_after = (
                                _auth_mcp.ratelimit_reset if _auth_mcp and _auth_mcp.ratelimit_reset > 0 else 60
                            )
                            _err_headers.append([b"retry-after", str(_retry_after).encode()])
                            _err_payload["error"]["data"] = {
                                "tier": _auth_mcp.tier if _auth_mcp else "free",
                                "limit": _auth_mcp.ratelimit_limit if _auth_mcp else FREE_HOURLY_LIMIT,
                                "pro_limit": PRO_HOURLY_LIMIT,
                                "retry_after_seconds": _retry_after,
                                "upgrade_url": UPGRADE_URL,
                            }
                        _err_body = _json.dumps(_err_payload).encode()
                        _err_headers.append([b"content-length", str(len(_err_body)).encode()])
                        await send(
                            {
                                "type": "http.response.start",
                                "status": _gate_exc.status_code,
                                "headers": _err_headers,
                            }
                        )
                        await send({"type": "http.response.body", "body": _err_body})
                        return
                # Extract + log tool name + sanitized params — best-effort, never raises
                extracted = _extract_tool_call(full_body)
                if extracted:
                    _log_mcp_tool(extracted[0], extracted[1])
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


def _sterilize_fastmcp_tool_errors() -> None:
    """Strip Pydantic 'errors.pydantic.dev/2.X/v/...' link from FastMCP ToolError
    messages. The library does `raise ToolError(f"Error executing tool {name}: {e}")`
    where `e` is a Pydantic ValidationError whose `__str__` appends the docs URL —
    leaks the Pydantic minor version (CWE-200). We wrap `Tool.run` once at startup.
    """
    try:
        import mcp.server.fastmcp.tools.base as _tool_base
    except ImportError:
        return
    if getattr(_tool_base.Tool, "_contrast_sterilized", False):
        return
    _orig_run = _tool_base.Tool.run

    async def _patched_run(self, *args, **kwargs):
        try:
            return await _orig_run(self, *args, **kwargs)
        except _tool_base.ToolError as e:
            msg = str(e)
            # Only sterilize Pydantic ValidationError repr — its presence is
            # uniquely signaled by the docs URL. Non-Pydantic ToolError text
            # passes through intact so `[type=...]` in unrelated messages is
            # not silently truncated.
            if "errors.pydantic.dev" in msg:
                # 1) Strip "For further information visit https://errors.pydantic.dev/2.X/v/..."
                #    (CWE-200 Pydantic minor-version disclosure).
                # 2) Strip "[type=missing, input_value={...}, input_type=dict]" —
                #    input_value echoes attacker-controlled request body, would
                #    surface to untrusted MCP clients / downstream LLM agents
                #    (CWE-79/116/117 + prompt-injection vector).
                msg = msg.split("For further information visit", 1)[0]
                msg = msg.split("[type=", 1)[0].rstrip()
            raise _tool_base.ToolError(msg) from None

    _tool_base.Tool.run = _patched_run
    _tool_base.Tool._contrast_sterilized = True


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
        _sterilize_fastmcp_tool_errors()
        app.mount("/mcp", _MCPIPForwardMiddleware(starlette_app, client_ip_var, safe_ip))
    except ImportError:
        logger.warning("MCP server not available (mcp package not installed)")
