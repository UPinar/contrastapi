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
from config import (
    BASE_DIR,
    COST_AUDIT,
    COST_TECH_CVE_AUDIT,
    COST_THREAT_REPORT,
    FREE_HOURLY_LIMIT,
    MCP_TOOL_COUNT,
    PRO_HOURLY_LIMIT,
    UPGRADE_URL,
    VERSION,
    settings,
)
from fastapi import FastAPI, HTTPException
from starlette.requests import Request as _MCPStarletteRequest

logger = logging.getLogger("contrastapi")

session_mgr: Any = None  # set by init_mcp; consumed by lifespan factory in main.py
_mcp_mod: Any = None  # set by init_mcp; raw mcp_server module — read via mcp_module()
# Pre-serialized tools/list "result" portion (without JSON-RPC envelope) — set
# by build_and_set_tools_list_cache() at lifespan startup. Per-request id is
# concatenated via byte template at request time; eliminates ~80-120ms of
# FastMCP Pydantic→JSON serialization per Smithery probe.
_tools_list_result_bytes: "bytes | None" = None
# v1.32.4: Composite tools that invoke multiple internal sub-operations
# inline pay a weighted credit cost so Free-tier users cannot draw N units
# of upstream work while burning a single credit. Atomic tools (default)
# are absent from the map and fall through to cost=1.
#
# Tools listed here charge the MCP gate the mapped cost. For tools that
# ALSO expose a REST endpoint, listing them here is SAFE ONLY when the MCP
# wrapper calls the shared `_impl()` helper directly (Pattern B refactor)
# instead of HTTP-hopping to REST via `_aget()`. A wrapper that still calls
# `_aget()` MUST stay out of the map — otherwise the REST gate + MCP gate
# both fire on a single call (double-charge).
#
# v1.32.4 Pattern B shipped: `audit_domain` (Batch 4) + `threat_report`
# (Batch 5). `domain_vulns` still HTTP-hops via `_aget()` → stays out.
_TOOL_COST: dict[str, int] = {
    "audit_domain": COST_AUDIT,
    "threat_report": COST_THREAT_REPORT,
    "tech_stack_cve_audit": COST_TECH_CVE_AUDIT,
}

# v1.32.5 / v1.32.7: experimental probe methods the MCP SDK doesn't implement.
# Smithery decays catalog score for every -32601/-32602 response — short-circuit
# known-safe probes with an empty-array body keyed by the last URI segment.
# Bytes literal (not dict) so the middleware can concat without JSON-encoding
# per request. Add a new entry only after verifying the probe is safe and idem-
# potent — anything that would normally do real work belongs in tools/call.
_SMITHERY_PROBE_RESULT: dict[str, bytes] = {
    "triggers/list": b'{"triggers":[]}',
    "ai.smithery/events/list": b'{"events":[]}',
}


def mcp_module() -> Any:
    """Return the loaded MCP server module (raw mcp_server.py), or None if MCP failed to load."""
    return _mcp_mod


def mcp_session_mgr() -> Any:
    """Return the MCP session manager set by init_mcp, or None if MCP failed to load."""
    return session_mgr


_SLIM_ANNOT_KEYS = ("description", "title", "examples", "default")
_SLIM_NAME_MAPS = ("properties", "$defs", "definitions", "patternProperties")


def _slim_output_schema(schema: object) -> None:
    """Drop JSON-Schema annotation keywords (description/title/examples/default)
    from a tool outputSchema in place. Keys inside properties/$defs/definitions/
    patternProperties are field/model NAMES, not keywords — never popped; only
    their subschema values are recursed. Keeps every field declaration +
    type/required/$ref/$defs structure (0 dangling $ref, spec-valid; ~57% wire
    reduction). WIRE-only: mutates the model_dump()ed dict, never the FastMCP
    tool objects, so internal mcp.list_tools() and tools/call structuredContent
    are unaffected.
    """
    if isinstance(schema, dict):
        for _k in _SLIM_ANNOT_KEYS:
            schema.pop(_k, None)
        for _key, _val in schema.items():
            if _key in _SLIM_NAME_MAPS and isinstance(_val, dict):
                for _sub in _val.values():
                    _slim_output_schema(_sub)
            else:
                _slim_output_schema(_val)
    elif isinstance(schema, list):
        for _v in schema:
            _slim_output_schema(_v)


async def build_and_set_tools_list_cache() -> "int | None":
    """Pre-serialize the FastMCP tools/list result and stash it on the module.

    Called once at lifespan startup (after init_mcp + sigma load). Per-request
    `id` is concatenated via byte template in the middleware fast-path, so the
    cached bytes here contain only the static `result` portion.

    Best-effort: returns the cached byte length on success, None on failure
    (mcp module missing, list_tools raised). Never raises — a None cache
    falls through to the FastMCP slow path.
    """
    global _tools_list_result_bytes
    mod = mcp_module()
    if mod is None:
        return None
    try:
        tools = await mod.mcp.list_tools()
        result = {"tools": [t.model_dump(mode="json", exclude_none=True) for t in tools]}
        for _t in result["tools"]:
            _osch = _t.get("outputSchema")
            if isinstance(_osch, dict):
                _slim_output_schema(_osch)
        _tools_list_result_bytes = _json.dumps(result, separators=(",", ":")).encode()
        logger.info("tools/list cache pre-serialized: %d bytes", len(_tools_list_result_bytes))
        return len(_tools_list_result_bytes)
    except Exception as e:
        # Log only the exception class name — the str() of a Pydantic
        # ValidationError appends a docs URL that leaks the Pydantic minor
        # version (CWE-200). Same sterilization pattern as the fast-path
        # exception handler below.
        logger.warning("Failed to pre-serialize tools/list (%s)", type(e).__name__)
        return None


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

    def __init__(self, asgi_app, client_ip_var, safe_ip_fn, user_tier_var):
        self.app = asgi_app
        self._client_ip_var = client_ip_var
        self._safe_ip = safe_ip_fn
        self._user_tier_var = user_tier_var

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            # Pattern B token: captured only when the tools/call gate succeeds
            # below; reset in the finally block alongside _client_ip_var so the
            # tier value cannot bleed past the request scope.
            _tier_token = None
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
                            [b"cache-control", b"public, max-age=300"],
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
                # Lazy-rebuild: a tools/list with an id but a None cache
                # (startup build failed / test cleared) would otherwise fall
                # to the fat FastMCP slow path. Rebuild the slim cache once so
                # the fast-path below serves slimmed bytes; only a still-None
                # rebuild (FastMCP broken) falls through.
                if (
                    _method == "tools/list"
                    and _tools_list_result_bytes is None
                    and isinstance(_rpc, dict)
                    and "id" in _rpc
                ):
                    await build_and_set_tools_list_cache()
                # Fast-path: tools/list is deterministic except for the JSON-RPC
                # id field. Serve pre-serialized result bytes with the id spliced
                # in at the byte level — sub-millisecond vs ~80-120ms FastMCP
                # Pydantic→JSON. Falls through to the slow path if cache is None
                # (startup failure or monkeypatched in tests) or if the request
                # is a JSON-RPC notification (no "id" key — spec §5.3 forbids a
                # response, FastMCP handles that correctly).
                if (
                    _method == "tools/list"
                    and _tools_list_result_bytes is not None
                    and isinstance(_rpc, dict)
                    and "id" in _rpc
                ):
                    try:
                        _req_id_bytes = _json.dumps(_rpc["id"]).encode()
                        _fp_body = (
                            b'{"jsonrpc":"2.0","id":' + _req_id_bytes + b',"result":' + _tools_list_result_bytes + b"}"
                        )
                        await send(
                            {
                                "type": "http.response.start",
                                "status": 200,
                                "headers": [
                                    [b"content-type", b"application/json"],
                                    [b"content-length", str(len(_fp_body)).encode()],
                                ],
                            }
                        )
                        await send({"type": "http.response.body", "body": _fp_body})
                        return
                    except Exception as _fp_exc:
                        # Log only the exception class name — the str() of a
                        # Pydantic ValidationError appends a docs URL that leaks
                        # the Pydantic minor version (CWE-200). _sterilize_fastmcp_tool_errors
                        # patches the tool-call path; this path is separate.
                        logger.warning(
                            "tools/list fast-path failed (%s), falling through to slow path",
                            type(_fp_exc).__name__,
                        )
                # v1.32.5 / v1.32.7: Smithery (and other catalog indexers)
                # probe experimental method names that the MCP SDK does not
                # implement. Without intervention FastMCP returns -32601/-32602
                # for every probe and Smithery decays the server score under a
                # rolling window (observed 99→85 over ~5 days). Short-circuit
                # known-safe probes with an empty-array result keyed by the
                # last URI segment ("supported, none exposed").
                #
                # v1.32.7 diagnosis (S241 SMITHERY_PROBE debug log): Smithery's
                # actual probe is `ai.smithery/events/list`, NOT `triggers/list`
                # as their user-facing "Failed to list triggers" inspector text
                # suggests. We cover both: `triggers/list` for forward-compat
                # with the MCP draft spec, `ai.smithery/events/list` for the
                # current Smithery scoring criterion.
                #
                # `_rpc["id"] is not None` excludes JSON-RPC notifications:
                # spec §5.3 forbids responding to notifications; `"id" in _rpc`
                # alone would accept `{"id": null}` which some clients use as
                # an intentional drop-response signal.
                if (
                    isinstance(_method, str)
                    and _method in _SMITHERY_PROBE_RESULT
                    and isinstance(_rpc, dict)
                    and "id" in _rpc
                    and _rpc["id"] is not None
                ):
                    try:
                        _req_id_bytes = _json.dumps(_rpc["id"]).encode()
                        _trig_body = (
                            b'{"jsonrpc":"2.0","id":'
                            + _req_id_bytes
                            + b',"result":'
                            + _SMITHERY_PROBE_RESULT[_method]
                            + b"}"
                        )
                        await send(
                            {
                                "type": "http.response.start",
                                "status": 200,
                                "headers": [
                                    [b"content-type", b"application/json"],
                                    [b"content-length", str(len(_trig_body)).encode()],
                                ],
                            }
                        )
                        await send({"type": "http.response.body", "body": _trig_body})
                        return
                    except Exception as _tg_exc:
                        logger.warning(
                            "Smithery probe fast-path failed for %s (%s), falling through",
                            _method,
                            type(_tg_exc).__name__,
                        )
                if _method == "tools/call":
                    _gate_req = _MCPStarletteRequest(scope)
                    # Cost lookup with input validation mirroring _extract_tool_call
                    # (line 185): bound length and alphanumeric+underscore only. An
                    # oversized or whitespace/control-laden name from a crafted body
                    # falls through to cost=1, but the downstream FastMCP dispatcher
                    # rejects it anyway — never reaches a registered tool.
                    _cost = 1
                    try:
                        _params = _rpc.get("params") if isinstance(_rpc, dict) else None
                        if isinstance(_params, dict):
                            _maybe_name = _params.get("name")
                            if (
                                isinstance(_maybe_name, str)
                                and _maybe_name
                                and len(_maybe_name) <= 64
                                and _maybe_name.replace("_", "").isalnum()
                            ):
                                _cost = _TOOL_COST.get(_maybe_name, 1)
                    except (AttributeError, TypeError):
                        _cost = 1
                    try:
                        _mcp_authenticate(_gate_req, "/mcp/", cost=_cost)
                        # Pattern B foundation: publish the resolved tier so MCP
                        # tool wrappers (audit_domain, threat_report — Batches
                        # 4-5) can gate Pro-only sub-calls without HTTP-hopping
                        # back to require_auth. Token captured so the finally
                        # block at the bottom of __call__ resets it — same
                        # request-scoped lifecycle as _client_ip_var.
                        _auth_resolved = getattr(_gate_req.state, "auth", None)
                        if _auth_resolved is not None:
                            _tier_token = self._user_tier_var.set(_auth_resolved.tier)
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
                if _tier_token is not None:
                    self._user_tier_var.reset(_tier_token)
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
        user_tier_var = mod._user_tier_var
        safe_ip = mod._safe_ip
        starlette_app = instance.streamable_http_app()
        session_mgr = instance.session_manager
        _sterilize_fastmcp_tool_errors()
        app.mount("/mcp", _MCPIPForwardMiddleware(starlette_app, client_ip_var, safe_ip, user_tier_var))
    except ImportError:
        logger.warning("MCP server not available (mcp package not installed)")
