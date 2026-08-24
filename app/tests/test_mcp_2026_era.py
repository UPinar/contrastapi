"""2026-07-28 protocol-era wire coverage (mcp SDK v2 only).

The legacy (2025-era) suite lives in test_mcp.py / test_mcp_v123.py. These
tests pin the three behaviours `mcp-spec-check` treats as mandatory for the
2026-07-28 spec — server/discover, routing-header validation, and stateless
operation — plus the spec-required `resultType` on results.

They skip wholesale under the v1 SDK, which has no 2026 era.
"""

import pytest

pytest.importorskip("mcp.server.mcpserver", reason="v1 SDK has no 2026-07-28 era")

# Reserved envelope keys every modern request must carry (SEP-2575).
META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "spec-probe", "version": "1.0"},
    "io.modelcontextprotocol/clientCapabilities": {},
}
SENTINEL_CACHE = b'{"tools":[{"name":"_sentinel_era_"}]}'
MODERN_HEADERS = {
    "content-type": "application/json",
    "accept": "application/json, text/event-stream",
    "mcp-protocol-version": "2026-07-28",
}


def _modern(client, method, req_id, *, header_method=None):
    """POST a modern-era JSON-RPC request; header_method defaults to the body method."""
    headers = {**MODERN_HEADERS, "mcp-method": header_method or method}
    return client.post(
        "/mcp/",
        headers=headers,
        json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": {"_meta": META}},
    )


class TestServerDiscover:
    """`server/discover` replaces the initialize handshake in the stateless core."""

    def test_discover_advertises_capabilities(self, mcp_client):
        r = _modern(mcp_client, "server/discover", 1)
        assert r.status_code == 200
        result = r.json()["result"]
        assert "capabilities" in result
        assert "tools" in result["capabilities"]


class TestRoutingHeaders:
    """SEP-2243: a Mcp-Method header contradicting the body MUST be rejected."""

    def test_mismatch_on_tools_list_is_rejected(self, mcp_client):
        """The regression: the byte-splice fast-path used to answer this 200."""
        r = _modern(mcp_client, "tools/list", 2, header_method="tools/call")
        assert r.status_code == 400
        assert r.json()["error"]["code"] == -32020

    def test_mismatch_on_prompts_list_is_rejected(self, mcp_client):
        r = _modern(mcp_client, "prompts/list", 3, header_method="tools/call")
        assert r.status_code == 400
        assert r.json()["error"]["code"] == -32020

    def test_matching_header_is_accepted(self, mcp_client):
        r = _modern(mcp_client, "tools/list", 4)
        assert r.status_code == 200
        assert "error" not in r.json()


class TestResultType:
    """Every 2026-era result carries resultType (SEP-2322)."""

    def test_tools_list_carries_result_type(self, mcp_client):
        """The regression: the fast-path's cached bytes have no resultType."""
        r = _modern(mcp_client, "tools/list", 5)
        assert r.status_code == 200
        assert r.json()["result"]["resultType"] == "complete"

    def test_prompts_list_carries_result_type(self, mcp_client):
        r = _modern(mcp_client, "prompts/list", 6)
        assert r.status_code == 200
        assert r.json()["result"]["resultType"] == "complete"


class TestLegacyEraUnaffected:
    """The fast-path must still serve header-less legacy traffic (all of prod today)."""

    def test_legacy_tools_list_still_served(self, mcp_client):
        r = mcp_client.post(
            "/mcp/",
            headers={"content-type": "application/json", "accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}},
        )
        assert r.status_code == 200
        result = r.json()["result"]
        assert len(result["tools"]) > 0
        assert "resultType" not in result

    @pytest.mark.parametrize("version", ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"])
    def test_handshake_era_version_header_keeps_fast_path(self, mcp_client, monkeypatch, version):
        """A handshake-era value is NOT the modern era.

        Clients have sent `mcp-protocol-version` on every post-initialize
        request since 2025-06-18, so a presence-only era check would drop
        today's real traffic onto the SDK slow path. Era is decided by the
        VALUE, as the SDK decides it.

        Sentinel-pinned: the SDK's legacy path also answers 200 with no
        resultType, so only byte-equality with a planted cache proves the
        fast-path — not the response shape.
        """
        from core import mcp_proxy

        monkeypatch.setattr(mcp_proxy, "_tools_list_result_bytes", SENTINEL_CACHE)
        r = mcp_client.post(
            "/mcp/",
            headers={
                "content-type": "application/json",
                "accept": "application/json, text/event-stream",
                "mcp-protocol-version": version,
            },
            json={"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {}},
        )
        assert r.status_code == 200
        assert r.content == b'{"jsonrpc":"2.0","id":9,"result":' + SENTINEL_CACHE + b"}"

    def test_legacy_ignores_routing_header(self, mcp_client):
        """No protocol-version header ⇒ legacy era ⇒ mcp-method is not enforced."""
        r = mcp_client.post(
            "/mcp/",
            headers={
                "content-type": "application/json",
                "accept": "application/json, text/event-stream",
                "mcp-method": "tools/call",
            },
            json={"jsonrpc": "2.0", "id": 8, "method": "tools/list", "params": {}},
        )
        assert r.status_code == 200
        assert "error" not in r.json()


class TestEraGate:
    """The cache is gated on protocol era — the fix this suite exists for."""

    def test_modern_era_bypasses_the_cache(self, mcp_client, monkeypatch):
        """Mirror of the handshake sentinel: a modern request must reach the SDK."""
        from core import mcp_proxy

        monkeypatch.setattr(mcp_proxy, "_tools_list_result_bytes", SENTINEL_CACHE)
        r = _modern(mcp_client, "tools/list", 10)
        assert r.status_code == 200
        assert b"_sentinel_era_" not in r.content
        assert r.json()["result"]["resultType"] == "complete"

    def test_handshake_set_matches_the_sdk(self):
        """Drift guard: our hardcoded handshake set must equal the SDK's."""
        from core.mcp_proxy import _HANDSHAKE_PROTOCOL_VERSIONS
        from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS

        assert frozenset(HANDSHAKE_PROTOCOL_VERSIONS) == _HANDSHAKE_PROTOCOL_VERSIONS


class TestSubscriptionsListenBoundary:
    """We implement no subscriptions, so the SDK's SSE branch stays shut."""

    def test_listen_is_refused_before_the_sse_branch(self, mcp_client):
        """`subscriptions/listen` is the only method the SDK routes to SSE.

        The gate answers it with the SDK's own -32601 envelope rather than
        letting a stream open that nothing would ever feed.
        """
        r = _modern(mcp_client, "subscriptions/listen", 11)
        assert r.status_code == 404
        assert r.json()["error"]["code"] == -32601
        assert r.json()["id"] == 11

    def test_listen_with_a_notification_filter_does_not_hold_the_connection(self, mcp_client):
        """The availability guard: with a filter the SDK commits an endless stream.

        It is keyless and unmetered, and its ping cadence defeats a proxy
        idle-read timeout, so a few hundred of these exhaust the worker slots.
        A hang is the defect being guarded, so the call runs on a daemon thread
        and the deadline is the assertion.
        """
        import threading

        outcome = {}

        def _post():
            try:
                outcome["response"] = mcp_client.post(
                    "/mcp/",
                    headers={**MODERN_HEADERS, "mcp-method": "subscriptions/listen"},
                    json={
                        "jsonrpc": "2.0",
                        "id": 12,
                        "method": "subscriptions/listen",
                        "params": {"_meta": META, "notifications": {"toolsListChanged": True}},
                    },
                )
            except Exception as exc:
                outcome["error"] = exc

        caller = threading.Thread(target=_post, daemon=True)
        caller.start()
        caller.join(timeout=5)
        assert not caller.is_alive(), "listen held the connection open — the SSE branch is reachable"
        assert "error" not in outcome, f"listen raised: {outcome.get('error')!r}"
        assert outcome["response"].json()["error"]["code"] == -32601

    def test_gate_defers_to_the_real_receive_after_the_body_replay(self):
        """Pins the ASGI contract whose breach produced the bare-500 outage.

        Once the buffered body has been replayed, the closure must hand the real
        channel back. A synthetic `http.disconnect` made any handler watching for
        a disconnect cancel before answering, and uvicorn turned that into a
        21-byte `Internal Server Error`. This guard drives the middleware
        directly, so it keeps working even though no method reaches the SDK's
        SSE branch any more.
        """
        import asyncio
        import contextvars

        from core.mcp_proxy import _MCPIPForwardMiddleware

        body = b'{"jsonrpc":"2.0","id":13,"method":"resources/list","params":{}}'
        seen = []

        async def downstream(scope, receive, send):
            seen.append(await receive())
            seen.append(await receive())
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"{}"})

        reads = {"count": 0}

        async def real_receive():
            reads["count"] += 1
            if reads["count"] == 1:
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "probe.sentinel"}

        async def send(message):
            return None

        middleware = _MCPIPForwardMiddleware(
            downstream,
            contextvars.ContextVar("probe_client_ip", default=None),
            lambda value: value or "203.0.113.9",
            contextvars.ContextVar("probe_user_tier", default=None),
        )
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [(b"content-type", b"application/json"), (b"x-real-ip", b"203.0.113.9")],
        }
        asyncio.run(middleware(scope, real_receive, send))

        assert seen[0]["body"] == body
        assert seen[1] == {"type": "probe.sentinel"}
