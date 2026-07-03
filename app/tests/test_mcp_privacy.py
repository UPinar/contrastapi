"""Privacy regression guard for MCP tool audit log.

Privacy policy (`app/templates/privacy.html`) states query inputs are NOT
stored. v1.30.0 commit `e88aeec` added a "structured audit log" feature whose
allowlist treated PII (email/phone/username/domain/ip/cve_id/query) as
"safe to record" — directly contradicting the policy.

These tests pin the contract: PII keys are DROPPED, metadata keys are KEPT.
Adding any PII key back to the keep-set will fail this test BEFORE ship
(/check pipeline runs `pytest -x`).
"""

import json as _json

import pytest

# Keys that reveal what the user is querying / who they are. MUST drop.
PII_KEYS = [
    # Identity
    ("email", "alice@acme.com"),
    ("phone", "+15551234567"),
    ("username", "octocat"),
    ("password", "hunter2"),
    # Network targets (user's intent)
    ("domain", "example.com"),
    ("url", "https://example.com/login"),
    ("uri", "/admin"),
    ("ip", "8.8.8.8"),
    ("asn", "AS15169"),
    ("hash", "44d88612fea8a8f36de82e1278abb02f"),
    ("indicator", "malicious.tld"),
    # CVE / CWE / vendor / product (user's research target)
    ("cve_id", "CVE-2021-44228"),
    ("cve_ids", "CVE-2021-44228,CVE-2024-12345"),
    ("cwe_id", "CWE-79"),
    ("cwe", "CWE-79"),
    ("product", "log4j"),
    ("vendor", "apache"),
    ("tag", "rce"),
    # ATLAS / D3FEND (user's adversary-research interest)
    ("technique_id", "AML.T0051"),
    ("defense_id", "D3-AT"),
    ("case_study_id", "AML.CS0021"),
    # Free text (worst case — arbitrary user input)
    ("query", "log4j rce internal employee search"),
    # Auth surface (must always be dropped)
    ("Authorization", "Bearer xyz"),
    ("api_key", "sk-secret-123"),
    ("token", "ghp_xxx"),
    ("secret", "shh"),
]

# Keys that describe HOW results are filtered/paginated, not WHAT the user
# is searching for. Safe to keep — they enable usage analytics without
# revealing query content.
METADATA_KEYS = [
    ("severity", "HIGH"),
    ("kev", True),
    ("epss_min", 0.5),
    ("cvss_min", 7.0),
    ("cvss_max", 10.0),
    ("sort", "epss"),
    ("limit", 25),
    ("offset", 0),
    ("include", "all"),
    ("tagged", True),
    ("page", 2),
    ("max_results", 100),
    ("lite", True),
    ("method", "GET"),
    ("published_after", "2024-01-01"),
    ("published_before", "2024-12-31"),
]


def _build_body(name: str, arguments: dict) -> bytes:
    return _json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    ).encode()


@pytest.mark.parametrize("key,value", PII_KEYS)
def test_pii_keys_are_dropped_from_extracted_params(key, value):
    """Every key in PII_KEYS must be dropped — privacy policy compliance."""
    from core.mcp_proxy import _extract_tool_call

    body = _build_body("cve_search", {key: value})
    extracted = _extract_tool_call(body)
    assert extracted is not None
    _, params = extracted
    assert key not in params, (
        f"PRIVACY REGRESSION: '{key}' leaked into audit log. "
        f"Privacy policy says we don't store query inputs. "
        f"If you need this for analytics, hash it instead."
    )


@pytest.mark.parametrize("key,value", METADATA_KEYS)
def test_metadata_keys_are_kept_in_extracted_params(key, value):
    """Every key in METADATA_KEYS must be retained — these power usage analytics."""
    from core.mcp_proxy import _extract_tool_call

    body = _build_body("cve_search", {key: value})
    extracted = _extract_tool_call(body)
    assert extracted is not None
    _, params = extracted
    assert key in params, (
        f"'{key}' is metadata (filter/pagination), not PII — should be kept for usage analytics but was dropped."
    )


def test_mixed_payload_drops_pii_keeps_metadata():
    """Realistic mixed payload — only metadata survives extraction."""
    from core.mcp_proxy import _extract_tool_call

    body = _build_body(
        "cve_search",
        {
            "product": "log4j",  # PII
            "vendor": "apache",  # PII
            "query": "rce vulnerable internal asset",  # PII (worst case)
            "severity": "HIGH",  # metadata
            "kev": True,  # metadata
            "limit": 25,  # metadata
            "Authorization": "Bearer secret",  # auth surface
        },
    )
    extracted = _extract_tool_call(body)
    assert extracted is not None
    _, params = extracted
    assert params == {"severity": "HIGH", "kev": True, "limit": 25}


def test_log_record_contains_no_pii(tmp_path, monkeypatch):
    """End-to-end: full log shape after _log_mcp_tool — no PII on disk."""
    from core import mcp_proxy

    log_path = tmp_path / "mcp_tools.jsonl"
    monkeypatch.setattr(mcp_proxy, "_MCP_TOOL_LOG", str(log_path))

    body = _build_body(
        "email_verify",
        {
            "email": "alice@acme.com",
            "domain": "acme.com",
            "limit": 10,
        },
    )
    extracted = mcp_proxy._extract_tool_call(body)
    assert extracted is not None
    mcp_proxy._log_mcp_tool(extracted[0], extracted[1])

    raw = log_path.read_text()
    # Substring scan — catches PII even if it sneaks into a non-`params` field.
    assert "alice@acme.com" not in raw
    assert "acme.com" not in raw
    record = _json.loads(raw.strip())
    assert record["tool"] == "email_verify"
    # Only metadata survives
    assert record.get("params") == {"limit": 10}


def test_log_record_client_channel(tmp_path, monkeypatch):
    """`client` field carries the coarse channel enum label; omitted when None
    so older log readers stay field-additive-safe. Never a raw UA/clientInfo."""
    from core import mcp_proxy

    log_path = tmp_path / "mcp_tools.jsonl"
    monkeypatch.setattr(mcp_proxy, "_MCP_TOOL_LOG", str(log_path))

    mcp_proxy._log_mcp_tool("cve_lookup", client="cursor")
    mcp_proxy._log_mcp_tool("cve_lookup")

    lines = [_json.loads(ln) for ln in log_path.read_text().splitlines()]
    assert lines[0]["client"] == "cursor"
    assert "client" not in lines[1]


def test_pii_value_substring_scan_in_log_line(tmp_path, monkeypatch):
    """Defense in depth: even if a PII key gets re-added later, the value
    substring scan catches the leak. Pins the contract that no recognizable
    PII string ever appears on disk regardless of which key carried it."""
    from core import mcp_proxy

    log_path = tmp_path / "mcp_tools.jsonl"
    monkeypatch.setattr(mcp_proxy, "_MCP_TOOL_LOG", str(log_path))

    sentinel_values = [
        "alice@acme.com",
        "+15551234567",
        "octocat",
        "example.com",
        "8.8.8.8",
        "AS15169",
        "CVE-2021-44228",
        "CWE-79",
        "log4j",
        "AML.T0051",
        "Bearer xyz",
    ]
    for v in sentinel_values:
        body = _build_body("cve_search", {"product": v, "domain": v, "query": v, "ip": v})
        extracted = mcp_proxy._extract_tool_call(body)
        if extracted:
            mcp_proxy._log_mcp_tool(extracted[0], extracted[1])

    raw = log_path.read_text() if log_path.exists() else ""
    for v in sentinel_values:
        assert v not in raw, f"PRIVACY LEAK: sentinel '{v}' appeared in audit log"


@pytest.mark.parametrize("metadata_key", [k for k, _ in METADATA_KEYS])
def test_list_values_under_metadata_keys_are_dropped(metadata_key):
    """Smuggling test: PII inside a list value under an allowlisted metadata
    key. Every metadata key is scalar, so list values must be dropped wholesale
    — otherwise a caller could log `{"limit": ["alice@acme.com"]}` and bypass
    the key-based PII filter."""
    from core.mcp_proxy import _extract_tool_call

    pii_payload = ["alice@acme.com", "CVE-2021-44228", "log4j"]
    body = _build_body("cve_search", {metadata_key: pii_payload})
    extracted = _extract_tool_call(body)
    assert extracted is not None
    _, params = extracted
    assert metadata_key not in params, (
        f"PRIVACY REGRESSION: list value under '{metadata_key}' was kept; PII inside list ({pii_payload}) reaches disk."
    )


def test_dict_values_under_metadata_keys_are_dropped():
    """Same as the list test but for dict values — `str(dict)` would leak
    structured key/value pairs into the audit log if not dropped."""
    from core.mcp_proxy import _extract_tool_call

    body = _build_body(
        "cve_search",
        {"limit": {"secret_field": "alice@acme.com"}, "severity": "HIGH"},
    )
    extracted = _extract_tool_call(body)
    assert extracted is not None
    _, params = extracted
    assert params == {"severity": "HIGH"}


@pytest.mark.parametrize(
    "value",
    [
        "HIGH\nalice@acme.com",  # newline injection
        "HIGH\r\nalice@acme.com",  # CRLF injection
        "HIGH\talice@acme.com",  # tab injection
        "HIGH alice@acme.com",  # space-separated PII
        "alice@acme.com",  # @ alone (email signal)
        "HIGH\x00alice@acme.com",  # NUL byte
        "HIGH\x1balice",  # ANSI escape
        "HIGH\x7falice",  # DEL
        "HIGH; SELECT * FROM users",  # SQL-ish chars
        "HIGH<script>",  # HTML tag chars
        "HIGH/etc/passwd",  # path-shaped (slash)
        "HIGH#comment",  # hash
        "HIGH\\nlogin",  # backslash
    ],
)
def test_string_values_with_unsafe_chars_are_dropped(value):
    """Defense against PII embedding in metadata string values. Even if the
    KEY is an allowlisted metadata key (severity, sort, etc.), the VALUE
    must match the metadata shape — alphanumeric + `._-:,` + ≤64 chars.
    Anything else (whitespace, control chars, @, /, <, >, ;, #, \\, ...)
    is dropped silently."""
    from core.mcp_proxy import _extract_tool_call

    body = _build_body("cve_search", {"severity": value, "kev": True})
    extracted = _extract_tool_call(body)
    assert extracted is not None
    _, params = extracted
    assert "severity" not in params, (
        f"PRIVACY REGRESSION: severity={value!r} accepted; PII could be embedded inside metadata string values."
    )
    # `kev` (bool) is unaffected — confirms only the malformed string was dropped
    assert params == {"kev": True}


@pytest.mark.parametrize(
    "value",
    [
        "HIGH",
        "LOW",
        "CRITICAL",
        "epss",
        "cvss_v3",
        "2024-01-01",  # ISO date
        "2024-12-31T23:59:59",  # ISO datetime
        "full,refs",  # comma-separated
        "kev:true",  # colon
        "GET",
        "all",
        "AB.cd_ef-gh",  # mixed allowed punctuation
    ],
)
def test_string_values_with_safe_chars_are_kept(value):
    """Legitimate metadata values (short alphanumeric tokens with allowed
    punctuation `._-:,`) pass the shape filter. Pins the contract that the
    filter does not over-reject."""
    from core.mcp_proxy import _extract_tool_call

    body = _build_body("cve_search", {"severity": value})
    extracted = _extract_tool_call(body)
    assert extracted is not None
    _, params = extracted
    assert params.get("severity") == value, f"OVER-REJECT: legitimate metadata value {value!r} was dropped."


def test_log_record_no_pii_via_value_embedding(tmp_path, monkeypatch):
    """End-to-end: even when the PAYLOAD smuggles PII inside an allowlisted
    key's string value, the audit log on disk contains no PII substring."""
    from core import mcp_proxy

    log_path = tmp_path / "mcp_tools.jsonl"
    monkeypatch.setattr(mcp_proxy, "_MCP_TOOL_LOG", str(log_path))

    sentinels = ["alice@acme.com", "+15551234567", "8.8.8.8", "log4j-rce"]
    for sentinel in sentinels:
        # Try to smuggle the sentinel inside a metadata key's value.
        for key in ("severity", "sort", "include", "method"):
            body = _build_body("cve_search", {key: f"HIGH\n{sentinel}"})
            extracted = mcp_proxy._extract_tool_call(body)
            if extracted:
                mcp_proxy._log_mcp_tool(extracted[0], extracted[1])

    raw = log_path.read_text() if log_path.exists() else ""
    for sentinel in sentinels:
        assert sentinel not in raw, f"PRIVACY LEAK via value embedding: '{sentinel}' appeared in audit log"


def test_metadata_keys_in_test_match_allowlist_exactly():
    """Drift guard: every key in `_ALLOWED_TOOL_PARAM_KEYS` must appear in
    METADATA_KEYS (so the keep-tests cover all of them), and vice versa.
    Adding a key to the allowlist without adding it here will fail this test
    — forcing the maintainer to confirm it is actually metadata, not PII."""
    from core.mcp_proxy import _ALLOWED_TOOL_PARAM_KEYS

    test_keys = {k for k, _ in METADATA_KEYS}
    missing_in_test = _ALLOWED_TOOL_PARAM_KEYS - test_keys
    extra_in_test = test_keys - _ALLOWED_TOOL_PARAM_KEYS
    assert not missing_in_test, (
        f"Allowlist has keys not covered by METADATA_KEYS test: {missing_in_test}. "
        f"Add them to METADATA_KEYS (or confirm they should be PII and remove from allowlist)."
    )
    assert not extra_in_test, (
        f"METADATA_KEYS tests keys not in allowlist: {extra_in_test}. Stale test entries — remove."
    )


def test_log_record_includes_tier_when_provided(tmp_path, monkeypatch):
    """NSA audit (#7): each MCP invocation records caller tier + key_hash so the
    log answers 'who' (Free vs Pro / which key), not just 'what'. tier is not PII;
    key_hash is a one-way SHA-256 digest."""
    from core import mcp_proxy

    log_path = tmp_path / "mcp_tools.jsonl"
    monkeypatch.setattr(mcp_proxy, "_MCP_TOOL_LOG", str(log_path))

    mcp_proxy._log_mcp_tool("cve_lookup", None, status="ok", duration_ms=5, tier="pro", key_hash="f" * 64)

    record = _json.loads(log_path.read_text().strip())
    assert record["tier"] == "pro"
    assert record["key_hash"] == "f" * 64


def test_log_record_omits_key_hash_when_none(tmp_path, monkeypatch):
    """Free / keyless callers have key_hash=None — the field is omitted (keeps the
    log field-additive-safe), but tier='free' is still recorded."""
    from core import mcp_proxy

    log_path = tmp_path / "mcp_tools.jsonl"
    monkeypatch.setattr(mcp_proxy, "_MCP_TOOL_LOG", str(log_path))

    mcp_proxy._log_mcp_tool("cve_lookup", None, status="ok", tier="free", key_hash=None)

    record = _json.loads(log_path.read_text().strip())
    assert record["tier"] == "free"
    assert "key_hash" not in record


def test_log_identity_adds_no_ip_or_raw_key(tmp_path, monkeypatch):
    """Privacy regression: adding identity must not introduce a client IP or the
    raw API key. key_hash is pseudonymous; the cc_ key itself must never appear."""
    from core import mcp_proxy

    log_path = tmp_path / "mcp_tools.jsonl"
    monkeypatch.setattr(mcp_proxy, "_MCP_TOOL_LOG", str(log_path))

    mcp_proxy._log_mcp_tool("ip_lookup", None, status="ok", tier="pro", key_hash="a" * 64)

    raw = log_path.read_text()
    assert "client_ip" not in raw
    assert "cc_" not in raw
