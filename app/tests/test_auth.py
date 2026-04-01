"""Tests for auth.py"""

from unittest.mock import MagicMock

import pytest

# --- generate_key ---


def test_generate_key_prefix():
    from auth import generate_key

    key = generate_key()
    assert key.startswith("cc_")


def test_generate_key_length():
    from auth import generate_key

    key = generate_key()
    # cc_ + 48 hex chars = 51 total
    assert len(key) == 51


def test_generate_key_unique():
    from auth import generate_key

    keys = {generate_key() for _ in range(100)}
    assert len(keys) == 100


# --- hash_key ---


def test_hash_key_deterministic():
    from auth import hash_key

    h1 = hash_key("cc_abc123")
    h2 = hash_key("cc_abc123")
    assert h1 == h2


def test_hash_key_different_inputs():
    from auth import hash_key

    h1 = hash_key("cc_key1")
    h2 = hash_key("cc_key2")
    assert h1 != h2


def test_hash_key_is_hex():
    from auth import hash_key

    h = hash_key("cc_test")
    assert len(h) == 64  # SHA-256 hex
    int(h, 16)  # should not raise


# --- extract_key ---


def test_extract_key_bearer():
    from auth import extract_key

    request = MagicMock()
    request.headers = {"authorization": "Bearer cc_aabbccddeeff00112233445566778899aabbccddeeff0011"}
    assert extract_key(request) == "cc_aabbccddeeff00112233445566778899aabbccddeeff0011"


def test_extract_key_no_header():
    from auth import extract_key

    request = MagicMock()
    request.headers = {}
    assert extract_key(request) is None


def test_extract_key_wrong_prefix():
    from auth import extract_key

    request = MagicMock()
    request.headers = {"authorization": "Bearer sk_wrongprefix"}
    assert extract_key(request) is None


def test_extract_key_no_bearer():
    from auth import extract_key

    request = MagicMock()
    request.headers = {"authorization": "Token cc_abc123"}
    assert extract_key(request) is None


def test_extract_key_empty_bearer():
    from auth import extract_key

    request = MagicMock()
    request.headers = {"authorization": "Bearer "}
    assert extract_key(request) is None


# --- authenticate ---


def test_authenticate_keyless_allowed():
    from auth import authenticate

    # Direct test via mock request
    request = MagicMock()
    request.headers = {}
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    ctx = authenticate(request, "/v1/cve/test")
    assert ctx["tier"] == "free"
    assert ctx["key_hash"] is None
    assert ctx["client_ip"] == "1.2.3.4"


def test_authenticate_pro_key_valid():
    from auth import authenticate, generate_key, hash_key
    from db import save_api_key

    key = generate_key()
    save_api_key(hash_key(key))
    request = MagicMock()
    request.headers = {"authorization": f"Bearer {key}"}
    request.client = MagicMock()
    request.client.host = "5.6.7.8"
    ctx = authenticate(request, "/v1/cve/test")
    assert ctx["tier"] == "pro"
    assert ctx["key_hash"] == hash_key(key)


def test_authenticate_invalid_key_401():
    from auth import authenticate
    from fastapi import HTTPException

    request = MagicMock()
    request.headers = {"authorization": "Bearer cc_invalidkey00000000000000000000000000000000000000"}
    request.client = MagicMock()
    request.client.host = "9.8.7.6"
    with pytest.raises(HTTPException) as exc_info:
        authenticate(request, "/v1/test")
    assert exc_info.value.status_code == 401


def test_authenticate_keyless_rate_limit_429():
    from auth import authenticate
    from config import FREE_HOURLY_LIMIT
    from fastapi import HTTPException

    # Exhaust the limit
    for i in range(FREE_HOURLY_LIMIT):
        request = MagicMock()
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "99.99.99.99"
        authenticate(request, "/v1/test")
    # Next request should be blocked
    request = MagicMock()
    request.headers = {}
    request.client = MagicMock()
    request.client.host = "99.99.99.99"
    with pytest.raises(HTTPException) as exc_info:
        authenticate(request, "/v1/test")
    assert exc_info.value.status_code == 429


def test_authenticate_deactivated_key_401():
    from auth import authenticate, generate_key, hash_key
    from db import deactivate_api_key, save_api_key
    from fastapi import HTTPException

    key = generate_key()
    save_api_key(hash_key(key), order_id="order_deact_test")
    deactivate_api_key("order_deact_test")
    request = MagicMock()
    request.headers = {"authorization": f"Bearer {key}"}
    request.client = MagicMock()
    request.client.host = "1.1.1.1"
    with pytest.raises(HTTPException) as exc_info:
        authenticate(request, "/v1/test")
    assert exc_info.value.status_code == 401


def test_authenticate_pro_rate_limit_429():
    from auth import authenticate, generate_key, hash_key
    from config import PRO_HOURLY_LIMIT
    from db import save_api_key
    from fastapi import HTTPException

    key = generate_key()
    kh = hash_key(key)
    save_api_key(kh)
    # Exhaust the limit via authenticate calls (sliding window)
    for i in range(PRO_HOURLY_LIMIT):
        request = MagicMock()
        request.headers = {"authorization": f"Bearer {key}"}
        request.client = MagicMock()
        request.client.host = "2.2.2.2"
        authenticate(request, "/v1/test")
    # Next request should be blocked
    request = MagicMock()
    request.headers = {"authorization": f"Bearer {key}"}
    request.client = MagicMock()
    request.client.host = "2.2.2.2"
    with pytest.raises(HTTPException) as exc_info:
        authenticate(request, "/v1/test")
    assert exc_info.value.status_code == 429


# --- Rate limit state on request ---


def test_authenticate_sets_ratelimit_state():
    from auth import authenticate

    request = MagicMock()
    request.headers = {}
    request.client = MagicMock()
    request.client.host = "10.10.10.10"
    authenticate(request, "/v1/test")
    assert request.state.ratelimit_limit == 100
    assert request.state.ratelimit_remaining == 98  # 49 actual * 2 (advertised scaling)
    assert request.state.ratelimit_reset >= 0


def test_authenticate_ratelimit_remaining_decreases():
    from auth import authenticate

    for i in range(5):
        request = MagicMock()
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "11.11.11.11"
        authenticate(request, "/v1/test")
    assert request.state.ratelimit_remaining == 90  # 45 actual * 2 (advertised scaling)


# --- localhost rate limit exemption ---


def test_authenticate_localhost_ipv4_skips_rate_limit():
    from auth import authenticate
    from config import FREE_HOURLY_LIMIT

    # Send more requests than the free limit from 127.0.0.1
    for _ in range(FREE_HOURLY_LIMIT + 5):
        request = MagicMock()
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        ctx = authenticate(request, "/v1/test")
        assert ctx["tier"] == "free"
        assert ctx["client_ip"] == "127.0.0.1"


def test_authenticate_localhost_ipv6_skips_rate_limit():
    from auth import authenticate
    from config import FREE_HOURLY_LIMIT

    for _ in range(FREE_HOURLY_LIMIT + 5):
        request = MagicMock()
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "::1"
        ctx = authenticate(request, "/v1/test")
        assert ctx["tier"] == "free"
        assert ctx["client_ip"] == "::1"


def test_authenticate_localhost_pro_skips_rate_limit():
    from auth import authenticate, generate_key, hash_key
    from config import PRO_HOURLY_LIMIT
    from db import save_api_key

    key = generate_key()
    save_api_key(hash_key(key))
    for _ in range(PRO_HOURLY_LIMIT + 5):
        request = MagicMock()
        request.headers = {"authorization": f"Bearer {key}"}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        ctx = authenticate(request, "/v1/test")
        assert ctx["tier"] == "pro"


def test_authenticate_localhost_still_logs_usage(monkeypatch):
    import auth
    from auth import authenticate

    calls = []
    monkeypatch.setattr(auth, "log_usage", lambda *a, **kw: calls.append((a, kw)))
    request = MagicMock()
    request.headers = {}
    request.client = MagicMock()
    request.client.host = "127.0.0.1"
    authenticate(request, "/v1/test")
    assert len(calls) == 1
    assert calls[0][0] == ("127.0.0.1", "/v1/test")


# --- extract_key length validation ---


class TestExtractKeyLength:
    def test_too_short_rejected(self):
        from auth import extract_key
        from config import KEY_LENGTH

        request = MagicMock()
        request.headers = {"authorization": "Bearer cc_" + "a" * (KEY_LENGTH - 1)}
        request.query_params = {}
        assert extract_key(request) is None

    def test_too_long_rejected(self):
        from auth import extract_key
        from config import KEY_LENGTH

        request = MagicMock()
        request.headers = {"authorization": "Bearer cc_" + "a" * (KEY_LENGTH + 1)}
        request.query_params = {}
        assert extract_key(request) is None

    def test_exact_length_accepted(self):
        from auth import extract_key
        from config import KEY_LENGTH

        request = MagicMock()
        request.headers = {"authorization": "Bearer cc_" + "a" * KEY_LENGTH}
        request.query_params = {}
        result = extract_key(request)
        assert result is not None
