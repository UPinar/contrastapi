"""Tests for webhooks.py — Lemon Squeezy webhook handling.

All tests skipped until webhook router is enabled in main.py.
"""

import hashlib
import hmac
import json
from unittest.mock import patch

import pytest

# pytestmark = pytest.mark.skip(reason="Webhook router disabled until Lemon Squeezy verification")

WEBHOOK_SECRET = "test_webhook_secret_123"


def _sign(payload: bytes, secret: str = WEBHOOK_SECRET) -> str:
    """Generate HMAC-SHA256 signature for test payloads."""
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def _make_payload(event_name: str, data: dict, event_id: str | None = None) -> bytes:
    meta = {"event_name": event_name}
    if event_id:
        meta["event_id"] = event_id
    return json.dumps({"meta": meta, "data": data}).encode()


# --- verify_signature ---


def test_verify_signature_valid():
    from webhooks import verify_signature

    payload = b'{"test": true}'
    sig = _sign(payload)
    assert verify_signature(payload, sig, WEBHOOK_SECRET) is True


def test_verify_signature_invalid():
    from webhooks import verify_signature

    payload = b'{"test": true}'
    assert verify_signature(payload, "bad_signature", WEBHOOK_SECRET) is False


def test_verify_signature_empty_secret():
    from webhooks import verify_signature

    assert verify_signature(b"data", "sig", "") is False


def test_verify_signature_empty_signature():
    from webhooks import verify_signature

    assert verify_signature(b"data", "", WEBHOOK_SECRET) is False


# --- Webhook endpoint (via TestClient) ---


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from main import app
    from ratelimit import reset

    reset("welcome")
    return TestClient(app, raise_server_exceptions=False)


def test_webhook_invalid_signature_403(client):
    payload = _make_payload("order_created", {"id": "order_1"})
    with patch("webhooks.LEMONSQUEEZY_WEBHOOK_SECRET", WEBHOOK_SECRET):
        resp = client.post(
            "/webhooks/lemonsqueezy",
            content=payload,
            headers={"x-signature": "wrong_signature"},
        )
    assert resp.status_code == 403


def test_webhook_missing_signature_403(client):
    payload = _make_payload("order_created", {"id": "order_1"})
    with patch("webhooks.LEMONSQUEEZY_WEBHOOK_SECRET", WEBHOOK_SECRET):
        resp = client.post("/webhooks/lemonsqueezy", content=payload)
    assert resp.status_code == 403


def test_webhook_order_created_provisions_key(client):
    payload = _make_payload("order_created", {"id": "order_100"}, event_id="evt_100")
    sig = _sign(payload)
    with patch("webhooks.LEMONSQUEEZY_WEBHOOK_SECRET", WEBHOOK_SECRET):
        resp = client.post(
            "/webhooks/lemonsqueezy",
            content=payload,
            headers={"x-signature": sig},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "provisioned"
    assert data["order_id"] == "order_100"
    # Raw API key must NOT be in response
    assert "api_key" not in data

    # Verify key is in DB via order_id
    from db import get_key_by_order_id

    key_row = get_key_by_order_id("order_100")
    assert key_row is not None
    assert key_row["order_id"] == "order_100"


def test_webhook_duplicate_order_idempotent(client):
    # Use different event_ids so replay protection doesn't block the second request
    payload1 = _make_payload("order_created", {"id": "order_dup"}, event_id="evt_dup_1")
    sig1 = _sign(payload1)
    payload2 = _make_payload("order_created", {"id": "order_dup"}, event_id="evt_dup_2")
    sig2 = _sign(payload2)
    with patch("webhooks.LEMONSQUEEZY_WEBHOOK_SECRET", WEBHOOK_SECRET):
        resp1 = client.post(
            "/webhooks/lemonsqueezy",
            content=payload1,
            headers={"x-signature": sig1},
        )
        resp2 = client.post(
            "/webhooks/lemonsqueezy",
            content=payload2,
            headers={"x-signature": sig2},
        )
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "provisioned"
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "already_provisioned"

    # Only one key in DB for this order
    from db import get_key_by_order_id

    key_row = get_key_by_order_id("order_dup")
    assert key_row is not None


def test_webhook_subscription_cancelled_deactivates(client):
    # First create a key via order_created
    payload_create = _make_payload("order_created", {"id": "order_cancel"}, event_id="evt_cancel_1")
    sig_create = _sign(payload_create)
    with patch("webhooks.LEMONSQUEEZY_WEBHOOK_SECRET", WEBHOOK_SECRET):
        resp = client.post(
            "/webhooks/lemonsqueezy",
            content=payload_create,
            headers={"x-signature": sig_create},
        )
    assert resp.status_code == 200
    assert "api_key" not in resp.json()

    # Now cancel subscription
    payload_cancel = _make_payload(
        "subscription_cancelled",
        {"id": "sub_1", "attributes": {"order_id": "order_cancel"}},
        event_id="evt_cancel_2",
    )
    sig_cancel = _sign(payload_cancel)
    with patch("webhooks.LEMONSQUEEZY_WEBHOOK_SECRET", WEBHOOK_SECRET):
        resp = client.post(
            "/webhooks/lemonsqueezy",
            content=payload_cancel,
            headers={"x-signature": sig_cancel},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "deactivated"
    assert resp.json()["keys_affected"] == 1

    # Verify key is deactivated via order lookup
    from db import get_key_by_order_id

    key_row = get_key_by_order_id("order_cancel")
    assert key_row is not None
    assert key_row["active"] == 0


def test_webhook_subscription_expired_deactivates(client):
    # Create key
    payload_create = _make_payload("order_created", {"id": "order_expire"}, event_id="evt_expire_1")
    sig_create = _sign(payload_create)
    with patch("webhooks.LEMONSQUEEZY_WEBHOOK_SECRET", WEBHOOK_SECRET):
        resp = client.post(
            "/webhooks/lemonsqueezy",
            content=payload_create,
            headers={"x-signature": sig_create},
        )
    assert resp.status_code == 200

    # Expire subscription
    payload_expire = _make_payload(
        "subscription_expired",
        {"id": "sub_2", "attributes": {"order_id": "order_expire"}},
        event_id="evt_expire_2",
    )
    sig_expire = _sign(payload_expire)
    with patch("webhooks.LEMONSQUEEZY_WEBHOOK_SECRET", WEBHOOK_SECRET):
        resp = client.post(
            "/webhooks/lemonsqueezy",
            content=payload_expire,
            headers={"x-signature": sig_expire},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "deactivated"


def test_webhook_unknown_event_ignored(client):
    payload = _make_payload("subscription_payment_success", {"id": "pay_1"}, event_id="evt_unk")
    sig = _sign(payload)
    with patch("webhooks.LEMONSQUEEZY_WEBHOOK_SECRET", WEBHOOK_SECRET):
        resp = client.post(
            "/webhooks/lemonsqueezy",
            content=payload,
            headers={"x-signature": sig},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"


def test_webhook_replay_protection(client):
    """Same event_id sent twice should return already_processed on second call."""
    payload = _make_payload("order_created", {"id": "order_replay"}, event_id="evt_replay_same")
    sig = _sign(payload)
    with patch("webhooks.LEMONSQUEEZY_WEBHOOK_SECRET", WEBHOOK_SECRET):
        resp1 = client.post(
            "/webhooks/lemonsqueezy",
            content=payload,
            headers={"x-signature": sig},
        )
        resp2 = client.post(
            "/webhooks/lemonsqueezy",
            content=payload,
            headers={"x-signature": sig},
        )
    assert resp1.status_code == 200
    assert resp1.json()["status"] == "provisioned"
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "already_processed"
    assert resp2.json()["event_id"] == "evt_replay_same"


def test_webhook_missing_order_id_400(client):
    payload = _make_payload("order_created", {}, event_id="evt_no_order")
    sig = _sign(payload)
    with patch("webhooks.LEMONSQUEEZY_WEBHOOK_SECRET", WEBHOOK_SECRET):
        resp = client.post(
            "/webhooks/lemonsqueezy",
            content=payload,
            headers={"x-signature": sig},
        )
    assert resp.status_code == 400


def test_webhook_invalid_json_400(client):
    payload = b"not json"
    sig = _sign(payload)
    with patch("webhooks.LEMONSQUEEZY_WEBHOOK_SECRET", WEBHOOK_SECRET):
        resp = client.post(
            "/webhooks/lemonsqueezy",
            content=payload,
            headers={"x-signature": sig},
        )
    assert resp.status_code == 400


def test_webhook_cancel_nonexistent_order(client):
    payload = _make_payload(
        "subscription_cancelled",
        {"id": "sub_x", "attributes": {"order_id": "order_nonexistent"}},
    )
    sig = _sign(payload)
    with patch("webhooks.LEMONSQUEEZY_WEBHOOK_SECRET", WEBHOOK_SECRET):
        resp = client.post(
            "/webhooks/lemonsqueezy",
            content=payload,
            headers={"x-signature": sig},
        )
    assert resp.status_code == 200
    assert resp.json()["keys_affected"] == 0


# --- _extract_order_id ---


def test_extract_order_id_from_data_id():
    from webhooks import _extract_order_id

    assert _extract_order_id({"id": "123"}) == "123"


def test_extract_order_id_from_attributes():
    from webhooks import _extract_order_id

    assert _extract_order_id({"id": "sub_1", "attributes": {"order_id": "456"}}) == "456"


def test_extract_order_id_empty():
    from webhooks import _extract_order_id

    assert _extract_order_id({}) is None


# --- get_key_by_order_id ---


def test_get_key_by_order_id_found():
    from auth import generate_key, hash_key
    from db import get_key_by_order_id, save_api_key

    key = generate_key()
    save_api_key(hash_key(key), order_id="order_find")
    row = get_key_by_order_id("order_find")
    assert row is not None
    assert row["order_id"] == "order_find"


def test_get_key_by_order_id_not_found():
    from db import get_key_by_order_id

    assert get_key_by_order_id("nonexistent") is None


# --- Welcome page ---

_UUID_WELCOME = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee01"
_UUID_ONCE = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee02"
_UUID_INVALID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee03"
_UUID_CHECK = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee04"
_UUID_CLEANUP = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeee05"


def test_welcome_shows_key_after_purchase(client):
    """POST order_created webhook, then GET /welcome shows the API key."""
    payload = _make_payload("order_created", {"id": _UUID_WELCOME}, event_id="evt_welcome_1")
    sig = _sign(payload)
    with patch("webhooks.LEMONSQUEEZY_WEBHOOK_SECRET", WEBHOOK_SECRET):
        resp = client.post(
            "/webhooks/lemonsqueezy",
            content=payload,
            headers={"x-signature": sig},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "provisioned"

    resp = client.get("/welcome", params={"order_id": _UUID_WELCOME})
    assert resp.status_code == 200
    assert "api-key" in resp.text
    assert "will not be shown again" in resp.text


def test_welcome_key_cleared_after_first_view(client):
    """Second GET /welcome for the same order shows 'already claimed'."""
    payload = _make_payload("order_created", {"id": _UUID_ONCE}, event_id="evt_once_1")
    sig = _sign(payload)
    with patch("webhooks.LEMONSQUEEZY_WEBHOOK_SECRET", WEBHOOK_SECRET):
        client.post(
            "/webhooks/lemonsqueezy",
            content=payload,
            headers={"x-signature": sig},
        )

    # First view — key shown
    resp1 = client.get("/welcome", params={"order_id": _UUID_ONCE})
    assert resp1.status_code == 200
    assert "api-key" in resp1.text

    # Second view — key already claimed, shows error (not polling)
    resp2 = client.get("/welcome", params={"order_id": _UUID_ONCE})
    assert resp2.status_code == 200
    assert "already been claimed" in resp2.text


def test_welcome_invalid_order(client):
    """GET /welcome with nonexistent UUID order_id shows polling (webhook may not have arrived)."""
    resp = client.get("/welcome", params={"order_id": _UUID_INVALID})
    assert resp.status_code == 200
    assert "polling-section" in resp.text


def test_welcome_invalid_order_id_format(client):
    """GET /welcome with non-UUID order_id returns 400."""
    resp = client.get("/welcome", params={"order_id": "not-a-uuid"})
    assert resp.status_code == 400


def test_welcome_missing_order_id(client):
    """GET /welcome without order_id returns 400."""
    resp = client.get("/welcome")
    assert resp.status_code == 400


def test_welcome_rate_limit(client):
    """GET /welcome more than 5 times/min returns 429."""
    from ratelimit import reset

    reset("welcome")
    uid = "aaaaaaaa-bbbb-cccc-dddd-ffffffffffff"
    for _ in range(5):
        resp = client.get("/welcome", params={"order_id": uid})
        assert resp.status_code == 200
    resp = client.get("/welcome", params={"order_id": uid})
    assert resp.status_code == 429


# --- /api/check-key ---


def test_check_key_ready_after_webhook(client):
    """check-key returns ready=true when pending key exists."""
    payload = _make_payload("order_created", {"id": _UUID_CHECK}, event_id="evt_check_1")
    sig = _sign(payload)
    with patch("webhooks.LEMONSQUEEZY_WEBHOOK_SECRET", WEBHOOK_SECRET):
        client.post("/webhooks/lemonsqueezy", content=payload, headers={"x-signature": sig})

    resp = client.get("/api/check-key", params={"order_id": _UUID_CHECK})
    assert resp.status_code == 200
    assert resp.json()["ready"] is True


def test_check_key_not_ready(client):
    """check-key returns ready=false for unknown order."""
    resp = client.get("/api/check-key", params={"order_id": _UUID_INVALID})
    assert resp.status_code == 200
    assert resp.json()["ready"] is False


def test_check_key_missing_order_id(client):
    """check-key without order_id returns 400."""
    resp = client.get("/api/check-key")
    assert resp.status_code == 400


def test_check_key_invalid_format(client):
    """check-key with non-UUID returns 400."""
    resp = client.get("/api/check-key", params={"order_id": "not-a-uuid"})
    assert resp.status_code == 400


def test_check_key_rate_limit(client):
    """check-key more than 10 times/min returns 429."""
    from ratelimit import reset

    reset("check_key")
    uid = "aaaaaaaa-bbbb-cccc-dddd-ffffffffffff"
    for _ in range(10):
        resp = client.get("/api/check-key", params={"order_id": uid})
        assert resp.status_code == 200
    resp = client.get("/api/check-key", params={"order_id": uid})
    assert resp.status_code == 429


# --- cleanup_expired_pending_keys ---


def test_cleanup_expired_pending_keys(client):
    """Expired pending keys are cleared by cleanup."""
    from datetime import UTC, datetime, timedelta

    from db import cleanup_expired_pending_keys, get_api_db, has_pending_key

    # Create a key via webhook
    payload = _make_payload("order_created", {"id": _UUID_CLEANUP}, event_id="evt_cleanup_1")
    sig = _sign(payload)
    with patch("webhooks.LEMONSQUEEZY_WEBHOOK_SECRET", WEBHOOK_SECRET):
        client.post("/webhooks/lemonsqueezy", content=payload, headers={"x-signature": sig})

    assert has_pending_key(_UUID_CLEANUP) is True

    # Backdate the pending_key_created_at to 25 hours ago
    old_ts = (datetime.now(UTC) - timedelta(hours=25)).isoformat()
    with get_api_db() as con:
        con.execute("UPDATE api_keys SET pending_key_created_at = ? WHERE order_id = ?", (old_ts, _UUID_CLEANUP))

    cleared = cleanup_expired_pending_keys(max_age_hours=24)
    assert cleared >= 1
    assert has_pending_key(_UUID_CLEANUP) is False
