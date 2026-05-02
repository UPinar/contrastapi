"""Tests for crypto_billing.py — NOWPayments crypto checkout + IPN webhook."""

import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import pytest

IPN_SECRET = "test_ipn_secret_xyz"
API_KEY = "test_nowpayments_api_key"


def _canonical_sign(payload: dict, secret: str = IPN_SECRET) -> tuple[bytes, str]:
    """Build a NOWPayments-style payload + matching HMAC-SHA512 signature."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sig = hmac.new(secret.encode(), canonical.encode(), hashlib.sha512).hexdigest()
    # The body sent on the wire need NOT be canonically sorted — verify_ipn_signature
    # re-sorts before HMAC. Use indent=None to mimic real wire bytes.
    body = json.dumps(payload).encode()
    return body, sig


# --- verify_ipn_signature -------------------------------------------------


def test_verify_ipn_signature_valid():
    from crypto_billing import verify_ipn_signature

    body, sig = _canonical_sign({"invoice_id": "1", "payment_status": "finished"})
    assert verify_ipn_signature(body, sig, IPN_SECRET) is True


def test_verify_ipn_signature_wrong_signature():
    from crypto_billing import verify_ipn_signature

    body, _ = _canonical_sign({"invoice_id": "1"})
    assert verify_ipn_signature(body, "deadbeef", IPN_SECRET) is False


def test_verify_ipn_signature_empty_secret():
    from crypto_billing import verify_ipn_signature

    body, sig = _canonical_sign({"invoice_id": "1"})
    assert verify_ipn_signature(body, sig, "") is False


def test_verify_ipn_signature_empty_signature():
    from crypto_billing import verify_ipn_signature

    body, _ = _canonical_sign({"invoice_id": "1"})
    assert verify_ipn_signature(body, "", IPN_SECRET) is False


def test_verify_ipn_signature_malformed_json():
    from crypto_billing import verify_ipn_signature

    assert verify_ipn_signature(b"not json", "deadbeef", IPN_SECRET) is False


def test_verify_ipn_signature_non_dict_payload():
    """A JSON list/string body must not pass — only dicts can be canonicalized."""
    from crypto_billing import verify_ipn_signature

    body = b"[1, 2, 3]"
    canonical = json.dumps([1, 2, 3], sort_keys=True, separators=(",", ":"))
    sig = hmac.new(IPN_SECRET.encode(), canonical.encode(), hashlib.sha512).hexdigest()
    assert verify_ipn_signature(body, sig, IPN_SECRET) is False


def test_verify_ipn_signature_key_order_independent():
    """Wire body unsorted, signature computed on sorted form — must verify."""
    from crypto_billing import verify_ipn_signature

    payload = {"z_last": 1, "a_first": 2, "m_middle": 3}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sig = hmac.new(IPN_SECRET.encode(), canonical.encode(), hashlib.sha512).hexdigest()
    # Send body with reversed key order (insertion-ordered dict trick)
    body = json.dumps({"z_last": 1, "a_first": 2, "m_middle": 3}).encode()
    assert verify_ipn_signature(body, sig, IPN_SECRET) is True


# --- TestClient fixture ---------------------------------------------------


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from main import app
    from ratelimit import reset

    reset("welcome")
    return TestClient(app, raise_server_exceptions=False)


# --- crypto_checkout ------------------------------------------------------


def test_checkout_missing_api_key_returns_503(client):
    with patch("crypto_billing.NOWPAYMENTS_API_KEY", ""):
        resp = client.post("/v1/billing/crypto/checkout")
    assert resp.status_code == 503


def test_checkout_success_returns_invoice_url(client):
    fake_response = MagicMock()
    fake_response.read.return_value = json.dumps(
        {"id": 5228306332, "invoice_url": "https://nowpayments.io/payment/?iid=5228306332"}
    ).encode()
    fake_response.__enter__.return_value = fake_response
    fake_response.__exit__.return_value = False
    with (
        patch("crypto_billing.NOWPAYMENTS_API_KEY", API_KEY),
        patch("crypto_billing.urllib.request.urlopen", return_value=fake_response) as mock_open,
    ):
        resp = client.post("/v1/billing/crypto/checkout")
    assert resp.status_code == 200
    body = resp.json()
    assert body["invoice_id"] == "5228306332"
    assert body["invoice_url"].startswith("https://nowpayments.io/")
    # Regression: NOWPayments' Cloudflare layer 403's the default Python-urllib UA
    # with error code 1010. Ensure we send a self-identifying User-Agent.
    sent_request = mock_open.call_args[0][0]
    ua = sent_request.headers.get("User-agent")
    assert ua is not None, "Outbound request must set a User-Agent"
    assert "ContrastAPI" in ua


def test_checkout_provider_unreachable_returns_502(client):
    import urllib.error

    with (
        patch("crypto_billing.NOWPAYMENTS_API_KEY", API_KEY),
        patch(
            "crypto_billing.urllib.request.urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ),
    ):
        resp = client.post("/v1/billing/crypto/checkout")
    assert resp.status_code == 502


def test_checkout_malformed_provider_response_returns_502(client):
    fake_response = MagicMock()
    fake_response.read.return_value = b"<html>upstream error</html>"
    fake_response.__enter__.return_value = fake_response
    fake_response.__exit__.return_value = False
    with (
        patch("crypto_billing.NOWPAYMENTS_API_KEY", API_KEY),
        patch("crypto_billing.urllib.request.urlopen", return_value=fake_response),
    ):
        resp = client.post("/v1/billing/crypto/checkout")
    assert resp.status_code == 502


def test_checkout_provider_missing_invoice_url_returns_502(client):
    fake_response = MagicMock()
    fake_response.read.return_value = json.dumps({"id": 1}).encode()
    fake_response.__enter__.return_value = fake_response
    fake_response.__exit__.return_value = False
    with (
        patch("crypto_billing.NOWPAYMENTS_API_KEY", API_KEY),
        patch("crypto_billing.urllib.request.urlopen", return_value=fake_response),
    ):
        resp = client.post("/v1/billing/crypto/checkout")
    assert resp.status_code == 502


# --- crypto_ipn -----------------------------------------------------------


def test_ipn_invalid_signature_returns_403(client):
    body = json.dumps({"invoice_id": "ipn1", "payment_status": "finished"}).encode()
    with patch("crypto_billing.NOWPAYMENTS_IPN_SECRET", IPN_SECRET):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": "wrong"},
        )
    assert resp.status_code == 403


def test_ipn_oversized_body_returns_413(client):
    big = b"x" * 1_048_577
    with patch("crypto_billing.NOWPAYMENTS_IPN_SECRET", IPN_SECRET):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=big,
            headers={"x-nowpayments-sig": "anything"},
        )
    assert resp.status_code == 413


def test_ipn_missing_invoice_id_returns_400(client):
    body, sig = _canonical_sign({"payment_status": "finished"})
    with patch("crypto_billing.NOWPAYMENTS_IPN_SECRET", IPN_SECRET):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
    assert resp.status_code == 400


def test_ipn_pending_status_ignored(client):
    body, sig = _canonical_sign({"invoice_id": "pending_inv", "payment_status": "pending"})
    with patch("crypto_billing.NOWPAYMENTS_IPN_SECRET", IPN_SECRET):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ignored"
    assert data["payment_status"] == "pending"

    # No key should have been created
    from db import get_key_by_order_id

    assert get_key_by_order_id("pending_inv") is None


def test_ipn_finished_provisions_key(client):
    invoice = "crypto_inv_001"
    body, sig = _canonical_sign({"invoice_id": invoice, "payment_status": "finished"})
    with (
        patch("crypto_billing.NOWPAYMENTS_IPN_SECRET", IPN_SECRET),
        patch("crypto_billing._notify_telegram") as mock_tg,
    ):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "provisioned"
    assert data["invoice_id"] == invoice
    # Raw key NEVER in the IPN HTTP response
    assert "api_key" not in data
    # Response advertises the 30-day expiry to the IPN sender (audit + sanity)
    assert "expires_at" in data
    mock_tg.assert_called_once()

    from db import get_key_by_order_id

    row = get_key_by_order_id(invoice)
    assert row is not None
    assert row["order_id"] == invoice
    # Expiry is populated on a crypto-provisioned key (~30 days out)
    assert row["expires_at"] is not None
    from datetime import UTC, datetime

    exp = datetime.fromisoformat(row["expires_at"])
    delta_days = (exp - datetime.now(UTC)).total_seconds() / 86400
    assert 29 < delta_days < 31


def test_ipn_replay_same_invoice_returns_already_processed(client):
    invoice = "crypto_inv_replay"
    body, sig = _canonical_sign({"invoice_id": invoice, "payment_status": "finished"})
    with (
        patch("crypto_billing.NOWPAYMENTS_IPN_SECRET", IPN_SECRET),
        patch("crypto_billing._notify_telegram"),
    ):
        r1 = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
        r2 = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
    assert r1.status_code == 200
    assert r1.json()["status"] == "provisioned"
    assert r2.status_code == 200
    assert r2.json()["status"] == "already_processed"


def test_ipn_idempotent_when_key_already_exists(client):
    """Cold-cache path: replay store cleared but key already in DB."""
    invoice = "crypto_inv_idem"
    body, sig = _canonical_sign({"invoice_id": invoice, "payment_status": "finished"})
    with (
        patch("crypto_billing.NOWPAYMENTS_IPN_SECRET", IPN_SECRET),
        patch("crypto_billing._notify_telegram"),
    ):
        r1 = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
        # Simulate process restart: replay store cleared but DB persists
        from crypto_billing import _processed_invoices

        _processed_invoices.clear()
        r2 = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
    assert r1.json()["status"] == "provisioned"
    assert r2.status_code == 200
    assert r2.json()["status"] == "already_provisioned"


def test_ipn_failed_status_ignored(client):
    body, sig = _canonical_sign({"invoice_id": "failed_inv", "payment_status": "failed"})
    with patch("crypto_billing.NOWPAYMENTS_IPN_SECRET", IPN_SECRET):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"

    from db import get_key_by_order_id

    assert get_key_by_order_id("failed_inv") is None


@pytest.mark.parametrize(
    "status",
    ["confirming", "sending", "partially_paid", "expired", "refunded", "waiting"],
)
def test_ipn_non_terminal_states_are_no_ops(client, status):
    """Every NOWPayments state other than 'finished' must be a no-op.

    Documented states: waiting, confirming, confirmed, sending, partially_paid,
    finished, failed, refunded, expired. Only `finished` provisions a key.
    """
    invoice_id = f"state_{status}_inv"
    body, sig = _canonical_sign({"invoice_id": invoice_id, "payment_status": status})
    with patch("crypto_billing.NOWPAYMENTS_IPN_SECRET", IPN_SECRET):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"

    from db import get_key_by_order_id

    assert get_key_by_order_id(invoice_id) is None


def test_ipn_pending_then_finished_provisions_key(client):
    """Regression: NOWPayments emits multiple IPNs per invoice (waiting->confirming
    ->finished). A non-finished IPN must NOT mark the invoice as replayed,
    otherwise the later "finished" event is dropped and no key is provisioned.
    """
    invoice = "lifecycle_inv_001"
    pending_body, pending_sig = _canonical_sign({"invoice_id": invoice, "payment_status": "confirming"})
    finished_body, finished_sig = _canonical_sign({"invoice_id": invoice, "payment_status": "finished"})
    with (
        patch("crypto_billing.NOWPAYMENTS_IPN_SECRET", IPN_SECRET),
        patch("crypto_billing._notify_telegram"),
    ):
        r1 = client.post(
            "/v1/billing/crypto/webhook",
            content=pending_body,
            headers={"x-nowpayments-sig": pending_sig},
        )
        r2 = client.post(
            "/v1/billing/crypto/webhook",
            content=finished_body,
            headers={"x-nowpayments-sig": finished_sig},
        )
    assert r1.status_code == 200
    assert r1.json()["status"] == "ignored"
    assert r2.status_code == 200
    assert r2.json()["status"] == "provisioned"
    assert r2.json()["invoice_id"] == invoice

    from db import get_key_by_order_id

    row = get_key_by_order_id(invoice)
    assert row is not None
    assert row["expires_at"] is not None


def test_ipn_payment_id_fallback_when_invoice_id_absent(client):
    """If only `payment_id` is present, it is used as the order key."""
    body, sig = _canonical_sign({"payment_id": "pay_fallback_001", "payment_status": "finished"})
    with (
        patch("crypto_billing.NOWPAYMENTS_IPN_SECRET", IPN_SECRET),
        patch("crypto_billing._notify_telegram"),
    ):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "provisioned"
    assert resp.json()["invoice_id"] == "pay_fallback_001"

    from db import get_key_by_order_id

    assert get_key_by_order_id("pay_fallback_001") is not None


# --- Expiry enforcement ----------------------------------------------------


def test_expired_key_is_rejected_by_get_api_key():
    """A row with expires_at <= now must NOT authorise (revenue-leak prevention)."""
    from datetime import UTC, datetime, timedelta

    from auth import generate_key, hash_key
    from db import get_api_db, get_api_key, save_api_key

    raw = generate_key()
    kh = hash_key(raw)
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    save_api_key(kh, order_id="expired_test_inv", expires_at=past)

    # Sanity: row exists in DB but get_api_key filters it out
    with get_api_db() as con:
        row = con.execute("SELECT 1 FROM api_keys WHERE key_hash = ?", (kh,)).fetchone()
        assert row is not None
    assert get_api_key(kh) is None


def test_lemonsqueezy_subscription_key_never_expires():
    """A row with expires_at = NULL (subscription model) keeps authorising."""
    from auth import generate_key, hash_key
    from db import get_api_key, save_api_key

    raw = generate_key()
    kh = hash_key(raw)
    save_api_key(kh, order_id="ls_sub_inv", expires_at=None)
    row = get_api_key(kh)
    assert row is not None
    assert row["order_id"] == "ls_sub_inv"
    assert row["expires_at"] is None


def test_future_expiry_key_still_authorises():
    """A crypto key within its 30-day window must authorise normally."""
    from datetime import UTC, datetime, timedelta

    from auth import generate_key, hash_key
    from db import get_api_key, save_api_key

    raw = generate_key()
    kh = hash_key(raw)
    future = (datetime.now(UTC) + timedelta(days=29)).isoformat()
    save_api_key(kh, order_id="fresh_crypto_inv", expires_at=future)
    assert get_api_key(kh) is not None


def test_checkout_rejects_untrusted_invoice_url(client):
    """Defense-in-depth: provider response with a non-NOWPayments URL must 502."""
    fake_response = MagicMock()
    fake_response.read.return_value = json.dumps(
        {"id": 1, "invoice_url": "https://phishing-site.example/steal"}
    ).encode()
    fake_response.__enter__.return_value = fake_response
    fake_response.__exit__.return_value = False
    with (
        patch("crypto_billing.NOWPAYMENTS_API_KEY", API_KEY),
        patch("crypto_billing.urllib.request.urlopen", return_value=fake_response),
    ):
        resp = client.post("/v1/billing/crypto/checkout")
    assert resp.status_code == 502
