"""Tests for crypto_billing.py — NOWPayments crypto checkout + IPN webhook."""

import hashlib
import hmac
import json
import uuid
from unittest.mock import MagicMock, patch

import pytest

IPN_SECRET = "test_ipn_secret_xyz"
API_KEY = "test_nowpayments_api_key"


def _uuid() -> str:
    """Fresh UUID per test — keeps DB rows from colliding across tests."""
    return str(uuid.uuid4())


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
    with patch("config.settings.nowpayments_api_key", ""):
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
        patch("config.settings.nowpayments_api_key", API_KEY),
        patch("crypto_billing.urllib.request.urlopen", return_value=fake_response) as mock_open,
    ):
        resp = client.post("/v1/billing/crypto/checkout")
    assert resp.status_code == 200
    body = resp.json()
    assert body["invoice_id"] == "5228306332"
    assert body["invoice_url"].startswith("https://nowpayments.io/")
    # `order_id` is our locally-generated UUID, returned to the caller so the
    # browser can later read it back from the welcome page redirect.
    uuid.UUID(body["order_id"])  # raises if not a valid UUID

    # Regression: NOWPayments' Cloudflare layer 403's the default Python-urllib UA
    # with error code 1010. Ensure we send a self-identifying User-Agent.
    sent_request = mock_open.call_args[0][0]
    ua = sent_request.headers.get("User-agent")
    assert ua is not None, "Outbound request must set a User-Agent"
    assert "ContrastAPI" in ua

    # Outbound /invoice payload must carry `order_id` (echoed in IPN) AND
    # embed it in `success_url` (welcome page reads ?order_id=<uuid>).
    sent_payload = json.loads(sent_request.data)
    assert sent_payload["order_id"] == body["order_id"]
    assert sent_payload["success_url"] == f"https://api.contrastcyber.com/welcome?order_id={body['order_id']}"


def test_checkout_provider_unreachable_returns_502(client):
    import urllib.error

    with (
        patch("config.settings.nowpayments_api_key", API_KEY),
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
        patch("config.settings.nowpayments_api_key", API_KEY),
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
        patch("config.settings.nowpayments_api_key", API_KEY),
        patch("crypto_billing.urllib.request.urlopen", return_value=fake_response),
    ):
        resp = client.post("/v1/billing/crypto/checkout")
    assert resp.status_code == 502


# --- crypto_ipn -----------------------------------------------------------


def test_ipn_invalid_signature_returns_403(client):
    body = json.dumps({"invoice_id": "ipn1", "order_id": _uuid(), "payment_status": "finished"}).encode()
    with patch("config.settings.nowpayments_ipn_secret", IPN_SECRET):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": "wrong"},
        )
    assert resp.status_code == 403


def test_ipn_oversized_body_returns_413(client):
    big = b"x" * 1_048_577
    with patch("config.settings.nowpayments_ipn_secret", IPN_SECRET):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=big,
            headers={"x-nowpayments-sig": "anything"},
        )
    assert resp.status_code == 413


def test_ipn_missing_invoice_id_returns_400(client):
    body, sig = _canonical_sign({"order_id": _uuid(), "payment_status": "finished"})
    with patch("config.settings.nowpayments_ipn_secret", IPN_SECRET):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
    assert resp.status_code == 400


def test_ipn_missing_order_id_returns_400(client):
    body, sig = _canonical_sign({"invoice_id": "ipn1", "payment_status": "finished"})
    with patch("config.settings.nowpayments_ipn_secret", IPN_SECRET):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
    assert resp.status_code == 400
    assert "order_id" in resp.json().get("error", {}).get("message", "").lower() or "order_id" in resp.text.lower()


def test_ipn_invalid_order_id_format_returns_400(client):
    """A non-UUID order_id (e.g. NOWPayments' numeric invoice_id mistakenly
    echoed) must be rejected — the welcome page validator demands UUIDs."""
    body, sig = _canonical_sign({"invoice_id": "ipn1", "order_id": "5228306332", "payment_status": "finished"})
    with patch("config.settings.nowpayments_ipn_secret", IPN_SECRET):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
    assert resp.status_code == 400


def test_ipn_pending_status_ignored(client):
    order_id = _uuid()
    body, sig = _canonical_sign({"invoice_id": "pending_inv", "order_id": order_id, "payment_status": "pending"})
    with patch("config.settings.nowpayments_ipn_secret", IPN_SECRET):
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

    assert get_key_by_order_id(order_id) is None


def test_ipn_finished_provisions_key(client):
    invoice = "crypto_inv_001"
    order_id = _uuid()
    body, sig = _canonical_sign({"invoice_id": invoice, "order_id": order_id, "payment_status": "finished"})
    with (
        patch("config.settings.nowpayments_ipn_secret", IPN_SECRET),
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
    assert data["order_id"] == order_id
    # Raw key NEVER in the IPN HTTP response
    assert "api_key" not in data
    # Response advertises the 30-day expiry to the IPN sender (audit + sanity)
    assert "expires_at" in data
    mock_tg.assert_called_once()

    from db import get_key_by_order_id

    row = get_key_by_order_id(order_id)
    assert row is not None
    assert row["order_id"] == order_id
    # Expiry is populated on a crypto-provisioned key (~30 days out)
    assert row["expires_at"] is not None
    from datetime import UTC, datetime

    exp = datetime.fromisoformat(row["expires_at"])
    delta_days = (exp - datetime.now(UTC)).total_seconds() / 86400
    assert 29 < delta_days < 31


def test_ipn_replay_same_invoice_returns_already_processed(client):
    invoice = "crypto_inv_replay"
    order_id = _uuid()
    body, sig = _canonical_sign({"invoice_id": invoice, "order_id": order_id, "payment_status": "finished"})
    with (
        patch("config.settings.nowpayments_ipn_secret", IPN_SECRET),
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
    order_id = _uuid()
    body, sig = _canonical_sign({"invoice_id": invoice, "order_id": order_id, "payment_status": "finished"})
    with (
        patch("config.settings.nowpayments_ipn_secret", IPN_SECRET),
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
    order_id = _uuid()
    body, sig = _canonical_sign({"invoice_id": "failed_inv", "order_id": order_id, "payment_status": "failed"})
    with patch("config.settings.nowpayments_ipn_secret", IPN_SECRET):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"

    from db import get_key_by_order_id

    assert get_key_by_order_id(order_id) is None


def test_ipn_partially_paid_dust_short_provisions_key(client):
    """actually_paid within 1% of pay_amount (dust rounding) auto-provisions."""
    invoice = "dust_ok_inv"
    order_id = _uuid()
    body, sig = _canonical_sign(
        {
            "invoice_id": invoice,
            "order_id": order_id,
            "payment_status": "partially_paid",
            "actually_paid": 15.02209,
            "pay_amount": 15.02209752,
        }
    )
    with (
        patch("config.settings.nowpayments_ipn_secret", IPN_SECRET),
        patch("crypto_billing._notify_telegram") as mock_tg,
    ):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "provisioned"
    mock_tg.assert_called_once()

    from db import get_key_by_order_id

    assert get_key_by_order_id(order_id) is not None


def test_ipn_partially_paid_underpaid_alerts_no_provision(client):
    """A real underpayment (<99%) alerts ops and provisions nothing."""
    invoice = "dust_short_inv"
    order_id = _uuid()
    body, sig = _canonical_sign(
        {
            "invoice_id": invoice,
            "order_id": order_id,
            "payment_status": "partially_paid",
            "actually_paid": 9.5,
            "pay_amount": 15.0,
        }
    )
    with (
        patch("config.settings.nowpayments_ipn_secret", IPN_SECRET),
        patch("crypto_billing._notify_telegram") as mock_tg,
    ):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"
    mock_tg.assert_called_once()

    from db import get_key_by_order_id

    assert get_key_by_order_id(order_id) is None


@pytest.mark.parametrize("status", ["failed", "expired", "refunded"])
def test_ipn_terminal_fail_states_alert_no_provision(client, status):
    """failed/expired/refunded each fire an ops alert and provision nothing."""
    order_id = _uuid()
    body, sig = _canonical_sign({"invoice_id": f"term_{status}_inv", "order_id": order_id, "payment_status": status})
    with (
        patch("config.settings.nowpayments_ipn_secret", IPN_SECRET),
        patch("crypto_billing._notify_telegram") as mock_tg,
    ):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"
    mock_tg.assert_called_once()

    from db import get_key_by_order_id

    assert get_key_by_order_id(order_id) is None


@pytest.mark.parametrize("status", ["waiting", "confirming"])
def test_ipn_intermediate_states_no_alert_no_provision(client, status):
    """waiting/confirming stay silent no-ops (no alert, no provision)."""
    order_id = _uuid()
    body, sig = _canonical_sign({"invoice_id": f"mid_{status}_inv", "order_id": order_id, "payment_status": status})
    with (
        patch("config.settings.nowpayments_ipn_secret", IPN_SECRET),
        patch("crypto_billing._notify_telegram") as mock_tg,
    ):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"
    mock_tg.assert_not_called()

    from db import get_key_by_order_id

    assert get_key_by_order_id(order_id) is None


@pytest.mark.parametrize(
    "status",
    ["confirming", "sending", "waiting"],
)
def test_ipn_non_terminal_states_are_no_ops(client, status):
    """Intermediate NOWPayments states must be silent no-ops (no key, no alert).

    Covers only the truly-silent states. partially_paid / expired / refunded /
    failed now emit ops alerts and are exercised by their dedicated tests; only
    `finished` (and dust-tolerant partially_paid) provisions a key.
    """
    invoice_id = f"state_{status}_inv"
    order_id = _uuid()
    body, sig = _canonical_sign({"invoice_id": invoice_id, "order_id": order_id, "payment_status": status})
    with patch("config.settings.nowpayments_ipn_secret", IPN_SECRET):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"

    from db import get_key_by_order_id

    assert get_key_by_order_id(order_id) is None


def test_ipn_pending_then_finished_provisions_key(client):
    """Regression: NOWPayments emits multiple IPNs per invoice (waiting->confirming
    ->finished). A non-finished IPN must NOT mark the invoice as replayed,
    otherwise the later "finished" event is dropped and no key is provisioned.
    """
    invoice = "lifecycle_inv_001"
    order_id = _uuid()
    pending_body, pending_sig = _canonical_sign(
        {"invoice_id": invoice, "order_id": order_id, "payment_status": "confirming"}
    )
    finished_body, finished_sig = _canonical_sign(
        {"invoice_id": invoice, "order_id": order_id, "payment_status": "finished"}
    )
    with (
        patch("config.settings.nowpayments_ipn_secret", IPN_SECRET),
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
    assert r2.json()["order_id"] == order_id

    from db import get_key_by_order_id

    row = get_key_by_order_id(order_id)
    assert row is not None
    assert row["expires_at"] is not None


def test_ipn_payment_id_fallback_when_invoice_id_absent(client):
    """If only `payment_id` is present, it stands in for the missing
    invoice_id (replay-cache key); `order_id` is still required separately."""
    order_id = _uuid()
    body, sig = _canonical_sign({"payment_id": "pay_fallback_001", "order_id": order_id, "payment_status": "finished"})
    with (
        patch("config.settings.nowpayments_ipn_secret", IPN_SECRET),
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
    assert resp.json()["order_id"] == order_id

    from db import get_key_by_order_id

    assert get_key_by_order_id(order_id) is not None


def test_ipn_concurrent_insert_race_returns_already_provisioned(client, caplog):
    """Two concurrent IPNs that both pass the in-memory replay cache must not
    crash with a 500 on the second INSERT. The unique index on order_id catches
    the loser; we treat that as idempotent (already_provisioned)."""
    import logging
    from unittest.mock import patch as _patch

    invoice = "race_inv_001"
    order_id = _uuid()
    body, sig = _canonical_sign({"invoice_id": invoice, "order_id": order_id, "payment_status": "finished"})

    # Fresh process state so the replay cache miss matches the race scenario.
    from crypto_billing import _processed_invoices

    _processed_invoices.clear()

    from db import save_api_key_with_pending as real_save_atomic

    save_call_count = {"n": 0}

    def racing_save(key_hash, raw_key, order_id, expires_at):
        save_call_count["n"] += 1
        if save_call_count["n"] == 1:
            # First call: actually insert (the "winning" worker)
            real_save_atomic(key_hash, raw_key, order_id=order_id, expires_at=expires_at)
            return
        # Second call: simulate the racing worker hitting the unique index
        import sqlite3 as _sq

        raise _sq.IntegrityError("UNIQUE constraint failed: api_keys.order_id")

    # The cold-cache idempotency check (`get_key_by_order_id` → already
    # provisioned) catches sequential replays cleanly. To force the actual
    # INSERT race we also stub that lookup to return None on the second call,
    # mimicking two workers that both passed the idempotency check before
    # either INSERT landed.
    lookup_call_count = {"n": 0}

    def racing_lookup(_order_id):
        lookup_call_count["n"] += 1
        return None

    with (
        _patch("config.settings.nowpayments_ipn_secret", IPN_SECRET),
        _patch("crypto_billing._notify_telegram"),
        _patch("crypto_billing.save_api_key_with_pending", side_effect=racing_save),
        _patch("crypto_billing.get_key_by_order_id", side_effect=racing_lookup),
        caplog.at_level(logging.INFO, logger="contrastapi"),
    ):
        r1 = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
        # Replay cache prevents the second IPN from racing for the same
        # invoice_id, so to reach the INSERT path we clear it between calls.
        _processed_invoices.clear()
        r2 = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )

    assert r1.status_code == 200
    assert r1.json()["status"] == "provisioned"
    assert r2.status_code == 200
    assert r2.json()["status"] == "already_provisioned"
    assert r2.json()["order_id"] == order_id
    # Race log line is emitted at INFO so ops can audit it
    assert "concurrent-insert lost race" in caplog.text


def test_ipn_signature_failure_logs_client_ip(client, caplog):
    """fail2ban needs the (CF-restored) source IP on each forged-IPN attempt."""
    import logging

    body = json.dumps({"invoice_id": "ipn_forge", "order_id": _uuid(), "payment_status": "finished"}).encode()
    with (
        patch("config.settings.nowpayments_ipn_secret", IPN_SECRET),
        caplog.at_level(logging.WARNING, logger="contrastapi"),
    ):
        resp = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": "deadbeef"},
        )
    assert resp.status_code == 403
    assert "signature verification failed from " in caplog.text


def test_save_api_key_with_pending_writes_both_columns_atomically():
    """Single INSERT must populate both `key_hash` and `pending_key` so the
    welcome-page polling loop never sees a row with NULL pending_key. Two-statement
    INSERT-then-UPDATE breaks this invariant if the UPDATE fails (disk full, etc.).
    """
    from auth import generate_key, hash_key
    from db import get_api_db, save_api_key_with_pending

    raw = generate_key()
    kh = hash_key(raw)
    order_id = _uuid()
    save_api_key_with_pending(kh, raw, order_id=order_id, expires_at=None)

    with get_api_db() as con:
        row = con.execute(
            "SELECT pending_key, pending_key_created_at, key_hash, expires_at FROM api_keys WHERE order_id = ?",
            (order_id,),
        ).fetchone()
    assert row is not None
    assert row[0] == raw  # pending_key populated
    assert row[1] is not None  # pending_key_created_at populated
    assert row[2] == kh
    assert row[3] is None


def test_e2e_checkout_to_welcome_returns_raw_key(client):
    """End-to-end happy path: checkout -> IPN finished -> /welcome serves raw key.

    Regression for the host+order_id integration class of bugs that broke
    the original wiring (SUCCESS_URL pointing at landing host with no route,
    welcome page demanding UUID order_id but webhook persisting numeric
    invoice_id, etc.). If any layer drifts again, this test fails.
    """
    fake_response = MagicMock()
    fake_response.read.return_value = json.dumps(
        {"id": 9999000111, "invoice_url": "https://nowpayments.io/payment/?iid=9999000111"}
    ).encode()
    fake_response.__enter__.return_value = fake_response
    fake_response.__exit__.return_value = False
    with (
        patch("config.settings.nowpayments_api_key", API_KEY),
        patch("crypto_billing.urllib.request.urlopen", return_value=fake_response),
    ):
        checkout = client.post("/v1/billing/crypto/checkout")
    assert checkout.status_code == 200
    order_id = checkout.json()["order_id"]
    invoice_id = checkout.json()["invoice_id"]

    body, sig = _canonical_sign({"invoice_id": invoice_id, "order_id": order_id, "payment_status": "finished"})
    with (
        patch("config.settings.nowpayments_ipn_secret", IPN_SECRET),
        patch("crypto_billing._notify_telegram"),
    ):
        ipn = client.post(
            "/v1/billing/crypto/webhook",
            content=body,
            headers={"x-nowpayments-sig": sig},
        )
    assert ipn.status_code == 200
    assert ipn.json()["status"] == "provisioned"

    welcome = client.get(f"/welcome?order_id={order_id}")
    assert welcome.status_code == 200
    # Raw key (cc_*) is rendered into the page exactly once
    assert 'id="api-key">cc_' in welcome.text

    # Second visit: pending key already consumed, page shows "already claimed"
    welcome2 = client.get(f"/welcome?order_id={order_id}")
    assert welcome2.status_code == 200
    assert "already been claimed" in welcome2.text


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
        patch("config.settings.nowpayments_api_key", API_KEY),
        patch("crypto_billing.urllib.request.urlopen", return_value=fake_response),
    ):
        resp = client.post("/v1/billing/crypto/checkout")
    assert resp.status_code == 502
