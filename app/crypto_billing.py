"""NOWPayments crypto checkout + IPN webhook handler.

Flow:
  1. Customer clicks "Pay with Crypto" on pricing page
     -> POST /v1/billing/crypto/checkout (no body)
  2. We POST to NOWPayments /v1/invoice with X-API-Key
     -> return {invoice_id, invoice_url}
  3. Customer redirected to NOWPayments hosted page
     -> pays USDT TRC20 (~$7)
  4. NOWPayments POSTs IPN to /v1/billing/crypto/webhook
     (HMAC-SHA512 signed, sorted-keys canonical JSON)
  5. payment_status == "finished" -> generate API key, save in DB
     -> raw key delivered via existing welcome page polling pattern
"""

import hashlib
import hmac
import html
import json
import logging
import sqlite3
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import OrderedDict
from datetime import UTC, datetime, timedelta

from auth import generate_key, hash_key
from config import VERSION, settings
from db import get_key_by_order_id, save_api_key_with_pending
from fastapi import APIRouter, HTTPException, Request
from validation import get_client_ip
from webhooks import _notify_telegram

logger = logging.getLogger("contrastapi")


def _safe(value: object) -> str:
    """Strip CR/LF from values flowing into log records (defense vs log injection)."""
    return str(value).replace("\r", "").replace("\n", "")


NOWPAYMENTS_API_BASE = "https://api.nowpayments.io/v1"
PRO_PRICE_USD = 7.00
PRO_VALIDITY_DAYS = 30
INVOICE_CREATE_TIMEOUT = 10
SUCCESS_URL = "https://api.contrastcyber.com/welcome"
CANCEL_URL = "https://contrastcyber.com/pricing"
ORDER_DESCRIPTION = "ContrastAPI Pro 30-day key"

# Allowlist for the redirect URL returned by NOWPayments — defense-in-depth
# against a poisoned upstream response causing an open-redirect. Pinned to the
# apex; if NOWPayments ever migrates to a subdomain we want the deploy to fail
# loudly here rather than silently redirecting users somewhere unexpected.
ALLOWED_INVOICE_URL_PREFIXES = ("https://nowpayments.io/",)

if not settings.nowpayments_api_key:
    logger.warning("NOWPAYMENTS_API_KEY is not set — crypto checkout endpoint will return 503")
if not settings.nowpayments_ipn_secret:
    logger.warning("NOWPAYMENTS_IPN_SECRET is not set — all IPN webhooks will be rejected")

router = APIRouter(tags=["Billing"])

# Replay protection (separate from webhooks.py to keep modules isolated)
_processed_invoices: OrderedDict[str, None] = OrderedDict()
_processed_lock = threading.Lock()
_MAX_PROCESSED = 10000


def _canonical_sorted_json(payload: dict) -> str:
    """NOWPayments IPN signature spec: sorted keys, no whitespace separators."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def verify_ipn_signature(body_bytes: bytes, signature: str, secret: str) -> bool:
    """Verify NOWPayments IPN HMAC-SHA512 signature.

    NOWPayments signs the JSON body sorted by keys (canonical form), not the
    raw bytes. We must re-serialize before HMAC.
    """
    if not secret or not signature:
        return False
    try:
        payload = json.loads(body_bytes)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    canonical = _canonical_sorted_json(payload)
    expected = hmac.new(secret.encode(), canonical.encode(), hashlib.sha512).hexdigest()
    return hmac.compare_digest(expected, signature)


def _create_nowpayments_invoice(api_key: str, order_id: str) -> dict:
    """POST to NOWPayments /v1/invoice. Returns parsed JSON or raises HTTPException.

    No `pay_currency` is set: the NOWPayments hosted page lets the customer
    pick from any coin enabled on the account. This avoids hard failures when
    the per-coin minimum (e.g. ~11 USDT TRC20 at current rates) exceeds our
    $7/mo price; cheaper coins (BTC sats, TRX, DOGE) clear the minimum and
    auto-convert to the USDT TRC20 payout wallet.

    `order_id` is our locally-generated UUID, echoed back in the IPN and
    appended to `success_url` so the welcome page can identify the order
    without depending on NOWPayments' undocumented redirect querystring.
    """
    payload = {
        "price_amount": PRO_PRICE_USD,
        "price_currency": "usd",
        "order_id": order_id,
        "order_description": ORDER_DESCRIPTION,
        "ipn_callback_url": "https://api.contrastcyber.com/v1/billing/crypto/webhook",
        "success_url": f"{SUCCESS_URL}?order_id={urllib.parse.quote(order_id)}",
        "cancel_url": CANCEL_URL,
    }
    body = json.dumps(payload).encode()
    # Identify ourselves: NOWPayments anti-bot filter rejects the default
    # "Python-urllib/X.Y" User-Agent with a 403, even when the API key is valid.
    req = urllib.request.Request(
        f"{NOWPAYMENTS_API_BASE}/invoice",
        data=body,
        method="POST",
        headers={
            "X-API-Key": api_key,
            "Content-Type": "application/json",
            "User-Agent": f"ContrastAPI/{VERSION} (+https://contrastcyber.com)",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=INVOICE_CREATE_TIMEOUT) as resp:
            raw = resp.read()
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        logger.error("NOWPayments invoice request failed: %s", e)
        raise HTTPException(status_code=502, detail="Payment provider unreachable") from None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        logger.error("NOWPayments invoice response was not valid JSON")
        raise HTTPException(status_code=502, detail="Malformed payment provider response") from None


@router.post("/v1/billing/crypto/checkout", include_in_schema=False)
async def crypto_checkout(request: Request) -> dict:
    """Create a NOWPayments invoice for the $7/mo Pro tier.

    Returns the hosted checkout URL the browser should redirect to.
    """
    if not settings.nowpayments_api_key:
        raise HTTPException(status_code=503, detail="Crypto payment temporarily unavailable")
    order_id = str(uuid.uuid4())
    data = _create_nowpayments_invoice(settings.nowpayments_api_key, order_id)
    invoice_id = data.get("id")
    invoice_url = data.get("invoice_url")
    if not invoice_id or not invoice_url:
        logger.error("NOWPayments invoice missing id or invoice_url")
        raise HTTPException(status_code=502, detail="Malformed payment provider response")
    if not isinstance(invoice_url, str) or not invoice_url.startswith(ALLOWED_INVOICE_URL_PREFIXES):
        logger.error("NOWPayments invoice_url failed allowlist check")
        raise HTTPException(status_code=502, detail="Untrusted payment redirect")
    return {"invoice_id": str(invoice_id), "invoice_url": invoice_url, "order_id": order_id}


@router.post("/v1/billing/crypto/webhook", include_in_schema=False)
async def crypto_ipn(request: Request) -> dict:
    """Handle NOWPayments IPN.

    Verifies HMAC-SHA512 signature on canonical (sorted-keys) JSON body.
    On payment_status == "finished", provisions a Pro API key for the
    invoice_id (idempotent + replay-protected).
    """
    body = await request.body()
    if len(body) > 1_048_576:
        raise HTTPException(status_code=413, detail="Payload too large")
    signature = request.headers.get("x-nowpayments-sig", "")
    if not verify_ipn_signature(body, signature, settings.nowpayments_ipn_secret):
        # Logging the (CF-restored) client IP is what enables fail2ban to
        # catch flood/forgery attempts on the public webhook endpoint.
        logger.warning(
            "NOWPayments IPN signature verification failed from %s",
            get_client_ip(request),
        )
        raise HTTPException(status_code=403, detail="Invalid signature")
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from None

    invoice_id = payload.get("invoice_id") or payload.get("payment_id")
    if invoice_id is None:
        raise HTTPException(status_code=400, detail="Missing invoice_id")
    invoice_id = str(invoice_id)
    # `order_id` is the UUID we sent on the outbound /invoice request and that
    # NOWPayments echoes back. The welcome page validates UUID format, so we
    # MUST persist this value (not the numeric `invoice_id`) under the order_id
    # column. Defense vs poisoned IPN: validate UUID shape before trusting it.
    raw_order_id = payload.get("order_id")
    if not raw_order_id:
        raise HTTPException(status_code=400, detail="Missing order_id")
    try:
        order_id = str(uuid.UUID(str(raw_order_id)))
    except (ValueError, AttributeError, TypeError) as e:
        logger.warning(
            "NOWPayments IPN rejected: invoice_id=%s order_id=%r reason=%s",
            _safe(invoice_id),
            raw_order_id,
            e,
        )
        raise HTTPException(status_code=400, detail="Invalid order_id format") from None
    payment_status = payload.get("payment_status", "")

    # NOWPayments emits multiple IPN events per invoice as state advances
    # (waiting -> confirming -> finished). Non-terminal states must be ack'd
    # without entering the replay cache, otherwise a later "finished" event
    # for the same invoice_id would be silently dropped and the key never
    # provisioned.
    if payment_status != "finished":
        logger.info(
            "NOWPayments IPN ignored: invoice_id=%s order_id=%s payment_status=%s",
            _safe(invoice_id),
            order_id,
            _safe(payment_status),
        )
        return {
            "status": "ignored",
            "invoice_id": invoice_id,
            "order_id": order_id,
            "payment_status": payment_status,
        }

    # Replay protection keyed by invoice_id (stable per NOWPayments invoice).
    with _processed_lock:
        if invoice_id in _processed_invoices:
            logger.info("NOWPayments IPN replay ignored: invoice_id=%s", _safe(invoice_id))
            return {"status": "already_processed", "invoice_id": invoice_id, "order_id": order_id}
        while len(_processed_invoices) >= _MAX_PROCESSED:
            _processed_invoices.popitem(last=False)
        _processed_invoices[invoice_id] = None

    # Idempotency: key already provisioned for this order (cold-cache safety
    # after a process restart where _processed_invoices is empty but the DB
    # row persists).
    if get_key_by_order_id(order_id):
        logger.info("NOWPayments IPN idempotent: key already exists for order %s", order_id)
        return {"status": "already_provisioned", "invoice_id": invoice_id, "order_id": order_id}

    # Provision new Pro key with 30-day expiry (one-time crypto payment, no auto-renew).
    # Single atomic INSERT writes both the api_keys row AND the one-time
    # pending_key column in one transaction — keyed on our UUID `order_id`
    # so the welcome page's UUID validator accepts it. If we ever split this
    # into two statements again we re-introduce the "row exists but no pending
    # key → welcome page polls forever" failure mode.
    raw_key = generate_key()
    kh = hash_key(raw_key)
    expires_at = (datetime.now(UTC) + timedelta(days=PRO_VALIDITY_DAYS)).isoformat()
    try:
        save_api_key_with_pending(kh, raw_key, order_id=order_id, expires_at=expires_at)
    except sqlite3.IntegrityError:
        # Concurrent IPN for the same order_id won the insert race. The replay
        # cache (above) catches sequential replays, but two simultaneous
        # workers can both pass it before either INSERT lands. The unique index
        # on api_keys.order_id then rejects the loser — treat as idempotent.
        logger.info(
            "NOWPayments IPN concurrent-insert lost race for order %s, treating as already provisioned",
            order_id,
        )
        return {"status": "already_provisioned", "invoice_id": invoice_id, "order_id": order_id}

    logger.info(
        "Crypto Pro key provisioned for order %s (invoice %s, expires %s)",
        order_id,
        _safe(invoice_id),
        expires_at,
    )
    _notify_telegram(
        f"<b>💰 New Crypto Pro Customer!</b>\n"
        f"Order: <code>{html.escape(order_id)}</code>\n"
        f"Invoice: <code>{html.escape(invoice_id)}</code>\n"
        f"Expires: {html.escape(expires_at)}"
    )
    return {
        "status": "provisioned",
        "invoice_id": invoice_id,
        "order_id": order_id,
        "expires_at": expires_at,
    }
