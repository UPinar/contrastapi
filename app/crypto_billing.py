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
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from datetime import UTC, datetime, timedelta

from auth import generate_key, hash_key
from config import NOWPAYMENTS_API_KEY, NOWPAYMENTS_IPN_SECRET, VERSION
from db import get_key_by_order_id, save_api_key, save_pending_key
from fastapi import APIRouter, HTTPException, Request
from webhooks import _notify_telegram

logger = logging.getLogger("contrastapi")

NOWPAYMENTS_API_BASE = "https://api.nowpayments.io/v1"
PRO_PRICE_USD = 7.00
PRO_VALIDITY_DAYS = 30
INVOICE_CREATE_TIMEOUT = 10
SUCCESS_URL = "https://contrastcyber.com/welcome"
CANCEL_URL = "https://contrastcyber.com/pricing"
ORDER_DESCRIPTION = "ContrastAPI Pro 30-day key"

# Allowlist for the redirect URL returned by NOWPayments — defense-in-depth
# against a poisoned upstream response causing an open-redirect.
ALLOWED_INVOICE_URL_PREFIXES = ("https://nowpayments.io/", "https://www.nowpayments.io/")

if not NOWPAYMENTS_API_KEY:
    logger.warning("NOWPAYMENTS_API_KEY is not set — crypto checkout endpoint will return 503")
if not NOWPAYMENTS_IPN_SECRET:
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


def _create_nowpayments_invoice(api_key: str) -> dict:
    """POST to NOWPayments /v1/invoice. Returns parsed JSON or raises HTTPException.

    No `pay_currency` is set: the NOWPayments hosted page lets the customer
    pick from any coin enabled on the account. This avoids hard failures when
    the per-coin minimum (e.g. ~11 USDT TRC20 at current rates) exceeds our
    $7/mo price; cheaper coins (BTC sats, TRX, DOGE) clear the minimum and
    auto-convert to the USDT TRC20 payout wallet.
    """
    payload = {
        "price_amount": PRO_PRICE_USD,
        "price_currency": "usd",
        "order_description": ORDER_DESCRIPTION,
        "ipn_callback_url": "https://api.contrastcyber.com/v1/billing/crypto/webhook",
        "success_url": SUCCESS_URL,
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
    if not NOWPAYMENTS_API_KEY:
        raise HTTPException(status_code=503, detail="Crypto payment temporarily unavailable")
    data = _create_nowpayments_invoice(NOWPAYMENTS_API_KEY)
    invoice_id = data.get("id")
    invoice_url = data.get("invoice_url")
    if not invoice_id or not invoice_url:
        logger.error("NOWPayments invoice missing id or invoice_url")
        raise HTTPException(status_code=502, detail="Malformed payment provider response")
    if not isinstance(invoice_url, str) or not invoice_url.startswith(ALLOWED_INVOICE_URL_PREFIXES):
        logger.error("NOWPayments invoice_url failed allowlist check")
        raise HTTPException(status_code=502, detail="Untrusted payment redirect")
    return {"invoice_id": str(invoice_id), "invoice_url": invoice_url}


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
    if not verify_ipn_signature(body, signature, NOWPAYMENTS_IPN_SECRET):
        logger.warning("NOWPayments IPN signature verification failed")
        raise HTTPException(status_code=403, detail="Invalid signature")
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from None

    invoice_id = payload.get("invoice_id") or payload.get("payment_id")
    if invoice_id is None:
        raise HTTPException(status_code=400, detail="Missing invoice_id")
    invoice_id = str(invoice_id)
    payment_status = payload.get("payment_status", "")

    # NOWPayments emits multiple IPN events per invoice as state advances
    # (waiting -> confirming -> finished). Non-terminal states must be ack'd
    # without entering the replay cache, otherwise a later "finished" event
    # for the same invoice_id would be silently dropped and the key never
    # provisioned.
    if payment_status != "finished":
        logger.info(
            "NOWPayments IPN ignored: invoice_id=%s payment_status=%s",
            invoice_id,
            payment_status,
        )
        return {"status": "ignored", "invoice_id": invoice_id, "payment_status": payment_status}

    # Replay protection guards only the provisioning code path.
    with _processed_lock:
        if invoice_id in _processed_invoices:
            logger.info("NOWPayments IPN replay ignored: invoice_id=%s", invoice_id)
            return {"status": "already_processed", "invoice_id": invoice_id}
        while len(_processed_invoices) >= _MAX_PROCESSED:
            _processed_invoices.popitem(last=False)
        _processed_invoices[invoice_id] = None

    # Idempotency: key already provisioned for this invoice (cold-cache safety
    # after a process restart where _processed_invoices is empty but the DB
    # row persists).
    if get_key_by_order_id(invoice_id):
        logger.info("NOWPayments IPN idempotent: key already exists for invoice %s", invoice_id)
        return {"status": "already_provisioned", "invoice_id": invoice_id}

    # Provision new Pro key with 30-day expiry (one-time crypto payment, no auto-renew).
    # Raw key delivered via welcome page (existing pending_keys flow).
    raw_key = generate_key()
    kh = hash_key(raw_key)
    expires_at = (datetime.now(UTC) + timedelta(days=PRO_VALIDITY_DAYS)).isoformat()
    save_api_key(kh, order_id=invoice_id, expires_at=expires_at)
    save_pending_key(invoice_id, raw_key)

    logger.info("Crypto Pro key provisioned for invoice %s (expires %s)", invoice_id, expires_at)
    _notify_telegram(
        f"<b>💰 New Crypto Pro Customer!</b>\n"
        f"Invoice: <code>{html.escape(invoice_id)}</code>\n"
        f"Expires: {html.escape(expires_at)}"
    )
    return {"status": "provisioned", "invoice_id": invoice_id, "expires_at": expires_at}
