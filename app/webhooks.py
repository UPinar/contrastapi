"""Lemon Squeezy webhook handler for API key provisioning.

Flow:
  1. Customer pays via Lemon Squeezy checkout
  2. LS sends POST /webhooks/lemonsqueezy with signed payload
  3. We verify HMAC-SHA256 signature
  4. order_created  → generate API key, store in DB (key delivered via LS email)
  5. subscription_cancelled/expired → deactivate key
"""

import hashlib
import hmac
import html
import json
import logging
import threading
import urllib.parse
import urllib.request
from collections import OrderedDict
from pathlib import Path

from auth import generate_key, hash_key
from config import LEMONSQUEEZY_WEBHOOK_SECRET
from db import deactivate_api_key, get_key_by_order_id, save_api_key, save_pending_key
from fastapi import APIRouter, HTTPException, Request

logger = logging.getLogger("contrastapi")

if not LEMONSQUEEZY_WEBHOOK_SECRET:
    logger.warning("LEMONSQUEEZY_WEBHOOK_SECRET is not set — all webhooks will be rejected")

_TELEGRAM_TOKEN_FILE = Path("/etc/telegram-bot/token")
_TELEGRAM_CHAT_FILE = Path("/etc/telegram-bot/chat_ids")


def _notify_telegram(message: str) -> None:
    """Send Telegram notification in background thread (fire-and-forget)."""

    def _send():
        try:
            token = _TELEGRAM_TOKEN_FILE.read_text().strip()
            chat_ids = _TELEGRAM_CHAT_FILE.read_text().splitlines()
        except FileNotFoundError:
            return
        for line in chat_ids:
            cid = line.strip()
            if not cid or cid.startswith("#"):
                continue
            try:
                data = urllib.parse.urlencode(
                    {
                        "chat_id": cid,
                        "parse_mode": "HTML",
                        "text": message,
                    }
                ).encode()
                req = urllib.request.Request(
                    f"https://api.telegram.org/bot{token}/sendMessage",
                    data=data,
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=10)
            except Exception:
                logger.warning("Telegram notify failed for chat %s", cid)

    threading.Thread(target=_send, daemon=True).start()


router = APIRouter(tags=["Webhooks"])

# Replay protection: track processed event IDs (in-memory, FIFO eviction)
_processed_events: OrderedDict[str, None] = OrderedDict()
_processed_lock = threading.Lock()
_MAX_PROCESSED = 10000


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify Lemon Squeezy HMAC-SHA256 webhook signature."""
    if not secret or not signature:
        return False
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _extract_order_id(data: dict) -> str | None:
    """Extract order ID from webhook payload (data.id or data.attributes.order_id)."""
    # order_created: data.id is the order ID
    # subscription events: data.attributes.order_id
    attrs = data.get("attributes", {})
    order_id = attrs.get("order_id") or attrs.get("identifier")
    if order_id:
        return str(order_id)
    data_id = data.get("id")
    if data_id:
        return str(data_id)
    return None


@router.post("/webhooks/lemonsqueezy", include_in_schema=False)
async def lemonsqueezy_webhook(request: Request):
    """Handle Lemon Squeezy webhook events."""
    # Read raw body for signature verification (limit to 1MB to prevent memory exhaustion)
    body = await request.body()
    if len(body) > 1_048_576:
        raise HTTPException(status_code=413, detail="Payload too large")
    signature = request.headers.get("x-signature", "")

    if not verify_signature(body, signature, LEMONSQUEEZY_WEBHOOK_SECRET):
        logger.warning("Webhook signature verification failed")
        raise HTTPException(status_code=403, detail="Invalid signature")

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from None

    meta = payload.get("meta", {})
    event_name = meta.get("event_name", "")
    event_id = meta.get("event_id")
    data = payload.get("data", {})

    # Replay protection: skip already-processed events
    if event_id:
        with _processed_lock:
            if event_id in _processed_events:
                logger.info("Webhook replay ignored: event_id=%s", event_id)
                return {"status": "already_processed", "event_id": event_id}
            # FIFO eviction: remove oldest entries when store is full
            while len(_processed_events) >= _MAX_PROCESSED:
                _processed_events.popitem(last=False)
            _processed_events[event_id] = None

    if event_name == "order_created":
        return _handle_order_created(data)
    elif event_name in ("subscription_cancelled", "subscription_expired"):
        return _handle_subscription_ended(data, event_name)
    else:
        # Unknown event — acknowledge silently
        logger.info("Webhook event ignored: %s", event_name)
        return {"status": "ignored", "event": event_name}


def _handle_order_created(data: dict) -> dict:
    """Generate and store API key for a new order."""
    order_id = _extract_order_id(data)
    if not order_id:
        raise HTTPException(status_code=400, detail="Missing order ID in payload")

    # Idempotency: check if key already exists for this order
    existing = get_key_by_order_id(order_id)
    if existing:
        logger.info("Webhook idempotent: key already exists for order %s", order_id)
        return {"status": "already_provisioned", "order_id": order_id}

    # Generate and store — raw key is delivered via Lemon Squeezy email,
    # never exposed in the webhook HTTP response
    raw_key = generate_key()
    kh = hash_key(raw_key)
    save_api_key(kh, order_id=order_id)
    save_pending_key(order_id, raw_key)

    logger.info("API key provisioned for order %s", order_id)
    _notify_telegram(f"<b>💰 New Pro Customer!</b>\nOrder: <code>{html.escape(order_id)}</code>")

    return {"status": "provisioned", "order_id": order_id}


def _handle_subscription_ended(data: dict, event_name: str) -> dict:
    """Deactivate API key when subscription is cancelled or expired."""
    order_id = _extract_order_id(data)
    if not order_id:
        raise HTTPException(status_code=400, detail="Missing order ID in payload")

    count = deactivate_api_key(order_id)
    logger.info("Webhook %s: deactivated %d key(s) for order %s", event_name, count, order_id)
    return {"status": "deactivated", "order_id": order_id, "keys_affected": count}
