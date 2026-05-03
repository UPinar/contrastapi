"""Telegram alert helper. Fire-and-forget background thread; never raises."""

import logging
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

logger = logging.getLogger("contrastapi")

_TELEGRAM_TOKEN_FILE = Path("/etc/telegram-bot/token")
_TELEGRAM_CHAT_FILE = Path("/etc/telegram-bot/chat_ids")


def notify_telegram(message: str) -> None:
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
            except (urllib.error.URLError, OSError):
                logger.warning("Telegram notify failed for chat %s", cid)

    threading.Thread(target=_send, daemon=True).start()
