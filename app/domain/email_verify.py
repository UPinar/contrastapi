"""Combined email validation for v1.25.0: syntax + MX + disposable + role + free-provider.

Explicitly NOT included:
- SMTP `RCPT TO` deliverability probe. Hunter.io / NeverBounce-style mailbox
  enumeration is an ethical grey area: it leaks "this exact address exists"
  to anyone who asks, and unsolicited SMTP from datacenter IPs (Hetzner) is
  a Hetzner ToS risk. Customers needing that signal should use a service
  whose business model includes the SMTP-handshake liability.
- Catch-all detection. Same SMTP-probe ethics + low signal:noise.

What we do return is purely *passive* signal derived from DNS + a static
classification table — anyone with `dig` could reproduce it.
"""

from __future__ import annotations

import re

# Generic role / functional addresses. Localpart match is case-insensitive
# (we lowercase before lookup). The list is intentionally short — we only
# want unambiguously-generic patterns; CRM tools have lots of overlap with
# real user names ("hr@", "billing@") so we skip those.
ROLE_KEYWORDS = frozenset(
    [
        "admin",
        "administrator",
        "info",
        "noreply",
        "no-reply",
        "donotreply",
        "support",
        "contact",
        "hello",
        "hi",
        "sales",
        "marketing",
        "webmaster",
        "postmaster",
        "abuse",
        "security",
        "team",
        "office",
        "help",
        "feedback",
    ]
)

# Consumer-mailbox providers. Hitting one of these on a B2B-sounding handle
# is a useful "personal address used for work" signal for our marketing /
# CRM customers. Punycode equivalents are NOT included — IDN consumer mail
# providers are rare and we'd rather miss them than expand the table blindly.
FREE_PROVIDERS = frozenset(
    [
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "msn.com",
        "yahoo.com",
        "yahoo.co.uk",
        "yahoo.co.jp",
        "ymail.com",
        "rocketmail.com",
        "icloud.com",
        "me.com",
        "mac.com",
        "proton.me",
        "protonmail.com",
        "pm.me",
        "aol.com",
        "fastmail.com",
        "fastmail.fm",
        "tutanota.com",
        "tutanota.de",
        "tuta.io",
        "zoho.com",
        "yandex.com",
        "yandex.ru",
        "mail.ru",
        "mail.com",
        "gmx.com",
        "gmx.de",
        "gmx.net",
        "web.de",
        "qq.com",
        "163.com",
        "126.com",
        "naver.com",
        "daum.net",
    ]
)

# Pragmatic syntax check. NOT a full RFC 5322 parser (those exist as
# 800-line libs); this rejects the obvious garbage and lets the MX/DNS
# resolution decide deliverability. Allowed local-part chars are the
# unquoted superset from RFC 5321 §4.1.2 (Atom). The domain must have at
# least one dot; we don't enforce ICANN's 2-char TLD policy at the regex
# level (single-char TLDs don't exist in the public root anyway, and a
# strict cap would reject future puny-TLDs like `xn--abc`).
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+\-!#$&'*/=?^`{|}~]+"
    r"@"
    r"[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$"
)


def _has_control_chars(s: str) -> bool:
    return any(ord(c) < 0x20 or ord(c) == 0x7F for c in s)


def parse_email(email: str) -> tuple[str, str] | None:
    """Split a candidate email into (local, domain) lowercased, or None on bad
    input. Strict on length + control chars before the regex check so a
    pathological 100KB input never reaches the regex engine.
    """
    if not email or len(email) > 254:
        return None
    if _has_control_chars(email):
        return None
    if not _EMAIL_RE.match(email):
        return None
    local, _, domain = email.rpartition("@")
    if not local or not domain:
        return None
    # RFC 5321 §4.5.3.1.1: local-part max 64 octets.
    if len(local) > 64:
        return None
    return local.lower(), domain.lower()


def role_classification(local_part: str) -> tuple[bool, str | None]:
    """Return (is_role, role_keyword). Case-insensitive lookup. The role
    keyword is the *exact* match from ROLE_KEYWORDS that the local part
    started with (so 'admin+marketing@' classifies as 'admin').
    """
    lp = local_part.lower()
    # Strip plus-tags (Gmail-style) before classification — `noreply+ci@` is
    # still a noreply.
    if "+" in lp:
        lp = lp.split("+", 1)[0]
    if lp in ROLE_KEYWORDS:
        return True, lp
    return False, None


def is_free_provider(domain: str) -> bool:
    return domain.lower() in FREE_PROVIDERS
