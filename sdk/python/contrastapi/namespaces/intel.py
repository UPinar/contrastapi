"""Compact namespaces for endpoints with 1-2 methods each:
ip, asn, email, phone, password, username.
"""

from __future__ import annotations

from urllib.parse import quote

from .._transport import _AsyncTransport, _SyncTransport
from ..models import (
    AsnResponse,
    DisposableResponse,
    EmailMxResponse,
    IpLookupResponse,
    PasswordResponse,
    PhoneLookupResponse,
    ThreatReportResponse,
    UsernameLookupResponse,
)


def _enc(value: str) -> str:
    if value is None or value == "":
        raise ValueError("Missing required parameter")
    return quote(str(value), safe="")


# --- IP ---


class Ip:
    def __init__(self, transport: _SyncTransport) -> None:
        self._t = transport

    def lookup(self, ip: str) -> IpLookupResponse:
        return self._t.get(f"/v1/ip/{_enc(ip)}")

    def threat_report(self, ip: str) -> ThreatReportResponse:
        return self._t.get(f"/v1/threat-report/{_enc(ip)}")


class AsyncIp:
    def __init__(self, transport: _AsyncTransport) -> None:
        self._t = transport

    async def lookup(self, ip: str) -> IpLookupResponse:
        return await self._t.aget(f"/v1/ip/{_enc(ip)}")

    async def threat_report(self, ip: str) -> ThreatReportResponse:
        return await self._t.aget(f"/v1/threat-report/{_enc(ip)}")


# --- ASN ---


class Asn:
    def __init__(self, transport: _SyncTransport) -> None:
        self._t = transport

    def lookup(self, target: str) -> AsnResponse:
        return self._t.get(f"/v1/asn/{_enc(target)}")


class AsyncAsn:
    def __init__(self, transport: _AsyncTransport) -> None:
        self._t = transport

    async def lookup(self, target: str) -> AsnResponse:
        return await self._t.aget(f"/v1/asn/{_enc(target)}")


# --- Email ---


class Email:
    def __init__(self, transport: _SyncTransport) -> None:
        self._t = transport

    def mx(self, domain: str) -> EmailMxResponse:
        return self._t.get(f"/v1/email/mx/{_enc(domain)}")

    def disposable(self, email: str) -> DisposableResponse:
        return self._t.get(f"/v1/email/disposable/{_enc(email)}")


class AsyncEmail:
    def __init__(self, transport: _AsyncTransport) -> None:
        self._t = transport

    async def mx(self, domain: str) -> EmailMxResponse:
        return await self._t.aget(f"/v1/email/mx/{_enc(domain)}")

    async def disposable(self, email: str) -> DisposableResponse:
        return await self._t.aget(f"/v1/email/disposable/{_enc(email)}")


# --- Phone ---


class Phone:
    def __init__(self, transport: _SyncTransport) -> None:
        self._t = transport

    def lookup(self, number: str) -> PhoneLookupResponse:
        return self._t.get(f"/v1/phone/{_enc(number)}")


class AsyncPhone:
    def __init__(self, transport: _AsyncTransport) -> None:
        self._t = transport

    async def lookup(self, number: str) -> PhoneLookupResponse:
        return await self._t.aget(f"/v1/phone/{_enc(number)}")


# --- Password ---


class Password:
    def __init__(self, transport: _SyncTransport) -> None:
        self._t = transport

    def check(self, sha1_hash: str) -> PasswordResponse:
        return self._t.get(f"/v1/password/{_enc(sha1_hash)}")


class AsyncPassword:
    def __init__(self, transport: _AsyncTransport) -> None:
        self._t = transport

    async def check(self, sha1_hash: str) -> PasswordResponse:
        return await self._t.aget(f"/v1/password/{_enc(sha1_hash)}")


# --- Username (NEW vs Node SDK v1.3.0) ---


class Username:
    def __init__(self, transport: _SyncTransport) -> None:
        self._t = transport

    def lookup(self, username: str) -> UsernameLookupResponse:
        return self._t.get(f"/v1/username/{_enc(username)}")


class AsyncUsername:
    def __init__(self, transport: _AsyncTransport) -> None:
        self._t = transport

    async def lookup(self, username: str) -> UsernameLookupResponse:
        return await self._t.aget(f"/v1/username/{_enc(username)}")
