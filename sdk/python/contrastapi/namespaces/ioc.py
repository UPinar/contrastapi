"""IOC namespace — indicator lookup, hash, phishing, bulk."""

from __future__ import annotations

from urllib.parse import quote

from .._transport import _AsyncTransport, _SyncTransport
from ..models import BulkIocResponse, HashResponse, IocResponse, PhishingResponse


def _enc(value: str) -> str:
    if value is None or value == "":
        raise ValueError("Missing required parameter")
    return quote(str(value), safe="")


def _enc_path(value: str) -> str:
    """For URL-typed indicators (paths) — preserve `/` as a separator."""
    if value is None or value == "":
        raise ValueError("Missing required parameter")
    return "/".join(quote(seg, safe="") for seg in str(value).split("/"))


def _validate_bulk(items: list[str]) -> list[str]:
    if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
        raise ValueError("indicators must be a list of strings")
    return items


class Ioc:
    def __init__(self, transport: _SyncTransport) -> None:
        self._t = transport

    def lookup(self, indicator: str) -> IocResponse:
        return self._t.get(f"/v1/ioc/{_enc_path(indicator)}")

    def hash(self, file_hash: str) -> HashResponse:
        return self._t.get(f"/v1/hash/{_enc(file_hash)}")

    def phishing(self, url: str) -> PhishingResponse:
        return self._t.get(f"/v1/phishing/{_enc_path(url)}")

    def bulk(self, indicators: list[str]) -> BulkIocResponse:
        return self._t.post("/v1/iocs/bulk", json_body={"indicators": _validate_bulk(indicators)})


class AsyncIoc:
    def __init__(self, transport: _AsyncTransport) -> None:
        self._t = transport

    async def lookup(self, indicator: str) -> IocResponse:
        return await self._t.aget(f"/v1/ioc/{_enc_path(indicator)}")

    async def hash(self, file_hash: str) -> HashResponse:
        return await self._t.aget(f"/v1/hash/{_enc(file_hash)}")

    async def phishing(self, url: str) -> PhishingResponse:
        return await self._t.aget(f"/v1/phishing/{_enc_path(url)}")

    async def bulk(self, indicators: list[str]) -> BulkIocResponse:
        return await self._t.apost("/v1/iocs/bulk", json_body={"indicators": _validate_bulk(indicators)})
