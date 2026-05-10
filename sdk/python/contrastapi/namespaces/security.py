"""Code-security + live-scan namespaces."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from .._transport import _AsyncTransport, _SyncTransport
from ..models import (
    CheckHeadersResponse,
    CodeCheckResponse,
    DependenciesResponse,
    ScanHeadersResponse,
)


def _enc(value: str) -> str:
    if value is None or value == "":
        raise ValueError("Missing required parameter")
    return quote(str(value), safe="")


def _validate_packages(packages: list[str]) -> list[str]:
    if not isinstance(packages, list) or not all(isinstance(p, str) for p in packages):
        raise ValueError("packages must be a list of strings")
    return packages


def _validate_headers(headers: dict[str, str]) -> dict[str, str]:
    if not isinstance(headers, dict):
        raise ValueError("headers must be a dict[str, str]")
    return headers


class Check:
    def __init__(self, transport: _SyncTransport) -> None:
        self._t = transport

    def secrets(self, code: str, language: str | None = None) -> CodeCheckResponse:
        body: dict[str, Any] = {"code": code}
        if language is not None:
            body["language"] = language
        return self._t.post("/v1/check/secrets", json_body=body)

    def injection(self, code: str, language: str | None = None) -> CodeCheckResponse:
        body: dict[str, Any] = {"code": code}
        if language is not None:
            body["language"] = language
        return self._t.post("/v1/check/injection", json_body=body)

    def headers(self, headers: dict[str, str]) -> CheckHeadersResponse:
        return self._t.post("/v1/check/headers", json_body={"headers": _validate_headers(headers)})

    def dependencies(self, packages: list[str]) -> DependenciesResponse:
        return self._t.post("/v1/check/dependencies", json_body={"packages": _validate_packages(packages)})


class Scan:
    def __init__(self, transport: _SyncTransport) -> None:
        self._t = transport

    def headers(self, domain: str) -> ScanHeadersResponse:
        return self._t.get(f"/v1/scan/headers/{_enc(domain)}")


class AsyncCheck:
    def __init__(self, transport: _AsyncTransport) -> None:
        self._t = transport

    async def secrets(self, code: str, language: str | None = None) -> CodeCheckResponse:
        body: dict[str, Any] = {"code": code}
        if language is not None:
            body["language"] = language
        return await self._t.apost("/v1/check/secrets", json_body=body)

    async def injection(self, code: str, language: str | None = None) -> CodeCheckResponse:
        body: dict[str, Any] = {"code": code}
        if language is not None:
            body["language"] = language
        return await self._t.apost("/v1/check/injection", json_body=body)

    async def headers(self, headers: dict[str, str]) -> CheckHeadersResponse:
        return await self._t.apost("/v1/check/headers", json_body={"headers": _validate_headers(headers)})

    async def dependencies(self, packages: list[str]) -> DependenciesResponse:
        return await self._t.apost("/v1/check/dependencies", json_body={"packages": _validate_packages(packages)})


class AsyncScan:
    def __init__(self, transport: _AsyncTransport) -> None:
        self._t = transport

    async def headers(self, domain: str) -> ScanHeadersResponse:
        return await self._t.aget(f"/v1/scan/headers/{_enc(domain)}")
