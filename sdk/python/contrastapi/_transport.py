"""HTTP transport for ContrastAPI SDK — sync (httpx.Client) and async (httpx.AsyncClient).

Both transports share:
  * Base URL + API key handling (HTTPS-only unless allow_insecure=True).
  * Error envelope parsing via exceptions._parse_error.
  * Response size cap (10 MB) to mirror Node SDK behaviour.
  * Identical User-Agent (`contrastapi-python/<version>`).

Design note: keeping sync and async classes side-by-side in one module avoids
the duplicated-stub problem and makes the parity guarantee obvious. Namespace
classes accept the transport instance and call `transport.get(...)` /
`transport.post(...)` (or `aget` / `apost` for the async variant) — the rest is
just URL construction.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

import httpx

from ._version import __version__
from .exceptions import ContrastAPIError, TransportError, _parse_error

DEFAULT_BASE_URL = "https://api.contrastcyber.com"
DEFAULT_TIMEOUT = 30.0
MIN_TIMEOUT = 1.0
MAX_TIMEOUT = 120.0
MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB — parity with Node SDK
USER_AGENT = f"contrastapi-python/{__version__}"


def _normalize_base_url(base_url: str, *, allow_insecure: bool) -> str:
    parts = urlsplit(base_url)
    if parts.scheme not in ("https", "http"):
        raise ValueError(f"Unsupported scheme: {parts.scheme!r}")
    if parts.scheme == "http" and not allow_insecure:
        raise ValueError("Only HTTPS is allowed. Pass allow_insecure=True to override.")
    return base_url.rstrip("/")


def _build_headers(api_key: str | None, base_scheme: str, has_body: bool) -> dict[str, str]:
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if api_key:
        if base_scheme != "https":
            raise ValueError("Refusing to send API key over insecure connection")
        headers["X-API-Key"] = api_key
    if has_body:
        headers["Content-Type"] = "application/json"
    return headers


def _clamp_timeout(value: float | None) -> float:
    if value is None:
        return DEFAULT_TIMEOUT
    return max(MIN_TIMEOUT, min(float(value), MAX_TIMEOUT))


def _decode_response(response: httpx.Response) -> Any:
    """Parse JSON body with size cap. Raises ContrastAPIError on bad JSON or oversize."""
    content = response.content
    if len(content) > MAX_RESPONSE_BYTES:
        raise ContrastAPIError(
            f"Response too large ({len(content)} bytes > {MAX_RESPONSE_BYTES})",
            status_code=response.status_code,
        )
    try:
        return json.loads(content) if content else None
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ContrastAPIError(
            f"Invalid JSON response (HTTP {response.status_code}): {exc}",
            status_code=response.status_code,
        ) from exc


def _handle_response(response: httpx.Response) -> Any:
    body = _decode_response(response)
    if response.status_code >= 400:
        raise _parse_error(response.status_code, body)
    return body


class _SyncTransport:
    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        api_key: str | None = None,
        timeout: float | None = None,
        allow_insecure: bool = False,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = _normalize_base_url(base_url, allow_insecure=allow_insecure)
        self._scheme = urlsplit(self.base_url).scheme
        self.api_key = api_key
        self.timeout = _clamp_timeout(timeout)
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=self.timeout)

    def get(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        headers = _build_headers(self.api_key, self._scheme, has_body=False)
        try:
            response = self._client.get(self.base_url + path, params=params, headers=headers)
        except httpx.HTTPError as exc:
            raise TransportError(str(exc)) from exc
        return _handle_response(response)

    def post(self, path: str, *, json_body: Any | None = None) -> Any:
        headers = _build_headers(self.api_key, self._scheme, has_body=json_body is not None)
        try:
            response = self._client.post(self.base_url + path, json=json_body, headers=headers)
        except httpx.HTTPError as exc:
            raise TransportError(str(exc)) from exc
        return _handle_response(response)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> _SyncTransport:
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()


class _AsyncTransport:
    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        api_key: str | None = None,
        timeout: float | None = None,
        allow_insecure: bool = False,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = _normalize_base_url(base_url, allow_insecure=allow_insecure)
        self._scheme = urlsplit(self.base_url).scheme
        self.api_key = api_key
        self.timeout = _clamp_timeout(timeout)
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=self.timeout)

    async def aget(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        headers = _build_headers(self.api_key, self._scheme, has_body=False)
        try:
            response = await self._client.get(self.base_url + path, params=params, headers=headers)
        except httpx.HTTPError as exc:
            raise TransportError(str(exc)) from exc
        return _handle_response(response)

    async def apost(self, path: str, *, json_body: Any | None = None) -> Any:
        headers = _build_headers(self.api_key, self._scheme, has_body=json_body is not None)
        try:
            response = await self._client.post(self.base_url + path, json=json_body, headers=headers)
        except httpx.HTTPError as exc:
            raise TransportError(str(exc)) from exc
        return _handle_response(response)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> _AsyncTransport:
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.aclose()
