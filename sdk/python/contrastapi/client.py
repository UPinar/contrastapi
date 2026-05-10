"""ContrastAPI / AsyncContrastAPI — top-level clients.

Two parallel surfaces:
  * `ContrastAPI` (sync) → uses `httpx.Client`, namespace methods are plain `def`.
  * `AsyncContrastAPI` (async) → uses `httpx.AsyncClient`, namespace methods are
    `async def`.

Both classes accept the same options (`api_key`, `base_url`, `timeout`,
`allow_insecure`) and expose the same namespace property names. Choose whichever
matches your application's I/O model.

All 14 namespaces (cve, cwe, ioc, atlas, d3fend, domain, ip, asn, email, phone,
password, username, check, scan) are exposed as instance attributes. The async
client mirrors the sync surface 1:1 — same names, async methods.
"""

from __future__ import annotations

from typing import Any

from ._transport import DEFAULT_BASE_URL, _AsyncTransport, _SyncTransport
from ._version import __version__
from .models import StatusResponse, UsageResponse
from .namespaces.atlas import AsyncAtlas, Atlas
from .namespaces.cve import AsyncCve, AsyncCwe, Cve, Cwe
from .namespaces.d3fend import AsyncD3fend, D3fend
from .namespaces.domain import AsyncDomain, Domain
from .namespaces.intel import (
    Asn,
    AsyncAsn,
    AsyncEmail,
    AsyncIp,
    AsyncPassword,
    AsyncPhone,
    AsyncUsername,
    Email,
    Ip,
    Password,
    Phone,
    Username,
)
from .namespaces.ioc import AsyncIoc, Ioc
from .namespaces.security import AsyncCheck, AsyncScan, Check, Scan


class ContrastAPI:
    """Synchronous ContrastAPI client.

    Usage:
        >>> from contrastapi import ContrastAPI
        >>> client = ContrastAPI()  # keyless (free tier)
        >>> cve = client.cve.lookup("CVE-2021-44228")
        >>> assert cve["kev"]["in_kev"]
        >>> client.close()

    Or as context manager:
        >>> with ContrastAPI(api_key="cc_...") as client:
        ...     defenses = client.d3fend.defense_for_attack("T1059")
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float | None = None,
        allow_insecure: bool = False,
    ) -> None:
        self._transport = _SyncTransport(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            allow_insecure=allow_insecure,
        )
        self.cve = Cve(self._transport)
        self.cwe = Cwe(self._transport)
        self.ioc = Ioc(self._transport)
        self.atlas = Atlas(self._transport)
        self.d3fend = D3fend(self._transport)
        self.domain = Domain(self._transport)
        self.ip = Ip(self._transport)
        self.asn = Asn(self._transport)
        self.email = Email(self._transport)
        self.phone = Phone(self._transport)
        self.password = Password(self._transport)
        self.username = Username(self._transport)
        self.check = Check(self._transport)
        self.scan = Scan(self._transport)

    @property
    def version(self) -> str:
        return __version__

    def status(self) -> StatusResponse:
        """GET /v1/status — returns service health + version."""
        return self._transport.get("/v1/status")

    def usage(self) -> UsageResponse:
        """GET /v1/usage — returns rate-limit window for current API key (or anonymous IP)."""
        return self._transport.get("/v1/usage")

    def close(self) -> None:
        self._transport.close()

    def __enter__(self) -> ContrastAPI:
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()


class AsyncContrastAPI:
    """Asynchronous ContrastAPI client. Mirrors ContrastAPI namespace surface.

    Usage:
        >>> import asyncio
        >>> from contrastapi import AsyncContrastAPI
        >>> async def main():
        ...     async with AsyncContrastAPI() as client:
        ...         tech = await client.atlas.technique("AML.T0051")
        ...         print(tech["name"])
        >>> asyncio.run(main())
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float | None = None,
        allow_insecure: bool = False,
    ) -> None:
        self._transport = _AsyncTransport(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            allow_insecure=allow_insecure,
        )
        self.cve = AsyncCve(self._transport)
        self.cwe = AsyncCwe(self._transport)
        self.ioc = AsyncIoc(self._transport)
        self.atlas = AsyncAtlas(self._transport)
        self.d3fend = AsyncD3fend(self._transport)
        self.domain = AsyncDomain(self._transport)
        self.ip = AsyncIp(self._transport)
        self.asn = AsyncAsn(self._transport)
        self.email = AsyncEmail(self._transport)
        self.phone = AsyncPhone(self._transport)
        self.password = AsyncPassword(self._transport)
        self.username = AsyncUsername(self._transport)
        self.check = AsyncCheck(self._transport)
        self.scan = AsyncScan(self._transport)

    @property
    def version(self) -> str:
        return __version__

    async def status(self) -> StatusResponse:
        return await self._transport.aget("/v1/status")

    async def usage(self) -> UsageResponse:
        return await self._transport.aget("/v1/usage")

    async def aclose(self) -> None:
        await self._transport.aclose()

    async def __aenter__(self) -> AsyncContrastAPI:
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.aclose()
