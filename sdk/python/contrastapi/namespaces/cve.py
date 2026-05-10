"""CVE namespace — vulnerabilities, KEV, CWE, exploits, bulk lookup, leading list."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from .._transport import _AsyncTransport, _SyncTransport
from ..models import (
    BulkCveResponse,
    CveResponse,
    CveSearchResponse,
    CvssDetailsResponse,
    CweLookupResponse,
    ExploitResponse,
    KevDetailResponse,
    RiskScoreResponse,
)


def _enc(value: str) -> str:
    if value is None or value == "":
        raise ValueError("Missing required parameter")
    return quote(str(value), safe="")


def _search_params(
    *,
    product: str | None = None,
    severity: str | None = None,
    days: int | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if product is not None:
        params["product"] = product
    if severity is not None:
        params["severity"] = severity
    if days is not None:
        params["days"] = days
    if limit is not None:
        params["limit"] = limit
    return params


def _leading_params(
    *,
    limit: int | None = None,
    offset: int | None = None,
    include: str | None = None,
) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if include is not None:
        params["include"] = include
    return params


def _validate_bulk_ids(ids: list[str]) -> list[str]:
    if not isinstance(ids, list) or not all(isinstance(c, str) for c in ids):
        raise ValueError("cve_ids must be a list of strings")
    return ids


class Cve:
    def __init__(self, transport: _SyncTransport) -> None:
        self._t = transport

    def lookup(self, cve_id: str) -> CveResponse:
        return self._t.get(f"/v1/cve/{_enc(cve_id)}")

    def search(self, **kwargs: Any) -> CveSearchResponse:
        return self._t.get("/v1/cves", params=_search_params(**kwargs))

    def leading(self, **kwargs: Any) -> CveSearchResponse:
        return self._t.get("/v1/cve/leading", params=_leading_params(**kwargs))

    def kev(self, cve_id: str) -> KevDetailResponse:
        return self._t.get(f"/v1/kev/{_enc(cve_id)}")

    def exploit(self, cve_id: str) -> ExploitResponse:
        return self._t.get(f"/v1/exploit/{_enc(cve_id)}")

    def risk_score(self, cve_id: str) -> RiskScoreResponse:
        """v1.29.1 — Composite risk score (CVSS+EPSS+KEV+PoC fusion, 0-100)."""
        return self._t.get(f"/v1/cve/{_enc(cve_id)}/risk_score")

    def cvss_details(self, vector: str) -> CvssDetailsResponse:
        """v1.29.1 — Parse a CVSS v3.x vector into per-metric breakdown + recomputed score."""
        return self._t.get("/v1/cvss/details", params={"vector": vector})

    def bulk(self, cve_ids: list[str]) -> BulkCveResponse:
        return self._t.post("/v1/cves/bulk", json_body={"cve_ids": _validate_bulk_ids(cve_ids)})


class Cwe:
    def __init__(self, transport: _SyncTransport) -> None:
        self._t = transport

    def lookup(self, cwe_id: str) -> CweLookupResponse:
        return self._t.get(f"/v1/cwe/{_enc(cwe_id)}")


class AsyncCve:
    def __init__(self, transport: _AsyncTransport) -> None:
        self._t = transport

    async def lookup(self, cve_id: str) -> CveResponse:
        return await self._t.aget(f"/v1/cve/{_enc(cve_id)}")

    async def search(self, **kwargs: Any) -> CveSearchResponse:
        return await self._t.aget("/v1/cves", params=_search_params(**kwargs))

    async def leading(self, **kwargs: Any) -> CveSearchResponse:
        return await self._t.aget("/v1/cve/leading", params=_leading_params(**kwargs))

    async def kev(self, cve_id: str) -> KevDetailResponse:
        return await self._t.aget(f"/v1/kev/{_enc(cve_id)}")

    async def exploit(self, cve_id: str) -> ExploitResponse:
        return await self._t.aget(f"/v1/exploit/{_enc(cve_id)}")

    async def risk_score(self, cve_id: str) -> RiskScoreResponse:
        """v1.29.1 — Composite risk score (CVSS+EPSS+KEV+PoC fusion, 0-100)."""
        return await self._t.aget(f"/v1/cve/{_enc(cve_id)}/risk_score")

    async def cvss_details(self, vector: str) -> CvssDetailsResponse:
        """v1.29.1 — Parse a CVSS v3.x vector into per-metric breakdown + recomputed score."""
        return await self._t.aget("/v1/cvss/details", params={"vector": vector})

    async def bulk(self, cve_ids: list[str]) -> BulkCveResponse:
        return await self._t.apost("/v1/cves/bulk", json_body={"cve_ids": _validate_bulk_ids(cve_ids)})


class AsyncCwe:
    def __init__(self, transport: _AsyncTransport) -> None:
        self._t = transport

    async def lookup(self, cwe_id: str) -> CweLookupResponse:
        return await self._t.aget(f"/v1/cwe/{_enc(cwe_id)}")
