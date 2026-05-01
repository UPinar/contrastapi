"""ATLAS namespace — MITRE ATLAS AI/ML attack catalog (techniques + case studies)."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from .._transport import _AsyncTransport, _SyncTransport
from ..models import (
    AtlasCaseStudyResponse,
    AtlasCaseStudySearchResponse,
    AtlasTechniqueResponse,
    AtlasTechniqueSearchResponse,
    BulkAtlasTechniqueResponse,
)


def _enc(value: str) -> str:
    if value is None or value == "":
        raise ValueError("Missing required parameter")
    return quote(str(value), safe="")


def _resolve_keyword(keyword: str | None, q: str | None) -> str | None:
    """Server param is `keyword`; SDK accepts `keyword=` or back-compat `q=` (Node parity)."""
    if keyword is not None and q is not None:
        raise ValueError("Pass only one of `keyword` or `q` (q is a back-compat alias)")
    return keyword if keyword is not None else q


def _technique_search_params(
    *,
    keyword: str | None = None,
    q: str | None = None,
    tactic: str | None = None,
    maturity: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    include: str | None = None,
    exclude_id: str | None = None,
) -> dict[str, Any]:
    params: dict[str, Any] = {}
    kw = _resolve_keyword(keyword, q)
    if kw is not None:
        params["keyword"] = kw
    if tactic is not None:
        params["tactic"] = tactic
    if maturity is not None:
        params["maturity"] = maturity
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if include is not None:
        params["include"] = include
    if exclude_id is not None:
        params["exclude_id"] = exclude_id
    return params


def _case_study_search_params(
    *,
    keyword: str | None = None,
    q: str | None = None,
    target_type: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    include: str | None = None,
) -> dict[str, Any]:
    params: dict[str, Any] = {}
    kw = _resolve_keyword(keyword, q)
    if kw is not None:
        params["keyword"] = kw
    if target_type is not None:
        params["target_type"] = target_type
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if include is not None:
        params["include"] = include
    return params


def _validate_bulk(ids: list[str]) -> list[str]:
    if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
        raise ValueError("technique_ids must be a list of strings")
    return ids


class Atlas:
    def __init__(self, transport: _SyncTransport) -> None:
        self._t = transport

    def technique(self, technique_id: str) -> AtlasTechniqueResponse:
        return self._t.get(f"/v1/atlas/{_enc(technique_id)}")

    def technique_search(self, **kwargs: Any) -> AtlasTechniqueSearchResponse:
        return self._t.get("/v1/atlas/techniques", params=_technique_search_params(**kwargs))

    def bulk_technique_lookup(self, technique_ids: list[str]) -> BulkAtlasTechniqueResponse:
        return self._t.post(
            "/v1/atlas/techniques/bulk",
            json_body={"technique_ids": _validate_bulk(technique_ids)},
        )

    def case_study(self, case_study_id: str) -> AtlasCaseStudyResponse:
        return self._t.get(f"/v1/atlas/case-studies/{_enc(case_study_id)}")

    def case_study_search(self, **kwargs: Any) -> AtlasCaseStudySearchResponse:
        return self._t.get("/v1/atlas/case-studies", params=_case_study_search_params(**kwargs))


class AsyncAtlas:
    def __init__(self, transport: _AsyncTransport) -> None:
        self._t = transport

    async def technique(self, technique_id: str) -> AtlasTechniqueResponse:
        return await self._t.aget(f"/v1/atlas/{_enc(technique_id)}")

    async def technique_search(self, **kwargs: Any) -> AtlasTechniqueSearchResponse:
        return await self._t.aget("/v1/atlas/techniques", params=_technique_search_params(**kwargs))

    async def bulk_technique_lookup(self, technique_ids: list[str]) -> BulkAtlasTechniqueResponse:
        return await self._t.apost(
            "/v1/atlas/techniques/bulk",
            json_body={"technique_ids": _validate_bulk(technique_ids)},
        )

    async def case_study(self, case_study_id: str) -> AtlasCaseStudyResponse:
        return await self._t.aget(f"/v1/atlas/case-studies/{_enc(case_study_id)}")

    async def case_study_search(self, **kwargs: Any) -> AtlasCaseStudySearchResponse:
        return await self._t.aget("/v1/atlas/case-studies", params=_case_study_search_params(**kwargs))
