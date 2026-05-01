"""D3FEND namespace — MITRE D3FEND defense catalog mapped to ATT&CK."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from .._transport import _AsyncTransport, _SyncTransport
from ..models import (
    D3fendCoverageResponse,
    D3fendDefenseResponse,
    D3fendDefenseSearchResponse,
    D3fendForAttackResponse,
)


def _enc(value: str) -> str:
    if value is None or value == "":
        raise ValueError("Missing required parameter")
    return quote(str(value), safe="")


def _resolve_keyword(keyword: str | None, q: str | None) -> str | None:
    """Server param is `keyword`; SDK accepts `keyword=` or back-compat `q=` (Node parity).
    Passing both raises so we don't silently pick a winner.
    """
    if keyword is not None and q is not None:
        raise ValueError("Pass only one of `keyword` or `q` (q is a back-compat alias)")
    return keyword if keyword is not None else q


def _defense_search_params(
    *,
    keyword: str | None = None,
    q: str | None = None,
    tactic: str | None = None,
    artifact: str | None = None,
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
    if artifact is not None:
        params["artifact"] = artifact
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if include is not None:
        params["include"] = include
    if exclude_id is not None:
        params["exclude_id"] = exclude_id
    return params


def _for_attack_params(
    *,
    include: str | None = None,
    exclude_id: str | None = None,
) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if include is not None:
        params["include"] = include
    if exclude_id is not None:
        params["exclude_id"] = exclude_id
    return params


def _validate_attack_ids(ids: list[str]) -> list[str]:
    if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
        raise ValueError("attack_technique_ids must be a list of strings")
    return ids


class D3fend:
    def __init__(self, transport: _SyncTransport) -> None:
        self._t = transport

    def defense(self, defense_id: str) -> D3fendDefenseResponse:
        return self._t.get(f"/v1/d3fend/{_enc(defense_id)}")

    def defense_search(self, **kwargs: Any) -> D3fendDefenseSearchResponse:
        return self._t.get("/v1/d3fend/defenses", params=_defense_search_params(**kwargs))

    def defense_for_attack(self, attack_technique_id: str, **kwargs: Any) -> D3fendForAttackResponse:
        return self._t.get(
            f"/v1/d3fend/attack/{_enc(attack_technique_id)}",
            params=_for_attack_params(**kwargs),
        )

    def coverage(self, attack_technique_ids: list[str]) -> D3fendCoverageResponse:
        return self._t.post(
            "/v1/d3fend/coverage",
            json_body={"attack_technique_ids": _validate_attack_ids(attack_technique_ids)},
        )


class AsyncD3fend:
    def __init__(self, transport: _AsyncTransport) -> None:
        self._t = transport

    async def defense(self, defense_id: str) -> D3fendDefenseResponse:
        return await self._t.aget(f"/v1/d3fend/{_enc(defense_id)}")

    async def defense_search(self, **kwargs: Any) -> D3fendDefenseSearchResponse:
        return await self._t.aget("/v1/d3fend/defenses", params=_defense_search_params(**kwargs))

    async def defense_for_attack(self, attack_technique_id: str, **kwargs: Any) -> D3fendForAttackResponse:
        return await self._t.aget(
            f"/v1/d3fend/attack/{_enc(attack_technique_id)}",
            params=_for_attack_params(**kwargs),
        )

    async def coverage(self, attack_technique_ids: list[str]) -> D3fendCoverageResponse:
        return await self._t.apost(
            "/v1/d3fend/coverage",
            json_body={"attack_technique_ids": _validate_attack_ids(attack_technique_ids)},
        )
