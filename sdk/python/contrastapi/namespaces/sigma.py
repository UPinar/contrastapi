"""Sigma namespace — detection-rule lookup by UUID + bulk lookup (≤50)."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from .._transport import _AsyncTransport, _SyncTransport


def _enc(value: str) -> str:
    if value is None or value == "":
        raise ValueError("Missing required parameter")
    return quote(str(value), safe="")


def _validate_rule_ids(rule_ids: list[str]) -> list[str]:
    if not isinstance(rule_ids, list) or not all(isinstance(r, str) for r in rule_ids):
        raise ValueError("rule_ids must be a list of strings")
    return rule_ids


class Sigma:
    def __init__(self, transport: _SyncTransport) -> None:
        self._t = transport

    def lookup(self, rule_id: str) -> dict[str, Any]:
        return self._t.get(f"/v1/sigma/{_enc(rule_id)}")

    def bulk(self, rule_ids: list[str]) -> dict[str, Any]:
        return self._t.post("/v1/sigma/bulk", json_body={"rule_ids": _validate_rule_ids(rule_ids)})


class AsyncSigma:
    def __init__(self, transport: _AsyncTransport) -> None:
        self._t = transport

    async def lookup(self, rule_id: str) -> dict[str, Any]:
        return await self._t.aget(f"/v1/sigma/{_enc(rule_id)}")

    async def bulk(self, rule_ids: list[str]) -> dict[str, Any]:
        return await self._t.apost("/v1/sigma/bulk", json_body={"rule_ids": _validate_rule_ids(rule_ids)})
