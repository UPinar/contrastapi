"""Domain namespace — DNS, WHOIS, SSL, subdomains, tech, threat, monitor, vulns, audit, wayback."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from .._transport import _AsyncTransport, _SyncTransport
from ..models import (
    AuditResponse,
    BulkDomainResponse,
    CertsResponse,
    DnsResponse,
    DomainReportResponse,
    SslResponse,
    SubdomainsResponse,
    TechResponse,
    ThreatResponse,
    WaybackResponse,
    WhoisResponse,
)


def _enc(value: str) -> str:
    if value is None or value == "":
        raise ValueError("Missing required parameter")
    return quote(str(value), safe="")


def _validate_domains(domains: list[str]) -> list[str]:
    if not isinstance(domains, list) or not all(isinstance(d, str) for d in domains):
        raise ValueError("domains must be a list of strings")
    return domains


def _report_params(lite: bool) -> dict[str, Any] | None:
    """`lite=True` → {"lite": "true"}; `lite=False` → None (clean URL).

    Server treats only the literal string `true` as truthy (lowercase).
    """
    return {"lite": "true"} if lite else None


class Domain:
    def __init__(self, transport: _SyncTransport) -> None:
        self._t = transport

    def report(self, domain: str, *, lite: bool = False) -> DomainReportResponse:
        return self._t.get(f"/v1/domain/{_enc(domain)}", params=_report_params(lite))

    def dns(self, domain: str) -> DnsResponse:
        return self._t.get(f"/v1/dns/{_enc(domain)}")

    def whois(self, domain: str) -> WhoisResponse:
        return self._t.get(f"/v1/whois/{_enc(domain)}")

    def subdomains(self, domain: str) -> SubdomainsResponse:
        return self._t.get(f"/v1/subdomains/{_enc(domain)}")

    def certs(self, domain: str) -> CertsResponse:
        return self._t.get(f"/v1/certs/{_enc(domain)}")

    def ssl(self, domain: str) -> SslResponse:
        return self._t.get(f"/v1/ssl/{_enc(domain)}")

    def tech(self, domain: str) -> TechResponse:
        return self._t.get(f"/v1/tech/{_enc(domain)}")

    def threat(self, domain: str) -> ThreatResponse:
        return self._t.get(f"/v1/threat/{_enc(domain)}")

    def monitor(self, domain: str) -> dict[str, Any]:
        return self._t.get(f"/v1/monitor/{_enc(domain)}")

    def vulns(self, domain: str) -> dict[str, Any]:
        return self._t.get(f"/v1/domain/{_enc(domain)}/vulns")

    def audit(self, domain: str) -> AuditResponse:
        return self._t.get(f"/v1/audit/{_enc(domain)}")

    def wayback(self, domain: str) -> WaybackResponse:
        return self._t.get(f"/v1/archive/{_enc(domain)}")

    def bulk(self, domains: list[str]) -> BulkDomainResponse:
        return self._t.post("/v1/domains/bulk", json_body={"domains": _validate_domains(domains)})


class AsyncDomain:
    def __init__(self, transport: _AsyncTransport) -> None:
        self._t = transport

    async def report(self, domain: str, *, lite: bool = False) -> DomainReportResponse:
        return await self._t.aget(f"/v1/domain/{_enc(domain)}", params=_report_params(lite))

    async def dns(self, domain: str) -> DnsResponse:
        return await self._t.aget(f"/v1/dns/{_enc(domain)}")

    async def whois(self, domain: str) -> WhoisResponse:
        return await self._t.aget(f"/v1/whois/{_enc(domain)}")

    async def subdomains(self, domain: str) -> SubdomainsResponse:
        return await self._t.aget(f"/v1/subdomains/{_enc(domain)}")

    async def certs(self, domain: str) -> CertsResponse:
        return await self._t.aget(f"/v1/certs/{_enc(domain)}")

    async def ssl(self, domain: str) -> SslResponse:
        return await self._t.aget(f"/v1/ssl/{_enc(domain)}")

    async def tech(self, domain: str) -> TechResponse:
        return await self._t.aget(f"/v1/tech/{_enc(domain)}")

    async def threat(self, domain: str) -> ThreatResponse:
        return await self._t.aget(f"/v1/threat/{_enc(domain)}")

    async def monitor(self, domain: str) -> dict[str, Any]:
        return await self._t.aget(f"/v1/monitor/{_enc(domain)}")

    async def vulns(self, domain: str) -> dict[str, Any]:
        return await self._t.aget(f"/v1/domain/{_enc(domain)}/vulns")

    async def audit(self, domain: str) -> AuditResponse:
        return await self._t.aget(f"/v1/audit/{_enc(domain)}")

    async def wayback(self, domain: str) -> WaybackResponse:
        return await self._t.aget(f"/v1/archive/{_enc(domain)}")

    async def bulk(self, domains: list[str]) -> BulkDomainResponse:
        return await self._t.apost("/v1/domains/bulk", json_body={"domains": _validate_domains(domains)})
