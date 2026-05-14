"""Behavior tests for the MCP-only composite tool `tech_stack_cve_audit`.

These tests exercise `_tech_stack_cve_audit_impl()` directly to pin tier
branching, sub-call composition, and response envelope shape. Gate / cost /
no-loopback regression guards live in `tests/test_mcp_rate_limit_gate.py`.

Mocks target the SOURCE modules (`domain.recon`, `domain.tech`) because the
impl uses lazy imports — patching `app.domain.routes.fetch_live_headers`
would not take effect.
"""

from __future__ import annotations

import inspect

import pytest
from fastapi import HTTPException


def test_tech_stack_cve_audit_impl_signature():
    """_tech_stack_cve_audit_impl must expose the Pattern B signature so the
    MCP wrapper can call it positionally + with `tier` and `client_ip` kwargs."""
    from app.domain.routes import _tech_stack_cve_audit_impl

    assert inspect.iscoroutinefunction(_tech_stack_cve_audit_impl), "_tech_stack_cve_audit_impl must be async"
    sig = inspect.signature(_tech_stack_cve_audit_impl)
    assert "domain" in sig.parameters
    assert "tier" in sig.parameters
    assert "client_ip" in sig.parameters


@pytest.mark.asyncio
async def test_tech_stack_cve_audit_happy_path(monkeypatch):
    """Domain → 2 techs → 3 CVE candidates → 1 KEV match → Pro tier sees
    exploit_findings. Envelope carries domain, technologies, cves_by_tech,
    kev_findings, exploit_findings, summary, next_calls."""
    from app.domain import routes as _routes

    async def _fake_live_headers(domain):
        return {"headers": {"Server": "nginx/1.18.0"}}

    def _fake_detect(headers, html=None):
        return {
            "technologies": [
                {"name": "nginx", "version": "1.18.0", "category": "web-server", "confidence": 100},
                {"name": "Apache", "version": "2.4.51", "category": "web-server", "confidence": 90},
            ],
            "categories": {"web-server": ["nginx", "Apache"]},
            "count": 2,
            "summary": "2 technologies detected",
        }

    async def _fake_candidates(tech_list, *, limit):
        ids = ["CVE-2021-44228", "CVE-2021-45046", "CVE-2022-22965"][:limit]
        return ids, {"nginx": ["CVE-2021-44228"], "apache": ["CVE-2021-45046", "CVE-2022-22965"]}

    async def _fake_bulk_cve(cve_ids):
        return {
            "results": [
                {
                    "cve_id": cid,
                    "status": "ok",
                    "cve": {"cve_id": cid, "severity": "CRITICAL", "kev": {"in_kev": cid == "CVE-2021-44228"}},
                }
                for cid in cve_ids
            ],
            "total": len(cve_ids),
            "successful": len(cve_ids),
            "failed": 0,
            "timed_out": 0,
            "partial": False,
            "summary": f"{len(cve_ids)} CVEs",
        }

    async def _fake_kev(cve_id):
        if cve_id == "CVE-2021-44228":
            return {"cve_id": cve_id, "vulnerability_name": "Log4Shell", "due_date": "2021-12-24"}
        return None

    async def _fake_exploit(cve_id):
        return {"cve_id": cve_id, "has_public_exploit": True, "exploits_found": 5}

    monkeypatch.setattr("domain.recon.fetch_live_headers", _fake_live_headers)
    monkeypatch.setattr("domain.tech.detect_technologies", _fake_detect)
    monkeypatch.setattr(_routes, "_tech_stack_cve_candidates", _fake_candidates)
    monkeypatch.setattr(_routes, "_tech_stack_bulk_cve_lookup", _fake_bulk_cve)
    monkeypatch.setattr(_routes, "_tech_stack_kev_lookup", _fake_kev)
    monkeypatch.setattr(_routes, "_tech_stack_exploit_lookup", _fake_exploit)

    from app.domain.routes import _tech_stack_cve_audit_impl

    result = await _tech_stack_cve_audit_impl("example.com", tier="pro", client_ip="")

    assert result["domain"] == "example.com"
    assert result["technologies"]["count"] == 2
    assert "cves_by_tech" in result
    # Attribution correctness: nginx (lowercase, direct match) maps to CVE-2021-44228.
    # Apache (TitleCase tech name) MUST also map via normalize_product().strip().lower()
    # to "apache" — if the normalization is missing, this assertion catches the silent [].
    assert result["cves_by_tech"]["nginx/1.18.0"] == ["CVE-2021-44228"]
    assert result["cves_by_tech"]["Apache/2.4.51"] == ["CVE-2021-45046", "CVE-2022-22965"]
    assert isinstance(result["kev_findings"], list)
    assert len(result["kev_findings"]) == 1
    assert result["kev_findings"][0]["cve_id"] == "CVE-2021-44228"
    assert "exploit_findings" in result, "Pro tier MUST include exploit_findings field"
    assert isinstance(result["exploit_findings"], list)
    assert "summary" in result
    assert isinstance(result.get("next_calls"), list) and len(result["next_calls"]) > 0


@pytest.mark.asyncio
async def test_tech_stack_cve_audit_free_tier_no_exploit(monkeypatch):
    """Free tier MUST omit `exploit_findings` from the response envelope
    entirely (key absent — not None, not empty list)."""
    from app.domain import routes as _routes

    async def _fake_live_headers(domain):
        return {"headers": {"Server": "nginx/1.18.0"}}

    def _fake_detect(headers, html=None):
        return {
            "technologies": [{"name": "nginx", "version": "1.18.0", "category": "web-server", "confidence": 100}],
            "categories": {"web-server": ["nginx"]},
            "count": 1,
            "summary": "1 tech",
        }

    async def _fake_candidates(tech_list, *, limit):
        ids = ["CVE-2024-0001"][:limit]
        return ids, {"nginx": ids}

    async def _fake_bulk_cve(cve_ids):
        return {
            "results": [
                {"cve_id": cid, "status": "ok", "cve": {"cve_id": cid, "severity": "HIGH", "kev": {"in_kev": False}}}
                for cid in cve_ids
            ],
            "total": len(cve_ids),
            "successful": len(cve_ids),
            "failed": 0,
            "timed_out": 0,
            "partial": False,
            "summary": "1 CVE",
        }

    async def _fake_kev(cve_id):
        return None

    exploit_calls: list[str] = []

    async def _fake_exploit(cve_id):
        exploit_calls.append(cve_id)
        return {}

    monkeypatch.setattr("domain.recon.fetch_live_headers", _fake_live_headers)
    monkeypatch.setattr("domain.tech.detect_technologies", _fake_detect)
    monkeypatch.setattr(_routes, "_tech_stack_cve_candidates", _fake_candidates)
    monkeypatch.setattr(_routes, "_tech_stack_bulk_cve_lookup", _fake_bulk_cve)
    monkeypatch.setattr(_routes, "_tech_stack_kev_lookup", _fake_kev)
    monkeypatch.setattr(_routes, "_tech_stack_exploit_lookup", _fake_exploit)

    from app.domain.routes import _tech_stack_cve_audit_impl

    result = await _tech_stack_cve_audit_impl("example.com", tier="free", client_ip="")

    assert "exploit_findings" not in result, f"Free tier MUST drop exploit_findings; got keys {sorted(result.keys())}"
    assert exploit_calls == [], f"Free tier MUST NOT invoke exploit lookup; got {exploit_calls}"


@pytest.mark.asyncio
async def test_tech_stack_cve_audit_pro_tier_bulk_batch_50(monkeypatch):
    """Pro tier requests limit=50 for the CVE candidate generator."""
    from app.domain import routes as _routes

    seen_limits: list[int] = []

    async def _fake_live_headers(domain):
        return {"headers": {"Server": "nginx/1.18.0"}}

    def _fake_detect(headers, html=None):
        return {
            "technologies": [{"name": "nginx", "version": "1.18.0", "category": "web-server", "confidence": 100}],
            "categories": {},
            "count": 1,
            "summary": "1 tech",
        }

    async def _fake_candidates(tech_list, *, limit):
        seen_limits.append(limit)
        return [], {}

    async def _fake_bulk_cve(cve_ids):
        return {
            "results": [],
            "total": 0,
            "successful": 0,
            "failed": 0,
            "timed_out": 0,
            "partial": False,
            "summary": "no CVEs",
        }

    async def _fake_kev(cve_id):
        return None

    async def _fake_exploit(cve_id):
        return {}

    monkeypatch.setattr("domain.recon.fetch_live_headers", _fake_live_headers)
    monkeypatch.setattr("domain.tech.detect_technologies", _fake_detect)
    monkeypatch.setattr(_routes, "_tech_stack_cve_candidates", _fake_candidates)
    monkeypatch.setattr(_routes, "_tech_stack_bulk_cve_lookup", _fake_bulk_cve)
    monkeypatch.setattr(_routes, "_tech_stack_kev_lookup", _fake_kev)
    monkeypatch.setattr(_routes, "_tech_stack_exploit_lookup", _fake_exploit)

    from app.domain.routes import _tech_stack_cve_audit_impl

    await _tech_stack_cve_audit_impl("example.com", tier="pro", client_ip="")
    assert seen_limits == [50], f"Pro tier must request limit=50; got {seen_limits}"


@pytest.mark.asyncio
async def test_tech_stack_cve_audit_free_tier_bulk_batch_10(monkeypatch):
    """Free tier requests limit=10 for the CVE candidate generator."""
    from app.domain import routes as _routes

    seen_limits: list[int] = []

    async def _fake_live_headers(domain):
        return {"headers": {"Server": "nginx/1.18.0"}}

    def _fake_detect(headers, html=None):
        return {
            "technologies": [{"name": "nginx", "version": "1.18.0", "category": "web-server", "confidence": 100}],
            "categories": {},
            "count": 1,
            "summary": "1 tech",
        }

    async def _fake_candidates(tech_list, *, limit):
        seen_limits.append(limit)
        return [], {}

    async def _fake_bulk_cve(cve_ids):
        return {
            "results": [],
            "total": 0,
            "successful": 0,
            "failed": 0,
            "timed_out": 0,
            "partial": False,
            "summary": "no CVEs",
        }

    async def _fake_kev(cve_id):
        return None

    async def _fake_exploit(cve_id):
        return {}

    monkeypatch.setattr("domain.recon.fetch_live_headers", _fake_live_headers)
    monkeypatch.setattr("domain.tech.detect_technologies", _fake_detect)
    monkeypatch.setattr(_routes, "_tech_stack_cve_candidates", _fake_candidates)
    monkeypatch.setattr(_routes, "_tech_stack_bulk_cve_lookup", _fake_bulk_cve)
    monkeypatch.setattr(_routes, "_tech_stack_kev_lookup", _fake_kev)
    monkeypatch.setattr(_routes, "_tech_stack_exploit_lookup", _fake_exploit)

    from app.domain.routes import _tech_stack_cve_audit_impl

    await _tech_stack_cve_audit_impl("example.com", tier="free", client_ip="")
    assert seen_limits == [10], f"Free tier must request limit=10; got {seen_limits}"


@pytest.mark.asyncio
async def test_tech_stack_cve_audit_no_techs_detected(monkeypatch):
    """Empty fingerprint → zero techs → no CVE lookup, empty cves_by_tech,
    empty kev_findings. Must not crash."""
    from app.domain import routes as _routes

    async def _fake_live_headers(domain):
        return {"headers": {}}

    def _fake_detect(headers, html=None):
        return {"technologies": [], "categories": {}, "count": 0, "summary": ""}

    bulk_calls: list[list[str]] = []

    async def _fake_candidates(tech_list, *, limit):
        return [], {}

    async def _fake_bulk_cve(cve_ids):
        bulk_calls.append(list(cve_ids))
        return {
            "results": [],
            "total": 0,
            "successful": 0,
            "failed": 0,
            "timed_out": 0,
            "partial": False,
            "summary": "no CVEs",
        }

    async def _fake_kev(cve_id):
        return None

    async def _fake_exploit(cve_id):
        return {}

    monkeypatch.setattr("domain.recon.fetch_live_headers", _fake_live_headers)
    monkeypatch.setattr("domain.tech.detect_technologies", _fake_detect)
    monkeypatch.setattr(_routes, "_tech_stack_cve_candidates", _fake_candidates)
    monkeypatch.setattr(_routes, "_tech_stack_bulk_cve_lookup", _fake_bulk_cve)
    monkeypatch.setattr(_routes, "_tech_stack_kev_lookup", _fake_kev)
    monkeypatch.setattr(_routes, "_tech_stack_exploit_lookup", _fake_exploit)

    from app.domain.routes import _tech_stack_cve_audit_impl

    result = await _tech_stack_cve_audit_impl("static-site.example", tier="pro", client_ip="")
    assert result["technologies"]["count"] == 0
    assert result["cves_by_tech"] == {}
    assert result["kev_findings"] == []
    assert bulk_calls == [], "bulk_cve must not be called when no CVE candidates"


@pytest.mark.asyncio
async def test_tech_stack_cve_audit_invalid_domain():
    """Malformed inputs raise HTTPException(400) via clean_domain."""
    from app.domain.routes import _tech_stack_cve_audit_impl

    for bad in ["", "   ", "not a domain", "192.168.1.1"]:
        with pytest.raises(HTTPException) as exc_info:
            await _tech_stack_cve_audit_impl(bad, tier="pro", client_ip="")
        assert exc_info.value.status_code == 400, f"input {bad!r} must 400; got {exc_info.value.status_code}"


def test_tech_stack_cve_audit_response_free_tier_serializes_without_exploit_findings():
    """Wire-shape guard: Free tier wrapping MUST NOT include `exploit_findings`
    in `model_dump()` output. Pricing-leak fix: even though the field is
    declared with default=None on the model, the custom @model_serializer
    drops it when None so Free-tier callers never see the key on the wire."""
    from app.schemas import TechStackCveAuditResponse

    free_response = TechStackCveAuditResponse(
        domain="example.com",
        technologies={"technologies": [], "categories": {}, "count": 0, "summary": ""},
        cves_by_tech={},
        kev_findings=[],
        summary="ok",
    )
    data = free_response.model_dump()
    assert "exploit_findings" not in data, f"Wire response leaks exploit_findings on Free: keys={sorted(data.keys())}"


def test_tech_stack_cve_audit_response_pro_tier_serializes_with_exploit_findings():
    """Symmetric guard: Pro tier wrapping MUST include `exploit_findings` in
    `model_dump()` output when populated."""
    from app.schemas import TechStackCveAuditResponse

    pro_response = TechStackCveAuditResponse(
        domain="example.com",
        technologies={"technologies": [], "categories": {}, "count": 0, "summary": ""},
        cves_by_tech={},
        kev_findings=[],
        summary="ok",
        exploit_findings=[{"cve_id": "CVE-2024-0001", "has_public_exploit": True, "exploits_found": 3}],
    )
    data = pro_response.model_dump()
    assert "exploit_findings" in data
    assert data["exploit_findings"][0]["cve_id"] == "CVE-2024-0001"
