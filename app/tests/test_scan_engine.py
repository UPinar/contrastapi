"""Tests for the website-scanner engine port (app/scan/) — Faz-1, engine only.

Everything network/subprocess-shaped is mocked: DNS via
``scan.validation.socket.getaddrinfo``, the C binary via
``scan.engine.subprocess.run``. No test here touches the network or requires
the compiled binary.
"""

import asyncio
import json
import socket
import subprocess

import pytest
from config import SCANNER_PATH, SEVERITY_ORDER
from fastapi import HTTPException
from fastapi.testclient import TestClient
from main import app
from scan import engine
from scan.findings import enrich_with_findings
from scan.validation import (
    clean_domain,
    get_resolved_ip_with_bypass,
    is_private_ip,
    validate_domain,
)

PUBLIC_IP = "93.184.216.34"

# Faz-2 route tests — module-level client mirrors test_domain.py:18. Keyless
# requests authenticate as Free tier ("testclient" IP); first-swipe never
# applies on the REST path (mcp_tool is None), so credit counts are pure.
client = TestClient(app)


def _addrinfo(ip):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]


class _Proc:
    def __init__(self, returncode=0, stdout=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


class _FakeSemaphore:
    def __init__(self, allow=True):
        self.allow = allow
        self.acquired = 0
        self.released = 0

    def acquire(self, timeout=None):
        if self.allow:
            self.acquired += 1
        return self.allow

    def release(self):
        self.released += 1


# --- clean_domain ---


class TestCleanDomain:
    def test_lowercases(self):
        assert clean_domain("Example.COM") == "example.com"

    def test_strips_https_protocol(self):
        assert clean_domain("https://example.com") == "example.com"

    def test_strips_http_protocol(self):
        assert clean_domain("http://example.com") == "example.com"

    def test_strips_path(self):
        assert clean_domain("example.com/path/to/page?q=1") == "example.com"

    def test_strips_port(self):
        assert clean_domain("example.com:8443") == "example.com"

    def test_combined(self):
        assert clean_domain("HTTPS://Example.com:443/login") == "example.com"

    def test_strips_whitespace(self):
        assert clean_domain("  example.com  ") == "example.com"

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            clean_domain("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError):
            clean_domain("   ")

    def test_protocol_only_raises(self):
        with pytest.raises(ValueError):
            clean_domain("https://")


# --- is_private_ip ---


class TestIsPrivateIp:
    @pytest.mark.parametrize(
        "ip",
        ["10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1"],
    )
    def test_private_loopback_linklocal(self, ip):
        assert is_private_ip(ip) is True

    @pytest.mark.parametrize("ip", ["8.8.8.8", "93.184.216.34", "1.1.1.1"])
    def test_public(self, ip):
        assert is_private_ip(ip) is False

    @pytest.mark.parametrize("ip", ["not-an-ip", "", "example.com"])
    def test_parse_error_returns_false(self, ip):
        assert is_private_ip(ip) is False


# --- validate_domain ---


class TestValidateDomain:
    def test_returns_resolved_public_ip(self, monkeypatch):
        monkeypatch.setattr("scan.validation.socket.getaddrinfo", lambda *a, **kw: _addrinfo(PUBLIC_IP))
        assert validate_domain("https://Example.com/login") == PUBLIC_IP

    def test_rejects_ip_literal(self, monkeypatch):
        def _boom(*a, **kw):
            raise AssertionError("getaddrinfo must not be called for IP literals")

        monkeypatch.setattr("scan.validation.socket.getaddrinfo", _boom)
        with pytest.raises(ValueError):
            validate_domain("8.8.8.8")

    def test_rejects_private_resolution(self, monkeypatch):
        monkeypatch.setattr("scan.validation.socket.getaddrinfo", lambda *a, **kw: _addrinfo("10.0.0.5"))
        with pytest.raises(ValueError):
            validate_domain("internal.example.com")

    def test_rejects_unresolvable(self, monkeypatch):
        def _fail(*a, **kw):
            raise socket.gaierror("NXDOMAIN")

        monkeypatch.setattr("scan.validation.socket.getaddrinfo", _fail)
        with pytest.raises(ValueError):
            validate_domain("definitely-not-a-real-domain.example")

    def test_rejects_empty_resolution(self, monkeypatch):
        monkeypatch.setattr("scan.validation.socket.getaddrinfo", lambda *a, **kw: [])
        with pytest.raises(ValueError):
            validate_domain("example.com")

    def test_rejects_empty_domain(self):
        with pytest.raises(ValueError):
            validate_domain("")


# --- get_resolved_ip_with_bypass ---


class TestSelfDomainBypass:
    def test_self_domain(self):
        assert get_resolved_ip_with_bypass("contrastcyber.com", PUBLIC_IP) == "127.0.0.1"

    def test_self_domain_www(self):
        assert get_resolved_ip_with_bypass("www.contrastcyber.com", PUBLIC_IP) == "127.0.0.1"

    def test_self_domain_without_resolved_ip(self):
        assert get_resolved_ip_with_bypass("contrastcyber.com") == "127.0.0.1"

    def test_other_domain_passthrough(self):
        assert get_resolved_ip_with_bypass("example.com", PUBLIC_IP) == PUBLIC_IP

    def test_other_domain_none(self):
        assert get_resolved_ip_with_bypass("example.com") is None


# --- run_scan ---


class TestRunScan:
    def test_success_parses_json_and_builds_list_argv(self, monkeypatch):
        calls = {}

        def fake_run(cmd, **kwargs):
            calls["cmd"] = cmd
            calls["kwargs"] = kwargs
            return _Proc(0, json.dumps({"domain": "example.com", "total_score": 50}))

        monkeypatch.setattr(engine.subprocess, "run", fake_run)
        result = engine.run_scan("example.com", PUBLIC_IP)
        assert result == {"domain": "example.com", "total_score": 50}
        assert isinstance(calls["cmd"], list)
        assert calls["cmd"] == [str(SCANNER_PATH), "example.com", PUBLIC_IP]
        assert calls["kwargs"]["timeout"] == engine.SCAN_TIMEOUT
        assert "shell" not in calls["kwargs"]

    def test_success_without_resolved_ip(self, monkeypatch):
        calls = {}

        def fake_run(cmd, **kwargs):
            calls["cmd"] = cmd
            return _Proc(0, "{}")

        monkeypatch.setattr(engine.subprocess, "run", fake_run)
        assert engine.run_scan("example.com") == {}
        assert calls["cmd"] == [str(SCANNER_PATH), "example.com"]

    def test_timeout_maps_to_504(self, monkeypatch):
        def fake_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=engine.SCAN_TIMEOUT)

        monkeypatch.setattr(engine.subprocess, "run", fake_run)
        with pytest.raises(HTTPException) as exc_info:
            engine.run_scan("example.com", PUBLIC_IP)
        assert exc_info.value.status_code == 504

    def test_missing_binary_maps_to_500(self, monkeypatch):
        def fake_run(cmd, **kwargs):
            raise FileNotFoundError(cmd[0])

        monkeypatch.setattr(engine.subprocess, "run", fake_run)
        with pytest.raises(HTTPException) as exc_info:
            engine.run_scan("example.com", PUBLIC_IP)
        assert exc_info.value.status_code == 500

    def test_nonzero_exit_maps_to_502(self, monkeypatch):
        monkeypatch.setattr(engine.subprocess, "run", lambda cmd, **kw: _Proc(1, ""))
        with pytest.raises(HTTPException) as exc_info:
            engine.run_scan("example.com", PUBLIC_IP)
        assert exc_info.value.status_code == 502

    def test_bad_json_maps_to_502(self, monkeypatch):
        monkeypatch.setattr(engine.subprocess, "run", lambda cmd, **kw: _Proc(0, "not-json{"))
        with pytest.raises(HTTPException) as exc_info:
            engine.run_scan("example.com", PUBLIC_IP)
        assert exc_info.value.status_code == 502

    def test_queue_full_maps_to_503(self, monkeypatch):
        sem = _FakeSemaphore(allow=False)
        monkeypatch.setattr(engine, "_scan_semaphore", sem)
        monkeypatch.setattr(engine.subprocess, "run", lambda cmd, **kw: _Proc(0, "{}"))
        with pytest.raises(HTTPException) as exc_info:
            engine.run_scan("example.com", PUBLIC_IP)
        assert exc_info.value.status_code == 503
        assert sem.released == 0  # never acquired, must not be released

    def test_semaphore_released_on_success(self, monkeypatch):
        sem = _FakeSemaphore()
        monkeypatch.setattr(engine, "_scan_semaphore", sem)
        monkeypatch.setattr(engine.subprocess, "run", lambda cmd, **kw: _Proc(0, "{}"))
        engine.run_scan("example.com", PUBLIC_IP)
        assert sem.acquired == 1
        assert sem.released == 1

    def test_semaphore_released_on_failure(self, monkeypatch):
        sem = _FakeSemaphore()
        monkeypatch.setattr(engine, "_scan_semaphore", sem)
        monkeypatch.setattr(engine.subprocess, "run", lambda cmd, **kw: _Proc(3, ""))
        with pytest.raises(HTTPException):
            engine.run_scan("example.com", PUBLIC_IP)
        assert sem.acquired == 1
        assert sem.released == 1


# --- contrast_scan ---


class TestContrastScan:
    def test_caller_supplied_private_ip_rejected(self):
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(engine.contrast_scan("example.com", resolved_ip="192.168.1.10"))
        assert exc_info.value.status_code == 400

    def test_caller_supplied_loopback_ip_rejected(self):
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(engine.contrast_scan("example.com", resolved_ip="127.0.0.1"))
        assert exc_info.value.status_code == 400

    def test_empty_domain_rejected(self):
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(engine.contrast_scan(""))
        assert exc_info.value.status_code == 400

    def test_unresolvable_domain_rejected(self, monkeypatch):
        def _fail(domain):
            raise ValueError("Could not resolve")

        monkeypatch.setattr(engine, "validate_domain", _fail)
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(engine.contrast_scan("nope.example"))
        assert exc_info.value.status_code == 400

    def test_happy_path_enriches(self, monkeypatch):
        monkeypatch.setattr(engine, "validate_domain", lambda d: PUBLIC_IP)
        raw = {"domain": "example.com", "total_score": 50, "max_score": 100, "grade": "D"}
        monkeypatch.setattr(engine, "run_scan", lambda d, ip: dict(raw))
        result = asyncio.run(engine.contrast_scan("example.com"))
        assert result["resolved_ip"] == PUBLIC_IP
        assert "findings" in result
        assert "findings_count" in result

    def test_self_domain_scans_via_localhost(self, monkeypatch):
        calls = {}

        def fake_run_scan(domain, ip):
            calls["args"] = (domain, ip)
            return {"domain": domain}

        monkeypatch.setattr(engine, "run_scan", fake_run_scan)
        result = asyncio.run(engine.contrast_scan("contrastcyber.com", resolved_ip="104.21.32.1"))
        assert calls["args"] == ("contrastcyber.com", "127.0.0.1")
        assert result["resolved_ip"] == "127.0.0.1"

    def test_domain_is_cleaned_before_scan(self, monkeypatch):
        calls = {}

        def fake_run_scan(domain, ip):
            calls["args"] = (domain, ip)
            return {"domain": domain}

        monkeypatch.setattr(engine, "run_scan", fake_run_scan)
        asyncio.run(engine.contrast_scan("HTTPS://Example.com/x?q=1", resolved_ip=PUBLIC_IP))
        assert calls["args"] == ("example.com", PUBLIC_IP)


# --- findings enrichment ---


class TestFindingsEnrichment:
    def test_minimal_result_gains_findings(self):
        result = enrich_with_findings({"domain": "example.com"})
        assert isinstance(result["findings"], list)
        assert result["findings"]  # missing headers/DNS produce findings
        assert set(result["findings_count"]) == {"critical", "high", "medium", "low"}

    def test_findings_sorted_by_severity(self):
        result = enrich_with_findings({"domain": "example.com"})
        ranks = [SEVERITY_ORDER.get(f["severity"], 5) for f in result["findings"]]
        assert ranks == sorted(ranks)

    def test_counts_match_findings(self):
        result = enrich_with_findings({"domain": "example.com"})
        total = sum(result["findings_count"].values())
        in_levels = [f for f in result["findings"] if f["severity"] in result["findings_count"]]
        assert total == len(in_levels)

    def test_enterprise_detection(self):
        result = enrich_with_findings({"domain": "google.com"})
        assert result["enterprise"]["is_enterprise"] is True
        assert result["enterprise"]["company"] == "Google"

    def test_non_enterprise_has_no_enterprise_key(self):
        result = enrich_with_findings({"domain": "example.com"})
        assert "enterprise" not in result


# --- /v1/scan/{domain} REST route (Faz-2: scan.routes) ---


class TestScanRoute:
    def test_scan_route_200_returns_engine_payload(self, monkeypatch):
        from unittest.mock import AsyncMock

        engine_result = {
            "domain": "example.com",
            "resolved_ip": PUBLIC_IP,
            "total_score": 50,
            "max_score": 100,
            "grade": "C",
            "findings": [{"severity": "high", "category": "headers", "title": "Missing CSP"}],
            "findings_count": {"critical": 0, "high": 1, "medium": 0, "low": 0},
            "headers": {"score": 10, "max": 20},
            "ssl": {},
            "dns": {},
            "redirect": {},
            "disclosure": {},
            "cookies": {},
            "dnssec": {},
            "methods": {},
            "cors": {},
            "html": {},
            "csp_analysis": {},
        }
        monkeypatch.setattr("scan.routes._run_scan_engine", AsyncMock(return_value=dict(engine_result)))

        r = client.get("/v1/scan/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "example.com"
        assert data["resolved_ip"] == PUBLIC_IP
        assert data["grade"] == "C"
        assert data["findings_count"]["high"] == 1
        assert data["headers"]["score"] == 10
        # enterprise absent from engine dict -> None -> stripped by exclude_none
        assert "enterprise" not in data

    def test_scan_route_registered_with_contrast_scan_operation_id(self):
        # fastapi 0.137+ no longer surfaces nested-router routes as top-level
        # APIRoute objects in app.routes; assert via the stable public OpenAPI
        # contract instead. (A same-path+same-method duplicate collapses to one
        # openapi entry and is invisible here; the operationId count below guards
        # the realistic different-path alias / duplicate-id regression.)
        spec = app.openapi()
        path_item = spec["paths"].get("/v1/scan/{domain}")
        assert path_item is not None, "GET /v1/scan/{domain} must be registered"
        assert "get" in path_item, "GET /v1/scan/{domain} must expose GET"
        http_methods = {"get", "post", "put", "delete", "patch", "options", "head", "trace"}
        exposed = {m for m in path_item if m in http_methods}
        assert exposed == {"get"}, "/v1/scan/{domain} must expose only GET"
        assert path_item["get"]["operationId"] == "contrast_scan"
        contrast_scan_ops = sum(
            1
            for item in spec["paths"].values()
            for op in item.values()
            if isinstance(op, dict) and op.get("operationId") == "contrast_scan"
        )
        assert contrast_scan_ops == 1, f"contrast_scan must map to exactly one operation; got {contrast_scan_ops}"

    def test_scan_route_rest_gate_charges_cost_scan(self, monkeypatch):
        """REST single-gate: one keyless GET /v1/scan/{domain} must withdraw exactly
        COST_SCAN credits from the Free bucket (require_auth cost wiring), and the
        impl must not charge again. Key derivation mirrors
        test_mcp_rate_limit_gate._free_store_key."""
        from unittest.mock import AsyncMock

        from config import COST_SCAN
        from db import get_api_db, hash_client_ip

        monkeypatch.setattr("scan.routes._run_scan_engine", AsyncMock(return_value={"domain": "example.com"}))

        r = client.get("/v1/scan/example.com")
        assert r.status_code == 200

        store_key = f"free:{hash_client_ip('testclient')}"
        with get_api_db() as con:
            row = con.execute(
                "SELECT COUNT(*) FROM rate_limits WHERE key = ?",
                (f"api:{store_key}",),
            ).fetchone()
        assert int(row[0]) == COST_SCAN, f"REST /v1/scan must charge exactly COST_SCAN={COST_SCAN}; got {int(row[0])}"

    def test_scan_route_target_throttle_429_before_engine(self, monkeypatch):
        """Per-target eTLD+1 throttle fires in the shared impl BEFORE the engine —
        429 + Retry-After, scanner subprocess never spawned."""
        from unittest.mock import AsyncMock

        spy = AsyncMock(return_value={"domain": "example.com"})
        monkeypatch.setattr("scan.routes._run_scan_engine", spy)
        monkeypatch.setattr("target_throttle.consume_target_throttle", lambda host: (False, 30))

        r = client.get("/v1/scan/example.com")
        assert r.status_code == 429
        assert r.headers.get("Retry-After") == "30"
        assert spy.await_count == 0, "engine must not run when the target throttle denies"

    def test_impl_invalid_domain_400(self):
        """clean_domain ValueError (whitespace-only input) maps to HTTP 400 inside
        the shared impl — same contract as the engine's own validation."""
        from scan.routes import _contrast_scan_impl

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(_contrast_scan_impl("   "))
        assert exc_info.value.status_code == 400
