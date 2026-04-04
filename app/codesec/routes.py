"""Code Security API routes — /v1/check/*"""

import threading
from collections import Counter

from auth import authenticate
from codesec.headers import check_headers
from codesec.injection import detect_injection
from codesec.secrets import detect_secrets
from db import search_cves_by_product
from domain.recon import fetch_live_headers
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from schemas import CheckHeadersResponse, CodeCheckResponse, DependenciesResponse, ScanHeadersResponse
from validation import _is_valid_format, clean_domain, is_valid_ip, validate_domain

router = APIRouter(prefix="/v1", tags=["Code Security"])

MAX_CODE_BYTES = 500 * 1024  # 500 KB
MAX_CONCURRENT_SCANS = 4

# Limits concurrent code scans to prevent thread-pool starvation
_scan_semaphore = threading.Semaphore(MAX_CONCURRENT_SCANS)


# --- Request models ---

ALLOWED_LANGUAGES = {"generic", "python", "javascript", "typescript", "java", "go", "ruby", "shell", "bash"}
MAX_HEADERS = 50


class CodeInput(BaseModel):
    code: str
    language: str = "generic"


class HeadersInput(BaseModel):
    headers: dict[str, str]


class PackageItem(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    version: str | None = None


class DependenciesInput(BaseModel):
    packages: list[PackageItem] = Field(..., min_length=1, max_length=500)


# --- Helpers ---


def _check_code_size(code: str) -> None:
    if len(code.encode("utf-8")) > MAX_CODE_BYTES:
        raise HTTPException(status_code=400, detail="Code input exceeds 500KB limit")


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = Counter(f["severity"] for f in findings)
    return {s: counts.get(s, 0) for s in ("critical", "high", "medium", "low") if counts.get(s, 0)}


# --- Endpoints ---


@router.post(
    "/check/secrets", operation_id="check_secrets", response_model=CodeCheckResponse, response_model_exclude_none=True
)
def check_secrets_endpoint(body: CodeInput, request: Request):
    """Detect hardcoded secrets (AWS keys, tokens, passwords, etc.) in source code."""
    authenticate(request, "/v1/check/secrets")
    _check_code_size(body.code)
    lang = body.language.lower()
    if lang not in ALLOWED_LANGUAGES:
        raise HTTPException(
            status_code=400,
            detail=f"Language '{body.language}' not supported. Allowed: {', '.join(sorted(ALLOWED_LANGUAGES))}",
        )

    acquired = _scan_semaphore.acquire(timeout=5)
    if not acquired:
        raise HTTPException(status_code=503, detail="Too many concurrent scans. Please retry.")
    try:
        findings = detect_secrets(body.code, lang)
    finally:
        _scan_semaphore.release()
    by_severity = _severity_counts(findings)
    total = len(findings)

    if total == 0:
        summary = "No hardcoded secrets detected"
    else:
        summary = f"Found {total} hardcoded secret{'s' if total != 1 else ''} ({', '.join(f'{v} {k}' for k, v in by_severity.items())})"

    return {
        "findings": findings,
        "total": total,
        "by_severity": by_severity,
        "summary": summary,
    }


@router.post(
    "/check/injection",
    operation_id="check_injection",
    response_model=CodeCheckResponse,
    response_model_exclude_none=True,
)
def check_injection_endpoint(body: CodeInput, request: Request):
    """Detect SQL injection, command injection, and path traversal patterns in source code."""
    authenticate(request, "/v1/check/injection")
    _check_code_size(body.code)
    lang = body.language.lower()
    if lang not in ALLOWED_LANGUAGES:
        raise HTTPException(
            status_code=400,
            detail=f"Language '{body.language}' not supported. Allowed: {', '.join(sorted(ALLOWED_LANGUAGES))}",
        )

    acquired = _scan_semaphore.acquire(timeout=5)
    if not acquired:
        raise HTTPException(status_code=503, detail="Too many concurrent scans. Please retry.")
    try:
        findings = detect_injection(body.code, lang)
    finally:
        _scan_semaphore.release()
    by_severity = _severity_counts(findings)
    total = len(findings)

    if total == 0:
        summary = "No injection vulnerabilities detected"
    else:
        summary = f"Found {total} injection pattern{'s' if total != 1 else ''} ({', '.join(f'{v} {k}' for k, v in by_severity.items())})"

    return {
        "findings": findings,
        "total": total,
        "by_severity": by_severity,
        "summary": summary,
    }


@router.get(
    "/scan/headers/{domain}",
    operation_id="scan_headers",
    tags=["Domain Intelligence"],
    response_model=ScanHeadersResponse,
    response_model_exclude_none=True,
)
def scan_headers_endpoint(domain: str, request: Request):
    """Fetch a domain's HTTP headers live and analyze security posture."""
    domain = clean_domain(domain)
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain")
    if is_valid_ip(domain):
        raise HTTPException(
            status_code=400, detail=f"'{domain}' is an IP address, not a domain. Use /v1/ip/{domain} instead."
        )
    if not _is_valid_format(domain):
        raise HTTPException(status_code=400, detail="Invalid domain")
    authenticate(request, request.url.path)
    resolved_ip = validate_domain(domain)
    if not resolved_ip:
        raise HTTPException(status_code=422, detail="Could not resolve this domain. DNS resolution failed.")

    result = fetch_live_headers(domain)
    if "error" in result:
        raise HTTPException(status_code=504, detail=result["error"])

    analysis = check_headers(result["headers"])
    return {
        "domain": domain,
        "status_code": result["status_code"],
        "url": result["url"],
        **analysis,
    }


@router.post(
    "/check/headers",
    operation_id="check_headers",
    response_model=CheckHeadersResponse,
    response_model_exclude_none=True,
)
def check_headers_endpoint(body: HeadersInput, request: Request):
    """Validate HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)."""
    authenticate(request, "/v1/check/headers")
    if len(body.headers) > MAX_HEADERS:
        raise HTTPException(status_code=400, detail=f"Too many headers (max {MAX_HEADERS})")

    result = check_headers(body.headers)
    by_severity = _severity_counts(result["findings"])

    return {
        "findings": result["findings"],
        "total": len(result["findings"]),
        "by_severity": by_severity,
        "summary": result["summary"],
        "score": result["score"],
        "grade": result["grade"],
        "headers_present": result["headers_present"],
        "headers_missing": result["headers_missing"],
    }


@router.post(
    "/check/dependencies",
    operation_id="check_dependencies",
    response_model=DependenciesResponse,
    response_model_exclude_none=True,
)
def check_dependencies_endpoint(body: DependenciesInput, request: Request):
    """Check packages against the CVE database for known vulnerabilities."""
    authenticate(request, "/v1/check/dependencies")

    findings = []
    for pkg in body.packages:
        # Use cve_products table for precise vendor/product matching with version ranges
        cves = search_cves_by_product(pkg.name, version=pkg.version, limit=20)
        for cve in cves:
            severity = (cve.get("severity") or "unknown").lower()
            findings.append(
                {
                    "package": pkg.name,
                    "version": pkg.version,
                    "cve_id": cve["cve_id"],
                    "severity": severity,
                    "cvss_v3": cve.get("cvss_v3"),
                    "description": cve.get("description", "")[:300],
                    "epss_score": cve.get("epss_score"),
                    "in_kev": bool(cve.get("in_kev")),
                    "remediation": f"Check if {pkg.name} {pkg.version or 'current'} is affected by {cve['cve_id']} and upgrade if so",
                }
            )

    by_severity = _severity_counts(findings)
    total = len(findings)
    pkg_count = len(body.packages)

    if total == 0:
        summary = f"No known CVEs found for {pkg_count} package{'s' if pkg_count != 1 else ''}"
    else:
        affected = len({f["package"] for f in findings})
        summary = (
            f"Found {total} CVE{'s' if total != 1 else ''} across {affected} of {pkg_count} "
            f"package{'s' if pkg_count != 1 else ''} ({', '.join(f'{v} {k}' for k, v in by_severity.items())})"
        )

    return {
        "findings": findings,
        "total": total,
        "by_severity": by_severity,
        "summary": summary,
    }
