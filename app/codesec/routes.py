"""Code Security API routes — /v1/check/*"""

from collections import Counter
from typing import Annotated

import anyio
from auth import AuthCtx, require_auth
from codesec.headers import check_headers
from codesec.injection import detect_injection
from codesec.schemas import CheckHeadersResponse, CodeCheckResponse, DependenciesResponse, ScanHeadersResponse
from codesec.secrets import detect_secrets
from db import _normalize_product, _parse_version, asearch_cves_by_products_bulk, hash_client_ip
from domain.recon import fetch_live_headers
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from validation import _is_valid_format, clean_domain, is_valid_ip, validate_domain

router = APIRouter(prefix="/v1", tags=["Code Security"])

MAX_CODE_BYTES = 500 * 1024  # 500 KB
MAX_CONCURRENT_SCANS = 4
SEMAPHORE_TIMEOUT = 5

# Limits concurrent code scans to prevent thread-pool starvation. anyio.Semaphore
# (not asyncio.Semaphore) so acquire() yields the event loop AND survives across
# event loops — TestClient creates a fresh loop per request, which would bind
# asyncio.Semaphore to a dead loop and raise on the second test.
_scan_semaphore = anyio.Semaphore(MAX_CONCURRENT_SCANS)


# --- Request models ---

ALLOWED_LANGUAGES = {"generic", "python", "javascript", "typescript", "java", "go", "ruby", "shell", "bash"}
MAX_HEADERS = 50


class CodeInput(BaseModel):
    code: str = Field(
        ...,
        description=(
            "Source code snippet to scan. Plain text; no length cap, but each scanner has its "
            "own per-line caps (ReDoS protection). Submit only code you have authorization to "
            "share — content is processed in-memory and not persisted."
        ),
    )
    language: str = Field(
        default="generic",
        description=(
            "Source language hint for comment-stripping and rule selection. Allowed: "
            "generic, python, javascript, typescript, java, go, ruby, shell, bash. "
            "Use 'generic' if unknown — falls back to language-agnostic patterns."
        ),
    )


class HeadersInput(BaseModel):
    headers: dict[str, str] = Field(
        ...,
        description=(
            "HTTP response header name-value pairs to validate against best practices. "
            f"Maximum {MAX_HEADERS} headers per request. Header names are case-insensitive; "
            "include only security-relevant headers (CSP, HSTS, X-Frame-Options, etc.) — "
            "non-security headers are ignored."
        ),
    )


class PackageItem(BaseModel):
    name: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Package name as published in its ecosystem registry (e.g. 'requests', 'lodash', 'log4j-core').",
    )
    version: str | None = Field(
        default=None,
        max_length=100,
        description="Optional exact version string. Omit to check the package itself for advisories without version filtering.",
    )


class DependenciesInput(BaseModel):
    packages: list[PackageItem] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="List of package name+version pairs to check against known vulnerability advisories. Max 50 per request.",
    )


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
async def check_secrets_endpoint(
    body: CodeInput,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/check/secrets"))],
):
    """Detect hardcoded secrets (AWS keys, tokens, passwords, etc.) in source code."""
    _check_code_size(body.code)
    lang = body.language.lower()
    if lang not in ALLOWED_LANGUAGES:
        raise HTTPException(
            status_code=400,
            detail=f"Language '{body.language}' not supported. Allowed: {', '.join(sorted(ALLOWED_LANGUAGES))}",
        )

    try:
        with anyio.fail_after(SEMAPHORE_TIMEOUT):
            await _scan_semaphore.acquire()
    except TimeoutError:
        raise HTTPException(status_code=503, detail="Too many concurrent scans. Please retry.") from None
    try:
        findings = await run_in_threadpool(detect_secrets, body.code, lang)
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
async def check_injection_endpoint(
    body: CodeInput,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/check/injection"))],
):
    """Detect SQL injection, command injection, and path traversal patterns in source code."""
    _check_code_size(body.code)
    lang = body.language.lower()
    if lang not in ALLOWED_LANGUAGES:
        raise HTTPException(
            status_code=400,
            detail=f"Language '{body.language}' not supported. Allowed: {', '.join(sorted(ALLOWED_LANGUAGES))}",
        )

    try:
        with anyio.fail_after(SEMAPHORE_TIMEOUT):
            await _scan_semaphore.acquire()
    except TimeoutError:
        raise HTTPException(status_code=503, detail="Too many concurrent scans. Please retry.") from None
    try:
        findings = await run_in_threadpool(detect_injection, body.code, lang)
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
async def scan_headers_endpoint(
    domain: Annotated[
        str,
        Path(
            description=(
                "Registrable domain, e.g. 'example.com'. No scheme, no path. "
                "Bare IPs are rejected — use /v1/ip/{ip} instead. Live HTTPS fetch is performed; "
                "use /v1/check/headers (POST) to analyze a header dict you already have."
            ),
        ),
    ],
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/scan/headers"))],
    include: Annotated[
        str | None,
        Query(
            description=(
                "Detail level. Default returns slim findings (raw header values capped at 500 chars; "
                "total_value_length carries the honest pre-truncation length when truncation occurred). "
                "Pass include=full to restore the full raw value for every present-with-validator header "
                "(useful for inspecting full CSP directives end-to-end)."
            ),
        ),
    ] = None,
):
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
    if include not in (None, "", "full"):
        raise HTTPException(status_code=400, detail="include must be 'full' (omit for slim default)")
    resolved_ip = await run_in_threadpool(validate_domain, domain)
    if not resolved_ip:
        raise HTTPException(status_code=422, detail="Could not resolve this domain. DNS resolution failed.")

    result = await fetch_live_headers(domain)
    if "error" in result:
        raise HTTPException(status_code=504, detail=result["error"])

    analysis = check_headers(result["headers"], include_full=(include == "full"))
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
async def check_headers_endpoint(
    body: HeadersInput,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/check/headers"))],
    include: Annotated[
        str | None,
        Query(
            description=(
                "Detail level. Default returns slim findings (raw header values capped at 500 chars; "
                "total_value_length carries the honest pre-truncation length when truncation occurred). "
                "Pass include=full to restore the full raw value for every present-with-validator header."
            ),
        ),
    ] = None,
):
    """Validate HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)."""
    if include not in (None, "", "full"):
        raise HTTPException(status_code=400, detail="include must be 'full' (omit for slim default)")
    if len(body.headers) > MAX_HEADERS:
        raise HTTPException(status_code=400, detail=f"Too many headers (max {MAX_HEADERS})")

    result = check_headers(body.headers, include_full=(include == "full"))
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
async def check_dependencies_endpoint(
    body: DependenciesInput,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/check/dependencies"))],
):
    """Check packages against the CVE database for known vulnerabilities.

    Up to 10 packages (free) or 50 (pro). Each package counts as 1 request toward rate limit.
    """
    import ratelimit
    from config import FREE_BULK_LIMIT, FREE_HOURLY_LIMIT, PRO_BULK_LIMIT, PRO_HOURLY_LIMIT

    seen: set[tuple[str, str | None]] = set()
    packages: list[PackageItem] = []
    for p in body.packages:
        version_norm = p.version.strip().lower() if p.version else None
        key = (p.name.strip().lower(), version_norm)
        if not key[0] or key in seen:
            continue
        seen.add(key)
        packages.append(p)
    count = len(packages)
    if count == 0:
        raise HTTPException(status_code=400, detail="packages must contain at least one non-empty name")

    bulk_limit = PRO_BULK_LIMIT if auth.tier == "pro" else FREE_BULK_LIMIT
    if count > bulk_limit:
        raise HTTPException(
            status_code=422,
            detail=f"Too many packages. Limit: {bulk_limit} (your tier: {auth.tier})",
        )

    if auth.tier == "pro":
        store_key = f"pro:{auth.key_hash}"
        limit = PRO_HOURLY_LIMIT
    else:
        store_key = f"free:{hash_client_ip(auth.client_ip)}"
        limit = FREE_HOURLY_LIMIT

    if count > 1 and not await ratelimit.aconsume_bulk("api", store_key, count - 1, limit):
        raise HTTPException(
            status_code=429,
            detail=f"Insufficient rate limit quota for {count} packages.",
        )

    product_names = [pkg.name for pkg in packages]
    # NOTE: version-range matching below reads affected_products from the raw DB row
    # via asearch_cves_by_products_bulk — NOT from the HTTP API response — so it is not
    # affected by the default truncation in _format_cve(). Do not rewire this path
    # through the API without restoring full affected_products, or version matches
    # against products 21+ will be silently missed.
    try:
        cve_groups = await asearch_cves_by_products_bulk(product_names, limit_per_product=20)
    except Exception:
        raise HTTPException(status_code=503, detail="CVE database temporarily unavailable. Please retry.") from None

    findings = []
    for pkg in packages:
        pkg_name_norm = _normalize_product(pkg.name).strip().lower()
        cves = cve_groups.get(pkg_name_norm, [])
        parsed_ver = _parse_version(pkg.version) if pkg.version else None
        matched_cves: list[tuple[dict, str | None]] = []
        for cve in cves:
            fix_version: str | None = None
            if parsed_ver:
                matched = False
                for prod in cve.get("affected_products", []):
                    if pkg_name_norm not in (prod.get("product") or "").lower():
                        continue
                    vs = prod.get("version_start")
                    ve = prod.get("version_end")
                    try:
                        if vs and parsed_ver < _parse_version(vs):
                            continue
                        if ve and parsed_ver >= _parse_version(ve):
                            continue
                    except TypeError:
                        continue
                    matched = True
                    # version_end is the first patched release per NVD/MITRE semantics.
                    # Open-ended ranges (no upper bound) leave fix_version None and the
                    # generic remediation copy is emitted instead.
                    fix_version = ve or None
                    break
                if not matched and cve.get("affected_products"):
                    continue
            matched_cves.append((cve, fix_version))
            if len(matched_cves) >= 20:
                break
        for cve, fix_version in matched_cves:
            severity = (cve.get("severity") or "unknown").lower()
            if fix_version:
                remediation = (
                    f"Upgrade {pkg.name} to {fix_version} or later "
                    f"(current: {pkg.version or 'unknown'}) to patch {cve['cve_id']}"
                )
            else:
                remediation = (
                    f"Check if {pkg.name} {pkg.version or 'current'} is affected by {cve['cve_id']} and upgrade if so"
                )
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
                    "fixed_in": fix_version,
                    "remediation": remediation,
                }
            )

    by_severity = _severity_counts(findings)
    total = len(findings)
    pkg_count = count

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
