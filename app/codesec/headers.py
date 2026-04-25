"""Validate HTTP security headers and produce a scored report."""

import re
from collections.abc import Callable

# Weight multipliers per severity
_SEVERITY_WEIGHT = {"high": 25, "medium": 15, "low": 10}

# CSP values from large sites (GitHub, Cloudflare consoles) routinely exceed 4 KB
# verbatim — that blows past MCP token budgets when the agent only needs to see
# directive shape. Default truncation keeps the leading window; total_value_length
# preserves the honest pre-truncation length, ?include=full restores the full value.
MAX_HEADER_VALUE_DEFAULT = 500

# Fetch directives for CSP validation
_FETCH_DIRECTIVES = {
    "default-src",
    "script-src",
    "script-src-elem",
    "script-src-attr",
    "style-src",
    "style-src-elem",
    "style-src-attr",
    "img-src",
    "connect-src",
    "font-src",
    "frame-src",
    "media-src",
    "object-src",
    "worker-src",
    "child-src",
}

# (header_name, severity, description, remediation, owasp_reference)
_HEADER_RULES = [
    (
        "Content-Security-Policy",
        "high",
        "Controls which resources the browser is allowed to load, mitigating XSS and data injection",
        "Add a Content-Security-Policy header with a strict policy; start with default-src 'self'",
        "https://owasp.org/www-project-secure-headers/#content-security-policy",
    ),
    (
        "Strict-Transport-Security",
        "high",
        "Enforces HTTPS connections and prevents protocol downgrade attacks",
        "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "https://owasp.org/www-project-secure-headers/#strict-transport-security",
    ),
    (
        "X-Content-Type-Options",
        "medium",
        "Prevents MIME-type sniffing which can lead to XSS via content-type confusion",
        "Add X-Content-Type-Options: nosniff",
        "https://owasp.org/www-project-secure-headers/#x-content-type-options",
    ),
    (
        "X-Frame-Options",
        "medium",
        "Prevents clickjacking by controlling whether the page can be embedded in frames",
        "Add X-Frame-Options: DENY or SAMEORIGIN",
        "https://owasp.org/www-project-secure-headers/#x-frame-options",
    ),
    (
        "Referrer-Policy",
        "low",
        "Controls how much referrer information is sent with requests, protecting user privacy",
        "Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer",
        "https://owasp.org/www-project-secure-headers/#referrer-policy",
    ),
    (
        "Permissions-Policy",
        "low",
        "Restricts browser features like camera, microphone, and geolocation",
        "Add Permissions-Policy to disable unnecessary browser features (e.g., camera=(), microphone=())",
        "https://owasp.org/www-project-secure-headers/#permissions-policy",
    ),
]

_MAX_SCORE = sum(_SEVERITY_WEIGHT[sev] for _, sev, *_ in _HEADER_RULES)


def _hsts_tokens(value: str) -> list[str]:
    return [t.strip().lower() for t in value.split(";") if t.strip()]


# Validator functions for header values
def _validate_xfo(value: str) -> tuple[bool, list[str]]:
    """Validate X-Frame-Options header value."""
    v = value.strip().upper()
    if v in {"DENY", "SAMEORIGIN"}:
        return True, []
    return False, [f"Invalid value '{value}'. Allowed: DENY, SAMEORIGIN (case-insensitive)"]


def _validate_hsts(value: str) -> tuple[bool, list[str]]:
    """Validate Strict-Transport-Security header value."""
    issues = []
    hard_fail = False

    # Parse tokens
    tokens = _hsts_tokens(value)

    # Check max-age directive
    max_age_token = next((t for t in tokens if t.startswith("max-age")), None)
    if not max_age_token:
        issues.append("Missing max-age directive")
        hard_fail = True
    else:
        ma_match = re.search(r'^max-age\s*=\s*(?:"(\d+)"|(\d+))$', max_age_token, re.IGNORECASE)
        if not ma_match:
            issues.append("Malformed max-age directive")
            hard_fail = True
        else:
            age = int(ma_match.group(1) or ma_match.group(2))
            if age < 15768000:
                issues.append(f"max-age={age} is below recommended minimum of 15768000 (6 months)")
                hard_fail = True

    # Check includeSubDomains
    has_include_subdomains = "includesubdomains" in tokens
    if not has_include_subdomains:
        issues.append("Missing includeSubDomains directive")
        hard_fail = True

    # Check preload (advisory only)
    has_preload = "preload" in tokens
    if not has_preload:
        issues.append("Missing preload directive (recommended)")

    return not hard_fail, issues


def _validate_csp(value: str) -> tuple[bool, list[str]]:
    """Validate Content-Security-Policy header value."""
    issues: list[str] = []

    for directive in value.split(";"):
        parts = directive.strip().split()
        if len(parts) < 2:
            continue
        name = parts[0].lower()
        sources = [s.lower() for s in parts[1:]]
        if name not in _FETCH_DIRECTIVES:
            continue
        if "*" in sources:
            issues.append(f"Permissive CSP: '{name} *' allows any source (XSS risk)")
        if "'unsafe-inline'" in sources:
            issues.append(f"Permissive CSP: '{name}' allows 'unsafe-inline' (XSS risk)")
        if "'unsafe-eval'" in sources:
            issues.append(f"Permissive CSP: '{name}' allows 'unsafe-eval' (code injection risk)")

    return len(issues) == 0, issues


_HEADER_VALIDATORS: dict[str, Callable[[str], tuple[bool, list[str]]]] = {
    "x-frame-options": _validate_xfo,
    "strict-transport-security": _validate_hsts,
    "content-security-policy": _validate_csp,
}


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 70:
        return "B"
    if score >= 50:
        return "C"
    if score >= 30:
        return "D"
    return "F"


def check_headers(headers: dict, include_full: bool = False) -> dict:
    """Evaluate HTTP security headers and return a scored report.

    Args:
        headers: Dict of header name -> value pairs (case-insensitive matching).
        include_full: When True, the raw header `value` is returned verbatim.
            When False (default), `value` is capped at MAX_HEADER_VALUE_DEFAULT
            chars and `total_value_length` carries the honest pre-truncation
            length so callers can decide whether to refetch with include_full.

    Returns:
        Dict with score (0-100), grade (A-F), findings, summary,
        headers_present, and headers_missing.
    """
    # Normalize input keys to lowercase for case-insensitive lookup
    lower_headers = {k.lower(): (k, v) for k, v in headers.items()}

    earned = 0
    findings = []
    present = []
    missing = []

    for header_name, severity, description, remediation, reference in _HEADER_RULES:
        header_key = header_name.lower()
        is_present = header_key in lower_headers

        finding = {
            "header": header_name,
            "severity": severity,
            "present": is_present,
            "description": description,
            "remediation": remediation,
            "reference": reference,
        }

        if is_present:
            _, raw_value = lower_headers[header_key]
            validator = _HEADER_VALIDATORS.get(header_key)
            if validator:
                valid, issues = validator(raw_value)
                finding["valid"] = valid
                finding["issues"] = issues
                if include_full or len(raw_value) <= MAX_HEADER_VALUE_DEFAULT:
                    finding["value"] = raw_value
                else:
                    finding["value"] = raw_value[:MAX_HEADER_VALUE_DEFAULT]
                    finding["total_value_length"] = len(raw_value)
            else:
                finding["valid"] = True
                finding["value"] = None
                finding["issues"] = []
            earned += _SEVERITY_WEIGHT[severity]
            present.append(header_name)
        else:
            finding["valid"] = False
            finding["value"] = None
            finding["issues"] = []
            missing.append(header_name)

        findings.append(finding)

    score = round(earned * 100 / _MAX_SCORE)
    grade = _grade(score)

    if not missing:
        summary = f"All {len(present)} security headers present — score {score}/100 (grade {grade})"
    else:
        summary = (
            f"{len(present)}/{len(_HEADER_RULES)} security headers present — "
            f"missing {', '.join(missing)} — score {score}/100 (grade {grade})"
        )

    return {
        "score": score,
        "grade": grade,
        "findings": findings,
        "summary": summary,
        "headers_present": present,
        "headers_missing": missing,
    }
