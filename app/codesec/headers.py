"""Validate HTTP security headers and produce a scored report."""

# Weight multipliers per severity
_SEVERITY_WEIGHT = {"high": 25, "medium": 15, "low": 10}

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


def check_headers(headers: dict) -> dict:
    """Evaluate HTTP security headers and return a scored report.

    Args:
        headers: Dict of header name -> value pairs (case-insensitive matching).

    Returns:
        Dict with score (0-100), grade (A-F), findings, summary,
        headers_present, and headers_missing.
    """
    # Normalize input keys to lowercase for case-insensitive lookup
    lower_headers = {k.lower(): v for k, v in headers.items()}

    earned = 0
    findings = []
    present = []
    missing = []

    for header_name, severity, description, remediation, reference in _HEADER_RULES:
        is_present = header_name.lower() in lower_headers

        if is_present:
            earned += _SEVERITY_WEIGHT[severity]
            present.append(header_name)
        else:
            missing.append(header_name)

        findings.append({
            "header": header_name,
            "severity": severity,
            "present": is_present,
            "description": description,
            "remediation": remediation,
            "reference": reference,
        })

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
