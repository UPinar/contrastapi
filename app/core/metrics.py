"""In-memory metrics counters + path normalization/sanitization helpers.

`metrics` dict + `metrics_lock` are read by /metrics endpoint, written by
RequestContextMiddleware. `_sanitize_path` is consumed by request loggers to
redact PII (domains, IPs, emails) before paths land in journald.
"""

import re
import threading

metrics_lock = threading.Lock()
metrics: dict = {
    "requests_total": 0,
    "requests_by_status": {},
    "requests_by_path": {},
    "errors_total": 0,
    "latency_sum_ms": 0,
}


_PATH_NORMALIZE = re.compile(
    r"/v1/(cve|domain|dns|whois|subdomains|certs|ssl|threat|ip|epss|exploit|scan/headers|monitor|ioc|hash|password|asn|phishing|tech|email/mx|email/disposable|phone)/[^/]+(?:/(changes|vulns))?"
)

_MAX_TRACKED_PATHS = 200

_LOG_SANITIZE = re.compile(
    r"/v1/(phone|email/security-posture|email/verify|email/mx|email/disposable|ip|domain|dns|whois|subdomains|certs|ssl|threat-report|threat|tech|monitor|ioc|phishing|scan/headers|scan|redirect|robots|brand|seo|audit|kev|atlas/case-studies|atlas|d3fend/attack|d3fend|sigma|cwe|asn|password|archive|username|cve|cves|exploit|hash|epss)(?:/(lookup|search|leading|bulk|report))?/[^?]+",
    re.IGNORECASE,
)


def _sanitize_path(path: str) -> str:
    """Redact PII (domains, IPs, emails, phones) from request paths for safe logging."""
    safe = re.sub(r"[\x00-\x1f\x7f]", "", path)
    query_idx = safe.find("?")
    if query_idx >= 0:
        safe = safe[:query_idx]
    return _LOG_SANITIZE.sub(
        lambda m: (
            f"/v1/{m.group(1).lower()}/{m.group(2).lower()}/***" if m.group(2) else f"/v1/{m.group(1).lower()}/***"
        ),
        safe,
    )


def _normalize_path(path: str) -> str:
    """Normalize dynamic path segments to prevent unbounded memory growth."""
    m = _PATH_NORMALIZE.match(path)
    if m:
        return f"/v1/{m.group(1)}/{{id}}"
    return path


def record_metric(path: str, status: int, elapsed_ms: int) -> None:
    with metrics_lock:
        metrics["requests_total"] += 1
        metrics["latency_sum_ms"] += elapsed_ms
        status_key = str(status)
        metrics["requests_by_status"][status_key] = metrics["requests_by_status"].get(status_key, 0) + 1
        if path.startswith("/v1/"):
            norm = _normalize_path(path)
            if len(metrics["requests_by_path"]) < _MAX_TRACKED_PATHS or norm in metrics["requests_by_path"]:
                metrics["requests_by_path"][norm] = metrics["requests_by_path"].get(norm, 0) + 1
        if status >= 400:
            metrics["errors_total"] += 1
