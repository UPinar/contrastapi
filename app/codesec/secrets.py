"""Detect hardcoded secrets in source code via regex patterns."""

import re

from codesec.utils import is_comment, safe_line

# (name, pattern, severity, description, remediation)
_SECRET_RULES = [
    (
        "AWS Access Key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "critical",
        "AWS access key ID detected",
        "Use IAM roles or environment variables instead of hardcoded AWS keys",
    ),
    (
        "AWS Secret Key",
        re.compile(
            r"""(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]""",
            re.IGNORECASE,
        ),
        "critical",
        "AWS secret access key detected",
        "Use IAM roles or environment variables instead of hardcoded AWS keys",
    ),
    (
        "GitHub Token",
        re.compile(r"gh[posr]_[A-Za-z0-9_]{36,255}"),
        "critical",
        "GitHub personal access or OAuth token detected",
        "Use GitHub Apps or store tokens in a secrets manager",
    ),
    (
        "GitHub Fine-Grained PAT",
        re.compile(r"github_pat_[A-Za-z0-9_]{22,255}"),
        "critical",
        "GitHub fine-grained personal access token detected",
        "Use GitHub Apps or store tokens in a secrets manager",
    ),
    (
        "Google API Key",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "high",
        "Google API key detected",
        "Restrict the API key and move it to environment variables",
    ),
    (
        "Slack Token",
        re.compile(r"xox[bp]-[0-9A-Za-z\-]{10,250}"),
        "critical",
        "Slack bot or user token detected",
        "Rotate the token and store it in a secrets manager",
    ),
    (
        "Stripe Secret Key",
        re.compile(r"sk_live_[0-9a-zA-Z]{24,99}"),
        "critical",
        "Stripe live secret key detected",
        "Use restricted keys and store them server-side in environment variables",
    ),
    (
        "Stripe Publishable Key",
        re.compile(r"pk_live_[0-9a-zA-Z]{24,99}"),
        "low",
        "Stripe live publishable key detected",
        "Publishable keys are less sensitive but should still not be in source control",
    ),
    (
        "JWT Token",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "high",
        "JSON Web Token detected",
        "Never hardcode JWTs; generate them at runtime and store securely",
    ),
    (
        "Private Key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "critical",
        "Private key block detected",
        "Store private keys in a vault or secrets manager, never in source code",
    ),
    (
        "SendGrid API Key",
        re.compile(r"SG\.[A-Za-z0-9_-]{20,50}\.[A-Za-z0-9_-]{20,50}"),
        "critical",
        "SendGrid API key detected",
        "Rotate the key and store it in environment variables",
    ),
    (
        "Twilio API Key",
        re.compile(r"SK[0-9a-fA-F]{32}"),
        "high",
        "Twilio API key detected",
        "Rotate the key and use environment variables or a secrets manager",
    ),
    (
        "Password Assignment",
        re.compile(
            r"""(?:password|passwd|pwd|secret|api_key|apikey|api_secret|access_token|auth_token)"""
            r"""\s*[:=]\s*['"][^'"]{4,}['"]""",
            re.IGNORECASE,
        ),
        "high",
        "Hardcoded password or secret assignment detected",
        "Use environment variables or a secrets manager for credentials",
    ),
    (
        "Database Connection String",
        re.compile(
            r"(?:mysql|postgres|postgresql|mongodb|redis|amqp|mssql)"
            r"://[^:]+:[^@]+@[^\s'\"]+",
            re.IGNORECASE,
        ),
        "critical",
        "Database connection string with embedded credentials detected",
        "Use environment variables for connection strings; never embed credentials in URIs",
    ),
]


def _redact(value: str) -> str:
    """Redact a matched secret: show first 4 and last 2 chars."""
    if len(value) <= 8:
        return "***"
    return value[:4] + "..." + value[-2:]


def detect_secrets(code: str, language: str = "generic") -> list[dict]:
    """Scan code for hardcoded secrets.

    Args:
        code: Source code string to scan.
        language: Programming language for comment detection.

    Returns:
        List of findings, each with: type, severity, line, match, description, remediation.
    """
    language = language.lower()
    findings = []
    lines = code.split("\n")

    for line_num, line in enumerate(lines, start=1):
        if is_comment(line, language):
            continue
        line = safe_line(line)

        for rule_name, pattern, severity, description, remediation in _SECRET_RULES:
            for m in pattern.finditer(line):
                findings.append({
                    "type": rule_name,
                    "severity": severity,
                    "line": line_num,
                    "match": _redact(m.group()),
                    "description": description,
                    "remediation": remediation,
                })

    return findings
