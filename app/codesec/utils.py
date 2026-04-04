"""Shared utilities for code security scanners."""

import concurrent.futures
import logging
import re

logger = logging.getLogger(__name__)

# Comment patterns per language (single-line only)
_COMMENT_PATTERNS = {
    "python": re.compile(r"^\s*#"),
    "javascript": re.compile(r"^\s*//"),
    "typescript": re.compile(r"^\s*//"),
    "java": re.compile(r"^\s*//"),
    "go": re.compile(r"^\s*//"),
    "ruby": re.compile(r"^\s*#"),
    "shell": re.compile(r"^\s*#"),
    "bash": re.compile(r"^\s*#"),
    "generic": re.compile(r"^\s*(?:#|//)"),
}

# Max line length to scan — longer lines are truncated to prevent ReDoS
MAX_LINE_LENGTH = 2000

# Max lines to scan — prevents CPU exhaustion on many-line payloads
MAX_LINES = 10_000

# Max findings per scan — caps memory and response size
MAX_FINDINGS = 1_000

# Per-line regex timeout in seconds — prevents catastrophic backtracking
REGEX_TIMEOUT_SECONDS = 1.0

# Shared executor for regex timeout (4 workers for concurrent requests)
_regex_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)

# Type alias for rule tuples: (name, pattern, severity, description, remediation)
type Rule = tuple[str, re.Pattern, str, str, str]


def is_comment(line: str, language: str) -> bool:
    """Check if a line is a single-line comment."""
    pattern = _COMMENT_PATTERNS.get(language, _COMMENT_PATTERNS["generic"])
    return bool(pattern.match(line))


def safe_line(line: str) -> str:
    """Truncate overly long lines to prevent regex backtracking."""
    if len(line) > MAX_LINE_LENGTH:
        return line[:MAX_LINE_LENGTH]
    return line


def _scan_line(rules: list[Rule], text: str) -> list[tuple[str, str, str, str, str]]:
    """Run all rules against a single line. Runs inside thread pool."""
    results = []
    for rule_name, pattern, severity, description, remediation in rules:
        for m in pattern.finditer(text):
            results.append((rule_name, severity, m.group(), description, remediation))
    return results


def safe_scan_line(
    rules: list[Rule], text: str, timeout: float = REGEX_TIMEOUT_SECONDS
) -> list[tuple[str, str, str, str, str]]:
    """Run all rules against a single line with timeout protection.

    Batches all pattern matches for one line into a single thread-pool task
    to minimize submissions (N lines, not N*rules).

    Returns list of (rule_name, severity, match_text, description, remediation)
    tuples, or empty list if the line scan exceeds the timeout.
    """
    future = _regex_executor.submit(_scan_line, rules, text)
    try:
        return future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        logger.warning(
            "Regex scan timeout (%.1fs): line_len=%d rules=%d",
            timeout,
            len(text),
            len(rules),
        )
        future.cancel()
        return []
