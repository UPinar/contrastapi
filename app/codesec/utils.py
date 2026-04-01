"""Shared utilities for code security scanners."""

import re

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


def is_comment(line: str, language: str) -> bool:
    """Check if a line is a single-line comment."""
    pattern = _COMMENT_PATTERNS.get(language, _COMMENT_PATTERNS["generic"])
    return bool(pattern.match(line))


def safe_line(line: str) -> str:
    """Truncate overly long lines to prevent regex backtracking."""
    if len(line) > MAX_LINE_LENGTH:
        return line[:MAX_LINE_LENGTH]
    return line
