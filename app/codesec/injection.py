"""Detect SQL, command, and path injection patterns in source code."""

import re

from codesec.utils import is_comment, safe_line

# --- SQL Injection rules ---

_SQL_RULES = [
    (
        "SQL Injection: f-string query",
        re.compile(
            r"""f(['"])\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|MERGE)\b"""
            r"""[^'"]*\{""",
            re.IGNORECASE,
        ),
        "critical",
        "SQL query built with f-string interpolation",
        "Use parameterized queries or an ORM instead of string interpolation in SQL",
    ),
    (
        "SQL Injection: .format() query",
        re.compile(
            r"""(['"])\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|MERGE)\b"""
            r"""[^'"]*\{[^}]*\}[^'"]*\1\s*\.format\s*\(""",
            re.IGNORECASE,
        ),
        "critical",
        "SQL query built with .format() string interpolation",
        "Use parameterized queries or an ORM instead of .format() in SQL",
    ),
    (
        "SQL Injection: percent-format query",
        re.compile(
            r"""(['"])\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|MERGE)\b"""
            r"""[^'"]*%\s*(?:s|d|r)[^'"]*\1\s*%\s*""",
            re.IGNORECASE,
        ),
        "critical",
        "SQL query built with %-format string interpolation",
        "Use parameterized queries or an ORM instead of % formatting in SQL",
    ),
    (
        "SQL Injection: string concatenation in query",
        re.compile(
            r"""(['"])\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|MERGE)\b"""
            r"""[^'"]*\1\s*\+""",
            re.IGNORECASE,
        ),
        "high",
        "SQL query built with string concatenation",
        "Use parameterized queries or an ORM instead of concatenating user input into SQL",
    ),
    (
        "SQL Injection: raw SQL execute with variable",
        re.compile(
            r"""(?:execute|executemany|raw|execute_sql|cursor\.execute)\s*\(\s*"""
            r"""(?:f['"]|[^'",)]+\+|[^'",)]+\.format|[^'",)]+%)""",
            re.IGNORECASE,
        ),
        "critical",
        "Raw SQL execution with dynamic string construction",
        "Pass parameters separately via the second argument to execute()",
    ),
    (
        "SQL Injection: Java concatenation",
        re.compile(
            r"""(?:executeQuery|executeUpdate|prepareStatement|execute)\s*\(\s*"""
            r"""['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^'"]*['"]\s*\+""",
            re.IGNORECASE,
        ),
        "critical",
        "Java SQL query built with string concatenation",
        "Use PreparedStatement with parameter placeholders instead of concatenation",
    ),
]

# --- Command Injection rules ---

_CMD_RULES = [
    (
        "Command Injection: os.system()",
        re.compile(
            r"""os\.system\s*\(""",
        ),
        "critical",
        "os.system() executes commands through the shell",
        "Use subprocess.run() with a list of arguments and shell=False (the default)",
    ),
    (
        "Command Injection: os.popen()",
        re.compile(
            r"""os\.popen\s*\(""",
        ),
        "critical",
        "os.popen() executes commands through the shell",
        "Use subprocess.run() with a list of arguments and capture_output=True",
    ),
    (
        "Command Injection: subprocess shell=True",
        re.compile(
            r"""subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True""",
        ),
        "critical",
        "subprocess called with shell=True allows shell injection",
        "Pass arguments as a list and remove shell=True",
    ),
    (
        "Command Injection: eval()",
        re.compile(
            r"""(?<!\w)eval\s*\(""",
        ),
        "critical",
        "eval() executes arbitrary code",
        "Avoid eval(); use ast.literal_eval() for data or a safe parser for expressions",
    ),
    (
        "Command Injection: exec()",
        re.compile(
            r"""(?<!\w)exec\s*\(""",
        ),
        "critical",
        "exec() executes arbitrary code",
        "Avoid exec(); refactor to use safe alternatives like importlib or a plugin system",
    ),
    (
        "Command Injection: child_process.exec()",
        re.compile(
            r"""child_process\.exec\s*\(""",
        ),
        "critical",
        "child_process.exec() runs commands through the shell",
        "Use child_process.execFile() or child_process.spawn() with an argument array",
    ),
    (
        "Command Injection: child_process execSync()",
        re.compile(
            r"""(?:child_process\.)?execSync\s*\(""",
        ),
        "high",
        "execSync() runs commands through the shell synchronously",
        "Use child_process.execFileSync() or child_process.spawnSync() with an argument array",
    ),
    (
        "Command Injection: Runtime.exec() Java",
        re.compile(
            r"""Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(""",
        ),
        "critical",
        "Runtime.exec() can execute arbitrary system commands",
        "Use ProcessBuilder with a list of arguments; validate and sanitize all inputs",
    ),
    (
        "Command Injection: shell backtick execution",
        re.compile(
            r"""`[^`]*\$\{[^}]+\}[^`]*`""",
        ),
        "high",
        "Template literal with interpolation used as shell command",
        "Use child_process.execFile() or spawn() with an argument array",
    ),
]

# --- Path Traversal rules ---

_PATH_RULES = [
    (
        "Path Traversal: dot-dot-slash in file operation",
        re.compile(
            r"""(?:open|read|write|readFile|readFileSync|writeFile|writeFileSync|"""
            r"""createReadStream|createWriteStream)\s*\([^)]*\.\./""",
        ),
        "high",
        "File operation contains ../ path traversal sequence",
        "Canonicalize paths with os.path.realpath() and verify they stay within the allowed directory",
    ),
    (
        "Path Traversal: unsanitized path join with user input",
        re.compile(
            r"""(?:os\.path\.join|path\.join|Path)\s*\([^)]*(?:request|req|params|query|"""
            r"""input|args|argv|user_input|filename|file_name)""",
            re.IGNORECASE,
        ),
        "high",
        "Path join with potentially unsanitized user input",
        "Validate the resolved path starts with the intended base directory after canonicalization",
    ),
    (
        "Path Traversal: direct ../ in string",
        re.compile(
            r"""['"](?:[^'"]*\.\.\/[^'"]*|[^'"]*\.\.\\[^'"]*)['"]\s*(?:\)|,|\])""",
        ),
        "medium",
        "String literal containing ../ may indicate path traversal",
        "Use os.path.realpath() to resolve paths and validate against an allowed base directory",
    ),
    (
        "Path Traversal: open() with variable path",
        re.compile(
            r"""open\s*\(\s*(?:f['"]|[^'",)]+\+|[^'",)]+\.format|[^'",)]+%)""",
        ),
        "high",
        "open() called with dynamically constructed path",
        "Canonicalize the path and validate it resolves within the expected directory",
    ),
    (
        "Path Traversal: send_file/send with user input",
        re.compile(
            r"""(?:send_file|sendFile|send_from_directory|static_file)\s*\([^)]*"""
            r"""(?:request|req|params|query|input|args|filename|file_name)""",
            re.IGNORECASE,
        ),
        "high",
        "File-serving function called with potentially unsanitized input",
        "Use a whitelist of allowed files or validate the resolved path stays within the static directory",
    ),
]

_ALL_RULES = _SQL_RULES + _CMD_RULES + _PATH_RULES


def _redact(value: str) -> str:
    """Redact a match: show first 20 chars + '...' if longer."""
    if len(value) <= 23:
        return value
    return value[:20] + "..."


def detect_injection(code: str, language: str = "generic") -> list[dict]:
    """Scan code for SQL, command, and path injection patterns.

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

        for rule_name, pattern, severity, description, remediation in _ALL_RULES:
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
