"""Tests for Code Security module — secrets, injection, headers, and routes."""

import re
from unittest.mock import MagicMock, patch

from codesec.headers import check_headers
from codesec.injection import detect_injection
from codesec.secrets import detect_secrets
from codesec.utils import MAX_FINDINGS, MAX_LINE_LENGTH, MAX_LINES, REGEX_TIMEOUT_SECONDS, safe_scan_line
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


# =========== detect_secrets unit tests ===========


class TestDetectSecretsAWS:
    def test_aws_access_key(self):
        r = detect_secrets('key = "AKIAIOSFODNN7EXAMPLE"')
        assert len(r) == 1
        assert r[0]["type"] == "AWS Access Key"
        assert r[0]["severity"] == "critical"

    def test_aws_key_redacted(self):
        r = detect_secrets('key = "AKIAIOSFODNN7EXAMPLE"')
        assert r[0]["match"] == "AKIA...LE"

    def test_aws_key_line_number(self):
        r = detect_secrets('x = 1\nkey = "AKIAIOSFODNN7EXAMPLE"')
        assert r[0]["line"] == 2

    def test_aws_secret_key_env_var_style(self):
        r = detect_secrets("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        aws_secret = [f for f in r if f["type"] == "AWS Secret Key"]
        assert len(aws_secret) == 1
        assert aws_secret[0]["severity"] == "critical"

    def test_aws_secret_key_quoted_still_works(self):
        r = detect_secrets('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')
        aws_secret = [f for f in r if f["type"] == "AWS Secret Key"]
        assert len(aws_secret) == 1

    def test_aws_secret_key_no_context_not_matched(self):
        r = detect_secrets('blob = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')
        assert not any(f["type"] == "AWS Secret Key" for f in r)


class TestDetectSecretsGitHub:
    def test_github_pat(self):
        token = "ghp_" + "A" * 36
        r = detect_secrets(f'token = "{token}"')
        assert any(f["type"] == "GitHub Token" for f in r)
        assert any(f["severity"] == "critical" for f in r)

    def test_github_oauth_token(self):
        token = "gho_" + "B" * 36
        r = detect_secrets(f't = "{token}"')
        assert any(f["type"] == "GitHub Token" for f in r)

    def test_github_server_token(self):
        token = "ghs_" + "C" * 36
        r = detect_secrets(f't = "{token}"')
        assert any(f["type"] == "GitHub Token" for f in r)


class TestDetectSecretsJWT:
    def test_jwt_detected(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        r = detect_secrets(f't = "{jwt}"')
        assert any(f["type"] == "JWT Token" for f in r)
        assert any(f["severity"] == "high" for f in r)

    def test_jwt_redacted(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        r = detect_secrets(f't = "{jwt}"')
        match = [f for f in r if f["type"] == "JWT Token"][0]["match"]
        assert match.startswith("eyJh")
        assert "..." in match
        assert len(match) < len(jwt)


class TestDetectSecretsPassword:
    def test_password_assignment(self):
        r = detect_secrets('password = "super_secret_123"')
        assert any(f["type"] == "Password Assignment" for f in r)

    def test_api_key_assignment(self):
        r = detect_secrets('api_key = "abcdef123456"')
        assert any(f["type"] == "Password Assignment" for f in r)

    def test_secret_assignment(self):
        r = detect_secrets("secret = 'my_secret_value'")
        assert any(f["type"] == "Password Assignment" for f in r)

    def test_short_password_ignored(self):
        r = detect_secrets('password = "ab"')
        assert not any(f["type"] == "Password Assignment" for f in r)


class TestDetectSecretsDBConn:
    def test_postgres_connection_string(self):
        r = detect_secrets('db = "postgres://admin:pass123@db.example.com/mydb"')
        assert any(f["type"] == "Database Connection String" for f in r)
        assert any(f["severity"] == "critical" for f in r)

    def test_mysql_connection_string(self):
        r = detect_secrets('url = "mysql://root:secret@localhost/app"')
        assert any(f["type"] == "Database Connection String" for f in r)

    def test_mongodb_connection_string(self):
        r = detect_secrets('uri = "mongodb://user:pass@mongo.internal/db"')
        assert any(f["type"] == "Database Connection String" for f in r)


class TestDetectSecretsComments:
    def test_python_comment_skipped(self):
        r = detect_secrets('# key = "AKIAIOSFODNN7EXAMPLE"', "python")
        assert len(r) == 0

    def test_js_comment_skipped(self):
        r = detect_secrets('// key = "AKIAIOSFODNN7EXAMPLE"', "javascript")
        assert len(r) == 0

    def test_non_comment_detected(self):
        r = detect_secrets('key = "AKIAIOSFODNN7EXAMPLE"', "python")
        assert len(r) >= 1


class TestDetectSecretsClean:
    def test_clean_code_no_findings(self):
        r = detect_secrets("x = 1 + 2\nprint('hello world')")
        assert r == []

    def test_finding_structure(self):
        r = detect_secrets('key = "AKIAIOSFODNN7EXAMPLE"')
        f = r[0]
        assert set(f.keys()) == {"type", "severity", "line", "match", "description", "remediation"}


# =========== detect_injection unit tests ===========


class TestInjectionSQL:
    def test_fstring_sql(self):
        r = detect_injection('q = f"SELECT * FROM users WHERE id = {uid}"')
        assert any("f-string" in f["type"] for f in r)
        assert any(f["severity"] == "critical" for f in r)

    def test_format_sql(self):
        r = detect_injection('"SELECT * FROM users WHERE id = {}".format(uid)')
        assert any(".format()" in f["type"] for f in r)

    def test_percent_sql(self):
        r = detect_injection('"SELECT * FROM users WHERE id = %s" % uid')
        assert any("percent-format" in f["type"] for f in r)

    def test_concat_sql(self):
        r = detect_injection('"SELECT * FROM users WHERE id = " + uid')
        assert any("concatenation" in f["type"] for f in r)

    def test_execute_fstring(self):
        r = detect_injection('cursor.execute(f"SELECT * FROM {table}")')
        assert any("raw SQL" in f["type"] for f in r)

    def test_concat_sql_mixed_quotes(self):
        r = detect_injection('''q = "SELECT * FROM users WHERE id = '" + user_id + "'"''')
        assert any("concatenation" in f["type"] for f in r), r

    def test_concat_sql_single_outer_double_inner(self):
        r = detect_injection("""q = 'SELECT * FROM users WHERE name = "' + name + '"'""")
        assert any("concatenation" in f["type"] for f in r), r


class TestInjectionCommand:
    def test_os_system(self):
        r = detect_injection("os.system(cmd)")
        assert any("os.system" in f["type"] for f in r)
        assert any(f["severity"] == "critical" for f in r)

    def test_os_popen(self):
        r = detect_injection("os.popen(cmd)")
        assert any("os.popen" in f["type"] for f in r)

    def test_subprocess_shell_true(self):
        r = detect_injection("subprocess.run(cmd, shell=True)")
        assert any("subprocess" in f["type"] for f in r)
        assert any(f["severity"] == "critical" for f in r)

    def test_subprocess_call_shell_true(self):
        r = detect_injection("subprocess.call(args, shell=True)")
        assert any("subprocess" in f["type"] for f in r)

    def test_eval(self):
        r = detect_injection("result = eval(user_input)")
        assert any("eval()" in f["type"] for f in r)
        assert any(f["severity"] == "critical" for f in r)

    def test_exec(self):
        r = detect_injection("exec(code_string)")
        assert any("exec()" in f["type"] for f in r)

    def test_child_process_exec(self):
        r = detect_injection("child_process.exec(cmd)", "javascript")
        assert any("child_process.exec" in f["type"] for f in r)

    def test_runtime_exec_java(self):
        r = detect_injection("Runtime.getRuntime().exec(cmd);", "java")
        assert any("Runtime" in f["type"] for f in r)


class TestInjectionPathTraversal:
    def test_dotdotslash_in_open(self):
        r = detect_injection('f = open("../../etc/passwd")')
        assert any("dot-dot-slash" in f["type"] for f in r)

    def test_path_join_user_input(self):
        r = detect_injection('p = os.path.join(base, request.args["file"])')
        assert any("path join" in f["type"] for f in r)

    def test_open_fstring(self):
        r = detect_injection('data = open(f"/uploads/{filename}")')
        assert any("open()" in f["type"] for f in r)

    def test_send_file_user_input(self):
        r = detect_injection('return send_file(request.args["path"])')
        assert any("send_file" in f["type"] for f in r)

    def test_path_bare_concat_prefix(self):
        r = detect_injection('dst = "/var/data/" + filename')
        assert any("path-like" in f["type"] for f in r), r

    def test_path_bare_concat_suffix(self):
        r = detect_injection('dst = base + "/uploads/file.txt"')
        assert any("path-like" in f["type"] for f in r), r


class TestInjectionComments:
    def test_python_comment_skipped(self):
        r = detect_injection("# os.system(cmd)", "python")
        assert r == []

    def test_js_comment_skipped(self):
        r = detect_injection("// eval(input)", "javascript")
        assert r == []


class TestInjectionClean:
    def test_orm_query_no_findings(self):
        r = detect_injection("result = db.query(User).filter_by(id=uid).first()")
        assert r == []

    def test_finding_structure(self):
        r = detect_injection("os.system(cmd)")
        f = r[0]
        assert set(f.keys()) == {"type", "severity", "line", "match", "description", "remediation"}

    def test_redaction_short(self):
        r = detect_injection("os.system(x)")
        match = [f for f in r if "os.system" in f["type"]][0]["match"]
        assert len(match) <= 23

    def test_redaction_long(self):
        r = detect_injection('os.system("rm -rf /very/long/path/that/exceeds/limit")')
        match = [f for f in r if "os.system" in f["type"]][0]["match"]
        assert match.endswith("...") or len(match) <= 23


# =========== check_headers unit tests ===========


_ALL_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
}


class TestCheckHeadersAllPresent:
    def test_score_100(self):
        r = check_headers(_ALL_HEADERS)
        assert r["score"] == 100

    def test_grade_a(self):
        r = check_headers(_ALL_HEADERS)
        assert r["grade"] == "A"

    def test_all_present_list(self):
        r = check_headers(_ALL_HEADERS)
        assert len(r["headers_present"]) == 6
        assert r["headers_missing"] == []

    def test_all_findings_present(self):
        r = check_headers(_ALL_HEADERS)
        assert all(f["present"] for f in r["findings"])

    def test_summary_all(self):
        r = check_headers(_ALL_HEADERS)
        assert "All 6" in r["summary"]


class TestCheckHeadersNonePresent:
    def test_score_0(self):
        r = check_headers({})
        assert r["score"] == 0

    def test_grade_f(self):
        r = check_headers({})
        assert r["grade"] == "F"

    def test_all_missing(self):
        r = check_headers({})
        assert len(r["headers_missing"]) == 6
        assert r["headers_present"] == []

    def test_summary_missing(self):
        r = check_headers({})
        assert "missing" in r["summary"]


class TestCheckHeadersPartial:
    def test_high_only_score_50(self):
        r = check_headers(
            {
                "Content-Security-Policy": "x",
                "Strict-Transport-Security": "x",
            }
        )
        assert r["score"] == 50
        assert r["grade"] == "C"

    def test_medium_only_score_30(self):
        r = check_headers(
            {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            }
        )
        assert r["score"] == 30
        assert r["grade"] == "D"

    def test_low_only_score_20(self):
        r = check_headers(
            {
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=()",
            }
        )
        assert r["score"] == 20
        assert r["grade"] == "F"

    def test_grade_b_boundary(self):
        r = check_headers(
            {
                "Content-Security-Policy": "x",
                "Strict-Transport-Security": "x",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            }
        )
        assert r["score"] == 80
        assert r["grade"] == "B"

    def test_grade_a_boundary(self):
        r = check_headers(
            {
                "Content-Security-Policy": "x",
                "Strict-Transport-Security": "x",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "x",
            }
        )
        assert r["score"] == 90
        assert r["grade"] == "A"


class TestCheckHeadersCaseInsensitive:
    def test_lowercase_keys(self):
        r = check_headers({"content-security-policy": "x", "strict-transport-security": "x"})
        assert "Content-Security-Policy" in r["headers_present"]
        assert "Strict-Transport-Security" in r["headers_present"]

    def test_uppercase_keys(self):
        r = check_headers({"CONTENT-SECURITY-POLICY": "x"})
        assert "Content-Security-Policy" in r["headers_present"]


class TestCheckHeadersFindingStructure:
    def test_finding_keys(self):
        r = check_headers({})
        f = r["findings"][0]
        assert set(f.keys()) == {
            "header",
            "severity",
            "present",
            "valid",
            "value",
            "issues",
            "description",
            "remediation",
            "reference",
        }

    def test_reference_is_owasp_url(self):
        r = check_headers({})
        for f in r["findings"]:
            assert f["reference"].startswith("https://owasp.org/")

    def test_six_findings_always(self):
        r = check_headers({})
        assert len(r["findings"]) == 6

    def test_irrelevant_headers_ignored(self):
        r = check_headers({"X-Powered-By": "Express", "Server": "nginx"})
        assert r["score"] == 0
        assert r["headers_present"] == []


class TestCheckHeadersValueValidation:
    def _finding(self, r, header):
        return next(f for f in r["findings"] if f["header"] == header)

    # XFO tests
    def test_xfo_deny_valid(self):
        r = check_headers({"X-Frame-Options": "DENY"})
        finding = self._finding(r, "X-Frame-Options")
        assert finding["valid"] is True
        assert finding["issues"] == []
        assert finding["value"] == "DENY"

    def test_xfo_sameorigin_valid(self):
        r = check_headers({"X-Frame-Options": "SAMEORIGIN"})
        finding = self._finding(r, "X-Frame-Options")
        assert finding["valid"] is True

    def test_xfo_lowercase_sameorigin_valid(self):
        r = check_headers({"X-Frame-Options": "sameorigin"})
        finding = self._finding(r, "X-Frame-Options")
        assert finding["valid"] is True

    def test_xfo_allow_invalid(self):
        r = check_headers({"X-Frame-Options": "ALLOW"})
        finding = self._finding(r, "X-Frame-Options")
        assert finding["valid"] is False
        assert any("Invalid value 'ALLOW'" in issue for issue in finding["issues"])

    def test_xfo_allow_from_invalid(self):
        r = check_headers({"X-Frame-Options": "ALLOW-FROM https://example.com"})
        finding = self._finding(r, "X-Frame-Options")
        assert finding["valid"] is False

    def test_xfo_empty_invalid(self):
        r = check_headers({"X-Frame-Options": ""})
        finding = self._finding(r, "X-Frame-Options")
        assert finding["valid"] is False

    # HSTS tests
    def test_hsts_full_valid(self):
        r = check_headers({"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"})
        finding = self._finding(r, "Strict-Transport-Security")
        assert finding["valid"] is True
        assert finding["issues"] == []

    def test_hsts_min_valid(self):
        r = check_headers({"Strict-Transport-Security": "max-age=15768000; includeSubDomains"})
        finding = self._finding(r, "Strict-Transport-Security")
        assert finding["valid"] is True
        assert any("Missing preload" in i for i in finding["issues"])

    def test_hsts_max_age_too_low_invalid(self):
        r = check_headers({"Strict-Transport-Security": "max-age=3600; includeSubDomains"})
        finding = self._finding(r, "Strict-Transport-Security")
        assert finding["valid"] is False
        assert any("15768000" in issue for issue in finding["issues"])

    def test_hsts_no_max_age_invalid(self):
        r = check_headers({"Strict-Transport-Security": "includeSubDomains"})
        finding = self._finding(r, "Strict-Transport-Security")
        assert finding["valid"] is False
        assert any("Missing max-age" in issue for issue in finding["issues"])

    def test_hsts_no_include_subdomains_invalid(self):
        r = check_headers({"Strict-Transport-Security": "max-age=31536000"})
        finding = self._finding(r, "Strict-Transport-Security")
        assert finding["valid"] is False
        assert any("includeSubDomains" in issue for issue in finding["issues"])

    def test_hsts_max_age_at_minimum_boundary(self):
        r = check_headers({"Strict-Transport-Security": "max-age=15768000; includeSubDomains"})
        finding = self._finding(r, "Strict-Transport-Security")
        assert finding["valid"] is True

    def test_hsts_notincludesubdomains_does_not_pass(self):
        r = check_headers({"Strict-Transport-Security": "max-age=31536000; notincludesubdomains"})
        finding = self._finding(r, "Strict-Transport-Security")
        assert finding["valid"] is False
        assert any("includeSubDomains" in i for i in finding["issues"])

    def test_hsts_nopreload_token_not_preload_token(self):
        r = check_headers({"Strict-Transport-Security": "max-age=31536000; includeSubDomains; nopreload"})
        finding = self._finding(r, "Strict-Transport-Security")
        assert any("Missing preload" in i for i in finding["issues"])
        assert finding["valid"] is True  # preload is advisory, not hard-fail

    def test_hsts_quoted_max_age_accepted(self):
        r = check_headers({"Strict-Transport-Security": 'max-age="31536000"; includeSubDomains'})
        finding = self._finding(r, "Strict-Transport-Security")
        assert finding["valid"] is True

    def test_hsts_mismatched_trailing_quote_rejected(self):
        r = check_headers({"Strict-Transport-Security": 'max-age=31536000"; includeSubDomains'})
        finding = self._finding(r, "Strict-Transport-Security")
        assert finding["valid"] is False
        assert any("Malformed max-age" in i or "Missing max-age" in i for i in finding["issues"])

    def test_hsts_mismatched_leading_quote_rejected(self):
        r = check_headers({"Strict-Transport-Security": 'max-age="31536000; includeSubDomains'})
        finding = self._finding(r, "Strict-Transport-Security")
        assert finding["valid"] is False

    def test_hsts_malformed_max_age_value(self):
        r = check_headers({"Strict-Transport-Security": "max-age=abc; includeSubDomains"})
        finding = self._finding(r, "Strict-Transport-Security")
        assert finding["valid"] is False
        assert any("Malformed max-age" in i for i in finding["issues"])

    # CSP tests
    def test_csp_strict_valid(self):
        r = check_headers({"Content-Security-Policy": "default-src 'self'; script-src 'self'"})
        finding = self._finding(r, "Content-Security-Policy")
        assert finding["valid"] is True
        assert finding["issues"] == []

    def test_csp_wildcard_default_invalid(self):
        r = check_headers({"Content-Security-Policy": "default-src *"})
        finding = self._finding(r, "Content-Security-Policy")
        assert finding["valid"] is False
        assert any("default-src" in i and "*" in i for i in finding["issues"])

    def test_csp_unsafe_inline_invalid(self):
        r = check_headers({"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"})
        finding = self._finding(r, "Content-Security-Policy")
        assert finding["valid"] is False
        assert any("unsafe-inline" in i for i in finding["issues"])

    def test_csp_unsafe_eval_invalid(self):
        r = check_headers({"Content-Security-Policy": "default-src 'self' 'unsafe-eval'"})
        finding = self._finding(r, "Content-Security-Policy")
        assert finding["valid"] is False
        assert any("unsafe-eval" in i for i in finding["issues"])

    def test_csp_multiple_permissive_flags(self):
        r = check_headers({"Content-Security-Policy": "default-src * 'unsafe-inline' 'unsafe-eval'"})
        finding = self._finding(r, "Content-Security-Policy")
        assert finding["valid"] is False
        assert len(finding["issues"]) == 3

    def test_csp_uppercase_unsafe_inline_still_detected(self):
        r = check_headers({"Content-Security-Policy": "default-src 'self' 'UNSAFE-INLINE'"})
        finding = self._finding(r, "Content-Security-Policy")
        assert finding["valid"] is False

    def test_csp_wildcard_non_adjacent_invalid(self):
        r = check_headers({"Content-Security-Policy": "default-src 'self' *"})
        finding = self._finding(r, "Content-Security-Policy")
        assert finding["valid"] is False
        assert any("default-src" in i and "*" in i for i in finding["issues"])

    def test_csp_script_src_wildcard_invalid(self):
        r = check_headers({"Content-Security-Policy": "default-src 'self'; script-src *"})
        finding = self._finding(r, "Content-Security-Policy")
        assert finding["valid"] is False
        assert any("script-src" in i for i in finding["issues"])

    def test_csp_unsafe_inline_in_report_uri_not_false_positive(self):
        r = check_headers(
            {"Content-Security-Policy": "default-src 'self'; report-uri https://example.com/log?tag=unsafe-inline"}
        )
        finding = self._finding(r, "Content-Security-Policy")
        assert finding["valid"] is True
        assert finding["issues"] == []


# =========== Route tests ===========


class TestSecretsRoute:
    def test_200_with_finding(self):
        r = client.post("/v1/check/secrets", json={"code": 'k = "AKIAIOSFODNN7EXAMPLE"', "language": "python"})
        assert r.status_code == 200
        d = r.json()
        assert d["total"] == 1
        assert "critical" in d["by_severity"]
        assert "summary" in d
        assert d["findings"][0]["type"] == "AWS Access Key"

    def test_200_clean_code(self):
        r = client.post("/v1/check/secrets", json={"code": "x = 1 + 2"})
        assert r.status_code == 200
        d = r.json()
        assert d["total"] == 0
        assert d["findings"] == []
        assert "No hardcoded secrets" in d["summary"]

    def test_400_oversized(self):
        r = client.post("/v1/check/secrets", json={"code": "x" * (500 * 1024 + 1)})
        assert r.status_code == 400

    def test_default_language(self):
        r = client.post("/v1/check/secrets", json={"code": "x = 1"})
        assert r.status_code == 200

    def test_response_shape(self):
        r = client.post("/v1/check/secrets", json={"code": "x = 1"})
        d = r.json()
        assert set(d.keys()) == {"findings", "total", "by_severity", "summary"}


class TestInjectionRoute:
    def test_200_sql_injection(self):
        r = client.post(
            "/v1/check/injection", json={"code": 'f"SELECT * FROM users WHERE id = {uid}"', "language": "python"}
        )
        assert r.status_code == 200
        assert r.json()["total"] >= 1

    def test_200_command_injection(self):
        r = client.post("/v1/check/injection", json={"code": "os.system(cmd)"})
        assert r.status_code == 200
        assert r.json()["total"] >= 1

    def test_200_clean_code(self):
        r = client.post("/v1/check/injection", json={"code": "x = db.query(User).filter_by(id=uid).first()"})
        assert r.status_code == 200
        assert r.json()["total"] == 0
        assert "No injection" in r.json()["summary"]

    def test_400_oversized(self):
        r = client.post("/v1/check/injection", json={"code": "x" * (500 * 1024 + 1)})
        assert r.status_code == 400

    def test_response_shape(self):
        r = client.post("/v1/check/injection", json={"code": "x = 1"})
        d = r.json()
        assert set(d.keys()) == {"findings", "total", "by_severity", "summary"}


class TestHeadersRoute:
    def test_200_all_headers(self):
        r = client.post("/v1/check/headers", json={"headers": _ALL_HEADERS})
        assert r.status_code == 200
        d = r.json()
        assert d["score"] == 100
        assert d["grade"] == "A"
        assert len(d["headers_present"]) == 6

    def test_200_no_headers(self):
        r = client.post("/v1/check/headers", json={"headers": {}})
        assert r.status_code == 200
        d = r.json()
        assert d["score"] == 0
        assert d["grade"] == "F"

    def test_response_shape(self):
        r = client.post("/v1/check/headers", json={"headers": {}})
        d = r.json()
        expected = {
            "findings",
            "total",
            "by_severity",
            "summary",
            "score",
            "grade",
            "headers_present",
            "headers_missing",
        }
        assert expected == set(d.keys())

    def test_400_too_many_headers(self):
        many = {f"X-Custom-{i}": "v" for i in range(51)}
        r = client.post("/v1/check/headers", json={"headers": many})
        assert r.status_code == 400


class TestDependenciesRoute:
    def test_200_single_package(self):
        r = client.post("/v1/check/dependencies", json={"packages": [{"name": "flask", "version": "2.0.0"}]})
        assert r.status_code == 200
        d = r.json()
        assert "findings" in d
        assert "total" in d
        assert "by_severity" in d
        assert "summary" in d

    def test_200_multiple_packages(self):
        r = client.post(
            "/v1/check/dependencies", json={"packages": [{"name": "flask"}, {"name": "django", "version": "3.2"}]}
        )
        assert r.status_code == 200
        assert r.json()["total"] >= 0

    def test_200_no_version(self):
        r = client.post("/v1/check/dependencies", json={"packages": [{"name": "somelib"}]})
        assert r.status_code == 200

    def test_response_shape(self):
        r = client.post("/v1/check/dependencies", json={"packages": [{"name": "x"}]})
        d = r.json()
        assert set(d.keys()) == {"findings", "total", "by_severity", "summary"}

    def test_over_free_limit_422(self):
        """Free tier: >10 packages → 422 before any DB work."""
        from unittest.mock import patch

        with (
            patch("ratelimit.consume_bulk", return_value=True) as mock_consume,
            patch(
                "codesec.routes.authenticate",
                return_value={"tier": "free", "key_hash": None, "client_ip": "127.0.0.1"},
            ),
        ):
            pkgs = [{"name": f"pkg{i}"} for i in range(11)]
            r = client.post("/v1/check/dependencies", json={"packages": pkgs})
            assert r.status_code == 422
            assert "Too many packages" in r.json().get("error", "")

    def test_over_pydantic_max_422(self):
        """>50 packages rejected by Pydantic before auth runs."""
        pkgs = [{"name": f"pkg{i}"} for i in range(51)]
        r = client.post("/v1/check/dependencies", json={"packages": pkgs})
        assert r.status_code == 422

    def test_consume_bulk_called_with_count_minus_one(self):
        """Verify per-package charging: N packages → consume_bulk(count - 1) after authenticate()'s 1."""
        from unittest.mock import patch

        with (
            patch("ratelimit.consume_bulk", return_value=True) as mock_consume,
            patch(
                "codesec.routes.authenticate",
                return_value={"tier": "free", "key_hash": None, "client_ip": "127.0.0.1"},
            ),
        ):
            pkgs = [{"name": f"pkg{i}"} for i in range(5)]
            r = client.post("/v1/check/dependencies", json={"packages": pkgs})
            assert r.status_code == 200
            mock_consume.assert_called_once()
            assert mock_consume.call_args.args[2] == 4  # count(5) - 1

    def test_bulk_rate_limit_exhausted(self):
        """When consume_bulk returns False → 429."""
        from unittest.mock import patch

        with (
            patch("ratelimit.consume_bulk", return_value=False),
            patch(
                "codesec.routes.authenticate",
                return_value={"tier": "free", "key_hash": None, "client_ip": "127.0.0.1"},
            ),
        ):
            pkgs = [{"name": f"pkg{i}"} for i in range(5)]
            r = client.post("/v1/check/dependencies", json={"packages": pkgs})
            assert r.status_code == 429

    def test_deduplicates_repeat_packages(self):
        """Duplicate (name, version) pairs are collapsed before charging — prevents 10x credit waste on same pkg."""
        from unittest.mock import patch

        with (
            patch("ratelimit.consume_bulk", return_value=True) as mock_consume,
            patch(
                "codesec.routes.authenticate",
                return_value={"tier": "free", "key_hash": None, "client_ip": "127.0.0.1"},
            ),
        ):
            pkgs = [{"name": "flask", "version": "2.0.0"}] * 5 + [{"name": "django"}]
            r = client.post("/v1/check/dependencies", json={"packages": pkgs})
            assert r.status_code == 200
            # 2 unique after dedup → consume_bulk called with 2 - 1 = 1
            mock_consume.assert_called_once()
            assert mock_consume.call_args.args[2] == 1

    def test_single_package_skips_consume_bulk(self):
        """count=1 → authenticate()'s 1 credit is enough, consume_bulk must NOT be called."""
        from unittest.mock import patch

        with (
            patch("ratelimit.consume_bulk") as mock_consume,
            patch(
                "codesec.routes.authenticate",
                return_value={"tier": "free", "key_hash": None, "client_ip": "127.0.0.1"},
            ),
        ):
            r = client.post("/v1/check/dependencies", json={"packages": [{"name": "flask"}]})
            assert r.status_code == 200
            mock_consume.assert_not_called()

    def test_dedup_normalizes_version_whitespace_and_case(self):
        """Versions differing only in whitespace/case are deduped — blocks charge-inflation via formatting."""
        from unittest.mock import patch

        with (
            patch("ratelimit.consume_bulk", return_value=True) as mock_consume,
            patch(
                "codesec.routes.authenticate",
                return_value={"tier": "free", "key_hash": None, "client_ip": "127.0.0.1"},
            ),
        ):
            pkgs = [
                {"name": "foo", "version": "1.0.0"},
                {"name": "foo", "version": "1.0.0 "},
                {"name": "foo", "version": "1.0.0"},
                {"name": "FOO", "version": "1.0.0"},
            ]
            r = client.post("/v1/check/dependencies", json={"packages": pkgs})
            assert r.status_code == 200
            # All 4 collapse to 1 → count=1 path, consume_bulk NOT called
            mock_consume.assert_not_called()

    def test_maven_artifactid_alias_finds_cves(self):
        """Regression: posting a Maven artifactId (log4j-core) must resolve to
        NVD canonical name (log4j) via PRODUCT_ALIAS and return the CVE.
        Caught a CRITICAL bug where the bulk function returned a dict keyed by
        normalized name but the caller looked up by original input."""
        from db import upsert_cve

        upsert_cve(
            {
                "cve_id": "CVE-2021-44228",
                "description": "Log4Shell RCE",
                "severity": "CRITICAL",
                "published": "2021-12-10T00:00:00Z",
                "affected_products": [
                    {"vendor": "apache", "product": "log4j", "version_start": "2.0.0", "version_end": "2.15.0"}
                ],
            }
        )

        r = client.post(
            "/v1/check/dependencies",
            json={"packages": [{"name": "log4j-core", "version": "2.14.1"}]},
        )
        assert r.status_code == 200
        findings = r.json()["findings"]
        assert any(f["cve_id"] == "CVE-2021-44228" for f in findings), (
            f"Maven artifactId 'log4j-core' should alias to 'log4j' and find CVE-2021-44228, got findings: {findings}"
        )


class TestOpenApiCodesec:
    def test_operation_ids_present(self):
        schema = client.get("/openapi.json").json()
        op_ids = set()
        for path_obj in schema["paths"].values():
            for method_obj in path_obj.values():
                if isinstance(method_obj, dict) and "operationId" in method_obj:
                    op_ids.add(method_obj["operationId"])
        for oid in ("check_secrets", "check_injection", "check_headers", "check_dependencies"):
            assert oid in op_ids, f"Missing operation_id: {oid}"

    def test_code_security_tag(self):
        schema = client.get("/openapi.json").json()
        tags = set()
        for path_obj in schema["paths"].values():
            for method_obj in path_obj.values():
                if isinstance(method_obj, dict):
                    for t in method_obj.get("tags", []):
                        tags.add(t)
        assert "Code Security" in tags


# =========== code size limit tests ===========


class TestCodeSizeLimit:
    def test_secrets_rejects_oversized_code(self):
        oversized = "a" * (500 * 1024 + 1)
        r = client.post("/v1/check/secrets", json={"code": oversized})
        assert r.status_code == 400
        assert "500KB" in r.json()["error"]

    def test_injection_rejects_oversized_code(self):
        oversized = "a" * (500 * 1024 + 1)
        r = client.post("/v1/check/injection", json={"code": oversized})
        assert r.status_code == 400
        assert "500KB" in r.json()["error"]

    def test_secrets_accepts_under_limit(self):
        code = "x = 1\n" * 100
        r = client.post("/v1/check/secrets", json={"code": code})
        assert r.status_code == 200


# =========== response_model filtering tests ===========


class TestResponseModelFiltering:
    """Verify response_model_exclude_none behavior on codesec endpoints."""

    def test_secrets_finding_exclude_none(self):
        """Finding with no match → match field absent from response."""
        code = "safe_code = 42"
        r = client.post("/v1/check/secrets", json={"code": code})
        assert r.status_code == 200
        data = r.json()
        for finding in data["findings"]:
            if finding.get("match") is None:
                assert "match" not in finding

    def test_injection_finding_exclude_none(self):
        """Finding with no match → match field absent from response."""
        code = "safe_code = 42"
        r = client.post("/v1/check/injection", json={"code": code})
        assert r.status_code == 200
        data = r.json()
        for finding in data["findings"]:
            if finding.get("match") is None:
                assert "match" not in finding

    def test_check_headers_exclude_none(self):
        """Headers response has no None values."""
        r = client.post("/v1/check/headers", json={"headers": {}})
        assert r.status_code == 200
        data = r.json()
        # All fields should be present (no Optional fields at top level)
        assert "findings" in data
        assert "score" in data
        assert "grade" in data

    def test_dependencies_exclude_none(self):
        """Dependency finding with version=None → version absent."""
        r = client.post(
            "/v1/check/dependencies",
            json={"packages": [{"name": "nonexistent-pkg-xyz"}]},
        )
        assert r.status_code == 200
        data = r.json()
        # No CVEs found for fake package, but response shape is correct
        assert "findings" in data
        assert "total" in data
        assert data["total"] == 0

    def test_dependencies_version_none_excluded(self):
        """When version is None in a finding, it should be absent."""
        r = client.post(
            "/v1/check/dependencies",
            json={"packages": [{"name": "nginx"}]},
        )
        assert r.status_code == 200
        data = r.json()
        for finding in data["findings"]:
            if finding.get("version") is None:
                assert "version" not in finding


# =========== ReDoS protection tests ===========


class TestSafeScanLine:
    """Unit tests for safe_scan_line timeout wrapper."""

    def test_normal_match_returns_results(self):
        """safe_scan_line returns matches for normal input."""
        rules = [("test_rule", re.compile(r"foo"), "high", "desc", "fix")]
        results = safe_scan_line(rules, "foo bar foo")
        assert len(results) == 2
        assert results[0][0] == "test_rule"
        assert results[0][2] == "foo"  # match text

    def test_no_match_returns_empty(self):
        """safe_scan_line returns empty list when no match."""
        rules = [("test_rule", re.compile(r"xyz"), "high", "desc", "fix")]
        assert safe_scan_line(rules, "hello world") == []

    def test_empty_string(self):
        """safe_scan_line handles empty string."""
        rules = [("test_rule", re.compile(r"foo"), "high", "desc", "fix")]
        assert safe_scan_line(rules, "") == []

    def test_multiple_rules_single_line(self):
        """All rules are checked against the same line in one batch."""
        rules = [
            ("rule_a", re.compile(r"foo"), "high", "desc_a", "fix_a"),
            ("rule_b", re.compile(r"bar"), "medium", "desc_b", "fix_b"),
        ]
        results = safe_scan_line(rules, "foo and bar")
        assert len(results) == 2
        names = {r[0] for r in results}
        assert names == {"rule_a", "rule_b"}

    def test_timeout_returns_empty(self):
        """safe_scan_line returns [] when scan exceeds timeout."""
        import concurrent.futures

        with patch("codesec.utils._regex_executor") as mock_exec:
            mock_future = mock_exec.submit.return_value
            mock_future.result.side_effect = concurrent.futures.TimeoutError()
            rules = [("test_rule", re.compile(r"foo"), "high", "desc", "fix")]
            result = safe_scan_line(rules, "foo bar")
            assert result == []
            mock_future.cancel.assert_called_once()

    def test_timeout_logs_warning(self):
        """Timeout triggers a warning log with line_len and rules count."""
        import concurrent.futures

        with (
            patch("codesec.utils._regex_executor") as mock_exec,
            patch("codesec.utils.logger") as mock_logger,
        ):
            mock_future = mock_exec.submit.return_value
            mock_future.result.side_effect = concurrent.futures.TimeoutError()
            rules = [("r1", re.compile(r"x"), "high", "d", "f")]
            safe_scan_line(rules, "x" * 500)
            mock_logger.warning.assert_called_once()
            log_msg = mock_logger.warning.call_args[0][0]
            assert "timeout" in log_msg.lower()

    def test_uses_configured_timeout(self):
        """Default timeout matches REGEX_TIMEOUT_SECONDS constant."""
        assert REGEX_TIMEOUT_SECONDS == 1.0

    def test_custom_timeout_passed(self):
        """Custom timeout is forwarded to future.result()."""
        with patch("codesec.utils._regex_executor") as mock_exec:
            mock_future = mock_exec.submit.return_value
            mock_future.result.return_value = []
            rules = [("r", re.compile(r"x"), "h", "d", "f")]
            safe_scan_line(rules, "x", timeout=5.0)
            mock_future.result.assert_called_once_with(timeout=5.0)

    def test_complex_injection_pattern(self):
        """Injection-style regex patterns work through safe_scan_line."""
        rules = [
            (
                "SQL f-string",
                re.compile(r"""f(['"])\s*SELECT\b[^'"]*\{""", re.IGNORECASE),
                "critical",
                "desc",
                "fix",
            )
        ]
        code = '''query = f"SELECT * FROM users WHERE id = {user_id}"'''
        results = safe_scan_line(rules, code)
        assert len(results) == 1
        assert results[0][0] == "SQL f-string"

    def test_result_tuple_structure(self):
        """Each result is (rule_name, severity, match_text, description, remediation)."""
        rules = [("my_rule", re.compile(r"abc"), "critical", "my_desc", "my_fix")]
        results = safe_scan_line(rules, "abc")
        assert len(results) == 1
        name, severity, match_text, desc, fix = results[0]
        assert name == "my_rule"
        assert severity == "critical"
        assert match_text == "abc"
        assert desc == "my_desc"
        assert fix == "my_fix"


class TestReDoSProtectionIntegration:
    """Integration tests — timeout protection in detect_injection/detect_secrets."""

    def test_injection_long_line_truncated(self):
        """Lines exceeding MAX_LINE_LENGTH are truncated before regex."""
        long_line = "eval(" + "x" * (MAX_LINE_LENGTH + 500) + ")"
        findings = detect_injection(long_line)
        assert any("eval" in f["type"].lower() for f in findings)

    def test_injection_truncation_hides_late_pattern(self):
        """Pattern placed after MAX_LINE_LENGTH is NOT detected."""
        padding = "x" * (MAX_LINE_LENGTH + 100)
        code = padding + 'eval("danger")'
        findings = detect_injection(code)
        assert not any("eval" in f["type"].lower() for f in findings)

    def test_injection_timeout_returns_partial(self):
        """If regex times out on one line, other lines still scanned."""
        code = 'os.system("rm -rf /")\nHANG_LINE\neval("code")'
        with patch("codesec.injection.safe_scan_line") as mock_ssl:

            def selective_timeout(rules, text):
                if "HANG" in text:
                    return []  # Simulate timeout — line skipped
                # Run real scan for other lines
                results = []
                for rule_name, pattern, severity, desc, fix in rules:
                    for m in pattern.finditer(text):
                        results.append((rule_name, severity, m.group(), desc, fix))
                return results

            mock_ssl.side_effect = selective_timeout
            findings = detect_injection(code)
            types = [f["type"] for f in findings]
            assert any("os.system" in t for t in types)
            assert any("eval" in t for t in types)

    def test_secrets_timeout_graceful(self):
        """detect_secrets returns partial results on timeout."""
        code = 'key = "AKIAIOSFODNN7EXAMPLE"\nHANG\nsk_live_abcdefghijklmnopqrstuvwx'
        with patch("codesec.secrets.safe_scan_line") as mock_ssl:

            def selective_timeout(rules, text):
                if "HANG" in text:
                    return []
                results = []
                for rule_name, pattern, severity, desc, fix in rules:
                    for m in pattern.finditer(text):
                        results.append((rule_name, severity, m.group(), desc, fix))
                return results

            mock_ssl.side_effect = selective_timeout
            findings = detect_secrets(code)
            assert any("AWS" in f["type"] for f in findings)

    def test_max_line_length_constant(self):
        """MAX_LINE_LENGTH is reasonable for regex performance."""
        assert MAX_LINE_LENGTH <= 2000
        assert MAX_LINE_LENGTH >= 500

    def test_max_lines_constant(self):
        """MAX_LINES prevents CPU exhaustion on many-line payloads."""
        assert MAX_LINES == 10_000

    def test_injection_respects_max_lines(self):
        """Lines beyond MAX_LINES are not scanned."""
        # Put eval() on line MAX_LINES+1 — should not be detected
        safe_lines = ["x = 1\n"] * MAX_LINES
        code = "".join(safe_lines) + 'eval("danger")'
        findings = detect_injection(code)
        assert not any("eval" in f["type"].lower() for f in findings)

    def test_secrets_respects_max_lines(self):
        """Lines beyond MAX_LINES are not scanned."""
        safe_lines = ["x = 1\n"] * MAX_LINES
        code = "".join(safe_lines) + 'key = "AKIAIOSFODNN7EXAMPLE"'
        findings = detect_secrets(code)
        assert len(findings) == 0

    def test_injection_route_long_input(self):
        """API endpoint handles long lines without hanging."""
        long_code = "\n".join(['x = "' + "a" * 3000 + '"'] * 10)
        r = client.post("/v1/check/injection", json={"code": long_code})
        assert r.status_code == 200

    def test_secrets_route_long_input(self):
        """Secrets endpoint handles long lines without hanging."""
        long_code = "\n".join(['password = "' + "a" * 3000 + '"'] * 10)
        r = client.post("/v1/check/secrets", json={"code": long_code})
        assert r.status_code == 200

    def test_real_redos_pattern_does_not_hang(self):
        """safe_scan_line returns [] on timeout instead of hanging.

        Mocks the executor to simulate a slow regex that exceeds the timeout.
        """
        import concurrent.futures

        evil_pattern = re.compile(r"(a+)+$")
        rules = [("evil", evil_pattern, "critical", "desc", "fix")]
        evil_input = "a" * 25 + "!"

        # Simulate a future that times out
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()

        with patch("codesec.utils._regex_executor") as mock_exec:
            mock_exec.submit.return_value = mock_future
            results = safe_scan_line(rules, evil_input, timeout=0.1)

        assert results == []
        mock_future.cancel.assert_called_once()

    def test_max_findings_constant(self):
        """MAX_FINDINGS caps memory usage."""
        assert MAX_FINDINGS == 1_000

    def test_injection_respects_max_findings(self):
        """detect_injection stops after MAX_FINDINGS."""
        # Each line triggers eval() detection — generate more lines than MAX_FINDINGS
        code = "\n".join(['eval("x")'] * (MAX_FINDINGS + 500))
        findings = detect_injection(code)
        assert len(findings) <= MAX_FINDINGS

    def test_secrets_respects_max_findings(self):
        """detect_secrets stops after MAX_FINDINGS."""
        code = "\n".join(['key = "AKIAIOSFODNN7EXAMPLE"'] * (MAX_FINDINGS + 500))
        findings = detect_secrets(code)
        assert len(findings) <= MAX_FINDINGS


class TestScanConcurrency:
    """Tests for concurrent scan limiting."""

    @patch("codesec.routes.SEMAPHORE_TIMEOUT", 0.1)
    def test_semaphore_503_on_exhaustion(self):
        """When semaphore is exhausted, returns 503."""
        from codesec.routes import _scan_semaphore

        # Drain all permits
        acquired = []
        for _ in range(4):
            acquired.append(_scan_semaphore.acquire(timeout=0))

        try:
            r = client.post("/v1/check/injection", json={"code": 'eval("x")'})
            assert r.status_code == 503
            body = r.json()
            msg = body.get("detail", body.get("error", "")).lower()
            assert "concurrent" in msg
        finally:
            for _ in acquired:
                _scan_semaphore.release()

    def test_semaphore_released_on_success(self):
        """Semaphore is released after successful scan."""
        from codesec.routes import _scan_semaphore

        before = _scan_semaphore._value
        r = client.post("/v1/check/injection", json={"code": "safe_code = 1"})
        assert r.status_code == 200
        after = _scan_semaphore._value
        assert before == after

    @patch("codesec.routes.SEMAPHORE_TIMEOUT", 0.1)
    def test_secrets_semaphore_503(self):
        """Secrets endpoint also respects concurrency limit."""
        from codesec.routes import _scan_semaphore

        acquired = []
        for _ in range(4):
            acquired.append(_scan_semaphore.acquire(timeout=0))

        try:
            r = client.post("/v1/check/secrets", json={"code": "x = 1"})
            assert r.status_code == 503
        finally:
            for _ in acquired:
                _scan_semaphore.release()
