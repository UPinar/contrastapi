"""Tests for Code Security module — secrets, injection, headers, and routes."""

import pytest

from fastapi.testclient import TestClient
from main import app

from codesec.secrets import detect_secrets
from codesec.injection import detect_injection
from codesec.headers import check_headers

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
        r = check_headers({
            "Content-Security-Policy": "x",
            "Strict-Transport-Security": "x",
        })
        assert r["score"] == 50
        assert r["grade"] == "C"

    def test_medium_only_score_30(self):
        r = check_headers({
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        })
        assert r["score"] == 30
        assert r["grade"] == "D"

    def test_low_only_score_20(self):
        r = check_headers({
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
        })
        assert r["score"] == 20
        assert r["grade"] == "F"

    def test_grade_b_boundary(self):
        r = check_headers({
            "Content-Security-Policy": "x",
            "Strict-Transport-Security": "x",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        })
        assert r["score"] == 80
        assert r["grade"] == "B"

    def test_grade_a_boundary(self):
        r = check_headers({
            "Content-Security-Policy": "x",
            "Strict-Transport-Security": "x",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "x",
        })
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
        assert set(f.keys()) == {"header", "severity", "present", "description", "remediation", "reference"}

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
        r = client.post("/v1/check/injection", json={"code": 'f"SELECT * FROM users WHERE id = {uid}"', "language": "python"})
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
        expected = {"findings", "total", "by_severity", "summary", "score", "grade", "headers_present", "headers_missing"}
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
        r = client.post("/v1/check/dependencies", json={"packages": [{"name": "flask"}, {"name": "django", "version": "3.2"}]})
        assert r.status_code == 200
        assert r.json()["total"] >= 0

    def test_200_no_version(self):
        r = client.post("/v1/check/dependencies", json={"packages": [{"name": "somelib"}]})
        assert r.status_code == 200

    def test_response_shape(self):
        r = client.post("/v1/check/dependencies", json={"packages": [{"name": "x"}]})
        d = r.json()
        assert set(d.keys()) == {"findings", "total", "by_severity", "summary"}


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
