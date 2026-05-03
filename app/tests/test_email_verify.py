"""Tests for /v1/email/verify/{email} + helpers in domain/email_verify.py."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


# === parse_email ===


class TestParseEmail:
    def test_basic_valid(self):
        from domain.email_verify import parse_email

        assert parse_email("user@example.com") == ("user", "example.com")

    def test_lowercased(self):
        from domain.email_verify import parse_email

        assert parse_email("Admin@Example.COM") == ("admin", "example.com")

    def test_plus_tag_preserved_in_local(self):
        from domain.email_verify import parse_email

        # Plus-tags ARE part of the local-part, so parse_email keeps them.
        # role_classification is what strips them for role lookup.
        assert parse_email("user+ci@example.com") == ("user+ci", "example.com")

    def test_dotted_local(self):
        from domain.email_verify import parse_email

        assert parse_email("a.b.c@example.com") == ("a.b.c", "example.com")

    def test_no_at_rejected(self):
        from domain.email_verify import parse_email

        assert parse_email("not-an-email") is None

    def test_empty_local_rejected(self):
        from domain.email_verify import parse_email

        assert parse_email("@example.com") is None

    def test_empty_domain_rejected(self):
        from domain.email_verify import parse_email

        assert parse_email("user@") is None

    def test_no_tld_rejected(self):
        from domain.email_verify import parse_email

        assert parse_email("user@localhost") is None

    def test_oversize_rejected(self):
        from domain.email_verify import parse_email

        assert parse_email("a" * 300 + "@example.com") is None

    def test_oversize_local_part_rejected(self):
        from domain.email_verify import parse_email

        # 65-char local-part > RFC 5321 §4.5.3.1.1's 64-octet cap
        assert parse_email("a" * 65 + "@example.com") is None

    def test_control_chars_rejected(self):
        from domain.email_verify import parse_email

        assert parse_email("user\x00@example.com") is None
        assert parse_email("user@example.com\x7f") is None


# === role_classification ===


class TestRoleClassification:
    def test_admin(self):
        from domain.email_verify import role_classification

        assert role_classification("admin") == (True, "admin")

    def test_noreply_dashed(self):
        from domain.email_verify import role_classification

        assert role_classification("no-reply") == (True, "no-reply")

    def test_plus_tag_stripped(self):
        from domain.email_verify import role_classification

        assert role_classification("noreply+ci") == (True, "noreply")

    def test_personal_name_not_role(self):
        from domain.email_verify import role_classification

        assert role_classification("john") == (False, None)
        assert role_classification("john.doe") == (False, None)

    def test_case_insensitive(self):
        from domain.email_verify import role_classification

        assert role_classification("ADMIN") == (True, "admin")
        assert role_classification("Support") == (True, "support")


class TestIsFreeProvider:
    def test_gmail(self):
        from domain.email_verify import is_free_provider

        assert is_free_provider("gmail.com") is True

    def test_outlook(self):
        from domain.email_verify import is_free_provider

        assert is_free_provider("outlook.com") is True

    def test_corporate_not_free(self):
        from domain.email_verify import is_free_provider

        assert is_free_provider("microsoft.com") is False
        assert is_free_provider("contrastcyber.com") is False

    def test_case_insensitive(self):
        from domain.email_verify import is_free_provider

        assert is_free_provider("Gmail.COM") is True


# === Route /v1/email/verify/{email} ===


class TestEmailVerifyRoute:
    @patch("domain.routes.check_disposable", return_value={"disposable": False, "provider": None})
    @patch("domain.routes.dns_lookup", return_value={"mx": [{"priority": 10, "host": "aspmx.l.google.com."}]})
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_verify_corporate_email_200(self, mock_validate, mock_save, mock_cache, mock_dns, mock_disp):
        r = client.get("/v1/email/verify/jane.doe@corp.com")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["email"] == "jane.doe@corp.com"
        assert data["domain"] == "corp.com"
        assert data["syntax_valid"] is True
        assert data["disposable"] is False
        assert data["role_address"] is False
        assert data["free_provider"] is False
        assert len(data["mx_records"]) == 1

    @patch("domain.routes.check_disposable", return_value={"disposable": False, "provider": None})
    @patch("domain.routes.dns_lookup", return_value={"mx": [{"priority": 1, "host": "smtp.gmail.com."}]})
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="142.250.80.5")
    def test_verify_free_provider_flagged(self, mock_validate, mock_save, mock_cache, mock_dns, mock_disp):
        r = client.get("/v1/email/verify/user@gmail.com")
        assert r.status_code == 200
        data = r.json()
        assert data["free_provider"] is True

    @patch("domain.routes.check_disposable", return_value={"disposable": False, "provider": None})
    @patch("domain.routes.dns_lookup", return_value={"mx": [{"priority": 10, "host": "mx.example.com."}]})
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_verify_role_address_flagged(self, mock_validate, mock_save, mock_cache, mock_dns, mock_disp):
        r = client.get("/v1/email/verify/admin+ci@corp.com")
        assert r.status_code == 200
        data = r.json()
        assert data["role_address"] is True
        assert data["role_type"] == "admin"

    @patch("domain.routes.check_disposable", return_value={"disposable": True, "provider": "Mailinator"})
    @patch("domain.routes.dns_lookup", return_value={"mx": [{"priority": 10, "host": "mx.mailinator.com."}]})
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="1.2.3.4")
    def test_verify_disposable_flagged(self, mock_validate, mock_save, mock_cache, mock_dns, mock_disp):
        r = client.get("/v1/email/verify/throwaway@mailinator.com")
        assert r.status_code == 200
        data = r.json()
        assert data["disposable"] is True
        assert data["disposable_provider"] == "Mailinator"
        assert "disposable" in data["summary"]

    def test_verify_invalid_syntax_returns_falsy_response(self):
        # Garbage input still returns 200 (we did parsing work) with syntax_valid=false
        r = client.get("/v1/email/verify/not-an-email")
        assert r.status_code == 200
        data = r.json()
        assert data["syntax_valid"] is False
        assert data["mx_records"] == []
        assert data["disposable"] is False

    @patch("domain.routes.validate_domain", return_value=None)
    def test_verify_unresolvable_domain_returns_no_mx(self, mock_validate):
        r = client.get("/v1/email/verify/user@nonexistent.invalid")
        assert r.status_code == 200
        data = r.json()
        assert data["syntax_valid"] is True
        assert data["mx_records"] == []
        assert "does not resolve" in data["summary"]

    @patch("domain.routes.dns_lookup")
    @patch("domain.routes.check_disposable")
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_verify_cache_hit_recomputes_role_per_email(self, mock_validate, mock_save, mock_disp, mock_dns):
        """Cache stores domain-level facets only; per-email facets (role, syntax)
        must be recomputed from the live local-part on cache hit."""
        cached_payload = {
            "domain": "corp.com",
            "mx_records": [{"priority": 10, "host": "mx.corp.com."}],
            "disposable": False,
            "disposable_provider": None,
            "free_provider": False,
        }
        with patch("domain.routes.get_cached_domain", return_value=cached_payload):
            r1 = client.get("/v1/email/verify/admin@corp.com")
            r2 = client.get("/v1/email/verify/jane.doe@corp.com")
        assert r1.status_code == 200
        assert r2.status_code == 200
        d1, d2 = r1.json(), r2.json()
        # Both share the cached domain-level data
        assert d1["mx_records"] == d2["mx_records"] == [{"priority": 10, "host": "mx.corp.com."}]
        assert d1["disposable"] is False
        # But role classification is different per email
        assert d1["role_address"] is True
        assert d1["role_type"] == "admin"
        assert d2["role_address"] is False
        # role_type=None is excluded by response_model_exclude_none=True
        assert "role_type" not in d2 or d2["role_type"] is None
        # Cache hit short-circuits — the upstream resolvers should NOT be called
        mock_validate.assert_not_called()
        mock_dns.assert_not_called()
        mock_disp.assert_not_called()
        # And the cache write path is NOT re-triggered for our email_verify key
        keys_written = [c.args[0] for c in mock_save.call_args_list]
        assert "email_verify:corp.com" not in keys_written

    def test_verify_no_smtp_probe_documented_in_response_model(self):
        """EmailVerifyResponse docstring must explicitly state we do not probe SMTP."""
        from domain.schemas import EmailVerifyResponse

        assert "RCPT TO" in EmailVerifyResponse.__doc__
        assert "do not" in EmailVerifyResponse.__doc__.lower() or "do NOT" in EmailVerifyResponse.__doc__


def test_email_verify_mcp_tool_registered(mcp_client):
    pytest.importorskip("mcp")
    r = mcp_client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream", "Content-Type": "application/json"},
    )
    assert r.status_code == 200
    assert "email_verify" in r.text
