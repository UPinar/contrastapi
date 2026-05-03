"""Tests for email MX, disposable email, and phone lookup endpoints."""

from unittest.mock import AsyncMock, patch

from auth import AuthCtx
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

# Faz 3: routes use Annotated[AuthCtx, Depends(require_auth(...))] — patches
# must hit auth.authenticate_sync (the sync core) not the route-local symbol.
_AUTH_FREE = AuthCtx(
    tier="free",
    key_hash=None,
    client_ip="127.0.0.1",
    ratelimit_limit=100,
    ratelimit_remaining=99,
    ratelimit_reset=0,
    ratelimit_cost=1,
)

# =========== detect_mail_provider unit tests ===========


class TestDetectMailProvider:
    def test_google_workspace(self):
        from domain.recon import detect_mail_provider

        mx = [{"priority": 10, "host": "alt1.aspmx.l.google.com"}, {"priority": 1, "host": "aspmx.l.google.com"}]
        assert detect_mail_provider(mx) == "Google Workspace"

    def test_microsoft_365(self):
        from domain.recon import detect_mail_provider

        mx = [{"priority": 10, "host": "example-com.mail.protection.outlook.com"}]
        assert detect_mail_provider(mx) == "Microsoft 365"

    def test_protonmail(self):
        from domain.recon import detect_mail_provider

        mx = [{"priority": 10, "host": "mail.protonmail.ch"}]
        assert detect_mail_provider(mx) == "ProtonMail"

    def test_unknown_provider(self):
        from domain.recon import detect_mail_provider

        mx = [{"priority": 10, "host": "mail.custom-server.example.org"}]
        assert detect_mail_provider(mx) is None

    def test_empty_mx(self):
        from domain.recon import detect_mail_provider

        assert detect_mail_provider([]) is None

    def test_none_mx(self):
        from domain.recon import detect_mail_provider

        assert detect_mail_provider(None) is None

    def test_priority_ordering(self):
        from domain.recon import detect_mail_provider

        mx = [
            {"priority": 20, "host": "alt.aspmx.l.google.com"},
            {"priority": 5, "host": "mx.zoho.com"},
        ]
        assert detect_mail_provider(mx) == "Zoho Mail"

    def test_trailing_dot(self):
        from domain.recon import detect_mail_provider

        mx = [{"priority": 10, "host": "aspmx.l.google.com."}]
        assert detect_mail_provider(mx) == "Google Workspace"


# =========== /v1/email/mx route tests ===========


MOCK_MX_DNS = {
    "a": ["93.184.216.34"],
    "mx": [{"priority": 1, "host": "aspmx.l.google.com"}, {"priority": 5, "host": "alt1.aspmx.l.google.com"}],
    "txt": ["v=spf1 include:_spf.google.com ~all"],
}

MOCK_EMAIL_SECURITY = {
    "spf": "v=spf1 include:_spf.google.com ~all",
    "dmarc": "v=DMARC1; p=reject",
    "dkim_selectors": ["google"],
    "grade": "A",
    "issues": [],
}


class TestEmailMxRoute:
    @patch("domain.routes.email_security", return_value=MOCK_EMAIL_SECURITY)
    @patch("domain.routes.dns_lookup", return_value=MOCK_MX_DNS)
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_email_mx_200(self, mock_validate, mock_save, mock_cache, mock_dns, mock_email):
        r = client.get("/v1/email/mx/example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "example.com"
        assert data["mail_provider"] == "Google Workspace"
        assert len(data["mx_records"]) == 2
        assert data["email_security"]["grade"] == "A"
        assert "Google Workspace" in data["summary"]

    @patch(
        "domain.routes.email_security",
        return_value={"spf": None, "dmarc": None, "dkim_selectors": [], "grade": "F", "issues": ["No SPF"]},
    )
    @patch("domain.routes.dns_lookup", return_value={"a": ["1.2.3.4"]})
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="1.2.3.4")
    def test_email_mx_no_mx_records(self, mock_validate, mock_save, mock_cache, mock_dns, mock_email):
        r = client.get("/v1/email/mx/nomx.example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["mx_records"] == []
        assert data.get("mail_provider") is None
        assert "no MX records" in data["summary"]

    @patch("domain.routes.get_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_email_mx_cached(self, mock_validate, mock_cache):
        mock_cache.return_value = {
            "domain": "example.com",
            "mx_records": [{"priority": 1, "host": "aspmx.l.google.com"}],
            "mail_provider": "Google Workspace",
            "email_security": MOCK_EMAIL_SECURITY,
            "summary": "example.com — uses Google Workspace",
        }
        r = client.get("/v1/email/mx/example.com")
        assert r.status_code == 200

    def test_email_mx_invalid_domain(self):
        r = client.get("/v1/email/mx/not_a_domain")
        assert r.status_code == 400

    @patch("domain.routes.validate_domain", return_value=None)
    def test_email_mx_unresolvable(self, mock_validate):
        r = client.get("/v1/email/mx/nonexistent.invalid")
        assert r.status_code == 422

    @patch("domain.routes.email_security", return_value=MOCK_EMAIL_SECURITY)
    @patch("domain.routes.dns_lookup", return_value=MOCK_MX_DNS)
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_email_mx_response_shape(self, mock_validate, mock_save, mock_cache, mock_dns, mock_email):
        r = client.get("/v1/email/mx/example.com")
        assert r.status_code == 200
        assert set(r.json().keys()) == {"domain", "mx_records", "mail_provider", "email_security", "summary"}

    @patch("domain.routes.RECON_TIMEOUT", 0.1)
    @patch("domain.routes.email_security", side_effect=lambda *a, **kw: __import__("time").sleep(0.5))
    @patch("domain.routes.dns_lookup", return_value=MOCK_MX_DNS)
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="93.184.216.34")
    def test_email_mx_timeout_fallback(self, mock_validate, mock_save, mock_cache, mock_dns, mock_email):
        r = client.get("/v1/email/mx/slow.example.com")
        assert r.status_code == 200
        data = r.json()
        assert data["email_security"]["grade"] == "F"
        assert "timed out" in data["email_security"]["issues"][0]


# =========== check_disposable unit tests ===========


MOCK_DISPOSABLE_RESULT = {
    "email": "test@tempmail.com",
    "domain": "tempmail.com",
    "disposable": True,
    "provider": "TempMail",
    "mx_disposable": False,
    "risk_level": "high",
    "mx_records": [],
}

MOCK_CLEAN_RESULT = {
    "email": "user@google.com",
    "domain": "google.com",
    "disposable": False,
    "provider": None,
    "mx_disposable": False,
    "risk_level": "low",
    "mx_records": [{"priority": 10, "host": "smtp.google.com"}],
}

MOCK_MX_ONLY_RESULT = {
    "email": "user@sneakydomain.com",
    "domain": "sneakydomain.com",
    "disposable": True,
    "provider": None,
    "mx_disposable": True,
    "risk_level": "medium",
    "mx_records": [{"priority": 10, "host": "mx.guerrillamail.com"}],
}


class TestCheckDisposableUnit:
    @patch("domain.recon.dns_lookup", return_value={"mx": []})
    def test_check_disposable_known_domain(self, mock_dns):
        from domain.recon import check_disposable

        result = check_disposable("test@guerrillamail.com")
        assert result["disposable"] is True
        assert result["provider"] == "Guerrilla Mail"
        assert result["risk_level"] == "high"

    @patch("domain.recon.dns_lookup", return_value={"mx": [{"priority": 10, "host": "smtp.google.com"}]})
    def test_check_disposable_clean_domain(self, mock_dns):
        from domain.recon import check_disposable

        result = check_disposable("user@google.com")
        assert result["disposable"] is False
        assert result["risk_level"] == "low"

    @patch("domain.recon.dns_lookup", return_value={"mx": [{"priority": 10, "host": "mx1.guerrillamail.com"}]})
    def test_check_disposable_mx_match(self, mock_dns):
        from domain.recon import check_disposable

        result = check_disposable("user@somecustomdomain.xyz")
        assert result["mx_disposable"] is True
        assert result["disposable"] is True
        assert result["risk_level"] == "medium"

    @patch("domain.recon.dns_lookup", return_value={"mx": []})
    def test_check_disposable_tempmail_com(self, mock_dns):
        """Regression: tempmail.com used to return disposable=False because the domain
        was missing from DISPOSABLE_DOMAINS even though it was in DISPOSABLE_PROVIDERS."""
        from domain.recon import check_disposable

        result = check_disposable("test@tempmail.com")
        assert result["disposable"] is True
        assert result["provider"] == "TempMail"
        assert result["risk_level"] == "high"


class TestDisposableListSyncInvariant:
    """Guard against drift between DISPOSABLE_PROVIDERS and DISPOSABLE_DOMAINS.

    Every domain in DISPOSABLE_PROVIDERS must also be in DISPOSABLE_DOMAINS, otherwise
    check_disposable() short-circuits on the membership test and never reaches the
    provider lookup — the original cause of the tempmail.com false negative.
    """

    def test_every_provider_domain_is_in_domains_set(self):
        from domain.disposable_domains import DISPOSABLE_DOMAINS, DISPOSABLE_PROVIDERS

        missing = sorted(d for d in DISPOSABLE_PROVIDERS if d not in DISPOSABLE_DOMAINS)
        assert not missing, (
            "DISPOSABLE_PROVIDERS keys missing from DISPOSABLE_DOMAINS — "
            "check_disposable() will return disposable=False for these: "
            f"{missing}"
        )

    def test_domains_is_superset_of_providers(self):
        from domain.disposable_domains import DISPOSABLE_DOMAINS, DISPOSABLE_PROVIDERS

        assert len(DISPOSABLE_DOMAINS) >= len(DISPOSABLE_PROVIDERS)


# =========== /v1/email/disposable route tests ===========


class TestDisposableRoute:
    @patch("domain.routes.check_disposable", return_value=MOCK_DISPOSABLE_RESULT)
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="1.2.3.4")
    def test_disposable_known(self, mock_validate, mock_save, mock_cache, mock_check):
        r = client.get("/v1/email/disposable/test@tempmail.com")
        assert r.status_code == 200
        data = r.json()
        assert data["disposable"] is True
        assert data["provider"] == "TempMail"
        assert data["risk_level"] == "high"
        assert "disposable" in data["summary"]

    @patch("domain.routes.check_disposable", return_value=MOCK_CLEAN_RESULT)
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="1.2.3.4")
    def test_not_disposable(self, mock_validate, mock_save, mock_cache, mock_check):
        r = client.get("/v1/email/disposable/user@google.com")
        assert r.status_code == 200
        data = r.json()
        assert data["disposable"] is False
        assert data["risk_level"] == "low"
        assert "not disposable" in data["summary"]

    @patch("domain.routes.check_disposable", return_value=MOCK_MX_ONLY_RESULT)
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="1.2.3.4")
    def test_mx_only_disposable(self, mock_validate, mock_save, mock_cache, mock_check):
        r = client.get("/v1/email/disposable/user@sneakydomain.com")
        assert r.status_code == 200
        data = r.json()
        assert data["mx_disposable"] is True
        assert data["risk_level"] == "medium"

    def test_invalid_email_no_at(self):
        r = client.get("/v1/email/disposable/notanemail")
        assert r.status_code == 400

    @patch("domain.routes.get_cached_domain")
    def test_cached(self, mock_cache):
        mock_cache.return_value = {
            "email": "test@tempmail.com",
            "domain": "tempmail.com",
            "disposable": True,
            "provider": "TempMail",
            "mx_disposable": False,
            "risk_level": "high",
            "mx_records": [],
            "summary": "test@tempmail.com — disposable (TempMail), risk: high",
        }
        r = client.get("/v1/email/disposable/test@tempmail.com")
        assert r.status_code == 200

    @patch("domain.routes.check_disposable", return_value=MOCK_DISPOSABLE_RESULT)
    @patch("domain.routes.get_cached_domain", return_value=None)
    @patch("domain.routes.save_cached_domain")
    @patch("domain.routes.validate_domain", return_value="1.2.3.4")
    def test_response_shape(self, mock_validate, mock_save, mock_cache, mock_check):
        r = client.get("/v1/email/disposable/test@tempmail.com")
        assert r.status_code == 200
        data = r.json()
        # provider included when not None; excluded when None (exclude_none=True)
        required_keys = {
            "email",
            "domain",
            "disposable",
            "mx_disposable",
            "risk_level",
            "mx_records",
            "summary",
        }
        assert required_keys.issubset(set(data.keys()))

    @patch("domain.routes.validate_domain", return_value=None)
    def test_unresolvable_domain(self, mock_validate):
        r = client.get("/v1/email/disposable/user@nonexistent.invalid")
        assert r.status_code == 422

    def test_empty_local_part(self):
        r = client.get("/v1/email/disposable/@tempmail.com")
        assert r.status_code == 400
        assert "local-part" in r.json()["error"]["message"]

    def test_multiple_at_signs(self):
        """Multiple @ — rsplit takes last part as domain."""
        r = client.get("/v1/email/disposable/user@foo@bar.com")
        # Should not crash; rsplit("@", 1) extracts "bar.com"
        assert r.status_code in (200, 400, 422)

    def test_long_local_part_rejected(self):
        long_local = "a" * 255
        r = client.get(f"/v1/email/disposable/{long_local}@example.com")
        assert r.status_code == 400
        assert "local-part" in r.json()["error"]["message"]

    @patch("domain.routes.get_cached_domain")
    def test_cached_returns_correct_email(self, mock_cache):
        """M1 fix: cached response must return the requested email, not the original."""
        mock_cache.return_value = {
            "email": "alice@tempmail.com",
            "domain": "tempmail.com",
            "disposable": True,
            "provider": "TempMail",
            "mx_disposable": False,
            "risk_level": "high",
            "mx_records": [],
            "summary": "cached",
        }
        r = client.get("/v1/email/disposable/bob@tempmail.com")
        assert r.status_code == 200
        data = r.json()
        assert data["email"] == "bob@tempmail.com"
        assert "bob@tempmail.com" in data["summary"]
        assert "alice@tempmail.com" not in data["summary"]

    def test_control_chars_rejected(self):
        r = client.get("/v1/email/disposable/user%00name@example.com")
        assert r.status_code == 400

    def test_crlf_rejected(self):
        r = client.get("/v1/email/disposable/user%0D%0Aname@example.com")
        assert r.status_code == 400


class TestCheckDisposableEdgeCases:
    def test_no_at_returns_safe_default(self):
        from domain.recon import check_disposable

        result = check_disposable("notanemail")
        assert result["disposable"] is False
        assert result["domain"] == ""

    @patch("domain.recon.dns_lookup", return_value={"mx": []})
    def test_domain_param_overrides_extraction(self, mock_dns):
        from domain.recon import check_disposable

        result = check_disposable("user@whatever.com", domain="guerrillamail.com")
        assert result["disposable"] is True
        assert result["domain"] == "guerrillamail.com"


# =========== phone_lookup unit tests ===========


class TestPhoneLookup:
    def test_valid_tr_number(self):
        from domain.recon import phone_lookup

        result = phone_lookup("+905321234567")
        assert result["valid"] is True
        assert result["country_code"] == "TR"
        assert result["country_name"] == "Turkey"
        assert result["type"] in ("mobile", "fixed_line_or_mobile")
        assert result["format"]["e164"] == "+905321234567"
        assert result["format"]["international"].startswith("+90")
        assert result["format"]["national"] != ""
        assert isinstance(result["timezone"], list)
        assert len(result["timezone"]) > 0

    def test_valid_us_number(self):
        from domain.recon import phone_lookup

        result = phone_lookup("+12025551234")
        assert result["valid"] is True
        assert result["country_code"] == "US"
        assert result["country_name"] != ""
        assert result["format"]["e164"] == "+12025551234"

    def test_us_country_name_is_country_not_city(self):
        from domain.recon import phone_lookup

        result = phone_lookup("+14155552671")
        assert result["valid"] is True
        assert result["country_code"] == "US"
        assert result["country_name"] == "United States"

    def test_invalid_number(self):
        from domain.recon import phone_lookup

        result = phone_lookup("+999999999999999")
        assert result["valid"] is False
        assert "error" in result

    def test_missing_plus_prefix(self):
        from domain.recon import phone_lookup

        result = phone_lookup("905321234567")
        assert result["valid"] is True
        assert result["country_code"] == "TR"

    def test_garbage_input(self):
        from domain.recon import phone_lookup

        result = phone_lookup("notanumber")
        assert result["valid"] is False
        assert "error" in result

    def test_phone_too_long(self):
        from domain.recon import phone_lookup

        result = phone_lookup("+" + "9" * 100)
        assert not result["valid"]
        assert "too long" in result.get("error", "")

    def test_summary_present(self):
        from domain.recon import phone_lookup

        result = phone_lookup("+905321234567")
        assert result["valid"] is True
        assert result["summary"] != ""
        assert "TR" in result["summary"] or "Turkey" in result["summary"] or "+90" in result["summary"]


class TestPhoneCarrierHonesty:
    """Bug M: empty carrier string masked 'unsupported region' as 'no carrier'."""

    def test_tr_number_carrier_known(self):
        # libphonenumber's carrier DB covers Turkey
        from domain.recon import phone_lookup

        result = phone_lookup("+905321234567")
        assert result["valid"] is True
        assert result["carrier_status"] == "known"
        assert result["carrier"] is not None
        assert result["carrier"] != ""

    def test_us_number_carrier_unsupported(self):
        # US/CA libphonenumber returns "" (MNP rules block carrier inference)
        from domain.recon import phone_lookup

        result = phone_lookup("+14155552671")
        assert result["valid"] is True
        assert result["carrier_status"] == "unsupported_region"
        assert result["carrier"] is None

    def test_route_drops_carrier_when_unsupported(self):
        # response_model_exclude_none=True → carrier key absent from JSON for US
        with patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE):
            r = client.get("/v1/phone/%2B14155552671")
            assert r.status_code == 200
            data = r.json()
            assert data["valid"] is True
            assert data["carrier_status"] == "unsupported_region"
            assert "carrier" not in data, "carrier must be omitted when unsupported_region"

    def test_route_emits_carrier_when_known(self):
        with patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE):
            r = client.get("/v1/phone/%2B905321234567")
            assert r.status_code == 200
            data = r.json()
            assert data["valid"] is True
            assert data["carrier_status"] == "known"
            assert data.get("carrier")  # truthy, non-empty


class TestPhoneRoute:
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_phone_valid(self, mock_auth):
        r = client.get("/v1/phone/%2B905321234567")
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is True
        assert data["country_code"] == "TR"

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_phone_invalid(self, mock_auth):
        r = client.get("/v1/phone/notanumber")
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is False

    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_AUTH_FREE)
    def test_phone_response_shape(self, mock_auth):
        # Use a TR number — libphonenumber's carrier DB covers it, so the carrier
        # field is present. US/CA omit `carrier` per Bug M (unsupported_region).
        r = client.get("/v1/phone/%2B905321234567")
        assert r.status_code == 200
        data = r.json()
        expected_keys = {
            "valid",
            "number",
            "format",
            "country_code",
            "country_name",
            "type",
            "carrier",
            "carrier_status",
            "timezone",
            "summary",
        }
        assert expected_keys.issubset(set(data.keys()))
