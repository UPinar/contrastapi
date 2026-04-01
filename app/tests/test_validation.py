"""Tests for validation.py"""

import socket
from unittest.mock import MagicMock, patch

# --- clean_domain ---


def test_clean_domain_strips_protocol():
    from validation import clean_domain

    assert clean_domain("https://example.com") == "example.com"
    assert clean_domain("http://example.com") == "example.com"


def test_clean_domain_strips_path():
    from validation import clean_domain

    assert clean_domain("example.com/page") == "example.com"


def test_clean_domain_strips_port():
    from validation import clean_domain

    assert clean_domain("example.com:8080") == "example.com"


def test_clean_domain_strips_trailing_dot():
    from validation import clean_domain

    assert clean_domain("example.com.") == "example.com"


def test_clean_domain_lowercases():
    from validation import clean_domain

    assert clean_domain("EXAMPLE.COM") == "example.com"


def test_clean_domain_strips_whitespace():
    from validation import clean_domain

    assert clean_domain("  example.com  ") == "example.com"


def test_clean_domain_strips_null_bytes():
    from validation import clean_domain

    assert clean_domain("example\x00.com") == "example.com"


def test_clean_domain_full_url():
    from validation import clean_domain

    assert clean_domain("https://www.example.com/path?q=1") == "www.example.com"


def test_clean_domain_strips_userinfo():
    from validation import clean_domain

    assert clean_domain("https://user:pass@example.com/path") == "example.com"
    assert clean_domain("user@example.com") == "example.com"


# --- is_private_ip ---


def test_private_ip_loopback():
    from validation import is_private_ip

    assert is_private_ip("127.0.0.1") is True


def test_private_ip_rfc1918():
    from validation import is_private_ip

    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("172.16.0.1") is True


def test_private_ip_public():
    from validation import is_private_ip

    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False


def test_private_ip_invalid():
    from validation import is_private_ip

    assert is_private_ip("not-an-ip") is True


def test_private_ip_ipv6_loopback():
    from validation import is_private_ip

    assert is_private_ip("::1") is True


# --- is_valid_ip ---


def test_valid_ip_v4():
    from validation import is_valid_ip

    assert is_valid_ip("1.2.3.4") is True


def test_valid_ip_v6():
    from validation import is_valid_ip

    assert is_valid_ip("::1") is True


def test_invalid_ip():
    from validation import is_valid_ip

    assert is_valid_ip("not-ip") is False
    assert is_valid_ip("999.999.999.999") is False


# --- validate_cve_id ---


def test_validate_cve_id_valid():
    from validation import validate_cve_id

    assert validate_cve_id("CVE-2024-1234") is True
    assert validate_cve_id("CVE-2024-12345") is True


def test_validate_cve_id_invalid():
    from validation import validate_cve_id

    assert validate_cve_id("CVE-2024") is False
    assert validate_cve_id("not-a-cve") is False
    assert validate_cve_id("CVE-24-1234") is False


def test_validate_cve_id_rejects_lowercase():
    from validation import validate_cve_id

    assert validate_cve_id("cve-2024-1234") is False


# --- validate_domain ---


def test_validate_domain_rejects_empty():
    from validation import validate_domain

    assert validate_domain("") is None


def test_validate_domain_rejects_no_dot():
    from validation import validate_domain

    assert validate_domain("localhost") is None


def test_validate_domain_rejects_too_long():
    from validation import validate_domain

    assert validate_domain("a" * 254 + ".com") is None


def test_validate_domain_rejects_special_chars():
    from validation import validate_domain

    assert validate_domain("exam ple.com") is None
    assert validate_domain("exam!ple.com") is None


# --- get_client_ip ---


def test_get_client_ip_real_ip():
    from validation import get_client_ip

    request = MagicMock()
    request.headers = {"x-real-ip": "1.2.3.4"}
    request.client = MagicMock()
    request.client.host = "127.0.0.1"
    assert get_client_ip(request) == "1.2.3.4"


def test_get_client_ip_forwarded_for():
    from validation import get_client_ip

    request = MagicMock()
    request.headers = {"x-forwarded-for": "5.6.7.8, 10.0.0.1"}
    request.client = MagicMock()
    request.client.host = "127.0.0.1"
    assert get_client_ip(request) == "5.6.7.8"


def test_get_client_ip_direct():
    from validation import get_client_ip

    request = MagicMock()
    request.headers = {}
    request.client = MagicMock()
    request.client.host = "9.8.7.6"
    assert get_client_ip(request) == "9.8.7.6"


def test_get_client_ip_no_client():
    from validation import get_client_ip

    request = MagicMock()
    request.headers = {}
    request.client = None
    assert get_client_ip(request) == "unknown"


def test_get_client_ip_invalid_real_ip_falls_through():
    from validation import get_client_ip

    request = MagicMock()
    request.headers = {"x-real-ip": "not-valid"}
    request.client = MagicMock()
    request.client.host = "4.3.2.1"
    assert get_client_ip(request) == "4.3.2.1"


# --- resolve_and_check ---


def test_resolve_and_check_public_ip():
    from unittest.mock import patch

    from validation import resolve_and_check

    with patch(
        "validation.socket.getaddrinfo",
        return_value=[
            (2, 1, 6, "", ("93.184.216.34", 443)),
        ],
    ):
        result = resolve_and_check("example.com")
        assert result == "93.184.216.34"


def test_resolve_and_check_rejects_private():
    from unittest.mock import patch

    from validation import resolve_and_check

    with patch(
        "validation.socket.getaddrinfo",
        return_value=[
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ],
    ):
        assert resolve_and_check("evil.com") is None


def test_resolve_and_check_dns_failure():
    import socket
    from unittest.mock import patch

    from validation import resolve_and_check

    with (
        patch("validation.socket.getaddrinfo", side_effect=socket.gaierror("fail")),
        patch("validation._dns_fallback", return_value=None),
    ):
        assert resolve_and_check("nonexistent.invalid") is None


# --- validate_domain success + SSRF ---


def test_validate_domain_success():
    from unittest.mock import patch

    from validation import validate_domain

    with patch("validation.resolve_and_check", return_value="93.184.216.34"):
        result = validate_domain("example.com")
        assert result == "93.184.216.34"


def test_validate_domain_rejects_private_ip():
    from unittest.mock import patch

    from validation import validate_domain

    with patch("validation.resolve_and_check", return_value=None):
        assert validate_domain("internal.evil.com") is None


# --- resolve_and_check SSRF tests ---


class TestResolveAndCheckSSRF:
    @patch(
        "validation.socket.getaddrinfo",
        return_value=[
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ],
    )
    def test_rejects_mixed_public_private_ips(self, mock_getaddr):
        from validation import resolve_and_check

        assert resolve_and_check("evil.com") is None

    @patch(
        "validation.socket.getaddrinfo",
        return_value=[
            (2, 1, 6, "", ("10.0.0.1", 443)),
        ],
    )
    def test_rejects_all_private(self, mock_getaddr):
        from validation import resolve_and_check

        assert resolve_and_check("internal.com") is None

    @patch("validation._dns_fallback", return_value=None)
    @patch("validation.socket.getaddrinfo", return_value=[])
    def test_empty_results(self, mock_getaddr, mock_fallback):
        from validation import resolve_and_check

        assert resolve_and_check("norecord.com") is None


# --- validate_domain edge cases ---


class TestValidateDomainEdgeCases:
    def test_rejects_leading_hyphen_label(self):
        from validation import validate_domain

        assert validate_domain("-example.com") is None

    def test_rejects_trailing_hyphen_label(self):
        from validation import validate_domain

        assert validate_domain("example-.com") is None

    def test_rejects_label_over_63_chars(self):
        from validation import validate_domain

        long_label = "a" * 64 + ".com"
        assert validate_domain(long_label) is None

    def test_accepts_label_exactly_63_chars(self):
        from unittest.mock import patch

        from validation import validate_domain

        # 63-char label should pass format validation and reach DNS resolution
        label_63 = "a" * 63 + ".com"
        with patch("validation.resolve_and_check", return_value="93.184.216.34") as mock_resolve:
            result = validate_domain(label_63)
            assert result == "93.184.216.34"
            mock_resolve.assert_called_once_with(label_63)


# --- clean_domain edge cases ---


class TestCleanDomainEdgeCases:
    def test_strips_fragment(self):
        from validation import clean_domain

        assert clean_domain("example.com#section") == "example.com"

    def test_strips_fragment_with_protocol(self):
        from validation import clean_domain

        assert clean_domain("https://example.com/path#frag") == "example.com"

    def test_double_protocol(self):
        from validation import clean_domain

        # After stripping first https://, remainder is "https://example.com"
        # split("/") → "https:", split(":") → "https"
        result = clean_domain("https://https://example.com")
        assert result == "https"

    def test_null_byte_stripped(self):
        from validation import clean_domain

        assert clean_domain("example\x00.com") == "example.com"


# --- get_client_ip untrusted proxy ---


class TestGetClientIpUntrustedProxy:
    def test_ignores_xff_from_untrusted_proxy(self):
        from validation import get_client_ip

        request = MagicMock()
        request.headers = {"x-forwarded-for": "1.2.3.4, 10.0.0.1"}
        request.client = MagicMock()
        request.client.host = "5.5.5.5"
        assert get_client_ip(request) == "5.5.5.5"

    def test_ignores_real_ip_from_untrusted_proxy(self):
        from validation import get_client_ip

        request = MagicMock()
        request.headers = {"x-real-ip": "1.2.3.4"}
        request.client = MagicMock()
        request.client.host = "5.5.5.5"
        assert get_client_ip(request) == "5.5.5.5"

    def test_trusts_xff_from_localhost(self):
        from validation import get_client_ip

        request = MagicMock()
        request.headers = {"x-forwarded-for": "203.0.113.5, 10.0.0.1"}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        assert get_client_ip(request) == "203.0.113.5"


# --- validate_cve_id injection ---


class TestValidateCveIdInjection:
    def test_rejects_sql_injection(self):
        from validation import validate_cve_id

        assert validate_cve_id("CVE-2024-1234' OR '1'='1") is False

    def test_rejects_semicolon_injection(self):
        from validation import validate_cve_id

        assert validate_cve_id("CVE-2024-1234; DROP TABLE cves;--") is False


# --- DNS fallback ---


class TestDnsFallback:
    @patch("validation.dns.resolver.Resolver")
    @patch("validation.socket.getaddrinfo", side_effect=socket.gaierror("fail"))
    def test_fallback_used_when_getaddrinfo_fails(self, mock_getaddr, mock_resolver_cls):
        from validation import resolve_and_check

        mock_resolver = MagicMock()
        mock_answer = MagicMock()
        mock_answer.__str__ = lambda self: "93.184.216.34"
        mock_resolver.resolve.return_value = [mock_answer]
        mock_resolver_cls.return_value = mock_resolver
        result = resolve_and_check("example.com.tr")
        assert result == "93.184.216.34"
        mock_resolver.resolve.assert_called_with("example.com.tr", "A")

    @patch("validation.dns.resolver.Resolver")
    @patch("validation.socket.getaddrinfo", side_effect=socket.gaierror("fail"))
    def test_fallback_private_ip_rejected(self, mock_getaddr, mock_resolver_cls):
        from validation import resolve_and_check

        mock_resolver = MagicMock()
        mock_answer = MagicMock()
        mock_answer.__str__ = lambda self: "192.168.1.1"
        mock_resolver.resolve.return_value = [mock_answer]
        mock_resolver_cls.return_value = mock_resolver
        assert resolve_and_check("evil.internal") is None

    @patch("validation.dns.resolver.Resolver")
    @patch("validation.socket.getaddrinfo", side_effect=socket.gaierror("fail"))
    def test_fallback_also_fails_returns_none(self, mock_getaddr, mock_resolver_cls):
        import dns.resolver as dns_resolver
        from validation import resolve_and_check

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns_resolver.NoAnswer()
        mock_resolver_cls.return_value = mock_resolver
        assert resolve_and_check("nonexistent.invalid") is None

    @patch("validation.dns.resolver.Resolver")
    @patch(
        "validation.socket.getaddrinfo",
        return_value=[
            (2, 1, 6, "", ("93.184.216.34", 443)),
        ],
    )
    def test_primary_succeeds_no_fallback(self, mock_getaddr, mock_resolver_cls):
        from validation import resolve_and_check

        result = resolve_and_check("example.com")
        assert result == "93.184.216.34"
        mock_resolver_cls.assert_not_called()


# --- _is_valid_format ---


class TestIsValidFormat:
    def test_valid_format_returns_true(self):
        from validation import _is_valid_format

        assert _is_valid_format("example.com") is True

    def test_no_dot_returns_false(self):
        from validation import _is_valid_format

        assert _is_valid_format("localhost") is False

    def test_too_long_returns_false(self):
        from validation import _is_valid_format

        assert _is_valid_format("a" * 254 + ".com") is False

    def test_special_chars_returns_false(self):
        from validation import _is_valid_format

        assert _is_valid_format("exam!ple.com") is False

    def test_leading_hyphen_returns_false(self):
        from validation import _is_valid_format

        assert _is_valid_format("-example.com") is False

    def test_comtr_format_valid(self):
        from validation import _is_valid_format

        assert _is_valid_format("motomax.com.tr") is True


# --- _TRUSTED_PROXIES IPv4-mapped IPv6 ---


def test_trusted_proxies_contains_ipv4_mapped_ipv6():
    from validation import _TRUSTED_PROXIES

    assert "::ffff:127.0.0.1" in _TRUSTED_PROXIES


def test_get_client_ip_ipv4_mapped_ipv6_trusted():
    """When direct IP is ::ffff:127.0.0.1, X-Real-IP should be used."""
    from types import SimpleNamespace

    from validation import get_client_ip

    class FakeRequest:
        client = SimpleNamespace(host="::ffff:127.0.0.1")
        headers = {"x-real-ip": "203.0.113.50"}

    assert get_client_ip(FakeRequest()) == "203.0.113.50"
