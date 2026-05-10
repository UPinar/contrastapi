"""Tests for domain/ip_intel.py — cloud provider lookup, Tor exit detection, risk scoring."""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytricia


class _AsyncBytesIter:
    """Async iterator yielding bytes chunks from a sync iterable — for AsyncClient mocks."""

    def __init__(self, chunks):
        self._chunks = iter(chunks)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._chunks)
        except StopIteration:
            raise StopAsyncIteration


# ── helpers ──────────────────────────────────────────────────────────────────


def _make_aws_json():
    return {
        "prefixes": [{"ip_prefix": "3.0.0.0/8", "region": "us-east-1", "service": "EC2"}],
        "ipv6_prefixes": [],
    }


def _make_gcp_json():
    return {
        "prefixes": [{"ipv4Prefix": "8.8.8.0/24"}, {"ipv6Prefix": "2001:4860::/32"}],
    }


def _make_cf_json():
    return {
        "result": {
            "ipv4_cidrs": ["1.1.1.0/24"],
            "ipv6_cidrs": ["2606:4700::/32"],
        }
    }


# ── cloud cache tests ─────────────────────────────────────────────────────────


class TestRefreshCloudCache:
    def setup_method(self):
        import domain.ip_intel as m

        m._cloud_cache = {"v4": None, "v6": None, "fetched_at": 0.0}

    def _stream_ctx(self, body: bytes, content_length: str | None = None):
        """Build a MagicMock acting as httpx streaming response context manager."""
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        headers = {}
        if content_length is not None:
            headers["content-length"] = content_length
        resp.headers.get = lambda k, default=None: headers.get(k, default)
        # iter_bytes yields body in a single chunk
        resp.aiter_bytes = lambda: _AsyncBytesIter([body])
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=resp)
        ctx.__aexit__ = AsyncMock(return_value=False)
        return ctx

    def test_aws_only_others_fail(self):
        import json as _json

        import httpx

        aws_body = _json.dumps(_make_aws_json()).encode()

        def stream_side_effect(method, url, **kwargs):
            if "amazonaws" in url:
                return self._stream_ctx(aws_body)
            raise httpx.TimeoutException("timeout")

        with patch("domain.ip_intel._intel_client") as mock_client:
            mock_client.stream.side_effect = stream_side_effect

            from domain.ip_intel import _refresh_cloud_cache

            v4, v6 = asyncio.run(_refresh_cloud_cache())

        # AWS prefix should be present; no exception bubbled
        assert v4.get("3.5.0.1") == "AWS"

    def test_body_cap_returns_previous(self):
        import domain.ip_intel as m

        # Pre-seed cache with AWS prefix; body-cap on all sources should preserve it
        prev_v4 = pytricia.PyTricia(32)
        prev_v4["10.0.0.0/8"] = "AWS"
        prev_v6 = pytricia.PyTricia(128)
        m._cloud_cache = {"v4": prev_v4, "v6": prev_v6, "fetched_at": 0.0}

        # Content-Length declares oversize → early abort, no iter_bytes consumed
        big_ctx = self._stream_ctx(b"", content_length=str(10 * 1024 * 1024))

        with patch("domain.ip_intel._intel_client") as mock_client:
            mock_client.stream.return_value = big_ctx

            from domain.ip_intel import _refresh_cloud_cache

            v4, _ = asyncio.run(_refresh_cloud_cache())

        # All sources hit body cap → previous AWS prefix preserved
        assert v4.get("10.0.0.0/8") == "AWS"

    def test_ttl_hit_skips_fetch(self):
        import domain.ip_intel as m

        v4 = pytricia.PyTricia(32)
        v4["3.0.0.0/8"] = "AWS"
        v6 = pytricia.PyTricia(128)
        m._cloud_cache = {"v4": v4, "v6": v6, "fetched_at": time.time()}

        with patch("domain.ip_intel._intel_client") as mock_client:
            from domain.ip_intel import _refresh_cloud_cache

            asyncio.run(_refresh_cloud_cache())
            mock_client.stream.assert_not_called()


# ── tor cache tests ───────────────────────────────────────────────────────────


class TestRefreshTorCache:
    def setup_method(self):
        import domain.ip_intel as m

        m._tor_cache = {
            "data": frozenset(),
            "fetched_at": 0.0,
            "fetch_status": "initial",
            "line_count": 0,
        }

    def test_parses_plaintext(self):
        tor_text = "1.2.3.4\n5.6.7.8\n# comment\n\n9.9.9.9\n"
        body = tor_text.encode()

        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.headers.get = lambda k, default=None: None
        resp.aiter_bytes = lambda: _AsyncBytesIter([body])
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=resp)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("domain.ip_intel._intel_client") as mock_client:
            mock_client.stream.return_value = ctx

            from domain.ip_intel import _refresh_tor_cache

            result = asyncio.run(_refresh_tor_cache())

        assert "1.2.3.4" in result
        assert "5.6.7.8" in result
        assert "9.9.9.9" in result
        assert "# comment" not in result

    def test_ttl_hit_skips_fetch(self):
        import domain.ip_intel as m

        m._tor_cache = {
            "data": frozenset({"1.2.3.4"}),
            "fetched_at": time.time(),
            "fetch_status": "ok",
            "line_count": 1,
        }

        with patch("domain.ip_intel._intel_client") as mock_client:
            from domain.ip_intel import _refresh_tor_cache

            result = asyncio.run(_refresh_tor_cache())
            mock_client.stream.assert_not_called()

        assert "1.2.3.4" in result

    def test_success_sets_status_ok(self):
        """NEW-B: a successful fetch records fetch_status='ok' and line_count
        so the verdict layer can surface 'tor' as queried (not unavailable)."""
        body = b"1.2.3.4\n5.6.7.8\n"
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.headers.get = lambda k, default=None: None
        resp.aiter_bytes = lambda: _AsyncBytesIter([body])
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=resp)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("domain.ip_intel._intel_client") as mock_client:
            mock_client.stream = MagicMock(return_value=ctx)
            from domain.ip_intel import _refresh_tor_cache, tor_cache_status

            asyncio.run(_refresh_tor_cache())
            assert tor_cache_status() == "ok"
            import domain.ip_intel as m

            assert m._tor_cache["line_count"] == 2

    def test_fetch_exception_sets_status_failed(self):
        """NEW-B: timeout / network error → fetch_status='failed' so the
        verdict layer adds 'tor' to sources_unavailable, turning the silent
        false-negative into honest signal."""
        with patch("domain.ip_intel._intel_client") as mock_client:
            mock_client.stream.side_effect = Exception("boom")

            from domain.ip_intel import _refresh_tor_cache, tor_cache_status

            result = asyncio.run(_refresh_tor_cache())
            assert result == frozenset()
            assert tor_cache_status() == "failed"

    def test_body_capped_sets_status_capped(self):
        """NEW-B: when _fetch_capped returns None (cap exceeded) the cache
        records 'capped' status — not 'ok' just because the in-memory frozenset
        happens to be empty."""
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        # Force the cap branch by claiming a too-large content-length.
        resp.headers.get = lambda k, default=None: "999999999" if k == "content-length" else default
        resp.aiter_bytes = lambda: _AsyncBytesIter([])
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=resp)
        ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("domain.ip_intel._intel_client") as mock_client:
            mock_client.stream = MagicMock(return_value=ctx)
            from domain.ip_intel import _refresh_tor_cache, tor_cache_status

            asyncio.run(_refresh_tor_cache())
            assert tor_cache_status() == "capped"

    def test_initial_status_before_first_fetch(self):
        """tor_cache_status() returns 'initial' until the first refresh runs.
        Lets the verdict layer flag 'tor' as unavailable on the very first
        request after a service restart."""
        from domain.ip_intel import tor_cache_status

        assert tor_cache_status() == "initial"


# ── lookup tests ──────────────────────────────────────────────────────────────


class TestCheckCloudProvider:
    def setup_method(self):
        import domain.ip_intel as m

        m._cloud_cache = {"v4": None, "v6": None, "fetched_at": 0.0}

    def test_returns_provider(self):
        import domain.ip_intel as m

        v4 = pytricia.PyTricia(32)
        v4["3.0.0.0/8"] = "AWS"
        v6 = pytricia.PyTricia(128)
        m._cloud_cache = {"v4": v4, "v6": v6, "fetched_at": time.time()}

        from domain.ip_intel import check_cloud_provider

        assert asyncio.run(check_cloud_provider("3.5.140.2")) == "AWS"

    def test_returns_none_outside_range(self):
        import domain.ip_intel as m

        v4 = pytricia.PyTricia(32)
        v4["3.0.0.0/8"] = "AWS"
        v6 = pytricia.PyTricia(128)
        m._cloud_cache = {"v4": v4, "v6": v6, "fetched_at": time.time()}

        from domain.ip_intel import check_cloud_provider

        assert asyncio.run(check_cloud_provider("9.9.9.9")) is None

    def test_ipv6_lookup(self):
        import domain.ip_intel as m

        v4 = pytricia.PyTricia(32)
        v6 = pytricia.PyTricia(128)
        v6["2606:4700::/32"] = "Cloudflare"
        m._cloud_cache = {"v4": v4, "v6": v6, "fetched_at": time.time()}

        from domain.ip_intel import check_cloud_provider

        assert asyncio.run(check_cloud_provider("2606:4700::1111")) == "Cloudflare"


class TestCheckTorExit:
    def setup_method(self):
        import domain.ip_intel as m

        m._tor_cache = {
            "data": frozenset(),
            "fetched_at": 0.0,
            "fetch_status": "initial",
            "line_count": 0,
        }

    def test_ip_in_exit_set(self):
        import domain.ip_intel as m

        m._tor_cache = {
            "data": frozenset({"5.9.32.230"}),
            "fetched_at": time.time(),
            "fetch_status": "ok",
            "line_count": 1,
        }

        from domain.ip_intel import check_tor_exit

        assert asyncio.run(check_tor_exit("5.9.32.230")) is True

    def test_ip_not_in_exit_set(self):
        import domain.ip_intel as m

        m._tor_cache = {
            "data": frozenset({"5.9.32.230"}),
            "fetched_at": time.time(),
            "fetch_status": "ok",
            "line_count": 1,
        }

        from domain.ip_intel import check_tor_exit

        assert asyncio.run(check_tor_exit("8.8.8.8")) is False


# ── FireHOL tests ─────────────────────────────────────────────────────────────


@pytest.mark.real_firehol
class TestFirehol:
    @pytest.fixture(autouse=True)
    def _reset_firehol_cache(self):
        from domain import ip_intel

        ip_intel._firehol_cache = {
            "v4": None,
            "v6": None,
            "fetched_at": 0.0,
            "consecutive_failures": 0,
            "last_failure_at": 0.0,
        }
        yield

    def _stream_ctx(self, body: bytes):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.headers.get = lambda k, default=None: None
        resp.aiter_bytes = lambda: _AsyncBytesIter([body])
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=resp)
        ctx.__aexit__ = AsyncMock(return_value=False)
        return ctx

    def test_firehol_listed_ip(self):
        body = b"1.2.3.0/24\n"
        with patch("domain.ip_intel._intel_client") as mock_client:
            mock_client.stream.return_value = self._stream_ctx(body)

            from domain.ip_intel import check_firehol

            result = asyncio.run(check_firehol("1.2.3.5"))

        assert result == {"status": "ok", "listed": True, "lists_matched": ["firehol_level1"]}

    def test_firehol_clean_ip(self):
        body = b"1.2.3.0/24\n"
        with patch("domain.ip_intel._intel_client") as mock_client:
            mock_client.stream.return_value = self._stream_ctx(body)

            from domain.ip_intel import check_firehol

            result = asyncio.run(check_firehol("9.9.9.9"))

        assert result == {"status": "ok", "listed": False, "lists_matched": []}

    def test_firehol_fetch_failure_graceful(self):
        import httpx

        with patch("domain.ip_intel._intel_client") as mock_client:
            mock_client.stream.side_effect = httpx.TimeoutException("timeout")

            from domain.ip_intel import check_firehol

            result = asyncio.run(check_firehol("5.5.5.5"))

        assert result["status"] == "unavailable"
        assert result["listed"] is False
        assert result["lists_matched"] == []

    def test_firehol_private_ip_skipped(self):
        with patch("domain.ip_intel._intel_client") as mock_client:
            from domain.ip_intel import check_firehol

            result = asyncio.run(check_firehol("10.0.0.1"))

        assert result["status"] == "skipped"
        assert result["listed"] is False
        mock_client.stream.assert_not_called()

    def test_firehol_comment_and_blank_lines_ignored(self):
        body = b"# comment\n\n  \n1.2.3.4\n"
        with patch("domain.ip_intel._intel_client") as mock_client:
            mock_client.stream.return_value = self._stream_ctx(body)

            from domain.ip_intel import _refresh_firehol_cache

            v4, v6 = asyncio.run(_refresh_firehol_cache())

        assert v4.get("1.2.3.4") is True
        count = sum(1 for _ in v4)
        assert count == 1

    def test_firehol_cache_refresh_respects_ttl(self):
        body = b"1.2.3.0/24\n"
        with patch("domain.ip_intel._intel_client") as mock_client:
            mock_client.stream.return_value = self._stream_ctx(body)

            with patch("domain.ip_intel.time") as mock_time:
                mock_time.time.return_value = 0.0
                from domain.ip_intel import _refresh_firehol_cache

                asyncio.run(_refresh_firehol_cache())

                mock_client.stream.reset_mock()
                mock_client.stream.return_value = self._stream_ctx(body)

                # Simulate TTL expiry
                from config import FIREHOL_TTL

                mock_time.time.return_value = FIREHOL_TTL + 1.0
                asyncio.run(_refresh_firehol_cache())

        assert mock_client.stream.call_count == 1

    def test_firehol_ipv6_cidr_in_v6_trie(self):
        # Use a routable (non-reserved, non-documentation) IPv6 prefix
        body = b"2607:f8b0::/32\n"
        with patch("domain.ip_intel._intel_client") as mock_client:
            mock_client.stream.return_value = self._stream_ctx(body)

            from domain.ip_intel import check_firehol

            result = asyncio.run(check_firehol("2607:f8b0::1"))

        assert result == {"status": "ok", "listed": True, "lists_matched": ["firehol_level1"]}

    def test_firehol_ipv6_clean_not_listed(self):
        # Different v6 prefix from the listed one → must return listed=False
        body = b"2607:f8b0::/32\n"
        with patch("domain.ip_intel._intel_client") as mock_client:
            mock_client.stream.return_value = self._stream_ctx(body)

            from domain.ip_intel import check_firehol

            result = asyncio.run(check_firehol("2606:4700::1"))

        assert result == {"status": "ok", "listed": False, "lists_matched": []}

    def test_firehol_failure_backoff_suppresses_refetch(self):
        import httpx
        from config import FIREHOL_FAILURE_THRESHOLD

        with patch("domain.ip_intel._intel_client") as mock_client:
            mock_client.stream.side_effect = httpx.TimeoutException("timeout")

            from domain.ip_intel import _refresh_firehol_cache

            for _ in range(FIREHOL_FAILURE_THRESHOLD):
                asyncio.run(_refresh_firehol_cache())
            # Next call within backoff window must NOT hit upstream
            fetches_before = mock_client.stream.call_count
            asyncio.run(_refresh_firehol_cache())
            assert mock_client.stream.call_count == fetches_before

    def test_firehol_malformed_line_skipped(self):
        body = b"NOT_AN_IP\n1.2.3.4\n"
        with patch("domain.ip_intel._intel_client") as mock_client:
            mock_client.stream.return_value = self._stream_ctx(body)

            from domain.ip_intel import _refresh_firehol_cache

            v4, _ = asyncio.run(_refresh_firehol_cache())

        count = sum(1 for _ in v4)
        assert count == 1
        assert v4.get("1.2.3.4") is True


# ── score_ip tests ────────────────────────────────────────────────────────────


class TestIsDatacenter:
    """Phase 3: is_datacenter helper for two-tier datacenter detection."""

    def test_returns_true_for_cloudflare_asn(self):
        from domain.ip_intel import is_datacenter

        # 1.1.1.1 → AS13335 (Cloudflare) is in _ASN_TO_CLOUD_PROVIDER, so even
        # without an explicit cloud_provider arg the ASN check should hit.
        assert is_datacenter("1.1.1.1", asn=13335, cloud_provider=None) is True

    def test_returns_true_when_cloud_provider_set(self):
        from domain.ip_intel import is_datacenter

        # cloud_provider non-None short-circuits regardless of ASN value
        # (covers IPs whose CIDR resolves but RIPE Stat ASN lookup failed).
        assert is_datacenter("9.9.9.9", asn=None, cloud_provider="AWS") is True
        assert is_datacenter("203.0.113.1", asn=99999, cloud_provider="GCP") is True

    def test_returns_false_for_residential_asn(self):
        from domain.ip_intel import is_datacenter

        # Random non-datacenter ASN with no cloud_provider hit → residential.
        # asn=0 / negative / bool guards keep junk inputs from passing.
        assert is_datacenter("203.0.113.1", asn=12345, cloud_provider=None) is False
        assert is_datacenter("203.0.113.1", asn=0, cloud_provider=None) is False
        assert is_datacenter("203.0.113.1", asn=None, cloud_provider=None) is False
        assert is_datacenter("203.0.113.1", asn=True, cloud_provider=None) is False


class TestScoreIp:
    def _score(self, reputation=None, ports=None, ptr=None, cloud=None, tor=False, **kw):
        from domain.ip_intel import score_ip

        return score_ip(reputation, ports or [], ptr, cloud, tor, **kw)

    def test_no_reputation(self):
        score = self._score(reputation=None)
        assert 0 <= score <= 100

    def test_clamps_high(self):
        rep = {"abuseipdb": {"abuse_score": 100}}
        score = self._score(reputation=rep, ports=list(range(50)), tor=True)
        assert score >= 90

    def test_clamps_low(self):
        # cloud_provider / ptr inert in v1.17.0 formula; clean residential IP → 0
        score = self._score(reputation={"abuseipdb": {"abuse_score": 0}}, cloud="GCP", ptr="dns.google")
        assert score == 0

    def test_high_risk_tor_abuse(self):
        # Tor (+30) + AbuseIPDB 90 (round(15 * 0.9) = 14) = 44
        rep = {"abuseipdb": {"abuse_score": 90}}
        score = self._score(reputation=rep, tor=True)
        assert score >= 40

    def test_low_risk_clean_residential(self):
        rep = {"abuseipdb": {"abuse_score": 0}}
        score = self._score(reputation=rep, cloud="GCP", ptr="dns.google")
        assert score <= 15

    def test_tor_penalty_applied(self):
        score_no_tor = self._score()
        score_tor = self._score(tor=True)
        assert score_tor > score_no_tor

    def test_datacenter_penalty_applied(self):
        # v1.17.0: is_datacenter is now a +10 risk component (was -10 trust bonus
        # pre-1.17). Cloud-provider arg is inert; route the signal via the new kwarg.
        score_residential = self._score(tor=True, is_datacenter=False)
        score_datacenter = self._score(tor=True, is_datacenter=True)
        assert score_datacenter > score_residential
        assert score_datacenter - score_residential == 10

    def test_none_abuse_score(self):
        rep = {"abuseipdb": {"abuse_score": None}}
        score = self._score(reputation=rep)
        assert 0 <= score <= 100


class TestScoreIpPhase5:
    """v1.17.0 formula: firehol / vulns / is_datacenter components added."""

    def _score(self, **kw):
        from domain.ip_intel import score_ip

        kw.setdefault("reputation", None)
        kw.setdefault("ports", [])
        kw.setdefault("ptr", None)
        kw.setdefault("cloud_provider", None)
        kw.setdefault("tor_exit", False)
        return score_ip(**kw)

    def test_firehol_listed_penalty(self):
        baseline = self._score()
        listed = self._score(firehol={"status": "ok", "listed": True})
        assert listed - baseline == 20

    def test_firehol_not_listed_no_penalty(self):
        baseline = self._score()
        clean = self._score(firehol={"status": "ok", "listed": False})
        assert clean == baseline

    def test_vulns_count_component(self):
        # Phase 2: vulns is list[VulnInfo dict]; only count matters here.
        baseline = self._score()
        two_vulns = self._score(vulns=[{"cve_id": "CVE-1"}, {"cve_id": "CVE-2"}])
        assert two_vulns - baseline == 10

    def test_vulns_count_capped_at_4(self):
        baseline = self._score()
        ten_vulns = self._score(vulns=[{"cve_id": f"CVE-{i}"} for i in range(10)])
        assert ten_vulns - baseline == 20  # 5 * min(10, 4) = 20

    def test_is_datacenter_penalty(self):
        baseline = self._score()
        datacenter = self._score(is_datacenter=True)
        assert datacenter - baseline == 10

    def test_ports_capped_at_5(self):
        baseline = self._score()
        many_ports = self._score(ports=list(range(20)))
        assert many_ports - baseline == 50  # 10 * min(20, 5) = 50

    def test_abuse_score_15_max_component(self):
        baseline = self._score()
        max_abuse = self._score(reputation={"abuseipdb": {"abuse_score": 100}})
        assert max_abuse - baseline == 15  # round(15 * 100/100) = 15

    def test_clean_cloudflare_ip_low(self):
        # 1.1.1.1 — datacenter, no abuse, no firehol, no vulns, no tor, no ports observed.
        # v1.17.0: was 0 pre-refactor, now 10 (datacenter penalty alone).
        score = self._score(
            reputation={"abuseipdb": {"abuse_score": 0}},
            ports=[],
            is_datacenter=True,
            firehol={"status": "ok", "listed": False},
            vulns=[],
        )
        assert score == 10

    def test_severity_label_remains_low_at_boundary(self):
        # v1.17.0 drift sanity: 1.1.1.1 stays "low" (severity boundary @ 25).
        from domain.ip_intel import severity_label

        assert severity_label(10) == "low"
        assert severity_label(24) == "low"

    def test_vulns_string_input_treated_as_empty(self):
        # Defense-in-depth: a poisoned upstream (or future caller) handing us
        # `vulns="CVE-2023-1234"` must not silently inflate the component via
        # len() on a string (would yield 13 → +20 instead of the intended 0).
        baseline = self._score()
        assert self._score(vulns="CVE-2023-1234") == baseline

    def test_ports_non_list_treated_as_empty(self):
        baseline = self._score()
        assert self._score(ports="80,443,22") == baseline

    def test_firehol_non_dict_treated_as_unlisted(self):
        baseline = self._score()
        assert self._score(firehol="listed") == baseline


class TestSeverityLabel:
    """Phase 5 mini (v1.16.1): risk_score → 4-bucket label for Nuclei + MCP triage."""

    def test_low_below_25(self):
        from domain.ip_intel import severity_label

        assert severity_label(0) == "low"
        assert severity_label(24) == "low"

    def test_medium_25_to_49(self):
        from domain.ip_intel import severity_label

        assert severity_label(25) == "medium"
        assert severity_label(49) == "medium"

    def test_high_50_to_74(self):
        from domain.ip_intel import severity_label

        assert severity_label(50) == "high"
        assert severity_label(74) == "high"

    def test_critical_75_plus(self):
        from domain.ip_intel import severity_label

        assert severity_label(75) == "critical"
        assert severity_label(100) == "critical"
