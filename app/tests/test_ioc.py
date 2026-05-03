"""Tests for ioc/ module — IOC enrichment, malware hash, password breach."""

import socket
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from auth import AuthCtx

# Routes use Annotated[AuthCtx, Depends(require_auth(...))]; require_auth's
# dep awaits auth.aauthenticate (Faz 4 batch 4e), so patches target
# auth.aauthenticate with new_callable=AsyncMock.
_FREE_AUTH_CTX = AuthCtx(
    tier="free",
    key_hash=None,
    client_ip="127.0.0.1",
    ratelimit_limit=100,
    ratelimit_remaining=99,
    ratelimit_reset=0,
    ratelimit_cost=1,
)

# === detect_indicator_type ===


def test_detect_ip():
    from ioc.lookup import detect_indicator_type

    assert detect_indicator_type("44.228.249.3") == "ip"


def test_detect_domain():
    from ioc.lookup import detect_indicator_type

    assert detect_indicator_type("evil.example.com") == "domain"


def test_detect_url_http():
    from ioc.lookup import detect_indicator_type

    assert detect_indicator_type("http://evil.com/malware.exe") == "url"


def test_detect_url_https():
    from ioc.lookup import detect_indicator_type

    assert detect_indicator_type("https://evil.com/payload") == "url"


def test_detect_hash_md5():
    from ioc.lookup import detect_indicator_type

    assert detect_indicator_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"


def test_detect_hash_sha1():
    from ioc.lookup import detect_indicator_type

    assert detect_indicator_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash"


def test_detect_hash_sha256():
    from ioc.lookup import detect_indicator_type

    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert detect_indicator_type(h) == "hash"


def test_detect_unknown():
    from ioc.lookup import detect_indicator_type

    assert detect_indicator_type("not_an_ioc") == "unknown"


def test_detect_empty():
    from ioc.lookup import detect_indicator_type

    assert detect_indicator_type("") == "unknown"


# === query_threatfox ===


def test_threatfox_found():
    from ioc.lookup import query_threatfox

    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "query_status": "ok",
        "data": [
            {
                "malware_printable": "Cobalt Strike",
                "threat_type": "botnet_cc",
                "confidence_level": 75,
                "tags": ["c2"],
                "first_seen_utc": "2024-01-01",
            }
        ],
    }
    mock_resp.raise_for_status = MagicMock()
    with patch("ioc.lookup._client.post", return_value=mock_resp):
        result = query_threatfox("44.228.249.3")
    assert result["found"] is True
    assert result["malware"] == "Cobalt Strike"


def test_threatfox_not_found():
    from ioc.lookup import query_threatfox

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"query_status": "no_result", "data": None}
    mock_resp.raise_for_status = MagicMock()
    with patch("ioc.lookup._client.post", return_value=mock_resp):
        result = query_threatfox("1.2.3.4")
    assert result["found"] is False


def test_threatfox_timeout():
    from ioc.lookup import query_threatfox

    with patch("ioc.lookup._client.post", side_effect=httpx.ConnectTimeout("timeout")):
        result = query_threatfox("1.2.3.4")
    assert result["found"] is False
    assert "error" in result


# === query_feodo ===


def test_feodo_found():
    import time

    from ioc.lookup import _feodo_cache, query_feodo

    # Pre-populate cache
    _feodo_cache["data"] = {
        "1.2.3.4": {"malware": "QakBot", "first_seen": "2024-01-15", "last_online": None, "status": "online"}
    }
    _feodo_cache["fetched_at"] = time.time()
    result = query_feodo("1.2.3.4")
    assert result["found"] is True
    assert result["malware"] == "QakBot"


def test_feodo_not_found():
    import time

    from ioc.lookup import _feodo_cache, query_feodo

    _feodo_cache["data"] = {"9.9.9.9": {"malware": "test"}}
    _feodo_cache["fetched_at"] = time.time()
    result = query_feodo("1.2.3.4")
    assert result["found"] is False


# === query_malwarebazaar ===


def test_malwarebazaar_found():
    from ioc.lookup import query_malwarebazaar

    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "query_status": "ok",
        "data": [
            {
                "signature": "AgentTesla",
                "file_type": "exe",
                "file_size": 245760,
                "first_seen": "2024-03-15",
                "tags": ["stealer"],
                "file_name": "payload.exe",
            }
        ],
    }
    mock_resp.raise_for_status = MagicMock()
    with patch("ioc.lookup._client.post", return_value=mock_resp):
        result = query_malwarebazaar("a" * 64)
    assert result["found"] is True
    assert result["malware_family"] == "AgentTesla"
    assert result["file_type"] == "exe"


def test_malwarebazaar_not_found():
    from ioc.lookup import query_malwarebazaar

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"query_status": "hash_not_found", "data": None}
    mock_resp.raise_for_status = MagicMock()
    with patch("ioc.lookup._client.post", return_value=mock_resp):
        result = query_malwarebazaar("b" * 64)
    assert result["found"] is False


def test_malwarebazaar_timeout():
    from ioc.lookup import query_malwarebazaar

    with patch("ioc.lookup._client.post", side_effect=httpx.ReadTimeout("timeout")):
        result = query_malwarebazaar("c" * 64)
    assert result["found"] is False
    assert "error" in result


# === password.py ===


def test_is_valid_sha1():
    from ioc.password import is_valid_sha1

    assert is_valid_sha1("a" * 40) is True
    assert is_valid_sha1("A94A8FE5CCB19BA61C4C0873D391E987982FBBD3") is True


def test_is_valid_sha1_invalid():
    from ioc.password import is_valid_sha1

    assert is_valid_sha1("a" * 39) is False  # too short
    assert is_valid_sha1("a" * 41) is False  # too long
    assert is_valid_sha1("g" * 40) is False  # non-hex
    assert is_valid_sha1("") is False
    assert is_valid_sha1("abcde") is False  # 5 chars (old prefix format)


def test_query_pwned_hash_found():
    from ioc.password import query_pwned_hash

    # SHA1 of "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    sha1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
    suffix = sha1[5:]  # E4C9B93F3F0682250B6CF8331B7EE68FD8
    mock_resp = MagicMock()
    mock_resp.text = (
        f"0018A45C4D1DEF81644B54AB7F969B88D65:23\n{suffix}:3861493\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:7\n"
    )
    mock_resp.raise_for_status = MagicMock()
    with patch("ioc.password._client.get", return_value=mock_resp):
        result = query_pwned_hash(sha1)
    assert result["found"] is True
    assert result["breach_count"] == 3861493
    assert result["hash_prefix"] == "5BAA6"


def test_query_pwned_hash_not_found():
    from ioc.password import query_pwned_hash

    sha1 = "a" * 40
    mock_resp = MagicMock()
    mock_resp.text = "0018A45C4D1DEF81644B54AB7F969B88D65:23\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:7\n"
    mock_resp.raise_for_status = MagicMock()
    with patch("ioc.password._client.get", return_value=mock_resp):
        result = query_pwned_hash(sha1)
    assert result["found"] is False
    assert result["breach_count"] == 0


def test_query_pwned_hash_timeout():
    from ioc.password import query_pwned_hash

    with patch("ioc.password._client.get", side_effect=httpx.ConnectTimeout("timeout")):
        result = query_pwned_hash("a" * 40)
    assert result["found"] is False
    assert "error" in result


# === API endpoint tests (via TestClient) ===


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from main import app

    return TestClient(app, raise_server_exceptions=False)


# --- /v1/ioc/{indicator} ---


def test_ioc_ip_endpoint(client):
    with (
        patch("ioc.routes.query_threatfox", return_value={"found": False}),
        patch("ioc.routes.query_feodo", return_value={"found": False}),
        patch("ioc.routes.check_urlhaus", return_value={"urlhaus_status": "clean", "url_count": 0, "urls_online": 0}),
    ):
        resp = client.get("/v1/ioc/8.8.8.8")
    assert resp.status_code == 200
    data = resp.json()
    assert data["indicator"] == "8.8.8.8"
    assert data["type"] == "ip"
    assert data["threat_level"] == "none"
    assert "threatfox" in data["sources"]
    assert "feodo" in data["sources"]


def test_ioc_domain_endpoint(client):
    with (
        patch("ioc.routes.query_threatfox", return_value={"found": False}),
        patch("ioc.routes.check_urlhaus", return_value={"urlhaus_status": "clean", "url_count": 0, "urls_online": 0}),
    ):
        resp = client.get("/v1/ioc/evil.com")
    assert resp.status_code == 200
    data = resp.json()
    assert data["type"] == "domain"


def test_ioc_hash_endpoint(client):
    with patch(
        "ioc.routes.query_threatfox",
        return_value={"found": True, "malware": "Emotet", "threat_type": "payload", "tags": ["trojan"]},
    ):
        resp = client.get("/v1/ioc/" + "a" * 64)
    assert resp.status_code == 200
    data = resp.json()
    assert data["type"] == "hash"
    assert data["threat_level"] == "medium"


def test_ioc_url_endpoint(client):
    with (
        patch("ioc.routes.query_threatfox", return_value={"found": False}),
        patch("ioc.routes.check_urlhaus", return_value={"urlhaus_status": "clean", "url_count": 0, "urls_online": 0}),
    ):
        resp = client.get("/v1/ioc/http://evil.com/payload.exe")
    assert resp.status_code == 200
    data = resp.json()
    assert data["type"] == "url"


def test_ioc_url_ssrf_localhost(client):
    """URL IOC with localhost IP should be rejected with 400."""
    resp = client.get("/v1/ioc/http://127.0.0.1/malware.exe")
    assert resp.status_code == 400


def test_ioc_threatfox_test_tag_caps_to_low(client):
    """ThreatFox honeypot tags (test/example/demo) must cap threat_level to 'low'
    even when multiple sources report found=True (false-positive guard)."""
    with (
        patch(
            "ioc.routes.query_threatfox",
            return_value={"found": True, "malware": "Sample", "threat_type": "test", "tags": ["test", "appleseed"]},
        ),
        patch("ioc.routes.check_urlhaus", return_value={"urlhaus_status": "online", "url_count": 1, "urls_online": 1}),
    ):
        resp = client.get("/v1/ioc/example.com")
    assert resp.status_code == 200
    data = resp.json()
    # Without cap this would be 'high' (2 sources found). Test tag forces 'low'.
    assert data["threat_level"] == "low"
    assert "capped" in data["summary"].lower()


def test_ioc_real_malware_tags_unchanged(client):
    """Regression guard: real malware tags (banker, trojan) must NOT trigger the cap;
    threat_level should remain 'high' when 2+ sources hit."""
    with (
        patch(
            "ioc.routes.query_threatfox",
            return_value={
                "found": True,
                "malware": "Emotet",
                "threat_type": "botnet_cc",
                "tags": ["banker", "trojan"],
            },
        ),
        patch("ioc.routes.check_urlhaus", return_value={"urlhaus_status": "online", "url_count": 5, "urls_online": 3}),
    ):
        resp = client.get("/v1/ioc/badactor.example")
    assert resp.status_code == 200
    data = resp.json()
    assert data["threat_level"] == "high"
    assert "capped" not in data["summary"].lower()


def test_ioc_url_ssrf_metadata(client):
    """URL IOC with cloud metadata IP should be rejected with 400."""
    resp = client.get("/v1/ioc/http://169.254.169.254/latest/meta-data")
    assert resp.status_code == 400


def test_ioc_url_ssrf_private_10(client):
    """URL IOC with RFC1918 10.x host should be rejected with 400."""
    resp = client.get("/v1/ioc/http://10.0.0.1/internal")
    assert resp.status_code == 400


def test_ioc_url_public_host_calls_urlhaus(client):
    """URL IOC with public host should still call URLhaus."""
    with (
        patch("ioc.routes.query_threatfox", return_value={"found": False}),
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}),
    ):
        resp = client.get("/v1/ioc/http://evil.com/payload.exe")
    assert resp.status_code == 200
    assert "urlhaus" in resp.json()["sources"]


def test_ioc_url_empty_host(client):
    """URL IOC with empty/missing host should not crash."""
    with patch("ioc.routes.query_threatfox", return_value={"found": False}):
        # "http://" has empty hostname
        resp = client.get("/v1/ioc/http://")
    # Should return 200 (url type detected) or 400 — not 500
    assert resp.status_code in (200, 400)


def test_ioc_ip_private_rejected(client):
    """Private IP as IOC indicator should be rejected with 400."""
    resp = client.get("/v1/ioc/192.168.1.1")
    assert resp.status_code == 400
    assert "Private" in resp.json()["error"]["message"]


def test_ioc_ip_loopback_rejected(client):
    """Loopback IP as IOC indicator should be rejected with 400."""
    resp = client.get("/v1/ioc/127.0.0.1")
    assert resp.status_code == 400


def test_ioc_url_ssrf_hostname_resolves_private(client):
    """URL with hostname that resolves to private IP should be rejected with 400."""
    fake_addr = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
    with patch("ioc.routes.socket.getaddrinfo", return_value=fake_addr):
        resp = client.get("/v1/ioc/http://localhost/admin")
    assert resp.status_code == 400


def test_ioc_invalid_indicator(client):
    resp = client.get("/v1/ioc/not_valid_ioc")
    assert resp.status_code == 400


def test_ioc_threat_level_high(client):
    with (
        patch("ioc.routes.query_threatfox", return_value={"found": True, "malware": "Cobalt Strike"}),
        patch("ioc.routes.query_feodo", return_value={"found": True, "malware": "QakBot"}),
        patch("ioc.routes.check_urlhaus", return_value={"urlhaus_status": "clean", "url_count": 0, "urls_online": 0}),
    ):
        resp = client.get("/v1/ioc/1.2.3.4")
    assert resp.status_code == 200
    assert resp.json()["threat_level"] == "high"


def test_ioc_lookup_verdict(client):
    with (
        patch("ioc.routes.query_threatfox", return_value={"found": False}),
        patch("ioc.routes.query_feodo", return_value={"found": False}),
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}),
    ):
        resp = client.get("/v1/ioc/8.8.8.8")
    assert resp.status_code == 200
    body = resp.json()
    assert "verdict" in body
    v = body["verdict"]
    assert v["deterministic"] is True
    assert set(v["falsifiable_fields"]) >= {"type", "threat_level", "sources"}
    assert v["data_age_seconds"] == 0
    assert set(v["sources_queried"]) >= {"threatfox", "urlhaus"}
    assert v["sources_unavailable"] == []
    assert v["completeness"] == "complete"


def test_ioc_lookup_verdict_partial_on_source_failure(client):
    with (
        patch("ioc.routes.query_threatfox", side_effect=TimeoutError("timeout")),
        patch("ioc.routes.query_feodo", return_value={"found": False}),
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}),
    ):
        resp = client.get("/v1/ioc/8.8.8.8")
    assert resp.status_code == 200
    v = resp.json()["verdict"]
    assert v["completeness"] == "partial"
    assert "sources_queried" in v
    assert isinstance(v["sources_queried"], list)
    assert len(v["sources_queried"]) >= 1
    assert "threatfox" in v["sources_unavailable"]


# --- Per-type source coverage (Bug #8: docstring honesty) ---


def test_ioc_lookup_hash_queries_only_threatfox(client):
    """Hash IOCs only run ThreatFox — Feodo and URLhaus do not index hashes."""
    with (
        patch("ioc.routes.query_threatfox", return_value={"found": False}) as tf,
        patch("ioc.routes.query_feodo", return_value={"found": False}) as feodo,
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}) as urlhaus,
    ):
        resp = client.get("/v1/ioc/" + "a" * 64)
    assert resp.status_code == 200
    body = resp.json()
    assert body["type"] == "hash"
    queried = set(body["verdict"]["sources_queried"])
    assert queried == {"threatfox"}, f"hash should only query threatfox, got {queried}"
    assert tf.called
    assert not feodo.called
    assert not urlhaus.called
    assert set(body["sources"].keys()) == {"threatfox"}


def test_ioc_lookup_ip_queries_threatfox_feodo_urlhaus_tor(client):
    """IP IOCs run ThreatFox + Feodo + URLhaus + Tor exit cache (Bug I5).
    The local Tor cache is a free in-memory check that ip_lookup already
    consults — adding it here closes the asymmetry where a SOC agent
    triaging an IP IOC could not see Tor membership without a second
    ip_lookup call."""
    with (
        patch("ioc.routes.query_threatfox", return_value={"found": False}),
        patch("ioc.routes.query_feodo", return_value={"found": False}),
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}),
        patch("ioc.routes.check_tor_exit", return_value=False),
        patch("ioc.routes.tor_cache_status", return_value="ok"),
    ):
        resp = client.get("/v1/ioc/8.8.8.8")
    assert resp.status_code == 200
    body = resp.json()
    queried = set(body["verdict"]["sources_queried"])
    assert queried == {"threatfox", "feodo", "urlhaus", "tor"}, f"IP should query all 4, got {queried}"
    assert body["sources"]["tor"]["listed"] is False
    assert body["sources"]["tor"]["fetch_status"] == "ok"


def test_ioc_lookup_ip_tor_listed_surfaces_in_summary(client):
    """When the IP is in the Tor exit list, summary mentions it."""
    with (
        patch("ioc.routes.query_threatfox", return_value={"found": False}),
        patch("ioc.routes.query_feodo", return_value={"found": False}),
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}),
        patch("ioc.routes.check_tor_exit", return_value=True),
        patch("ioc.routes.tor_cache_status", return_value="ok"),
    ):
        resp = client.get("/v1/ioc/185.220.101.1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["sources"]["tor"]["listed"] is True
    assert "Tor exit node" in body["summary"]


def test_ioc_lookup_ip_tor_fetch_failed_marks_unavailable(client):
    """If the Tor list fetch was failed/initial, the verdict marks 'tor'
    as unavailable so an agent can tell `listed=false because not in list`
    from `listed=false because we never got the list`."""
    with (
        patch("ioc.routes.query_threatfox", return_value={"found": False}),
        patch("ioc.routes.query_feodo", return_value={"found": False}),
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}),
        patch("ioc.routes.check_tor_exit", return_value=False),
        patch("ioc.routes.tor_cache_status", return_value="failed"),
    ):
        resp = client.get("/v1/ioc/8.8.8.8")
    assert resp.status_code == 200
    body = resp.json()
    assert "tor" in body["verdict"]["sources_unavailable"]


def test_ioc_lookup_domain_does_not_query_tor(client):
    """Domain IOCs do not run the Tor cache lookup (IP-only signal)."""
    with (
        patch("ioc.routes.query_threatfox", return_value={"found": False}),
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}),
        patch("ioc.routes.check_tor_exit") as mock_tor,
    ):
        resp = client.get("/v1/ioc/evil.com")
    assert resp.status_code == 200
    queried = set(resp.json()["verdict"]["sources_queried"])
    assert "tor" not in queried
    assert not mock_tor.called


def test_ioc_lookup_domain_queries_threatfox_and_urlhaus_no_feodo(client):
    """Domain IOCs run ThreatFox + URLhaus — Feodo is IP-only."""
    with (
        patch("ioc.routes.query_threatfox", return_value={"found": False}),
        patch("ioc.routes.query_feodo", return_value={"found": False}) as feodo,
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}),
    ):
        resp = client.get("/v1/ioc/evil.com")
    assert resp.status_code == 200
    body = resp.json()
    queried = set(body["verdict"]["sources_queried"])
    assert queried == {"threatfox", "urlhaus"}, f"domain should query 2, got {queried}"
    assert not feodo.called


def test_ioc_lookup_second_call_served_from_cache(client):
    """Second call for same indicator must skip all upstream feeds."""
    with (
        patch("ioc.routes.query_threatfox", return_value={"found": False}) as tf,
        patch("ioc.routes.query_feodo", return_value={"found": False}),
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}),
        patch("ioc.routes.check_tor_exit", return_value=False),
        patch("ioc.routes.tor_cache_status", return_value="ok"),
    ):
        r1 = client.get("/v1/ioc/8.8.8.8")
        r2 = client.get("/v1/ioc/8.8.8.8")
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json() == r2.json()
    assert tf.call_count == 1, "ThreatFox must only fire on cold call"


def test_ioc_lookup_cache_segregates_by_indicator(client):
    """Distinct indicators must produce distinct cache entries."""
    with (
        patch("ioc.routes.query_threatfox", return_value={"found": False}) as tf,
        patch("ioc.routes.query_feodo", return_value={"found": False}),
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}),
        patch("ioc.routes.check_tor_exit", return_value=False),
        patch("ioc.routes.tor_cache_status", return_value="ok"),
    ):
        client.get("/v1/ioc/8.8.8.8")
        client.get("/v1/ioc/1.1.1.1")
    assert tf.call_count == 2


# --- /v1/hash/{hash} ---


def test_hash_valid_sha256(client):
    with patch(
        "ioc.routes.query_malwarebazaar",
        return_value={
            "found": True,
            "malware_family": "AgentTesla",
            "file_type": "exe",
            "file_size": 245760,
            "first_seen": "2024-03-15",
            "tags": ["stealer"],
            "file_name": "test.exe",
        },
    ):
        resp = client.get("/v1/hash/" + "a" * 64)
    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is True
    assert data["hash_type"] == "sha256"
    assert data["malware_family"] == "AgentTesla"


def test_hash_valid_md5(client):
    with patch("ioc.routes.query_malwarebazaar", return_value={"found": False}):
        resp = client.get("/v1/hash/" + "b" * 32)
    assert resp.status_code == 200
    assert resp.json()["hash_type"] == "md5"
    assert resp.json()["found"] is False


def test_hash_valid_sha1(client):
    with patch("ioc.routes.query_malwarebazaar", return_value={"found": False}):
        resp = client.get("/v1/hash/" + "c" * 40)
    assert resp.status_code == 200
    assert resp.json()["hash_type"] == "sha1"


def test_hash_invalid_length(client):
    resp = client.get("/v1/hash/" + "a" * 50)
    assert resp.status_code == 400


def test_hash_non_hex(client):
    resp = client.get("/v1/hash/" + "g" * 64)
    assert resp.status_code == 400


def test_hash_not_found(client):
    with patch("ioc.routes.query_malwarebazaar", return_value={"found": False}):
        resp = client.get("/v1/hash/" + "d" * 64)
    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is False
    assert "No malware data" in data["summary"]


# --- /v1/password/{sha1_hash} ---


def test_password_found(client):
    sha1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
    suffix = sha1[5:]
    mock_resp = MagicMock()
    mock_resp.text = f"0018A45C4D1DEF81644B54AB7F969B88D65:23\n{suffix}:9999\n"
    mock_resp.raise_for_status = MagicMock()
    with patch("ioc.password._client.get", return_value=mock_resp):
        resp = client.get(f"/v1/password/{sha1}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is True
    assert data["breach_count"] == 9999
    assert "9,999 data breaches" in data["summary"]


def test_password_not_found(client):
    sha1 = "a" * 40
    mock_resp = MagicMock()
    mock_resp.text = "0018A45C4D1DEF81644B54AB7F969B88D65:23\n"
    mock_resp.raise_for_status = MagicMock()
    with patch("ioc.password._client.get", return_value=mock_resp):
        resp = client.get(f"/v1/password/{sha1}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is False
    assert "not been found" in data["summary"]


def test_password_invalid_too_short(client):
    resp = client.get("/v1/password/21B")
    assert resp.status_code == 400


def test_password_invalid_nonhex(client):
    resp = client.get("/v1/password/" + "g" * 40)
    assert resp.status_code == 400


def test_password_upstream_failure(client):
    with patch("ioc.password._client.get", side_effect=httpx.ConnectTimeout("timeout")):
        resp = client.get("/v1/password/" + "a" * 40)
    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is False


# --- /v1/password edge cases ---


def test_password_39_chars_400(client):
    """SHA1 must be exactly 40 hex chars; 39 is rejected."""
    resp = client.get("/v1/password/" + "a" * 39)
    assert resp.status_code == 400


def test_password_41_chars_400(client):
    """SHA1 must be exactly 40 hex chars; 41 is rejected."""
    resp = client.get("/v1/password/" + "a" * 41)
    assert resp.status_code == 400


def test_password_5_char_prefix_400(client):
    """Old k-anonymity prefix format (5 chars) should be rejected — full SHA1 required."""
    resp = client.get("/v1/password/5BAA6")
    assert resp.status_code == 400


# --- /v1/threat/{domain} route tests (IOC module) ---

# --- /v1/phishing/{url} ---


def test_phishing_both_found(client):
    """URL + host both found in URLhaus → high threat."""
    url_resp = MagicMock()
    url_resp.json.return_value = {"query_status": "ok", "threat": "malware_download", "tags": ["elf", "mozi"]}
    url_resp.raise_for_status = MagicMock()
    with (
        patch("ioc.routes._phish_client.post", return_value=url_resp),
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 5, "urls_online": 3}),
    ):
        resp = client.get("/v1/phishing/https://evil.example.com/payload.exe")
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_malicious"] is True
    assert data["host"] == "evil.example.com"
    assert data["urlhaus_url"]["found"] is True
    assert data["urlhaus_url"]["threat"] == "malware_download"
    assert data["urlhaus_host"]["found"] is True
    assert data["urlhaus_host"]["urls_online"] == 3
    assert data["urlhaus_host"]["url_count"] == 5
    assert data["threat_level"] == "high"
    assert "malicious" in data["summary"]


def test_phishing_not_found(client):
    """URL and host both clean → none threat."""
    url_resp = MagicMock()
    url_resp.json.return_value = {"query_status": "no_results"}
    url_resp.raise_for_status = MagicMock()
    with (
        patch("ioc.routes._phish_client.post", return_value=url_resp),
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}),
    ):
        resp = client.get("/v1/phishing/https://safe.example.com/page")
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_malicious"] is False
    assert data["threat_level"] == "none"
    assert "not found" in data["summary"]


def test_phishing_url_only(client):
    """Exact URL found but host clean → medium threat."""
    url_resp = MagicMock()
    url_resp.json.return_value = {"query_status": "ok", "threat": "phishing", "tags": ["phish"]}
    url_resp.raise_for_status = MagicMock()
    with (
        patch("ioc.routes._phish_client.post", return_value=url_resp),
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}),
    ):
        resp = client.get("/v1/phishing/http://compromised.example.com/login")
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_malicious"] is True
    assert data["urlhaus_url"]["found"] is True
    assert data["urlhaus_host"]["found"] is False
    assert data["threat_level"] == "medium"


def test_phishing_host_only(client):
    """Host found but exact URL not listed → medium threat."""
    url_resp = MagicMock()
    url_resp.json.return_value = {"query_status": "no_results"}
    url_resp.raise_for_status = MagicMock()
    with (
        patch("ioc.routes._phish_client.post", return_value=url_resp),
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 2, "urls_online": 1}),
    ):
        resp = client.get("/v1/phishing/https://badhost.example.com/new-path")
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_malicious"] is True
    assert data["urlhaus_url"]["found"] is False
    assert data["urlhaus_host"]["found"] is True
    assert data["threat_level"] == "medium"


def test_phishing_invalid_url(client):
    """URL without http/https prefix → 400."""
    resp = client.get("/v1/phishing/ftp://evil.com/file")
    assert resp.status_code == 400


def test_phishing_private_ip_rejected(client):
    """URL with private IP host → 400 (SSRF prevention)."""
    resp = client.get("/v1/phishing/http://192.168.1.1/admin")
    assert resp.status_code == 400


def test_phishing_urlhaus_url_timeout(client):
    """URLhaus URL lookup timeout → graceful fallback, no 500."""
    with (
        patch("ioc.routes._phish_client.post", side_effect=httpx.ConnectTimeout("timeout")),
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}),
    ):
        resp = client.get("/v1/phishing/https://timeout.example.com/page")
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_malicious"] is False
    assert data["urlhaus_url"]["found"] is False
    assert data["threat_level"] == "none"


def test_phishing_stale_host_only(client):
    """Host has historical url_count > 0 but urls_online == 0 → is_malicious=False, is_stale=True, low."""
    url_resp = MagicMock()
    url_resp.json.return_value = {"query_status": "no_results"}
    url_resp.raise_for_status = MagicMock()
    with (
        patch("ioc.routes._phish_client.post", return_value=url_resp),
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 5, "urls_online": 0}),
    ):
        resp = client.get("/v1/phishing/https://past-incident.example.com/page")
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_malicious"] is False
    assert data["is_stale"] is True
    assert data["urlhaus_host"]["found"] is True
    assert data["urlhaus_host"]["url_count"] == 5
    assert data["urlhaus_host"]["urls_online"] == 0
    assert data["threat_level"] == "low"
    assert "stale historical evidence only" in data["summary"]


def test_phishing_stale_url_offline(client):
    """Exact URL listed but url_status == 'offline' → is_malicious=False, is_stale=True, low."""
    url_resp = MagicMock()
    url_resp.json.return_value = {
        "query_status": "ok",
        "url_status": "offline",
        "threat": "malware_download",
        "tags": ["elf"],
    }
    url_resp.raise_for_status = MagicMock()
    with (
        patch("ioc.routes._phish_client.post", return_value=url_resp),
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}),
    ):
        resp = client.get("/v1/phishing/https://taken-down.example.com/old.exe")
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_malicious"] is False
    assert data["is_stale"] is True
    assert data["urlhaus_url"]["found"] is True
    assert data["urlhaus_url"]["status"] == "offline"
    assert data["threat_level"] == "low"
    assert "stale historical evidence only" in data["summary"]


def test_phishing_active_url_offline_host_stale_medium(client):
    """Exact URL active (online) + host has stale-only evidence → is_malicious=True, threat_level='medium'."""
    url_resp = MagicMock()
    url_resp.json.return_value = {
        "query_status": "ok",
        "url_status": "online",
        "threat": "phishing",
        "tags": ["phish"],
    }
    url_resp.raise_for_status = MagicMock()
    with (
        patch("ioc.routes._phish_client.post", return_value=url_resp),
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 3, "urls_online": 0}),
    ):
        resp = client.get("/v1/phishing/https://compromised.example.com/login")
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_malicious"] is True
    assert data["is_stale"] is False
    assert data["urlhaus_url"]["status"] == "online"
    assert data["threat_level"] == "medium"  # url active, host stale → only one active dimension


def test_phishing_url_status_missing_treated_as_active(client):
    """URLhaus omits url_status → treat as active (conservative), is_malicious=True."""
    url_resp = MagicMock()
    url_resp.json.return_value = {"query_status": "ok", "threat": "phishing", "tags": []}
    url_resp.raise_for_status = MagicMock()
    with (
        patch("ioc.routes._phish_client.post", return_value=url_resp),
        patch("ioc.routes.check_urlhaus", return_value={"url_count": 0, "urls_online": 0}),
    ):
        resp = client.get("/v1/phishing/https://no-status.example.com/page")
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_malicious"] is True
    assert data["urlhaus_url"]["status"] == "unknown"
    assert data["threat_level"] == "medium"


def test_threat_endpoint_clean(client):
    """Threat intel for a clean domain returns 200 with expected fields."""
    with (
        patch("domain.routes._validate_domain_input", return_value=("example.com", "93.184.216.34")),
        patch(
            "domain.routes.check_urlhaus", return_value={"urlhaus_status": "clean", "urls_online": 0, "url_count": 0}
        ),
    ):
        resp = client.get("/v1/threat/example.com")
    assert resp.status_code == 200
    data = resp.json()
    assert data["domain"] == "example.com"
    assert data["url_count"] == 0
    assert "no threats" in data["summary"]


def test_threat_endpoint_listed(client):
    """Threat intel for a listed domain returns 200 with threat details."""
    with (
        patch("domain.routes._validate_domain_input", return_value=("evil.com", "1.2.3.4")),
        patch(
            "domain.routes.check_urlhaus",
            return_value={
                "urlhaus_status": "listed",
                "urls_online": 3,
                "url_count": 5,
                "threat_types": ["malware_download"],
                "tags": [],
                "urls": [],
            },
        ),
    ):
        resp = client.get("/v1/threat/evil.com")
    assert resp.status_code == 200
    data = resp.json()
    assert data["url_count"] == 5
    assert data["urls_online"] == 3
    assert "5 URL" in data["summary"]


# === /v1/iocs/bulk ===


class TestBulkIocLookup:
    """Tests for POST /v1/iocs/bulk"""

    @patch("ioc.routes.check_urlhaus")
    @patch("ioc.routes.query_feodo")
    @patch("ioc.routes.query_threatfox")
    @patch("ioc.routes.detect_indicator_type")
    def test_bulk_ioc_success(self, mock_detect, mock_tf, mock_feodo, mock_urlhaus, client):
        mock_detect.return_value = "ip"
        mock_tf.return_value = {"found": False}
        mock_feodo.return_value = {"found": False}
        mock_urlhaus.return_value = {"urlhaus_status": "not_found"}
        r = client.post("/v1/iocs/bulk", json={"indicators": ["8.8.8.8", "1.1.1.1"]})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 2
        assert data["successful"] == 2
        assert data["partial"] is False

    def test_bulk_ioc_empty_list(self, client):
        """v1.21.0 parity: empty list → 200 + empty results (matches bulk_atlas + bulk_cve)."""
        r = client.post("/v1/iocs/bulk", json={"indicators": []})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 0
        assert data["results"] == []
        assert data["successful"] == 0
        assert data["partial"] is False

    def test_bulk_ioc_over_free_limit(self, client):
        r = client.post("/v1/iocs/bulk", json={"indicators": [f"8.8.8.{i}" for i in range(11)]})
        assert r.status_code == 422

    def test_bulk_ioc_over_max_limit(self, client):
        r = client.post("/v1/iocs/bulk", json={"indicators": [f"8.8.8.{i}" for i in range(51)]})
        assert r.status_code == 422

    @patch("ioc.routes.detect_indicator_type", return_value="unknown")
    def test_bulk_ioc_unknown_type(self, mock_detect, client):
        """v1.21.0: validation rejection → status='invalid_format' (was 'error')."""
        r = client.post("/v1/iocs/bulk", json={"indicators": ["???"]})
        assert r.status_code == 200
        data = r.json()
        assert data["successful"] == 0
        assert data["results"][0]["status"] == "invalid_format"
        assert "Unknown" in data["results"][0]["error"]

    @patch("ioc.routes.detect_indicator_type", return_value="ip")
    def test_bulk_ioc_private_ip(self, mock_detect, client):
        """v1.21.0: private IP rejection → status='invalid_format'."""
        r = client.post("/v1/iocs/bulk", json={"indicators": ["192.168.1.1"]})
        assert r.status_code == 200
        data = r.json()
        assert data["successful"] == 0
        assert data["results"][0]["status"] == "invalid_format"
        assert "Private" in data["results"][0]["error"]

    def test_bulk_ioc_summary_counts_invalid_separately(self, client):
        """v1.21.0: summary counts 'invalid' alongside 'failed'/'timed_out'."""
        # 1 invalid (private IP via real detector) — status='invalid_format', not 'failed'
        r = client.post("/v1/iocs/bulk", json={"indicators": ["10.0.0.1"]})
        assert r.status_code == 200
        data = r.json()
        # Real detector classifies 10.0.0.1 as private IP
        assert data["results"][0]["status"] == "invalid_format"
        assert "invalid" in data["summary"].lower()

    def test_bulk_ioc_response_exposes_invalid_count(self, client):
        """v1.21.0 round-2 review fix: BulkIocResponse.invalid is a separate counter
        (was missing — invalid_format items had no quantitative field). Invariant:
        successful + failed + timed_out + invalid == total."""
        r = client.post("/v1/iocs/bulk", json={"indicators": ["10.0.0.1", "192.168.1.1"]})
        assert r.status_code == 200
        data = r.json()
        assert "invalid" in data
        assert data["invalid"] == 2
        assert data["successful"] == 0
        assert data["failed"] == 0
        assert data["timed_out"] == 0
        assert data["successful"] + data["failed"] + data["timed_out"] + data["invalid"] == data["total"]
        # partial flag now also fires when there are invalid items
        assert data["partial"] is True

    @patch("ratelimit.consume_bulk", return_value=False)
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_FREE_AUTH_CTX)
    def test_bulk_ioc_rate_limit(self, mock_auth, mock_consume, client):
        r = client.post("/v1/iocs/bulk", json={"indicators": [f"8.8.8.{i}" for i in range(5)]})
        assert r.status_code == 429

    @patch("ioc.routes.check_urlhaus")
    @patch("ioc.routes.query_feodo", return_value={"found": False})
    @patch("ioc.routes.query_threatfox", return_value={"found": False})
    @patch("ioc.routes.detect_indicator_type", return_value="ip")
    def test_bulk_ioc_strips_control_chars(self, mock_detect, mock_tf, mock_feodo, mock_urlhaus, client):
        """Indicators with newlines/control chars must be sanitized."""
        mock_urlhaus.return_value = {"urlhaus_status": "not_found"}
        r = client.post("/v1/iocs/bulk", json={"indicators": ["8.8.8.8\n", "8.8.8.8\u202e"]})
        assert r.status_code == 200
        data = r.json()
        for item in data["results"]:
            assert "\n" not in item["indicator"]
            assert "\u202e" not in item["indicator"]

    @patch("ioc.routes.check_urlhaus", return_value={"urlhaus_status": "not_found"})
    @patch("ioc.routes.query_feodo", return_value={"found": False})
    @patch("ioc.routes.query_threatfox", return_value={"found": False})
    @patch("ioc.routes.detect_indicator_type", return_value="ip")
    def test_bulk_ioc_lookup_uses_cleaned_indicator(self, mock_detect, mock_tf, mock_feodo, mock_urlhaus, client):
        """Downstream lookup functions must receive the SANITIZED indicator, not raw input."""
        r = client.post("/v1/iocs/bulk", json={"indicators": ["8.8.8.8\n"]})
        assert r.status_code == 200
        # query_threatfox must have been called with the cleaned indicator
        called_with = mock_tf.call_args.args[0]
        assert "\n" not in called_with
        assert called_with == "8.8.8.8"

    @patch("ioc.routes.check_urlhaus", return_value={"urlhaus_status": "not_found"})
    @patch("ioc.routes.query_feodo", return_value={"found": False})
    @patch("ioc.routes.query_threatfox", return_value={"found": False})
    @patch("ioc.routes.detect_indicator_type", return_value="ip")
    def test_bulk_ioc_deduplicates(self, mock_detect, mock_tf, mock_feodo, mock_urlhaus, client):
        """Duplicate indicators should be deduplicated — only unique ones processed."""
        r = client.post("/v1/iocs/bulk", json={"indicators": ["8.8.8.8", "8.8.8.8", "8.8.8.8"]})
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 1
        assert len(data["results"]) == 1

    @patch("ratelimit.consume_bulk", return_value=False)
    @patch("auth.aauthenticate", new_callable=AsyncMock, return_value=_FREE_AUTH_CTX)
    def test_bulk_ioc_consume_bulk_call_args(self, mock_auth, mock_consume, client):
        """Verify consume_bulk is called with count - 1 (authenticate consumed 1)."""
        r = client.post("/v1/iocs/bulk", json={"indicators": [f"8.8.8.{i}" for i in range(5)]})
        assert r.status_code == 429
        mock_consume.assert_called_once()
        args = mock_consume.call_args.args
        assert args[0] == "api"
        assert args[2] == 4  # count - 1 = 5 - 1 = 4
