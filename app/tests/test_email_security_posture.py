"""Tests for /v1/email/security-posture/{domain} + parsers."""

from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


class TestSpfParser:
    def test_spf_strict(self):
        from domain.recon import _parse_spf

        result = _parse_spf("v=spf1 include:_spf.google.com -all")
        assert result["present"] is True
        assert result["all_policy"] == "strict"

    def test_spf_permissive(self):
        from domain.recon import _parse_spf

        result = _parse_spf("v=spf1 +all")
        assert result["all_policy"] == "permissive"
        assert any(f["severity"] == "critical" for f in result["findings"])

    def test_spf_none(self):
        from domain.recon import _parse_spf

        result = _parse_spf(None)
        assert result["present"] is False


class TestDmarcParser:
    def test_dmarc_reject(self):
        from domain.recon import _parse_dmarc

        result = _parse_dmarc("v=DMARC1; p=reject; aspf=s; adkim=s")
        assert result["present"] is True
        assert result["policy"] == "reject"

    def test_dmarc_none_monitoring(self):
        from domain.recon import _parse_dmarc

        result = _parse_dmarc("v=DMARC1; p=none")
        assert result["policy"] == "none"
        assert any("monitoring" in f["description"].lower() for f in result["findings"])

    def test_dmarc_missing(self):
        from domain.recon import _parse_dmarc

        result = _parse_dmarc(None)
        assert result["present"] is False


class TestDkimProber:
    def test_dkim_verified(self):
        from domain.recon import _probe_dkim_posture

        with patch("domain.recon.dns.resolver.Resolver") as mock_res:
            r = MagicMock()
            rec = MagicMock()
            rec.strings = [b"v=DKIM1; p=MIGf..."]
            r.resolve = lambda qname, rdtype: (
                [rec] if "google._domainkey" in qname else (_ for _ in ()).throw(Exception())
            )
            r.timeout = 2
            r.lifetime = 3
            mock_res.return_value = r
            result = _probe_dkim_posture("example.com", timeout=8)
            assert result["status"] == "verified"

    def test_dkim_unverifiable(self):
        from domain.recon import _probe_dkim_posture

        with patch("domain.recon.dns.resolver.Resolver") as mock_res:
            r = MagicMock()
            r.timeout = 2
            r.lifetime = 3
            r.resolve = MagicMock(side_effect=Exception())
            mock_res.return_value = r
            result = _probe_dkim_posture("example.com", timeout=8)
            assert result["status"] == "unverifiable"


class TestSelectorValidation:
    def test_selectors_capped_at_10(self):
        from domain.recon import _normalize_dkim_selectors

        result = _normalize_dkim_selectors(",".join(f"sel{i}" for i in range(50)))
        assert result is not None and len(result) == 10

    def test_invalid_selectors_filtered(self):
        from domain.recon import _normalize_dkim_selectors

        result = _normalize_dkim_selectors("ok1,bad.sel,../etc/passwd,GOOD2,sql' OR 1=1")
        assert result == ["ok1", "good2"]

    def test_selectors_none_passthrough(self):
        from domain.recon import _normalize_dkim_selectors

        assert _normalize_dkim_selectors(None) is None
        assert _normalize_dkim_selectors("") is None
        assert _normalize_dkim_selectors("!@#$,...") is None

    def test_edge_hyphens_rejected(self):
        """RFC 1035 LDH: hyphens forbidden at label edges."""
        from domain.recon import _normalize_dkim_selectors

        result = _normalize_dkim_selectors("-leading,trailing-,-both-,mid-ok")
        assert result == ["mid-ok"]

    def test_label_length_boundary(self):
        from domain.recon import _normalize_dkim_selectors

        sel_63 = "a" * 63
        sel_64 = "a" * 64
        result = _normalize_dkim_selectors(f"{sel_63},{sel_64}")
        assert result == [sel_63]


class TestScoring:
    def test_score_aplus(self):
        from domain.recon import _score_email_security_posture

        spf = {"present": True, "all_policy": "strict", "lookup_count": 5, "findings": []}
        dmarc = {
            "present": True,
            "policy": "reject",
            "pct": 100,
            "aspf": "s",
            "adkim": "s",
            "rua_uris": ["x"],
            "ruf_uris": [],
            "findings": [],
        }
        dkim = {"status": "verified", "verified_selectors": ["google"], "findings": []}
        result = _score_email_security_posture(spf, dmarc, dkim)
        assert result["posture_score"] >= 95
        assert result["posture_grade"] == "A+"

    def test_score_f(self):
        from domain.recon import _score_email_security_posture

        spf = {"present": False, "findings": []}
        dmarc = {"present": False, "findings": []}
        dkim = {"status": "unverifiable", "verified_selectors": [], "findings": []}
        result = _score_email_security_posture(spf, dmarc, dkim)
        assert result["posture_score"] < 25
        assert result["posture_grade"] == "F"
