"""Unit tests for cve.risk_scorer.compute_risk_score."""

from datetime import UTC, datetime, timedelta

import pytest
from cve.risk_scorer import compute_risk_score


def test_zero_signal_yields_zero():
    r = compute_risk_score(cvss_v3=None, epss_score=None, in_kev=False, has_poc=False)
    assert r.score == 0.0
    assert r.label == "LOW"
    assert r.boosters_applied == []


def test_low_band_pure_low_severity():
    r = compute_risk_score(cvss_v3=3.0, epss_score=0.01, in_kev=False, has_poc=False)
    # base = 3*10*0.20 + 0.01*100*0.35 + 0 + 0 = 6 + 0.35 = 6.35
    assert r.label == "LOW"
    assert r.score == pytest.approx(6.35, abs=0.1)


def test_kev_alone_pushes_to_medium():
    r = compute_risk_score(cvss_v3=5.0, epss_score=0.05, in_kev=True, has_poc=False)
    # base = 5*10*0.20 + 0.05*100*0.35 + 100*0.30 + 0 = 10 + 1.75 + 30 = 41.75
    assert r.label == "MEDIUM"
    assert r.components["in_kev"] is True


def test_critical_with_kev_and_poc_applies_booster():
    r = compute_risk_score(cvss_v3=10.0, epss_score=0.95, in_kev=True, has_poc=True)
    # base = 10*10*0.20 + 0.95*100*0.35 + 100*0.30 + 100*0.15
    #      = 20 + 33.25 + 30 + 15 = 98.25
    # boosters: *1.15 (kev+poc) *1.10 (cvss>=9 and epss>0.7) = *1.265
    # final = min(100, 98.25 * 1.265) = capped at 100
    assert r.score == 100.0
    assert r.label == "CRITICAL"
    assert "kev_with_public_poc" in r.boosters_applied
    assert "critical_severity_high_epss" in r.boosters_applied


def test_recent_publication_applies_5pct_booster():
    recent = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    r = compute_risk_score(cvss_v3=7.0, epss_score=0.10, in_kev=False, has_poc=False, published_at=recent)
    assert "published_within_7_days" in r.boosters_applied


def test_old_publication_skips_recency_booster():
    old = (datetime.now(UTC) - timedelta(days=60)).isoformat()
    r = compute_risk_score(cvss_v3=7.0, epss_score=0.10, in_kev=False, has_poc=False, published_at=old)
    assert "published_within_7_days" not in r.boosters_applied


def test_malformed_published_at_does_not_crash():
    r = compute_risk_score(cvss_v3=7.0, epss_score=0.10, in_kev=False, has_poc=False, published_at="not-a-date")
    assert "published_within_7_days" not in r.boosters_applied


def test_in_kev_dictates_urgency():
    r = compute_risk_score(cvss_v3=5.0, epss_score=0.05, in_kev=True, has_poc=False)
    assert "actively exploited" in r.urgency.lower()


def test_high_cvss_alone_does_not_trigger_critical_booster():
    # CVSS=9.5, EPSS=0.5 — booster condition requires EPSS > 0.7
    r = compute_risk_score(cvss_v3=9.5, epss_score=0.5, in_kev=False, has_poc=False)
    assert "critical_severity_high_epss" not in r.boosters_applied


def test_components_breakdown_present():
    r = compute_risk_score(cvss_v3=8.5, epss_score=0.4, in_kev=True, has_poc=True)
    assert r.components["cvss_v3"] == 8.5
    assert r.components["epss_score"] == 0.4
    assert r.components["in_kev"] is True
    assert r.components["has_public_poc"] is True
    assert "weighted_breakdown" in r.components
    wb = r.components["weighted_breakdown"]
    assert wb["cvss"] == pytest.approx(17.0, abs=0.01)
    assert wb["epss"] == pytest.approx(14.0, abs=0.01)
    assert wb["kev"] == pytest.approx(30.0, abs=0.01)
    assert wb["poc"] == pytest.approx(15.0, abs=0.01)


def test_score_clamped_to_100():
    r = compute_risk_score(cvss_v3=10.0, epss_score=1.0, in_kev=True, has_poc=True)
    assert r.score <= 100.0
