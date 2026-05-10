"""Unit tests for cve.cvss_parser.parse_cvss_vector."""

import pytest
from cve.cvss_parser import parse_cvss_vector


def test_parse_canonical_critical_vector():
    parsed = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert parsed["version"] == "3.1"
    assert parsed["base_score"] == 9.8
    assert parsed["base_severity"] == "CRITICAL"
    assert parsed["metrics"]["attack_vector"] == "NETWORK"
    assert parsed["metrics"]["attack_complexity"] == "LOW"
    assert parsed["metrics"]["privileges_required"] == "NONE"
    assert parsed["metrics"]["scope"] == "UNCHANGED"
    assert parsed["metrics"]["confidentiality_impact"] == "HIGH"


def test_parse_v3_0_vector():
    parsed = parse_cvss_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:N")
    assert parsed["version"] == "3.0"
    assert parsed["metrics"]["attack_vector"] == "LOCAL"


def test_parse_strips_whitespace():
    parsed = parse_cvss_vector("  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  ")
    assert parsed["base_score"] == 9.8


def test_v2_vector_rejected_with_clear_message():
    with pytest.raises(ValueError, match="Unrecognized CVSS vector format"):
        parse_cvss_vector("AV:N/AC:L/Au:N/C:C/I:C/A:C")


def test_empty_vector_rejected():
    with pytest.raises(ValueError, match="empty"):
        parse_cvss_vector("")


def test_malformed_v3_vector_rejected():
    with pytest.raises(ValueError, match="Invalid CVSS v3 vector"):
        parse_cvss_vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


def test_low_severity_vector():
    parsed = parse_cvss_vector("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
    assert parsed["base_severity"] in {"LOW", "MEDIUM"}
    assert parsed["base_score"] < 5.0


def test_temporal_environmental_optional():
    parsed = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    # When no explicit temporal/environmental metrics, scores equal base
    assert parsed["temporal_score"] == 9.8
    assert parsed["environmental_score"] == 9.8
