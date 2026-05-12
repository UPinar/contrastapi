"""Unit tests for sigma/parser.py — YAML parsing and normalization."""

import pytest
import yaml
from sigma.parser import normalize_cve_tag, parse_sigma_rule


class TestNormalizeCveTag:
    """Tests for CVE tag normalization."""

    def test_cve_dot_format(self):
        """cve.2024.1234 → CVE-2024-1234"""
        assert normalize_cve_tag("cve.2024.1234") == "CVE-2024-1234"

    def test_cve_dash_format(self):
        """cve.2024-1234 → CVE-2024-1234"""
        assert normalize_cve_tag("cve.2024-1234") == "CVE-2024-1234"

    def test_cve_colon_format(self):
        """cve:2024:1234 → CVE-2024-1234"""
        assert normalize_cve_tag("cve:2024:1234") == "CVE-2024-1234"

    def test_cve_uppercase(self):
        """CVE-2024-1234 → CVE-2024-1234"""
        assert normalize_cve_tag("CVE-2024-1234") == "CVE-2024-1234"

    def test_non_cve_tag_returns_none(self):
        """Non-CVE tags return None"""
        assert normalize_cve_tag("attack.t1059") is None
        assert normalize_cve_tag("detection.threat_hunting") is None

    def test_malformed_cve_returns_none(self):
        """CVE tag without valid year-number pattern returns None"""
        assert normalize_cve_tag("cve.abc.def") is None
        assert normalize_cve_tag("cve.2024") is None


class TestParseSigmaRule:
    """Tests for parse_sigma_rule function."""

    def test_parse_minimal_rule(self):
        """Minimal valid rule with required fields only."""
        yaml_text = """
title: Test Rule
id: 12345678-1234-1234-1234-123456789012
detection:
  selection:
    EventID: 4656
  condition: selection
"""
        rule = parse_sigma_rule(yaml_text)
        assert rule.rule_id == "12345678-1234-1234-1234-123456789012"
        assert rule.title == "Test Rule"
        assert rule.status == "test"  # default
        assert rule.level == "medium"  # default
        assert rule.description is None
        assert rule.author is None
        assert rule.tags == []
        assert rule.detection.condition == "selection"

    def test_parse_full_rule(self):
        """Full rule with all fields present."""
        yaml_text = """
title: Full Test Rule
id: 87654321-4321-4321-4321-210987654321
status: stable
level: high
description: This is a test description.
author: Test Author
date: 2024-01-15
modified: 2024-05-12
tags:
  - attack.t1059
  - attack.t1059.001
  - cve.2024.5678
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection_1:
    Image|endswith: powershell.exe
  selection_2:
    CommandLine|contains: IEX
  condition: selection_1 and selection_2
references:
  - https://example.com
falsepositives:
  - Legitimate scripts
"""
        rule = parse_sigma_rule(yaml_text)
        assert rule.title == "Full Test Rule"
        assert rule.status == "stable"
        assert rule.level == "high"
        assert rule.description == "This is a test description."
        assert rule.author == "Test Author"
        assert "attack.t1059" in rule.tags
        assert "CVE-2024-5678" in rule.tags  # Normalized
        assert rule.logsource["product"] == "windows"
        assert "https://example.com" in rule.references
        assert "Legitimate scripts" in rule.falsepositives

    def test_missing_id_raises_error(self):
        """Rule without 'id' field raises ValueError."""
        yaml_text = """
title: No ID Rule
detection:
  selection:
    EventID: 4656
  condition: selection
"""
        with pytest.raises(ValueError, match="'id' field is required"):
            parse_sigma_rule(yaml_text)

    def test_missing_title_raises_error(self):
        """Rule without 'title' field raises ValueError."""
        yaml_text = """
id: 12345678-1234-1234-1234-123456789012
detection:
  selection:
    EventID: 4656
  condition: selection
"""
        with pytest.raises(ValueError, match="'title' field is required"):
            parse_sigma_rule(yaml_text)

    def test_missing_detection_raises_error(self):
        """Rule without 'detection' field raises ValueError."""
        yaml_text = """
title: No Detection Rule
id: 12345678-1234-1234-1234-123456789012
"""
        with pytest.raises(ValueError, match="'detection' field is required"):
            parse_sigma_rule(yaml_text)

    def test_malformed_yaml_raises_error(self):
        """Malformed YAML raises yaml.YAMLError."""
        yaml_text = """
title: Broken YAML
id: 12345678-1234-1234-1234-123456789012
broken: [unclosed
"""
        with pytest.raises(yaml.YAMLError):
            parse_sigma_rule(yaml_text)

    def test_no_tags_defaults_to_empty_list(self):
        """Rule without 'tags' field defaults to empty list."""
        yaml_text = """
title: No Tags Rule
id: 12345678-1234-1234-1234-123456789012
detection:
  selection:
    EventID: 4656
  condition: selection
"""
        rule = parse_sigma_rule(yaml_text)
        assert rule.tags == []

    def test_no_logsource_defaults_to_empty_dict(self):
        """Rule without 'logsource' field defaults to empty dict."""
        yaml_text = """
title: No Logsource Rule
id: 12345678-1234-1234-1234-123456789012
detection:
  selection:
    EventID: 4656
  condition: selection
"""
        rule = parse_sigma_rule(yaml_text)
        assert rule.logsource == {}

    def test_references_as_string_converted_to_list(self):
        """'references' as a single string is converted to a list."""
        yaml_text = """
title: String Ref Rule
id: 12345678-1234-1234-1234-123456789012
references: https://example.com
detection:
  selection:
    EventID: 4656
  condition: selection
"""
        rule = parse_sigma_rule(yaml_text)
        assert rule.references == ["https://example.com"]

    def test_falsepositives_as_string_converted_to_list(self):
        """'falsepositives' as a single string is converted to a list."""
        yaml_text = """
title: String FP Rule
id: 12345678-1234-1234-1234-123456789012
falsepositives: Admin activity
detection:
  selection:
    EventID: 4656
  condition: selection
"""
        rule = parse_sigma_rule(yaml_text)
        assert rule.falsepositives == ["Admin activity"]

    def test_multiple_technique_tags(self):
        """Rule with multiple attack.t#### tags all preserved."""
        yaml_text = """
title: Multi-Technique Rule
id: 12345678-1234-1234-1234-123456789012
tags:
  - attack.t1059
  - attack.t1560.001
detection:
  selection:
    EventID: 4656
  condition: selection
"""
        rule = parse_sigma_rule(yaml_text)
        assert "attack.t1059" in rule.tags
        assert "attack.t1560.001" in rule.tags

    def test_detection_summary_counts_selections(self):
        """detection_summary reflects number of selection blocks."""
        yaml_text = """
title: Multi-Selection Rule
id: 12345678-1234-1234-1234-123456789012
detection:
  selection_a:
    Field1: value1
  selection_b:
    Field2: value2
  selection_c:
    Field3: value3
  condition: all of selection_*
"""
        rule = parse_sigma_rule(yaml_text)
        assert "3 selections" in rule.detection_summary
        assert "all of selection_*" in rule.detection_summary

    def test_cve_tag_normalization_in_tags(self):
        """CVE tags in the tags list are normalized."""
        yaml_text = """
title: CVE Normalization Rule
id: 12345678-1234-1234-1234-123456789012
tags:
  - cve.2024.1234
  - cve.2024-5678
  - cve:2024:9999
detection:
  selection:
    EventID: 4656
  condition: selection
"""
        rule = parse_sigma_rule(yaml_text)
        assert "CVE-2024-1234" in rule.tags
        assert "CVE-2024-5678" in rule.tags
        assert "CVE-2024-9999" in rule.tags

    def test_vendor_extension_fields_dropped(self):
        """Attacker-crafted YAML with unknown fields must not propagate to the
        serialized SigmaRule (CWE-116). extra='ignore' on the model drops them
        at construction time so MCP responses cannot leak smuggled keys to an
        LLM agent."""
        yaml_text = """
title: Vendor Extension Probe
id: 12345678-1234-1234-1234-123456789012
detection:
  selection:
    EventID: 4656
  condition: selection
x_malicious_field: should_be_dropped
custom_vendor_key: {nested: payload}
"""
        rule = parse_sigma_rule(yaml_text)
        dumped = rule.model_dump()
        assert "x_malicious_field" not in dumped
        assert "custom_vendor_key" not in dumped
        assert rule.title == "Vendor Extension Probe"
