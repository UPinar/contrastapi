"""Unit tests for sigma/index.py — in-memory Sigma rule indexer."""

import pytest
from sigma.index import SigmaRuleIndex


@pytest.fixture
def sample_rules_dir(tmp_path):
    """Create a temporary directory with sample Sigma rules."""
    sigma_dir = tmp_path / "sigma"
    sigma_dir.mkdir()

    # Rule 1: Process creation, attack.t1059
    rule1 = """
title: Process Creation - PowerShell
id: 195e1b9d-bfc2-4ffa-ab4e-35aef69815f8
status: stable
level: medium
description: Detects suspicious PowerShell execution.
author: Test
date: 2024-01-15
tags:
  - attack.execution
  - attack.t1059
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection:
    Image|endswith: powershell.exe
  condition: selection
"""
    (sigma_dir / "rule1.yml").write_text(rule1)

    # Rule 2: AWS IAM, CVE tags
    rule2 = """
title: AWS CloudTrail - IAM Activity
id: 98765432-abcd-ef01-2345-6789abcdef01
status: test
level: high
description: Detects suspicious IAM privilege escalation.
author: Test
tags:
  - attack.privilege_escalation
  - attack.t1548
  - cve.2024.1234
  - cve.2024-5678
logsource:
  product: aws
  service: cloudtrail
  category: iam_activity
detection:
  selection:
    eventSource: iam.amazonaws.com
  condition: selection
"""
    (sigma_dir / "rule2.yml").write_text(rule2)

    # Rule 3: No tags
    rule3 = """
title: Generic Process Rule
id: cccccccc-dddd-eeee-ffff-000000000001
status: experimental
level: low
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains: test
  condition: selection
"""
    (sigma_dir / "rule3.yml").write_text(rule3)

    # Rule 4: Deprecated (should be excluded by default)
    rule4 = """
title: Deprecated Old Rule
id: 12345678-90ab-cdef-1234-567890abcdef
status: deprecated
level: informational
tags:
  - attack.t1001
logsource:
  product: windows
  category: file_access
detection:
  selection:
    EventID: 4656
  condition: selection
"""
    (sigma_dir / "rule4.yml").write_text(rule4)

    return sigma_dir


class TestSigmaRuleIndex:
    """Tests for SigmaRuleIndex."""

    def test_load_from_directory_excludes_deprecated(self, sample_rules_dir):
        """Load directory with exclude_deprecated=True skips deprecated rules."""
        index = SigmaRuleIndex()
        count = index.load_from_directory(sample_rules_dir, exclude_deprecated=True)
        assert count == 3  # Only rule1, rule2, rule3 loaded
        assert "12345678-90ab-cdef-1234-567890abcdef" not in index.rules

    def test_load_from_directory_includes_deprecated(self, sample_rules_dir):
        """Load directory with exclude_deprecated=False includes deprecated rules."""
        index = SigmaRuleIndex()
        count = index.load_from_directory(sample_rules_dir, exclude_deprecated=False)
        assert count == 4  # All rules loaded
        assert "12345678-90ab-cdef-1234-567890abcdef" in index.rules

    def test_lookup_by_id_returns_rule(self, sample_rules_dir):
        """lookup_by_id returns the correct rule or None."""
        index = SigmaRuleIndex()
        index.load_from_directory(sample_rules_dir, exclude_deprecated=True)

        rule = index.lookup_by_id("195e1b9d-bfc2-4ffa-ab4e-35aef69815f8")
        assert rule is not None
        assert rule.title == "Process Creation - PowerShell"

        missing = index.lookup_by_id("nonexistent-id")
        assert missing is None

    def test_lookup_by_technique_exact_match(self, sample_rules_dir):
        """lookup_by_technique with T1059 finds rules tagged with attack.t1059."""
        index = SigmaRuleIndex()
        index.load_from_directory(sample_rules_dir, exclude_deprecated=True)

        rules = index.lookup_by_technique("T1059")
        assert len(rules) == 1
        assert rules[0].title == "Process Creation - PowerShell"

    def test_lookup_by_technique_prefix_match(self, sample_rules_dir):
        """lookup_by_technique with T15 finds T1548 (prefix match)."""
        index = SigmaRuleIndex()
        index.load_from_directory(sample_rules_dir, exclude_deprecated=True)

        rules = index.lookup_by_technique("T15")
        assert len(rules) == 1
        assert "attack.t1548" in rules[0].tags

    def test_lookup_by_technique_case_insensitive(self, sample_rules_dir):
        """lookup_by_technique normalizes to uppercase."""
        index = SigmaRuleIndex()
        index.load_from_directory(sample_rules_dir, exclude_deprecated=True)

        rules_upper = index.lookup_by_technique("T1059")
        rules_lower = index.lookup_by_technique("t1059")
        assert len(rules_upper) == len(rules_lower) == 1

    def test_lookup_by_cve(self, sample_rules_dir):
        """lookup_by_cve returns rules tagged with that CVE."""
        index = SigmaRuleIndex()
        index.load_from_directory(sample_rules_dir, exclude_deprecated=True)

        rules = index.lookup_by_cve("CVE-2024-1234")
        assert len(rules) == 1
        assert rules[0].title == "AWS CloudTrail - IAM Activity"

    def test_lookup_by_cve_case_insensitive(self, sample_rules_dir):
        """lookup_by_cve normalizes to uppercase."""
        index = SigmaRuleIndex()
        index.load_from_directory(sample_rules_dir, exclude_deprecated=True)

        rules = index.lookup_by_cve("cve-2024-1234")
        assert len(rules) == 1

    def test_lookup_by_logsource_product_only(self, sample_rules_dir):
        """lookup_by_logsource with product only filters by product."""
        index = SigmaRuleIndex()
        index.load_from_directory(sample_rules_dir, exclude_deprecated=True)

        rules = index.lookup_by_logsource(product="windows")
        assert len(rules) == 1
        assert rules[0].logsource["product"] == "windows"

    def test_lookup_by_logsource_category_only(self, sample_rules_dir):
        """lookup_by_logsource with category only filters by category."""
        index = SigmaRuleIndex()
        index.load_from_directory(sample_rules_dir, exclude_deprecated=True)

        rules = index.lookup_by_logsource(category="process_creation")
        assert len(rules) == 2  # rule1 and rule3

    def test_lookup_by_logsource_product_and_category(self, sample_rules_dir):
        """lookup_by_logsource with both product and category (AND logic)."""
        index = SigmaRuleIndex()
        index.load_from_directory(sample_rules_dir, exclude_deprecated=True)

        rules = index.lookup_by_logsource(product="windows", category="process_creation")
        assert len(rules) == 1
        assert rules[0].title == "Process Creation - PowerShell"

    def test_search_by_text_title_match(self, sample_rules_dir):
        """search_by_text matches rule titles."""
        index = SigmaRuleIndex()
        index.load_from_directory(sample_rules_dir, exclude_deprecated=True)

        rules = index.search_by_text("PowerShell")
        assert len(rules) == 1
        assert "PowerShell" in rules[0].title

    def test_search_by_text_description_match(self, sample_rules_dir):
        """search_by_text matches rule descriptions."""
        index = SigmaRuleIndex()
        index.load_from_directory(sample_rules_dir, exclude_deprecated=True)

        rules = index.search_by_text("suspicious IAM")
        assert len(rules) == 1
        assert "CloudTrail" in rules[0].title

    def test_search_by_text_case_insensitive(self, sample_rules_dir):
        """search_by_text is case-insensitive."""
        index = SigmaRuleIndex()
        index.load_from_directory(sample_rules_dir, exclude_deprecated=True)

        rules_upper = index.search_by_text("POWERSHELL")
        rules_lower = index.search_by_text("powershell")
        assert len(rules_upper) == len(rules_lower) == 1

    def test_filter_by_status_all(self, sample_rules_dir):
        """filter_by_status with 'all' returns all rules."""
        index = SigmaRuleIndex()
        index.load_from_directory(sample_rules_dir, exclude_deprecated=False)

        rules = index.lookup_by_id("195e1b9d-bfc2-4ffa-ab4e-35aef69815f8")
        rules_list = [rules] if rules else []
        filtered = index.filter_by_status(rules_list, "all")
        assert len(filtered) == len(rules_list)

    def test_filter_by_status_stable(self, sample_rules_dir):
        """filter_by_status('stable') returns only stable rules."""
        index = SigmaRuleIndex()
        index.load_from_directory(sample_rules_dir, exclude_deprecated=False)

        all_rules = list(index.rules.values())
        filtered = index.filter_by_status(all_rules, "stable")
        assert len(filtered) == 1
        assert all(r.status == "stable" for r in filtered)

    def test_filter_by_level_all(self, sample_rules_dir):
        """filter_by_level with 'all' returns all rules."""
        index = SigmaRuleIndex()
        index.load_from_directory(sample_rules_dir, exclude_deprecated=True)

        rules = list(index.rules.values())
        filtered = index.filter_by_level(rules, "all")
        assert len(filtered) == len(rules)

    def test_filter_by_level_medium_includes_high(self, sample_rules_dir):
        """filter_by_level('medium') includes medium and high (and up)."""
        index = SigmaRuleIndex()
        index.load_from_directory(sample_rules_dir, exclude_deprecated=True)

        rules = list(index.rules.values())
        filtered = index.filter_by_level(rules, "medium")
        # Should include: medium (rule1) and high (rule2)
        assert len(filtered) == 2
        assert not any(r.level == "low" or r.level == "informational" for r in filtered)

    def test_filter_by_level_critical_includes_only_critical(self, sample_rules_dir):
        """filter_by_level('critical') returns only critical rules."""
        index = SigmaRuleIndex()
        index.load_from_directory(sample_rules_dir, exclude_deprecated=True)

        rules = list(index.rules.values())
        filtered = index.filter_by_level(rules, "critical")
        assert len(filtered) == 0  # No critical rules in fixtures

    def test_rules_without_tags_still_indexed(self, sample_rules_dir):
        """Rules without tags are indexed by rule_id, logsource."""
        index = SigmaRuleIndex()
        index.load_from_directory(sample_rules_dir, exclude_deprecated=True)

        rule = index.lookup_by_id("cccccccc-dddd-eeee-ffff-000000000001")
        assert rule is not None
        assert rule.title == "Generic Process Rule"
        assert rule.tags == []

        # Should still be findable by logsource
        rules = index.lookup_by_logsource(product="linux")
        assert any(r.rule_id == "cccccccc-dddd-eeee-ffff-000000000001" for r in rules)

    def test_malformed_yaml_skipped_silently(self, tmp_path):
        """Malformed YAML files are skipped without raising errors."""
        sigma_dir = tmp_path / "sigma"
        sigma_dir.mkdir()

        # Valid rule
        (sigma_dir / "good.yml").write_text("""
title: Good Rule
id: 11111111-1111-1111-1111-111111111111
detection:
  selection:
    EventID: 4656
  condition: selection
""")

        # Malformed rule
        (sigma_dir / "bad.yml").write_text("""
title: Bad Rule
id: 22222222-2222-2222-2222-222222222222
broken: [unclosed
""")

        index = SigmaRuleIndex()
        count = index.load_from_directory(sigma_dir)
        assert count == 1  # Only good rule loaded
        assert "11111111-1111-1111-1111-111111111111" in index.rules
