"""In-memory Sigma rule indexer with reverse lookups."""

import logging
from pathlib import Path

from sigma.parser import parse_sigma_rule
from sigma.schemas import SigmaRule

logger = logging.getLogger(__name__)


class SigmaRuleIndex:
    """In-memory index of Sigma rules with reverse lookups.

    Supports searching by:
    - rule_id (UUID)
    - technique (MITRE ATT&CK T-code, with prefix match)
    - cve_id (normalized CVE format)
    - logsource_product + logsource_category
    - freetext (title + description substring match)
    - status + level filtering
    """

    def __init__(self):
        """Initialize empty indexes."""
        self.rules: dict[str, SigmaRule] = {}  # rule_id → rule
        self.technique_index: dict[str, set[str]] = {}  # technique_id → set of rule_ids
        self.cve_index: dict[str, set[str]] = {}  # cve_id → set of rule_ids
        self.product_index: dict[str, set[str]] = {}  # product → set of rule_ids
        self.category_index: dict[str, set[str]] = {}  # category → set of rule_ids

    def load_from_directory(self, path: str | Path, exclude_deprecated: bool = True) -> int:
        """Load all YAML files from directory recursively.

        Args:
            path: Directory containing Sigma YAML rules
            exclude_deprecated: If True, skip rules with status='deprecated'

        Returns:
            Number of rules successfully loaded

        Note:
            Malformed YAML files are skipped with a silent continue (patterns from
            research). Errors are not re-raised to upstream; indexing continues.
        """
        path = Path(path)
        if not path.is_dir():
            return 0

        count = 0
        for yaml_file in path.rglob("*.yml"):
            try:
                yaml_text = yaml_file.read_text(encoding="utf-8")
                rule = parse_sigma_rule(yaml_text)

                if exclude_deprecated and rule.status == "deprecated":
                    continue

                self._add_rule(rule)
                count += 1
            except (MemoryError, SystemExit, KeyboardInterrupt):
                # Never swallow resource-exhaustion or shutdown signals — a
                # crafted YAML bomb is exactly the case we want to surface.
                raise
            except Exception as exc:
                logger.warning("Skipped malformed Sigma rule %s: %s", yaml_file.name, type(exc).__name__)
                continue

        return count

    def _add_rule(self, rule: SigmaRule) -> None:
        """Add a parsed rule to all indexes."""
        rule_id = rule.rule_id

        # Store rule
        self.rules[rule_id] = rule

        # Index by technique (extract attack.t#### tags)
        for tag in rule.tags:
            if tag.lower().startswith("attack.t"):
                # Normalize: attack.t1059 → T1059
                tech = tag.split(".")[-1].upper()
                if tech not in self.technique_index:
                    self.technique_index[tech] = set()
                self.technique_index[tech].add(rule_id)

        # Index by CVE (extract CVE-YYYY-NNNNN tags)
        for tag in rule.tags:
            if tag.startswith("CVE-"):
                if tag not in self.cve_index:
                    self.cve_index[tag] = set()
                self.cve_index[tag].add(rule_id)

        # Index by logsource
        product = (rule.logsource or {}).get("product", "unknown")
        category = (rule.logsource or {}).get("category", "unknown")

        if product not in self.product_index:
            self.product_index[product] = set()
        self.product_index[product].add(rule_id)

        if category not in self.category_index:
            self.category_index[category] = set()
        self.category_index[category].add(rule_id)

    def lookup_by_id(self, rule_id: str) -> SigmaRule | None:
        """Fetch rule by UUID."""
        return self.rules.get(rule_id)

    def lookup_by_technique(self, technique: str, limit: int = 50) -> list[SigmaRule]:
        """Fetch rules by MITRE ATT&CK T-code.

        Supports prefix match: T1059 matches both T1059 and T1059.001.

        Args:
            technique: T-code (e.g., 'T1059', 'T1059.001')
            limit: Max rules returned (capped at 200 to bound JSON payload — CWE-400).

        Returns:
            List of matching SigmaRule objects. Order is unspecified (hash-based
            set iteration); callers needing stable ordering must sort downstream.
        """
        technique = technique.upper()
        limit = max(1, min(limit, 200))
        matching_ids: set[str] = set()

        for tech_key, rule_ids in self.technique_index.items():
            if tech_key.startswith(technique):
                matching_ids.update(rule_ids)

        return [self.rules[rid] for rid in list(matching_ids)[:limit] if rid in self.rules]

    def lookup_by_cve(self, cve_id: str) -> list[SigmaRule]:
        """Fetch rules by CVE ID.

        Args:
            cve_id: Canonical format CVE-YYYY-NNNNN

        Returns:
            List of matching SigmaRule objects
        """
        cve_id = cve_id.upper()
        rule_ids = self.cve_index.get(cve_id, set())
        return [self.rules[rid] for rid in rule_ids if rid in self.rules]

    def lookup_by_logsource(self, product: str | None = None, category: str | None = None) -> list[SigmaRule]:
        """Fetch rules by logsource product and/or category.

        Args:
            product: e.g., 'windows', 'linux', 'aws'
            category: e.g., 'process_creation', 'dns_query'

        Returns:
            List of matching SigmaRule objects (AND logic if both provided)
        """
        if product is None and category is None:
            return []

        product_rules = set(self.product_index.get(product, set())) if product else set(self.rules.keys())
        category_rules = set(self.category_index.get(category, set())) if category else set(self.rules.keys())

        matching_ids = product_rules & category_rules
        return [self.rules[rid] for rid in matching_ids if rid in self.rules]

    def search_by_text(self, query: str, limit: int = 50) -> list[SigmaRule]:
        """Freetext search on title + description (case-insensitive substring match).

        Args:
            query: Search string
            limit: Max rules returned (capped at 200 to bound JSON payload — CWE-400).

        Returns:
            List of matching SigmaRule objects
        """
        query_lower = query.lower()
        limit = max(1, min(limit, 200))
        results: list[SigmaRule] = []

        for rule in self.rules.values():
            title_match = query_lower in (rule.title or "").lower()
            desc_match = query_lower in (rule.description or "").lower()
            if title_match or desc_match:
                results.append(rule)
                if len(results) >= limit:
                    break

        return results

    def filter_by_status(self, rules: list[SigmaRule], status: str) -> list[SigmaRule]:
        """Filter rules by status.

        Args:
            rules: List of SigmaRule objects
            status: 'all', 'test', 'stable', 'experimental', 'deprecated'

        Returns:
            Filtered list
        """
        if status == "all":
            return rules
        return [r for r in rules if r.status == status]

    def filter_by_level(self, rules: list[SigmaRule], level: str) -> list[SigmaRule]:
        """Filter rules by alert level (inclusive: level+ includes everything at that level and above).

        Args:
            rules: List of SigmaRule objects
            level: 'all', 'informational', 'low', 'medium', 'high', 'critical'

        Returns:
            Filtered list
        """
        if level == "all":
            return rules

        level_rank = {
            "informational": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }

        threshold = level_rank.get(level, 0)
        return [r for r in rules if level_rank.get(r.level, 0) >= threshold]
