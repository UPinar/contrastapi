"""Pure function YAML parser for Sigma rules."""

import re
from datetime import UTC, datetime

import yaml
from sigma.schemas import SigmaDetection, SigmaRule


def normalize_cve_tag(tag: str) -> str | None:
    """Normalize CVE tag formats into canonical CVE-YYYY-NNNNN form.

    Handles: cve.2024.1234, cve.2024-1234, cve:2024-1234, CVE-2024-1234.
    Returns None if tag does not match CVE pattern.
    """
    if not tag.lower().startswith("cve"):
        return None
    # Extract year and number from various separators
    m = re.search(r"(\d{4})[.\-:](\d+)", tag)
    if m:
        return f"CVE-{m.group(1)}-{m.group(2)}"
    return None


def _summarize_detection(detection_dict: dict) -> str:
    """Generate human-readable summary of detection block.

    E.g., '3 selections, condition: all of selection_*'
    """
    if not isinstance(detection_dict, dict):
        return "invalid detection"
    selections = [k for k in detection_dict if k.startswith("selection")]
    condition = detection_dict.get("condition", "unknown")
    return f"{len(selections)} selections, condition: {condition}"


def parse_sigma_rule(yaml_text: str) -> SigmaRule:
    """Parse YAML text into SigmaRule model.

    Handles missing fields with sensible defaults:
    - No description → None
    - No author → None
    - No tags → []
    - No logsource → {product: "unknown"}
    - No references → []
    - No falsepositives → []

    Normalizes CVE tag formats. Validates against SigmaRule schema.

    Args:
        yaml_text: Raw YAML string from Sigma rule file

    Returns:
        SigmaRule model instance

    Raises:
        yaml.YAMLError: If YAML is malformed
        ValueError: If required fields (id, title, detection) are missing
    """
    data = yaml.safe_load(yaml_text)

    if not data or not isinstance(data, dict):
        raise ValueError("YAML did not parse to a dictionary")

    # Validate required fields
    rule_id = data.get("id")
    title = data.get("title")
    detection_raw = data.get("detection")

    if not rule_id:
        raise ValueError("'id' field is required")
    if not title:
        raise ValueError("'title' field is required")
    if not detection_raw or not isinstance(detection_raw, dict):
        raise ValueError("'detection' field is required and must be a dict")

    # Parse detection block
    selections = {k: v for k, v in detection_raw.items() if k.startswith("selection")}
    condition = detection_raw.get("condition", "unknown")
    detection = SigmaDetection(selections=selections, condition=condition)
    detection_summary = _summarize_detection(detection_raw)

    # Normalize tags: apply CVE normalization in-place
    tags_raw = data.get("tags") or []
    if not isinstance(tags_raw, list):
        tags_raw = []
    tags_normalized = []
    for tag in tags_raw:
        cve_norm = normalize_cve_tag(tag)
        if cve_norm:
            tags_normalized.append(cve_norm)
        else:
            tags_normalized.append(tag)

    # Normalize logsource
    logsource_raw = data.get("logsource") or {}
    if not isinstance(logsource_raw, dict):
        logsource_raw = {}

    # Parse references
    references_raw = data.get("references") or []
    if isinstance(references_raw, str):
        references = [references_raw]
    elif isinstance(references_raw, list):
        references = references_raw
    else:
        references = []

    # Parse falsepositives
    falsepositives_raw = data.get("falsepositives") or []
    if isinstance(falsepositives_raw, str):
        falsepositives = [falsepositives_raw]
    elif isinstance(falsepositives_raw, list):
        falsepositives = falsepositives_raw
    else:
        falsepositives = []

    # Build rule
    rule = SigmaRule(
        rule_id=str(rule_id),
        title=title,
        status=data.get("status", "test"),
        level=data.get("level", "medium"),
        description=data.get("description"),
        author=data.get("author"),
        date=str(data["date"]) if data.get("date") is not None else None,
        modified=str(data["modified"]) if data.get("modified") is not None else None,
        tags=tags_normalized,
        logsource=logsource_raw,
        detection=detection,
        detection_summary=detection_summary,
        references=references,
        falsepositives=falsepositives,
        license=data.get("license", "DRL 1.1"),
        source_url=data.get("source_url", ""),
        updated_at=datetime.now(UTC).replace(tzinfo=None).isoformat() + "Z",
    )

    return rule
