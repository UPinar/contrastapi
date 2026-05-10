"""CVSS v3.x vector parser — wraps the `cvss` library into a normalized dict.

Returns a flat per-metric breakdown so agents can reason about the vector
without re-parsing it themselves. v2 is rejected explicitly (callers should
use the `cvss_v2_vector` field already on `CveResponse`).
"""

from __future__ import annotations

from cvss import CVSS3, CVSSError

_V3_METRIC_KEYS = {
    "attack_vector": "attackVector",
    "attack_complexity": "attackComplexity",
    "privileges_required": "privilegesRequired",
    "user_interaction": "userInteraction",
    "scope": "scope",
    "confidentiality_impact": "confidentialityImpact",
    "integrity_impact": "integrityImpact",
    "availability_impact": "availabilityImpact",
}


def parse_cvss_vector(vector: str) -> dict:
    """Parse a CVSS v3.x vector string into per-metric breakdown + recomputed score.

    Raises ValueError on invalid input.
    """
    if not isinstance(vector, str) or not vector.strip():
        raise ValueError("CVSS vector is empty.")
    cleaned = vector.strip()
    if not cleaned.startswith("CVSS:3"):
        raise ValueError(
            f"Unrecognized CVSS vector format: {cleaned[:20]!r}. Expected 'CVSS:3.0/...' or 'CVSS:3.1/...'."
        )
    try:
        cvss_obj = CVSS3(cleaned)
    except CVSSError as exc:
        raise ValueError(f"Invalid CVSS v3 vector: {exc}") from exc

    data = cvss_obj.as_json()
    metrics = {api_key: data[json_key] for api_key, json_key in _V3_METRIC_KEYS.items()}

    base_score = float(data["baseScore"])
    base_severity = data["baseSeverity"]
    temporal_raw = data.get("temporalScore")
    environmental_raw = data.get("environmentalScore")

    return {
        "version": data["version"],
        "vector": data["vectorString"],
        "base_score": base_score,
        "base_severity": base_severity,
        "metrics": metrics,
        "temporal_score": float(temporal_raw) if temporal_raw is not None else None,
        "environmental_score": (float(environmental_raw) if environmental_raw is not None else None),
    }
