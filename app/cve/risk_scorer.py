"""Composite CVE risk scoring (CVSS / EPSS / KEV / PoC fusion).

Methodology adapted from mukul975/cve-mcp-server (Apache-2.0):
https://github.com/mukul975/cve-mcp-server — see `src/cve_mcp/utils/risk_scorer.py`
for the upstream weighting/booster scheme. This is a clean-room
re-implementation tailored to ContrastAPI's data model — no upstream code is
copied; only the formula and booster constants are shared.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(frozen=True)
class RiskScoreResult:
    score: float
    label: str
    urgency: str
    components: dict
    boosters_applied: list[str] = field(default_factory=list)
    recommendation: str = ""


_LABEL_BANDS = (
    (90.0, "CRITICAL"),
    (70.0, "HIGH"),
    (40.0, "MEDIUM"),
    (0.0, "LOW"),
)


def _label_for(score: float) -> str:
    for threshold, label in _LABEL_BANDS:
        if score >= threshold:
            return label
    return "LOW"


def _urgency_for(label: str, in_kev: bool) -> str:
    if in_kev:
        return "Patch immediately — actively exploited (CISA KEV)."
    if label == "CRITICAL":
        return "Patch within 24 hours."
    if label == "HIGH":
        return "Patch within 72 hours."
    if label == "MEDIUM":
        return "Patch within 30 days."
    return "Routine patch cycle."


def _recommendation_for(label: str, has_poc: bool, in_kev: bool) -> str:
    if in_kev:
        return (
            "Active exploitation confirmed by CISA — apply the vendor patch "
            "now and review intrusion telemetry for the affected service."
        )
    if has_poc and label in {"CRITICAL", "HIGH"}:
        return "Public PoC available with high impact — prioritise patching above routine maintenance."
    if label == "CRITICAL":
        return "Critical impact even without a public PoC — schedule the patch in the same change window."
    if label == "HIGH":
        return "High impact — schedule the patch in the next maintenance window."
    if label == "MEDIUM":
        return "Track in the vulnerability backlog and patch within standard cadence."
    return "Low risk — apply during the routine update cycle."


def _is_recent(published_at: str | None, days: int) -> bool:
    if not published_at:
        return False
    try:
        ts = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    delta_seconds = (datetime.now(UTC) - ts).total_seconds()
    return 0 <= delta_seconds <= days * 86400


def compute_risk_score(
    *,
    cvss_v3: float | None,
    epss_score: float | None,
    in_kev: bool,
    has_poc: bool,
    published_at: str | None = None,
) -> RiskScoreResult:
    """Compute composite CVE risk score in [0, 100].

    Base formula (each component rescaled to 0-100, then weighted):
        CVSS*0.20 + EPSS*0.35 + KEV*0.30 + PoC*0.15

    Multiplicative boosters (final score is min(100, base * multiplier)):
        - KEV present AND public PoC available: *1.15
        - CVSS ≥ 9 AND EPSS > 0.7:                *1.10
        - Published within the last 7 days:       *1.05
    """
    cvss = float(cvss_v3) if cvss_v3 is not None else 0.0
    epss = float(epss_score) if epss_score is not None else 0.0

    cvss_part = cvss * 10.0 * 0.20
    epss_part = epss * 100.0 * 0.35
    kev_part = (100.0 if in_kev else 0.0) * 0.30
    poc_part = (100.0 if has_poc else 0.0) * 0.15

    base = cvss_part + epss_part + kev_part + poc_part

    boosters: list[str] = []
    multiplier = 1.0
    if in_kev and has_poc:
        multiplier *= 1.15
        boosters.append("kev_with_public_poc")
    if cvss >= 9.0 and epss > 0.7:
        multiplier *= 1.10
        boosters.append("critical_severity_high_epss")
    if _is_recent(published_at, days=7):
        multiplier *= 1.05
        boosters.append("published_within_7_days")

    score = min(100.0, round(base * multiplier, 1))
    label = _label_for(score)
    urgency = _urgency_for(label, in_kev)
    recommendation = _recommendation_for(label, has_poc, in_kev)
    components = {
        "cvss_v3": round(cvss, 1),
        "epss_score": round(epss, 4),
        "in_kev": in_kev,
        "has_public_poc": has_poc,
        "weighted_breakdown": {
            "cvss": round(cvss_part, 2),
            "epss": round(epss_part, 2),
            "kev": round(kev_part, 2),
            "poc": round(poc_part, 2),
        },
    }
    return RiskScoreResult(
        score=score,
        label=label,
        urgency=urgency,
        components=components,
        boosters_applied=boosters,
        recommendation=recommendation,
    )
