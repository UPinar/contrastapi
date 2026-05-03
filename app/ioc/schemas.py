"""Pydantic response models for IOC enrichment / hash / password / phishing endpoints."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field
from schemas import BaseSuccessResponse


class ThreatFoxSource(BaseModel):
    """ThreatFox abuse.ch source entry inside IocResponse.sources.threatfox."""

    found: bool = Field(description="True when ThreatFox returned at least one IOC entry for the indicator.")
    malware: str | None = Field(
        default=None, description="Malware family name (e.g. 'Cobalt Strike'). Null when found=False."
    )
    threat_type: str | None = Field(
        default=None,
        description="Threat classification (e.g. 'botnet_cc', 'payload_delivery'). Null when found=False.",
    )
    confidence: int | None = Field(
        default=None,
        description="ThreatFox confidence score (0-100). Null when found=False or not provided upstream.",
    )
    tags: list[str] = Field(
        default_factory=list, description="ThreatFox tags. May include 'test'/'demo' for honeypot entries."
    )
    first_seen: str | None = Field(
        default=None,
        description="ISO timestamp of first ThreatFox observation. Null when found=False.",
    )
    ioc_count: int | None = Field(
        default=None,
        description="Total ThreatFox IOC entries matching this indicator. Null when found=False.",
    )
    error: str | None = Field(
        default=None,
        description="'upstream timeout' or 'upstream error' when ThreatFox query failed; absent on success.",
    )

    model_config = {"extra": "ignore"}


class FeodoSource(BaseModel):
    """Feodo Tracker C2 blocklist entry inside IocResponse.sources.feodo (IP only)."""

    found: bool = Field(description="True when the IP appears on the Feodo Tracker C2 blocklist.")
    malware: str | None = Field(
        default=None, description="Malware family attributed by Feodo (e.g. 'Emotet'). Null when found=False."
    )
    first_seen: str | None = Field(
        default=None,
        description="ISO timestamp of first Feodo observation. Null when found=False.",
    )
    last_online: str | None = Field(
        default=None,
        description="ISO timestamp the C2 was last seen online. Null when found=False.",
    )
    status: str | None = Field(
        default=None,
        description="C2 lifecycle status per Feodo (e.g. 'online', 'offline'). Null when found=False.",
    )

    model_config = {"extra": "ignore"}


class UrlhausSource(BaseModel):
    """URLhaus abuse.ch source entry inside IocResponse.sources.urlhaus."""

    found: bool = Field(description="True when URLhaus has at least one URL for the indicator.")
    urls_online: int = Field(default=0, description="Subset of URLhaus URLs currently marked online.")

    model_config = {"extra": "ignore"}


class TorSource(BaseModel):
    """Tor exit list entry inside IocResponse.sources.tor (IP only)."""

    listed: bool = Field(description="True when the IP appears in the Tor Project's bulk exit list.")
    fetch_status: Literal["initial", "ok", "failed", "capped"] = Field(
        description=(
            "Cache state of the Tor exit list snapshot used for the lookup. "
            "'initial' = no refresh has run yet; 'ok' = fresh fetch; 'failed' = upstream "
            "fetch failed (treat listed=False as 'unknown', not 'safe'); 'capped' = upstream "
            "response exceeded the size cap and was rejected."
        ),
    )

    model_config = {"extra": "ignore"}


class IocSourcesInfo(BaseModel):
    """Per-source lookup results inside IocResponse. Keys present depend on indicator type.

    - hash → only `threatfox` (Feodo and URLhaus do not index hashes).
    - ip → `threatfox` + `feodo` + `urlhaus` + `tor`.
    - domain / url → `threatfox` + `urlhaus`.
    """

    threatfox: ThreatFoxSource | None = Field(default=None, description="ThreatFox lookup result. Always queried.")
    feodo: FeodoSource | None = Field(
        default=None, description="Feodo Tracker C2 blocklist lookup. IP indicators only."
    )
    urlhaus: UrlhausSource | None = Field(default=None, description="URLhaus URL/host match. IP/domain/URL indicators.")
    tor: TorSource | None = Field(default=None, description="Tor exit list membership. IP indicators only.")

    model_config = {"extra": "ignore"}


class IocResponse(BaseSuccessResponse):
    indicator: str = Field(description="Echoed input indicator (sanitized; control chars stripped).")
    type: Literal["ip", "domain", "url", "hash", "unknown"] = Field(
        description="Auto-detected indicator type. 'unknown' is rejected at route level (400).",
    )
    threat_level: Literal["none", "low", "medium", "high"] = Field(
        default="none",
        description=(
            "Heuristic threat tier from cross-source agreement. 'high' = >=2 sources flagged; "
            "'medium' = 1 source flagged; 'none' = no source flagged. 'low' is a soft cap applied "
            "when the only flag came from a ThreatFox test/demo honeypot tag."
        ),
    )
    sources: IocSourcesInfo = Field(
        default_factory=IocSourcesInfo,
        description="Per-source lookup results. See IocSourcesInfo for which sources apply per indicator type.",
    )
    summary: str = Field(default="", description="One-line human summary aggregating threat indicators across sources.")

    model_config = {"extra": "ignore"}


class HashResponse(BaseSuccessResponse):
    hash: str
    hash_type: str
    found: bool = False
    malware_family: str | None = None
    file_type: str | None = None
    file_size: int | None = None
    first_seen: str | None = None
    tags: list[str] = Field(default_factory=list)
    file_name: str | None = None
    summary: str = ""


class PasswordResponse(BaseSuccessResponse):
    hash_prefix: str = Field(
        description=(
            "First 5 chars of the SHA-1 hash (the only data sent upstream — k-anonymity). "
            "The full hash never leaves the server."
        ),
    )
    found: bool = Field(
        default=False,
        description="True when the full SHA-1 was matched in HIBP's breach corpus.",
    )
    breach_count: int = Field(
        default=0,
        description="Number of breach corpora that contained this password. 0 when found=False.",
    )
    summary: str = Field(
        default="",
        description="One-line human-readable result (e.g. 'This password appeared in 12,345 data breaches').",
    )

    model_config = {"extra": "ignore"}


class UrlhausHostDetail(BaseModel):
    found: bool = False
    urls_online: int = 0
    url_count: int = 0


class UrlhausUrlDetail(BaseModel):
    found: bool = False
    threat: str | None = None
    tags: list[str] = Field(default_factory=list)
    status: str | None = Field(
        default=None,
        description=(
            "URLhaus url_status for the exact URL match: 'online' (active threat), "
            "'offline' (historical, threat may be cleaned up), or 'unknown'. Null when "
            "the URL was not found."
        ),
    )


class PhishingResponse(BaseSuccessResponse):
    url: str
    host: str
    is_malicious: bool = False
    is_stale: bool = Field(
        default=False,
        description=(
            "True when the only URLhaus evidence is historical (host has url_count > 0 "
            "but urls_online == 0, OR exact URL match has status == 'offline'). The host "
            "or URL was once flagged but no live malware is currently being served — useful "
            "for distinguishing past compromise from active threat."
        ),
    )
    urlhaus_host: UrlhausHostDetail = Field(default_factory=UrlhausHostDetail)
    urlhaus_url: UrlhausUrlDetail = Field(default_factory=UrlhausUrlDetail)
    threat_level: Literal["none", "low", "medium", "high"] = Field(
        default="none",
        description=(
            "Aggregate severity. 'high' = exact URL active AND host has live malware URLs. "
            "'medium' = exactly one of those active. 'low' = only stale historical evidence "
            "(is_stale=True). 'none' = no URLhaus listing for either."
        ),
    )
    summary: str = ""


class BulkIocItem(BaseModel):
    indicator: str = Field(description="Echoed input indicator (sanitized; type auto-detected per-item).")
    status: Literal["ok", "error", "not_found", "invalid_format"] = Field(
        default="ok",
        description=(
            "Per-item outcome (v1.21.0+ unified across bulk_cve/bulk_ioc/bulk_atlas): 'ok' = ioc "
            "populated; 'invalid_format' = indicator failed validation (empty / unknown type / "
            "private IP); 'error' = transient lookup failure (timeout / upstream error); "
            "'not_found' is reserved for parity with bulk_cve_lookup — IOC queries always reach "
            "upstream feeds, so this value is rarely emitted (treat as semantic equivalent of 'ok' "
            "with threat_level='none' and empty sources)."
        ),
    )
    ioc: dict | None = Field(
        default=None,
        description=(
            "Slim IOC enrichment when status='ok' — keys: type, threat_level, sources. "
            "Bulk endpoint omits indicator/summary/verdict (use /v1/ioc/{indicator} for the "
            "full IocResponse shape). Per-source dicts may carry richer fields than the single "
            "endpoint (raw urlhaus dict instead of {found, urls_online})."
        ),
    )
    error: str | None = Field(
        default=None,
        description="Human-readable error message when status='error' (timeout, invalid indicator, upstream error).",
    )


class BulkIocResponse(BaseSuccessResponse):
    results: list[BulkIocItem] = Field(
        default_factory=list,
        description="Per-indicator outcome list, preserving input order.",
    )
    total: int = Field(default=0, description="Total number of input indicators processed (== len(results)).")
    successful: int = Field(default=0, description="Count of items with status='ok'.")
    failed: int = Field(default=0, description="Count of items with status='error' from non-timeout failures.")
    timed_out: int = Field(default=0, description="Count of items that hit the per-IOC or overall timeout.")
    invalid: int = Field(
        default=0,
        description=(
            "Count of items with status='invalid_format' (validation rejection: empty / unknown "
            "type / private IP). Distinct from `failed` which counts only transient errors. "
            "`successful + failed + timed_out + invalid == total` always holds."
        ),
    )
    partial: bool = Field(default=False, description="True when at least one item failed, timed out, or was invalid.")
    summary: str = Field(default="", description="One-line aggregate summary (e.g. '12/15 indicators enriched').")
