"""Sigma rule corpus REST endpoints — /v1/sigma/*."""

import re
import uuid
from typing import Annotated, Literal

from auth import AuthCtx, require_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from schemas import PivotHint
from sigma import get_sigma_index
from sigma.parser import normalize_cve_tag
from sigma.schemas import (
    BulkSigmaRuleLookupItem,
    BulkSigmaRuleLookupRequest,
    BulkSigmaRuleLookupResponse,
    SigmaRule,
    SigmaRuleLookupResponse,
    SigmaRuleSearchResponse,
)

router = APIRouter(prefix="/sigma", tags=["Sigma Rules"])

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_PIVOT_CAP = 3


def _is_uuid(value: str) -> bool:
    if not _UUID_RE.match(value):
        return False
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def _pivot_hints_for_rule(rule: SigmaRule) -> list[PivotHint]:
    """Surface up to 3 next_calls based on the rule's tags."""
    hints: list[PivotHint] = []
    for tag in rule.tags:
        if len(hints) >= _PIVOT_CAP:
            break
        tag_lower = tag.lower()
        if tag_lower.startswith("attack.t"):
            tech = tag.split(".")[-1].upper()
            hints.append(
                PivotHint(
                    tool="atlas_technique_lookup",
                    input=tech,
                    reason=f"Sigma rule tagged {tech} — fetch MITRE ATT&CK context",
                )
            )
            continue
        cve_norm = normalize_cve_tag(tag) if tag_lower.startswith("cve") else None
        if cve_norm:
            hints.append(
                PivotHint(
                    tool="cve_lookup",
                    input=cve_norm,
                    reason=f"Sigma rule references {cve_norm} — fetch CVE detail",
                )
            )
    return hints[:_PIVOT_CAP]


@router.get(
    "/search",
    operation_id="sigma_rule_search",
    response_model=SigmaRuleSearchResponse,
    response_model_exclude_none=True,
)
def sigma_search(
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/sigma/search"))],
    technique: Annotated[str | None, Query(max_length=32)] = None,
    cve_id: Annotated[str | None, Query(max_length=32)] = None,
    logsource_product: Annotated[str | None, Query(max_length=64)] = None,
    logsource_category: Annotated[str | None, Query(max_length=64)] = None,
    query: Annotated[str | None, Query(max_length=128)] = None,
    status: Annotated[
        Literal["all", "test", "stable", "experimental", "unsupported", "deprecated"],
        Query(),
    ] = "all",
    level: Annotated[
        Literal["all", "informational", "low", "medium", "high", "critical"],
        Query(),
    ] = "all",
    include_deprecated: Annotated[bool, Query()] = False,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> SigmaRuleSearchResponse:
    """Multi-param search across the Sigma rule corpus.

    Filters compose with AND logic. When no filter is supplied, all non-deprecated rules are returned.
    """
    idx = get_sigma_index()

    if technique:
        rules = idx.lookup_by_technique(technique, limit=200)
    elif cve_id:
        rules = idx.lookup_by_cve(cve_id)
    elif logsource_product or logsource_category:
        rules = idx.lookup_by_logsource(product=logsource_product, category=logsource_category)
    elif query:
        rules = idx.search_by_text(query, limit=200)
    else:
        rules = list(idx.rules.values())

    if not include_deprecated:
        rules = [r for r in rules if r.status != "deprecated"]
    if status != "all":
        rules = idx.filter_by_status(rules, status)
    if level != "all":
        rules = idx.filter_by_level(rules, level)

    total = len(rules)
    page = rules[offset : offset + limit]
    next_calls = _pivot_hints_for_rule(page[0]) if page else []

    return SigmaRuleSearchResponse(
        rules=page,
        total_matches=total,
        limit=limit,
        offset=offset,
        truncated=total > offset + limit,
        next_calls=next_calls or None,
    )


@router.get(
    "/{rule_id}",
    operation_id="sigma_rule_lookup",
    response_model=SigmaRuleLookupResponse,
    response_model_exclude_none=True,
)
def sigma_lookup(
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/sigma/{rule_id}"))],
    rule_id: Annotated[
        str,
        Path(
            min_length=36,
            max_length=36,
            pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        ),
    ],
) -> SigmaRuleLookupResponse:
    """Fetch a single Sigma rule by UUID."""
    idx = get_sigma_index()
    rule = idx.lookup_by_id(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Sigma rule {rule_id} not found")
    return SigmaRuleLookupResponse(rule=rule, next_calls=_pivot_hints_for_rule(rule) or None)


@router.post(
    "/bulk",
    operation_id="sigma_rule_bulk",
    response_model=BulkSigmaRuleLookupResponse,
    response_model_exclude_none=True,
)
def sigma_bulk(
    body: BulkSigmaRuleLookupRequest,
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/sigma/bulk"))],
) -> BulkSigmaRuleLookupResponse:
    """Bulk lookup up to 50 Sigma rules by UUID. Each rule_id consumes 1 unit of the
    per-hour quota; ids beyond the caller's remaining quota land in
    `skipped_due_to_rate_limit` instead of failing the whole batch — parity with
    bulk_cve_lookup / bulk_ioc_lookup (v1.27 dynamic budget)."""
    import ratelimit
    from config import FREE_HOURLY_LIMIT, PRO_HOURLY_LIMIT
    from db import hash_client_ip
    from validation import sanitize_echo

    rule_ids = list(dict.fromkeys(body.rule_ids))
    count = len(rule_ids)

    if auth.tier == "pro":
        store_key = f"pro:{auth.key_hash}"
        limit = PRO_HOURLY_LIMIT
    else:
        store_key = f"free:{hash_client_ip(auth.client_ip)}"
        limit = FREE_HOURLY_LIMIT

    available_budget = auth.ratelimit_remaining + 1
    processable = min(count, available_budget)
    extra = processable - 1

    if extra > 0 and not ratelimit.consume_bulk("api", store_key, extra, limit):
        # Race: another worker drained quota between require_auth and here.
        # Fall back to processing only the unit require_auth already paid for.
        processable = 1

    skipped_ids = [sanitize_echo(s) for s in rule_ids[processable:]]
    rule_ids = rule_ids[:processable]

    idx = get_sigma_index()
    items: list[BulkSigmaRuleLookupItem] = []
    for rid in rule_ids:
        if not _is_uuid(rid):
            items.append(
                BulkSigmaRuleLookupItem(rule_id=sanitize_echo(rid), status="invalid_format", error="not a UUID")
            )
            continue
        rule = idx.lookup_by_id(rid)
        if rule is None:
            items.append(
                BulkSigmaRuleLookupItem(rule_id=sanitize_echo(rid), status="not_found", error="rule not in index")
            )
        else:
            items.append(BulkSigmaRuleLookupItem(rule_id=rid, status="ok", rule=rule))

    processed = len(items)
    skipped_count = len(skipped_ids)
    total = processed + skipped_count
    successful = sum(1 for i in items if i.status == "ok")
    failed = processed - successful
    return BulkSigmaRuleLookupResponse(
        results=items,
        total=total,
        processed=processed,
        skipped_due_to_rate_limit=skipped_ids,
        successful=successful,
        failed=failed,
        partial=failed > 0 or skipped_count > 0,
        summary=f"{successful}/{total} rules found",
        next_calls=None,
    )
