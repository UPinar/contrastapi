"""HTML landing pages: /, /bot, /cn, /welcome, /quickstart, /mcp-setup, /playground.

All routes are include_in_schema=False (no OpenAPI surface). Templates live in
core.templates singleton.
"""

import logging
import uuid

from config import (
    ATLAS_CASE_STUDY_COUNT,
    ATLAS_TECHNIQUE_COUNT,
    D3FEND_DEFENSE_COUNT,
    ENDPOINT_COUNT,
    MCP_PROMPT_COUNT,
    MCP_RESOURCE_COUNT,
    MCP_TOOL_COUNT,
    TARGET_THROTTLE_PER_MIN,
    TEST_COUNT,
    VERSION,
)
from core.templates import templates
from db import (
    get_and_clear_pending_key,
    get_key_by_order_id,
    get_total_requests,
    hash_client_ip,
)
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from mcp.types import LATEST_PROTOCOL_VERSION
from ratelimit import check_limit
from validation import get_client_ip

logger = logging.getLogger("contrastapi")

router = APIRouter()


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def landing_page(request: Request):
    total = get_total_requests()
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "total_requests": total,
            "tool_count": MCP_TOOL_COUNT,
            "resource_count": MCP_RESOURCE_COUNT,
            "prompt_count": MCP_PROMPT_COUNT,
            "endpoint_count": ENDPOINT_COUNT,
            "test_count": TEST_COUNT,
            "atlas_technique_count": ATLAS_TECHNIQUE_COUNT,
            "atlas_case_study_count": ATLAS_CASE_STUDY_COUNT,
            "d3fend_defense_count": D3FEND_DEFENSE_COUNT,
        },
    )


@router.get("/bot", response_class=HTMLResponse, include_in_schema=False)
def bot_landing(request: Request):
    response = templates.TemplateResponse(
        request,
        "bot.html",
        {
            "version": VERSION,
            "throttle_per_min": TARGET_THROTTLE_PER_MIN,
        },
    )
    response.headers["Cache-Control"] = "no-store, must-revalidate"
    return response


@router.get("/cn/", response_class=HTMLResponse, include_in_schema=False)
@router.get("/cn", response_class=HTMLResponse, include_in_schema=False)
def landing_page_cn(request: Request):
    total = get_total_requests()
    return templates.TemplateResponse(
        request,
        "index_cn.html",
        {
            "total_requests": total,
            "tool_count": MCP_TOOL_COUNT,
            "resource_count": MCP_RESOURCE_COUNT,
            "prompt_count": MCP_PROMPT_COUNT,
            "endpoint_count": ENDPOINT_COUNT,
            "test_count": TEST_COUNT,
            "atlas_technique_count": ATLAS_TECHNIQUE_COUNT,
            "atlas_case_study_count": ATLAS_CASE_STUDY_COUNT,
            "d3fend_defense_count": D3FEND_DEFENSE_COUNT,
        },
    )


@router.get("/welcome", response_class=HTMLResponse, include_in_schema=False)
def welcome_page(request: Request, order_id: str = ""):
    if not order_id:
        raise HTTPException(status_code=400, detail="Missing order_id")

    # Validate order_id is a UUID
    try:
        uuid.UUID(order_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid order_id format") from None

    # Rate limit: 5 req/min per IP
    client_ip = get_client_ip(request)
    if not check_limit("welcome", hash_client_ip(client_ip), max_requests=5, window_seconds=60):
        raise HTTPException(status_code=429, detail="Too many requests")

    api_key = get_and_clear_pending_key(order_id)

    if api_key:
        context = {"api_key": api_key, "error": None, "polling": False, "order_id": order_id}
    elif get_key_by_order_id(order_id):
        # Order exists but pending_key already consumed — already claimed
        context = {
            "api_key": None,
            "error": "This API key has already been claimed. If you lost your key, please contact support.",
            "polling": False,
            "order_id": order_id,
        }
    else:
        # Order not in DB yet — webhook may not have arrived, show polling spinner
        context = {"api_key": None, "error": None, "polling": True, "order_id": order_id}

    try:
        return templates.TemplateResponse(
            request,
            "welcome.html",
            context,
        )
    except (ValueError, OSError) as exc:
        if api_key:
            logger.error("Template render failed for order %s: %s, returning plain text fallback", order_id, exc)
            return PlainTextResponse(
                f"Your API key: {api_key}\n\nSave this key now. It will not be shown again.",
                media_type="text/plain",
            )
        raise


@router.get("/quickstart", response_class=HTMLResponse, include_in_schema=False)
def quickstart(request: Request):
    return templates.TemplateResponse(
        request,
        "quickstart.html",
        {
            "tool_count": MCP_TOOL_COUNT,
            "resource_count": MCP_RESOURCE_COUNT,
            "prompt_count": MCP_PROMPT_COUNT,
        },
    )


@router.get("/mcp-setup", response_class=HTMLResponse, include_in_schema=False)
def mcp_setup(request: Request):
    return templates.TemplateResponse(
        request,
        "mcp_setup.html",
        {
            "tool_count": MCP_TOOL_COUNT,
            "resource_count": MCP_RESOURCE_COUNT,
            "prompt_count": MCP_PROMPT_COUNT,
            "protocol_version": LATEST_PROTOCOL_VERSION,
        },
    )


@router.get("/playground", response_class=HTMLResponse, include_in_schema=False)
def playground(request: Request):
    return templates.TemplateResponse(
        request,
        "playground.html",
        {
            "atlas_technique_count": ATLAS_TECHNIQUE_COUNT,
            "atlas_case_study_count": ATLAS_CASE_STUDY_COUNT,
            "d3fend_defense_count": D3FEND_DEFENSE_COUNT,
        },
    )


@router.get("/pricing", response_class=HTMLResponse, include_in_schema=False)
def pricing_page(request: Request):
    return templates.TemplateResponse(request, "pricing.html")


@router.get("/terms", response_class=HTMLResponse, include_in_schema=False)
def terms_page(request: Request):
    return templates.TemplateResponse(request, "terms.html")


@router.get("/privacy", response_class=HTMLResponse, include_in_schema=False)
def privacy_page(request: Request):
    return templates.TemplateResponse(request, "privacy.html")
