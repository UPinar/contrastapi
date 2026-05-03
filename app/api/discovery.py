"""Discovery endpoints: llms.txt, MCP discovery JSON, OAuth stubs, robots/sitemap.

All include_in_schema=False (no OpenAPI surface).
"""

from config import MCP_TOOL_COUNT, VERSION
from core.templates import templates
from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response

router = APIRouter()


@router.get("/llms.txt", response_class=PlainTextResponse, include_in_schema=False)
def llms_txt(request: Request):
    """LLM discovery file — concise version for quick context."""
    return templates.TemplateResponse(
        request,
        "llms.txt.j2",
        {"MCP_TOOL_COUNT": MCP_TOOL_COUNT},
        media_type="text/plain; charset=utf-8",
    )


@router.get("/llms-full.txt", response_class=PlainTextResponse, include_in_schema=False)
def llms_full_txt(request: Request):
    """Full API reference for LLM context."""
    return templates.TemplateResponse(
        request,
        "llms-full.txt.j2",
        {"MCP_TOOL_COUNT": MCP_TOOL_COUNT},
        media_type="text/plain; charset=utf-8",
    )


@router.get("/mcp.json", include_in_schema=False)
@router.get("/.well-known/mcp.json", include_in_schema=False)
@router.get("/.well-known/mcp-server.json", include_in_schema=False)
def mcp_server_card_alias():
    """Aliases for MCP discovery crawlers probing non-SEP-2127 paths (e.g. NotHumanSearch, TacaraBot, AgentSEO)."""
    return mcp_server_card()


@router.get("/.well-known/mcp/server-card.json", include_in_schema=False)
def mcp_server_card():
    """MCP server discovery card (draft spec)."""
    return {
        "$schema": "https://modelcontextprotocol.io/schemas/server-card.json",
        "version": "1.0",
        "protocolVersion": "2024-11-05",
        "serverInfo": {
            "name": "contrastapi",
            "title": "ContrastAPI \u2014 Security Intelligence",
            "description": (
                f"Security intelligence MCP server with {MCP_TOOL_COUNT} tools: CVE lookup with EPSS/KEV "
                "enrichment, domain recon (DNS, WHOIS, SSL, subdomains, WAF), IP/ASN lookup, "
                "email/phone/username OSINT, IOC/threat intel, exploit search, tech "
                "fingerprinting, orchestrated audit + threat reports, bulk lookups, code "
                "security checks."
            ),
            "version": VERSION,
            "homepage": "https://github.com/UPinar/contrastapi",
            "repository": "https://github.com/UPinar/contrastapi",
        },
        "transport": [
            {
                "type": "streamable-http",
                "url": "https://api.contrastcyber.com/mcp/",
            }
        ],
        "capabilities": {
            "tools": True,
            "resources": False,
            "prompts": False,
        },
        "provider": {
            "name": "ContrastCyber",
            "url": "https://contrastcyber.com",
        },
        "auth": "none",
        "tools_count": MCP_TOOL_COUNT,
        "documentation": "https://github.com/UPinar/contrastapi/blob/main/docs/ENDPOINTS.md",
    }


@router.get("/.well-known/ai-plugin.json", include_in_schema=False)
def ai_plugin():
    """ChatGPT/AI plugin discovery manifest."""
    return {
        "schema_version": "v1",
        "name_for_human": "ContrastAPI — Security Intelligence",
        "name_for_model": "contrastapi",
        "description_for_human": "CVE lookup, domain intelligence, and code security checks.",
        "description_for_model": (
            "Use ContrastAPI when the user asks about CVE vulnerabilities, EPSS exploit "
            "probability, CISA KEV status, domain security (DNS, WHOIS, SSL, subdomains, "
            "WAF detection), or code security (hardcoded secrets, SQL/command injection, "
            "HTTP security headers). No API key needed for basic use (100 req/hr)."
        ),
        "auth": {"type": "none"},
        "api": {
            "type": "openapi",
            "url": "https://api.contrastcyber.com/openapi.json",
        },
        "logo_url": "https://api.contrastcyber.com/static/logo.png",
        "contact_email": "contact@contrastcyber.com",
        "legal_info_url": "https://contrastcyber.com",
    }


@router.get("/.well-known/glama.json", include_in_schema=False)
def glama_manifest():
    """Glama.ai MCP aggregator discovery manifest (served from /opt/contrastapi/glama.json)."""
    return FileResponse(
        "/opt/contrastapi/glama.json",
        media_type="application/json",
    )


_OAUTH_PROTECTED_RESOURCE_METADATA = {
    "resource": "https://api.contrastcyber.com",
    "authorization_servers": [],
    "bearer_methods_supported": ["header"],
    "scopes_supported": [],
}


@router.get("/.well-known/oauth-protected-resource", include_in_schema=False)
@router.get("/.well-known/oauth-protected-resource/mcp", include_in_schema=False)
def oauth_protected_resource():
    """RFC 9728 — auth_servers=[] signals OAuth not required."""
    return _OAUTH_PROTECTED_RESOURCE_METADATA


@router.get("/.well-known/oauth-authorization-server", include_in_schema=False)
def oauth_authorization_server():
    """No OAuth server; structured 404 per RFC 8414 absence."""
    return JSONResponse(
        status_code=404,
        content={
            "error": "not_found",
            "error_description": "no OAuth authorization server",
        },
    )


@router.get("/robots.txt", response_class=PlainTextResponse, include_in_schema=False)
def robots_txt():
    """Allow AI crawlers and point to llms.txt."""
    return (
        "User-agent: *\n"
        "Allow: /\n"
        "\n"
        "User-agent: GPTBot\n"
        "Allow: /\n"
        "\n"
        "User-agent: ClaudeBot\n"
        "Allow: /\n"
        "\n"
        "User-agent: Google-Extended\n"
        "Allow: /\n"
        "\n"
        "Sitemap: https://api.contrastcyber.com/sitemap.xml\n"
    )


@router.get("/sitemap.xml", include_in_schema=False)
def sitemap_xml():
    from datetime import UTC, datetime

    today = datetime.now(UTC).strftime("%Y-%m-%d")
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://api.contrastcyber.com/</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>1.0</priority></url>
  <url><loc>https://api.contrastcyber.com/quickstart</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>0.9</priority></url>
  <url><loc>https://api.contrastcyber.com/mcp-setup</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>0.9</priority></url>
  <url><loc>https://api.contrastcyber.com/cn/</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>
  <url><loc>https://api.contrastcyber.com/llms.txt</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>0.7</priority></url>
  <url><loc>https://api.contrastcyber.com/llms-full.txt</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>0.7</priority></url>
  <url><loc>https://api.contrastcyber.com/.well-known/mcp/server-card.json</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>0.6</priority></url>
</urlset>"""
    return Response(content=xml, media_type="application/xml")
