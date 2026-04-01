"""
Stdio MCP wrapper for ContrastAPI.

Starts the FastAPI app internally and exposes MCP tools over stdio
for Glama and other stdio-based MCP clients.

Usage: python mcp_stdio.py
"""

import sys
import os
import asyncio
import json
import logging
import urllib.parse

# ── MCP stdio protocol: stdout = JSON-RPC only, logs → stderr ──
for h in logging.root.handlers[:]:
    logging.root.removeHandler(h)
_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(logging.Formatter("%(levelname)s: %(name)s: %(message)s"))
logging.root.addHandler(_handler)
logging.root.setLevel(logging.WARNING)

from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

import httpx

server = Server("ContrastAPI")

BASE_URL = "https://api.contrastcyber.com"


async def fetch_openapi_spec():
    """Fetch OpenAPI spec from production API."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"{BASE_URL}/openapi.json")
            if r.status_code == 200:
                return r.json()
    except Exception as e:
        logging.warning("Failed to fetch OpenAPI spec: %s", e)
    return None


# will be populated on startup
_openapi_spec = None
_tools = []


def openapi_to_mcp_tools(spec):
    """Convert OpenAPI paths to MCP tool definitions."""
    tools = []
    for path, methods in spec.get("paths", {}).items():
        for method, op in methods.items():
            op_id = op.get("operationId")
            if not op_id:
                continue
            # skip internal endpoints
            if op_id in ("landing_page", "llms_txt", "llms_full_txt",
                         "mcp_discovery", "ai_plugin", "robots_txt",
                         "sitemap_xml", "mcp_endpoint"):
                continue

            desc = op.get("summary", "") or op.get("description", "") or op_id
            params = op.get("parameters", [])

            properties = {}
            required = []
            for p in params:
                schema = p.get("schema", {"type": "string"})
                properties[p["name"]] = {
                    "type": schema.get("type", "string"),
                    "description": p.get("description", ""),
                }
                if p.get("required"):
                    required.append(p["name"])

            # request body
            body = op.get("requestBody", {})
            if body:
                content = body.get("content", {})
                json_schema = content.get("application/json", {}).get("schema", {})
                if "$ref" in json_schema:
                    ref = json_schema["$ref"].split("/")[-1]
                    json_schema = spec.get("components", {}).get("schemas", {}).get(ref, {})
                for prop_name, prop_schema in json_schema.get("properties", {}).items():
                    properties[prop_name] = {
                        "type": prop_schema.get("type", "string"),
                        "description": prop_schema.get("description", ""),
                    }
                for r_name in json_schema.get("required", []):
                    required.append(r_name)

            tools.append({
                "op_id": op_id,
                "method": method.upper(),
                "path": path,
                "name": op_id,
                "description": desc[:1024],
                "input_schema": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            })
    return tools


@server.list_tools()
async def list_tools():
    return [
        types.Tool(
            name=t["name"],
            description=t["description"],
            inputSchema=t["input_schema"],
        )
        for t in _tools
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    tool = None
    for t in _tools:
        if t["name"] == name:
            tool = t
            break
    if not tool:
        return [types.TextContent(type="text", text=f"Unknown tool: {name}")]

    path = tool["path"]
    method = tool["method"]
    allowed_keys = set(tool["input_schema"].get("properties", {}).keys())

    # reject unknown arguments
    unknown = set(arguments.keys()) - allowed_keys
    if unknown:
        return [types.TextContent(type="text",
            text=f"Unknown parameters: {', '.join(sorted(unknown))}")]

    # substitute path parameters
    query_params = {}
    body = None
    for key, value in arguments.items():
        if "{" + key + "}" in path:
            path = path.replace("{" + key + "}",
                                urllib.parse.quote(str(value), safe=""))
        elif method == "GET":
            query_params[key] = value
        else:
            if body is None:
                body = {}
            body[key] = value

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.request(
                method, f"{BASE_URL}{path}",
                params=query_params, json=body,
            )
            if len(r.content) > 1_000_000:
                return [types.TextContent(type="text",
                    text="Response too large (exceeds 1 MB limit)")]
            try:
                result = r.json()
                text = json.dumps(result, indent=2, ensure_ascii=False)
            except Exception:
                text = r.text
    except Exception as e:
        logging.warning("call_tool %s failed: %s", name, e)
        text = "Request failed"

    return [types.TextContent(type="text", text=text)]


async def main():
    global _openapi_spec, _tools

    _openapi_spec = await fetch_openapi_spec()
    if _openapi_spec:
        _tools = openapi_to_mcp_tools(_openapi_spec)

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
