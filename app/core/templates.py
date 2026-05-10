"""Jinja2Templates singleton — shared between main.py and api/landing.py.

Config-derived counts (`tool_count`, `resource_count`, `prompt_count`,
`endpoint_count`, `test_count`, `version`) are exposed as Jinja globals so
every template can reference them without each route handler having to
re-pass them in its context dict. Per-route handlers may still inject
dynamic per-request vars (e.g. `total_requests`).
"""

from config import (
    BASE_DIR,
    ENDPOINT_COUNT,
    FREE_HOURLY_LIMIT,
    MCP_PROMPT_COUNT,
    MCP_RESOURCE_COUNT,
    MCP_TOOL_COUNT,
    PRO_HOURLY_LIMIT,
    TEST_COUNT,
    VERSION,
)
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory=BASE_DIR / "templates")

templates.env.globals.update(
    {
        "tool_count": MCP_TOOL_COUNT,
        "resource_count": MCP_RESOURCE_COUNT,
        "prompt_count": MCP_PROMPT_COUNT,
        "endpoint_count": ENDPOINT_COUNT,
        "test_count": TEST_COUNT,
        "version": VERSION,
        "free_limit": FREE_HOURLY_LIMIT,
        "pro_limit": PRO_HOURLY_LIMIT,
    }
)
