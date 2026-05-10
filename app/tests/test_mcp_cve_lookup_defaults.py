"""B5 — MCP cve_lookup / bulk_cve_lookup default-true regression.

v1.29.2 flips three opt-in flags from default False -> True at the MCP
wrapper layer (HTTP REST defaults stay False for backward-compat). Agents
should now receive references_full + severity_sources + the full reference
list automatically, without having to pass include_*=true.
"""

import importlib.util
from pathlib import Path

import pytest


def _load_mcp_module():
    """Load mcp_server.py as an importable module — same trick as mcp_proxy.py."""
    spec = importlib.util.spec_from_file_location(
        "mcp_server", str(Path(__file__).resolve().parent.parent.parent / "mcp_server.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def mcp_mod():
    pytest.importorskip("mcp", reason="mcp package not installed")
    return _load_mcp_module()


def _signature_default(fn, name: str):
    """Pull a parameter's default out of a function (handles @mcp_tool_safe wrap)."""
    import inspect

    inner = fn
    while hasattr(inner, "__wrapped__"):
        inner = inner.__wrapped__
    return inspect.signature(inner).parameters[name].default


def test_cve_lookup_include_full_references_default_true(mcp_mod):
    assert _signature_default(mcp_mod.cve_lookup, "include_full_references") is True


def test_cve_lookup_include_reference_tags_default_true(mcp_mod):
    assert _signature_default(mcp_mod.cve_lookup, "include_reference_tags") is True


def test_cve_lookup_include_severity_breakdown_default_true(mcp_mod):
    assert _signature_default(mcp_mod.cve_lookup, "include_severity_breakdown") is True


def test_bulk_cve_lookup_three_flags_default_true(mcp_mod):
    for name in ("include_full_references", "include_reference_tags", "include_severity_breakdown"):
        assert _signature_default(mcp_mod.bulk_cve_lookup, name) is True, f"{name} should default True"
