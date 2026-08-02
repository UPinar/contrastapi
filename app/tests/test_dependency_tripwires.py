"""Dependency tripwires — invariants over the installed environment.

mcp>=2 depends on opentelemetry-api, which is a no-op shim with no network
code: telemetry egress is impossible unless opentelemetry-sdk (plus an
exporter) is ever installed. Privacy stance: that must never happen
transitively. This test fails the suite the moment any resolver pulls it in.
"""

import importlib.metadata

import pytest


@pytest.mark.parametrize(
    "package",
    ["opentelemetry-sdk", "opentelemetry-exporter-otlp"],
)
def test_otel_egress_packages_absent(package):
    with pytest.raises(importlib.metadata.PackageNotFoundError):
        importlib.metadata.version(package)
