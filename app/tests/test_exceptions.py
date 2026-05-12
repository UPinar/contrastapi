"""Regression tests for AppException invariants used by the MCP error envelope."""

from exceptions import AppException, InvalidDomainException


def test_message_truncated_to_500_chars_prevents_pydantic_validation_error():
    """AppException must truncate message to ErrorDetail.max_length (500) so that
    to_error_detail() never raises ValidationError mid-flight in the mcp_tool_safe
    decorator's `except AppException` block (which would escape unhandled).
    """
    long_msg = "x" * 2000
    exc = AppException(long_msg)
    assert len(exc.message) == 500
    detail = exc.to_error_detail()
    assert len(detail.message) == 500


def test_subclass_long_message_also_truncated():
    long_domain = "a" * 1000 + ".example.com"
    exc = InvalidDomainException(f"Invalid domain format: {long_domain!r}")
    assert len(exc.message) == 500
    exc.to_error_detail()
