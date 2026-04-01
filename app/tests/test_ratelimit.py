"""Tests for ratelimit.py"""

import time

import pytest


@pytest.fixture(autouse=True)
def reset_stores():
    from ratelimit import reset

    reset()
    yield
    reset()


# --- check_limit ---


def test_check_limit_allows_under_limit():
    from ratelimit import check_limit

    assert check_limit("test", "key1", 5) is True


def test_check_limit_blocks_at_limit():
    from ratelimit import check_limit

    for _ in range(5):
        check_limit("test", "key1", 5)
    assert check_limit("test", "key1", 5) is False


def test_check_limit_different_keys_independent():
    from ratelimit import check_limit

    for _ in range(5):
        check_limit("test", "key1", 5)
    assert check_limit("test", "key1", 5) is False
    assert check_limit("test", "key2", 5) is True


def test_check_limit_different_stores_independent():
    from ratelimit import check_limit

    for _ in range(3):
        check_limit("store_a", "key1", 3)
    assert check_limit("store_a", "key1", 3) is False
    assert check_limit("store_b", "key1", 3) is True


def test_check_limit_window_expiry(monkeypatch):
    from ratelimit import check_limit

    fake_time = [1000.0]
    monkeypatch.setattr(time, "time", lambda: fake_time[0])
    # Fill up limit
    for _ in range(3):
        check_limit("expire", "key1", 3, window_seconds=1)
    assert check_limit("expire", "key1", 3, window_seconds=1) is False
    # Advance past window
    fake_time[0] = 1001.1
    assert check_limit("expire", "key1", 3, window_seconds=1) is True


# --- get_count ---


def test_get_count_zero():
    from ratelimit import get_count

    assert get_count("test", "nonexistent") == 0


def test_get_count_tracks():
    from ratelimit import check_limit, get_count

    check_limit("counter", "key1", 100)
    check_limit("counter", "key1", 100)
    check_limit("counter", "key1", 100)
    assert get_count("counter", "key1") == 3


def test_get_count_respects_window(monkeypatch):
    from ratelimit import check_limit, get_count

    fake_time = [1000.0]
    monkeypatch.setattr(time, "time", lambda: fake_time[0])
    check_limit("window", "key1", 100, window_seconds=1)
    assert get_count("window", "key1", window_seconds=1) == 1
    fake_time[0] = 1001.1
    assert get_count("window", "key1", window_seconds=1) == 0


# --- reset ---


def test_reset_single_store():
    from ratelimit import check_limit, get_count, reset

    check_limit("a", "key", 100)
    check_limit("b", "key", 100)
    reset("a")
    assert get_count("a", "key") == 0
    assert get_count("b", "key") == 1


# --- get_reset_time ---


def test_get_reset_time_zero_when_empty():
    from ratelimit import get_reset_time

    assert get_reset_time("test", "nobody") == 0


def test_get_reset_time_positive_when_active():
    from ratelimit import check_limit, get_reset_time

    check_limit("timer", "key1", 100, window_seconds=3600)
    reset_time = get_reset_time("timer", "key1", window_seconds=3600)
    assert 3590 <= reset_time <= 3600


def test_get_reset_time_decreases(monkeypatch):
    from ratelimit import check_limit, get_reset_time

    fake_time = [1000.0]
    monkeypatch.setattr(time, "time", lambda: fake_time[0])
    check_limit("decay", "key1", 100, window_seconds=2)
    fake_time[0] = 1001.0
    reset_time = get_reset_time("decay", "key1", window_seconds=2)
    assert 0 <= reset_time <= 1


def test_reset_all():
    from ratelimit import check_limit, get_count, reset

    check_limit("x", "key", 100)
    check_limit("y", "key", 100)
    reset()
    assert get_count("x", "key") == 0
    assert get_count("y", "key") == 0


# --- check_limit_with_count ---


class TestCheckLimitWithCount:
    def test_under_limit_returns_true_and_remaining(self):
        from ratelimit import check_limit_with_count

        allowed, remaining = check_limit_with_count("cwc", "key1", 5)
        assert allowed is True
        assert remaining == 4  # 5 - 1

    def test_at_limit_returns_false_zero(self):
        from ratelimit import check_limit_with_count

        for _ in range(5):
            check_limit_with_count("cwc_full", "key1", 5)
        allowed, remaining = check_limit_with_count("cwc_full", "key1", 5)
        assert allowed is False
        assert remaining == 0

    def test_count_decreases_correctly(self):
        from ratelimit import check_limit_with_count

        _, rem1 = check_limit_with_count("cwc_dec", "key1", 3)
        _, rem2 = check_limit_with_count("cwc_dec", "key1", 3)
        _, rem3 = check_limit_with_count("cwc_dec", "key1", 3)
        assert rem1 == 2
        assert rem2 == 1
        assert rem3 == 0
