"""Tests for config.py — Settings (pydantic) + module-level constants.

Settings is exercised by instantiating ``Settings()`` directly with the test
env (via monkeypatch) rather than reloading the config module. Reloading
config orphans every ``from config import settings`` reference held by other
modules, so subsequent tests would patch a singleton that the route handlers
no longer see.
"""

from pathlib import Path

from config import Settings


def test_base_dir_is_app():
    from config import BASE_DIR

    assert BASE_DIR.name == "app"
    assert BASE_DIR.is_dir()


def test_settings_db_paths_are_path():
    from config import settings

    assert isinstance(settings.api_db, Path)
    assert isinstance(settings.cve_db, Path)
    assert isinstance(settings.cache_db, Path)


def test_settings_default_path_fallback(monkeypatch):
    """When CONTRASTAPI_DB is unset and /var/lib/contrastapi/ doesn't exist, fall back to BASE_DIR."""
    monkeypatch.delenv("CONTRASTAPI_DB", raising=False)
    monkeypatch.delenv("CONTRASTAPI_CVE_DB", raising=False)
    monkeypatch.delenv("CONTRASTAPI_CACHE_DB", raising=False)
    s = Settings()
    if not Path("/var/lib/contrastapi").exists():
        assert "app" in str(s.api_db)


def test_settings_env_override_db_path(monkeypatch, tmp_path):
    db_file = tmp_path / "test.db"
    monkeypatch.setenv("CONTRASTAPI_DB", str(db_file))
    s = Settings()
    assert s.api_db == db_file


def test_settings_env_override_secrets(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "nvd-test-xxx")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuse-test-xxx")
    monkeypatch.setenv("SHODAN_API_KEY", "shodan-test-xxx")
    monkeypatch.setenv("URLHAUS_API_KEY", "urlhaus-test-xxx")
    monkeypatch.setenv("LEMONSQUEEZY_WEBHOOK_SECRET", "lemon-test-xxx")
    monkeypatch.setenv("LEMONSQUEEZY_API_KEY", "lemon-api-test-xxx")
    monkeypatch.setenv("NOWPAYMENTS_API_KEY", "nowpay-test-xxx")
    monkeypatch.setenv("NOWPAYMENTS_IPN_SECRET", "ipn-test-xxx")
    s = Settings()
    assert s.nvd_api_key == "nvd-test-xxx"
    assert s.abuseipdb_api_key == "abuse-test-xxx"
    assert s.shodan_api_key == "shodan-test-xxx"
    assert s.urlhaus_api_key == "urlhaus-test-xxx"
    assert s.lemonsqueezy_webhook_secret == "lemon-test-xxx"
    assert s.lemonsqueezy_api_key == "lemon-api-test-xxx"
    assert s.nowpayments_api_key == "nowpay-test-xxx"
    assert s.nowpayments_ipn_secret == "ipn-test-xxx"


def test_settings_secrets_default_empty(monkeypatch):
    """Unset env vars produce empty strings, not None — callers do `if not key:` checks."""
    for var in (
        "NVD_API_KEY",
        "ABUSEIPDB_API_KEY",
        "SHODAN_API_KEY",
        "URLHAUS_API_KEY",
        "LEMONSQUEEZY_WEBHOOK_SECRET",
        "LEMONSQUEEZY_API_KEY",
        "NOWPAYMENTS_API_KEY",
        "NOWPAYMENTS_IPN_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)
    s = Settings()
    assert s.nvd_api_key == ""
    assert s.abuseipdb_api_key == ""
    assert s.shodan_api_key == ""
    assert s.urlhaus_api_key == ""
    assert s.lemonsqueezy_webhook_secret == ""
    assert s.lemonsqueezy_api_key == ""
    assert s.nowpayments_api_key == ""
    assert s.nowpayments_ipn_secret == ""


def test_settings_hash_secret_uses_env_when_set(monkeypatch):
    monkeypatch.setenv("CONTRASTAPI_HASH_SECRET", ("aa" * 32))
    s = Settings()
    assert s.hash_secret == ("aa" * 32)


def test_settings_hash_secret_fallback_deterministic(monkeypatch):
    """Empty CONTRASTAPI_HASH_SECRET → deterministic SHA-256 over hostname + db path."""
    monkeypatch.delenv("CONTRASTAPI_HASH_SECRET", raising=False)
    h1 = Settings().hash_secret
    h2 = Settings().hash_secret
    assert h1 == h2
    assert len(h1) == 64  # sha256 hex


def test_settings_target_throttle_disabled_default_false(monkeypatch):
    monkeypatch.delenv("TARGET_THROTTLE_DISABLED", raising=False)
    assert Settings().target_throttle_disabled is False


def test_settings_target_throttle_disabled_env(monkeypatch):
    monkeypatch.setenv("TARGET_THROTTLE_DISABLED", "1")
    assert Settings().target_throttle_disabled is True


def test_settings_testing_flag(monkeypatch):
    monkeypatch.setenv("TESTING", "1")
    assert Settings().testing is True


def test_settings_extra_env_ignored(monkeypatch):
    """Unrecognised env vars must not raise (extra='ignore')."""
    monkeypatch.setenv("UNRELATED_VAR_XYZ", "noise")
    s = Settings()
    assert not hasattr(s, "unrelated_var_xyz")


def test_settings_direct_instantiation_for_unit_tests():
    """Settings can be instantiated with kwargs — useful for testing alternate configs without env mutation."""
    s = Settings(nvd_api_key="direct-arg", abuseipdb_api_key="also-direct")
    assert s.nvd_api_key == "direct-arg"
    assert s.abuseipdb_api_key == "also-direct"


def test_singleton_is_mutable():
    """Tests rely on ``patch('config.settings.X', value)`` to flip secrets per test;
    that requires the singleton to be mutable (BaseSettings default, but pin it here)."""
    from config import settings

    original = settings.nvd_api_key
    settings.nvd_api_key = "mutated-by-test"
    try:
        assert settings.nvd_api_key == "mutated-by-test"
    finally:
        settings.nvd_api_key = original


def test_rate_limits_positive():
    from config import FREE_HOURLY_LIMIT, PRO_HOURLY_LIMIT

    assert FREE_HOURLY_LIMIT > 0
    assert PRO_HOURLY_LIMIT > FREE_HOURLY_LIMIT


def test_key_prefix():
    from config import KEY_LENGTH, KEY_PREFIX

    assert KEY_PREFIX == "cc_"
    assert KEY_LENGTH == 48


def test_max_domain_length():
    from config import MAX_DOMAIN_LENGTH

    assert MAX_DOMAIN_LENGTH == 253


def test_severity_order():
    from config import SEVERITY_ORDER

    assert SEVERITY_ORDER["critical"] < SEVERITY_ORDER["high"]
    assert SEVERITY_ORDER["high"] < SEVERITY_ORDER["medium"]
    assert SEVERITY_ORDER["medium"] < SEVERITY_ORDER["low"]
