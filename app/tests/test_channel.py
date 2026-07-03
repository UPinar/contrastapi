"""Tests for core.channel.classify_channel + the api_usage.channel column.

Channel = coarse runtime label (fixed enum) for regulars-chart attribution.
clientInfo.name wins over User-Agent; raw strings never reach the DB.
"""


class TestClassifyChannel:
    def test_clientinfo_wins_over_ua(self):
        from core.channel import classify_channel

        assert classify_channel("cursor", "node") == "cursor"

    def test_clientinfo_claude_desktop_name(self):
        from core.channel import classify_channel

        assert classify_channel("Claude Desktop", None) == "claude-desktop"

    def test_clientinfo_gemini_substring(self):
        from core.channel import classify_channel

        assert classify_channel("gemini-cli-mcp-client", "node") == "gemini-cli"

    def test_clientinfo_bad_shape_falls_back_to_ua(self):
        from core.channel import classify_channel

        assert classify_channel("evil\nname@x.com", "curl/8.5.0") == "curl"

    def test_clientinfo_unknown_falls_back_to_ua(self):
        from core.channel import classify_channel

        assert classify_channel("rl-test", "python-httpx/0.28.1") == "python"

    def test_ua_claude_desktop(self):
        from core.channel import classify_channel

        assert classify_channel(None, "claude-code/2.1.197 (claude-desktop, agent-sdk/0.3.197)") == "claude-desktop"

    def test_ua_claude_code_cli(self):
        from core.channel import classify_channel

        assert classify_channel(None, "claude-code/2.1.88-source.0 (cli)") == "claude-code"

    def test_ua_opencode(self):
        from core.channel import classify_channel

        assert classify_channel(None, "opencode/1.17.12") == "opencode"

    def test_ua_python_requests(self):
        from core.channel import classify_channel

        assert classify_channel(None, "python-requests/2.34.2") == "python"

    def test_ua_known_bot(self):
        from core.channel import classify_channel

        assert classify_channel(None, "SentinelOracle/0.1 (liveness-only)") == "bot"

    def test_ua_node_and_undici(self):
        from core.channel import classify_channel

        assert classify_channel(None, "node") == "node"
        assert classify_channel(None, "undici") == "node"

    def test_ua_browser_and_empty_are_other(self):
        from core.channel import classify_channel

        assert classify_channel(None, "Mozilla/5.0 (X11; Linux x86_64)") == "other"
        assert classify_channel(None, "") == "other"
        assert classify_channel(None, None) == "other"

    def test_non_string_ua_is_other(self):
        from core.channel import classify_channel

        assert classify_channel(None, 123) == "other"

    def test_clientinfo_chatgpt_and_openai(self):
        from core.channel import classify_channel

        assert classify_channel("ChatGPT", None) == "chatgpt"
        assert classify_channel("openai-mcp", "python-httpx/0.28.1") == "chatgpt"

    def test_ua_chatgpt_user_not_bot(self):
        from core.channel import classify_channel

        # Real ChatGPT-User UA embeds "+https://openai.com/bot" — the chatgpt
        # rule must win over the bot-token substring match.
        ua = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"
        assert classify_channel(None, ua) == "chatgpt"
        assert classify_channel(None, "openai-mcp/1.0") == "chatgpt"

    def test_ua_openai_crawlers_stay_bot(self):
        from core.channel import classify_channel

        # GPTBot / OAI-SearchBot are web crawlers, not MCP user runtimes.
        assert classify_channel(None, "GPTBot/1.1 (+https://openai.com/gptbot)") == "bot"
        assert classify_channel(None, "OAI-SearchBot/1.0; +https://openai.com/searchbot") == "bot"

    def test_every_label_in_allowed_set(self):
        from core.channel import CHANNELS, classify_channel

        for ci, ua in [
            ("cursor", None),
            (None, "curl/8.5.0"),
            (None, "weird-thing/9"),
            ("Claude Desktop", "node"),
        ]:
            assert classify_channel(ci, ua) in CHANNELS


class TestChannelColumn:
    def test_api_usage_has_channel_column(self):
        from db import get_api_db

        with get_api_db() as con:
            cols = {r[1] for r in con.execute("PRAGMA table_info(api_usage)").fetchall()}
        assert "channel" in cols

    def test_log_usage_writes_channel(self):
        from db import get_api_db, log_usage

        log_usage("1.2.3.4", "/v1/cve/test", channel="python")
        with get_api_db() as con:
            row = con.execute("SELECT channel FROM api_usage ORDER BY id DESC LIMIT 1").fetchone()
        assert row[0] == "python"

    def test_log_usage_channel_defaults_null(self):
        from db import get_api_db, log_usage

        log_usage("1.2.3.4", "/v1/cve/test")
        with get_api_db() as con:
            row = con.execute("SELECT channel FROM api_usage ORDER BY id DESC LIMIT 1").fetchone()
        assert row[0] is None

    def test_init_api_db_rerun_is_idempotent(self):
        from db import init_api_db

        init_api_db()
        init_api_db()
