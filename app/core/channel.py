"""Channel classification for usage analytics (regulars-chart attribution).

Maps MCP initialize clientInfo.name (priority) or the User-Agent header
(fallback) to a fixed label set. Raw strings are never stored — only the
coarse label reaches the world-readable api.db, mirroring the
normalize_endpoint coarsening precedent in db.py.
"""

import re

# The ONLY values that may reach api_usage.channel.
CHANNELS = frozenset(
    {
        "claude-desktop",
        "claude-code",
        "chatgpt",
        "cursor",
        "gemini-cli",
        "windsurf",
        "vscode",
        "opencode",
        "node",
        "python",
        "curl",
        "bot",
        "other",
    }
)

# clientInfo.name shape guard: short printable token (spaces allowed —
# "Claude Desktop"). Anything else is attacker-shaped → ignored, UA fallback.
_NAME_SHAPE = re.compile(r"^[A-Za-z0-9 ._/\-]{1,64}\Z")

# Substring → label for sanitized clientInfo names; first hit wins.
_CLIENTINFO_MAP = (
    ("claude-desktop", "claude-desktop"),
    ("claude desktop", "claude-desktop"),
    ("claude-code", "claude-code"),
    ("claude code", "claude-code"),
    ("chatgpt", "chatgpt"),
    ("openai", "chatgpt"),
    ("cursor", "cursor"),
    ("gemini", "gemini-cli"),
    ("windsurf", "windsurf"),
    ("visual studio code", "vscode"),
    ("vscode", "vscode"),
    ("opencode", "opencode"),
)

# UA substrings that identify crawlers/liveness probes (lowercased match).
_UA_BOT_TOKENS = (
    "bot",
    "crawler",
    "spider",
    "sentineloracle",
    "aisec-registry",
    "doppelops",
    "402explorer",
    "mcpscoringengine",
    "loop-mcp-catalog",
    "agent-tools",
)


def classify_channel(client_info_name: str | None, user_agent: str | None) -> str:
    """Coarse runtime label for a request. clientInfo wins; UA is fallback."""
    if client_info_name and _NAME_SHAPE.match(client_info_name):
        name = client_info_name.lower()
        for token, label in _CLIENTINFO_MAP:
            if token in name:
                return label
    ua = user_agent.strip().lower() if isinstance(user_agent, str) else ""
    if not ua:
        return "other"
    if ua.startswith("claude-code/"):
        return "claude-desktop" if "claude-desktop" in ua else "claude-code"
    if ua.startswith("opencode/"):
        return "opencode"
    if ua.startswith(("python-httpx", "python-requests", "python-urllib", "aiohttp")):
        return "python"
    if ua.startswith("curl/"):
        return "curl"
    # Before the bot tokens: ChatGPT-User's real UA embeds "+https://openai.com/bot".
    # GPTBot / OAI-SearchBot crawlers contain neither substring and stay "bot".
    if "chatgpt" in ua or "openai-" in ua:
        return "chatgpt"
    if any(t in ua for t in _UA_BOT_TOKENS):
        return "bot"
    if ua.startswith(("node", "undici")):
        return "node"
    return "other"
