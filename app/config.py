"""Configuration for ContrastAPI.

Env-backed values live on the ``Settings`` class (pydantic-settings, typed).
Pure constants stay as module-level globals. Import ``settings`` to read any
env-derived value — no module-level aliases.
"""

import hashlib
import socket
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

VERSION = "1.35.3"
MCP_TOOL_COUNT = 55  # +geo_audit (AI-visibility readiness); Faz-2: +contrast_scan
MCP_RESOURCE_COUNT = 7  # v1.23.0: atlas+d3fend+cwe (4 templates + 3 catalogs)
MCP_PROMPT_COUNT = 3  # v1.23.0: security_audit, vulnerability_check, contrast_triage
ENDPOINT_COUNT = "60+"
TEST_COUNT = 2446
# Catalog row counts surfaced on the landing page. Bump after `python -m cve.sync
# --source atlas` (ATLAS upstream cadence ~6 months) or `--source d3fend` (yearly).
ATLAS_TECHNIQUE_COUNT = 167
ATLAS_CASE_STUDY_COUNT = 57
D3FEND_DEFENSE_COUNT = 149

# asn_lookup: prefix list cap to keep MCP responses within token budget.
# Cloudflare AS13335 announces 2500+ IPv4 prefixes; full list blows past
# context. Cache stores full set, response truncates per request.
MAX_ASN_PREFIXES_DEFAULT = 50

# .resolve() is load-bearing: via the MCP `from app.*` path, config can be
# imported through uvicorn's relative "." sys.path entry → relative __file__ →
# the Path(".").parent == Path(".") trap silently breaks BASE_DIR.parent paths
# (SCANNER_PATH pointed one level too deep → contrast_scan "Scanner not available").
BASE_DIR = Path(__file__).resolve().parent


class Settings(BaseSettings):
    """Env-backed configuration.

    Field names are pythonic; ``alias`` maps to the actual env var. Reading
    ``settings.api_db`` returns a typed ``Path``; ``settings.nvd_api_key`` a
    ``str``. Tests override via ``monkeypatch.setenv`` + module reload, or by
    instantiating ``Settings(api_db=...)`` directly.

    Operational filesystem paths (DBs, log file, manifest) default to
    ``BASE_DIR``-relative for local dev; production sets explicit absolute
    paths via the systemd ``EnvironmentFile``.
    """

    model_config = SettingsConfigDict(
        env_file=None,  # systemd EnvironmentFile already injects into os.environ
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    # DB paths (typed Path; prod overrides via env vars, dev uses BASE_DIR-relative)
    api_db: Path = Field(
        default_factory=lambda: BASE_DIR / "api.db",
        alias="CONTRASTAPI_DB",
    )
    cve_db: Path = Field(
        default_factory=lambda: BASE_DIR / "cve.db",
        alias="CONTRASTAPI_CVE_DB",
    )
    cache_db: Path = Field(
        default_factory=lambda: BASE_DIR / "domain_cache.db",
        alias="CONTRASTAPI_CACHE_DB",
    )
    sigma_path: Path = Field(
        default_factory=lambda: BASE_DIR / "tests" / "fixtures" / "sigma",
        alias="CONTRASTAPI_SIGMA_PATH",
    )

    # Operational artifacts (prod overrides via env vars, dev uses BASE_DIR-relative)
    mcp_tool_log_path: Path = Field(
        default_factory=lambda: BASE_DIR / "mcp_tools.jsonl",
        alias="MCP_TOOL_LOG_PATH",
    )
    glama_manifest_path: Path = Field(
        default_factory=lambda: BASE_DIR / "glama.json",
        alias="GLAMA_MANIFEST_PATH",
    )

    # CVE intelligence
    nvd_api_key: str = ""

    # Billing — Lemon Squeezy (cards) + NOWPayments (crypto)
    lemonsqueezy_webhook_secret: str = ""
    lemonsqueezy_api_key: str = ""
    nowpayments_api_key: str = ""
    nowpayments_ipn_secret: str = ""

    # External enrichment APIs
    abuseipdb_api_key: str = ""
    shodan_api_key: str = ""
    shodan_refs_limit: int = Field(default=200, alias="SHODAN_REFS_LIMIT", ge=1, le=1000)
    urlhaus_api_key: str = ""

    # Privacy — empty → deterministic fallback (host+db) computed below.
    hash_secret_raw: str = Field(default="", alias="CONTRASTAPI_HASH_SECRET")

    # Test mode + per-target throttle kill-switch
    testing: bool = False
    target_throttle_disabled: bool = False

    @property
    def hash_secret(self) -> str:
        """Final hash secret. Env value when set, deterministic host+db fallback otherwise."""
        if self.hash_secret_raw:
            return self.hash_secret_raw
        return hashlib.sha256(f"{socket.gethostname()}:{self.api_db}".encode()).hexdigest()


settings = Settings()

# Rate limits
FREE_HOURLY_LIMIT = 30  # keyless: 30 req/hr per IP (S236, P90 of legit usage)
PRO_HOURLY_LIMIT = 500  # Pro key: 500 req/hr (S236, 16.7x Free, well above legit human peak ~80/hr)
FIRST_SWIPE_ENABLED = True  # feature flag for the IP-grace below (name kept from v1.34.0 for compat)
# v1.34.x IP-grace: replaces the per-(identity,tool) first-swipe ledger with ONE
# 24h grace window per keyless identity. The clock starts at the identity's first
# eligible keyless cost==1 MCP call (not literal first HTTP contact) and never
# resets; inside the window every cost==1 MCP tool meters against
# GRACE_HOURLY_LIMIT on a separate namespace (DoS backstop) instead of the 30/hr
# Free wall. After the window the identity permanently falls back to
# FREE_HOURLY_LIMIT.
GRACE_WINDOW_SECONDS = 86400  # 24h grace window (one per identity, never reset)
GRACE_HOURLY_LIMIT = 120  # per-bucket ceiling DURING grace (DoS backstop, not the 30/hr wall)
# v1.27: per-tier bulk caps removed; bulk endpoints partial-fill against the
# caller's remaining hourly quota (Pydantic max_length=50 still bounds input).
ENRICHMENT_DAILY_LIMIT = 10  # enriched scans per IP per day (protects external API quotas)

# v1.25.0 web-intel etik guardrail stack
# Per-target eTLD+1 throttle: paying customers can't weaponise our infra against
# a single target site. Subdomain rotation (a1.victim.com / a2.victim.com) maps
# to the same eTLD+1 bucket so the cap can't be cheaply bypassed.
TARGET_THROTTLE_PER_MIN = 60
TARGET_THROTTLE_DAILY_ALERT = 500  # Telegram fires once/day when an eTLD+1 crosses
BOT_USER_AGENT = f"ContrastAPI/{VERSION} (+https://contrastcyber.com/bot)"

# robots.txt fetcher — max body size before truncation (well above 99% of real
# files; Google itself stops parsing past 500KB but caps at 1MB).
ROBOTS_MAX_BYTES = 512 * 1024
ROBOTS_TIMEOUT = 5  # seconds — separate from RECON_TIMEOUT so robots fetch can be tuned independently
ROBOTS_CACHE_TTL = 3600  # 1 hour — robots.txt is fairly stable but not static

# redirect_chain endpoint — manual hop-by-hop walk so we can re-validate the SSRF
# guard at every redirect target, AND so that target_throttle gets a chance to
# fire on each cross-host hop (a chain across 11 unrelated domains can't
# slip through with one throttle slot).
# Cache TTL is currently the shared DOMAIN_CACHE_TTL=1h via save_cached_domain;
# per-key TTL override is parked for v1.26+.
REDIRECT_MAX_HOPS = 10
REDIRECT_TIMEOUT = 5  # seconds per hop

# brand_assets endpoint — homepage HTML scrape for favicon, og:image, theme-color,
# og:site_name, JSON-LD organization.logo. Honour robots.txt Disallow on the
# target's homepage for our UA (Guardrail #3 in v1.25.0 plan).
BRAND_ASSETS_TIMEOUT = 5  # seconds, separate from RECON_TIMEOUT
BRAND_ASSETS_CACHE_TTL = 3600  # 1h via DOMAIN_CACHE_TTL pathway

# Endpoint token costs — based on upstream API calls per request.
# Default is 1 (single upstream). Orchestration endpoints cost more because
# they aggregate multiple sources. Transparent pricing, surfaced via X-RateLimit-Cost header.
#
# v1.32.4 Plan A (2026-05-14) raised composite costs to align Free 30/hr with
# the "2 guaranteed premium / 3 mid / 5 light composite calls per hour" target.
# Breaking change from v1.32.3: audit + threat + domain_vulns. See research.md.
COST_DEFAULT = 1
COST_AUDIT = 6  # v1.32.4 4->6 — DNS+WHOIS+SSL+CT+subdom+headers+tech+email+cache (9-11 sources)
COST_THREAT_REPORT = 6  # v1.32.4 4->6 — IP enrich+AbuseIPDB+Shodan+ASN+Tor+cloud+FireHOL+CVE (8 sources)
COST_DOMAIN_VULNS = 4  # v1.32.4 NEW (was implicit cost=1) — tech_fingerprint + bulk CVE per product
COST_TECH_CVE_AUDIT = 10  # v1.32.4 NEW — tech_fingerprint + bulk_cve + exploit_lookup + kev_detail
COST_GENERATE_RISK_REPORT = 15  # v1.32.4 NEW — N CVE risk-score + markdown (Pro upsell anchor)
COST_CVE_TIMELINE = 6  # v1.32.4 NEW — KEV + EPSS + PoC count + vendor advisory feeds
COST_PRIORITIZE_CVES = 10  # v1.32.4 NEW — bulk_cve + per-item calculate_risk_score
COST_TRENDING_CVES = 5  # v1.32.4 NEW — EPSS feed + cve_search (marketing/SEO funnel)
COST_SCAN = 6  # Faz-2 5->6 — website scan: C binary (11 modules) + findings enrichment, composite

# API key
KEY_PREFIX = "cc_"
KEY_LENGTH = 48  # hex chars after prefix

# Upgrade signal — pricing URL surfaced to free-tier clients on 429
UPGRADE_URL = "https://api.contrastcyber.com/pricing"

# Domain validation
MAX_DOMAIN_LENGTH = 253

# Username validation
MAX_USERNAME_LENGTH = 39  # GitHub's limit, reasonable cap

# Domain cache TTL
DOMAIN_CACHE_TTL = 3600  # 1 hour

# NVD sync
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE_SIZE = 2000

# CISA KEV (GitHub mirror — CISA blocks datacenter IPs)
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"

# FIRST EPSS
EPSS_URL = "https://api.first.org/data/v1/epss"

# MITRE cvelistV5 (CNA-direct upstream, typically hours ahead of NVD)
MITRE_RELEASES_URL = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"

# MITRE CWE catalog (weekly cadence; ZIP of CSVs by view: 1000 = research, 699 = software)
CWE_ZIP_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"

# GitHub Security Advisories (leads NVD on OSS CVEs)
GHSA_API_URL = "https://api.github.com/advisories"

# External API URLs
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
SHODAN_API_URL = "https://api.shodan.io/shodan/host"
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1"
HIBP_URL = "https://api.pwnedpasswords.com/range"

# Feodo Tracker cache
FEODO_TTL = 3600  # 1 hour cache refresh
FEODO_MAX_BYTES = 10 * 1024 * 1024  # 10 MB response size limit

# IP intel cache (cloud provider ranges + Tor exit list)
CLOUD_IP_TTL = 3600
TOR_EXIT_TTL = 3600
CLOUD_IP_MAX_BYTES = 5 * 1024 * 1024  # AWS ~1.5MB, GCP ~200KB, CF ~5KB
TOR_EXIT_MAX_BYTES = 1 * 1024 * 1024
AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GCP_IP_RANGES_URL = "https://www.gstatic.com/ipranges/cloud.json"
CF_IP_RANGES_URL = "https://api.cloudflare.com/client/v4/ips"
TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"

# FireHOL level1 reputation (aggregated spam/malware/botnet blocklist, daily)
FIREHOL_TTL = 6 * 3600  # 6 hours — upstream updates daily, 4x refresh = max 6h staleness
FIREHOL_MAX_BYTES = 5 * 1024 * 1024
FIREHOL_LEVEL1_URL = "https://iplists.firehol.org/files/firehol_level1.netset"
FIREHOL_FAILURE_BACKOFF_SEC = 60  # suppress retry for 60s after consecutive failures
FIREHOL_FAILURE_THRESHOLD = 3  # trip backoff after this many consecutive failures

# IP cache TTL
IP_CACHE_TTL = 3600  # 1 hour

# Cache entry size limit
CACHE_MAX_BYTES = 1 * 1024 * 1024  # 1 MB per cached result

# Timeouts
RECON_TIMEOUT = 5
USERNAME_LOOKUP_TIMEOUT = 5  # per-platform HTTP timeout for username checks
USERNAME_MAX_RETRIES = 2  # additional attempts on 403/429/timeout/5xx (first try excluded)
USERNAME_BACKOFF_INITIAL = 1.0  # seconds before first retry
USERNAME_BACKOFF_MULTIPLIER = 2.0  # exponential backoff factor
# lowered from 10: crt.sh slow responses dominated wall time; 3s graceful fallback to wordlist subdomains
CRTSH_TIMEOUT = 3
CRTSH_MAX_RESULTS = 1000
CRTSH_MAX_BYTES = 10 * 1024 * 1024  # 10 MB hard cap on crt.sh response body before JSON parse
BULK_PER_DOMAIN_TIMEOUT = 25
# Hard ceiling for /v1/domain/{domain} single-domain report. Lower than
# BULK_PER_DOMAIN_TIMEOUT because slow upstream fail-overs (WHOIS, CT logs,
# subdomain enum) tied up workers during bot-fuzz bursts (Session 202, 1 May
# 2026). Cap at 8s — typical full report completes in 2-5s; >8s indicates a
# stuck upstream.
DOMAIN_HARD_TIMEOUT = 8
# Behavioral burst throttle for /v1/domain/{domain} — Free tier only. Catches
# UA-rotating bot fleets that bypass nginx UA blocklist by querying many
# distinct domains rapidly. Pro tier explicitly pays for higher quota and is
# not throttled here.
DOMAIN_BURST_LIMIT = 5
DOMAIN_BURST_WINDOW = 60

# Wayback Machine CDX API limits
WAYBACK_CDX_TIMEOUT = 20
WAYBACK_CDX_MAX_RESULTS = 10000
WAYBACK_CDX_MAX_BYTES = 50 * 1024 * 1024  # 50 MB body cap
WAYBACK_CACHE_TTL = 86400  # 24h — wayback history is very stable
# Short TTL for upstream-failure responses (Bug I): a 1-second CDX hiccup must not
# poison the cache for 24h. 5 min absorbs retry bursts while letting transient
# outages recover quickly.
WAYBACK_CACHE_TTL_UNAVAILABLE = 300
WAYBACK_CACHE_MAX = 500  # LRU cap on in-memory cache
BULK_OVERALL_TIMEOUT = 120  # hard cap for entire bulk request; partial results returned on expiry

# Severity ordering
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_LEVELS = ("critical", "high", "medium", "low")

# Website scanner engine (ContrastScan port — Faz-2: wired to /v1/scan + MCP contrast_scan)
SCANNER_PATH = BASE_DIR.parent / "scanner" / "contrastscan"
SCAN_TIMEOUT = 30  # seconds — hard cap on one scanner subprocess
SCAN_CONCURRENCY = 3  # Faz-2 5->3 — max simultaneous scanner subprocesses (engine snapshots at import)
