"""Configuration constants for ContrastAPI"""

import hashlib
import os
import socket
from pathlib import Path

VERSION = "1.24.2"
MCP_TOOL_COUNT = 44  # v1.25.0 Batch 3: +robots_txt +redirect_chain
MCP_RESOURCE_COUNT = 7  # v1.23.0: atlas+d3fend+cwe (4 templates + 3 catalogs)
MCP_PROMPT_COUNT = 3  # v1.23.0: security_audit, vulnerability_check, contrast_triage
ENDPOINT_COUNT = "50+"
TEST_COUNT = 1666
# Catalog row counts surfaced on landing/playground. Bump after `python -m cve.sync
# --source atlas` (ATLAS upstream cadence ~6 months) or `--source d3fend` (yearly).
ATLAS_TECHNIQUE_COUNT = 167
ATLAS_CASE_STUDY_COUNT = 57
D3FEND_DEFENSE_COUNT = 149

# asn_lookup: prefix list cap to keep MCP responses within token budget.
# Cloudflare AS13335 announces 2500+ IPv4 prefixes; full list blows past
# context. Cache stores full set, response truncates per request.
MAX_ASN_PREFIXES_DEFAULT = 50

BASE_DIR = Path(__file__).parent

# Database paths
_default_api_db = Path("/var/lib/contrastapi/api.db")
_default_cve_db = Path("/var/lib/contrastapi/cve.db")
_default_cache_db = Path("/var/lib/contrastapi/domain_cache.db")

API_DB_PATH = Path(
    os.environ.get("CONTRASTAPI_DB", str(_default_api_db if _default_api_db.parent.exists() else BASE_DIR / "api.db"))
)
CVE_DB_PATH = Path(
    os.environ.get(
        "CONTRASTAPI_CVE_DB", str(_default_cve_db if _default_cve_db.parent.exists() else BASE_DIR / "cve.db")
    )
)
CACHE_DB_PATH = Path(
    os.environ.get(
        "CONTRASTAPI_CACHE_DB",
        str(_default_cache_db if _default_cache_db.parent.exists() else BASE_DIR / "domain_cache.db"),
    )
)

# Rate limits
FREE_HOURLY_LIMIT = 100  # keyless: 100 req/hr per IP (shared across workers)
PRO_HOURLY_LIMIT = 1000  # Pro key: 1000 req/hr (shared across workers)
FREE_BULK_LIMIT = 10  # max domains per bulk request (free)
PRO_BULK_LIMIT = 50  # max domains per bulk request (pro)
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

# Endpoint credit costs — based on upstream API calls per request.
# Default is 1 (single upstream). Orchestration endpoints cost more because
# they aggregate multiple sources. Transparent pricing, surfaced via X-RateLimit-Cost header.
COST_DEFAULT = 1
COST_AUDIT = 4  # domain_report + live_headers + tech_detect + cache layer
COST_THREAT_REPORT = 4  # ip_enrichment + abuseipdb + shodan + asn

# API key
KEY_PREFIX = "cc_"
KEY_LENGTH = 48  # hex chars after prefix

# Upgrade signal — pricing URL surfaced to free-tier clients on 429
UPGRADE_URL = "https://contrastcyber.com/pricing"

# Domain validation
MAX_DOMAIN_LENGTH = 253

# Username validation
MAX_USERNAME_LENGTH = 39  # GitHub's limit, reasonable cap

# Domain cache TTL
DOMAIN_CACHE_TTL = 3600  # 1 hour

# NVD sync
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE_SIZE = 2000
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

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

# Lemon Squeezy (payment / API key provisioning)
LEMONSQUEEZY_WEBHOOK_SECRET = os.environ.get("LEMONSQUEEZY_WEBHOOK_SECRET", "")
LEMONSQUEEZY_API_KEY = os.environ.get("LEMONSQUEEZY_API_KEY", "")

# NOWPayments (crypto payment provider — RU/CN/IR fallback when card is restricted)
NOWPAYMENTS_API_KEY = os.environ.get("NOWPAYMENTS_API_KEY", "")
NOWPAYMENTS_IPN_SECRET = os.environ.get("NOWPAYMENTS_IPN_SECRET", "")

# External API keys (reputation/enrichment)
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
URLHAUS_API_KEY = os.environ.get("URLHAUS_API_KEY", "")

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

# Client IP hashing secret — deterministic fallback so hashes survive restarts
_raw_secret = os.environ.get("CONTRASTAPI_HASH_SECRET", "")
HASH_SECRET = _raw_secret or hashlib.sha256(f"{socket.gethostname()}:{API_DB_PATH}".encode()).hexdigest()
