"""Configuration constants for ContrastAPI"""

import hashlib
import os
import socket
from pathlib import Path

VERSION = "1.7.0"
MCP_TOOL_COUNT = 31
ENDPOINT_COUNT = "40+"

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

# GitHub Security Advisories (leads NVD on OSS CVEs)
GHSA_API_URL = "https://api.github.com/advisories"

# Lemon Squeezy (payment / API key provisioning)
LEMONSQUEEZY_WEBHOOK_SECRET = os.environ.get("LEMONSQUEEZY_WEBHOOK_SECRET", "")
LEMONSQUEEZY_API_KEY = os.environ.get("LEMONSQUEEZY_API_KEY", "")

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

# IP cache TTL
IP_CACHE_TTL = 3600  # 1 hour

# Cache entry size limit
CACHE_MAX_BYTES = 1 * 1024 * 1024  # 1 MB per cached result

# Timeouts
RECON_TIMEOUT = 5
USERNAME_LOOKUP_TIMEOUT = 5  # per-platform HTTP timeout for username checks
CRTSH_TIMEOUT = 10
BULK_PER_DOMAIN_TIMEOUT = 25  # must exceed CRTSH_TIMEOUT + RECON_TIMEOUT + buffer (19s worst case)
BULK_OVERALL_TIMEOUT = 120  # hard cap for entire bulk request; partial results returned on expiry

# Severity ordering
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Client IP hashing secret — deterministic fallback so hashes survive restarts
_raw_secret = os.environ.get("CONTRASTAPI_HASH_SECRET", "")
HASH_SECRET = _raw_secret or hashlib.sha256(f"{socket.gethostname()}:{API_DB_PATH}".encode()).hexdigest()
