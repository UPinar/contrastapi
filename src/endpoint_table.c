#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

#include "endpoint.h"
#include "cve.h"
#include "cvss.h"
#include "endpoint_run.h"
#include "endpoint_weight.h"
#include "external/hibp.h"
#include "dns.h"
#include "emailcheck.h"
#include "ip.h"
#include "ipguard.h"
#include "tlsprobe.h"
#include "header_fetch.h"
#include "vendorkey.h"
#include "keyvault.h"
#include "watchlist/watchlist.h"
#include "d3fend.h"
#include "lol.h"
#include "package.h"
#include "attack.h"
#include "jsonbuf.h"
#include "billing.h"
#include "macro.h"
#include "pricing.h"
#include "validate.h"

static const char* const CVSS_SEVERITY_VALUES[]      = { "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", NULL };
static const char* const CVESEARCH_SORT_VALUES[]     = { "published_time", "epss", "cvss", NULL };
static const char* const WATCHLIST_ACTION_VALUES[]   = { "add", "remove", NULL };
static const char* const VENDORKEYEDIT_ACTION_VALUES[] = { "apply", "status", NULL };
static const char* const WATCHLIST_ENDPOINT_VALUES[] = { "cve_lookup", "kev_lookup", "cve_exploit", "product_exposure", "cve_search", "dns_lookup", "ssl_check", "whois_lookup", "headers_check", "cert_search", "package_check", "ip_lookup", NULL };

static const EndpointParamSpec_t SPEC_VENDOR = {
  .mp_name              = "vendor",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = CVESEARCH_VENDOR_LEN,
  .m_validatorFunction  = validate_searchString,
  .mp_message           = "vendor must not contain wildcard %",
};

static const EndpointParamSpec_t SPEC_PRODUCT = {
  .mp_name              = "product",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = CVESEARCH_PRODUCT_LEN,
  .m_validatorFunction  = validate_searchString,
  .mp_message           = "product must not contain wildcard %",
};

static const EndpointParamSpec_t SPEC_SEVERITY = {
  .mp_name              = "severity",
  .m_type               = ENDPOINT_PARAM_TYPE_ENUM,
  .m_maxLen             = CVELOOKUP_SEVERITY_LEN,
  .mp_enumValues        = CVSS_SEVERITY_VALUES,
  .mp_message           = "severity must be CRITICAL, HIGH, MEDIUM, LOW, or NONE",
};

static const EndpointParamSpec_t SPEC_CVESEARCH_CWE_ID = {
  .mp_name              = "cwe_id",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = CVELOOKUP_CWE_ID_LEN,
  .m_validatorFunction  = validate_cweId,
  .mp_message           = "cwe_id must be CWE-N",
};

static const EndpointParamSpec_t SPEC_MIN_CVSS = {
  .mp_name              = "min_cvss",
  .m_type               = ENDPOINT_PARAM_TYPE_DOUBLE,
  .m_min                = 0.0,
  .m_max                = 10.0,
  .mp_message           = "min_cvss must be a number between 0.0 and 10.0",
  .m_default            = -1.0,
};

static const EndpointParamSpec_t SPEC_MIN_EPSS = {
  .mp_name              = "min_epss",
  .m_type               = ENDPOINT_PARAM_TYPE_DOUBLE,
  .m_min                = 0.0,
  .m_max                = 1.0,
  .mp_message           = "min_epss must be a number between 0.0 and 1.0",
  .m_default            = -1.0,
};

static const EndpointParamSpec_t SPEC_MIN_RISK_SCORE = {
  .mp_name              = "min_risk_score",
  .m_type               = ENDPOINT_PARAM_TYPE_DOUBLE,
  .m_min                = 0.0,
  .m_max                = 100.0,
  .mp_message           = "min_risk_score must be a number between 0.0 and 100.0",
  .m_default            = -1.0,
};

static const EndpointParamSpec_t SPEC_IN_KEV = {
  .mp_name              = "in_kev",
  .m_type               = ENDPOINT_PARAM_TYPE_KEV_FILTER,
  .mp_message           = "in_kev must be true or false",
};

static const EndpointParamSpec_t SPEC_KNOWN_RANSOMWARE = {
  .mp_name              = "known_ransomware",
  .m_type               = ENDPOINT_PARAM_TYPE_BOOL,
  .m_isOnlyTrueAccepted = true,
  .mp_message           = "known_ransomware must be true",
};

static const EndpointParamSpec_t SPEC_HAS_NUCLEI_TEMPLATE = {
  .mp_name              = "has_nuclei_template",
  .m_type               = ENDPOINT_PARAM_TYPE_BOOL,
  .m_isOnlyTrueAccepted = true,
  .mp_message           = "has_nuclei_template must be true",
};

static const EndpointParamSpec_t SPEC_PUBLISHED_AFTER = {
  .mp_name              = "published_after",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = CVELOOKUP_PUBLISHED_LEN,
  .m_validatorFunction  = validate_date,
  .mp_message           = "published_after must be a valid calendar date in YYYY-MM-DD form",
};

static const EndpointParamSpec_t SPEC_PUBLISHED_BEFORE = {
  .mp_name              = "published_before",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = CVELOOKUP_PUBLISHED_LEN,
  .m_validatorFunction  = validate_date,
  .mp_message           = "published_before must be a valid calendar date in YYYY-MM-DD form",
};

static const EndpointParamSpec_t SPEC_SORT = {
  .mp_name              = "sort",
  .m_type               = ENDPOINT_PARAM_TYPE_ENUM,
  .m_maxLen             = CVESEARCH_SORT_LEN - 1,
  .mp_enumValues        = CVESEARCH_SORT_VALUES,
  .mp_message           = "sort must be published_time, epss, or cvss",
};

static const EndpointParamSpec_t SPEC_LIMIT = {
  .mp_name              = "limit",
  .m_type               = ENDPOINT_PARAM_TYPE_INT,
  .m_min                = 1,
  .m_max                = CVE_LIST_MAX_LIMIT,
  .mp_message           = "limit must be an integer between 1 and 100",
  .m_default            = CVE_LIST_DEFAULT_LIMIT,
};

static const EndpointParamSpec_t SPEC_CVELEADING_LIMIT = {
  .mp_name              = "limit",
  .m_type               = ENDPOINT_PARAM_TYPE_INT,
  .m_min                = 1,
  .m_max                = CVE_LIST_RANKED_MAX_LIMIT,
  .mp_message           = "limit must be an integer between 1 and 50",
  .m_default            = CVE_LIST_DEFAULT_LIMIT,
};

static const EndpointParamSpec_t SPEC_CPESEARCH_LIMIT = {
  .mp_name              = "limit",
  .m_type               = ENDPOINT_PARAM_TYPE_INT,
  .m_min                = 1,
  .m_max                = CPESEARCH_MAX_LIMIT,
  .mp_message           = "limit must be an integer between 1 and 50",
  .m_default            = CVE_LIST_DEFAULT_LIMIT,
};

static const EndpointParamSpec_t SPEC_PACKAGECHECK_LIMIT = {
  .mp_name              = "limit",
  .m_type               = ENDPOINT_PARAM_TYPE_INT,
  .m_min                = 1,
  .m_max                = PACKAGECHECK_MAX_LIMIT,
  .mp_message           = "limit must be an integer between 1 and 50",
  .m_default            = CVE_LIST_DEFAULT_LIMIT,
};

static const EndpointParamSpec_t SPEC_PACKAGE_ECOSYSTEM = {
  .mp_name              = "ecosystem",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = PACKAGECHECK_ECOSYSTEM_MAX_LEN,
  .m_validatorFunction  = validate_packageEcosystem,
  .mp_message           = VALIDATE_PACKAGE_ECOSYSTEM_REFUSAL_MESSAGE,
};

static const EndpointParamSpec_t SPEC_PACKAGE_NAME = {
  .mp_name              = "name",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = PACKAGECHECK_NAME_MAX_LEN,
  .m_validatorFunction  = validate_packageName,
  .mp_message           = VALIDATE_PACKAGE_NAME_REFUSAL_MESSAGE,
};

_Static_assert(PRODUCTEXPOSURE_VERSION_MAX_LEN == PACKAGECHECK_VERSION_MAX_LEN,
               "PRODUCTEXPOSURE_VERSION_MAX_LEN must equal PACKAGECHECK_VERSION_MAX_LEN");
static const EndpointParamSpec_t SPEC_VERSION = {
  .mp_name              = "version",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = PACKAGECHECK_VERSION_MAX_LEN,
  .m_validatorFunction  = validate_packageVersion,
  .mp_message           = VALIDATE_PACKAGE_VERSION_REFUSAL_MESSAGE,
};

static const EndpointParamSpec_t SPEC_CPESEARCH_SEARCH = {
  .mp_name              = "search",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = CPESEARCH_SEARCH_MAX_LEN,
  .m_validatorFunction  = validate_searchQuery,
  .mp_message           = "search must hold at least 3 bytes and not only spaces",
};

static const EndpointParamSpec_t SPEC_CVEPRODUCTS_LIMIT = {
  .mp_name              = "limit",
  .m_type               = ENDPOINT_PARAM_TYPE_INT,
  .m_min                = 1,
  .m_max                = CVEPRODUCTS_MAX_LIMIT,
  .mp_message           = "limit must be an integer between 1 and 50",
  .m_default            = CVELOOKUP_PRODUCT_MAX_ROWS,
};

static const EndpointParamSpec_t SPEC_OFFSET = {
  .mp_name              = "offset",
  .m_type               = ENDPOINT_PARAM_TYPE_INT,
  .m_min                = 0,
  .m_max                = INT_MAX,
  .mp_message           = "offset must be an integer between 0 and 2147483647",
  .m_default            = 0,
};

static const EndpointParamSpec_t SPEC_CVESEARCH_OFFSET = {
  .mp_name              = "offset",
  .m_type               = ENDPOINT_PARAM_TYPE_INT,
  .m_min                = 0,
  .m_max                = CVE_LIST_MAX_OFFSET,
  .mp_message           = "offset must be an integer between 0 and 10000; narrow the list with filters or a published_after/published_before window",
  .m_default            = 0,
};

static const EndpointParamSpec_t SPEC_CVETRIAGE_OFFSET = {
  .mp_name              = "offset",
  .m_type               = ENDPOINT_PARAM_TYPE_INT,
  .m_min                = 0,
  .m_max                = CVE_LIST_MAX_OFFSET,
  .mp_message           = "offset must be an integer between 0 and 10000; narrow the list with vendor, product or min_risk_score",
  .m_default            = 0,
};

static const EndpointParamSpec_t SPEC_CPESEARCH_OFFSET = {
  .mp_name              = "offset",
  .m_type               = ENDPOINT_PARAM_TYPE_INT,
  .m_min                = 0,
  .m_max                = CVE_LIST_MAX_OFFSET,
  .mp_message           = "offset must be an integer between 0 and 10000; narrow the list with a longer search text",
  .m_default            = 0,
};

static const EndpointParamSpec_t SPEC_CVE_ID = {
  .mp_name              = "cve_id",
  .m_type               = ENDPOINT_PARAM_TYPE_CVE_ID,
  .m_maxLen             = CVELOOKUP_ID_MAX_LEN,
  .m_validatorFunction  = validate_cveId,
  .mp_message           = "CVE ID must be CVE-YYYY-NNNN[N...]",
};

static const EndpointParamSpec_t SPEC_CWE_ID = {
  .mp_name              = "cwe_id",
  .m_type               = ENDPOINT_PARAM_TYPE_CWE_ID,
  .m_maxLen             = CWELOOKUP_ID_MAX_LEN,
  .m_validatorFunction  = validate_cweId,
  .mp_message           = "CWE ID must be CWE-N",
};

static const EndpointParamSpec_t SPEC_INCLUDE_GHSA = {
  .mp_name              = "include_ghsa",
  .m_type               = ENDPOINT_PARAM_TYPE_BOOL,
  .mp_message           = "include_ghsa must be true or false",
};

static const EndpointParamSpec_t SPEC_INCLUDE_REJECTED = {
  .mp_name              = "include_rejected",
  .m_type               = ENDPOINT_PARAM_TYPE_BOOL,
  .mp_message           = "include_rejected must be true or false",
};

static const EndpointParamSpec_t SPEC_CVELOOKUPBULK_IDS = {
  .mp_name              = "cve_ids",
  .m_type               = ENDPOINT_PARAM_TYPE_CVE_ID_ARRAY,
  .m_min                = 1,
  .m_max                = CVELOOKUPBULK_MAX_IDS,
  .m_maxLen             = CVELOOKUP_ID_MAX_LEN,
  .m_validatorFunction  = validate_cveId,
};

static const EndpointParamSpec_t SPEC_CVETRIAGEBULK_IDS = {
  .mp_name              = "cve_ids",
  .m_type               = ENDPOINT_PARAM_TYPE_CVE_ID_ARRAY,
  .m_min                = 1,
  .m_max                = CVETRIAGEBULK_MAX_IDS,
  .m_maxLen             = CVELOOKUP_ID_MAX_LEN,
  .m_validatorFunction  = validate_cveId,
};

static const EndpointParamSpec_t SPEC_VECTOR = {
  .mp_name              = "vector",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = CVSS_VECTOR_MAX_LEN - 1,
};

static const EndpointParamSpec_t SPEC_SHA1_HASH = {
  .mp_name              = "sha1_hash",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = VALIDATE_SHA1_HEX_LEN,
  .m_validatorFunction  = validate_sha1Hex,
  .mp_message           = VALIDATE_SHA1_HEX_REFUSAL_MESSAGE,
};

static const EndpointParamSpec_t SPEC_FILE_HASH = {
  .mp_name              = "file_hash",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = VALIDATE_SHA256_HEX_LEN,
  .m_validatorFunction  = validate_fileHashHex,
  .mp_message           = VALIDATE_FILE_HASH_HEX_REFUSAL_MESSAGE,
};

static const EndpointParamSpec_t SPEC_DRIVERLOOKUPBULK_HASHES = {
  .mp_name              = "hashes",
  .m_type               = ENDPOINT_PARAM_TYPE_FILE_HASH_ARRAY,
  .m_min                = 1,
  .m_max                = DRIVERLOOKUPBULK_MAX_IDS,
  .m_maxLen             = VALIDATE_SHA256_HEX_LEN,
  .m_validatorFunction  = validate_fileHashHex,
};

static const EndpointParamSpec_t SPEC_PACKAGECHECKBULK_ITEMS = {
  .mp_name              = "items",
  .m_type               = ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY,
  .m_min                = 1,
  .m_max                = PACKAGECHECKBULK_MAX_ITEMS,
};

static const EndpointParamSpec_t SPEC_INCLUDE_COMMANDS = {
  .mp_name              = "include_commands",
  .m_type               = ENDPOINT_PARAM_TYPE_BOOL,
  .mp_message           = "include_commands must be true or false",
};

static const EndpointParamSpec_t SPEC_INCLUDE_FULL_HEADER_VALUES = {
  .mp_name              = "include_full_header_values",
  .m_type               = ENDPOINT_PARAM_TYPE_BOOL,
  .mp_message           = "include_full_header_values must be true or false",
};

static const EndpointParamSpec_t SPEC_ATTACK_TECHNIQUE_ID = {
  .mp_name              = "attack_technique_id",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = ATTACK_TECHNIQUE_ID_MAX_LEN,
  .m_validatorFunction  = validate_attackTechniqueId,
  .mp_message           = VALIDATE_ATTACK_TECHNIQUE_ID_REFUSAL_MESSAGE,
};

static const EndpointParamSpec_t SPEC_IMAGE = {
  .mp_name              = "image",
  .m_type               = ENDPOINT_PARAM_TYPE_BYTES,
  .m_maxLen             = ENDPOINT_MAX_BODY_BYTE_COUNT,
};

static const EndpointParamSpec_t SPEC_LEMONSQUEEZY_BODY = {
  .mp_name              = "body",
  .m_type               = ENDPOINT_PARAM_TYPE_BYTES,
  .m_maxLen             = BILLING_LEMONSQUEEZY_BODY_MAX_BYTE_COUNT,
};

static const EndpointParamSpec_t SPEC_LEMONSQUEEZY_SIGNATURE = {
  .mp_name              = "X-Signature",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = BILLING_LEMONSQUEEZY_SIGNATURE_LEN,
};

static const EndpointParamSpec_t SPEC_NOWPAYMENTS_BODY = {
  .mp_name              = "body",
  .m_type               = ENDPOINT_PARAM_TYPE_BYTES,
  .m_maxLen             = BILLING_NOWPAYMENTS_BODY_MAX_BYTE_COUNT,
};

static const EndpointParamSpec_t SPEC_NOWPAYMENTS_SIGNATURE = {
  .mp_name              = "x-nowpayments-sig",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = BILLING_NOWPAYMENTS_SIGNATURE_LEN,
};

#define APIKEYCLAIM_ORDER_ID_REFUSAL_MESSAGE "order_id must be a UUID: 36 lower-case characters with hyphens"

static const EndpointParamSpec_t SPEC_ORDER_ID = {
  .mp_name              = "order_id",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = VALIDATE_UUID_LEN,
  .m_validatorFunction  = validate_uuid,
  .mp_message           = APIKEYCLAIM_ORDER_ID_REFUSAL_MESSAGE,
};

static const EndpointParamSpec_t SPEC_DOMAIN = {
  .mp_name                = "domain",
  .m_type                 = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen               = VALIDATE_DOMAIN_NAME_MAX_LEN,
  .m_validatorFunction    = validate_publicDnsName,
  .mp_message             = VALIDATE_PUBLIC_DNS_NAME_REFUSAL_MESSAGE,
  .m_isWrittenInLowerCase = true,
};

static const EndpointParamSpec_t SPEC_DKIM_SELECTOR = {
  .mp_name              = "dkim_selector",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = VALIDATE_DKIM_SELECTOR_MAX_LEN,
  .m_validatorFunction  = validate_dkimSelector,
  .mp_message           = VALIDATE_DKIM_SELECTOR_REFUSAL_MESSAGE,
};

static const EndpointParamSpec_t SPEC_EMAIL_ADDRESS = {
  .mp_name                       = "email",
  .m_type                        = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen                      = VALIDATE_EMAIL_ADDRESS_MAX_LEN,
  .m_validatorFunction           = validate_emailAddress,
  .mp_message                    = VALIDATE_EMAIL_ADDRESS_REFUSAL_MESSAGE,
  .m_isPathSegmentPercentDecoded = true,
};

static const EndpointParamSpec_t SPEC_IP_ADDRESS = {
  .mp_name              = "ip_address",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = INET6_ADDRSTRLEN - 1,
  .m_validatorFunction  = ipguard_isGloballyReachableIp,
  .mp_message           = IPGUARD_GLOBALLY_REACHABLE_IP_REFUSAL_MESSAGE,
};

static const EndpointParamSpec_t SPEC_ASN_LOOKUP_TARGET = {
  .mp_name              = "target",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = INET6_ADDRSTRLEN - 1,
  .m_validatorFunction  = validate_asnLookupTarget,
  .mp_message           = VALIDATE_ASN_LOOKUP_TARGET_REFUSAL_MESSAGE,
};

static const EndpointParamSpec_t SPEC_ASNLOOKUP_LIMIT = {
  .mp_name              = "limit",
  .m_type               = ENDPOINT_PARAM_TYPE_INT,
  .m_min                = 1,
  .m_max                = ASNLOOKUP_MAX_LIMIT,
  .mp_message           = "limit must be an integer between 1 and 50",
  .m_default            = ASNLOOKUP_MAX_LIMIT,
};

static const EndpointParamSpec_t SPEC_WATCHLIST_ACTION = {
  .mp_name              = "action",
  .m_type               = ENDPOINT_PARAM_TYPE_ENUM,
  .m_maxLen             = WATCHLIST_ACTION_MAX_LEN,
  .mp_enumValues        = WATCHLIST_ACTION_VALUES,
  .mp_message           = "action must be add or remove",
};

static const EndpointParamSpec_t SPEC_WATCHLIST_ENDPOINT = {
  .mp_name              = "endpoint",
  .m_type               = ENDPOINT_PARAM_TYPE_ENUM,
  .m_maxLen             = WATCHLIST_ENDPOINT_MAX_LEN,
  .mp_enumValues        = WATCHLIST_ENDPOINT_VALUES,
  .mp_message           = "endpoint must be one of cve_lookup, kev_lookup, cve_exploit, product_exposure, cve_search, dns_lookup, ssl_check, whois_lookup, headers_check, cert_search, package_check, ip_lookup",
};

static const EndpointParamSpec_t SPEC_WATCHLIST_CLEAR = {
  .mp_name              = "clear",
  .m_type               = ENDPOINT_PARAM_TYPE_BOOL,
  .m_isOnlyTrueAccepted = true,
  .mp_message           = "clear must be true",
};

static const EndpointParamSpec_t SPEC_VENDORKEYEDIT_ACTION = {
  .mp_name              = "action",
  .m_type               = ENDPOINT_PARAM_TYPE_ENUM,
  .m_maxLen             = VENDORKEYEDIT_ACTION_MAX_LEN,
  .mp_enumValues        = VENDORKEYEDIT_ACTION_VALUES,
  .mp_message           = "action must be apply or status",
};

static const EndpointParamSpec_t SPEC_VENDORKEYEDIT_LINK = {
  .mp_name              = "link",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = KEYVAULT_VENDOR_KEY_LINK_LEN,
  .m_validatorFunction  = validate_vendorKeyLink,
  .mp_message           = "link must be the 64 lower-case hex digits after #l= in a manage link",
};

static const EndpointParamSpec_t SPEC_VENDORKEYEDIT_SHODAN_KEY = {
  .mp_name              = "shodan_key",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = KEYVAULT_VENDOR_KEY_MAX_LEN,
  .m_validatorFunction  = validate_vendorKey,
  .mp_message           = "shodan_key must be 1 to 128 printable ASCII characters",
};

static const EndpointParamSpec_t SPEC_VENDORKEYEDIT_ABUSEIPDB_KEY = {
  .mp_name              = "abuseipdb_key",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = KEYVAULT_VENDOR_KEY_MAX_LEN,
  .m_validatorFunction  = validate_vendorKey,
  .mp_message           = "abuseipdb_key must be 1 to 128 printable ASCII characters",
};

static const EndpointParamSpec_t SPEC_VENDORKEYEDIT_SHODAN_DELETE = {
  .mp_name              = "shodan_delete",
  .m_type               = ENDPOINT_PARAM_TYPE_BOOL,
  .m_isOnlyTrueAccepted = true,
  .mp_message           = "shodan_delete must be true",
};

static const EndpointParamSpec_t SPEC_VENDORKEYEDIT_ABUSEIPDB_DELETE = {
  .mp_name              = "abuseipdb_delete",
  .m_type               = ENDPOINT_PARAM_TYPE_BOOL,
  .m_isOnlyTrueAccepted = true,
  .mp_message           = "abuseipdb_delete must be true",
};

static const EndpointParamSpec_t SPEC_WATCHLIST_CURSOR = {
  .mp_name              = "cursor",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = WATCHLIST_CURSOR_MAX_LEN,
  .m_validatorFunction  = validate_watchlistCursor,
  .mp_message           = "cursor must be the next_cursor of an earlier answer",
};

static const EndpointParamSpec_t SPEC_WATCHLIST_REPEAT = {
  .mp_name              = "repeat",
  .m_type               = ENDPOINT_PARAM_TYPE_BOOL,
  .m_isOnlyTrueAccepted = true,
  .mp_message           = "repeat must be true",
};

static const EndpointParamSpec_t SPEC_WATCHLIST_PACKAGES = {
  .mp_name                    = "packages",
  .m_type                     = ENDPOINT_PARAM_TYPE_PACKAGE_ARRAY,
  .m_min                      = 1,
  .m_max                      = WATCHLIST_PACKAGE_ITEM_MAX_COUNT_PER_API_KEY,
  .m_isPackageVersionOptional = true,
};

static const EndpointParam_t CVELOOKUP_PARAMS[] = {
  {
    .mp_spec              = &SPEC_CVE_ID,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "CVE ID, e.g. CVE-2021-44228",
    .m_offset             = offsetof(CVELOOKUPParams_t, ma_cveId),
    .m_size               = MACRO_FIELD_SIZE(CVELOOKUPParams_t, ma_cveId),
  },
  {
    .mp_spec              = &SPEC_INCLUDE_GHSA,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Add the GitHub Security Advisory of the CVE, from the local copy of the GitHub Advisory Database",
    .m_offset             = offsetof(CVELOOKUPParams_t, m_isGhsaIncluded),
    .m_size               = MACRO_FIELD_SIZE(CVELOOKUPParams_t, m_isGhsaIncluded),
  },
};

static const EndpointParam_t CVELOOKUPBULK_PARAMS[] = {
  {
    .mp_spec              = &SPEC_CVELOOKUPBULK_IDS,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "CVE IDs",
    .m_offset             = 0,
    .m_size               = sizeof(BulkIdsParams_t),
  },
};

static const EndpointParam_t CVEPRODUCTS_PARAMS[] = {
  {
    .mp_spec              = &SPEC_CVE_ID,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "CVE ID, e.g. CVE-2021-44228",
    .m_offset             = offsetof(CVEPRODUCTSParams_t, ma_cveId),
    .m_size               = MACRO_FIELD_SIZE(CVEPRODUCTSParams_t, ma_cveId),
  },
  {
    .mp_spec              = &SPEC_VENDOR,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Exact vendor name, as affected_products writes it",
    .m_offset             = offsetof(CVEPRODUCTSParams_t, ma_vendor),
    .m_size               = MACRO_FIELD_SIZE(CVEPRODUCTSParams_t, ma_vendor),
  },
  {
    .mp_spec              = &SPEC_PRODUCT,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Exact product name, as affected_products writes it",
    .m_offset             = offsetof(CVEPRODUCTSParams_t, ma_product),
    .m_size               = MACRO_FIELD_SIZE(CVEPRODUCTSParams_t, ma_product),
  },
  {
    .mp_spec              = &SPEC_CVEPRODUCTS_LIMIT,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .m_offset             = offsetof(CVEPRODUCTSParams_t, m_limit),
    .m_size               = MACRO_FIELD_SIZE(CVEPRODUCTSParams_t, m_limit),
  },
  {
    .mp_spec              = &SPEC_OFFSET,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .m_offset             = offsetof(CVEPRODUCTSParams_t, m_offset),
    .m_size               = MACRO_FIELD_SIZE(CVEPRODUCTSParams_t, m_offset),
  },
};

static const EndpointParam_t CVESEARCH_PARAMS[] = {
  {
    .mp_spec              = &SPEC_SEVERITY,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = NULL,
    .m_offset             = offsetof(CVESEARCHParams_t, ma_severity),
    .m_size               = MACRO_FIELD_SIZE(CVESEARCHParams_t, ma_severity),
  },
  {
    .mp_spec              = &SPEC_VENDOR,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = NULL,
    .m_offset             = offsetof(CVESEARCHParams_t, ma_vendor),
    .m_size               = MACRO_FIELD_SIZE(CVESEARCHParams_t, ma_vendor),
  },
  {
    .mp_spec              = &SPEC_PRODUCT,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = NULL,
    .m_offset             = offsetof(CVESEARCHParams_t, ma_product),
    .m_size               = MACRO_FIELD_SIZE(CVESEARCHParams_t, ma_product),
  },
  {
    .mp_spec              = &SPEC_CVESEARCH_CWE_ID,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "e.g. CWE-79",
    .m_offset             = offsetof(CVESEARCHParams_t, ma_cweId),
    .m_size               = MACRO_FIELD_SIZE(CVESEARCHParams_t, ma_cweId),
  },
  {
    .mp_spec              = &SPEC_MIN_CVSS,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "CVSS v3, or v4 when a CVE has no v3",
    .m_offset             = offsetof(CVESEARCHParams_t, m_minCvss),
    .m_size               = MACRO_FIELD_SIZE(CVESEARCHParams_t, m_minCvss),
  },
  {
    .mp_spec              = &SPEC_MIN_EPSS,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .m_offset             = offsetof(CVESEARCHParams_t, m_minEpss),
    .m_size               = MACRO_FIELD_SIZE(CVESEARCHParams_t, m_minEpss),
  },
  {
    .mp_spec              = &SPEC_IN_KEV,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = NULL,
    .m_offset             = offsetof(CVESEARCHParams_t, m_kevFilter),
    .m_size               = MACRO_FIELD_SIZE(CVESEARCHParams_t, m_kevFilter),
  },
  {
    .mp_spec              = &SPEC_KNOWN_RANSOMWARE,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Only CVEs whose CISA KEV entry notes known ransomware use",
    .m_offset             = offsetof(CVESEARCHParams_t, m_knownRansomware),
    .m_size               = MACRO_FIELD_SIZE(CVESEARCHParams_t, m_knownRansomware),
  },
  {
    .mp_spec              = &SPEC_HAS_NUCLEI_TEMPLATE,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Only CVEs with a Nuclei detection template",
    .m_offset             = offsetof(CVESEARCHParams_t, m_hasNucleiTemplate),
    .m_size               = MACRO_FIELD_SIZE(CVESEARCHParams_t, m_hasNucleiTemplate),
  },
  {
    .mp_spec              = &SPEC_PUBLISHED_AFTER,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "YYYY-MM-DD",
    .m_offset             = offsetof(CVESEARCHParams_t, ma_publishedAfter),
    .m_size               = MACRO_FIELD_SIZE(CVESEARCHParams_t, ma_publishedAfter),
  },
  {
    .mp_spec              = &SPEC_PUBLISHED_BEFORE,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "YYYY-MM-DD",
    .m_offset             = offsetof(CVESEARCHParams_t, ma_publishedBefore),
    .m_size               = MACRO_FIELD_SIZE(CVESEARCHParams_t, ma_publishedBefore),
  },
  {
    .mp_spec              = &SPEC_INCLUDE_REJECTED,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Also list the CVEs that NVD marks Rejected",
    .m_offset             = offsetof(CVESEARCHParams_t, m_isRejectedIncluded),
    .m_size               = MACRO_FIELD_SIZE(CVESEARCHParams_t, m_isRejectedIncluded),
  },
  {
    .mp_spec              = &SPEC_SORT,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = NULL,
    .m_offset             = offsetof(CVESEARCHParams_t, ma_sort),
    .m_size               = MACRO_FIELD_SIZE(CVESEARCHParams_t, ma_sort),
  },
  {
    .mp_spec              = &SPEC_LIMIT,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .m_offset             = offsetof(CVESEARCHParams_t, m_limit),
    .m_size               = MACRO_FIELD_SIZE(CVESEARCHParams_t, m_limit),
  },
  {
    .mp_spec              = &SPEC_CVESEARCH_OFFSET,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .m_offset             = offsetof(CVESEARCHParams_t, m_offset),
    .m_size               = MACRO_FIELD_SIZE(CVESEARCHParams_t, m_offset),
  },
};

static const EndpointParam_t CVELEADING_PARAMS[] = {
  {
    .mp_spec              = &SPEC_VENDOR,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = NULL,
    .m_offset             = offsetof(CVELEADINGParams_t, ma_vendor),
    .m_size               = MACRO_FIELD_SIZE(CVELEADINGParams_t, ma_vendor),
  },
  {
    .mp_spec              = &SPEC_PRODUCT,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = NULL,
    .m_offset             = offsetof(CVELEADINGParams_t, ma_product),
    .m_size               = MACRO_FIELD_SIZE(CVELEADINGParams_t, ma_product),
  },
  {
    .mp_spec              = &SPEC_MIN_EPSS,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .m_offset             = offsetof(CVELEADINGParams_t, m_minEpss),
    .m_size               = MACRO_FIELD_SIZE(CVELEADINGParams_t, m_minEpss),
  },
  {
    .mp_spec              = &SPEC_IN_KEV,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = NULL,
    .m_offset             = offsetof(CVELEADINGParams_t, m_kevFilter),
    .m_size               = MACRO_FIELD_SIZE(CVELEADINGParams_t, m_kevFilter),
  },
  {
    .mp_spec              = &SPEC_KNOWN_RANSOMWARE,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Only CVEs whose CISA KEV entry notes known ransomware use",
    .m_offset             = offsetof(CVELEADINGParams_t, m_knownRansomware),
    .m_size               = MACRO_FIELD_SIZE(CVELEADINGParams_t, m_knownRansomware),
  },
  {
    .mp_spec              = &SPEC_HAS_NUCLEI_TEMPLATE,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Only CVEs with a Nuclei detection template",
    .m_offset             = offsetof(CVELEADINGParams_t, m_hasNucleiTemplate),
    .m_size               = MACRO_FIELD_SIZE(CVELEADINGParams_t, m_hasNucleiTemplate),
  },
  {
    .mp_spec              = &SPEC_INCLUDE_REJECTED,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Also list the CVEs that NVD marks Rejected",
    .m_offset             = offsetof(CVELEADINGParams_t, m_isRejectedIncluded),
    .m_size               = MACRO_FIELD_SIZE(CVELEADINGParams_t, m_isRejectedIncluded),
  },
  {
    .mp_spec              = &SPEC_CVELEADING_LIMIT,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .m_offset             = offsetof(CVELEADINGParams_t, m_limit),
    .m_size               = MACRO_FIELD_SIZE(CVELEADINGParams_t, m_limit),
  },
};

static const EndpointParam_t CVE_ID_ONLY_PARAMS[] = {
  {
    .mp_spec              = &SPEC_CVE_ID,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "CVE ID",
    .m_offset             = offsetof(CveIdParams_t, ma_cveId),
    .m_size               = MACRO_FIELD_SIZE(CveIdParams_t, ma_cveId),
  },
};

static const EndpointParam_t CWELOOKUP_PARAMS[] = {
  {
    .mp_spec              = &SPEC_CWE_ID,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "CWE ID, e.g. CWE-79",
    .m_offset             = offsetof(CWELOOKUPParams_t, ma_cweId),
    .m_size               = MACRO_FIELD_SIZE(CWELOOKUPParams_t, ma_cweId),
  },
};

static const EndpointParam_t CVETRIAGE_PARAMS[] = {
  {
    .mp_spec              = &SPEC_VENDOR,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = NULL,
    .m_offset             = offsetof(CVETRIAGEParams_t, ma_vendor),
    .m_size               = MACRO_FIELD_SIZE(CVETRIAGEParams_t, ma_vendor),
  },
  {
    .mp_spec              = &SPEC_PRODUCT,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = NULL,
    .m_offset             = offsetof(CVETRIAGEParams_t, ma_product),
    .m_size               = MACRO_FIELD_SIZE(CVETRIAGEParams_t, ma_product),
  },
  {
    .mp_spec              = &SPEC_MIN_RISK_SCORE,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Composite risk-score threshold",
    .m_offset             = offsetof(CVETRIAGEParams_t, m_minRiskScore),
    .m_size               = MACRO_FIELD_SIZE(CVETRIAGEParams_t, m_minRiskScore),
  },
  {
    .mp_spec              = &SPEC_INCLUDE_REJECTED,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Also list the CVEs that NVD marks Rejected",
    .m_offset             = offsetof(CVETRIAGEParams_t, m_isRejectedIncluded),
    .m_size               = MACRO_FIELD_SIZE(CVETRIAGEParams_t, m_isRejectedIncluded),
  },
  {
    .mp_spec              = &SPEC_LIMIT,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .m_offset             = offsetof(CVETRIAGEParams_t, m_limit),
    .m_size               = MACRO_FIELD_SIZE(CVETRIAGEParams_t, m_limit),
  },
  {
    .mp_spec              = &SPEC_CVETRIAGE_OFFSET,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .m_offset             = offsetof(CVETRIAGEParams_t, m_offset),
    .m_size               = MACRO_FIELD_SIZE(CVETRIAGEParams_t, m_offset),
  },
};

static const EndpointParam_t CVETRIAGEBULK_PARAMS[] = {
  {
    .mp_spec              = &SPEC_CVETRIAGEBULK_IDS,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "CVE IDs",
    .m_offset             = 0,
    .m_size               = sizeof(BulkIdsParams_t),
  },
};

static const EndpointParam_t PRODUCTEXPOSURE_PARAMS[] = {
  {
    .mp_spec              = &SPEC_VENDOR,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = NULL,
    .m_offset             = offsetof(PRODUCTEXPOSUREParams_t, ma_vendor),
    .m_size               = MACRO_FIELD_SIZE(PRODUCTEXPOSUREParams_t, ma_vendor),
  },
  {
    .mp_spec              = &SPEC_PRODUCT,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = NULL,
    .m_offset             = offsetof(PRODUCTEXPOSUREParams_t, ma_product),
    .m_size               = MACRO_FIELD_SIZE(PRODUCTEXPOSUREParams_t, ma_product),
  },
  {
    .mp_spec              = &SPEC_VERSION,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Product version, e.g. 22.21.1 or 11-24h2; picks the release cycle of eol",
    .m_offset             = offsetof(PRODUCTEXPOSUREParams_t, ma_version),
    .m_size               = MACRO_FIELD_SIZE(PRODUCTEXPOSUREParams_t, ma_version),
  },
  {
    .mp_spec              = &SPEC_INCLUDE_REJECTED,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Also count and list the CVEs that NVD marks Rejected",
    .m_offset             = offsetof(PRODUCTEXPOSUREParams_t, m_isRejectedIncluded),
    .m_size               = MACRO_FIELD_SIZE(PRODUCTEXPOSUREParams_t, m_isRejectedIncluded),
  },
};

static const EndpointParam_t CPESEARCH_PARAMS[] = {
  {
    .mp_spec              = &SPEC_CPESEARCH_SEARCH,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "Text in vendor or product names, at least 3 bytes; case does not matter, and _ matches a space",
    .m_offset             = offsetof(CPESEARCHParams_t, ma_search),
    .m_size               = MACRO_FIELD_SIZE(CPESEARCHParams_t, ma_search),
  },
  {
    .mp_spec              = &SPEC_CPESEARCH_LIMIT,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .m_offset             = offsetof(CPESEARCHParams_t, m_limit),
    .m_size               = MACRO_FIELD_SIZE(CPESEARCHParams_t, m_limit),
  },
  {
    .mp_spec              = &SPEC_CPESEARCH_OFFSET,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .m_offset             = offsetof(CPESEARCHParams_t, m_offset),
    .m_size               = MACRO_FIELD_SIZE(CPESEARCHParams_t, m_offset),
  },
};

static const EndpointParam_t PACKAGECHECK_PARAMS[] = {
  {
    .mp_spec              = &SPEC_PACKAGE_ECOSYSTEM,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "npm, PyPI, Maven, Go, NuGet, RubyGems, crates.io, Packagist or SwiftURL. Case does not matter.",
    .m_offset             = offsetof(PACKAGECHECKParams_t, ma_ecosystem),
    .m_size               = MACRO_FIELD_SIZE(PACKAGECHECKParams_t, ma_ecosystem),
  },
  {
    .mp_spec              = &SPEC_PACKAGE_NAME,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "Package name as the dependency file writes it, e.g. lodash, @babel/core, org.apache.logging.log4j:log4j-core, golang.org/x/net",
    .m_offset             = offsetof(PACKAGECHECKParams_t, ma_packageName),
    .m_size               = MACRO_FIELD_SIZE(PACKAGECHECKParams_t, ma_packageName),
  },
  {
    .mp_spec              = &SPEC_VERSION,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Exact version, e.g. 4.17.20; without it every result is listed",
    .m_offset             = offsetof(PACKAGECHECKParams_t, ma_version),
    .m_size               = MACRO_FIELD_SIZE(PACKAGECHECKParams_t, ma_version),
  },
  {
    .mp_spec              = &SPEC_PACKAGECHECK_LIMIT,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .m_offset             = offsetof(PACKAGECHECKParams_t, m_limit),
    .m_size               = MACRO_FIELD_SIZE(PACKAGECHECKParams_t, m_limit),
  },
  {
    .mp_spec              = &SPEC_OFFSET,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .m_offset             = offsetof(PACKAGECHECKParams_t, m_offset),
    .m_size               = MACRO_FIELD_SIZE(PACKAGECHECKParams_t, m_offset),
  },
};

static const EndpointParam_t CVSSCALCULATOR_PARAMS[] = {
  {
    .mp_spec              = &SPEC_VECTOR,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "CVSS v3.0/v3.1 vector, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    .m_offset             = offsetof(CVSSCALCULATORParams_t, ma_vector),
    .m_size               = MACRO_FIELD_SIZE(CVSSCALCULATORParams_t, ma_vector),
  },
};

static const EndpointParam_t PASSWORDCHECK_PARAMS[] = {
  {
    .mp_spec              = &SPEC_SHA1_HASH,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "SHA-1 of the password: 40 hex digits, either case",
    .m_offset             = offsetof(PASSWORDCHECKParams_t, ma_sha1Hash),
    .m_size               = MACRO_FIELD_SIZE(PASSWORDCHECKParams_t, ma_sha1Hash),
  },
};

static const EndpointParam_t D3FENDFORATTACK_PARAMS[] = {
  {
    .mp_spec              = &SPEC_ATTACK_TECHNIQUE_ID,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "MITRE ATT&CK technique id in upper case, e.g. T1055 or T1055.012",
    .m_offset             = offsetof(D3FENDFORATTACKParams_t, ma_attackTechniqueId),
    .m_size               = MACRO_FIELD_SIZE(D3FENDFORATTACKParams_t, ma_attackTechniqueId),
  },
};

static const EndpointParam_t DRIVERLOOKUP_PARAMS[] = {
  {
    .mp_spec              = &SPEC_FILE_HASH,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "MD5, SHA1 or SHA256 of the driver file, or its Authentihash: 32, 40 or 64 hex digits, either case",
    .m_offset             = offsetof(DRIVERLOOKUPParams_t, ma_fileHash),
    .m_size               = MACRO_FIELD_SIZE(DRIVERLOOKUPParams_t, ma_fileHash),
  },
  {
    .mp_spec              = &SPEC_INCLUDE_COMMANDS,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "true adds the catalog's command text to each match",
    .m_offset             = offsetof(DRIVERLOOKUPParams_t, m_isCommandIncluded),
    .m_size               = MACRO_FIELD_SIZE(DRIVERLOOKUPParams_t, m_isCommandIncluded),
  },
};

static const EndpointParam_t DRIVERLOOKUPBULK_PARAMS[] = {
  {
    .mp_spec              = &SPEC_DRIVERLOOKUPBULK_HASHES,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "MD5, SHA1 or SHA256 of driver files or of their Authentihash",
    .m_offset             = 0,
    .m_size               = sizeof(BulkIdsParams_t),
  },
};

static const EndpointParam_t PACKAGECHECKBULK_PARAMS[] = {
  {
    .mp_spec              = &SPEC_PACKAGECHECKBULK_ITEMS,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "Packages, each with its ecosystem, name and exact version",
    .m_offset             = 0,
    .m_size               = sizeof(PACKAGECHECKBULKParams_t),
  },
};

static const EndpointParam_t IMAGEINSPECT_PARAMS[] = {
  {
    .mp_spec              = &SPEC_IMAGE,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_RAW_BODY,
    .m_isRequired         = true,
    .m_offset             = offsetof(IMAGEINSPECTParams_t, m_image),
    .m_size               = MACRO_FIELD_SIZE(IMAGEINSPECTParams_t, m_image),
  },
};

static const EndpointParam_t WEBHOOKLEMONSQUEEZY_PARAMS[] = {
  {
    .mp_spec              = &SPEC_LEMONSQUEEZY_BODY,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_RAW_BODY,
    .m_isRequired         = true,
    .m_offset             = offsetof(WEBHOOKLEMONSQUEEZYParams_t, m_body),
    .m_size               = MACRO_FIELD_SIZE(WEBHOOKLEMONSQUEEZYParams_t, m_body),
  },
  {
    .mp_spec              = &SPEC_LEMONSQUEEZY_SIGNATURE,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_HEADER,
    .m_isRequired         = false,
    .m_offset             = offsetof(WEBHOOKLEMONSQUEEZYParams_t, ma_signature),
    .m_size               = MACRO_FIELD_SIZE(WEBHOOKLEMONSQUEEZYParams_t, ma_signature),
  },
};

static const EndpointParam_t WEBHOOKNOWPAYMENTS_PARAMS[] = {
  {
    .mp_spec              = &SPEC_NOWPAYMENTS_BODY,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_RAW_BODY,
    .m_isRequired         = true,
    .m_offset             = offsetof(WEBHOOKNOWPAYMENTSParams_t, m_body),
    .m_size               = MACRO_FIELD_SIZE(WEBHOOKNOWPAYMENTSParams_t, m_body),
  },
  {
    .mp_spec              = &SPEC_NOWPAYMENTS_SIGNATURE,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_HEADER,
    .m_isRequired         = false,
    .m_offset             = offsetof(WEBHOOKNOWPAYMENTSParams_t, ma_signature),
    .m_size               = MACRO_FIELD_SIZE(WEBHOOKNOWPAYMENTSParams_t, ma_signature),
  },
};

static const EndpointParam_t APIKEYCLAIM_PARAMS[] = {
  {
    .mp_spec              = &SPEC_ORDER_ID,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY,
    .m_isRequired         = true,
    .m_offset             = offsetof(APIKEYCLAIMParams_t, ma_orderId),
    .m_size               = MACRO_FIELD_SIZE(APIKEYCLAIMParams_t, ma_orderId),
  },
};

static const EndpointParam_t DNSLOOKUP_PARAMS[] = {
  {
    .mp_spec              = &SPEC_DOMAIN,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "Domain name, such as example.com",
    .m_offset             = offsetof(DNSLOOKUPParams_t, ma_domain),
    .m_size               = MACRO_FIELD_SIZE(DNSLOOKUPParams_t, ma_domain),
  },
};

static const EndpointParam_t DNSTAKEOVERCHECK_PARAMS[] = {
  {
    .mp_spec              = &SPEC_DOMAIN,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "Host name, such as shop.example.com",
    .m_offset             = offsetof(DNSTAKEOVERCHECKParams_t, ma_hostname),
    .m_size               = MACRO_FIELD_SIZE(DNSTAKEOVERCHECKParams_t, ma_hostname),
  },
};

static const EndpointParam_t EMAILAUTHCHECK_PARAMS[] = {
  {
    .mp_spec              = &SPEC_DOMAIN,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "Domain name, such as example.com",
    .m_offset             = offsetof(EMAILAUTHCHECKParams_t, ma_domain),
    .m_size               = MACRO_FIELD_SIZE(EMAILAUTHCHECKParams_t, ma_domain),
  },
  {
    .mp_spec              = &SPEC_DKIM_SELECTOR,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "DKIM selector, such as google; without it the check tries the selectors of the domain's mail providers",
    .m_offset             = offsetof(EMAILAUTHCHECKParams_t, ma_dkimSelector),
    .m_size               = MACRO_FIELD_SIZE(EMAILAUTHCHECKParams_t, ma_dkimSelector),
  },
};

static const EndpointParam_t EMAILADDRESSCHECK_PARAMS[] = {
  {
    .mp_spec              = &SPEC_EMAIL_ADDRESS,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "E-mail address, such as name@example.com",
    .m_offset             = offsetof(EMAILADDRESSCHECKParams_t, ma_email),
    .m_size               = MACRO_FIELD_SIZE(EMAILADDRESSCHECKParams_t, ma_email),
  },
};

static const EndpointParam_t IPLOOKUP_PARAMS[] = {
  {
    .mp_spec              = &SPEC_IP_ADDRESS,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "Public IPv4 or IPv6 address, such as 8.8.8.8 or 2001:4860:4860::8888",
    .m_offset             = offsetof(IPLOOKUPParams_t, ma_ipAddress),
    .m_size               = MACRO_FIELD_SIZE(IPLOOKUPParams_t, ma_ipAddress),
  },
};

static const EndpointParam_t SSLCHECK_PARAMS[] = {
  {
    .mp_spec              = &SPEC_DOMAIN,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "Host name, such as www.example.com",
    .m_offset             = offsetof(SSLCHECKParams_t, ma_hostname),
    .m_size               = MACRO_FIELD_SIZE(SSLCHECKParams_t, ma_hostname),
  },
};

static const EndpointParam_t HEADERSCHECK_PARAMS[] = {
  {
    .mp_spec              = &SPEC_DOMAIN,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "Host name of the site, such as www.example.com",
    .m_offset             = offsetof(HEADERSCHECKParams_t, ma_hostname),
    .m_size               = MACRO_FIELD_SIZE(HEADERSCHECKParams_t, ma_hostname),
  },
  {
    .mp_spec              = &SPEC_INCLUDE_FULL_HEADER_VALUES,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "true sends each header value and URL whole, instead of cutting it after 500 code points",
    .m_offset             = offsetof(HEADERSCHECKParams_t, m_isFullHeaderValueIncluded),
    .m_size               = MACRO_FIELD_SIZE(HEADERSCHECKParams_t, m_isFullHeaderValueIncluded),
  },
};

static const EndpointParam_t WHOISLOOKUP_PARAMS[] = {
  {
    .mp_spec              = &SPEC_DOMAIN,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "Domain name, such as example.com; www.example.com asks about example.com",
    .m_offset             = offsetof(WHOISLOOKUPParams_t, ma_domain),
    .m_size               = MACRO_FIELD_SIZE(WHOISLOOKUPParams_t, ma_domain),
  },
};

static const EndpointParam_t WAYBACKLOOKUP_PARAMS[] = {
  {
    .mp_spec              = &SPEC_DOMAIN,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "Host name, such as example.com",
    .m_offset             = offsetof(WAYBACKLOOKUPParams_t, ma_domain),
    .m_size               = MACRO_FIELD_SIZE(WAYBACKLOOKUPParams_t, ma_domain),
  },
};

static const EndpointParam_t CERTSEARCH_PARAMS[] = {
  {
    .mp_spec              = &SPEC_DOMAIN,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "Host name, such as example.com or www.example.com",
    .m_offset             = offsetof(CERTSEARCHParams_t, ma_domain),
    .m_size               = MACRO_FIELD_SIZE(CERTSEARCHParams_t, ma_domain),
  },
};

static const EndpointParam_t SUBDOMAINENUM_PARAMS[] = {
  {
    .mp_spec              = &SPEC_DOMAIN,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "Domain name, such as example.com; www.example.com asks about example.com",
    .m_offset             = offsetof(SUBDOMAINENUMParams_t, ma_domain),
    .m_size               = MACRO_FIELD_SIZE(SUBDOMAINENUMParams_t, ma_domain),
  },
};

static const EndpointParam_t ASNLOOKUP_PARAMS[] = {
  {
    .mp_spec              = &SPEC_ASN_LOOKUP_TARGET,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "AS number, such as AS15169 or 15169, or a public IPv4 or IPv6 address, such as 8.8.8.8",
    .m_offset             = offsetof(ASNLOOKUPParams_t, ma_target),
    .m_size               = MACRO_FIELD_SIZE(ASNLOOKUPParams_t, ma_target),
  },
  {
    .mp_spec              = &SPEC_ASNLOOKUP_LIMIT,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .m_offset             = offsetof(ASNLOOKUPParams_t, m_limit),
    .m_size               = MACRO_FIELD_SIZE(ASNLOOKUPParams_t, m_limit),
  },
  {
    .mp_spec              = &SPEC_OFFSET,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .m_offset             = offsetof(ASNLOOKUPParams_t, m_offset),
    .m_size               = MACRO_FIELD_SIZE(ASNLOOKUPParams_t, m_offset),
  },
};

static const EndpointParam_t WATCHLISTEDIT_PARAMS[] = {
  {
    .mp_spec              = &SPEC_WATCHLIST_ACTION,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "add or remove; leave out to list the items",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, ma_action),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, ma_action),
  },
  {
    .mp_spec              = &SPEC_WATCHLIST_ENDPOINT,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "The tool the item watches",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, ma_endpoint),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, ma_endpoint),
  },
  {
    .mp_spec              = &SPEC_CVE_ID,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "For a cve_lookup, kev_lookup or cve_exploit item, e.g. CVE-2021-44228",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, ma_cveId),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, ma_cveId),
  },
  {
    .mp_spec              = &SPEC_VENDOR,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Vendor, for a product_exposure or cve_search item",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, ma_vendor),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, ma_vendor),
  },
  {
    .mp_spec              = &SPEC_PRODUCT,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Product, for a product_exposure or cve_search item",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, ma_product),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, ma_product),
  },
  {
    .mp_spec              = &SPEC_SEVERITY,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "cve_search items only",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, ma_severity),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, ma_severity),
  },
  {
    .mp_spec              = &SPEC_CVESEARCH_CWE_ID,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "cve_search items only, e.g. CWE-79",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, ma_cweId),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, ma_cweId),
  },
  {
    .mp_spec              = &SPEC_MIN_CVSS,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "CVSS v3, or v4 when a CVE has no v3; cve_search items only",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, m_minCvss),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, m_minCvss),
  },
  {
    .mp_spec              = &SPEC_MIN_EPSS,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "At most three decimals; cve_search items only",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, m_minEpss),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, m_minEpss),
  },
  {
    .mp_spec              = &SPEC_IN_KEV,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "cve_search items only",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, m_inKev),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, m_inKev),
  },
  {
    .mp_spec              = &SPEC_KNOWN_RANSOMWARE,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "cve_search items only",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, m_knownRansomware),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, m_knownRansomware),
  },
  {
    .mp_spec              = &SPEC_HAS_NUCLEI_TEMPLATE,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "cve_search items only",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, m_hasNucleiTemplate),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, m_hasNucleiTemplate),
  },
  {
    .mp_spec              = &SPEC_DOMAIN,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "For a dns_lookup, ssl_check, whois_lookup, headers_check or cert_search item, such as example.com",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, ma_domain),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, ma_domain),
  },
  {
    .mp_spec              = &SPEC_PACKAGE_ECOSYSTEM,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "For a package_check item: npm, PyPI, Maven, Go, NuGet, RubyGems, crates.io, Packagist or SwiftURL",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, ma_ecosystem),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, ma_ecosystem),
  },
  {
    .mp_spec              = &SPEC_PACKAGE_NAME,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Package name of a package_check item, e.g. lodash",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, ma_packageName),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, ma_packageName),
  },
  {
    .mp_spec              = &SPEC_VERSION,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Exact version of a product_exposure or package_check item; leave out to watch every version",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, ma_version),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, ma_version),
  },
  {
    .mp_spec              = &SPEC_IP_ADDRESS,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Public IPv4 or IPv6 address of an ip_lookup item, such as 8.8.8.8, no prefix",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, ma_ipAddress),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, ma_ipAddress),
  },
  {
    .mp_spec              = &SPEC_WATCHLIST_CLEAR,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Deletes every item and the event cursor; takes no other argument",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, m_isWatchlistCleared),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, m_isWatchlistCleared),
  },
  {
    .mp_spec              = &SPEC_WATCHLIST_PACKAGES,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "package_check items, each with an ecosystem, a name and an optional version",
    .m_offset             = offsetof(WATCHLISTEDITParams_t, m_packages),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEDITParams_t, m_packages),
  },
};

static const EndpointParam_t VENDORKEYEDIT_PARAMS[] = {
  {
    .mp_spec              = &SPEC_VENDORKEYEDIT_ACTION,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = true,
    .mp_mcpArgDescription = "apply saves or deletes keys; status reports the stored keys and needs link",
    .m_offset             = offsetof(VENDORKEYEDITParams_t, ma_action),
    .m_size               = MACRO_FIELD_SIZE(VENDORKEYEDITParams_t, ma_action),
  },
  {
    .mp_spec              = &SPEC_VENDORKEYEDIT_LINK,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "The 64 hex digits after #l= in a manage link; leave out to use this Pro API key",
    .m_offset             = offsetof(VENDORKEYEDITParams_t, ma_link),
    .m_size               = MACRO_FIELD_SIZE(VENDORKEYEDITParams_t, ma_link),
  },
  {
    .mp_spec              = &SPEC_VENDORKEYEDIT_SHODAN_KEY,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "a Shodan key to check and save",
    .m_offset             = offsetof(VENDORKEYEDITParams_t, ma_shodanKey),
    .m_size               = MACRO_FIELD_SIZE(VENDORKEYEDITParams_t, ma_shodanKey),
  },
  {
    .mp_spec              = &SPEC_VENDORKEYEDIT_SHODAN_DELETE,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "deletes the stored Shodan key",
    .m_offset             = offsetof(VENDORKEYEDITParams_t, m_isShodanDeleted),
    .m_size               = MACRO_FIELD_SIZE(VENDORKEYEDITParams_t, m_isShodanDeleted),
  },
  {
    .mp_spec              = &SPEC_VENDORKEYEDIT_ABUSEIPDB_KEY,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "an AbuseIPDB key to check and save",
    .m_offset             = offsetof(VENDORKEYEDITParams_t, ma_abuseIpDbKey),
    .m_size               = MACRO_FIELD_SIZE(VENDORKEYEDITParams_t, ma_abuseIpDbKey),
  },
  {
    .mp_spec              = &SPEC_VENDORKEYEDIT_ABUSEIPDB_DELETE,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_BODY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "deletes the stored AbuseIPDB key",
    .m_offset             = offsetof(VENDORKEYEDITParams_t, m_isAbuseIpDbDeleted),
    .m_size               = MACRO_FIELD_SIZE(VENDORKEYEDITParams_t, m_isAbuseIpDbDeleted),
  },
};

static const EndpointParam_t WATCHLISTEVENTS_PARAMS[] = {
  {
    .mp_spec              = &SPEC_LIMIT,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Events per call; repeat=true answers the whole last batch",
    .m_offset             = offsetof(WATCHLISTEVENTSParams_t, m_limit),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEVENTSParams_t, m_limit),
  },
  {
    .mp_spec              = &SPEC_WATCHLIST_CURSOR,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "next_cursor of an earlier answer; reads after it and keeps the position",
    .m_offset             = offsetof(WATCHLISTEVENTSParams_t, ma_cursor),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEVENTSParams_t, ma_cursor),
  },
  {
    .mp_spec              = &SPEC_WATCHLIST_REPEAT,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_QUERY | ENDPOINT_PARAM_SRC_MCP_ARG,
    .m_isRequired         = false,
    .mp_mcpArgDescription = "Answers the last batch again; cannot be combined with cursor",
    .m_offset             = offsetof(WATCHLISTEVENTSParams_t, m_isRepeat),
    .m_size               = MACRO_FIELD_SIZE(WATCHLISTEVENTSParams_t, m_isRepeat),
  },
};

const Endpoint_t endpoints[] = {
  {
    .mp_httpPath               = "/health",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"GET", NULL},
    .mp_mcpToolName            = "health",
    .mp_mcpToolDescription     = "Database freshness: CVE/KEV/CWE counts and latest entries, and the sync state of each upstream feed. Costs no credits.",
    .mp_mcpToolTitle           = "Health and Data Freshness",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_OPERATIONS,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 0,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .m_runFunction             = endpoint_HEALTHRun,
    .m_isDbRequired            = false,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/cve_lookup/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "cve_lookup",
    .mp_mcpToolDescription     = "Full CVE record by ID (CVSS, EPSS, KEV, CWE, references, CISA SSVC, Nuclei templates), with the optional GitHub Security Advisory. Call the cve_products tool for every affected product. If your SSVC level is unknown, read high.",
    .mp_mcpToolTitle           = "CVE Lookup",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_CVE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = CVELOOKUP_PARAMS,
    .m_paramCount              = (int)(sizeof(CVELOOKUP_PARAMS) / sizeof(CVELOOKUP_PARAMS[0])),
    .m_paramsSize              = sizeof(CVELOOKUPParams_t),
    .mp_notFoundMessage        = "CVE not found",
    .m_runFunction             = endpoint_CVELOOKUPRun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/cve_lookup_bulk",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"POST", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "cve_lookup_bulk",
    .mp_mcpToolDescription     = "Look up many CVEs at once, each with the fields of cve_lookup. Ids beyond the remaining credits come back in not_processed.",
    .mp_mcpToolTitle           = "Bulk CVE Lookup",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_CVE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_BULK_IDS,
    .mp_params                 = CVELOOKUPBULK_PARAMS,
    .m_paramCount              = (int)(sizeof(CVELOOKUPBULK_PARAMS) / sizeof(CVELOOKUPBULK_PARAMS[0])),
    .m_paramsSize              = sizeof(BulkIdsParams_t),
    .m_runFunction             = endpoint_CVELOOKUPBULKRun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/cve_products/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "cve_products",
    .mp_mcpToolDescription     = "The products a CVE affects, one page at a time, with the vulnerable products first. The vendor and product arguments keep only the products with that exact name.",
    .mp_mcpToolTitle           = "CVE Affected Products",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_CVE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = CVEPRODUCTS_PARAMS,
    .m_paramCount              = (int)(sizeof(CVEPRODUCTS_PARAMS) / sizeof(CVEPRODUCTS_PARAMS[0])),
    .m_paramsSize              = sizeof(CVEPRODUCTSParams_t),
    .mp_notFoundMessage        = "CVE not found",
    .m_runFunction             = endpoint_CVEPRODUCTSRun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/cve_search",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "cve_search",
    .mp_mcpToolDescription     = "Search CVEs by severity, CWE, CVSS, EPSS, CISA KEV, ransomware use, Nuclei template, vendor, product and publish date, one page at a time. Call the cve_lookup tool for a full record, and the cpe_search tool to find the names.",
    .mp_mcpToolTitle           = "CVE Search",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_CVE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = CVESEARCH_PARAMS,
    .m_paramCount              = (int)(sizeof(CVESEARCH_PARAMS) / sizeof(CVESEARCH_PARAMS[0])),
    .m_paramsSize              = sizeof(CVESEARCHParams_t),
    .m_runFunction             = endpoint_CVESEARCHRun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/cve_leading",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "cve_leading",
    .mp_mcpToolDescription     = "List the CVEs most likely to be exploited, by EPSS score (the probability of exploitation in the next 30 days), with a verdict on the top score. To rank by composite risk score, call the cve_triage tool.",
    .mp_mcpToolTitle           = "Leading CVEs by EPSS",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_CVE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = CVELEADING_PARAMS,
    .m_paramCount              = (int)(sizeof(CVELEADING_PARAMS) / sizeof(CVELEADING_PARAMS[0])),
    .m_paramsSize              = sizeof(CVELEADINGParams_t),
    .m_runFunction             = endpoint_CVELEADINGRun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/kev_lookup/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "kev_lookup",
    .mp_mcpToolDescription     = "CISA KEV catalog entry for a CVE: the required action, the patch deadline and known ransomware use. A CVE that CISA removed answers in_kev false, and one never listed answers \"KEV entry not found\".",
    .mp_mcpToolTitle           = "CISA KEV Lookup",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_CVE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = CVE_ID_ONLY_PARAMS,
    .m_paramCount              = (int)(sizeof(CVE_ID_ONLY_PARAMS) / sizeof(CVE_ID_ONLY_PARAMS[0])),
    .m_paramsSize              = sizeof(CveIdParams_t),
    .mp_notFoundMessage        = "KEV entry not found",
    .m_runFunction             = endpoint_KEVLOOKUPRun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/cwe_lookup/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "cwe_lookup",
    .mp_mcpToolDescription     = "CWE weakness details (description, mitigations, examples), with how many CVEs and CISA KEV entries name it. To list them, call the cve_search tool with its cwe_id argument.",
    .mp_mcpToolTitle           = "CWE Lookup",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_CVE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = CWELOOKUP_PARAMS,
    .m_paramCount              = (int)(sizeof(CWELOOKUP_PARAMS) / sizeof(CWELOOKUP_PARAMS[0])),
    .m_paramsSize              = sizeof(CWELOOKUPParams_t),
    .mp_notFoundMessage        = "CWE not found",
    .m_runFunction             = endpoint_CWELOOKUPRun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/cve_risk_score/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "cve_risk_score",
    .mp_mcpToolDescription     = "Composite risk score of a CVE, from 0 to 100, for patch priority. It reads EPSS, CISA KEV, Metasploit, CVSS, NVD exploit references and ExploitDB. has_public_poc is null when no source names an exploit.",
    .mp_mcpToolTitle           = "CVE Risk Score",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_CVE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = CVE_ID_ONLY_PARAMS,
    .m_paramCount              = (int)(sizeof(CVE_ID_ONLY_PARAMS) / sizeof(CVE_ID_ONLY_PARAMS[0])),
    .m_paramsSize              = sizeof(CveIdParams_t),
    .mp_notFoundMessage        = "CVE not found",
    .m_runFunction             = endpoint_CVERISKSCORERun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/cve_exploit/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "cve_exploit",
    .mp_mcpToolDescription     = "Public exploit intelligence (GitHub PoCs, Metasploit, NVD exploit references, ExploitDB). GitHub PoC repositories are listed but not counted as proof of a public exploit.",
    .mp_mcpToolTitle           = "CVE Exploit Intelligence",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_CVE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = CVE_ID_ONLY_PARAMS,
    .m_paramCount              = (int)(sizeof(CVE_ID_ONLY_PARAMS) / sizeof(CVE_ID_ONLY_PARAMS[0])),
    .m_paramsSize              = sizeof(CveIdParams_t),
    .m_runFunction             = endpoint_CVEEXPLOITRun,
    .m_isDbRequired            = true,
    .m_callsUpstream           = false,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/cve_triage",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "cve_triage",
    .mp_mcpToolDescription     = "Rank the CVEs of a vendor or product by composite risk score, at or above the optional min_risk_score argument, as lean rows (cve_id, risk_score, label). Call the cve_lookup tool for detail, and the cpe_search tool to find the names.",
    .mp_mcpToolTitle           = "CVE Triage",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_CVE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = CVETRIAGE_PARAMS,
    .m_paramCount              = (int)(sizeof(CVETRIAGE_PARAMS) / sizeof(CVETRIAGE_PARAMS[0])),
    .m_paramsSize              = sizeof(CVETRIAGEParams_t),
    .m_runFunction             = endpoint_CVETRIAGERun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/cve_triage_bulk",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"POST", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "cve_triage_bulk",
    .mp_mcpToolDescription     = "Triage many CVEs at once, ranked by composite risk score. Ids beyond the remaining credits come back in not_processed.",
    .mp_mcpToolTitle           = "Bulk CVE Triage",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_CVE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_BULK_IDS,
    .mp_params                 = CVETRIAGEBULK_PARAMS,
    .m_paramCount              = (int)(sizeof(CVETRIAGEBULK_PARAMS) / sizeof(CVETRIAGEBULK_PARAMS[0])),
    .m_paramsSize              = sizeof(BulkIdsParams_t),
    .m_runFunction             = endpoint_CVETRIAGEBULKRun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/product_exposure",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "product_exposure",
    .mp_mcpToolDescription     = "CVE exposure of one vendor and product: severity, KEV and PoC counts, CVSS, EPSS, the worst risk score, the top CVEs and the endoflife.date support dates. To find the names, call the cpe_search tool.",
    .mp_mcpToolTitle           = "Product Exposure",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_CVE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = PRODUCTEXPOSURE_PARAMS,
    .m_paramCount              = (int)(sizeof(PRODUCTEXPOSURE_PARAMS) / sizeof(PRODUCTEXPOSURE_PARAMS[0])),
    .m_paramsSize              = sizeof(PRODUCTEXPOSUREParams_t),
    .m_runFunction             = endpoint_PRODUCTEXPOSURERun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/cpe_search",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "cpe_search",
    .mp_mcpToolDescription     = "Find the CPE vendor and product names that hold a text, ranked by vulnerable CVE count. Pass a name that holds no % as it is to the vendor and product arguments of the cve_search, cve_triage, cve_leading and product_exposure tools.",
    .mp_mcpToolTitle           = "CPE Search",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_CVE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = CPESEARCH_PARAMS,
    .m_paramCount              = (int)(sizeof(CPESEARCH_PARAMS) / sizeof(CPESEARCH_PARAMS[0])),
    .m_paramsSize              = sizeof(CPESEARCHParams_t),
    .m_runFunction             = endpoint_CPESEARCHRun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/cvss_calculator",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "cvss_calculator",
    .mp_mcpToolDescription     = "Decode a CVSS v3.0/v3.1 vector into its base metrics and recompute its base, temporal and environmental scores.",
    .mp_mcpToolTitle           = "CVSS Calculator",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_CVE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = CVSSCALCULATOR_PARAMS,
    .m_paramCount              = (int)(sizeof(CVSSCALCULATOR_PARAMS) / sizeof(CVSSCALCULATOR_PARAMS[0])),
    .m_paramsSize              = sizeof(CVSSCALCULATORParams_t),
    .m_runFunction             = endpoint_CVSSCALCULATORRun,
    .m_isDbRequired            = false,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath                      = "/watchlist_edit",
    .m_hasPathSegment                 = false,
    .ma_allowedMethods                = {"POST", NULL},
    .m_readsCreditBudget              = true,
    .mp_mcpToolName                   = "watchlist_edit",
    .mp_mcpToolDescription            = "Add, remove, list or clear the items this API key watches: CVEs, products, CVE searches, packages, domains and IP addresses. Read their changes with the watchlist_events tool. Requires a Pro API key.",
    .mp_mcpToolTitle                  = "Watchlist: CVE, Package, Domain and IP Monitoring",
    .m_mcpToolCategory                = ENDPOINT_MCP_TOOL_CATEGORY_MONITORING,
    .m_mcpToolEffect                  = ENDPOINT_MCP_TOOL_EFFECT_EDITS,
    .m_creditCost                     = 1,
    .m_costRule                       = ENDPOINT_COST_FLAT,
    .mp_params                        = WATCHLISTEDIT_PARAMS,
    .m_paramCount                     = (int)(sizeof(WATCHLISTEDIT_PARAMS) / sizeof(WATCHLISTEDIT_PARAMS[0])),
    .m_paramsSize                     = sizeof(WATCHLISTEDITParams_t),
    .m_runFunction                    = endpoint_WATCHLISTEDITRun,
    .m_isDbRequired                   = true,
    .m_callsUpstreamFunction          = endpoint_WATCHLISTEDITWillAskResolver,
    .m_jsonCeiling                    = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/watchlist_events",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"GET", NULL},
    .m_readsCreditBudget       = true,
    .mp_mcpToolName            = "watchlist_events",
    .mp_mcpToolDescription     = "Report what changed on the items this API key watches, such as a new advisory for a package or a certificate about to expire, oldest first. A plain call continues where the last one stopped. Requires a Pro API key.",
    .mp_mcpToolTitle           = "Monitoring Events",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_MONITORING,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_MOVES_POSITION,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = WATCHLISTEVENTS_PARAMS,
    .m_paramCount              = (int)(sizeof(WATCHLISTEVENTS_PARAMS) / sizeof(WATCHLISTEVENTS_PARAMS[0])),
    .m_paramsSize              = sizeof(WATCHLISTEVENTSParams_t),
    .m_runFunction             = endpoint_WATCHLISTEVENTSRun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/privacy_my_data",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"GET", NULL},
    .m_readsCreditBudget       = true,
    .mp_mcpToolName            = PRICING_PRIVACY_MY_DATA_TOOL_NAME,
    .mp_mcpToolDescription     = "What this server keeps about the caller: the hash its credits are counted under, the rate limit left in this hour and the privacy policy. For a Pro key, which vendor keys are stored and a 15-minute link to change them.",
    .mp_mcpToolTitle           = "Privacy: My Data",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_OPERATIONS,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .m_runFunction             = endpoint_PRIVACYMYDATARun,
    .m_isDbRequired            = false,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/vendor_key_edit",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"POST", NULL},
    .m_readsCreditBudget       = true,
    .mp_mcpToolName            = "vendor_key_edit",
    .mp_mcpToolDescription     = "Save, delete or check your own Shodan and AbuseIPDB keys, which the ip_lookup tool uses. Needs a Pro API key or a manage link. The privacy_my_data tool gives a web link where a person can save the keys without the agent seeing them.",
    .mp_mcpToolTitle           = "Vendor key edit",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_OPERATIONS,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_EDITS,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = VENDORKEYEDIT_PARAMS,
    .m_paramCount              = (int)(sizeof(VENDORKEYEDIT_PARAMS) / sizeof(VENDORKEYEDIT_PARAMS[0])),
    .m_paramsSize              = sizeof(VENDORKEYEDITParams_t),
    .m_runFunction             = endpoint_VENDORKEYEDITRun,
    .m_isDbRequired            = true,
    .m_callsUpstreamFunction   = endpoint_VENDORKEYEDITWillCallVendor,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/password_check/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "password_check",
    .mp_mcpToolDescription     = "Check a password's SHA-1 against Have I Been Pwned's Pwned Passwords list. It takes the full SHA-1, never the password. Only its first 5 hex digits leave this server.",
    .mp_mcpToolTitle           = "Breached Password Check",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_CREDENTIAL,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = PASSWORDCHECK_PARAMS,
    .m_paramCount              = (int)(sizeof(PASSWORDCHECK_PARAMS) / sizeof(PASSWORDCHECK_PARAMS[0])),
    .m_paramsSize              = sizeof(PASSWORDCHECKParams_t),
    .m_runFunction             = endpoint_PASSWORDCHECKRun,
    .m_isDbRequired            = true,
    .m_callsUpstream           = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/dns_lookup/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "dns_lookup",
    .mp_mcpToolDescription     = "Look up a domain's DNS records: A, AAAA, MX, NS, TXT, CNAME, SOA and CAA. A record type the resolver could not answer is listed under unavailable.",
    .mp_mcpToolTitle           = "DNS Lookup",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_DOMAIN,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = DNSLOOKUP_PARAMS,
    .m_paramCount              = (int)(sizeof(DNSLOOKUP_PARAMS) / sizeof(DNSLOOKUP_PARAMS[0])),
    .m_paramsSize              = sizeof(DNSLOOKUPParams_t),
    .mp_notFoundMessage        = "domain does not exist",
    .m_runFunction             = endpoint_DNSLOOKUPRun,
    .m_isDbRequired            = false,
    .m_callsUpstream           = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/dns_takeover_check/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "dns_takeover_check",
    .mp_mcpToolDescription     = "Check a host name for subdomain takeover through a dangling CNAME. takeover_possible is null when the CNAME points to a service whose DNS does not show whether the name can be claimed.",
    .mp_mcpToolTitle           = "Subdomain Takeover Check",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_DOMAIN,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = DNSTAKEOVERCHECK_PARAMS,
    .m_paramCount              = (int)(sizeof(DNSTAKEOVERCHECK_PARAMS) / sizeof(DNSTAKEOVERCHECK_PARAMS[0])),
    .m_paramsSize              = sizeof(DNSTAKEOVERCHECKParams_t),
    .mp_notFoundMessage        = "hostname does not exist",
    .m_runFunction             = endpoint_DNSTAKEOVERCHECKRun,
    .m_isDbRequired            = false,
    .m_callsUpstream           = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/email_auth_check/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "email_auth_check",
    .mp_mcpToolDescription     = "Check a domain's mail authentication: SPF, DMARC (from a parent domain when the domain has no record of its own), DKIM, MX and MTA-STS, each check with pass, warn or fail and a severity.",
    .mp_mcpToolTitle           = "Email Authentication Check (SPF, DMARC, DKIM)",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_DOMAIN,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = EMAILAUTHCHECK_PARAMS,
    .m_paramCount              = (int)(sizeof(EMAILAUTHCHECK_PARAMS) / sizeof(EMAILAUTHCHECK_PARAMS[0])),
    .m_paramsSize              = sizeof(EMAILAUTHCHECKParams_t),
    .mp_notFoundMessage        = "domain does not exist",
    .m_runFunction             = endpoint_EMAILAUTHCHECKRun,
    .m_isDbRequired            = false,
    .m_callsUpstream           = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/email_address_check/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "email_address_check",
    .mp_mcpToolDescription     = "Check an e-mail address without sending mail: whether its domain exists and takes mail, and whether a disposable domain list names it. It cannot tell whether the mailbox exists.",
    .mp_mcpToolTitle           = "Email Address Check",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_DOMAIN,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = EMAILADDRESSCHECK_PARAMS,
    .m_paramCount              = (int)(sizeof(EMAILADDRESSCHECK_PARAMS) / sizeof(EMAILADDRESSCHECK_PARAMS[0])),
    .m_paramsSize              = sizeof(EMAILADDRESSCHECKParams_t),
    .m_runFunction             = endpoint_EMAILADDRESSCHECKRun,
    .m_isDbRequired            = true,
    .m_callsUpstream           = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/ssl_check/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "ssl_check",
    .mp_mcpToolDescription     = "Check the TLS certificate and settings of a host name on port 443: version, cipher, trust, OCSP revocation, expiry, DNS names, the chain and an abuse.ch SSL Blacklist listing.",
    .mp_mcpToolTitle           = "SSL/TLS Certificate Check",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_DOMAIN,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = SSLCHECK_PARAMS,
    .m_paramCount              = (int)(sizeof(SSLCHECK_PARAMS) / sizeof(SSLCHECK_PARAMS[0])),
    .m_paramsSize              = sizeof(SSLCHECKParams_t),
    .mp_notFoundMessage        = "hostname does not exist",
    .m_runFunction             = endpoint_SSLCHECKRun,
    .m_isDbRequired            = false,
    .m_callsUpstream           = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/headers_check/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "headers_check",
    .mp_mcpToolDescription     = "Rate nine security headers of a web site, such as CSP, HSTS and Set-Cookie, from one GET to https://<domain>/ that follows up to 5 redirects on the same host or its www pair. Each finding that does not pass has a remediation.",
    .mp_mcpToolTitle           = "Security Headers Check",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_DOMAIN,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = HEADERSCHECK_PARAMS,
    .m_paramCount              = (int)(sizeof(HEADERSCHECK_PARAMS) / sizeof(HEADERSCHECK_PARAMS[0])),
    .m_paramsSize              = sizeof(HEADERSCHECKParams_t),
    .m_runFunction             = endpoint_HEADERSCHECKRun,
    .m_isDbRequired            = false,
    .m_callsUpstream           = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/whois_lookup/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "whois_lookup",
    .mp_mcpToolDescription     = "Look up a domain's registration over RDAP, or WHOIS where allowed: registrar, dates, status, name servers and DNSSEC. A name under a registered domain asks about that domain. No registrant data.",
    .mp_mcpToolTitle           = "WHOIS / RDAP Lookup",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_DOMAIN,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = WHOISLOOKUP_PARAMS,
    .m_paramCount              = (int)(sizeof(WHOISLOOKUP_PARAMS) / sizeof(WHOISLOOKUP_PARAMS[0])),
    .m_paramsSize              = sizeof(WHOISLOOKUPParams_t),
    .mp_notFoundMessage        = "domain is not registered",
    .m_runFunction             = endpoint_WHOISLOOKUPRun,
    .m_isDbRequired            = true,
    .m_callsUpstream           = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/wayback_lookup/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "wayback_lookup",
    .mp_mcpToolDescription     = "List when the Wayback Machine captured a host's home page: the first and last capture, the years between them and the latest 10 captures with links.",
    .mp_mcpToolTitle           = "Wayback Machine Lookup",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_DOMAIN,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = WAYBACKLOOKUP_PARAMS,
    .m_paramCount              = (int)(sizeof(WAYBACKLOOKUP_PARAMS) / sizeof(WAYBACKLOOKUP_PARAMS[0])),
    .m_paramsSize              = sizeof(WAYBACKLOOKUPParams_t),
    .m_runFunction             = endpoint_WAYBACKLOOKUPRun,
    .m_isDbRequired            = true,
    .m_callsUpstream           = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/cert_search/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "cert_search",
    .mp_mcpToolDescription     = "List the unexpired certificates that Certificate Transparency logs hold for a host name, wildcards included, from SSLMate's Cert Spotter: the 10 newest, with issuer, validity and DNS names. Costs 2 credits.",
    .mp_mcpToolTitle           = "Certificate Transparency Search",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_DOMAIN,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 2,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = CERTSEARCH_PARAMS,
    .m_paramCount              = (int)(sizeof(CERTSEARCH_PARAMS) / sizeof(CERTSEARCH_PARAMS[0])),
    .m_paramsSize              = sizeof(CERTSEARCHParams_t),
    .m_runFunction             = endpoint_CERTSEARCHRun,
    .m_isDbRequired            = true,
    .m_callsUpstream           = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/subdomain_enum/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "subdomain_enum",
    .mp_mcpToolDescription     = "List up to 50 subdomains of a registrable domain from Certificate Transparency, DNS queries for 94 common names and the domain's MX, NS and SPF records. Costs 2 credits.",
    .mp_mcpToolTitle           = "Subdomain Enumeration",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_DOMAIN,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 2,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = SUBDOMAINENUM_PARAMS,
    .m_paramCount              = (int)(sizeof(SUBDOMAINENUM_PARAMS) / sizeof(SUBDOMAINENUM_PARAMS[0])),
    .m_paramsSize              = sizeof(SUBDOMAINENUMParams_t),
    .m_runFunction             = endpoint_SUBDOMAINENUMRun,
    .m_isDbRequired            = true,
    .m_callsUpstream           = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/ip_lookup/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_readsCreditBudget       = true,
    .m_isPayable               = true,
    .mp_mcpToolName            = "ip_lookup",
    .mp_mcpToolDescription     = "Look up a public IP address: AS, country, cloud provider, CDN, datacenter or Tor exit, DROP listing and PTR name. A Pro key with its own Shodan or AbuseIPDB key adds exposure and reputation.",
    .mp_mcpToolTitle           = "IP Lookup",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_IP,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = IPLOOKUP_PARAMS,
    .m_paramCount              = (int)(sizeof(IPLOOKUP_PARAMS) / sizeof(IPLOOKUP_PARAMS[0])),
    .m_paramsSize              = sizeof(IPLOOKUPParams_t),
    .m_runFunction             = endpoint_IPLOOKUPRun,
    .m_isDbRequired            = true,
    .m_callsUpstream           = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/asn_lookup/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "asn_lookup",
    .mp_mcpToolDescription     = "Look up an autonomous system by number, such as AS15169, or by an IP address it holds: name, country and one page of its IPv4 and IPv6 prefixes, derived from IPtoASN.",
    .mp_mcpToolTitle           = "ASN Lookup",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_IP,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = ASNLOOKUP_PARAMS,
    .m_paramCount              = (int)(sizeof(ASNLOOKUP_PARAMS) / sizeof(ASNLOOKUP_PARAMS[0])),
    .m_paramsSize              = sizeof(ASNLOOKUPParams_t),
    .mp_notFoundMessage        = "AS not found",
    .m_runFunction             = endpoint_ASNLOOKUPRun,
    .m_isDbRequired            = true,
    .m_callsUpstream           = false,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/d3fend_for_attack/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "d3fend_for_attack",
    .mp_mcpToolDescription     = "MITRE D3FEND defenses that counter a MITRE ATT&CK technique. A technique id such as T1055 also matches its sub-techniques. Source: MITRE D3FEND (MIT license).",
    .mp_mcpToolTitle           = "D3FEND Defenses for ATT&CK",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_THREAT_DEFENSE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = D3FENDFORATTACK_PARAMS,
    .m_paramCount              = (int)(sizeof(D3FENDFORATTACK_PARAMS) / sizeof(D3FENDFORATTACK_PARAMS[0])),
    .m_paramsSize              = sizeof(D3FENDFORATTACKParams_t),
    .m_runFunction             = endpoint_D3FENDFORATTACKRun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/driver_lookup/",
    .m_hasPathSegment          = true,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "driver_lookup",
    .mp_mcpToolDescription     = "Look up a Windows driver file hash in the LOLDrivers catalog of vulnerable and malicious drivers. Block on the file and Authenticode hashes, not on the detection rules. Source: LOLDrivers (Apache-2.0).",
    .mp_mcpToolTitle           = "Windows Driver Lookup (LOLDrivers)",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_THREAT_DEFENSE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = DRIVERLOOKUP_PARAMS,
    .m_paramCount              = (int)(sizeof(DRIVERLOOKUP_PARAMS) / sizeof(DRIVERLOOKUP_PARAMS[0])),
    .m_paramsSize              = sizeof(DRIVERLOOKUPParams_t),
    .m_runFunction             = endpoint_DRIVERLOOKUPRun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/driver_lookup_bulk",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"POST", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "driver_lookup_bulk",
    .mp_mcpToolDescription     = "Look up many driver file hashes in the LOLDrivers catalog at once, each with the fields of driver_lookup. Hashes beyond the remaining credits come back in not_processed.",
    .mp_mcpToolTitle           = "Bulk Windows Driver Lookup",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_THREAT_DEFENSE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_BULK_IDS,
    .mp_params                 = DRIVERLOOKUPBULK_PARAMS,
    .m_paramCount              = (int)(sizeof(DRIVERLOOKUPBULK_PARAMS) / sizeof(DRIVERLOOKUPBULK_PARAMS[0])),
    .m_paramsSize              = sizeof(BulkIdsParams_t),
    .m_runFunction             = endpoint_DRIVERLOOKUPBULKRun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_MAX_CEILING,
  },
  {
    .mp_httpPath               = "/package_check",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"GET", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "package_check",
    .mp_mcpToolDescription     = "Check a package against the OSV.dev advisories (GitHub, Go, PyPA, RustSec) and the OpenSSF malicious package list, with the fixed version and endoflife.date dates. For severity, pass the CVE aliases to the cve_triage_bulk tool.",
    .mp_mcpToolTitle           = "Package Vulnerability Check",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_PACKAGE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = PACKAGECHECK_PARAMS,
    .m_paramCount              = (int)(sizeof(PACKAGECHECK_PARAMS) / sizeof(PACKAGECHECK_PARAMS[0])),
    .m_paramsSize              = sizeof(PACKAGECHECKParams_t),
    .m_runFunction             = endpoint_PACKAGECHECKRun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/package_check_bulk",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"POST", NULL},
    .m_isPayable               = true,
    .mp_mcpToolName            = "package_check_bulk",
    .mp_mcpToolDescription     = "Check many packages at once, each an ecosystem, a name and an exact version, against the advisories package_check reads. For the summary and ranges of an advisory, call the package_check tool.",
    .mp_mcpToolTitle           = "Bulk Package Check (SBOM)",
    .m_mcpToolCategory         = ENDPOINT_MCP_TOOL_CATEGORY_PACKAGE,
    .m_mcpToolEffect           = ENDPOINT_MCP_TOOL_EFFECT_READ_ONLY,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_BULK_IDS,
    .mp_params                 = PACKAGECHECKBULK_PARAMS,
    .m_paramCount              = (int)(sizeof(PACKAGECHECKBULK_PARAMS) / sizeof(PACKAGECHECKBULK_PARAMS[0])),
    .m_paramsSize              = sizeof(PACKAGECHECKBULKParams_t),
    .m_runFunction             = endpoint_PACKAGECHECKBULKRun,
    .m_weighFunction           = endpoint_PACKAGECHECKBULKWeigh,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/image_inspect",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"POST", NULL},
    .m_isPayable               = true,
    .m_creditCost              = 2,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = IMAGEINSPECT_PARAMS,
    .m_paramCount              = (int)(sizeof(IMAGEINSPECT_PARAMS) / sizeof(IMAGEINSPECT_PARAMS[0])),
    .m_paramsSize              = sizeof(IMAGEINSPECTParams_t),
    .m_runFunction             = endpoint_IMAGEINSPECTRun,
    .m_isDbRequired            = false,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/webhook_lemonsqueezy",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"POST", NULL},
    .m_creditCost              = 0,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = WEBHOOKLEMONSQUEEZY_PARAMS,
    .m_paramCount              = (int)(sizeof(WEBHOOKLEMONSQUEEZY_PARAMS) / sizeof(WEBHOOKLEMONSQUEEZY_PARAMS[0])),
    .m_paramsSize              = sizeof(WEBHOOKLEMONSQUEEZYParams_t),
    .m_runFunction             = endpoint_WEBHOOKLEMONSQUEEZYRun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/webhook_nowpayments",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"POST", NULL},
    .m_creditCost              = 0,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = WEBHOOKNOWPAYMENTS_PARAMS,
    .m_paramCount              = (int)(sizeof(WEBHOOKNOWPAYMENTS_PARAMS) / sizeof(WEBHOOKNOWPAYMENTS_PARAMS[0])),
    .m_paramsSize              = sizeof(WEBHOOKNOWPAYMENTSParams_t),
    .m_runFunction             = endpoint_WEBHOOKNOWPAYMENTSRun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/api_key_claim",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"POST", NULL},
    .m_creditCost              = 0,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .mp_params                 = APIKEYCLAIM_PARAMS,
    .m_paramCount              = (int)(sizeof(APIKEYCLAIM_PARAMS) / sizeof(APIKEYCLAIM_PARAMS[0])),
    .m_paramsSize              = sizeof(APIKEYCLAIMParams_t),
    .mp_notFoundMessage        = "no paid order has this order_id yet",
    .m_runFunction             = endpoint_APIKEYCLAIMRun,
    .m_isDbRequired            = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/crypto_checkout",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"POST", NULL},
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
    .m_runFunction             = endpoint_CRYPTOCHECKOUTRun,
    .m_isDbRequired            = false,
    .m_callsUpstream           = true,
    .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
  },
  {
    .mp_httpPath               = "/mcp",
    .m_hasPathSegment          = false,
    .ma_allowedMethods         = {"POST", NULL},
    .m_isMcpEndpoint           = true,
    .m_creditCost              = 1,
    .m_costRule                = ENDPOINT_COST_FLAT,
  },
};

const int endpoint_count = (int)(sizeof(endpoints) / sizeof(endpoints[0]));
