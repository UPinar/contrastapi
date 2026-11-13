#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <libpq-fe.h>

#include "db.h"
#include "dbhelper.h"
#include "macro.h"
#include "bulk.h"
#include "cve.h"
#include "ssvc.h"
#include "d3fend.h"
#include "lol.h"
#include "ip.h"
#include "validate.h"
#include "emailcheck.h"
#include "etld.h"
#include "package.h"

#define DB_API_KEY_STATE_MAX_LEN 8

#define DB_BILLING_PROVIDER_LEMONSQUEEZY "lemonsqueezy"

#define DB_BILLING_EVENT_STATUS_MAX_LEN  9
#define DB_BILLING_CLAIM_STATUS_MAX_LEN 15

#define DB_VENDOR_KEY_STATE_MAX_LEN 8

#define DB_INT64_PARAM_BUF_SIZE   24
_Static_assert(DB_INT64_PARAM_BUF_SIZE >= sizeof("-9223372036854775808"),
               "DB_INT64_PARAM_BUF_SIZE must hold every int64_t in decimal text");

#define DB_CVESEARCH_FILTER_COUNT  12
#define DB_CVELEADING_FILTER_COUNT  7
#define DB_CVETRIAGE_FILTER_COUNT   4
#define DB_CPESEARCH_FILTER_COUNT   1

#define DB_ID_ARRAY_PARAM_BUF_SIZE  (sizeof(((const BulkIdsParams_t*)0)->ma_ids) + sizeof("{"))

#define CVESEARCH_COLUMNS(X)                             \
  X(CVESEARCH_COLUMN_CVE_ID,          "cve_id")          \
  X(CVESEARCH_COLUMN_SEVERITY,        "severity")        \
  X(CVESEARCH_COLUMN_CVSS_V3,         "cvss_v3")         \
  X(CVESEARCH_COLUMN_EPSS_SCORE,      "epss_score")      \
  X(CVESEARCH_COLUMN_EPSS_PERCENTILE, "epss_percentile") \
  X(CVESEARCH_COLUMN_IN_KEV,          "in_kev")          \
  X(CVESEARCH_COLUMN_PUBLISHED_TIME,  "published_time")  \
  X(CVESEARCH_COLUMN_CWE_ID,          "cwe_id")          \
  X(CVESEARCH_COLUMN_CVSS_V4,         "cvss_v4")         \
  X(CVESEARCH_COLUMN_HAS_CVSS_V4,     "has_cvss_v4")     \
  X(CVESEARCH_COLUMN_HAS_CVSS_V3,     "has_cvss_v3")     \
  X(CVESEARCH_COLUMN_CVSS_V3_SOURCE,  "cvss_v3_source")  \
  X(CVESEARCH_COLUMN_CVSS_V4_SOURCE,  "cvss_v4_source")  \
  X(CVESEARCH_COLUMN_CWE_SOURCE,      "cwe_source")
enum { CVESEARCH_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const CVESEARCH_COLUMN_NAMES[] = { CVESEARCH_COLUMNS(DBHELPER_COLUMN_NAME) };

#define CVETRIAGE_COLUMNS(X)                   \
  X(CVETRIAGE_COLUMN_CVE_ID,     "cve_id")     \
  X(CVETRIAGE_COLUMN_EPSS_SCORE, "epss_score") \
  X(CVETRIAGE_COLUMN_CVSS_V3,    "cvss_v3")    \
  X(CVETRIAGE_COLUMN_RISK_SCORE, "risk_score") \
  X(CVETRIAGE_COLUMN_RISK_LABEL, "risk_label")
enum { CVETRIAGE_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const CVETRIAGE_COLUMN_NAMES[] = { CVETRIAGE_COLUMNS(DBHELPER_COLUMN_NAME) };

#define CVELOOKUP_COLUMNS(X)                                                     \
  X(CVELOOKUP_COLUMN_CVE_ID,                      "cve_id")                      \
  X(CVELOOKUP_COLUMN_CVE_DESCRIPTION,             "cve_description")             \
  X(CVELOOKUP_COLUMN_SEVERITY,                    "severity")                    \
  X(CVELOOKUP_COLUMN_CVSS_V3,                     "cvss_v3")                     \
  X(CVELOOKUP_COLUMN_CVSS_V3_VECTOR,              "cvss_v3_vector")              \
  X(CVELOOKUP_COLUMN_PUBLISHED_TIME,              "published_time")              \
  X(CVELOOKUP_COLUMN_EPSS_SCORE,                  "epss_score")                  \
  X(CVELOOKUP_COLUMN_EPSS_PERCENTILE,             "epss_percentile")             \
  X(CVELOOKUP_COLUMN_CWE_ID,                      "cwe_id")                      \
  X(CVELOOKUP_COLUMN_CWES,                        "cwes")                        \
  X(CVELOOKUP_COLUMN_IN_KEV,                      "in_kev")                      \
  X(CVELOOKUP_COLUMN_KEV_DATE_ADDED,              "kev_date_added")              \
  X(CVELOOKUP_COLUMN_VULNERABILITY_STATUS,        "vulnerability_status")        \
  X(CVELOOKUP_COLUMN_POC_COUNT,                   "poc_count")                   \
  X(CVELOOKUP_COLUMN_VENDOR_ADVISORY_COUNT,       "vendor_advisory_count")       \
  X(CVELOOKUP_COLUMN_CVE_TAGS,                    "cve_tags")                    \
  X(CVELOOKUP_COLUMN_METASPLOIT_MODULE_COUNT,     "metasploit_module_count")     \
  X(CVELOOKUP_COLUMN_AFFECTED_PRODUCTS,           "affected_products")           \
  X(CVELOOKUP_COLUMN_REFS,                        "refs")                        \
  X(CVELOOKUP_COLUMN_EPSS_TREND,                  "epss_trend")                  \
  X(CVELOOKUP_COLUMN_RANSOMWARE_CAMPAIGN,         "ransomware_campaign")         \
  X(CVELOOKUP_COLUMN_CVSS_V4,                     "cvss_v4")                     \
  X(CVELOOKUP_COLUMN_CVSS_V4_VECTOR,              "cvss_v4_vector")              \
  X(CVELOOKUP_COLUMN_SSVC_EXPLOITATION,           "ssvc_exploitation")           \
  X(CVELOOKUP_COLUMN_SSVC_AUTOMATABLE,            "ssvc_automatable")            \
  X(CVELOOKUP_COLUMN_SSVC_TECHNICAL_IMPACT,       "ssvc_technical_impact")       \
  X(CVELOOKUP_COLUMN_SSVC_VERSION,                "ssvc_version")                \
  X(CVELOOKUP_COLUMN_SSVC_SCORED_AT,              "ssvc_scored_at")              \
  X(CVELOOKUP_COLUMN_METASPLOIT_FEED_LOADED,      "metasploit_feed_loaded")      \
  X(CVELOOKUP_COLUMN_NUCLEI_TEMPLATE_COUNT,       "nuclei_template_count")       \
  X(CVELOOKUP_COLUMN_NUCLEI_TEMPLATE_FEED_LOADED, "nuclei_template_feed_loaded") \
  X(CVELOOKUP_COLUMN_NUCLEI_TEMPLATES,            "nuclei_templates")            \
  X(CVELOOKUP_COLUMN_CVSS_V3_SOURCE,              "cvss_v3_source")              \
  X(CVELOOKUP_COLUMN_CVSS_V4_SOURCE,              "cvss_v4_source")              \
  X(CVELOOKUP_COLUMN_CWE_SOURCE,                  "cwe_source")                  \
  X(CVELOOKUP_COLUMN_AFFECTED_PRODUCT_COUNT,      "affected_product_count")      \
  X(CVELOOKUP_COLUMN_PRODUCT_COUNT_BY_VENDOR,     "product_count_by_vendor")     \
  X(CVELOOKUP_COLUMN_REF_COUNT,                   "ref_count")
enum { CVELOOKUP_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const CVELOOKUP_COLUMN_NAMES[] = { CVELOOKUP_COLUMNS(DBHELPER_COLUMN_NAME) };

#define CPESEARCH_COLUMNS(X)                               \
  X(CPESEARCH_COLUMN_VENDOR,               "vendor")               \
  X(CPESEARCH_COLUMN_PRODUCT,              "product")              \
  X(CPESEARCH_COLUMN_VULNERABLE_CVE_COUNT, "vulnerable_cve_count") \
  X(CPESEARCH_COLUMN_PRODUCT_NAMED_BY,     "product_named_by")
enum { CPESEARCH_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const CPESEARCH_COLUMN_NAMES[] = { CPESEARCH_COLUMNS(DBHELPER_COLUMN_NAME) };

#define D3FENDFORATTACK_COLUMNS(X)                                         \
  X(D3FENDFORATTACK_COLUMN_DEFENSE_ID,            "defense_id")            \
  X(D3FENDFORATTACK_COLUMN_DEFENSE_LABEL,         "defense_label")         \
  X(D3FENDFORATTACK_COLUMN_DEFENSE_TACTIC,        "defense_tactic")        \
  X(D3FENDFORATTACK_COLUMN_DIGITAL_ARTIFACT,      "digital_artifact")      \
  X(D3FENDFORATTACK_COLUMN_PARENT_DEFENSE_LABELS, "parent_defense_labels") \
  X(D3FENDFORATTACK_COLUMN_ATTACK_TECHNIQUE_IDS,  "attack_technique_ids")  \
  X(D3FENDFORATTACK_COLUMN_ATTACK_TECHNIQUES,     "attack_techniques")
enum { D3FENDFORATTACK_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const D3FENDFORATTACK_COLUMN_NAMES[] = { D3FENDFORATTACK_COLUMNS(DBHELPER_COLUMN_NAME) };

#define DRIVERLOOKUP_COLUMNS(X)                                   \
  X(DRIVERLOOKUP_COLUMN_FILE_HASH,          "file_hash")          \
  X(DRIVERLOOKUP_COLUMN_MATCH_COUNT,        "match_count")        \
  X(DRIVERLOOKUP_COLUMN_DRIVER_FEED_LOADED, "driver_feed_loaded") \
  X(DRIVERLOOKUP_COLUMN_MATCHES,            "matches")
enum { DRIVERLOOKUP_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const DRIVERLOOKUP_COLUMN_NAMES[] = { DRIVERLOOKUP_COLUMNS(DBHELPER_COLUMN_NAME) };

#define IPLOOKUP_COLUMNS(X)                                         \
  X(IPLOOKUP_COLUMN_ASN,                   "asn")                   \
  X(IPLOOKUP_COLUMN_ASN_NAME,              "asn_name")              \
  X(IPLOOKUP_COLUMN_ASN_COUNTRY,           "asn_country")           \
  X(IPLOOKUP_COLUMN_GEO_COUNTRY,           "geo_country")           \
  X(IPLOOKUP_COLUMN_CLOUD_PROVIDER,        "cloud_provider")        \
  X(IPLOOKUP_COLUMN_CLOUD_SERVICE,         "cloud_service")         \
  X(IPLOOKUP_COLUMN_IS_CDN,                "is_cdn")                \
  X(IPLOOKUP_COLUMN_IS_DATACENTER,         "is_datacenter")         \
  X(IPLOOKUP_COLUMN_IS_TOR_EXIT,           "is_tor_exit")           \
  X(IPLOOKUP_COLUMN_LISTED_ON,             "listed_on")             \
  X(IPLOOKUP_COLUMN_ASN_FEED_LOADED,       "asn_feed_loaded")       \
  X(IPLOOKUP_COLUMN_GEO_FEED_LOADED,       "geo_feed_loaded")       \
  X(IPLOOKUP_COLUMN_CLOUD_FEED_LOADED,     "cloud_feed_loaded")     \
  X(IPLOOKUP_COLUMN_TOR_FEED_LOADED,       "tor_feed_loaded")       \
  X(IPLOOKUP_COLUMN_DROP_LIST_FEED_LOADED, "drop_list_feed_loaded")
enum { IPLOOKUP_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const IPLOOKUP_COLUMN_NAMES[] = { IPLOOKUP_COLUMNS(DBHELPER_COLUMN_NAME) };

#define ASNLOOKUPPREFIX_COLUMNS(X)                 \
  X(ASNLOOKUPPREFIX_COLUMN_ASN,    "asn")          \
  X(ASNLOOKUPPREFIX_COLUMN_PREFIX, "prefix")
enum { ASNLOOKUPPREFIX_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const ASNLOOKUPPREFIX_COLUMN_NAMES[] = { ASNLOOKUPPREFIX_COLUMNS(DBHELPER_COLUMN_NAME) };

#define ASNLOOKUP_COLUMNS(X)                                       \
  X(ASNLOOKUP_COLUMN_ASN,               "asn")                     \
  X(ASNLOOKUP_COLUMN_ASN_NAME,          "asn_name")                \
  X(ASNLOOKUP_COLUMN_ASN_COUNTRY,       "asn_country")             \
  X(ASNLOOKUP_COLUMN_IPV4_PREFIX_COUNT, "ipv4_prefix_count")       \
  X(ASNLOOKUP_COLUMN_IPV6_PREFIX_COUNT, "ipv6_prefix_count")       \
  X(ASNLOOKUP_COLUMN_IPV4_PREFIXES,     "ipv4_prefixes")           \
  X(ASNLOOKUP_COLUMN_IPV6_PREFIXES,     "ipv6_prefixes")
enum { ASNLOOKUP_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const ASNLOOKUP_COLUMN_NAMES[] = { ASNLOOKUP_COLUMNS(DBHELPER_COLUMN_NAME) };

#define EMAILADDRESSCHECK_COLUMNS(X)                                             \
  X(EMAILADDRESSCHECK_COLUMN_DISPOSABLE_FEED_LOADED, "disposable_feed_loaded")   \
  X(EMAILADDRESSCHECK_COLUMN_LISTED_DOMAIN,          "listed_domain")
enum { EMAILADDRESSCHECK_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const EMAILADDRESSCHECK_COLUMN_NAMES[] = { EMAILADDRESSCHECK_COLUMNS(DBHELPER_COLUMN_NAME) };

#define SSLCHECK_COLUMNS(X)                                                \
  X(SSLCHECK_COLUMN_SSL_BLACKLIST_FEED_LOADED, "ssl_blacklist_feed_loaded") \
  X(SSLCHECK_COLUMN_LISTING_REASON,            "listing_reason")            \
  X(SSLCHECK_COLUMN_LISTING_TIME,              "listing_time")
enum { SSLCHECK_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const SSLCHECK_COLUMN_NAMES[] = { SSLCHECK_COLUMNS(DBHELPER_COLUMN_NAME) };

#define PACKAGECHECK_COLUMNS(X)                                       \
  X(PACKAGECHECK_COLUMN_ADVISORY_FEED_LOADED, "advisory_feed_loaded") \
  X(PACKAGECHECK_COLUMN_HAS_ADVISORY_DATA,    "has_advisory_data")    \
  X(PACKAGECHECK_COLUMN_RESULT_COUNT,         "result_count")         \
  X(PACKAGECHECK_COLUMN_FIXED_VERSION,        "fixed_version")        \
  X(PACKAGECHECK_COLUMN_MALICIOUS,            "malicious")            \
  X(PACKAGECHECK_COLUMN_RESULTS,              "results")              \
  X(PACKAGECHECK_COLUMN_ATTRIBUTION,          "attribution")
enum { PACKAGECHECK_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const PACKAGECHECK_COLUMN_NAMES[] = { PACKAGECHECK_COLUMNS(DBHELPER_COLUMN_NAME) };

#define PACKAGECHECKBULK_COLUMNS(X)                                       \
  X(PACKAGECHECKBULK_COLUMN_ADVISORY_FEED_LOADED, "advisory_feed_loaded") \
  X(PACKAGECHECKBULK_COLUMN_RESULTS,              "results")              \
  X(PACKAGECHECKBULK_COLUMN_ATTRIBUTION,          "attribution")          \
  X(PACKAGECHECKBULK_COLUMN_FAILED_ITEM_COUNT,    "failed_item_count")
enum { PACKAGECHECKBULK_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const PACKAGECHECKBULK_COLUMN_NAMES[] = { PACKAGECHECKBULK_COLUMNS(DBHELPER_COLUMN_NAME) };

#define PACKAGECHECKBULKWEIGH_COLUMNS(X)                                        \
  X(PACKAGECHECKBULKWEIGH_COLUMN_SERVED_ITEM_COUNT, "served_item_count")
enum { PACKAGECHECKBULKWEIGH_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const PACKAGECHECKBULKWEIGH_COLUMN_NAMES[] = { PACKAGECHECKBULKWEIGH_COLUMNS(DBHELPER_COLUMN_NAME) };

_Static_assert(PACKAGECHECKBULK_WEIGHT_BUDGET > 0,
               "a weight budget of 0 would serve no package, and db_PACKAGECHECKBULKWeigh would refuse every answer");

#define CVELOOKUPGHSA_COLUMNS(X)                               \
  X(CVELOOKUPGHSA_COLUMN_GHSA_FEED_LOADED, "ghsa_feed_loaded") \
  X(CVELOOKUPGHSA_COLUMN_ADVISORY,         "advisory")
enum { CVELOOKUPGHSA_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const CVELOOKUPGHSA_COLUMN_NAMES[] = { CVELOOKUPGHSA_COLUMNS(DBHELPER_COLUMN_NAME) };

#define CVEPRODUCTS_COLUMNS(X)                                           \
  X(CVEPRODUCTS_COLUMN_AFFECTED_PRODUCT_COUNT, "affected_product_count") \
  X(CVEPRODUCTS_COLUMN_LISTED_PRODUCT_COUNT,   "listed_product_count")   \
  X(CVEPRODUCTS_COLUMN_AFFECTED_PRODUCTS,      "affected_products")
enum { CVEPRODUCTS_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const CVEPRODUCTS_COLUMN_NAMES[] = { CVEPRODUCTS_COLUMNS(DBHELPER_COLUMN_NAME) };

#define HEALTH_COLUMNS(X)                                             \
  X(HEALTH_COLUMN_CVE_COUNT,               "cve_count")               \
  X(HEALTH_COLUMN_NVD_LAST_CVE_ID,         "nvd_last_cve_id")         \
  X(HEALTH_COLUMN_NVD_LAST_PUBLISHED_TIME, "nvd_last_published_time") \
  X(HEALTH_COLUMN_KEV_COUNT,               "kev_count")               \
  X(HEALTH_COLUMN_KEV_LAST_CVE_ID,         "kev_last_cve_id")         \
  X(HEALTH_COLUMN_KEV_LAST_DATE_ADDED,     "kev_last_date_added")     \
  X(HEALTH_COLUMN_CWE_COUNT,               "cwe_count")               \
  X(HEALTH_COLUMN_CWE_LAST_ID,             "cwe_last_id")             \
  X(HEALTH_COLUMN_CWE_LAST_UPDATED_AT,     "cwe_last_updated_at")
enum { HEALTH_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const HEALTH_COLUMN_NAMES[] = { HEALTH_COLUMNS(DBHELPER_COLUMN_NAME) };

#define HEALTH_FEED_COLUMNS(X)                             \
  X(HEALTH_FEED_COLUMN_FEED_NAME,       "feed_name")       \
  X(HEALTH_FEED_COLUMN_LAST_SYNCED,     "last_synced")     \
  X(HEALTH_FEED_COLUMN_LAST_STATUS,     "last_status")     \
  X(HEALTH_FEED_COLUMN_RECORDS_UPDATED, "records_updated")
enum { HEALTH_FEED_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const HEALTH_FEED_COLUMN_NAMES[] = { HEALTH_FEED_COLUMNS(DBHELPER_COLUMN_NAME) };

#define KEVLOOKUP_COLUMNS(X)                                       \
  X(KEVLOOKUP_COLUMN_CVE_ID,               "cve_id")               \
  X(KEVLOOKUP_COLUMN_VENDOR_PROJECT,       "vendor_project")       \
  X(KEVLOOKUP_COLUMN_PRODUCT,              "product")              \
  X(KEVLOOKUP_COLUMN_PATCH_DEADLINE,       "patch_deadline")       \
  X(KEVLOOKUP_COLUMN_REQUIRED_ACTION,      "required_action")      \
  X(KEVLOOKUP_COLUMN_KNOWN_RANSOMWARE_USE, "known_ransomware_use") \
  X(KEVLOOKUP_COLUMN_VULNERABILITY_NAME,   "vulnerability_name")   \
  X(KEVLOOKUP_COLUMN_SHORT_DESCRIPTION,    "short_description")    \
  X(KEVLOOKUP_COLUMN_KEV_DATE_ADDED,       "kev_date_added")       \
  X(KEVLOOKUP_COLUMN_DATE_REMOVED,         "date_removed")         \
  X(KEVLOOKUP_COLUMN_CWES,                 "cwes")                 \
  X(KEVLOOKUP_COLUMN_NOTES,                "notes")                \
  X(KEVLOOKUP_COLUMN_IN_KEV,               "in_kev")
enum { KEVLOOKUP_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const KEVLOOKUP_COLUMN_NAMES[] = { KEVLOOKUP_COLUMNS(DBHELPER_COLUMN_NAME) };

#define CWELOOKUP_COLUMNS(X)                                       \
  X(CWELOOKUP_COLUMN_CWE_ID,               "cwe_id")               \
  X(CWELOOKUP_COLUMN_CWE_NAME,             "cwe_name")             \
  X(CWELOOKUP_COLUMN_CWE_DESCRIPTION,      "cwe_description")      \
  X(CWELOOKUP_COLUMN_LIKELIHOOD,           "likelihood")           \
  X(CWELOOKUP_COLUMN_PARENT_CWE,           "parent_cwe")           \
  X(CWELOOKUP_COLUMN_UPDATED_AT,           "updated_at")           \
  X(CWELOOKUP_COLUMN_MITIGATIONS,          "mitigations")          \
  X(CWELOOKUP_COLUMN_EXTENDED_DESCRIPTION, "extended_description") \
  X(CWELOOKUP_COLUMN_EXAMPLES,             "examples")             \
  X(CWELOOKUP_COLUMN_ABSTRACT_TYPE,        "abstract_type")        \
  X(CWELOOKUP_COLUMN_CWE_STATUS,           "cwe_status")           \
  X(CWELOOKUP_COLUMN_KEV_CVE_COUNT,        "kev_cve_count")        \
  X(CWELOOKUP_COLUMN_AVG_CVSS,             "avg_cvss")             \
  X(CWELOOKUP_COLUMN_AVG_EPSS,             "avg_epss")             \
  X(CWELOOKUP_COLUMN_CVE_COUNT,            "cve_count")
enum { CWELOOKUP_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const CWELOOKUP_COLUMN_NAMES[] = { CWELOOKUP_COLUMNS(DBHELPER_COLUMN_NAME) };

#define CVERISKSCORE_COLUMNS(X)                           \
  X(CVERISKSCORE_COLUMN_RISK_SCORE,     "risk_score")     \
  X(CVERISKSCORE_COLUMN_EXPLOITABILITY, "exploitability") \
  X(CVERISKSCORE_COLUMN_IMPACT,         "impact")         \
  X(CVERISKSCORE_COLUMN_EVIDENCE,       "evidence")       \
  X(CVERISKSCORE_COLUMN_HAS_PUBLIC_POC, "has_public_poc") \
  X(CVERISKSCORE_COLUMN_RISK_LABEL,     "risk_label")
enum { CVERISKSCORE_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const CVERISKSCORE_COLUMN_NAMES[] = { CVERISKSCORE_COLUMNS(DBHELPER_COLUMN_NAME) };

#define DB_SCHEMA_VERSION_COLUMNS(X)                           \
  X(DB_SCHEMA_VERSION_COLUMN_SCHEMA_VERSION, "schema_version")
enum { DB_SCHEMA_VERSION_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const DB_SCHEMA_VERSION_COLUMN_NAMES[] = { DB_SCHEMA_VERSION_COLUMNS(DBHELPER_COLUMN_NAME) };

#define DB_CONNECTION_ROLE_STATE_COLUMNS(X)                                 \
  X(DB_CONNECTION_ROLE_STATE_COLUMN_IS_SUPERUSER,    "is_superuser")        \
  X(DB_CONNECTION_ROLE_STATE_COLUMN_IS_OWNER_MEMBER, "is_owner_member")
enum { DB_CONNECTION_ROLE_STATE_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const DB_CONNECTION_ROLE_STATE_COLUMN_NAMES[] = { DB_CONNECTION_ROLE_STATE_COLUMNS(DBHELPER_COLUMN_NAME) };

#define DB_API_KEY_STATE_COLUMNS(X)                           \
  X(DB_API_KEY_STATE_COLUMN_API_KEY_STATE,  "api_key_state")  \
  X(DB_API_KEY_STATE_COLUMN_KEY_EXPIRES_AT, "key_expires_at")
enum { DB_API_KEY_STATE_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const DB_API_KEY_STATE_COLUMN_NAMES[] = { DB_API_KEY_STATE_COLUMNS(DBHELPER_COLUMN_NAME) };

#define DB_BILLING_EVENT_STATUS_COLUMNS(X)                                      \
  X(DB_BILLING_EVENT_STATUS_COLUMN_BILLING_EVENT_STATUS, "billing_event_status")
enum { DB_BILLING_EVENT_STATUS_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const DB_BILLING_EVENT_STATUS_COLUMN_NAMES[] = { DB_BILLING_EVENT_STATUS_COLUMNS(DBHELPER_COLUMN_NAME) };

#define DB_BILLING_CLAIM_STATUS_COLUMNS(X)                                      \
  X(DB_BILLING_CLAIM_STATUS_COLUMN_BILLING_CLAIM_STATUS, "billing_claim_status")
enum { DB_BILLING_CLAIM_STATUS_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const DB_BILLING_CLAIM_STATUS_COLUMN_NAMES[] = { DB_BILLING_CLAIM_STATUS_COLUMNS(DBHELPER_COLUMN_NAME) };

#define DB_VENDOR_KEY_READ_COLUMNS(X)                                       \
  X(DB_VENDOR_KEY_READ_COLUMN_API_KEY_ID,           "api_key_id")           \
  X(DB_VENDOR_KEY_READ_COLUMN_KEY_FINGERPRINT,      "key_fingerprint")      \
  X(DB_VENDOR_KEY_READ_COLUMN_SHODAN_SEALED_HEX,    "shodan_sealed_hex")    \
  X(DB_VENDOR_KEY_READ_COLUMN_ABUSEIPDB_SEALED_HEX, "abuseipdb_sealed_hex")
enum { DB_VENDOR_KEY_READ_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const DB_VENDOR_KEY_READ_COLUMN_NAMES[] = { DB_VENDOR_KEY_READ_COLUMNS(DBHELPER_COLUMN_NAME) };

#define DB_VENDOR_KEY_LINK_OPEN_COLUMNS(X)                                \
  X(DB_VENDOR_KEY_LINK_OPEN_COLUMN_LINK_EXPIRES_AT, "link_expires_at")
enum { DB_VENDOR_KEY_LINK_OPEN_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const DB_VENDOR_KEY_LINK_OPEN_COLUMN_NAMES[] = { DB_VENDOR_KEY_LINK_OPEN_COLUMNS(DBHELPER_COLUMN_NAME) };

#define DB_VENDOR_KEY_LINK_READ_COLUMNS(X)                                       \
  X(DB_VENDOR_KEY_LINK_READ_COLUMN_LINK_STATE,           "link_state")           \
  X(DB_VENDOR_KEY_LINK_READ_COLUMN_API_KEY_ID,           "api_key_id")           \
  X(DB_VENDOR_KEY_LINK_READ_COLUMN_LINK_EXPIRES_AT,      "link_expires_at")      \
  X(DB_VENDOR_KEY_LINK_READ_COLUMN_SHODAN_SEALED_HEX,    "shodan_sealed_hex")    \
  X(DB_VENDOR_KEY_LINK_READ_COLUMN_ABUSEIPDB_SEALED_HEX, "abuseipdb_sealed_hex")
enum { DB_VENDOR_KEY_LINK_READ_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const DB_VENDOR_KEY_LINK_READ_COLUMN_NAMES[] = { DB_VENDOR_KEY_LINK_READ_COLUMNS(DBHELPER_COLUMN_NAME) };

#define DB_VENDOR_KEY_APPLY_STATUS_COLUMNS(X)                                            \
  X(DB_VENDOR_KEY_APPLY_STATUS_COLUMN_VENDOR_KEY_APPLY_STATUS, "vendor_key_apply_status")
enum { DB_VENDOR_KEY_APPLY_STATUS_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const DB_VENDOR_KEY_APPLY_STATUS_COLUMN_NAMES[] = { DB_VENDOR_KEY_APPLY_STATUS_COLUMNS(DBHELPER_COLUMN_NAME) };

#define PRODUCTEXPOSURE_COLUMNS(X)                                         \
  X(PRODUCTEXPOSURE_COLUMN_CVE_COUNT,             "cve_count")             \
  X(PRODUCTEXPOSURE_COLUMN_CRITICAL_COUNT,        "critical_count")        \
  X(PRODUCTEXPOSURE_COLUMN_HIGH_COUNT,            "high_count")            \
  X(PRODUCTEXPOSURE_COLUMN_MEDIUM_COUNT,          "medium_count")          \
  X(PRODUCTEXPOSURE_COLUMN_LOW_COUNT,             "low_count")             \
  X(PRODUCTEXPOSURE_COLUMN_KEV_COUNT,             "kev_count")             \
  X(PRODUCTEXPOSURE_COLUMN_MAX_CVSS,              "max_cvss")              \
  X(PRODUCTEXPOSURE_COLUMN_AVG_CVSS,              "avg_cvss")              \
  X(PRODUCTEXPOSURE_COLUMN_MAX_EPSS,              "max_epss")              \
  X(PRODUCTEXPOSURE_COLUMN_POC_BACKED_COUNT,      "poc_backed_count")      \
  X(PRODUCTEXPOSURE_COLUMN_WORST_RISK_SCORE,      "worst_risk_score")      \
  X(PRODUCTEXPOSURE_COLUMN_MOST_RECENT_PUBLISHED, "most_recent_published") \
  X(PRODUCTEXPOSURE_COLUMN_CVE_ID,                "cve_id")                \
  X(PRODUCTEXPOSURE_COLUMN_RISK_SCORE,            "risk_score")            \
  X(PRODUCTEXPOSURE_COLUMN_RISK_LABEL,            "risk_label")
enum { PRODUCTEXPOSURE_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const PRODUCTEXPOSURE_COLUMN_NAMES[] = { PRODUCTEXPOSURE_COLUMNS(DBHELPER_COLUMN_NAME) };

#define PRODUCTEXPOSURE_EOL_COLUMNS(X)                                       \
  X(PRODUCTEXPOSURE_EOL_COLUMN_ROW_KIND,               "row_kind")               \
  X(PRODUCTEXPOSURE_EOL_COLUMN_NAME,                   "name")                   \
  X(PRODUCTEXPOSURE_EOL_COLUMN_URL,                    "url")                    \
  X(PRODUCTEXPOSURE_EOL_COLUMN_EOL_DATE,               "eol_date")               \
  X(PRODUCTEXPOSURE_EOL_COLUMN_IS_EOL,                 "is_eol")                 \
  X(PRODUCTEXPOSURE_EOL_COLUMN_IS_MAINTAINED,          "is_maintained")          \
  X(PRODUCTEXPOSURE_EOL_COLUMN_IS_LTS,                 "is_lts")                 \
  X(PRODUCTEXPOSURE_EOL_COLUMN_LATEST_VERSION,         "latest_version")         \
  X(PRODUCTEXPOSURE_EOL_COLUMN_MAINTAINED_CYCLE_COUNT, "maintained_cycle_count")
enum { PRODUCTEXPOSURE_EOL_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const PRODUCTEXPOSURE_EOL_COLUMN_NAMES[] = { PRODUCTEXPOSURE_EOL_COLUMNS(DBHELPER_COLUMN_NAME) };

#define PRODUCTEXPOSURE_EOL_ROW_KIND_MAX_LEN 10

static const char*  static_int64Param                     (char* buf, size_t size, int64_t value);
static bool         static_tryWriteIdArray                (const BulkIdsParams_t* params, char* literal_out);
static bool         static_tryReadMatchCount              (PGconn* conn, const char* query, const char* column_name, int param_count, const char** param_values, int* match_count_out);
static DbStatus_t   static_CVESEARCHReadPage              (PGconn* conn, const char* query, int param_count, const char** param_values, CveListResult_t* results_out);
static bool         static_CVELOOKUPTryFillRecord         (PGresult* res, int row, CVELOOKUPRecord_t* rec);
static bool         static_CVELOOKUPTryReadSsvc           (PGresult* res, int row, CVELOOKUPRecord_t* rec);
static bool         static_KEVLOOKUPTryFillRecord         (PGresult* res, KEVLOOKUPRecord_t* rec);
static bool         static_CWELOOKUPTryFillRecord         (PGresult* res, CWELOOKUPRecord_t* rec);
static bool         static_CVESEARCHFillItem              (PGresult* res, int row_index, CveListItem_t* item);
static DbStatus_t   static_CVETRIAGEReadPage              (PGconn* conn, const char* query, int param_count, const char** param_values, CVETRIAGEResult_t* results_out);
static bool         static_PRODUCTEXPOSURETryReadEol      (PGresult* res, PRODUCTEXPOSUREEol_t* eol_out);
static bool         static_PRODUCTEXPOSURETryReadEolCycle (PGresult* res, int row, PRODUCTEXPOSUREEolCycle_t* cycle_out);
static bool         static_CVETRIAGEFillItem              (PGresult* res, int row_index, CVETRIAGEItem_t* item);
static bool         static_PRODUCTEXPOSUREFillTopItem     (PGresult* res, int row_index, CVETRIAGEItem_t* item);
static DbStatus_t   static_CPESEARCHReadPage              (PGconn* conn, const char* query, int param_count, const char** param_values, CPESEARCHResult_t* results_out);
static bool         static_CPESEARCHFillItem              (PGresult* res, int row_index, CPESEARCHItem_t* item);
static bool         static_D3FENDFORATTACKFillItem        (PGresult* res, int row_index, D3FENDFORATTACKItem_t* item);
static bool         static_DRIVERLOOKUPTryFillRecord      (PGresult* res, int row, DRIVERLOOKUPRecord_t* record);
static bool         static_IPLOOKUPTryFillRecord          (PGresult* res, IPLOOKUPRecord_t* record);
static bool         static_IPLOOKUPTryReadAsn             (PGresult* res, uint32_t* asn_out);
static bool         static_IPLOOKUPTryReadDatacenter      (PGresult* res, IPLOOKUPRecord_t* record);
static DbStatus_t   static_ASNLOOKUPReadPrefix            (PGconn* conn, const char* ip_address, char asn_text_out[DBHELPER_UINT_STR_BUF_SIZE], ASNLOOKUPRecord_t* record);
static bool         static_ASNLOOKUPTryParseAsn           (const char* asn_text, uint32_t* asn_out);
static bool         static_ASNLOOKUPTryFillRecord         (PGresult* res, ASNLOOKUPRecord_t* record);
static bool         static_EMAILADDRESSCHECKTryFillRecord (PGresult* res, const char* domain, EMAILADDRESSCHECKRecord_t* record);
static bool         static_EMAILADDRESSCHECKIsDomainUnder (const char* domain, const char* listed_domain);
static bool         static_SSLCHECKTryFillRecord          (PGresult* res, SSLCHECKRecord_t* record);
static bool         static_PACKAGECHECKTryFillResult      (PGresult* res, PACKAGECHECKResult_t* result);
static bool         static_tryReadKeyExpiry               (PGresult* res, DbApiKeyExpiry_t* expiry_out);
static bool         static_tryReadBillingEventStatus      (PGresult* res, DbBillingEventStatus_t* status_out);
static DbStatus_t   static_readBillingEventAnswer         (PGresult* res, bool is_column_list_equal, DbBillingEventStatus_t* status_out);
static bool         static_tryReadBillingClaimStatus      (PGresult* res, DbBillingClaimStatus_t* status_out);

PGconn* db_open(const char* conninfo)
{
  PGconn* conn = PQconnectdb(conninfo);
  if (PQstatus(conn) != CONNECTION_OK)
  {
    fprintf(stderr, "db_open: %s\n", PQerrorMessage(conn));
    PQfinish(conn);
    return NULL;
  }
  return conn;
}

void db_close(PGconn* conn)
{
  if (conn)
    PQfinish(conn);
}

DbStatus_t db_readSchemaVersion(PGconn* conn, int* version_out)
{
  assert(version_out != NULL);

  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_schema_version() AS schema_version",
                                        0,
                                        NULL);
  if (!res)
    return DB_ERROR;

  bool is_read = PQntuples(res) == 1
              && dbhelper_isColumnListEqual(res, DB_SCHEMA_VERSION_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_SCHEMA_VERSION_COLUMN_NAMES))
              && !PQgetisnull(res, 0, DB_SCHEMA_VERSION_COLUMN_SCHEMA_VERSION)
              && dbhelper_fetchColInt(res, 0, DB_SCHEMA_VERSION_COLUMN_SCHEMA_VERSION, 0, version_out);
  PQclear(res);
  return is_read ? DB_OK : DB_ERROR;
}

DbStatus_t db_readConnectionRoleState(PGconn* conn, DbConnectionRoleState_t* state_out)
{
  assert(state_out != NULL);

  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_connection_role_state()",
                                        0,
                                        NULL);
  if (!res)
    return DB_ERROR;

  bool is_read = PQntuples(res) == 1
              && dbhelper_isColumnListEqual(res, DB_CONNECTION_ROLE_STATE_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_CONNECTION_ROLE_STATE_COLUMN_NAMES))
              && dbhelper_fetchColBool(res, 0, DB_CONNECTION_ROLE_STATE_COLUMN_IS_SUPERUSER, &state_out->m_isSuperuser)
              && dbhelper_fetchColBool(res, 0, DB_CONNECTION_ROLE_STATE_COLUMN_IS_OWNER_MEMBER, &state_out->m_isOwnerMember);
  PQclear(res);
  return is_read ? DB_OK : DB_ERROR;
}

static bool static_tryReadKeyExpiry(PGresult* res, DbApiKeyExpiry_t* expiry_out)
{
  if (PQgetisnull(res, 0, DB_API_KEY_STATE_COLUMN_KEY_EXPIRES_AT))
  {
    expiry_out->m_hasExpiry = false;
    expiry_out->m_expiresAt = 0;
    return true;
  }
  if (PQgetlength(res, 0, DB_API_KEY_STATE_COLUMN_KEY_EXPIRES_AT) == 0)
    return false;

  expiry_out->m_hasExpiry = true;
  return dbhelper_fetchColInt64(res, 0, DB_API_KEY_STATE_COLUMN_KEY_EXPIRES_AT, 0, &expiry_out->m_expiresAt);
}

DbStatus_t db_readApiKeyState(PGconn* conn, const char* key_hash, DbApiKeyState_t* state_out, DbApiKeyExpiry_t* expiry_out)
{
  assert(key_hash != NULL);
  assert(state_out != NULL);
  assert(expiry_out != NULL);

  const char* param_values[] = { key_hash };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_api_key_state($1)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  char             state_text[DB_API_KEY_STATE_MAX_LEN + 1];
  DbApiKeyExpiry_t expiry  = { 0 };
  bool             is_read = PQntuples(res) == 1
                          && dbhelper_isColumnListEqual(res, DB_API_KEY_STATE_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_API_KEY_STATE_COLUMN_NAMES))
                          && dbhelper_fetchColStr(res, 0, DB_API_KEY_STATE_COLUMN_API_KEY_STATE, state_text, DB_API_KEY_STATE_MAX_LEN)
                          && static_tryReadKeyExpiry(res, &expiry);
  PQclear(res);
  if (!is_read)
    return DB_ERROR;

  DbApiKeyState_t state;
  if (strcmp(state_text, "active") == 0)
    state = DB_API_KEY_ACTIVE;
  else if (strcmp(state_text, "inactive") == 0)
    state = DB_API_KEY_INACTIVE;
  else if (strcmp(state_text, "unknown") == 0)
    state = DB_API_KEY_UNKNOWN;
  else
    return DB_ERROR;

  *state_out  = state;
  *expiry_out = expiry;
  return DB_OK;
}

static bool static_tryReadBillingEventStatus(PGresult* res, DbBillingEventStatus_t* status_out)
{
  char status_text[DB_BILLING_EVENT_STATUS_MAX_LEN + 1];
  if (PQntuples(res) != 1 || 
      !dbhelper_fetchColStr(res, 0, DB_BILLING_EVENT_STATUS_COLUMN_BILLING_EVENT_STATUS, status_text, DB_BILLING_EVENT_STATUS_MAX_LEN))
  {
    return false;
  }

  if (strcmp(status_text, "applied") == 0)
    *status_out = DB_BILLING_EVENT_APPLIED;
  else if (strcmp(status_text, "duplicate") == 0)
    *status_out = DB_BILLING_EVENT_DUPLICATE;
  else if (strcmp(status_text, "exists") == 0)
    *status_out = DB_BILLING_EVENT_EXISTS;
  else if (strcmp(status_text, "stale") == 0)
    *status_out = DB_BILLING_EVENT_STALE;
  else if (strcmp(status_text, "revoked") == 0)
    *status_out = DB_BILLING_EVENT_ORDER_REVOKED;
  else if (strcmp(status_text, "unknown") == 0)
    *status_out = DB_BILLING_EVENT_UNKNOWN_ORDER;
  else
    return false;

  return true;
}

static DbStatus_t static_readBillingEventAnswer(PGresult* res, bool is_column_list_equal, DbBillingEventStatus_t* status_out)
{
  DbBillingEventStatus_t status  = DB_BILLING_EVENT_APPLIED;
  bool                   is_read = is_column_list_equal && static_tryReadBillingEventStatus(res, &status);
  PQclear(res);
  if (!is_read)
    return DB_ERROR;

  *status_out = status;
  return DB_OK;
}

const char* db_billingEventStatusText(DbBillingEventStatus_t status)
{
  switch (status)
  {
    case DB_BILLING_EVENT_APPLIED:       return "applied";
    case DB_BILLING_EVENT_DUPLICATE:     return "duplicate";
    case DB_BILLING_EVENT_EXISTS:        return "exists";
    case DB_BILLING_EVENT_STALE:         return "stale";
    case DB_BILLING_EVENT_ORDER_REVOKED: return "revoked";
    case DB_BILLING_EVENT_UNKNOWN_ORDER: return "unknown";
  }
  return "";
}

static bool static_tryReadBillingClaimStatus(PGresult* res, DbBillingClaimStatus_t* status_out)
{
  char status_text[DB_BILLING_CLAIM_STATUS_MAX_LEN + 1];
  if (PQntuples(res) != 1 || !dbhelper_fetchColStr(res, 0, DB_BILLING_CLAIM_STATUS_COLUMN_BILLING_CLAIM_STATUS, status_text, DB_BILLING_CLAIM_STATUS_MAX_LEN))
    return false;

  if (strcmp(status_text, "claimed") == 0)
    *status_out = DB_BILLING_CLAIM_CLAIMED;
  else if (strcmp(status_text, "already_claimed") == 0)
    *status_out = DB_BILLING_CLAIM_ALREADY_CLAIMED;
  else if (strcmp(status_text, "lapsed") == 0)
    *status_out = DB_BILLING_CLAIM_LAPSED;
  else if (strcmp(status_text, "revoked") == 0)
    *status_out = DB_BILLING_CLAIM_REVOKED;
  else if (strcmp(status_text, "unknown") == 0)
    *status_out = DB_BILLING_CLAIM_UNKNOWN;
  else
    return false;
  
  return true;
}

DbStatus_t db_billingLemonSqueezyOrderPaid(PGconn* conn, const BillingLemonSqueezyEvent_t* event, DbBillingEventStatus_t* status_out)
{
  assert(event      != NULL);
  assert(status_out != NULL);

  const char* param_values[] = { event->ma_webhookId, event->ma_orderId, event->ma_providerOrderRef };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_billing_lemonsqueezy_order_paid($1, $2, $3) AS billing_event_status",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  bool is_column_list_equal = dbhelper_isColumnListEqual(res, DB_BILLING_EVENT_STATUS_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_BILLING_EVENT_STATUS_COLUMN_NAMES));
  return static_readBillingEventAnswer(res, is_column_list_equal, status_out);
}

DbStatus_t db_billingLemonSqueezySetExpiry(PGconn* conn, const BillingLemonSqueezyEvent_t* event, DbBillingEventStatus_t* status_out)
{
  assert(event      != NULL);
  assert(status_out != NULL);

  char updated_at_str[DB_INT64_PARAM_BUF_SIZE];
  char expires_at_str[DB_INT64_PARAM_BUF_SIZE];
  const char* param_values[] = {
    event->ma_webhookId,
    event->ma_providerOrderRef,
    event->ma_providerSubscriptionRef,
    static_int64Param(updated_at_str, sizeof(updated_at_str), event->m_providerUpdatedAt),
    static_int64Param(expires_at_str, sizeof(expires_at_str), event->m_endsAt),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_billing_lemonsqueezy_set_expiry($1, $2, $3, $4, $5) AS billing_event_status",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  bool is_column_list_equal = dbhelper_isColumnListEqual(res, DB_BILLING_EVENT_STATUS_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_BILLING_EVENT_STATUS_COLUMN_NAMES));
  return static_readBillingEventAnswer(res, is_column_list_equal, status_out);
}

DbStatus_t db_billingLemonSqueezyClearExpiry(PGconn* conn, const BillingLemonSqueezyEvent_t* event, DbBillingEventStatus_t* status_out)
{
  assert(event      != NULL);
  assert(status_out != NULL);

  char updated_at_str[DB_INT64_PARAM_BUF_SIZE];
  const char* param_values[] = {
    event->ma_webhookId,
    event->ma_providerOrderRef,
    event->ma_providerSubscriptionRef,
    static_int64Param(updated_at_str, sizeof(updated_at_str), event->m_providerUpdatedAt),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_billing_lemonsqueezy_clear_expiry($1, $2, $3, $4) AS billing_event_status",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  bool is_column_list_equal = dbhelper_isColumnListEqual(res, DB_BILLING_EVENT_STATUS_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_BILLING_EVENT_STATUS_COLUMN_NAMES));
  return static_readBillingEventAnswer(res, is_column_list_equal, status_out);
}

DbStatus_t db_billingLemonSqueezyRevoke(PGconn* conn, const BillingLemonSqueezyEvent_t* event, DbBillingEventStatus_t* status_out)
{
  assert(event               != NULL);
  assert(event->mp_eventName != NULL);
  assert(status_out          != NULL);

  const char* param_values[] = { event->ma_webhookId, event->mp_eventName, event->ma_providerOrderRef };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_billing_lemonsqueezy_revoke($1, $2, $3) AS billing_event_status",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  bool is_column_list_equal = dbhelper_isColumnListEqual(res, DB_BILLING_EVENT_STATUS_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_BILLING_EVENT_STATUS_COLUMN_NAMES));
  return static_readBillingEventAnswer(res, is_column_list_equal, status_out);
}

DbStatus_t db_billingLemonSqueezyEventRecord(PGconn* conn, const BillingLemonSqueezyEvent_t* event, DbBillingEventStatus_t* status_out)
{
  assert(event               != NULL);
  assert(event->mp_eventName != NULL);
  assert(status_out          != NULL);

  const char* param_values[] = {
    DB_BILLING_PROVIDER_LEMONSQUEEZY,
    event->ma_webhookId,
    event->mp_eventName,
    dbhelper_textOrNull(event->ma_providerOrderRef),
    dbhelper_textOrNull(event->ma_providerSubscriptionRef),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_billing_event_record($1, $2, $3, $4, $5) AS billing_event_status",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  bool is_column_list_equal = dbhelper_isColumnListEqual(res, DB_BILLING_EVENT_STATUS_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_BILLING_EVENT_STATUS_COLUMN_NAMES));
  return static_readBillingEventAnswer(res, is_column_list_equal, status_out);
}

DbStatus_t db_billingNowPaymentsOrderPaid(PGconn* conn, const char* event_ref, const char* event_name, const char* order_id, const char* order_ref, DbBillingEventStatus_t* status_out)
{
  assert(event_ref  != NULL);
  assert(event_name != NULL);
  assert(order_id   != NULL);
  assert(order_ref  != NULL);
  assert(status_out != NULL);

  const char* param_values[] = { event_ref, event_name, order_id, order_ref };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_billing_nowpayments_order_paid($1, $2, $3, $4) AS billing_event_status",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  bool is_column_list_equal = dbhelper_isColumnListEqual(res, DB_BILLING_EVENT_STATUS_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_BILLING_EVENT_STATUS_COLUMN_NAMES));
  return static_readBillingEventAnswer(res, is_column_list_equal, status_out);
}

DbStatus_t db_billingClaim(PGconn* conn, const char* order_id, const char* key_hash, DbBillingClaimStatus_t* status_out)
{
  assert(order_id   != NULL);
  assert(key_hash   != NULL);
  assert(status_out != NULL);

  const char* param_values[] = { order_id, key_hash };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_billing_claim($1, $2) AS billing_claim_status",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  DbBillingClaimStatus_t status  = DB_BILLING_CLAIM_CLAIMED;
  bool                   is_read = dbhelper_isColumnListEqual(res, DB_BILLING_CLAIM_STATUS_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_BILLING_CLAIM_STATUS_COLUMN_NAMES))
                                && static_tryReadBillingClaimStatus(res, &status);
  PQclear(res);
  if (!is_read)
    return DB_ERROR;

  *status_out = status;
  return DB_OK;
}

DbStatus_t db_readVendorKeys(PGconn* conn, const char* key_hash, DbVendorKeys_t* vendor_keys_out)
{
  assert(key_hash        != NULL);
  assert(vendor_keys_out != NULL);

  const char* param_values[] = { key_hash };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_vendor_key_read($1)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  DbVendorKeys_t vendor_keys = { 0 };
  bool           is_read     = PQntuples(res) == 1
                            && dbhelper_isColumnListEqual(res, DB_VENDOR_KEY_READ_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_VENDOR_KEY_READ_COLUMN_NAMES));
  if (is_read && !PQgetisnull(res, 0, DB_VENDOR_KEY_READ_COLUMN_API_KEY_ID))
  {
    int api_key_id = 0;
    is_read = dbhelper_fetchColInt(res, 0, DB_VENDOR_KEY_READ_COLUMN_API_KEY_ID, 0, &api_key_id)
           && api_key_id >= 1
           && dbhelper_fetchColStr(res, 0, DB_VENDOR_KEY_READ_COLUMN_KEY_FINGERPRINT, vendor_keys.ma_keyFingerprint, DB_VENDOR_KEY_FINGERPRINT_HEX_LEN)
           && strlen(vendor_keys.ma_keyFingerprint) == DB_VENDOR_KEY_FINGERPRINT_HEX_LEN
           && dbhelper_fetchColStr(res, 0, DB_VENDOR_KEY_READ_COLUMN_SHODAN_SEALED_HEX, vendor_keys.ma_shodanSealedHex, KEYVAULT_SEALED_HEX_MAX_LEN)
           && dbhelper_fetchColStr(res, 0, DB_VENDOR_KEY_READ_COLUMN_ABUSEIPDB_SEALED_HEX, vendor_keys.ma_abuseIpDbSealedHex, KEYVAULT_SEALED_HEX_MAX_LEN);
    vendor_keys.m_apiKeyId = api_key_id;
  }
  PQclear(res);
  if (!is_read)
    return DB_ERROR;

  *vendor_keys_out = vendor_keys;
  return DB_OK;
}

DbStatus_t db_openVendorKeyLink(PGconn* conn, int64_t api_key_id, const char* link_hash_hex, int64_t* link_expires_at_out)
{
  assert(link_hash_hex       != NULL);
  assert(link_expires_at_out != NULL);

  char        api_key_id_str[DB_INT64_PARAM_BUF_SIZE];
  char        lifetime_str[DBHELPER_INT_PARAM_BUF_SIZE];
  const char* param_values[] = {
    static_int64Param(api_key_id_str, sizeof(api_key_id_str), api_key_id),
    link_hash_hex,
    dbhelper_intParam(lifetime_str, sizeof(lifetime_str), DB_VENDOR_KEY_LINK_LIFETIME_SECONDS),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_vendor_key_link_open($1, $2, $3) AS link_expires_at",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  int64_t link_expires_at = 0;
  bool    is_shaped       = PQntuples(res) == 1
                         && dbhelper_isColumnListEqual(res, DB_VENDOR_KEY_LINK_OPEN_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_VENDOR_KEY_LINK_OPEN_COLUMN_NAMES));
  bool    is_null         = is_shaped && PQgetisnull(res, 0, DB_VENDOR_KEY_LINK_OPEN_COLUMN_LINK_EXPIRES_AT);
  bool    is_read         = is_shaped && !is_null
                         && dbhelper_fetchColInt64(res, 0, DB_VENDOR_KEY_LINK_OPEN_COLUMN_LINK_EXPIRES_AT, 0, &link_expires_at)
                         && link_expires_at >= 1;
  PQclear(res);
  if (is_null)
    return DB_NOT_FOUND;
  if (!is_read)
    return DB_ERROR;

  *link_expires_at_out = link_expires_at;
  return DB_OK;
}

DbStatus_t db_readVendorKeyLink(PGconn* conn, const char* link_hash_hex, DbVendorKeyLink_t* vendor_key_link_out)
{
  assert(link_hash_hex       != NULL);
  assert(vendor_key_link_out != NULL);

  const char* param_values[] = { link_hash_hex };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_vendor_key_link_read($1)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  char              state_text[DB_VENDOR_KEY_STATE_MAX_LEN + 1];
  DbVendorKeyLink_t vendor_key_link = { 0 };
  bool              is_read         = PQntuples(res) == 1
                                   && dbhelper_isColumnListEqual(res, DB_VENDOR_KEY_LINK_READ_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_VENDOR_KEY_LINK_READ_COLUMN_NAMES))
                                   && dbhelper_fetchColStr(res, 0, DB_VENDOR_KEY_LINK_READ_COLUMN_LINK_STATE, state_text, DB_VENDOR_KEY_STATE_MAX_LEN);
  bool              is_open         = is_read && strcmp(state_text, "open") == 0;
  if (is_open)
  {
    int api_key_id = 0;
    is_read = dbhelper_fetchColInt(res, 0, DB_VENDOR_KEY_LINK_READ_COLUMN_API_KEY_ID, 0, &api_key_id)
           && api_key_id >= 1
           && dbhelper_fetchColInt64(res, 0, DB_VENDOR_KEY_LINK_READ_COLUMN_LINK_EXPIRES_AT, 0, &vendor_key_link.m_linkExpiresAt)
           && vendor_key_link.m_linkExpiresAt >= 1
           && dbhelper_fetchColStr(res, 0, DB_VENDOR_KEY_LINK_READ_COLUMN_SHODAN_SEALED_HEX, vendor_key_link.ma_shodanSealedHex, KEYVAULT_SEALED_HEX_MAX_LEN)
           && dbhelper_fetchColStr(res, 0, DB_VENDOR_KEY_LINK_READ_COLUMN_ABUSEIPDB_SEALED_HEX, vendor_key_link.ma_abuseIpDbSealedHex, KEYVAULT_SEALED_HEX_MAX_LEN);
    vendor_key_link.m_apiKeyId = api_key_id;
  }
  PQclear(res);
  if (!is_read)
    return DB_ERROR;

  if (is_open)
    vendor_key_link.m_linkState = DB_VENDOR_KEY_LINK_OPEN;
  else if (strcmp(state_text, "expired") == 0)
    vendor_key_link.m_linkState = DB_VENDOR_KEY_LINK_EXPIRED;
  else if (strcmp(state_text, "invalid") == 0)
    vendor_key_link.m_linkState = DB_VENDOR_KEY_LINK_INVALID;
  else
    return DB_ERROR;

  *vendor_key_link_out = vendor_key_link;
  return DB_OK;
}

DbStatus_t db_applyVendorKeys(PGconn* conn, const DbVendorKeyChange_t* change, DbVendorKeyApplyStatus_t* apply_status_out)
{
  assert(change           != NULL);
  assert(apply_status_out != NULL);

  char        api_key_id_str[DB_INT64_PARAM_BUF_SIZE];
  const char* param_values[] = {
    static_int64Param(api_key_id_str, sizeof(api_key_id_str), change->m_apiKeyId),
    change->mp_linkHash,
    change->mp_keyFingerprint,
    change->m_isLinkSpent ? "true" : "false",
    change->mp_shodanSealedHex,
    change->m_isShodanDeleted ? "true" : "false",
    change->mp_abuseIpDbSealedHex,
    change->m_isAbuseIpDbDeleted ? "true" : "false",
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_vendor_key_apply($1, $2, $3, $4, $5, $6, $7, $8) AS vendor_key_apply_status",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  char status_text[DB_VENDOR_KEY_STATE_MAX_LEN + 1];
  bool is_read = PQntuples(res) == 1
              && dbhelper_isColumnListEqual(res, DB_VENDOR_KEY_APPLY_STATUS_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DB_VENDOR_KEY_APPLY_STATUS_COLUMN_NAMES))
              && dbhelper_fetchColStr(res, 0, DB_VENDOR_KEY_APPLY_STATUS_COLUMN_VENDOR_KEY_APPLY_STATUS, status_text, DB_VENDOR_KEY_STATE_MAX_LEN);
  PQclear(res);
  if (!is_read)
    return DB_ERROR;

  if (strcmp(status_text, "applied") == 0)
    *apply_status_out = DB_VENDOR_KEY_APPLY_APPLIED;
  else if (strcmp(status_text, "expired") == 0)
    *apply_status_out = DB_VENDOR_KEY_APPLY_EXPIRED;
  else if (strcmp(status_text, "invalid") == 0)
    *apply_status_out = DB_VENDOR_KEY_APPLY_INVALID;
  else if (strcmp(status_text, "inactive") == 0)
    *apply_status_out = DB_VENDOR_KEY_APPLY_INACTIVE;
  else
    return DB_ERROR;

  return DB_OK;
}

bool db_purgeExpiredVendorKeys(PGconn* conn)
{
  assert(conn != NULL);

  return dbhelper_runPurgeLoop(conn,
                               "SELECT api.fn_vendor_key_purge($1) AS purged_key_count",
                               "purged_key_count",
                               DB_VENDOR_KEY_PURGE_BATCH_KEY_COUNT);
}

bool db_purgeExpiredVendorKeyLinks(PGconn* conn)
{
  assert(conn != NULL);

  return dbhelper_runPurgeLoop(conn,
                               "SELECT api.fn_vendor_key_link_purge($1) AS purged_link_count",
                               "purged_link_count",
                               DB_VENDOR_KEY_LINK_PURGE_BATCH_ROW_COUNT);
}

bool db_purgeExpiredBillingEvents(PGconn* conn)
{
  assert(conn != NULL);

  return dbhelper_runPurgeLoop(conn,
                               "SELECT api.fn_billing_event_purge($1) AS purged_event_count",
                               "purged_event_count",
                               DB_BILLING_EVENT_PURGE_BATCH_EVENT_COUNT);
}

DbStatus_t db_HEALTH(PGconn* conn, HEALTHData_t* result_out)
{
  memset(result_out, 0, sizeof(*result_out));

  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_health()",
                                        0,
                                        NULL);
  if (!res) 
    return DB_ERROR;
  bool is_read = PQntuples(res) == 1
              && dbhelper_isColumnListEqual(res, HEALTH_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(HEALTH_COLUMN_NAMES))
              && dbhelper_fetchColInt(res, 0, HEALTH_COLUMN_CVE_COUNT,               0, &result_out->m_cveCount)
              && dbhelper_fetchColStr(res, 0, HEALTH_COLUMN_NVD_LAST_CVE_ID,         result_out->ma_nvdLastCveId, CVELOOKUP_ID_MAX_LEN)
              && dbhelper_fetchColStr(res, 0, HEALTH_COLUMN_NVD_LAST_PUBLISHED_TIME, result_out->ma_nvdLastPublishedTime, CVELOOKUP_PUBLISHED_LEN)
              && dbhelper_fetchColInt(res, 0, HEALTH_COLUMN_KEV_COUNT,               0, &result_out->m_kevCount)
              && dbhelper_fetchColStr(res, 0, HEALTH_COLUMN_KEV_LAST_CVE_ID,         result_out->ma_kevLastCveId, CVELOOKUP_ID_MAX_LEN)
              && dbhelper_fetchColStr(res, 0, HEALTH_COLUMN_KEV_LAST_DATE_ADDED,     result_out->ma_kevLastDateAdded, CVELOOKUP_PUBLISHED_LEN)
              && dbhelper_fetchColInt(res, 0, HEALTH_COLUMN_CWE_COUNT,               0, &result_out->m_cweCount)
              && dbhelper_fetchColStr(res, 0, HEALTH_COLUMN_CWE_LAST_ID,             result_out->ma_cweLastId, CWELOOKUP_ID_MAX_LEN)
              && dbhelper_fetchColStr(res, 0, HEALTH_COLUMN_CWE_LAST_UPDATED_AT,     result_out->ma_cweLastUpdatedAt, CWELOOKUP_UPDATED_AT_LEN);
  PQclear(res);
  if (!is_read) 
    return DB_ERROR;

  const char* feed_param_values[] = { MACRO_STR(HEALTH_MAX_FEEDS) };
  res = dbhelper_executeQuery(conn,
                              "SELECT * FROM api.fn_upstream_feed_status($1)",
                              DBHELPER_PARAM_COUNT(feed_param_values),
                              feed_param_values);
  if (!res) 
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, HEALTH_FEED_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(HEALTH_FEED_COLUMN_NAMES)))
  {
    PQclear(res);
    return DB_ERROR;
  }

  int feed_row_count = PQntuples(res);
  for (int row = 0; row < feed_row_count && result_out->m_feedCount < HEALTH_MAX_FEEDS; row++)
  {
    HEALTHFeed_t feed;
    if (dbhelper_fetchColStr(res, row, HEALTH_FEED_COLUMN_FEED_NAME,       feed.ma_name,       HEALTH_FEED_NAME_LEN)        &&
        dbhelper_fetchColStr(res, row, HEALTH_FEED_COLUMN_LAST_SYNCED,     feed.ma_lastSynced, HEALTH_FEED_LAST_SYNCED_LEN) &&
        dbhelper_fetchColStr(res, row, HEALTH_FEED_COLUMN_LAST_STATUS,     feed.ma_lastStatus, HEALTH_FEED_LAST_STATUS_LEN) &&
        dbhelper_fetchColInt(res, row, HEALTH_FEED_COLUMN_RECORDS_UPDATED, 0, &feed.m_recordsUpdated))
      result_out->ma_feeds[result_out->m_feedCount++] = feed;
  }
  PQclear(res);

  return DB_OK;
}

DbStatus_t db_CVELOOKUP(PGconn* conn, const char* cve_id, CVELOOKUPRecord_t* record_out)
{
  record_out->mp_cwes                 = NULL;
  record_out->mp_cveTags              = NULL;
  record_out->mp_affectedProducts     = NULL;
  record_out->mp_productCountByVendor = NULL;
  record_out->mp_refs                 = NULL;
  record_out->mp_epssTrend            = NULL;
  record_out->mp_nucleiTemplates      = NULL;
  record_out->mp_ghsa                 = NULL;

  const char* param_values[] = {
    cve_id,
    MACRO_STR(CVELOOKUP_EPSS_TREND_MAX_ROWS),
    MACRO_STR(CVELOOKUP_NUCLEI_TEMPLATE_MAX_ROWS),
    MACRO_STR(CVELOOKUP_PRODUCT_MAX_ROWS),
    MACRO_STR(CVELOOKUP_VENDOR_MAX_ROWS),
    MACRO_STR(CVELOOKUP_REF_MAX_ROWS),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_cve_lookup(ARRAY[$1], $2, $3, $4, $5, $6)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res) 
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, CVELOOKUP_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(CVELOOKUP_COLUMN_NAMES)))
  {
    PQclear(res);
    return DB_ERROR;
  }

  if (PQntuples(res) == 0)
  {
    PQclear(res);
    return DB_NOT_FOUND;
  }

  if (!static_CVELOOKUPTryFillRecord(res, 0, record_out))
  {
    PQclear(res);
    return DB_ERROR;
  }

  PQclear(res);
  return DB_OK;
}

void db_CVELOOKUPRecordFree(CVELOOKUPRecord_t * record)
{
  if (!record) return;
  free(record->mp_cwes);
  free(record->mp_cveTags);
  free(record->mp_affectedProducts);
  free(record->mp_productCountByVendor);
  free(record->mp_refs);
  free(record->mp_epssTrend);
  free(record->mp_nucleiTemplates);
  free(record->mp_ghsa);
  record->mp_cwes                 = NULL;
  record->mp_cveTags              = NULL;
  record->mp_affectedProducts     = NULL;
  record->mp_productCountByVendor = NULL;
  record->mp_refs                 = NULL;
  record->mp_epssTrend            = NULL;
  record->mp_nucleiTemplates      = NULL;
  record->mp_ghsa                 = NULL;
}

DbStatus_t db_CVELOOKUPGHSA(PGconn* conn, const char* cve_id, CVELOOKUPRecord_t* record)
{
  assert(record->mp_ghsa == NULL);

  const char* param_values[] = {
    cve_id,
    MACRO_STR(CVELOOKUP_GHSA_PACKAGE_MAX_ROWS),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_cve_ghsa_advisory($1, $2)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, CVELOOKUPGHSA_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(CVELOOKUPGHSA_COLUMN_NAMES)) ||
      PQntuples(res) != 1)
  {
    PQclear(res);
    return DB_ERROR;
  }

  bool is_read = dbhelper_fetchColBool     (res, 0, CVELOOKUPGHSA_COLUMN_GHSA_FEED_LOADED, &record->m_isGhsaFeedLoaded) &&
                 dbhelper_isColWithinLength(res, 0, CVELOOKUPGHSA_COLUMN_ADVISORY, CVELOOKUP_GHSA_MAX_LEN)          &&
                 dbhelper_fetchColStrdup   (res, 0, CVELOOKUPGHSA_COLUMN_ADVISORY, &record->mp_ghsa);
  PQclear(res);

  return is_read ? DB_OK : DB_ERROR;
}

DbStatus_t db_CVELOOKUPBULK(PGconn* conn, const BulkIdsParams_t* params, CVELOOKUPBULKResult_t* results_out)
{
  results_out->m_successful = 0;
  results_out->m_failed     = 0;
  results_out->mp_items     = NULL;

  char cve_id_array[DB_ID_ARRAY_PARAM_BUF_SIZE];
  if (!static_tryWriteIdArray(params, cve_id_array))
    return DB_ERROR;

  const char* param_values[] = {
    cve_id_array,
    MACRO_STR(CVELOOKUP_EPSS_TREND_MAX_ROWS),
    MACRO_STR(CVELOOKUP_NUCLEI_TEMPLATE_MAX_ROWS),
    MACRO_STR(CVELOOKUP_PRODUCT_MAX_ROWS),
    MACRO_STR(CVELOOKUP_VENDOR_MAX_ROWS),
    MACRO_STR(CVELOOKUP_REF_MAX_ROWS),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_cve_lookup($1, $2, $3, $4, $5, $6)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  int row_count = PQntuples(res);
  if (!dbhelper_isColumnListEqual(res, CVELOOKUP_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(CVELOOKUP_COLUMN_NAMES)) ||
      row_count > params->m_idCount)
  {
    PQclear(res);
    return DB_ERROR;
  }

  int successful = 0;
  if (row_count > 0)
  {
    results_out->mp_items = calloc((size_t)row_count, sizeof(CVELOOKUPRecord_t));
    if (!results_out->mp_items)
    {
      PQclear(res);
      return DB_ERROR;
    }
    for (int row_index = 0; row_index < row_count; row_index++)
    {
      if (static_CVELOOKUPTryFillRecord(res, row_index, &results_out->mp_items[successful]))
        successful++;
    }
  }
  PQclear(res);

  results_out->m_successful = successful;
  results_out->m_failed     = params->m_idCount - successful;
  return DB_OK;
}

void db_CVELOOKUPBULKResultFree(CVELOOKUPBULKResult_t* results)
{
  if (!results || !results->mp_items) 
    return;

  for (int i = 0; i < results->m_successful; i++)
    db_CVELOOKUPRecordFree(&results->mp_items[i]);

  free(results->mp_items);
  results->mp_items = NULL;
}

DbStatus_t db_CVEPRODUCTS(PGconn* conn, const CVEPRODUCTSParams_t* params, CVEPRODUCTSResult_t* result_out)
{
  result_out->m_affectedProductCount = 0;
  result_out->m_listedProductCount   = 0;
  result_out->mp_affectedProducts    = NULL;

  char row_count[DBHELPER_INT_PARAM_BUF_SIZE];
  char row_offset[DBHELPER_INT_PARAM_BUF_SIZE];

  const char* param_values[] = {
    params->ma_cveId,
    dbhelper_textOrNull(params->ma_vendor),
    dbhelper_textOrNull(params->ma_product),
    dbhelper_intParam(row_count,  sizeof(row_count),  params->m_limit),
    dbhelper_intParam(row_offset, sizeof(row_offset), params->m_offset),
  };

  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_cve_products($1, $2, $3, $4, $5)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, CVEPRODUCTS_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(CVEPRODUCTS_COLUMN_NAMES)) ||
      PQntuples(res) > 1)
  {
    PQclear(res);
    return DB_ERROR;
  }

  if (PQntuples(res) == 0)
  {
    PQclear(res);
    return DB_NOT_FOUND;
  }

  bool is_read = dbhelper_fetchColInt   (res, 0, CVEPRODUCTS_COLUMN_AFFECTED_PRODUCT_COUNT, 0, &result_out->m_affectedProductCount) &&
                 dbhelper_fetchColInt   (res, 0, CVEPRODUCTS_COLUMN_LISTED_PRODUCT_COUNT,   0, &result_out->m_listedProductCount)   &&
                 dbhelper_fetchColStrdup(res, 0, CVEPRODUCTS_COLUMN_AFFECTED_PRODUCTS, &result_out->mp_affectedProducts);
  PQclear(res);

  if (!is_read)
  {
    db_CVEPRODUCTSResultFree(result_out);
    return DB_ERROR;
  }

  return DB_OK;
}

void db_CVEPRODUCTSResultFree(CVEPRODUCTSResult_t* result)
{
  if (!result)
    return;
  free(result->mp_affectedProducts);
  result->mp_affectedProducts = NULL;
}

DbStatus_t db_CVESEARCH(PGconn* conn, const CVESEARCHParams_t* params, CveListResult_t* results_out)
{
  results_out->m_total  = 0;
  results_out->m_count  = 0;
  results_out->mp_items = NULL;

  char min_cvss[DBHELPER_NUMERIC_PARAM_BUF_SIZE];
  char min_epss[DBHELPER_NUMERIC_PARAM_BUF_SIZE];
  char row_count[DBHELPER_INT_PARAM_BUF_SIZE];
  char row_offset[DBHELPER_INT_PARAM_BUF_SIZE];

  const char* param_values[] = {
    dbhelper_textOrNull(params->ma_severity),
    dbhelper_numberOrNull(min_cvss, sizeof(min_cvss), 2, params->m_minCvss),
    dbhelper_numberOrNull(min_epss, sizeof(min_epss), 6, params->m_minEpss),
    dbhelper_kevFilterValue(params->m_kevFilter),
    params->m_knownRansomware ? "true" : NULL,
    dbhelper_textOrNull(params->ma_cweId),
    dbhelper_textOrNull(params->ma_publishedAfter),
    dbhelper_textOrNull(params->ma_publishedBefore),
    dbhelper_textOrNull(params->ma_vendor),
    dbhelper_textOrNull(params->ma_product),
    params->m_hasNucleiTemplate ? "true" : NULL,
    params->m_isRejectedIncluded ? "true" : "false",
    dbhelper_textOrNull(params->ma_sort),
    dbhelper_intParam(row_count,  sizeof(row_count),  params->m_limit),
    dbhelper_intParam(row_offset, sizeof(row_offset), params->m_offset),
  };

  if (!static_tryReadMatchCount(conn, "SELECT api.fn_cve_search_match_count($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) AS cve_count",
                                "cve_count", DB_CVESEARCH_FILTER_COUNT, param_values, &results_out->m_total))
  {
    return DB_ERROR;
  }
  if (params->m_offset >= results_out->m_total)
    return DB_OK;
  return static_CVESEARCHReadPage(conn, "SELECT * FROM api.fn_cve_search($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
                                  DBHELPER_PARAM_COUNT(param_values), param_values, results_out);
}

void db_CveListResultFree(CveListResult_t* rec)
{
  if (!rec) return;
  free(rec->mp_items);
  rec->mp_items = NULL;
}

DbStatus_t db_CVELEADING(PGconn* conn, const CVELEADINGParams_t* params, CveListResult_t* results_out)
{
  results_out->m_total  = 0;
  results_out->m_count  = 0;
  results_out->mp_items = NULL;

  char min_epss[DBHELPER_NUMERIC_PARAM_BUF_SIZE];
  char row_count[DBHELPER_INT_PARAM_BUF_SIZE];

  const char* param_values[] = {
    dbhelper_numberOrNull(min_epss, sizeof(min_epss), 6, params->m_minEpss),
    dbhelper_kevFilterValue(params->m_kevFilter),
    params->m_knownRansomware ? "true" : NULL,
    dbhelper_textOrNull(params->ma_vendor),
    dbhelper_textOrNull(params->ma_product),
    params->m_hasNucleiTemplate ? "true" : NULL,
    params->m_isRejectedIncluded ? "true" : "false",
    dbhelper_intParam(row_count, sizeof(row_count), params->m_limit),
  };

  if (!static_tryReadMatchCount(conn, "SELECT api.fn_cve_leading_match_count($1, $2, $3, $4, $5, $6, $7) AS cve_count",
                                "cve_count", DB_CVELEADING_FILTER_COUNT, param_values, &results_out->m_total))
  {
    return DB_ERROR;
  }

  return static_CVESEARCHReadPage(conn, "SELECT * FROM api.fn_cve_leading($1, $2, $3, $4, $5, $6, $7, $8)",
                                  DBHELPER_PARAM_COUNT(param_values), param_values, results_out);
}

DbStatus_t db_KEVLOOKUP(PGconn* conn, const char* cve_id, KEVLOOKUPRecord_t* record_out)
{
  record_out->mp_cwes  = NULL;
  record_out->mp_notes = NULL;

  const char* param_values[] = { cve_id };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_kev_lookup($1)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res) 
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, KEVLOOKUP_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(KEVLOOKUP_COLUMN_NAMES)))
  {
    PQclear(res);
    return DB_ERROR;
  }
  if (PQntuples(res) == 0)
  {
    PQclear(res);
    return DB_NOT_FOUND;
  }

  if (!static_KEVLOOKUPTryFillRecord(res, record_out))
  {
    PQclear(res);
    return DB_ERROR;
  }

  PQclear(res);
  return DB_OK;
}

void db_KEVLOOKUPRecordFree(KEVLOOKUPRecord_t* rec)
{
  if (!rec)
    return;
  free(rec->mp_cwes);
  free(rec->mp_notes);
  rec->mp_cwes  = NULL;
  rec->mp_notes = NULL;
}

DbStatus_t db_CWELOOKUP(PGconn* conn, const char* cwe_id, CWELOOKUPRecord_t* record_out)
{
  record_out->mp_mitigations         = NULL;
  record_out->mp_extendedDescription = NULL;
  record_out->mp_examples            = NULL;

  const char* param_values[] = { cwe_id };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_cwe_lookup($1)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res) 
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, CWELOOKUP_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(CWELOOKUP_COLUMN_NAMES)))
  {
    PQclear(res);
    return DB_ERROR;
  }
  if (PQntuples(res) == 0)
  {
    PQclear(res);
    return DB_NOT_FOUND;
  }

  if (!static_CWELOOKUPTryFillRecord(res, record_out))
  {
    PQclear(res);
    return DB_ERROR;
  }

  PQclear(res);
  return DB_OK;
}

void db_CWELOOKUPRecordFree(CWELOOKUPRecord_t* rec)
{
  if (!rec) return;
  free(rec->mp_mitigations);
  free(rec->mp_extendedDescription);
  free(rec->mp_examples);
  rec->mp_mitigations         = NULL;
  rec->mp_extendedDescription = NULL;
  rec->mp_examples            = NULL;
}

DbStatus_t db_CVERISKSCORE(PGconn* conn, const char* cve_id, CVERISKSCORERecord_t* record_out)
{
  memset(record_out, 0, sizeof(*record_out));

  const char* param_values[] = { cve_id };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_cve_risk_breakdown($1)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res) 
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, CVERISKSCORE_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(CVERISKSCORE_COLUMN_NAMES)))
  {
    PQclear(res);
    return DB_ERROR;
  }

  if (PQntuples(res) == 0)
  {
    PQclear(res);
    return DB_NOT_FOUND;
  }

  if (!dbhelper_fetchColDouble(res, 0, CVERISKSCORE_COLUMN_RISK_SCORE,     0.0, &record_out->m_score)                   ||
      !dbhelper_fetchColDouble(res, 0, CVERISKSCORE_COLUMN_EXPLOITABILITY, 0.0, &record_out->m_exploitabilityComponent) ||
      !dbhelper_fetchColDouble(res, 0, CVERISKSCORE_COLUMN_IMPACT,         0.0, &record_out->m_impactComponent)         ||
      !dbhelper_fetchColDouble(res, 0, CVERISKSCORE_COLUMN_EVIDENCE,       0.0, &record_out->m_evidenceComponent)       ||
      !dbhelper_fetchColBool  (res, 0, CVERISKSCORE_COLUMN_HAS_PUBLIC_POC, &record_out->m_hasPublicPoc)                 ||
      !dbhelper_fetchColStr   (res, 0, CVERISKSCORE_COLUMN_RISK_LABEL,     record_out->ma_label, CVERISKSCORE_LABEL_LEN))
  {
    PQclear(res);
    return DB_ERROR;
  }
  PQclear(res);
  return DB_OK;
}

DbStatus_t db_CVETRIAGE(PGconn* conn, const CVETRIAGEParams_t* params, CVETRIAGEResult_t* results_out)
{
  results_out->m_total  = 0;
  results_out->m_count  = 0;
  results_out->mp_items = NULL;

  char min_risk_score[DBHELPER_NUMERIC_PARAM_BUF_SIZE];
  char row_count[DBHELPER_INT_PARAM_BUF_SIZE];
  char row_offset[DBHELPER_INT_PARAM_BUF_SIZE];

  const char* param_values[] = {
    dbhelper_textOrNull(params->ma_vendor),
    dbhelper_textOrNull(params->ma_product),
    dbhelper_numberOrNull(min_risk_score, sizeof(min_risk_score), 4, params->m_minRiskScore),
    params->m_isRejectedIncluded ? "true" : "false",
    dbhelper_intParam(row_count,  sizeof(row_count),  params->m_limit),
    dbhelper_intParam(row_offset, sizeof(row_offset), params->m_offset),
  };
  if (!static_tryReadMatchCount(conn, "SELECT api.fn_cve_triage_match_count($1, $2, $3, $4) AS cve_count",
                                "cve_count", DB_CVETRIAGE_FILTER_COUNT, param_values, &results_out->m_total))
  {
    return DB_ERROR;
  }
  if (params->m_offset >= results_out->m_total)
    return DB_OK;
  return static_CVETRIAGEReadPage(conn, "SELECT * FROM api.fn_cve_triage($1, $2, $3, $4, $5, $6)",
                                  DBHELPER_PARAM_COUNT(param_values), param_values, results_out);
}

DbStatus_t db_CVETRIAGEBULK(PGconn* conn, const BulkIdsParams_t* params, CVETRIAGEBULKResult_t* results_out)
{
  results_out->m_successful = 0;
  results_out->m_failed     = 0;
  results_out->mp_items     = NULL;

  char cve_id_array[DB_ID_ARRAY_PARAM_BUF_SIZE];
  if (!static_tryWriteIdArray(params, cve_id_array))
    return DB_ERROR;

  const char* param_values[] = { cve_id_array };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_cve_triage_bulk($1)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res) 
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, CVETRIAGE_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(CVETRIAGE_COLUMN_NAMES)))
  {
    PQclear(res);
    return DB_ERROR;
  }

  int row_count = PQntuples(res);
  if (row_count > params->m_idCount)
  {
    PQclear(res);
    return DB_ERROR;
  }

  int successful = 0;
  if (row_count > 0)
  {
    results_out->mp_items = malloc((size_t)row_count * sizeof(CVETRIAGEItem_t));
    if (!results_out->mp_items)
    {
      PQclear(res);
      return DB_ERROR;
    }
    for (int row_index = 0; row_index < row_count; row_index++)
    {
      if (static_CVETRIAGEFillItem(res, row_index, &results_out->mp_items[successful]))
        successful++;
    }
  }
  PQclear(res);

  results_out->m_successful = successful;
  results_out->m_failed     = params->m_idCount - successful;
  return DB_OK;
}

void db_CVETRIAGEResultFree(CVETRIAGEResult_t* results)
{
  if (!results) 
    return;
  free(results->mp_items);
  results->mp_items = NULL;
}

void db_CVETRIAGEBULKResultFree(CVETRIAGEBULKResult_t* results)
{
  if (!results) 
    return;
  free(results->mp_items);
  results->mp_items = NULL;
}

DbStatus_t db_PRODUCTEXPOSURE(PGconn* conn, const PRODUCTEXPOSUREParams_t* params, PRODUCTEXPOSURERecord_t* record_out)
{
  memset(record_out, 0, sizeof(*record_out));
  snprintf(record_out->ma_vendor,  sizeof(record_out->ma_vendor),  "%s", params->ma_vendor);
  snprintf(record_out->ma_product, sizeof(record_out->ma_product), "%s", params->ma_product);

  const char* vendor           = params->ma_vendor;
  const char* product          = params->ma_product;
  const char* include_rejected = params->m_isRejectedIncluded ? "true" : "false";
  const char* exposure_param_values[] = { vendor, product, include_rejected, MACRO_STR(PRODUCTEXPOSURE_TOP_N) };
  const char* eol_param_values[]      = { vendor, product, dbhelper_textOrNull(params->ma_version), MACRO_STR(PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX) };

  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_product_exposure($1, $2, $3, $4)",
                                        DBHELPER_PARAM_COUNT(exposure_param_values),
                                        exposure_param_values);
  if (!res) return DB_ERROR;
  if (!dbhelper_isColumnListEqual(res, PRODUCTEXPOSURE_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(PRODUCTEXPOSURE_COLUMN_NAMES)))
  {
    PQclear(res);
    return DB_ERROR;
  }

  int row_count = PQntuples(res);
  if (row_count > 0 &&
      (!dbhelper_fetchColInt   (res, 0, PRODUCTEXPOSURE_COLUMN_CVE_COUNT,        0,   &record_out->m_totalCveCount)  ||
       !dbhelper_fetchColInt   (res, 0, PRODUCTEXPOSURE_COLUMN_CRITICAL_COUNT,   0,   &record_out->m_criticalCount)  ||
       !dbhelper_fetchColInt   (res, 0, PRODUCTEXPOSURE_COLUMN_HIGH_COUNT,       0,   &record_out->m_highCount)      ||
       !dbhelper_fetchColInt   (res, 0, PRODUCTEXPOSURE_COLUMN_MEDIUM_COUNT,     0,   &record_out->m_mediumCount)    ||
       !dbhelper_fetchColInt   (res, 0, PRODUCTEXPOSURE_COLUMN_LOW_COUNT,        0,   &record_out->m_lowCount)       ||
       !dbhelper_fetchColInt   (res, 0, PRODUCTEXPOSURE_COLUMN_KEV_COUNT,        0,   &record_out->m_kevCount)       ||
       !dbhelper_fetchColDouble(res, 0, PRODUCTEXPOSURE_COLUMN_MAX_CVSS,         0.0, &record_out->m_maxCvss)        ||
       !dbhelper_fetchColDouble(res, 0, PRODUCTEXPOSURE_COLUMN_AVG_CVSS,         0.0, &record_out->m_avgCvss)        ||
       !dbhelper_fetchColDouble(res, 0, PRODUCTEXPOSURE_COLUMN_MAX_EPSS,         0.0, &record_out->m_maxEpss)        ||
       !dbhelper_fetchColInt   (res, 0, PRODUCTEXPOSURE_COLUMN_POC_BACKED_COUNT, 0,   &record_out->m_pocBackedCount) ||
       !dbhelper_fetchColDouble(res, 0, PRODUCTEXPOSURE_COLUMN_WORST_RISK_SCORE, 0.0, &record_out->m_worstRiskScore) ||
       !dbhelper_fetchColStr(res, 0, PRODUCTEXPOSURE_COLUMN_MOST_RECENT_PUBLISHED, record_out->ma_mostRecentPublished, CVELOOKUP_PUBLISHED_LEN)))
  {
    PQclear(res);
    return DB_ERROR;
  }

  bool is_summary_only = row_count == 1 && PQgetisnull(res, 0, PRODUCTEXPOSURE_COLUMN_CVE_ID);
  int  top_cve_count   = 0;
  if (!is_summary_only)
    top_cve_count = row_count < PRODUCTEXPOSURE_TOP_N ? row_count : PRODUCTEXPOSURE_TOP_N;
  for (int row_index = 0; row_index < top_cve_count; row_index++)
  {
    if (!static_PRODUCTEXPOSUREFillTopItem(res, row_index, &record_out->ma_topCves[row_index]))
    {
      PQclear(res);
      return DB_ERROR;
    }
  }
  record_out->m_topCveCount = top_cve_count;
  PQclear(res);

  res = dbhelper_executeQuery(conn,
                              "SELECT * FROM api.fn_product_exposure_eol($1, $2, $3, $4)",
                              DBHELPER_PARAM_COUNT(eol_param_values),
                              eol_param_values);
  if (!res)
    return DB_ERROR;

  bool is_eol_read = dbhelper_isColumnListEqual(res, PRODUCTEXPOSURE_EOL_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(PRODUCTEXPOSURE_EOL_COLUMN_NAMES)) &&
                     static_PRODUCTEXPOSURETryReadEol(res, &record_out->m_eol);
  PQclear(res);
  return is_eol_read ? DB_OK : DB_ERROR;
}

static bool static_PRODUCTEXPOSURETryReadEol(PGresult* res, PRODUCTEXPOSUREEol_t* eol_out)
{
  int row_count = PQntuples(res);
  for (int row = 0; row < row_count; row++)
  {
    char row_kind[PRODUCTEXPOSURE_EOL_ROW_KIND_MAX_LEN + 1];
    if (!dbhelper_fetchColStr(res, row, PRODUCTEXPOSURE_EOL_COLUMN_ROW_KIND, row_kind, PRODUCTEXPOSURE_EOL_ROW_KIND_MAX_LEN))
      return false;

    if (strcmp(row_kind, "product") == 0)
    {
      int maintained_cycle_count = -1;
      if (eol_out->m_hasEol ||
          !dbhelper_fetchColStr(res, row, PRODUCTEXPOSURE_EOL_COLUMN_NAME, eol_out->ma_eolProduct, PRODUCTEXPOSURE_EOL_PRODUCT_MAX_LEN) ||
          !dbhelper_fetchColStr(res, row, PRODUCTEXPOSURE_EOL_COLUMN_URL,  eol_out->ma_eolUrl,     PRODUCTEXPOSURE_EOL_URL_MAX_LEN)     ||
          !dbhelper_fetchColInt(res, row, PRODUCTEXPOSURE_EOL_COLUMN_MAINTAINED_CYCLE_COUNT, -1, &maintained_cycle_count)               ||
          maintained_cycle_count < 0)
        return false;
      eol_out->m_hasEol = true;
      eol_out->m_hasMoreEolMaintainedCycles = (maintained_cycle_count > PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX);
    }
    else if (strcmp(row_kind, "series") == 0)
    {
      if (eol_out->m_eolSeriesCycleCount == PRODUCTEXPOSURE_EOL_SERIES_CYCLE_MAX ||
          !static_PRODUCTEXPOSURETryReadEolCycle(res, row, &eol_out->ma_eolSeriesCycles[eol_out->m_eolSeriesCycleCount]))
        return false;
      eol_out->m_eolSeriesCycleCount++;
    }
    else if (strcmp(row_kind, "maintained") == 0)
    {
      if (eol_out->m_eolMaintainedCycleCount == PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX)
        continue;
      if (!static_PRODUCTEXPOSURETryReadEolCycle(res, row, &eol_out->ma_eolMaintainedCycles[eol_out->m_eolMaintainedCycleCount]))
        return false;
      eol_out->m_eolMaintainedCycleCount++;
    }
    else
    {
      return false;
    }
  }
  return row_count == 0 || eol_out->m_hasEol;
}

static bool static_PRODUCTEXPOSURETryReadEolCycle(PGresult* res, int row, PRODUCTEXPOSUREEolCycle_t* cycle_out)
{
  return dbhelper_fetchColStr (res, row, PRODUCTEXPOSURE_EOL_COLUMN_NAME,           cycle_out->ma_name,          PRODUCTEXPOSURE_EOL_CYCLE_NAME_MAX_LEN) &&
         dbhelper_fetchColStr (res, row, PRODUCTEXPOSURE_EOL_COLUMN_EOL_DATE,       cycle_out->ma_eolDate,       PRODUCTEXPOSURE_EOL_DATE_LEN) &&
         dbhelper_fetchColBool(res, row, PRODUCTEXPOSURE_EOL_COLUMN_IS_EOL,         &cycle_out->m_isEol) &&
         dbhelper_fetchColBool(res, row, PRODUCTEXPOSURE_EOL_COLUMN_IS_MAINTAINED,  &cycle_out->m_isMaintained) &&
         dbhelper_fetchColBool(res, row, PRODUCTEXPOSURE_EOL_COLUMN_IS_LTS,         &cycle_out->m_isLts) &&
         dbhelper_fetchColStr (res, row, PRODUCTEXPOSURE_EOL_COLUMN_LATEST_VERSION, cycle_out->ma_latestVersion, PRODUCTEXPOSURE_EOL_LATEST_VERSION_MAX_LEN);
}

DbStatus_t db_CPESEARCH(PGconn* conn, const CPESEARCHParams_t* params, CPESEARCHResult_t* results_out)
{
  results_out->m_total  = 0;
  results_out->m_count  = 0;
  results_out->mp_items = NULL;

  char row_count[DBHELPER_INT_PARAM_BUF_SIZE];
  char row_offset[DBHELPER_INT_PARAM_BUF_SIZE];

  const char* param_values[] = {
    params->ma_search,
    dbhelper_intParam(row_count,  sizeof(row_count),  params->m_limit),
    dbhelper_intParam(row_offset, sizeof(row_offset), params->m_offset),
  };
  if (!static_tryReadMatchCount(conn, "SELECT api.fn_cpe_search_match_count($1) AS product_count",
                                "product_count", DB_CPESEARCH_FILTER_COUNT, param_values, &results_out->m_total))
  {
    return DB_ERROR;
  }
  if (params->m_offset >= results_out->m_total)
    return DB_OK;
  return static_CPESEARCHReadPage(conn, "SELECT * FROM api.fn_cpe_search($1, $2, $3)",
                                  DBHELPER_PARAM_COUNT(param_values), param_values, results_out);
}

void db_CPESEARCHResultFree(CPESEARCHResult_t* results)
{
  if (!results)
    return;
  for (int i = 0; i < results->m_count; i++)
    free(results->mp_items[i].mp_productNamedBy);
  free(results->mp_items);
  results->mp_items = NULL;
  results->m_count  = 0;
}

DbStatus_t db_D3FENDFORATTACK(PGconn* conn, const char* attack_technique_id, D3FENDFORATTACKResult_t* result_out)
{
  result_out->mp_attackTechniques = NULL;
  result_out->m_defenseCount      = 0;
  result_out->mp_defenses         = NULL;

  const char* param_values[] = { attack_technique_id };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_d3fend_for_attack($1)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, D3FENDFORATTACK_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(D3FENDFORATTACK_COLUMN_NAMES)))
  {
    PQclear(res);
    return DB_ERROR;
  }

  int row_count = PQntuples(res);
  if (row_count == 0)
  {
    PQclear(res);
    return DB_OK;
  }

  result_out->mp_defenses = calloc((size_t)row_count, sizeof(D3FENDFORATTACKItem_t));
  if (!result_out->mp_defenses)
  {
    PQclear(res);
    return DB_ERROR;
  }
  result_out->m_defenseCount = row_count;

  if (!dbhelper_fetchColStrdup(res, 0, D3FENDFORATTACK_COLUMN_ATTACK_TECHNIQUES, &result_out->mp_attackTechniques))
  {
    PQclear(res);
    db_D3FENDFORATTACKResultFree(result_out);
    return DB_ERROR;
  }
  for (int row_index = 0; row_index < row_count; row_index++)
  {
    if (!static_D3FENDFORATTACKFillItem(res, row_index, &result_out->mp_defenses[row_index]))
    {
      PQclear(res);
      db_D3FENDFORATTACKResultFree(result_out);
      return DB_ERROR;
    }
  }
  PQclear(res);
  return DB_OK;
}

void db_D3FENDFORATTACKResultFree(D3FENDFORATTACKResult_t* result)
{
  if (!result)
    return;
  for (int i = 0; i < result->m_defenseCount; i++)
  {
    free(result->mp_defenses[i].mp_parentDefenseLabels);
    free(result->mp_defenses[i].mp_attackTechniqueIds);
  }
  free(result->mp_defenses);
  free(result->mp_attackTechniques);
  result->mp_defenses         = NULL;
  result->mp_attackTechniques = NULL;
  result->m_defenseCount      = 0;
}

DbStatus_t db_DRIVERLOOKUP(PGconn* conn, const char* file_hash, bool is_command_included, DRIVERLOOKUPRecord_t* record_out)
{
  record_out->mp_matches = NULL;

  const char* param_values[] = { file_hash, MACRO_STR(DRIVERLOOKUP_MATCH_MAX_ROWS), is_command_included ? "true" : "false" };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_driver_lookup(ARRAY[$1], $2, $3)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, DRIVERLOOKUP_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DRIVERLOOKUP_COLUMN_NAMES)) ||
      PQntuples(res) != 1)
  {
    PQclear(res);
    return DB_ERROR;
  }

  if (!static_DRIVERLOOKUPTryFillRecord(res, 0, record_out))
  {
    PQclear(res);
    return DB_ERROR;
  }

  PQclear(res);
  return DB_OK;
}

void db_DRIVERLOOKUPRecordFree(DRIVERLOOKUPRecord_t* record)
{
  if (!record)
    return;
  free(record->mp_matches);
  record->mp_matches = NULL;
}

DbStatus_t db_DRIVERLOOKUPBULK(PGconn* conn, const BulkIdsParams_t* params, DRIVERLOOKUPBULKResult_t* results_out)
{
  results_out->m_successful = 0;
  results_out->m_failed     = 0;
  results_out->mp_items     = NULL;

  char hash_array[DB_ID_ARRAY_PARAM_BUF_SIZE];
  if (!static_tryWriteIdArray(params, hash_array))
    return DB_ERROR;

  const char* param_values[] = { hash_array, MACRO_STR(DRIVERLOOKUP_MATCH_MAX_ROWS), "false" };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_driver_lookup($1, $2, $3)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  int row_count = PQntuples(res);
  if (!dbhelper_isColumnListEqual(res, DRIVERLOOKUP_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(DRIVERLOOKUP_COLUMN_NAMES)) ||
      row_count != params->m_idCount)
  {
    PQclear(res);
    return DB_ERROR;
  }

  int successful = 0;
  if (row_count > 0)
  {
    results_out->mp_items = calloc((size_t)row_count, sizeof(DRIVERLOOKUPRecord_t));
    if (!results_out->mp_items)
    {
      PQclear(res);
      return DB_ERROR;
    }
    for (int row_index = 0; row_index < row_count; row_index++)
    {
      if (static_DRIVERLOOKUPTryFillRecord(res, row_index, &results_out->mp_items[successful]))
        successful++;
    }
  }
  PQclear(res);

  results_out->m_successful = successful;
  results_out->m_failed     = params->m_idCount - successful;
  return DB_OK;
}

void db_DRIVERLOOKUPBULKResultFree(DRIVERLOOKUPBULKResult_t* results)
{
  if (!results)
    return;
  for (int i = 0; i < results->m_successful; i++)
    db_DRIVERLOOKUPRecordFree(&results->mp_items[i]);
  free(results->mp_items);
  results->mp_items     = NULL;
  results->m_successful = 0;
}

DbStatus_t db_IPLOOKUP(PGconn* conn, const char* ip_address, IPLOOKUPRecord_t* record_out)
{
  assert(ip_address != NULL);
  assert(record_out != NULL);

  record_out->mp_listedOn = NULL;

  size_t ip_address_len = strlen(ip_address);
  if (ip_address_len >= sizeof(record_out->ma_ipAddress))
    return DB_ERROR;
  memcpy(record_out->ma_ipAddress, ip_address, ip_address_len + 1);

  const char* param_values[] = { ip_address };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_ip_lookup($1)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, IPLOOKUP_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(IPLOOKUP_COLUMN_NAMES)) ||
      PQntuples(res) != 1)
  {
    PQclear(res);
    return DB_ERROR;
  }

  if (!static_IPLOOKUPTryFillRecord(res, record_out))
  {
    PQclear(res);
    return DB_ERROR;
  }

  PQclear(res);
  return DB_OK;
}

void db_IPLOOKUPRecordFree(IPLOOKUPRecord_t* record)
{
  if (!record)
    return;

  free(record->mp_listedOn);
  record->mp_listedOn = NULL;
}

DbStatus_t db_ASNLOOKUP(PGconn* conn, const ASNLOOKUPParams_t* params, ASNLOOKUPRecord_t* record_out)
{
  assert(params     != NULL);
  assert(record_out != NULL);

  record_out->mp_ipv4Prefixes = NULL;
  record_out->mp_ipv6Prefixes = NULL;
  record_out->ma_prefix[0]    = '\0';

  char asn_text[DBHELPER_UINT_STR_BUF_SIZE];
  if (strncmp(params->ma_target, "AS", sizeof("AS") - 1) == 0)
  {
    int asn_text_len = snprintf(asn_text, sizeof(asn_text), "%s", params->ma_target + sizeof("AS") - 1);
    if (asn_text_len < 0 || (size_t)asn_text_len >= sizeof(asn_text))
      return DB_ERROR;
  }
  else
  {
    DbStatus_t prefix_status = static_ASNLOOKUPReadPrefix(conn, params->ma_target, asn_text, record_out);
    if (prefix_status != DB_OK)
      return prefix_status;
  }

  char prefix_row_count[DBHELPER_INT_PARAM_BUF_SIZE];
  char prefix_row_offset[DBHELPER_INT_PARAM_BUF_SIZE];
  const char* param_values[] = {
    asn_text,
    dbhelper_intParam(prefix_row_count,  sizeof(prefix_row_count),  params->m_limit),
    dbhelper_intParam(prefix_row_offset, sizeof(prefix_row_offset), params->m_offset),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_asn_lookup($1, $2, $3)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, ASNLOOKUP_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(ASNLOOKUP_COLUMN_NAMES)) ||
      PQntuples(res) > 1)
  {
    PQclear(res);
    return DB_ERROR;
  }
  if (PQntuples(res) == 0)
  {
    PQclear(res);
    return DB_NOT_FOUND;
  }

  if (!static_ASNLOOKUPTryFillRecord(res, record_out))
  {
    PQclear(res);
    return DB_ERROR;
  }

  PQclear(res);
  return DB_OK;
}

void db_ASNLOOKUPRecordFree(ASNLOOKUPRecord_t* record)
{
  if (!record)
    return;

  free(record->mp_ipv4Prefixes);
  record->mp_ipv4Prefixes = NULL;
  free(record->mp_ipv6Prefixes);
  record->mp_ipv6Prefixes = NULL;
}

DbStatus_t db_EMAILADDRESSCHECK(PGconn* conn, const char* domain, EMAILADDRESSCHECKRecord_t* record_out)
{
  assert(domain     != NULL);
  assert(record_out != NULL);

  record_out->m_isDisposableFeedLoaded     = false;
  record_out->ma_disposableListedDomain[0] = '\0';

  const char* param_values[] = { domain };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_email_disposable_domain($1)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, EMAILADDRESSCHECK_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(EMAILADDRESSCHECK_COLUMN_NAMES)) ||
      PQntuples(res) != 1)
  {
    PQclear(res);
    return DB_ERROR;
  }

  bool is_record_filled = static_EMAILADDRESSCHECKTryFillRecord(res, domain, record_out);
  PQclear(res);
  if (!is_record_filled)
  {
    record_out->m_isDisposableFeedLoaded     = false;
    record_out->ma_disposableListedDomain[0] = '\0';
    return DB_ERROR;
  }

  return DB_OK;
}

DbStatus_t db_SSLCHECK(PGconn* conn, const char* sha1_hex, SSLCHECKRecord_t* record_out)
{
  assert(sha1_hex   != NULL);
  assert(record_out != NULL);

  record_out->m_isBlacklistFeedLoaded      = false;
  record_out->ma_blacklistListingReason[0] = '\0';
  record_out->ma_blacklistListingTime[0]   = '\0';

  const char* param_values[] = { sha1_hex };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_ssl_blacklist_certificate($1)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, SSLCHECK_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(SSLCHECK_COLUMN_NAMES)) ||
      PQntuples(res) != 1)
  {
    PQclear(res);
    return DB_ERROR;
  }

  bool is_record_filled = static_SSLCHECKTryFillRecord(res, record_out);
  PQclear(res);
  if (!is_record_filled)
  {
    record_out->m_isBlacklistFeedLoaded      = false;
    record_out->ma_blacklistListingReason[0] = '\0';
    record_out->ma_blacklistListingTime[0]   = '\0';
    return DB_ERROR;
  }

  return DB_OK;
}

DbStatus_t db_PACKAGECHECK(PGconn* conn, const PACKAGECHECKParams_t* params, PACKAGECHECKResult_t* result_out)
{
  result_out->mp_malicious   = NULL;
  result_out->mp_results     = NULL;
  result_out->mp_attribution = NULL;
  memset(&result_out->m_eol, 0, sizeof(result_out->m_eol));

  char row_count[DBHELPER_INT_PARAM_BUF_SIZE];
  char row_offset[DBHELPER_INT_PARAM_BUF_SIZE];

  const char* param_values[] = {
    params->ma_ecosystem,
    params->ma_packageName,
    dbhelper_textOrNull(params->ma_version),
    dbhelper_intParam(row_count,  sizeof(row_count),  params->m_limit),
    dbhelper_intParam(row_offset, sizeof(row_offset), params->m_offset),
  };
  const char* eol_param_values[] = {
    params->ma_ecosystem,
    params->ma_packageName,
    dbhelper_textOrNull(params->ma_version),
    MACRO_STR(PRODUCTEXPOSURE_EOL_MAINTAINED_CYCLE_MAX),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_package_check($1, $2, $3, $4, $5)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, PACKAGECHECK_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(PACKAGECHECK_COLUMN_NAMES)) ||
      PQntuples(res) != 1)
  {
    PQclear(res);
    return DB_ERROR;
  }

  if (!static_PACKAGECHECKTryFillResult(res, result_out))
  {
    PQclear(res);
    db_PACKAGECHECKResultFree(result_out);
    return DB_ERROR;
  }
  PQclear(res);

  res = dbhelper_executeQuery(conn,
                              "SELECT * FROM api.fn_package_check_eol($1, $2, $3, $4)",
                              DBHELPER_PARAM_COUNT(eol_param_values),
                              eol_param_values);
  bool is_eol_read = res != NULL &&
                     dbhelper_isColumnListEqual(res, PRODUCTEXPOSURE_EOL_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(PRODUCTEXPOSURE_EOL_COLUMN_NAMES)) &&
                     static_PRODUCTEXPOSURETryReadEol(res, &result_out->m_eol);
  PQclear(res);
  if (!is_eol_read)
  {
    db_PACKAGECHECKResultFree(result_out);
    return DB_ERROR;
  }
  return DB_OK;
}

DbStatus_t db_PACKAGECHECKBULK(PGconn* conn, const PACKAGECHECKBULKItem_t* items, int item_count, PACKAGECHECKBULKResult_t* result_out)
{
  assert(items != NULL);
  assert(item_count > 0 && item_count <= PACKAGECHECKBULK_MAX_ITEMS);

  result_out->m_successful   = 0;
  result_out->m_failed       = 0;
  result_out->mp_results     = NULL;
  result_out->mp_attribution = NULL;

  const char* ecosystems[PACKAGECHECKBULK_MAX_ITEMS];
  const char* package_names[PACKAGECHECKBULK_MAX_ITEMS];
  const char* versions[PACKAGECHECKBULK_MAX_ITEMS];
  for (int i = 0; i < item_count; i++)
  {
    ecosystems[i]    = items[i].ma_ecosystem;
    package_names[i] = items[i].ma_packageName;
    versions[i]      = items[i].ma_version;
  }

  char* ecosystem_array    = dbhelper_buildTextArrayLiteral(ecosystems, item_count);
  char* package_name_array = dbhelper_buildTextArrayLiteral(package_names, item_count);
  char* version_array      = dbhelper_buildTextArrayLiteral(versions, item_count);
  if (!ecosystem_array || !package_name_array || !version_array)
  {
    free(ecosystem_array);
    free(package_name_array);
    free(version_array);
    return DB_ERROR;
  }

  const char* param_values[] = { ecosystem_array, package_name_array, version_array, MACRO_STR(PACKAGECHECKBULK_ADVISORY_MAX_ROWS) };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_package_check_bulk($1, $2, $3, $4)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  free(ecosystem_array);
  free(package_name_array);
  free(version_array);
  
  if (!res)
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, PACKAGECHECKBULK_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(PACKAGECHECKBULK_COLUMN_NAMES)) ||
      PQntuples(res) != 1)
  {
    PQclear(res);
    return DB_ERROR;
  }

  int failed_item_count = -1;
  if (!dbhelper_fetchColBool     (res, 0, PACKAGECHECKBULK_COLUMN_ADVISORY_FEED_LOADED, &result_out->m_isAdvisoryFeedLoaded)  ||
      !dbhelper_isColWithinLength(res, 0, PACKAGECHECKBULK_COLUMN_RESULTS, PACKAGECHECKBULK_JSON_MAX_LEN)                     ||
      !dbhelper_isColWithinLength(res, 0, PACKAGECHECKBULK_COLUMN_ATTRIBUTION, PACKAGECHECKBULK_JSON_MAX_LEN)                 ||
      !dbhelper_fetchColInt      (res, 0, PACKAGECHECKBULK_COLUMN_FAILED_ITEM_COUNT, -1, &failed_item_count)                  ||
      failed_item_count < 0 || failed_item_count > item_count                                                                 ||
      !dbhelper_fetchColStrdup   (res, 0, PACKAGECHECKBULK_COLUMN_RESULTS, &result_out->mp_results)                           ||
      !dbhelper_fetchColStrdup   (res, 0, PACKAGECHECKBULK_COLUMN_ATTRIBUTION, &result_out->mp_attribution))
  {
    PQclear(res);
    db_PACKAGECHECKBULKResultFree(result_out);
    return DB_ERROR;
  }

  PQclear(res);
  result_out->m_successful = item_count - failed_item_count;
  result_out->m_failed     = failed_item_count;
  return DB_OK;
}

DbStatus_t db_PACKAGECHECKBULKWeigh(PGconn* conn, const PACKAGECHECKBULKItem_t* items, int item_count, int* served_item_count_out)
{
  assert(items != NULL);
  assert(served_item_count_out != NULL);
  assert(item_count > 0 && item_count <= PACKAGECHECKBULK_MAX_ITEMS);

  const char* ecosystems[PACKAGECHECKBULK_MAX_ITEMS];
  const char* package_names[PACKAGECHECKBULK_MAX_ITEMS];
  for (int i = 0; i < item_count; i++)
  {
    ecosystems[i]    = items[i].ma_ecosystem;
    package_names[i] = items[i].ma_packageName;
  }

  char* ecosystem_array    = dbhelper_buildTextArrayLiteral(ecosystems, item_count);
  char* package_name_array = dbhelper_buildTextArrayLiteral(package_names, item_count);
  if (!ecosystem_array || !package_name_array)
  {
    free(ecosystem_array);
    free(package_name_array);
    return DB_ERROR;
  }

  const char* param_values[] = {
    ecosystem_array,
    package_name_array,
    MACRO_STR(PACKAGECHECKBULK_ITEM_BASE_WEIGHT),
    MACRO_STR(PACKAGECHECKBULK_WEIGHT_BUDGET),
    MACRO_STR(PACKAGECHECKBULK_LISTED_VERSIONS_PER_WEIGHT),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_package_check_bulk_weigh($1, $2, $3, $4, $5) AS served_item_count",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  free(ecosystem_array);
  free(package_name_array);
  if (!res)
    return DB_ERROR;

  int  served_item_count = 0;
  bool is_read = PQntuples(res) == 1
              && dbhelper_isColumnListEqual(res, PACKAGECHECKBULKWEIGH_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(PACKAGECHECKBULKWEIGH_COLUMN_NAMES))
              && !PQgetisnull(res, 0, PACKAGECHECKBULKWEIGH_COLUMN_SERVED_ITEM_COUNT)
              && dbhelper_fetchColInt(res, 0, PACKAGECHECKBULKWEIGH_COLUMN_SERVED_ITEM_COUNT, 0, &served_item_count)
              && served_item_count >= 1
              && served_item_count <= item_count;
  PQclear(res);

  if (!is_read)
    return DB_ERROR;
  *served_item_count_out = served_item_count;
  return DB_OK;
}

void db_PACKAGECHECKBULKResultFree(PACKAGECHECKBULKResult_t* result)
{
  if (!result)
    return;
  free(result->mp_results);
  free(result->mp_attribution);
  result->mp_results     = NULL;
  result->mp_attribution = NULL;
}

void db_PACKAGECHECKResultFree(PACKAGECHECKResult_t* result)
{
  if (!result)
    return;
  free(result->mp_malicious);
  free(result->mp_results);
  free(result->mp_attribution);
  result->mp_malicious   = NULL;
  result->mp_results     = NULL;
  result->mp_attribution = NULL;
}

static const char* static_int64Param(char* buf, size_t size, int64_t value)
{
  assert(buf  != NULL);
  assert(size >= DB_INT64_PARAM_BUF_SIZE);

  snprintf(buf, size, "%" PRId64, value);
  return buf;
}

static bool static_tryWriteIdArray(const BulkIdsParams_t* params, char* literal_out)
{
  assert(params      != NULL);
  assert(literal_out != NULL);

  if (params->m_idCount < 0 || params->m_idCount > BULK_MAX_IDS)
    return false;

  size_t pos = 0;
  literal_out[pos++] = '{';
  for (int i = 0; i < params->m_idCount; i++)
  {
    const char* id     = params->ma_ids[i];
    const char* id_end = memchr(id, '\0', sizeof(params->ma_ids[i]));
    if (!id_end)
      return false;

    if (i > 0)
      literal_out[pos++] = ',';
    memcpy(literal_out + pos, id, (size_t)(id_end - id));
    pos += (size_t)(id_end - id);
  }
  literal_out[pos++] = '}';
  literal_out[pos]   = '\0';
  return true;
}

static bool static_tryReadMatchCount(PGconn* conn, const char* query, const char* column_name, int param_count, const char** param_values, int* match_count_out)
{
  assert(query           != NULL);
  assert(column_name     != NULL);
  assert(param_values    != NULL);
  assert(match_count_out != NULL);

  if (!conn)
  {
    fprintf(stderr, "static_tryReadMatchCount: no database connection\n");
    return false;
  }

  PGresult* res = dbhelper_executeQuery(conn,
                                        query,
                                        param_count,
                                        param_values);
  if (!res) 
    return false;
  
  const char* const column_names[] = { column_name };
  bool is_count_read = dbhelper_isColumnListEqual(res, column_names, DBHELPER_COLUMN_COUNT(column_names)) && PQntuples(res) == 1 && dbhelper_fetchColInt(res, 0, 0, 0, match_count_out);
  PQclear(res);
  return is_count_read;
}

static DbStatus_t static_CVESEARCHReadPage(PGconn* conn, const char* query, int param_count, const char** param_values, CveListResult_t* results_out)
{
  assert(conn         != NULL);
  assert(query        != NULL);
  assert(param_values != NULL);
  assert(results_out  != NULL);

  PGresult* res = dbhelper_executeQuery(conn,
                                        query,
                                        param_count,
                                        param_values);
  if (!res) 
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, CVESEARCH_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(CVESEARCH_COLUMN_NAMES)))
  {
    PQclear(res);
    return DB_ERROR;
  }

  int row_count = PQntuples(res);
  if (row_count == 0) 
  { 
    PQclear(res); 
    return DB_OK; 
  }

  results_out->mp_items = malloc((size_t)row_count * sizeof(CveListItem_t));
  if (!results_out->mp_items) 
  { 
    PQclear(res); 
    return DB_ERROR; 
  }

  for (int row_index = 0; row_index < row_count; row_index++)
  {
    if (!static_CVESEARCHFillItem(res, row_index, &results_out->mp_items[row_index]))
    {
      free(results_out->mp_items);
      results_out->mp_items = NULL;
      PQclear(res);
      return DB_ERROR;
    }
  }

  results_out->m_count = row_count;
  PQclear(res);
  return DB_OK;
}

static bool static_CVELOOKUPTryFillRecord(PGresult* res, int row, CVELOOKUPRecord_t* rec)
{
  assert(res != NULL);
  assert(rec != NULL);

  if (row < 0 || row >= PQntuples(res))
  {
    fprintf(stderr, "static_CVELOOKUPTryFillRecord: the result holds no row %d\n", row);
    return false;
  }

  if (!dbhelper_fetchColDouble(res, row, CVELOOKUP_COLUMN_CVSS_V3,                     0.0, &rec->m_cvssV3)                ||
      !dbhelper_fetchColDouble(res, row, CVELOOKUP_COLUMN_EPSS_SCORE,                  0.0, &rec->m_epssScore)             ||
      !dbhelper_fetchColDouble(res, row, CVELOOKUP_COLUMN_EPSS_PERCENTILE,             0.0, &rec->m_epssPercentile)        ||
      !dbhelper_fetchColBool  (res, row, CVELOOKUP_COLUMN_IN_KEV,                      &rec->m_inKev)                      ||
      !dbhelper_fetchColInt   (res, row, CVELOOKUP_COLUMN_POC_COUNT,                   0,   &rec->m_pocCount)              ||
      !dbhelper_fetchColInt   (res, row, CVELOOKUP_COLUMN_VENDOR_ADVISORY_COUNT,       0,   &rec->m_vendorAdvisoryCount)   ||
      !dbhelper_fetchColInt   (res, row, CVELOOKUP_COLUMN_METASPLOIT_MODULE_COUNT,     0,   &rec->m_metasploitModuleCount) ||
      !dbhelper_fetchColDouble(res, row, CVELOOKUP_COLUMN_CVSS_V4,                     0.0, &rec->m_cvssV4)                ||
      !dbhelper_fetchColBool  (res, row, CVELOOKUP_COLUMN_METASPLOIT_FEED_LOADED,      &rec->m_isMetasploitFeedLoaded)     ||
      !dbhelper_fetchColInt   (res, row, CVELOOKUP_COLUMN_NUCLEI_TEMPLATE_COUNT,       0,   &rec->m_nucleiTemplateCount)   ||
      !dbhelper_fetchColBool  (res, row, CVELOOKUP_COLUMN_NUCLEI_TEMPLATE_FEED_LOADED, &rec->m_isNucleiTemplateFeedLoaded)     ||
      !dbhelper_fetchColInt   (res, row, CVELOOKUP_COLUMN_AFFECTED_PRODUCT_COUNT,      0,   &rec->m_affectedProductCount)  ||
      !dbhelper_fetchColInt   (res, row, CVELOOKUP_COLUMN_REF_COUNT,                   0,   &rec->m_refCount))
    return false;

  if (!dbhelper_fetchColStr(res, row, CVELOOKUP_COLUMN_CVE_ID,               rec->ma_cveId,               CVELOOKUP_ID_MAX_LEN)    ||
      !dbhelper_fetchColStr(res, row, CVELOOKUP_COLUMN_CVE_DESCRIPTION,      rec->ma_description,         CVELOOKUP_DESC_MAX_LEN)  ||
      !dbhelper_fetchColStr(res, row, CVELOOKUP_COLUMN_SEVERITY,             rec->ma_severity,            CVELOOKUP_SEVERITY_LEN)  ||
      !dbhelper_fetchColStr(res, row, CVELOOKUP_COLUMN_CVSS_V3_VECTOR,       rec->ma_cvssV3Vector,        CVELOOKUP_V3_VECTOR_LEN) ||
      !dbhelper_fetchColStr(res, row, CVELOOKUP_COLUMN_PUBLISHED_TIME,       rec->ma_publishedTime,       CVELOOKUP_PUBLISHED_LEN) ||
      !dbhelper_fetchColStr(res, row, CVELOOKUP_COLUMN_CWE_ID,               rec->ma_cweId,               CVELOOKUP_CWE_ID_LEN)    ||
      !dbhelper_fetchColStr(res, row, CVELOOKUP_COLUMN_KEV_DATE_ADDED,       rec->ma_kevDateAdded,        CVELOOKUP_PUBLISHED_LEN) ||
      !dbhelper_fetchColStr(res, row, CVELOOKUP_COLUMN_VULNERABILITY_STATUS, rec->ma_vulnerabilityStatus, CVELOOKUP_STATUS_LEN)    ||
      !dbhelper_fetchColStr(res, row, CVELOOKUP_COLUMN_RANSOMWARE_CAMPAIGN,  rec->ma_ransomwareCampaign, CVELOOKUP_RANSOMWARE_LEN) ||
      !dbhelper_fetchColStr(res, row, CVELOOKUP_COLUMN_CVSS_V4_VECTOR,       rec->ma_cvssV4Vector,       CVELOOKUP_V4_VECTOR_LEN)  ||
      !dbhelper_fetchColStr(res, row, CVELOOKUP_COLUMN_CVSS_V3_SOURCE,       rec->ma_cvssV3Source,       CVELOOKUP_SOURCE_LEN)     ||
      !dbhelper_fetchColStr(res, row, CVELOOKUP_COLUMN_CVSS_V4_SOURCE,       rec->ma_cvssV4Source,       CVELOOKUP_SOURCE_LEN)     ||
      !dbhelper_fetchColStr(res, row, CVELOOKUP_COLUMN_CWE_SOURCE,           rec->ma_cweSource,          CVELOOKUP_SOURCE_LEN)     ||
      !static_CVELOOKUPTryReadSsvc(res, row, rec)                                                                                  ||
      !dbhelper_isColWithinLength(res, row, CVELOOKUP_COLUMN_EPSS_TREND, CVELOOKUP_EPSS_TREND_MAX_LEN)                             ||
      !dbhelper_isColWithinLength(res, row, CVELOOKUP_COLUMN_NUCLEI_TEMPLATES, CVELOOKUP_NUCLEI_TEMPLATES_MAX_LEN)                 ||
      !dbhelper_fetchColStrdup(res, row, CVELOOKUP_COLUMN_CWES,              &rec->mp_cwes)                                        ||
      !dbhelper_fetchColStrdup(res, row, CVELOOKUP_COLUMN_CVE_TAGS,          &rec->mp_cveTags)                                     ||
      !dbhelper_fetchColStrdup(res, row, CVELOOKUP_COLUMN_AFFECTED_PRODUCTS, &rec->mp_affectedProducts)                            ||
      !dbhelper_fetchColStrdup(res, row, CVELOOKUP_COLUMN_PRODUCT_COUNT_BY_VENDOR, &rec->mp_productCountByVendor)                  ||
      !dbhelper_fetchColStrdup(res, row, CVELOOKUP_COLUMN_REFS,              &rec->mp_refs)                                        ||
      !dbhelper_fetchColStrdup(res, row, CVELOOKUP_COLUMN_EPSS_TREND,        &rec->mp_epssTrend)                                   ||
      !dbhelper_fetchColStrdup(res, row, CVELOOKUP_COLUMN_NUCLEI_TEMPLATES, &rec->mp_nucleiTemplates))
  {
    db_CVELOOKUPRecordFree(rec);
    return false;
  }

  return true;
}

static bool static_CVELOOKUPTryReadSsvc(PGresult* res, int row, CVELOOKUPRecord_t* rec)
{
  memset(&rec->m_ssvcResult, 0, sizeof(rec->m_ssvcResult));
  if (!dbhelper_fetchColStr(res, row, CVELOOKUP_COLUMN_SSVC_EXPLOITATION,     rec->ma_ssvcExploitation,    CVELOOKUP_SSVC_VALUE_LEN) ||
      !dbhelper_fetchColStr(res, row, CVELOOKUP_COLUMN_SSVC_AUTOMATABLE,      rec->ma_ssvcAutomatable,     CVELOOKUP_SSVC_VALUE_LEN) ||
      !dbhelper_fetchColStr(res, row, CVELOOKUP_COLUMN_SSVC_TECHNICAL_IMPACT, rec->ma_ssvcTechnicalImpact, CVELOOKUP_SSVC_VALUE_LEN) ||
      !dbhelper_fetchColStr(res, row, CVELOOKUP_COLUMN_SSVC_VERSION,          rec->ma_ssvcVersion,         CVELOOKUP_SSVC_VALUE_LEN) ||
      !dbhelper_fetchColStr(res, row, CVELOOKUP_COLUMN_SSVC_SCORED_AT,        rec->ma_ssvcScoredAt,        CVELOOKUP_PUBLISHED_LEN))
    return false;

  bool has_ssvc_value = *rec->ma_ssvcExploitation    != '\0' ||
                        *rec->ma_ssvcAutomatable     != '\0' ||
                        *rec->ma_ssvcTechnicalImpact != '\0' ||
                        *rec->ma_ssvcVersion         != '\0' ||
                        *rec->ma_ssvcScoredAt        != '\0';
  if (!has_ssvc_value)
    return true;

  if (strcmp(rec->ma_ssvcVersion, SSVC_TREE_VERSION) != 0)
  {
    fprintf(stderr, "static_CVELOOKUPTryReadSsvc: %s holds an SSVC assessment that is not of version %s\n", rec->ma_cveId, SSVC_TREE_VERSION);
    return false;
  }

  SsvcStatus_t ssvc_status = ssvc_evaluate(rec->ma_ssvcExploitation, rec->ma_ssvcAutomatable, rec->ma_ssvcTechnicalImpact, &rec->m_ssvcResult);
  if (ssvc_status != SSVC_OK)
  {
    fprintf(stderr, "static_CVELOOKUPTryReadSsvc: %s holds an SSVC value that ssvc_evaluate refuses with status %d\n", rec->ma_cveId, (int)ssvc_status);
    return false;
  }
  return true;
}

static bool static_CVESEARCHFillItem(PGresult* res, int row_index, CveListItem_t* item)
{
  assert(res  != NULL);
  assert(item != NULL);
  assert(row_index >= 0 && row_index < PQntuples(res));

  return dbhelper_fetchColDouble(res, row_index, CVESEARCH_COLUMN_CVSS_V3,         0.0, &item->m_cvssV3)                        &&
         dbhelper_fetchColDouble(res, row_index, CVESEARCH_COLUMN_EPSS_SCORE,      0.0, &item->m_epssScore)                     &&
         dbhelper_fetchColDouble(res, row_index, CVESEARCH_COLUMN_EPSS_PERCENTILE, 0.0, &item->m_epssPercentile)                &&
         dbhelper_fetchColBool  (res, row_index, CVESEARCH_COLUMN_IN_KEV,          &item->m_inKev)                              &&
         dbhelper_fetchColDouble(res, row_index, CVESEARCH_COLUMN_CVSS_V4,         0.0, &item->m_cvssV4)                        &&
         dbhelper_fetchColBool  (res, row_index, CVESEARCH_COLUMN_HAS_CVSS_V4,     &item->m_hasCvssV4)                          &&
         dbhelper_fetchColBool  (res, row_index, CVESEARCH_COLUMN_HAS_CVSS_V3,     &item->m_hasCvssV3)                          &&
         dbhelper_fetchColStr(res, row_index, CVESEARCH_COLUMN_CVE_ID,         item->ma_cveId, CVELOOKUP_ID_MAX_LEN)            &&
         dbhelper_fetchColStr(res, row_index, CVESEARCH_COLUMN_SEVERITY,       item->ma_severity, CVELOOKUP_SEVERITY_LEN)       &&
         dbhelper_fetchColStr(res, row_index, CVESEARCH_COLUMN_PUBLISHED_TIME, item->ma_publishedTime, CVELOOKUP_PUBLISHED_LEN) &&
         dbhelper_fetchColStr(res, row_index, CVESEARCH_COLUMN_CWE_ID,         item->ma_cweId, CVELOOKUP_CWE_ID_LEN)            &&
         dbhelper_fetchColStr(res, row_index, CVESEARCH_COLUMN_CVSS_V3_SOURCE, item->ma_cvssV3Source, CVELOOKUP_SOURCE_LEN)     &&
         dbhelper_fetchColStr(res, row_index, CVESEARCH_COLUMN_CVSS_V4_SOURCE, item->ma_cvssV4Source, CVELOOKUP_SOURCE_LEN)     &&
         dbhelper_fetchColStr(res, row_index, CVESEARCH_COLUMN_CWE_SOURCE,     item->ma_cweSource, CVELOOKUP_SOURCE_LEN);
}

static DbStatus_t static_CVETRIAGEReadPage(PGconn* conn, const char* query, int param_count, const char** param_values, CVETRIAGEResult_t* results_out)
{
  assert(conn         != NULL);
  assert(query        != NULL);
  assert(param_values != NULL);
  assert(results_out  != NULL);

  PGresult* res = dbhelper_executeQuery(conn,
                                        query,
                                        param_count,
                                        param_values);
  if (!res) 
    return DB_ERROR;
  
  if (!dbhelper_isColumnListEqual(res, CVETRIAGE_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(CVETRIAGE_COLUMN_NAMES)))
  {
    PQclear(res);
    return DB_ERROR;
  }

  int row_count = PQntuples(res);
  if (row_count == 0)
  {
    PQclear(res);
    return DB_OK;
  }

  results_out->mp_items = malloc((size_t)row_count * sizeof(CVETRIAGEItem_t));
  if (!results_out->mp_items)
  {
    PQclear(res);
    return DB_ERROR;
  }

  for (int row_index = 0; row_index < row_count; row_index++)
  {
    if (!static_CVETRIAGEFillItem(res, row_index, &results_out->mp_items[row_index]))
    {
      free(results_out->mp_items);
      results_out->mp_items = NULL;
      PQclear(res);
      return DB_ERROR;
    }
  }

  results_out->m_count = row_count;
  PQclear(res);
  return DB_OK;
}

static bool static_CVETRIAGEFillItem(PGresult* res, int row_index, CVETRIAGEItem_t* item)
{
  assert(res  != NULL);
  assert(item != NULL);
  assert(row_index >= 0 && row_index < PQntuples(res));

  return dbhelper_fetchColStr(res, row_index, CVETRIAGE_COLUMN_CVE_ID, item->ma_cveId, CVELOOKUP_ID_MAX_LEN) &&
         dbhelper_fetchColDouble(res, row_index, CVETRIAGE_COLUMN_RISK_SCORE, 0.0, &item->m_riskScore)       &&
         dbhelper_fetchColStr(res, row_index, CVETRIAGE_COLUMN_RISK_LABEL, item->ma_label, CVERISKSCORE_LABEL_LEN);
}

static bool static_PRODUCTEXPOSUREFillTopItem(PGresult* res, int row_index, CVETRIAGEItem_t* item)
{
  assert(res  != NULL);
  assert(item != NULL);
  assert(row_index >= 0 && row_index < PQntuples(res));

  if (PQgetisnull(res, row_index, PRODUCTEXPOSURE_COLUMN_CVE_ID))
  {
    fprintf(stderr, "static_PRODUCTEXPOSUREFillTopItem: row %d has a NULL cve_id\n", row_index);
    return false;
  }
  return dbhelper_fetchColStr(res, row_index, PRODUCTEXPOSURE_COLUMN_CVE_ID, item->ma_cveId, CVELOOKUP_ID_MAX_LEN) &&
         dbhelper_fetchColDouble(res, row_index, PRODUCTEXPOSURE_COLUMN_RISK_SCORE, 0.0, &item->m_riskScore)       &&
         dbhelper_fetchColStr(res, row_index, PRODUCTEXPOSURE_COLUMN_RISK_LABEL, item->ma_label, CVERISKSCORE_LABEL_LEN);
}

static DbStatus_t static_CPESEARCHReadPage(PGconn* conn, const char* query, int param_count, const char** param_values, CPESEARCHResult_t* results_out)
{
  assert(conn         != NULL);
  assert(query        != NULL);
  assert(param_values != NULL);
  assert(results_out  != NULL);

  PGresult* res = dbhelper_executeQuery(conn,
                                        query,
                                        param_count,
                                        param_values);
  if (!res)
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, CPESEARCH_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(CPESEARCH_COLUMN_NAMES)))
  {
    PQclear(res);
    return DB_ERROR;
  }

  int row_count = PQntuples(res);
  if (row_count == 0)
  {
    PQclear(res);
    return DB_OK;
  }

  results_out->mp_items = calloc((size_t)row_count, sizeof(CPESEARCHItem_t));
  if (!results_out->mp_items)
  {
    PQclear(res);
    return DB_ERROR;
  }
  results_out->m_count = row_count;

  for (int row_index = 0; row_index < row_count; row_index++)
  {
    if (!static_CPESEARCHFillItem(res, row_index, &results_out->mp_items[row_index]))
    {
      PQclear(res);
      db_CPESEARCHResultFree(results_out);
      return DB_ERROR;
    }
  }

  PQclear(res);
  return DB_OK;
}

static bool static_CPESEARCHFillItem(PGresult* res, int row_index, CPESEARCHItem_t* item)
{
  assert(res  != NULL);
  assert(item != NULL);
  assert(row_index >= 0 && row_index < PQntuples(res));

  return dbhelper_fetchColStr   (res, row_index, CPESEARCH_COLUMN_VENDOR,               item->ma_vendor, CVESEARCH_VENDOR_LEN)   &&
         dbhelper_fetchColStr   (res, row_index, CPESEARCH_COLUMN_PRODUCT,              item->ma_product, CVESEARCH_PRODUCT_LEN) &&
         dbhelper_fetchColInt   (res, row_index, CPESEARCH_COLUMN_VULNERABLE_CVE_COUNT, 0, &item->m_vulnerableCveCount)          &&
         dbhelper_fetchColStrdup(res, row_index, CPESEARCH_COLUMN_PRODUCT_NAMED_BY,     &item->mp_productNamedBy);
}

static bool static_D3FENDFORATTACKFillItem(PGresult* res, int row_index, D3FENDFORATTACKItem_t* item)
{
  assert(res  != NULL);
  assert(item != NULL);
  assert(row_index >= 0 && row_index < PQntuples(res));

  return dbhelper_fetchColStr(res, row_index, D3FENDFORATTACK_COLUMN_DEFENSE_ID,       item->ma_defenseId,       D3FEND_DEFENSE_ID_MAX_LEN)       &&
         dbhelper_fetchColStr(res, row_index, D3FENDFORATTACK_COLUMN_DEFENSE_LABEL,    item->ma_defenseLabel,    D3FEND_DEFENSE_LABEL_MAX_LEN)    &&
         dbhelper_fetchColStr(res, row_index, D3FENDFORATTACK_COLUMN_DEFENSE_TACTIC,   item->ma_defenseTactic,   D3FEND_DEFENSE_TACTIC_MAX_LEN)   &&
         dbhelper_fetchColStr(res, row_index, D3FENDFORATTACK_COLUMN_DIGITAL_ARTIFACT, item->ma_digitalArtifact, D3FEND_DIGITAL_ARTIFACT_MAX_LEN) &&
         dbhelper_fetchColStrdup(res, row_index, D3FENDFORATTACK_COLUMN_PARENT_DEFENSE_LABELS, &item->mp_parentDefenseLabels)                     &&
         dbhelper_fetchColStrdup(res, row_index, D3FENDFORATTACK_COLUMN_ATTACK_TECHNIQUE_IDS,  &item->mp_attackTechniqueIds);
}

static bool static_DRIVERLOOKUPTryFillRecord(PGresult* res, int row, DRIVERLOOKUPRecord_t* record)
{
  assert(res    != NULL);
  assert(record != NULL);
  assert(row >= 0 && row < PQntuples(res));

  return dbhelper_fetchColStr      (res, row, DRIVERLOOKUP_COLUMN_FILE_HASH, record->ma_fileHash, VALIDATE_SHA256_HEX_LEN)  &&
         dbhelper_fetchColInt      (res, row, DRIVERLOOKUP_COLUMN_MATCH_COUNT, 0, &record->m_matchCount)                    &&
         dbhelper_fetchColBool     (res, row, DRIVERLOOKUP_COLUMN_DRIVER_FEED_LOADED, &record->m_isDriverFeedLoaded)        &&
         dbhelper_isColWithinLength(res, row, DRIVERLOOKUP_COLUMN_MATCHES, DRIVERLOOKUP_MATCHES_MAX_LEN)                    &&
         dbhelper_fetchColStrdup   (res, row, DRIVERLOOKUP_COLUMN_MATCHES, &record->mp_matches);
}

static bool static_IPLOOKUPTryFillRecord(PGresult* res, IPLOOKUPRecord_t* record)
{
  assert(res    != NULL);
  assert(record != NULL);
  assert(PQntuples(res) == 1);

  record->m_isCdn     = false;
  record->m_isTorExit = false;

  if (!dbhelper_fetchColBool(res, 0, IPLOOKUP_COLUMN_ASN_FEED_LOADED, &record->m_isAsnFeedLoaded)             ||
      !dbhelper_fetchColBool(res, 0, IPLOOKUP_COLUMN_GEO_FEED_LOADED, &record->m_isGeoFeedLoaded)             ||
      !dbhelper_fetchColBool(res, 0, IPLOOKUP_COLUMN_CLOUD_FEED_LOADED, &record->m_isCloudFeedLoaded)         ||
      !dbhelper_fetchColBool(res, 0, IPLOOKUP_COLUMN_TOR_FEED_LOADED, &record->m_isTorFeedLoaded)             ||
      !dbhelper_fetchColBool(res, 0, IPLOOKUP_COLUMN_DROP_LIST_FEED_LOADED, &record->m_isDropListFeedLoaded))
    return false;

  if (!static_IPLOOKUPTryReadAsn(res, &record->m_asn)                                                                           ||
      !dbhelper_fetchColStr(res, 0, IPLOOKUP_COLUMN_ASN_NAME, record->ma_asnName, IPLOOKUP_ASN_NAME_MAX_LEN)                    ||
      !dbhelper_fetchColStr(res, 0, IPLOOKUP_COLUMN_ASN_COUNTRY, record->ma_asnCountry, IPLOOKUP_COUNTRY_CODE_LEN)              ||
      !dbhelper_fetchColStr(res, 0, IPLOOKUP_COLUMN_GEO_COUNTRY, record->ma_geoCountry, IPLOOKUP_COUNTRY_CODE_LEN)              ||
      !dbhelper_fetchColStr(res, 0, IPLOOKUP_COLUMN_CLOUD_PROVIDER, record->ma_cloudProvider, IPLOOKUP_CLOUD_PROVIDER_MAX_LEN)  ||
      !dbhelper_fetchColStr(res, 0, IPLOOKUP_COLUMN_CLOUD_SERVICE, record->ma_cloudService, IPLOOKUP_CLOUD_SERVICE_MAX_LEN))
    return false;

  bool is_cloud_range_found = record->m_isCloudFeedLoaded && record->ma_cloudProvider[0] != '\0';
  if (is_cloud_range_found && !dbhelper_fetchColBool(res, 0, IPLOOKUP_COLUMN_IS_CDN, &record->m_isCdn))
    return false;
  if (!static_IPLOOKUPTryReadDatacenter(res, record))
    return false;
  if (record->m_isTorFeedLoaded && !dbhelper_fetchColBool(res, 0, IPLOOKUP_COLUMN_IS_TOR_EXIT, &record->m_isTorExit))
    return false;
  if (!record->m_isDropListFeedLoaded)
    return true;

  return !PQgetisnull              (res, 0, IPLOOKUP_COLUMN_LISTED_ON)                             &&
         dbhelper_isColWithinLength(res, 0, IPLOOKUP_COLUMN_LISTED_ON, IPLOOKUP_LISTED_ON_MAX_LEN) &&
         dbhelper_fetchColStrdup   (res, 0, IPLOOKUP_COLUMN_LISTED_ON, &record->mp_listedOn);
}

static bool static_IPLOOKUPTryReadDatacenter(PGresult* res, IPLOOKUPRecord_t* record)
{
  record->m_isDatacenter = false;
  if (PQgetisnull(res, 0, IPLOOKUP_COLUMN_IS_DATACENTER) && !(record->m_isAsnFeedLoaded && record->m_isCloudFeedLoaded))
    return true;
  return dbhelper_fetchColBool(res, 0, IPLOOKUP_COLUMN_IS_DATACENTER, &record->m_isDatacenter);
}

static bool static_EMAILADDRESSCHECKTryFillRecord(PGresult* res, const char* domain, EMAILADDRESSCHECKRecord_t* record)
{
  assert(res    != NULL);
  assert(record != NULL);
  assert(PQntuples(res) == 1);

  if (!dbhelper_fetchColBool(res, 0, EMAILADDRESSCHECK_COLUMN_DISPOSABLE_FEED_LOADED, &record->m_isDisposableFeedLoaded))
    return false;
  if (PQgetisnull(res, 0, EMAILADDRESSCHECK_COLUMN_LISTED_DOMAIN))
    return true;

  if (!record->m_isDisposableFeedLoaded                                                                                                       ||
      !dbhelper_fetchColStr(res, 0, EMAILADDRESSCHECK_COLUMN_LISTED_DOMAIN, record->ma_disposableListedDomain, VALIDATE_DOMAIN_NAME_MAX_LEN)  ||
      !static_EMAILADDRESSCHECKIsDomainUnder(domain, record->ma_disposableListedDomain))
    return false;

  if (etld_findPlusOne(record->ma_disposableListedDomain) == NULL)
    record->ma_disposableListedDomain[0] = '\0';

  return true;
}

static bool static_EMAILADDRESSCHECKIsDomainUnder(const char* domain, const char* listed_domain)
{
  size_t domain_len        = strlen(domain);
  size_t listed_domain_len = strlen(listed_domain);
  if (listed_domain_len == 0 || listed_domain_len > domain_len)
    return false;

  const char* tail_start = domain + domain_len - listed_domain_len;
  if (strcmp(tail_start, listed_domain) != 0)
    return false;

  return listed_domain_len == domain_len || tail_start[-1] == '.';
}

static bool static_SSLCHECKTryFillRecord(PGresult* res, SSLCHECKRecord_t* record)
{
  assert(res    != NULL);
  assert(record != NULL);
  assert(PQntuples(res) == 1);

  if (!dbhelper_fetchColBool(res, 0, SSLCHECK_COLUMN_SSL_BLACKLIST_FEED_LOADED, &record->m_isBlacklistFeedLoaded))
    return false;

  bool is_reason_null = PQgetisnull(res, 0, SSLCHECK_COLUMN_LISTING_REASON);
  bool is_time_null   = PQgetisnull(res, 0, SSLCHECK_COLUMN_LISTING_TIME);
  if (is_reason_null && is_time_null)
    return true;

  if (!record->m_isBlacklistFeedLoaded)
    return false;

  return dbhelper_fetchColStr(res, 0, SSLCHECK_COLUMN_LISTING_REASON, record->ma_blacklistListingReason, SSLCHECK_BLACKLIST_LISTING_REASON_MAX_LEN) &&
         dbhelper_fetchColStr(res, 0, SSLCHECK_COLUMN_LISTING_TIME, record->ma_blacklistListingTime, TLSPROBE_TIME_TEXT_SIZE - 1)                   &&
         record->ma_blacklistListingReason[0] != '\0'                                                                                               &&
         record->ma_blacklistListingTime[0] != '\0';
}

static bool static_IPLOOKUPTryReadAsn(PGresult* res, uint32_t* asn_out)
{
  *asn_out = 0;
  if (PQgetisnull(res, 0, IPLOOKUP_COLUMN_ASN))
    return true;
  if (!isdigit((unsigned char)PQgetvalue(res, 0, IPLOOKUP_COLUMN_ASN)[0]))
    return false;

  char* parse_end; errno = 0;
  unsigned long parsed_asn = strtoul(PQgetvalue(res, 0, IPLOOKUP_COLUMN_ASN), &parse_end, 10);
  if (*parse_end != '\0' || errno != 0 || parsed_asn < 1 || parsed_asn > UINT32_MAX)
    return false;

  *asn_out = (uint32_t)parsed_asn;
  return true;
}

static DbStatus_t static_ASNLOOKUPReadPrefix(PGconn* conn, const char* ip_address, char asn_text_out[DBHELPER_UINT_STR_BUF_SIZE], ASNLOOKUPRecord_t* record)
{
  const char* param_values[] = { ip_address };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_ip_asn_prefix($1)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return DB_ERROR;

  if (!dbhelper_isColumnListEqual(res, ASNLOOKUPPREFIX_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(ASNLOOKUPPREFIX_COLUMN_NAMES)) ||
      PQntuples(res) > 1)
  {
    PQclear(res);
    return DB_ERROR;
  }
  if (PQntuples(res) == 0)
  {
    PQclear(res);
    return DB_NOT_FOUND;
  }

  uint32_t asn;
  bool is_read = dbhelper_fetchColStr(res, 0, ASNLOOKUPPREFIX_COLUMN_ASN, asn_text_out, VALIDATE_ASN_MAX_DIGITS)        &&
                 static_ASNLOOKUPTryParseAsn(asn_text_out, &asn)                                                        &&
                 dbhelper_fetchColStr(res, 0, ASNLOOKUPPREFIX_COLUMN_PREFIX, record->ma_prefix, ASNLOOKUP_PREFIX_MAX_LEN);
  PQclear(res);
  return is_read ? DB_OK : DB_ERROR;
}

static bool static_ASNLOOKUPTryParseAsn(const char* asn_text, uint32_t* asn_out)
{
  *asn_out = 0;
  if (!isdigit((unsigned char)asn_text[0]))
    return false;

  char* parse_end; errno = 0;
  unsigned long parsed_asn = strtoul(asn_text, &parse_end, 10);
  if (*parse_end != '\0' || errno != 0 || parsed_asn < 1 || parsed_asn > UINT32_MAX)
    return false;

  *asn_out = (uint32_t)parsed_asn;
  return true;
}

static bool static_ASNLOOKUPTryFillRecord(PGresult* res, ASNLOOKUPRecord_t* record)
{
  assert(res    != NULL);
  assert(record != NULL);
  assert(PQntuples(res) == 1);

  char asn_text[DBHELPER_UINT_STR_BUF_SIZE];
  if (!dbhelper_fetchColStr(res, 0, ASNLOOKUP_COLUMN_ASN, asn_text, VALIDATE_ASN_MAX_DIGITS)                        ||
      !static_ASNLOOKUPTryParseAsn(asn_text, &record->m_asn)                                                        ||
      !dbhelper_fetchColStr(res, 0, ASNLOOKUP_COLUMN_ASN_NAME, record->ma_asnName, IPLOOKUP_ASN_NAME_MAX_LEN)       ||
      !dbhelper_fetchColStr(res, 0, ASNLOOKUP_COLUMN_ASN_COUNTRY, record->ma_asnCountry, IPLOOKUP_COUNTRY_CODE_LEN))
    return false;

  if (!dbhelper_fetchColInt(res, 0, ASNLOOKUP_COLUMN_IPV4_PREFIX_COUNT, -1, &record->m_ipv4PrefixCount) ||
      !dbhelper_fetchColInt(res, 0, ASNLOOKUP_COLUMN_IPV6_PREFIX_COUNT, -1, &record->m_ipv6PrefixCount) ||
      record->m_ipv4PrefixCount < 0 || record->m_ipv6PrefixCount < 0)
    return false;

  if (PQgetisnull(res, 0, ASNLOOKUP_COLUMN_IPV4_PREFIXES)                                                  ||
      PQgetisnull(res, 0, ASNLOOKUP_COLUMN_IPV6_PREFIXES)                                                  ||
      !dbhelper_isColWithinLength(res, 0, ASNLOOKUP_COLUMN_IPV4_PREFIXES, ASNLOOKUP_PREFIX_ARRAY_MAX_LEN)  ||
      !dbhelper_isColWithinLength(res, 0, ASNLOOKUP_COLUMN_IPV6_PREFIXES, ASNLOOKUP_PREFIX_ARRAY_MAX_LEN))
    return false;

  if (dbhelper_fetchColStrdup(res, 0, ASNLOOKUP_COLUMN_IPV4_PREFIXES, &record->mp_ipv4Prefixes) &&
      dbhelper_fetchColStrdup(res, 0, ASNLOOKUP_COLUMN_IPV6_PREFIXES, &record->mp_ipv6Prefixes))
    return true;

  db_ASNLOOKUPRecordFree(record);
  return false;
}

static bool static_PACKAGECHECKTryFillResult(PGresult* res, PACKAGECHECKResult_t* result)
{
  assert(res    != NULL);
  assert(result != NULL);
  assert(PQntuples(res) == 1);

  return dbhelper_fetchColBool     (res, 0, PACKAGECHECK_COLUMN_ADVISORY_FEED_LOADED, &result->m_isAdvisoryFeedLoaded)                &&
         dbhelper_fetchColBool     (res, 0, PACKAGECHECK_COLUMN_HAS_ADVISORY_DATA, &result->m_hasAdvisoryData)                        &&
         dbhelper_fetchColInt      (res, 0, PACKAGECHECK_COLUMN_RESULT_COUNT, 0, &result->m_resultCount)                              &&
         dbhelper_fetchColStr      (res, 0, PACKAGECHECK_COLUMN_FIXED_VERSION, result->ma_fixedVersion, PACKAGECHECK_VERSION_MAX_LEN) &&
         dbhelper_isColWithinLength(res, 0, PACKAGECHECK_COLUMN_MALICIOUS, PACKAGECHECK_JSON_MAX_LEN)                                 &&
         dbhelper_isColWithinLength(res, 0, PACKAGECHECK_COLUMN_RESULTS, PACKAGECHECK_JSON_MAX_LEN)                                   &&
         dbhelper_isColWithinLength(res, 0, PACKAGECHECK_COLUMN_ATTRIBUTION, PACKAGECHECK_JSON_MAX_LEN)                               &&
         dbhelper_fetchColStrdup   (res, 0, PACKAGECHECK_COLUMN_MALICIOUS, &result->mp_malicious)                                     &&
         dbhelper_fetchColStrdup   (res, 0, PACKAGECHECK_COLUMN_RESULTS, &result->mp_results)                                         &&
         dbhelper_fetchColStrdup   (res, 0, PACKAGECHECK_COLUMN_ATTRIBUTION, &result->mp_attribution);
}

static bool static_KEVLOOKUPTryFillRecord(PGresult* res, KEVLOOKUPRecord_t* rec)
{
  assert(res != NULL);
  assert(rec != NULL);

  if (PQntuples(res) < 1)
  {
    fprintf(stderr, "static_KEVLOOKUPTryFillRecord: the result holds no row\n");
    return false;
  }

  if (!dbhelper_fetchColBool(res, 0, KEVLOOKUP_COLUMN_KNOWN_RANSOMWARE_USE, &rec->m_knownRansomwareUse) ||
      !dbhelper_fetchColBool(res, 0, KEVLOOKUP_COLUMN_IN_KEV,               &rec->m_inKev))
    return false;

  if (!dbhelper_fetchColStr(res, 0, KEVLOOKUP_COLUMN_CVE_ID,             rec->ma_cveId,             CVELOOKUP_ID_MAX_LEN)          ||
      !dbhelper_fetchColStr(res, 0, KEVLOOKUP_COLUMN_VENDOR_PROJECT,     rec->ma_vendorProject,     KEVLOOKUP_VENDOR_LEN)          ||
      !dbhelper_fetchColStr(res, 0, KEVLOOKUP_COLUMN_PRODUCT,            rec->ma_product,           KEVLOOKUP_PRODUCT_LEN)         ||
      !dbhelper_fetchColStr(res, 0, KEVLOOKUP_COLUMN_PATCH_DEADLINE,     rec->ma_patchDeadline,     CVELOOKUP_PUBLISHED_LEN)       ||
      !dbhelper_fetchColStr(res, 0, KEVLOOKUP_COLUMN_REQUIRED_ACTION,    rec->ma_requiredAction,    KEVLOOKUP_REQUIRED_ACTION_LEN) ||
      !dbhelper_fetchColStr(res, 0, KEVLOOKUP_COLUMN_VULNERABILITY_NAME, rec->ma_vulnerabilityName, KEVLOOKUP_VULN_NAME_LEN)       ||
      !dbhelper_fetchColStr(res, 0, KEVLOOKUP_COLUMN_SHORT_DESCRIPTION,  rec->ma_shortDescription,  KEVLOOKUP_SHORT_DESC_LEN)      ||
      !dbhelper_fetchColStr(res, 0, KEVLOOKUP_COLUMN_KEV_DATE_ADDED,     rec->ma_dateAdded,         CVELOOKUP_PUBLISHED_LEN)       ||
      !dbhelper_fetchColStr(res, 0, KEVLOOKUP_COLUMN_DATE_REMOVED,       rec->ma_dateRemoved,       KEVLOOKUP_DATE_REMOVED_LEN)    ||
      !dbhelper_isColWithinLength(res, 0, KEVLOOKUP_COLUMN_CWES, KEVLOOKUP_CWES_MAX_LEN)                                           ||
      !dbhelper_fetchColStrdup(res, 0, KEVLOOKUP_COLUMN_CWES,  &rec->mp_cwes)                                                      ||
      !dbhelper_fetchColStrdup(res, 0, KEVLOOKUP_COLUMN_NOTES, &rec->mp_notes))
  {
    db_KEVLOOKUPRecordFree(rec);
    return false;
  }

  return true;
}

static bool static_CWELOOKUPTryFillRecord(PGresult* res, CWELOOKUPRecord_t* rec)
{
  assert(res != NULL);
  assert(rec != NULL);

  if (PQntuples(res) < 1)
  {
    fprintf(stderr, "static_CWELOOKUPTryFillRecord: the result holds no row\n");
    return false;
  }

  if (!dbhelper_fetchColInt   (res, 0, CWELOOKUP_COLUMN_KEV_CVE_COUNT, 0,   &rec->m_kevCount) ||
      !dbhelper_fetchColDouble(res, 0, CWELOOKUP_COLUMN_AVG_CVSS,      0.0, &rec->m_avgCvss)  ||
      !dbhelper_fetchColDouble(res, 0, CWELOOKUP_COLUMN_AVG_EPSS,      0.0, &rec->m_avgEpss)  ||
      !dbhelper_fetchColInt   (res, 0, CWELOOKUP_COLUMN_CVE_COUNT,     0,   &rec->m_cveCount))
    return false;

  if (!dbhelper_fetchColStr(res, 0, CWELOOKUP_COLUMN_CWE_ID,          rec->ma_cweId, CWELOOKUP_ID_MAX_LEN)            ||
      !dbhelper_fetchColStr(res, 0, CWELOOKUP_COLUMN_CWE_NAME,        rec->ma_name, CWELOOKUP_NAME_LEN)               ||
      !dbhelper_fetchColStr(res, 0, CWELOOKUP_COLUMN_CWE_DESCRIPTION, rec->ma_description, CWELOOKUP_DESC_MAX_LEN)    ||
      !dbhelper_fetchColStr(res, 0, CWELOOKUP_COLUMN_LIKELIHOOD,      rec->ma_likelihood, CWELOOKUP_LIKELIHOOD_LEN)   ||
      !dbhelper_fetchColStr(res, 0, CWELOOKUP_COLUMN_PARENT_CWE,      rec->ma_parentCwe, CWELOOKUP_PARENT_CWE_LEN)    ||
      !dbhelper_fetchColStr(res, 0, CWELOOKUP_COLUMN_UPDATED_AT,      rec->ma_updatedAt, CWELOOKUP_UPDATED_AT_LEN)    ||
      !dbhelper_fetchColStr(res, 0, CWELOOKUP_COLUMN_ABSTRACT_TYPE,   rec->ma_abstraction, CWELOOKUP_ABSTRACTION_LEN) ||
      !dbhelper_fetchColStr(res, 0, CWELOOKUP_COLUMN_CWE_STATUS,      rec->ma_status, CWELOOKUP_STATUS_LEN)           ||
      !dbhelper_isColWithinLength(res, 0, CWELOOKUP_COLUMN_MITIGATIONS,          CWELOOKUP_MITIGATIONS_MAX_LEN)       ||
      !dbhelper_isColWithinLength(res, 0, CWELOOKUP_COLUMN_EXTENDED_DESCRIPTION, CWELOOKUP_EXTENDED_DESC_MAX_LEN)     ||
      !dbhelper_isColWithinLength(res, 0, CWELOOKUP_COLUMN_EXAMPLES,             CWELOOKUP_EXAMPLES_MAX_LEN)          ||
      !dbhelper_fetchColStrdup(res, 0, CWELOOKUP_COLUMN_MITIGATIONS,          &rec->mp_mitigations)                   ||
      !dbhelper_fetchColStrdup(res, 0, CWELOOKUP_COLUMN_EXTENDED_DESCRIPTION, &rec->mp_extendedDescription)           ||
      !dbhelper_fetchColStrdup(res, 0, CWELOOKUP_COLUMN_EXAMPLES,             &rec->mp_examples))
  {
    db_CWELOOKUPRecordFree(rec);
    return false;
  }
  return true;
}
