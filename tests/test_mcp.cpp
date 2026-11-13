#include <stdlib.h>
#include <string.h>

#include <stdio.h>

#include "unity/unity.h"

extern "C" {
#include "mcp.h"
#include "jsonrpc.h"
#include "endpoint.h"
#include "db.h"
#include "jsonbuf.h"
#include "cvss.h"
#include "utf8.h"
#include "request_text.h"
#include "external/hibp.h"
#include "dns.h"
#include "tlsprobe.h"
#include "cache.h"
#include "external/rdap.h"
#include "quota.h"
#include "throttle.h"
#include "external/wayback.h"
#include "wayback_stub.h"
#include "header_fetch_stub.h"
#include "certspotter_stub.h"
#include "subdomain_stub.h"
#include "usagelog.h"
#include "endpoint_run.h"
void* __real_realloc(void* ptr, size_t size);
void* __wrap_realloc(void* ptr, size_t size);
void* __real_malloc(size_t size);
void* __wrap_malloc(size_t size);
int64_t __real_monotonic_nowMs(void);
int64_t __wrap_monotonic_nowMs(void);
}
#include "picohttpparser.h"
#include "version.h"

static const RequestCharge_t TEST_FULL_CHARGE = { .m_chargedCreditCount = ENDPOINT_FULL_CHARGE, .mp_creditBudget = NULL, .mp_x402Payment = NULL };


static bool g_reallocFailsNext = false;

extern "C" void* __wrap_realloc(void* ptr, size_t size)
{
  if (g_reallocFailsNext)
  {
    g_reallocFailsNext = false;
    return NULL;
  }
  return __real_realloc(ptr, size);
}

static volatile size_t g_mallocFailSize      = 0;
static volatile int    g_mallocFailSkipCount = 0;

extern "C" void* __wrap_malloc(size_t size)
{
  if (g_mallocFailSize != 0 && size == g_mallocFailSize)
  {
    if (g_mallocFailSkipCount > 0)
    {
      g_mallocFailSkipCount = g_mallocFailSkipCount - 1;
      return __real_malloc(size);
    }
    g_mallocFailSize = 0;
    return NULL;
  }
  return __real_malloc(size);
}

extern DbStatus_t g_stub_CVELOOKUP_status;
extern DbStatus_t g_stub_CVESEARCH_status;
extern DbStatus_t g_stub_HEALTH_status;
extern int        g_stub_HEALTH_call_count;
extern DbStatus_t g_stub_KEVLOOKUP_status;
extern DbStatus_t g_stub_CWELOOKUP_status;
extern DbStatus_t g_stub_CVERISKSCORE_status;
extern DbStatus_t g_stub_CVETRIAGE_status;
extern DbStatus_t g_stub_CVETRIAGEBULK_status;
extern DbStatus_t g_stub_PRODUCTEXPOSURE_status;
extern PRODUCTEXPOSUREParams_t g_stub_PRODUCTEXPOSURE_last_params;
extern DbStatus_t        g_stub_CPESEARCH_status;
extern CPESEARCHParams_t g_stub_CPESEARCH_last_params;
extern int               g_stub_CPESEARCH_call_count;
extern DbStatus_t          g_stub_CVEPRODUCTS_status;
extern CVEPRODUCTSParams_t g_stub_CVEPRODUCTS_last_params;
extern int                 g_stub_CVEPRODUCTS_call_count;

extern CVESEARCHParams_t g_stub_CVESEARCH_last_params;
extern int          g_stub_CVESEARCH_call_count;
extern int          g_stub_CVELOOKUP_call_count;
extern int          g_stub_CVELOOKUPBULK_call_count;
extern int          g_stub_CVELOOKUPBULK_id_count;
extern int          g_stub_CveListResultFree_call_count;

extern DbStatus_t          g_stub_CVELEADING_status;
extern CVELEADINGParams_t  g_stub_CVELEADING_last_params;
extern int                 g_stub_CVELEADING_call_count;
extern CVETRIAGEParams_t   g_stub_CVETRIAGE_last_params;
extern char                g_stub_CVERISKSCORE_last_cve_id[CVELOOKUP_ID_MAX_LEN + 1];
extern int                 g_stub_CVETRIAGE_call_count;
extern DbStatus_t                    g_stub_WATCHLISTEDIT_status;
extern WATCHLISTEDITStatus_t         g_stub_WATCHLISTEDIT_result_status;
extern WATCHLISTEDITItemsDbParams_t  g_stub_WATCHLISTEDIT_last_params;
extern int                           g_stub_WATCHLISTEDIT_call_count;
extern char                          g_stub_WATCHLISTEDIT_last_registered_domain[];
extern bool                          g_stub_WATCHLISTEDIT_last_has_registered_domain;
extern int                           g_stub_WATCHLISTEDITResultFree_call_count;
extern WATCHLISTEDITPackageElement_t g_stub_WATCHLISTEDIT_last_packages[];
extern int                           g_stub_WATCHLISTEDIT_last_package_count;
extern WATCHLISTEDITPackageRepeat_t  g_stub_WATCHLISTEDIT_package_repeat;
extern DbStatus_t                    g_stub_WATCHLISTEVENTS_status;
extern WATCHLISTEVENTSStatus_t       g_stub_WATCHLISTEVENTS_result_status;
extern WATCHLISTEVENTSParams_t       g_stub_WATCHLISTEVENTS_last_params;
extern int                           g_stub_WATCHLISTEVENTS_last_event_row_count;
extern int                           g_stub_WATCHLISTEVENTS_call_count;
extern int                           g_stub_WATCHLISTEVENTSResultFree_call_count;
extern CveListItem_t*      g_stub_CVESEARCH_items;
extern int                 g_stub_CVESEARCH_item_count;
extern CveListItem_t*      g_stub_CVELEADING_items;
extern int                 g_stub_CVELEADING_item_count;
extern int                 g_stub_CVETRIAGE_item_count;
extern size_t              g_stub_CVELOOKUP_affected_products_len;
extern size_t              g_stub_KEVLOOKUP_cwes_len;
extern size_t              g_stub_CWELOOKUP_mitigations_len;
extern bool                g_stub_HEALTH_full_feeds;

extern DbStatus_t  g_stub_CVELOOKUPGHSA_status;
extern bool        g_stub_CVELOOKUPGHSA_is_feed_loaded;
extern const char* g_stub_CVELOOKUPGHSA_advisory;
extern int         g_stub_CVELOOKUPGHSA_call_count;
extern char        g_stub_CVELOOKUPGHSA_last_cve_id[];
extern const char* g_stub_CVELOOKUP_ransomware;
extern bool g_stub_CVELOOKUP_has_ssvc;

extern bool g_stub_CVEEXPLOIT_escape_heavy;
extern bool g_stub_CVEEXPLOIT_metasploit_unavailable;
extern bool g_stub_CVEEXPLOIT_nvd_unavailable;
extern int  g_stub_CVEEXPLOIT_call_count;

extern "C" HibpStatus_t g_stub_PASSWORDCHECK_status;
extern "C" uint64_t     g_stub_PASSWORDCHECK_breach_count;
extern "C" int          g_stub_PASSWORDCHECK_call_count;
extern "C" char         g_stub_PASSWORDCHECK_last_sha1_hex[VALIDATE_SHA1_HEX_LEN + 1];

extern DbStatus_t g_stub_D3FENDFORATTACK_status;
extern int        g_stub_D3FENDFORATTACK_call_count;
extern char       g_stub_D3FENDFORATTACK_last_id[ATTACK_TECHNIQUE_ID_MAX_LEN + 1];
extern int        g_stub_D3FENDFORATTACKResultFree_call_count;

extern DbStatus_t g_stub_DRIVERLOOKUP_status;
extern int        g_stub_DRIVERLOOKUP_call_count;
extern char       g_stub_DRIVERLOOKUP_last_hash[VALIDATE_SHA256_HEX_LEN + 1];
extern bool       g_stub_DRIVERLOOKUP_last_is_command_included;
extern int        g_stub_DRIVERLOOKUP_match_count;
extern bool       g_stub_DRIVERLOOKUP_is_driver_feed_loaded;
extern int        g_stub_DRIVERLOOKUPRecordFree_call_count;

extern DbStatus_t g_stub_DRIVERLOOKUPBULK_status;
extern int        g_stub_DRIVERLOOKUPBULK_call_count;
extern char       g_stub_DRIVERLOOKUPBULK_last_ids[BULK_MAX_IDS][BULK_ID_MAX_LEN + 1];
extern int        g_stub_DRIVERLOOKUPBULK_last_id_count;
extern int        g_stub_DRIVERLOOKUPBULK_failed_index;
extern int        g_stub_DRIVERLOOKUPBULKResultFree_call_count;
extern size_t     g_stub_DRIVERLOOKUPBULK_matches_len;

extern DbStatus_t           g_stub_PACKAGECHECK_status;
extern PACKAGECHECKParams_t g_stub_PACKAGECHECK_last_params;
extern int                  g_stub_PACKAGECHECK_call_count;
extern bool                 g_stub_PACKAGECHECK_is_advisory_feed_loaded;
extern int                  g_stub_PACKAGECHECKResultFree_call_count;

extern DbStatus_t             g_stub_PACKAGECHECKBULK_status;
extern PACKAGECHECKBULKItem_t g_stub_PACKAGECHECKBULK_last_items[PACKAGECHECKBULK_MAX_ITEMS];
extern int                    g_stub_PACKAGECHECKBULK_last_item_count;
extern int                    g_stub_PACKAGECHECKBULK_call_count;
extern int                    g_stub_PACKAGECHECKBULKResultFree_call_count;

extern "C" DnsLookupStatus_t g_stub_DNSLOOKUP_status;
extern "C" int               g_stub_DNSLOOKUP_call_count;
extern "C" int               g_stub_DNSLOOKUP_free_count;
extern "C" char              g_stub_DNSLOOKUP_last_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];

extern "C" DnsLookupStatus_t g_stub_DNSTAKEOVERCHECK_status;
extern "C" int               g_stub_DNSTAKEOVERCHECK_call_count;
extern "C" char              g_stub_DNSTAKEOVERCHECK_last_hostname[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];

extern "C" DnsLookupStatus_t g_stub_EMAILAUTHCHECK_status;
extern "C" int               g_stub_EMAILAUTHCHECK_call_count;
extern "C" char              g_stub_EMAILAUTHCHECK_last_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern "C" char              g_stub_EMAILAUTHCHECK_last_dkim_selector[VALIDATE_DKIM_SELECTOR_MAX_LEN + 1];

extern DbStatus_t g_stub_EMAILADDRESSCHECK_status;
extern bool       g_stub_EMAILADDRESSCHECK_is_feed_loaded;
extern char       g_stub_EMAILADDRESSCHECK_listed_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern char       g_stub_EMAILADDRESSCHECK_last_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern int        g_stub_EMAILADDRESSCHECK_call_count;

extern DbStatus_t g_stub_SSLCHECK_status;
extern bool       g_stub_SSLCHECK_is_feed_loaded;
extern char       g_stub_SSLCHECK_listing_reason[SSLCHECK_BLACKLIST_LISTING_REASON_MAX_LEN + 1];
extern char       g_stub_SSLCHECK_listing_time[TLSPROBE_TIME_TEXT_SIZE];
extern int        g_stub_SSLCHECK_call_count;

extern "C" DnsLookupStatus_t g_stub_EMAILADDRESSCHECK_dns_status;
extern "C" int               g_stub_EMAILADDRESSCHECK_dns_call_count;
extern "C" int               g_stub_EMAILADDRESSCHECK_free_count;
extern "C" char              g_stub_EMAILADDRESSCHECK_last_dns_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];

extern DbStatus_t g_stub_IPLOOKUP_status;
extern char       g_stub_IPLOOKUP_last_ip_address[INET6_ADDRSTRLEN];
extern int        g_stub_IPLOOKUP_call_count;
extern int        g_stub_IPLOOKUPRecordFree_call_count;

extern DbStatus_t        g_stub_ASNLOOKUP_status;
extern ASNLOOKUPParams_t g_stub_ASNLOOKUP_last_params;
extern int               g_stub_ASNLOOKUP_call_count;
extern int               g_stub_ASNLOOKUPRecordFree_call_count;

extern "C" DnsAnswerStatus_t g_stub_PTR_status;
extern "C" int               g_stub_PTR_call_count;
extern "C" int               g_stub_PTR_free_count;
extern "C" char              g_stub_PTR_last_ip_address[INET6_ADDRSTRLEN];

extern "C" DnsAnswerStatus_t g_stub_ASKQUESTIONS_status;
extern "C" int               g_stub_ASKQUESTIONS_call_count;
extern "C" char              g_stub_ASKQUESTIONS_last_domain_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];

extern "C" const TlsProbeResult_t   g_stub_TLSPROBE_default_result;
extern "C" TlsProbeStatus_t         g_stub_TLSPROBE_status;
extern "C" TlsProbeResult_t         g_stub_TLSPROBE_result;
extern "C" TlsProbeHandshakeError_t g_stub_TLSPROBE_handshake_error;
extern "C" int                      g_stub_TLSPROBE_call_count;
extern "C" char                     g_stub_TLSPROBE_last_hostname[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];

extern "C" CacheStatus_t g_stub_CACHE_get_status;
extern "C" const char*   g_stub_CACHE_get_body;
extern "C" int           g_stub_CACHE_get_count;
extern "C" int           g_stub_CACHE_put_count;
extern "C" int           g_stub_CACHE_free_count;
extern "C" PGconn*       g_stub_CACHE_last_get_conn;
extern "C" char          g_stub_CACHE_last_get_key[CACHE_KEY_MAX_LEN + 1];
extern "C" char          g_stub_CACHE_last_put_key[CACHE_KEY_MAX_LEN + 1];
extern "C" unsigned int  g_stub_CACHE_last_put_expires_after_seconds;

extern "C" const char* const g_stub_RDAP_default_server_base_url;
extern "C" const char*       g_stub_RDAP_server_base_url;
extern "C" RdapStatus_t      g_stub_RDAP_lookup_status;
extern "C" int               g_stub_RDAP_find_count;
extern "C" int               g_stub_RDAP_lookup_count;
extern "C" char              g_stub_RDAP_last_find_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
extern "C" char              g_stub_RDAP_last_lookup_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];

extern "C" QuotaStatus_t g_stub_QUOTA_reserve_status;
extern "C" int           g_stub_QUOTA_reserve_count;
extern "C" PGconn*       g_stub_QUOTA_last_reserve_conn;
extern "C" QuotaRule_t   g_stub_QUOTA_last_reserve_rule;
extern "C" int           g_stub_QUOTA_reserve_status_count;
extern "C" int           g_stub_QUOTA_mark_count;
extern "C" QuotaRule_t   g_stub_QUOTA_last_mark_rule;

extern "C" bool         g_stub_QUOTA_hold_read_result;
extern "C" unsigned int g_stub_QUOTA_hold_seconds;
extern "C" int          g_stub_QUOTA_hold_read_count;
extern "C" PGconn*      g_stub_QUOTA_last_hold_read_conn;
extern "C" char         g_stub_QUOTA_last_hold_read_name[];
extern "C" int          g_stub_QUOTA_hold_set_count;
extern "C" PGconn*      g_stub_QUOTA_last_hold_set_conn;
extern "C" char         g_stub_QUOTA_last_hold_set_name[];
extern "C" unsigned int g_stub_QUOTA_last_hold_set_seconds;

extern "C" unsigned int g_stub_QUOTA_window_remaining_seconds;

extern "C" ThrottleStatus_t g_stub_THROTTLE_charge_status;
extern "C" unsigned int     g_stub_THROTTLE_retry_after_seconds;
extern "C" int              g_stub_THROTTLE_charge_count;
extern "C" PGconn*          g_stub_THROTTLE_last_conn;
extern "C" ThrottleRule_t   g_stub_THROTTLE_last_rule;
extern "C" char             g_stub_THROTTLE_last_target_name[THROTTLE_TARGET_NAME_MAX_LEN + 1];
extern "C" unsigned int     g_stub_THROTTLE_last_charged_count;

extern "C" const WaybackStubAnswer_t g_stub_WAYBACK_default_answers[2];
extern "C" WaybackStubAnswer_t       g_stub_WAYBACK_answers[2];
extern "C" int                       g_stub_WAYBACK_lookup_count;
extern "C" char                      g_stub_WAYBACK_last_lookup_name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];

static PGconn* g_conn = NULL;

static McpRoutingHeaders_t g_routingHeaders;
static bool                g_hasRoutingHeaders = false;

static const McpRoutingHeaders_t* static_installedRoutingHeaders(void)
{
  return g_hasRoutingHeaders ? &g_routingHeaders : NULL;
}

static int64_t g_clockShiftMs = 0;

extern "C" int64_t __wrap_monotonic_nowMs(void)
{
  return __real_monotonic_nowMs() + g_clockShiftMs;
}

void setUp(void)
{
  g_clockShiftMs          += ENDPOINT_RUN_HEALTH_CACHE_TTL_MS;
  g_stub_HEALTH_call_count = 0;
  g_conn = (PGconn*)1;
  g_hasRoutingHeaders = false;
  g_stub_CVELOOKUP_status                 = DB_NOT_FOUND;
  g_stub_CVELOOKUP_call_count             = 0;
  g_stub_CVELOOKUPBULK_call_count         = 0;
  g_stub_CVELOOKUPBULK_id_count           = 0;
  g_stub_CVESEARCH_status                 = DB_ERROR;
  g_stub_HEALTH_status                    = DB_OK;
  g_stub_KEVLOOKUP_status                 = DB_NOT_FOUND;
  g_stub_CWELOOKUP_status                 = DB_NOT_FOUND;
  g_stub_CVERISKSCORE_status              = DB_NOT_FOUND;
  g_stub_CVETRIAGE_status                 = DB_ERROR;
  g_stub_CVETRIAGEBULK_status             = DB_ERROR;
  g_stub_PRODUCTEXPOSURE_status           = DB_ERROR;
  g_stub_CPESEARCH_status                 = DB_ERROR;
  g_stub_CPESEARCH_call_count             = 0;
  memset(&g_stub_CPESEARCH_last_params, 0, sizeof(g_stub_CPESEARCH_last_params));
  g_stub_CVEPRODUCTS_status               = DB_ERROR;
  g_stub_CVEPRODUCTS_call_count           = 0;
  memset(&g_stub_CVEPRODUCTS_last_params, 0, sizeof(g_stub_CVEPRODUCTS_last_params));
  g_stub_CVELOOKUPGHSA_status             = DB_OK;
  g_stub_CVELOOKUPGHSA_is_feed_loaded     = true;
  g_stub_CVELOOKUPGHSA_advisory           = NULL;
  g_stub_CVELOOKUPGHSA_call_count         = 0;
  g_stub_CVELOOKUPGHSA_last_cve_id[0]     = '\0';
  g_stub_CVELOOKUP_ransomware             = "Known";
  g_stub_CVELOOKUP_has_ssvc               = false;
  g_stub_CVELEADING_status                = DB_ERROR;
  memset(&g_stub_CVESEARCH_last_params, 0, sizeof(g_stub_CVESEARCH_last_params));
  memset(g_stub_CVERISKSCORE_last_cve_id, 0, sizeof(g_stub_CVERISKSCORE_last_cve_id));
  g_stub_CVESEARCH_call_count             = 0;
  g_stub_CveListResultFree_call_count     = 0;
  memset(&g_stub_CVELEADING_last_params,  0, sizeof(g_stub_CVELEADING_last_params));
  g_stub_CVELEADING_call_count            = 0;
  memset(&g_stub_CVETRIAGE_last_params,   0, sizeof(g_stub_CVETRIAGE_last_params));
  g_stub_CVETRIAGE_call_count             = 0;
  memset(&g_stub_PRODUCTEXPOSURE_last_params, 0, sizeof(g_stub_PRODUCTEXPOSURE_last_params));
  g_stub_CVESEARCH_items                          = NULL;
  g_stub_WATCHLISTEDIT_status                     = DB_ERROR;
  g_stub_WATCHLISTEDIT_result_status              = WATCHLISTEDIT_OK;
  g_stub_WATCHLISTEDIT_package_repeat             = { .m_currentIndex = -1, .m_earlierIndex = -1 };
  g_stub_WATCHLISTEDIT_call_count                 = 0;
  g_stub_WATCHLISTEDIT_last_registered_domain[0]  = '\0';
  g_stub_WATCHLISTEDIT_last_has_registered_domain = false;
  g_stub_WATCHLISTEDITResultFree_call_count       = 0;
  memset(&g_stub_WATCHLISTEDIT_last_params, 0, sizeof(g_stub_WATCHLISTEDIT_last_params));
  g_stub_WATCHLISTEVENTS_status           = DB_ERROR;
  g_stub_WATCHLISTEVENTS_result_status    = WATCHLISTEVENTS_OK;
  g_stub_WATCHLISTEVENTS_call_count       = 0;
  g_stub_WATCHLISTEVENTSResultFree_call_count = 0;
  g_stub_WATCHLISTEVENTS_last_event_row_count = 0;
  memset(&g_stub_WATCHLISTEVENTS_last_params, 0, sizeof(g_stub_WATCHLISTEVENTS_last_params));
  g_stub_CVESEARCH_item_count             = 0;
  g_stub_CVELEADING_items                 = NULL;
  g_stub_CVELEADING_item_count            = 0;
  g_stub_CVETRIAGE_item_count             = 1;
  g_stub_CVELOOKUP_affected_products_len  = 0;
  g_stub_KEVLOOKUP_cwes_len               = 0;
  g_stub_HEALTH_full_feeds                = false;
  g_stub_CWELOOKUP_mitigations_len        = 0;
  g_stub_CVEEXPLOIT_escape_heavy          = false;
  g_stub_CVEEXPLOIT_metasploit_unavailable = false;
  g_stub_CVEEXPLOIT_nvd_unavailable       = false;
  g_stub_CVEEXPLOIT_call_count            = 0;
  g_stub_PASSWORDCHECK_status             = HIBP_OK;
  g_stub_PASSWORDCHECK_breach_count       = 0;
  g_stub_PASSWORDCHECK_call_count         = 0;
  memset(g_stub_PASSWORDCHECK_last_sha1_hex, 0, sizeof(g_stub_PASSWORDCHECK_last_sha1_hex));
  g_stub_D3FENDFORATTACK_status           = DB_ERROR;
  g_stub_D3FENDFORATTACK_call_count       = 0;
  g_stub_D3FENDFORATTACK_last_id[0]       = '\0';
  g_stub_D3FENDFORATTACKResultFree_call_count = 0;
  g_stub_DRIVERLOOKUP_status              = DB_ERROR;
  g_stub_DRIVERLOOKUP_call_count          = 0;
  g_stub_DRIVERLOOKUP_last_hash[0]        = '\0';
  g_stub_DRIVERLOOKUP_last_is_command_included = false;
  g_stub_DRIVERLOOKUP_match_count         = 1;
  g_stub_DRIVERLOOKUP_is_driver_feed_loaded = true;
  g_stub_DRIVERLOOKUPRecordFree_call_count = 0;
  g_stub_DRIVERLOOKUPBULK_status          = DB_ERROR;
  g_stub_DRIVERLOOKUPBULK_call_count      = 0;
  g_stub_DRIVERLOOKUPBULK_last_id_count   = 0;
  g_stub_DRIVERLOOKUPBULK_failed_index    = -1;
  g_stub_DRIVERLOOKUPBULKResultFree_call_count = 0;
  g_stub_DRIVERLOOKUPBULK_matches_len     = 0;
  g_stub_PACKAGECHECK_status              = DB_ERROR;
  memset(&g_stub_PACKAGECHECK_last_params, 0, sizeof(g_stub_PACKAGECHECK_last_params));
  g_stub_PACKAGECHECK_call_count          = 0;
  g_stub_PACKAGECHECK_is_advisory_feed_loaded = true;
  g_stub_PACKAGECHECKResultFree_call_count = 0;
  g_stub_PACKAGECHECKBULK_status          = DB_ERROR;
  g_stub_PACKAGECHECKBULK_last_item_count = 0;
  g_stub_PACKAGECHECKBULK_call_count      = 0;
  g_stub_PACKAGECHECKBULKResultFree_call_count = 0;
  g_stub_DNSLOOKUP_status                 = DNS_LOOKUP_OK;
  g_stub_DNSLOOKUP_call_count             = 0;
  g_stub_DNSLOOKUP_free_count             = 0;
  memset(g_stub_DNSLOOKUP_last_domain, 0, sizeof(g_stub_DNSLOOKUP_last_domain));
  g_stub_DNSTAKEOVERCHECK_status             = DNS_LOOKUP_OK;
  g_stub_DNSTAKEOVERCHECK_call_count         = 0;
  memset(g_stub_DNSTAKEOVERCHECK_last_hostname, 0, sizeof(g_stub_DNSTAKEOVERCHECK_last_hostname));
  g_stub_EMAILAUTHCHECK_status               = DNS_LOOKUP_OK;
  g_stub_EMAILAUTHCHECK_call_count           = 0;
  memset(g_stub_EMAILAUTHCHECK_last_domain, 0, sizeof(g_stub_EMAILAUTHCHECK_last_domain));
  memset(g_stub_EMAILAUTHCHECK_last_dkim_selector, 0, sizeof(g_stub_EMAILAUTHCHECK_last_dkim_selector));
  g_stub_SSLCHECK_status                     = DB_OK;
  g_stub_SSLCHECK_is_feed_loaded             = true;
  g_stub_SSLCHECK_call_count                 = 0;
  memset(g_stub_SSLCHECK_listing_reason, 0, sizeof(g_stub_SSLCHECK_listing_reason));
  memset(g_stub_SSLCHECK_listing_time, 0, sizeof(g_stub_SSLCHECK_listing_time));
  g_stub_EMAILADDRESSCHECK_status            = DB_ERROR;
  g_stub_EMAILADDRESSCHECK_is_feed_loaded    = true;
  g_stub_EMAILADDRESSCHECK_call_count        = 0;
  memset(g_stub_EMAILADDRESSCHECK_listed_domain, 0, sizeof(g_stub_EMAILADDRESSCHECK_listed_domain));
  memset(g_stub_EMAILADDRESSCHECK_last_domain, 0, sizeof(g_stub_EMAILADDRESSCHECK_last_domain));
  g_stub_EMAILADDRESSCHECK_dns_status        = DNS_LOOKUP_OK;
  g_stub_EMAILADDRESSCHECK_dns_call_count    = 0;
  g_stub_EMAILADDRESSCHECK_free_count        = 0;
  memset(g_stub_EMAILADDRESSCHECK_last_dns_domain, 0, sizeof(g_stub_EMAILADDRESSCHECK_last_dns_domain));
  g_stub_IPLOOKUP_status                     = DB_ERROR;
  g_stub_IPLOOKUP_call_count                 = 0;
  g_stub_IPLOOKUPRecordFree_call_count       = 0;
  memset(g_stub_IPLOOKUP_last_ip_address, 0, sizeof(g_stub_IPLOOKUP_last_ip_address));
  g_stub_ASNLOOKUP_status                    = DB_ERROR;
  g_stub_ASNLOOKUP_call_count                = 0;
  g_stub_ASNLOOKUPRecordFree_call_count      = 0;
  memset(&g_stub_ASNLOOKUP_last_params, 0, sizeof(g_stub_ASNLOOKUP_last_params));
  g_stub_PTR_status                          = DNS_ANSWER_OK;
  g_stub_PTR_call_count                      = 0;
  g_stub_PTR_free_count                      = 0;
  memset(g_stub_PTR_last_ip_address, 0, sizeof(g_stub_PTR_last_ip_address));
  g_stub_ASKQUESTIONS_status                 = DNS_ANSWER_OK;
  g_stub_ASKQUESTIONS_call_count             = 0;
  memset(g_stub_ASKQUESTIONS_last_domain_name, 0, sizeof(g_stub_ASKQUESTIONS_last_domain_name));
  g_stub_TLSPROBE_status                     = TLSPROBE_OK;
  g_stub_TLSPROBE_result                     = g_stub_TLSPROBE_default_result;
  g_stub_TLSPROBE_handshake_error            = TLSPROBE_HANDSHAKE_ERROR_NONE;
  g_stub_TLSPROBE_call_count                 = 0;
  memset(g_stub_TLSPROBE_last_hostname, 0, sizeof(g_stub_TLSPROBE_last_hostname));
  g_stub_CACHE_get_status                    = CACHE_MISS;
  g_stub_CACHE_get_body                      = "{}\n";
  g_stub_CACHE_get_count                     = 0;
  g_stub_CACHE_put_count                     = 0;
  g_stub_CACHE_free_count                    = 0;
  g_stub_CACHE_last_get_conn                 = NULL;
  g_stub_CACHE_last_get_key[0]               = '\0';
  g_stub_CACHE_last_put_key[0]               = '\0';
  g_stub_RDAP_server_base_url                = g_stub_RDAP_default_server_base_url;
  g_stub_RDAP_lookup_status                  = RDAP_OK;
  g_stub_RDAP_find_count                     = 0;
  g_stub_RDAP_lookup_count                   = 0;
  g_stub_RDAP_last_find_name[0]              = '\0';
  g_stub_RDAP_last_lookup_name[0]            = '\0';
  g_stub_QUOTA_reserve_status                = QUOTA_GRANTED;
  g_stub_QUOTA_reserve_count                 = 0;
  g_stub_QUOTA_last_reserve_conn             = NULL;
  memset(&g_stub_QUOTA_last_reserve_rule, 0, sizeof(g_stub_QUOTA_last_reserve_rule));
  g_stub_QUOTA_reserve_status_count          = 0;
  g_stub_QUOTA_mark_count                    = 0;
  memset(&g_stub_QUOTA_last_mark_rule, 0, sizeof(g_stub_QUOTA_last_mark_rule));
  g_stub_QUOTA_hold_read_result              = true;
  g_stub_QUOTA_hold_seconds                  = 0;
  g_stub_QUOTA_hold_read_count               = 0;
  g_stub_QUOTA_last_hold_read_conn           = NULL;
  g_stub_QUOTA_last_hold_read_name[0]        = '\0';
  g_stub_QUOTA_hold_set_count                = 0;
  g_stub_QUOTA_last_hold_set_conn            = NULL;
  g_stub_QUOTA_last_hold_set_name[0]         = '\0';
  g_stub_QUOTA_last_hold_set_seconds         = 0;
  g_stub_QUOTA_window_remaining_seconds      = 0;
  g_stub_THROTTLE_charge_status              = THROTTLE_CHARGED;
  g_stub_THROTTLE_retry_after_seconds        = 0;
  g_stub_THROTTLE_charge_count               = 0;
  g_stub_THROTTLE_last_conn                  = NULL;
  g_stub_THROTTLE_last_target_name[0]        = '\0';
  g_stub_THROTTLE_last_charged_count         = 0;
  memset(&g_stub_THROTTLE_last_rule, 0, sizeof(g_stub_THROTTLE_last_rule));
  memcpy(g_stub_WAYBACK_answers, g_stub_WAYBACK_default_answers, sizeof(g_stub_WAYBACK_answers));
  g_stub_WAYBACK_lookup_count                   = 0;
  g_stub_HEADER_FETCH_error                     = HTTP_ERROR_NONE;
  g_stub_HEADER_FETCH_answer                    = g_stub_HEADER_FETCH_default_answer;
  g_stub_HEADER_FETCH_call_count                = 0;
  g_stub_HEADER_FETCH_last_hostname[0]          = '\0';
  g_stub_HEADER_FETCH_free_count                = 0;
  g_stub_HEADER_FETCH_on_call                   = NULL;
  g_stub_WAYBACK_last_lookup_name[0]            = '\0';
  g_stub_CERTSPOTTER_answer                     = g_stub_CERTSPOTTER_default_answer;
  g_stub_CERTSPOTTER_lookup_count               = 0;
  g_stub_CERTSPOTTER_last_lookup_name[0]        = '\0';
  g_stub_CERTSPOTTER_on_call                    = NULL;
  g_stub_CERTSPOTTER_subtree_answer             = g_stub_CERTSPOTTER_default_subtree_answer;
  g_stub_CERTSPOTTER_subtree_lookup_count       = 0;
  g_stub_CERTSPOTTER_last_subtree_domain[0]     = '\0';
  g_stub_SUBDOMAIN_dns_answer                   = g_stub_SUBDOMAIN_default_dns_answer;
  g_stub_SUBDOMAIN_lookup_count                 = 0;
  g_stub_SUBDOMAIN_last_lookup_domain[0]        = '\0';
  g_stub_SUBDOMAIN_create_fails                 = false;
  g_reallocFailsNext                      = false;
  g_mallocFailSize                        = 0;
  g_mallocFailSkipCount                   = 0;
}
void tearDown(void) {}

static char* static_dispatch(const char* body, int* status)
{
  char* out = NULL;
  *status = -1;
  TEST_ASSERT_TRUE(mcp_dispatch(body, strlen(body), static_installedRoutingHeaders(), &out, status, g_conn, &TEST_FULL_CHARGE, NULL));
  return out;
}

static void static_assertContains(const char* haystack, const char* needle)
{
  TEST_ASSERT_NOT_NULL_MESSAGE(haystack, "response was NULL");
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(haystack, needle), needle);
}

static void static_assertEndsWith(const char* haystack, const char* suffix)
{
  TEST_ASSERT_NOT_NULL_MESSAGE(haystack, "response was NULL");
  size_t haystack_len = strlen(haystack);
  size_t suffix_len   = strlen(suffix);
  TEST_ASSERT_TRUE_MESSAGE(haystack_len >= suffix_len && strcmp(haystack + haystack_len - suffix_len, suffix) == 0, suffix);
}

static void static_assertToolSucceeded(char* response, int status)
{
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":false)");
  TEST_ASSERT_NULL(strstr(response, "-32603"));
  free(response);
}

static void static_assertToolInternalError(char* response, int status)
{
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "-32603");
  TEST_ASSERT_NULL(strstr(response, R"("isError":false)"));
  free(response);
}

static void static_assertToolRefusedBeforeDb(char* response, int status, const char* message, int db_call_count)
{
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  if (message != NULL)
    static_assertContains(response, message);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, db_call_count, "a refused argument must not reach db");
  free(response);
}

void test_initialize_echoes_supported_version(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":1,"method":"initialize",)"
                     R"("params":{"protocolVersion":"2025-06-18","capabilities":{}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("protocolVersion":"2025-06-18")");
  static_assertContains(response, R"("serverInfo")");
  static_assertContains(response, R"("id":1)");
  TEST_ASSERT_NULL(strstr(response, R"("error")"));
  free(response);
}

void test_initialize_negotiates_latest(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":1,"method":"initialize",)"
                     R"("params":{"protocolVersion":"2025-11-25","capabilities":{}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("protocolVersion":"2025-11-25")");
  free(response);
}

void test_initialize_unknown_version_falls_back(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":1,"method":"initialize",)"
                     R"("params":{"protocolVersion":"1999-01-01","capabilities":{}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("protocolVersion":"2025-11-25")");
  free(response);
}

void test_initialize_no_version_uses_default(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":1,"method":"initialize"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("protocolVersion":"2025-11-25")");
  static_assertContains(response, R"("serverInfo")");
  free(response);
}

void test_initialize_echoes_only_an_exact_supported_version(void)
{
  static const struct { const char* mp_version; const char* mp_expected; } cases[] = {
    { R"("2025-03-26")",                                         "2025-03-26" },
    { R"("2025-06-18")",                                         "2025-06-18" },
    { R"("2025-06-18-rc1")",                                     "2025-11-25" },
    { R"("2025-06-18xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")", "2025-11-25" },
    { "20250618",                                                "2025-11-25" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char body[256];
    snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":%s}})", cases[i].mp_version);
    int   status;
    char* response = static_dispatch(body, &status);
    char  expected[64];
    snprintf(expected, sizeof(expected), R"("protocolVersion":"%s")", cases[i].mp_expected);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, cases[i].mp_version);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, expected), cases[i].mp_version);
    free(response);
  }
}

void test_server_version_is_one_value_in_initialize_and_health(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":1,"method":"initialize"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("version":")" CONTRASTAPI_VERSION R"(")");
  free(response);

  response = static_dispatch(R"({"jsonrpc":"2.0","id":2,"method":"tools/call",)"
               R"("params":{"name":"health"}})", &status);
  static_assertContains(response, R"(\"version\":\")" CONTRASTAPI_VERSION R"(\")");
  static_assertToolSucceeded(response, status);
}

void test_protocol_version_and_instructions_are_shared_from_mcp_h(void)
{
  TEST_ASSERT_EQUAL_STRING("2025-11-25", MCP_PROTOCOL_VERSION);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":1,"method":"initialize"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("protocolVersion":")" MCP_PROTOCOL_VERSION R"(")");
  static_assertContains(response, R"("instructions":")" MCP_SERVER_INSTRUCTIONS R"(")");
  free(response);
}

void test_tool_count_is_the_number_of_tools_listed(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":1,"method":"tools/list"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  int listed_tool_count = 0;
  for (const char* cursor = response; (cursor = strstr(cursor, R"("inputSchema")")) != NULL; cursor++)
    listed_tool_count++;
  TEST_ASSERT_EQUAL_INT(37, listed_tool_count);
  TEST_ASSERT_EQUAL_INT(listed_tool_count, endpoint_mcpToolCount());
  free(response);
}

static char* static_dispatchInitializeWithParamsLength(size_t params_len, int* status)
{
  const char* params_head = R"({"protocolVersion":"2025-06-18","pad":")";
  const char* params_tail = R"("})";
  const char* body_head   = R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":)";
  size_t      pad_len     = params_len - strlen(params_head) - strlen(params_tail);
  size_t      body_size   = strlen(body_head) + params_len + sizeof("}");

  char* body = (char*)malloc(body_size);
  TEST_ASSERT_NOT_NULL(body);
  size_t pos = 0;
  pos += (size_t)snprintf(body + pos, body_size - pos, "%s%s", body_head, params_head);
  memset(body + pos, 'a', pad_len);
  pos += pad_len;
  snprintf(body + pos, body_size - pos, "%s}", params_tail);
  TEST_ASSERT_EQUAL_size_t(body_size - 1, strlen(body));

  char* response = static_dispatch(body, status);
  free(body);
  return response;
}

void test_initialize_params_of_any_length_negotiate(void)
{
  size_t longest_params_len = ENDPOINT_MCP_MAX_BODY_BYTE_COUNT - strlen(R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":)") - strlen("}");
  size_t params_lens[]      = { 4096, longest_params_len };
  for (size_t i = 0; i < sizeof(params_lens) / sizeof(params_lens[0]); i++)
  {
    int   status;
    char* response = static_dispatchInitializeWithParamsLength(params_lens[i], &status);
    TEST_ASSERT_EQUAL_INT(200, status);
    static_assertContains(response, R"("protocolVersion":"2025-06-18")");
    free(response);
  }
}

void test_initialize_reads_only_a_top_level_protocol_version(void)
{
  static const struct {
    const char* mp_params;
    const char* mp_expected;
  } cases[] = {
    { R"({"clientInfo":{"protocolVersion":"2025-03-26"},"protocolVersion":"2025-06-18"})", R"("protocolVersion":"2025-06-18")" },
    { R"({"clientInfo":{"protocolVersion":"2025-06-18"}})",                                R"("protocolVersion":"2025-11-25")" },
    { R"([{"protocolVersion":"2025-06-18"}])",                                             R"("protocolVersion":"2025-11-25")" },
    { R"({"x\"protocolVersion":"2025-03-26","protocolVersion":"2025-06-18"})",            R"("protocolVersion":"2025-06-18")" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char body[256];
    int  body_len = snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":%s})", cases[i].mp_params);
    TEST_ASSERT_TRUE(body_len > 0 && (size_t)body_len < sizeof(body));

    int   status;
    char* response = static_dispatch(body, &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, cases[i].mp_params);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, cases[i].mp_expected), cases[i].mp_params);
    TEST_ASSERT_NULL_MESSAGE(strstr(response, "2025-03-26"), cases[i].mp_params);
    free(response);
  }
}

void test_tools_list(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("tools":[)");
  static_assertContains(response, R"("name":"cve_lookup")");
  static_assertContains(response, R"("name":"cve_exploit")");
  static_assertContains(response, R"("inputSchema")");
  free(response);
}

static void static_appendToExpected(char* expected, size_t expected_size, size_t* used, const char* text)
{
  size_t text_len = strlen(text);
  TEST_ASSERT_TRUE_MESSAGE(*used < expected_size && text_len < expected_size - *used, "the expected document does not fit in its buffer");
  memcpy(expected + *used, text, text_len + 1);
  *used += text_len;
}

void test_tools_list_is_the_whole_catalogue(void)
{
  static const char* const tools[] = {
    R"json({"name":"health","title":"Health and Data Freshness","description":"Database freshness: CVE/KEV/CWE counts and latest entries, and the sync state of each upstream feed. Costs no credits.",)json"
      R"json("inputSchema":{"type":"object","properties":{},"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"Operations"}})json",
    R"json({"name":"cve_lookup","title":"CVE Lookup","description":"Full CVE record by ID (CVSS, EPSS, KEV, CWE, references, CISA SSVC, Nuclei templates), with the optional GitHub Security Advisory. Call the cve_products tool for every affected product. If your SSVC level is unknown, read high.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("cve_id":{"type":"string","maxLength":24,"description":"CVE ID, e.g. CVE-2021-44228"},)json"
      R"json("include_ghsa":{"type":"boolean","description":"Add the GitHub Security Advisory of the CVE, from the local copy of the GitHub Advisory Database"})json"
      R"json(},"required":["cve_id"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"CVE Intelligence"}})json",
    R"json({"name":"cve_lookup_bulk","title":"Bulk CVE Lookup","description":"Look up many CVEs at once, each with the fields of cve_lookup. Ids beyond the remaining credits come back in not_processed.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("cve_ids":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":50,"description":"CVE IDs"})json"
      R"json(},"required":["cve_ids"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"CVE Intelligence"}})json",
    R"json({"name":"cve_products","title":"CVE Affected Products","description":"The products a CVE affects, one page at a time, with the vulnerable products first. The vendor and product arguments keep only the products with that exact name.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("cve_id":{"type":"string","maxLength":24,"description":"CVE ID, e.g. CVE-2021-44228"},)json"
      R"json("vendor":{"type":"string","maxLength":128,"description":"Exact vendor name, as affected_products writes it"},)json"
      R"json("product":{"type":"string","maxLength":128,"description":"Exact product name, as affected_products writes it"},)json"
      R"json("limit":{"type":"integer","minimum":1,"maximum":50,"default":20},)json"
      R"json("offset":{"type":"integer","minimum":0,"default":0})json"
      R"json(},"required":["cve_id"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"CVE Intelligence"}})json",
    R"json({"name":"cve_search","title":"CVE Search","description":"Search CVEs by severity, CWE, CVSS, EPSS, CISA KEV, ransomware use, Nuclei template, vendor, product and publish date, one page at a time. Call the cve_lookup tool for a full record, and the cpe_search tool to find the names.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("severity":{"type":"string","enum":["CRITICAL","HIGH","MEDIUM","LOW","NONE"],"maxLength":16},)json"
      R"json("vendor":{"type":"string","maxLength":128},)json"
      R"json("product":{"type":"string","maxLength":128},)json"
      R"json("cwe_id":{"type":"string","maxLength":16,"description":"e.g. CWE-79"},)json"
      R"json("min_cvss":{"type":"number","minimum":0,"maximum":10,"description":"CVSS v3, or v4 when a CVE has no v3"},)json"
      R"json("min_epss":{"type":"number","minimum":0,"maximum":1},)json"
      R"json("in_kev":{"type":"boolean"},)json"
      R"json("known_ransomware":{"type":"boolean","const":true,"description":"Only CVEs whose CISA KEV entry notes known ransomware use"},)json"
      R"json("has_nuclei_template":{"type":"boolean","const":true,"description":"Only CVEs with a Nuclei detection template"},)json"
      R"json("published_after":{"type":"string","maxLength":31,"description":"YYYY-MM-DD"},)json"
      R"json("published_before":{"type":"string","maxLength":31,"description":"YYYY-MM-DD"},)json"
      R"json("include_rejected":{"type":"boolean","description":"Also list the CVEs that NVD marks Rejected"},)json"
      R"json("sort":{"type":"string","enum":["published_time","epss","cvss"],"maxLength":15},)json"
      R"json("limit":{"type":"integer","minimum":1,"maximum":100,"default":20},)json"
      R"json("offset":{"type":"integer","minimum":0,"maximum":10000,"default":0})json"
      R"json(},"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"CVE Intelligence"}})json",
    R"json({"name":"cve_leading","title":"Leading CVEs by EPSS","description":"List the CVEs most likely to be exploited, by EPSS score (the probability of exploitation in the next 30 days), with a verdict on the top score. To rank by composite risk score, call the cve_triage tool.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("vendor":{"type":"string","maxLength":128},)json"
      R"json("product":{"type":"string","maxLength":128},)json"
      R"json("min_epss":{"type":"number","minimum":0,"maximum":1},)json"
      R"json("in_kev":{"type":"boolean"},)json"
      R"json("known_ransomware":{"type":"boolean","const":true,"description":"Only CVEs whose CISA KEV entry notes known ransomware use"},)json"
      R"json("has_nuclei_template":{"type":"boolean","const":true,"description":"Only CVEs with a Nuclei detection template"},)json"
      R"json("include_rejected":{"type":"boolean","description":"Also list the CVEs that NVD marks Rejected"},)json"
      R"json("limit":{"type":"integer","minimum":1,"maximum":50,"default":20})json"
      R"json(},"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"CVE Intelligence"}})json",
    R"json({"name":"kev_lookup","title":"CISA KEV Lookup","description":"CISA KEV catalog entry for a CVE: the required action, the patch deadline and known ransomware use. A CVE that CISA removed answers in_kev false, and one never listed answers \"KEV entry not found\".",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("cve_id":{"type":"string","maxLength":24,"description":"CVE ID"})json"
      R"json(},"required":["cve_id"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"CVE Intelligence"}})json",
    R"json({"name":"cwe_lookup","title":"CWE Lookup","description":"CWE weakness details (description, mitigations, examples), with how many CVEs and CISA KEV entries name it. To list them, call the cve_search tool with its cwe_id argument.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("cwe_id":{"type":"string","maxLength":16,"description":"CWE ID, e.g. CWE-79"})json"
      R"json(},"required":["cwe_id"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"CVE Intelligence"}})json",
    R"json({"name":"cve_risk_score","title":"CVE Risk Score","description":"Composite risk score of a CVE, from 0 to 100, for patch priority. It reads EPSS, CISA KEV, Metasploit, CVSS, NVD exploit references and ExploitDB. has_public_poc is null when no source names an exploit.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("cve_id":{"type":"string","maxLength":24,"description":"CVE ID"})json"
      R"json(},"required":["cve_id"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"CVE Intelligence"}})json",
    R"json({"name":"cve_exploit","title":"CVE Exploit Intelligence","description":"Public exploit intelligence (GitHub PoCs, Metasploit, NVD exploit references, ExploitDB). GitHub PoC repositories are listed but not counted as proof of a public exploit.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("cve_id":{"type":"string","maxLength":24,"description":"CVE ID"})json"
      R"json(},"required":["cve_id"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"CVE Intelligence"}})json",
    R"json({"name":"cve_triage","title":"CVE Triage","description":"Rank the CVEs of a vendor or product by composite risk score, at or above the optional min_risk_score argument, as lean rows (cve_id, risk_score, label). Call the cve_lookup tool for detail, and the cpe_search tool to find the names.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("vendor":{"type":"string","maxLength":128},)json"
      R"json("product":{"type":"string","maxLength":128},)json"
      R"json("min_risk_score":{"type":"number","minimum":0,"maximum":100,"description":"Composite risk-score threshold"},)json"
      R"json("include_rejected":{"type":"boolean","description":"Also list the CVEs that NVD marks Rejected"},)json"
      R"json("limit":{"type":"integer","minimum":1,"maximum":100,"default":20},)json"
      R"json("offset":{"type":"integer","minimum":0,"maximum":10000,"default":0})json"
      R"json(},"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"CVE Intelligence"}})json",
    R"json({"name":"cve_triage_bulk","title":"Bulk CVE Triage","description":"Triage many CVEs at once, ranked by composite risk score. Ids beyond the remaining credits come back in not_processed.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("cve_ids":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":50,"description":"CVE IDs"})json"
      R"json(},"required":["cve_ids"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"CVE Intelligence"}})json",
    R"json({"name":"product_exposure","title":"Product Exposure","description":"CVE exposure of one vendor and product: severity, KEV and PoC counts, CVSS, EPSS, the worst risk score, the top CVEs and the endoflife.date support dates. To find the names, call the cpe_search tool.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("vendor":{"type":"string","maxLength":128},)json"
      R"json("product":{"type":"string","maxLength":128},)json"
      R"json("version":{"type":"string","maxLength":128,"description":"Product version, e.g. 22.21.1 or 11-24h2; picks the release cycle of eol"},)json"
      R"json("include_rejected":{"type":"boolean","description":"Also count and list the CVEs that NVD marks Rejected"})json"
      R"json(},"required":["vendor","product"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"CVE Intelligence"}})json",
    R"json({"name":"cpe_search","title":"CPE Search","description":"Find the CPE vendor and product names that hold a text, ranked by vulnerable CVE count. Pass a name that holds no % as it is to the vendor and product arguments of the cve_search, cve_triage, cve_leading and product_exposure tools.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("search":{"type":"string","maxLength":128,"description":"Text in vendor or product names, at least 3 bytes; case does not matter, and _ matches a space"},)json"
      R"json("limit":{"type":"integer","minimum":1,"maximum":50,"default":20},)json"
      R"json("offset":{"type":"integer","minimum":0,"maximum":10000,"default":0})json"
      R"json(},"required":["search"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"CVE Intelligence"}})json",
    R"json({"name":"cvss_calculator","title":"CVSS Calculator","description":"Decode a CVSS v3.0/v3.1 vector into its base metrics and recompute its base, temporal and environmental scores.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("vector":{"type":"string","maxLength":127,"description":"CVSS v3.0/v3.1 vector, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})json"
      R"json(},"required":["vector"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"CVE Intelligence"}})json",
    R"json({"name":"watchlist_edit","title":"Watchlist: CVE, Package, Domain and IP Monitoring","description":"Add, remove, list or clear the items this API key watches: CVEs, products, CVE searches, packages, domains and IP addresses. Read their changes with the watchlist_events tool. Requires a Pro API key.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("action":{"type":"string","enum":["add","remove"],"maxLength":8,"description":"add or remove; leave out to list the items"},)json"
      R"json("endpoint":{"type":"string","enum":["cve_lookup","kev_lookup","cve_exploit","product_exposure","cve_search","dns_lookup","ssl_check","whois_lookup","headers_check","cert_search","package_check","ip_lookup"],"maxLength":16,"description":"The tool the item watches"},)json"
      R"json("cve_id":{"type":"string","maxLength":24,"description":"For a cve_lookup, kev_lookup or cve_exploit item, e.g. CVE-2021-44228"},)json"
      R"json("vendor":{"type":"string","maxLength":128,"description":"Vendor, for a product_exposure or cve_search item"},)json"
      R"json("product":{"type":"string","maxLength":128,"description":"Product, for a product_exposure or cve_search item"},)json"
      R"json("severity":{"type":"string","enum":["CRITICAL","HIGH","MEDIUM","LOW","NONE"],"maxLength":16,"description":"cve_search items only"},)json"
      R"json("cwe_id":{"type":"string","maxLength":16,"description":"cve_search items only, e.g. CWE-79"},)json"
      R"json("min_cvss":{"type":"number","minimum":0,"maximum":10,"description":"CVSS v3, or v4 when a CVE has no v3; cve_search items only"},)json"
      R"json("min_epss":{"type":"number","minimum":0,"maximum":1,"description":"At most three decimals; cve_search items only"},)json"
      R"json("in_kev":{"type":"boolean","description":"cve_search items only"},)json"
      R"json("known_ransomware":{"type":"boolean","const":true,"description":"cve_search items only"},)json"
      R"json("has_nuclei_template":{"type":"boolean","const":true,"description":"cve_search items only"},)json"
      R"json("domain":{"type":"string","maxLength":253,"description":"For a dns_lookup, ssl_check, whois_lookup, headers_check or cert_search item, such as example.com"},)json"
      R"json("ecosystem":{"type":"string","maxLength":16,"description":"For a package_check item: npm, PyPI, Maven, Go, NuGet, RubyGems, crates.io, Packagist or SwiftURL"},)json"
      R"json("name":{"type":"string","maxLength":256,"description":"Package name of a package_check item, e.g. lodash"},)json"
      R"json("version":{"type":"string","maxLength":128,"description":"Exact version of a product_exposure or package_check item; leave out to watch every version"},)json"
      R"json("ip_address":{"type":"string","maxLength":45,"description":"Public IPv4 or IPv6 address of an ip_lookup item, such as 8.8.8.8, no prefix"},)json"
      R"json("clear":{"type":"boolean","const":true,"description":"Deletes every item and the event cursor; takes no other argument"},)json"
      R"json("packages":{"type":"array","items":{"type":"object","properties":{"ecosystem":{"type":"string"},"name":{"type":"string"},"version":{"type":"string"}},"required":["ecosystem","name"],"additionalProperties":false},"minItems":1,"maxItems":500,"description":"package_check items, each with an ecosystem, a name and an optional version"})json"
      R"json(},"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":true,"openWorldHint":true},"_meta":{"com.contrastcyber/category":"Monitoring"}})json",
    R"json({"name":"watchlist_events","title":"Monitoring Events","description":"Report what changed on the items this API key watches, such as a new advisory for a package or a certificate about to expire, oldest first. A plain call continues where the last one stopped. Requires a Pro API key.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("limit":{"type":"integer","minimum":1,"maximum":100,"default":20,"description":"Events per call; repeat=true answers the whole last batch"},)json"
      R"json("cursor":{"type":"string","maxLength":18,"description":"next_cursor of an earlier answer; reads after it and keeps the position"},)json"
      R"json("repeat":{"type":"boolean","const":true,"description":"Answers the last batch again; cannot be combined with cursor"})json"
      R"json(},"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"Monitoring"}})json",
    R"json({"name":"privacy_my_data","title":"Privacy: My Data","description":"What this server keeps about the caller: the hash its credits are counted under, the rate limit left in this hour and the privacy policy. For a Pro key, which vendor keys are stored and a 15-minute link to change them.",)json"
      R"json("inputSchema":{"type":"object","properties":{},"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"Operations"}})json",
    R"json({"name":"vendor_key_edit","title":"Vendor key edit","description":"Save, delete or check your own Shodan and AbuseIPDB keys, which the ip_lookup tool uses. Needs a Pro API key or a manage link. The privacy_my_data tool gives a web link where a person can save the keys without the agent seeing them.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("action":{"type":"string","enum":["apply","status"],"maxLength":6,"description":"apply saves or deletes keys; status reports the stored keys and needs link"},)json"
      R"json("link":{"type":"string","maxLength":64,"description":"The 64 hex digits after #l= in a manage link; leave out to use this Pro API key"},)json"
      R"json("shodan_key":{"type":"string","maxLength":128,"description":"a Shodan key to check and save"},)json"
      R"json("shodan_delete":{"type":"boolean","const":true,"description":"deletes the stored Shodan key"},)json"
      R"json("abuseipdb_key":{"type":"string","maxLength":128,"description":"an AbuseIPDB key to check and save"},)json"
      R"json("abuseipdb_delete":{"type":"boolean","const":true,"description":"deletes the stored AbuseIPDB key"})json"
      R"json(},"required":["action"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":true,"openWorldHint":true},"_meta":{"com.contrastcyber/category":"Operations"}})json",
    R"json({"name":"password_check","title":"Breached Password Check","description":"Check a password's SHA-1 against Have I Been Pwned's Pwned Passwords list. It takes the full SHA-1, never the password. Only its first 5 hex digits leave this server.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("sha1_hash":{"type":"string","maxLength":40,"description":"SHA-1 of the password: 40 hex digits, either case"})json"
      R"json(},"required":["sha1_hash"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":true},"_meta":{"com.contrastcyber/category":"Credential Checks"}})json",
    R"json({"name":"dns_lookup","title":"DNS Lookup","description":"Look up a domain's DNS records: A, AAAA, MX, NS, TXT, CNAME, SOA and CAA. A record type the resolver could not answer is listed under unavailable.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("domain":{"type":"string","maxLength":253,"description":"Domain name, such as example.com"})json"
      R"json(},"required":["domain"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":true},"_meta":{"com.contrastcyber/category":"Domain Intelligence"}})json",
    R"json({"name":"dns_takeover_check","title":"Subdomain Takeover Check","description":"Check a host name for subdomain takeover through a dangling CNAME. takeover_possible is null when the CNAME points to a service whose DNS does not show whether the name can be claimed.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("domain":{"type":"string","maxLength":253,"description":"Host name, such as shop.example.com"})json"
      R"json(},"required":["domain"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":true},"_meta":{"com.contrastcyber/category":"Domain Intelligence"}})json",
    R"json({"name":"email_auth_check","title":"Email Authentication Check (SPF, DMARC, DKIM)","description":"Check a domain's mail authentication: SPF, DMARC (from a parent domain when the domain has no record of its own), DKIM, MX and MTA-STS, each check with pass, warn or fail and a severity.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("domain":{"type":"string","maxLength":253,"description":"Domain name, such as example.com"},)json"
      R"json("dkim_selector":{"type":"string","maxLength":238,"description":"DKIM selector, such as google; without it the check tries the selectors of the domain's mail providers"})json"
      R"json(},"required":["domain"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":true},"_meta":{"com.contrastcyber/category":"Domain Intelligence"}})json",
    R"json({"name":"email_address_check","title":"Email Address Check","description":"Check an e-mail address without sending mail: whether its domain exists and takes mail, and whether a disposable domain list names it. It cannot tell whether the mailbox exists.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("email":{"type":"string","maxLength":254,"description":"E-mail address, such as name@example.com"})json"
      R"json(},"required":["email"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":true},"_meta":{"com.contrastcyber/category":"Domain Intelligence"}})json",
    R"json({"name":"ssl_check","title":"SSL/TLS Certificate Check","description":"Check the TLS certificate and settings of a host name on port 443: version, cipher, trust, OCSP revocation, expiry, DNS names, the chain and an abuse.ch SSL Blacklist listing.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("domain":{"type":"string","maxLength":253,"description":"Host name, such as www.example.com"})json"
      R"json(},"required":["domain"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":true},"_meta":{"com.contrastcyber/category":"Domain Intelligence"}})json",
    R"json({"name":"headers_check","title":"Security Headers Check","description":"Rate nine security headers of a web site, such as CSP, HSTS and Set-Cookie, from one GET to https://<domain>/ that follows up to 5 redirects on the same host or its www pair. Each finding that does not pass has a remediation.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("domain":{"type":"string","maxLength":253,"description":"Host name of the site, such as www.example.com"},)json"
      R"json("include_full_header_values":{"type":"boolean","description":"true sends each header value and URL whole, instead of cutting it after 500 code points"})json"
      R"json(},"required":["domain"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":true},"_meta":{"com.contrastcyber/category":"Domain Intelligence"}})json",
    R"json({"name":"whois_lookup","title":"WHOIS / RDAP Lookup","description":"Look up a domain's registration over RDAP, or WHOIS where allowed: registrar, dates, status, name servers and DNSSEC. A name under a registered domain asks about that domain. No registrant data.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("domain":{"type":"string","maxLength":253,"description":"Domain name, such as example.com; www.example.com asks about example.com"})json"
      R"json(},"required":["domain"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":true},"_meta":{"com.contrastcyber/category":"Domain Intelligence"}})json",
    R"json({"name":"wayback_lookup","title":"Wayback Machine Lookup","description":"List when the Wayback Machine captured a host's home page: the first and last capture, the years between them and the latest 10 captures with links.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("domain":{"type":"string","maxLength":253,"description":"Host name, such as example.com"})json"
      R"json(},"required":["domain"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":true},"_meta":{"com.contrastcyber/category":"Domain Intelligence"}})json",
    R"json({"name":"cert_search","title":"Certificate Transparency Search","description":"List the unexpired certificates that Certificate Transparency logs hold for a host name, wildcards included, from SSLMate's Cert Spotter: the 10 newest, with issuer, validity and DNS names. Costs 2 credits.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("domain":{"type":"string","maxLength":253,"description":"Host name, such as example.com or www.example.com"})json"
      R"json(},"required":["domain"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":true},"_meta":{"com.contrastcyber/category":"Domain Intelligence"}})json",
    R"json({"name":"subdomain_enum","title":"Subdomain Enumeration","description":"List up to 50 subdomains of a registrable domain from Certificate Transparency, DNS queries for 94 common names and the domain's MX, NS and SPF records. Costs 2 credits.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("domain":{"type":"string","maxLength":253,"description":"Domain name, such as example.com; www.example.com asks about example.com"})json"
      R"json(},"required":["domain"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":true},"_meta":{"com.contrastcyber/category":"Domain Intelligence"}})json",
    R"json({"name":"ip_lookup","title":"IP Lookup","description":"Look up a public IP address: AS, country, cloud provider, CDN, datacenter or Tor exit, DROP listing and PTR name. A Pro key with its own Shodan or AbuseIPDB key adds exposure and reputation.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("ip_address":{"type":"string","maxLength":45,"description":"Public IPv4 or IPv6 address, such as 8.8.8.8 or 2001:4860:4860::8888"})json"
      R"json(},"required":["ip_address"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":true},"_meta":{"com.contrastcyber/category":"IP Intelligence"}})json",
    R"json({"name":"asn_lookup","title":"ASN Lookup","description":"Look up an autonomous system by number, such as AS15169, or by an IP address it holds: name, country and one page of its IPv4 and IPv6 prefixes, derived from IPtoASN.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("target":{"type":"string","maxLength":45,"description":"AS number, such as AS15169 or 15169, or a public IPv4 or IPv6 address, such as 8.8.8.8"},)json"
      R"json("limit":{"type":"integer","minimum":1,"maximum":50,"default":50},)json"
      R"json("offset":{"type":"integer","minimum":0,"default":0})json"
      R"json(},"required":["target"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"IP Intelligence"}})json",
    R"json({"name":"d3fend_for_attack","title":"D3FEND Defenses for ATT&CK","description":"MITRE D3FEND defenses that counter a MITRE ATT&CK technique. A technique id such as T1055 also matches its sub-techniques. Source: MITRE D3FEND (MIT license).",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("attack_technique_id":{"type":"string","maxLength":9,"description":"MITRE ATT&CK technique id in upper case, e.g. T1055 or T1055.012"})json"
      R"json(},"required":["attack_technique_id"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"Threat Defense"}})json",
    R"json({"name":"driver_lookup","title":"Windows Driver Lookup (LOLDrivers)","description":"Look up a Windows driver file hash in the LOLDrivers catalog of vulnerable and malicious drivers. Block on the file and Authenticode hashes, not on the detection rules. Source: LOLDrivers (Apache-2.0).",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("file_hash":{"type":"string","maxLength":64,"description":"MD5, SHA1 or SHA256 of the driver file, or its Authentihash: 32, 40 or 64 hex digits, either case"},)json"
      R"json("include_commands":{"type":"boolean","description":"true adds the catalog's command text to each match"})json"
      R"json(},"required":["file_hash"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"Threat Defense"}})json",
    R"json({"name":"driver_lookup_bulk","title":"Bulk Windows Driver Lookup","description":"Look up many driver file hashes in the LOLDrivers catalog at once, each with the fields of driver_lookup. Hashes beyond the remaining credits come back in not_processed.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("hashes":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":20,"description":"MD5, SHA1 or SHA256 of driver files or of their Authentihash"})json"
      R"json(},"required":["hashes"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"Threat Defense"}})json",
    R"json({"name":"package_check","title":"Package Vulnerability Check","description":"Check a package against the OSV.dev advisories (GitHub, Go, PyPA, RustSec) and the OpenSSF malicious package list, with the fixed version and endoflife.date dates. For severity, pass the CVE aliases to the cve_triage_bulk tool.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("ecosystem":{"type":"string","maxLength":16,"description":"npm, PyPI, Maven, Go, NuGet, RubyGems, crates.io, Packagist or SwiftURL. Case does not matter."},)json"
      R"json("name":{"type":"string","maxLength":256,"description":"Package name as the dependency file writes it, e.g. lodash, @babel/core, org.apache.logging.log4j:log4j-core, golang.org/x/net"},)json"
      R"json("version":{"type":"string","maxLength":128,"description":"Exact version, e.g. 4.17.20; without it every result is listed"},)json"
      R"json("limit":{"type":"integer","minimum":1,"maximum":50,"default":20},)json"
      R"json("offset":{"type":"integer","minimum":0,"default":0})json"
      R"json(},"required":["ecosystem","name"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"Package Vulnerabilities (SBOM)"}})json",
    R"json({"name":"package_check_bulk","title":"Bulk Package Check (SBOM)","description":"Check many packages at once, each an ecosystem, a name and an exact version, against the advisories package_check reads. For the summary and ranges of an advisory, call the package_check tool.",)json"
      R"json("inputSchema":{"type":"object","properties":{)json"
      R"json("items":{"type":"array","items":{"type":"object","properties":{"ecosystem":{"type":"string"},"name":{"type":"string"},"version":{"type":"string"}},"required":["ecosystem","name","version"],"additionalProperties":false},"minItems":1,"maxItems":500,"description":"Packages, each with its ecosystem, name and exact version"})json"
      R"json(},"required":["items"],"additionalProperties":false})json"
      R"json(,"annotations":{"readOnlyHint":true,"openWorldHint":false},"_meta":{"com.contrastcyber/category":"Package Vulnerabilities (SBOM)"}})json",
  };
  static char expected[65536];
  size_t used = 0;
  static_appendToExpected(expected, sizeof(expected), &used, R"({"jsonrpc":"2.0","id":7,"result":{"tools":[)");
  for (size_t i = 0; i < sizeof(tools) / sizeof(tools[0]); i++)
  {
    if (i > 0)
      static_appendToExpected(expected, sizeof(expected), &used, ",");
    static_appendToExpected(expected, sizeof(expected), &used, tools[i]);
  }
  static_appendToExpected(expected, sizeof(expected), &used, "]}}");

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":7,"method":"tools/list"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(expected, response);
  free(response);
}

void test_tool_old_argument_names_are_refused(void)
{
  static const char* const calls[][2] = {
    { R"("params":{"name":"cve_lookup","arguments":{"id":"CVE-2021-44228"}}})",            "Invalid params: unknown argument; this tool takes cve_id, include_ghsa" },
    { R"("params":{"name":"kev_lookup","arguments":{"id":"CVE-2021-44228"}}})",            "Invalid params: unknown argument; this tool takes cve_id" },
    { R"("params":{"name":"cve_risk_score","arguments":{"id":"CVE-2021-44228"}}})",        "Invalid params: unknown argument; this tool takes cve_id" },
    { R"("params":{"name":"cve_exploit","arguments":{"id":"CVE-2021-44228"}}})",           "Invalid params: unknown argument; this tool takes cve_id" },
    { R"("params":{"name":"cwe_lookup","arguments":{"id":"CWE-79"}}})",                    "Invalid params: unknown argument; this tool takes cwe_id" },
    { R"("params":{"name":"cve_lookup_bulk","arguments":{"ids":["CVE-2021-44228"]}}})",    "Invalid params: unknown argument; this tool takes cve_ids" },
    { R"("params":{"name":"cve_triage_bulk","arguments":{"ids":["CVE-2021-44228"]}}})",    "Invalid params: unknown argument; this tool takes cve_ids" },
    { R"("params":{"name":"watchlist_events","arguments":{"kev":true}}})",                 "Invalid params: unknown argument; this tool takes limit, cursor, repeat" },
    { R"("params":{"name":"watchlist_events","arguments":{"limit":5,"exploit":true}}})",   "Invalid params: unknown argument; this tool takes limit, cursor, repeat" },
    { R"("params":{"name":"watchlist_edit","arguments":{"hostname":"example.com"}}})",     "Invalid params: unknown argument; this tool takes action, endpoint, cve_id, vendor, product, severity, cwe_id, min_cvss, min_epss, in_kev, known_ransomware, has_nuclei_template, domain, ecosystem, name, version, ip_address, clear, packages" },
    { R"("params":{"name":"dns_takeover_check","arguments":{"hostname":"example.com"}}})", "Invalid params: unknown argument; this tool takes domain" },
    { R"("params":{"name":"ssl_check","arguments":{"hostname":"example.com"}}})",          "Invalid params: unknown argument; this tool takes domain" },
    { R"("params":{"name":"headers_check","arguments":{"hostname":"example.com"}}})",      "Invalid params: unknown argument; this tool takes domain, include_full_header_values" },
  };
  for (size_t i = 0; i < sizeof(calls) / sizeof(calls[0]); i++)
  {
    char body[512];
    int  written = snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":%zu,"method":"tools/call",%s)", i + 1, calls[i][0]);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
    int   status;
    char* response = static_dispatch(body, &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, calls[i][0]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, R"("code":-32602)"), calls[i][0]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, calls[i][1]), calls[i][0]);
    free(response);
  }
}

void test_ping(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":3,"method":"ping"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("result":{})");
  free(response);
}

void test_request_without_id_is_202_no_body(void)
{
  char* out = (char*)0x1;
  int status = -1;
  TEST_ASSERT_TRUE(mcp_dispatch(R"({"jsonrpc":"2.0","method":"notifications/initialized"})",
                                strlen(R"({"jsonrpc":"2.0","method":"notifications/initialized"})"),
                                static_installedRoutingHeaders(), &out, &status, g_conn, &TEST_FULL_CHARGE, NULL));
  TEST_ASSERT_EQUAL_INT(202, status);
  TEST_ASSERT_NULL(out);
}

void test_unknown_method_is_method_not_found_32601(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":9,"method":"does/not/exist"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "-32601");
  static_assertContains(response, R"("id":9)");
  free(response);
}

void test_malformed_json_is_parse_error_32700(void)
{
  int status;
  char* response = static_dispatch("{not json", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "-32700");
  static_assertContains(response, R"("id":null)");
  free(response);
}

void test_json_that_is_not_an_object_is_invalid_request_32600(void)
{
  static const char* const bodies[] = { "[]", R"([{"jsonrpc":"2.0","id":1,"method":"ping"}])", R"("ping")", "42" };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    int status;
    char* response = static_dispatch(bodies[i], &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, bodies[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, R"("id":null,"error":{"code":-32600,"message":"Invalid Request"})"), bodies[i]);
    free(response);
  }
}

void test_jsonrpc_version_1_0_is_invalid_request_32600(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"1.0","id":1,"method":"ping"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "-32600");
  free(response);
}

void test_id_outside_the_grammar_is_invalid_request_with_null_id(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":-,"method":"ping"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid Request"}})", response);
  free(response);
}

static const char* CVELOOKUP_REQUEST_BODY =
  R"({"jsonrpc":"2.0","id":10,"method":"tools/call",)"
  R"("params":{"name":"cve_lookup","arguments":{"cve_id":"CVE-2021-44228"}}})";

void test_tool_CVELOOKUP_ok(void)
{
  g_stub_CVELOOKUP_status = DB_OK;

  int status;
  char* response = static_dispatch(CVELOOKUP_REQUEST_BODY, &status);

  static_assertContains(response, R"("content")");
  static_assertContains(response, "CVE-2021-44228");
  static_assertContains(response, R"("id":10)");
  static_assertToolSucceeded(response, status);
}

void test_tool_CVELOOKUP_cve_not_found(void)
{
  g_stub_CVELOOKUP_status = DB_NOT_FOUND;
  int status;
  char* response = static_dispatch(CVELOOKUP_REQUEST_BODY, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"CVE not found"}],"isError":true)");
  TEST_ASSERT_NULL(strstr(response, "CVE-2021-44228"));
  free(response);
}

void test_tools_answer_not_found_without_the_id(void)
{
  static const struct {
    const char* mp_body;
    const char* mp_id;
    const char* mp_text;
  } cases[] = {
    { R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cve_lookup","arguments":{"cve_id":"CVE-2020-1001"}}})", "CVE-2020-1001", R"("text":"CVE not found"}],"isError":true)" },
    { R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"kev_lookup","arguments":{"cve_id":"CVE-2020-1002"}}})", "CVE-2020-1002", R"("text":"KEV entry not found"}],"isError":true)" },
    { R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cwe_lookup","arguments":{"cwe_id":"CWE-901"}}})", "CWE-901", R"("text":"CWE not found"}],"isError":true)" },
    { R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cve_risk_score","arguments":{"cve_id":"CVE-2020-1003"}}})", "CVE-2020-1003", R"("text":"CVE not found"}],"isError":true)" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    int status;
    char* response = static_dispatch(cases[i].mp_body, &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, cases[i].mp_id);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, cases[i].mp_text), cases[i].mp_id);
    TEST_ASSERT_NULL_MESSAGE(strstr(response, cases[i].mp_id), cases[i].mp_id);
    free(response);
  }
}

void test_tool_CVELOOKUP_invalid_format(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":11,"method":"tools/call",)"
                     R"("params":{"name":"cve_lookup","arguments":{"cve_id":"not-a-cve"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"CVE ID must be CVE-YYYY-NNNN[N...]"}],"isError":true)");
  TEST_ASSERT_NULL(strstr(response, "not-a-cve"));
  free(response);
}

void test_tool_CVELOOKUP_missing_cve_id(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":12,"method":"tools/call",)"
                     R"("params":{"name":"cve_lookup","arguments":{}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "-32602");
  free(response);
}

void test_tool_CVELOOKUP_no_flags_no_enrich(void)
{
  g_stub_CVELOOKUP_status = DB_OK;
  int status;
  char* response = static_dispatch(CVELOOKUP_REQUEST_BODY, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVELOOKUPGHSA_call_count);
  free(response);
}

void test_tool_CVELOOKUP_ghsa_enriches(void)
{
  g_stub_CVELOOKUP_status       = DB_OK;
  g_stub_CVELOOKUPGHSA_advisory = R"({"ghsa_id": "GHSA-jfh8-c2jp-5v3q"})";
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":10,"method":"tools/call","params":)"
                     R"({"name":"cve_lookup","arguments":{"cve_id":"CVE-2021-44228","include_ghsa":true}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CVELOOKUPGHSA_call_count);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", g_stub_CVELOOKUPGHSA_last_cve_id);
  static_assertContains(response, R"(\"ghsa\":{\"ghsa_id\": \"GHSA-jfh8-c2jp-5v3q\"}})");
  free(response);
}

void test_tool_CVELOOKUP_ransomware_campaign_is_the_stored_value(void)
{
  g_stub_CVELOOKUP_status = DB_OK;
  int status;
  char* response = static_dispatch(CVELOOKUP_REQUEST_BODY, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"(\"ransomware_campaign\":\"Known\",)");
  TEST_ASSERT_NULL(strstr(response, "include=shodan"));
  free(response);
}

void test_tool_CVELOOKUP_ransomware_campaign_follows_the_record(void)
{
  static const struct { const char* mp_stored; const char* mp_json; } cases[] = {
    { "Known",   R"(\"ransomware_campaign\":\"Known\",)" },
    { "",        R"(\"ransomware_campaign\":null,)" },
    { "Unknown", R"(\"ransomware_campaign\":\"Unknown\",)" },
  };
  for (size_t case_index = 0; case_index < sizeof(cases) / sizeof(cases[0]); case_index++)
  {
    g_stub_CVELOOKUP_status     = DB_OK;
    g_stub_CVELOOKUP_ransomware = cases[case_index].mp_stored;
    int status;
    char* single = static_dispatch(CVELOOKUP_REQUEST_BODY, &status);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(single, cases[case_index].mp_json), cases[case_index].mp_json);
    free(single);
    char* bulk = static_dispatch(R"({"jsonrpc":"2.0","id":16,"method":"tools/call",)"
                                 R"("params":{"name":"cve_lookup_bulk",)"
                                 R"("arguments":{"cve_ids":["CVE-2021-44228","CVE-2021-45046"]}}})", &status);
    const char* first_value = strstr(bulk, cases[case_index].mp_json);
    TEST_ASSERT_NOT_NULL_MESSAGE(first_value, cases[case_index].mp_json);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(first_value + 1, cases[case_index].mp_json), cases[case_index].mp_json);
    free(bulk);
  }
}

void test_tool_CVELOOKUP_ssvc_follows_the_record(void)
{
  static const struct { bool m_hasSsvc; const char* mp_json; } cases[] = {
    { false, R"(\"ransomware_campaign\":\"Known\",\"ssvc\":null,\"ghsa\":)" },
    { true,  R"(\"ransomware_campaign\":\"Known\",\"ssvc\":{\"exploitation\":\"active\",\"automatable\":\"yes\",\"technical_impact\":\"total\",)"
        R"(\"version\":\"2.0.3\",\"scored_at\":\"2024-04-17T04:00:13Z\",\"mission_wellbeing\":{)"
        R"(\"low\":{\"decision\":\"Attend\",\"remediation_advice\":\"sooner than standard update timelines\"},)"
        R"(\"medium\":{\"decision\":\"Act\",\"remediation_advice\":\"as soon as possible\"},)"
        R"(\"high\":{\"decision\":\"Act\",\"remediation_advice\":\"as soon as possible\"}}},\"ghsa\":)" },
  };
  for (size_t case_index = 0; case_index < sizeof(cases) / sizeof(cases[0]); case_index++)
  {
    g_stub_CVELOOKUP_status   = DB_OK;
    g_stub_CVELOOKUP_has_ssvc = cases[case_index].m_hasSsvc;
    int status;
    char* single = static_dispatch(CVELOOKUP_REQUEST_BODY, &status);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(single, cases[case_index].mp_json), cases[case_index].mp_json);
    free(single);
    char* bulk = static_dispatch(R"({"jsonrpc":"2.0","id":16,"method":"tools/call",)"
                                 R"("params":{"name":"cve_lookup_bulk",)"
                                 R"("arguments":{"cve_ids":["CVE-2021-44228","CVE-2021-45046"]}}})", &status);
    const char* first_value = strstr(bulk, cases[case_index].mp_json);
    TEST_ASSERT_NOT_NULL_MESSAGE(first_value, cases[case_index].mp_json);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(first_value + 1, cases[case_index].mp_json), cases[case_index].mp_json);
    free(bulk);
  }
}

void test_tool_CVELOOKUP_writes_a_stored_byte_that_is_not_valid_utf8_as_u_fffd(void)
{
  g_stub_CVELOOKUP_status     = DB_OK;
  g_stub_CVELOOKUP_ransomware = "a\xff" "b\xe2\x80\xae" "c";
  int status;
  char* response = static_dispatch(CVELOOKUP_REQUEST_BODY, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_TRUE(utf8_isTextValid(response, strlen(response)));
  static_assertContains(response, "\\\"ransomware_campaign\\\":\\\"a\xef\xbf\xbd" "b\\\\u202e" "c\\\",");
  free(response);
}

void test_tool_CVELOOKUP_ghsa_without_an_advisory_answers_null(void)
{
  g_stub_CVELOOKUP_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":10,"method":"tools/call","params":)"
                     R"({"name":"cve_lookup","arguments":{"cve_id":"CVE-2021-44228","include_ghsa":true}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"(\"ghsa\":null})");
  static_assertContains(response, R"(\"ransomware_campaign\":\"Known\",)");
  free(response);
}

void test_tool_CVELOOKUP_flag_false_no_enrich(void)
{
  g_stub_CVELOOKUP_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":10,"method":"tools/call","params":)"
                     R"({"name":"cve_lookup","arguments":{"cve_id":"CVE-2021-44228","include_ghsa":false}}})", &status);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CVELOOKUP_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVELOOKUPGHSA_call_count);
  static_assertToolSucceeded(response, status);
}

void test_tool_CVELOOKUP_refuses_unknown_and_repeated_arguments(void)
{
  static const struct { const char* mp_extra; const char* mp_message; } cases[] = {
    { R"("shodan":true)",              "Invalid params: unknown argument; this tool takes cve_id, include_ghsa" },
    { R"("shodan":false)",             "Invalid params: unknown argument; this tool takes cve_id, include_ghsa" },
    { R"("shodan":"true")",            "Invalid params: unknown argument; this tool takes cve_id, include_ghsa" },
    { R"("shodan":{})",                "Invalid params: unknown argument; this tool takes cve_id, include_ghsa" },
    { R"("x":1)",                      "Invalid params: unknown argument; this tool takes cve_id, include_ghsa" },
    { R"("id":"CVE-2021-44228")",      "Invalid params: unknown argument; this tool takes cve_id, include_ghsa" },
    { R"("x":{"include_ghsa":true})",          "Invalid params: unknown argument; this tool takes cve_id, include_ghsa" },
    { R"("GHSA":true)",                "Invalid params: unknown argument; this tool takes cve_id, include_ghsa" },
    { R"("include_ghsa":false,"include_ghsa":true)",   "Invalid params: include_ghsa appears more than once" },
    { R"("cve_id":"CVE-2021-44228")",  "Invalid params: cve_id appears more than once" },
    { R"("include_ghsa":[])",                  "Invalid params: include_ghsa must not be an object or an array" },
  };
  g_stub_CVELOOKUP_status = DB_OK;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char body[512];
    int  written = snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":%zu,"method":"tools/call","params":{"name":"cve_lookup","arguments":{"cve_id":"CVE-2021-44228",%s}}})", i + 1, cases[i].mp_extra);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
    char expected[160];
    written = snprintf(expected, sizeof(expected), R"("code":-32602,"message":"%s")", cases[i].mp_message);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(expected));
    int   status;
    char* response = static_dispatch(body, &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, cases[i].mp_extra);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, expected), cases[i].mp_extra);
    free(response);
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVELOOKUP_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVELOOKUPGHSA_call_count);
}

void test_tool_CVELOOKUP_refuses_a_ghsa_that_is_not_boolean(void)
{
  static const char* const values[] = { "1", "null", R"("true")" };
  g_stub_CVELOOKUP_status = DB_OK;
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    char body[512];
    int  written = snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":%zu,"method":"tools/call","params":{"name":"cve_lookup","arguments":{"cve_id":"CVE-2021-44228","include_ghsa":%s}}})", i + 1, values[i]);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
    int   status;
    char* response = static_dispatch(body, &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, values[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, R"("text":"include_ghsa must be true or false"}],"isError":true)"), values[i]);
    free(response);
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVELOOKUP_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVELOOKUPGHSA_call_count);
}

static JsonReadSpan_t static_textSpan(const char* text)
{
  JsonReadSpan_t span = { text, strlen(text) };
  return span;
}

void test_CVELOOKUP_args_gate_accepts_listed_arguments(void)
{
  static const struct { const char* mp_args; bool m_isGhsaIncluded; } cases[] = {
    { R"({"cve_id":"CVE-2021-44228"})",                         false },
    { R"({"include_ghsa":true,"cve_id":"CVE-2021-44228"})",             true  },
    { R"({"cve_id":"CVE-2021-44228","include_ghsa":false})",            false },
    { R"({ "include_ghsa" : true , "cve_id" : "CVE-2021-44228" })",     true  },
  };
  const Endpoint_t* endpoint = endpoint_findByMcpName("cve_lookup");
  TEST_ASSERT_NOT_NULL(endpoint);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    CVELOOKUPParams_t params;
    memset(&params, 0, sizeof(params));
    params.m_isGhsaIncluded = !cases[i].m_isGhsaIncluded;
    TEST_ASSERT_EQUAL_INT_MESSAGE(ENDPOINT_GATE_OK, endpoint_mcpArgsGate(endpoint, static_textSpan(cases[i].mp_args), &params, sizeof(params)).m_status, cases[i].mp_args);
    TEST_ASSERT_TRUE_MESSAGE(params.m_isGhsaIncluded == cases[i].m_isGhsaIncluded, cases[i].mp_args);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("CVE-2021-44228", params.ma_cveId, cases[i].mp_args);
  }
}

void test_CVELOOKUP_args_gate_refuses_everything_else(void)
{
  static const struct { const char* mp_args; EndpointGateStatus_t m_status; } cases[] = {
    { R"({"shodan":true})",                                                     ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME },
    { R"({"include_ghsa":true,"shodan":true})",                                 ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME },
    { R"({"cve_id":"CVE-2021-44228","shodan":true,"include_ghsa":true})",       ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME },
    { R"({"x":{"include_ghsa":true},"cve_id":"CVE-2021-44228"})",               ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME },
    { R"({"ghsax":true,"cve_id":"CVE-2021-44228"})",                            ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME },
    { R"({"gh":true,"cve_id":"CVE-2021-44228"})",                               ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME },
    { R"({"":true,"cve_id":"CVE-2021-44228"})",                                 ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME },
    { R"({"ghsA":true,"cve_id":"CVE-2021-44228"})",                             ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME },
    { R"({"cve_ids":["CVE-2021-44228"]})",                                      ENDPOINT_GATE_REJECT_UNKNOWN_PARAM_NAME },
    { R"({"include_ghsa":true,"include_ghsa":true,"cve_id":"CVE-2021-44228"})", ENDPOINT_GATE_REJECT_DUPLICATE_PARAM_NAME },
    { R"([{"include_ghsa":true}])",                                             ENDPOINT_GATE_REJECT_BODY },
    { R"("ghsa")",                                                              ENDPOINT_GATE_REJECT_BODY },
    { R"(true)",                                                                ENDPOINT_GATE_REJECT_BODY },
    { R"({"include_ghsa":true})",                                               ENDPOINT_GATE_REJECT_MISSING },
    { R"({"include_ghsa":true,"cve_id":""})",                                   ENDPOINT_GATE_REJECT_MISSING },
    { R"({"include_ghsa":true,"cve_id":7})",                                    ENDPOINT_GATE_REJECT_TYPE },
    { R"({"include_ghsa":true,"cve_id":"not-a-cve"})",                          ENDPOINT_GATE_REJECT_VALUE },
    { R"({"include_ghsa":true,"cve_id":"CVE-2021-442280000000000000"})",        ENDPOINT_GATE_REJECT_VALUE },
    { R"({"cve_id":"CVE-2021-44228","include_ghsa":1})",                        ENDPOINT_GATE_REJECT_VALUE },
    { R"({"cve_id":"CVE-2021-44228","include_ghsa":null})",                     ENDPOINT_GATE_REJECT_VALUE },
    { R"({"cve_id":"CVE-2021-44228","include_ghsa":"true"})",                   ENDPOINT_GATE_REJECT_VALUE },
    { R"({"cve_id":"CVE-2021-44228","include_ghsa":{"include_ghsa":true}})",    ENDPOINT_GATE_REJECT_OBJECT_OR_ARRAY_VALUE },
    { R"({"cve_id":["CVE-2021-44228"]})",                                       ENDPOINT_GATE_REJECT_OBJECT_OR_ARRAY_VALUE },
  };
  const Endpoint_t* endpoint = endpoint_findByMcpName("cve_lookup");
  TEST_ASSERT_NOT_NULL(endpoint);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    CVELOOKUPParams_t params;
    memset(&params, 0, sizeof(params));
    params.m_isGhsaIncluded = true;
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, endpoint_mcpArgsGate(endpoint, static_textSpan(cases[i].mp_args), &params, sizeof(params)).m_status, cases[i].mp_args);
    TEST_ASSERT_FALSE_MESSAGE(params.m_isGhsaIncluded, cases[i].mp_args);
  }
}

static void static_buildLookupArgsOfLength(char* out_buf, size_t out_buf_size, size_t total_len)
{
  const char* head     = R"({"include_ghsa":true,"cve_id":"CVE-2021-44228")";
  const char* tail     = "}";
  size_t      head_len = strlen(head);
  size_t      tail_len = strlen(tail);
  TEST_ASSERT_TRUE(total_len > head_len + tail_len && total_len < out_buf_size);
  size_t pad_len = total_len - head_len - tail_len;
  memcpy(out_buf, head, head_len);
  memset(out_buf + head_len, ' ', pad_len);
  memcpy(out_buf + head_len + pad_len, tail, tail_len);
  out_buf[total_len] = '\0';
}

void test_CVELOOKUP_args_gate_refuses_an_object_too_large_to_buffer(void)
{
  static char args[ENDPOINT_JSON_OBJECT_BUF_SIZE + 64];
  const Endpoint_t* endpoint = endpoint_findByMcpName("cve_lookup");
  TEST_ASSERT_NOT_NULL(endpoint);
  CVELOOKUPParams_t params;
  memset(&params, 0, sizeof(params));

  static_buildLookupArgsOfLength(args, sizeof(args), ENDPOINT_JSON_OBJECT_BUF_SIZE - 1);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_OK, endpoint_mcpArgsGate(endpoint, static_textSpan(args), &params, sizeof(params)).m_status);
  TEST_ASSERT_TRUE(params.m_isGhsaIncluded);

  static_buildLookupArgsOfLength(args, sizeof(args), ENDPOINT_JSON_OBJECT_BUF_SIZE);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_GATE_REJECT_BODY_TOO_LARGE, endpoint_mcpArgsGate(endpoint, static_textSpan(args), &params, sizeof(params)).m_status);
  TEST_ASSERT_FALSE(params.m_isGhsaIncluded);
}

void test_tool_unknown(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":13,"method":"tools/call",)"
                     R"("params":{"name":"nope","arguments":{}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("code":-32602,"message":"Unknown tool"})");
  TEST_ASSERT_NULL(strstr(response, "nope"));
  free(response);
}

void test_tool_name_of_the_maximum_length_is_read_whole(void)
{
  char name[MCP_TOOL_NAME_MAX_LEN + 2];
  char body[256];
  int  status;

  memset(name, 'a', MCP_TOOL_NAME_MAX_LEN);
  name[MCP_TOOL_NAME_MAX_LEN] = '\0';
  int written = snprintf(body, sizeof(body),
           R"({"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"%s","arguments":{}}})", name);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
  char* response = static_dispatch(body, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "Unknown tool");
  TEST_ASSERT_NULL(strstr(response, "at most"));
  free(response);

  name[MCP_TOOL_NAME_MAX_LEN]     = 'a';
  name[MCP_TOOL_NAME_MAX_LEN + 1] = '\0';
  written = snprintf(body, sizeof(body),
           R"({"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"%s","arguments":{}}})", name);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
  response = static_dispatch(body, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "at most 32 characters");
  TEST_ASSERT_NULL(strstr(response, "Unknown tool"));
  free(response);
}

void test_tool_retired_names_are_unknown(void)
{
  static const char* const retired_tools[] = { "cves", "cve_trending" };
  for (size_t i = 0; i < sizeof(retired_tools) / sizeof(retired_tools[0]); i++)
  {
    char body[256];
    int written = snprintf(body, sizeof(body),
                           R"({"jsonrpc":"2.0","id":16,"method":"tools/call",)"
                           R"("params":{"name":"%s","arguments":{}}})", retired_tools[i]);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
    int status;
    char* response = static_dispatch(body, &status);
    TEST_ASSERT_EQUAL_INT(200, status);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, R"("code":-32602,"message":"Unknown tool"})"), retired_tools[i]);
    TEST_ASSERT_NULL_MESSAGE(strstr(response, retired_tools[i]), retired_tools[i]);
    free(response);
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVESEARCH_call_count);
}

void test_tools_list_offers_cve_search_not_retired_names(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":17,"method":"tools/list"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("name":"cve_search")");
  TEST_ASSERT_NULL(strstr(response, R"("name":"cves")"));
  TEST_ASSERT_NULL(strstr(response, R"("name":"cve_trending")"));
  free(response);
}

void test_tool_call_missing_params(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":14,"method":"tools/call"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "-32602");
  free(response);
}

void test_tool_HEALTH(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":15,"method":"tools/call",)"
                     R"("params":{"name":"health"}})", &status);

  static_assertContains(response, "status");
  static_assertContains(response, R"(\"cve_count\":251430)");
  static_assertContains(response, R"(\"feeds\":[{\"name\":\"nvd\",\"last_synced\":\"2026-05-22T10:05:00Z\")");
  static_assertEndsWith(response, R"("}],"isError":false}})");
  static_assertToolSucceeded(response, status);
}

void test_tool_HEALTH_db_error_is_internal_error(void)
{
  g_stub_HEALTH_status = DB_ERROR;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":16,"method":"tools/call",)"
                     R"("params":{"name":"health"}})", &status);

  TEST_ASSERT_NULL(strstr(response, "cve_count"));
  static_assertToolInternalError(response, status);
}

void test_tool_CVELOOKUPBULK_ok(void)
{
  g_stub_CVELOOKUP_status = DB_OK;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":16,"method":"tools/call",)"
                     R"("params":{"name":"cve_lookup_bulk",)"
                     R"("arguments":{"cve_ids":["CVE-2021-44228","CVE-2021-45046"]}}})", &status);

  static_assertContains(response, "successful");
  static_assertToolSucceeded(response, status);
}

void test_tool_CVELOOKUPBULK_empty(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":17,"method":"tools/call",)"
                     R"("params":{"name":"cve_lookup_bulk","arguments":{"cve_ids":[]}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, "cve_ids array must not be empty");
  free(response);
}

void test_tool_CVELOOKUPBULK_missing_ids(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":18,"method":"tools/call",)"
                     R"("params":{"name":"cve_lookup_bulk","arguments":{}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "-32602");
  free(response);
}

void test_tool_CVELOOKUPBULK_id_of_the_maximum_length_is_looked_up(void)
{
  g_stub_CVELOOKUP_status = DB_OK;
  TEST_ASSERT_EQUAL_UINT(CVELOOKUP_ID_MAX_LEN, strlen("CVE-2021-123456789012345"));

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":18,"method":"tools/call",)"
                     R"("params":{"name":"cve_lookup_bulk",)"
                     R"("arguments":{"cve_ids":["CVE-2021-123456789012345"]}}})", &status);

  TEST_ASSERT_EQUAL_INT(1, g_stub_CVELOOKUPBULK_id_count);
  static_assertContains(response, "CVE-2021-123456789012345");
  static_assertToolSucceeded(response, status);
}

void test_tool_KEVLOOKUP_ok(void)
{
  g_stub_KEVLOOKUP_status = DB_OK;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":19,"method":"tools/call",)"
                     R"("params":{"name":"kev_lookup","arguments":{"cve_id":"CVE-2021-44228"}}})", &status);

  static_assertContains(response, "Log4Shell");
  static_assertContains(response, R"(\"in_kev\":true,)");
  static_assertContains(response, R"(\"notes\":\"https://logging.apache.org/log4j/2.x/security.html\")");
  static_assertToolSucceeded(response, status);
}

void test_tool_CWELOOKUP_ok(void)
{
  g_stub_CWELOOKUP_status = DB_OK;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":20,"method":"tools/call",)"
                     R"("params":{"name":"cwe_lookup","arguments":{"cwe_id":"CWE-79"}}})", &status);

  static_assertContains(response, "Improper Input Validation");
  static_assertContains(response, R"(\"abstraction\":\"Class\",\"status\":\"Stable\")");
  static_assertToolSucceeded(response, status);
}

void test_tool_CVERISKSCORE_ok(void)
{
  g_stub_CVERISKSCORE_status = DB_OK;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":21,"method":"tools/call",)"
                     R"("params":{"name":"cve_risk_score","arguments":{"cve_id":"CVE-2021-44228"}}})", &status);

  static_assertContains(response, R"(\"score\":97.8,\"label\":\"CRITICAL\")");
  static_assertToolSucceeded(response, status);
}

void test_tool_CVESEARCH_db_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":22,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"severity":"CRITICAL"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "-32603");
  free(response);
}

void test_tool_CVESEARCH_bad_severity(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":23,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"severity":"WRONG"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, "severity");
  free(response);
}

void test_tool_CVESEARCH_cwe_id_must_be_a_cwe_id(void)
{
  g_stub_CVESEARCH_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":24,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"cwe_id":"79"}}})", &status);
  static_assertToolRefusedBeforeDb(response, status, R"("text":"cwe_id must be CWE-N"}],"isError":true)", g_stub_CVESEARCH_call_count);

  response = static_dispatch(R"({"jsonrpc":"2.0","id":25,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"cwe_id":""}}})", &status);
  static_assertToolRefusedBeforeDb(response, status, R"("text":"cwe_id must be CWE-N"}],"isError":true)", g_stub_CVESEARCH_call_count);
}

void test_tool_CVEEXPLOIT_ok(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":24,"method":"tools/call",)"
                     R"("params":{"name":"cve_exploit","arguments":{"cve_id":"CVE-2021-44228"}}})", &status);

  static_assertContains(response, R"(\"has_public_exploit\":true,\"in_kev\":true,)");
  static_assertContains(response, R"({\"name\":\"exploit_multi/http/log4shell\",\"type\":\"exploit\"})");
  static_assertContains(response, R"({\"source\":\"nvd\",\"available\":true,\"count\":11,\"top_results\":[{\"url\":\"https://nvd.test/exploit/log4shell\"}]})");
  static_assertToolSucceeded(response, status);
}

void test_tool_CVEEXPLOIT_metasploit_unavailable_is_a_result(void)
{
  g_stub_CVEEXPLOIT_metasploit_unavailable = true;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":78,"method":"tools/call",)"
                     R"("params":{"name":"cve_exploit","arguments":{"cve_id":"CVE-2021-44228"}}})", &status);

  static_assertContains(response, R"(\"source\":\"metasploit\",\"available\":false,\"reason\":\"database_error\",\"has_module\":false)");
  static_assertToolSucceeded(response, status);
}

void test_tool_CVEEXPLOIT_nvd_unavailable_is_a_result(void)
{
  g_stub_CVEEXPLOIT_nvd_unavailable = true;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":79,"method":"tools/call",)"
                     R"("params":{"name":"cve_exploit","arguments":{"cve_id":"CVE-2021-44228"}}})", &status);

  static_assertContains(response, R"(\"in_kev\":null,)");
  static_assertContains(response, R"(\"source\":\"nvd\",\"available\":false,\"reason\":\"database_error\",)");
  static_assertToolSucceeded(response, status);
}

void test_tools_list_includes_triage_tools(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("name":"cve_triage")");
  static_assertContains(response, R"("name":"cve_triage_bulk")");
  static_assertContains(response, R"("min_risk_score")");
  free(response);
}

void test_tool_CVETRIAGE_ok(void)
{
  g_stub_CVETRIAGE_status = DB_OK;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":30,"method":"tools/call",)"
                     R"("params":{"name":"cve_triage","arguments":{"min_risk_score":50}}})", &status);

  static_assertContains(response, "risk_score");
  static_assertContains(response, "CVE-2021-44228");
  static_assertToolSucceeded(response, status);
}

void test_tool_CVETRIAGE_db_error(void)
{
  g_stub_CVETRIAGE_status = DB_ERROR;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":31,"method":"tools/call",)"
                     R"("params":{"name":"cve_triage","arguments":{}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "-32603");
  free(response);
}

void test_tool_CVETRIAGE_bad_min_risk_score(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":32,"method":"tools/call",)"
                     R"("params":{"name":"cve_triage","arguments":{"min_risk_score":150}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, "min_risk_score");
  free(response);
}

void test_tool_CVETRIAGEBULK_ok(void)
{
  g_stub_CVETRIAGEBULK_status = DB_OK;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":33,"method":"tools/call",)"
                     R"("params":{"name":"cve_triage_bulk",)"
                     R"("arguments":{"cve_ids":["CVE-2021-44228","CVE-2021-45046"]}}})", &status);

  static_assertContains(response, "successful");
  static_assertContains(response, "risk_score");
  static_assertToolSucceeded(response, status);
}

void test_tool_CVETRIAGEBULK_empty(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":34,"method":"tools/call",)"
                     R"("params":{"name":"cve_triage_bulk","arguments":{"cve_ids":[]}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, "cve_ids array must not be empty");
  free(response);
}

void test_tool_CVETRIAGEBULK_missing_ids(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":35,"method":"tools/call",)"
                     R"("params":{"name":"cve_triage_bulk","arguments":{}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "-32602");
  free(response);
}

void test_tool_CVETRIAGEBULK_id_of_the_maximum_length_is_looked_up(void)
{
  g_stub_CVETRIAGEBULK_status = DB_OK;
  TEST_ASSERT_EQUAL_UINT(CVELOOKUP_ID_MAX_LEN, strlen("CVE-2021-123456789012345"));

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":35,"method":"tools/call",)"
                     R"("params":{"name":"cve_triage_bulk",)"
                     R"("arguments":{"cve_ids":["CVE-2021-123456789012345"]}}})", &status);

  static_assertContains(response, R"(\"processed\":1,\"successful\":1,\"skipped\":0)");
  static_assertToolSucceeded(response, status);
}

void test_tool_CVETRIAGE_min_risk_score_zero_accepted(void)
{
  g_stub_CVETRIAGE_status = DB_OK;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":36,"method":"tools/call",)"
                     R"("params":{"name":"cve_triage","arguments":{"min_risk_score":0}}})", &status);

  static_assertToolSucceeded(response, status);
}

void test_tool_CVETRIAGE_min_risk_score_hundred_accepted(void)
{
  g_stub_CVETRIAGE_status = DB_OK;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":37,"method":"tools/call",)"
                     R"("params":{"name":"cve_triage","arguments":{"min_risk_score":100}}})", &status);

  static_assertToolSucceeded(response, status);
}

void test_tool_bulk_too_many_cve_ids_is_a_tool_error(void)
{
  static const char* const tools[] = { "cve_triage_bulk", "cve_lookup_bulk" };
  for (size_t t = 0; t < sizeof(tools) / sizeof(tools[0]); t++)
  {
    const Endpoint_t* endpoint = endpoint_findByMcpName(tools[t]);
    TEST_ASSERT_NOT_NULL(endpoint);
    const EndpointParamSpec_t* spec = endpoint->mp_params[0].mp_spec;
    char message[64];
    int written = snprintf(message, sizeof(message), "%s array exceeds maximum of %d", spec->mp_name, (int)spec->m_max);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(message));

    char body[2048];
    int n = snprintf(body, sizeof(body),
      R"({"jsonrpc":"2.0","id":38,"method":"tools/call",)"
      R"("params":{"name":"%s","arguments":{"cve_ids":[)", tools[t]);
    TEST_ASSERT_TRUE(n > 0 && (size_t)n < sizeof(body));
    for (int i = 0; i < (int)spec->m_max + 1; i++)
    {
      n += snprintf(body + n, sizeof(body) - (size_t)n, R"(%s"CVE-2021-%04d")", i ? "," : "", i + 1);
      TEST_ASSERT_TRUE((size_t)n < sizeof(body));
    }
    TEST_ASSERT_TRUE((size_t)snprintf(body + n, sizeof(body) - (size_t)n, "]}}}") < sizeof(body) - (size_t)n);
    int status;
    char* response = static_dispatch(body, &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, tools[t]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, R"("isError":true)"), tools[t]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, message), tools[t]);
    free(response);
  }
}

void test_tool_bulk_repeated_id_is_a_tool_error_naming_the_pair(void)
{
  static const struct { const char* mp_cveIds; const char* mp_message; } cases[] = {
    { R"(["CVE-2021-44228","CVE-2022-12345","CVE-2021-44228","CVE-2022-12345"])", "cve_ids[2] repeats cve_ids[0]" },
    { R"([5,"CVE-2021-44228","CVE-2021-44228"])",                                  "cve_ids[2] repeats cve_ids[1]" },
  };
  static const char* const tools[] = { "cve_lookup_bulk", "cve_triage_bulk" };
  g_stub_CVELOOKUP_status     = DB_OK;
  g_stub_CVETRIAGEBULK_status = DB_OK;
  for (size_t t = 0; t < sizeof(tools) / sizeof(tools[0]); t++)
  {
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
    {
      char body[512];
      int written = snprintf(body, sizeof(body),
        R"({"jsonrpc":"2.0","id":39,"method":"tools/call","params":{"name":"%s","arguments":{"cve_ids":%s}}})", tools[t], cases[k].mp_cveIds);
      TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
      int status;
      char* response = static_dispatch(body, &status);
      TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, body);
      TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, R"("isError":true)"), body);
      TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, cases[k].mp_message), body);
      free(response);
    }
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVELOOKUPBULK_call_count);
}

void test_tool_bulk_refuses_unknown_and_repeated_arguments(void)
{
  static const char* const tools[] = { "cve_lookup_bulk", "cve_triage_bulk" };
  static const struct { const char* mp_args; const char* mp_message; } cases[] = {
    { R"({"cve_ids":["CVE-2021-44228"],"x":1})",        "Invalid params: unknown argument; this tool takes cve_ids" },
    { R"({"x":{"cve_ids":["CVE-2021-44228"]}})",        "Invalid params: unknown argument; this tool takes cve_ids" },
    { R"({"cve_ids":["CVE-2021-44228"],"cve_ids":[]})", "Invalid params: cve_ids appears more than once" },
  };
  g_stub_CVELOOKUP_status     = DB_OK;
  g_stub_CVETRIAGEBULK_status = DB_OK;
  for (size_t t = 0; t < sizeof(tools) / sizeof(tools[0]); t++)
  {
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++)
    {
      char body[512];
      int  written = snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"%s","arguments":%s}})", tools[t], cases[k].mp_args);
      TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
      char expected[160];
      written = snprintf(expected, sizeof(expected), R"("code":-32602,"message":"%s")", cases[k].mp_message);
      TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(expected));
      int   status;
      char* response = static_dispatch(body, &status);
      TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, body);
      TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, expected), body);
      free(response);
    }
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVELOOKUPBULK_call_count);
}

static void static_assertToolRefusedWith(const char* tool, const char* arguments, const char* message)
{
  char body[512];
  int  written = snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"%s","arguments":%s}})", tool, arguments);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
  char expected[320];
  written = snprintf(expected, sizeof(expected), R"("code":-32602,"message":"%s"})", message);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(expected));
  int   status;
  char* response = static_dispatch(body, &status);
  TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, body);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, expected), body);
  free(response);
}

void test_every_tool_refuses_names_and_values_it_does_not_read(void)
{
  int called = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (endpoint->mp_mcpToolName == NULL)
      continue;

    char message[256];
    int  used    = snprintf(message, sizeof(message), "Invalid params: unknown argument; this tool takes");
    bool has_arg = false;
    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      if (!(endpoint->mp_params[j].m_sources & ENDPOINT_PARAM_SRC_MCP_ARG))
        continue;
      used += snprintf(message + used, sizeof(message) - (size_t)used, "%s%s", has_arg ? ", " : " ", endpoint->mp_params[j].mp_spec->mp_name);
      has_arg = true;
    }
    TEST_ASSERT_TRUE(used > 0 && (size_t)used < sizeof(message));
    if (!has_arg)
      snprintf(message, sizeof(message), "Invalid params: this tool takes no arguments");
    static_assertToolRefusedWith(endpoint->mp_mcpToolName, R"({"zz":1})", message);

    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      const EndpointParam_t* param = &endpoint->mp_params[j];
      if (!(param->m_sources & ENDPOINT_PARAM_SRC_MCP_ARG))
        continue;
      const char* name = param->mp_spec->mp_name;
      char arguments[128];
      snprintf(arguments, sizeof(arguments), R"({"%s":1,"%s":1})", name, name);
      snprintf(message, sizeof(message), "Invalid params: %s appears more than once", name);
      static_assertToolRefusedWith(endpoint->mp_mcpToolName, arguments, message);
      if (endpoint_isBulkArrayType(param->mp_spec->m_type))
        continue;
      snprintf(message, sizeof(message), "Invalid params: %s must not be an object or an array", name);
      snprintf(arguments, sizeof(arguments), R"({"%s":{}})", name);
      static_assertToolRefusedWith(endpoint->mp_mcpToolName, arguments, message);
      snprintf(arguments, sizeof(arguments), R"({"%s":[]})", name);
      static_assertToolRefusedWith(endpoint->mp_mcpToolName, arguments, message);
    }
    called++;
  }
  TEST_ASSERT_EQUAL_INT(37, called);
}

void test_readToolCall_reads_the_name_and_the_arguments(void)
{
  static const struct { const char* mp_body; McpToolCallStatus_t m_status; const char* mp_name; const char* mp_args; } cases[] = {
    { R"({"jsonrpc":"2.0","id":1,"method":"tools/call"})",                                                MCP_TOOL_CALL_NO_PARAMS, NULL,         NULL },
    { R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}})",                                    MCP_TOOL_CALL_NO_NAME,   NULL,         NULL },
    { R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":7}})",                            MCP_TOOL_CALL_BAD_NAME,  NULL,         NULL },
    { R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a23456789012345678901234567890123"}})", MCP_TOOL_CALL_BAD_NAME, NULL, NULL },
    { R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"health"}})",                     MCP_TOOL_CALL_OK,        "health",     "{}" },
    { R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"kev_lookup","arguments":{"cve_id":"x"},"name":"y"}})", MCP_TOOL_CALL_OK, "kev_lookup", R"({"cve_id":"x"})" },
    { R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"health","arguments":7}})",       MCP_TOOL_CALL_OK,        "health",     "7" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    JsonRpcRequest_t request;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONRPC_OK, jsonrpc_parse(cases[i].mp_body, strlen(cases[i].mp_body), &request), cases[i].mp_body);
    char           name[MCP_TOOL_NAME_MAX_LEN + 1];
    JsonReadSpan_t args_span = { NULL, 0 };
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, mcp_readToolCall(&request, name, &args_span), cases[i].mp_body);
    if (cases[i].m_status != MCP_TOOL_CALL_OK)
      continue;
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_name, name, cases[i].mp_body);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(strlen(cases[i].mp_args), args_span.m_len, cases[i].mp_body);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, memcmp(cases[i].mp_args, args_span.mp_start, args_span.m_len), cases[i].mp_body);
  }
}

void test_tool_bulk_non_array_cve_ids_is_protocol_error(void)
{
  static const char* const calls[] = {
    R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cve_lookup_bulk","arguments":{"cve_ids":"CVE-2021-44228"}}})",
    R"({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"cve_triage_bulk","arguments":{"cve_ids":"CVE-2021-44228"}}})",
  };
  for (size_t i = 0; i < sizeof(calls) / sizeof(calls[0]); i++)
  {
    int   status;
    char* response = static_dispatch(calls[i], &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, calls[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, R"("code":-32602)"), calls[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, R"("message":"Invalid params: cve_ids must be an array")"), calls[i]);
    free(response);
  }
}

void test_tool_bulk_without_cve_ids_is_protocol_error(void)
{
  static const char* const calls[] = {
    R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cve_lookup_bulk","arguments":{}}})",
    R"({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"cve_triage_bulk","arguments":{}}})",
  };
  for (size_t i = 0; i < sizeof(calls) / sizeof(calls[0]); i++)
  {
    int   status;
    char* response = static_dispatch(calls[i], &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, calls[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, R"("code":-32602,"message":"Invalid params: cve_ids is required")"), calls[i]);
    free(response);
  }
}

void test_tools_list_triage_schema_details(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":39,"method":"tools/list"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"json("minItems":1,"maxItems":50,"description":"CVE IDs"}},"required":["cve_ids"])json");
  static_assertContains(response, R"("min_risk_score":{"type":"number","minimum":0,"maximum":100,"description":"Composite risk-score threshold"})");
  free(response);
}

void test_tools_list_PRODUCTEXPOSURE_included(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":40,"method":"tools/list"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("name":"product_exposure")");
  static_assertContains(response, R"("required":["vendor","product"])");
  free(response);
}

void test_tool_PRODUCTEXPOSURE_ok(void)
{
  g_stub_PRODUCTEXPOSURE_status = DB_OK;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":41,"method":"tools/call",)"
                     R"("params":{"name":"product_exposure",)"
                     R"("arguments":{"vendor":"cisco","product":"ios"}}})", &status);

  static_assertContains(response, "total_cves");
  static_assertContains(response, "top_cves");
  static_assertContains(response, "CVE-2021-44228");
  static_assertToolSucceeded(response, status);
}

void test_tool_PRODUCTEXPOSURE_passes_the_version(void)
{
  g_stub_PRODUCTEXPOSURE_status = DB_OK;
  snprintf(g_stub_PRODUCTEXPOSURE_last_params.ma_version, sizeof(g_stub_PRODUCTEXPOSURE_last_params.ma_version), "unset");

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":45,"method":"tools/call",)"
                     R"("params":{"name":"product_exposure",)"
                     R"("arguments":{"vendor":"nodejs","product":"node.js","version":"v22.21.1"}}})", &status);
  TEST_ASSERT_EQUAL_STRING("v22.21.1", g_stub_PRODUCTEXPOSURE_last_params.ma_version);
  static_assertContains(response, R"(\"eol\":null)");
  static_assertToolSucceeded(response, status);

  response = static_dispatch(R"({"jsonrpc":"2.0","id":46,"method":"tools/call",)"
               R"("params":{"name":"product_exposure",)"
               R"("arguments":{"vendor":"nodejs","product":"node.js"}}})", &status);
  TEST_ASSERT_EQUAL_STRING("", g_stub_PRODUCTEXPOSURE_last_params.ma_version);
  static_assertToolSucceeded(response, status);
}

void test_tool_PRODUCTEXPOSURE_passes_include_rejected(void)
{
  g_stub_PRODUCTEXPOSURE_status = DB_OK;
  static const char* const arguments[] = {
    R"({"vendor":"nodejs","product":"node.js","version":"22.1","include_rejected":true})",
    R"({"vendor":"nodejs","product":"node.js","version":"22.1","include_rejected":false})",
    R"({"vendor":"nodejs","product":"node.js","version":"22.1"})",
  };
  for (size_t i = 0; i < sizeof(arguments) / sizeof(arguments[0]); i++)
  {
    g_stub_PRODUCTEXPOSURE_last_params.m_isRejectedIncluded = i != 0;
    char request[256];
    int written = snprintf(request, sizeof(request),
                           R"({"jsonrpc":"2.0","id":47,"method":"tools/call","params":{"name":"product_exposure","arguments":%s}})",
                           arguments[i]);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(request));
    int status;
    char* response = static_dispatch(request, &status);
    static_assertToolSucceeded(response, status);
    TEST_ASSERT_TRUE_MESSAGE(g_stub_PRODUCTEXPOSURE_last_params.m_isRejectedIncluded == (i == 0), arguments[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("22.1", g_stub_PRODUCTEXPOSURE_last_params.ma_version, arguments[i]);
  }
}

void test_tool_PRODUCTEXPOSURE_version_with_a_space_is_refused(void)
{
  g_stub_PRODUCTEXPOSURE_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":47,"method":"tools/call",)"
                     R"("params":{"name":"product_exposure",)"
                     R"("arguments":{"vendor":"nodejs","product":"node.js","version":"22 1"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, "version");
  free(response);
}

void test_tool_PRODUCTEXPOSURE_db_error(void)
{
  g_stub_PRODUCTEXPOSURE_status = DB_ERROR;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":42,"method":"tools/call",)"
                     R"("params":{"name":"product_exposure",)"
                     R"("arguments":{"vendor":"cisco","product":"ios"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "-32603");
  free(response);
}

void test_tool_PRODUCTEXPOSURE_missing_vendor(void)
{
  g_stub_PRODUCTEXPOSURE_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":43,"method":"tools/call",)"
                     R"("params":{"name":"product_exposure",)"
                     R"("arguments":{"product":"ios"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "-32602");
  static_assertContains(response, "vendor");
  free(response);
}

void test_tool_PRODUCTEXPOSURE_wildcard_vendor(void)
{
  g_stub_PRODUCTEXPOSURE_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":44,"method":"tools/call",)"
                     R"("params":{"name":"product_exposure",)"
                     R"("arguments":{"vendor":"cis%","product":"ios"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, "vendor");
  free(response);
}

void test_tool_PRODUCTEXPOSURE_missing_product(void)
{
  g_stub_PRODUCTEXPOSURE_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":45,"method":"tools/call",)"
                     R"("params":{"name":"product_exposure",)"
                     R"("arguments":{"vendor":"cisco"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "-32602");
  static_assertContains(response, "product");
  free(response);
}

void test_tool_CPESEARCH_ok(void)
{
  g_stub_CPESEARCH_status = DB_OK;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":47,"method":"tools/call",)"
                     R"("params":{"name":"cpe_search",)"
                     R"("arguments":{"search":"notepad++","limit":5}}})", &status);

  static_assertContains(response, R"(\"vendor\":\"notepad-plus-plus\")");
  static_assertContains(response, R"(\"product\":\"notepad\\\\+\\\\+\")");
  static_assertContains(response, R"(\"vulnerable_cve_count\":7)");
  TEST_ASSERT_EQUAL_INT(1, g_stub_CPESEARCH_call_count);
  TEST_ASSERT_EQUAL_STRING("notepad++", g_stub_CPESEARCH_last_params.ma_search);
  TEST_ASSERT_EQUAL_INT(5, g_stub_CPESEARCH_last_params.m_limit);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CPESEARCH_last_params.m_offset);
  static_assertToolSucceeded(response, status);
}

void test_tool_CVEPRODUCTS_ok(void)
{
  g_stub_CVEPRODUCTS_status = DB_OK;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":48,"method":"tools/call",)"
                     R"("params":{"name":"cve_products",)"
                     R"("arguments":{"cve_id":"CVE-2021-44228","vendor":"apache","limit":5,"offset":3}}})", &status);

  static_assertContains(response, R"(\"cve_id\":\"CVE-2021-44228\",\"total\":37,\"limit\":5,\"offset\":3,\"next_offset\":4)");
  static_assertContains(response, R"(\"product\":\"log4j\")");
  TEST_ASSERT_EQUAL_INT(1, g_stub_CVEPRODUCTS_call_count);
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", g_stub_CVEPRODUCTS_last_params.ma_cveId);
  TEST_ASSERT_EQUAL_STRING("apache", g_stub_CVEPRODUCTS_last_params.ma_vendor);
  TEST_ASSERT_EQUAL_STRING("", g_stub_CVEPRODUCTS_last_params.ma_product);
  TEST_ASSERT_EQUAL_INT(5, g_stub_CVEPRODUCTS_last_params.m_limit);
  TEST_ASSERT_EQUAL_INT(3, g_stub_CVEPRODUCTS_last_params.m_offset);
  static_assertToolSucceeded(response, status);
}

void test_tool_CVEPRODUCTS_not_found(void)
{
  g_stub_CVEPRODUCTS_status = DB_NOT_FOUND;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":49,"method":"tools/call",)"
                     R"("params":{"name":"cve_products","arguments":{"cve_id":"CVE-2021-44228"}}})", &status);

  static_assertContains(response, R"("text":"CVE not found"}],"isError":true)");
  TEST_ASSERT_EQUAL_INT(1, g_stub_CVEPRODUCTS_call_count);
  TEST_ASSERT_EQUAL_INT(20, g_stub_CVEPRODUCTS_last_params.m_limit);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVEPRODUCTS_last_params.m_offset);
  free(response);
}

void test_tool_CPESEARCH_short_query(void)
{
  g_stub_CPESEARCH_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":48,"method":"tools/call",)"
                     R"("params":{"name":"cpe_search",)"
                     R"("arguments":{"search":"ab"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"search must hold at least 3 bytes and not only spaces"}],"isError":true)");
  TEST_ASSERT_EQUAL_INT(0, g_stub_CPESEARCH_call_count);
  free(response);
}

void test_tool_PRODUCTEXPOSURE_wildcard_product(void)
{
  g_stub_PRODUCTEXPOSURE_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":46,"method":"tools/call",)"
                     R"("params":{"name":"product_exposure",)"
                     R"("arguments":{"vendor":"cisco","product":"io%"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, "product");
  free(response);
}

#define META_2026 \
    R"("_meta":{)" \
    R"("io.modelcontextprotocol/protocolVersion":"2026-07-28",)" \
    R"("io.modelcontextprotocol/clientInfo":{"name":"probe","version":"1.0"},)" \
    R"("io.modelcontextprotocol/clientCapabilities":{}})"

static void static_copyHeaderField(char* dst, size_t cap, const char* src)
{
  size_t src_len = strlen(src);
  size_t n = (src_len < cap - 1) ? src_len : cap - 1;
  memcpy(dst, src, n);
  dst[n] = '\0';
}

static void static_setRoutingHeaders(const char* pv, const char* method, const char* name)
{
  McpRoutingHeaders_t h;
  memset(&h, 0, sizeof(h));
  if (pv)     
  { 
    h.m_hasProtocolVersion = true; 
    static_copyHeaderField(h.ma_protocolVersion, sizeof(h.ma_protocolVersion), pv); 
  }
  if (method) 
  { 
    h.m_hasMethod = true; 
    static_copyHeaderField(h.ma_method, sizeof(h.ma_method), method);
  }
  if (name)
  {
    h.m_hasName = true;
    static_copyHeaderField(h.ma_name, sizeof(h.ma_name), name); 
  }
  g_routingHeaders    = h;
  g_hasRoutingHeaders = true;
}

void test_era2026_no_header_stays_legacy_no_result_type(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":50,"method":"tools/list"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("tools":[)");
  TEST_ASSERT_NULL(strstr(response, R"("resultType")"));
  free(response);
}

void test_era2026_handshake_value_stays_legacy_ignores_mcp_method(void)
{
  static_setRoutingHeaders("2025-11-25", "tools/call", NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":51,"method":"tools/list"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("tools":[)");
  TEST_ASSERT_NULL(strstr(response, R"("error")"));
  TEST_ASSERT_NULL(strstr(response, R"("resultType")"));
  free(response);
}

void test_era2026_missing_meta_is_invalid_params_400(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/list", NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":52,"method":"tools/list","params":{}})", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32602)");
  static_assertContains(response, "params._meta must carry the reserved");
  free(response);
}

void test_era2026_method_header_mismatch_is_32020_400(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/call", NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":53,"method":"tools/list",)"
                     R"("params":{)" META_2026 "}}", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32020)");
  static_assertContains(response, "mcp-method header does not match");
  free(response);
}

void test_era2026_missing_method_header_is_32020_400(void)
{
  static_setRoutingHeaders("2026-07-28", NULL, NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":54,"method":"tools/list",)"
                     R"("params":{)" META_2026 "}}", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32020)");
  free(response);
}

void test_era2026_pv_header_envelope_mismatch_is_32020_400(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/list", NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":55,"method":"tools/list",)"
                     R"("params":{"_meta":{)"
                     R"("io.modelcontextprotocol/protocolVersion":"2027-01-01",)"
                     R"("io.modelcontextprotocol/clientInfo":{"name":"p","version":"1"},)"
                     R"("io.modelcontextprotocol/clientCapabilities":{}}}})", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32020)");
  static_assertContains(response, "mcp-protocol-version header does not match");
  free(response);
}

void test_era2026_unsupported_envelope_version_is_32022_with_data(void)
{
  static_setRoutingHeaders("2027-01-01", "tools/list", NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":56,"method":"tools/list",)"
                     R"("params":{"_meta":{)"
                     R"("io.modelcontextprotocol/protocolVersion":"2027-01-01",)"
                     R"("io.modelcontextprotocol/clientInfo":{"name":"p","version":"1"},)"
                     R"("io.modelcontextprotocol/clientCapabilities":{}}}})", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32022)");
  static_assertContains(response, R"("data":{"supported":["2026-07-28"],"requested":"2027-01-01"}}})");
  free(response);
}

void test_era2026_duplicate_routing_header_is_32020_400(void)
{
  McpRoutingHeaders_t h;
  memset(&h, 0, sizeof(h));
  h.m_hasProtocolVersion = true;
  strncpy(h.ma_protocolVersion, "2026-07-28", sizeof(h.ma_protocolVersion) - 1);
  h.m_hasMethod = true;
  strncpy(h.ma_method, "tools/list", sizeof(h.ma_method) - 1);
  h.m_duplicated = true;
  g_routingHeaders    = h;
  g_hasRoutingHeaders = true;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":57,"method":"tools/list",)"
                     R"("params":{)" META_2026 "}}", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32020)");
  static_assertContains(response, "appears more than once");
  free(response);
}

void test_era2026_request_without_id_rejected_400(void)
{
  static_setRoutingHeaders("2026-07-28", "notifications/initialized", NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","method":"notifications/initialized"})", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32600)");
  static_assertContains(response, R"("id":null)");
  free(response);
}

void test_era2026_tools_list_carries_result_type(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/list", NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":58,"method":"tools/list",)"
                     R"("params":{)" META_2026 "}}", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"(,"result":{"resultType":"complete","tools":[)");
  static_assertEndsWith(response, "]}}");
  free(response);
}

void test_era2026_tools_list_is_the_legacy_tools_list(void)
{
  int status;
  char* legacy = static_dispatch(R"({"jsonrpc":"2.0","id":58,"method":"tools/list"})", &status);
  static_setRoutingHeaders("2026-07-28", "tools/list", NULL);
  char* modern = static_dispatch(R"({"jsonrpc":"2.0","id":58,"method":"tools/list",)" R"("params":{)" META_2026 "}}", &status);
  const char* legacy_tools = strstr(legacy, R"("tools":[)");
  const char* modern_tools = strstr(modern, R"("tools":[)");
  TEST_ASSERT_NOT_NULL(legacy_tools);
  TEST_ASSERT_NOT_NULL(modern_tools);
  TEST_ASSERT_EQUAL_STRING(legacy_tools, modern_tools);
  free(legacy);
  free(modern);
}

void test_era2026_ping_carries_result_type(void)
{
  static_setRoutingHeaders("2026-07-28", "ping", NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":59,"method":"ping",)"
                     R"("params":{)" META_2026 "}}", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":59,"result":{"resultType":"complete"}})", response);
  free(response);
}

void test_era2026_server_discover_ok(void)
{
  static_setRoutingHeaders("2026-07-28", "server/discover", NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":60,"method":"server/discover",)"
                     R"("params":{)" META_2026 "}}", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("resultType":"complete")");
  static_assertContains(response, R"("capabilities":{"tools":{}})");
  static_assertContains(response, R"("supportedVersions":["2026-07-28"])");
  static_assertContains(response, R"("serverInfo":{"name":"contrastapi","title":"ContrastAPI","version":")" CONTRASTAPI_VERSION R"("})");
  static_assertContains(response, R"("cacheScope":"public")");
  static_assertContains(response, R"("ttlMs":)");
  TEST_ASSERT_NULL(strstr(response, R"("error")"));
  free(response);
}

void test_era2026_server_discover_legacy_method_not_found(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":61,"method":"server/discover"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("code":-32601)");
  free(response);
}

void test_era2026_initialize_is_method_not_found_404(void)
{
  static_setRoutingHeaders("2026-07-28", "initialize", NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":62,"method":"initialize",)"
                     R"("params":{)" META_2026 "}}", &status);
  TEST_ASSERT_EQUAL_INT(404, status);
  static_assertContains(response, R"("code":-32601)");
  free(response);
}

void test_era2026_unknown_method_404(void)
{
  static_setRoutingHeaders("2026-07-28", "no/such", NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":63,"method":"no/such",)"
                     R"("params":{)" META_2026 "}}", &status);
  TEST_ASSERT_EQUAL_INT(404, status);
  static_assertContains(response, R"("code":-32601)");
  free(response);
}

void test_era2026_tools_call_ok_result_type(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/call", "health");

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":64,"method":"tools/call",)"
                     R"("params":{)" META_2026 R"(,"name":"health","arguments":{}}})", &status);

  static_assertEndsWith(response, R"("}],"isError":false,"resultType":"complete"}})");
  static_assertToolSucceeded(response, status);
}

void test_era2026_tools_call_name_header_mismatch(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/call", "cve_lookup");
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":65,"method":"tools/call",)"
                     R"("params":{)" META_2026 R"(,"name":"health","arguments":{}}})", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32020)");
  static_assertContains(response, "mcp-name header does not match");
  free(response);
}

void test_era2026_tools_call_missing_name_header_mismatch(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/call", NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":66,"method":"tools/call",)"
                     R"("params":{)" META_2026 R"(,"name":"health","arguments":{}}})", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32020)");
  free(response);
}

void test_era2026_parse_error_400(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/list", NULL);
  int status;
  char* response = static_dispatch("{not json", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32700)");
  free(response);
}

void test_body_that_is_not_valid_utf8_is_parse_error_before_any_tool(void)
{
  static const char body[] = "{\"jsonrpc\":\"2.0\",\"id\":\"\xff\",\"method\":\"tools/call\",\"params\":{\"name\":\"cve_lookup\",\"arguments\":{\"cve_id\":\"CVE-2021-44228\",\"include_ghsa\":true}}}";
  int status;
  char* response = static_dispatch(body, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}})", response);
  free(response);

  static_setRoutingHeaders("2026-07-28", "tools/call", "cve_lookup");
  response = static_dispatch(body, &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}})", response);
  free(response);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVELOOKUP_call_count);

  EndpointPrice_t price;
  price.m_willCallUpstream       = true;
  price.m_isPartialChargeAllowed = true;
  mcp_creditCost(body, &price);
  TEST_ASSERT_EQUAL_UINT(1, price.m_creditCost);
  TEST_ASSERT_FALSE(price.m_willCallUpstream);
}

void test_tool_CVESEARCH_negative_nan_min_cvss_is_parse_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cve_search","arguments":{"min_cvss":-nan}}})", &status);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVESEARCH_call_count);
  static_assertContains(response, R"("code":-32700)");
  TEST_ASSERT_EQUAL_INT(200, status);
  free(response);
}

void test_era2026_invalid_envelope_is_400(void)
{
  static_setRoutingHeaders("2026-07-28", "ping", NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"1.0","id":58,"method":"ping"})", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32600)");
  free(response);
}

void test_era2026_id_outside_the_grammar_is_400(void)
{
  static_setRoutingHeaders("2026-07-28", "ping", NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":true,"method":"ping"})", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid Request"}})", response);
  free(response);
}

void test_era2026_all_handshake_versions_stay_legacy(void)
{
  const char* versions[] = { "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25" };
  for (size_t i = 0; i < sizeof(versions) / sizeof(versions[0]); i++)
  {
    static_setRoutingHeaders(versions[i], "ping", NULL);
    int status;
    char* response = static_dispatch(R"({"jsonrpc":"2.0","id":59,"method":"ping"})", &status);
    TEST_ASSERT_EQUAL_INT(200, status);
    static_assertContains(response, R"("result")");
    TEST_ASSERT_NULL(strstr(response, R"("resultType")"));
    free(response);
  }
}

void test_era2026_meta_missing_one_key_is_32602_400(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/list", NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":66,"method":"tools/list",)"
                     R"("params":{"_meta":{)"
                     R"("io.modelcontextprotocol/protocolVersion":"2026-07-28",)"
                     R"("io.modelcontextprotocol/clientInfo":{"name":"p","version":"1"}}}})", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32602)");
  static_assertContains(response, "params._meta must carry the reserved");
  free(response);
}

void test_era2026_meta_pv_not_string_is_32602_400(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/list", NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":67,"method":"tools/list",)"
                     R"("params":{"_meta":{)"
                     R"("io.modelcontextprotocol/protocolVersion":2026,)"
                     R"("io.modelcontextprotocol/clientInfo":{"name":"p","version":"1"},)"
                     R"("io.modelcontextprotocol/clientCapabilities":{}}}})", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32602)");
  free(response);
}

void test_era2026_missing_params_is_32602_400(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/list", NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":68,"method":"tools/list"})", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32602)");
  free(response);
}

void test_era2026_unknown_tool_is_32602_400(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/call", "nope");
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":69,"method":"tools/call",)"
                     R"("params":{)" META_2026 R"(,"name":"nope","arguments":{}}})", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32602,"message":"Unknown tool"})");
  free(response);
}

void test_era2026_tool_run_protocol_error_reaches_the_http_status(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/call", "cve_lookup");
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":71,"method":"tools/call",)"
                     R"("params":{)" META_2026 R"(,"name":"cve_lookup","arguments":{}}})", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32602,"message":"Invalid params: missing CVE ID")");
  free(response);

  g_stub_CVELOOKUP_status = DB_ERROR;
  response = static_dispatch(R"({"jsonrpc":"2.0","id":72,"method":"tools/call",)"
                     R"("params":{)" META_2026 R"(,"name":"cve_lookup","arguments":{"cve_id":"CVE-2021-44228"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("code":-32603,"message":"Internal error: database query failed")");
  free(response);
}

void test_era2026_tool_error_stays_200_with_result_type(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/call", "cve_search");
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":70,"method":"tools/call",)"
                     R"("params":{)" META_2026 R"(,"name":"cve_search","arguments":{"limit":999}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"("resultType":"complete")");
  static_assertContains(response, "limit must be an integer between 1 and 100");
  free(response);
}

void test_tool_bulk_serves_the_charged_ids_in_both_eras(void)
{
  g_stub_CVELOOKUP_status = DB_OK;
  const char* legacy_body = R"({"jsonrpc":"2.0","id":72,"method":"tools/call",)"
    R"("params":{"name":"cve_lookup_bulk","arguments":{"cve_ids":["CVE-2021-44228","CVE-2023-0001","CVE-2023-0002"]}}})";
  const char* modern_body = R"({"jsonrpc":"2.0","id":73,"method":"tools/call",)"
    R"("params":{)" META_2026 R"(,"name":"cve_lookup_bulk","arguments":{"cve_ids":["CVE-2021-44228","CVE-2023-0001","CVE-2023-0002"]}}})";
  const char* bodies[] = { legacy_body, modern_body };

  for (int i = 0; i < 2; i++)
  {
    if (i == 1)
      static_setRoutingHeaders("2026-07-28", "tools/call", "cve_lookup_bulk");
    g_stub_CVELOOKUPBULK_id_count = 0;
    char* response = NULL;
    int   status   = -1;
    const RequestCharge_t charge = { .m_chargedCreditCount = 2, .mp_creditBudget = NULL, .mp_x402Payment = NULL };
    TEST_ASSERT_TRUE(mcp_dispatch(bodies[i], strlen(bodies[i]), static_installedRoutingHeaders(), &response, &status, g_conn, &charge, NULL));
    TEST_ASSERT_EQUAL_INT(200, status);
    TEST_ASSERT_EQUAL_INT(2, g_stub_CVELOOKUPBULK_id_count);
    static_assertContains(response, R"(\"not_processed\":[\"CVE-2023-0002\"])");
    free(response);
  }
}

void test_runRow_has_no_body_on_not_found_and_db_error(void)
{
  const Endpoint_t* lookup = endpoint_findByMcpName("cve_lookup");
  TEST_ASSERT_NOT_NULL(lookup);
  const DbStatus_t statuses[] = { DB_NOT_FOUND, DB_ERROR };
  const EndpointRunStatus_t expected[] = { ENDPOINT_RUN_NOT_FOUND, ENDPOINT_RUN_DB_ERROR };
  for (int i = 0; i < 2; i++)
  {
    EndpointAnyParams_t params;
    memset(&params, 0, sizeof(params));
    snprintf(params.m_cveLookup.ma_cveId, sizeof(params.m_cveLookup.ma_cveId), "CVE-2021-44228");
    g_stub_CVELOOKUP_status = statuses[i];
    EndpointRunResult_t run_result = endpoint_runRow(lookup, &params, g_conn, &TEST_FULL_CHARGE);
    TEST_ASSERT_EQUAL_INT(expected[i], run_result.m_status);
    TEST_ASSERT_NULL(run_result.mp_body);
  }
}

#define MCP_TEST_CREDIT_BUDGET_HASH "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

void test_privacy_my_data_shows_the_credit_budget_it_is_handed(void)
{
  RequestCreditBudget_t credit_budget;
  memset(&credit_budget, 0, sizeof(credit_budget));
  memcpy(credit_budget.ma_budgetHash, MCP_TEST_CREDIT_BUDGET_HASH, sizeof(MCP_TEST_CREDIT_BUDGET_HASH));
  credit_budget.m_rateLimitInfo.m_limit     = 100;
  credit_budget.m_rateLimitInfo.m_remaining = 41;

  const char* legacy_body = R"({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"privacy_my_data"}})";
  const char* modern_body = R"({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{)" META_2026 R"(,"name":"privacy_my_data"}})";
  const char* bodies[] = { legacy_body, modern_body };

  for (int i = 0; i < 2; i++)
  {
    if (i == 1)
      static_setRoutingHeaders("2026-07-28", "tools/call", "privacy_my_data");
    char* response = NULL;
    int   status   = -1;
    const RequestCharge_t charge = { .m_chargedCreditCount = ENDPOINT_FULL_CHARGE, .mp_creditBudget = &credit_budget, .mp_x402Payment = NULL };
    TEST_ASSERT_TRUE(mcp_dispatch(bodies[i], strlen(bodies[i]), static_installedRoutingHeaders(), &response, &status, g_conn, &charge, NULL));
    TEST_ASSERT_EQUAL_INT(200, status);
    static_assertContains(response, R"("isError":false)");
    static_assertContains(response, R"(\"hash\":\")" MCP_TEST_CREDIT_BUDGET_HASH R"(\")");
    static_assertContains(response, R"(\"hourly_limit\":100,\"remaining_in_window\":41,)");
    free(response);
  }
}


static char* static_watchlistCall(const char* tool, const char* arguments, const RequestCreditBudget_t* credit_budget, int* status_out)
{
  char body[1024];
  int written = snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"%s","arguments":%s}})", tool, arguments);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
  char* response = NULL;
  *status_out = -1;
  const RequestCharge_t charge = { .m_chargedCreditCount = ENDPOINT_FULL_CHARGE, .mp_creditBudget = credit_budget, .mp_x402Payment = NULL };
  TEST_ASSERT_TRUE(mcp_dispatch(body, strlen(body), static_installedRoutingHeaders(), &response, status_out, g_conn, &charge, NULL));
  TEST_ASSERT_NOT_NULL(response);
  return response;
}

static void static_watchlistBudget(RequestCreditBudget_t* credit_budget, RequestTier_t tier)
{
  memset(credit_budget, 0, sizeof(*credit_budget));
  memcpy(credit_budget->ma_budgetHash, MCP_TEST_CREDIT_BUDGET_HASH, sizeof(MCP_TEST_CREDIT_BUDGET_HASH));
  credit_budget->m_tier = tier;
}

void test_watchlist_tools_refuse_a_call_without_an_api_key(void)
{
  RequestCreditBudget_t credit_budget;
  static_watchlistBudget(&credit_budget, REQUEST_TIER_FREE);
  g_stub_WATCHLISTEDIT_status   = DB_OK;
  g_stub_WATCHLISTEVENTS_status = DB_OK;
  int status;
  char* response = static_watchlistCall("watchlist_edit", R"({"action":"add","endpoint":"cve_lookup","cve_id":"CVE-2021-44228"})", &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"watchlist needs a Pro API key: https://api.contrastcyber.com/pricing"}],"isError":true)");
  free(response);
  response = static_watchlistCall("watchlist_events", "{}", &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"watchlist needs a Pro API key: https://api.contrastcyber.com/pricing"}],"isError":true)");
  free(response);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WATCHLISTEDIT_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WATCHLISTEVENTS_call_count);
}

void test_watchlist_edit_answers_the_list_and_each_db_status(void)
{
  RequestCreditBudget_t credit_budget;
  static_watchlistBudget(&credit_budget, REQUEST_TIER_PRO);
  g_stub_WATCHLISTEDIT_status = DB_OK;
  int status;
  char* response = static_watchlistCall("watchlist_edit", R"({"action":"add","endpoint":"cve_search","vendor":"apache","min_cvss":7.5,"in_kev":true,"has_nuclei_template":true})", &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":false)");
  static_assertContains(response, R"(\"items\":[{\"endpoint\":\"cve_lookup\",\"cve_id\":\"CVE-2021-44228\"},{\"endpoint\":\"product_exposure\",\"vendor\":\"apache\",\"product\":\"log4j\",\"version\":\"2.14.1\",\"product_has_cves\":true}],\"item_count\":2,\"item_limit\":100,\"package_item_count\":0,\"package_item_limit\":500})");
  free(response);
  TEST_ASSERT_EQUAL_INT(1, g_stub_WATCHLISTEDIT_call_count);
  TEST_ASSERT_EQUAL_PTR(&credit_budget, g_stub_WATCHLISTEDIT_last_params.mp_creditBudget);
  TEST_ASSERT_EQUAL_INT(WATCHLISTEDIT_ACTION_ADD, g_stub_WATCHLISTEDIT_last_params.m_action);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_CVE_SEARCH, g_stub_WATCHLISTEDIT_last_params.m_item.m_itemKind);
  TEST_ASSERT_EQUAL_STRING("apache", g_stub_WATCHLISTEDIT_last_params.m_item.m_cveSearch.ma_vendor);
  TEST_ASSERT_EQUAL_FLOAT(7.5, g_stub_WATCHLISTEDIT_last_params.m_item.m_cveSearch.m_minCvss);
  TEST_ASSERT_EQUAL_INT(CVE_KEV_FILTER_ONLY_IN_KEV, g_stub_WATCHLISTEDIT_last_params.m_item.m_cveSearch.m_kevFilter);
  TEST_ASSERT_TRUE(g_stub_WATCHLISTEDIT_last_params.m_item.m_cveSearch.m_hasNucleiTemplate);
  TEST_ASSERT_FALSE(g_stub_WATCHLISTEDIT_last_params.m_item.m_cveSearch.m_knownRansomware);
  TEST_ASSERT_FALSE(g_stub_WATCHLISTEDIT_last_has_registered_domain);
  TEST_ASSERT_EQUAL_INT(1, g_stub_WATCHLISTEDITResultFree_call_count);

  g_stub_WATCHLISTEDIT_result_status = WATCHLISTEDIT_OVER_LIMIT;
  response                           = static_watchlistCall("watchlist_edit", R"({"action":"add","endpoint":"cve_lookup","cve_id":"CVE-2021-44228"})", &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"watchlist holds at most 100 items"}],"isError":true)");
  free(response);

  g_stub_WATCHLISTEDIT_result_status = WATCHLISTEDIT_OVER_PACKAGE_LIMIT;
  response                           = static_watchlistCall("watchlist_edit", R"({"action":"add","endpoint":"package_check","ecosystem":"NPM","name":"Lodash","version":"4.17.20"})", &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"watchlist holds at most 500 package items"}],"isError":true)");
  free(response);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_PACKAGE_CHECK, g_stub_WATCHLISTEDIT_last_params.m_item.m_itemKind);
  TEST_ASSERT_EQUAL_STRING("NPM", g_stub_WATCHLISTEDIT_last_params.m_item.m_packageCheck.ma_ecosystem);
  TEST_ASSERT_EQUAL_STRING("Lodash", g_stub_WATCHLISTEDIT_last_params.m_item.m_packageCheck.ma_name);
  TEST_ASSERT_EQUAL_STRING("4.17.20", g_stub_WATCHLISTEDIT_last_params.m_item.m_packageCheck.ma_version);
  TEST_ASSERT_FALSE(g_stub_WATCHLISTEDIT_last_has_registered_domain);

  g_stub_WATCHLISTEDIT_result_status = WATCHLISTEDIT_UNKNOWN_KEY;
  response                           = static_watchlistCall("watchlist_edit", "{}", &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("code":-32603,"message":"Internal error: database query failed")");
  free(response);

  g_stub_WATCHLISTEDIT_result_status = WATCHLISTEDIT_PACKAGE_PROBLEM;
  response                           = static_watchlistCall("watchlist_edit", "{}", &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("code":-32603,"message":"Internal error: database query failed")");
  free(response);
  TEST_ASSERT_EQUAL_INT(5, g_stub_WATCHLISTEDIT_call_count);
}

void test_watchlist_edit_sends_a_package_list_and_answers_its_counts(void)
{
  RequestCreditBudget_t credit_budget;
  static_watchlistBudget(&credit_budget, REQUEST_TIER_PRO);
  g_stub_WATCHLISTEDIT_status        = DB_OK;
  g_stub_WATCHLISTEDIT_result_status = WATCHLISTEDIT_OK;
  int status;
  const char* add = R"({"action":"add","packages":[{"ecosystem":"npm","name":"lodash"},{"ecosystem":"PyPI","name":"Django","version":"4.2.1"}]})";
  char* response = static_watchlistCall("watchlist_edit", add, &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"{\"added_count\":1,\"unchanged_count\":2,\"package_item_count\":3,\"package_item_limit\":500}\n"}],"isError":false)");
  free(response);
  TEST_ASSERT_EQUAL_INT(1, g_stub_WATCHLISTEDIT_call_count);
  TEST_ASSERT_EQUAL_INT(WATCHLISTEDIT_ACTION_ADD, g_stub_WATCHLISTEDIT_last_params.m_action);
  TEST_ASSERT_EQUAL_INT(2, g_stub_WATCHLISTEDIT_last_package_count);
  TEST_ASSERT_EQUAL_STRING("npm", g_stub_WATCHLISTEDIT_last_packages[0].m_package.ma_ecosystem);
  TEST_ASSERT_EQUAL_STRING("lodash", g_stub_WATCHLISTEDIT_last_packages[0].m_package.ma_packageName);
  TEST_ASSERT_EQUAL_STRING("", g_stub_WATCHLISTEDIT_last_packages[0].m_package.ma_version);
  TEST_ASSERT_EQUAL_INT(PACKAGE_ELEMENT_PROBLEM_NONE, g_stub_WATCHLISTEDIT_last_packages[0].m_problem);
  TEST_ASSERT_EQUAL_STRING("PyPI", g_stub_WATCHLISTEDIT_last_packages[1].m_package.ma_ecosystem);
  TEST_ASSERT_EQUAL_STRING("Django", g_stub_WATCHLISTEDIT_last_packages[1].m_package.ma_packageName);
  TEST_ASSERT_EQUAL_STRING("4.2.1", g_stub_WATCHLISTEDIT_last_packages[1].m_package.ma_version);
  TEST_ASSERT_EQUAL_INT(1, g_stub_WATCHLISTEDITResultFree_call_count);

  const char* remove = R"({"action":"remove","packages":[{"ecosystem":"npm","name":"lodash"},{"ecosystem":"PyPI","name":"Django","version":"4.2.1"}]})";
  response = static_watchlistCall("watchlist_edit", remove, &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"{\"removed_count\":1,\"unchanged_count\":2,\"package_item_count\":3,)");
  static_assertContains(response, R"("isError":false)");
  free(response);
  TEST_ASSERT_EQUAL_INT(WATCHLISTEDIT_ACTION_REMOVE, g_stub_WATCHLISTEDIT_last_params.m_action);
  TEST_ASSERT_EQUAL_INT(2, g_stub_WATCHLISTEDIT_last_package_count);
  TEST_ASSERT_EQUAL_INT(2, g_stub_WATCHLISTEDITResultFree_call_count);

  const struct { WATCHLISTEDITStatus_t m_status; const char* mp_expected; } refused[] = {
    { WATCHLISTEDIT_UNKNOWN_KEY,         R"("code":-32603,"message":"Internal error: database query failed")" },
    { WATCHLISTEDIT_OVER_LIMIT,          R"("text":"watchlist holds at most 100 items"}],"isError":true)" },
    { WATCHLISTEDIT_OVER_DOMAIN_LIMIT,   R"("text":"limit: at most 20 watched names per registered domain per key"}],"isError":true)" },
    { WATCHLISTEDIT_OVER_PACKAGE_LIMIT,  R"("text":"watchlist holds at most 500 package items"}],"isError":true)" },
    { WATCHLISTEDIT_OVER_PACKAGE_WEIGHT, R"("text":"watchlist package items weigh at most )" },
  };
  for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
  {
    g_stub_WATCHLISTEDIT_result_status = refused[i].m_status;
    response                           = static_watchlistCall("watchlist_edit", add, &credit_budget, &status);
    TEST_ASSERT_EQUAL_INT(200, status);
    static_assertContains(response, refused[i].mp_expected);
    free(response);
  }
  TEST_ASSERT_EQUAL_INT(7, g_stub_WATCHLISTEDITResultFree_call_count);
}

void test_watchlist_edit_names_the_earlier_position_of_a_normalized_repeat(void)
{
  RequestCreditBudget_t credit_budget;
  static_watchlistBudget(&credit_budget, REQUEST_TIER_PRO);
  g_stub_WATCHLISTEDIT_status         = DB_OK;
  g_stub_WATCHLISTEDIT_result_status  = WATCHLISTEDIT_PACKAGE_PROBLEM;
  g_stub_WATCHLISTEDIT_package_repeat = { .m_currentIndex = 2, .m_earlierIndex = 1 };
  int status;
  char* response = static_watchlistCall("watchlist_edit", R"({"action":"add","packages":[{"ecosystem":"npm","name":"a"},{"ecosystem":"npm","name":"b"},{"ecosystem":"npm","name":"B"}]})", &credit_budget, &status);
  static_assertContains(response, R"(\"index\":2,\"ecosystem\":\"npm\",\"name\":\"B\",\"version\":null,\"reason\":\"names the package and version of packages[1] once the names are normalized\"}]})");
  free(response);
  g_stub_WATCHLISTEDIT_package_repeat = { .m_currentIndex = -1, .m_earlierIndex = -1 };
}

void test_watchlist_edit_answers_every_package_problem_as_a_tool_error(void)
{
  RequestCreditBudget_t credit_budget;
  static_watchlistBudget(&credit_budget, REQUEST_TIER_PRO);
  g_stub_WATCHLISTEDIT_status         = DB_OK;
  g_stub_WATCHLISTEDIT_result_status  = WATCHLISTEDIT_PACKAGE_PROBLEM;
  g_stub_WATCHLISTEDIT_package_repeat = { .m_currentIndex = 3, .m_earlierIndex = 0 };
  int status;
  const char* add = R"({"action":"add","packages":[{"ecosystem":"npm","name":"a"},"x",{"ecosystem":"npm","name":"a"},{"ecosystem":"npm","name":"A"},{"ecosystem":"npm"}]})";
  char* response = static_watchlistCall("watchlist_edit", add, &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"{\"error\":{\"code\":\"bad_request\",\"message\":\"packages holds elements that are not packages or that repeat an earlier element: problems lists each one, and nothing changed\"},\"problems\":[)"
                                  R"({\"index\":1,\"ecosystem\":null,\"name\":null,\"version\":null,\"reason\":\"the element is not a JSON object\"},)"
                                  R"({\"index\":2,\"ecosystem\":\"npm\",\"name\":\"a\",\"version\":null,\"reason\":\"repeats packages[0]\"},)"
                                  R"({\"index\":3,\"ecosystem\":\"npm\",\"name\":\"A\",\"version\":null,\"reason\":\"names the package and version of packages[0] once the names are normalized\"},)"
                                  R"({\"index\":4,\"ecosystem\":\"npm\",\"name\":null,\"version\":null,\"reason\":\"name is missing or empty\"}]}\n"}],"isError":true)");
  free(response);
  TEST_ASSERT_EQUAL_INT(5, g_stub_WATCHLISTEDIT_last_package_count);
  TEST_ASSERT_EQUAL_INT(PACKAGE_ELEMENT_PROBLEM_NOT_AN_OBJECT, g_stub_WATCHLISTEDIT_last_packages[1].m_problem);
  TEST_ASSERT_EQUAL_INT(PACKAGE_ELEMENT_PROBLEM_REPEATED, g_stub_WATCHLISTEDIT_last_packages[2].m_problem);
  TEST_ASSERT_EQUAL_INT(1, g_stub_WATCHLISTEDITResultFree_call_count);

  const WATCHLISTEDITPackageRepeat_t unmarkable[] = { { .m_currentIndex = 1, .m_earlierIndex = 0 }, { .m_currentIndex = 3, .m_earlierIndex = 3 }, { .m_currentIndex = 5, .m_earlierIndex = 0 }, { .m_currentIndex = 3, .m_earlierIndex = 1 }, { .m_currentIndex = 3, .m_earlierIndex = -1 } };
  for (size_t i = 0; i < sizeof(unmarkable) / sizeof(unmarkable[0]); i++)
  {
    g_stub_WATCHLISTEDIT_package_repeat = unmarkable[i];
    response = static_watchlistCall("watchlist_edit", add, &credit_budget, &status);
    static_assertContains(response, R"("error":{"code":-32603,"message":"Internal error: database query failed"})");
    free(response);
  }

  g_stub_WATCHLISTEDIT_package_repeat = { .m_currentIndex = -1, .m_earlierIndex = -1 };
  response                            = static_watchlistCall("watchlist_edit", R"({"action":"add","packages":[{"ecosystem":"npm","name":"a"}]})", &credit_budget, &status);
  static_assertContains(response, R"("error":{"code":-32603,"message":"Internal error: database query failed"})");
  free(response);
  TEST_ASSERT_EQUAL_INT(7, g_stub_WATCHLISTEDIT_call_count);
  TEST_ASSERT_EQUAL_INT(7, g_stub_WATCHLISTEDITResultFree_call_count);
}

void test_watchlist_edit_answers_a_db_error_when_the_db_accepts_an_element_with_a_problem(void)
{
  RequestCreditBudget_t credit_budget;
  static_watchlistBudget(&credit_budget, REQUEST_TIER_PRO);
  g_stub_WATCHLISTEDIT_status = DB_OK;
  const WATCHLISTEDITStatus_t accepting[] = { WATCHLISTEDIT_OK, WATCHLISTEDIT_OVER_LIMIT, WATCHLISTEDIT_OVER_PACKAGE_LIMIT, WATCHLISTEDIT_OVER_PACKAGE_WEIGHT };
  for (size_t i = 0; i < sizeof(accepting) / sizeof(accepting[0]); i++)
  {
    g_stub_WATCHLISTEDIT_result_status = accepting[i];
    int status;
    char* response = static_watchlistCall("watchlist_edit", R"({"action":"add","packages":[{"ecosystem":"npm","name":"a"},"x"]})", &credit_budget, &status);
    static_assertContains(response, R"("error":{"code":-32603,"message":"Internal error: database query failed"})");
    free(response);
  }
  TEST_ASSERT_EQUAL_INT(4, g_stub_WATCHLISTEDIT_call_count);
  TEST_ASSERT_EQUAL_INT(4, g_stub_WATCHLISTEDITResultFree_call_count);
}

void test_watchlist_edit_hands_a_domain_item_its_registered_domain(void)
{
  RequestCreditBudget_t credit_budget;
  static_watchlistBudget(&credit_budget, REQUEST_TIER_PRO);
  g_stub_WATCHLISTEDIT_status = DB_OK;
  int status;
  char* response = static_watchlistCall("watchlist_edit", R"({"action":"add","endpoint":"dns_lookup","domain":"shop.example.com"})", &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":false)");
  free(response);
  TEST_ASSERT_EQUAL_INT(1, g_stub_WATCHLISTEDIT_call_count);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_DNS_LOOKUP, g_stub_WATCHLISTEDIT_last_params.m_item.m_itemKind);
  TEST_ASSERT_EQUAL_STRING("shop.example.com", g_stub_WATCHLISTEDIT_last_params.m_item.m_dnsLookup.ma_domainName);
  TEST_ASSERT_TRUE(g_stub_WATCHLISTEDIT_last_has_registered_domain);
  TEST_ASSERT_EQUAL_STRING("example.com", g_stub_WATCHLISTEDIT_last_registered_domain);

  g_stub_WATCHLISTEDIT_result_status = WATCHLISTEDIT_OVER_DOMAIN_LIMIT;
  response                           = static_watchlistCall("watchlist_edit", R"({"action":"add","endpoint":"dns_lookup","domain":"www.Example.co.uk"})", &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"limit: at most 20 watched names per registered domain per key"}],"isError":true)");
  free(response);
  TEST_ASSERT_EQUAL_INT(2, g_stub_WATCHLISTEDIT_call_count);
  TEST_ASSERT_EQUAL_STRING("www.example.co.uk", g_stub_WATCHLISTEDIT_last_params.m_item.m_dnsLookup.ma_domainName);
  TEST_ASSERT_TRUE(g_stub_WATCHLISTEDIT_last_has_registered_domain);
  TEST_ASSERT_EQUAL_STRING("example.co.uk", g_stub_WATCHLISTEDIT_last_registered_domain);
  TEST_ASSERT_EQUAL_INT(2, g_stub_WATCHLISTEDITResultFree_call_count);
}

void test_watchlist_edit_refuses_an_ssl_check_add_of_a_name_dns_does_not_know(void)
{
  RequestCreditBudget_t credit_budget;
  static_watchlistBudget(&credit_budget, REQUEST_TIER_PRO);
  g_stub_WATCHLISTEDIT_status = DB_OK;
  g_stub_ASKQUESTIONS_status  = DNS_ANSWER_NXDOMAIN;
  int status;
  char* response = static_watchlistCall("watchlist_edit", R"({"action":"add","endpoint":"ssl_check","domain":"shop.example.org"})", &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"domain does not exist in DNS"}],"isError":true)");
  free(response);
  TEST_ASSERT_EQUAL_INT(1, g_stub_ASKQUESTIONS_call_count);
  TEST_ASSERT_EQUAL_STRING("shop.example.org", g_stub_ASKQUESTIONS_last_domain_name);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WATCHLISTEDIT_call_count);

  g_stub_ASKQUESTIONS_status = DNS_ANSWER_SERVER_ERROR;
  response = static_watchlistCall("watchlist_edit", R"({"action":"add","endpoint":"ssl_check","domain":"shop.example.org"})", &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":false)");
  free(response);
  TEST_ASSERT_EQUAL_INT(2, g_stub_ASKQUESTIONS_call_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_WATCHLISTEDIT_call_count);
  TEST_ASSERT_EQUAL_INT(WATCHLIST_ITEM_SSL_CHECK, g_stub_WATCHLISTEDIT_last_params.m_item.m_itemKind);
  TEST_ASSERT_EQUAL_STRING("example.org", g_stub_WATCHLISTEDIT_last_registered_domain);

  g_stub_ASKQUESTIONS_status = DNS_ANSWER_NXDOMAIN;
  response = static_watchlistCall("watchlist_edit", R"({"action":"remove","endpoint":"ssl_check","domain":"gone.example.org"})", &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":false)");
  free(response);
  TEST_ASSERT_EQUAL_INT(2, g_stub_ASKQUESTIONS_call_count);
  TEST_ASSERT_EQUAL_INT(2, g_stub_WATCHLISTEDIT_call_count);
  TEST_ASSERT_EQUAL_STRING("gone.example.org", g_stub_WATCHLISTEDIT_last_params.m_item.m_sslCheck.ma_domainName);
}

static void static_expectEditParams(WATCHLISTEDITItemsDbParams_t* expected, const RequestCreditBudget_t* credit_budget, WATCHLISTEDITAction_t action, WatchlistItemKind_t kind)
{
  memset(expected, 0, sizeof(*expected));
  expected->mp_creditBudget   = credit_budget;
  expected->m_action          = action;
  expected->m_item.m_itemKind = kind;
}

void test_watchlist_edit_hands_the_db_only_the_item_of_its_kind(void)
{
  RequestCreditBudget_t credit_budget;
  static_watchlistBudget(&credit_budget, REQUEST_TIER_PRO);
  g_stub_WATCHLISTEDIT_status = DB_OK;

  WATCHLISTEDITItemsDbParams_t expected[WATCHLIST_ITEM_KIND_COUNT + 1];
  static_expectEditParams(&expected[0], &credit_budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_CVE_LOOKUP);
  strcpy(expected[0].m_item.m_cveLookup.ma_cveId, "CVE-2021-44228");
  static_expectEditParams(&expected[1], &credit_budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_KEV_LOOKUP);
  strcpy(expected[1].m_item.m_kevLookup.ma_cveId, "CVE-2022-0001");
  static_expectEditParams(&expected[2], &credit_budget, WATCHLISTEDIT_ACTION_REMOVE, WATCHLIST_ITEM_CVE_EXPLOIT);
  strcpy(expected[2].m_item.m_cveExploit.ma_cveId, "CVE-2023-0002");
  static_expectEditParams(&expected[3], &credit_budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_PRODUCT_EXPOSURE);
  strcpy(expected[3].m_item.m_productExposure.ma_vendor,  "cisco");
  strcpy(expected[3].m_item.m_productExposure.ma_product, "ios");
  strcpy(expected[3].m_item.m_productExposure.ma_version, "15.2");
  static_expectEditParams(&expected[4], &credit_budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_CVE_SEARCH);
  WATCHLISTCVESEARCHItem_t* every_filter = &expected[4].m_item.m_cveSearch;
  strcpy(every_filter->ma_vendor,   "apache");
  strcpy(every_filter->ma_product,  "log4j");
  strcpy(every_filter->ma_severity, "HIGH");
  strcpy(every_filter->ma_cweId,    "CWE-917");
  every_filter->m_minCvss           = 7.5;
  every_filter->m_minEpss           = 0.25;
  every_filter->m_kevFilter         = CVE_KEV_FILTER_NOT_IN_KEV;
  every_filter->m_knownRansomware   = true;
  every_filter->m_hasNucleiTemplate = true;
  static_expectEditParams(&expected[5], &credit_budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_DNS_LOOKUP);
  strcpy(expected[5].m_item.m_dnsLookup.ma_domainName, "a.example.com");
  static_expectEditParams(&expected[6], &credit_budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_SSL_CHECK);
  strcpy(expected[6].m_item.m_sslCheck.ma_domainName, "b.example.org");
  static_expectEditParams(&expected[7], &credit_budget, WATCHLISTEDIT_ACTION_REMOVE, WATCHLIST_ITEM_WHOIS_LOOKUP);
  strcpy(expected[7].m_item.m_whoisLookup.ma_domainName, "example.net");
  static_expectEditParams(&expected[8], &credit_budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_HEADERS_CHECK);
  strcpy(expected[8].m_item.m_headersCheck.ma_domainName, "c.example.io");
  static_expectEditParams(&expected[9], &credit_budget, WATCHLISTEDIT_ACTION_REMOVE, WATCHLIST_ITEM_CERT_SEARCH);
  strcpy(expected[9].m_item.m_certSearch.ma_domainName, "d.example.dev");
  static_expectEditParams(&expected[10], &credit_budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_PACKAGE_CHECK);
  strcpy(expected[10].m_item.m_packageCheck.ma_ecosystem, "Go");
  strcpy(expected[10].m_item.m_packageCheck.ma_name,      "github.com/Gin-Gonic/gin");
  strcpy(expected[10].m_item.m_packageCheck.ma_version,   "v1.9.1");
  static_expectEditParams(&expected[11], &credit_budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_IP_LOOKUP);
  strcpy(expected[11].m_item.m_ipLookup.ma_ipAddress, "2606:4700::1111");
  static_expectEditParams(&expected[12], &credit_budget, WATCHLISTEDIT_ACTION_ADD, WATCHLIST_ITEM_CVE_SEARCH);
  WATCHLISTCVESEARCHItem_t* severity_only = &expected[12].m_item.m_cveSearch;
  strcpy(severity_only->ma_severity, "LOW");
  severity_only->m_minCvss   = -1.0;
  severity_only->m_minEpss   = -1.0;
  severity_only->m_kevFilter = CVE_KEV_FILTER_ANY;

  static const char* const arguments[WATCHLIST_ITEM_KIND_COUNT + 1] = {
    R"({"action":"add","endpoint":"cve_lookup","cve_id":"CVE-2021-44228"})",
    R"({"action":"add","endpoint":"kev_lookup","cve_id":"CVE-2022-0001"})",
    R"({"action":"remove","endpoint":"cve_exploit","cve_id":"CVE-2023-0002"})",
    R"({"action":"add","endpoint":"product_exposure","vendor":"cisco","product":"ios","version":"15.2"})",
    R"({"action":"add","endpoint":"cve_search","vendor":"apache","product":"log4j","severity":"HIGH","cwe_id":"CWE-917","min_cvss":7.5,"min_epss":0.25,"in_kev":false,"known_ransomware":true,"has_nuclei_template":true})",
    R"({"action":"add","endpoint":"dns_lookup","domain":"a.example.com"})",
    R"({"action":"add","endpoint":"ssl_check","domain":"b.example.org"})",
    R"({"action":"remove","endpoint":"whois_lookup","domain":"example.net"})",
    R"({"action":"add","endpoint":"headers_check","domain":"c.example.io"})",
    R"({"action":"remove","endpoint":"cert_search","domain":"d.example.dev"})",
    R"({"action":"add","endpoint":"package_check","ecosystem":"Go","name":"github.com/Gin-Gonic/gin","version":"v1.9.1"})",
    R"({"action":"add","endpoint":"ip_lookup","ip_address":"2606:4700:0000::1111"})",
    R"({"action":"add","endpoint":"cve_search","severity":"LOW"})",
  };
  for (size_t i = 0; i < sizeof(arguments) / sizeof(arguments[0]); i++)
  {
    memset(&g_stub_WATCHLISTEDIT_last_params, 0x5A, sizeof(g_stub_WATCHLISTEDIT_last_params));
    int   status;
    char* response = static_watchlistCall("watchlist_edit", arguments[i], &credit_budget, &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, arguments[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, R"("isError":false)"), arguments[i]);
    free(response);
    TEST_ASSERT_EQUAL_INT_MESSAGE((int)i + 1, g_stub_WATCHLISTEDIT_call_count, arguments[i]);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(&expected[i], &g_stub_WATCHLISTEDIT_last_params, sizeof(expected[i]), arguments[i]);
  }
}

void test_watchlist_edit_hands_the_db_the_action_of_the_request(void)
{
  RequestCreditBudget_t credit_budget;
  static_watchlistBudget(&credit_budget, REQUEST_TIER_PRO);
  g_stub_WATCHLISTEDIT_status = DB_OK;

  WATCHLISTEDITItemsDbParams_t expected[4];
  static_expectEditParams(&expected[0], &credit_budget, WATCHLISTEDIT_ACTION_LIST,   WATCHLIST_ITEM_CVE_LOOKUP);
  static_expectEditParams(&expected[1], &credit_budget, WATCHLISTEDIT_ACTION_CLEAR,  WATCHLIST_ITEM_CVE_LOOKUP);
  static_expectEditParams(&expected[2], &credit_budget, WATCHLISTEDIT_ACTION_ADD,    WATCHLIST_ITEM_CVE_LOOKUP);
  strcpy(expected[2].m_item.m_cveLookup.ma_cveId, "CVE-2024-3094");
  static_expectEditParams(&expected[3], &credit_budget, WATCHLISTEDIT_ACTION_REMOVE, WATCHLIST_ITEM_CVE_LOOKUP);
  strcpy(expected[3].m_item.m_cveLookup.ma_cveId, "CVE-2024-3094");
  static const char* const arguments[4] = {
    R"({})",
    R"({"clear":true})",
    R"({"action":"add","endpoint":"cve_lookup","cve_id":"CVE-2024-3094"})",
    R"({"action":"remove","endpoint":"cve_lookup","cve_id":"CVE-2024-3094"})",
  };
  for (size_t i = 0; i < sizeof(arguments) / sizeof(arguments[0]); i++)
  {
    memset(&g_stub_WATCHLISTEDIT_last_params, 0x5A, sizeof(g_stub_WATCHLISTEDIT_last_params));
    int   status;
    char* response = static_watchlistCall("watchlist_edit", arguments[i], &credit_budget, &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, arguments[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, R"("isError":false)"), arguments[i]);
    free(response);
    TEST_ASSERT_EQUAL_INT_MESSAGE((int)i + 1, g_stub_WATCHLISTEDIT_call_count, arguments[i]);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(&expected[i], &g_stub_WATCHLISTEDIT_last_params, sizeof(expected[i]), arguments[i]);
  }
}

void test_watchlist_events_answers_the_feed_and_each_db_status(void)
{
  RequestCreditBudget_t credit_budget;
  static_watchlistBudget(&credit_budget, REQUEST_TIER_PRO);
  g_stub_WATCHLISTEVENTS_status = DB_OK;
  int status;
  char* response = static_watchlistCall("watchlist_events", R"({"limit":7})", &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":false)");
  static_assertContains(response, R"({\"limit\":7,\"cursor\":null,\"repeat\":false,\"next_cursor\":\"58\",\"has_more\":false,\"items\":[{\"item\":{\"endpoint\":\"cve_lookup\",\"cve_id\":\"CVE-2021-44228\"},\"events\":[{\"event\":\"kev_added\",\"changed_at\":\"2026-10-15T08:09:10Z\",\"cve_id\":\"CVE-2021-44228\",\"previous\":null,\"current\":null,\"vendor\":null,\"product\":null}]},{\"item\":{\"endpoint\":\"dns_lookup\",\"domain\":\"example.com\"},\"events\":[{\"event\":\"ns_changed\",\"changed_at\":\"2026-10-15T08:09:11Z\",\"previous\":[\"ns1.example.net\",\"ns2.example.net\"],\"current\":[\"ns1.example.org\"]}]},{\"item\":{\"endpoint\":\"package_check\",\"ecosystem\":\"npm\",\"name\":\"lodash\",\"version\":\"4.17.20\"},\"events\":[{\"event\":\"fix_available\",\"changed_at\":\"2026-10-15T08:09:12Z\",\"cve_id\":null,\"advisory_id\":\"GHSA-p6mc-m468-83gw\",\"fixed_version\":\"4.17.21\",\"affects_version\":true}]},{\"item\":{\"endpoint\":\"product_exposure\",\"vendor\":\"f5\",\"product\":\"nginx\",\"version\":\"1.24.0\",\"product_has_cves\":true},\"events\":[{\"event\":\"eol_date_changed\",\"changed_at\":\"2026-10-15T08:09:13Z\",\"cve_id\":null,\"eol\":{\"product\":\"nginx\",\"cycle\":\"1.24\",\"eol_date\":\"2027-05-31\",\"previous_eol_date\":\"2026-11-30\"}}]}],\"cves\":{\"CVE-2021-44228\":{\"risk_score\":96.5,\"label\":\"CRITICAL\",\"in_kev\":true,\"kev_patch_deadline\":\"2021-12-24\",\"known_ransomware\":true,\"has_metasploit\":false,\"poc_count\":3},\"CVE-2020-8203\":{\"risk_score\":74.0,\"label\":\"HIGH\",\"in_kev\":false,\"kev_patch_deadline\":null,\"known_ransomware\":false,\"has_metasploit\":true,\"poc_count\":9}},\"domains\":{\"example.com\":{\"registered_domain\":\"example.com\",\"dns_presence\":\"found\",\"ns\":[\"ns1.example.org\"],\"mx\":[\"10 mx.example.com\"],\"ip_address_reachability\":\"public\",\"cname_takeover\":\"none\",\"email_auth_failing\":{\"dmarc_record\":\"fail\",\"dmarc_policy\":\"warn\"}}},\"advisories\":{\"GHSA-p6mc-m468-83gw\":{\"source\":\"ghsa\",\"aliases\":[\"CVE-2020-8203\"]}},\"attribution\":[{\"source\":\"endoflife.date\",\"license\":\"MIT\"},{\"source\":\"ghsa\",\"license\":\"CC-BY-4.0\"}]})");
  free(response);
  TEST_ASSERT_EQUAL_INT(7, g_stub_WATCHLISTEVENTS_last_event_row_count);
  TEST_ASSERT_EQUAL_PTR(&credit_budget, g_stub_WATCHLISTEVENTS_last_params.mp_creditBudget);
  TEST_ASSERT_EQUAL_INT(1, g_stub_WATCHLISTEVENTSResultFree_call_count);

  response = static_watchlistCall("watchlist_events", R"({"repeat":true})", &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"({\"limit\":20,\"cursor\":null,\"repeat\":true,\"next_cursor\":\"58\",\"has_more\":false,\"items\":[{\"item\":{\"endpoint\":\"cve_lookup\")");
  static_assertContains(response, R"(\"current\":[\"ns1.example.org\"]}]},{\"item\":{\"endpoint\":\"package_check\",\"ecosystem\":\"npm\",\"name\":\"lodash\",\"version\":\"4.17.20\"},\"events\":[{\"event\":\"fix_available\",\"changed_at\":\"2026-10-15T08:09:12Z\",\"cve_id\":null,\"advisory_id\":\"GHSA-p6mc-m468-83gw\",\"fixed_version\":\"4.17.21\",\"affects_version\":true}]},{\"item\":{\"endpoint\":\"product_exposure\",)");
  free(response);
  TEST_ASSERT_EQUAL_INT(CVE_LIST_MAX_LIMIT, g_stub_WATCHLISTEVENTS_last_event_row_count);
  TEST_ASSERT_TRUE(g_stub_WATCHLISTEVENTS_last_params.m_isRepeat);

  g_stub_WATCHLISTEVENTS_result_status = WATCHLISTEVENTS_NO_POSITION;
  response = static_watchlistCall("watchlist_events", "{}", &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"({\"limit\":20,\"cursor\":null,\"repeat\":false,\"next_cursor\":null,\"has_more\":false,\"items\":[],\"cves\":{},\"domains\":{},\"advisories\":{},\"attribution\":[]})");
  free(response);

  g_stub_WATCHLISTEVENTS_result_status = WATCHLISTEVENTS_CURSOR_INVALID;
  response = static_watchlistCall("watchlist_events", R"({"cursor":"41"})", &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"cursor_invalid: start again without cursor"}],"isError":true)");
  free(response);
  TEST_ASSERT_EQUAL_STRING("41", g_stub_WATCHLISTEVENTS_last_params.ma_cursor);

  g_stub_WATCHLISTEVENTS_result_status = WATCHLISTEVENTS_UNKNOWN_KEY;
  response = static_watchlistCall("watchlist_events", "{}", &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("code":-32603,"message":"Internal error: database query failed")");
  free(response);
  TEST_ASSERT_EQUAL_INT(5, g_stub_WATCHLISTEVENTS_call_count);
}

void test_watchlist_tools_refuse_shapes_before_any_query(void)
{
  RequestCreditBudget_t credit_budget;
  static_watchlistBudget(&credit_budget, REQUEST_TIER_PRO);
  g_stub_WATCHLISTEDIT_status   = DB_OK;
  g_stub_WATCHLISTEVENTS_status = DB_OK;
  static const struct { const char* mp_tool; const char* mp_arguments; const char* mp_message; } cases[] = {
    { "watchlist_events", R"({"cursor":"41","repeat":true})",                                          "cursor and repeat cannot be combined" },
    { "watchlist_events", R"({"cursor":"01"})",                                                        "cursor must be the next_cursor of an earlier answer" },
    { "watchlist_edit",   R"({"clear":true,"action":"add"})",                                          "clear takes no action and no item" },
    { "watchlist_edit",   R"({"action":"add","endpoint":"cve_search","cve_id":"CVE-2021-44228"})",     "cve_search items take at least one filter and no cve_id, domain, ecosystem, name, version or ip_address" },
    { "watchlist_edit",   R"({"action":"add","endpoint":"cve_search"})",                               "cve_search items take at least one filter and no cve_id, domain, ecosystem, name, version or ip_address" },
    { "watchlist_edit",   R"({"action":"add","endpoint":"cve_search","has_nuclei_template":false})",   "has_nuclei_template must be true" },
    { "watchlist_edit",   R"({"action":"add","endpoint":"cve_search","min_epss":0.1505})",              "min_epss of a cve_search item takes at most three decimals" },
    { "watchlist_edit",   R"({"action":"remove","endpoint":"product_exposure","vendor":"apache"})",    "product_exposure items take one vendor and one product, and may take a version" },
    { "watchlist_edit",   R"({"vendor":"apache"})",                                                    "an item needs action=add or action=remove" },
    { "watchlist_edit",   R"({"action":"add","endpoint":"ssl_check","cve_id":"CVE-2021-44228"})",      "dns_lookup, ssl_check, whois_lookup, headers_check and cert_search items take exactly one domain" },
    { "watchlist_edit",   R"({"endpoint":"cve_leading"})",                                             "endpoint must be one of cve_lookup, kev_lookup, cve_exploit, product_exposure, cve_search, dns_lookup, ssl_check, whois_lookup, headers_check, cert_search, package_check, ip_lookup" },
    { "watchlist_edit",   R"({"endpoint":"cve_triage"})",                                              "endpoint must be one of cve_lookup, kev_lookup, cve_exploit, product_exposure, cve_search, dns_lookup, ssl_check, whois_lookup, headers_check, cert_search, package_check, ip_lookup" },
    { "watchlist_edit",   R"({"action":"add","endpoint":"dns_takeover_check","domain":"example.com"})", "endpoint is too long" },
    { "watchlist_edit",   R"({"action":"add","endpoint":"dns_lookup","domain":"co.uk"})",              "domain is a public suffix, such as co.uk; name a domain registered under it" },
    { "watchlist_edit",   R"({"action":"add","endpoint":"package_check","ecosystem":"npm"})",          "package_check items take one ecosystem and one name, and may take a version" },
    { "watchlist_edit",   R"({"action":"add","endpoint":"package_check","ecosystem":"npm","name":"lodash","cve_id":"CVE-2021-44228"})", "package_check items take one ecosystem and one name, and may take a version" },
    { "watchlist_edit",   R"({"action":"add","endpoint":"cve_lookup","cve_id":"CVE-2021-44228","version":"1.0.0"})", "cve_lookup, kev_lookup and cve_exploit items take exactly one cve_id" },
    { "watchlist_edit",   R"({"action":"add","endpoint":"package_check","ecosystem":"Pub","name":"lodash"})", "ecosystem must be one of npm, PyPI, Maven, Go, NuGet, RubyGems, crates.io, Packagist or SwiftURL" },
    { "watchlist_edit",   R"({"action":"add","endpoint":"package_check","ecosystem":"npm","name":"left pad"})", "name must not contain a space" },
    { "watchlist_edit",   R"({"action":"add","endpoint":"package_check","ecosystem":"npm","name":"lodash","version":"1.0 beta"})", "version must hold only visible ASCII characters, with no space" },
    { "watchlist_edit",   R"({"action":"add","endpoint":"ip_lookup"})",                                "ip_lookup items take exactly one ip_address" },
    { "watchlist_edit",   R"({"action":"add","endpoint":"ip_lookup","ip_address":"8.8.8.8","domain":"example.com"})", "ip_lookup items take exactly one ip_address" },
    { "watchlist_edit",   R"({"action":"add","endpoint":"dns_lookup","domain":"example.com","ip_address":"8.8.8.8"})", "dns_lookup, ssl_check, whois_lookup, headers_check and cert_search items take exactly one domain" },
    { "watchlist_edit",   R"({"action":"add","endpoint":"ip_lookup","ip_address":"1.2.3.0/24"})",       "Provide a public IPv4 or IPv6 address, such as 8.8.8.8 or 2001:4860:4860::8888." },
    { "watchlist_edit",   R"({"action":"add","endpoint":"ip_lookup","ip_address":"192.168.1.1"})",      "Provide a public IPv4 or IPv6 address, such as 8.8.8.8 or 2001:4860:4860::8888." },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    int status;
    char* response = static_watchlistCall(cases[i].mp_tool, cases[i].mp_arguments, &credit_budget, &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, cases[i].mp_arguments);
    char needle[256];
    int written = snprintf(needle, sizeof(needle), R"("text":"%s"}],"isError":true)", cases[i].mp_message);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(needle));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, needle), cases[i].mp_arguments);
    free(response);
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_WATCHLISTEDIT_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WATCHLISTEVENTS_call_count);
}

void test_watchlist_tools_without_a_credit_budget_are_32603(void)
{
  g_stub_WATCHLISTEDIT_status   = DB_OK;
  g_stub_WATCHLISTEVENTS_status = DB_OK;
  int status;
  char* response = static_watchlistCall("watchlist_edit", "{}", NULL, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("code":-32603,"message":"Internal error"})");
  free(response);
  response = static_watchlistCall("watchlist_events", "{}", NULL, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("code":-32603,"message":"Internal error"})");
  free(response);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WATCHLISTEDIT_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WATCHLISTEVENTS_call_count);
}

#define SHA1_OF_PASSWORD "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"

void test_tool_PASSWORDCHECK_found(void)
{
  g_stub_PASSWORDCHECK_breach_count = 3861493;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":49,"method":"tools/call",)"
                     R"("params":{"name":"password_check","arguments":{"sha1_hash":")" SHA1_OF_PASSWORD R"("}}})", &status);
  static_assertContains(response, R"(\"hash_prefix\":\"5BAA6\",\"found\":true,\"breach_count\":3861493,)");
  static_assertContains(response, R"(\"summary\":\"This password has been seen 3,861,493 times in data breaches.\")");
  TEST_ASSERT_EQUAL_INT(1, g_stub_PASSWORDCHECK_call_count);
  TEST_ASSERT_EQUAL_STRING(SHA1_OF_PASSWORD, g_stub_PASSWORDCHECK_last_sha1_hex);
  static_assertToolSucceeded(response, status);
}

void test_tool_PASSWORDCHECK_prefix_is_a_tool_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":50,"method":"tools/call",)"
                     R"("params":{"name":"password_check","arguments":{"sha1_hash":"5BAA6"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"Provide the full SHA1 hash (40 hexadecimal characters)."}],"isError":true)");
  TEST_ASSERT_EQUAL_INT(0, g_stub_PASSWORDCHECK_call_count);
  free(response);
}

void test_tool_PASSWORDCHECK_missing_hash_is_32602(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":51,"method":"tools/call","params":{"name":"password_check"}})", &status);
  static_assertContains(response, R"("error":{"code":-32602,"message":"Invalid params: sha1_hash is required"})");
  TEST_ASSERT_EQUAL_INT(0, g_stub_PASSWORDCHECK_call_count);
  free(response);
}

void test_tool_PASSWORDCHECK_upstream_error_is_32603(void)
{
  g_stub_PASSWORDCHECK_status = HIBP_UPSTREAM_ERROR;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":52,"method":"tools/call",)"
                     R"("params":{"name":"password_check","arguments":{"sha1_hash":")" SHA1_OF_PASSWORD R"("}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("error":{"code":-32603,"message":"Internal error: upstream unavailable"})");
  TEST_ASSERT_NULL(strstr(response, "isError"));
  TEST_ASSERT_EQUAL_INT(1, g_stub_PASSWORDCHECK_call_count);
  free(response);
}

void test_tool_D3FENDFORATTACK_found(void)
{
  g_stub_D3FENDFORATTACK_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":92,"method":"tools/call",)"
                     R"("params":{"name":"d3fend_for_attack","arguments":{"attack_technique_id":"T1055.012"}}})", &status);
  static_assertContains(response, R"({\"attack_technique_id\":\"T1055.012\",\"attack_techniques\":[{\"attack_technique_id\":\"T1055.012\",\"subtechnique_of\":\"T1055\",\"attack_label\":\"Process Hollowing\"}],)");
  static_assertContains(response, R"(\"defense_count_by_defense_tactic\":{\"Model\":0,\"Harden\":1,\"Detect\":1,\"Isolate\":0,\"Deceive\":0,\"Evict\":0,\"Restore\":0},)");
  static_assertContains(response, R"(\"parent_defense_labels\":[\"Process Analysis\"],\"defense_tactic\":\"Detect\",\"digital_artifact\":\"System Call\",\"attack_technique_ids\":[\"T1055.012\"]}]})");
  TEST_ASSERT_EQUAL_INT(1, g_stub_D3FENDFORATTACK_call_count);
  TEST_ASSERT_EQUAL_STRING("T1055.012", g_stub_D3FENDFORATTACK_last_id);
  TEST_ASSERT_EQUAL_INT(1, g_stub_D3FENDFORATTACKResultFree_call_count);
  static_assertToolSucceeded(response, status);
}

void test_tool_D3FENDFORATTACK_lower_case_is_a_tool_error(void)
{
  g_stub_D3FENDFORATTACK_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":93,"method":"tools/call",)"
                     R"("params":{"name":"d3fend_for_attack","arguments":{"attack_technique_id":"t1055"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"Provide a MITRE ATT&CK technique id in upper case, such as T1059 or T1059.001."}],"isError":true)");
  TEST_ASSERT_EQUAL_INT(0, g_stub_D3FENDFORATTACK_call_count);
  free(response);
}

void test_tool_D3FENDFORATTACK_missing_id_is_32602(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":94,"method":"tools/call","params":{"name":"d3fend_for_attack"}})", &status);
  static_assertContains(response, R"("error":{"code":-32602,"message":"Invalid params: attack_technique_id is required"})");
  TEST_ASSERT_EQUAL_INT(0, g_stub_D3FENDFORATTACK_call_count);
  free(response);
}

void test_tool_D3FENDFORATTACK_db_error_is_32603(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":95,"method":"tools/call",)"
                     R"("params":{"name":"d3fend_for_attack","arguments":{"attack_technique_id":"T1055"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("error":{"code":-32603,"message":"Internal error: database query failed"})");
  TEST_ASSERT_NULL(strstr(response, "isError"));
  TEST_ASSERT_EQUAL_INT(1, g_stub_D3FENDFORATTACK_call_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_D3FENDFORATTACKResultFree_call_count);
  free(response);
}

#define DRIVERLOOKUP_TEST_MD5 "5F4DCC3B5AA765D61D8327DEB882CF99"

void test_tool_DRIVERLOOKUP_found(void)
{
  g_stub_DRIVERLOOKUP_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":96,"method":"tools/call",)"
                     R"("params":{"name":"driver_lookup","arguments":{"file_hash":")" DRIVERLOOKUP_TEST_MD5 R"(","include_commands":true}}})", &status);
  static_assertContains(response, R"({\"hash\":\"5f4dcc3b5aa765d61d8327deb882cf99\",\"hash_type\":\"md5\",)"
                                  R"(\"data_source\":{\"source\":\"loldrivers\",\"available\":true,\"license\":\"Apache-2.0\"},)"
                                  R"(\"found\":true,\"match_count\":1,\"matches\":[{\"driver_id\":\"00000000-0000-0000-0000-00000000000a\",)");
  TEST_ASSERT_EQUAL_INT(1, g_stub_DRIVERLOOKUP_call_count);
  TEST_ASSERT_EQUAL_STRING(DRIVERLOOKUP_TEST_MD5, g_stub_DRIVERLOOKUP_last_hash);
  TEST_ASSERT_TRUE(g_stub_DRIVERLOOKUP_last_is_command_included);
  TEST_ASSERT_EQUAL_INT(1, g_stub_DRIVERLOOKUPRecordFree_call_count);
  static_assertToolSucceeded(response, status);
}

void test_tool_DRIVERLOOKUP_refused_values_are_tool_errors(void)
{
  g_stub_DRIVERLOOKUP_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":97,"method":"tools/call",)"
                     R"("params":{"name":"driver_lookup","arguments":{"file_hash":"5f4dcc3b5aa765d61d8327deb882cf9"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"Provide an MD5, SHA1 or SHA256 hash (32, 40 or 64 hexadecimal characters)."}],"isError":true)");
  free(response);
  response = static_dispatch(R"({"jsonrpc":"2.0","id":98,"method":"tools/call",)"
               R"("params":{"name":"driver_lookup","arguments":{"file_hash":")" DRIVERLOOKUP_TEST_MD5 R"(","include_commands":"true"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"include_commands must be true or false"}],"isError":true)");
  free(response);
  TEST_ASSERT_EQUAL_INT(0, g_stub_DRIVERLOOKUP_call_count);
}

void test_tool_DRIVERLOOKUP_missing_hash_is_32602(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"driver_lookup"}})", &status);
  static_assertContains(response, R"("error":{"code":-32602,"message":"Invalid params: file_hash is required"})");
  TEST_ASSERT_EQUAL_INT(0, g_stub_DRIVERLOOKUP_call_count);
  free(response);
}

void test_tool_DRIVERLOOKUP_db_error_is_32603(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":100,"method":"tools/call",)"
                     R"("params":{"name":"driver_lookup","arguments":{"file_hash":")" DRIVERLOOKUP_TEST_MD5 R"("}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("error":{"code":-32603,"message":"Internal error: database query failed"})");
  TEST_ASSERT_NULL(strstr(response, "isError"));
  TEST_ASSERT_EQUAL_INT(1, g_stub_DRIVERLOOKUP_call_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_DRIVERLOOKUPRecordFree_call_count);
  free(response);
}

void test_tool_PACKAGECHECK_found(void)
{
  g_stub_PACKAGECHECK_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":104,"method":"tools/call",)"
                     R"("params":{"name":"package_check","arguments":{"ecosystem":"npm","name":"lodash","version":"4.17.20","limit":5}}})", &status);
  static_assertContains(response, R"({\"data_source\":{\"source\":\"osv\",\"available\":true},\"has_advisory_data\":true,\"total\":1,\"limit\":5,)"
                                  R"(\"offset\":0,\"next_offset\":1,\"fixed_version\":\"4.17.21\",)");
  TEST_ASSERT_EQUAL_INT(1, g_stub_PACKAGECHECK_call_count);
  TEST_ASSERT_EQUAL_STRING("npm", g_stub_PACKAGECHECK_last_params.ma_ecosystem);
  TEST_ASSERT_EQUAL_STRING("lodash", g_stub_PACKAGECHECK_last_params.ma_packageName);
  TEST_ASSERT_EQUAL_STRING("4.17.20", g_stub_PACKAGECHECK_last_params.ma_version);
  TEST_ASSERT_EQUAL_INT(5, g_stub_PACKAGECHECK_last_params.m_limit);
  TEST_ASSERT_EQUAL_INT(0, g_stub_PACKAGECHECK_last_params.m_offset);
  TEST_ASSERT_EQUAL_INT(1, g_stub_PACKAGECHECKResultFree_call_count);
  static_assertToolSucceeded(response, status);
}

void test_tool_PACKAGECHECK_refused_values_are_tool_errors(void)
{
  g_stub_PACKAGECHECK_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":105,"method":"tools/call",)"
                     R"("params":{"name":"package_check","arguments":{"ecosystem":"Pub","name":"lodash"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":")" VALIDATE_PACKAGE_ECOSYSTEM_REFUSAL_MESSAGE R"("}],"isError":true)");
  free(response);
  response = static_dispatch(R"({"jsonrpc":"2.0","id":106,"method":"tools/call",)"
               R"("params":{"name":"package_check","arguments":{"ecosystem":"npm","name":"left pad"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":")" VALIDATE_PACKAGE_NAME_REFUSAL_MESSAGE R"("}],"isError":true)");
  free(response);
  TEST_ASSERT_EQUAL_INT(0, g_stub_PACKAGECHECK_call_count);
}

void test_tool_PACKAGECHECK_missing_name_is_32602(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":107,"method":"tools/call",)"
                     R"("params":{"name":"package_check","arguments":{"ecosystem":"npm"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("error":{"code":-32602,"message":"Invalid params: name is required"})");
  TEST_ASSERT_EQUAL_INT(0, g_stub_PACKAGECHECK_call_count);
  free(response);
}

void test_tool_PACKAGECHECK_db_error_is_32603(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":108,"method":"tools/call",)"
                     R"("params":{"name":"package_check","arguments":{"ecosystem":"npm","name":"lodash"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("error":{"code":-32603,"message":"Internal error: database query failed"})");
  TEST_ASSERT_NULL(strstr(response, "isError"));
  TEST_ASSERT_EQUAL_INT(1, g_stub_PACKAGECHECK_call_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_PACKAGECHECKResultFree_call_count);
  free(response);
}

void test_tool_PACKAGECHECKBULK_found(void)
{
  g_stub_PACKAGECHECKBULK_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":109,"method":"tools/call","params":{"name":"package_check_bulk","arguments":{"items":[)"
                     R"({"ecosystem":"npm","name":"lodash","version":"4.17.20"},{"ecosystem":"npm","name":"lodash","version":"^4.0.0"}]}}})", &status);
  static_assertContains(response, R"("text":"{\"total\":2,\"processed\":1,\"successful\":1,\"skipped\":1,\"failed\":0,\"not_processed\":[],)"
                                  R"(\"data_source\":{\"source\":\"osv\",\"available\":true},)"
                                  R"(\"results\":[{\"name\":\"lodash\",\"advisories\":[]}],)"
                                  R"(\"attribution\":[{\"source\":\"ghsa\",\"license\":\"CC-BY-4.0\"}]}\n"}])");
  TEST_ASSERT_EQUAL_INT(1, g_stub_PACKAGECHECKBULK_call_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_PACKAGECHECKBULK_last_item_count);
  TEST_ASSERT_EQUAL_STRING("npm", g_stub_PACKAGECHECKBULK_last_items[0].ma_ecosystem);
  TEST_ASSERT_EQUAL_STRING("lodash", g_stub_PACKAGECHECKBULK_last_items[0].ma_packageName);
  TEST_ASSERT_EQUAL_STRING("4.17.20", g_stub_PACKAGECHECKBULK_last_items[0].ma_version);
  TEST_ASSERT_EQUAL_INT(1, g_stub_PACKAGECHECKBULKResultFree_call_count);
  static_assertToolSucceeded(response, status);
}

void test_tool_PACKAGECHECKBULK_repeat_missing_and_object_items_are_refused(void)
{
  g_stub_PACKAGECHECKBULK_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":110,"method":"tools/call","params":{"name":"package_check_bulk","arguments":{"items":[)"
                     R"({"ecosystem":"npm","name":"lodash","version":"4.17.20"},{"ecosystem":"NPM","name":"lodash","version":"4.17.20"}]}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"items[1] repeats items[0]"}],"isError":true)");
  free(response);
  response = static_dispatch(R"({"jsonrpc":"2.0","id":111,"method":"tools/call","params":{"name":"package_check_bulk"}})", &status);
  static_assertContains(response, R"("error":{"code":-32602,"message":"Invalid params: items is required"})");
  free(response);
  response = static_dispatch(R"({"jsonrpc":"2.0","id":112,"method":"tools/call","params":{"name":"package_check_bulk","arguments":{"items":{}}}})", &status);
  static_assertContains(response, R"("error":{"code":-32602,"message":"Invalid params: items must be an array"})");
  free(response);
  TEST_ASSERT_EQUAL_INT(0, g_stub_PACKAGECHECKBULK_call_count);
}

void test_tool_PACKAGECHECKBULK_db_error_is_32603(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":113,"method":"tools/call","params":{"name":"package_check_bulk","arguments":{"items":[)"
                     R"({"ecosystem":"npm","name":"lodash","version":"4.17.20"}]}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("error":{"code":-32603,"message":"Internal error: database query failed"})");
  TEST_ASSERT_NULL(strstr(response, "isError"));
  TEST_ASSERT_EQUAL_INT(1, g_stub_PACKAGECHECKBULK_call_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_PACKAGECHECKBULKResultFree_call_count);
  free(response);
}

void test_tool_DRIVERLOOKUPBULK_found(void)
{
  g_stub_DRIVERLOOKUPBULK_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":101,"method":"tools/call",)"
                     R"("params":{"name":"driver_lookup_bulk","arguments":{"hashes":[")" DRIVERLOOKUP_TEST_MD5 R"(","foo"]}}})", &status);
  static_assertContains(response, R"({\"total\":2,\"processed\":1,\"successful\":1,\"skipped\":1,\"failed\":0,\"not_processed\":[],)"
                                  R"(\"data_source\":{\"source\":\"loldrivers\",\"available\":true,\"license\":\"Apache-2.0\"},)"
                                  R"(\"results\":[{\"hash\":\"5f4dcc3b5aa765d61d8327deb882cf99\",\"hash_type\":\"md5\",\"found\":true,\"match_count\":1,)");
  TEST_ASSERT_EQUAL_INT(1, g_stub_DRIVERLOOKUPBULK_call_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_DRIVERLOOKUPBULK_last_id_count);
  TEST_ASSERT_EQUAL_STRING("5f4dcc3b5aa765d61d8327deb882cf99", g_stub_DRIVERLOOKUPBULK_last_ids[0]);
  TEST_ASSERT_EQUAL_INT(1, g_stub_DRIVERLOOKUPBULKResultFree_call_count);
  static_assertToolSucceeded(response, status);
}

void test_tool_DRIVERLOOKUPBULK_repeat_and_missing_hashes_are_refused(void)
{
  g_stub_DRIVERLOOKUPBULK_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":102,"method":"tools/call",)"
                     R"("params":{"name":"driver_lookup_bulk","arguments":{"hashes":[")" DRIVERLOOKUP_TEST_MD5 R"(","5f4dcc3b5aa765d61d8327deb882cf99"]}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"hashes[1] repeats hashes[0]"}],"isError":true)");
  free(response);
  response = static_dispatch(R"({"jsonrpc":"2.0","id":103,"method":"tools/call","params":{"name":"driver_lookup_bulk"}})", &status);
  static_assertContains(response, R"("error":{"code":-32602,"message":"Invalid params: hashes is required"})");
  free(response);
  TEST_ASSERT_EQUAL_INT(0, g_stub_DRIVERLOOKUPBULK_call_count);
}

void test_tool_DRIVERLOOKUPBULK_db_error_is_32603(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":104,"method":"tools/call",)"
                     R"("params":{"name":"driver_lookup_bulk","arguments":{"hashes":[")" DRIVERLOOKUP_TEST_MD5 R"("]}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("error":{"code":-32603,"message":"Internal error: database query failed"})");
  TEST_ASSERT_NULL(strstr(response, "isError"));
  TEST_ASSERT_EQUAL_INT(1, g_stub_DRIVERLOOKUPBULK_call_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_DRIVERLOOKUPBULKResultFree_call_count);
  free(response);
}

void test_tool_DNSLOOKUP_answer(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":53,"method":"tools/call",)"
                     R"("params":{"name":"dns_lookup","arguments":{"domain":"example.com"}}})", &status);
  static_assertContains(response, R"(\"records\":{\"a\":[\"93.184.215.14\",\"10.0.0.7\"],\"aaaa\":[],)");
  static_assertContains(response, R"(\"unavailable\":{\"caa\":\"timeout\"},\"non_public_addresses\":[\"10.0.0.7\"],)");
  static_assertContains(response, R"(\"services\":[{\"name\":\"google-workspace\",\"evidence\":\"google-site-verification\"}])");
  TEST_ASSERT_EQUAL_INT(1, g_stub_DNSLOOKUP_call_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_DNSLOOKUP_free_count);
  TEST_ASSERT_EQUAL_STRING("example.com", g_stub_DNSLOOKUP_last_domain);
  static_assertToolSucceeded(response, status);
}

void test_tool_DNSLOOKUP_special_use_name_is_a_tool_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":54,"method":"tools/call",)"
                     R"("params":{"name":"dns_lookup","arguments":{"domain":"printer.local"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"Provide a public domain name, such as example.com."}],"isError":true)");
  TEST_ASSERT_EQUAL_INT(0, g_stub_DNSLOOKUP_call_count);
  free(response);
}

void test_tool_DNSLOOKUP_missing_domain_is_32602(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":55,"method":"tools/call","params":{"name":"dns_lookup"}})", &status);
  static_assertContains(response, R"("error":{"code":-32602,"message":"Invalid params: domain is required"})");
  TEST_ASSERT_EQUAL_INT(0, g_stub_DNSLOOKUP_call_count);
  free(response);
}

void test_tool_DNSLOOKUP_not_found_and_no_answer(void)
{
  int status;
  g_stub_DNSLOOKUP_status = DNS_LOOKUP_NOT_FOUND;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":56,"method":"tools/call",)"
                     R"("params":{"name":"dns_lookup","arguments":{"domain":"example.com"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"domain does not exist"}],"isError":true)");
  free(response);

  g_stub_DNSLOOKUP_status = DNS_LOOKUP_NO_ANSWER;
  response = static_dispatch(R"({"jsonrpc":"2.0","id":57,"method":"tools/call",)"
                     R"("params":{"name":"dns_lookup","arguments":{"domain":"example.com"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("error":{"code":-32603,"message":"Internal error: upstream unavailable"})");
  TEST_ASSERT_NULL(strstr(response, "isError"));
  TEST_ASSERT_EQUAL_INT(2, g_stub_DNSLOOKUP_call_count);
  TEST_ASSERT_EQUAL_INT(2, g_stub_DNSLOOKUP_free_count);
  free(response);
}

void test_tool_DNSTAKEOVERCHECK_answer(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":58,"method":"tools/call",)"
                     R"("params":{"name":"dns_takeover_check","arguments":{"domain":"shop.example.com"}}})", &status);
  static_assertContains(response, R"(\"cname\":\"shop-example.cloudapp.net\",\"chain\":[\"shop-example.cloudapp.net\"],\"target_exists\":false,\"dangling\":true,\"provider\":\"Microsoft Azure\",\"takeover_possible\":true,)");
  TEST_ASSERT_EQUAL_INT(1, g_stub_DNSTAKEOVERCHECK_call_count);
  TEST_ASSERT_EQUAL_STRING("shop.example.com", g_stub_DNSTAKEOVERCHECK_last_hostname);
  static_assertToolSucceeded(response, status);
}

void test_tool_DNSTAKEOVERCHECK_missing_and_refused_domain(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":59,"method":"tools/call","params":{"name":"dns_takeover_check"}})", &status);
  static_assertContains(response, R"("error":{"code":-32602,"message":"Invalid params: domain is required"})");
  free(response);
  response = static_dispatch(R"({"jsonrpc":"2.0","id":60,"method":"tools/call",)"
                     R"("params":{"name":"dns_takeover_check","arguments":{"domain":"10.0.0.1"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"Provide a public domain name, such as example.com."}],"isError":true)");
  TEST_ASSERT_EQUAL_INT(0, g_stub_DNSTAKEOVERCHECK_call_count);
  free(response);
}

void test_tool_DNSTAKEOVERCHECK_not_found_is_a_tool_error(void)
{
  g_stub_DNSTAKEOVERCHECK_status = DNS_LOOKUP_NOT_FOUND;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":61,"method":"tools/call",)"
                     R"("params":{"name":"dns_takeover_check","arguments":{"domain":"shop.example.com"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"hostname does not exist"}],"isError":true)");
  TEST_ASSERT_EQUAL_INT(1, g_stub_DNSTAKEOVERCHECK_call_count);
  free(response);
}

void test_tool_EMAILAUTHCHECK_answer(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":62,"method":"tools/call",)"
                     R"("params":{"name":"email_auth_check","arguments":{"domain":"example.com","dkim_selector":"google"}}})", &status);
  static_assertContains(response, R"(\"checks\":[{\"id\":\"spf_record\",\"result\":\"fail\",\"severity\":\"high\",)");
  TEST_ASSERT_EQUAL_INT(1, g_stub_EMAILAUTHCHECK_call_count);
  TEST_ASSERT_EQUAL_STRING("example.com", g_stub_EMAILAUTHCHECK_last_domain);
  TEST_ASSERT_EQUAL_STRING("google", g_stub_EMAILAUTHCHECK_last_dkim_selector);
  static_assertToolSucceeded(response, status);

  response = static_dispatch(R"({"jsonrpc":"2.0","id":63,"method":"tools/call",)"
                     R"("params":{"name":"email_auth_check","arguments":{"domain":"example.com"}}})", &status);
  TEST_ASSERT_EQUAL_INT(2, g_stub_EMAILAUTHCHECK_call_count);
  TEST_ASSERT_EQUAL_STRING("", g_stub_EMAILAUTHCHECK_last_dkim_selector);
  static_assertToolSucceeded(response, status);
}

void test_tool_EMAILAUTHCHECK_missing_domain_and_refused_selector(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":64,"method":"tools/call","params":{"name":"email_auth_check"}})", &status);
  static_assertContains(response, R"("error":{"code":-32602,"message":"Invalid params: domain is required"})");
  free(response);
  response = static_dispatch(R"({"jsonrpc":"2.0","id":65,"method":"tools/call",)"
                     R"("params":{"name":"email_auth_check","arguments":{"domain":"example.com","dkim_selector":"a_b"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"dkim_selector must be labels of 1 to 63 letters, digits and hyphens, with dots between them, such as google. A label must not start or end with a hyphen."}],"isError":true)");
  TEST_ASSERT_EQUAL_INT(0, g_stub_EMAILAUTHCHECK_call_count);
  free(response);
}

void test_tool_SSLCHECK_answer(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":66,"method":"tools/call",)"
                     R"("params":{"name":"ssl_check","arguments":{"domain":"shop.example.com"}}})", &status);
  static_assertContains(response, R"({\"hostname\":\"shop.example.com\",\"ip_address\":\"192.0.2.10\",)");
  static_assertContains(response, R"(\"cipher\":{\"name\":\"ECDHE-RSA-AES128-GCM-SHA256\",\"bits\":128},)");
  TEST_ASSERT_EQUAL_INT(1, g_stub_TLSPROBE_call_count);
  TEST_ASSERT_EQUAL_STRING("shop.example.com", g_stub_TLSPROBE_last_hostname);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_STRING("ssl_check:shop.example.com", g_stub_CACHE_last_get_key);
  TEST_ASSERT_TRUE(g_stub_CACHE_last_get_conn == g_conn);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_STRING("ssl_check:shop.example.com", g_stub_CACHE_last_put_key);
  static_assertToolSucceeded(response, status);

  g_stub_CACHE_get_status = CACHE_HIT;
  g_stub_CACHE_get_body   = R"({"kept":true})";
  response = static_dispatch(R"({"jsonrpc":"2.0","id":67,"method":"tools/call",)"
                     R"("params":{"name":"ssl_check","arguments":{"domain":"shop.example.com"}}})", &status);
  static_assertContains(response, R"("content":[{"type":"text","text":"{\"kept\":true}"}],"isError":false)");
  TEST_ASSERT_EQUAL_INT(1, g_stub_TLSPROBE_call_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_free_count);
  static_assertToolSucceeded(response, status);
}

void test_tool_SSLCHECK_missing_and_refused_domain(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":68,"method":"tools/call","params":{"name":"ssl_check"}})", &status);
  static_assertContains(response, R"("error":{"code":-32602,"message":"Invalid params: domain is required"})");
  free(response);
  response = static_dispatch(R"({"jsonrpc":"2.0","id":69,"method":"tools/call",)"
                     R"("params":{"name":"ssl_check","arguments":{"domain":"10.0.0.1"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"Provide a public domain name, such as example.com."}],"isError":true)");
  TEST_ASSERT_EQUAL_INT(0, g_stub_TLSPROBE_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_get_count);
  free(response);
}

void test_tool_SSLCHECK_unreachable_target_is_a_tool_error(void)
{
  static const struct {
    TlsProbeStatus_t         m_status;
    TlsProbeHandshakeError_t m_handshakeError;
    const char*              mp_text;
  } cases[] = {
    { TLSPROBE_CONNECT_FAILED,   TLSPROBE_HANDSHAKE_ERROR_NONE,
      R"x("text":"no address of the host name took a connection on port 443"}],"isError":true)x" },
    { TLSPROBE_TIMEOUT,          TLSPROBE_HANDSHAKE_ERROR_NONE,
      R"x("text":"the TLS handshake did not finish within 5000 ms"}],"isError":true)x" },
    { TLSPROBE_HANDSHAKE_FAILED, TLSPROBE_HANDSHAKE_ERROR_UNRECOGNIZED_NAME,
      R"x("text":"the server does not serve the host name over TLS (unrecognized_name alert)"}],"isError":true)x" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    g_stub_TLSPROBE_status          = cases[i].m_status;
    g_stub_TLSPROBE_handshake_error = cases[i].m_handshakeError;
    int status;
    char* response = static_dispatch(R"({"jsonrpc":"2.0","id":70,"method":"tools/call",)"
                       R"("params":{"name":"ssl_check","arguments":{"domain":"shop.example.com"}}})", &status);
    TEST_ASSERT_EQUAL_INT(200, status);
    static_assertContains(response, cases[i].mp_text);
    TEST_ASSERT_NULL_MESSAGE(strstr(response, "-32603"), cases[i].mp_text);
    free(response);
  }
  TEST_ASSERT_EQUAL_INT(3, g_stub_TLSPROBE_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
}

void test_tool_SSLCHECK_body_buffer_failure_is_32603(void)
{
  g_mallocFailSize      = JSONBUF_INITIAL_CAP;
  g_mallocFailSkipCount = 1;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":71,"method":"tools/call",)"
                     R"("params":{"name":"ssl_check","arguments":{"domain":"shop.example.com"}}})", &status);
  TEST_ASSERT_EQUAL_size_t(0, g_mallocFailSize);
  TEST_ASSERT_EQUAL_INT(1, g_stub_TLSPROBE_call_count);
  static_assertContains(response, R"("error":{"code":-32603,"message":"Internal error"})");
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(response);
}

#define HEADERSCHECK_CHECKED_AT_MASK "YYYY-MM-DDTHH:MM:SSZ"

static void static_HEADERSCHECKUtcNow(char* text_out)
{
  time_t    now = time(NULL);
  struct tm now_utc;
  TEST_ASSERT_NOT_NULL(gmtime_r(&now, &now_utc));
  TEST_ASSERT_EQUAL_size_t(HEADERSCHECK_CHECKED_AT_TEXT_SIZE - 1, strftime(text_out, HEADERSCHECK_CHECKED_AT_TEXT_SIZE, "%Y-%m-%dT%H:%M:%SZ", &now_utc));
}

static void static_HEADERSCHECKMaskCheckedAt(char* response, const char* before, const char* after)
{
  static const char member[] = R"(\"checked_at\":\")";
  char* found = strstr(response, member);
  TEST_ASSERT_NOT_NULL_MESSAGE(found, response);
  char* value = found + strlen(member);
  char checked_at[sizeof(HEADERSCHECK_CHECKED_AT_MASK)];
  memcpy(checked_at, value, sizeof(checked_at) - 1);
  checked_at[sizeof(checked_at) - 1] = '\0';
  TEST_ASSERT_EQUAL_CHAR_MESSAGE('\\', value[sizeof(checked_at) - 1], response);
  TEST_ASSERT_TRUE_MESSAGE(strcmp(before, checked_at) <= 0 && strcmp(checked_at, after) <= 0, checked_at);
  memcpy(value, HEADERSCHECK_CHECKED_AT_MASK, sizeof(HEADERSCHECK_CHECKED_AT_MASK) - 1);
}

void test_tool_HEADERSCHECK_answer(void)
{
  char before[HEADERSCHECK_CHECKED_AT_TEXT_SIZE];
  char after[HEADERSCHECK_CHECKED_AT_TEXT_SIZE];
  static_HEADERSCHECKUtcNow(before);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":87,"method":"tools/call",)"
                     R"("params":{"name":"headers_check","arguments":{"domain":"WWW.Stub.Example.com","include_full_header_values":true}}})", &status);
  static_HEADERSCHECKUtcNow(after);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_HEADERSCHECKMaskCheckedAt(response, before, after);
  TEST_ASSERT_EQUAL_STRING(
    R"({"jsonrpc":"2.0","id":87,"result":{"content":[{"type":"text","text":")"
    R"x({\"url\":\"https://www.stub.example.com/\",\"status_code\":200,\"redirect_count\":1,\"checked_at\":\"YYYY-MM-DDTHH:MM:SSZ\",\"findings\":[)x"
    R"x({\"header\":\"Content-Security-Policy\",\"severity\":\"high\",\"result\":\"pass\",\"issues\":[],\"value\":\"default-src 'self'; object-src 'none'; base-uri 'self'\"})x"
    R"x(,{\"header\":\"Strict-Transport-Security\",\"severity\":\"high\",\"result\":\"fail\",\"issues\":[\"Missing includeSubDomains directive\"],\"value\":\"max-age=31536000\",\"remediation\":\"Add Strict-Transport-Security: max-age=63072000; includeSubDomains\"})x"
    R"x(,{\"header\":\"X-Content-Type-Options\",\"severity\":\"medium\",\"result\":\"pass\",\"issues\":[],\"value\":\"nosniff\"})x"
    R"x(,{\"header\":\"X-Frame-Options\",\"severity\":\"medium\",\"result\":\"missing\",\"issues\":[],\"value\":null,\"remediation\":\"Add X-Frame-Options: DENY or SAMEORIGIN\"})x"
    R"x(,{\"header\":\"Referrer-Policy\",\"severity\":\"low\",\"result\":\"fail\",\"issues\":[\"Policy unsafe-url sends the full URL, path and query included, to every origin\"],\"value\":\"unsafe-url\",\"remediation\":\"Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer\"})x"
    R"x(,{\"header\":\"Permissions-Policy\",\"severity\":\"low\",\"result\":\"missing\",\"issues\":[],\"value\":null,\"remediation\":\"Add Permissions-Policy to disable unnecessary browser features (e.g., camera=(), microphone=())\"})x"
    R"x(,{\"header\":\"X-XSS-Protection\",\"severity\":\"low\",\"result\":\"warn\",\"issues\":[\"A value other than 0 turns on the legacy XSS filter, which can create XSS vulnerabilities\"],\"value\":\"1; mode=block\",\"remediation\":\"Remove X-XSS-Protection or set it to 0; use Content-Security-Policy against XSS\"})x"
    R"x(,{\"header\":\"Set-Cookie\",\"severity\":\"medium\",\"result\":\"fail\",\"issues\":[\"Cookies with no Secure attribute: 1\"],\"value\":null,\"cookie_count\":2,\"remediation\":\"Mark every cookie Secure with SameSite=Lax or Strict, and mark session cookies HttpOnly\"})x"
    R"x(,{\"header\":\"Access-Control-Allow-Origin\",\"severity\":\"low\",\"result\":\"warn\",\"issues\":[\"Allowing the origin null lets any sandboxed frame read the answer\"],\"value\":\"null\",\"remediation\":\"Send Access-Control-Allow-Origin with one trusted origin; never null, and never * with credentials\"})x"
    R"x(]})x"
    R"(\n"}],"isError":false}})", response);
  free(response);
  TEST_ASSERT_EQUAL_INT(1, g_stub_HEADER_FETCH_call_count);
  TEST_ASSERT_EQUAL_STRING("www.stub.example.com", g_stub_HEADER_FETCH_last_hostname);
  TEST_ASSERT_EQUAL_INT(1, g_stub_HEADER_FETCH_free_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_STRING("headers_check:full:www.stub.example.com", g_stub_CACHE_last_get_key);
  TEST_ASSERT_TRUE(g_stub_CACHE_last_get_conn == g_conn);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_STRING("headers_check:full:www.stub.example.com", g_stub_CACHE_last_put_key);

  g_stub_CACHE_get_status = CACHE_HIT;
  g_stub_CACHE_get_body   = R"({"kept":true})";
  response = static_dispatch(R"({"jsonrpc":"2.0","id":88,"method":"tools/call",)"
                     R"("params":{"name":"headers_check","arguments":{"domain":"WWW.Stub.Example.com","include_full_header_values":true}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":88,"result":{"content":[{"type":"text","text":"{\"kept\":true}"}],"isError":false}})", response);
  free(response);
  TEST_ASSERT_EQUAL_INT(1, g_stub_HEADER_FETCH_call_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_free_count);
}

void test_tool_HEADERSCHECK_missing_and_refused_values(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":89,"method":"tools/call","params":{"name":"headers_check"}})", &status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":89,"error":{"code":-32602,"message":"Invalid params: domain is required"}})", response);
  free(response);
  response = static_dispatch(R"({"jsonrpc":"2.0","id":90,"method":"tools/call",)"
                     R"("params":{"name":"headers_check","arguments":{"domain":"printer.local"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":90,"result":{"content":[{"type":"text","text":"Provide a public domain name, such as example.com."}],"isError":true}})", response);
  free(response);
  response = static_dispatch(R"({"jsonrpc":"2.0","id":91,"method":"tools/call",)"
                     R"("params":{"name":"headers_check","arguments":{"domain":"example.com","include_full_header_values":"yes"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":91,"result":{"content":[{"type":"text","text":"include_full_header_values must be true or false"}],"isError":true}})", response);
  free(response);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_HEADER_FETCH_call_count);
}

void test_tool_HEADERSCHECK_failed_fetches(void)
{
  static const struct {
    HttpError_t m_error;
    const char* mp_response;
  } cases[] = {
    { HTTP_ERROR_TIMEOUT,
      R"x({"jsonrpc":"2.0","id":92,"result":{"content":[{"type":"text","text":"the site did not answer in time: a connection may take 2000 ms, and the whole fetch 5000 ms"}],"isError":true}})x" },
    { HTTP_ERROR_RESOLVE,
      R"x({"jsonrpc":"2.0","id":92,"result":{"content":[{"type":"text","text":"the host name did not resolve"}],"isError":true}})x" },
    { HTTP_ERROR_CONNECT,
      R"x({"jsonrpc":"2.0","id":92,"result":{"content":[{"type":"text","text":"no address of the site took a connection on port 443"}],"isError":true}})x" },
    { HTTP_ERROR_TLS,
      R"x({"jsonrpc":"2.0","id":92,"result":{"content":[{"type":"text","text":"the TLS handshake with the site failed, or its certificate did not verify; /ssl_check shows why"}],"isError":true}})x" },
    { HTTP_ERROR_BODY_TOO_LARGE,
      R"x({"jsonrpc":"2.0","id":92,"error":{"code":-32603,"message":"Internal error: upstream unavailable"}})x" },
    { HTTP_ERROR_BLOCKED,
      R"x({"jsonrpc":"2.0","id":92,"result":{"content":[{"type":"text","text":"hostname resolves to an address that is not globally reachable"}],"isError":true}})x" },
    { HTTP_ERROR_OTHER,
      R"x({"jsonrpc":"2.0","id":92,"error":{"code":-32603,"message":"Internal error: upstream unavailable"}})x" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    g_stub_HEADER_FETCH_error = cases[i].m_error;
    int status;
    char* response = static_dispatch(R"({"jsonrpc":"2.0","id":92,"method":"tools/call",)"
                       R"("params":{"name":"headers_check","arguments":{"domain":"example.com"}}})", &status);
    TEST_ASSERT_EQUAL_INT(200, status);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_response, response);
    free(response);
  }
  TEST_ASSERT_EQUAL_INT(7, g_stub_HEADER_FETCH_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
}

void test_tool_HEADERSCHECK_body_buffer_failure_is_32603(void)
{
  g_mallocFailSize      = JSONBUF_INITIAL_CAP;
  g_mallocFailSkipCount = 1;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":93,"method":"tools/call",)"
                     R"("params":{"name":"headers_check","arguments":{"domain":"example.com"}}})", &status);
  TEST_ASSERT_EQUAL_size_t(0, g_mallocFailSize);
  TEST_ASSERT_EQUAL_INT(1, g_stub_HEADER_FETCH_call_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_HEADER_FETCH_free_count);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":93,"error":{"code":-32603,"message":"Internal error"}})", response);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(response);
}

void test_tool_WHOISLOOKUP_answer(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":74,"method":"tools/call",)"
                     R"("params":{"name":"whois_lookup","arguments":{"domain":"www.Example.CO.uk"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(
    R"({"jsonrpc":"2.0","id":74,"result":{"content":[{"type":"text","text":")"
    R"({\"domain\":\"example.co.uk\",\"available\":true,\"rdap_server\":\"https://rdap.example.test/\",)"
    R"(\"whois_server\":null,)"
    R"(\"registrar_name\":\"Stub Registrar LLC\",\"registrar_iana_id\":1234,)"
    R"(\"created_at\":\"2001-02-03T04:05:06Z\",\"updated_at\":\"2025-06-07T08:09:10Z\",\"expires_at\":\"2030-11-12T13:14:15Z\",)"
    R"(\"status\":[\"client transfer prohibited\",\"server delete prohibited\"],\"status_count\":2,)"
    R"(\"name_servers\":[\"ns1.stub-dns.test\",\"ns2.stub-dns.test\"],\"name_server_count\":2,\"dnssec_signed\":true}\n)"
    R"("}],"isError":false}})", response);
  free(response);
  TEST_ASSERT_EQUAL_INT(1, g_stub_RDAP_find_count);
  TEST_ASSERT_EQUAL_STRING("example.co.uk", g_stub_RDAP_last_find_name);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_STRING("rdap:example.co.uk", g_stub_CACHE_last_get_key);
  TEST_ASSERT_TRUE(g_stub_CACHE_last_get_conn == g_conn);
  TEST_ASSERT_EQUAL_INT(1, g_stub_THROTTLE_charge_count);
  TEST_ASSERT_TRUE(g_stub_THROTTLE_last_conn == g_conn);
  TEST_ASSERT_EQUAL_STRING("rdap", g_stub_THROTTLE_last_rule.mp_throttleRuleName);
  TEST_ASSERT_EQUAL_UINT(60, g_stub_THROTTLE_last_rule.m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(30, g_stub_THROTTLE_last_rule.m_chargeLimit);
  TEST_ASSERT_EQUAL_STRING("rdap.example.test", g_stub_THROTTLE_last_target_name);
  TEST_ASSERT_EQUAL_INT(1, g_stub_RDAP_lookup_count);
  TEST_ASSERT_EQUAL_STRING("example.co.uk", g_stub_RDAP_last_lookup_name);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_STRING("rdap:example.co.uk", g_stub_CACHE_last_put_key);

  g_stub_CACHE_get_status = CACHE_HIT;
  g_stub_CACHE_get_body   = R"({"kept":true})";
  response = static_dispatch(R"({"jsonrpc":"2.0","id":75,"method":"tools/call",)"
                     R"("params":{"name":"whois_lookup","arguments":{"domain":"www.Example.CO.uk"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":75,"result":{"content":[{"type":"text","text":"{\"kept\":true}"}],"isError":false}})", response);
  free(response);
  TEST_ASSERT_EQUAL_INT(1, g_stub_THROTTLE_charge_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_RDAP_lookup_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_free_count);
}

void test_tool_WHOISLOOKUP_missing_and_refused_domain(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":76,"method":"tools/call","params":{"name":"whois_lookup"}})", &status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":76,"error":{"code":-32602,"message":"Invalid params: domain is required"}})", response);
  free(response);
  response = static_dispatch(R"({"jsonrpc":"2.0","id":77,"method":"tools/call",)"
                     R"("params":{"name":"whois_lookup","arguments":{"domain":"printer.local"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":77,"result":{"content":[{"type":"text","text":"Provide a public domain name, such as example.com."}],"isError":true}})", response);
  free(response);
  response = static_dispatch(R"({"jsonrpc":"2.0","id":78,"method":"tools/call",)"
                     R"("params":{"name":"whois_lookup","arguments":{"domain":"co.uk"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":78,"result":{"content":[{"type":"text","text":"domain is a public suffix, such as co.uk; name a domain registered under it"}],"isError":true}})", response);
  free(response);
  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_find_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_charge_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_RDAP_lookup_count);
}

void test_tool_WHOISLOOKUP_unavailable_answers_and_errors(void)
{
  static const struct {
    bool             m_hasServer;
    ThrottleStatus_t m_chargeStatus;
    RdapStatus_t     m_lookupStatus;
    const char*      mp_response;
  } cases[] = {
    { false, THROTTLE_CHARGED, RDAP_OK,
      R"({"jsonrpc":"2.0","id":79,"result":{"content":[{"type":"text","text":"{\"domain\":\"example.co.uk\",\"available\":false,\"reason\":\"no_registry_server\",\"retry_after_seconds\":null}\n"}],"isError":false}})" },
    { true, THROTTLE_REFUSED, RDAP_OK,
      R"({"jsonrpc":"2.0","id":79,"result":{"content":[{"type":"text","text":"{\"domain\":\"example.co.uk\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":17}\n"}],"isError":false}})" },
    { true, THROTTLE_ERROR, RDAP_OK,
      R"({"jsonrpc":"2.0","id":79,"error":{"code":-32603,"message":"Internal error: database query failed"}})" },
    { true, THROTTLE_CHARGED, RDAP_NOT_REGISTERED,
      R"({"jsonrpc":"2.0","id":79,"result":{"content":[{"type":"text","text":"domain is not registered"}],"isError":true}})" },
    { true, THROTTLE_CHARGED, RDAP_UPSTREAM_ERROR,
      R"({"jsonrpc":"2.0","id":79,"error":{"code":-32603,"message":"Internal error: upstream unavailable"}})" },
    { true, THROTTLE_CHARGED, RDAP_INVALID_NAME,
      R"({"jsonrpc":"2.0","id":79,"result":{"content":[{"type":"text","text":"Provide a public domain name, such as example.com."}],"isError":true}})" },
  };
  g_stub_THROTTLE_retry_after_seconds = 17;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    g_stub_RDAP_server_base_url   = cases[i].m_hasServer ? g_stub_RDAP_default_server_base_url : NULL;
    g_stub_THROTTLE_charge_status = cases[i].m_chargeStatus;
    g_stub_RDAP_lookup_status     = cases[i].m_lookupStatus;
    int status;
    char* response = static_dispatch(R"({"jsonrpc":"2.0","id":79,"method":"tools/call",)"
                       R"("params":{"name":"whois_lookup","arguments":{"domain":"www.Example.CO.uk"}}})", &status);
    TEST_ASSERT_EQUAL_INT(200, status);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_response, response);
    free(response);
  }
  TEST_ASSERT_EQUAL_INT(3, g_stub_RDAP_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
}

void test_tool_WHOISLOOKUP_body_buffer_failure_is_32603(void)
{
  g_mallocFailSize      = JSONBUF_INITIAL_CAP;
  g_mallocFailSkipCount = 1;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":80,"method":"tools/call",)"
                     R"("params":{"name":"whois_lookup","arguments":{"domain":"www.Example.CO.uk"}}})", &status);
  TEST_ASSERT_EQUAL_size_t(0, g_mallocFailSize);
  TEST_ASSERT_EQUAL_INT(1, g_stub_RDAP_lookup_count);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":80,"error":{"code":-32603,"message":"Internal error"}})", response);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(response);
}

void test_tool_WAYBACKLOOKUP_answer(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":81,"method":"tools/call",)"
                     R"("params":{"name":"wayback_lookup","arguments":{"domain":"WWW.Example.COM"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(
    R"({"jsonrpc":"2.0","id":81,"result":{"content":[{"type":"text","text":")"
    R"({\"domain\":\"www.example.com\",\"available\":true,\"first_seen\":\"2019-03-05\",\"last_seen\":\"2026-10-24\",\"years_online\":7,\"latest_captures\":[)"
    R"({\"captured_at\":\"2026-10-24T16:22:30Z\",\"http_status\":200,\"media_type\":\"text/html\",\"url\":\"https://web.archive.org/web/20261024162230/www.example.com\"})"
    R"(,{\"captured_at\":\"2019-03-05T01:02:03Z\",\"http_status\":301,\"media_type\":\"text/plain\",\"url\":\"https://web.archive.org/web/20190305010203/www.example.com\"})"
    R"(],\"archive_url\":\"https://web.archive.org/web/*/www.example.com\"}\n)"
    R"("}],"isError":false}})", response);
  free(response);
  TEST_ASSERT_EQUAL_INT(1, g_stub_WAYBACK_lookup_count);
  TEST_ASSERT_EQUAL_STRING("www.example.com", g_stub_WAYBACK_last_lookup_name);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_STRING("wayback:www.example.com", g_stub_CACHE_last_get_key);
  TEST_ASSERT_TRUE(g_stub_CACHE_last_get_conn == g_conn);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_TRUE(g_stub_QUOTA_last_reserve_conn == g_conn);
  TEST_ASSERT_EQUAL_STRING("wayback", g_stub_QUOTA_last_reserve_rule.mp_sourceName);
  TEST_ASSERT_EQUAL_UINT(10, g_stub_QUOTA_last_reserve_rule.m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(2, g_stub_QUOTA_last_reserve_rule.m_callLimit);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_STRING("wayback:www.example.com", g_stub_CACHE_last_put_key);

  g_stub_CACHE_get_status = CACHE_HIT;
  g_stub_CACHE_get_body   = R"({"kept":true})";
  response = static_dispatch(R"({"jsonrpc":"2.0","id":82,"method":"tools/call",)"
                     R"("params":{"name":"wayback_lookup","arguments":{"domain":"WWW.Example.COM"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":82,"result":{"content":[{"type":"text","text":"{\"kept\":true}"}],"isError":false}})", response);
  free(response);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_WAYBACK_lookup_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_free_count);
}

void test_tool_WAYBACKLOOKUP_missing_and_refused_domain(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":83,"method":"tools/call","params":{"name":"wayback_lookup"}})", &status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":83,"error":{"code":-32602,"message":"Invalid params: domain is required"}})", response);
  free(response);
  response = static_dispatch(R"({"jsonrpc":"2.0","id":84,"method":"tools/call",)"
                     R"("params":{"name":"wayback_lookup","arguments":{"domain":"printer.local"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":84,"result":{"content":[{"type":"text","text":"Provide a public domain name, such as example.com."}],"isError":true}})", response);
  free(response);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_WAYBACK_lookup_count);
}

void test_tool_WAYBACKLOOKUP_unavailable_answers_and_errors(void)
{
  static const struct {
    QuotaStatus_t   m_quotaStatus;
    WaybackStatus_t m_lookupStatus;
    const char*     mp_response;
  } cases[] = {
    { QUOTA_EXHAUSTED, WAYBACK_OK,
      R"({"jsonrpc":"2.0","id":85,"result":{"content":[{"type":"text","text":"{\"domain\":\"www.example.com\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":7}\n"}],"isError":false}})" },
    { QUOTA_ERROR, WAYBACK_OK,
      R"({"jsonrpc":"2.0","id":85,"error":{"code":-32603,"message":"Internal error: database query failed"}})" },
    { QUOTA_GRANTED, WAYBACK_RATE_LIMITED,
      R"({"jsonrpc":"2.0","id":85,"result":{"content":[{"type":"text","text":"{\"domain\":\"www.example.com\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":45}\n"}],"isError":false}})" },
    { QUOTA_GRANTED, WAYBACK_UPSTREAM_ERROR,
      R"({"jsonrpc":"2.0","id":85,"error":{"code":-32603,"message":"Internal error: upstream unavailable"}})" },
    { QUOTA_GRANTED, WAYBACK_INVALID_NAME,
      R"({"jsonrpc":"2.0","id":85,"result":{"content":[{"type":"text","text":"Provide a public domain name, such as example.com."}],"isError":true}})" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    g_stub_QUOTA_reserve_status           = cases[i].m_quotaStatus;
    g_stub_QUOTA_window_remaining_seconds = 7;
    g_stub_WAYBACK_answers[0].m_status    = cases[i].m_lookupStatus;
    g_stub_WAYBACK_answers[0].m_retryAfterSeconds = 45;
    g_stub_WAYBACK_lookup_count         = 0;
    int status;
    char* response = static_dispatch(R"({"jsonrpc":"2.0","id":85,"method":"tools/call",)"
                       R"("params":{"name":"wayback_lookup","arguments":{"domain":"WWW.Example.COM"}}})", &status);
    TEST_ASSERT_EQUAL_INT(200, status);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_response, response);
    free(response);
  }
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_hold_set_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
}

void test_tool_WAYBACKLOOKUP_body_buffer_failure_is_32603(void)
{
  g_mallocFailSize      = JSONBUF_INITIAL_CAP;
  g_mallocFailSkipCount = 1;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":86,"method":"tools/call",)"
                     R"("params":{"name":"wayback_lookup","arguments":{"domain":"www.example.com"}}})", &status);
  TEST_ASSERT_EQUAL_size_t(0, g_mallocFailSize);
  TEST_ASSERT_EQUAL_INT(1, g_stub_WAYBACK_lookup_count);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":86,"error":{"code":-32603,"message":"Internal error"}})", response);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(response);
}

#define CERTSEARCH_MCP_TEXT                                                                                                                     \
  R"({\"domain\":\"www.example.com\",\"available\":true,\"complete\":false,\"certificate_count\":3,\"certificates\":[)"                         \
  R"({\"sha256_fingerprint\":\"aa11bb22cc33dd44ee55ff6600778899aa11bb22cc33dd44ee55ff6600778899\",\"issuer\":\"Stub Trust CA\",)"                     \
  R"(\"issuer_caa_domains\":[\"stubtrust.example\",\"stub-ca.example\"],\"valid_from\":\"2026-09-01T01:02:03Z\",)"                            \
  R"(\"valid_until\":\"2026-12-01T04:05:06Z\",\"revoked\":true,\"dns_names\":[\"stub.example.com\",\"www.stub.example.com\"],\"dns_name_count\":2})" \
  R"(]}\n)"

void test_tool_CERTSEARCH_answer(void)
{
  g_stub_CERTSPOTTER_answer.m_certificateList.m_keptCount = 1;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":87,"method":"tools/call",)"
                     R"("params":{"name":"cert_search","arguments":{"domain":"WWW.Example.COM"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(
    R"({"jsonrpc":"2.0","id":87,"result":{"content":[{"type":"text","text":")" CERTSEARCH_MCP_TEXT R"("}],"isError":false}})", response);
  free(response);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CERTSPOTTER_lookup_count);
  TEST_ASSERT_EQUAL_STRING("www.example.com", g_stub_CERTSPOTTER_last_lookup_name);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_STRING("certspotter:www.example.com", g_stub_CACHE_last_get_key);
  TEST_ASSERT_TRUE(g_stub_CACHE_last_get_conn == g_conn);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_EQUAL_STRING("certspotter", g_stub_QUOTA_last_hold_read_name);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_TRUE(g_stub_QUOTA_last_reserve_conn == g_conn);
  TEST_ASSERT_EQUAL_STRING("certspotter_name", g_stub_QUOTA_last_reserve_rule.mp_sourceName);
  TEST_ASSERT_EQUAL_UINT(3600, g_stub_QUOTA_last_reserve_rule.m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(80, g_stub_QUOTA_last_reserve_rule.m_callLimit);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_STRING("certspotter:www.example.com", g_stub_CACHE_last_put_key);

  g_stub_CACHE_get_status = CACHE_HIT;
  g_stub_CACHE_get_body   = R"({"kept":true})";
  response = static_dispatch(R"({"jsonrpc":"2.0","id":88,"method":"tools/call",)"
                     R"("params":{"name":"cert_search","arguments":{"domain":"WWW.Example.COM"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":88,"result":{"content":[{"type":"text","text":"{\"kept\":true}"}],"isError":false}})", response);
  free(response);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CERTSPOTTER_lookup_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_free_count);
}

void test_tool_CERTSEARCH_missing_and_refused_domain(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":89,"method":"tools/call","params":{"name":"cert_search"}})", &status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":89,"error":{"code":-32602,"message":"Invalid params: domain is required"}})", response);
  free(response);
  response = static_dispatch(R"({"jsonrpc":"2.0","id":90,"method":"tools/call",)"
                     R"("params":{"name":"cert_search","arguments":{"domain":"printer.local"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":90,"result":{"content":[{"type":"text","text":"Provide a public domain name, such as example.com."}],"isError":true}})", response);
  free(response);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CERTSPOTTER_lookup_count);
}

void test_tool_CERTSEARCH_unavailable_answers_and_errors(void)
{
  static const struct {
    QuotaStatus_t       m_quotaStatus;
    CertSpotterStatus_t m_lookupStatus;
    const char*         mp_response;
  } cases[] = {
    { QUOTA_EXHAUSTED, CERTSPOTTER_OK,
      R"({"jsonrpc":"2.0","id":91,"result":{"content":[{"type":"text","text":"{\"domain\":\"www.example.com\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":1800}\n"}],"isError":false}})" },
    { QUOTA_ERROR, CERTSPOTTER_OK,
      R"({"jsonrpc":"2.0","id":91,"error":{"code":-32603,"message":"Internal error: database query failed"}})" },
    { QUOTA_GRANTED, CERTSPOTTER_RATE_LIMITED,
      R"({"jsonrpc":"2.0","id":91,"result":{"content":[{"type":"text","text":"{\"domain\":\"www.example.com\",\"available\":false,\"reason\":\"quota_exhausted\",\"retry_after_seconds\":45}\n"}],"isError":false}})" },
    { QUOTA_GRANTED, CERTSPOTTER_UPSTREAM_ERROR,
      R"({"jsonrpc":"2.0","id":91,"error":{"code":-32603,"message":"Internal error: upstream unavailable"}})" },
    { QUOTA_GRANTED, CERTSPOTTER_NO_API_KEY,
      R"({"jsonrpc":"2.0","id":91,"error":{"code":-32603,"message":"Internal error: upstream unavailable"}})" },
    { QUOTA_GRANTED, CERTSPOTTER_INVALID_NAME,
      R"({"jsonrpc":"2.0","id":91,"result":{"content":[{"type":"text","text":"Provide a public domain name, such as example.com."}],"isError":true}})" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    g_stub_QUOTA_reserve_status                   = cases[i].m_quotaStatus;
    g_stub_QUOTA_window_remaining_seconds         = 1800;
    g_stub_CERTSPOTTER_answer.m_status            = cases[i].m_lookupStatus;
    g_stub_CERTSPOTTER_answer.m_retryAfterSeconds = 45;
    int status;
    char* response = static_dispatch(R"({"jsonrpc":"2.0","id":91,"method":"tools/call",)"
                       R"("params":{"name":"cert_search","arguments":{"domain":"WWW.Example.COM"}}})", &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, cases[i].mp_response);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_response, response);
    free(response);
  }
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_hold_set_count);
  TEST_ASSERT_EQUAL_STRING("certspotter", g_stub_QUOTA_last_hold_set_name);
  TEST_ASSERT_EQUAL_UINT(45, g_stub_QUOTA_last_hold_set_seconds);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
}

void test_tool_CERTSEARCH_body_buffer_failure_is_32603(void)
{
  g_mallocFailSize      = JSONBUF_INITIAL_CAP;
  g_mallocFailSkipCount = 1;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":92,"method":"tools/call",)"
                     R"("params":{"name":"cert_search","arguments":{"domain":"www.example.com"}}})", &status);
  TEST_ASSERT_EQUAL_size_t(0, g_mallocFailSize);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CERTSPOTTER_lookup_count);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":92,"error":{"code":-32603,"message":"Internal error"}})", response);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  free(response);
}

#define SUBDOMAINENUM_MCP_TEXT                                                                 \
  R"({\"domain\":\"example.com\",\"subdomain_count\":4,\"subdomains\":[)"                      \
  R"({\"hostname\":\"mail.example.com\",\"sources\":[\"dns_records\"]},)"                      \
  R"({\"hostname\":\"www.example.com\",\"sources\":[\"certificate_logs\",\"dns_wordlist\"]},)" \
  R"({\"hostname\":\"api.example.com\",\"sources\":[\"certificate_logs\"]},)"                  \
  R"({\"hostname\":\"dev.example.com\",\"sources\":[\"certificate_logs\"]}],)"                 \
  R"(\"wildcard_dns\":\"absent\",\"certificate_logs_available\":true,\"certificate_logs_complete\":false}\n)"

void test_tool_SUBDOMAINENUM_answer(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":193,"method":"tools/call",)"
                     R"("params":{"name":"subdomain_enum","arguments":{"domain":"WWW.Example.COM"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(
    R"({"jsonrpc":"2.0","id":193,"result":{"content":[{"type":"text","text":")" SUBDOMAINENUM_MCP_TEXT R"("}],"isError":false}})", response);
  free(response);
  TEST_ASSERT_EQUAL_INT(1, g_stub_SUBDOMAIN_lookup_count);
  TEST_ASSERT_EQUAL_STRING("example.com", g_stub_SUBDOMAIN_last_lookup_domain);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CERTSPOTTER_subtree_lookup_count);
  TEST_ASSERT_EQUAL_STRING("example.com", g_stub_CERTSPOTTER_last_subtree_domain);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_get_count);
  TEST_ASSERT_EQUAL_STRING("subdomain:example.com", g_stub_CACHE_last_get_key);
  TEST_ASSERT_TRUE(g_stub_CACHE_last_get_conn == g_conn);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_hold_read_count);
  TEST_ASSERT_EQUAL_STRING("certspotter_subtree", g_stub_QUOTA_last_hold_read_name);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_TRUE(g_stub_QUOTA_last_reserve_conn == g_conn);
  TEST_ASSERT_EQUAL_STRING("certspotter_subtree", g_stub_QUOTA_last_reserve_rule.mp_sourceName);
  TEST_ASSERT_EQUAL_UINT(3600, g_stub_QUOTA_last_reserve_rule.m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(5, g_stub_QUOTA_last_reserve_rule.m_callLimit);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_STRING("subdomain:example.com", g_stub_CACHE_last_put_key);
  TEST_ASSERT_EQUAL_UINT(86400, g_stub_CACHE_last_put_expires_after_seconds);

  g_stub_CACHE_get_status = CACHE_HIT;
  g_stub_CACHE_get_body   = R"({"kept":true})";
  response = static_dispatch(R"({"jsonrpc":"2.0","id":194,"method":"tools/call",)"
                     R"("params":{"name":"subdomain_enum","arguments":{"domain":"WWW.Example.COM"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":194,"result":{"content":[{"type":"text","text":"{\"kept\":true}"}],"isError":false}})", response);
  free(response);
  TEST_ASSERT_EQUAL_INT(1, g_stub_SUBDOMAIN_lookup_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CERTSPOTTER_subtree_lookup_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CACHE_free_count);
}

void test_tool_SUBDOMAINENUM_missing_and_refused_domain(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":195,"method":"tools/call","params":{"name":"subdomain_enum"}})", &status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":195,"error":{"code":-32602,"message":"Invalid params: domain is required"}})", response);
  free(response);
  response = static_dispatch(R"({"jsonrpc":"2.0","id":196,"method":"tools/call",)"
                     R"("params":{"name":"subdomain_enum","arguments":{"domain":"printer.local"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":196,"result":{"content":[{"type":"text","text":"Provide a public domain name, such as example.com."}],"isError":true}})", response);
  free(response);
  response = static_dispatch(R"({"jsonrpc":"2.0","id":197,"method":"tools/call",)"
                     R"("params":{"name":"subdomain_enum","arguments":{"domain":"co.uk"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":197,"result":{"content":[{"type":"text","text":"domain is a public suffix, such as co.uk; name a domain registered under it"}],"isError":true}})", response);
  free(response);
  TEST_ASSERT_EQUAL_INT(0, g_stub_SUBDOMAIN_lookup_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_QUOTA_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CERTSPOTTER_subtree_lookup_count);
}

void test_tool_SUBDOMAINENUM_answers_without_certificate_logs_and_errors(void)
{
#define SUBDOMAINENUM_MCP_DNS_ONLY_HEAD                                             \
  R"({"jsonrpc":"2.0","id":198,"result":{"content":[{"type":"text","text":")"       \
  R"({\"domain\":\"example.com\",\"subdomain_count\":2,\"subdomains\":[)"           \
  R"({\"hostname\":\"mail.example.com\",\"sources\":[\"dns_records\"]},)"           \
  R"({\"hostname\":\"www.example.com\",\"sources\":[\"dns_wordlist\"]}],)"          \
  R"(\"wildcard_dns\":\"absent\",\"certificate_logs_available\":false,)"
  static const struct {
    QuotaStatus_t       m_quotaStatus;
    CertSpotterStatus_t m_lookupStatus;
    const char*         mp_response;
  } cases[] = {
    { QUOTA_EXHAUSTED, CERTSPOTTER_OK,
      SUBDOMAINENUM_MCP_DNS_ONLY_HEAD R"(\"certificate_logs_reason\":\"quota_exhausted\",\"retry_after_seconds\":1800}\n"}],"isError":false}})" },
    { QUOTA_ERROR, CERTSPOTTER_OK,
      R"({"jsonrpc":"2.0","id":198,"error":{"code":-32603,"message":"Internal error: database query failed"}})" },
    { QUOTA_GRANTED, CERTSPOTTER_RATE_LIMITED,
      SUBDOMAINENUM_MCP_DNS_ONLY_HEAD R"(\"certificate_logs_reason\":\"quota_exhausted\",\"retry_after_seconds\":45}\n"}],"isError":false}})" },
    { QUOTA_GRANTED, CERTSPOTTER_UPSTREAM_ERROR,
      SUBDOMAINENUM_MCP_DNS_ONLY_HEAD R"(\"certificate_logs_reason\":\"upstream_error\"}\n"}],"isError":false}})" },
    { QUOTA_GRANTED, CERTSPOTTER_NO_API_KEY,
      SUBDOMAINENUM_MCP_DNS_ONLY_HEAD R"(\"certificate_logs_reason\":\"upstream_error\"}\n"}],"isError":false}})" },
    { QUOTA_GRANTED, CERTSPOTTER_INVALID_NAME,
      R"({"jsonrpc":"2.0","id":198,"result":{"content":[{"type":"text","text":"Provide a public domain name, such as example.com."}],"isError":true}})" },
  };
#undef SUBDOMAINENUM_MCP_DNS_ONLY_HEAD
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    g_stub_QUOTA_reserve_status                           = cases[i].m_quotaStatus;
    g_stub_QUOTA_window_remaining_seconds                 = 1800;
    g_stub_CERTSPOTTER_subtree_answer.m_status            = cases[i].m_lookupStatus;
    g_stub_CERTSPOTTER_subtree_answer.m_retryAfterSeconds = 45;
    int status;
    char* response = static_dispatch(R"({"jsonrpc":"2.0","id":198,"method":"tools/call",)"
                       R"("params":{"name":"subdomain_enum","arguments":{"domain":"example.com"}}})", &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, cases[i].mp_response);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_response, response);
    free(response);
  }
  TEST_ASSERT_EQUAL_INT(1, g_stub_QUOTA_hold_set_count);
  TEST_ASSERT_EQUAL_STRING("certspotter_subtree", g_stub_QUOTA_last_hold_set_name);
  TEST_ASSERT_EQUAL_UINT(45, g_stub_QUOTA_last_hold_set_seconds);
}

void test_tool_SUBDOMAINENUM_body_buffer_failure_is_32603(void)
{
  g_stub_SUBDOMAIN_create_count  = 0;
  g_stub_SUBDOMAIN_destroy_count = 0;
  g_mallocFailSize      = JSONBUF_INITIAL_CAP;
  g_mallocFailSkipCount = 1;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":199,"method":"tools/call",)"
                     R"("params":{"name":"subdomain_enum","arguments":{"domain":"example.com"}}})", &status);
  TEST_ASSERT_EQUAL_size_t(0, g_mallocFailSize);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CERTSPOTTER_subtree_lookup_count);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":199,"error":{"code":-32603,"message":"Internal error"}})", response);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CACHE_put_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_SUBDOMAIN_create_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_SUBDOMAIN_destroy_count);
  free(response);
}

void test_tool_IPLOOKUP_answer(void)
{
  g_stub_IPLOOKUP_status = DB_OK;
  RequestCreditBudget_t credit_budget;
  static_watchlistBudget(&credit_budget, REQUEST_TIER_FREE);
  int status;
  char* response = static_watchlistCall("ip_lookup", R"({"ip_address":"2001:4860:4860:0:0:0:0:8888"})", &credit_budget, &status);
  static_assertContains(response, R"("text":"{\"ip_address\":\"2001:4860:4860::8888\",\"asn\":13335,\"asn_name\":\"CLOUDFLARENET\",)");
  static_assertContains(response, R"(\"ptr\":\"one.one.one.one\",)"
                                  R"(\"reputation\":{\"available\":false,\"reason\":\"pro_key_required\",\"action_url\":\"https://api.contrastcyber.com/pricing\"},)"
                                  R"(\"internet_exposure\":{\"available\":false,\"reason\":\"pro_key_required\",\"action_url\":\"https://api.contrastcyber.com/pricing\"},\"unavailable\":{}})");
  TEST_ASSERT_EQUAL_INT(1, g_stub_IPLOOKUP_call_count);
  TEST_ASSERT_EQUAL_STRING("2001:4860:4860::8888", g_stub_IPLOOKUP_last_ip_address);
  TEST_ASSERT_EQUAL_INT(1, g_stub_PTR_call_count);
  TEST_ASSERT_EQUAL_STRING("2001:4860:4860::8888", g_stub_PTR_last_ip_address);
  TEST_ASSERT_EQUAL_INT(1, g_stub_IPLOOKUPRecordFree_call_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_PTR_free_count);
  static_assertToolSucceeded(response, status);
}

void test_tool_IPLOOKUP_missing_and_refused_ip_address(void)
{
  g_stub_IPLOOKUP_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":67,"method":"tools/call","params":{"name":"ip_lookup"}})", &status);
  static_assertContains(response, R"("error":{"code":-32602,"message":"Invalid params: ip_address is required"})");
  free(response);
  response = static_dispatch(R"({"jsonrpc":"2.0","id":68,"method":"tools/call",)"
                     R"("params":{"name":"ip_lookup","arguments":{"ip_address":"10.0.0.1"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"Provide a public IPv4 or IPv6 address, such as 8.8.8.8 or 2001:4860:4860::8888."}],"isError":true)");
  free(response);
  TEST_ASSERT_EQUAL_INT(0, g_stub_IPLOOKUP_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_PTR_call_count);
}

void test_tool_IPLOOKUP_db_error_is_32603(void)
{
  RequestCreditBudget_t credit_budget;
  static_watchlistBudget(&credit_budget, REQUEST_TIER_PRO);
  int status;
  char* response = static_watchlistCall("ip_lookup", R"({"ip_address":"1.1.1.1"})", &credit_budget, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("error":{"code":-32603,"message":"Internal error: database query failed"})");
  TEST_ASSERT_NULL(strstr(response, "isError"));
  TEST_ASSERT_EQUAL_INT(1, g_stub_IPLOOKUP_call_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_IPLOOKUPRecordFree_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_PTR_call_count);
  free(response);
}

#define EMAILADDRESSCHECK_STUB_TEXT_MX \
  R"(\"mail_route\":\"mx\",\"mx_hosts\":[{\"priority\":10,\"host\":\"mx1.mail.example.net\"},{\"priority\":20,\"host\":\"mx2.mail.example.net\"}],)" \
  R"(\"disposable\":false,\"disposable_listed_domain\":null,)"

void test_tool_EMAILADDRESSCHECK_answer(void)
{
  g_stub_EMAILADDRESSCHECK_status = DB_OK;
  static const struct { const char* mp_email; const char* mp_domain; const char* mp_text; } cases[] = {
    { "Admin+ci@Example.COM", "example.com",
      R"("text":"{\"email\":\"Admin+ci@example.com\",\"domain\":\"example.com\",\"domain_exists\":true,\"accepts_mail\":true,)"
      EMAILADDRESSCHECK_STUB_TEXT_MX
      R"(\"unavailable\":{}}\n"}])" },
    { "a%40b@Gmail.com", "gmail.com",
      R"("text":"{\"email\":\"a%40b@gmail.com\",\"domain\":\"gmail.com\",\"domain_exists\":true,\"accepts_mail\":true,)"
      EMAILADDRESSCHECK_STUB_TEXT_MX
      R"(\"unavailable\":{}}\n"}])" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    g_stub_EMAILADDRESSCHECK_call_count     = 0;
    g_stub_EMAILADDRESSCHECK_dns_call_count = 0;
    g_stub_EMAILADDRESSCHECK_free_count     = 0;
    char request[256];
    int written = snprintf(request, sizeof(request),
                           R"({"jsonrpc":"2.0","id":75,"method":"tools/call","params":{"name":"email_address_check","arguments":{"email":"%s"}}})", cases[i].mp_email);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(request));
    int status;
    char* response = static_dispatch(request, &status);

    static_assertContains(response, cases[i].mp_text);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_EMAILADDRESSCHECK_call_count, cases[i].mp_email);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_domain, g_stub_EMAILADDRESSCHECK_last_domain, cases[i].mp_email);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_EMAILADDRESSCHECK_dns_call_count, cases[i].mp_email);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_domain, g_stub_EMAILADDRESSCHECK_last_dns_domain, cases[i].mp_email);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_EMAILADDRESSCHECK_free_count, cases[i].mp_email);
    static_assertToolSucceeded(response, status);
  }
}

void test_tool_EMAILADDRESSCHECK_missing_and_refused_values(void)
{
  g_stub_EMAILADDRESSCHECK_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":76,"method":"tools/call","params":{"name":"email_address_check"}})", &status);
  static_assertContains(response, R"("error":{"code":-32602,"message":"Invalid params: email is required"})");
  free(response);

  static const char* const refusal = R"("text":")" VALIDATE_EMAIL_ADDRESS_REFUSAL_MESSAGE R"("}],"isError":true)";
  static const char* const emails[] = { "name%40example.com", "name@example.local", ".name@example.com", "na me@example.com" };
  for (size_t i = 0; i < sizeof(emails) / sizeof(emails[0]); i++)
  {
    char request[256];
    int written = snprintf(request, sizeof(request),
                           R"({"jsonrpc":"2.0","id":77,"method":"tools/call","params":{"name":"email_address_check","arguments":{"email":"%s"}}})", emails[i]);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(request));
    response = static_dispatch(request, &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, emails[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, refusal), emails[i]);
    free(response);
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_EMAILADDRESSCHECK_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_EMAILADDRESSCHECK_dns_call_count);
}

void test_tool_EMAILADDRESSCHECK_db_error_upstream_error_and_no_domain(void)
{
  static const char* const request = R"({"jsonrpc":"2.0","id":78,"method":"tools/call","params":{"name":"email_address_check","arguments":{"email":"name@example.com"}}})";
  int status;
  g_stub_EMAILADDRESSCHECK_status = DB_ERROR;
  char* response = static_dispatch(request, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("error":{"code":-32603,"message":"Internal error: database query failed"})");
  TEST_ASSERT_EQUAL_INT(0, g_stub_EMAILADDRESSCHECK_dns_call_count);
  free(response);

  g_stub_EMAILADDRESSCHECK_status     = DB_OK;
  g_stub_EMAILADDRESSCHECK_dns_status = DNS_LOOKUP_NO_ANSWER;
  response = static_dispatch(request, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("error":{"code":-32603,"message":"Internal error: upstream unavailable"})");
  TEST_ASSERT_NULL(strstr(response, "isError"));
  free(response);

  g_stub_EMAILADDRESSCHECK_dns_status = DNS_LOOKUP_NOT_FOUND;
  response = static_dispatch(request, &status);
  static_assertContains(response, R"(\"domain_exists\":false,\"accepts_mail\":false,\"mail_route\":null,\"mx_hosts\":[],)");
  static_assertToolSucceeded(response, status);
  TEST_ASSERT_EQUAL_INT(2, g_stub_EMAILADDRESSCHECK_dns_call_count);
  TEST_ASSERT_EQUAL_INT(3, g_stub_EMAILADDRESSCHECK_free_count);
}

#define ASNLOOKUP_STUB_TEXT_COUNTS  R"(,\"ipv4_prefix_count\":1789,\"ipv6_prefix_count\":214,)"
#define ASNLOOKUP_STUB_TEXT_LISTS \
  R"(\"ipv4_prefixes\":[\"1.0.0.0/24\", \"1.1.1.0/24\"],\"ipv6_prefixes\":[\"2606:4700::/32\"]}\n"}])"

void test_tool_ASNLOOKUP_answer(void)
{
  g_stub_ASNLOOKUP_status = DB_OK;
  static const struct { const char* mp_arguments; const char* mp_target; int m_limit; int m_offset; const char* mp_textHead; const char* mp_textPage; } cases[] = {
    { R"({"target":"as13335","limit":7,"offset":1785})", "AS13335", 7, 1785,
      R"("text":"{\"target\":\"AS13335\",\"asn\":13335,\"asn_name\":\"CLOUDFLARENET\",\"asn_country\":\"US\",\"prefix\":null)",
      R"(\"limit\":7,\"offset\":1785,\"next_offset\":1789,)" },
    { R"({"target":"13335"})", "AS13335", 50, 0,
      R"("text":"{\"target\":\"AS13335\",\"asn\":13335,\"asn_name\":\"CLOUDFLARENET\",\"asn_country\":\"US\",\"prefix\":null)",
      R"(\"limit\":50,\"offset\":0,\"next_offset\":50,)" },
    { R"({"target":"2606:4700:0:0:0:0:0:1111","offset":3})", "2606:4700::1111", 50, 3,
      R"("text":"{\"target\":\"2606:4700::1111\",\"asn\":13335,\"asn_name\":\"CLOUDFLARENET\",\"asn_country\":\"US\",\"prefix\":\"1.1.1.0/24\")",
      R"(\"limit\":50,\"offset\":3,\"next_offset\":53,)" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    g_stub_ASNLOOKUP_call_count           = 0;
    g_stub_ASNLOOKUPRecordFree_call_count = 0;
    char request[256];
    int written = snprintf(request, sizeof(request),
                           R"({"jsonrpc":"2.0","id":70,"method":"tools/call","params":{"name":"asn_lookup","arguments":%s}})", cases[i].mp_arguments);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(request));
    char text[512];
    written = snprintf(text, sizeof(text), "%s" ASNLOOKUP_STUB_TEXT_COUNTS "%s" ASNLOOKUP_STUB_TEXT_LISTS, cases[i].mp_textHead, cases[i].mp_textPage);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(text));
    int status;
    char* response = static_dispatch(request, &status);

    static_assertContains(response, text);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_ASNLOOKUP_call_count, cases[i].mp_arguments);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_target, g_stub_ASNLOOKUP_last_params.ma_target, cases[i].mp_arguments);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_limit, g_stub_ASNLOOKUP_last_params.m_limit, cases[i].mp_arguments);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_offset, g_stub_ASNLOOKUP_last_params.m_offset, cases[i].mp_arguments);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_ASNLOOKUPRecordFree_call_count, cases[i].mp_arguments);
    static_assertToolSucceeded(response, status);
  }
}

void test_tool_ASNLOOKUP_missing_and_refused_values(void)
{
  g_stub_ASNLOOKUP_status = DB_OK;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":71,"method":"tools/call","params":{"name":"asn_lookup"}})", &status);
  static_assertContains(response, R"("error":{"code":-32602,"message":"Invalid params: target is required"})");
  free(response);

  static const char* const target_refusal = R"("text":"Provide an AS number, such as AS15169, or a public IPv4 or IPv6 address."}],"isError":true)";
  static const char* const limit_refusal  = R"("text":"limit must be an integer between 1 and 50"}],"isError":true)";
  static const char* const offset_refusal = R"("text":"offset must be an integer between 0 and 2147483647"}],"isError":true)";
  static const struct { const char* mp_arguments; const char* mp_refusal; } cases[] = {
    { R"({"target":"10.0.0.1"})",                                     target_refusal },
    { R"({"target":"AS0"})",                                          target_refusal },
    { R"({"target":"AS4294967296"})",                                 target_refusal },
    { R"({"target":"example.com"})",                                  target_refusal },
    { R"({"target":"AS15169","limit":0})",                            limit_refusal },
    { R"({"target":"AS15169","limit":51})",                           limit_refusal },
    { R"({"target":"AS15169","limit":"7"})",                          limit_refusal },
    { R"({"target":"AS15169","offset":-1})",                          offset_refusal },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char request[256];
    int written = snprintf(request, sizeof(request),
                           R"({"jsonrpc":"2.0","id":72,"method":"tools/call","params":{"name":"asn_lookup","arguments":%s}})", cases[i].mp_arguments);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(request));
    response = static_dispatch(request, &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, cases[i].mp_arguments);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, cases[i].mp_refusal), cases[i].mp_arguments);
    free(response);
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_ASNLOOKUP_call_count);
}

void test_tool_ASNLOOKUP_not_found_and_db_error(void)
{
  g_stub_ASNLOOKUP_status = DB_NOT_FOUND;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":73,"method":"tools/call",)"
                     R"("params":{"name":"asn_lookup","arguments":{"target":"AS64496"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("text":"AS not found"}],"isError":true)");
  free(response);

  g_stub_ASNLOOKUP_status = DB_ERROR;
  response = static_dispatch(R"({"jsonrpc":"2.0","id":74,"method":"tools/call",)"
                     R"("params":{"name":"asn_lookup","arguments":{"target":"AS64496"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("error":{"code":-32603,"message":"Internal error: database query failed"})");
  TEST_ASSERT_NULL(strstr(response, "isError"));
  free(response);
  TEST_ASSERT_EQUAL_INT(2, g_stub_ASNLOOKUP_call_count);
  TEST_ASSERT_EQUAL_INT(2, g_stub_ASNLOOKUPRecordFree_call_count);
}

void test_privacy_my_data_without_a_credit_budget_is_32603(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"privacy_my_data","arguments":{}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("error":{"code":-32603,"message":"Internal error"})");
  TEST_ASSERT_NULL(strstr(response, "isError"));
  free(response);
}

void test_era2026_name_header_with_missing_body_name_is_32602(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/call", "health");
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":71,"method":"tools/call",)"
                     R"("params":{)" META_2026 "}}", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32602)");
  static_assertContains(response, "missing tool name");
  TEST_ASSERT_NULL(strstr(response, "-32020"));
  free(response);
}

void test_era2026_oversize_name_falls_to_tool_name_limit_32602(void)
{
  char name70[71];
  memset(name70, 'a', sizeof(name70) - 1);
  name70[sizeof(name70) - 1] = '\0';

  static_setRoutingHeaders("2026-07-28", "tools/call", name70);
  char body[512];
  snprintf(body, sizeof(body),
           R"({"jsonrpc":"2.0","id":72,"method":"tools/call",)"
           R"("params":{)" META_2026 R"(,"name":"%s","arguments":{}}})", name70);
  int status;
  char* response = static_dispatch(body, &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32602)");
  static_assertContains(response, "at most 32 characters");
  free(response);
}

void test_era2026_oversize_protocol_version_is_32602_400(void)
{
  char pv45[46];
  memset(pv45, '9', sizeof(pv45) - 1);
  pv45[sizeof(pv45) - 1] = '\0';

  static_setRoutingHeaders(pv45, "tools/list", NULL);
  char body[512];
  snprintf(body, sizeof(body),
           R"({"jsonrpc":"2.0","id":73,"method":"tools/list",)"
           R"("params":{"_meta":{)"
           R"("io.modelcontextprotocol/protocolVersion":"%s",)"
           R"("io.modelcontextprotocol/clientInfo":{"name":"p","version":"1"},)"
           R"("io.modelcontextprotocol/clientCapabilities":{}}}})", pv45);
  int status;
  char* response = static_dispatch(body, &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32602)");
  free(response);
}

void test_era2026_unsupported_version_data_is_escaped(void)
{
  static_setRoutingHeaders(R"(2027-"e)", "tools/list", NULL);
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":74,"method":"tools/list",)"
                     R"("params":{"_meta":{)"
                     R"("io.modelcontextprotocol/protocolVersion":"2027-\"e",)"
                     R"("io.modelcontextprotocol/clientInfo":{"name":"p","version":"1"},)"
                     R"("io.modelcontextprotocol/clientCapabilities":{}}}})", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32022)");
  static_assertContains(response, R"("requested":"2027-\"e")");
  free(response);
}

static void static_readRoutingHeaders(const char* text, McpRoutingHeaders_t* headers_out)
{
  ReceiveResult_t request;
  TEST_ASSERT_TRUE_MESSAGE(requestText_parse(text, &request), text);
  mcp_readRoutingHeaders(request.ma_headers, request.m_headerCount, headers_out);
}

void test_parse_routing_headers_ignores_a_name_longer_or_shorter_than_a_routing_name(void)
{
  McpRoutingHeaders_t h;
  static_readRoutingHeaders(
    "POST /mcp HTTP/1.1\r\n"
    "Mcp-Names: health\r\n"
    "Mcp-Protocol: 2026-07-28\r\n"
    "\r\n"
    "{}", &h);
  TEST_ASSERT_FALSE(h.m_hasName);
  TEST_ASSERT_FALSE(h.m_hasProtocolVersion);
  TEST_ASSERT_FALSE(h.m_hasMethod);
}

void test_parse_routing_headers_extracts_all_case_insensitive(void)
{
  McpRoutingHeaders_t h;
  static_readRoutingHeaders(
    "POST /mcp HTTP/1.1\r\n"
    "Host: x\r\n"
    "MCP-Protocol-Version: 2026-07-28\r\n"
    "Mcp-Method:   tools/call  \r\n"
    "MCP-NAME: health\r\n"
    "\r\n"
    "{}", &h);
  TEST_ASSERT_TRUE(h.m_hasProtocolVersion);
  TEST_ASSERT_EQUAL_STRING("2026-07-28", h.ma_protocolVersion);
  TEST_ASSERT_TRUE(h.m_hasMethod);
  TEST_ASSERT_EQUAL_STRING("tools/call", h.ma_method);
  TEST_ASSERT_TRUE(h.m_hasName);
  TEST_ASSERT_EQUAL_STRING("health", h.ma_name);
  TEST_ASSERT_FALSE(h.m_duplicated);
}

void test_parse_routing_headers_duplicate_flag_first_wins(void)
{
  McpRoutingHeaders_t h;
  static_readRoutingHeaders(
    "POST /mcp HTTP/1.1\r\n"
    "mcp-protocol-version: 2026-07-28\r\n"
    "mcp-protocol-version: 2025-11-25\r\n"
    "\r\n"
    "{}", &h);
  TEST_ASSERT_TRUE(h.m_duplicated);
  TEST_ASSERT_EQUAL_STRING("2026-07-28", h.ma_protocolVersion);
}

void test_parse_routing_headers_absent_all_false(void)
{
  McpRoutingHeaders_t h;
  static_readRoutingHeaders(
    "POST /mcp HTTP/1.1\r\n"
    "Content-Type: application/json\r\n"
    "\r\n"
    "{}", &h);
  TEST_ASSERT_FALSE(h.m_hasProtocolVersion);
  TEST_ASSERT_FALSE(h.m_hasMethod);
  TEST_ASSERT_FALSE(h.m_hasName);
  TEST_ASSERT_FALSE(h.m_duplicated);
}

void test_parse_routing_headers_folded_value_flags_duplicated(void)
{
  McpRoutingHeaders_t h;
  static_readRoutingHeaders(
    "POST /mcp HTTP/1.1\r\n"
    "Mcp-Method: tools/list\r\n"
    " folded-continuation\r\n"
    "\r\n"
    "{}", &h);
  TEST_ASSERT_TRUE(h.m_duplicated);
  TEST_ASSERT_EQUAL_STRING("tools/list", h.ma_method);
}

void test_parse_routing_headers_too_long_version_clamped_to_max_length(void)
{
  McpRoutingHeaders_t h;
  static_readRoutingHeaders(
    "POST /mcp HTTP/1.1\r\n"
    "MCP-Protocol-Version: 2026-07-28-0123456789-0123456789-0123456789\r\n"
    "\r\n"
    "{}", &h);
  TEST_ASSERT_TRUE(h.m_hasProtocolVersion);
  TEST_ASSERT_EQUAL_size_t(MCP_HEADER_PROTOCOL_VERSION_MAX_LEN, strlen(h.ma_protocolVersion));
  TEST_ASSERT_EQUAL_MEMORY("2026-07-28-0123456789-0123456789-0123456", h.ma_protocolVersion, MCP_HEADER_PROTOCOL_VERSION_MAX_LEN);
}

void test_parse_routing_headers_too_long_version_leaves_method_flag_set(void)
{
  McpRoutingHeaders_t h;
  static_readRoutingHeaders(
    "POST /mcp HTTP/1.1\r\n"
    "Mcp-Method: tools/list\r\n"
    "MCP-Protocol-Version: 2026-07-28-0123456789-0123456789-0123456789\r\n"
    "\r\n"
    "{}", &h);
  TEST_ASSERT_TRUE(h.m_hasMethod);
  TEST_ASSERT_EQUAL_STRING("tools/list", h.ma_method);
}

void test_tool_CVESEARCH_wildcard_vendor_rejected(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":80,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"vendor":"cis%"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"(vendor must not contain wildcard %")");
  free(response);
}

void test_tool_CVESEARCH_wildcard_product_rejected(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":81,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"product":"io%"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"(product must not contain wildcard %")");
  free(response);
}

void test_tool_CVESEARCH_bad_published_after_rejected(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":82,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"published_after":"2020-13-99"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"(published_after must be a valid calendar date in YYYY-MM-DD form")");
  free(response);
}

void test_tool_CVESEARCH_bad_published_before_rejected(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":83,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"published_before":"not-a-date"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"(published_before must be a valid calendar date in YYYY-MM-DD form")");
  free(response);
}

void test_tool_CVESEARCH_impossible_calendar_date_rejected(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":85,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"published_after":"2026-02-31"}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, R"(published_after must be a valid calendar date in YYYY-MM-DD form")", g_stub_CVESEARCH_call_count);
}

void test_tool_CVESEARCH_impossible_calendar_published_before_rejected(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":86,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"published_before":"2023-02-29"}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, R"(published_before must be a valid calendar date in YYYY-MM-DD form")", g_stub_CVESEARCH_call_count);
}

void test_tool_CVESEARCH_bad_sort_rejected(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":84,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"sort":"nope"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"(sort must be published_time, epss, or cvss")");
  free(response);
}

void test_tool_CVETRIAGE_wildcard_vendor_rejected(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":85,"method":"tools/call",)"
                     R"("params":{"name":"cve_triage","arguments":{"vendor":"cis%"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"(vendor must not contain wildcard %")");
  free(response);
}

void test_tool_CVETRIAGE_wildcard_product_rejected(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":86,"method":"tools/call",)"
                     R"("params":{"name":"cve_triage","arguments":{"product":"io%"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"(product must not contain wildcard %")");
  free(response);
}

void test_tool_CVELEADING_wildcard_vendor_rejected(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":87,"method":"tools/call",)"
                     R"("params":{"name":"cve_leading","arguments":{"vendor":"cis%"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"(vendor must not contain wildcard %")");
  free(response);
}

void test_tool_CVELEADING_wildcard_product_rejected(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":88,"method":"tools/call",)"
                     R"("params":{"name":"cve_leading","arguments":{"product":"io%"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"(product must not contain wildcard %")");
  free(response);
}

void test_tool_CVESEARCH_accepted_filters_reach_db_params(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":89,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{)"
                     R"("vendor":"cisco","product":"ios","cwe_id":"CWE-79",)"
                     R"("severity":"CRITICAL","sort":"epss"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING("cisco",    g_stub_CVESEARCH_last_params.ma_vendor);
  TEST_ASSERT_EQUAL_STRING("ios",      g_stub_CVESEARCH_last_params.ma_product);
  TEST_ASSERT_EQUAL_STRING("CWE-79",   g_stub_CVESEARCH_last_params.ma_cweId);
  TEST_ASSERT_EQUAL_STRING("CRITICAL", g_stub_CVESEARCH_last_params.ma_severity);
  TEST_ASSERT_EQUAL_STRING("epss",     g_stub_CVESEARCH_last_params.ma_sort);
  free(response);
}

void test_tool_CVESEARCH_max_length_vendor_reaches_db_params(void)
{
  char vendor[CVESEARCH_VENDOR_LEN + 1];
  memset(vendor, 'a', CVESEARCH_VENDOR_LEN);
  vendor[CVESEARCH_VENDOR_LEN] = '\0';

  char body[512];
  int written = snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":90,"method":"tools/call",)"
                         R"("params":{"name":"cve_search","arguments":{"vendor":"%s"}}})", vendor);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));

  int status;
  char* response = static_dispatch(body, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING(vendor, g_stub_CVESEARCH_last_params.ma_vendor);
  free(response);
}

void test_tool_CVESEARCH_overlong_cwe_id_never_exceeds_field(void)
{
  char cwe_id[CVELOOKUP_CWE_ID_LEN + 2];
  memset(cwe_id, 'C', CVELOOKUP_CWE_ID_LEN + 1);
  cwe_id[CVELOOKUP_CWE_ID_LEN + 1] = '\0';

  char body[512];
  int written = snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":91,"method":"tools/call",)"
                         R"("params":{"name":"cve_search","arguments":{"cwe_id":"%s"}}})", cwe_id);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));

  int status;
  char* response = static_dispatch(body, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_TRUE(strlen(g_stub_CVESEARCH_last_params.ma_cweId) <= CVELOOKUP_CWE_ID_LEN);
  free(response);
}

static void static_dispatchOverlongArg(const char* tool, const char* key, size_t length, int id, char** response_out, int* status_out)
{
  char value[256];
  TEST_ASSERT_TRUE(length < sizeof(value));
  memset(value, 'a', length);
  value[length] = '\0';

  char body[512];
  int written = snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":%d,"method":"tools/call",)"
                         R"("params":{"name":"%s","arguments":{"%s":"%s"}}})", id, tool, key, value);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
  *response_out = static_dispatch(body, status_out);
}

void test_tool_CVESEARCH_severity_too_long_is_tool_error(void)
{
  int status;
  char* response;
  static_dispatchOverlongArg("cve_search", "severity", CVELOOKUP_SEVERITY_LEN + 1, 100, &response, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"(severity is too long")");
  free(response);
}

void test_tool_CVESEARCH_published_after_too_long_is_tool_error(void)
{
  int status;
  char* response;
  static_dispatchOverlongArg("cve_search", "published_after", CVELOOKUP_PUBLISHED_LEN + 1, 101, &response, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"(published_after is too long")");
  free(response);
}

void test_tool_CVESEARCH_published_before_too_long_is_tool_error(void)
{
  int status;
  char* response;
  static_dispatchOverlongArg("cve_search", "published_before", CVELOOKUP_PUBLISHED_LEN + 1, 102, &response, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"(published_before is too long")");
  free(response);
}

void test_tool_CVESEARCH_vendor_too_long_does_not_silently_drop_filter(void)
{
  int status;
  char* response;
  static_dispatchOverlongArg("cve_search", "vendor", CVESEARCH_VENDOR_LEN + 26, 103, &response, &status);

  static_assertToolRefusedBeforeDb(response, status, R"(vendor is too long")", g_stub_CVESEARCH_call_count);
}

void test_tool_CVESEARCH_cwe_id_too_long_is_tool_error(void)
{
  int status;
  char* response;
  static_dispatchOverlongArg("cve_search", "cwe_id", CVELOOKUP_CWE_ID_LEN + 1, 104, &response, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"(cwe_id is too long")");
  free(response);
}

void test_tool_CVESEARCH_sort_too_long_is_tool_error(void)
{
  int status;
  char* response;
  static_dispatchOverlongArg("cve_search", "sort", CVESEARCH_SORT_LEN, 105, &response, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"(sort is too long")");
  free(response);
}

void test_tool_CVETRIAGE_vendor_too_long_is_tool_error(void)
{
  int status;
  char* response;
  static_dispatchOverlongArg("cve_triage", "vendor", CVESEARCH_VENDOR_LEN + 1, 106, &response, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"(vendor is too long")");
  free(response);
}

void test_tool_CVELEADING_product_too_long_is_tool_error(void)
{
  int status;
  char* response;
  static_dispatchOverlongArg("cve_leading", "product", CVESEARCH_PRODUCT_LEN + 1, 107, &response, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"(product is too long")");
  free(response);
}

void test_tool_CVESEARCH_severity_exact_max_length_accepted(void)
{
  int status;
  char* response;
  static_dispatchOverlongArg("cve_search", "severity", CVELOOKUP_SEVERITY_LEN, 108, &response, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"(severity must be CRITICAL, HIGH, MEDIUM, LOW, or NONE")");
  free(response);
}

void test_tool_CVESEARCH_vendor_bad_escape_does_not_silently_drop_filter(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":109,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"vendor":"cisco\x"}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, R"(vendor contains an escape this server cannot decode")", g_stub_CVESEARCH_call_count);
}

void test_tool_CVESEARCH_cwe_id_bad_escape_is_rejected_by_name(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":110,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"cwe_id":"CWE-79\x"}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, R"(cwe_id contains an escape this server cannot decode")", g_stub_CVESEARCH_call_count);
}

void test_tool_CVESEARCH_absent_sort_reaches_db_empty(void)
{
  int status;
  g_stub_CVESEARCH_status = DB_OK;
  g_stub_CVESEARCH_last_params.ma_sort[0] = 'z';
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":111,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"severity":"HIGH"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CVESEARCH_call_count);
  TEST_ASSERT_EQUAL_STRING("", g_stub_CVESEARCH_last_params.ma_sort);
  free(response);
}

void test_tool_CVELOOKUP_overlong_id_is_refused_as_rest_refuses_it(void)
{
  int status;
  char id[64];
  memset(id, 'A', 48);
  id[48] = '\0';
  char body[512];
  int written = snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":112,"method":"tools/call",)"
                         R"("params":{"name":"cve_lookup","arguments":{"cve_id":"%s"}}})", id);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
  char* response = static_dispatch(body, &status);
  static_assertContains(response, R"("text":"CVE ID must be CVE-YYYY-NNNN[N...]"}],"isError":true)");
  TEST_ASSERT_NULL(strstr(response, id));
  free(response);
}

void test_tool_CVESEARCH_min_cvss_out_of_double_range_is_tool_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":120,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"min_cvss":1e999}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, R"(min_cvss must be a number between 0.0 and 10.0")", g_stub_CVESEARCH_call_count);
}

void test_tool_CVESEARCH_min_cvss_underflow_is_tool_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":121,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"min_cvss":1e-999}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, NULL, g_stub_CVESEARCH_call_count);
}

void test_tool_CVESEARCH_min_cvss_as_string_is_tool_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":122,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"min_cvss":"9.0"}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, NULL, g_stub_CVESEARCH_call_count);
}

void test_tool_CVESEARCH_min_cvss_as_null_is_tool_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":123,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"min_cvss":null}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, NULL, g_stub_CVESEARCH_call_count);
}

void test_tool_CVESEARCH_min_cvss_value_reaches_db_params(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":124,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"min_cvss":9.0}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CVESEARCH_call_count);
  TEST_ASSERT_EQUAL_INT(900, (int)(g_stub_CVESEARCH_last_params.m_minCvss * 100.0));
  free(response);
}

void test_tool_CVESEARCH_absent_min_cvss_reaches_db_as_not_set_sentinel(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":125,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"severity":"HIGH"}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CVESEARCH_call_count);
  TEST_ASSERT_EQUAL_INT(-100, (int)(g_stub_CVESEARCH_last_params.m_minCvss * 100.0));
  free(response);
}

void test_tool_CVESEARCH_min_cvss_ceiling_reaches_db_params(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":126,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"min_cvss":10.0}}})", &status);

  TEST_ASSERT_EQUAL_INT(1000, (int)(g_stub_CVESEARCH_last_params.m_minCvss * 100.0));
  free(response);
}

void test_tool_CVESEARCH_min_cvss_floor_reaches_db_params(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":127,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"min_cvss":0}}})", &status);

  TEST_ASSERT_EQUAL_INT(1, g_stub_CVESEARCH_call_count);
  TEST_ASSERT_EQUAL_INT(0, (int)(g_stub_CVESEARCH_last_params.m_minCvss * 100.0));
  free(response);
}

void test_tool_CVESEARCH_min_epss_out_of_double_range_is_tool_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":128,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"min_epss":1e999}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, R"(min_epss must be a number between 0.0 and 1.0")", g_stub_CVESEARCH_call_count);
}

void test_tool_CVESEARCH_limit_as_string_is_tool_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":129,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"limit":"20"}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, R"(limit must be an integer between 1 and 100")", g_stub_CVESEARCH_call_count);
}

void test_tool_CVESEARCH_offset_out_of_long_range_is_tool_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":130,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"offset":99999999999999999999}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, NULL, g_stub_CVESEARCH_call_count);
}

void test_tool_CVESEARCH_limit_and_offset_reach_db_params(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":131,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"limit":5,"offset":40}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CVESEARCH_call_count);
  TEST_ASSERT_EQUAL_INT(5,  g_stub_CVESEARCH_last_params.m_limit);
  TEST_ASSERT_EQUAL_INT(40, g_stub_CVESEARCH_last_params.m_offset);
  free(response);
}

void test_tool_CVESEARCH_vendor_as_null_does_not_silently_drop_filter(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":132,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"vendor":null}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, R"(vendor must be a string")", g_stub_CVESEARCH_call_count);
}

void test_tool_CVESEARCH_severity_as_number_does_not_silently_drop_filter(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":133,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"severity":9}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, NULL, g_stub_CVESEARCH_call_count);
}

void test_tool_CVESEARCH_sort_as_array_keeps_the_default_out_of_the_answer(void)
{
  static_assertToolRefusedWith("cve_search", R"({"sort":["epss"]})", "Invalid params: sort must not be an object or an array");
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVESEARCH_call_count);
}

void test_tool_CVETRIAGE_min_risk_score_as_string_is_tool_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":135,"method":"tools/call",)"
                     R"("params":{"name":"cve_triage","arguments":{"min_risk_score":"70"}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, R"(min_risk_score must be a number between 0.0 and 100.0")", g_stub_CVETRIAGE_call_count);
}

void test_tool_CVETRIAGE_min_risk_score_value_reaches_db_params(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":136,"method":"tools/call",)"
                     R"("params":{"name":"cve_triage","arguments":{"min_risk_score":70}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CVETRIAGE_call_count);
  TEST_ASSERT_EQUAL_INT(7000, (int)(g_stub_CVETRIAGE_last_params.m_minRiskScore * 100.0));
  free(response);
}

void test_tool_CVELEADING_min_epss_out_of_double_range_is_tool_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":137,"method":"tools/call",)"
                     R"("params":{"name":"cve_leading","arguments":{"min_epss":1e999}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, NULL, g_stub_CVELEADING_call_count);
}

void test_tool_CVELEADING_min_epss_value_reaches_db_params(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":138,"method":"tools/call",)"
                     R"("params":{"name":"cve_leading","arguments":{"min_epss":0.75}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CVELEADING_call_count);
  TEST_ASSERT_EQUAL_INT(75, (int)(g_stub_CVELEADING_last_params.m_minEpss * 100.0));
  free(response);
}

void test_tool_CVESEARCH_limit_and_offset_floors_reach_db_params(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":901,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"limit":1,"offset":0}}})", &status);

  TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CVESEARCH_call_count, "limit=1 offset=0 are legal");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CVESEARCH_last_params.m_limit,  "limit floor reached DB");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_CVESEARCH_last_params.m_offset, "offset floor reached DB");
  free(response);
}

void test_tool_CVESEARCH_limit_ceiling_reaches_db_params(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":902,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"limit":100}}})", &status);

  TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CVESEARCH_call_count, "limit=100 is legal");
  TEST_ASSERT_EQUAL_INT_MESSAGE(100, g_stub_CVESEARCH_last_params.m_limit, "limit ceiling reached DB");
  free(response);
}

void test_tool_CVESEARCH_integer_bounds_refuse_one_step_outside(void)
{
  const char* bodies[] = {
    R"({"jsonrpc":"2.0","id":903,"method":"tools/call",)"
    R"("params":{"name":"cve_search","arguments":{"limit":0}}})",
    R"({"jsonrpc":"2.0","id":904,"method":"tools/call",)"
    R"("params":{"name":"cve_search","arguments":{"limit":101}}})",
    R"({"jsonrpc":"2.0","id":905,"method":"tools/call",)"
    R"("params":{"name":"cve_search","arguments":{"offset":-1}}})",
    R"({"jsonrpc":"2.0","id":909,"method":"tools/call",)"
    R"("params":{"name":"cve_search","arguments":{"offset":10001}}})",
    R"({"jsonrpc":"2.0","id":906,"method":"tools/call",)"
    R"("params":{"name":"cve_search","arguments":{"offset":4294967296}}})"
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    g_stub_CVESEARCH_call_count = 0;

    int status;
    char* response = static_dispatch(bodies[i], &status);

    static_assertToolRefusedBeforeDb(response, status, NULL, g_stub_CVESEARCH_call_count);
  }
}

void test_tool_CVESEARCH_min_epss_over_one_is_tool_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":907,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"min_epss":2.0}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, R"(min_epss must be a number between 0.0 and 1.0")", g_stub_CVESEARCH_call_count);
}

void test_tool_CVELEADING_min_epss_over_one_is_tool_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":908,"method":"tools/call",)"
                     R"("params":{"name":"cve_leading","arguments":{"min_epss":2.0}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, NULL, g_stub_CVELEADING_call_count);
}

void test_tool_CVELEADING_min_epss_one_reaches_db_params(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":910,"method":"tools/call",)"
                     R"("params":{"name":"cve_leading","arguments":{"min_epss":1.0}}})", &status);

  TEST_ASSERT_EQUAL_INT(1, g_stub_CVELEADING_call_count);
  TEST_ASSERT_EQUAL_INT(100, (int)(g_stub_CVELEADING_last_params.m_minEpss * 100.0));
  free(response);
}

void test_tool_CVELEADING_limit_over_50_is_tool_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":911,"method":"tools/call",)"
                     R"("params":{"name":"cve_leading","arguments":{"limit":51}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, R"(limit must be an integer between 1 and 50")", g_stub_CVELEADING_call_count);
}

void test_tool_CVELEADING_limit_50_reaches_db_params(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":912,"method":"tools/call",)"
                     R"("params":{"name":"cve_leading","arguments":{"limit":50}}})", &status);

  TEST_ASSERT_EQUAL_INT(1, g_stub_CVELEADING_call_count);
  TEST_ASSERT_EQUAL_INT(50, g_stub_CVELEADING_last_params.m_limit);
  free(response);
}

void test_tool_CVESEARCH_absent_min_epss_reaches_db_as_not_set_sentinel(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":916,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"severity":"HIGH"}}})", &status);

  TEST_ASSERT_EQUAL_INT(1, g_stub_CVESEARCH_call_count);
  TEST_ASSERT_EQUAL_INT_MESSAGE(-100, (int)(g_stub_CVESEARCH_last_params.m_minEpss * 100.0),
                                "absent cve_search.min_epss stays at the not-set sentinel");
  free(response);
}

void test_tool_CVELEADING_absent_min_epss_reaches_db_as_not_set_sentinel(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":917,"method":"tools/call",)"
                     R"("params":{"name":"cve_leading","arguments":{"vendor":"cisco"}}})", &status);

  TEST_ASSERT_EQUAL_INT(1, g_stub_CVELEADING_call_count);
  TEST_ASSERT_EQUAL_INT_MESSAGE(-100, (int)(g_stub_CVELEADING_last_params.m_minEpss * 100.0),
                                "absent cve_leading.min_epss stays at the not-set sentinel");
  free(response);
}

void test_tool_CVETRIAGE_absent_min_risk_score_reaches_db_as_not_set_sentinel(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":919,"method":"tools/call",)"
                     R"("params":{"name":"cve_triage","arguments":{"vendor":"cisco"}}})", &status);

  TEST_ASSERT_EQUAL_INT(1, g_stub_CVETRIAGE_call_count);
  TEST_ASSERT_EQUAL_INT_MESSAGE(-100, (int)(g_stub_CVETRIAGE_last_params.m_minRiskScore * 100.0),
                                "absent cve_triage.min_risk_score stays at the not-set sentinel");
  free(response);
}

void test_tool_CVESEARCH_partially_consumed_number_is_tool_error(void)
{
  const char* bodies[] = {
    R"({"jsonrpc":"2.0","id":920,"method":"tools/call",)"
    R"("params":{"name":"cve_search","arguments":{"min_cvss":1.2.3}}})",
    R"({"jsonrpc":"2.0","id":921,"method":"tools/call",)"
    R"("params":{"name":"cve_search","arguments":{"min_cvss":1-2}}})",
    R"({"jsonrpc":"2.0","id":922,"method":"tools/call",)"
    R"("params":{"name":"cve_search","arguments":{"limit":1e3}}})"
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    g_stub_CVESEARCH_call_count = 0;

    int status;
    char* response = static_dispatch(bodies[i], &status);

    static_assertToolRefusedBeforeDb(response, status, NULL, g_stub_CVESEARCH_call_count);
  }
}

void test_tool_CVESEARCH_numbers_outside_the_json_grammar_are_tool_errors(void)
{
  static const struct { const char* mp_arguments; const char* mp_text; } cases[] = {
    { R"({"min_cvss":01})",   R"("text":"min_cvss must be a number between 0.0 and 10.0"}],"isError":true)" },
    { R"({"min_cvss":00})",   R"("text":"min_cvss must be a number between 0.0 and 10.0"}],"isError":true)" },
    { R"({"min_cvss":1.})",   R"("text":"min_cvss must be a number between 0.0 and 10.0"}],"isError":true)" },
    { R"({"min_cvss":01.5})", R"("text":"min_cvss must be a number between 0.0 and 10.0"}],"isError":true)" },
    { R"({"min_cvss":1.e0})", R"("text":"min_cvss must be a number between 0.0 and 10.0"}],"isError":true)" },
    { R"({"limit":01})",      R"("text":"limit must be an integer between 1 and 100"}],"isError":true)" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    g_stub_CVESEARCH_call_count = 0;

    char body[256];
    int  written = snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":%zu,"method":"tools/call","params":{"name":"cve_search","arguments":%s}})", i + 1, cases[i].mp_arguments);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
    int status;
    char* response = static_dispatch(body, &status);

    static_assertToolRefusedBeforeDb(response, status, cases[i].mp_text, g_stub_CVESEARCH_call_count);
  }
}

void test_tool_CVESEARCH_negative_threshold_is_tool_error(void)
{
  const char* bodies[] = {
    R"({"jsonrpc":"2.0","id":930,"method":"tools/call",)"
    R"("params":{"name":"cve_search","arguments":{"min_cvss":-1.0}}})",
    R"({"jsonrpc":"2.0","id":931,"method":"tools/call",)"
    R"("params":{"name":"cve_search","arguments":{"min_epss":-1.0}}})",
    R"({"jsonrpc":"2.0","id":932,"method":"tools/call",)"
    R"("params":{"name":"cve_search","arguments":{"min_cvss":-0.5}}})"
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    g_stub_CVESEARCH_call_count = 0;

    int status;
    char* response = static_dispatch(bodies[i], &status);

    static_assertToolRefusedBeforeDb(response, status, NULL, g_stub_CVESEARCH_call_count);
  }
}

void test_tool_CVETRIAGE_negative_min_risk_score_is_tool_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":933,"method":"tools/call",)"
                     R"("params":{"name":"cve_triage","arguments":{"min_risk_score":-1.0}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, NULL, g_stub_CVETRIAGE_call_count);
}

void test_tool_CVELEADING_negative_min_epss_is_tool_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":934,"method":"tools/call",)"
                     R"("params":{"name":"cve_leading","arguments":{"min_epss":-1.0}}})", &status);

  static_assertToolRefusedBeforeDb(response, status, NULL, g_stub_CVELEADING_call_count);
}

static void static_assertBoolFilterRefused(const char* body, const char* needle, int* counter)
{
  int status;
  *counter = 0;
  char* response = static_dispatch(body, &status);
  TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, body);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, needle);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, *counter, body);
  free(response);
}

void test_tool_CVESEARCH_non_boolean_in_kev_is_tool_error(void)
{
  const char* values[] = { "1", "0", "-1", R"("true")", R"("false")", "null" };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    char body[512];
    int written = snprintf(body, sizeof(body),
                           R"({"jsonrpc":"2.0","id":950,"method":"tools/call",)"
                           R"("params":{"name":"cve_search","arguments":{"in_kev":%s}}})", values[i]);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
    static_assertBoolFilterRefused(body, R"(in_kev must be true or false")", &g_stub_CVESEARCH_call_count);
  }
}

void test_tool_CVESEARCH_non_boolean_known_ransomware_is_tool_error(void)
{
  const char* values[] = { "1", "0", "-1", R"("true")", "null" };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    char body[512];
    int written = snprintf(body, sizeof(body),
                           R"({"jsonrpc":"2.0","id":951,"method":"tools/call",)"
                           R"("params":{"name":"cve_search","arguments":{"known_ransomware":%s}}})", values[i]);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
    static_assertBoolFilterRefused(body, R"(known_ransomware must be true")", &g_stub_CVESEARCH_call_count);
  }
}

void test_tool_CVESEARCH_known_ransomware_false_is_tool_error(void)
{
  static_assertBoolFilterRefused(R"({"jsonrpc":"2.0","id":952,"method":"tools/call",)"
                                 R"("params":{"name":"cve_search","arguments":{"known_ransomware":false}}})",
                                 R"(known_ransomware must be true")", &g_stub_CVESEARCH_call_count);
}

void test_tool_CVELEADING_known_ransomware_false_is_tool_error(void)
{
  static_assertBoolFilterRefused(R"({"jsonrpc":"2.0","id":953,"method":"tools/call",)"
                                 R"("params":{"name":"cve_leading","arguments":{"known_ransomware":false}}})",
                                 R"(known_ransomware must be true")", &g_stub_CVELEADING_call_count);
}

void test_tool_CVELEADING_in_kev_as_string_is_tool_error(void)
{
  static_assertBoolFilterRefused(R"({"jsonrpc":"2.0","id":954,"method":"tools/call",)"
                                 R"("params":{"name":"cve_leading","arguments":{"in_kev":"true"}}})",
                                 R"(in_kev must be true or false")", &g_stub_CVELEADING_call_count);
}

void test_tool_CVELEADING_known_ransomware_as_number_is_tool_error(void)
{
  static_assertBoolFilterRefused(R"({"jsonrpc":"2.0","id":955,"method":"tools/call",)"
                                 R"("params":{"name":"cve_leading","arguments":{"known_ransomware":1}}})",
                                 R"(known_ransomware must be true")", &g_stub_CVELEADING_call_count);
}

void test_tool_CVESEARCH_in_kev_true_reaches_db_params(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":958,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"in_kev":true}}})", &status);

  TEST_ASSERT_EQUAL_INT(1, g_stub_CVESEARCH_call_count);
  TEST_ASSERT_EQUAL_INT_MESSAGE(CVE_KEV_FILTER_ONLY_IN_KEV, g_stub_CVESEARCH_last_params.m_kevFilter, "in_kev:true reaches db as CVE_KEV_FILTER_ONLY_IN_KEV");
  TEST_ASSERT_FALSE_MESSAGE(g_stub_CVESEARCH_last_params.m_knownRansomware, "in_kev must not write the ransomware field");
  free(response);
}

void test_tool_CVESEARCH_known_ransomware_true_reaches_db_params(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":959,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"known_ransomware":true}}})", &status);

  TEST_ASSERT_EQUAL_INT(1, g_stub_CVESEARCH_call_count);
  TEST_ASSERT_TRUE_MESSAGE(g_stub_CVESEARCH_last_params.m_knownRansomware, "known_ransomware:true reaches db as true");
  TEST_ASSERT_EQUAL_INT_MESSAGE(CVE_KEV_FILTER_ANY, g_stub_CVESEARCH_last_params.m_kevFilter,
                                "known_ransomware must not write the in_kev field");
  free(response);
}

void test_tool_CVELEADING_in_kev_true_reaches_db_params(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":967,"method":"tools/call",)"
                     R"("params":{"name":"cve_leading","arguments":{"in_kev":true}}})", &status);

  TEST_ASSERT_EQUAL_INT(1, g_stub_CVELEADING_call_count);
  TEST_ASSERT_EQUAL_INT_MESSAGE(CVE_KEV_FILTER_ONLY_IN_KEV, g_stub_CVELEADING_last_params.m_kevFilter, "cve_leading in_kev:true reaches db as CVE_KEV_FILTER_ONLY_IN_KEV");
  TEST_ASSERT_FALSE_MESSAGE(g_stub_CVELEADING_last_params.m_knownRansomware, "in_kev must not write the ransomware field");
  free(response);
}

void test_tool_CVELEADING_known_ransomware_true_reaches_db_params(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":968,"method":"tools/call",)"
                     R"("params":{"name":"cve_leading","arguments":{"known_ransomware":true}}})", &status);

  TEST_ASSERT_EQUAL_INT(1, g_stub_CVELEADING_call_count);
  TEST_ASSERT_TRUE_MESSAGE(g_stub_CVELEADING_last_params.m_knownRansomware, "cve_leading known_ransomware:true reaches db as true");
  TEST_ASSERT_EQUAL_INT_MESSAGE(CVE_KEV_FILTER_ANY, g_stub_CVELEADING_last_params.m_kevFilter,
                                "known_ransomware must not write the in_kev field");
  free(response);
}

void test_tool_CVESEARCH_in_kev_false_reaches_db_params_as_not_in_kev(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":960,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"in_kev":false}}})", &status);

  TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CVESEARCH_call_count, "cve_search in_kev:false must reach db");
  TEST_ASSERT_EQUAL_INT_MESSAGE(CVE_KEV_FILTER_NOT_IN_KEV, g_stub_CVESEARCH_last_params.m_kevFilter, "cve_search in_kev:false reaches db as CVE_KEV_FILTER_NOT_IN_KEV");
  free(response);
}

void test_tool_CVELEADING_in_kev_false_reaches_db_params_as_not_in_kev(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":961,"method":"tools/call",)"
                     R"("params":{"name":"cve_leading","arguments":{"in_kev":false}}})", &status);

  TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CVELEADING_call_count, "cve_leading in_kev:false must reach db");
  TEST_ASSERT_EQUAL_INT_MESSAGE(CVE_KEV_FILTER_NOT_IN_KEV, g_stub_CVELEADING_last_params.m_kevFilter, "cve_leading in_kev:false reaches db as CVE_KEV_FILTER_NOT_IN_KEV");
  free(response);
}

void test_tool_CVESEARCH_absent_boolean_filters_reach_db_as_not_set(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":963,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"severity":"HIGH"}}})", &status);

  TEST_ASSERT_EQUAL_INT(1, g_stub_CVESEARCH_call_count);
  TEST_ASSERT_EQUAL_INT_MESSAGE(CVE_KEV_FILTER_ANY, g_stub_CVESEARCH_last_params.m_kevFilter, "absent cve_search.in_kev stays not-set");
  TEST_ASSERT_FALSE_MESSAGE(g_stub_CVESEARCH_last_params.m_knownRansomware, "absent cve_search.known_ransomware stays not-set");
  free(response);
}

void test_tool_CVELEADING_absent_boolean_filters_reach_db_as_not_set(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":964,"method":"tools/call",)"
                     R"("params":{"name":"cve_leading","arguments":{"vendor":"cisco"}}})", &status);

  TEST_ASSERT_EQUAL_INT(1, g_stub_CVELEADING_call_count);
  TEST_ASSERT_EQUAL_INT_MESSAGE(CVE_KEV_FILTER_ANY, g_stub_CVELEADING_last_params.m_kevFilter, "absent cve_leading.in_kev stays not-set");
  TEST_ASSERT_FALSE_MESSAGE(g_stub_CVELEADING_last_params.m_knownRansomware, "absent cve_leading.known_ransomware stays not-set");
  free(response);
}

void test_tool_call_scalar_arguments_is_protocol_error(void)
{
  const char* envelopes[] = {
    "null", "true", "false", R"("vendor=cisco")", "-1",
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "12", "3.5"
  };
  for (size_t i = 0; i < sizeof(envelopes) / sizeof(envelopes[0]); i++)
  {
    char body[512];
    int written = snprintf(body, sizeof(body),
                           R"({"jsonrpc":"2.0","id":970,"method":"tools/call",)"
                           R"("params":{"name":"cve_search","arguments":%s}})", envelopes[i]);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));

    int status;
    g_stub_CVESEARCH_call_count = 0;
    char* response = static_dispatch(body, &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, envelopes[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, R"("message":"Invalid params: arguments must be a JSON object")"),
                                 envelopes[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_CVESEARCH_call_count, envelopes[i]);
    free(response);
  }
}

void test_tool_call_empty_array_arguments_is_protocol_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":971,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":[]}})", &status);

  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("code":-32602)");
  static_assertContains(response, "arguments must be a JSON object");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_CVESEARCH_call_count, "empty array envelope must not reach db");
  free(response);
}

void test_tool_call_array_wrapped_arguments_is_protocol_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":972,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":[{"vendor":"cisco","in_kev":true}]}})", &status);

  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("code":-32602)");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_CVESEARCH_call_count,
                                "arguments wrapped in an array must not reach db");
  free(response);
}

void test_tool_call_array_wrapped_required_argument_is_protocol_error(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":973,"method":"tools/call",)"
                     R"("params":{"name":"cve_lookup","arguments":[{"cve_id":"CVE-2021-44228"}]}})", &status);

  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("code":-32602)");
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_CVELOOKUP_call_count,
                                "a wrapped required argument must not reach db");
  free(response);
}

void test_tool_call_absent_arguments_still_runs_with_defaults(void)
{
  int status;
  g_stub_CVESEARCH_call_count = 0;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":974,"method":"tools/call",)"
                     R"("params":{"name":"cve_search"}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CVESEARCH_call_count, "absent arguments must still reach db");
  TEST_ASSERT_EQUAL_INT_MESSAGE(CVE_LIST_DEFAULT_LIMIT, g_stub_CVESEARCH_last_params.m_limit,
                                "absent arguments keeps the default limit");
  TEST_ASSERT_EQUAL_INT_MESSAGE(CVE_KEV_FILTER_ANY, g_stub_CVESEARCH_last_params.m_kevFilter, "absent arguments keeps in_kev not set");
  TEST_ASSERT_FALSE_MESSAGE(g_stub_CVESEARCH_last_params.m_knownRansomware, "absent arguments keeps known_ransomware not set");
  free(response);
}

void test_era2026_non_object_arguments_is_400(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/call", "cve_search");
  int status;
  g_stub_CVESEARCH_call_count = 0;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":975,"method":"tools/call",)"
                     R"("params":{)" META_2026 R"(,"name":"cve_search","arguments":null}})", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(response, R"("code":-32602)");
  static_assertContains(response, "arguments must be a JSON object");
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVESEARCH_call_count);
  free(response);
}

static void static_assertToolEntryHas(const char* payload, const char* tool_name, const char* needle, bool expect_present)
{
  char anchor[64] = "";
  int written = snprintf(anchor, sizeof(anchor), R"({"name":"%s",)", tool_name);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(anchor));

  const char* tool_start = strstr(payload, anchor);
  TEST_ASSERT_NOT_NULL_MESSAGE(tool_start, tool_name);
  const char* next_tool = strstr(tool_start + 1, R"({"name":")");
  size_t tool_len = next_tool ? (size_t)(next_tool - tool_start) : strlen(tool_start);

  char* tool_slice = (char*)malloc(tool_len + 1);
  TEST_ASSERT_NOT_NULL(tool_slice);
  memcpy(tool_slice, tool_start, tool_len);
  tool_slice[tool_len] = '\0';

  char message[256] = "";
  written = snprintf(message, sizeof(message), "%s: %s", tool_name, needle);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(message));
  if (expect_present)
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(tool_slice, needle), message);
  else
    TEST_ASSERT_NULL_MESSAGE(strstr(tool_slice, needle), message);
  free(tool_slice);
}

void test_tools_list_boolean_filter_schemas(void)
{
  const char* kev_needle    = R"("in_kev":{"type":"boolean"},)";
  const char* kev_const     = R"("in_kev":{"type":"boolean","const")";
  const char* ransom_needle = R"("known_ransomware":{"type":"boolean","const":true,)";

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":966,"method":"tools/list"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);

  static_assertToolEntryHas(response, "cve_search",   kev_needle,    true);
  static_assertToolEntryHas(response, "cve_leading",  kev_needle,    true);
  static_assertToolEntryHas(response, "cve_search",   kev_const,     false);
  static_assertToolEntryHas(response, "cve_leading",  kev_const,     false);
  static_assertToolEntryHas(response, "cve_search",   ransom_needle, true);
  static_assertToolEntryHas(response, "cve_leading",  ransom_needle, true);
  free(response);
}

#define TEST_TOOLS_LIST_MAX_BYTE_COUNT 28672

#define TEST_MCP_TOOL_DESCRIPTION_MAX_LEN 240

void test_tools_list_fits_its_byte_cap(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":7,"method":"tools/list"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_LESS_OR_EQUAL_size_t(TEST_TOOLS_LIST_MAX_BYTE_COUNT, strlen(response));
  free(response);
}

void test_mcp_tool_descriptions_fit_their_byte_cap(void)
{
  int tool_count = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    if (endpoints[i].mp_mcpToolName == NULL)
      continue;
    TEST_ASSERT_NOT_NULL_MESSAGE(endpoints[i].mp_mcpToolDescription, endpoints[i].mp_mcpToolName);
    TEST_ASSERT_LESS_OR_EQUAL_size_t_MESSAGE(TEST_MCP_TOOL_DESCRIPTION_MAX_LEN, strlen(endpoints[i].mp_mcpToolDescription),
                                             endpoints[i].mp_mcpToolName);
    tool_count++;
  }
  TEST_ASSERT_TRUE(tool_count > 0);
}

static char* static_copyMcpArgSchema(const char* payload, const char* tool_name, const char* arg_name)
{
  char anchor[64] = "";
  int written = snprintf(anchor, sizeof(anchor), R"({"name":"%s",)", tool_name);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(anchor));
  const char* tool_start = strstr(payload, anchor);
  TEST_ASSERT_NOT_NULL_MESSAGE(tool_start, tool_name);
  const char* next_tool = strstr(tool_start + 1, R"({"name":")");

  char key[96] = "";
  written = snprintf(key, sizeof(key), R"("%s":{)", arg_name);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(key));
  const char* key_start = strstr(tool_start, key);
  TEST_ASSERT_NOT_NULL_MESSAGE(key_start, arg_name);
  TEST_ASSERT_TRUE_MESSAGE(next_tool == NULL || key_start < next_tool, arg_name);

  const char* object_start = key_start + strlen(key) - 1;
  const char* cursor       = object_start;
  int         depth        = 0;
  bool        is_in_string = false;
  for (; *cursor != '\0'; cursor++)
  {
    if (is_in_string)
    {
      if (*cursor == '\\' && cursor[1] != '\0')
        cursor++;
      else if (*cursor == '"')
        is_in_string = false;
      continue;
    }
    if (*cursor == '"')
      is_in_string = true;
    else if (*cursor == '{')
      depth++;
    else if (*cursor == '}' && --depth == 0)
      break;
  }
  TEST_ASSERT_EQUAL_CHAR_MESSAGE('}', *cursor, arg_name);

  size_t object_len = (size_t)(cursor - object_start) + 1;
  char*  object     = (char*)malloc(object_len + 1);
  TEST_ASSERT_NOT_NULL(object);
  memcpy(object, object_start, object_len);
  object[object_len] = '\0';
  return object;
}

static void static_assertSchemaHasMember(const char* schema, const char* member, const char* message)
{
  const char* found = strstr(schema, member);
  TEST_ASSERT_NOT_NULL_MESSAGE(found, message);
  char after = found[strlen(member)];
  TEST_ASSERT_TRUE_MESSAGE(after == ',' || after == '}', message);
}

static void static_assertNumberSchemaIsExact(const char* schema, const char* expected_head, const char* message)
{
  size_t head_len = strlen(expected_head);
  TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE(expected_head, schema, head_len, message);
  const char* rest = schema + head_len;
  TEST_ASSERT_TRUE_MESSAGE(strcmp(rest, "}") == 0 || strncmp(rest, R"(,"description":)", strlen(R"(,"description":)")) == 0, message);
}

void test_tools_list_args_carry_their_spec_bounds(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":7,"method":"tools/list"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);

  int number_count = 0;
  int string_count = 0;
  int array_count  = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (endpoint->mp_mcpToolName == NULL)
      continue;
    for (int j = 0; j < endpoint->m_paramCount; j++)
    {
      const EndpointParam_t* param = &endpoint->mp_params[j];
      if ((param->m_sources & ENDPOINT_PARAM_SRC_MCP_ARG) == 0)
        continue;
      const EndpointParamSpec_t* spec = param->mp_spec;

      char message[160] = "";
      snprintf(message, sizeof(message), "%s.%s", endpoint->mp_mcpToolName, spec->mp_name);
      char* schema = static_copyMcpArgSchema(response, endpoint->mp_mcpToolName, spec->mp_name);

      char expected[160] = "";
      int  used          = 0;
      if (spec->m_type == ENDPOINT_PARAM_TYPE_INT)
      {
        used += snprintf(expected + used, sizeof(expected) - (size_t)used, R"({"type":"integer","minimum":%d)", (int)spec->m_min);
        if (spec->m_max != INT_MAX)
          used += snprintf(expected + used, sizeof(expected) - (size_t)used, R"(,"maximum":%d)", (int)spec->m_max);
        if (spec->m_default != -1.0)
          used += snprintf(expected + used, sizeof(expected) - (size_t)used, R"(,"default":%d)", (int)spec->m_default);
        TEST_ASSERT_TRUE(used > 0 && (size_t)used < sizeof(expected));
        static_assertNumberSchemaIsExact(schema, expected, message);
        number_count++;
      }
      else if (spec->m_type == ENDPOINT_PARAM_TYPE_DOUBLE)
      {
        used += snprintf(expected + used, sizeof(expected) - (size_t)used, R"({"type":"number","minimum":%g,"maximum":%g)", spec->m_min, spec->m_max);
        if (spec->m_default != -1.0)
          used += snprintf(expected + used, sizeof(expected) - (size_t)used, R"(,"default":%g)", spec->m_default);
        TEST_ASSERT_TRUE(used > 0 && (size_t)used < sizeof(expected));
        static_assertNumberSchemaIsExact(schema, expected, message);
        number_count++;
      }
      else if (strcmp(endpoint_jsonSchemaTypeName(spec->m_type), "string") == 0)
      {
        TEST_ASSERT_TRUE_MESSAGE(spec->m_maxLen > 0, message);
        snprintf(expected, sizeof(expected), R"("maxLength":%zu)", spec->m_maxLen);
        static_assertSchemaHasMember(schema, expected, message);
        string_count++;
      }
      else if (endpoint_isBulkArrayType(spec->m_type))
      {
        snprintf(expected, sizeof(expected), R"("minItems":1,"maxItems":%d)", (int)spec->m_max);
        static_assertSchemaHasMember(schema, expected, message);
        array_count++;
      }
      free(schema);
    }
  }
  TEST_ASSERT_TRUE(number_count > 0);
  TEST_ASSERT_TRUE(string_count > 0);
  TEST_ASSERT_TRUE(array_count > 0);
  free(response);
}

void test_tools_list_bounds_hold_their_literal_values(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":7,"method":"tools/list"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);

  char* limit = static_copyMcpArgSchema(response, "cve_search", "limit");
  static_assertNumberSchemaIsExact(limit, R"({"type":"integer","minimum":1,"maximum":100,"default":20)", "cve_search.limit");
  free(limit);

  char* offset = static_copyMcpArgSchema(response, "cve_search", "offset");
  static_assertNumberSchemaIsExact(offset, R"({"type":"integer","minimum":0,"maximum":10000,"default":0)", "cve_search.offset");
  free(offset);

  char* asn_limit = static_copyMcpArgSchema(response, "asn_lookup", "limit");
  static_assertNumberSchemaIsExact(asn_limit, R"({"type":"integer","minimum":1,"maximum":50,"default":50)", "asn_lookup.limit");
  free(asn_limit);

  char* min_cvss = static_copyMcpArgSchema(response, "cve_search", "min_cvss");
  static_assertNumberSchemaIsExact(min_cvss, R"({"type":"number","minimum":0,"maximum":10)", "cve_search.min_cvss");
  free(min_cvss);

  char* vendor = static_copyMcpArgSchema(response, "cve_search", "vendor");
  static_assertSchemaHasMember(vendor, R"("maxLength":128)", "cve_search.vendor");
  free(vendor);

  char* cve_ids = static_copyMcpArgSchema(response, "cve_lookup_bulk", "cve_ids");
  static_assertSchemaHasMember(cve_ids, R"("minItems":1,"maxItems":50)", "cve_lookup_bulk.cve_ids");
  free(cve_ids);

  free(response);
}

void test_tools_list_open_world_hint_follows_the_upstream_call(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":991,"method":"tools/list"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);

  static_assertToolEntryHas(response, "kev_lookup", R"("annotations":{"readOnlyHint":true,"openWorldHint":false})", true);
  static_assertToolEntryHas(response, "dns_lookup", R"("annotations":{"readOnlyHint":true,"openWorldHint":true})",  true);
  free(response);
}

void test_tools_list_watchlist_annotations_follow_the_effect(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":992,"method":"tools/list"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);

  static_assertToolEntryHas(response, "watchlist_edit", R"("annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":true,"openWorldHint":true})", true);
  static_assertToolEntryHas(response, "watchlist_events", R"("annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false})", true);
  free(response);
}

void test_tools_list_meta_names_the_category(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":993,"method":"tools/list"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);

  static_assertToolEntryHas(response, "kev_lookup", R"("_meta":{"com.contrastcyber/category":"CVE Intelligence"})", true);
  free(response);
}

void test_tools_list_document_carries_no_structural_whitespace(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":990,"method":"tools/list"})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);

  bool in_string = false;
  bool escaped   = false;
  for (const char* cursor = response; *cursor != '\0'; cursor++)
  {
    if (escaped)
      escaped = false;
    else if (*cursor == '\\')
      escaped = true;
    else if (*cursor == '"')
      in_string = !in_string;
    else if (!in_string && (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' || *cursor == '\r'))
    {
      char message[160] = "";
      int written = snprintf(message, sizeof(message), "whitespace outside a string at offset %ld: %.24s",
                             (long)(cursor - response), (cursor - response) > 12 ? cursor - 12 : response);
      TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(message));
      TEST_FAIL_MESSAGE(message);
    }
  }
  TEST_ASSERT_FALSE_MESSAGE(in_string, "unbalanced quote in the tools/list document");
  free(response);
}

void test_tool_negative_integer_arguments_are_refused_on_every_tool(void)
{
  struct { const char* tool; const char* args; int* counter; } cases[] = {
    { "cve_search",   R"({"limit":-1})",  &g_stub_CVESEARCH_call_count   },
    { "cve_triage",   R"({"limit":-1})",  &g_stub_CVETRIAGE_call_count   },
    { "cve_triage",   R"({"offset":-1})", &g_stub_CVETRIAGE_call_count   },
    { "cve_leading",  R"({"limit":-1})",  &g_stub_CVELEADING_call_count  }
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char body[512];
    int written = snprintf(body, sizeof(body),
                           R"({"jsonrpc":"2.0","id":940,"method":"tools/call",)"
                           R"("params":{"name":"%s","arguments":%s}})", cases[i].tool, cases[i].args);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));

    int status;
    *cases[i].counter = 0;
    char* response = static_dispatch(body, &status);
    TEST_ASSERT_EQUAL_INT(200, status);
    static_assertContains(response, R"("isError":true)");
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, *cases[i].counter, "a negative integer must not reach db");
    free(response);
  }
}

#define MCP_FAT_AFFECTED_PRODUCTS_LEN (80u * 1024u)

static char* static_callCVELOOKUPBULKWithMaxIds(int request_id, int* status)
{
  char ids[2048];
  size_t pos = 0;
  for (int i = 0; i < CVELOOKUPBULK_MAX_IDS; i++)
    pos += (size_t)snprintf(ids + pos, sizeof(ids) - pos, R"(%s"CVE-2021-%05d")", i ? "," : "", 10000 + i);
  char body[2304];
  snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":%d,"method":"tools/call",)"
                               R"("params":{"name":"cve_lookup_bulk","arguments":{"cve_ids":[%s]}}})", request_id, ids);
  return static_dispatch(body, status);
}

void test_tool_CVETRIAGE_full_page_past_initial_capacity_is_a_result(void)
{
  g_stub_CVETRIAGE_status     = DB_OK;
  g_stub_CVETRIAGE_item_count = CVE_LIST_MAX_LIMIT;
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":902,"method":"tools/call",)"
                     R"("params":{"name":"cve_triage","arguments":{"limit":100}}})", &status);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_GREATER_THAN_size_t(JSONBUF_INITIAL_CAP, strlen(response));
  static_assertContains(response, R"(\"total\":100)");
  static_assertContains(response, R"(]}\n"}],"isError":false)");
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_NULL(strstr(response, "-32603"));
  free(response);
}

void test_tool_CVELOOKUPBULK_body_just_under_ceiling_is_a_result(void)
{
  g_stub_CVELOOKUP_status = DB_OK;
  g_stub_CVELOOKUP_affected_products_len = MCP_FAT_AFFECTED_PRODUCTS_LEN;
  TEST_ASSERT_GREATER_THAN_size_t(JSONBUF_DEFAULT_CEILING / 4 * 3, (size_t)CVELOOKUPBULK_MAX_IDS * MCP_FAT_AFFECTED_PRODUCTS_LEN);
  int status;
  char* response = static_callCVELOOKUPBULKWithMaxIds(903, &status);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_GREATER_THAN_size_t(JSONBUF_DEFAULT_CEILING / 4 * 3, strlen(response));
  static_assertContains(response, R"(\"successful\":50)");
  static_assertContains(response, R"(]}"}],"isError":false)");
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_NULL(strstr(response, "-32603"));
  const char* cursor = response;
  for (int i = 0; i < CVELOOKUPBULK_MAX_IDS; i++)
  {
    char needle[64];
    snprintf(needle, sizeof(needle), R"(%s{\"cve_id\":\"CVE-2021-%05d\")", i ? R"(}\n,)" : R"(\"results\":[)", 10000 + i);
    cursor = strstr(cursor, needle);
    TEST_ASSERT_NOT_NULL_MESSAGE(cursor, needle);
    cursor += strlen(needle);
  }
  free(response);
}

#define MCP_LIST_PAGE_ITEMS CVE_LIST_RANKED_MAX_LIMIT
static CveListItem_t g_mcpListPage[MCP_LIST_PAGE_ITEMS];

static char* static_callListToolWithPage(const char* name, const char* args, CveListItem_t** items_slot, int* count_slot, DbStatus_t* status_slot, int* status)
{
  memset(g_mcpListPage, 0, sizeof(g_mcpListPage));
  for (int i = 0; i < MCP_LIST_PAGE_ITEMS; i++)
    strncpy(g_mcpListPage[i].ma_cveId, "CVE-2021-44228", CVELOOKUP_ID_MAX_LEN);
  *items_slot  = g_mcpListPage;
  *count_slot  = MCP_LIST_PAGE_ITEMS;
  *status_slot = DB_OK;
  char body[256];
  snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":901,"method":"tools/call","params":{"name":"%s","arguments":%s}})", name, args);
  return static_dispatch(body, status);
}

static void static_assertListPageIsAResult(char* response, int status)
{
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_GREATER_THAN_size_t(JSONBUF_INITIAL_CAP, strlen(response));
  static_assertContains(response, R"(]}\n"}],"isError":false)");
  static_assertToolSucceeded(response, status);
}

void test_tool_CVESEARCH_page_past_initial_capacity_is_a_result(void)
{
  int status;
  char* response = static_callListToolWithPage("cve_search", R"({"severity":"HIGH","limit":50})", &g_stub_CVESEARCH_items, &g_stub_CVESEARCH_item_count, &g_stub_CVESEARCH_status, &status);
  static_assertListPageIsAResult(response, status);
}

void test_tool_CVELEADING_page_past_initial_capacity_is_a_result(void)
{
  int status;
  char* response = static_callListToolWithPage("cve_leading", R"({"limit":50})", &g_stub_CVELEADING_items, &g_stub_CVELEADING_item_count, &g_stub_CVELEADING_status, &status);
  static_assertListPageIsAResult(response, status);
}

void test_tool_CVESEARCH_page_that_cannot_grow_is_internal_error(void)
{
  g_reallocFailsNext = true;
  int status;
  char* response = static_callListToolWithPage("cve_search", R"({"severity":"HIGH","limit":50})", &g_stub_CVESEARCH_items, &g_stub_CVESEARCH_item_count, &g_stub_CVESEARCH_status, &status);
  TEST_ASSERT_FALSE_MESSAGE(g_reallocFailsNext, "no growth step was reached");
  static_assertContains(response, R"("message":"Internal error"})");
  static_assertToolInternalError(response, status);
}

void test_tool_CVELEADING_page_that_cannot_grow_is_internal_error(void)
{
  g_reallocFailsNext = true;
  int status;
  char* response = static_callListToolWithPage("cve_leading", R"({"limit":50})", &g_stub_CVELEADING_items, &g_stub_CVELEADING_item_count, &g_stub_CVELEADING_status, &status);
  TEST_ASSERT_FALSE_MESSAGE(g_reallocFailsNext, "no growth step was reached");
  static_assertContains(response, R"("message":"Internal error"})");
  static_assertToolInternalError(response, status);
}

#define MCP_BULK_OVER_CEILING_AFFECTED_PRODUCTS_LEN (88u * 1024u)

void test_tool_CVELOOKUP_record_past_initial_capacity_is_a_result(void)
{
  g_stub_CVELOOKUP_status = DB_OK;
  g_stub_CVELOOKUP_affected_products_len = 2 * JSONBUF_INITIAL_CAP;
  int status;
  char* response = static_dispatch(CVELOOKUP_REQUEST_BODY, &status);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_GREATER_THAN_size_t(JSONBUF_INITIAL_CAP, strlen(response));
  static_assertContains(response, R"(?include_ghsa=true\"}\n"}],"isError":false)");
  static_assertToolSucceeded(response, status);
}

void test_tool_CVELOOKUP_record_just_under_ceiling_is_a_result(void)
{
  g_stub_CVELOOKUP_status = DB_OK;
  g_stub_CVELOOKUP_affected_products_len = JSONBUF_DEFAULT_CEILING - JSONBUF_INITIAL_CAP;
  int status;
  char* response = static_dispatch(CVELOOKUP_REQUEST_BODY, &status);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_GREATER_THAN_size_t(JSONBUF_DEFAULT_CEILING - JSONBUF_INITIAL_CAP, strlen(response));
  static_assertContains(response, R"(?include_ghsa=true\"}\n"}],"isError":false)");
  static_assertToolSucceeded(response, status);
}

void test_tool_CVELOOKUP_record_over_ceiling_is_internal_error(void)
{
  g_stub_CVELOOKUP_status = DB_OK;
  g_stub_CVELOOKUP_affected_products_len = JSONBUF_DEFAULT_CEILING;
  int status;
  char* response = static_dispatch(CVELOOKUP_REQUEST_BODY, &status);
  static_assertToolInternalError(response, status);
}

void test_tool_CVELOOKUPBULK_body_over_ceiling_is_internal_error(void)
{
  g_stub_CVELOOKUP_status = DB_OK;
  g_stub_CVELOOKUP_affected_products_len = MCP_BULK_OVER_CEILING_AFFECTED_PRODUCTS_LEN;
  TEST_ASSERT_GREATER_THAN_size_t(JSONBUF_DEFAULT_CEILING, (size_t)CVELOOKUPBULK_MAX_IDS * MCP_BULK_OVER_CEILING_AFFECTED_PRODUCTS_LEN);
  TEST_ASSERT_LESS_THAN_size_t(JSONBUF_MAX_CEILING, (size_t)CVELOOKUPBULK_MAX_IDS * MCP_BULK_OVER_CEILING_AFFECTED_PRODUCTS_LEN);
  int status;
  char* response = static_callCVELOOKUPBULKWithMaxIds(904, &status);
  static_assertToolInternalError(response, status);
}

void test_tool_CVSSCALCULATOR_ok(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":61,"method":"tools/call",)"
                     R"("params":{"name":"cvss_calculator",)"
                     R"("arguments":{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/RC:U"}}})", &status);

  static_assertContains(response, R"(\"base_score\":10.0)");
  static_assertContains(response, R"(\"temporal_score\":9.2,\"environmental_score\":9.2)");
  static_assertToolSucceeded(response, status);
}

void test_tool_CVSSCALCULATOR_needs_no_database(void)
{
  g_conn = NULL;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":62,"method":"tools/call",)"
                     R"("params":{"name":"cvss_calculator",)"
                     R"("arguments":{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}})", &status);

  static_assertContains(response, R"(\"base_score\":9.8)");
  static_assertToolSucceeded(response, status);
}

void test_tools_without_a_database(void)
{
  static const char* const calls[] = {
    R"("params":{"name":"cve_lookup","arguments":{"cve_id":"CVE-2021-44228"}}})",
    R"("params":{"name":"kev_lookup","arguments":{"cve_id":"CVE-2021-44228"}}})",
    R"("params":{"name":"cve_risk_score","arguments":{"cve_id":"CVE-2021-44228"}}})",
    R"("params":{"name":"cwe_lookup","arguments":{"cwe_id":"CWE-79"}}})",
    R"("params":{"name":"cve_exploit","arguments":{"cve_id":"CVE-2021-44228"}}})",
    R"("params":{"name":"cve_lookup_bulk","arguments":{"cve_ids":[5,"foo"]}}})",
    R"("params":{"name":"cve_triage_bulk","arguments":{"cve_ids":[5,"foo"]}}})",
  };
  g_conn                     = NULL;
  g_stub_CVELOOKUP_status    = DB_OK;
  g_stub_KEVLOOKUP_status    = DB_OK;
  g_stub_CVERISKSCORE_status = DB_OK;
  g_stub_CWELOOKUP_status    = DB_OK;
  for (size_t i = 0; i < sizeof(calls) / sizeof(calls[0]); i++)
  {
    char body[512];
    int  written = snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":%zu,"method":"tools/call",%s)", i + 1, calls[i]);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
    int   status;
    char* response = static_dispatch(body, &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, calls[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, R"("code":-32603,"message":"Internal error: database unavailable")"), calls[i]);
    free(response);
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVELOOKUP_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVELOOKUPBULK_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVEEXPLOIT_call_count);
}

void test_tool_CVSSCALCULATOR_missing_vector(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":63,"method":"tools/call",)"
                     R"("params":{"name":"cvss_calculator","arguments":{}}})", &status);

  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "-32602");
  static_assertContains(response, R"(Invalid params: vector is required")");
  free(response);
}

void test_tool_CVSSCALCULATOR_empty_vector(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":64,"method":"tools/call",)"
                     R"("params":{"name":"cvss_calculator","arguments":{"vector":""}}})", &status);

  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "-32602");
  static_assertContains(response, R"(Invalid params: vector is required")");
  free(response);
}

void test_tool_CVSSCALCULATOR_vector_not_a_string(void)
{
  const char* bodies[] = {
    R"({"jsonrpc":"2.0","id":68,"method":"tools/call","params":{"name":"cvss_calculator","arguments":{"vector":42}}})",
    R"({"jsonrpc":"2.0","id":69,"method":"tools/call","params":{"name":"cvss_calculator","arguments":{"vector":null}}})",
  };

  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    int status;
    char* response = static_dispatch(bodies[i], &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, bodies[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, "-32602"), bodies[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, "Invalid params: vector must be a string"), bodies[i]);
    TEST_ASSERT_NULL_MESSAGE(strstr(response, "isError"), bodies[i]);
    free(response);
  }
}

void test_tool_CVSSCALCULATOR_vector_with_a_unicode_escape_is_read_decoded(void)
{
  const char* body = "{\"jsonrpc\":\"2.0\",\"id\":70,\"method\":\"tools/call\",\"params\":{\"name\":\"cvss_calculator\",\"arguments\":{\"vector\":\"\\u0043VSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\"}}}";
  TEST_ASSERT_NOT_NULL(strstr(body, "\\u0043"));

  int status;
  char* response = static_dispatch(body, &status);
  static_assertContains(response, R"(\"base_score\":9.8)");
  static_assertToolSucceeded(response, status);
}

void test_tool_CVSSCALCULATOR_refused_vector_reports_its_reason_and_no_echo(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":65,"method":"tools/call",)"
                     R"("params":{"name":"cvss_calculator",)"
                     R"("arguments":{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:<script>"}}})", &status);

  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, "vector has a metric value CVSS v3 does not define");
  TEST_ASSERT_NULL(strstr(response, "<script>"));
  free(response);
}

void test_tool_CVSSCALCULATOR_leading_tab_is_refused_not_trimmed(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":71,"method":"tools/call",)"
                     R"("params":{"name":"cvss_calculator",)"
                     R"("arguments":{"vector":"\tCVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}})", &status);

  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, "vector must not contain control characters");
  free(response);
}

void test_tool_CVSSCALCULATOR_trailing_space_is_refused_not_trimmed(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":72,"method":"tools/call",)"
                     R"("params":{"name":"cvss_calculator",)"
                     R"("arguments":{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H "}}})", &status);

  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, "vector has a metric value CVSS v3 does not define");
  free(response);
}

void test_tool_CVSSCALCULATOR_each_other_refusal_reports_its_message(void)
{
  const struct { const char* mp_vector; CvssParseStatus_t m_status; } rows[] = {
    { "CVSS:3.1/XX:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CVSS_ERR_UNKNOWN_METRIC      },
    { "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CVSS_ERR_DUPLICATE_METRIC    },
    { "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",          CVSS_ERR_MISSING_BASE_METRIC },
    { "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/",     CVSS_ERR_EMPTY_COMPONENT     },
  };

  for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
  {
    CvssResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(rows[i].m_status, cvss_parse(rows[i].mp_vector, &result), rows[i].mp_vector);

    char body[512];
    int written = snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":73,"method":"tools/call","params":{"name":"cvss_calculator","arguments":{"vector":"%s"}}})", rows[i].mp_vector);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
    int status;
    char* response = static_dispatch(body, &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, rows[i].mp_vector);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, R"("isError":true)"), rows[i].mp_vector);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, cvss_parseStatusMessage(rows[i].m_status)), rows[i].mp_vector);
    free(response);
  }
}

void test_tool_CVSSCALCULATOR_vector_as_long_as_the_buffer_is_too_long(void)
{
  int status;
  char* response;
  static_dispatchOverlongArg("cvss_calculator", "vector", CVSS_VECTOR_MAX_LEN, 66, &response, &status);

  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, R"(vector is too long")");
  free(response);
}

void test_tool_CVSSCALCULATOR_vector_one_byte_shorter_reaches_the_parser(void)
{
  int status;
  char* response;
  static_dispatchOverlongArg("cvss_calculator", "vector", CVSS_VECTOR_MAX_LEN - 1, 67, &response, &status);

  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  static_assertContains(response, "vector must start with CVSS:3.0/ or CVSS:3.1/");
  TEST_ASSERT_NULL(strstr(response, "vector is too long"));
  free(response);
}

void test_tool_CVSSCALCULATOR_arguments_too_large(void)
{
  char pad[ENDPOINT_JSON_OBJECT_BUF_SIZE + 1];
  memset(pad, 'a', sizeof(pad) - 1);
  pad[sizeof(pad) - 1] = '\0';
  char body[ENDPOINT_JSON_OBJECT_BUF_SIZE + 512];
  int written = snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":74,"method":"tools/call","params":{"name":"cvss_calculator",)"
                         R"("arguments":{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","pad":"%s"}}})", pad);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));

  int status;
  char* response = static_dispatch(body, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "-32602");
  static_assertContains(response, "arguments too large");
  free(response);
}

void test_tool_KEVLOOKUP_body_past_initial_capacity_is_a_result(void)
{
  g_stub_KEVLOOKUP_status   = DB_OK;
  g_stub_KEVLOOKUP_cwes_len = 2 * JSONBUF_INITIAL_CAP;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":75,"method":"tools/call",)"
                     R"("params":{"name":"kev_lookup","arguments":{"cve_id":"CVE-2021-44228"}}})", &status);

  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_GREATER_THAN_size_t(JSONBUF_INITIAL_CAP, strlen(response));
  static_assertContains(response, R"(\"date_removed\":\"\"}\n"}],"isError":false)");
  static_assertToolSucceeded(response, status);
}

void test_tool_CWELOOKUP_body_past_initial_capacity_is_a_result(void)
{
  g_stub_CWELOOKUP_status    = DB_OK;
  g_stub_CWELOOKUP_mitigations_len = 2 * JSONBUF_INITIAL_CAP;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":76,"method":"tools/call",)"
                     R"("params":{"name":"cwe_lookup","arguments":{"cwe_id":"CWE-79"}}})", &status);

  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_GREATER_THAN_size_t(JSONBUF_INITIAL_CAP, strlen(response));
  static_assertContains(response, R"(\"updated_at\":\"2026-05-21T00:00:00+00:00\"}\n"}],"isError":false)");
  static_assertToolSucceeded(response, status);
}

void test_tool_CVEEXPLOIT_body_past_initial_capacity_is_a_result(void)
{
  g_stub_CVEEXPLOIT_escape_heavy = true;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":77,"method":"tools/call",)"
                     R"("params":{"name":"cve_exploit","arguments":{"cve_id":"CVE-2021-44228"}}})", &status);

  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_GREATER_THAN_size_t(JSONBUF_INITIAL_CAP, strlen(response));
  static_assertContains(response, R"(]}]}\n"}],"isError":false)");
  static_assertToolSucceeded(response, status);
}

void test_tool_KEVLOOKUP_body_over_ceiling_is_internal_error(void)
{
  g_stub_KEVLOOKUP_status   = DB_OK;
  g_stub_KEVLOOKUP_cwes_len = JSONBUF_DEFAULT_CEILING;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":78,"method":"tools/call",)"
                     R"("params":{"name":"kev_lookup","arguments":{"cve_id":"CVE-2021-44228"}}})", &status);

  static_assertToolInternalError(response, status);
}

void test_tool_CWELOOKUP_body_over_ceiling_is_internal_error(void)
{
  g_stub_CWELOOKUP_status    = DB_OK;
  g_stub_CWELOOKUP_mitigations_len = JSONBUF_DEFAULT_CEILING;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":79,"method":"tools/call",)"
                     R"("params":{"name":"cwe_lookup","arguments":{"cwe_id":"CWE-79"}}})", &status);

  static_assertToolInternalError(response, status);
}

void test_tool_HEALTH_body_that_cannot_grow_is_internal_error(void)
{
  g_stub_HEALTH_full_feeds = true;
  g_reallocFailsNext       = true;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":81,"method":"tools/call",)"
                     R"("params":{"name":"health"}})", &status);

  TEST_ASSERT_FALSE(g_reallocFailsNext);
  static_assertToolInternalError(response, status);
}

void test_tool_CVEEXPLOIT_body_that_cannot_grow_is_internal_error(void)
{
  g_stub_CVEEXPLOIT_escape_heavy = true;
  g_reallocFailsNext             = true;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":80,"method":"tools/call",)"
                     R"("params":{"name":"cve_exploit","arguments":{"cve_id":"CVE-2021-44228"}}})", &status);

  static_assertToolInternalError(response, status);
}

static void static_assertBufferThatCannotBeCreatedIsInternalError(const char* body)
{
  int status;
  char* response = static_dispatch(body, &status);
  static_assertToolSucceeded(response, status);

  g_mallocFailSize = JSONBUF_INITIAL_CAP;
  response = static_dispatch(body, &status);
  TEST_ASSERT_EQUAL_size_t_MESSAGE(0, g_mallocFailSize, "second run: no body malloc was reached");
  static_assertContains(response, R"("message":"Internal error"})");
  static_assertToolInternalError(response, status);
}

void test_tool_HEALTH_buffer_that_cannot_be_created_is_internal_error(void)
{
  static_assertBufferThatCannotBeCreatedIsInternalError(R"({"jsonrpc":"2.0","id":1001,"method":"tools/call",)"
    R"("params":{"name":"health"}})");
}

void test_tools_list_buffer_that_cannot_be_created_fails_the_dispatch(void)
{
  const char* body     = R"({"jsonrpc":"2.0","id":1002,"method":"tools/list"})";
  char*       response = NULL;
  int         status   = 0;
  TEST_ASSERT_TRUE(mcp_dispatch(body, strlen(body), static_installedRoutingHeaders(), &response, &status, g_conn, &TEST_FULL_CHARGE, NULL));
  TEST_ASSERT_NOT_NULL(response);
  free(response);

  g_mallocFailSize = JSONBUF_INITIAL_CAP;
  response = NULL;
  TEST_ASSERT_FALSE(mcp_dispatch(body, strlen(body), static_installedRoutingHeaders(), &response, &status, g_conn, &TEST_FULL_CHARGE, NULL));
  TEST_ASSERT_EQUAL_size_t(0, g_mallocFailSize);
  TEST_ASSERT_NULL(response);
}

void test_tool_CVELOOKUP_buffer_that_cannot_be_created_is_internal_error(void)
{
  g_stub_CVELOOKUP_status = DB_OK;

  static_assertBufferThatCannotBeCreatedIsInternalError(R"({"jsonrpc":"2.0","id":1002,"method":"tools/call",)"
    R"("params":{"name":"cve_lookup","arguments":{"cve_id":"CVE-2021-44228"}}})");
}

void test_tool_CVELOOKUPBULK_buffer_that_cannot_be_created_is_internal_error(void)
{
  g_stub_CVELOOKUP_status = DB_OK;

  static_assertBufferThatCannotBeCreatedIsInternalError(R"({"jsonrpc":"2.0","id":1003,"method":"tools/call",)"
    R"("params":{"name":"cve_lookup_bulk","arguments":{"cve_ids":["CVE-2021-44228","CVE-2021-45046"]}}})");
}

void test_tool_CVESEARCH_buffer_that_cannot_be_created_is_internal_error(void)
{
  g_stub_CVESEARCH_status = DB_OK;

  static_assertBufferThatCannotBeCreatedIsInternalError(R"({"jsonrpc":"2.0","id":1004,"method":"tools/call",)"
    R"("params":{"name":"cve_search","arguments":{}}})");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CVESEARCH_call_count, "only the first run queries");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CveListResultFree_call_count, "the first run frees its page once");
}

void test_tool_CVELEADING_buffer_that_cannot_be_created_is_internal_error(void)
{
  g_stub_CVELEADING_status = DB_OK;

  static_assertBufferThatCannotBeCreatedIsInternalError(R"({"jsonrpc":"2.0","id":1005,"method":"tools/call",)"
    R"("params":{"name":"cve_leading","arguments":{}}})");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CVELEADING_call_count, "only the first run queries");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_CveListResultFree_call_count, "the first run frees its page once");
}

void test_tool_KEVLOOKUP_buffer_that_cannot_be_created_is_internal_error(void)
{
  g_stub_KEVLOOKUP_status = DB_OK;

  static_assertBufferThatCannotBeCreatedIsInternalError(R"({"jsonrpc":"2.0","id":1007,"method":"tools/call",)"
    R"("params":{"name":"kev_lookup","arguments":{"cve_id":"CVE-2021-44228"}}})");
}

void test_tool_CWELOOKUP_buffer_that_cannot_be_created_is_internal_error(void)
{
  g_stub_CWELOOKUP_status = DB_OK;

  static_assertBufferThatCannotBeCreatedIsInternalError(R"({"jsonrpc":"2.0","id":1008,"method":"tools/call",)"
    R"("params":{"name":"cwe_lookup","arguments":{"cwe_id":"CWE-79"}}})");
}

void test_tool_CVERISKSCORE_buffer_that_cannot_be_created_is_internal_error(void)
{
  g_stub_CVERISKSCORE_status = DB_OK;

  static_assertBufferThatCannotBeCreatedIsInternalError(R"({"jsonrpc":"2.0","id":1009,"method":"tools/call",)"
    R"("params":{"name":"cve_risk_score","arguments":{"cve_id":"CVE-2021-44228"}}})");
}

void test_tool_CVEEXPLOIT_buffer_that_cannot_be_created_is_internal_error(void)
{
  static_assertBufferThatCannotBeCreatedIsInternalError(R"({"jsonrpc":"2.0","id":1010,"method":"tools/call",)"
    R"("params":{"name":"cve_exploit","arguments":{"cve_id":"CVE-2021-44228"}}})");
}

void test_tool_CVETRIAGE_buffer_that_cannot_be_created_is_internal_error(void)
{
  g_stub_CVETRIAGE_status = DB_OK;

  static_assertBufferThatCannotBeCreatedIsInternalError(R"({"jsonrpc":"2.0","id":1011,"method":"tools/call",)"
    R"("params":{"name":"cve_triage","arguments":{}}})");
}

void test_tool_CVETRIAGEBULK_buffer_that_cannot_be_created_is_internal_error(void)
{
  g_stub_CVETRIAGEBULK_status = DB_OK;

  static_assertBufferThatCannotBeCreatedIsInternalError(R"({"jsonrpc":"2.0","id":1012,"method":"tools/call",)"
    R"("params":{"name":"cve_triage_bulk","arguments":{"cve_ids":["CVE-2021-44228","CVE-2021-45046"]}}})");
}

void test_tool_PRODUCTEXPOSURE_buffer_that_cannot_be_created_is_internal_error(void)
{
  g_stub_PRODUCTEXPOSURE_status = DB_OK;

  static_assertBufferThatCannotBeCreatedIsInternalError(R"({"jsonrpc":"2.0","id":1013,"method":"tools/call",)"
    R"("params":{"name":"product_exposure","arguments":{"vendor":"cisco","product":"ios"}}})");
}

void test_tool_CVSSCALCULATOR_buffer_that_cannot_be_created_is_internal_error(void)
{
  static_assertBufferThatCannotBeCreatedIsInternalError(R"({"jsonrpc":"2.0","id":1014,"method":"tools/call",)"
    R"("params":{"name":"cvss_calculator","arguments":{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/RC:U"}}})");
}

void test_tool_CVETRIAGE_page_that_cannot_grow_is_internal_error(void)
{
  g_stub_CVETRIAGE_status     = DB_OK;
  g_stub_CVETRIAGE_item_count = CVE_LIST_MAX_LIMIT;
  g_reallocFailsNext          = true;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":1015,"method":"tools/call",)"
                     R"("params":{"name":"cve_triage","arguments":{"limit":100}}})", &status);

  TEST_ASSERT_FALSE_MESSAGE(g_reallocFailsNext, "no growth step was reached");
  static_assertContains(response, R"("message":"Internal error"})");
  static_assertToolInternalError(response, status);
}

void test_envelope_that_cannot_be_created_fails_dispatch(void)
{
  struct { const char* label; const char* protocol_version; const char* method; const char* body; } cases[] = {
    { "legacy ping",           NULL,         NULL,         R"({"jsonrpc":"2.0","id":1030,"method":"ping"})" },
    { "legacy initialize",     NULL,         NULL,         R"({"jsonrpc":"2.0","id":1031,"method":"initialize"})" },
    { "legacy unknown method", NULL,         NULL,         R"({"jsonrpc":"2.0","id":1032,"method":"no/such/method"})" },
    { "modern ping",           "2026-07-28", "ping",       R"({"jsonrpc":"2.0","id":1033,"method":"ping","params":{)" META_2026 "}}" },
    { "modern -32022",         "2027-01-01", "tools/list", R"({"jsonrpc":"2.0","id":1034,"method":"tools/list","params":{"_meta":{)"
                                                           R"("io.modelcontextprotocol/protocolVersion":"2027-01-01",)"
                                                           R"("io.modelcontextprotocol/clientInfo":{"name":"p","version":"1"},)"
                                                           R"("io.modelcontextprotocol/clientCapabilities":{}}}})" }
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    if (cases[i].protocol_version)
      static_setRoutingHeaders(cases[i].protocol_version, cases[i].method, NULL);
    else
      g_hasRoutingHeaders = false;

    char* response = NULL;
    int   status   = -1;
    TEST_ASSERT_TRUE_MESSAGE(mcp_dispatch(cases[i].body, strlen(cases[i].body), static_installedRoutingHeaders(), &response, &status, g_conn, &TEST_FULL_CHARGE, NULL), cases[i].label);
    TEST_ASSERT_NOT_NULL_MESSAGE(response, cases[i].label);
    free(response);

    response = NULL;
    g_mallocFailSize = JSONBUF_INITIAL_CAP;
    TEST_ASSERT_FALSE_MESSAGE(mcp_dispatch(cases[i].body, strlen(cases[i].body), static_installedRoutingHeaders(), &response, &status, g_conn, &TEST_FULL_CHARGE, NULL), cases[i].label);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0, g_mallocFailSize, cases[i].label);
    TEST_ASSERT_NULL_MESSAGE(response, cases[i].label);
  }
}

void test_tool_content_that_cannot_be_created_is_internal_error(void)
{
  const char* body = R"({"jsonrpc":"2.0","id":1035,"method":"tools/call",)"
                     R"("params":{"name":"cve_lookup_bulk","arguments":{"cve_ids":[]}}})";
  int status;
  char* response = static_dispatch(body, &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, R"("isError":true)");
  free(response);

  g_mallocFailSize = JSONBUF_INITIAL_CAP;
  response = static_dispatch(body, &status);
  TEST_ASSERT_EQUAL_size_t_MESSAGE(0, g_mallocFailSize, "no envelope malloc was reached");
  static_assertContains(response, R"({"jsonrpc":"2.0","id":1035,"error":{"code":-32603,)");
  static_assertContains(response, R"("message":"Internal error: the tool result could not be encoded")");
  static_assertToolInternalError(response, status);
}

#define MCP_ENVELOPE_OVER_CEILING_MATCHES_LEN  (838738u)
#define MCP_ENVELOPE_UNDER_CEILING_MATCHES_LEN (838726u)

static char* static_callDRIVERLOOKUPBULKWithMaxIds(int request_id, int* status)
{
  char hashes[1024];
  size_t pos = 0;
  for (int i = 0; i < DRIVERLOOKUPBULK_MAX_IDS; i++)
    pos += (size_t)snprintf(hashes + pos, sizeof(hashes) - pos, R"(%s"%032d")", i ? "," : "", i);
  char body[1280];
  snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":%d,"method":"tools/call",)"
                               R"("params":{"name":"driver_lookup_bulk","arguments":{"hashes":[%s]}}})", request_id, hashes);
  return static_dispatch(body, status);
}

void test_tool_DRIVERLOOKUPBULK_body_whose_envelope_passes_the_ceiling_is_internal_error(void)
{
  g_stub_DRIVERLOOKUPBULK_status      = DB_OK;
  g_stub_DRIVERLOOKUPBULK_matches_len = MCP_ENVELOPE_OVER_CEILING_MATCHES_LEN;
  TEST_ASSERT_LESS_THAN_size_t(JSONBUF_MAX_CEILING, (size_t)DRIVERLOOKUPBULK_MAX_IDS * MCP_ENVELOPE_OVER_CEILING_MATCHES_LEN);
  int status;
  char* response = static_callDRIVERLOOKUPBULKWithMaxIds(1036, &status);
  static_assertContains(response, R"("message":"Internal error: the tool result could not be encoded")");
  static_assertToolInternalError(response, status);
}

void test_tool_DRIVERLOOKUPBULK_body_whose_envelope_just_fits_is_a_result(void)
{
  g_stub_DRIVERLOOKUPBULK_status      = DB_OK;
  g_stub_DRIVERLOOKUPBULK_matches_len = MCP_ENVELOPE_UNDER_CEILING_MATCHES_LEN;
  int status;
  char* response = static_callDRIVERLOOKUPBULKWithMaxIds(1037, &status);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_GREATER_THAN_size_t(JSONBUF_MAX_CEILING - 1024, strlen(response));
  static_assertEndsWith(response, R"(]}"}],"isError":false}})");
  static_assertToolSucceeded(response, status);
}

void test_envelope_after_a_first_buffer_that_cannot_be_created_fails_dispatch(void)
{
  struct { const char* label; const char* protocol_version; const char* method; const char* body; } cases[] = {
    { "legacy initialize", NULL,         NULL,         R"({"jsonrpc":"2.0","id":1038,"method":"initialize"})" },
    { "modern -32022",     "2027-01-01", "tools/list", R"({"jsonrpc":"2.0","id":1039,"method":"tools/list","params":{"_meta":{)"
                                                       R"("io.modelcontextprotocol/protocolVersion":"2027-01-01",)"
                                                       R"("io.modelcontextprotocol/clientInfo":{"name":"p","version":"1"},)"
                                                       R"("io.modelcontextprotocol/clientCapabilities":{}}}})" }
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    if (cases[i].protocol_version)
      static_setRoutingHeaders(cases[i].protocol_version, cases[i].method, NULL);
    else
      g_hasRoutingHeaders = false;

    char* response = NULL;
    int   status   = -1;
    g_mallocFailSize      = JSONBUF_INITIAL_CAP;
    g_mallocFailSkipCount = 1;
    TEST_ASSERT_FALSE_MESSAGE(mcp_dispatch(cases[i].body, strlen(cases[i].body), static_installedRoutingHeaders(), &response, &status, g_conn, &TEST_FULL_CHARGE, NULL), cases[i].label);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0, g_mallocFailSize, cases[i].label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_mallocFailSkipCount, cases[i].label);
    TEST_ASSERT_NULL_MESSAGE(response, cases[i].label);
  }
}

void test_malloc_wrapper_fails_only_the_armed_size(void)
{
  g_mallocFailSize = JSONBUF_INITIAL_CAP;

  void* volatile other = malloc(JSONBUF_INITIAL_CAP - 1);
  void* volatile armed = malloc(JSONBUF_INITIAL_CAP);

  TEST_ASSERT_NOT_NULL_MESSAGE(other, "a malloc of another size must not fail");
  TEST_ASSERT_NULL_MESSAGE(armed, "the malloc of the armed size must fail");
  TEST_ASSERT_EQUAL_size_t(0, g_mallocFailSize);
  free(other);
}

#define X402_TOOL_CALL_BODY R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cve_lookup","arguments":{"cve_id":"CVE-2021-44228"}}})"

void test_mcp_credit_cost_offers_payment_on_a_payable_tool(void)
{
  EndpointPrice_t price;
  memset(&price, 0, sizeof(price));
  mcp_creditCost(X402_TOOL_CALL_BODY, &price);
  TEST_ASSERT_TRUE(price.m_isPaymentOfferable);
  TEST_ASSERT_EQUAL_PTR(endpoint_findByMcpName("cve_lookup"), price.mp_pricedEndpoint);
}

void test_mcp_credit_cost_offers_no_payment_on_a_non_payable_tool(void)
{
  const char* names[]  = { "health", "watchlist_edit" };
  const char* bodies[] = {
    R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"health","arguments":{}}})",
    R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"watchlist_edit","arguments":{"action":"list"}}})",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    EndpointPrice_t price;
    memset(&price, 0, sizeof(price));
    price.m_isPaymentOfferable = true;
    mcp_creditCost(bodies[i], &price);
    TEST_ASSERT_FALSE_MESSAGE(price.m_isPaymentOfferable, names[i]);
    TEST_ASSERT_EQUAL_PTR_MESSAGE(endpoint_findByMcpName(names[i]), price.mp_pricedEndpoint, names[i]);
  }
}

void test_mcp_credit_cost_offers_no_payment_when_the_gate_refuses(void)
{
  EndpointPrice_t price;
  memset(&price, 0, sizeof(price));
  price.m_isPaymentOfferable = true;
  mcp_creditCost(R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cve_lookup","arguments":{"cve_id":"not-a-cve"}}})", &price);
  TEST_ASSERT_FALSE(price.m_isPaymentOfferable);
  TEST_ASSERT_EQUAL_PTR(endpoint_findByMcpName("cve_lookup"), price.mp_pricedEndpoint);
}

void test_mcp_credit_cost_offers_no_payment_for_tools_list_and_notifications(void)
{
  const char* bodies[] = {
    R"({"jsonrpc":"2.0","id":1,"method":"tools/list"})",
    R"({"jsonrpc":"2.0","method":"notifications/initialized"})",
    "not json",
    R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}})",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    EndpointPrice_t price;
    memset(&price, 0, sizeof(price));
    price.m_isPaymentOfferable = true;
    price.mp_pricedEndpoint    = &endpoints[0];
    mcp_creditCost(bodies[i], &price);
    TEST_ASSERT_FALSE_MESSAGE(price.m_isPaymentOfferable, bodies[i]);
    TEST_ASSERT_NULL_MESSAGE(price.mp_pricedEndpoint, bodies[i]);
  }
}

#define X402_PAYABLE_TOOL_COUNT 32
void test_mcp_credit_cost_payable_tools_are_the_payable_rows(void)
{
  int payable_tool_count = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    if (endpoints[i].mp_mcpToolName == NULL)
      continue;
    const Endpoint_t* endpoint = endpoint_findByMcpName(endpoints[i].mp_mcpToolName);
    TEST_ASSERT_EQUAL_PTR(&endpoints[i], endpoint);
    if (endpoint->m_isPayable)
      payable_tool_count++;
  }
  TEST_ASSERT_EQUAL_INT(X402_PAYABLE_TOOL_COUNT, payable_tool_count);
}

void test_mcp_readPaymentMeta_is_none_without_a_payment_member(void)
{
  const char* bodies[] = {
    X402_TOOL_CALL_BODY,
    R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"other":1},"name":"cve_lookup"}})",
    R"({"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"x402/payment":{"a":1}}}})",
    R"({"jsonrpc":"2.0","method":"tools/call","params":{"_meta":{"x402/payment":{"a":1}},"name":"cve_lookup"}})",
    R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"x402/payment":{"a":1}})",
    R"({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"x402/payment":{"a":1}}}})",
    R"({"jsonrpc":"2.0","id":1,"method":"tools/call"})",
    R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":7,"name":"cve_lookup"}})",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    McpPaymentMeta_t meta;
    meta.m_status = MCP_PAYMENT_META_FOUND;
    mcp_readPaymentMeta(bodies[i], &meta);
    TEST_ASSERT_EQUAL_INT_MESSAGE(MCP_PAYMENT_META_NONE, meta.m_status, bodies[i]);
  }
}

void test_mcp_readPaymentMeta_finds_the_member_and_its_exact_span(void)
{
  const char* body = R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cve_lookup","_meta":{"k":1,"x402/payment":{"x402Version":2,"payload":{"t":"AQ=="}}},"arguments":{}}})";
  McpPaymentMeta_t meta;
  mcp_readPaymentMeta(body, &meta);
  TEST_ASSERT_EQUAL_INT(MCP_PAYMENT_META_FOUND, meta.m_status);
  TEST_ASSERT_TRUE(jsonread_isSpanEqual(meta.m_span, R"({"x402Version":2,"payload":{"t":"AQ=="}})"));
}

void test_mcp_readPaymentMeta_is_repeated_for_a_duplicate_or_an_escaped_key(void)
{
  const char* bodies[] = {
    R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cve_lookup","_meta":{"x402/payment":{"a":1},"x402/payment":{"a":2}}}})",
    R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cve_lookup","_meta":{"x402\/payment":{"a":1}}}})",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    McpPaymentMeta_t meta;
    mcp_readPaymentMeta(bodies[i], &meta);
    TEST_ASSERT_EQUAL_INT_MESSAGE(MCP_PAYMENT_META_REPEATED, meta.m_status, bodies[i]);
  }
}

void test_mcp_isModernEra_is_true_only_for_a_modern_version(void)
{
  TEST_ASSERT_FALSE(mcp_isModernEra(NULL));
  static_setRoutingHeaders("2025-06-18", "tools/call", "cve_lookup");
  TEST_ASSERT_FALSE(mcp_isModernEra(&g_routingHeaders));
  static_setRoutingHeaders("2026-07-28", "tools/call", "cve_lookup");
  TEST_ASSERT_TRUE(mcp_isModernEra(&g_routingHeaders));
}

void test_mcp_tryBuildModernRefusal_is_false_for_the_legacy_era(void)
{
  char* json   = (char*)0x1;
  int   status = 0;
  TEST_ASSERT_FALSE(mcp_tryBuildModernRefusal("not json", strlen("not json"), NULL, &json, &status));
  TEST_ASSERT_EQUAL_PTR((char*)0x1, json);
}

void test_mcp_tryBuildModernRefusal_refuses_missing_meta_keys(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/call", "cve_lookup");
  const char* body = R"({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"_meta":{"x402/payment":{"a":1}},"name":"cve_lookup","arguments":{}}})";
  char* json   = NULL;
  int   status = 0;
  TEST_ASSERT_TRUE(mcp_tryBuildModernRefusal(body, strlen(body), &g_routingHeaders, &json, &status));
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(json, R"("id":9,"error":{"code":-32602)");
  free(json);
}

void test_mcp_tryBuildModernRefusal_is_false_when_the_ladder_passes(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/call", "health");
  const char* body = R"({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{)" META_2026 R"(,"name":"health","arguments":{}}})";
  char* json   = NULL;
  int   status = 0;
  TEST_ASSERT_FALSE(mcp_tryBuildModernRefusal(body, strlen(body), &g_routingHeaders, &json, &status));
  TEST_ASSERT_NULL(json);
}

void test_mcp_tryBuildModernRefusal_refuses_a_notification_and_a_parse_error(void)
{
  static_setRoutingHeaders("2026-07-28", "tools/call", "health");
  const char* notification = R"({"jsonrpc":"2.0","method":"tools/call","params":{)" META_2026 R"(,"name":"health"}})";
  char* json   = NULL;
  int   status = 0;
  TEST_ASSERT_TRUE(mcp_tryBuildModernRefusal(notification, strlen(notification), &g_routingHeaders, &json, &status));
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(json, R"("code":-32600)");
  free(json);

  json = NULL;
  TEST_ASSERT_TRUE(mcp_tryBuildModernRefusal("not json", strlen("not json"), &g_routingHeaders, &json, &status));
  TEST_ASSERT_EQUAL_INT(400, status);
  static_assertContains(json, R"("code":-32700)");
  free(json);
}

void test_mcp_dispatch_run_report_of_a_run_tool(void)
{
  const char* body = R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"health","arguments":{}}})";
  McpRunReport_t report;
  memset(&report, 0xA5, sizeof(report));
  char* response = NULL;
  int   status   = 0;
  TEST_ASSERT_TRUE(mcp_dispatch(body, strlen(body), NULL, &response, &status, g_conn, &TEST_FULL_CHARGE, &report));
  TEST_ASSERT_TRUE(report.m_isRun);
  TEST_ASSERT_EQUAL_INT(ENDPOINT_RUN_OK, report.m_runStatus);
  TEST_ASSERT_EQUAL_PTR(endpoint_findByMcpName("health"), report.mp_endpoint);
  const char* prefix = R"({"jsonrpc":"2.0","id":1,"result":{)";
  TEST_ASSERT_EQUAL_size_t(strlen(prefix), report.m_resultMetaOffset);
  TEST_ASSERT_EQUAL_CHAR('{', response[report.m_resultMetaOffset - 1]);
  TEST_ASSERT_EQUAL_INT(0, strncmp(response, prefix, strlen(prefix)));
  free(response);
}

void test_mcp_dispatch_run_report_of_a_protocol_error(void)
{
  const char* bodies[] = {
    R"({"jsonrpc":"2.0","id":1,"method":"no/such"})",
    R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}})",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    McpRunReport_t report;
    memset(&report, 0xA5, sizeof(report));
    char* response = NULL;
    int   status   = 0;
    TEST_ASSERT_TRUE(mcp_dispatch(bodies[i], strlen(bodies[i]), NULL, &response, &status, g_conn, &TEST_FULL_CHARGE, &report));
    TEST_ASSERT_FALSE_MESSAGE(report.m_isRun, bodies[i]);
    TEST_ASSERT_NULL_MESSAGE(report.mp_endpoint, bodies[i]);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0, report.m_resultMetaOffset, bodies[i]);
    free(response);
  }
}

void test_mcp_dispatch_run_report_of_a_gate_refusal(void)
{
  const char* body = R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cve_lookup","arguments":{"cve_id":"not-a-cve"}}})";
  McpRunReport_t report;
  memset(&report, 0xA5, sizeof(report));
  char* response = NULL;
  int   status   = 0;
  TEST_ASSERT_TRUE(mcp_dispatch(body, strlen(body), NULL, &response, &status, g_conn, &TEST_FULL_CHARGE, &report));
  TEST_ASSERT_FALSE(report.m_isRun);
  TEST_ASSERT_EQUAL_PTR(endpoint_findByMcpName("cve_lookup"), report.mp_endpoint);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVELOOKUP_call_count);
  free(response);
}

void test_mcp_buildResultWithMeta_inserts_the_member(void)
{
  const char* body = R"({"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"health","arguments":{}}})";
  McpRunReport_t report;
  char* response = NULL;
  int   status   = 0;
  TEST_ASSERT_TRUE(mcp_dispatch(body, strlen(body), NULL, &response, &status, g_conn, &TEST_FULL_CHARGE, &report));
  const char* value = R"({"success":true,"transaction":"sig","network":"solana:x"})";
  char* with_meta = mcp_buildResultWithMeta(response, report.m_resultMetaOffset, MCP_META_KEY_X402_PAYMENT_RESPONSE, value);
  TEST_ASSERT_NOT_NULL(with_meta);
  TEST_ASSERT_EQUAL_size_t(strlen(response) + strlen(R"("_meta":{"x402/payment-response":},)") + strlen(value), strlen(with_meta));

  JsonReadSpan_t root, result, meta, member, content_before, content_after, result_before;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(with_meta, strlen(with_meta), &root));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root, "result", &result));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(result, "_meta", &meta));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(meta, MCP_META_KEY_X402_PAYMENT_RESPONSE, &member));
  TEST_ASSERT_TRUE(jsonread_isSpanEqual(member, value));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(result, "content", &content_after));

  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(response, strlen(response), &root));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root, "result", &result_before));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(result_before, "content", &content_before));
  TEST_ASSERT_EQUAL_size_t(content_before.m_len, content_after.m_len);
  TEST_ASSERT_EQUAL_INT(0, memcmp(content_before.mp_start, content_after.mp_start, content_before.m_len));
  free(with_meta);
  free(response);
}

static void static_assertPaymentRequiredCopies(const char* response, const char* expected)
{
  JsonReadSpan_t root, result, structured, content, first, text_span;
  size_t element_offset = 0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(response, strlen(response), &root));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root, "result", &result));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(result, "structuredContent", &structured));
  TEST_ASSERT_TRUE(jsonread_isSpanEqual(structured, expected));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(result, "content", &content));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_arrayNextElement(content, &element_offset, &first));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(first, "text", &text_span));
  char text[512];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToStrStatus(text_span, text, sizeof(text)));
  TEST_ASSERT_EQUAL_STRING(expected, text);
  static_assertContains(response, R"("isError":true)");
}

void test_mcp_buildPaymentRequiredResult_has_both_copies(void)
{
  const char* payment_required = R"({"x402Version":2,"error":"say \"pay\""})";
  char* legacy = mcp_buildPaymentRequiredResult("7", payment_required, false);
  TEST_ASSERT_NOT_NULL(legacy);
  TEST_ASSERT_EQUAL_INT(0, strncmp(legacy, R"({"jsonrpc":"2.0","id":7,"result":{"content":[)", strlen(R"({"jsonrpc":"2.0","id":7,"result":{"content":[)")));
  static_assertPaymentRequiredCopies(legacy, payment_required);
  TEST_ASSERT_NULL(strstr(legacy, "resultType"));
  static_assertEndsWith(legacy, R"("isError":true}})");
  free(legacy);

  char* modern = mcp_buildPaymentRequiredResult("7", payment_required, true);
  TEST_ASSERT_NOT_NULL(modern);
  static_assertPaymentRequiredCopies(modern, payment_required);
  static_assertEndsWith(modern, R"("isError":true,"resultType":"complete"}})");
  free(modern);
}

void test_mcp_buildToolErrorResult_is_the_tool_error_content(void)
{
  char* legacy = mcp_buildToolErrorResult("\"q\"", "wait \"here\"", false);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":"q","result":{"content":[{"type":"text","text":"wait \"here\""}],"isError":true}})", legacy);
  free(legacy);
  char* modern = mcp_buildToolErrorResult("3", "wait", true);
  TEST_ASSERT_EQUAL_STRING(R"({"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"wait"}],"isError":true,"resultType":"complete"}})", modern);
  free(modern);
}

void test_mcp_server_instructions_name_x402_pay_per_call(void)
{
  static_assertEndsWith(MCP_SERVER_INSTRUCTIONS, "A call with no API key and no credits left can pay per call with x402 in USDC on Solana.");
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(402, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

#define TEST_REST_ONLY_MESSAGE "the test run refuses"

static EndpointRunStatus_t static_runUnauthorized(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)conn;
  (void)params;
  (void)json_buf;
  *message_out = TEST_REST_ONLY_MESSAGE;
  return ENDPOINT_RUN_UNAUTHORIZED;
}

static EndpointRunStatus_t static_runGone(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)conn;
  (void)params;
  (void)json_buf;
  *message_out = TEST_REST_ONLY_MESSAGE;
  return ENDPOINT_RUN_GONE;
}

static Endpoint_t static_restOnlyToolRow(const char* tool_name, EndpointRunFunction_t run_function)
{
  Endpoint_t row = {};
  row.mp_httpPath     = "/test_rest_only";
  row.mp_mcpToolName  = tool_name;
  row.m_creditCost    = 0;
  row.m_costRule      = ENDPOINT_COST_FLAT;
  row.m_runFunction   = run_function;
  row.m_jsonCeiling   = JSONBUF_DEFAULT_CEILING;
  return row;
}

static const Endpoint_t TEST_UNAUTHORIZED_TOOL_ROW = static_restOnlyToolRow("test_unauthorized", static_runUnauthorized);
static const Endpoint_t TEST_GONE_TOOL_ROW         = static_restOnlyToolRow("test_gone",         static_runGone);

extern "C" const Endpoint_t* __real_endpoint_findByMcpName(const char* tool_name);
extern "C" const Endpoint_t* __wrap_endpoint_findByMcpName(const char* tool_name);

static Endpoint_t      g_longNameListToolRow;
static EndpointParam_t g_longNameListToolParams[ENDPOINT_MAX_PARAMS];

extern "C" const Endpoint_t* __wrap_endpoint_findByMcpName(const char* tool_name)
{
  if (strcmp(tool_name, "test_long_names") == 0)
    return &g_longNameListToolRow;
  if (strcmp(tool_name, "test_unauthorized") == 0)
    return &TEST_UNAUTHORIZED_TOOL_ROW;
  if (strcmp(tool_name, "test_gone") == 0)
    return &TEST_GONE_TOOL_ROW;
  return __real_endpoint_findByMcpName(tool_name);
}

void test_tools_call_maps_rest_only_run_statuses_to_internal_error(void)
{
  static const char* const bodies[] = {
    "{\"jsonrpc\":\"2.0\",\"id\":91,\"method\":\"tools/call\",\"params\":{\"name\":\"test_unauthorized\",\"arguments\":{}}}",
    "{\"jsonrpc\":\"2.0\",\"id\":92,\"method\":\"tools/call\",\"params\":{\"name\":\"test_gone\",\"arguments\":{}}}",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    int status = 0;
    char* response = static_dispatch(bodies[i], &status);
    static_assertContains(response, "\"Internal error\"");
    TEST_ASSERT_NULL_MESSAGE(strstr(response, TEST_REST_ONLY_MESSAGE), response);
    static_assertToolInternalError(response, status);
  }
}

static void static_fillLongNameListToolRow(void)
{
  const Endpoint_t* base = __real_endpoint_findByMcpName("cve_search");
  TEST_ASSERT_NOT_NULL(base);
  int longest_index = -1;
  for (int i = 0; i < base->m_paramCount; i++)
  {
    if (!(base->mp_params[i].m_sources & ENDPOINT_PARAM_SRC_MCP_ARG))
      continue;
    if (longest_index < 0 || strlen(base->mp_params[i].mp_spec->mp_name) > strlen(base->mp_params[longest_index].mp_spec->mp_name))
      longest_index = i;
  }
  TEST_ASSERT_TRUE(longest_index >= 0);
  TEST_ASSERT_TRUE(ENDPOINT_MAX_PARAMS * (strlen(base->mp_params[longest_index].mp_spec->mp_name) + 2) > ENDPOINT_MESSAGE_BUF_SIZE + sizeof("Invalid params: "));

  for (int i = 0; i < ENDPOINT_MAX_PARAMS; i++)
    g_longNameListToolParams[i] = base->mp_params[longest_index];
  g_longNameListToolRow                = *base;
  g_longNameListToolRow.mp_mcpToolName = "test_long_names";
  g_longNameListToolRow.mp_params      = g_longNameListToolParams;
  g_longNameListToolRow.m_paramCount   = ENDPOINT_MAX_PARAMS;
}

void test_tools_call_unknown_arg_with_a_list_too_long_is_a_fixed_32602(void)
{
  static_fillLongNameListToolRow();
  int status;
  char* response = static_dispatch("{\"jsonrpc\":\"2.0\",\"id\":93,\"method\":\"tools/call\",\"params\":{\"name\":\"test_long_names\",\"arguments\":{\"unknown_name\":1}}}", &status);
  static_assertContains(response, R"("error":{"code":-32602,"message":"Invalid params: unknown argument"})");
  free(response);
}

void test_tools_call_unreadable_name_is_32602(void)
{
  static const char* const bodies[] = {
    "{\"jsonrpc\":\"2.0\",\"id\":90,\"method\":\"tools/call\",\"params\":{\"name\":5,\"arguments\":{}}}",
    "{\"jsonrpc\":\"2.0\",\"id\":90,\"method\":\"tools/call\",\"params\":{\"name\":\"cve_\\ud800ookup\",\"arguments\":{}}}",
    "{\"jsonrpc\":\"2.0\",\"id\":90,\"method\":\"tools/call\",\"params\":{\"name\":\"cve_lookup\\x\",\"arguments\":{}}}",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    int status;
    char* response = static_dispatch(bodies[i], &status);
    static_assertContains(response, "-32602");
    static_assertContains(response, "at most 32 characters");
    free(response);
  }
}
void test_era2026_unreadable_body_name_falls_to_tool_name_limit_32602(void)
{
  static const char* const names[] = { "5", "\"cve_\\ud800ookup\"" };
  for (size_t i = 0; i < 2; i++)
  {
    static_setRoutingHeaders("2026-07-28", "tools/call", "cve_lookup");
    char body[512];
    snprintf(body, sizeof(body),
             "{\"jsonrpc\":\"2.0\",\"id\":72,\"method\":\"tools/call\",\"params\":{" META_2026 ",\"name\":%s,\"arguments\":{}}}", names[i]);
    int status;
    char* response = static_dispatch(body, &status);
    TEST_ASSERT_EQUAL_INT(400, status);
    static_assertContains(response, "\"code\":-32602");
    static_assertContains(response, "at most 32 characters");
    free(response);
  }
}
void test_bulk_tools_skip_an_overlong_id(void)
{
  g_stub_CVELOOKUP_status = DB_OK;
  int status;
  char* response = static_dispatch("{\"jsonrpc\":\"2.0\",\"id\":91,\"method\":\"tools/call\",\"params\":{\"name\":\"cve_lookup_bulk\","
                                   "\"arguments\":{\"cve_ids\":[\"CVE-2021-1234567890123456\"]}}}", &status);
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVELOOKUPBULK_call_count);
  free(response);
  g_stub_CVETRIAGEBULK_status = DB_OK;
  response = static_dispatch("{\"jsonrpc\":\"2.0\",\"id\":92,\"method\":\"tools/call\",\"params\":{\"name\":\"cve_triage_bulk\","
                             "\"arguments\":{\"cve_ids\":[\"CVE-2021-1234567890123456\"]}}}", &status);
  static_assertContains(response, "\\\"skipped\\\":1");
  free(response);
}
void test_bulk_tools_skip_a_malformed_id(void)
{
  g_stub_CVELOOKUP_status = DB_OK;
  int status;
  char* response = static_dispatch("{\"jsonrpc\":\"2.0\",\"id\":94,\"method\":\"tools/call\",\"params\":{\"name\":\"cve_lookup_bulk\","
                                   "\"arguments\":{\"cve_ids\":[\"CVE-2021-44228\",\"not-a-cve\"]}}}", &status);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CVELOOKUPBULK_id_count);
  static_assertContains(response, "\\\"skipped\\\":1");
  free(response);
  g_stub_CVETRIAGEBULK_status = DB_OK;
  response = static_dispatch("{\"jsonrpc\":\"2.0\",\"id\":95,\"method\":\"tools/call\",\"params\":{\"name\":\"cve_triage_bulk\","
                             "\"arguments\":{\"cve_ids\":[\"CVE-2021-44228\",\"not-a-cve\"]}}}", &status);
  static_assertContains(response, "\\\"processed\\\":1,\\\"successful\\\":1,\\\"skipped\\\":1");
  free(response);
}
void test_tool_CWELOOKUP_invalid_format(void)
{
  g_stub_CWELOOKUP_status = DB_OK;
  int status;
  char* response = static_dispatch("{\"jsonrpc\":\"2.0\",\"id\":96,\"method\":\"tools/call\","
                                   "\"params\":{\"name\":\"cwe_lookup\",\"arguments\":{\"cwe_id\":\"not-a-cwe\"}}}", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  static_assertContains(response, "\"text\":\"CWE ID must be CWE-N\"}],\"isError\":true");
  TEST_ASSERT_NULL(strstr(response, "not-a-cwe"));
  free(response);
}
void test_every_arguments_copy_refuses_arguments_too_large(void)
{
  static char pad[PACKAGECHECKBULK_JSON_OBJECT_BUF_SIZE];
  memset(pad, 'a', sizeof(pad));
  const size_t pad_frame_len = strlen(R"({"pad":""})");
  int called = 0;
  for (int i = 0; i < endpoint_count; i++)
  {
    const Endpoint_t* endpoint = &endpoints[i];
    if (endpoint->mp_mcpToolName == NULL)
      continue;

    size_t pad_len = endpoint_jsonObjectSizeLimit(endpoint) - pad_frame_len;
    TEST_ASSERT_TRUE(pad_len <= sizeof(pad));
    static char body[PACKAGECHECKBULK_JSON_OBJECT_BUF_SIZE + 512];
    int written = snprintf(body, sizeof(body), "{\"jsonrpc\":\"2.0\",\"id\":93,\"method\":\"tools/call\",\"params\":{\"name\":\"%s\",\"arguments\":{\"pad\":\"%.*s\"}}}", endpoint->mp_mcpToolName, (int)pad_len, pad);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
    int status;
    char* response = static_dispatch(body, &status);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, R"("code":-32602,"message":"Invalid params: arguments too large"})"), endpoint->mp_mcpToolName);
    free(response);
    called++;
  }
  TEST_ASSERT_EQUAL_INT(37, called);
}

void test_tool_arguments_reach_the_lookup(void)
{
  g_stub_KEVLOOKUP_status       = DB_OK;
  g_stub_CWELOOKUP_status       = DB_OK;
  g_stub_CVERISKSCORE_status    = DB_OK;
  g_stub_PRODUCTEXPOSURE_status = DB_OK;

  int   status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"kev_lookup","arguments":{"cve_id":"CVE-2023-4863"}}})", &status);
  static_assertContains(response, R"(\"cve_id\":\"CVE-2023-4863\")");
  static_assertToolSucceeded(response, status);

  response = static_dispatch(R"({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"cwe_lookup","arguments":{"cwe_id":"CWE-787"}}})", &status);
  static_assertContains(response, R"(\"cwe_id\":\"CWE-787\")");
  static_assertToolSucceeded(response, status);

  response = static_dispatch(R"({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"cve_exploit","arguments":{"cve_id":"CVE-2023-4863"}}})", &status);
  static_assertContains(response, R"(\"cve_id\":\"CVE-2023-4863\")");
  static_assertToolSucceeded(response, status);

  response = static_dispatch(R"({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"cve_risk_score","arguments":{"cve_id":"CVE-2023-4863"}}})", &status);
  TEST_ASSERT_EQUAL_STRING("CVE-2023-4863", g_stub_CVERISKSCORE_last_cve_id);
  static_assertToolSucceeded(response, status);

  response = static_dispatch(R"({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"product_exposure","arguments":{"vendor":"cisco","product":"ios"}}})", &status);
  static_assertContains(response, R"(\"vendor\":\"cisco\",\"product\":\"ios\")");
  static_assertToolSucceeded(response, status);
}

void test_tools_without_a_database_answer_a_malformed_id_first(void)
{
  static const struct { const char* mp_call; const char* mp_text; } cases[] = {
    { R"("params":{"name":"cve_lookup","arguments":{"cve_id":"not-a-cve"}}})",     R"("text":"CVE ID must be CVE-YYYY-NNNN[N...]"}],"isError":true)" },
    { R"("params":{"name":"kev_lookup","arguments":{"cve_id":"not-a-cve"}}})",     R"("text":"CVE ID must be CVE-YYYY-NNNN[N...]"}],"isError":true)" },
    { R"("params":{"name":"cve_risk_score","arguments":{"cve_id":"not-a-cve"}}})", R"("text":"CVE ID must be CVE-YYYY-NNNN[N...]"}],"isError":true)" },
    { R"("params":{"name":"cwe_lookup","arguments":{"cwe_id":"not-a-cwe"}}})",     R"("text":"CWE ID must be CWE-N"}],"isError":true)" },
  };
  g_conn = NULL;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char body[512];
    int  written = snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":%zu,"method":"tools/call",%s)", i + 1, cases[i].mp_call);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
    int   status;
    char* response = static_dispatch(body, &status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, status, cases[i].mp_call);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(response, cases[i].mp_text), cases[i].mp_call);
    free(response);
  }
}

void test_creditCost_early_returns_clear_the_price_flags(void)
{
  const char* bodies[] = { "not json", R"({"jsonrpc":"2.0","id":1,"method":"tools/list"})" };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    EndpointPrice_t price;
    price.m_creditCost             = 7;
    price.m_willCallUpstream       = true;
    price.m_isPartialChargeAllowed = true;
    price.mp_weighedEndpoint       = &endpoints[0];
    mcp_creditCost(bodies[i], &price);
    TEST_ASSERT_EQUAL_UINT(1, price.m_creditCost);
    TEST_ASSERT_FALSE(price.m_willCallUpstream);
    TEST_ASSERT_FALSE(price.m_isPartialChargeAllowed);
    TEST_ASSERT_NULL(price.mp_weighedEndpoint);
  }
}

void test_creditCost_hands_on_only_an_accepted_weighed_call(void)
{
  EndpointPrice_t price;
  memset(&price, 0, sizeof(price));
  price.mp_weighedEndpoint = &endpoints[0];
  mcp_creditCost(R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"package_check_bulk","arguments":{"items":[)"
                R"({"ecosystem":"npm","name":"a","version":"1.0.0"},{"ecosystem":"npm","name":"b","version":"^1.0.0"},)"
                R"({"ecosystem":"npm","name":"c","version":"2.0.0"}]}}})",
                &price);
  TEST_ASSERT_EQUAL_UINT(2, price.m_creditCost);
  TEST_ASSERT_EQUAL_PTR(endpoint_findByMcpName("package_check_bulk"), price.mp_weighedEndpoint);
  TEST_ASSERT_EQUAL_INT(2, price.m_weighedParams.m_packageCheckBulk.m_itemCount);
  TEST_ASSERT_EQUAL_INT(1, price.m_weighedParams.m_packageCheckBulk.m_skippedItemCount);
  TEST_ASSERT_EQUAL_INT(0, price.m_weighedParams.m_packageCheckBulk.m_notProcessedItemCount);

  price.mp_weighedEndpoint = &endpoints[0];
  mcp_creditCost(R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"package_check_bulk","arguments":{"items":[]}}})", &price);
  TEST_ASSERT_EQUAL_UINT(1, price.m_creditCost);
  TEST_ASSERT_NULL(price.mp_weighedEndpoint);

  price.mp_weighedEndpoint = &endpoints[0];
  mcp_creditCost(R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cve_lookup_bulk","arguments":{"cve_ids":["CVE-2021-44228","CVE-2022-0001"]}}})", &price);
  TEST_ASSERT_EQUAL_UINT(2, price.m_creditCost);
  TEST_ASSERT_NULL(price.mp_weighedEndpoint);
}

void test_creditCost_marks_only_a_domain_item_add_of_watchlist_edit_as_upstream(void)
{
  static const struct { const char* mp_arguments; bool m_willCallUpstream; } cases[] = {
    { R"({"action":"add","endpoint":"dns_lookup","domain":"example.com"})",    true  },
    { R"({"action":"add","endpoint":"ssl_check","domain":"example.com"})",     true  },
    { R"({"action":"add","endpoint":"headers_check","domain":"example.com"})", true  },
    { R"({"action":"add","endpoint":"cert_search","domain":"example.com"})",   true  },
    { R"({"action":"add","endpoint":"whois_lookup","domain":"example.com"})",  false },
    { R"({"action":"remove","endpoint":"dns_lookup","domain":"example.com"})", false },
    { R"({"action":"add","endpoint":"cve_lookup","cve_id":"CVE-2021-44228"})", false },
    { R"({})",                                                                 false },
  };
  char body[512];
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    int written = snprintf(body, sizeof(body), R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"watchlist_edit","arguments":%s}})",
                           cases[i].mp_arguments);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(body));
    EndpointPrice_t price;
    memset(&price, 0, sizeof(price));
    price.m_willCallUpstream       = !cases[i].m_willCallUpstream;
    price.m_isPartialChargeAllowed = true;
    mcp_creditCost(body, &price);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(1, price.m_creditCost, cases[i].mp_arguments);
    TEST_ASSERT_EQUAL_MESSAGE(cases[i].m_willCallUpstream, price.m_willCallUpstream, cases[i].mp_arguments);
    TEST_ASSERT_FALSE_MESSAGE(price.m_isPartialChargeAllowed, cases[i].mp_arguments);
  }
}

#define USAGELOG_TEST_INSTANCE_PORT 8002

static char g_usageLines[USAGELOG_DRAIN_BUF_SIZE];

static int static_dispatchForUsageLine(const char* body)
{
  usagelog_start(USAGELOG_TEST_INSTANCE_PORT);
  usagelog_drainLines(g_usageLines, sizeof(g_usageLines));
  usagelog_beginRequest();
  int status;
  char* response = static_dispatch(body, &status);
  free(response);
  usagelog_writeRequest();
  usagelog_drainLines(g_usageLines, sizeof(g_usageLines));
  int line_count = 0;
  for (const char* c = g_usageLines; *c != '\0'; c++)
    line_count += *c == '\n';
  return line_count;
}

static void static_assertUsageLineHas(const char* needle)
{
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, needle), g_usageLines);
}

void test_usage_name_of_a_known_tool_is_its_row(void)
{
  TEST_ASSERT_EQUAL_INT(1, static_dispatchForUsageLine(
    R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cve_lookup","arguments":{"cve_id":"CVE-2021-44228"}}})"));
  static_assertUsageLineHas(R"("endpoint":"cve_lookup","endpoint_exists":true,"tier":"free","status":0,"run_status":"not_found","duration_ms":)");
}

void test_usage_name_of_a_tool_that_fails_the_filter_is_unknown(void)
{
  TEST_ASSERT_EQUAL_INT(1, static_dispatchForUsageLine(
    R"({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x@y.z","arguments":{}}})"));
  static_assertUsageLineHas(R"("endpoint":"unknown","endpoint_exists":false,)");
  TEST_ASSERT_NULL_MESSAGE(strchr(g_usageLines, '@'), g_usageLines);
}

void test_usage_name_of_an_unknown_tool_that_passes_the_filter(void)
{
  TEST_ASSERT_EQUAL_INT(1, static_dispatchForUsageLine(
    R"({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"old_tool","arguments":{}}})"));
  static_assertUsageLineHas(R"("endpoint":"old_tool","endpoint_exists":false,)");
}

void test_usage_name_of_each_answered_method(void)
{
  static const struct { const char* mp_body; const char* mp_name; } cases[] = {
    { R"({"jsonrpc":"2.0","id":4,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}})", R"("endpoint":"initialize","endpoint_exists":true,)" },
    { R"({"jsonrpc":"2.0","id":5,"method":"tools/list"})",                                                            R"("endpoint":"tools/list","endpoint_exists":true,)" },
    { R"({"jsonrpc":"2.0","id":6,"method":"ping"})",                                                                  R"("endpoint":"ping","endpoint_exists":true,)" },
    { R"({"jsonrpc":"2.0","id":7,"method":"tools/call"})",                                                            R"("endpoint":"tools/call","endpoint_exists":true,)" },
    { R"({"jsonrpc":"2.0","method":"notifications/initialized"})",                                                    R"("endpoint":"notifications/initialized","endpoint_exists":true,)" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_dispatchForUsageLine(cases[i].mp_body), cases[i].mp_body);
    static_assertUsageLineHas(cases[i].mp_name);
  }

  static_setRoutingHeaders("2026-07-28", "server/discover", NULL);
  TEST_ASSERT_EQUAL_INT(1, static_dispatchForUsageLine(R"({"jsonrpc":"2.0","id":8,"method":"server/discover",)"
                                                       R"("params":{)" META_2026 "}}"));
  static_assertUsageLineHas(R"("endpoint":"server/discover","endpoint_exists":true,)");
}

void test_usage_name_of_an_unknown_method(void)
{
  TEST_ASSERT_EQUAL_INT(1, static_dispatchForUsageLine(R"({"jsonrpc":"2.0","id":9,"method":"resources/list"})"));
  static_assertUsageLineHas(R"("endpoint":"unknown","endpoint_exists":false,)");

  TEST_ASSERT_EQUAL_INT(1, static_dispatchForUsageLine(R"({"jsonrpc":"2.0","id":10,"method":"foo_bar"})"));
  static_assertUsageLineHas(R"("endpoint":"foo_bar","endpoint_exists":false,)");

  TEST_ASSERT_EQUAL_INT(1, static_dispatchForUsageLine(R"({"jsonrpc":"2.0","id":13,"method":"ping_all"})"));
  static_assertUsageLineHas(R"("endpoint":"ping_all","endpoint_exists":false,)");
}

void test_usage_run_status_of_arguments_the_gate_refuses(void)
{
  TEST_ASSERT_EQUAL_INT(1, static_dispatchForUsageLine(
    R"({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"cve_lookup","arguments":{"cve_id":"not-a-cve"}}})"));
  static_assertUsageLineHas(R"("endpoint":"cve_lookup","endpoint_exists":true,)");
  static_assertUsageLineHas(R"("run_status":"gate_refused",)");
  TEST_ASSERT_EQUAL_INT(0, g_stub_CVELOOKUP_call_count);
}

void test_usage_name_of_a_tool_call_without_a_name_stays_the_method(void)
{
  TEST_ASSERT_EQUAL_INT(1, static_dispatchForUsageLine(
    R"({"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"arguments":{}}})"));
  static_assertUsageLineHas(R"("endpoint":"tools/call","endpoint_exists":true,"tier":"free","status":0,"duration_ms":)");
}

void test_tool_CVESEARCH_offset_cap_is_served_and_one_more_is_refused(void)
{
  g_stub_CVESEARCH_status = DB_OK;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":9101,"method":"tools/call",)"
                     R"("params":{"name":"cve_search","arguments":{"offset":10000}}})", &status);
  static_assertToolSucceeded(response, status);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CVESEARCH_call_count);
  TEST_ASSERT_EQUAL_INT(10000, g_stub_CVESEARCH_last_params.m_offset);

  g_stub_CVESEARCH_call_count = 0;
  response = static_dispatch(R"({"jsonrpc":"2.0","id":9102,"method":"tools/call",)"
               R"("params":{"name":"cve_search","arguments":{"offset":10001}}})", &status);
  static_assertToolRefusedBeforeDb(response, status,
    R"("text":"offset must be an integer between 0 and 10000; narrow the list with filters or a published_after/published_before window"}],"isError":true)",
    g_stub_CVESEARCH_call_count);
}

void test_tool_CVETRIAGE_offset_cap_is_served_and_one_more_is_refused(void)
{
  g_stub_CVETRIAGE_status = DB_OK;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":9103,"method":"tools/call",)"
                     R"("params":{"name":"cve_triage","arguments":{"offset":10000}}})", &status);
  static_assertToolSucceeded(response, status);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CVETRIAGE_call_count);
  TEST_ASSERT_EQUAL_INT(10000, g_stub_CVETRIAGE_last_params.m_offset);

  g_stub_CVETRIAGE_call_count = 0;
  response = static_dispatch(R"({"jsonrpc":"2.0","id":9104,"method":"tools/call",)"
               R"("params":{"name":"cve_triage","arguments":{"offset":10001}}})", &status);
  static_assertToolRefusedBeforeDb(response, status,
    R"("text":"offset must be an integer between 0 and 10000; narrow the list with vendor, product or min_risk_score"}],"isError":true)",
    g_stub_CVETRIAGE_call_count);
}

void test_tool_CPESEARCH_offset_cap_is_served_and_one_more_is_refused(void)
{
  g_stub_CPESEARCH_status = DB_OK;

  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":9105,"method":"tools/call",)"
                     R"("params":{"name":"cpe_search","arguments":{"search":"windows","offset":10000}}})", &status);
  static_assertToolSucceeded(response, status);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CPESEARCH_call_count);
  TEST_ASSERT_EQUAL_INT(10000, g_stub_CPESEARCH_last_params.m_offset);

  g_stub_CPESEARCH_call_count = 0;
  response = static_dispatch(R"({"jsonrpc":"2.0","id":9106,"method":"tools/call",)"
               R"("params":{"name":"cpe_search","arguments":{"search":"windows","offset":10001}}})", &status);
  static_assertToolRefusedBeforeDb(response, status,
    R"("text":"offset must be an integer between 0 and 10000; narrow the list with a longer search text"}],"isError":true)",
    g_stub_CPESEARCH_call_count);
}

void test_tool_offset_cap_leaves_the_other_lists_at_the_int_range(void)
{
  int status;
  char* response = static_dispatch(R"({"jsonrpc":"2.0","id":9107,"method":"tools/call",)"
                     R"("params":{"name":"cve_products","arguments":{"cve_id":"CVE-2021-44228","offset":10001}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_INT(1, g_stub_CVEPRODUCTS_call_count);
  TEST_ASSERT_EQUAL_INT(10001, g_stub_CVEPRODUCTS_last_params.m_offset);
  free(response);

  response = static_dispatch(R"({"jsonrpc":"2.0","id":9108,"method":"tools/call",)"
               R"("params":{"name":"package_check","arguments":{"ecosystem":"npm","name":"lodash","offset":10001}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_INT(1, g_stub_PACKAGECHECK_call_count);
  TEST_ASSERT_EQUAL_INT(10001, g_stub_PACKAGECHECK_last_params.m_offset);
  free(response);

  response = static_dispatch(R"({"jsonrpc":"2.0","id":9109,"method":"tools/call",)"
               R"("params":{"name":"asn_lookup","arguments":{"target":"AS15169","offset":10001}}})", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_INT(1, g_stub_ASNLOOKUP_call_count);
  TEST_ASSERT_EQUAL_INT(10001, g_stub_ASNLOOKUP_last_params.m_offset);
  free(response);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_initialize_echoes_supported_version);
  RUN_TEST(test_initialize_negotiates_latest);
  RUN_TEST(test_initialize_unknown_version_falls_back);
  RUN_TEST(test_initialize_no_version_uses_default);
  RUN_TEST(test_initialize_echoes_only_an_exact_supported_version);
  RUN_TEST(test_server_version_is_one_value_in_initialize_and_health);
  RUN_TEST(test_protocol_version_and_instructions_are_shared_from_mcp_h);
  RUN_TEST(test_tool_count_is_the_number_of_tools_listed);
  RUN_TEST(test_initialize_params_of_any_length_negotiate);
  RUN_TEST(test_initialize_reads_only_a_top_level_protocol_version);
  RUN_TEST(test_tools_list);
  RUN_TEST(test_tools_list_is_the_whole_catalogue);
  RUN_TEST(test_tool_old_argument_names_are_refused);
  RUN_TEST(test_ping);
  RUN_TEST(test_request_without_id_is_202_no_body);
  RUN_TEST(test_unknown_method_is_method_not_found_32601);
  RUN_TEST(test_malformed_json_is_parse_error_32700);
  RUN_TEST(test_tool_CVESEARCH_negative_nan_min_cvss_is_parse_error);
  RUN_TEST(test_body_that_is_not_valid_utf8_is_parse_error_before_any_tool);
  RUN_TEST(test_tool_CVELOOKUP_writes_a_stored_byte_that_is_not_valid_utf8_as_u_fffd);
  RUN_TEST(test_jsonrpc_version_1_0_is_invalid_request_32600);
  RUN_TEST(test_id_outside_the_grammar_is_invalid_request_with_null_id);
  RUN_TEST(test_tool_CVELOOKUP_ok);
  RUN_TEST(test_tool_CVELOOKUP_cve_not_found);
  RUN_TEST(test_tools_answer_not_found_without_the_id);
  RUN_TEST(test_tool_CVELOOKUP_invalid_format);
  RUN_TEST(test_tool_CVELOOKUP_missing_cve_id);
  RUN_TEST(test_tool_CVELOOKUP_no_flags_no_enrich);
  RUN_TEST(test_tool_CVELOOKUP_ghsa_enriches);
  RUN_TEST(test_tool_CVELOOKUP_ransomware_campaign_is_the_stored_value);
  RUN_TEST(test_tool_CVELOOKUP_ransomware_campaign_follows_the_record);
  RUN_TEST(test_tool_CVELOOKUP_ssvc_follows_the_record);
  RUN_TEST(test_tool_CVELOOKUP_ghsa_without_an_advisory_answers_null);
  RUN_TEST(test_tool_CVELOOKUP_flag_false_no_enrich);
  RUN_TEST(test_tool_CVELOOKUP_refuses_unknown_and_repeated_arguments);
  RUN_TEST(test_tool_CVELOOKUP_refuses_a_ghsa_that_is_not_boolean);
  RUN_TEST(test_CVELOOKUP_args_gate_accepts_listed_arguments);
  RUN_TEST(test_CVELOOKUP_args_gate_refuses_everything_else);
  RUN_TEST(test_CVELOOKUP_args_gate_refuses_an_object_too_large_to_buffer);
  RUN_TEST(test_tool_unknown);
  RUN_TEST(test_tool_name_of_the_maximum_length_is_read_whole);
  RUN_TEST(test_tool_retired_names_are_unknown);
  RUN_TEST(test_tools_list_offers_cve_search_not_retired_names);
  RUN_TEST(test_tool_call_missing_params);
  RUN_TEST(test_tool_HEALTH);
  RUN_TEST(test_tool_HEALTH_db_error_is_internal_error);
  RUN_TEST(test_tool_CVELOOKUPBULK_ok);
  RUN_TEST(test_tool_CVELOOKUPBULK_empty);
  RUN_TEST(test_tool_CVELOOKUPBULK_missing_ids);
  RUN_TEST(test_tool_CVELOOKUPBULK_id_of_the_maximum_length_is_looked_up);
  RUN_TEST(test_tool_KEVLOOKUP_ok);
  RUN_TEST(test_tool_CWELOOKUP_ok);
  RUN_TEST(test_tool_CVERISKSCORE_ok);
  RUN_TEST(test_tool_CVESEARCH_db_error);
  RUN_TEST(test_tool_CVESEARCH_bad_severity);
  RUN_TEST(test_tool_CVESEARCH_cwe_id_must_be_a_cwe_id);
  RUN_TEST(test_tool_CVESEARCH_wildcard_vendor_rejected);
  RUN_TEST(test_tool_CVESEARCH_wildcard_product_rejected);
  RUN_TEST(test_tool_CVESEARCH_bad_published_after_rejected);
  RUN_TEST(test_tool_CVESEARCH_bad_published_before_rejected);
  RUN_TEST(test_tool_CVESEARCH_impossible_calendar_date_rejected);
  RUN_TEST(test_tool_CVESEARCH_impossible_calendar_published_before_rejected);
  RUN_TEST(test_tool_CVESEARCH_bad_sort_rejected);
  RUN_TEST(test_tool_CVETRIAGE_wildcard_vendor_rejected);
  RUN_TEST(test_tool_CVETRIAGE_wildcard_product_rejected);
  RUN_TEST(test_tool_CVELEADING_wildcard_vendor_rejected);
  RUN_TEST(test_tool_CVELEADING_wildcard_product_rejected);
  RUN_TEST(test_tool_CVESEARCH_accepted_filters_reach_db_params);
  RUN_TEST(test_tool_CVESEARCH_max_length_vendor_reaches_db_params);
  RUN_TEST(test_tool_CVESEARCH_overlong_cwe_id_never_exceeds_field);
  RUN_TEST(test_tool_CVEEXPLOIT_ok);
  RUN_TEST(test_tool_CVEEXPLOIT_metasploit_unavailable_is_a_result);
  RUN_TEST(test_tool_CVEEXPLOIT_nvd_unavailable_is_a_result);
  RUN_TEST(test_tools_list_includes_triage_tools);
  RUN_TEST(test_tool_CVETRIAGE_ok);
  RUN_TEST(test_tool_CVETRIAGE_db_error);
  RUN_TEST(test_tool_CVETRIAGE_bad_min_risk_score);
  RUN_TEST(test_tool_CVETRIAGEBULK_ok);
  RUN_TEST(test_tool_CVETRIAGEBULK_empty);
  RUN_TEST(test_tool_CVETRIAGEBULK_missing_ids);
  RUN_TEST(test_tool_CVETRIAGEBULK_id_of_the_maximum_length_is_looked_up);
  RUN_TEST(test_tool_CVETRIAGE_min_risk_score_zero_accepted);
  RUN_TEST(test_tool_CVETRIAGE_min_risk_score_hundred_accepted);
  RUN_TEST(test_tool_bulk_too_many_cve_ids_is_a_tool_error);
  RUN_TEST(test_tool_bulk_repeated_id_is_a_tool_error_naming_the_pair);
  RUN_TEST(test_tool_bulk_refuses_unknown_and_repeated_arguments);
  RUN_TEST(test_every_tool_refuses_names_and_values_it_does_not_read);
  RUN_TEST(test_readToolCall_reads_the_name_and_the_arguments);
  RUN_TEST(test_tool_bulk_non_array_cve_ids_is_protocol_error);
  RUN_TEST(test_tool_bulk_without_cve_ids_is_protocol_error);
  RUN_TEST(test_tools_list_triage_schema_details);
  RUN_TEST(test_tools_list_PRODUCTEXPOSURE_included);
  RUN_TEST(test_tool_PRODUCTEXPOSURE_ok);
  RUN_TEST(test_tool_PRODUCTEXPOSURE_passes_the_version);
  RUN_TEST(test_tool_PRODUCTEXPOSURE_version_with_a_space_is_refused);
  RUN_TEST(test_tool_PRODUCTEXPOSURE_passes_include_rejected);
  RUN_TEST(test_tool_PRODUCTEXPOSURE_db_error);
  RUN_TEST(test_tool_PRODUCTEXPOSURE_missing_vendor);
  RUN_TEST(test_tool_PRODUCTEXPOSURE_wildcard_vendor);
  RUN_TEST(test_tool_PRODUCTEXPOSURE_missing_product);
  RUN_TEST(test_tool_PRODUCTEXPOSURE_wildcard_product);
  RUN_TEST(test_tool_CPESEARCH_ok);
  RUN_TEST(test_tool_CPESEARCH_short_query);
  RUN_TEST(test_tool_CVEPRODUCTS_ok);
  RUN_TEST(test_tool_CVEPRODUCTS_not_found);
  RUN_TEST(test_tool_PASSWORDCHECK_found);
  RUN_TEST(test_tool_PASSWORDCHECK_prefix_is_a_tool_error);
  RUN_TEST(test_tool_PASSWORDCHECK_missing_hash_is_32602);
  RUN_TEST(test_tool_PASSWORDCHECK_upstream_error_is_32603);
  RUN_TEST(test_tool_D3FENDFORATTACK_found);
  RUN_TEST(test_tool_D3FENDFORATTACK_lower_case_is_a_tool_error);
  RUN_TEST(test_tool_D3FENDFORATTACK_missing_id_is_32602);
  RUN_TEST(test_tool_D3FENDFORATTACK_db_error_is_32603);
  RUN_TEST(test_tool_DRIVERLOOKUP_found);
  RUN_TEST(test_tool_DRIVERLOOKUP_refused_values_are_tool_errors);
  RUN_TEST(test_tool_DRIVERLOOKUP_missing_hash_is_32602);
  RUN_TEST(test_tool_DRIVERLOOKUP_db_error_is_32603);
  RUN_TEST(test_tool_PACKAGECHECK_found);
  RUN_TEST(test_tool_PACKAGECHECK_refused_values_are_tool_errors);
  RUN_TEST(test_tool_PACKAGECHECK_missing_name_is_32602);
  RUN_TEST(test_tool_PACKAGECHECK_db_error_is_32603);
  RUN_TEST(test_tool_PACKAGECHECKBULK_found);
  RUN_TEST(test_tool_PACKAGECHECKBULK_repeat_missing_and_object_items_are_refused);
  RUN_TEST(test_tool_PACKAGECHECKBULK_db_error_is_32603);
  RUN_TEST(test_tool_DRIVERLOOKUPBULK_found);
  RUN_TEST(test_tool_DRIVERLOOKUPBULK_repeat_and_missing_hashes_are_refused);
  RUN_TEST(test_tool_DRIVERLOOKUPBULK_db_error_is_32603);
  RUN_TEST(test_tool_DNSLOOKUP_answer);
  RUN_TEST(test_tool_DNSLOOKUP_special_use_name_is_a_tool_error);
  RUN_TEST(test_tool_DNSLOOKUP_missing_domain_is_32602);
  RUN_TEST(test_tool_DNSLOOKUP_not_found_and_no_answer);
  RUN_TEST(test_tool_DNSTAKEOVERCHECK_answer);
  RUN_TEST(test_tool_DNSTAKEOVERCHECK_missing_and_refused_domain);
  RUN_TEST(test_tool_DNSTAKEOVERCHECK_not_found_is_a_tool_error);
  RUN_TEST(test_tool_EMAILAUTHCHECK_answer);
  RUN_TEST(test_tool_EMAILAUTHCHECK_missing_domain_and_refused_selector);
  RUN_TEST(test_tool_SSLCHECK_answer);
  RUN_TEST(test_tool_SSLCHECK_missing_and_refused_domain);
  RUN_TEST(test_tool_SSLCHECK_unreachable_target_is_a_tool_error);
  RUN_TEST(test_tool_SSLCHECK_body_buffer_failure_is_32603);
  RUN_TEST(test_tool_HEADERSCHECK_answer);
  RUN_TEST(test_tool_HEADERSCHECK_missing_and_refused_values);
  RUN_TEST(test_tool_HEADERSCHECK_failed_fetches);
  RUN_TEST(test_tool_HEADERSCHECK_body_buffer_failure_is_32603);
  RUN_TEST(test_tool_WHOISLOOKUP_answer);
  RUN_TEST(test_tool_WHOISLOOKUP_missing_and_refused_domain);
  RUN_TEST(test_tool_WHOISLOOKUP_unavailable_answers_and_errors);
  RUN_TEST(test_tool_WHOISLOOKUP_body_buffer_failure_is_32603);
  RUN_TEST(test_tool_WAYBACKLOOKUP_answer);
  RUN_TEST(test_tool_WAYBACKLOOKUP_missing_and_refused_domain);
  RUN_TEST(test_tool_WAYBACKLOOKUP_unavailable_answers_and_errors);
  RUN_TEST(test_tool_WAYBACKLOOKUP_body_buffer_failure_is_32603);
  RUN_TEST(test_tool_CERTSEARCH_answer);
  RUN_TEST(test_tool_CERTSEARCH_missing_and_refused_domain);
  RUN_TEST(test_tool_CERTSEARCH_unavailable_answers_and_errors);
  RUN_TEST(test_tool_CERTSEARCH_body_buffer_failure_is_32603);
  RUN_TEST(test_tool_SUBDOMAINENUM_answer);
  RUN_TEST(test_tool_SUBDOMAINENUM_missing_and_refused_domain);
  RUN_TEST(test_tool_SUBDOMAINENUM_answers_without_certificate_logs_and_errors);
  RUN_TEST(test_tool_SUBDOMAINENUM_body_buffer_failure_is_32603);
  RUN_TEST(test_tool_IPLOOKUP_answer);
  RUN_TEST(test_tool_IPLOOKUP_missing_and_refused_ip_address);
  RUN_TEST(test_tool_IPLOOKUP_db_error_is_32603);
  RUN_TEST(test_tool_EMAILADDRESSCHECK_answer);
  RUN_TEST(test_tool_EMAILADDRESSCHECK_missing_and_refused_values);
  RUN_TEST(test_tool_EMAILADDRESSCHECK_db_error_upstream_error_and_no_domain);
  RUN_TEST(test_tool_ASNLOOKUP_answer);
  RUN_TEST(test_tool_ASNLOOKUP_missing_and_refused_values);
  RUN_TEST(test_tool_ASNLOOKUP_not_found_and_db_error);
  RUN_TEST(test_tool_CVSSCALCULATOR_ok);
  RUN_TEST(test_tool_CVSSCALCULATOR_needs_no_database);
  RUN_TEST(test_tools_without_a_database);
  RUN_TEST(test_tool_arguments_reach_the_lookup);
  RUN_TEST(test_tools_without_a_database_answer_a_malformed_id_first);
  RUN_TEST(test_tool_CVSSCALCULATOR_missing_vector);
  RUN_TEST(test_tool_CVSSCALCULATOR_empty_vector);
  RUN_TEST(test_tool_CVSSCALCULATOR_vector_not_a_string);
  RUN_TEST(test_tool_CVSSCALCULATOR_vector_with_a_unicode_escape_is_read_decoded);
  RUN_TEST(test_tool_CVSSCALCULATOR_refused_vector_reports_its_reason_and_no_echo);
  RUN_TEST(test_tool_CVSSCALCULATOR_leading_tab_is_refused_not_trimmed);
  RUN_TEST(test_tool_CVSSCALCULATOR_trailing_space_is_refused_not_trimmed);
  RUN_TEST(test_tool_CVSSCALCULATOR_each_other_refusal_reports_its_message);
  RUN_TEST(test_tool_CVSSCALCULATOR_vector_as_long_as_the_buffer_is_too_long);
  RUN_TEST(test_tool_CVSSCALCULATOR_vector_one_byte_shorter_reaches_the_parser);
  RUN_TEST(test_tool_CVSSCALCULATOR_arguments_too_large);
  RUN_TEST(test_era2026_no_header_stays_legacy_no_result_type);
  RUN_TEST(test_era2026_handshake_value_stays_legacy_ignores_mcp_method);
  RUN_TEST(test_era2026_missing_meta_is_invalid_params_400);
  RUN_TEST(test_era2026_method_header_mismatch_is_32020_400);
  RUN_TEST(test_era2026_missing_method_header_is_32020_400);
  RUN_TEST(test_era2026_pv_header_envelope_mismatch_is_32020_400);
  RUN_TEST(test_era2026_unsupported_envelope_version_is_32022_with_data);
  RUN_TEST(test_era2026_duplicate_routing_header_is_32020_400);
  RUN_TEST(test_era2026_request_without_id_rejected_400);
  RUN_TEST(test_era2026_tools_list_carries_result_type);
  RUN_TEST(test_era2026_tools_list_is_the_legacy_tools_list);
  RUN_TEST(test_era2026_ping_carries_result_type);
  RUN_TEST(test_era2026_server_discover_ok);
  RUN_TEST(test_era2026_server_discover_legacy_method_not_found);
  RUN_TEST(test_era2026_initialize_is_method_not_found_404);
  RUN_TEST(test_era2026_unknown_method_404);
  RUN_TEST(test_era2026_tools_call_ok_result_type);
  RUN_TEST(test_era2026_tools_call_name_header_mismatch);
  RUN_TEST(test_era2026_tools_call_missing_name_header_mismatch);
  RUN_TEST(test_era2026_parse_error_400);
  RUN_TEST(test_json_that_is_not_an_object_is_invalid_request_32600);
  RUN_TEST(test_era2026_invalid_envelope_is_400);
  RUN_TEST(test_era2026_id_outside_the_grammar_is_400);
  RUN_TEST(test_era2026_all_handshake_versions_stay_legacy);
  RUN_TEST(test_era2026_meta_missing_one_key_is_32602_400);
  RUN_TEST(test_era2026_meta_pv_not_string_is_32602_400);
  RUN_TEST(test_era2026_missing_params_is_32602_400);
  RUN_TEST(test_era2026_unknown_tool_is_32602_400);
  RUN_TEST(test_era2026_tool_run_protocol_error_reaches_the_http_status);
  RUN_TEST(test_era2026_tool_error_stays_200_with_result_type);
  RUN_TEST(test_tool_bulk_serves_the_charged_ids_in_both_eras);
  RUN_TEST(test_runRow_has_no_body_on_not_found_and_db_error);
  RUN_TEST(test_privacy_my_data_shows_the_credit_budget_it_is_handed);
  RUN_TEST(test_privacy_my_data_without_a_credit_budget_is_32603);
  RUN_TEST(test_watchlist_tools_refuse_a_call_without_an_api_key);
  RUN_TEST(test_watchlist_edit_answers_the_list_and_each_db_status);
  RUN_TEST(test_watchlist_edit_sends_a_package_list_and_answers_its_counts);
  RUN_TEST(test_watchlist_edit_names_the_earlier_position_of_a_normalized_repeat);
  RUN_TEST(test_watchlist_edit_answers_every_package_problem_as_a_tool_error);
  RUN_TEST(test_watchlist_edit_answers_a_db_error_when_the_db_accepts_an_element_with_a_problem);
  RUN_TEST(test_watchlist_edit_hands_a_domain_item_its_registered_domain);
  RUN_TEST(test_watchlist_edit_refuses_an_ssl_check_add_of_a_name_dns_does_not_know);
  RUN_TEST(test_watchlist_edit_hands_the_db_only_the_item_of_its_kind);
  RUN_TEST(test_watchlist_edit_hands_the_db_the_action_of_the_request);
  RUN_TEST(test_watchlist_events_answers_the_feed_and_each_db_status);
  RUN_TEST(test_watchlist_tools_refuse_shapes_before_any_query);
  RUN_TEST(test_watchlist_tools_without_a_credit_budget_are_32603);
  RUN_TEST(test_era2026_name_header_with_missing_body_name_is_32602);
  RUN_TEST(test_era2026_oversize_name_falls_to_tool_name_limit_32602);
  RUN_TEST(test_era2026_oversize_protocol_version_is_32602_400);
  RUN_TEST(test_era2026_unsupported_version_data_is_escaped);
  RUN_TEST(test_parse_routing_headers_extracts_all_case_insensitive);
  RUN_TEST(test_parse_routing_headers_ignores_a_name_longer_or_shorter_than_a_routing_name);
  RUN_TEST(test_parse_routing_headers_duplicate_flag_first_wins);
  RUN_TEST(test_parse_routing_headers_absent_all_false);
  RUN_TEST(test_parse_routing_headers_folded_value_flags_duplicated);
  RUN_TEST(test_parse_routing_headers_too_long_version_clamped_to_max_length);
  RUN_TEST(test_parse_routing_headers_too_long_version_leaves_method_flag_set);
  RUN_TEST(test_tool_CVESEARCH_severity_too_long_is_tool_error);
  RUN_TEST(test_tool_CVESEARCH_published_after_too_long_is_tool_error);
  RUN_TEST(test_tool_CVESEARCH_published_before_too_long_is_tool_error);
  RUN_TEST(test_tool_CVESEARCH_vendor_too_long_does_not_silently_drop_filter);
  RUN_TEST(test_tool_CVESEARCH_cwe_id_too_long_is_tool_error);
  RUN_TEST(test_tool_CVESEARCH_sort_too_long_is_tool_error);
  RUN_TEST(test_tool_CVETRIAGE_vendor_too_long_is_tool_error);
  RUN_TEST(test_tool_CVELEADING_product_too_long_is_tool_error);
  RUN_TEST(test_tool_CVESEARCH_severity_exact_max_length_accepted);
  RUN_TEST(test_tool_CVESEARCH_vendor_bad_escape_does_not_silently_drop_filter);
  RUN_TEST(test_tool_CVESEARCH_cwe_id_bad_escape_is_rejected_by_name);
  RUN_TEST(test_tool_CVESEARCH_absent_sort_reaches_db_empty);
  RUN_TEST(test_tool_CVELOOKUP_overlong_id_is_refused_as_rest_refuses_it);
  RUN_TEST(test_tool_CVESEARCH_min_cvss_out_of_double_range_is_tool_error);
  RUN_TEST(test_tool_CVESEARCH_min_cvss_underflow_is_tool_error);
  RUN_TEST(test_tool_CVESEARCH_min_cvss_as_string_is_tool_error);
  RUN_TEST(test_tool_CVESEARCH_min_cvss_as_null_is_tool_error);
  RUN_TEST(test_tool_CVESEARCH_min_cvss_value_reaches_db_params);
  RUN_TEST(test_tool_CVESEARCH_absent_min_cvss_reaches_db_as_not_set_sentinel);
  RUN_TEST(test_tool_CVESEARCH_min_cvss_ceiling_reaches_db_params);
  RUN_TEST(test_tool_CVESEARCH_min_cvss_floor_reaches_db_params);
  RUN_TEST(test_tool_CVESEARCH_min_epss_out_of_double_range_is_tool_error);
  RUN_TEST(test_tool_CVESEARCH_limit_as_string_is_tool_error);
  RUN_TEST(test_tool_CVESEARCH_offset_out_of_long_range_is_tool_error);
  RUN_TEST(test_tool_CVESEARCH_limit_and_offset_reach_db_params);
  RUN_TEST(test_tool_CVESEARCH_vendor_as_null_does_not_silently_drop_filter);
  RUN_TEST(test_tool_CVESEARCH_severity_as_number_does_not_silently_drop_filter);
  RUN_TEST(test_tool_CVESEARCH_sort_as_array_keeps_the_default_out_of_the_answer);
  RUN_TEST(test_tool_CVETRIAGE_min_risk_score_as_string_is_tool_error);
  RUN_TEST(test_tool_CVETRIAGE_min_risk_score_value_reaches_db_params);
  RUN_TEST(test_tool_CVELEADING_min_epss_out_of_double_range_is_tool_error);
  RUN_TEST(test_tool_CVELEADING_min_epss_value_reaches_db_params);
  RUN_TEST(test_tool_CVESEARCH_limit_and_offset_floors_reach_db_params);
  RUN_TEST(test_tool_CVESEARCH_limit_ceiling_reaches_db_params);
  RUN_TEST(test_tool_CVESEARCH_integer_bounds_refuse_one_step_outside);
  RUN_TEST(test_tool_CVESEARCH_min_epss_over_one_is_tool_error);
  RUN_TEST(test_tool_CVELEADING_min_epss_over_one_is_tool_error);
  RUN_TEST(test_tool_CVELEADING_min_epss_one_reaches_db_params);
  RUN_TEST(test_tool_CVELEADING_limit_over_50_is_tool_error);
  RUN_TEST(test_tool_CVELEADING_limit_50_reaches_db_params);
  RUN_TEST(test_tool_CVESEARCH_absent_min_epss_reaches_db_as_not_set_sentinel);
  RUN_TEST(test_tool_CVELEADING_absent_min_epss_reaches_db_as_not_set_sentinel);
  RUN_TEST(test_tool_CVETRIAGE_absent_min_risk_score_reaches_db_as_not_set_sentinel);
  RUN_TEST(test_tool_CVESEARCH_partially_consumed_number_is_tool_error);
  RUN_TEST(test_tool_CVESEARCH_numbers_outside_the_json_grammar_are_tool_errors);
  RUN_TEST(test_tool_CVESEARCH_negative_threshold_is_tool_error);
  RUN_TEST(test_tool_CVETRIAGE_negative_min_risk_score_is_tool_error);
  RUN_TEST(test_tool_CVELEADING_negative_min_epss_is_tool_error);
  RUN_TEST(test_tool_negative_integer_arguments_are_refused_on_every_tool);
  RUN_TEST(test_tool_CVESEARCH_non_boolean_in_kev_is_tool_error);
  RUN_TEST(test_tool_CVESEARCH_non_boolean_known_ransomware_is_tool_error);
  RUN_TEST(test_tool_CVESEARCH_known_ransomware_false_is_tool_error);
  RUN_TEST(test_tool_CVELEADING_known_ransomware_false_is_tool_error);
  RUN_TEST(test_tool_CVELEADING_in_kev_as_string_is_tool_error);
  RUN_TEST(test_tool_CVELEADING_known_ransomware_as_number_is_tool_error);
  RUN_TEST(test_tool_CVESEARCH_in_kev_true_reaches_db_params);
  RUN_TEST(test_tool_CVESEARCH_known_ransomware_true_reaches_db_params);
  RUN_TEST(test_tool_CVELEADING_in_kev_true_reaches_db_params);
  RUN_TEST(test_tool_CVELEADING_known_ransomware_true_reaches_db_params);
  RUN_TEST(test_tool_CVESEARCH_in_kev_false_reaches_db_params_as_not_in_kev);
  RUN_TEST(test_tool_CVELEADING_in_kev_false_reaches_db_params_as_not_in_kev);
  RUN_TEST(test_tool_CVESEARCH_absent_boolean_filters_reach_db_as_not_set);
  RUN_TEST(test_tool_CVELEADING_absent_boolean_filters_reach_db_as_not_set);
  RUN_TEST(test_tools_list_boolean_filter_schemas);
  RUN_TEST(test_tools_list_fits_its_byte_cap);
  RUN_TEST(test_mcp_tool_descriptions_fit_their_byte_cap);
  RUN_TEST(test_tools_list_args_carry_their_spec_bounds);
  RUN_TEST(test_tools_list_bounds_hold_their_literal_values);
  RUN_TEST(test_tools_list_document_carries_no_structural_whitespace);
  RUN_TEST(test_tools_list_open_world_hint_follows_the_upstream_call);
  RUN_TEST(test_tools_list_watchlist_annotations_follow_the_effect);
  RUN_TEST(test_tools_list_meta_names_the_category);
  RUN_TEST(test_tool_call_scalar_arguments_is_protocol_error);
  RUN_TEST(test_tool_call_empty_array_arguments_is_protocol_error);
  RUN_TEST(test_tool_call_array_wrapped_arguments_is_protocol_error);
  RUN_TEST(test_tool_call_array_wrapped_required_argument_is_protocol_error);
  RUN_TEST(test_tool_call_absent_arguments_still_runs_with_defaults);
  RUN_TEST(test_era2026_non_object_arguments_is_400);
  RUN_TEST(test_tool_CVETRIAGE_full_page_past_initial_capacity_is_a_result);
  RUN_TEST(test_tool_CVELOOKUPBULK_body_just_under_ceiling_is_a_result);
  RUN_TEST(test_tool_CVESEARCH_page_past_initial_capacity_is_a_result);
  RUN_TEST(test_tool_CVELEADING_page_past_initial_capacity_is_a_result);
  RUN_TEST(test_tool_CVESEARCH_page_that_cannot_grow_is_internal_error);
  RUN_TEST(test_tool_CVELEADING_page_that_cannot_grow_is_internal_error);
  RUN_TEST(test_tool_CVELOOKUP_record_past_initial_capacity_is_a_result);
  RUN_TEST(test_tool_CVELOOKUP_record_just_under_ceiling_is_a_result);
  RUN_TEST(test_tool_KEVLOOKUP_body_past_initial_capacity_is_a_result);
  RUN_TEST(test_tool_CWELOOKUP_body_past_initial_capacity_is_a_result);
  RUN_TEST(test_tool_CVEEXPLOIT_body_past_initial_capacity_is_a_result);
  RUN_TEST(test_tool_CVELOOKUP_record_over_ceiling_is_internal_error);
  RUN_TEST(test_tool_CVELOOKUPBULK_body_over_ceiling_is_internal_error);
  RUN_TEST(test_tool_KEVLOOKUP_body_over_ceiling_is_internal_error);
  RUN_TEST(test_tool_CWELOOKUP_body_over_ceiling_is_internal_error);
  RUN_TEST(test_tool_CVEEXPLOIT_body_that_cannot_grow_is_internal_error);
  RUN_TEST(test_tool_HEALTH_body_that_cannot_grow_is_internal_error);
  RUN_TEST(test_tool_HEALTH_buffer_that_cannot_be_created_is_internal_error);
  RUN_TEST(test_tools_list_buffer_that_cannot_be_created_fails_the_dispatch);
  RUN_TEST(test_tool_CVELOOKUP_buffer_that_cannot_be_created_is_internal_error);
  RUN_TEST(test_tool_CVELOOKUPBULK_buffer_that_cannot_be_created_is_internal_error);
  RUN_TEST(test_tool_CVESEARCH_buffer_that_cannot_be_created_is_internal_error);
  RUN_TEST(test_tool_CVELEADING_buffer_that_cannot_be_created_is_internal_error);
  RUN_TEST(test_tool_KEVLOOKUP_buffer_that_cannot_be_created_is_internal_error);
  RUN_TEST(test_tool_CWELOOKUP_buffer_that_cannot_be_created_is_internal_error);
  RUN_TEST(test_tool_CVERISKSCORE_buffer_that_cannot_be_created_is_internal_error);
  RUN_TEST(test_tool_CVEEXPLOIT_buffer_that_cannot_be_created_is_internal_error);
  RUN_TEST(test_tool_CVETRIAGE_buffer_that_cannot_be_created_is_internal_error);
  RUN_TEST(test_tool_CVETRIAGEBULK_buffer_that_cannot_be_created_is_internal_error);
  RUN_TEST(test_tool_PRODUCTEXPOSURE_buffer_that_cannot_be_created_is_internal_error);
  RUN_TEST(test_tool_CVSSCALCULATOR_buffer_that_cannot_be_created_is_internal_error);
  RUN_TEST(test_tool_CVETRIAGE_page_that_cannot_grow_is_internal_error);
  RUN_TEST(test_envelope_that_cannot_be_created_fails_dispatch);
  RUN_TEST(test_tool_content_that_cannot_be_created_is_internal_error);
  RUN_TEST(test_tool_DRIVERLOOKUPBULK_body_whose_envelope_passes_the_ceiling_is_internal_error);
  RUN_TEST(test_tool_DRIVERLOOKUPBULK_body_whose_envelope_just_fits_is_a_result);
  RUN_TEST(test_envelope_after_a_first_buffer_that_cannot_be_created_fails_dispatch);
  RUN_TEST(test_malloc_wrapper_fails_only_the_armed_size);
  RUN_TEST(test_tools_call_unknown_arg_with_a_list_too_long_is_a_fixed_32602);
  RUN_TEST(test_tools_call_unreadable_name_is_32602);
  RUN_TEST(test_era2026_unreadable_body_name_falls_to_tool_name_limit_32602);
  RUN_TEST(test_bulk_tools_skip_an_overlong_id);
  RUN_TEST(test_bulk_tools_skip_a_malformed_id);
  RUN_TEST(test_tool_CWELOOKUP_invalid_format);
  RUN_TEST(test_every_arguments_copy_refuses_arguments_too_large);
  RUN_TEST(test_creditCost_early_returns_clear_the_price_flags);
  RUN_TEST(test_creditCost_hands_on_only_an_accepted_weighed_call);
  RUN_TEST(test_creditCost_marks_only_a_domain_item_add_of_watchlist_edit_as_upstream);
  RUN_TEST(test_usage_name_of_a_known_tool_is_its_row);
  RUN_TEST(test_usage_name_of_a_tool_that_fails_the_filter_is_unknown);
  RUN_TEST(test_usage_name_of_an_unknown_tool_that_passes_the_filter);
  RUN_TEST(test_usage_name_of_each_answered_method);
  RUN_TEST(test_usage_name_of_an_unknown_method);
  RUN_TEST(test_usage_run_status_of_arguments_the_gate_refuses);
  RUN_TEST(test_usage_name_of_a_tool_call_without_a_name_stays_the_method);
  RUN_TEST(test_tools_call_maps_rest_only_run_statuses_to_internal_error);
  RUN_TEST(test_mcp_credit_cost_offers_payment_on_a_payable_tool);
  RUN_TEST(test_mcp_credit_cost_offers_no_payment_on_a_non_payable_tool);
  RUN_TEST(test_mcp_credit_cost_offers_no_payment_when_the_gate_refuses);
  RUN_TEST(test_mcp_credit_cost_offers_no_payment_for_tools_list_and_notifications);
  RUN_TEST(test_mcp_credit_cost_payable_tools_are_the_payable_rows);
  RUN_TEST(test_mcp_readPaymentMeta_is_none_without_a_payment_member);
  RUN_TEST(test_mcp_readPaymentMeta_finds_the_member_and_its_exact_span);
  RUN_TEST(test_mcp_readPaymentMeta_is_repeated_for_a_duplicate_or_an_escaped_key);
  RUN_TEST(test_mcp_isModernEra_is_true_only_for_a_modern_version);
  RUN_TEST(test_mcp_tryBuildModernRefusal_is_false_for_the_legacy_era);
  RUN_TEST(test_mcp_tryBuildModernRefusal_refuses_missing_meta_keys);
  RUN_TEST(test_mcp_tryBuildModernRefusal_is_false_when_the_ladder_passes);
  RUN_TEST(test_mcp_tryBuildModernRefusal_refuses_a_notification_and_a_parse_error);
  RUN_TEST(test_mcp_dispatch_run_report_of_a_run_tool);
  RUN_TEST(test_mcp_dispatch_run_report_of_a_protocol_error);
  RUN_TEST(test_mcp_dispatch_run_report_of_a_gate_refusal);
  RUN_TEST(test_mcp_buildResultWithMeta_inserts_the_member);
  RUN_TEST(test_mcp_buildPaymentRequiredResult_has_both_copies);
  RUN_TEST(test_mcp_buildToolErrorResult_is_the_tool_error_content);
  RUN_TEST(test_mcp_server_instructions_name_x402_pay_per_call);
  RUN_TEST(test_tool_CVESEARCH_offset_cap_is_served_and_one_more_is_refused);
  RUN_TEST(test_tool_CVETRIAGE_offset_cap_is_served_and_one_more_is_refused);
  RUN_TEST(test_tool_CPESEARCH_offset_cap_is_served_and_one_more_is_refused);
  RUN_TEST(test_tool_offset_cap_leaves_the_other_lists_at_the_int_range);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
