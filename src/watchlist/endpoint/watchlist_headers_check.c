#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "watchlist_headers_check.h"
#include "watchlist/watchlist_domain.h"
#include "watchlist/watchlist_domain_scan.h"
#include "db.h"
#include "etld.h"
#include "header_check.h"
#include "header_fetch.h"
#include "http.h"
#include "quota.h"
#include "robotstxt.h"
#include "throttle.h"
#include "usagelog.h"
#include "validate.h"

static const QuotaRule_t WATCHLIST_HEADERS_CHECK_DAILY_QUOTA_RULE = { "domain_scan_headers", 86400, 20000 };

static const ThrottleRule_t WATCHLIST_HEADERS_CHECK_THROTTLE_RULE = { "headers_scan", 60, 10 };
#define WATCHLIST_HEADERS_CHECK_THROTTLE_CHARGE_COUNT 2

#define WATCHLIST_HEADERS_CHECK_ROBOTS_TXT_PRODUCT_TOKEN "ContrastAPI"

#define WATCHLIST_HEADERS_CHECK_HOME_PAGE_PATH "/"

static int64_t g_headersCapLineDay = -1;

static bool                         static_isUrlValidAsFirstLine  (const char* url);
static WatchlistDomainScanOutcome_t static_scanHeadersDomain      (PGconn* conn, const WatchlistDomainScanClaim_t* claim);
static void                         static_readSecurityHeaders    (const char* domain, WatchlistDomainScanValue_t* value);
static bool                         static_isHomePageFetchAllowed (const char* domain);
static bool                         static_isStatusInClass        (int http_status, int status_class);

bool watchlist_headers_check_scanNextDomains(PGconn* conn)
{
  const WatchlistDomainScanLane_t lane = {
    .mp_laneName    = DB_DOMAIN_WATCH_LANE_HEADERS,
    .m_scanFunction = static_scanHeadersDomain,
    .mp_capLineDay  = &g_headersCapLineDay,
    .m_capEvent     = USAGELOG_EVENT_HEADERS_SCAN_CAP_REACHED,
  };

  return watchlist_domain_scan_scanNextLaneDomains(conn, &lane);
}

typedef struct {
  HeaderCheckHeader_t  m_header;
  const char*          mp_lineName;
} WATCHLISTHEADERSCHECKSecurityHeader_t;

static const WATCHLISTHEADERSCHECKSecurityHeader_t WATCHLIST_HEADERS_CHECK_SECURITY_HEADERS[] = {
  { HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY,   "content-security-policy"   },
  { HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY, "strict-transport-security" },
  { HEADER_CHECK_HEADER_X_CONTENT_TYPE_OPTIONS,    "x-content-type-options"    },
  { HEADER_CHECK_HEADER_X_FRAME_OPTIONS,           "x-frame-options"           },
  { HEADER_CHECK_HEADER_REFERRER_POLICY,           "referrer-policy"           },
  { HEADER_CHECK_HEADER_PERMISSIONS_POLICY,        "permissions-policy"        },
};

#define WATCHLIST_HEADERS_CHECK_SECURITY_HEADER_COUNT ((int)(sizeof(WATCHLIST_HEADERS_CHECK_SECURITY_HEADERS) / sizeof(WATCHLIST_HEADERS_CHECK_SECURITY_HEADERS[0])))

bool watchlist_headers_check_tryWriteSecurityHeaders(const char* url, const HeaderCheckReport_t* report, WatchlistDomainValue_t* value_out)
{
  assert(report    != NULL);
  assert(value_out != NULL);

  if (url == NULL || !static_isUrlValidAsFirstLine(url))
    return false;

  WatchlistDomainLine_t lines[1 + WATCHLIST_HEADERS_CHECK_SECURITY_HEADER_COUNT];
  int line_count = 0;
  lines[line_count++] = (WatchlistDomainLine_t){ .mp_prefix = url, .m_prefixLen = strlen(url), .mp_domainName = "", .m_domainNameLen = 0 };
  for (int i = 0; i < WATCHLIST_HEADERS_CHECK_SECURITY_HEADER_COUNT; i++)
  {
    const WATCHLISTHEADERSCHECKSecurityHeader_t* header = &WATCHLIST_HEADERS_CHECK_SECURITY_HEADERS[i];
    if (report->ma_findings[header->m_header].m_result == HEADER_CHECK_RESULT_MISSING)
      continue;
    lines[line_count++] = (WatchlistDomainLine_t){ .mp_prefix = header->mp_lineName, .m_prefixLen = strlen(header->mp_lineName), .mp_domainName = "", .m_domainNameLen = 0 };
  }

  WatchlistDomainValue_t value;
  if (!watchlist_domain_tryWriteLinesAsGiven(lines, line_count, &value) || value.m_keptItemCount != value.m_itemCount)
    return false;

  memcpy(value_out, &value, sizeof(*value_out));
  return true;
}

static bool static_isUrlValidAsFirstLine(const char* url)
{
  size_t url_len = strnlen(url, WATCHLIST_DOMAIN_VALUE_MAX_LEN + 1);
  if (url_len == 0 || url_len > WATCHLIST_DOMAIN_VALUE_MAX_LEN)
    return false;
  for (size_t i = 0; i < url_len; i++)
  {
    unsigned char byte = (unsigned char)url[i];
    if (byte < 0x21 || byte > 0x7e)
      return false;
  }
  return true;
}

static WatchlistDomainScanOutcome_t static_scanHeadersDomain(PGconn* conn, const WatchlistDomainScanClaim_t* claim)
{
  DbHeadersScanRecord_t scan = { .mp_domain = claim->ma_domain, .mp_claimedUntil = claim->ma_claimedUntil };
  WatchlistDomainScanValue_t value;
  memset(&value, 0, sizeof(value));

  const char* registered_domain = validate_publicDnsName(claim->ma_domain) ? etld_findPlusOne(claim->ma_domain) : NULL;
  if (registered_domain != NULL)
  {
    unsigned int retry_after_seconds = 0;
    switch (throttle_dbCharge(conn, &WATCHLIST_HEADERS_CHECK_THROTTLE_RULE, registered_domain, WATCHLIST_HEADERS_CHECK_THROTTLE_CHARGE_COUNT, &retry_after_seconds))
    {
      case THROTTLE_CHARGED:
      {
        QuotaStatus_t quota_status = quota_dbReserve(conn, &WATCHLIST_HEADERS_CHECK_DAILY_QUOTA_RULE);
        if (quota_status == QUOTA_EXHAUSTED)
          return WATCHLIST_DOMAIN_SCAN_OUTCOME_QUOTA_EXHAUSTED;
        else if (quota_status != QUOTA_GRANTED)
          return WATCHLIST_DOMAIN_SCAN_OUTCOME_DB_ERROR;

        static_readSecurityHeaders(claim->ma_domain, &value);
        scan.mp_securityHeadersValue = watchlist_domain_scan_valueOrNull(&value);
        break;
      }
      case THROTTLE_REFUSED:
        scan.m_retryAfterSeconds = watchlist_domain_scan_clampDeferSeconds(retry_after_seconds);
        break;
      case THROTTLE_ERROR:
        return WATCHLIST_DOMAIN_SCAN_OUTCOME_DB_ERROR;
    }
  }

  if (db_recordHeadersScan(conn, &scan) != DB_OK)
    return WATCHLIST_DOMAIN_SCAN_OUTCOME_DB_ERROR;
  return WATCHLIST_DOMAIN_SCAN_OUTCOME_RECORDED;
}

static void static_readSecurityHeaders(const char* domain, WatchlistDomainScanValue_t* value)
{
  if (!static_isHomePageFetchAllowed(domain))
    return;

  HeaderFetchResult_t page;
  if (header_fetch_fetchHomePage(domain, &page) != HTTP_ERROR_NONE)
    return;

  if (static_isStatusInClass(page.m_httpStatus, 2) && page.m_capturedHeaderValueCount == HEADER_CHECK_HEADER_COUNT)
  {
    HeaderCheckReport_t report;
    header_check_evaluate(page.mp_capturedHeaderValues, page.m_setCookieCopyCount, &report);
    value->m_hasValue = watchlist_headers_check_tryWriteSecurityHeaders(page.mp_url, &report, &value->m_value);
  }
  header_fetch_resultFree(&page);
}

static bool static_isHomePageFetchAllowed(const char* domain)
{
  HeaderFetchRobotsTxt_t robots_fetch;
  if (header_fetch_fetchRobotsTxt(domain, &robots_fetch) != HTTP_ERROR_NONE)
    return false;

  bool is_allowed = false;
  if (static_isStatusInClass(robots_fetch.m_httpStatus, 2))
  {
    RobotsTxt_t robots;
    if (robotstxt_parse(robots_fetch.mp_body, robots_fetch.m_bodyLen, robots_fetch.m_isBodyCut, WATCHLIST_HEADERS_CHECK_ROBOTS_TXT_PRODUCT_TOKEN, &robots))
    {
      RobotsTxtVerdict_t verdict = robotstxt_checkPath(&robots, robots_fetch.mp_body, WATCHLIST_HEADERS_CHECK_HOME_PAGE_PATH, sizeof(WATCHLIST_HEADERS_CHECK_HOME_PAGE_PATH) - 1);
      is_allowed = verdict.m_decision == ROBOTSTXT_DECISION_ALLOWED;
      robotstxt_free(&robots);
    }
  }
  else if (static_isStatusInClass(robots_fetch.m_httpStatus, 4))
    is_allowed = true;

  header_fetch_robotsTxtFree(&robots_fetch);
  return is_allowed;
}

static bool static_isStatusInClass(int http_status, int status_class)
{
  return http_status >= status_class * 100 && http_status <= status_class * 100 + 99;
}
