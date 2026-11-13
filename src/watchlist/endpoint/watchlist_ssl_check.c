#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "watchlist_ssl_check.h"
#include "watchlist/watchlist_domain.h"
#include "watchlist/watchlist_domain_scan.h"
#include "db.h"
#include "macro.h"
#include "quota.h"
#include "tlsprobe.h"
#include "usagelog.h"

static const QuotaRule_t WATCHLIST_SSL_CHECK_DAILY_QUOTA_RULE = { "domain_scan_tls", 86400, 20000 };

static int64_t g_tlsCapLineDay = -1;

typedef struct {
  WatchlistDomainScanValue_t m_certificateExpiryValue;
  WatchlistDomainScanValue_t m_certificateValidityValue;
  WatchlistDomainScanValue_t m_certificateListingValue;
  WatchlistDomainScanValue_t m_tlsProtocolValue;
} WATCHLISTSSLCHECKScanValues_t;

static WatchlistDomainScanOutcome_t static_scanTlsDomain (PGconn* conn, const WatchlistDomainScanClaim_t* claim);
static void                         static_readTlsValues (PGconn* conn, const char* domain, WATCHLISTSSLCHECKScanValues_t* values);

bool watchlist_ssl_check_scanNextDomains(PGconn* conn)
{
  const WatchlistDomainScanLane_t lane = {
    .mp_laneName    = DB_DOMAIN_WATCH_LANE_TLS,
    .m_scanFunction = static_scanTlsDomain,
    .mp_capLineDay  = &g_tlsCapLineDay,
    .m_capEvent     = USAGELOG_EVENT_TLS_SCAN_CAP_REACHED,
  };

  return watchlist_domain_scan_scanNextLaneDomains(conn, &lane);
}

static const WatchlistDomainExpiryBucket_t WATCHLIST_SSL_CHECK_CERTIFICATE_EXPIRY_BUCKETS[] = {
  { WATCHLIST_DOMAIN_EXPIRY_LAST_DAY_DAYS,  MACRO_STR(WATCHLIST_DOMAIN_EXPIRY_LAST_DAY_DAYS)  },
  { WATCHLIST_DOMAIN_EXPIRY_LAST_WEEK_DAYS, MACRO_STR(WATCHLIST_DOMAIN_EXPIRY_LAST_WEEK_DAYS) },
};

bool watchlist_ssl_check_tryWriteCertificateExpiry(const TlsProbeResult_t* result, WatchlistDomainValue_t* value_out)
{
  assert(result    != NULL);
  assert(value_out != NULL);

  const char* valid_until = result->m_serverCertificate.ma_validUntil;
  if (valid_until[0] == '\0')
    return false;

  const char* bucket = watchlist_domain_findExpiryBucket( WATCHLIST_SSL_CHECK_CERTIFICATE_EXPIRY_BUCKETS,
                                                          (int)(sizeof(WATCHLIST_SSL_CHECK_CERTIFICATE_EXPIRY_BUCKETS) / sizeof(WATCHLIST_SSL_CHECK_CERTIFICATE_EXPIRY_BUCKETS[0])),
                                                          result->m_daysRemaining);

  const WatchlistDomainLine_t lines[2] = {
    { bucket,      strlen(bucket),      "", 0 },
    { valid_until, strlen(valid_until), "", 0 },
  };
  return watchlist_domain_tryWriteLinesAsGiven(lines, 2, value_out);
}

bool watchlist_ssl_check_tryWriteCertificateValidity(const TlsProbeResult_t* result, WatchlistDomainValue_t* value_out)
{
  assert(result    != NULL);
  assert(value_out != NULL);

  WatchlistDomainLine_t lines[TLSPROBE_PROBLEM_NAME_COUNT];
  int line_count = 0;
  for (int i = 0; i < TLSPROBE_PROBLEM_NAME_COUNT; i++)
  {
    if ((result->m_problems & tlsprobe_problemNames[i].m_bit) == 0)
      continue;
    const char* name = tlsprobe_problemNames[i].mp_name;
    lines[line_count] = (WatchlistDomainLine_t){ .mp_prefix = name, .m_prefixLen = strlen(name), .mp_domainName = "", .m_domainNameLen = 0 };
    line_count++;
  }

  if (line_count == 0)
    return watchlist_domain_tryWriteState("valid", value_out);
  return watchlist_domain_tryWriteLinesAsGiven(lines, line_count, value_out);
}

bool watchlist_ssl_check_tryWriteCertificateListing(const SSLCHECKRecord_t* record, WatchlistDomainValue_t* value_out)
{
  assert(record    != NULL);
  assert(value_out != NULL);

  if (record->m_isBlacklistUnavailable || !record->m_isBlacklistFeedLoaded)
    return false;
  if (record->ma_blacklistListingReason[0] == '\0')
    return watchlist_domain_tryWriteState("not_listed", value_out);

  const char* reason = record->ma_blacklistListingReason;
  const WatchlistDomainLine_t lines[2] = {
    { "listed", strlen("listed"), "", 0 },
    { reason,   strlen(reason),   "", 0 },
  };
  return watchlist_domain_tryWriteLinesAsGiven(lines, 2, value_out);
}

bool watchlist_ssl_check_tryWriteTlsProtocol(const TlsProbeResult_t* result, WatchlistDomainValue_t* value_out)
{
  assert(result    != NULL);
  assert(value_out != NULL);

  if (result->ma_protocol[0] == '\0')
    return false;
  return watchlist_domain_tryWriteState(result->ma_protocol, value_out);
}

static WatchlistDomainScanOutcome_t static_scanTlsDomain(PGconn* conn, const WatchlistDomainScanClaim_t* claim)
{
  QuotaStatus_t quota_status = quota_dbReserve(conn, &WATCHLIST_SSL_CHECK_DAILY_QUOTA_RULE);
  if (quota_status == QUOTA_EXHAUSTED)
    return WATCHLIST_DOMAIN_SCAN_OUTCOME_QUOTA_EXHAUSTED;
  else if (quota_status != QUOTA_GRANTED)
    return WATCHLIST_DOMAIN_SCAN_OUTCOME_DB_ERROR;

  WATCHLISTSSLCHECKScanValues_t values;
  static_readTlsValues(conn, claim->ma_domain, &values);

  const DbTlsScanRecord_t scan = {
    .mp_domain                   = claim->ma_domain,
    .mp_claimedUntil             = claim->ma_claimedUntil,
    .mp_certificateExpiryValue   = watchlist_domain_scan_valueOrNull(&values.m_certificateExpiryValue),
    .mp_certificateValidityValue = watchlist_domain_scan_valueOrNull(&values.m_certificateValidityValue),
    .mp_certificateListingValue  = watchlist_domain_scan_valueOrNull(&values.m_certificateListingValue),
    .mp_tlsProtocolValue         = watchlist_domain_scan_valueOrNull(&values.m_tlsProtocolValue),
  };

  if (db_recordTlsScan(conn, &scan) != DB_OK)
    return WATCHLIST_DOMAIN_SCAN_OUTCOME_DB_ERROR;
  return WATCHLIST_DOMAIN_SCAN_OUTCOME_RECORDED;
}

static void static_readTlsValues(PGconn* conn, const char* domain, WATCHLISTSSLCHECKScanValues_t* values)
{
  memset(values, 0, sizeof(*values));

  SSLCHECKRecord_t record;
  memset(&record, 0, sizeof(record));
  if (tlsprobe_probeHost(domain, &record.m_result) != TLSPROBE_OK)
    return;

  values->m_certificateExpiryValue.m_hasValue   = watchlist_ssl_check_tryWriteCertificateExpiry(&record.m_result, &values->m_certificateExpiryValue.m_value);
  values->m_certificateValidityValue.m_hasValue = watchlist_ssl_check_tryWriteCertificateValidity(&record.m_result, &values->m_certificateValidityValue.m_value);
  values->m_tlsProtocolValue.m_hasValue         = watchlist_ssl_check_tryWriteTlsProtocol(&record.m_result, &values->m_tlsProtocolValue.m_value);

  record.m_isBlacklistUnavailable = db_SSLCHECK(conn, record.m_result.m_serverCertificate.ma_sha1Hex, &record) != DB_OK;
  values->m_certificateListingValue.m_hasValue  = watchlist_ssl_check_tryWriteCertificateListing(&record, &values->m_certificateListingValue.m_value);
}
