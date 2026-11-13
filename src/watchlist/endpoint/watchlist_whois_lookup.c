#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "watchlist_whois_lookup.h"
#include "watchlist/watchlist_domain.h"
#include "watchlist/watchlist_domain_scan.h"
#include "datetime.h"
#include "db.h"
#include "external/rdap.h"
#include "macro.h"
#include "quota.h"
#include "registryask.h"
#include "usagelog.h"
#include "utf8.h"

static const QuotaRule_t WATCHLIST_WHOIS_LOOKUP_DAILY_QUOTA_RULE = { "domain_scan_rdap_whois", 86400, 10000 };

static int64_t g_rdapWhoisCapLineDay = -1;

typedef struct {
  WatchlistDomainScanValue_t m_registrationExpiryValue;
  WatchlistDomainScanValue_t m_registrarValue;
  WatchlistDomainScanValue_t m_transferLockValue;
  WatchlistDomainScanValue_t m_dnssecDelegationValue;
} WATCHLISTWHOISLOOKUPScanValues_t;

static bool                         static_isRegistrarNameWritable (const char* name);
static WatchlistDomainScanOutcome_t static_scanRdapWhoisDomain     (PGconn* conn, const WatchlistDomainScanClaim_t* claim);
static void                         static_readRdapWhoisValues     (const RdapRegistration_t* registration, WATCHLISTWHOISLOOKUPScanValues_t* values);

bool watchlist_whois_lookup_scanNextDomains(PGconn* conn)
{
  const WatchlistDomainScanLane_t lane = {
    .mp_laneName    = DB_DOMAIN_WATCH_LANE_RDAP_WHOIS,
    .m_scanFunction = static_scanRdapWhoisDomain,
    .mp_capLineDay  = &g_rdapWhoisCapLineDay,
    .m_capEvent     = USAGELOG_EVENT_RDAP_WHOIS_SCAN_CAP_REACHED,
  };

  return watchlist_domain_scan_scanNextLaneDomains(conn, &lane);
}

#define WATCHLIST_WHOIS_LOOKUP_REGISTRATION_EXPIRY_MAX_LEN (4 + 1 + RDAP_DATE_MAX_LEN)
#define WATCHLIST_WHOIS_LOOKUP_REGISTRAR_MAX_LEN           (19 + 1 + RDAP_REGISTRAR_NAME_MAX_LEN)
#define WATCHLIST_WHOIS_LOOKUP_TRANSFER_LOCK_MAX_LEN       (26 + 1 + 26)

_Static_assert(WATCHLIST_WHOIS_LOOKUP_REGISTRATION_EXPIRY_MAX_LEN < WATCHLIST_DOMAIN_VALUE_MAX_LEN, "a registration_expiry text is never cut");
_Static_assert(WATCHLIST_WHOIS_LOOKUP_REGISTRAR_MAX_LEN < WATCHLIST_DOMAIN_VALUE_MAX_LEN, "a registrar text is never cut");
_Static_assert(WATCHLIST_WHOIS_LOOKUP_TRANSFER_LOCK_MAX_LEN < WATCHLIST_DOMAIN_VALUE_MAX_LEN, "a transfer_lock text is never cut");

static const WatchlistDomainExpiryBucket_t WATCHLIST_WHOIS_LOOKUP_REGISTRATION_EXPIRY_BUCKETS[] = {
  { WATCHLIST_DOMAIN_EXPIRY_LAST_DAY_DAYS,   MACRO_STR(WATCHLIST_DOMAIN_EXPIRY_LAST_DAY_DAYS)   },
  { WATCHLIST_DOMAIN_EXPIRY_LAST_WEEK_DAYS,  MACRO_STR(WATCHLIST_DOMAIN_EXPIRY_LAST_WEEK_DAYS)  },
  { WATCHLIST_DOMAIN_EXPIRY_LAST_MONTH_DAYS, MACRO_STR(WATCHLIST_DOMAIN_EXPIRY_LAST_MONTH_DAYS) },
};

typedef struct {
  const char*  mp_rdapForm;
  const char*  mp_eppForm;
} WATCHLISTWHOISLOOKUPTransferLock_t;

static const WATCHLISTWHOISLOOKUPTransferLock_t WATCHLIST_WHOIS_LOOKUP_TRANSFER_LOCKS[] = {
  { "client transfer prohibited", "clienttransferprohibited" },
  { "server transfer prohibited", "servertransferprohibited" },
};

#define WATCHLIST_WHOIS_LOOKUP_TRANSFER_LOCK_COUNT ((int)(sizeof(WATCHLIST_WHOIS_LOOKUP_TRANSFER_LOCKS) / sizeof(WATCHLIST_WHOIS_LOOKUP_TRANSFER_LOCKS[0])))

#define WATCHLIST_WHOIS_LOOKUP_IANA_ID_SIZE 21

bool watchlist_whois_lookup_tryWriteRegistrationExpiry(const RdapRegistration_t* registration, int64_t now_epoch, WatchlistDomainValue_t* value_out)
{
  assert(registration != NULL);
  assert(value_out    != NULL);

  const char* expires_at     = registration->ma_expiresAt;
  size_t      expires_at_len = strnlen(expires_at, RDAP_DATE_MAX_LEN + 1);
  int64_t     expiry_epoch   = 0;
  if (expires_at_len == 0)
    return false;
  if (!datetime_tryReadDateTime(expires_at, expires_at + expires_at_len, &expiry_epoch) && !datetime_tryReadFullDate(expires_at, expires_at + expires_at_len, &expiry_epoch))
    return false;

  int         days_remaining = datetime_daysUntil(expiry_epoch, now_epoch);
  const char* bucket         = watchlist_domain_findExpiryBucket(WATCHLIST_WHOIS_LOOKUP_REGISTRATION_EXPIRY_BUCKETS, (int)(sizeof(WATCHLIST_WHOIS_LOOKUP_REGISTRATION_EXPIRY_BUCKETS) / sizeof(WATCHLIST_WHOIS_LOOKUP_REGISTRATION_EXPIRY_BUCKETS[0])), days_remaining);

  const WatchlistDomainLine_t lines[2] = {
    { bucket,     strlen(bucket), "", 0 },
    { expires_at, expires_at_len, "", 0 },
  };
  return watchlist_domain_tryWriteLinesAsGiven(lines, 2, value_out);
}

bool watchlist_whois_lookup_tryWriteRegistrar(const RdapRegistration_t* registration, WatchlistDomainValue_t* value_out)
{
  assert(registration != NULL);
  assert(value_out    != NULL);

  const char* name = registration->ma_registrarName;
  if (name[0] == '\0' && registration->m_registrarIanaId < 0)
    return false;
  if (!static_isRegistrarNameWritable(name))
    return false;

  char iana_id[WATCHLIST_WHOIS_LOOKUP_IANA_ID_SIZE] = "-";
  if (registration->m_registrarIanaId >= 0)
    snprintf(iana_id, sizeof(iana_id), "%ld", registration->m_registrarIanaId);

  const WatchlistDomainLine_t lines[2] = {
    { iana_id, strlen(iana_id), "", 0 },
    { name,    strlen(name),    "", 0 },
  };
  return watchlist_domain_tryWriteLinesAsGiven(lines, 2, value_out);
}

bool watchlist_whois_lookup_tryWriteTransferLock(const RdapRegistration_t* registration, WatchlistDomainValue_t* value_out)
{
  assert(registration != NULL);
  assert(value_out    != NULL);

  if (registration->m_statusCount <= 0 || registration->m_statusCount > RDAP_STATUS_MAX_COUNT)
    return false;

  bool is_lock_found[WATCHLIST_WHOIS_LOOKUP_TRANSFER_LOCK_COUNT] = { false };
  for (int i = 0; i < registration->m_statusCount; i++)
  {
    const char* status = registration->ma_statuses[i];
    for (int lock = 0; lock < WATCHLIST_WHOIS_LOOKUP_TRANSFER_LOCK_COUNT; lock++)
    {
      if (strcasecmp(status, WATCHLIST_WHOIS_LOOKUP_TRANSFER_LOCKS[lock].mp_rdapForm) == 0 || strcasecmp(status, WATCHLIST_WHOIS_LOOKUP_TRANSFER_LOCKS[lock].mp_eppForm) == 0)
        is_lock_found[lock] = true;
    }
  }

  WatchlistDomainLine_t lines[WATCHLIST_WHOIS_LOOKUP_TRANSFER_LOCK_COUNT];
  int line_count = 0;
  for (int lock = 0; lock < WATCHLIST_WHOIS_LOOKUP_TRANSFER_LOCK_COUNT; lock++)
  {
    if (!is_lock_found[lock])
      continue;
    const char* rdap_form = WATCHLIST_WHOIS_LOOKUP_TRANSFER_LOCKS[lock].mp_rdapForm;
    lines[line_count] = (WatchlistDomainLine_t){ .mp_prefix = rdap_form, .m_prefixLen = strlen(rdap_form), .mp_domainName = "", .m_domainNameLen = 0 };
    line_count++;
  }
  return watchlist_domain_tryWriteLinesAsGiven(lines, line_count, value_out);
}

bool watchlist_whois_lookup_tryWriteDnssecDelegation(const RdapRegistration_t* registration, WatchlistDomainValue_t* value_out)
{
  assert(registration != NULL);
  assert(value_out    != NULL);

  if (registration->m_delegationSigned == RDAP_DELEGATION_SIGNED_YES)
    return watchlist_domain_tryWriteState("signed", value_out);
  else if (registration->m_delegationSigned == RDAP_DELEGATION_SIGNED_NO)
    return watchlist_domain_tryWriteState("unsigned", value_out);
  return false;
}

static bool static_isRegistrarNameWritable(const char* name)
{
  size_t name_len = strlen(name);
  for (size_t i = 0; i < name_len; i++)
  {
    unsigned char byte = (unsigned char)name[i];
    if (byte < 0x20 || byte == 0x7f)
      return false;
  }
  return utf8_isTextValid(name, name_len);
}

static WatchlistDomainScanOutcome_t static_scanRdapWhoisDomain(PGconn* conn, const WatchlistDomainScanClaim_t* claim)
{
  DbRdapWhoisScanRecord_t scan = { .mp_domain = claim->ma_domain, .mp_claimedUntil = claim->ma_claimedUntil };
  WATCHLISTWHOISLOOKUPScanValues_t values;
  memset(&values, 0, sizeof(values));

  RegistryAskServer_t server;
  if (registryask_tryFindServer(claim->ma_domain, &server))
  {
    RdapRegistration_t registration;
    memset(&registration, 0, sizeof(registration));
    unsigned int retry_after_seconds = 0;
    RegistryAskStatus_t ask_status = registryask_askDomain(conn, &registryask_watchlistScanThrottleRules, &WATCHLIST_WHOIS_LOOKUP_DAILY_QUOTA_RULE, &server, claim->ma_domain, &registration, &retry_after_seconds);
    switch (ask_status)
    {
      case REGISTRYASK_OK:
        static_readRdapWhoisValues(&registration, &values);
        scan.mp_registrationExpiryValue = watchlist_domain_scan_valueOrNull(&values.m_registrationExpiryValue);
        scan.mp_registrarValue          = watchlist_domain_scan_valueOrNull(&values.m_registrarValue);
        scan.mp_transferLockValue       = watchlist_domain_scan_valueOrNull(&values.m_transferLockValue);
        scan.mp_dnssecDelegationValue   = watchlist_domain_scan_valueOrNull(&values.m_dnssecDelegationValue);
        break;
      case REGISTRYASK_UNAVAILABLE:
        scan.m_retryAfterSeconds = watchlist_domain_scan_clampDeferSeconds(retry_after_seconds);
        break;
      case REGISTRYASK_NOT_REGISTERED:
      case REGISTRYASK_INVALID_NAME:
      case REGISTRYASK_UPSTREAM_ERROR:
        break;
      case REGISTRYASK_DAILY_QUOTA_EXHAUSTED:
        return WATCHLIST_DOMAIN_SCAN_OUTCOME_QUOTA_EXHAUSTED;
      case REGISTRYASK_DB_ERROR:
        return WATCHLIST_DOMAIN_SCAN_OUTCOME_DB_ERROR;
    }
  }

  if (db_recordRdapWhoisScan(conn, &scan) != DB_OK)
    return WATCHLIST_DOMAIN_SCAN_OUTCOME_DB_ERROR;
  return WATCHLIST_DOMAIN_SCAN_OUTCOME_RECORDED;
}

static void static_readRdapWhoisValues(const RdapRegistration_t* registration, WATCHLISTWHOISLOOKUPScanValues_t* values)
{
  int64_t now_epoch = (int64_t)time(NULL);
  values->m_registrationExpiryValue.m_hasValue = watchlist_whois_lookup_tryWriteRegistrationExpiry(registration, now_epoch, &values->m_registrationExpiryValue.m_value);
  values->m_registrarValue.m_hasValue          = watchlist_whois_lookup_tryWriteRegistrar(registration, &values->m_registrarValue.m_value);
  values->m_transferLockValue.m_hasValue       = watchlist_whois_lookup_tryWriteTransferLock(registration, &values->m_transferLockValue.m_value);
  values->m_dnssecDelegationValue.m_hasValue   = watchlist_whois_lookup_tryWriteDnssecDelegation(registration, &values->m_dnssecDelegationValue.m_value);
}
