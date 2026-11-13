#ifndef WATCHLIST_DOMAIN_H
#define WATCHLIST_DOMAIN_H

#include <stdbool.h>
#include <stddef.h>

#include "validate.h"

#define WATCHLIST_DOMAIN_VALUE_MAX_LEN  2048
#define WATCHLIST_DOMAIN_SHA256_HEX_LEN 64

typedef struct {
  char ma_text[WATCHLIST_DOMAIN_VALUE_MAX_LEN + 1];
  int  m_itemCount;
  int  m_keptItemCount;
  char ma_sha256Hex[WATCHLIST_DOMAIN_SHA256_HEX_LEN + 1];
} WatchlistDomainValue_t;

#define WATCHLIST_DOMAIN_EXPIRY_LAST_DAY_DAYS   1
#define WATCHLIST_DOMAIN_EXPIRY_LAST_WEEK_DAYS  7
#define WATCHLIST_DOMAIN_EXPIRY_LAST_MONTH_DAYS 30

typedef struct {
  int          m_maxDays;
  const char*  mp_text;
} WatchlistDomainExpiryBucket_t;

typedef struct {
  const char*  mp_prefix;
  size_t       m_prefixLen;
  const char*  mp_domainName;
  size_t       m_domainNameLen;
} WatchlistDomainLine_t;

#define WATCHLIST_DOMAIN_SCAN_CLAIMED_UNTIL_MAX_LEN 128

typedef struct {
  char  ma_domain[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  char  ma_claimedUntil[WATCHLIST_DOMAIN_SCAN_CLAIMED_UNTIL_MAX_LEN + 1];
} WatchlistDomainScanClaim_t;

bool        watchlist_domain_tryWriteState        (const char* state, WatchlistDomainValue_t* value_out);
const char* watchlist_domain_findExpiryBucket     (const WatchlistDomainExpiryBucket_t* buckets, int bucket_count, int days_remaining);
bool        watchlist_domain_tryWriteLines        (WatchlistDomainLine_t* lines, int line_count, WatchlistDomainValue_t* value_out);
bool        watchlist_domain_tryWriteLinesAsGiven (const WatchlistDomainLine_t* lines, int line_count, WatchlistDomainValue_t* value_out);

#endif
