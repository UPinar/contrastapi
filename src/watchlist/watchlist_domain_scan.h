#ifndef WATCHLIST_DOMAIN_SCAN_H
#define WATCHLIST_DOMAIN_SCAN_H

#include <stdbool.h>
#include <stdint.h>
#include <libpq-fe.h>

#include "usagelog.h"
#include "watchlist_domain.h"

#define WATCHLIST_DOMAIN_SCAN_RUN_DEADLINE_MS 30000

#define WATCHLIST_DOMAIN_SCAN_INTERVAL_SECONDS 60

typedef enum {
  WATCHLIST_DOMAIN_SCAN_OUTCOME_RECORDED = 0,
  WATCHLIST_DOMAIN_SCAN_OUTCOME_QUOTA_EXHAUSTED,
  WATCHLIST_DOMAIN_SCAN_OUTCOME_DB_ERROR,
} WatchlistDomainScanOutcome_t;

typedef struct {
  WatchlistDomainValue_t m_value;
  bool                   m_hasValue;
} WatchlistDomainScanValue_t;

typedef WatchlistDomainScanOutcome_t (*WatchlistDomainScanLaneScanFunction_t)(PGconn* conn, const WatchlistDomainScanClaim_t* claim);

typedef struct {
  const char*                           mp_laneName;
  WatchlistDomainScanLaneScanFunction_t m_scanFunction;
  int64_t*                              mp_capLineDay;
  UsageLogEvent_t                       m_capEvent;
} WatchlistDomainScanLane_t;

bool                          watchlist_domain_scan_scanNextLaneDomains (PGconn* conn, const WatchlistDomainScanLane_t* lane);
unsigned int                  watchlist_domain_scan_clampDeferSeconds   (unsigned int retry_after_seconds);
const WatchlistDomainValue_t* watchlist_domain_scan_valueOrNull         (const WatchlistDomainScanValue_t* value);

#endif
