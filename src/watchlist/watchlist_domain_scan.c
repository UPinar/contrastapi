#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "watchlist_domain_scan.h"
#include "watchlist/watchlist_domain.h"
#include "db.h"
#include "monotonic.h"
#include "retryafter.h"
#include "usagelog.h"

static bool static_isRunDeadlinePassed(int64_t start_ms);

bool watchlist_domain_scan_scanNextLaneDomains(PGconn* conn, const WatchlistDomainScanLane_t* lane)
{
  int64_t start_ms = monotonic_nowMs();
  for (;;)
  {
    if (static_isRunDeadlinePassed(start_ms))
      return true;

    WatchlistDomainScanClaim_t claims[DB_DOMAIN_SCAN_CLAIM_DOMAIN_COUNT];
    int claim_count = 0;
    if (db_claimDomainLaneScans(conn, lane->mp_laneName, claims, &claim_count) != DB_OK)
      return false;
    if (claim_count == 0)
      return true;

    for (int i = 0; i < claim_count; i++)
    {
      if (static_isRunDeadlinePassed(start_ms))
        return true;

      WatchlistDomainScanOutcome_t outcome = lane->m_scanFunction(conn, &claims[i]);
      if (outcome == WATCHLIST_DOMAIN_SCAN_OUTCOME_QUOTA_EXHAUSTED)
      {
        usagelog_writeEventOncePerDay(lane->m_capEvent);
        return true;
      }
      else if (outcome == WATCHLIST_DOMAIN_SCAN_OUTCOME_DB_ERROR)
        return false;
    }
  }
}

unsigned int watchlist_domain_scan_clampDeferSeconds(unsigned int retry_after_seconds)
{
  if (retry_after_seconds < RETRYAFTER_MIN_SECONDS)
    return RETRYAFTER_MIN_SECONDS;
  if (retry_after_seconds > RETRYAFTER_MAX_SECONDS)
    return RETRYAFTER_MAX_SECONDS;
  return retry_after_seconds;
}

const WatchlistDomainValue_t* watchlist_domain_scan_valueOrNull(const WatchlistDomainScanValue_t* value)
{
  return value->m_hasValue ? &value->m_value : NULL;
}

static bool static_isRunDeadlinePassed(int64_t start_ms)
{
  return monotonic_nowMs() - start_ms >= WATCHLIST_DOMAIN_SCAN_RUN_DEADLINE_MS;
}
