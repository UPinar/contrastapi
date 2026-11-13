#ifndef RATELIMIT_H
#define RATELIMIT_H

#include <stdbool.h>
#include <time.h>
#include <libpq-fe.h>
#include "maintenance.h"

#define RL_ANON_CREDIT_LIMIT  30
#define RL_KEY_CREDIT_LIMIT 500
#define RL_WINDOW_SECONDS 3600

#define RL_RETENTION_MAX_SECONDS (RL_WINDOW_SECONDS + MAINTENANCE_INTERVAL_SECONDS)

typedef enum {
  RATELIMIT_ALLOW,
  RATELIMIT_DENY,
  RATELIMIT_ERROR,
} RateLimitStatus_t;

typedef struct {
  unsigned int m_limit;
  int          m_remaining;
  time_t       m_reset;
} RateLimitInfo_t;

RateLimitStatus_t ratelimit_dbCreditBudgetCheck    (PGconn* conn, const char* ip_hash, bool has_api_key, unsigned int credit_cost, bool is_partial_charge_allowed, RateLimitInfo_t* info_out, unsigned int* charged_credit_count_out);
RateLimitStatus_t ratelimit_dbCreditBudgetRemaining(PGconn* conn, const char* ip_hash, bool has_api_key, RateLimitInfo_t* info_out, unsigned int* remaining_credit_count_out);

bool ratelimit_isStartupCreditBudgetProbePassed(PGconn* conn);

#define RL_PURGE_BATCH_ROW_COUNT 10000

bool ratelimit_dbPurgeExpiredCreditBudgetRows(PGconn* conn);

#endif
