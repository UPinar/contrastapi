#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dbhelper.h"
#include "ratelimit.h"

#define RL_CREDIT_COST_STR_BUF_SIZE    8
#define RL_CREDIT_LIMIT_STR_BUF_SIZE  16

#define RL_PROBE_BUCKET         "startup-probe"

#define RL_CHARGE_ATTEMPT_COUNT  2

#define RATELIMIT_USED_COLUMNS(X)                           \
  X(RATELIMIT_USED_COLUMN_CREDIT_COUNT,   "credit_count")   \
  X(RATELIMIT_USED_COLUMN_WINDOW_EXPIRED, "window_expired")
enum { RATELIMIT_USED_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const RATELIMIT_USED_COLUMN_NAMES[] = { RATELIMIT_USED_COLUMNS(DBHELPER_COLUMN_NAME) };

#define RATELIMIT_CHARGE_COLUMNS(X)                     \
  X(RATELIMIT_CHARGE_COLUMN_CREDIT_COUNT, "credit_count")
enum { RATELIMIT_CHARGE_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const RATELIMIT_CHARGE_COLUMN_NAMES[] = { RATELIMIT_CHARGE_COLUMNS(DBHELPER_COLUMN_NAME) };

static bool static_readUsedCreditCount (PGconn* conn, const char* ip_hash, const char* has_api_key_str, unsigned int* used_credit_count_out);
static void static_fillRateLimitInfo   (RateLimitInfo_t* info_out, unsigned int credit_limit, int remaining_credit_count);
static bool static_beginTransaction    (PGconn* conn);
static bool static_rollbackTransaction (PGconn* conn);

static int static_computeRemainingCreditCount(unsigned int credit_limit, unsigned int used_credit_count)
{
  return (used_credit_count < credit_limit) ? (int)(credit_limit - used_credit_count) : 0;
}

static bool static_readUsedCreditCount(PGconn* conn, const char* ip_hash, const char* has_api_key_str, unsigned int* used_credit_count_out)
{
  *used_credit_count_out = 0;

  const char* param_values[] = { ip_hash, has_api_key_str };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_credit_budget_used($1, $2)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return false;

  if (!dbhelper_isColumnListEqual(res, RATELIMIT_USED_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(RATELIMIT_USED_COLUMN_NAMES)))
  {
    PQclear(res);
    return false;
  }

  if (PQntuples(res) > 0)
  {
    int window_expired = PQgetisnull(res, 0, RATELIMIT_USED_COLUMN_WINDOW_EXPIRED) || strcmp(PQgetvalue(res, 0, RATELIMIT_USED_COLUMN_WINDOW_EXPIRED), "t") == 0;
    if (!window_expired)
    {
      char* parse_end; errno = 0;
      unsigned long parsed_credit_count = strtoul(PQgetvalue(res, 0, RATELIMIT_USED_COLUMN_CREDIT_COUNT), &parse_end, 10);
      if (*parse_end == '\0' && errno == 0 && parsed_credit_count <= UINT_MAX)
        *used_credit_count_out = (unsigned int)parsed_credit_count;
    }
  }
  PQclear(res);
  return true;
}

static void static_fillRateLimitInfo(RateLimitInfo_t* info_out, unsigned int credit_limit, int remaining_credit_count)
{
  if (!info_out)
    return;

  info_out->m_limit     = credit_limit;
  info_out->m_remaining = remaining_credit_count;
  info_out->m_reset     = (time(NULL) / RL_WINDOW_SECONDS + 1) * RL_WINDOW_SECONDS;
}

RateLimitStatus_t ratelimit_dbCreditBudgetCheck(PGconn* conn, const char* ip_hash, bool has_api_key, unsigned int credit_cost, bool is_partial_charge_allowed, RateLimitInfo_t* info_out, unsigned int* charged_credit_count_out)
{
  assert(ip_hash != NULL);

  if (charged_credit_count_out)
    *charged_credit_count_out = 0;
  
  if (!conn)
  {
    fprintf(stderr, "ratelimit_dbCreditBudgetCheck: no database connection\n");
    return RATELIMIT_ERROR;
  }
  if (credit_cost == 0)
  {
    fprintf(stderr, "ratelimit_dbCreditBudgetCheck: credit_cost is 0\n");
    return RATELIMIT_ERROR;
  }
  unsigned int min_charged_credit_count = is_partial_charge_allowed ? 1 : credit_cost;
  bool can_charge_less_than_cost        = min_charged_credit_count < credit_cost;

  const char* has_api_key_str = has_api_key ? "true" : "false";
  unsigned int credit_limit   = has_api_key ? RL_KEY_CREDIT_LIMIT : RL_ANON_CREDIT_LIMIT;

  char credit_limit_str[RL_CREDIT_LIMIT_STR_BUF_SIZE];
  int limit_str_len = snprintf(credit_limit_str, sizeof(credit_limit_str), "%u", credit_limit);
  if (limit_str_len < 0 || (size_t)limit_str_len >= sizeof(credit_limit_str))
    return RATELIMIT_ERROR;

  int attempt_count = can_charge_less_than_cost ? RL_CHARGE_ATTEMPT_COUNT : 1;
  for (int attempt = 0; attempt < attempt_count; attempt++)
  {
    unsigned int used_credit_count = 0;
    if (!static_readUsedCreditCount(conn, ip_hash, has_api_key_str, &used_credit_count))
      return RATELIMIT_ERROR;

    int remaining_credit_count = static_computeRemainingCreditCount(credit_limit, used_credit_count);
    if ((unsigned int)remaining_credit_count < min_charged_credit_count)
    {
      static_fillRateLimitInfo(info_out, credit_limit, remaining_credit_count);
      return RATELIMIT_DENY;
    }

    unsigned int charged_credit_count = (credit_cost <= (unsigned int)remaining_credit_count) ? credit_cost : (unsigned int)remaining_credit_count;
    char credit_cost_str[RL_CREDIT_COST_STR_BUF_SIZE];
    int cost_str_len = snprintf(credit_cost_str, sizeof(credit_cost_str), "%u", charged_credit_count);
    if (cost_str_len < 0 || (size_t)cost_str_len >= sizeof(credit_cost_str))
      return RATELIMIT_ERROR;

    const char* param_values[] = { ip_hash, has_api_key_str, credit_cost_str, credit_limit_str };
    PGresult* res = dbhelper_executeQuery(conn,
                                          "SELECT * FROM api.fn_credit_budget_charge($1, $2, $3, $4)",
                                          DBHELPER_PARAM_COUNT(param_values),
                                          param_values);
    if (!res)
      return RATELIMIT_ERROR;

    if (!dbhelper_isColumnListEqual(res, RATELIMIT_CHARGE_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(RATELIMIT_CHARGE_COLUMN_NAMES)))
    {
      PQclear(res);
      return RATELIMIT_ERROR;
    }

    if (PQntuples(res) > 0)
    {
      unsigned int new_credit_count = used_credit_count + charged_credit_count;
      char* parse_end; errno = 0;
      unsigned long parsed_credit_count = strtoul(PQgetvalue(res, 0, RATELIMIT_CHARGE_COLUMN_CREDIT_COUNT), &parse_end, 10);
      if (*parse_end == '\0' && errno == 0 && parsed_credit_count <= UINT_MAX)
        new_credit_count = (unsigned int)parsed_credit_count;
      PQclear(res);

      static_fillRateLimitInfo(info_out, credit_limit, static_computeRemainingCreditCount(credit_limit, new_credit_count));
      if (charged_credit_count_out)
        *charged_credit_count_out = charged_credit_count;
      return RATELIMIT_ALLOW;
    }
    PQclear(res);
  }

  static_fillRateLimitInfo(info_out, credit_limit, 0);
  return RATELIMIT_DENY;
}

RateLimitStatus_t ratelimit_dbCreditBudgetRemaining(PGconn* conn, const char* ip_hash, bool has_api_key, RateLimitInfo_t* info_out, unsigned int* remaining_credit_count_out)
{
  assert(ip_hash != NULL);
  assert(remaining_credit_count_out != NULL);

  *remaining_credit_count_out = 0;
  if (!conn)
  {
    fprintf(stderr, "ratelimit_dbCreditBudgetRemaining: no database connection\n");
    return RATELIMIT_ERROR;
  }

  unsigned int credit_limit      = has_api_key ? RL_KEY_CREDIT_LIMIT : RL_ANON_CREDIT_LIMIT;
  unsigned int used_credit_count = 0;
  if (!static_readUsedCreditCount(conn, ip_hash, has_api_key ? "true" : "false", &used_credit_count))
    return RATELIMIT_ERROR;

  int remaining_credit_count = static_computeRemainingCreditCount(credit_limit, used_credit_count);
  static_fillRateLimitInfo(info_out, credit_limit, remaining_credit_count);
  if (remaining_credit_count == 0)
    return RATELIMIT_DENY;

  *remaining_credit_count_out = (unsigned int)remaining_credit_count;
  return RATELIMIT_ALLOW;
}

bool ratelimit_isStartupCreditBudgetProbePassed(PGconn* conn)
{
  assert(conn != NULL);

  if (!static_beginTransaction(conn))
    return false;

  RateLimitStatus_t probe_status = ratelimit_dbCreditBudgetCheck(conn, RL_PROBE_BUCKET, false, 1, false, NULL, NULL);
  bool is_rolled_back = static_rollbackTransaction(conn);
  return probe_status != RATELIMIT_ERROR && is_rolled_back;
}

bool ratelimit_dbPurgeExpiredCreditBudgetRows(PGconn* conn)
{
  assert(conn != NULL);

  return dbhelper_runPurgeLoop(conn,
                               "SELECT api.fn_credit_budget_purge($1) AS purged_row_count",
                               "purged_row_count",
                               RL_PURGE_BATCH_ROW_COUNT);
}

static bool static_beginTransaction(PGconn* conn)
{
  PGresult* res = PQexec(conn, "BEGIN");
  bool is_begun = res != NULL && PQresultStatus(res) == PGRES_COMMAND_OK;
  PQclear(res);
  return is_begun;
}

static bool static_rollbackTransaction(PGconn* conn)
{
  PGresult* res = PQexec(conn, "ROLLBACK");
  bool is_rolled_back = res != NULL && PQresultStatus(res) == PGRES_COMMAND_OK;
  PQclear(res);
  return is_rolled_back;
}
