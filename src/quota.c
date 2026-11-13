#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#include "dbhelper.h"
#include "quota.h"
#include "retryafter.h"

#define QUOTA_RESERVE_COLUMNS(X)                   \
  X(QUOTA_RESERVE_COLUMN_IS_GRANTED, "is_granted")
enum { QUOTA_RESERVE_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const QUOTA_RESERVE_COLUMN_NAMES[] = { QUOTA_RESERVE_COLUMNS(DBHELPER_COLUMN_NAME) };

#define QUOTA_MARK_EXHAUSTED_COLUMNS(X)                 \
  X(QUOTA_MARK_EXHAUSTED_COLUMN_IS_MARKED, "is_marked")
enum { QUOTA_MARK_EXHAUSTED_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const QUOTA_MARK_EXHAUSTED_COLUMN_NAMES[] = { QUOTA_MARK_EXHAUSTED_COLUMNS(DBHELPER_COLUMN_NAME) };

#define QUOTA_HOLD_SET_COLUMNS(X)            \
  X(QUOTA_HOLD_SET_COLUMN_IS_SET, "is_set")
enum { QUOTA_HOLD_SET_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const QUOTA_HOLD_SET_COLUMN_NAMES[] = { QUOTA_HOLD_SET_COLUMNS(DBHELPER_COLUMN_NAME) };

#define QUOTA_HOLD_REMAINING_COLUMNS(X)                                       \
  X(QUOTA_HOLD_REMAINING_COLUMN_REMAINING_SECONDS, "remaining_seconds")
enum { QUOTA_HOLD_REMAINING_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const QUOTA_HOLD_REMAINING_COLUMN_NAMES[] = { QUOTA_HOLD_REMAINING_COLUMNS(DBHELPER_COLUMN_NAME) };

static bool static_formatRuleNumbers(const QuotaRule_t* rule, char* window_seconds_str, char* call_limit_str);

QuotaStatus_t quota_dbReserve(PGconn* conn, const QuotaRule_t* rule)
{
  assert(rule                != NULL);
  assert(rule->mp_sourceName != NULL);

  if (!conn)
  {
    fprintf(stderr, "quota_dbReserve: no database connection\n");
    return QUOTA_ERROR;
  }

  char window_seconds_str[DBHELPER_UINT_STR_BUF_SIZE];
  char call_limit_str[DBHELPER_UINT_STR_BUF_SIZE];
  if (!static_formatRuleNumbers(rule, window_seconds_str, call_limit_str))
    return QUOTA_ERROR;

  const char* param_values[] = { rule->mp_sourceName, window_seconds_str, call_limit_str };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_upstream_quota_reserve($1, $2, $3) AS is_granted",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return QUOTA_ERROR;

  bool is_granted = false;
  bool is_read    = PQntuples(res) == 1                                                                                            &&
                    dbhelper_isColumnListEqual(res, QUOTA_RESERVE_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(QUOTA_RESERVE_COLUMN_NAMES)) &&
                    dbhelper_fetchColBool(res, 0, QUOTA_RESERVE_COLUMN_IS_GRANTED, &is_granted);
  PQclear(res);

  if (!is_read)
    return QUOTA_ERROR;
  return is_granted ? QUOTA_GRANTED : QUOTA_EXHAUSTED;
}

bool quota_dbMarkExhausted(PGconn* conn, const QuotaRule_t* rule)
{
  assert(rule                != NULL);
  assert(rule->mp_sourceName != NULL);

  if (!conn)
  {
    fprintf(stderr, "quota_dbMarkExhausted: no database connection\n");
    return false;
  }

  char window_seconds_str[DBHELPER_UINT_STR_BUF_SIZE];
  char call_limit_str[DBHELPER_UINT_STR_BUF_SIZE];
  if (!static_formatRuleNumbers(rule, window_seconds_str, call_limit_str))
    return false;

  const char* param_values[] = { rule->mp_sourceName, window_seconds_str, call_limit_str };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_upstream_quota_mark_exhausted($1, $2, $3) AS is_marked",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return false;

  bool is_marked = false;
  bool is_read   = PQntuples(res) == 1                                                                                                          &&
                   dbhelper_isColumnListEqual(res, QUOTA_MARK_EXHAUSTED_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(QUOTA_MARK_EXHAUSTED_COLUMN_NAMES)) &&
                   dbhelper_fetchColBool(res, 0, QUOTA_MARK_EXHAUSTED_COLUMN_IS_MARKED, &is_marked);
  PQclear(res);
  return is_read && is_marked;
}

unsigned int quota_windowRemainingSeconds(const QuotaRule_t* rule, time_t now)
{
  assert(rule                  != NULL);
  assert(rule->m_windowSeconds  > 0);

  time_t window_seconds  = (time_t)rule->m_windowSeconds;
  time_t elapsed_seconds = now % window_seconds;
  if (elapsed_seconds < 0)
    elapsed_seconds += window_seconds;
  return (unsigned int)(window_seconds - elapsed_seconds);
}

bool quota_dbSetHold(PGconn* conn, const char* hold_name, unsigned int hold_seconds)
{
  assert(hold_name != NULL);

  if (!conn)
  {
    fprintf(stderr, "quota_dbSetHold: no database connection\n");
    return false;
  }
  if (hold_seconds > RETRYAFTER_MAX_SECONDS)
    hold_seconds = RETRYAFTER_MAX_SECONDS;

  char hold_seconds_str[DBHELPER_UINT_STR_BUF_SIZE];
  int hold_seconds_len = snprintf(hold_seconds_str, sizeof(hold_seconds_str), "%u", hold_seconds);
  if (hold_seconds_len < 0 || hold_seconds_len >= DBHELPER_UINT_STR_BUF_SIZE)
    return false;

  const char* param_values[] = { hold_name, hold_seconds_str };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_upstream_hold_set($1, $2) AS is_set",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return false;

  bool is_set  = false;
  bool is_read = PQntuples(res) == 1                                                                                              &&
                 dbhelper_isColumnListEqual(res, QUOTA_HOLD_SET_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(QUOTA_HOLD_SET_COLUMN_NAMES)) &&
                 dbhelper_fetchColBool(res, 0, QUOTA_HOLD_SET_COLUMN_IS_SET, &is_set);
  PQclear(res);
  return is_read && is_set;
}

bool quota_dbTryReadHoldRemainingSeconds(PGconn* conn, const char* hold_name, unsigned int* remaining_seconds_out)
{
  assert(hold_name             != NULL);
  assert(remaining_seconds_out != NULL);

  *remaining_seconds_out = 0;
  if (!conn)
  {
    fprintf(stderr, "quota_dbTryReadHoldRemainingSeconds: no database connection\n");
    return false;
  }

  const char* param_values[] = { hold_name };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT api.fn_upstream_hold_remaining_seconds($1) AS remaining_seconds",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return false;

  int  remaining_seconds = -1;
  bool is_read           = PQntuples(res) == 1                                                                                                          &&
                           dbhelper_isColumnListEqual(res, QUOTA_HOLD_REMAINING_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(QUOTA_HOLD_REMAINING_COLUMN_NAMES)) &&
                           dbhelper_fetchColInt(res, 0, QUOTA_HOLD_REMAINING_COLUMN_REMAINING_SECONDS, -1, &remaining_seconds);
  PQclear(res);

  if (!is_read || remaining_seconds < 0)
    return false;
  *remaining_seconds_out = (unsigned int)remaining_seconds;
  return true;
}

bool quota_dbPurgeExpiredRows(PGconn* conn)
{
  assert(conn != NULL);

  return dbhelper_runPurgeLoop(conn,
                               "SELECT api.fn_upstream_quota_purge($1) AS purged_row_count",
                               "purged_row_count",
                               QUOTA_PURGE_BATCH_ROW_COUNT);
}

static bool static_formatRuleNumbers(const QuotaRule_t* rule, char* window_seconds_str, char* call_limit_str)
{
  int window_seconds_len = snprintf(window_seconds_str, DBHELPER_UINT_STR_BUF_SIZE, "%u", rule->m_windowSeconds);
  int call_limit_len     = snprintf(call_limit_str, DBHELPER_UINT_STR_BUF_SIZE, "%u", rule->m_callLimit);

  return  window_seconds_len >= 0                           &&
          window_seconds_len < DBHELPER_UINT_STR_BUF_SIZE   &&
          call_limit_len     >= 0                           &&
          call_limit_len     < DBHELPER_UINT_STR_BUF_SIZE;
}
