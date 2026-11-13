#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "dbhelper.h"
#include "throttle.h"

#define THROTTLE_CHARGE_COLUMNS(X)                                               \
  X(THROTTLE_CHARGE_COLUMN_IS_CHARGED,               "is_charged")               \
  X(THROTTLE_CHARGE_COLUMN_WINDOW_REMAINING_SECONDS, "window_remaining_seconds")
enum { THROTTLE_CHARGE_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const THROTTLE_CHARGE_COLUMN_NAMES[] = { THROTTLE_CHARGE_COLUMNS(DBHELPER_COLUMN_NAME) };

#define THROTTLE_LOAD_COLUMNS(X)                                               \
  X(THROTTLE_LOAD_COLUMN_LOAD_COUNT,               "load_count")               \
  X(THROTTLE_LOAD_COLUMN_WINDOW_REMAINING_SECONDS, "window_remaining_seconds")
enum { THROTTLE_LOAD_COLUMNS(DBHELPER_COLUMN_INDEX) };
static const char* const THROTTLE_LOAD_COLUMN_NAMES[] = { THROTTLE_LOAD_COLUMNS(DBHELPER_COLUMN_NAME) };

ThrottleStatus_t throttle_dbCharge(PGconn* conn, const ThrottleRule_t* rule, const char* target_name, unsigned int charged_count, unsigned int* retry_after_seconds_out)
{
  assert(rule                     != NULL);
  assert(rule->mp_throttleRuleName != NULL);
  assert(target_name              != NULL);
  assert(retry_after_seconds_out  != NULL);

  *retry_after_seconds_out = 0;
  if (!conn)
  {
    fprintf(stderr, "throttle_dbCharge: no database connection\n");
    return THROTTLE_ERROR;
  }
  if (charged_count == 0)
  {
    fprintf(stderr, "throttle_dbCharge: charged_count is 0\n");
    return THROTTLE_ERROR;
  }
  size_t target_name_len = strlen(target_name);
  if (target_name_len == 0 || target_name_len > THROTTLE_TARGET_NAME_MAX_LEN)
  {
    fprintf(stderr, "throttle_dbCharge: target_name is empty or longer than THROTTLE_TARGET_NAME_MAX_LEN\n");
    return THROTTLE_ERROR;
  }

  char window_seconds_str[DBHELPER_UINT_STR_BUF_SIZE];
  char charged_count_str[DBHELPER_UINT_STR_BUF_SIZE];
  char charge_limit_str[DBHELPER_UINT_STR_BUF_SIZE];
  int window_seconds_len = snprintf(window_seconds_str, sizeof(window_seconds_str), "%u", rule->m_windowSeconds);
  int charged_count_len  = snprintf(charged_count_str, sizeof(charged_count_str), "%u", charged_count);
  int charge_limit_len   = snprintf(charge_limit_str, sizeof(charge_limit_str), "%u", rule->m_chargeLimit);
  if (window_seconds_len < 0 || window_seconds_len >= DBHELPER_UINT_STR_BUF_SIZE ||
      charged_count_len  < 0 || charged_count_len  >= DBHELPER_UINT_STR_BUF_SIZE ||
      charge_limit_len   < 0 || charge_limit_len   >= DBHELPER_UINT_STR_BUF_SIZE)
    return THROTTLE_ERROR;

  const char* param_values[] = { rule->mp_throttleRuleName, target_name, window_seconds_str, charged_count_str, charge_limit_str };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_target_throttle_charge($1, $2, $3, $4, $5)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return THROTTLE_ERROR;

  bool is_charged               = false;
  int  window_remaining_seconds = 0;
  bool is_read                  = PQntuples(res) == 1                                                                                                &&
                                  dbhelper_isColumnListEqual(res, THROTTLE_CHARGE_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(THROTTLE_CHARGE_COLUMN_NAMES)) &&
                                  dbhelper_fetchColBool(res, 0, THROTTLE_CHARGE_COLUMN_IS_CHARGED, &is_charged)                                      &&
                                  dbhelper_fetchColInt(res, 0, THROTTLE_CHARGE_COLUMN_WINDOW_REMAINING_SECONDS, 0, &window_remaining_seconds);
  PQclear(res);

  if (!is_read || window_remaining_seconds <= 0)
    return THROTTLE_ERROR;
  if (is_charged)
    return THROTTLE_CHARGED;

  *retry_after_seconds_out = (unsigned int)window_remaining_seconds;
  return THROTTLE_REFUSED;
}

bool throttle_dbTryReadLoad(PGconn* conn, const ThrottleRule_t* rule, const char* target_name, unsigned int* load_count_out, unsigned int* retry_after_seconds_out)
{
  assert(rule                      != NULL);
  assert(rule->mp_throttleRuleName != NULL);
  assert(rule->m_windowSeconds     <= INT_MAX);
  assert(target_name               != NULL);
  assert(load_count_out            != NULL);
  assert(retry_after_seconds_out   != NULL);

  *load_count_out          = 0;
  *retry_after_seconds_out = 0;
  if (!conn)
  {
    fprintf(stderr, "throttle_dbTryReadLoad: no database connection\n");
    return false;
  }
  size_t target_name_len = strlen(target_name);
  if (target_name_len == 0 || target_name_len > THROTTLE_TARGET_NAME_MAX_LEN)
  {
    fprintf(stderr, "throttle_dbTryReadLoad: target_name is empty or longer than THROTTLE_TARGET_NAME_MAX_LEN\n");
    return false;
  }

  char window_seconds_str[DBHELPER_INT_PARAM_BUF_SIZE];
  const char* param_values[] = {
    rule->mp_throttleRuleName,
    target_name,
    dbhelper_intParam(window_seconds_str, sizeof(window_seconds_str), (int)rule->m_windowSeconds),
  };
  PGresult* res = dbhelper_executeQuery(conn,
                                        "SELECT * FROM api.fn_target_throttle_load($1, $2, $3)",
                                        DBHELPER_PARAM_COUNT(param_values),
                                        param_values);
  if (!res)
    return false;

  int  load_count = -1;
  int  window_remaining_seconds = 0;
  bool is_read  = PQntuples(res) == 1                                                                                            &&
                  dbhelper_isColumnListEqual(res, THROTTLE_LOAD_COLUMN_NAMES, DBHELPER_COLUMN_COUNT(THROTTLE_LOAD_COLUMN_NAMES)) &&
                  dbhelper_fetchColInt(res, 0, THROTTLE_LOAD_COLUMN_LOAD_COUNT, -1, &load_count)                                 &&
                  dbhelper_fetchColInt(res, 0, THROTTLE_LOAD_COLUMN_WINDOW_REMAINING_SECONDS, 0, &window_remaining_seconds);
  PQclear(res);

  if (!is_read || load_count < 0 || window_remaining_seconds <= 0 || (unsigned int)window_remaining_seconds > rule->m_windowSeconds)
    return false;

  *load_count_out          = (unsigned int)load_count;
  *retry_after_seconds_out = (unsigned int)window_remaining_seconds;
  return true;
}

bool throttle_dbPurgeExpiredRows(PGconn* conn)
{
  assert(conn != NULL);

  return dbhelper_runPurgeLoop(conn,
                               "SELECT api.fn_target_throttle_purge($1) AS purged_row_count",
                               "purged_row_count",
                               THROTTLE_PURGE_BATCH_ROW_COUNT);
}
