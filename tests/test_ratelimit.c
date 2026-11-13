#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <libpq-fe.h>

#include "unity/unity.h"
#include "ratelimit.h"

#define FAKE_CONN ((PGconn*)1)

#define FAKE_BUCKET "bucket"

#define FAKE_ANSWER_QUEUE_LEN    8
#define FAKE_ANSWER_MAX_COLUMNS  2
#define FAKE_CALL_LOG_BUF_SIZE 128
#define FAKE_PARAM_BUF_SIZE     64
#define FAKE_COMMAND_BUF_SIZE 1024

typedef struct
{
  ExecStatusType m_status;
  int            m_columnCount;
  int            m_rowCount;
  const char*    ma_cells[FAKE_ANSWER_MAX_COLUMNS];
  const char*    ma_columnNames[FAKE_ANSWER_MAX_COLUMNS];
} FakeAnswer_t;

static FakeAnswer_t g_queuedAnswers[FAKE_ANSWER_QUEUE_LEN];
static int          g_queuedAnswerCount = 0;
static int          g_callCount         = 0;

static char g_callLog[FAKE_CALL_LOG_BUF_SIZE];

static char g_lastCommand[FAKE_COMMAND_BUF_SIZE];

static int g_lastParamCount = -1;

static char g_lastParamLog[FAKE_CALL_LOG_BUF_SIZE];

static char g_firstSelectParam[FAKE_PARAM_BUF_SIZE];

static char g_upsertChargeLog[FAKE_CALL_LOG_BUF_SIZE];

static char g_upsertBucketLog[FAKE_CALL_LOG_BUF_SIZE];

PGresult*      __wrap_PQexec(PGconn* conn, const char* command);
PGresult*      __wrap_PQexecParams(PGconn* conn, const char* command, int n_params, const Oid* param_types,
                                   const char* const* param_values, const int* param_lengths,
                                   const int* param_formats, int result_format);
ConnStatusType __wrap_PQstatus(const PGconn* conn);

void setUp(void)
{
  memset(g_queuedAnswers, 0, sizeof(g_queuedAnswers));
  g_queuedAnswerCount   = 0;
  g_callCount           = 0;
  g_callLog[0]          = '\0';
  g_lastCommand[0]      = '\0';
  g_lastParamCount      = -1;
  g_lastParamLog[0]     = '\0';
  g_firstSelectParam[0] = '\0';
  g_upsertChargeLog[0]  = '\0';
  g_upsertBucketLog[0]  = '\0';
}

void tearDown(void) {}

static void static_queueAnswer(ExecStatusType status)
{
  assert(g_queuedAnswerCount < FAKE_ANSWER_QUEUE_LEN);
  FakeAnswer_t* answer = &g_queuedAnswers[g_queuedAnswerCount++];
  answer->m_status = status;
}

static void static_queueRow(int column_count, const char* first, const char* second)
{
  assert(g_queuedAnswerCount < FAKE_ANSWER_QUEUE_LEN);
  FakeAnswer_t* answer = &g_queuedAnswers[g_queuedAnswerCount++];
  answer->m_status      = PGRES_TUPLES_OK;
  answer->m_columnCount = column_count;
  answer->m_rowCount    = 1;
  answer->ma_cells[0]   = first;
  answer->ma_cells[1]   = second;
}

static void static_queueNoRow(int column_count)
{
  assert(g_queuedAnswerCount < FAKE_ANSWER_QUEUE_LEN);
  FakeAnswer_t* answer = &g_queuedAnswers[g_queuedAnswerCount++];
  answer->m_status      = PGRES_TUPLES_OK;
  answer->m_columnCount = column_count;
}

static void static_nameLastColumn(int col, const char* name)
{
  assert(g_queuedAnswerCount > 0 && col >= 0 && col < FAKE_ANSWER_MAX_COLUMNS);
  g_queuedAnswers[g_queuedAnswerCount - 1].ma_columnNames[col] = name;
}

static void static_queueUsedRow(const char* count, const char* expired)
{
  static_queueRow(2, count, expired);
  static_nameLastColumn(0, "credit_count");
  static_nameLastColumn(1, "window_expired");
}

static void static_queueUsedNoRow(void)
{
  static_queueNoRow(2);
  static_nameLastColumn(0, "credit_count");
  static_nameLastColumn(1, "window_expired");
}

static void static_queueChargedRow(const char* count)
{
  static_queueRow(1, count, NULL);
  static_nameLastColumn(0, "credit_count");
}

static void static_queueChargeNoRow(void)
{
  static_queueNoRow(1);
  static_nameLastColumn(0, "credit_count");
}

static void static_formatCount(char* text_out, int count)
{
  int written = snprintf(text_out, FAKE_PARAM_BUF_SIZE, "%d", count);
  TEST_ASSERT_TRUE(written >= 0 && written < FAKE_PARAM_BUF_SIZE);
}

static void static_queuePurgeCount(const char* count)
{
  static_queueRow(1, count, NULL);
  static_nameLastColumn(0, "purged_row_count");
}

static void static_logCommand(const char* command)
{
  const char* name     = strstr(command, "api.");
  int         name_len = 0;
  if (name)
  {
    name    += strlen("api.");
    name_len = (int)strcspn(name, "(");
  }
  else
  {
    name     = command;
    name_len = (int)strcspn(command, " ");
  }
  size_t used = strlen(g_callLog);
  int written = snprintf(g_callLog + used, sizeof(g_callLog) - used, "%.*s ", name_len, name);
  TEST_ASSERT_TRUE(written >= 0 && (size_t)written < sizeof(g_callLog) - used);
  written = snprintf(g_lastCommand, sizeof(g_lastCommand), "%s", command);
  TEST_ASSERT_TRUE(written >= 0 && (size_t)written < sizeof(g_lastCommand));
}

static PGresult* static_nextAnswer(void)
{
  int call_index = g_callCount++;
  if (call_index >= g_queuedAnswerCount)
    return NULL;

  const FakeAnswer_t* answer = &g_queuedAnswers[call_index];
  PGresult* result = PQmakeEmptyPGresult(NULL, answer->m_status);
  TEST_ASSERT_NOT_NULL(result);
  if (answer->m_columnCount == 0)
    return result;

  PGresAttDesc columns[FAKE_ANSWER_MAX_COLUMNS];
  memset(columns, 0, sizeof(columns));
  for (int col = 0; col < answer->m_columnCount; col++)
    columns[col].name = (char*)(answer->ma_columnNames[col] ? answer->ma_columnNames[col] : "column");
  TEST_ASSERT_TRUE(PQsetResultAttrs(result, answer->m_columnCount, columns));
  for (int col = 0; col < answer->m_columnCount && answer->m_rowCount == 1; col++)
  {
    const char* cell = answer->ma_cells[col];
    TEST_ASSERT_TRUE(PQsetvalue(result, 0, col, (char*)cell, cell ? (int)strlen(cell) : -1));
  }
  return result;
}

PGresult* __wrap_PQexec(PGconn* conn, const char* command)
{
  (void)conn;
  static_logCommand(command);
  return static_nextAnswer();
}

PGresult* __wrap_PQexecParams(PGconn* conn, const char* command, int n_params, const Oid* param_types,
                              const char* const* param_values, const int* param_lengths,
                              const int* param_formats, int result_format)
{
  (void)conn;
  (void)param_types;
  (void)param_lengths;
  (void)param_formats;
  (void)result_format;
  static_logCommand(command);
  g_lastParamCount = n_params;
  g_lastParamLog[0] = '\0';
  for (int i = 0; i < n_params && param_values; i++)
  {
    size_t used = strlen(g_lastParamLog);
    int written = snprintf(g_lastParamLog + used, sizeof(g_lastParamLog) - used, "%s%s", i > 0 ? "|" : "", param_values[i] ? param_values[i] : "NULL");
    TEST_ASSERT_TRUE(written >= 0 && (size_t)written < sizeof(g_lastParamLog) - used);
  }
  if (g_firstSelectParam[0] == '\0' && n_params >= 1 && param_values && param_values[0])
  {
    int written = snprintf(g_firstSelectParam, sizeof(g_firstSelectParam), "%s", param_values[0]);
    TEST_ASSERT_TRUE(written >= 0 && (size_t)written < sizeof(g_firstSelectParam));
  }
  if (n_params == 4 && param_values && param_values[2])
  {
    size_t used = strlen(g_upsertChargeLog);
    int written = snprintf(g_upsertChargeLog + used, sizeof(g_upsertChargeLog) - used, "%s ", param_values[2]);
    TEST_ASSERT_TRUE(written >= 0 && (size_t)written < sizeof(g_upsertChargeLog) - used);
    used = strlen(g_upsertBucketLog);
    written = snprintf(g_upsertBucketLog + used, sizeof(g_upsertBucketLog) - used, "%s|%s|%s ", param_values[0], param_values[1], param_values[3]);
    TEST_ASSERT_TRUE(written >= 0 && (size_t)written < sizeof(g_upsertBucketLog) - used);
  }
  return static_nextAnswer();
}

ConnStatusType __wrap_PQstatus(const PGconn* conn)
{
  (void)conn;
  return CONNECTION_OK;
}

void test_check_charges_the_remaining_credits_when_the_cost_does_not_fit(void)
{
  static_queueUsedRow("20", "f");
  static_queueChargedRow("30");

  RateLimitInfo_t info = { 0 };
  unsigned int charged = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ALLOW, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 50, true, &info, &charged));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_used fn_credit_budget_charge ", g_callLog);
  TEST_ASSERT_EQUAL_STRING("10 ", g_upsertChargeLog);
  TEST_ASSERT_EQUAL_UINT(10, charged);
  TEST_ASSERT_EQUAL_UINT(RL_ANON_CREDIT_LIMIT, info.m_limit);
  TEST_ASSERT_EQUAL_INT(0, info.m_remaining);
}

void test_check_charges_the_whole_cost_when_it_fits(void)
{
  static_queueUsedRow("20", "f");
  static_queueChargedRow("25");

  RateLimitInfo_t info = { 0 };
  unsigned int charged = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ALLOW, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 5, true, &info, &charged));
  TEST_ASSERT_EQUAL_STRING("5 ", g_upsertChargeLog);
  TEST_ASSERT_EQUAL_UINT(5, charged);
  TEST_ASSERT_EQUAL_INT(5, info.m_remaining);
}

void test_check_partial_denies_without_the_upsert_when_no_credit_remains(void)
{
  static_queueUsedRow("30", "f");

  RateLimitInfo_t info = { 0 };
  unsigned int charged = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_DENY, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 50, true, &info, &charged));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_used ", g_callLog);
  TEST_ASSERT_EQUAL_UINT(0, charged);
  TEST_ASSERT_EQUAL_INT(0, info.m_remaining);
}

void test_check_partial_charges_the_last_credit(void)
{
  static_queueUsedRow("29", "f");
  static_queueChargedRow("30");

  unsigned int charged = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ALLOW, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 50, true, NULL, &charged));
  TEST_ASSERT_EQUAL_STRING("1 ", g_upsertChargeLog);
  TEST_ASSERT_EQUAL_UINT(1, charged);
}

void test_check_runs_again_after_a_partial_charge_loses_the_race(void)
{
  static_queueUsedRow("20", "f");
  static_queueChargeNoRow();
  static_queueUsedRow("25", "f");
  static_queueChargedRow("30");

  unsigned int charged = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ALLOW, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 50, true, NULL, &charged));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_used fn_credit_budget_charge fn_credit_budget_used fn_credit_budget_charge ", g_callLog);
  TEST_ASSERT_EQUAL_STRING("10 5 ", g_upsertChargeLog);
  TEST_ASSERT_EQUAL_STRING("bucket|false|30 bucket|false|30 ", g_upsertBucketLog);
  TEST_ASSERT_EQUAL_UINT(5, charged);
}

void test_check_denies_after_the_second_lost_race(void)
{
  static_queueUsedRow("20", "f");
  static_queueChargeNoRow();
  static_queueUsedRow("20", "f");
  static_queueChargeNoRow();

  RateLimitInfo_t info = { 0 };
  unsigned int charged = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_DENY, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 50, true, &info, &charged));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_used fn_credit_budget_charge fn_credit_budget_used fn_credit_budget_charge ", g_callLog);
  TEST_ASSERT_EQUAL_UINT(0, charged);
  TEST_ASSERT_EQUAL_INT(0, info.m_remaining);
}

void test_check_does_not_run_again_when_the_whole_cost_is_required(void)
{
  static_queueUsedRow("20", "f");
  static_queueChargeNoRow();

  TEST_ASSERT_EQUAL_INT(RATELIMIT_DENY, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 5, false, NULL, NULL));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_used fn_credit_budget_charge ", g_callLog);
}

void test_check_fails_for_a_zero_cost(void)
{
  unsigned int charged = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ERROR, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 0, false, NULL, &charged));
  TEST_ASSERT_EQUAL_UINT(0, charged);
  charged = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ERROR, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 0, true, NULL, &charged));
  TEST_ASSERT_EQUAL_UINT(0, charged);
  TEST_ASSERT_EQUAL_STRING("", g_callLog);
}

void test_check_fails_for_a_null_connection(void)
{
  unsigned int charged = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ERROR, ratelimit_dbCreditBudgetCheck(NULL, FAKE_BUCKET, false, 5, true, NULL, &charged));
  TEST_ASSERT_EQUAL_UINT(0, charged);
  TEST_ASSERT_EQUAL_STRING("", g_callLog);
}

void test_check_whole_cost_denies_without_the_upsert_when_less_than_the_cost_remains(void)
{
  static_queueUsedRow("27", "f");

  RateLimitInfo_t info = { 0 };
  unsigned int charged = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_DENY, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 5, false, &info, &charged));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_used ", g_callLog);
  TEST_ASSERT_EQUAL_UINT(0, charged);
  TEST_ASSERT_EQUAL_INT(3, info.m_remaining);
}

void test_check_second_attempt_denies_without_the_upsert_when_the_bucket_is_full(void)
{
  static_queueUsedRow("20", "f");
  static_queueChargeNoRow();
  static_queueUsedRow("30", "f");

  RateLimitInfo_t info = { 0 };
  unsigned int charged = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_DENY, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 50, true, &info, &charged));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_used fn_credit_budget_charge fn_credit_budget_used ", g_callLog);
  TEST_ASSERT_EQUAL_STRING("10 ", g_upsertChargeLog);
  TEST_ASSERT_EQUAL_UINT(0, charged);
  TEST_ASSERT_EQUAL_INT(0, info.m_remaining);
}

void test_check_fails_when_the_second_select_fails(void)
{
  static_queueUsedRow("20", "f");
  static_queueChargeNoRow();
  static_queueAnswer(PGRES_FATAL_ERROR);

  unsigned int charged = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ERROR, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 50, true, NULL, &charged));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_used fn_credit_budget_charge fn_credit_budget_used ", g_callLog);
  TEST_ASSERT_EQUAL_UINT(0, charged);
}

void test_check_fails_when_the_upsert_fails(void)
{
  static_queueUsedRow("20", "f");
  static_queueAnswer(PGRES_FATAL_ERROR);

  unsigned int charged = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ERROR, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 5, false, NULL, &charged));
  TEST_ASSERT_EQUAL_UINT(0, charged);
}

void test_check_fails_when_the_second_upsert_fails(void)
{
  static_queueUsedRow("20", "f");
  static_queueChargeNoRow();
  static_queueUsedRow("20", "f");
  static_queueAnswer(PGRES_FATAL_ERROR);

  unsigned int charged = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ERROR, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 50, true, NULL, &charged));
  TEST_ASSERT_EQUAL_UINT(0, charged);
}

void test_check_reports_the_remaining_credits_from_the_returned_count(void)
{
  static_queueUsedRow("20", "f");
  static_queueChargedRow("28");

  RateLimitInfo_t info = { 0 };
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ALLOW, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 5, false, &info, NULL));
  TEST_ASSERT_EQUAL_INT(2, info.m_remaining);
}

void test_check_charges_a_key_bucket_against_the_key_limit(void)
{
  static_queueUsedRow("20", "f");
  static_queueChargeNoRow();
  static_queueUsedRow("20", "f");
  static_queueChargedRow("70");

  RateLimitInfo_t info = { 0 };
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ALLOW, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, true, 50, true, &info, NULL));
  TEST_ASSERT_EQUAL_STRING("bucket|true|500 bucket|true|500 ", g_upsertBucketLog);
  TEST_ASSERT_EQUAL_UINT(RL_KEY_CREDIT_LIMIT, info.m_limit);
  TEST_ASSERT_EQUAL_INT(430, info.m_remaining);
}

void test_check_counts_an_expired_window_as_zero(void)
{
  static_queueUsedRow("29", "t");
  static_queueChargedRow("5");

  TEST_ASSERT_EQUAL_INT(RATELIMIT_ALLOW, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 5, false, NULL, NULL));
  TEST_ASSERT_EQUAL_STRING("5 ", g_upsertChargeLog);
}

void test_check_partial_runs_again_for_a_cost_of_two(void)
{
  static_queueUsedRow("20", "f");
  static_queueChargeNoRow();
  static_queueUsedRow("20", "f");
  static_queueChargedRow("22");

  TEST_ASSERT_EQUAL_INT(RATELIMIT_ALLOW, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 2, true, NULL, NULL));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_used fn_credit_budget_charge fn_credit_budget_used fn_credit_budget_charge ", g_callLog);
}

void test_check_partial_does_not_run_again_for_a_cost_of_one(void)
{
  static_queueUsedRow("20", "f");
  static_queueChargeNoRow();

  TEST_ASSERT_EQUAL_INT(RATELIMIT_DENY, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 1, true, NULL, NULL));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_used fn_credit_budget_charge ", g_callLog);
}

void test_probe_runs_the_check_inside_a_rolled_back_transaction(void)
{
  static_queueAnswer(PGRES_COMMAND_OK);
  static_queueUsedNoRow();
  static_queueChargedRow("1");
  static_queueAnswer(PGRES_COMMAND_OK);

  TEST_ASSERT_TRUE(ratelimit_isStartupCreditBudgetProbePassed(FAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("BEGIN fn_credit_budget_used fn_credit_budget_charge ROLLBACK ", g_callLog);
  TEST_ASSERT_EQUAL_STRING("startup-probe", g_firstSelectParam);
}

void test_probe_fails_when_begin_fails(void)
{
  static_queueAnswer(PGRES_FATAL_ERROR);

  TEST_ASSERT_FALSE(ratelimit_isStartupCreditBudgetProbePassed(FAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("BEGIN ", g_callLog);
}

void test_probe_rolls_back_and_fails_when_the_check_fails(void)
{
  static_queueAnswer(PGRES_COMMAND_OK);
  static_queueAnswer(PGRES_FATAL_ERROR);
  static_queueAnswer(PGRES_COMMAND_OK);

  TEST_ASSERT_FALSE(ratelimit_isStartupCreditBudgetProbePassed(FAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("BEGIN fn_credit_budget_used ROLLBACK ", g_callLog);
}

void test_probe_fails_when_rollback_fails(void)
{
  static_queueAnswer(PGRES_COMMAND_OK);
  static_queueUsedNoRow();
  static_queueChargedRow("1");
  static_queueAnswer(PGRES_FATAL_ERROR);

  TEST_ASSERT_FALSE(ratelimit_isStartupCreditBudgetProbePassed(FAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("BEGIN fn_credit_budget_used fn_credit_budget_charge ROLLBACK ", g_callLog);
}

void test_probe_passes_when_the_check_denies(void)
{
  char limit_str[16];
  snprintf(limit_str, sizeof(limit_str), "%d", RL_ANON_CREDIT_LIMIT);
  static_queueAnswer(PGRES_COMMAND_OK);
  static_queueUsedRow(limit_str, "f");
  static_queueAnswer(PGRES_COMMAND_OK);

  TEST_ASSERT_TRUE(ratelimit_isStartupCreditBudgetProbePassed(FAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("BEGIN fn_credit_budget_used ROLLBACK ", g_callLog);
}

void test_purge_stops_after_a_short_batch(void)
{
  char batch_str[FAKE_PARAM_BUF_SIZE];
  static_formatCount(batch_str, RL_PURGE_BATCH_ROW_COUNT);
  static_queuePurgeCount("42");

  TEST_ASSERT_TRUE(ratelimit_dbPurgeExpiredCreditBudgetRows(FAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_purge ", g_callLog);
  TEST_ASSERT_EQUAL_STRING("SELECT api.fn_credit_budget_purge($1) AS purged_row_count", g_lastCommand);
  TEST_ASSERT_EQUAL_INT(1, g_lastParamCount);
  TEST_ASSERT_EQUAL_STRING(batch_str, g_firstSelectParam);
}

void test_purge_stops_after_a_batch_one_row_short(void)
{
  char short_str[FAKE_PARAM_BUF_SIZE];
  static_formatCount(short_str, RL_PURGE_BATCH_ROW_COUNT - 1);
  static_queuePurgeCount(short_str);

  TEST_ASSERT_TRUE(ratelimit_dbPurgeExpiredCreditBudgetRows(FAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_purge ", g_callLog);
}

void test_purge_runs_again_after_a_full_batch(void)
{
  char batch_str[FAKE_PARAM_BUF_SIZE];
  static_formatCount(batch_str, RL_PURGE_BATCH_ROW_COUNT);
  static_queuePurgeCount(batch_str);
  static_queuePurgeCount("0");

  TEST_ASSERT_TRUE(ratelimit_dbPurgeExpiredCreditBudgetRows(FAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_purge fn_credit_budget_purge ", g_callLog);
}

void test_purge_fails_when_the_query_fails(void)
{
  static_queueAnswer(PGRES_FATAL_ERROR);

  TEST_ASSERT_FALSE(ratelimit_dbPurgeExpiredCreditBudgetRows(FAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_purge ", g_callLog);
}

void test_purge_fails_when_a_later_call_fails(void)
{
  char batch_str[FAKE_PARAM_BUF_SIZE];
  static_formatCount(batch_str, RL_PURGE_BATCH_ROW_COUNT);
  static_queuePurgeCount(batch_str);
  static_queueAnswer(PGRES_FATAL_ERROR);

  TEST_ASSERT_FALSE(ratelimit_dbPurgeExpiredCreditBudgetRows(FAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_purge fn_credit_budget_purge ", g_callLog);
}

void test_purge_fails_when_the_column_has_another_name(void)
{
  static_queueRow(1, "0", NULL);

  TEST_ASSERT_FALSE(ratelimit_dbPurgeExpiredCreditBudgetRows(FAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_purge ", g_callLog);
}

void test_purge_fails_when_the_count_is_null(void)
{
  static_queuePurgeCount(NULL);

  TEST_ASSERT_FALSE(ratelimit_dbPurgeExpiredCreditBudgetRows(FAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_purge ", g_callLog);
}

void test_purge_fails_when_the_count_cannot_be_read(void)
{
  static_queuePurgeCount("many");

  TEST_ASSERT_FALSE(ratelimit_dbPurgeExpiredCreditBudgetRows(FAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_purge ", g_callLog);
}

void test_check_calls_the_two_api_functions_with_their_parameters(void)
{
  char limit_str[FAKE_PARAM_BUF_SIZE];
  static_formatCount(limit_str, RL_ANON_CREDIT_LIMIT);
  static_queueUsedRow(limit_str, "f");

  TEST_ASSERT_EQUAL_INT(RATELIMIT_DENY, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 5, false, NULL, NULL));
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_credit_budget_used($1, $2)", g_lastCommand);
  TEST_ASSERT_EQUAL_STRING("bucket|false", g_lastParamLog);

  static_queueUsedRow("20", "f");
  static_queueChargedRow("25");
  char key_params[FAKE_PARAM_BUF_SIZE];
  int written = snprintf(key_params, sizeof(key_params), "bucket|true|5|%d", RL_KEY_CREDIT_LIMIT);
  TEST_ASSERT_TRUE(written >= 0 && (size_t)written < sizeof(key_params));

  TEST_ASSERT_EQUAL_INT(RATELIMIT_ALLOW, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, true, 5, false, NULL, NULL));
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_credit_budget_charge($1, $2, $3, $4)", g_lastCommand);
  TEST_ASSERT_EQUAL_STRING(key_params, g_lastParamLog);
}

void test_check_fails_when_the_read_answer_has_other_column_names(void)
{
  static_queueUsedRow("20", "f");
  static_nameLastColumn(1, "expired");

  unsigned int charged = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ERROR, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 5, false, NULL, &charged));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_used ", g_callLog);
  TEST_ASSERT_EQUAL_UINT(0, charged);
}

void test_check_fails_when_an_empty_read_answer_has_other_column_names(void)
{
  static_queueUsedNoRow();
  static_nameLastColumn(1, "expired");
  static_queueChargedRow("5");

  TEST_ASSERT_EQUAL_INT(RATELIMIT_ERROR, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 5, false, NULL, NULL));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_used ", g_callLog);
}

void test_check_fails_when_the_charge_answer_has_another_column_name(void)
{
  static_queueUsedRow("20", "f");
  static_queueChargedRow("25");
  static_nameLastColumn(0, "fn_credit_budget_charge");

  RateLimitInfo_t info = { 0 };
  unsigned int charged = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ERROR, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 5, false, &info, &charged));
  TEST_ASSERT_EQUAL_UINT(0, charged);
  TEST_ASSERT_EQUAL_UINT(0, info.m_limit);
}

void test_check_fails_when_an_empty_charge_answer_has_another_column_name(void)
{
  static_queueUsedRow("20", "f");
  static_queueChargeNoRow();
  static_nameLastColumn(0, "fn_credit_budget_charge");
  static_queueUsedRow("20", "f");
  static_queueChargedRow("30");

  TEST_ASSERT_EQUAL_INT(RATELIMIT_ERROR, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 50, true, NULL, NULL));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_used fn_credit_budget_charge ", g_callLog);
}

void test_check_fails_when_the_second_charge_answer_has_another_column_name(void)
{
  static_queueUsedRow("20", "f");
  static_queueChargeNoRow();
  static_queueUsedRow("20", "f");
  static_queueChargedRow("30");
  static_nameLastColumn(0, "fn_credit_budget_charge");

  unsigned int charged = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ERROR, ratelimit_dbCreditBudgetCheck(FAKE_CONN, FAKE_BUCKET, false, 50, true, NULL, &charged));
  TEST_ASSERT_EQUAL_UINT(0, charged);
}

void test_remaining_reads_the_budget_without_a_charge(void)
{
  static_queueUsedRow("7", "f");

  RateLimitInfo_t info = { 0 };
  unsigned int remaining = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ALLOW, ratelimit_dbCreditBudgetRemaining(FAKE_CONN, FAKE_BUCKET, true, &info, &remaining));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_used ", g_callLog);
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_credit_budget_used($1, $2)", g_lastCommand);
  TEST_ASSERT_EQUAL_STRING("bucket|true", g_lastParamLog);
  TEST_ASSERT_EQUAL_UINT(RL_KEY_CREDIT_LIMIT - 7, remaining);
  TEST_ASSERT_EQUAL_UINT(RL_KEY_CREDIT_LIMIT, info.m_limit);
  TEST_ASSERT_EQUAL_INT(RL_KEY_CREDIT_LIMIT - 7, info.m_remaining);
  TEST_ASSERT_TRUE(info.m_reset > 0);
}

void test_remaining_counts_no_row_and_an_expired_window_as_unused(void)
{
  char full_str[FAKE_PARAM_BUF_SIZE];
  static_formatCount(full_str, RL_ANON_CREDIT_LIMIT);
  char one_short_str[FAKE_PARAM_BUF_SIZE];
  static_formatCount(one_short_str, RL_ANON_CREDIT_LIMIT - 1);
  static_queueUsedNoRow();
  static_queueUsedRow(full_str, "t");
  static_queueUsedRow(one_short_str, "f");

  unsigned int remaining = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ALLOW, ratelimit_dbCreditBudgetRemaining(FAKE_CONN, FAKE_BUCKET, false, NULL, &remaining));
  TEST_ASSERT_EQUAL_UINT(RL_ANON_CREDIT_LIMIT, remaining);
  remaining = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ALLOW, ratelimit_dbCreditBudgetRemaining(FAKE_CONN, FAKE_BUCKET, false, NULL, &remaining));
  TEST_ASSERT_EQUAL_UINT(RL_ANON_CREDIT_LIMIT, remaining);
  TEST_ASSERT_EQUAL_STRING("bucket|false", g_lastParamLog);
  remaining = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ALLOW, ratelimit_dbCreditBudgetRemaining(FAKE_CONN, FAKE_BUCKET, false, NULL, &remaining));
  TEST_ASSERT_EQUAL_UINT(1, remaining);
}

void test_remaining_denies_a_spent_budget(void)
{
  char full_str[FAKE_PARAM_BUF_SIZE];
  static_formatCount(full_str, RL_ANON_CREDIT_LIMIT);
  static_queueUsedRow(full_str, "f");

  RateLimitInfo_t info = { .m_limit = 1, .m_remaining = 99, .m_reset = 0 };
  unsigned int remaining = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_DENY, ratelimit_dbCreditBudgetRemaining(FAKE_CONN, FAKE_BUCKET, false, &info, &remaining));
  TEST_ASSERT_EQUAL_STRING("fn_credit_budget_used ", g_callLog);
  TEST_ASSERT_EQUAL_UINT(0, remaining);
  TEST_ASSERT_EQUAL_UINT(RL_ANON_CREDIT_LIMIT, info.m_limit);
  TEST_ASSERT_EQUAL_INT(0, info.m_remaining);
  TEST_ASSERT_TRUE(info.m_reset > 0);
}

void test_remaining_fails_without_a_connection_or_a_named_answer(void)
{
  RateLimitInfo_t info = { .m_limit = 3, .m_remaining = 4, .m_reset = 5 };
  unsigned int remaining = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ERROR, ratelimit_dbCreditBudgetRemaining(NULL, FAKE_BUCKET, false, &info, &remaining));
  TEST_ASSERT_EQUAL_STRING("", g_callLog);
  TEST_ASSERT_EQUAL_UINT(0, remaining);

  static_queueAnswer(PGRES_FATAL_ERROR);
  remaining = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ERROR, ratelimit_dbCreditBudgetRemaining(FAKE_CONN, FAKE_BUCKET, false, &info, &remaining));
  TEST_ASSERT_EQUAL_UINT(0, remaining);

  static_queueUsedRow("20", "f");
  static_nameLastColumn(1, "expired");
  remaining = 99;
  TEST_ASSERT_EQUAL_INT(RATELIMIT_ERROR, ratelimit_dbCreditBudgetRemaining(FAKE_CONN, FAKE_BUCKET, false, &info, &remaining));
  TEST_ASSERT_EQUAL_UINT(0, remaining);
  TEST_ASSERT_EQUAL_UINT(3, info.m_limit);
  TEST_ASSERT_EQUAL_INT(4, info.m_remaining);
  TEST_ASSERT_EQUAL_INT(5, (int)info.m_reset);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(43, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_check_charges_the_remaining_credits_when_the_cost_does_not_fit);
  RUN_TEST(test_check_charges_the_whole_cost_when_it_fits);
  RUN_TEST(test_check_partial_denies_without_the_upsert_when_no_credit_remains);
  RUN_TEST(test_check_partial_charges_the_last_credit);
  RUN_TEST(test_check_runs_again_after_a_partial_charge_loses_the_race);
  RUN_TEST(test_check_denies_after_the_second_lost_race);
  RUN_TEST(test_check_does_not_run_again_when_the_whole_cost_is_required);
  RUN_TEST(test_check_fails_for_a_zero_cost);
  RUN_TEST(test_check_fails_for_a_null_connection);
  RUN_TEST(test_check_whole_cost_denies_without_the_upsert_when_less_than_the_cost_remains);
  RUN_TEST(test_check_second_attempt_denies_without_the_upsert_when_the_bucket_is_full);
  RUN_TEST(test_check_fails_when_the_second_select_fails);
  RUN_TEST(test_check_fails_when_the_upsert_fails);
  RUN_TEST(test_check_fails_when_the_second_upsert_fails);
  RUN_TEST(test_check_reports_the_remaining_credits_from_the_returned_count);
  RUN_TEST(test_check_charges_a_key_bucket_against_the_key_limit);
  RUN_TEST(test_check_counts_an_expired_window_as_zero);
  RUN_TEST(test_check_partial_runs_again_for_a_cost_of_two);
  RUN_TEST(test_check_partial_does_not_run_again_for_a_cost_of_one);
  RUN_TEST(test_check_calls_the_two_api_functions_with_their_parameters);
  RUN_TEST(test_remaining_reads_the_budget_without_a_charge);
  RUN_TEST(test_remaining_counts_no_row_and_an_expired_window_as_unused);
  RUN_TEST(test_remaining_denies_a_spent_budget);
  RUN_TEST(test_remaining_fails_without_a_connection_or_a_named_answer);
  RUN_TEST(test_check_fails_when_the_read_answer_has_other_column_names);
  RUN_TEST(test_check_fails_when_an_empty_read_answer_has_other_column_names);
  RUN_TEST(test_check_fails_when_the_charge_answer_has_another_column_name);
  RUN_TEST(test_check_fails_when_an_empty_charge_answer_has_another_column_name);
  RUN_TEST(test_check_fails_when_the_second_charge_answer_has_another_column_name);
  RUN_TEST(test_probe_runs_the_check_inside_a_rolled_back_transaction);
  RUN_TEST(test_probe_fails_when_begin_fails);
  RUN_TEST(test_probe_rolls_back_and_fails_when_the_check_fails);
  RUN_TEST(test_probe_fails_when_rollback_fails);
  RUN_TEST(test_probe_passes_when_the_check_denies);
  RUN_TEST(test_purge_stops_after_a_short_batch);
  RUN_TEST(test_purge_stops_after_a_batch_one_row_short);
  RUN_TEST(test_purge_runs_again_after_a_full_batch);
  RUN_TEST(test_purge_fails_when_the_query_fails);
  RUN_TEST(test_purge_fails_when_a_later_call_fails);
  RUN_TEST(test_purge_fails_when_the_column_has_another_name);
  RUN_TEST(test_purge_fails_when_the_count_is_null);
  RUN_TEST(test_purge_fails_when_the_count_cannot_be_read);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
