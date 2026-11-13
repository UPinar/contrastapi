#include "unity/unity.h"
#include "pq_fake.h"
#include "quota.h"
#include "retryafter.h"

static const QuotaRule_t TEST_RULE = { "t_source", 3600, 7 };

static const QuotaRule_t TEST_SHORT_RULE = { "t_short", 10, 2 };

#define TEST_WINDOW_START ((time_t)1793001600)

static const char TEST_HOLD_NAME[] = "rdap:rdap.example";

#define TEST_STALE_SECONDS 77u

void setUp(void)
{
  pqfake_reset();
}

void tearDown(void) {}

static void static_queueOneCell(const char* column_name, const char* cell)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 1, 1, { column_name }, { cell } };
  pqfake_queue(&answer);
}

void test_reserve_sends_the_rule_and_answers_granted(void)
{
  static_queueOneCell("is_granted", "t");

  TEST_ASSERT_EQUAL_INT(QUOTA_GRANTED, quota_dbReserve(PQFAKE_CONN, &TEST_RULE));
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);
  TEST_ASSERT_EQUAL_STRING("SELECT api.fn_upstream_quota_reserve($1, $2, $3) AS is_granted", g_pqfakeLastCommand);
  TEST_ASSERT_EQUAL_STRING("t_source|3600|7", g_pqfakeLastParamLog);
}

void test_reserve_answers_exhausted_when_the_limit_is_spent(void)
{
  static_queueOneCell("is_granted", "f");

  TEST_ASSERT_EQUAL_INT(QUOTA_EXHAUSTED, quota_dbReserve(PQFAKE_CONN, &TEST_RULE));
}

void test_reserve_fails_for_a_null_connection(void)
{
  static_queueOneCell("is_granted", "t");

  TEST_ASSERT_EQUAL_INT(QUOTA_ERROR, quota_dbReserve(NULL, &TEST_RULE));
  TEST_ASSERT_EQUAL_INT(0, g_pqfakeCallCount);
}

void test_reserve_fails_when_the_query_fails(void)
{
  TEST_ASSERT_EQUAL_INT(QUOTA_ERROR, quota_dbReserve(PQFAKE_CONN, &TEST_RULE));
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);
}

void test_reserve_fails_when_the_column_has_another_name(void)
{
  static_queueOneCell("fn_upstream_quota_reserve", "t");

  TEST_ASSERT_EQUAL_INT(QUOTA_ERROR, quota_dbReserve(PQFAKE_CONN, &TEST_RULE));
}

void test_reserve_fails_for_an_answer_with_no_row(void)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 1, 0, { "is_granted" }, { NULL } };
  pqfake_queue(&answer);

  TEST_ASSERT_EQUAL_INT(QUOTA_ERROR, quota_dbReserve(PQFAKE_CONN, &TEST_RULE));
}

void test_reserve_fails_for_an_answer_with_two_rows(void)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 1, 2, { "is_granted" }, { "t" } };
  pqfake_queue(&answer);

  TEST_ASSERT_EQUAL_INT(QUOTA_ERROR, quota_dbReserve(PQFAKE_CONN, &TEST_RULE));
}

void test_reserve_fails_for_a_null_answer(void)
{
  static_queueOneCell("is_granted", NULL);

  TEST_ASSERT_EQUAL_INT(QUOTA_ERROR, quota_dbReserve(PQFAKE_CONN, &TEST_RULE));
}

void test_mark_exhausted_sends_the_rule_and_succeeds(void)
{
  static_queueOneCell("is_marked", "t");

  TEST_ASSERT_TRUE(quota_dbMarkExhausted(PQFAKE_CONN, &TEST_RULE));
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);
  TEST_ASSERT_EQUAL_STRING("SELECT api.fn_upstream_quota_mark_exhausted($1, $2, $3) AS is_marked", g_pqfakeLastCommand);
  TEST_ASSERT_EQUAL_STRING("t_source|3600|7", g_pqfakeLastParamLog);
}

void test_mark_exhausted_fails_for_a_null_connection(void)
{
  static_queueOneCell("is_marked", "t");

  TEST_ASSERT_FALSE(quota_dbMarkExhausted(NULL, &TEST_RULE));
  TEST_ASSERT_EQUAL_INT(0, g_pqfakeCallCount);
}

void test_mark_exhausted_fails_when_the_query_fails(void)
{
  TEST_ASSERT_FALSE(quota_dbMarkExhausted(PQFAKE_CONN, &TEST_RULE));
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);
}

void test_mark_exhausted_fails_when_the_column_has_another_name(void)
{
  static_queueOneCell("fn_upstream_quota_mark_exhausted", "t");

  TEST_ASSERT_FALSE(quota_dbMarkExhausted(PQFAKE_CONN, &TEST_RULE));
}

void test_mark_exhausted_fails_for_an_answer_with_no_row(void)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 1, 0, { "is_marked" }, { NULL } };
  pqfake_queue(&answer);

  TEST_ASSERT_FALSE(quota_dbMarkExhausted(PQFAKE_CONN, &TEST_RULE));
}

void test_mark_exhausted_fails_for_an_answer_with_two_rows(void)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 1, 2, { "is_marked" }, { "t" } };
  pqfake_queue(&answer);

  TEST_ASSERT_FALSE(quota_dbMarkExhausted(PQFAKE_CONN, &TEST_RULE));
}

void test_mark_exhausted_fails_for_a_null_answer(void)
{
  static_queueOneCell("is_marked", NULL);

  TEST_ASSERT_FALSE(quota_dbMarkExhausted(PQFAKE_CONN, &TEST_RULE));
}

void test_mark_exhausted_fails_when_the_window_is_not_marked(void)
{
  static_queueOneCell("is_marked", "f");

  TEST_ASSERT_FALSE(quota_dbMarkExhausted(PQFAKE_CONN, &TEST_RULE));
}

void test_purge_sends_the_batch_and_succeeds(void)
{
  static_queueOneCell("purged_row_count", "3");

  TEST_ASSERT_TRUE(quota_dbPurgeExpiredRows(PQFAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("SELECT api.fn_upstream_quota_purge($1) AS purged_row_count", g_pqfakeLastCommand);
  TEST_ASSERT_EQUAL_STRING("10000", g_pqfakeLastParamLog);
  TEST_ASSERT_EQUAL_STRING("fn_upstream_quota_purge ", g_pqfakeCallLog);
}

void test_purge_runs_again_after_a_full_batch(void)
{
  static_queueOneCell("purged_row_count", "10000");
  static_queueOneCell("purged_row_count", "0");

  TEST_ASSERT_TRUE(quota_dbPurgeExpiredRows(PQFAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("fn_upstream_quota_purge fn_upstream_quota_purge ", g_pqfakeCallLog);
}

void test_purge_fails_when_the_query_fails(void)
{
  TEST_ASSERT_FALSE(quota_dbPurgeExpiredRows(PQFAKE_CONN));
}

void test_purge_fails_for_an_answer_with_two_rows(void)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 1, 2, { "purged_row_count" }, { "3" } };
  pqfake_queue(&answer);

  TEST_ASSERT_FALSE(quota_dbPurgeExpiredRows(PQFAKE_CONN));
}

void test_reserve_null_connection_writes_one_stderr_line(void)
{
  char text[256];

  pqfake_beginStderrCapture();
  QuotaStatus_t status = quota_dbReserve(NULL, &TEST_RULE);
  pqfake_endStderrCapture(text, sizeof(text));

  TEST_ASSERT_EQUAL_INT(QUOTA_ERROR, status);
  TEST_ASSERT_EQUAL_STRING("quota_dbReserve: no database connection\n", text);
}

void test_mark_exhausted_null_connection_writes_one_stderr_line(void)
{
  char text[256];

  pqfake_beginStderrCapture();
  bool is_marked = quota_dbMarkExhausted(NULL, &TEST_RULE);
  pqfake_endStderrCapture(text, sizeof(text));

  TEST_ASSERT_FALSE(is_marked);
  TEST_ASSERT_EQUAL_STRING("quota_dbMarkExhausted: no database connection\n", text);
}

void test_failed_purge_names_the_purge_function(void)
{
  char text[512];

  pqfake_beginStderrCapture();
  bool is_purged = quota_dbPurgeExpiredRows(PQFAKE_CONN);
  pqfake_endStderrCapture(text, sizeof(text));

  TEST_ASSERT_FALSE(is_purged);
  TEST_ASSERT_EQUAL_STRING("dbhelper_executeQueryFrom: quota_dbPurgeExpiredRows: query failed "
                           "(status no result, sqlstate none, connection ok)\n", text);
}

void test_set_hold_sends_the_name_and_the_seconds_and_succeeds(void)
{
  static_queueOneCell("is_set", "t");

  TEST_ASSERT_TRUE(quota_dbSetHold(PQFAKE_CONN, TEST_HOLD_NAME, 120));
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);
  TEST_ASSERT_EQUAL_STRING("SELECT api.fn_upstream_hold_set($1, $2) AS is_set", g_pqfakeLastCommand);
  TEST_ASSERT_EQUAL_STRING("rdap:rdap.example|120", g_pqfakeLastParamLog);
}

void test_set_hold_cuts_a_hold_past_the_maximum(void)
{
  static_queueOneCell("is_set", "t");
  static_queueOneCell("is_set", "t");

  TEST_ASSERT_TRUE(quota_dbSetHold(PQFAKE_CONN, TEST_HOLD_NAME, RETRYAFTER_MAX_SECONDS));
  TEST_ASSERT_EQUAL_STRING("rdap:rdap.example|3600", g_pqfakeLastParamLog);
  TEST_ASSERT_TRUE(quota_dbSetHold(PQFAKE_CONN, TEST_HOLD_NAME, RETRYAFTER_MAX_SECONDS + 1u));
  TEST_ASSERT_EQUAL_STRING("rdap:rdap.example|3600", g_pqfakeLastParamLog);
}

void test_set_hold_fails_for_a_null_connection(void)
{
  static_queueOneCell("is_set", "t");

  TEST_ASSERT_FALSE(quota_dbSetHold(NULL, TEST_HOLD_NAME, 120));
  TEST_ASSERT_EQUAL_INT(0, g_pqfakeCallCount);
}

void test_set_hold_fails_when_the_query_fails(void)
{
  TEST_ASSERT_FALSE(quota_dbSetHold(PQFAKE_CONN, TEST_HOLD_NAME, 120));
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);
}

void test_set_hold_fails_when_the_column_has_another_name(void)
{
  static_queueOneCell("fn_upstream_hold_set", "t");

  TEST_ASSERT_FALSE(quota_dbSetHold(PQFAKE_CONN, TEST_HOLD_NAME, 120));
}

void test_set_hold_fails_for_an_answer_with_no_row(void)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 1, 0, { "is_set" }, { NULL } };
  pqfake_queue(&answer);

  TEST_ASSERT_FALSE(quota_dbSetHold(PQFAKE_CONN, TEST_HOLD_NAME, 120));
}

void test_set_hold_fails_for_an_answer_with_two_rows(void)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 1, 2, { "is_set" }, { "t" } };
  pqfake_queue(&answer);

  TEST_ASSERT_FALSE(quota_dbSetHold(PQFAKE_CONN, TEST_HOLD_NAME, 120));
}

void test_set_hold_fails_for_a_null_answer(void)
{
  static_queueOneCell("is_set", NULL);

  TEST_ASSERT_FALSE(quota_dbSetHold(PQFAKE_CONN, TEST_HOLD_NAME, 120));
}

void test_set_hold_fails_when_the_hold_is_not_set(void)
{
  static_queueOneCell("is_set", "f");

  TEST_ASSERT_FALSE(quota_dbSetHold(PQFAKE_CONN, TEST_HOLD_NAME, 120));
}

void test_read_hold_sends_the_name_and_answers_the_seconds(void)
{
  unsigned int hold_seconds = TEST_STALE_SECONDS;
  static_queueOneCell("remaining_seconds", "37");

  TEST_ASSERT_TRUE(quota_dbTryReadHoldRemainingSeconds(PQFAKE_CONN, TEST_HOLD_NAME, &hold_seconds));
  TEST_ASSERT_EQUAL_UINT(37, hold_seconds);
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);
  TEST_ASSERT_EQUAL_STRING("SELECT api.fn_upstream_hold_remaining_seconds($1) AS remaining_seconds", g_pqfakeLastCommand);
  TEST_ASSERT_EQUAL_STRING("rdap:rdap.example", g_pqfakeLastParamLog);
}

void test_read_hold_answers_zero_for_an_upstream_that_is_not_held(void)
{
  unsigned int hold_seconds = TEST_STALE_SECONDS;
  static_queueOneCell("remaining_seconds", "0");

  TEST_ASSERT_TRUE(quota_dbTryReadHoldRemainingSeconds(PQFAKE_CONN, TEST_HOLD_NAME, &hold_seconds));
  TEST_ASSERT_EQUAL_UINT(0, hold_seconds);
}

void test_read_hold_fails_for_a_null_connection(void)
{
  unsigned int hold_seconds = TEST_STALE_SECONDS;
  static_queueOneCell("remaining_seconds", "37");

  TEST_ASSERT_FALSE(quota_dbTryReadHoldRemainingSeconds(NULL, TEST_HOLD_NAME, &hold_seconds));
  TEST_ASSERT_EQUAL_UINT(0, hold_seconds);
  TEST_ASSERT_EQUAL_INT(0, g_pqfakeCallCount);
}

void test_read_hold_fails_when_the_query_fails(void)
{
  unsigned int hold_seconds = TEST_STALE_SECONDS;

  TEST_ASSERT_FALSE(quota_dbTryReadHoldRemainingSeconds(PQFAKE_CONN, TEST_HOLD_NAME, &hold_seconds));
  TEST_ASSERT_EQUAL_UINT(0, hold_seconds);
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);
}

void test_read_hold_fails_when_the_column_has_another_name(void)
{
  unsigned int hold_seconds = TEST_STALE_SECONDS;
  static_queueOneCell("fn_upstream_hold_remaining_seconds", "37");

  TEST_ASSERT_FALSE(quota_dbTryReadHoldRemainingSeconds(PQFAKE_CONN, TEST_HOLD_NAME, &hold_seconds));
  TEST_ASSERT_EQUAL_UINT(0, hold_seconds);
}

void test_read_hold_fails_for_an_answer_with_no_row(void)
{
  unsigned int hold_seconds = TEST_STALE_SECONDS;
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 1, 0, { "remaining_seconds" }, { NULL } };
  pqfake_queue(&answer);

  TEST_ASSERT_FALSE(quota_dbTryReadHoldRemainingSeconds(PQFAKE_CONN, TEST_HOLD_NAME, &hold_seconds));
  TEST_ASSERT_EQUAL_UINT(0, hold_seconds);
}

void test_read_hold_fails_for_an_answer_with_two_rows(void)
{
  unsigned int hold_seconds = TEST_STALE_SECONDS;
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 1, 2, { "remaining_seconds" }, { "37" } };
  pqfake_queue(&answer);

  TEST_ASSERT_FALSE(quota_dbTryReadHoldRemainingSeconds(PQFAKE_CONN, TEST_HOLD_NAME, &hold_seconds));
  TEST_ASSERT_EQUAL_UINT(0, hold_seconds);
}

void test_read_hold_fails_for_a_null_answer(void)
{
  unsigned int hold_seconds = TEST_STALE_SECONDS;
  static_queueOneCell("remaining_seconds", NULL);

  TEST_ASSERT_FALSE(quota_dbTryReadHoldRemainingSeconds(PQFAKE_CONN, TEST_HOLD_NAME, &hold_seconds));
  TEST_ASSERT_EQUAL_UINT(0, hold_seconds);
}

void test_read_hold_fails_for_text_that_is_not_a_number(void)
{
  unsigned int hold_seconds = TEST_STALE_SECONDS;
  static_queueOneCell("remaining_seconds", "x");

  TEST_ASSERT_FALSE(quota_dbTryReadHoldRemainingSeconds(PQFAKE_CONN, TEST_HOLD_NAME, &hold_seconds));
  TEST_ASSERT_EQUAL_UINT(0, hold_seconds);
}

void test_read_hold_fails_for_a_negative_answer(void)
{
  unsigned int hold_seconds = TEST_STALE_SECONDS;
  static_queueOneCell("remaining_seconds", "-1");

  TEST_ASSERT_FALSE(quota_dbTryReadHoldRemainingSeconds(PQFAKE_CONN, TEST_HOLD_NAME, &hold_seconds));
  TEST_ASSERT_EQUAL_UINT(0, hold_seconds);
}

void test_set_hold_null_connection_writes_one_stderr_line(void)
{
  char text[256];

  pqfake_beginStderrCapture();
  bool is_set = quota_dbSetHold(NULL, TEST_HOLD_NAME, 120);
  pqfake_endStderrCapture(text, sizeof(text));

  TEST_ASSERT_FALSE(is_set);
  TEST_ASSERT_EQUAL_STRING("quota_dbSetHold: no database connection\n", text);
}

void test_read_hold_null_connection_writes_one_stderr_line(void)
{
  char text[256];
  unsigned int hold_seconds = TEST_STALE_SECONDS;

  pqfake_beginStderrCapture();
  bool is_read = quota_dbTryReadHoldRemainingSeconds(NULL, TEST_HOLD_NAME, &hold_seconds);
  pqfake_endStderrCapture(text, sizeof(text));

  TEST_ASSERT_FALSE(is_read);
  TEST_ASSERT_EQUAL_STRING("quota_dbTryReadHoldRemainingSeconds: no database connection\n", text);
}

void test_window_remaining_seconds_is_the_whole_window_at_its_first_second(void)
{
  TEST_ASSERT_EQUAL_UINT(3600, quota_windowRemainingSeconds(&TEST_RULE, TEST_WINDOW_START));
  TEST_ASSERT_EQUAL_UINT(10, quota_windowRemainingSeconds(&TEST_SHORT_RULE, TEST_WINDOW_START));
}

void test_window_remaining_seconds_is_one_less_a_second_after_the_start(void)
{
  TEST_ASSERT_EQUAL_UINT(3599, quota_windowRemainingSeconds(&TEST_RULE, TEST_WINDOW_START + 1));
  TEST_ASSERT_EQUAL_UINT(9, quota_windowRemainingSeconds(&TEST_SHORT_RULE, TEST_WINDOW_START + 1));
}

void test_window_remaining_seconds_is_one_at_the_last_second(void)
{
  TEST_ASSERT_EQUAL_UINT(1, quota_windowRemainingSeconds(&TEST_RULE, TEST_WINDOW_START + 3600 - 1));
  TEST_ASSERT_EQUAL_UINT(1, quota_windowRemainingSeconds(&TEST_SHORT_RULE, TEST_WINDOW_START + 10 - 1));
}

void test_window_remaining_seconds_before_the_epoch_counts_in_the_window_before(void)
{
  TEST_ASSERT_EQUAL_UINT(1, quota_windowRemainingSeconds(&TEST_RULE, (time_t)-1));
  TEST_ASSERT_EQUAL_UINT(1, quota_windowRemainingSeconds(&TEST_SHORT_RULE, (time_t)-1));
  TEST_ASSERT_EQUAL_UINT(3600, quota_windowRemainingSeconds(&TEST_RULE, (time_t)-3600));
  TEST_ASSERT_EQUAL_UINT(10, quota_windowRemainingSeconds(&TEST_SHORT_RULE, (time_t)-10));
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(49, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_reserve_sends_the_rule_and_answers_granted);
  RUN_TEST(test_reserve_answers_exhausted_when_the_limit_is_spent);
  RUN_TEST(test_reserve_fails_for_a_null_connection);
  RUN_TEST(test_reserve_fails_when_the_query_fails);
  RUN_TEST(test_reserve_fails_when_the_column_has_another_name);
  RUN_TEST(test_reserve_fails_for_an_answer_with_no_row);
  RUN_TEST(test_reserve_fails_for_an_answer_with_two_rows);
  RUN_TEST(test_reserve_fails_for_a_null_answer);
  RUN_TEST(test_mark_exhausted_sends_the_rule_and_succeeds);
  RUN_TEST(test_mark_exhausted_fails_for_a_null_connection);
  RUN_TEST(test_mark_exhausted_fails_when_the_query_fails);
  RUN_TEST(test_mark_exhausted_fails_when_the_column_has_another_name);
  RUN_TEST(test_mark_exhausted_fails_for_an_answer_with_no_row);
  RUN_TEST(test_mark_exhausted_fails_for_an_answer_with_two_rows);
  RUN_TEST(test_mark_exhausted_fails_for_a_null_answer);
  RUN_TEST(test_mark_exhausted_fails_when_the_window_is_not_marked);
  RUN_TEST(test_purge_sends_the_batch_and_succeeds);
  RUN_TEST(test_purge_runs_again_after_a_full_batch);
  RUN_TEST(test_purge_fails_when_the_query_fails);
  RUN_TEST(test_purge_fails_for_an_answer_with_two_rows);
  RUN_TEST(test_reserve_null_connection_writes_one_stderr_line);
  RUN_TEST(test_mark_exhausted_null_connection_writes_one_stderr_line);
  RUN_TEST(test_failed_purge_names_the_purge_function);
  RUN_TEST(test_set_hold_sends_the_name_and_the_seconds_and_succeeds);
  RUN_TEST(test_set_hold_cuts_a_hold_past_the_maximum);
  RUN_TEST(test_set_hold_fails_for_a_null_connection);
  RUN_TEST(test_set_hold_fails_when_the_query_fails);
  RUN_TEST(test_set_hold_fails_when_the_column_has_another_name);
  RUN_TEST(test_set_hold_fails_for_an_answer_with_no_row);
  RUN_TEST(test_set_hold_fails_for_an_answer_with_two_rows);
  RUN_TEST(test_set_hold_fails_for_a_null_answer);
  RUN_TEST(test_set_hold_fails_when_the_hold_is_not_set);
  RUN_TEST(test_read_hold_sends_the_name_and_answers_the_seconds);
  RUN_TEST(test_read_hold_answers_zero_for_an_upstream_that_is_not_held);
  RUN_TEST(test_read_hold_fails_for_a_null_connection);
  RUN_TEST(test_read_hold_fails_when_the_query_fails);
  RUN_TEST(test_read_hold_fails_when_the_column_has_another_name);
  RUN_TEST(test_read_hold_fails_for_an_answer_with_no_row);
  RUN_TEST(test_read_hold_fails_for_an_answer_with_two_rows);
  RUN_TEST(test_read_hold_fails_for_a_null_answer);
  RUN_TEST(test_read_hold_fails_for_text_that_is_not_a_number);
  RUN_TEST(test_read_hold_fails_for_a_negative_answer);
  RUN_TEST(test_set_hold_null_connection_writes_one_stderr_line);
  RUN_TEST(test_read_hold_null_connection_writes_one_stderr_line);
  RUN_TEST(test_window_remaining_seconds_is_the_whole_window_at_its_first_second);
  RUN_TEST(test_window_remaining_seconds_is_one_less_a_second_after_the_start);
  RUN_TEST(test_window_remaining_seconds_is_one_at_the_last_second);
  RUN_TEST(test_window_remaining_seconds_before_the_epoch_counts_in_the_window_before);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
