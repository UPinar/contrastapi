#include <string.h>

#include "unity/unity.h"
#include "pq_fake.h"
#include "throttle.h"

static const ThrottleRule_t TEST_RULE = { "t_fetch", 3600, 100 };

void setUp(void)
{
  pqfake_reset();
}

void tearDown(void) {}

static void static_queueChargeRow(const char* is_charged, const char* window_remaining_seconds)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 2, 1, { "is_charged", "window_remaining_seconds" }, { is_charged, window_remaining_seconds } };
  pqfake_queue(&answer);
}

void test_charge_sends_the_five_parameters_and_answers_charged(void)
{
  static_queueChargeRow("t", "1200");

  unsigned int retry_after_seconds = 99;
  TEST_ASSERT_EQUAL_INT(THROTTLE_CHARGED, throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, "example.com", 3, &retry_after_seconds));
  TEST_ASSERT_EQUAL_UINT(0, retry_after_seconds);
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_target_throttle_charge($1, $2, $3, $4, $5)", g_pqfakeLastCommand);
  TEST_ASSERT_EQUAL_STRING("t_fetch|example.com|3600|3|100", g_pqfakeLastParamLog);
}

void test_charge_answers_refused_with_the_seconds_left(void)
{
  static_queueChargeRow("f", "1200");

  unsigned int retry_after_seconds = 0;
  TEST_ASSERT_EQUAL_INT(THROTTLE_REFUSED, throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, "example.com", 3, &retry_after_seconds));
  TEST_ASSERT_EQUAL_UINT(1200, retry_after_seconds);
}

void test_charge_answers_refused_with_one_second_left(void)
{
  static_queueChargeRow("f", "1");

  unsigned int retry_after_seconds = 0;
  TEST_ASSERT_EQUAL_INT(THROTTLE_REFUSED, throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, "example.com", 3, &retry_after_seconds));
  TEST_ASSERT_EQUAL_UINT(1, retry_after_seconds);
}

void test_charge_fails_for_a_null_connection_and_a_charge_of_zero(void)
{
  static_queueChargeRow("t", "1200");

  unsigned int retry_after_seconds = 99;
  TEST_ASSERT_EQUAL_INT(THROTTLE_ERROR, throttle_dbCharge(NULL, &TEST_RULE, "example.com", 3, &retry_after_seconds));
  TEST_ASSERT_EQUAL_UINT(0, retry_after_seconds);
  retry_after_seconds = 99;
  TEST_ASSERT_EQUAL_INT(THROTTLE_ERROR, throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, "example.com", 0, &retry_after_seconds));
  TEST_ASSERT_EQUAL_UINT(0, retry_after_seconds);
  TEST_ASSERT_EQUAL_INT(0, g_pqfakeCallCount);
}

void test_charge_sends_a_charge_of_one(void)
{
  static_queueChargeRow("t", "1200");

  unsigned int retry_after_seconds = 99;
  TEST_ASSERT_EQUAL_INT(THROTTLE_CHARGED, throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, "example.com", 1, &retry_after_seconds));
  TEST_ASSERT_EQUAL_STRING("t_fetch|example.com|3600|1|100", g_pqfakeLastParamLog);
}

void test_charge_fails_when_the_query_fails(void)
{
  unsigned int retry_after_seconds = 99;
  TEST_ASSERT_EQUAL_INT(THROTTLE_ERROR, throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, "example.com", 3, &retry_after_seconds));
  TEST_ASSERT_EQUAL_UINT(0, retry_after_seconds);
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);
}

void test_charge_fails_when_a_column_has_another_name(void)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 2, 1, { "is_charged", "retry_after_seconds" }, { "f", "1200" } };
  pqfake_queue(&answer);

  unsigned int retry_after_seconds = 99;
  TEST_ASSERT_EQUAL_INT(THROTTLE_ERROR, throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, "example.com", 3, &retry_after_seconds));
  TEST_ASSERT_EQUAL_UINT(0, retry_after_seconds);
}

void test_charge_fails_for_no_row_and_for_two_rows(void)
{
  PqFakeAnswer_t no_row = { PGRES_TUPLES_OK, 2, 0, { "is_charged", "window_remaining_seconds" }, { NULL } };
  PqFakeAnswer_t two_rows = { PGRES_TUPLES_OK, 2, 2, { "is_charged", "window_remaining_seconds" }, { "t", "1200" } };
  pqfake_queue(&no_row);
  pqfake_queue(&two_rows);

  unsigned int retry_after_seconds = 99;
  TEST_ASSERT_EQUAL_INT(THROTTLE_ERROR, throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, "example.com", 3, &retry_after_seconds));
  TEST_ASSERT_EQUAL_UINT(0, retry_after_seconds);
  retry_after_seconds = 99;
  TEST_ASSERT_EQUAL_INT(THROTTLE_ERROR, throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, "example.com", 3, &retry_after_seconds));
  TEST_ASSERT_EQUAL_UINT(0, retry_after_seconds);
  TEST_ASSERT_EQUAL_INT(2, g_pqfakeCallCount);
}

void test_charge_fails_for_a_null_flag(void)
{
  static_queueChargeRow(NULL, "1200");

  unsigned int retry_after_seconds = 99;
  TEST_ASSERT_EQUAL_INT(THROTTLE_ERROR, throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, "example.com", 3, &retry_after_seconds));
  TEST_ASSERT_EQUAL_UINT(0, retry_after_seconds);
}

void test_charge_fails_for_seconds_that_cannot_be_read(void)
{
  static_queueChargeRow("f", NULL);
  static_queueChargeRow("f", "x");

  unsigned int retry_after_seconds = 99;
  TEST_ASSERT_EQUAL_INT(THROTTLE_ERROR, throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, "example.com", 3, &retry_after_seconds));
  TEST_ASSERT_EQUAL_UINT(0, retry_after_seconds);
  retry_after_seconds = 99;
  TEST_ASSERT_EQUAL_INT(THROTTLE_ERROR, throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, "example.com", 3, &retry_after_seconds));
  TEST_ASSERT_EQUAL_UINT(0, retry_after_seconds);
}

void test_charge_fails_for_zero_seconds_left(void)
{
  static_queueChargeRow("f", "0");

  unsigned int retry_after_seconds = 99;
  TEST_ASSERT_EQUAL_INT(THROTTLE_ERROR, throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, "example.com", 3, &retry_after_seconds));
  TEST_ASSERT_EQUAL_UINT(0, retry_after_seconds);
}

void test_purge_sends_the_batch_and_fails_when_the_query_fails(void)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 1, 1, { "purged_row_count" }, { "3" } };
  pqfake_queue(&answer);

  TEST_ASSERT_TRUE(throttle_dbPurgeExpiredRows(PQFAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("SELECT api.fn_target_throttle_purge($1) AS purged_row_count", g_pqfakeLastCommand);
  TEST_ASSERT_EQUAL_STRING("10000", g_pqfakeLastParamLog);
  TEST_ASSERT_FALSE(throttle_dbPurgeExpiredRows(PQFAKE_CONN));
}

void test_charge_accepts_a_target_of_1_to_253_bytes(void)
{
  static const char* const refusal_line = "throttle_dbCharge: target_name is empty or longer than THROTTLE_TARGET_NAME_MAX_LEN\n";
  static_queueChargeRow("t", "1200");
  static_queueChargeRow("t", "1200");
  char target_name[255];
  memset(target_name, 't', sizeof(target_name));
  char text[512];

  unsigned int retry_after_seconds = 99;
  pqfake_beginStderrCapture();
  ThrottleStatus_t status = throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, "", 3, &retry_after_seconds);
  pqfake_endStderrCapture(text, sizeof(text));
  TEST_ASSERT_EQUAL_INT(THROTTLE_ERROR, status);
  TEST_ASSERT_EQUAL_STRING(refusal_line, text);
  TEST_ASSERT_EQUAL_UINT(0, retry_after_seconds);
  TEST_ASSERT_EQUAL_INT(0, g_pqfakeCallCount);

  TEST_ASSERT_EQUAL_INT(THROTTLE_CHARGED, throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, "t", 3, &retry_after_seconds));
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);

  target_name[253] = '\0';
  TEST_ASSERT_EQUAL_INT(THROTTLE_CHARGED, throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, target_name, 3, &retry_after_seconds));
  TEST_ASSERT_EQUAL_INT(2, g_pqfakeCallCount);

  target_name[253] = 't';
  target_name[254] = '\0';
  retry_after_seconds = 99;
  pqfake_beginStderrCapture();
  status = throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, target_name, 3, &retry_after_seconds);
  pqfake_endStderrCapture(text, sizeof(text));
  TEST_ASSERT_EQUAL_INT(THROTTLE_ERROR, status);
  TEST_ASSERT_EQUAL_STRING(refusal_line, text);
  TEST_ASSERT_EQUAL_UINT(0, retry_after_seconds);
  TEST_ASSERT_EQUAL_INT(2, g_pqfakeCallCount);
}

void test_purge_runs_again_after_a_full_batch(void)
{
  PqFakeAnswer_t full  = { PGRES_TUPLES_OK, 1, 1, { "purged_row_count" }, { "10000" } };
  PqFakeAnswer_t empty = { PGRES_TUPLES_OK, 1, 1, { "purged_row_count" }, { "0" } };
  pqfake_queue(&full);
  pqfake_queue(&empty);

  TEST_ASSERT_TRUE(throttle_dbPurgeExpiredRows(PQFAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("fn_target_throttle_purge fn_target_throttle_purge ", g_pqfakeCallLog);
}

void test_charge_fails_for_a_charged_answer_with_no_seconds_left(void)
{
  static_queueChargeRow("t", "0");

  unsigned int retry_after_seconds = 99;
  TEST_ASSERT_EQUAL_INT(THROTTLE_ERROR, throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, "example.com", 3, &retry_after_seconds));
  TEST_ASSERT_EQUAL_UINT(0, retry_after_seconds);
}

void test_charge_of_zero_writes_one_stderr_line(void)
{
  char text[256];
  unsigned int retry_after_seconds = 99;

  pqfake_beginStderrCapture();
  ThrottleStatus_t status = throttle_dbCharge(PQFAKE_CONN, &TEST_RULE, "example.com", 0, &retry_after_seconds);
  pqfake_endStderrCapture(text, sizeof(text));

  TEST_ASSERT_EQUAL_INT(THROTTLE_ERROR, status);
  TEST_ASSERT_EQUAL_STRING("throttle_dbCharge: charged_count is 0\n", text);
}

void test_charge_null_connection_writes_one_stderr_line(void)
{
  char text[256];
  unsigned int retry_after_seconds = 99;

  pqfake_beginStderrCapture();
  ThrottleStatus_t status = throttle_dbCharge(NULL, &TEST_RULE, "example.com", 3, &retry_after_seconds);
  pqfake_endStderrCapture(text, sizeof(text));

  TEST_ASSERT_EQUAL_INT(THROTTLE_ERROR, status);
  TEST_ASSERT_EQUAL_STRING("throttle_dbCharge: no database connection\n", text);
}

void test_failed_purge_names_the_purge_function(void)
{
  char text[512];

  pqfake_beginStderrCapture();
  bool is_purged = throttle_dbPurgeExpiredRows(PQFAKE_CONN);
  pqfake_endStderrCapture(text, sizeof(text));

  TEST_ASSERT_FALSE(is_purged);
  TEST_ASSERT_EQUAL_STRING("dbhelper_executeQueryFrom: throttle_dbPurgeExpiredRows: query failed "
                           "(status no result, sqlstate none, connection ok)\n", text);
}

static void static_queueLoadRow(const char* load_count, const char* window_remaining_seconds)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 2, 1, { "load_count", "window_remaining_seconds" }, { load_count, window_remaining_seconds } };
  pqfake_queue(&answer);
}

static void static_assertLoadFails(void)
{
  unsigned int load_count          = 99;
  unsigned int retry_after_seconds = 99;
  TEST_ASSERT_FALSE(throttle_dbTryReadLoad(PQFAKE_CONN, &TEST_RULE, "example.com", &load_count, &retry_after_seconds));
  TEST_ASSERT_EQUAL_UINT(0, load_count);
  TEST_ASSERT_EQUAL_UINT(0, retry_after_seconds);
}

void test_load_sends_the_three_parameters_and_answers_the_row(void)
{
  static_queueLoadRow("7", "1200");

  unsigned int load_count          = 99;
  unsigned int retry_after_seconds = 99;
  TEST_ASSERT_TRUE(throttle_dbTryReadLoad(PQFAKE_CONN, &TEST_RULE, "example.com", &load_count, &retry_after_seconds));
  TEST_ASSERT_EQUAL_UINT(7, load_count);
  TEST_ASSERT_EQUAL_UINT(1200, retry_after_seconds);
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_target_throttle_load($1, $2, $3)", g_pqfakeLastCommand);
  TEST_ASSERT_EQUAL_STRING("t_fetch|example.com|3600", g_pqfakeLastParamLog);
}

void test_load_answers_the_edges_of_the_load_and_the_wait(void)
{
  static_queueLoadRow("0", "3600");
  static_queueLoadRow("100", "1");

  unsigned int load_count          = 99;
  unsigned int retry_after_seconds = 99;
  TEST_ASSERT_TRUE(throttle_dbTryReadLoad(PQFAKE_CONN, &TEST_RULE, "example.com", &load_count, &retry_after_seconds));
  TEST_ASSERT_EQUAL_UINT(0, load_count);
  TEST_ASSERT_EQUAL_UINT(3600, retry_after_seconds);
  TEST_ASSERT_TRUE(throttle_dbTryReadLoad(PQFAKE_CONN, &TEST_RULE, "example.com", &load_count, &retry_after_seconds));
  TEST_ASSERT_EQUAL_UINT(100, load_count);
  TEST_ASSERT_EQUAL_UINT(1, retry_after_seconds);
}

void test_load_fails_when_a_column_has_another_name(void)
{
  PqFakeAnswer_t first_renamed  = { PGRES_TUPLES_OK, 2, 1, { "charged_unit_count", "window_remaining_seconds" }, { "7", "1200" } };
  PqFakeAnswer_t second_renamed = { PGRES_TUPLES_OK, 2, 1, { "load_count", "retry_after_seconds" }, { "7", "1200" } };
  pqfake_queue(&first_renamed);
  pqfake_queue(&second_renamed);

  static_assertLoadFails();
  static_assertLoadFails();
  TEST_ASSERT_EQUAL_INT(2, g_pqfakeCallCount);
}

void test_load_fails_for_another_column_count(void)
{
  PqFakeAnswer_t one_column    = { PGRES_TUPLES_OK, 1, 1, { "load_count" }, { "7" } };
  PqFakeAnswer_t three_columns = { PGRES_TUPLES_OK, 3, 1, { "load_count", "window_remaining_seconds", "window_seconds" }, { "7", "1200", "3600" } };
  pqfake_queue(&one_column);
  pqfake_queue(&three_columns);

  static_assertLoadFails();
  static_assertLoadFails();
  TEST_ASSERT_EQUAL_INT(2, g_pqfakeCallCount);
}

void test_load_fails_for_no_row_and_for_two_rows(void)
{
  PqFakeAnswer_t no_row   = { PGRES_TUPLES_OK, 2, 0, { "load_count", "window_remaining_seconds" }, { NULL } };
  PqFakeAnswer_t two_rows = { PGRES_TUPLES_OK, 2, 2, { "load_count", "window_remaining_seconds" }, { "7", "1200" } };
  pqfake_queue(&no_row);
  pqfake_queue(&two_rows);

  static_assertLoadFails();
  static_assertLoadFails();
  TEST_ASSERT_EQUAL_INT(2, g_pqfakeCallCount);
}

void test_load_fails_for_a_null_negative_or_unreadable_load(void)
{
  static_queueLoadRow(NULL, "1200");
  static_queueLoadRow("-1", "1200");
  static_queueLoadRow("x", "1200");

  static_assertLoadFails();
  static_assertLoadFails();
  static_assertLoadFails();
  TEST_ASSERT_EQUAL_INT(3, g_pqfakeCallCount);
}

void test_load_fails_for_seconds_outside_the_window(void)
{
  static_queueLoadRow("7", NULL);
  static_queueLoadRow("7", "x");
  static_queueLoadRow("7", "0");
  static_queueLoadRow("7", "-5");
  static_queueLoadRow("7", "3601");

  static_assertLoadFails();
  static_assertLoadFails();
  static_assertLoadFails();
  static_assertLoadFails();
  static_assertLoadFails();
  TEST_ASSERT_EQUAL_INT(5, g_pqfakeCallCount);
}

void test_load_fails_when_the_query_fails(void)
{
  static_assertLoadFails();
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);
}

void test_load_fails_for_a_null_connection(void)
{
  static_queueLoadRow("7", "1200");
  char text[256];
  unsigned int load_count          = 99;
  unsigned int retry_after_seconds = 99;

  pqfake_beginStderrCapture();
  bool is_read = throttle_dbTryReadLoad(NULL, &TEST_RULE, "example.com", &load_count, &retry_after_seconds);
  pqfake_endStderrCapture(text, sizeof(text));

  TEST_ASSERT_FALSE(is_read);
  TEST_ASSERT_EQUAL_UINT(0, load_count);
  TEST_ASSERT_EQUAL_UINT(0, retry_after_seconds);
  TEST_ASSERT_EQUAL_INT(0, g_pqfakeCallCount);
  TEST_ASSERT_EQUAL_STRING("throttle_dbTryReadLoad: no database connection\n", text);
}

void test_load_accepts_a_target_of_1_to_253_bytes(void)
{
  static const char* const refusal_line = "throttle_dbTryReadLoad: target_name is empty or longer than THROTTLE_TARGET_NAME_MAX_LEN\n";
  static_queueLoadRow("7", "1200");
  static_queueLoadRow("7", "1200");
  char target_name[255];
  memset(target_name, 't', sizeof(target_name));
  char text[512];

  unsigned int load_count          = 99;
  unsigned int retry_after_seconds = 99;
  pqfake_beginStderrCapture();
  bool is_read = throttle_dbTryReadLoad(PQFAKE_CONN, &TEST_RULE, "", &load_count, &retry_after_seconds);
  pqfake_endStderrCapture(text, sizeof(text));
  TEST_ASSERT_FALSE(is_read);
  TEST_ASSERT_EQUAL_STRING(refusal_line, text);
  TEST_ASSERT_EQUAL_UINT(0, load_count);
  TEST_ASSERT_EQUAL_UINT(0, retry_after_seconds);
  TEST_ASSERT_EQUAL_INT(0, g_pqfakeCallCount);

  TEST_ASSERT_TRUE(throttle_dbTryReadLoad(PQFAKE_CONN, &TEST_RULE, "t", &load_count, &retry_after_seconds));
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);

  target_name[253] = '\0';
  TEST_ASSERT_TRUE(throttle_dbTryReadLoad(PQFAKE_CONN, &TEST_RULE, target_name, &load_count, &retry_after_seconds));
  TEST_ASSERT_EQUAL_INT(2, g_pqfakeCallCount);

  target_name[253]    = 't';
  target_name[254]    = '\0';
  load_count          = 99;
  retry_after_seconds = 99;
  pqfake_beginStderrCapture();
  is_read = throttle_dbTryReadLoad(PQFAKE_CONN, &TEST_RULE, target_name, &load_count, &retry_after_seconds);
  pqfake_endStderrCapture(text, sizeof(text));
  TEST_ASSERT_FALSE(is_read);
  TEST_ASSERT_EQUAL_STRING(refusal_line, text);
  TEST_ASSERT_EQUAL_UINT(0, load_count);
  TEST_ASSERT_EQUAL_UINT(0, retry_after_seconds);
  TEST_ASSERT_EQUAL_INT(2, g_pqfakeCallCount);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(29, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_charge_sends_the_five_parameters_and_answers_charged);
  RUN_TEST(test_charge_answers_refused_with_the_seconds_left);
  RUN_TEST(test_charge_answers_refused_with_one_second_left);
  RUN_TEST(test_charge_fails_for_a_null_connection_and_a_charge_of_zero);
  RUN_TEST(test_charge_accepts_a_target_of_1_to_253_bytes);
  RUN_TEST(test_charge_sends_a_charge_of_one);
  RUN_TEST(test_charge_fails_when_the_query_fails);
  RUN_TEST(test_charge_fails_when_a_column_has_another_name);
  RUN_TEST(test_charge_fails_for_no_row_and_for_two_rows);
  RUN_TEST(test_charge_fails_for_a_null_flag);
  RUN_TEST(test_charge_fails_for_seconds_that_cannot_be_read);
  RUN_TEST(test_charge_fails_for_zero_seconds_left);
  RUN_TEST(test_purge_sends_the_batch_and_fails_when_the_query_fails);
  RUN_TEST(test_purge_runs_again_after_a_full_batch);
  RUN_TEST(test_charge_fails_for_a_charged_answer_with_no_seconds_left);
  RUN_TEST(test_charge_of_zero_writes_one_stderr_line);
  RUN_TEST(test_charge_null_connection_writes_one_stderr_line);
  RUN_TEST(test_failed_purge_names_the_purge_function);
  RUN_TEST(test_load_sends_the_three_parameters_and_answers_the_row);
  RUN_TEST(test_load_answers_the_edges_of_the_load_and_the_wait);
  RUN_TEST(test_load_fails_when_a_column_has_another_name);
  RUN_TEST(test_load_fails_for_another_column_count);
  RUN_TEST(test_load_fails_for_no_row_and_for_two_rows);
  RUN_TEST(test_load_fails_for_a_null_negative_or_unreadable_load);
  RUN_TEST(test_load_fails_for_seconds_outside_the_window);
  RUN_TEST(test_load_fails_when_the_query_fails);
  RUN_TEST(test_load_fails_for_a_null_connection);
  RUN_TEST(test_load_accepts_a_target_of_1_to_253_bytes);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
