#include <string.h>

#include "unity/unity.h"
#include "pq_fake.h"
#include "cache.h"
#include "version.h"

#define TEST_FETCHED_AT "2026-10-17T18:00:00Z"

static char g_longText[CACHE_MAX_BODY_LEN + 2];

static const char* static_longText(size_t length)
{
  memset(g_longText, 'b', sizeof(g_longText));
  g_longText[length] = '\0';
  return g_longText;
}

static size_t static_versionPrefixLen(void)
{
  return strlen(CONTRASTAPI_VERSION) + 1;
}

void setUp(void)
{
  pqfake_reset();
}

void tearDown(void) {}

static void static_queueGetRow(const char* body, const char* is_error, const char* fetched_at)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 3, 1, { "body", "is_error", "fetched_at" }, { body, is_error, fetched_at } };
  pqfake_queue(&answer);
}

static void static_queueOneCell(const char* column_name, const char* cell)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 1, 1, { column_name }, { cell } };
  pqfake_queue(&answer);
}

void test_get_sends_the_versioned_key_and_answers_the_row(void)
{
  static_queueGetRow("{\"a\":1}", "f", TEST_FETCHED_AT);

  CacheEntry_t entry = { 0 };
  TEST_ASSERT_EQUAL_INT(CACHE_HIT, cache_dbGet(PQFAKE_CONN, "t-key", &entry));
  TEST_ASSERT_EQUAL_STRING("SELECT * FROM api.fn_upstream_cache_get($1)", g_pqfakeLastCommand);
  TEST_ASSERT_EQUAL_STRING(CONTRASTAPI_VERSION ":t-key", g_pqfakeLastParamLog);
  TEST_ASSERT_EQUAL_STRING("{\"a\":1}", entry.mp_body);
  TEST_ASSERT_FALSE(entry.m_isError);
  TEST_ASSERT_EQUAL_STRING(TEST_FETCHED_AT, entry.ma_fetchedAt);
  cache_entryFree(&entry);
}

void test_get_reads_an_error_body(void)
{
  static_queueGetRow("{\"error\":\"x\"}", "t", TEST_FETCHED_AT);

  CacheEntry_t entry = { 0 };
  TEST_ASSERT_EQUAL_INT(CACHE_HIT, cache_dbGet(PQFAKE_CONN, "t-key", &entry));
  TEST_ASSERT_TRUE(entry.m_isError);
  TEST_ASSERT_EQUAL_STRING("{\"error\":\"x\"}", entry.mp_body);
  cache_entryFree(&entry);
}

void test_get_answers_miss_for_no_row(void)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 3, 0, { "body", "is_error", "fetched_at" }, { NULL } };
  pqfake_queue(&answer);

  CacheEntry_t entry = { 0 };
  TEST_ASSERT_EQUAL_INT(CACHE_MISS, cache_dbGet(PQFAKE_CONN, "t-key", &entry));
  TEST_ASSERT_NULL(entry.mp_body);
}

void test_get_fails_for_a_null_connection(void)
{
  static_queueGetRow("{}", "f", TEST_FETCHED_AT);

  CacheEntry_t entry = { NULL, true, "old" };
  TEST_ASSERT_EQUAL_INT(CACHE_ERROR, cache_dbGet(NULL, "t-key", &entry));
  TEST_ASSERT_EQUAL_INT(0, g_pqfakeCallCount);
  TEST_ASSERT_FALSE(entry.m_isError);
  TEST_ASSERT_EQUAL_STRING("", entry.ma_fetchedAt);
}

void test_get_refuses_a_key_past_the_longest(void)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 3, 0, { "body", "is_error", "fetched_at" }, { NULL } };
  pqfake_queue(&answer);

  CacheEntry_t entry = { 0 };
  TEST_ASSERT_EQUAL_INT(CACHE_MISS, cache_dbGet(PQFAKE_CONN, static_longText(CACHE_KEY_MAX_LEN - static_versionPrefixLen()), &entry));
  TEST_ASSERT_EQUAL_INT(CACHE_ERROR, cache_dbGet(PQFAKE_CONN, static_longText(CACHE_KEY_MAX_LEN - static_versionPrefixLen() + 1), &entry));
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);
}

void test_get_refuses_an_empty_key(void)
{
  static_queueGetRow("{}", "f", TEST_FETCHED_AT);

  CacheEntry_t entry = { 0 };
  char text[256];
  pqfake_beginStderrCapture();
  CacheStatus_t status = cache_dbGet(PQFAKE_CONN, "", &entry);
  pqfake_endStderrCapture(text, sizeof(text));

  TEST_ASSERT_EQUAL_INT(CACHE_ERROR, status);
  TEST_ASSERT_EQUAL_STRING("static_writeVersionedKey: empty key\n", text);
  TEST_ASSERT_NULL(entry.mp_body);
  TEST_ASSERT_EQUAL_INT(0, g_pqfakeCallCount);
}

void test_get_fails_when_the_query_fails(void)
{
  CacheEntry_t entry = { 0 };
  TEST_ASSERT_EQUAL_INT(CACHE_ERROR, cache_dbGet(PQFAKE_CONN, "t-key", &entry));
  TEST_ASSERT_NULL(entry.mp_body);
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);
}

void test_get_fails_for_an_empty_answer_with_other_column_names(void)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 3, 0, { "body", "error", "fetched_at" }, { NULL } };
  pqfake_queue(&answer);

  CacheEntry_t entry = { 0 };
  TEST_ASSERT_EQUAL_INT(CACHE_ERROR, cache_dbGet(PQFAKE_CONN, "t-key", &entry));
  TEST_ASSERT_NULL(entry.mp_body);
}

void test_get_fails_for_a_row_with_other_column_names(void)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 3, 1, { "body", "is_error", "fetched" }, { "{}", "f", TEST_FETCHED_AT } };
  pqfake_queue(&answer);

  CacheEntry_t entry = { 0 };
  TEST_ASSERT_EQUAL_INT(CACHE_ERROR, cache_dbGet(PQFAKE_CONN, "t-key", &entry));
  TEST_ASSERT_NULL(entry.mp_body);
}

void test_get_fails_for_two_rows(void)
{
  PqFakeAnswer_t answer = { PGRES_TUPLES_OK, 3, 2, { "body", "is_error", "fetched_at" }, { "{}", "f", TEST_FETCHED_AT } };
  pqfake_queue(&answer);

  CacheEntry_t entry = { 0 };
  TEST_ASSERT_EQUAL_INT(CACHE_ERROR, cache_dbGet(PQFAKE_CONN, "t-key", &entry));
  TEST_ASSERT_NULL(entry.mp_body);
}

void test_get_fails_for_a_null_body(void)
{
  static_queueGetRow(NULL, "f", TEST_FETCHED_AT);

  CacheEntry_t entry = { 0 };
  TEST_ASSERT_EQUAL_INT(CACHE_ERROR, cache_dbGet(PQFAKE_CONN, "t-key", &entry));
  TEST_ASSERT_NULL(entry.mp_body);
}

void test_get_refuses_a_body_past_the_longest(void)
{
  static_queueGetRow(static_longText(CACHE_MAX_BODY_LEN), "f", TEST_FETCHED_AT);

  CacheEntry_t entry = { 0 };
  TEST_ASSERT_EQUAL_INT(CACHE_HIT, cache_dbGet(PQFAKE_CONN, "t-key", &entry));
  TEST_ASSERT_EQUAL_size_t(CACHE_MAX_BODY_LEN, strlen(entry.mp_body));
  cache_entryFree(&entry);

  static_queueGetRow(static_longText(CACHE_MAX_BODY_LEN + 1), "f", TEST_FETCHED_AT);
  TEST_ASSERT_EQUAL_INT(CACHE_ERROR, cache_dbGet(PQFAKE_CONN, "t-key", &entry));
  TEST_ASSERT_NULL(entry.mp_body);
}

void test_get_fails_for_a_null_flag(void)
{
  static_queueGetRow("{}", NULL, TEST_FETCHED_AT);

  CacheEntry_t entry = { 0 };
  TEST_ASSERT_EQUAL_INT(CACHE_ERROR, cache_dbGet(PQFAKE_CONN, "t-key", &entry));
  TEST_ASSERT_NULL(entry.mp_body);
}

void test_get_fails_for_a_fetched_at_past_its_field(void)
{
  static_queueGetRow("{}", "t", TEST_FETCHED_AT "x");

  CacheEntry_t entry = { 0 };
  TEST_ASSERT_EQUAL_INT(CACHE_ERROR, cache_dbGet(PQFAKE_CONN, "t-key", &entry));
  TEST_ASSERT_NULL(entry.mp_body);
  TEST_ASSERT_FALSE(entry.m_isError);
}

void test_put_sends_the_four_parameters(void)
{
  static_queueOneCell("is_written", "t");

  TEST_ASSERT_TRUE(cache_dbPut(PQFAKE_CONN, "t-key", "{\"e\":1}", true, 90));
  TEST_ASSERT_EQUAL_STRING("SELECT api.fn_upstream_cache_put($1, $2, $3, $4) AS is_written", g_pqfakeLastCommand);
  TEST_ASSERT_EQUAL_STRING(CONTRASTAPI_VERSION ":t-key|{\"e\":1}|true|90", g_pqfakeLastParamLog);
}

void test_put_sends_false_for_a_body_that_is_not_an_error(void)
{
  static_queueOneCell("is_written", "t");

  TEST_ASSERT_TRUE(cache_dbPut(PQFAKE_CONN, "t-key", "{}", false, 1));
  TEST_ASSERT_EQUAL_STRING(CONTRASTAPI_VERSION ":t-key|{}|false|1", g_pqfakeLastParamLog);
}

void test_put_fails_for_a_null_connection_and_an_expiry_of_zero(void)
{
  static_queueOneCell("is_written", "t");

  TEST_ASSERT_FALSE(cache_dbPut(NULL, "t-key", "{}", false, 60));
  TEST_ASSERT_FALSE(cache_dbPut(PQFAKE_CONN, "t-key", "{}", false, 0));
  TEST_ASSERT_EQUAL_INT(0, g_pqfakeCallCount);
}

void test_put_refuses_a_body_past_the_longest(void)
{
  static_queueOneCell("is_written", "t");

  TEST_ASSERT_FALSE(cache_dbPut(PQFAKE_CONN, "t-key", static_longText(CACHE_MAX_BODY_LEN + 1), false, 60));
  TEST_ASSERT_EQUAL_INT(0, g_pqfakeCallCount);
  TEST_ASSERT_TRUE(cache_dbPut(PQFAKE_CONN, "t-key", static_longText(CACHE_MAX_BODY_LEN), false, 60));
  TEST_ASSERT_EQUAL_STRING(CONTRASTAPI_VERSION ":t-key|<1048576 bytes>|false|60", g_pqfakeLastParamLog);
}

void test_put_refuses_a_key_past_the_longest(void)
{
  static_queueOneCell("is_written", "t");

  char key[CACHE_KEY_MAX_LEN + 1];
  memset(key, 'k', sizeof(key));
  key[CACHE_KEY_MAX_LEN - static_versionPrefixLen() + 1] = '\0';
  TEST_ASSERT_FALSE(cache_dbPut(PQFAKE_CONN, key, "{}", false, 60));
  TEST_ASSERT_EQUAL_INT(0, g_pqfakeCallCount);
}

void test_put_refuses_an_empty_key(void)
{
  static_queueOneCell("is_written", "t");

  TEST_ASSERT_FALSE(cache_dbPut(PQFAKE_CONN, "", "{}", false, 60));
  TEST_ASSERT_EQUAL_INT(0, g_pqfakeCallCount);
}

void test_put_fails_when_the_query_fails(void)
{
  TEST_ASSERT_FALSE(cache_dbPut(PQFAKE_CONN, "t-key", "{}", false, 60));
  TEST_ASSERT_EQUAL_INT(1, g_pqfakeCallCount);
}

void test_put_fails_when_the_column_has_another_name(void)
{
  static_queueOneCell("fn_upstream_cache_put", "t");

  TEST_ASSERT_FALSE(cache_dbPut(PQFAKE_CONN, "t-key", "{}", false, 60));
}

void test_put_fails_for_no_row_and_for_two_rows(void)
{
  PqFakeAnswer_t no_row   = { PGRES_TUPLES_OK, 1, 0, { "is_written" }, { NULL } };
  PqFakeAnswer_t two_rows = { PGRES_TUPLES_OK, 1, 2, { "is_written" }, { "t" } };
  pqfake_queue(&no_row);
  pqfake_queue(&two_rows);

  TEST_ASSERT_FALSE(cache_dbPut(PQFAKE_CONN, "t-key", "{}", false, 60));
  TEST_ASSERT_FALSE(cache_dbPut(PQFAKE_CONN, "t-key", "{}", false, 60));
  TEST_ASSERT_EQUAL_INT(2, g_pqfakeCallCount);
}

void test_put_fails_when_the_row_is_not_written(void)
{
  static_queueOneCell("is_written", "f");
  static_queueOneCell("is_written", NULL);

  TEST_ASSERT_FALSE(cache_dbPut(PQFAKE_CONN, "t-key", "{}", false, 60));
  TEST_ASSERT_FALSE(cache_dbPut(PQFAKE_CONN, "t-key", "{}", false, 60));
  TEST_ASSERT_EQUAL_INT(2, g_pqfakeCallCount);
}

void test_entry_free_frees_the_body_and_zeroes_the_entry(void)
{
  static_queueGetRow("{}", "t", TEST_FETCHED_AT);

  CacheEntry_t entry = { 0 };
  TEST_ASSERT_EQUAL_INT(CACHE_HIT, cache_dbGet(PQFAKE_CONN, "t-key", &entry));
  cache_entryFree(&entry);
  TEST_ASSERT_NULL(entry.mp_body);
  TEST_ASSERT_FALSE(entry.m_isError);
  TEST_ASSERT_EQUAL_STRING("", entry.ma_fetchedAt);
}

void test_purge_sends_the_batch_and_fails_when_the_query_fails(void)
{
  static_queueOneCell("purged_row_count", "3");

  TEST_ASSERT_TRUE(cache_dbPurgeExpiredRows(PQFAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("SELECT api.fn_upstream_cache_purge($1) AS purged_row_count", g_pqfakeLastCommand);
  TEST_ASSERT_EQUAL_STRING("10000", g_pqfakeLastParamLog);
  TEST_ASSERT_FALSE(cache_dbPurgeExpiredRows(PQFAKE_CONN));
}

void test_purge_runs_again_after_a_full_batch(void)
{
  static_queueOneCell("purged_row_count", "10000");
  static_queueOneCell("purged_row_count", "0");

  TEST_ASSERT_TRUE(cache_dbPurgeExpiredRows(PQFAKE_CONN));
  TEST_ASSERT_EQUAL_STRING("fn_upstream_cache_purge fn_upstream_cache_purge ", g_pqfakeCallLog);
}

void test_key_refusal_line_holds_no_part_of_the_key(void)
{
  char key[CACHE_KEY_MAX_LEN + 1];
  memset(key, 'Z', sizeof(key));
  key[CACHE_KEY_MAX_LEN - static_versionPrefixLen() + 1] = '\0';
  char text[1024];
  CacheEntry_t entry = { 0 };

  pqfake_beginStderrCapture();
  CacheStatus_t status = cache_dbGet(PQFAKE_CONN, key, &entry);
  pqfake_endStderrCapture(text, sizeof(text));

  TEST_ASSERT_EQUAL_INT(CACHE_ERROR, status);
  TEST_ASSERT_EQUAL_STRING("static_writeVersionedKey: key longer than CACHE_KEY_MAX_LEN\n", text);
}

void test_fetched_at_field_holds_the_text_and_its_nul(void)
{
  CacheEntry_t entry;

  TEST_ASSERT_EQUAL_size_t(21, sizeof(entry.ma_fetchedAt));
}

void test_each_refusal_writes_its_own_stderr_line(void)
{
  char text[256];
  CacheEntry_t entry = { 0 };

  pqfake_beginStderrCapture();
  CacheStatus_t status = cache_dbGet(NULL, "t-key", &entry);
  pqfake_endStderrCapture(text, sizeof(text));
  TEST_ASSERT_EQUAL_INT(CACHE_ERROR, status);
  TEST_ASSERT_EQUAL_STRING("cache_dbGet: no database connection\n", text);

  pqfake_beginStderrCapture();
  bool is_written = cache_dbPut(NULL, "t-key", "{}", false, 60);
  pqfake_endStderrCapture(text, sizeof(text));
  TEST_ASSERT_FALSE(is_written);
  TEST_ASSERT_EQUAL_STRING("cache_dbPut: no database connection\n", text);

  pqfake_beginStderrCapture();
  is_written = cache_dbPut(PQFAKE_CONN, "t-key", "{}", false, 0);
  pqfake_endStderrCapture(text, sizeof(text));
  TEST_ASSERT_FALSE(is_written);
  TEST_ASSERT_EQUAL_STRING("cache_dbPut: expires_after_seconds is 0\n", text);

  pqfake_beginStderrCapture();
  is_written = cache_dbPut(PQFAKE_CONN, "t-key", static_longText(CACHE_MAX_BODY_LEN + 1), false, 60);
  pqfake_endStderrCapture(text, sizeof(text));
  TEST_ASSERT_FALSE(is_written);
  TEST_ASSERT_EQUAL_STRING("cache_dbPut: body longer than CACHE_MAX_BODY_LEN\n", text);
  TEST_ASSERT_EQUAL_INT(0, g_pqfakeCallCount);
}

void test_failed_purge_names_the_purge_function(void)
{
  char text[512];

  pqfake_beginStderrCapture();
  bool is_purged = cache_dbPurgeExpiredRows(PQFAKE_CONN);
  pqfake_endStderrCapture(text, sizeof(text));

  TEST_ASSERT_FALSE(is_purged);
  TEST_ASSERT_EQUAL_STRING("dbhelper_executeQueryFrom: cache_dbPurgeExpiredRows: query failed "
                           "(status no result, sqlstate none, connection ok)\n", text);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(32, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_get_sends_the_versioned_key_and_answers_the_row);
  RUN_TEST(test_get_reads_an_error_body);
  RUN_TEST(test_get_answers_miss_for_no_row);
  RUN_TEST(test_get_fails_for_a_null_connection);
  RUN_TEST(test_get_refuses_a_key_past_the_longest);
  RUN_TEST(test_get_refuses_an_empty_key);
  RUN_TEST(test_get_fails_when_the_query_fails);
  RUN_TEST(test_get_fails_for_an_empty_answer_with_other_column_names);
  RUN_TEST(test_get_fails_for_a_row_with_other_column_names);
  RUN_TEST(test_get_fails_for_two_rows);
  RUN_TEST(test_get_fails_for_a_null_body);
  RUN_TEST(test_get_refuses_a_body_past_the_longest);
  RUN_TEST(test_get_fails_for_a_null_flag);
  RUN_TEST(test_get_fails_for_a_fetched_at_past_its_field);
  RUN_TEST(test_put_sends_the_four_parameters);
  RUN_TEST(test_put_sends_false_for_a_body_that_is_not_an_error);
  RUN_TEST(test_put_fails_for_a_null_connection_and_an_expiry_of_zero);
  RUN_TEST(test_put_refuses_a_body_past_the_longest);
  RUN_TEST(test_put_refuses_a_key_past_the_longest);
  RUN_TEST(test_put_refuses_an_empty_key);
  RUN_TEST(test_put_fails_when_the_query_fails);
  RUN_TEST(test_put_fails_when_the_column_has_another_name);
  RUN_TEST(test_put_fails_for_no_row_and_for_two_rows);
  RUN_TEST(test_put_fails_when_the_row_is_not_written);
  RUN_TEST(test_entry_free_frees_the_body_and_zeroes_the_entry);
  RUN_TEST(test_purge_sends_the_batch_and_fails_when_the_query_fails);
  RUN_TEST(test_purge_runs_again_after_a_full_batch);
  RUN_TEST(test_key_refusal_line_holds_no_part_of_the_key);
  RUN_TEST(test_fetched_at_field_holds_the_text_and_its_nul);
  RUN_TEST(test_each_refusal_writes_its_own_stderr_line);
  RUN_TEST(test_failed_purge_names_the_purge_function);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
