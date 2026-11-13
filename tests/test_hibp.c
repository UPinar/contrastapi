#include <stdio.h>
#include <string.h>

#include "unity/unity.h"
#include "external/hibp.h"
#include "http_stub.h"

#define PASSWORD_SUFFIX "1E4C9B93F3F0682250B6CF8331B7EE68FD8"

static const char HIBP_PASSWORD_RANGE_BODY[] =
  "003D68EB55068C33ACE09247EE4C639306B:3\r\n"
  "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n"
  "1E4D1B4C29A30E7D4B07A8EC7E1F7CAC0F8:0\r\n"
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:12\r\n";

static unsigned int g_retryAfterSeconds;

void setUp(void)
{
  g_stub_http_call_count  = 0;
  g_stub_last_url[0]      = '\0';
  g_stub_last_header[0]   = '\0';
  g_stub_next_status      = 200;
  g_stub_next_body        = NULL;
  g_stub_next_body_null   = false;
  g_stub_last_timeout_ms  = -1;
  g_stub_answers          = NULL;
  g_stub_answer_count     = 0;
  g_retryAfterSeconds     = 7;
}

void tearDown(void) {}

static bool static_tryReadPasswordBreachCount(const char* body, uint64_t* breach_count_out)
{
  return hibp_tryReadBreachCount(body, strlen(body), PASSWORD_SUFFIX, breach_count_out);
}

void test_tryReadBreachCount_finds_the_suffix_and_reads_its_count(void)
{
  uint64_t breach_count = 0;
  TEST_ASSERT_TRUE(static_tryReadPasswordBreachCount(HIBP_PASSWORD_RANGE_BODY, &breach_count));
  TEST_ASSERT_EQUAL_UINT64(3861493, breach_count);
}

void test_tryReadBreachCount_suffix_not_in_the_body_is_count_zero(void)
{
  uint64_t breach_count = 99;
  TEST_ASSERT_TRUE(hibp_tryReadBreachCount(HIBP_PASSWORD_RANGE_BODY, strlen(HIBP_PASSWORD_RANGE_BODY), "0000000000000000000000000000000000A", &breach_count));
  TEST_ASSERT_EQUAL_UINT64(0, breach_count);
}

void test_tryReadBreachCount_padding_line_is_count_zero(void)
{
  uint64_t breach_count = 99;
  TEST_ASSERT_TRUE(hibp_tryReadBreachCount(HIBP_PASSWORD_RANGE_BODY, strlen(HIBP_PASSWORD_RANGE_BODY), "1E4D1B4C29A30E7D4B07A8EC7E1F7CAC0F8", &breach_count));
  TEST_ASSERT_EQUAL_UINT64(0, breach_count);
}

void test_tryReadBreachCount_reads_lines_ended_by_a_line_feed_alone(void)
{
  uint64_t breach_count = 0;
  TEST_ASSERT_TRUE(static_tryReadPasswordBreachCount("003D68EB55068C33ACE09247EE4C639306B:3\n" PASSWORD_SUFFIX ":7\n", &breach_count));
  TEST_ASSERT_EQUAL_UINT64(7, breach_count);
}

void test_tryReadBreachCount_reads_a_last_line_without_a_line_end(void)
{
  uint64_t breach_count = 0;
  TEST_ASSERT_TRUE(static_tryReadPasswordBreachCount("003D68EB55068C33ACE09247EE4C639306B:3\r\n" PASSWORD_SUFFIX ":7", &breach_count));
  TEST_ASSERT_EQUAL_UINT64(7, breach_count);
}

void test_tryReadBreachCount_matches_a_lower_case_line(void)
{
  uint64_t breach_count = 0;
  TEST_ASSERT_TRUE(static_tryReadPasswordBreachCount("1e4c9b93f3f0682250b6cf8331b7ee68fd8:5\r\n", &breach_count));
  TEST_ASSERT_EQUAL_UINT64(5, breach_count);
}

void test_tryReadBreachCount_largest_count_is_read(void)
{
  uint64_t breach_count = 0;
  TEST_ASSERT_TRUE(static_tryReadPasswordBreachCount(PASSWORD_SUFFIX ":18446744073709551615\r\n", &breach_count));
  TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, breach_count);
}

void test_tryReadBreachCount_matching_line_with_a_bad_count_is_unreadable(void)
{
  static const char* const bad_counts[] = {
    PASSWORD_SUFFIX ":\r\n", PASSWORD_SUFFIX ":-1\r\n", PASSWORD_SUFFIX ":+1\r\n",
    PASSWORD_SUFFIX ": 1\r\n", PASSWORD_SUFFIX ":1 \r\n", PASSWORD_SUFFIX ":1a\r\n",
    PASSWORD_SUFFIX ":18446744073709551616\r\n", PASSWORD_SUFFIX "\r\n",
    PASSWORD_SUFFIX "0:1\r\n",
  };
  for (size_t i = 0; i < sizeof(bad_counts) / sizeof(bad_counts[0]); i++)
  {
    char body[128];
    snprintf(body, sizeof(body), "003D68EB55068C33ACE09247EE4C639306B:3\r\n%s", bad_counts[i]);
    uint64_t breach_count = 0;
    TEST_ASSERT_FALSE_MESSAGE(static_tryReadPasswordBreachCount(body, &breach_count), bad_counts[i]);
  }
}

void test_tryReadBreachCount_skips_an_unreadable_line_of_another_suffix(void)
{
  uint64_t breach_count = 0;
  TEST_ASSERT_TRUE(static_tryReadPasswordBreachCount("003D68EB55068C33ACE09247EE4C639306:3\r\n"
                                             "003D68EB55068C33ACE09247EE4C639306BB:3\r\n"
                                             "ZZZ\r\n"
                                             "\r\n" PASSWORD_SUFFIX ":9\r\n", &breach_count));
  TEST_ASSERT_EQUAL_UINT64(9, breach_count);
  TEST_ASSERT_TRUE(static_tryReadPasswordBreachCount("003D68EB55068C33ACE09247EE4C639306B:3\r\nZZZ", &breach_count));
  TEST_ASSERT_EQUAL_UINT64(0, breach_count);
}

void test_tryReadBreachCount_colon_one_byte_off_is_unreadable(void)
{
  uint64_t breach_count = 0;
  TEST_ASSERT_FALSE(static_tryReadPasswordBreachCount("003D68EB55068C33ACE09247EE4C639306:3\r\n", &breach_count));
  TEST_ASSERT_FALSE(static_tryReadPasswordBreachCount("003D68EB55068C33ACE09247EE4C639306BB:3\r\n", &breach_count));
}

void test_tryReadBreachCount_suffix_with_a_byte_that_is_not_hex_is_unreadable(void)
{
  uint64_t breach_count = 0;
  TEST_ASSERT_FALSE(static_tryReadPasswordBreachCount("003D68EB55068C33ACE09247EE4C639306G:3\r\n", &breach_count));
}

void test_tryReadBreachCount_body_without_a_readable_line_is_unreadable(void)
{
  uint64_t breach_count = 0;
  TEST_ASSERT_FALSE(static_tryReadPasswordBreachCount("", &breach_count));
  TEST_ASSERT_FALSE(static_tryReadPasswordBreachCount("{}", &breach_count));
  TEST_ASSERT_FALSE(static_tryReadPasswordBreachCount("\r\n\r\n", &breach_count));
}

void test_tryReadBreachCount_body_with_a_nul_byte_is_unreadable(void)
{
  static const char body[] = "003D68EB55068C33ACE09247EE4C639306B:3\r\n\0" PASSWORD_SUFFIX ":9\r\n";
  static const char body_ending_in_nul[] = "003D68EB55068C33ACE09247EE4C639306B:3\r\n\0";
  uint64_t breach_count = 0;
  TEST_ASSERT_FALSE(hibp_tryReadBreachCount(body, sizeof(body) - 1, PASSWORD_SUFFIX, &breach_count));
  TEST_ASSERT_FALSE(hibp_tryReadBreachCount(body_ending_in_nul, sizeof(body_ending_in_nul) - 1, PASSWORD_SUFFIX, &breach_count));
}

void test_check_sends_only_the_prefix_and_asks_for_padding(void)
{
  PASSWORDCHECKRecord_t record;
  g_stub_next_body = HIBP_PASSWORD_RANGE_BODY;
  TEST_ASSERT_EQUAL_INT(HIBP_OK, hibp_check("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", &record, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("https://api.pwnedpasswords.com/range/5BAA6", g_stub_last_url);
  TEST_ASSERT_EQUAL_STRING("Add-Padding: true", g_stub_last_header);
  TEST_ASSERT_EQUAL_INT(5000, g_stub_last_timeout_ms);
  TEST_ASSERT_TRUE(g_stub_requests[0].m_isTargetTrusted);
  TEST_ASSERT_EQUAL_STRING("Retry-After", g_stub_requests[0].ma_headerNamesToCapture);
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
}

void test_check_refuses_a_value_that_is_not_a_sha1_hash(void)
{
  static const char* const bad_hashes[] = {
    "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FDG", "5BAA6", "",
  };
  for (size_t i = 0; i < sizeof(bad_hashes) / sizeof(bad_hashes[0]); i++)
  {
    PASSWORDCHECKRecord_t record;
    memset(&record, 'x', sizeof(record));
    TEST_ASSERT_EQUAL_INT_MESSAGE(HIBP_INVALID_HASH, hibp_check(bad_hashes[i], &record, &g_retryAfterSeconds), bad_hashes[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_http_call_count, bad_hashes[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", record.ma_hashPrefix, bad_hashes[i]);
  }
}

void test_check_found_hash(void)
{
  PASSWORDCHECKRecord_t record;
  g_stub_next_body = HIBP_PASSWORD_RANGE_BODY;
  TEST_ASSERT_EQUAL_INT(HIBP_OK, hibp_check("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", &record, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_STRING("5BAA6", record.ma_hashPrefix);
  TEST_ASSERT_EQUAL_UINT64(3861493, record.m_breachCount);
}

void test_check_found_hash_sent_in_lower_case(void)
{
  PASSWORDCHECKRecord_t record;
  g_stub_next_body = HIBP_PASSWORD_RANGE_BODY;
  TEST_ASSERT_EQUAL_INT(HIBP_OK, hibp_check("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", &record, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT64(3861493, record.m_breachCount);
}

void test_check_hash_not_found(void)
{
  PASSWORDCHECKRecord_t record;
  g_stub_next_body = HIBP_PASSWORD_RANGE_BODY;
  TEST_ASSERT_EQUAL_INT(HIBP_OK, hibp_check("5BAA60000000000000000000000000000000000A", &record, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_STRING("5BAA6", record.ma_hashPrefix);
  TEST_ASSERT_EQUAL_UINT64(0, record.m_breachCount);
}

void test_check_padding_line_is_not_found(void)
{
  PASSWORDCHECKRecord_t record;
  g_stub_next_body = HIBP_PASSWORD_RANGE_BODY;
  TEST_ASSERT_EQUAL_INT(HIBP_OK, hibp_check("5BAA61E4D1B4C29A30E7D4B07A8EC7E1F7CAC0F8", &record, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT64(0, record.m_breachCount);
}

void test_check_upstream_failure_is_an_error(void)
{
  static const int failing_statuses[] = { 0, 206, 404, 503 };
  for (size_t i = 0; i < sizeof(failing_statuses) / sizeof(failing_statuses[0]); i++)
  {
    PASSWORDCHECKRecord_t record;
    g_stub_next_body   = HIBP_PASSWORD_RANGE_BODY;
    g_stub_next_status = failing_statuses[i];
    TEST_ASSERT_EQUAL_INT_MESSAGE(HIBP_UPSTREAM_ERROR, hibp_check("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", &record, &g_retryAfterSeconds), "status");
    TEST_ASSERT_EQUAL_STRING("5BAA6", record.ma_hashPrefix);
    TEST_ASSERT_EQUAL_UINT64(0, record.m_breachCount);
    TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  }
}

void test_check_429_is_rate_limited_with_its_wait(void)
{
  static const char* const seconds_header[] = { "Retry-After: 120", NULL };
  static const char* const date_header[]    = { "Retry-After: Wed, 21 Oct 2026 07:28:00 GMT", NULL };
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 429, .mp_headerLines = seconds_header },
    { .m_status = 429 },
    { .m_status = 429, .mp_headerLines = date_header },
    { .m_status = 503, .mp_headerLines = seconds_header },
  };
  g_stub_answers      = answers;
  g_stub_answer_count = (int)(sizeof(answers) / sizeof(answers[0]));
  PASSWORDCHECKRecord_t record;
  TEST_ASSERT_EQUAL_INT(HIBP_RATE_LIMITED, hibp_check("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", &record, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT(120, g_retryAfterSeconds);
  TEST_ASSERT_EQUAL_STRING("5BAA6", record.ma_hashPrefix);
  TEST_ASSERT_EQUAL_INT(HIBP_RATE_LIMITED, hibp_check("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", &record, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT(60, g_retryAfterSeconds);
  TEST_ASSERT_EQUAL_INT(HIBP_RATE_LIMITED, hibp_check("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", &record, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT(60, g_retryAfterSeconds);
  TEST_ASSERT_EQUAL_INT(HIBP_UPSTREAM_ERROR, hibp_check("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", &record, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  TEST_ASSERT_EQUAL_INT(4, g_stub_http_call_count);
}

void test_check_keeps_the_default_body_cap(void)
{
  PASSWORDCHECKRecord_t record;
  g_stub_next_body = HIBP_PASSWORD_RANGE_BODY;
  TEST_ASSERT_EQUAL_INT(HIBP_OK, hibp_check("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", &record, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_size_t(0, g_stub_requests[0].m_maxBodyByteCount);
}

void test_check_no_body_is_an_error(void)
{
  PASSWORDCHECKRecord_t record;
  g_stub_next_body_null = true;
  TEST_ASSERT_EQUAL_INT(HIBP_UPSTREAM_ERROR, hibp_check("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", &record, &g_retryAfterSeconds));
}

void test_check_unreadable_body_is_an_error(void)
{
  PASSWORDCHECKRecord_t record;
  TEST_ASSERT_EQUAL_INT(HIBP_UPSTREAM_ERROR, hibp_check("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", &record, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT64(0, record.m_breachCount);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_tryReadBreachCount_finds_the_suffix_and_reads_its_count);
  RUN_TEST(test_tryReadBreachCount_suffix_not_in_the_body_is_count_zero);
  RUN_TEST(test_tryReadBreachCount_padding_line_is_count_zero);
  RUN_TEST(test_tryReadBreachCount_reads_lines_ended_by_a_line_feed_alone);
  RUN_TEST(test_tryReadBreachCount_reads_a_last_line_without_a_line_end);
  RUN_TEST(test_tryReadBreachCount_matches_a_lower_case_line);
  RUN_TEST(test_tryReadBreachCount_largest_count_is_read);
  RUN_TEST(test_tryReadBreachCount_matching_line_with_a_bad_count_is_unreadable);
  RUN_TEST(test_tryReadBreachCount_skips_an_unreadable_line_of_another_suffix);
  RUN_TEST(test_tryReadBreachCount_colon_one_byte_off_is_unreadable);
  RUN_TEST(test_tryReadBreachCount_suffix_with_a_byte_that_is_not_hex_is_unreadable);
  RUN_TEST(test_tryReadBreachCount_body_without_a_readable_line_is_unreadable);
  RUN_TEST(test_tryReadBreachCount_body_with_a_nul_byte_is_unreadable);
  RUN_TEST(test_check_sends_only_the_prefix_and_asks_for_padding);
  RUN_TEST(test_check_refuses_a_value_that_is_not_a_sha1_hash);
  RUN_TEST(test_check_found_hash);
  RUN_TEST(test_check_found_hash_sent_in_lower_case);
  RUN_TEST(test_check_hash_not_found);
  RUN_TEST(test_check_padding_line_is_not_found);
  RUN_TEST(test_check_upstream_failure_is_an_error);
  RUN_TEST(test_check_429_is_rate_limited_with_its_wait);
  RUN_TEST(test_check_keeps_the_default_body_cap);
  RUN_TEST(test_check_no_body_is_an_error);
  RUN_TEST(test_check_unreadable_body_is_an_error);
  return UNITY_END();
}
