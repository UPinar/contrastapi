#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <regex.h>

#include "unity/unity.h"
#include "external/abuseipdb.h"
#include "http_stub.h"

#define TEST_KEY  "0123456789abcdef!~"
#define TEST_IP   "192.0.2.7"
#define TEST_NOW  ((time_t)1800000000)

static const char ABUSEIPDB_FULL_BODY[] =
  "{\"data\":{\"ipAddress\":\"192.0.2.7\",\"isPublic\":true,\"ipVersion\":4,\"isWhitelisted\":false,"
  "\"abuseConfidenceScore\":37,\"countryCode\":\"US\",\"usageType\":\"Data Center/Web Hosting/Transit\","
  "\"isp\":\"Example ISP\",\"domain\":\"example.com\",\"hostnames\":[\"a.example.com\"],\"isTor\":false,"
  "\"totalReports\":5,\"numDistinctUsers\":3,\"lastReportedAt\":\"2026-11-01T10:00:00+00:00\","
  "\"extraKey\":{\"nested\":[1,2]}}}";

time_t __wrap_time(time_t* time_out);
time_t __wrap_time(time_t* time_out)
{
  if (time_out != NULL)
    *time_out = TEST_NOW;
  return TEST_NOW;
}

static unsigned int      g_retryAfterSeconds;
static AbuseIpDbReport_t g_report;

void setUp(void)
{
  g_retryAfterSeconds             = 7;
  g_stub_answers                  = NULL;
  g_stub_answer_count             = 0;
  g_stub_http_call_count          = 0;
  g_stub_last_url[0]              = '\0';
  g_stub_last_header[0]           = '\0';
  g_stub_next_status              = 200;
  g_stub_next_body                = NULL;
  g_stub_next_body_null           = false;
  g_stub_next_error               = HTTP_ERROR_NONE;
  g_stub_last_timeout_ms          = -1;
  g_stub_last_max_body_byte_count = 0;
  g_stub_last_is_target_trusted   = false;
  memset(g_stub_requests, 0, sizeof(g_stub_requests));
  memset(&g_report, 0x5A, sizeof(g_report));
}

void tearDown(void) {}

static AbuseIpDbStatus_t static_checkBody(const char* body)
{
  g_stub_next_body = body;
  return abuseipdb_checkAddress(TEST_KEY, TEST_IP, &g_report, &g_retryAfterSeconds);
}

static AbuseIpDbStatus_t static_checkStatus(int status)
{
  g_stub_next_status = status;
  return static_checkBody(ABUSEIPDB_FULL_BODY);
}

static unsigned int static_retryAfter429(const char* const* header_lines)
{
  HttpStubAnswer_t answer = { .m_status = 429, .mp_body = "{}", .mp_headerLines = header_lines };
  g_stub_answers          = &answer;
  g_stub_answer_count     = 1;
  g_stub_http_call_count  = 0;
  g_retryAfterSeconds     = 7;
  AbuseIpDbStatus_t status = abuseipdb_checkAddress(TEST_KEY, TEST_IP, &g_report, &g_retryAfterSeconds);
  g_stub_answers          = NULL;
  g_stub_answer_count     = 0;
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_RATE_LIMITED, status);
  return g_retryAfterSeconds;
}

static void static_assertReportEmpty(void)
{
  TEST_ASSERT_EQUAL_INT(0, g_report.m_abuseConfidenceScore);
  TEST_ASSERT_EQUAL_INT(0, g_report.m_reportCount);
  TEST_ASSERT_EQUAL_INT(0, g_report.m_distinctReporterCount);
  TEST_ASSERT_EQUAL_STRING("", g_report.ma_lastReportedAt);
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_WHITELIST_UNKNOWN, g_report.m_whitelist);
  TEST_ASSERT_EQUAL_STRING("", g_report.ma_usageType);
}

static char* static_makeRun(char byte, size_t count)
{
  char* run = malloc(count + 1);
  TEST_ASSERT_NOT_NULL(run);
  memset(run, byte, count);
  run[count] = '\0';
  return run;
}

void test_checkAddress_sends_the_check_url_and_the_key_header(void)
{
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, static_checkStatus(200));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("https://api.abuseipdb.com/api/v2/check?ipAddress=" TEST_IP "&maxAgeInDays=90", g_stub_requests[0].ma_url);
  TEST_ASSERT_EQUAL_STRING("Key: " TEST_KEY "\nAccept: application/json", g_stub_last_header);
}

void test_checkAddress_request_flags_timeout_cap_and_captures(void)
{
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, static_checkStatus(200));
  TEST_ASSERT_TRUE(g_stub_requests[0].m_isTargetTrusted);
  TEST_ASSERT_TRUE(g_stub_requests[0].m_isRedirectLeftToCaller);
  TEST_ASSERT_FALSE(g_stub_requests[0].m_isBodyCutAccepted);
  TEST_ASSERT_EQUAL_INT(3000, ABUSEIPDB_TIMEOUT_MS);
  TEST_ASSERT_EQUAL_INT(3000, g_stub_requests[0].m_timeoutMs);
  TEST_ASSERT_EQUAL_size_t(16384, ABUSEIPDB_MAX_BODY_BYTE_COUNT);
  TEST_ASSERT_EQUAL_size_t(16384, g_stub_requests[0].m_maxBodyByteCount);
  TEST_ASSERT_EQUAL_STRING("X-RateLimit-Reset\nRetry-After", g_stub_requests[0].ma_headerNamesToCapture);
}

void test_checkAddress_maps_each_status(void)
{
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, static_checkStatus(200));
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  g_retryAfterSeconds = 7;
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_KEY_REJECTED, static_checkStatus(401));
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  static_assertReportEmpty();
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_KEY_REJECTED, static_checkStatus(403));
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_RATE_LIMITED, static_checkStatus(429));
  TEST_ASSERT_EQUAL_UINT(60, g_retryAfterSeconds);
  static_assertReportEmpty();

  static const int statuses[] = { 404, 422, 500, 302, 201, 503 };
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
  {
    g_retryAfterSeconds = 7;
    TEST_ASSERT_EQUAL_INT(ABUSEIPDB_UNAVAILABLE, static_checkStatus(statuses[i]));
    TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
    static_assertReportEmpty();
  }
}

void test_checkAddress_transfer_failures_are_unavailable(void)
{
  g_stub_next_error = HTTP_ERROR_TIMEOUT;
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_UNAVAILABLE, static_checkStatus(200));
  static_assertReportEmpty();
  g_stub_next_error = HTTP_ERROR_BODY_TOO_LARGE;
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_UNAVAILABLE, static_checkStatus(200));
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
}

void test_checkAddress_body_at_the_cap_is_read(void)
{
  char* body = static_makeRun(' ', ABUSEIPDB_MAX_BODY_BYTE_COUNT);
  size_t len = strlen(ABUSEIPDB_FULL_BODY);
  memcpy(body, ABUSEIPDB_FULL_BODY, len);
  AbuseIpDbStatus_t status = static_checkBody(body);
  free(body);
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, status);
  TEST_ASSERT_EQUAL_INT(37, g_report.m_abuseConfidenceScore);
}

void test_rate_limited_wait_from_the_reset_time(void)
{
  static const char* const at_now[]    = { "X-RateLimit-Reset: 1800000000", "Retry-After: 30", NULL };
  static const char* const at_1[]      = { "X-RateLimit-Reset: 1800000001", NULL };
  static const char* const at_2[]      = { "X-RateLimit-Reset: 1800000002", NULL };
  static const char* const at_day[]    = { "X-RateLimit-Reset: 1800086400", NULL };
  static const char* const past_day[]  = { "X-RateLimit-Reset: 1800086401", NULL };
  static const char* const in_past[]   = { "X-RateLimit-Reset: 1700000000", "Retry-After: 30", NULL };
  TEST_ASSERT_EQUAL_UINT(1,     static_retryAfter429(at_now));
  TEST_ASSERT_EQUAL_UINT(1,     static_retryAfter429(at_1));
  TEST_ASSERT_EQUAL_UINT(2,     static_retryAfter429(at_2));
  TEST_ASSERT_EQUAL_UINT(86400, static_retryAfter429(at_day));
  TEST_ASSERT_EQUAL_UINT(86400, static_retryAfter429(past_day));
  TEST_ASSERT_EQUAL_UINT(1,     static_retryAfter429(in_past));
}

void test_rate_limited_wait_falls_back_to_retry_after_then_the_default(void)
{
  static const char* const garbage[]      = { "X-RateLimit-Reset: soon", "Retry-After: 120", NULL };
  static const char* const retry_only[]   = { "Retry-After: 120", NULL };
  static const char* const neither[]      = { "X-Other: 5", NULL };
  static const char* const both_garbage[] = { "X-RateLimit-Reset: -5", "Retry-After: soon", NULL };
  TEST_ASSERT_EQUAL_UINT(120, static_retryAfter429(garbage));
  TEST_ASSERT_EQUAL_UINT(120, static_retryAfter429(retry_only));
  TEST_ASSERT_EQUAL_UINT(60,  static_retryAfter429(neither));
  TEST_ASSERT_EQUAL_UINT(60,  static_retryAfter429(both_garbage));
}

void test_refused_keys_send_no_request(void)
{
  static const char* const keys[] = {
    "ab cd", "ab\x7f" "cd", "ab\x80" "cd", "ab\xff", "ab\rcd", "ab\ncd", "ab\r\nX-Evil: 1", "ab\tcd", "ab\x01", " abcd", "\nabcd", ""
  };
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
  {
    g_retryAfterSeconds = 7;
    TEST_ASSERT_EQUAL_INT_MESSAGE(ABUSEIPDB_KEY_REJECTED, abuseipdb_checkAddress(keys[i], TEST_IP, &g_report, &g_retryAfterSeconds), keys[i]);
    TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
    static_assertReportEmpty();
  }

  char* too_long = static_makeRun('k', ABUSEIPDB_KEY_MAX_LEN + 1);
  AbuseIpDbStatus_t status = abuseipdb_checkAddress(too_long, TEST_IP, &g_report, &g_retryAfterSeconds);
  free(too_long);
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_KEY_REJECTED, status);
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
}

void test_accepted_keys_are_sent_whole(void)
{
  TEST_ASSERT_EQUAL_INT(128, ABUSEIPDB_KEY_MAX_LEN);
  g_stub_next_body = ABUSEIPDB_FULL_BODY;
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, abuseipdb_checkAddress("!~", TEST_IP, &g_report, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_STRING("Key: !~\nAccept: application/json", g_stub_last_header);

  char* longest = static_makeRun('k', ABUSEIPDB_KEY_MAX_LEN);
  char  expected[256];
  snprintf(expected, sizeof(expected), "Key: %s\nAccept: application/json", longest);
  AbuseIpDbStatus_t status = abuseipdb_checkAddress(longest, TEST_IP, &g_report, &g_retryAfterSeconds);
  free(longest);
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, status);
  TEST_ASSERT_EQUAL_STRING(expected, g_stub_last_header);
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
}

void test_address_length_bounds(void)
{
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_UNAVAILABLE, abuseipdb_checkAddress(TEST_KEY, "", &g_report, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  static_assertReportEmpty();
  char* too_long = static_makeRun('1', 46);
  AbuseIpDbStatus_t status = abuseipdb_checkAddress(TEST_KEY, too_long, &g_report, &g_retryAfterSeconds);
  free(too_long);
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_UNAVAILABLE, status);
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);

  g_stub_next_body = ABUSEIPDB_FULL_BODY;
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, abuseipdb_checkAddress(TEST_KEY, "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255", &g_report, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_STRING("https://api.abuseipdb.com/api/v2/check?ipAddress=ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255&maxAgeInDays=90", g_stub_last_url);
}

void test_checkAddress_reads_each_field(void)
{
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, static_checkBody(ABUSEIPDB_FULL_BODY));
  TEST_ASSERT_EQUAL_INT(37, g_report.m_abuseConfidenceScore);
  TEST_ASSERT_EQUAL_INT(5,  g_report.m_reportCount);
  TEST_ASSERT_EQUAL_INT(3,  g_report.m_distinctReporterCount);
  TEST_ASSERT_EQUAL_STRING("2026-11-01T10:00:00+00:00", g_report.ma_lastReportedAt);
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_WHITELIST_NO, g_report.m_whitelist);
  TEST_ASSERT_EQUAL_STRING("Data Center/Web Hosting/Transit", g_report.ma_usageType);
}

void test_score_bounds_and_types(void)
{
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, static_checkBody("{\"data\":{\"abuseConfidenceScore\":0,\"totalReports\":0,\"numDistinctUsers\":0}}"));
  TEST_ASSERT_EQUAL_INT(0, g_report.m_abuseConfidenceScore);
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, static_checkBody("{\"data\":{\"abuseConfidenceScore\":100,\"totalReports\":1,\"numDistinctUsers\":1}}"));
  TEST_ASSERT_EQUAL_INT(100, g_report.m_abuseConfidenceScore);

  static const char* const bodies[] = {
    "{\"data\":{\"abuseConfidenceScore\":-1,\"totalReports\":1,\"numDistinctUsers\":1}}",
    "{\"data\":{\"abuseConfidenceScore\":101,\"totalReports\":1,\"numDistinctUsers\":1}}",
    "{\"data\":{\"abuseConfidenceScore\":\"5\",\"totalReports\":1,\"numDistinctUsers\":1}}",
    "{\"data\":{\"abuseConfidenceScore\":1.5,\"totalReports\":1,\"numDistinctUsers\":1}}",
    "{\"data\":{\"abuseConfidenceScore\":null,\"totalReports\":1,\"numDistinctUsers\":1}}",
    "{\"data\":{\"totalReports\":1,\"numDistinctUsers\":1}}",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT_MESSAGE(ABUSEIPDB_UNAVAILABLE, static_checkBody(bodies[i]), bodies[i]);
    static_assertReportEmpty();
  }
}

void test_count_bounds_and_types(void)
{
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, static_checkBody("{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":2147483647,\"numDistinctUsers\":2147483647}}"));
  TEST_ASSERT_EQUAL_INT(2147483647, g_report.m_reportCount);
  TEST_ASSERT_EQUAL_INT(2147483647, g_report.m_distinctReporterCount);
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, static_checkBody("{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":0,\"numDistinctUsers\":0}}"));
  TEST_ASSERT_EQUAL_INT(0, g_report.m_reportCount);
  TEST_ASSERT_EQUAL_INT(0, g_report.m_distinctReporterCount);

  static const char* const bodies[] = {
    "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":-1,\"numDistinctUsers\":1}}",
    "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":2147483648,\"numDistinctUsers\":1}}",
    "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":\"1\",\"numDistinctUsers\":1}}",
    "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":null,\"numDistinctUsers\":1}}",
    "{\"data\":{\"abuseConfidenceScore\":1,\"numDistinctUsers\":1}}",
    "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":1,\"numDistinctUsers\":-1}}",
    "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":1,\"numDistinctUsers\":2147483648}}",
    "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":1,\"numDistinctUsers\":true}}",
    "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":1,\"numDistinctUsers\":null}}",
    "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":1}}",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT_MESSAGE(ABUSEIPDB_UNAVAILABLE, static_checkBody(bodies[i]), bodies[i]);
    static_assertReportEmpty();
  }
}

void test_whitelist_is_tri_state(void)
{
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, static_checkBody("{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":1,\"numDistinctUsers\":1,\"isWhitelisted\":true}}"));
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_WHITELIST_YES, g_report.m_whitelist);
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, static_checkBody("{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":1,\"numDistinctUsers\":1,\"isWhitelisted\":false}}"));
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_WHITELIST_NO, g_report.m_whitelist);
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, static_checkBody("{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":1,\"numDistinctUsers\":1,\"isWhitelisted\":null}}"));
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_WHITELIST_UNKNOWN, g_report.m_whitelist);
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, static_checkBody("{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":1,\"numDistinctUsers\":1}}"));
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_WHITELIST_UNKNOWN, g_report.m_whitelist);
}

void test_null_or_missing_texts_are_empty(void)
{
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, static_checkBody("{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":0,\"numDistinctUsers\":0,\"lastReportedAt\":null,\"usageType\":null}}"));
  TEST_ASSERT_EQUAL_STRING("", g_report.ma_lastReportedAt);
  TEST_ASSERT_EQUAL_STRING("", g_report.ma_usageType);
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, static_checkBody("{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":0,\"numDistinctUsers\":0}}"));
  TEST_ASSERT_EQUAL_STRING("", g_report.ma_lastReportedAt);
  TEST_ASSERT_EQUAL_STRING("", g_report.ma_usageType);
}

void test_over_long_texts_are_left_out(void)
{
  TEST_ASSERT_EQUAL_INT(32, ABUSEIPDB_LAST_REPORTED_AT_MAX_LEN);
  TEST_ASSERT_EQUAL_INT(64, ABUSEIPDB_USAGE_TYPE_MAX_LEN);
  char* at_32 = static_makeRun('a', 32);
  char* at_33 = static_makeRun('a', 33);
  char* ut_64 = static_makeRun('u', 64);
  char* ut_65 = static_makeRun('u', 65);
  char  body[512];

  snprintf(body, sizeof(body), "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":0,\"numDistinctUsers\":0,\"lastReportedAt\":\"%s\",\"usageType\":\"%s\"}}", at_32, ut_64);
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, static_checkBody(body));
  TEST_ASSERT_EQUAL_STRING(at_32, g_report.ma_lastReportedAt);
  TEST_ASSERT_EQUAL_STRING(ut_64, g_report.ma_usageType);

  snprintf(body, sizeof(body), "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":0,\"numDistinctUsers\":0,\"lastReportedAt\":\"%s\",\"usageType\":\"%s\"}}", at_33, ut_65);
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, static_checkBody(body));
  TEST_ASSERT_EQUAL_STRING("", g_report.ma_lastReportedAt);
  TEST_ASSERT_EQUAL_STRING("", g_report.ma_usageType);
  TEST_ASSERT_EQUAL_INT(1, g_report.m_abuseConfidenceScore);

  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_OK, static_checkBody("{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":0,\"numDistinctUsers\":0,\"lastReportedAt\":\"a\\u0000\",\"usageType\":\"b\\u0000\"}}"));
  TEST_ASSERT_EQUAL_STRING("", g_report.ma_lastReportedAt);
  TEST_ASSERT_EQUAL_STRING("", g_report.ma_usageType);
  free(at_32);
  free(at_33);
  free(ut_64);
  free(ut_65);
}

void test_wrong_text_and_flag_types_are_unavailable(void)
{
  static const char* const bodies[] = {
    "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":0,\"numDistinctUsers\":0,\"lastReportedAt\":5}}",
    "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":0,\"numDistinctUsers\":0,\"lastReportedAt\":[]}}",
    "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":0,\"numDistinctUsers\":0,\"usageType\":false}}",
    "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":0,\"numDistinctUsers\":0,\"usageType\":{}}}",
    "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":0,\"numDistinctUsers\":0,\"isWhitelisted\":\"true\"}}",
    "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":0,\"numDistinctUsers\":0,\"isWhitelisted\":1}}",
    "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":0,\"numDistinctUsers\":0,\"lastReportedAt\":\"a\\qb\"}}",
    "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":0,\"numDistinctUsers\":0,\"usageType\":\"a\\u12\"}}",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT_MESSAGE(ABUSEIPDB_UNAVAILABLE, static_checkBody(bodies[i]), bodies[i]);
    static_assertReportEmpty();
  }
}

void test_unreadable_bodies_are_unavailable(void)
{
  static const char* const bodies[] = {
    "{}", "{\"data\":[]}", "{\"data\":null}", "{\"data\":\"x\"}", "[]", "not json", "",
    "{\"errors\":[{\"detail\":\"Authentication failed.\",\"status\":401}]}",
    "{\"data\":{\"abuseConfidenceScore\":1,\"totalReports\":0,\"numDistinctUsers\":0}} x",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT_MESSAGE(ABUSEIPDB_UNAVAILABLE, static_checkBody(bodies[i]), bodies[i]);
    static_assertReportEmpty();
  }
  g_stub_next_body_null = true;
  TEST_ASSERT_EQUAL_INT(ABUSEIPDB_UNAVAILABLE, static_checkBody(NULL));
}

void test_page_key_pattern_matches_isKeyAccepted(void)
{
  FILE* file = fopen("web/static/js/vendor_keys.js", "rb");
  TEST_ASSERT_NOT_NULL(file);
  static char script[65536];
  size_t script_len = fread(script, 1, sizeof(script) - 1, file);
  fclose(file);
  script[script_len] = '\0';
  const char* head = strstr(script, "    abuseipdb: /");
  TEST_ASSERT_NOT_NULL(head);
  head += strlen("    abuseipdb: /");
  const char* tail = strchr(head, '\n');
  TEST_ASSERT_NOT_NULL(tail);
  while (tail > head && tail[-1] != '/')
    tail--;
  TEST_ASSERT_TRUE(tail > head);
  tail--;
  char pattern[128];
  TEST_ASSERT_TRUE((size_t)(tail - head) < sizeof(pattern));
  snprintf(pattern, sizeof(pattern), "%.*s", (int)(tail - head), head);
  regex_t regex;
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB), pattern);

  char key[ABUSEIPDB_KEY_MAX_LEN + 2];
  for (int byte = 1; byte < 256; byte++)
  {
    key[0] = (char)byte;
    key[1] = '\0';
    TEST_ASSERT_EQUAL_INT_MESSAGE(abuseipdb_isKeyAccepted(key), regexec(&regex, key, 0, NULL, 0) == 0, pattern);
  }
  const size_t lengths[] = { 1, ABUSEIPDB_KEY_MAX_LEN, ABUSEIPDB_KEY_MAX_LEN + 1 };
  for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++)
  {
    memset(key, 'A', lengths[i]);
    key[lengths[i]] = '\0';
    TEST_ASSERT_EQUAL_INT_MESSAGE(abuseipdb_isKeyAccepted(key), regexec(&regex, key, 0, NULL, 0) == 0, pattern);
  }
  regfree(&regex);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(20, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_checkAddress_sends_the_check_url_and_the_key_header);
  RUN_TEST(test_checkAddress_request_flags_timeout_cap_and_captures);
  RUN_TEST(test_checkAddress_maps_each_status);
  RUN_TEST(test_checkAddress_transfer_failures_are_unavailable);
  RUN_TEST(test_checkAddress_body_at_the_cap_is_read);
  RUN_TEST(test_rate_limited_wait_from_the_reset_time);
  RUN_TEST(test_rate_limited_wait_falls_back_to_retry_after_then_the_default);
  RUN_TEST(test_refused_keys_send_no_request);
  RUN_TEST(test_accepted_keys_are_sent_whole);
  RUN_TEST(test_address_length_bounds);
  RUN_TEST(test_checkAddress_reads_each_field);
  RUN_TEST(test_score_bounds_and_types);
  RUN_TEST(test_count_bounds_and_types);
  RUN_TEST(test_whitelist_is_tri_state);
  RUN_TEST(test_null_or_missing_texts_are_empty);
  RUN_TEST(test_over_long_texts_are_left_out);
  RUN_TEST(test_wrong_text_and_flag_types_are_unavailable);
  RUN_TEST(test_unreadable_bodies_are_unavailable);
  RUN_TEST(test_page_key_pattern_matches_isKeyAccepted);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
