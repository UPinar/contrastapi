#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "unity/unity.h"
#include "external/wayback.h"
#include "http_stub.h"

static const char WAYBACK_TEST_ANSWER[] = R"([["timestamp","statuscode","mimetype"],
["20261024162230","200","text/html"],
["20240305010203","301","-"],
["20110607080910","-","application/pdf"]])";

#define WAYBACK_TEST_HEADER_ROW R"(["timestamp","statuscode","mimetype"])"

#define WAYBACK_TEST_CAPTURE_ROOM (WAYBACK_LATEST_CAPTURE_MAX_COUNT + 1)

static int64_t g_nowMs = 0;

int64_t __wrap_monotonic_nowMs(void)
{
  return g_nowMs;
}

static unsigned int g_retryAfterSeconds;

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
  g_nowMs                         = 1000000;
}

void tearDown(void) {}

static bool static_tryReadAnswer(const char* body, WaybackCapture_t captures_out[WAYBACK_LATEST_CAPTURE_MAX_COUNT], int* count_out)
{
  return wayback_tryReadCaptures(body, strlen(body), captures_out, WAYBACK_LATEST_CAPTURE_MAX_COUNT, count_out);
}

static bool static_tryReadOneRow(const char* row)
{
  char body[512];
  snprintf(body, sizeof(body), "[" WAYBACK_TEST_HEADER_ROW ",%s]", row);
  WaybackCapture_t captures[WAYBACK_LATEST_CAPTURE_MAX_COUNT];
  int              count = -1;
  return static_tryReadAnswer(body, captures, &count);
}

void test_tryReadCaptures_reads_each_field_of_each_row(void)
{
  WaybackCapture_t captures[WAYBACK_LATEST_CAPTURE_MAX_COUNT];
  int              count = -1;
  TEST_ASSERT_TRUE(static_tryReadAnswer(WAYBACK_TEST_ANSWER, captures, &count));
  TEST_ASSERT_EQUAL_INT(3, count);
  TEST_ASSERT_EQUAL_STRING("20261024162230", captures[0].ma_timestamp);
  TEST_ASSERT_EQUAL_INT(200, captures[0].m_httpStatus);
  TEST_ASSERT_EQUAL_STRING("text/html", captures[0].ma_mediaType);
  TEST_ASSERT_EQUAL_STRING("20240305010203", captures[1].ma_timestamp);
  TEST_ASSERT_EQUAL_INT(301, captures[1].m_httpStatus);
  TEST_ASSERT_EQUAL_STRING("", captures[1].ma_mediaType);
  TEST_ASSERT_EQUAL_STRING("20110607080910", captures[2].ma_timestamp);
  TEST_ASSERT_EQUAL_INT(0, captures[2].m_httpStatus);
  TEST_ASSERT_EQUAL_STRING("application/pdf", captures[2].ma_mediaType);
}

void test_tryReadCaptures_empty_list_and_header_alone_hold_no_capture(void)
{
  WaybackCapture_t captures[WAYBACK_LATEST_CAPTURE_MAX_COUNT];
  int              count = -1;
  TEST_ASSERT_TRUE(static_tryReadAnswer("[]", captures, &count));
  TEST_ASSERT_EQUAL_INT(0, count);

  count = -1;
  TEST_ASSERT_TRUE(static_tryReadAnswer("[" WAYBACK_TEST_HEADER_ROW "]", captures, &count));
  TEST_ASSERT_EQUAL_INT(0, count);
}

void test_tryReadCaptures_refuses_a_body_that_is_not_a_list_of_rows(void)
{
  WaybackCapture_t captures[WAYBACK_LATEST_CAPTURE_MAX_COUNT];
  int              count = -1;
  TEST_ASSERT_FALSE(static_tryReadAnswer("{}", captures, &count));
  TEST_ASSERT_FALSE(static_tryReadAnswer("[", captures, &count));
  TEST_ASSERT_FALSE(static_tryReadAnswer("[" WAYBACK_TEST_HEADER_ROW ",[\"20261024162230\",\"200\",\"text/html\"],]", captures, &count));
  TEST_ASSERT_FALSE(static_tryReadAnswer("[" WAYBACK_TEST_HEADER_ROW ",[\"20261024162230\",\"200\",\"text/html\"]", captures, &count));
  TEST_ASSERT_EQUAL_INT(0, count);
}

void test_tryReadCaptures_refuses_another_header_row(void)
{
  WaybackCapture_t captures[WAYBACK_LATEST_CAPTURE_MAX_COUNT];
  int              count = -1;
  TEST_ASSERT_FALSE(static_tryReadAnswer(R"([["statuscode","timestamp","mimetype"]])", captures, &count));
  TEST_ASSERT_FALSE(static_tryReadAnswer(R"([["timestamp","mimetype","statuscode"]])", captures, &count));
  TEST_ASSERT_FALSE(static_tryReadAnswer(R"([["timestamp","statuscode","digest"]])", captures, &count));
  TEST_ASSERT_FALSE(static_tryReadAnswer(R"([["timestamp","statuscode"]])", captures, &count));
  TEST_ASSERT_FALSE(static_tryReadAnswer(R"([["timestamp","statuscode","mimetype","digest"]])", captures, &count));
  TEST_ASSERT_FALSE(static_tryReadAnswer(R"(["timestamp"])", captures, &count));
}

void test_tryReadCaptures_reads_max_count_rows_and_refuses_one_more(void)
{
  char body[1024] = "[" WAYBACK_TEST_HEADER_ROW;
  for (int i = 0; i < WAYBACK_LATEST_CAPTURE_MAX_COUNT; i++)
  {
    size_t used = strlen(body);
    snprintf(body + used, sizeof(body) - used, ",[\"202610%02d000000\",\"200\",\"text/html\"]", i + 1);
  }
  size_t used = strlen(body);
  snprintf(body + used, sizeof(body) - used, "]");

  WaybackCapture_t captures[WAYBACK_LATEST_CAPTURE_MAX_COUNT + 1];
  int              count = -1;
  TEST_ASSERT_TRUE(static_tryReadAnswer(body, captures, &count));
  TEST_ASSERT_EQUAL_INT(WAYBACK_LATEST_CAPTURE_MAX_COUNT, count);
  TEST_ASSERT_EQUAL_STRING("20261010000000", captures[WAYBACK_LATEST_CAPTURE_MAX_COUNT - 1].ma_timestamp);

  body[strlen(body) - 1] = '\0';
  used = strlen(body);
  snprintf(body + used, sizeof(body) - used, ",[\"20261011000000\",\"200\",\"text/html\"]]");
  count = -1;
  TEST_ASSERT_FALSE(static_tryReadAnswer(body, captures, &count));
  TEST_ASSERT_EQUAL_INT(0, count);
}

void test_tryReadCaptures_a_row_holds_three_fields(void)
{
  TEST_ASSERT_TRUE(static_tryReadOneRow(R"(["20261024162230","200","text/html"])"));
  TEST_ASSERT_FALSE(static_tryReadOneRow(R"(["20261024162230","200"])"));
  TEST_ASSERT_FALSE(static_tryReadOneRow(R"(["20261024162230","200","text/html","x"])"));
  TEST_ASSERT_FALSE(static_tryReadOneRow(R"(["20261024162230","200","text/html",])"));
  TEST_ASSERT_FALSE(static_tryReadOneRow(R"("20261024162230")"));
}

void test_tryReadCaptures_time_is_fourteen_digits(void)
{
  TEST_ASSERT_FALSE(static_tryReadOneRow(R"(["2026102416223","200","text/html"])"));
  TEST_ASSERT_FALSE(static_tryReadOneRow(R"(["202610241622301","200","text/html"])"));
  TEST_ASSERT_FALSE(static_tryReadOneRow(R"(["x0261024162230","200","text/html"])"));
  TEST_ASSERT_FALSE(static_tryReadOneRow(R"(["2026102416223x","200","text/html"])"));
  TEST_ASSERT_FALSE(static_tryReadOneRow(R"([20261024162230,"200","text/html"])"));
}

void test_tryReadCaptures_status_is_a_dash_or_three_digits(void)
{
  TEST_ASSERT_FALSE(static_tryReadOneRow(R"(["20261024162230","20","text/html"])"));
  TEST_ASSERT_FALSE(static_tryReadOneRow(R"(["20261024162230","2000","text/html"])"));
  TEST_ASSERT_FALSE(static_tryReadOneRow(R"(["20261024162230","x00","text/html"])"));
  TEST_ASSERT_FALSE(static_tryReadOneRow(R"(["20261024162230","2x0","text/html"])"));
  TEST_ASSERT_FALSE(static_tryReadOneRow(R"(["20261024162230","20x","text/html"])"));
  TEST_ASSERT_FALSE(static_tryReadOneRow(R"(["20261024162230",200,"text/html"])"));
  TEST_ASSERT_FALSE(static_tryReadOneRow(R"(["20261024162230","","text/html"])"));
  TEST_ASSERT_FALSE(static_tryReadOneRow(R"(["20261024162230","-1","text/html"])"));
  TEST_ASSERT_FALSE(static_tryReadOneRow(R"(["20261024162230","--","text/html"])"));

  WaybackCapture_t captures[WAYBACK_LATEST_CAPTURE_MAX_COUNT];
  int              count = -1;
  TEST_ASSERT_TRUE(static_tryReadAnswer("[" WAYBACK_TEST_HEADER_ROW R"(,["20261024162230","599","text/html"]])", captures, &count));
  TEST_ASSERT_EQUAL_INT(599, captures[0].m_httpStatus);
}

void test_tryReadCaptures_leaves_out_a_media_type_that_does_not_fit(void)
{
  char media_type[WAYBACK_MEDIA_TYPE_MAX_LEN + 2];
  memset(media_type, 'a', sizeof(media_type) - 1);
  media_type[sizeof(media_type) - 1] = '\0';

  WaybackCapture_t captures[WAYBACK_LATEST_CAPTURE_MAX_COUNT];
  int              count = -1;
  char             body[512];
  snprintf(body, sizeof(body), "[" WAYBACK_TEST_HEADER_ROW ",[\"20261024162230\",\"200\",\"%s\"]]", media_type);
  TEST_ASSERT_TRUE(static_tryReadAnswer(body, captures, &count));
  TEST_ASSERT_EQUAL_INT(1, count);
  TEST_ASSERT_EQUAL_STRING("", captures[0].ma_mediaType);

  media_type[WAYBACK_MEDIA_TYPE_MAX_LEN] = '\0';
  snprintf(body, sizeof(body), "[" WAYBACK_TEST_HEADER_ROW ",[\"20261024162230\",\"200\",\"%s\"]]", media_type);
  TEST_ASSERT_TRUE(static_tryReadAnswer(body, captures, &count));
  TEST_ASSERT_EQUAL_STRING(media_type, captures[0].ma_mediaType);

  TEST_ASSERT_TRUE(static_tryReadAnswer("[" WAYBACK_TEST_HEADER_ROW R"(,["20261024162230","200",7]])", captures, &count));
  TEST_ASSERT_EQUAL_INT(1, count);
  TEST_ASSERT_EQUAL_STRING("", captures[0].ma_mediaType);

  TEST_ASSERT_TRUE(static_tryReadAnswer("[" WAYBACK_TEST_HEADER_ROW R"(,["20261024162230","200","-x"]])", captures, &count));
  TEST_ASSERT_EQUAL_STRING("-x", captures[0].ma_mediaType);
}

void test_lookupCaptures_newest_first_sends_a_trusted_request_for_the_host(void)
{
  g_stub_next_body = WAYBACK_TEST_ANSWER;
  WaybackCapture_t captures[WAYBACK_TEST_CAPTURE_ROOM];
  int              count = -1;
  TEST_ASSERT_EQUAL_INT(WAYBACK_OK, wayback_lookupCaptures("www.example.com", WAYBACK_ORDER_NEWEST_FIRST, WAYBACK_LATEST_CAPTURE_MAX_COUNT,
                                                           g_nowMs + WAYBACK_LOOKUP_DEADLINE_MS, captures, &count, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("https://web.archive.org/cdx/search/cdx?url=www.example.com&output=json&fl=timestamp,statuscode,mimetype"
                           "&collapse=timestamp:8&limit=10&sort=reverse", g_stub_last_url);
  TEST_ASSERT_EQUAL_STRING("", g_stub_last_header);
  TEST_ASSERT_EQUAL_INT(10000, g_stub_last_timeout_ms);
  TEST_ASSERT_EQUAL_size_t(64 * 1024, g_stub_last_max_body_byte_count);
  TEST_ASSERT_TRUE(g_stub_last_is_target_trusted);
  TEST_ASSERT_EQUAL_STRING("Retry-After", g_stub_requests[0].ma_headerNamesToCapture);
  TEST_ASSERT_EQUAL_INT(3, count);
  TEST_ASSERT_EQUAL_STRING("20110607080910", captures[2].ma_timestamp);
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
}

void test_lookupCaptures_oldest_first_does_not_sort_in_reverse(void)
{
  g_stub_next_body = "[" WAYBACK_TEST_HEADER_ROW R"(,["19981111184551","200","text/html"]])";
  WaybackCapture_t captures[WAYBACK_TEST_CAPTURE_ROOM];
  int              count = -1;
  TEST_ASSERT_EQUAL_INT(WAYBACK_OK, wayback_lookupCaptures("example.com", WAYBACK_ORDER_OLDEST_FIRST, 1, g_nowMs + 1500, captures, &count, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_STRING("https://web.archive.org/cdx/search/cdx?url=example.com&output=json&fl=timestamp,statuscode,mimetype"
                           "&collapse=timestamp:8&limit=1", g_stub_last_url);
  TEST_ASSERT_EQUAL_INT(1, count);
  TEST_ASSERT_EQUAL_STRING("19981111184551", captures[0].ma_timestamp);
}

void test_lookupCaptures_waits_until_the_deadline_and_at_most_ten_seconds(void)
{
  WaybackCapture_t captures[WAYBACK_TEST_CAPTURE_ROOM];
  int              count = -1;
  g_stub_next_body = "[]";

  TEST_ASSERT_EQUAL_INT(WAYBACK_OK, wayback_lookupCaptures("example.com", WAYBACK_ORDER_OLDEST_FIRST, 1, g_nowMs + 1, captures, &count, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(1, g_stub_last_timeout_ms);
  TEST_ASSERT_EQUAL_INT(WAYBACK_OK, wayback_lookupCaptures("example.com", WAYBACK_ORDER_OLDEST_FIRST, 1, g_nowMs + 9999, captures, &count, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(9999, g_stub_last_timeout_ms);
  TEST_ASSERT_EQUAL_INT(WAYBACK_OK, wayback_lookupCaptures("example.com", WAYBACK_ORDER_OLDEST_FIRST, 1, g_nowMs + 10001, captures, &count, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(10000, g_stub_last_timeout_ms);
  TEST_ASSERT_EQUAL_INT(WAYBACK_OK, wayback_lookupCaptures("example.com", WAYBACK_ORDER_OLDEST_FIRST, 1, g_nowMs + INT64_C(10000000000), captures, &count, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(10000, g_stub_last_timeout_ms);
  TEST_ASSERT_EQUAL_INT(4, g_stub_http_call_count);
}

void test_lookupCaptures_past_deadline_sends_no_request(void)
{
  WaybackCapture_t captures[WAYBACK_TEST_CAPTURE_ROOM];
  int              count = -1;
  TEST_ASSERT_EQUAL_INT(WAYBACK_UPSTREAM_ERROR, wayback_lookupCaptures("example.com", WAYBACK_ORDER_NEWEST_FIRST, 1, g_nowMs, captures, &count, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(WAYBACK_UPSTREAM_ERROR, wayback_lookupCaptures("example.com", WAYBACK_ORDER_NEWEST_FIRST, 1, g_nowMs - 1, captures, &count, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(0, count);
}

void test_lookupCaptures_429_is_rate_limited_with_its_wait(void)
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
  WaybackCapture_t captures[WAYBACK_TEST_CAPTURE_ROOM];
  int              count = -1;
  static const unsigned int waits[] = { 120, 60, 60 };
  for (size_t i = 0; i < sizeof(waits) / sizeof(waits[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT(WAYBACK_RATE_LIMITED, wayback_lookupCaptures("example.com", WAYBACK_ORDER_NEWEST_FIRST, WAYBACK_LATEST_CAPTURE_MAX_COUNT,
                                                                       g_nowMs + WAYBACK_LOOKUP_DEADLINE_MS, captures, &count, &g_retryAfterSeconds));
    TEST_ASSERT_EQUAL_UINT(waits[i], g_retryAfterSeconds);
    TEST_ASSERT_EQUAL_INT(0, count);
  }
  TEST_ASSERT_EQUAL_INT(WAYBACK_UPSTREAM_ERROR, wayback_lookupCaptures("example.com", WAYBACK_ORDER_NEWEST_FIRST, WAYBACK_LATEST_CAPTURE_MAX_COUNT,
                                                                       g_nowMs + WAYBACK_LOOKUP_DEADLINE_MS, captures, &count, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  TEST_ASSERT_EQUAL_INT(4, g_stub_http_call_count);
}

void test_lookupCaptures_other_answers_are_upstream_errors(void)
{
  WaybackCapture_t captures[WAYBACK_TEST_CAPTURE_ROOM];
  int              count = -1;
  const int64_t    deadline_ms = g_nowMs + WAYBACK_LOOKUP_DEADLINE_MS;

  g_stub_next_body   = WAYBACK_TEST_ANSWER;
  g_stub_next_status = 404;
  TEST_ASSERT_EQUAL_INT(WAYBACK_UPSTREAM_ERROR, wayback_lookupCaptures("example.com", WAYBACK_ORDER_NEWEST_FIRST, WAYBACK_LATEST_CAPTURE_MAX_COUNT, deadline_ms, captures, &count, &g_retryAfterSeconds));
  g_stub_next_status = 503;
  TEST_ASSERT_EQUAL_INT(WAYBACK_UPSTREAM_ERROR, wayback_lookupCaptures("example.com", WAYBACK_ORDER_NEWEST_FIRST, WAYBACK_LATEST_CAPTURE_MAX_COUNT, deadline_ms, captures, &count, &g_retryAfterSeconds));
  g_stub_next_status = 201;
  TEST_ASSERT_EQUAL_INT(WAYBACK_UPSTREAM_ERROR, wayback_lookupCaptures("example.com", WAYBACK_ORDER_NEWEST_FIRST, WAYBACK_LATEST_CAPTURE_MAX_COUNT, deadline_ms, captures, &count, &g_retryAfterSeconds));
  g_stub_next_status = 299;
  TEST_ASSERT_EQUAL_INT(WAYBACK_UPSTREAM_ERROR, wayback_lookupCaptures("example.com", WAYBACK_ORDER_NEWEST_FIRST, WAYBACK_LATEST_CAPTURE_MAX_COUNT, deadline_ms, captures, &count, &g_retryAfterSeconds));

  g_stub_next_status = 200;
  g_stub_next_body   = "{}";
  TEST_ASSERT_EQUAL_INT(WAYBACK_UPSTREAM_ERROR, wayback_lookupCaptures("example.com", WAYBACK_ORDER_NEWEST_FIRST, WAYBACK_LATEST_CAPTURE_MAX_COUNT, deadline_ms, captures, &count, &g_retryAfterSeconds));

  g_stub_next_body      = WAYBACK_TEST_ANSWER;
  g_stub_next_body_null = true;
  TEST_ASSERT_EQUAL_INT(WAYBACK_UPSTREAM_ERROR, wayback_lookupCaptures("example.com", WAYBACK_ORDER_NEWEST_FIRST, WAYBACK_LATEST_CAPTURE_MAX_COUNT, deadline_ms, captures, &count, &g_retryAfterSeconds));

  g_stub_next_body_null = false;
  g_stub_next_error     = HTTP_ERROR_TIMEOUT;
  TEST_ASSERT_EQUAL_INT(WAYBACK_UPSTREAM_ERROR, wayback_lookupCaptures("example.com", WAYBACK_ORDER_NEWEST_FIRST, WAYBACK_LATEST_CAPTURE_MAX_COUNT, deadline_ms, captures, &count, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(7, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(0, count);
}

void test_lookupCaptures_more_rows_than_the_limit_is_an_upstream_error(void)
{
  g_stub_next_body = WAYBACK_TEST_ANSWER;
  WaybackCapture_t captures[WAYBACK_TEST_CAPTURE_ROOM];
  int              count = -1;
  TEST_ASSERT_EQUAL_INT(WAYBACK_UPSTREAM_ERROR, wayback_lookupCaptures("example.com", WAYBACK_ORDER_NEWEST_FIRST, 2, g_nowMs + WAYBACK_LOOKUP_DEADLINE_MS, captures, &count, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(0, count);
}

void test_lookupCaptures_invalid_name_sends_no_request(void)
{
  WaybackCapture_t captures[WAYBACK_TEST_CAPTURE_ROOM];
  int              count = -1;
  TEST_ASSERT_EQUAL_INT(WAYBACK_INVALID_NAME, wayback_lookupCaptures("example.com&limit=99", WAYBACK_ORDER_NEWEST_FIRST, 1, g_nowMs + WAYBACK_LOOKUP_DEADLINE_MS, captures, &count, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(WAYBACK_INVALID_NAME, wayback_lookupCaptures("", WAYBACK_ORDER_NEWEST_FIRST, 1, g_nowMs + WAYBACK_LOOKUP_DEADLINE_MS, captures, &count, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(0, count);
}

void test_lookupCaptures_url_of_the_longest_name_is_sent(void)
{
  char name[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  for (int i = 0; i < VALIDATE_DOMAIN_NAME_MAX_LEN; i++)
    name[i] = (i % 64 == 63) ? '.' : 'a';
  name[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';

  g_stub_next_body = "[]";
  WaybackCapture_t captures[WAYBACK_TEST_CAPTURE_ROOM];
  int              count = -1;
  TEST_ASSERT_EQUAL_INT(WAYBACK_OK, wayback_lookupCaptures(name, WAYBACK_ORDER_NEWEST_FIRST, WAYBACK_LATEST_CAPTURE_MAX_COUNT,
                                                           g_nowMs + WAYBACK_LOOKUP_DEADLINE_MS, captures, &count, &g_retryAfterSeconds));
  char expected_url[1024];
  snprintf(expected_url, sizeof(expected_url), "https://web.archive.org/cdx/search/cdx?url=%s&output=json&fl=timestamp,statuscode,mimetype"
           "&collapse=timestamp:8&limit=10&sort=reverse", name);
  TEST_ASSERT_EQUAL_STRING(expected_url, g_stub_last_url);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_tryReadCaptures_reads_each_field_of_each_row);
  RUN_TEST(test_tryReadCaptures_empty_list_and_header_alone_hold_no_capture);
  RUN_TEST(test_tryReadCaptures_refuses_a_body_that_is_not_a_list_of_rows);
  RUN_TEST(test_tryReadCaptures_refuses_another_header_row);
  RUN_TEST(test_tryReadCaptures_reads_max_count_rows_and_refuses_one_more);
  RUN_TEST(test_tryReadCaptures_a_row_holds_three_fields);
  RUN_TEST(test_tryReadCaptures_time_is_fourteen_digits);
  RUN_TEST(test_tryReadCaptures_status_is_a_dash_or_three_digits);
  RUN_TEST(test_tryReadCaptures_leaves_out_a_media_type_that_does_not_fit);
  RUN_TEST(test_lookupCaptures_newest_first_sends_a_trusted_request_for_the_host);
  RUN_TEST(test_lookupCaptures_oldest_first_does_not_sort_in_reverse);
  RUN_TEST(test_lookupCaptures_waits_until_the_deadline_and_at_most_ten_seconds);
  RUN_TEST(test_lookupCaptures_past_deadline_sends_no_request);
  RUN_TEST(test_lookupCaptures_429_is_rate_limited_with_its_wait);
  RUN_TEST(test_lookupCaptures_other_answers_are_upstream_errors);
  RUN_TEST(test_lookupCaptures_more_rows_than_the_limit_is_an_upstream_error);
  RUN_TEST(test_lookupCaptures_invalid_name_sends_no_request);
  RUN_TEST(test_lookupCaptures_url_of_the_longest_name_is_sent);
  return UNITY_END();
}
