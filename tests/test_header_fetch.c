#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <curl/curl.h>

#include "unity/unity.h"
#include "header_fetch.h"
#include "http_stub.h"

#define TEST_HEADER_NAMES_JOINED "Content-Security-Policy\nStrict-Transport-Security\nX-Content-Type-Options\nX-Frame-Options\nReferrer-Policy\nPermissions-Policy\nX-XSS-Protection\nSet-Cookie\nAccess-Control-Allow-Origin\nContent-Security-Policy-Report-Only\nAccess-Control-Allow-Credentials"

static const char* const TEST_FIRST_HEADER_LINES[] = { "Strict-Transport-Security: max-age=11", "X-Frame-Options: SAMEORIGIN", NULL };
static const char* const TEST_LAST_HEADER_LINES[]  = { "strict-transport-security: max-age=22; includeSubDomains", "X-FRAME-OPTIONS: DENY", NULL };

#define TEST_CLOCK_MAX_READING_COUNT 16

static int64_t g_clockReadings[TEST_CLOCK_MAX_READING_COUNT];
static int     g_clockReadingCount = 0;
static int     g_clockReadIndex    = 0;

int64_t __wrap_monotonic_nowMs(void)
{
  int index = g_clockReadIndex < g_clockReadingCount ? g_clockReadIndex : g_clockReadingCount - 1;
  g_clockReadIndex++;
  return g_clockReadings[index];
}

static int g_curlUrlCallCount      = 0;
static int g_curlUrlGetCallCount   = 0;
static int g_curlUrlFailingCall    = -1;
static int g_curlUrlGetFailingCall = -1;

CURLU*    __real_curl_url(void);
CURLUcode __real_curl_url_get(const CURLU* url, CURLUPart part, char** text_out, unsigned int flags);

CURLU* __wrap_curl_url(void)
{
  if (g_curlUrlCallCount++ == g_curlUrlFailingCall)
    return NULL;
  return __real_curl_url();
}

CURLUcode __wrap_curl_url_get(const CURLU* url, CURLUPart part, char** text_out, unsigned int flags)
{
  if (g_curlUrlGetCallCount++ == g_curlUrlGetFailingCall)
    return CURLUE_OUT_OF_MEMORY;
  return __real_curl_url_get(url, part, text_out, flags);
}

static void static_setClockReadings(const int64_t* readings, int count)
{
  memcpy(g_clockReadings, readings, (size_t)count * sizeof(readings[0]));
  g_clockReadingCount = count;
  g_clockReadIndex    = 0;
}

void setUp(void)
{
  g_stub_http_call_count = 0;
  memset(g_stub_requests, 0, sizeof(g_stub_requests));
  g_stub_answers         = NULL;
  g_stub_answer_count    = 0;
  g_stub_next_status     = 200;
  g_stub_next_body       = NULL;
  g_stub_next_body_null  = false;
  g_stub_next_error      = HTTP_ERROR_NONE;

  static const int64_t still_clock[] = { 1000 };
  static_setClockReadings(still_clock, 1);

  g_curlUrlCallCount      = 0;
  g_curlUrlGetCallCount   = 0;
  g_curlUrlFailingCall    = -1;
  g_curlUrlGetFailingCall = -1;
}

void tearDown(void) {}

static void static_setAnswers(const HttpStubAnswer_t* answers, int count)
{
  g_stub_answers      = answers;
  g_stub_answer_count = count;
}

static HttpError_t static_fetch(const char* hostname, HeaderFetchResult_t* result_out)
{
  memset(result_out, 0xA5, sizeof(*result_out));
  return header_fetch_fetchHomePage(hostname, result_out);
}

static void static_assertZeroedResult(const HeaderFetchResult_t* result)
{
  TEST_ASSERT_EQUAL_INT(0, result->m_httpStatus);
  TEST_ASSERT_NULL(result->mp_url);
  TEST_ASSERT_EQUAL_INT(0, result->m_followedRedirectCount);
  TEST_ASSERT_NULL(result->mp_unfollowedRedirectUrl);
  TEST_ASSERT_NULL(result->mp_capturedHeaderValues);
  TEST_ASSERT_EQUAL_INT(0, result->m_capturedHeaderValueCount);
  TEST_ASSERT_EQUAL_size_t(0, result->m_setCookieCopyCount);
}

static void static_assertFetchFlags(int request_count)
{
  for (int i = 0; i < request_count; i++)
  {
    const HttpStubRequest_t* request = &g_stub_requests[i];
    TEST_ASSERT_EQUAL_STRING(TEST_HEADER_NAMES_JOINED, request->ma_headerNamesToCapture);
    TEST_ASSERT_EQUAL_size_t(65536, request->m_maxBodyByteCount);
    TEST_ASSERT_FALSE(request->m_isTargetTrusted);
    TEST_ASSERT_TRUE(request->m_isHttpsOnly);
    TEST_ASSERT_TRUE(request->m_isRedirectLeftToCaller);
    TEST_ASSERT_TRUE(request->m_isBodyCutAccepted);
    TEST_ASSERT_EQUAL_UINT16(443, request->m_requiredPort);
  }
}

void test_answer_without_redirect_is_kept_after_one_request(void)
{
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 203, .mp_body = "<html>", .mp_headerLines = TEST_LAST_HEADER_LINES },
  };
  static_setAnswers(answers, 1);

  HeaderFetchResult_t result;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetch("example.com", &result));

  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("https://example.com/", g_stub_requests[0].ma_url);
  TEST_ASSERT_EQUAL_INT(5000, g_stub_requests[0].m_timeoutMs);
  static_assertFetchFlags(1);

  TEST_ASSERT_EQUAL_INT(203, result.m_httpStatus);
  TEST_ASSERT_EQUAL_STRING("https://example.com/", result.mp_url);
  TEST_ASSERT_EQUAL_INT(0, result.m_followedRedirectCount);
  TEST_ASSERT_NULL(result.mp_unfollowedRedirectUrl);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_HEADER_COUNT, result.m_capturedHeaderValueCount);
  for (int i = 0; i < HEADER_CHECK_HEADER_COUNT; i++)
  {
    if (i == HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY)
      TEST_ASSERT_EQUAL_STRING("max-age=22; includeSubDomains", result.mp_capturedHeaderValues[i]);
    else if (i == HEADER_CHECK_HEADER_X_FRAME_OPTIONS)
      TEST_ASSERT_EQUAL_STRING("DENY", result.mp_capturedHeaderValues[i]);
    else
      TEST_ASSERT_NULL(result.mp_capturedHeaderValues[i]);
  }
  header_fetch_resultFree(&result);
  static_assertZeroedResult(&result);
}

void test_cut_answer_without_headers_keeps_a_null_value_for_each_name(void)
{
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 404, .mp_body = "not found", .m_isBodyCut = true },
  };
  static_setAnswers(answers, 1);

  HeaderFetchResult_t result;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetch("example.com", &result));
  TEST_ASSERT_EQUAL_INT(404, result.m_httpStatus);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_HEADER_COUNT, result.m_capturedHeaderValueCount);
  for (int i = 0; i < HEADER_CHECK_HEADER_COUNT; i++)
    TEST_ASSERT_NULL(result.mp_capturedHeaderValues[i]);
  header_fetch_resultFree(&result);
}

void test_bare_name_follows_its_www_name_and_keeps_the_last_answer(void)
{
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 301, .mp_redirectUrl = "https://www.example.com/home?session=abc#top", .mp_headerLines = TEST_FIRST_HEADER_LINES, .m_setCookieCopyCount = 3 },
    { .m_status = 202, .mp_headerLines = TEST_LAST_HEADER_LINES, .m_setCookieCopyCount = 60 },
  };
  static_setAnswers(answers, 2);

  HeaderFetchResult_t result;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetch("example.com", &result));

  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("https://example.com/", g_stub_requests[0].ma_url);
  TEST_ASSERT_EQUAL_STRING("https://www.example.com/home?session=abc", g_stub_requests[1].ma_url);
  static_assertFetchFlags(2);

  TEST_ASSERT_EQUAL_INT(202, result.m_httpStatus);
  TEST_ASSERT_EQUAL_STRING("https://www.example.com/home", result.mp_url);
  TEST_ASSERT_EQUAL_INT(1, result.m_followedRedirectCount);
  TEST_ASSERT_NULL(result.mp_unfollowedRedirectUrl);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_HEADER_COUNT, result.m_capturedHeaderValueCount);
  TEST_ASSERT_EQUAL_STRING("max-age=22; includeSubDomains", result.mp_capturedHeaderValues[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY]);
  TEST_ASSERT_EQUAL_STRING("DENY", result.mp_capturedHeaderValues[HEADER_CHECK_HEADER_X_FRAME_OPTIONS]);
  TEST_ASSERT_EQUAL_size_t(60, result.m_setCookieCopyCount);
  header_fetch_resultFree(&result);
  static_assertZeroedResult(&result);
}

void test_www_pair_and_same_host_are_followed_in_any_case(void)
{
  static const struct {
    const char* mp_hostname;
    const char* mp_target;
    const char* mp_nextUrl;
  } cases[] = {
    { "www.example.com", "https://EXAMPLE.com/",                   "https://EXAMPLE.com/" },
    { "WWW.Example.com", "https://example.COM/a",                  "https://example.COM/a" },
    { "example.com",     "https://Example.COM/b?x=1",              "https://Example.COM/b?x=1" },
    { "Example.com",     "https://WWW.example.COM/c",              "https://WWW.example.COM/c" },
    { "example.com",     "https://example.com:443/d",              "https://example.com/d" },
    { "example.com",     "https://user:secret@www.example.com/e",  "https://www.example.com/e" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    HttpStubAnswer_t answers[] = {
      { .m_status = 302, .mp_redirectUrl = cases[i].mp_target },
      { .m_status = 200 },
    };
    static_setAnswers(answers, 2);
    g_stub_http_call_count = 0;

    HeaderFetchResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(HTTP_ERROR_NONE, static_fetch(cases[i].mp_hostname, &result), cases[i].mp_target);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, g_stub_http_call_count, cases[i].mp_target);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_nextUrl, g_stub_requests[1].ma_url, cases[i].mp_target);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, result.m_followedRedirectCount, cases[i].mp_target);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, result.m_httpStatus, cases[i].mp_target);
    TEST_ASSERT_NULL_MESSAGE(result.mp_unfollowedRedirectUrl, cases[i].mp_target);
    header_fetch_resultFree(&result);
  }
}

static HttpError_t static_fetchChain(int redirect_count, HttpStubAnswer_t last_answer, HeaderFetchResult_t* result_out)
{
  static const char* const targets[] = {
    "https://example.com/1", "https://example.com/2", "https://example.com/3", "https://example.com/4",
    "https://example.com/5", "https://example.com/6", "https://example.com/7",
  };
  static HttpStubAnswer_t answers[HTTP_STUB_MAX_REQUEST_COUNT];
  TEST_ASSERT_TRUE(redirect_count < HTTP_STUB_MAX_REQUEST_COUNT);
  for (int i = 0; i < redirect_count; i++)
    answers[i] = (HttpStubAnswer_t){ .m_status = 307, .mp_redirectUrl = targets[i], .mp_headerLines = TEST_FIRST_HEADER_LINES };
  answers[redirect_count] = last_answer;
  static_setAnswers(answers, redirect_count + 1);
  return static_fetch("example.com", result_out);
}

void test_four_and_five_redirects_are_followed(void)
{
  static const struct { int m_followedRedirectCount; const char* mp_url; } cases[] = {
    { 4, "https://example.com/4" },
    { 5, "https://example.com/5" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    g_stub_http_call_count = 0;
    HeaderFetchResult_t result;
    TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchChain(cases[i].m_followedRedirectCount, (HttpStubAnswer_t){ .m_status = 200, .mp_headerLines = TEST_LAST_HEADER_LINES }, &result));
    TEST_ASSERT_EQUAL_INT(cases[i].m_followedRedirectCount + 1, g_stub_http_call_count);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_url, g_stub_requests[cases[i].m_followedRedirectCount].ma_url);
    static_assertFetchFlags(cases[i].m_followedRedirectCount + 1);
    TEST_ASSERT_EQUAL_INT(200, result.m_httpStatus);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_url, result.mp_url);
    TEST_ASSERT_EQUAL_INT(cases[i].m_followedRedirectCount, result.m_followedRedirectCount);
    TEST_ASSERT_NULL(result.mp_unfollowedRedirectUrl);
    TEST_ASSERT_FALSE(result.m_isRedirectLimitReached);
    TEST_ASSERT_EQUAL_STRING("DENY", result.mp_capturedHeaderValues[HEADER_CHECK_HEADER_X_FRAME_OPTIONS]);
    header_fetch_resultFree(&result);
  }
}

void test_sixth_redirect_is_kept_with_its_target(void)
{
  HeaderFetchResult_t result;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchChain(6, (HttpStubAnswer_t){ .m_status = 200 }, &result));
  TEST_ASSERT_EQUAL_INT(6, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("https://example.com/5", g_stub_requests[5].ma_url);
  TEST_ASSERT_EQUAL_INT(307, result.m_httpStatus);
  TEST_ASSERT_EQUAL_STRING("https://example.com/5", result.mp_url);
  TEST_ASSERT_EQUAL_INT(5, result.m_followedRedirectCount);
  TEST_ASSERT_EQUAL_STRING("https://example.com/6", result.mp_unfollowedRedirectUrl);
  TEST_ASSERT_TRUE(result.m_isRedirectLimitReached);
  TEST_ASSERT_EQUAL_STRING("SAMEORIGIN", result.mp_capturedHeaderValues[HEADER_CHECK_HEADER_X_FRAME_OPTIONS]);
  header_fetch_resultFree(&result);
}

void test_target_off_the_site_after_five_redirects_is_not_the_limit(void)
{
  HeaderFetchResult_t result;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchChain(5, (HttpStubAnswer_t){ .m_status = 308, .mp_redirectUrl = "https://other.example/x" }, &result));
  TEST_ASSERT_EQUAL_INT(6, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(308, result.m_httpStatus);
  TEST_ASSERT_EQUAL_INT(5, result.m_followedRedirectCount);
  TEST_ASSERT_EQUAL_STRING("https://other.example/x", result.mp_unfollowedRedirectUrl);
  TEST_ASSERT_FALSE(result.m_isRedirectLimitReached);
  header_fetch_resultFree(&result);
}

void test_redirect_off_the_site_is_kept_with_its_target(void)
{
  static const struct { const char* mp_target; const char* mp_unfollowedRedirectUrl; } cases[] = {
    { "https://other.example/x?q=1#f",           "https://other.example/x" },
    { "http://example.com/",                     "http://example.com/" },
    { "http://www.example.com/p?token=t",        "http://www.example.com/p" },
    { "https://example.com:8443/a?b=2",          "https://example.com:8443/a" },
    { "https://www.example.com:444/",            "https://www.example.com:444/" },
    { "https://user:secret@other.example/",      "https://other.example/" },
    { "https://other.example:443/y",             "https://other.example/y" },
    { "https://www.www.example.com/",            "https://www.www.example.com/" },
    { "https://example.com.evil.example/",       "https://example.com.evil.example/" },
    { "https://wwwexample.com/",                 "https://wwwexample.com/" },
    { "https://example.com:4430/",               "https://example.com:4430/" },
    { "http://example.com:443/",                 "http://example.com:443/" },
    { "https://www.example/",                    "https://www.example/" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    HttpStubAnswer_t answers[] = {
      { .m_status = 308, .mp_redirectUrl = cases[i].mp_target, .mp_headerLines = TEST_FIRST_HEADER_LINES },
      { .m_status = 200 },
    };
    static_setAnswers(answers, 2);
    g_stub_http_call_count = 0;

    HeaderFetchResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(HTTP_ERROR_NONE, static_fetch("example.com", &result), cases[i].mp_target);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_http_call_count, cases[i].mp_target);
    TEST_ASSERT_EQUAL_INT_MESSAGE(308, result.m_httpStatus, cases[i].mp_target);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("https://example.com/", result.mp_url, cases[i].mp_target);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, result.m_followedRedirectCount, cases[i].mp_target);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_unfollowedRedirectUrl, result.mp_unfollowedRedirectUrl, cases[i].mp_target);
    TEST_ASSERT_FALSE_MESSAGE(result.m_isRedirectLimitReached, cases[i].mp_target);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("max-age=11", result.mp_capturedHeaderValues[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY], cases[i].mp_target);
    header_fetch_resultFree(&result);
  }
}

void test_www_name_does_not_follow_a_second_www(void)
{
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 301, .mp_redirectUrl = "https://www.www.example.com/" },
    { .m_status = 200 },
  };
  static_setAnswers(answers, 2);

  HeaderFetchResult_t result;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetch("www.example.com", &result));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(301, result.m_httpStatus);
  TEST_ASSERT_EQUAL_STRING("https://www.example.com/", result.mp_url);
  TEST_ASSERT_EQUAL_STRING("https://www.www.example.com/", result.mp_unfollowedRedirectUrl);
  header_fetch_resultFree(&result);
}

void test_redirect_without_a_target_libcurl_reads_is_kept_without_one(void)
{
  static const HttpStubAnswer_t cases[] = {
    { .m_status = 302 },
    { .m_status = 303, .m_isBodyCut = true },
    { .m_status = 301, .mp_redirectUrl = "https://example.com/a b" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    HttpStubAnswer_t answers[] = { cases[i], { .m_status = 200 } };
    static_setAnswers(answers, 2);
    g_stub_http_call_count = 0;

    HeaderFetchResult_t result;
    TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetch("example.com", &result));
    TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
    TEST_ASSERT_EQUAL_INT(cases[i].m_status, result.m_httpStatus);
    TEST_ASSERT_EQUAL_STRING("https://example.com/", result.mp_url);
    TEST_ASSERT_EQUAL_INT(0, result.m_followedRedirectCount);
    TEST_ASSERT_NULL(result.mp_unfollowedRedirectUrl);
    header_fetch_resultFree(&result);
  }
}

void test_requests_share_one_deadline_and_none_is_sent_after_it(void)
{
  static const int64_t readings[] = { 1000, 1000, 3500, 5999, 6000 };
  static_setClockReadings(readings, 5);

  HeaderFetchResult_t result;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_TIMEOUT, static_fetchChain(5, (HttpStubAnswer_t){ .m_status = 200 }, &result));
  TEST_ASSERT_EQUAL_INT(3, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(5000, g_stub_requests[0].m_timeoutMs);
  TEST_ASSERT_EQUAL_INT(2500, g_stub_requests[1].m_timeoutMs);
  TEST_ASSERT_EQUAL_INT(1, g_stub_requests[2].m_timeoutMs);
  static_assertZeroedResult(&result);
}

void test_failed_request_writes_no_url_and_keeps_its_error(void)
{
  static const int64_t readings[] = { 1000, 1000, 7000 };
  static_setClockReadings(readings, 3);
  g_curlUrlGetFailingCall = 4;

  HeaderFetchResult_t result;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_TIMEOUT, static_fetchChain(1, (HttpStubAnswer_t){ .m_status = 200 }, &result));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  static_assertZeroedResult(&result);
}

void test_fetch_past_its_deadline_sends_no_request(void)
{
  static const int64_t readings[] = { 1000, 7000 };
  static_setClockReadings(readings, 2);

  HeaderFetchResult_t result;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_TIMEOUT, static_fetch("example.com", &result));
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
  static_assertZeroedResult(&result);
}

void test_request_error_is_the_error_of_the_fetch(void)
{
  static const HttpError_t errors[] = {
    HTTP_ERROR_TIMEOUT, HTTP_ERROR_RESOLVE, HTTP_ERROR_CONNECT, HTTP_ERROR_TLS,
    HTTP_ERROR_BODY_TOO_LARGE, HTTP_ERROR_BLOCKED, HTTP_ERROR_OTHER,
  };
  for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++)
  {
    HttpStubAnswer_t first_fails[] = { { .m_error = errors[i] } };
    static_setAnswers(first_fails, 1);
    g_stub_http_call_count = 0;
    HeaderFetchResult_t result;
    TEST_ASSERT_EQUAL_INT(errors[i], static_fetch("example.com", &result));
    TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
    static_assertZeroedResult(&result);

    HttpStubAnswer_t second_fails[] = {
      { .m_status = 301, .mp_redirectUrl = "https://www.example.com/", .mp_headerLines = TEST_FIRST_HEADER_LINES },
      { .m_error = errors[i] },
    };
    static_setAnswers(second_fails, 2);
    g_stub_http_call_count = 0;
    TEST_ASSERT_EQUAL_INT(errors[i], static_fetch("example.com", &result));
    TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
    static_assertZeroedResult(&result);
  }
}

void test_host_name_of_253_bytes_is_fetched_and_254_is_refused(void)
{
  char hostname[255];
  memset(hostname, 'a', 253);
  for (int i = 63; i < 253; i += 64)
    hostname[i] = '.';
  hostname[253] = '\0';
  char expected_url[sizeof("https:///") + 253];
  snprintf(expected_url, sizeof(expected_url), "https://%s/", hostname);

  static const HttpStubAnswer_t answers[] = { { .m_status = 200 } };
  static_setAnswers(answers, 1);
  HeaderFetchResult_t result;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetch(hostname, &result));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING(expected_url, g_stub_requests[0].ma_url);
  TEST_ASSERT_EQUAL_STRING(expected_url, result.mp_url);
  header_fetch_resultFree(&result);

  hostname[253] = 'a';
  hostname[254] = '\0';
  g_stub_http_call_count = 0;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, static_fetch(hostname, &result));
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
  static_assertZeroedResult(&result);
}

void test_host_name_libcurl_cannot_parse_sends_no_request(void)
{
  HeaderFetchResult_t result;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, static_fetch("exa mple.com", &result));
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
  static_assertZeroedResult(&result);
}

void test_url_handle_libcurl_cannot_make_fails_the_fetch(void)
{
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 301, .mp_redirectUrl = "https://www.example.com/", .mp_headerLines = TEST_FIRST_HEADER_LINES },
    { .m_status = 200 },
  };
  for (int failing_call = 0; failing_call < 2; failing_call++)
  {
    static_setAnswers(answers, 2);
    g_stub_http_call_count = 0;
    g_curlUrlCallCount     = 0;
    g_curlUrlFailingCall   = failing_call;
    HeaderFetchResult_t result;
    TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, static_fetch("example.com", &result));
    TEST_ASSERT_EQUAL_INT(failing_call, g_stub_http_call_count);
    static_assertZeroedResult(&result);
  }
}

void test_url_libcurl_cannot_write_fails_the_fetch(void)
{
  static const HttpStubAnswer_t no_redirect[] = { { .m_status = 200 } };
  static const HttpStubAnswer_t on_site[]     = { { .m_status = 301, .mp_redirectUrl = "https://www.example.com/" }, { .m_status = 200 } };
  static const HttpStubAnswer_t off_site[]    = { { .m_status = 301, .mp_redirectUrl = "https://other.example/" }, { .m_status = 200 } };
  static const struct {
    const HttpStubAnswer_t* mp_answers;
    int                     m_failingCall;
    int                     m_requestCount;
    const char*             mp_what;
  } cases[] = {
    { no_redirect, 0, 0, "the URL of the first request" },
    { no_redirect, 1, 1, "the URL the result shows" },
    { on_site,     4, 1, "the URL of the second request" },
    { on_site,     5, 2, "the URL the result shows after a redirect" },
    { off_site,    4, 1, "the target the result shows" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_setAnswers(cases[i].mp_answers, 2);
    g_stub_http_call_count  = 0;
    g_curlUrlGetCallCount   = 0;
    g_curlUrlGetFailingCall = cases[i].m_failingCall;
    HeaderFetchResult_t result;
    TEST_ASSERT_EQUAL_INT_MESSAGE(HTTP_ERROR_OTHER, static_fetch("example.com", &result), cases[i].mp_what);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_requestCount, g_stub_http_call_count, cases[i].mp_what);
    static_assertZeroedResult(&result);
  }
}

void test_target_at_the_limit_libcurl_cannot_write_fails_the_fetch(void)
{
  g_curlUrlGetFailingCall = 24;
  HeaderFetchResult_t result;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, static_fetchChain(6, (HttpStubAnswer_t){ .m_status = 200 }, &result));
  TEST_ASSERT_EQUAL_INT(6, g_stub_http_call_count);
  static_assertZeroedResult(&result);
}

void test_target_part_libcurl_cannot_hand_back_stops_the_fetch(void)
{
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 301, .mp_redirectUrl = "https://www.example.com/next" },
    { .m_status = 200 },
  };
  for (int failing_call = 1; failing_call <= 3; failing_call++)
  {
    static_setAnswers(answers, 2);
    g_stub_http_call_count  = 0;
    g_curlUrlGetCallCount   = 0;
    g_curlUrlGetFailingCall = failing_call;
    HeaderFetchResult_t result;
    TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetch("example.com", &result));
    TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
    TEST_ASSERT_EQUAL_INT(301, result.m_httpStatus);
    TEST_ASSERT_EQUAL_INT(0, result.m_followedRedirectCount);
    TEST_ASSERT_EQUAL_STRING("https://www.example.com/next", result.mp_unfollowedRedirectUrl);
    header_fetch_resultFree(&result);
  }
}

static void static_assertRobotsTxtFetchFlags(int request_count)
{
  for (int i = 0; i < request_count; i++)
  {
    const HttpStubRequest_t* request = &g_stub_requests[i];
    TEST_ASSERT_EQUAL_STRING("", request->ma_headerNamesToCapture);
    TEST_ASSERT_EQUAL_size_t(512 * 1024, request->m_maxBodyByteCount);
    TEST_ASSERT_FALSE(request->m_isTargetTrusted);
    TEST_ASSERT_TRUE(request->m_isHttpsOnly);
    TEST_ASSERT_TRUE(request->m_isRedirectLeftToCaller);
    TEST_ASSERT_TRUE(request->m_isBodyCutAccepted);
    TEST_ASSERT_EQUAL_UINT16(443, request->m_requiredPort);
  }
}

static void static_assertZeroedRobotsTxt(const HeaderFetchRobotsTxt_t* result)
{
  TEST_ASSERT_EQUAL_INT(0, result->m_httpStatus);
  TEST_ASSERT_NULL(result->mp_body);
  TEST_ASSERT_EQUAL_size_t(0, result->m_bodyLen);
  TEST_ASSERT_FALSE(result->m_isBodyCut);
}

void test_robots_txt_fetch_asks_robots_txt_and_keeps_the_body(void)
{
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 200, .mp_body = "User-agent: *\nDisallow: /x\n" },
  };
  static_setAnswers(answers, 1);

  HeaderFetchRobotsTxt_t result;
  memset(&result, 0xA5, sizeof(result));
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, header_fetch_fetchRobotsTxt("example.com", &result));

  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("https://example.com/robots.txt", g_stub_requests[0].ma_url);
  TEST_ASSERT_EQUAL_INT(5000, g_stub_requests[0].m_timeoutMs);
  static_assertRobotsTxtFetchFlags(1);

  TEST_ASSERT_EQUAL_INT(200, result.m_httpStatus);
  TEST_ASSERT_EQUAL_STRING("User-agent: *\nDisallow: /x\n", result.mp_body);
  TEST_ASSERT_EQUAL_size_t(strlen("User-agent: *\nDisallow: /x\n"), result.m_bodyLen);
  TEST_ASSERT_FALSE(result.m_isBodyCut);
  header_fetch_robotsTxtFree(&result);
  static_assertZeroedRobotsTxt(&result);
}

void test_robots_txt_fetch_fits_the_longest_host_name(void)
{
  char hostname[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  memset(hostname, 'a', VALIDATE_DOMAIN_NAME_MAX_LEN);
  hostname[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';
  for (int i = 63; i < VALIDATE_DOMAIN_NAME_MAX_LEN; i += 64)
    hostname[i] = '.';
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 200, .mp_body = "" },
  };
  static_setAnswers(answers, 1);

  HeaderFetchRobotsTxt_t result;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, header_fetch_fetchRobotsTxt(hostname, &result));
  char expected_url[sizeof("https:///robots.txt") + VALIDATE_DOMAIN_NAME_MAX_LEN];
  snprintf(expected_url, sizeof(expected_url), "https://%s/robots.txt", hostname);
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING(expected_url, g_stub_requests[0].ma_url);
  header_fetch_robotsTxtFree(&result);
}

void test_robots_txt_fetch_follows_its_www_pair_and_keeps_a_cut_body(void)
{
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 301, .mp_body = "", .mp_redirectUrl = "https://www.example.com/robots.txt" },
    { .m_status = 200, .mp_body = "User-agent: *\nAllow: /\n", .m_isBodyCut = true },
  };
  static_setAnswers(answers, 2);

  HeaderFetchRobotsTxt_t result;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, header_fetch_fetchRobotsTxt("example.com", &result));

  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("https://www.example.com/robots.txt", g_stub_requests[1].ma_url);
  static_assertRobotsTxtFetchFlags(2);
  TEST_ASSERT_EQUAL_INT(200, result.m_httpStatus);
  TEST_ASSERT_EQUAL_STRING("User-agent: *\nAllow: /\n", result.mp_body);
  TEST_ASSERT_EQUAL_size_t(strlen("User-agent: *\nAllow: /\n"), result.m_bodyLen);
  TEST_ASSERT_TRUE(result.m_isBodyCut);
  header_fetch_robotsTxtFree(&result);
}

void test_robots_txt_redirect_off_the_site_is_not_followed(void)
{
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 302, .mp_body = "moved", .mp_redirectUrl = "https://cdn.example.net/robots.txt" },
  };
  static_setAnswers(answers, 1);

  HeaderFetchRobotsTxt_t result;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, header_fetch_fetchRobotsTxt("example.com", &result));

  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(302, result.m_httpStatus);
  TEST_ASSERT_EQUAL_STRING("moved", result.mp_body);
  header_fetch_robotsTxtFree(&result);
}

void test_failed_robots_txt_fetch_keeps_nothing(void)
{
  static const HttpStubAnswer_t second_fails[] = {
    { .m_status = 301, .mp_body = "moved", .mp_redirectUrl = "https://www.example.com/robots.txt" },
    { .m_error = HTTP_ERROR_CONNECT },
  };
  static const HttpStubAnswer_t url_unwritten[] = {
    { .m_status = 200, .mp_body = "User-agent: *\nAllow: /\n" },
  };
  static const struct {
    const HttpStubAnswer_t* mp_answers;
    int                     m_answerCount;
    int                     m_failingCall;
    HttpError_t             m_error;
    int                     m_requestCount;
    const char*             mp_what;
  } cases[] = {
    { second_fails,  2, -1, HTTP_ERROR_CONNECT, 2, "a second request that fails" },
    { url_unwritten, 1, 1,  HTTP_ERROR_OTHER,   1, "a URL libcurl cannot write" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_setAnswers(cases[i].mp_answers, cases[i].m_answerCount);
    g_stub_http_call_count  = 0;
    g_curlUrlGetCallCount   = 0;
    g_curlUrlGetFailingCall = cases[i].m_failingCall;
    HeaderFetchRobotsTxt_t result;
    memset(&result, 0xA5, sizeof(result));
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_error, header_fetch_fetchRobotsTxt("example.com", &result), cases[i].mp_what);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_requestCount, g_stub_http_call_count, cases[i].mp_what);
    static_assertZeroedRobotsTxt(&result);
  }
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(26, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_answer_without_redirect_is_kept_after_one_request);
  RUN_TEST(test_cut_answer_without_headers_keeps_a_null_value_for_each_name);
  RUN_TEST(test_bare_name_follows_its_www_name_and_keeps_the_last_answer);
  RUN_TEST(test_www_pair_and_same_host_are_followed_in_any_case);
  RUN_TEST(test_four_and_five_redirects_are_followed);
  RUN_TEST(test_sixth_redirect_is_kept_with_its_target);
  RUN_TEST(test_target_off_the_site_after_five_redirects_is_not_the_limit);
  RUN_TEST(test_redirect_off_the_site_is_kept_with_its_target);
  RUN_TEST(test_www_name_does_not_follow_a_second_www);
  RUN_TEST(test_redirect_without_a_target_libcurl_reads_is_kept_without_one);
  RUN_TEST(test_requests_share_one_deadline_and_none_is_sent_after_it);
  RUN_TEST(test_failed_request_writes_no_url_and_keeps_its_error);
  RUN_TEST(test_fetch_past_its_deadline_sends_no_request);
  RUN_TEST(test_request_error_is_the_error_of_the_fetch);
  RUN_TEST(test_host_name_of_253_bytes_is_fetched_and_254_is_refused);
  RUN_TEST(test_host_name_libcurl_cannot_parse_sends_no_request);
  RUN_TEST(test_url_handle_libcurl_cannot_make_fails_the_fetch);
  RUN_TEST(test_url_libcurl_cannot_write_fails_the_fetch);
  RUN_TEST(test_target_at_the_limit_libcurl_cannot_write_fails_the_fetch);
  RUN_TEST(test_target_part_libcurl_cannot_hand_back_stops_the_fetch);
  RUN_TEST(test_robots_txt_fetch_asks_robots_txt_and_keeps_the_body);
  RUN_TEST(test_robots_txt_fetch_fits_the_longest_host_name);
  RUN_TEST(test_robots_txt_fetch_follows_its_www_pair_and_keeps_a_cut_body);
  RUN_TEST(test_robots_txt_redirect_off_the_site_is_not_followed);
  RUN_TEST(test_failed_robots_txt_fetch_keeps_nothing);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
