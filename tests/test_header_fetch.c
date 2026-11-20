#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <curl/curl.h>

#include "unity/unity.h"
#include "header_fetch.h"
#include "http_stub.h"

#define TEST_HEADER_NAMES_JOINED "Content-Security-Policy\nStrict-Transport-Security\nX-Content-Type-Options\nX-Frame-Options\nReferrer-Policy\nPermissions-Policy\nX-XSS-Protection\nSet-Cookie\nAccess-Control-Allow-Origin\nContent-Security-Policy-Report-Only\nAccess-Control-Allow-Credentials\nLocation\nRefresh"

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
CURLU*    __real_curl_url_dup(const CURLU* url);
CURLUcode __real_curl_url_get(const CURLU* url, CURLUPart part, char** text_out, unsigned int flags);

CURLU* __wrap_curl_url(void)
{
  if (g_curlUrlCallCount++ == g_curlUrlFailingCall)
    return NULL;
  return __real_curl_url();
}

CURLU* __wrap_curl_url_dup(const CURLU* url)
{
  if (g_curlUrlCallCount++ == g_curlUrlFailingCall)
    return NULL;
  return __real_curl_url_dup(url);
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

void test_unwritten_url_at_a_deadline_stop_fails_the_fetch(void)
{
  static const int64_t readings[] = { 1000, 1000, 7000 };
  static_setClockReadings(readings, 3);
  g_curlUrlGetFailingCall = 11;

  HeaderFetchResult_t result;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, static_fetchChain(1, (HttpStubAnswer_t){ .m_status = 200 }, &result));
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
    { no_redirect, 4,  1, "the URL the result shows" },
    { on_site,     7,  1, "the URL of the second request" },
    { on_site,     11, 2, "the URL the result shows after a redirect" },
    { off_site,    11, 1, "the target the result shows" },
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
  g_curlUrlGetFailingCall = 46;
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
  for (int failing_call = 8; failing_call <= 10; failing_call++)
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

void test_first_url_part_libcurl_cannot_hand_back_fails_the_fetch(void)
{
  static const HttpStubAnswer_t answers[] = { { .m_status = 200 } };
  for (int failing_call = 1; failing_call <= 3; failing_call++)
  {
    static_setAnswers(answers, 1);
    g_stub_http_call_count  = 0;
    g_curlUrlGetCallCount   = 0;
    g_curlUrlGetFailingCall = failing_call;
    HeaderFetchResult_t result;
    TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, static_fetch("example.com", &result));
    TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
    static_assertZeroedResult(&result);
  }
}

#define TEST_CHAIN_DEADLINE_MS 6000

#define TEST_PERMISSION_MAX_CALL_COUNT 4

typedef struct {
  HeaderFetchPermission_t  ma_answers[TEST_PERMISSION_MAX_CALL_COUNT];
  unsigned                 m_retryAfterSeconds;
  int                      m_callCount;
  char                     ma_hosts[TEST_PERMISSION_MAX_CALL_COUNT][64];
  char                     ma_pathsAndQueries[TEST_PERMISSION_MAX_CALL_COUNT][64];
  const void*              mp_seenContext;
} TestPermission_t;

static HeaderFetchPermission_t static_askTestPermission(void* permission_context, const HeaderFetchTarget_t* target, unsigned* retry_after_seconds_out)
{
  TestPermission_t* permission = permission_context;
  int call_index = permission->m_callCount++;
  TEST_ASSERT_TRUE(call_index < TEST_PERMISSION_MAX_CALL_COUNT);
  permission->mp_seenContext = permission_context;
  snprintf(permission->ma_hosts[call_index], sizeof(permission->ma_hosts[call_index]), "%s", target->mp_host);
  snprintf(permission->ma_pathsAndQueries[call_index], sizeof(permission->ma_pathsAndQueries[call_index]), "%s", target->mp_pathAndQuery);
  if (permission->ma_answers[call_index] == HEADER_FETCH_PERMISSION_THROTTLED)
    *retry_after_seconds_out = permission->m_retryAfterSeconds;
  return permission->ma_answers[call_index];
}

static HttpError_t static_runChain(const char* first_url, HeaderFetchHopRule_t hop_rule, const char* const* names, TestPermission_t* permission, HeaderFetchChain_t* chain_out)
{
  const HeaderFetchPolicy_t policy = {
    .m_hopRule                = hop_rule,
    .m_maxBodyByteCount       = 512 * 1024,
    .mp_headerNamesToCapture  = names,
    .m_askPermission          = permission != NULL ? static_askTestPermission : NULL,
    .mp_permissionContext     = permission,
  };
  memset(chain_out, 0xA5, sizeof(*chain_out));
  return header_fetch_fetchChain(first_url, &policy, TEST_CHAIN_DEADLINE_MS, chain_out);
}

static void static_assertZeroedChain(const HeaderFetchChain_t* chain)
{
  static const HeaderFetchChain_t zeroed_chain;
  TEST_ASSERT_EQUAL_MEMORY(&zeroed_chain, chain, sizeof(*chain));
}

static void static_assertSiteChainFlags(int request_count)
{
  for (int i = 0; i < request_count; i++)
  {
    const HttpStubRequest_t* request = &g_stub_requests[i];
    TEST_ASSERT_EQUAL_STRING("Location\nRefresh", request->ma_headerNamesToCapture);
    TEST_ASSERT_EQUAL_size_t(512 * 1024, request->m_maxBodyByteCount);
    TEST_ASSERT_EQUAL_INT(5000, request->m_timeoutMs);
    TEST_ASSERT_FALSE(request->m_isTargetTrusted);
    TEST_ASSERT_TRUE(request->m_isHttpsOnly);
    TEST_ASSERT_TRUE(request->m_isRedirectLeftToCaller);
    TEST_ASSERT_TRUE(request->m_isBodyCutAccepted);
    TEST_ASSERT_EQUAL_UINT16(443, request->m_requiredPort);
  }
}

void test_chain_asks_its_path_and_keeps_the_body(void)
{
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 200, .mp_body = "User-agent: *\nDisallow: /x\n" },
  };
  static_setAnswers(answers, 1);

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://example.com/robots.txt", HEADER_FETCH_HOP_RULE_SAME_SITE, NULL, NULL, &chain));

  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("https://example.com/robots.txt", g_stub_requests[0].ma_url);
  static_assertSiteChainFlags(1);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_FINAL_ANSWER, chain.m_stopReason);
  TEST_ASSERT_EQUAL_INT(1, chain.m_hopCount);
  TEST_ASSERT_EQUAL_STRING("https://example.com/robots.txt", chain.ma_hops[0].mp_url);
  TEST_ASSERT_EQUAL_INT(200, chain.ma_hops[0].m_httpStatus);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, chain.ma_hops[0].m_error);
  TEST_ASSERT_FALSE(chain.ma_hops[0].m_isUserInfoDropped);
  TEST_ASSERT_NULL(chain.ma_hops[0].mp_refresh);
  TEST_ASSERT_NULL(chain.mp_unfollowedUrl);
  TEST_ASSERT_NULL(chain.mp_invalidLocation);
  TEST_ASSERT_EQUAL_STRING("User-agent: *\nDisallow: /x\n", chain.mp_body);
  TEST_ASSERT_EQUAL_size_t(strlen("User-agent: *\nDisallow: /x\n"), chain.m_bodyLen);
  TEST_ASSERT_FALSE(chain.m_isBodyCut);
  TEST_ASSERT_NULL(chain.mp_capturedHeaderValues);
  TEST_ASSERT_EQUAL_INT(0, chain.m_capturedHeaderValueCount);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, header_fetch_chainError(&chain));
  header_fetch_chainFree(&chain);
  static_assertZeroedChain(&chain);
}

void test_chain_fits_the_longest_host_name(void)
{
  char hostname[VALIDATE_DOMAIN_NAME_MAX_LEN + 1];
  memset(hostname, 'a', VALIDATE_DOMAIN_NAME_MAX_LEN);
  hostname[VALIDATE_DOMAIN_NAME_MAX_LEN] = '\0';
  for (int i = 63; i < VALIDATE_DOMAIN_NAME_MAX_LEN; i += 64)
    hostname[i] = '.';
  char first_url[sizeof("https:///robots.txt") + VALIDATE_DOMAIN_NAME_MAX_LEN];
  snprintf(first_url, sizeof(first_url), "https://%s/robots.txt", hostname);
  static const HttpStubAnswer_t answers[] = { { .m_status = 200, .mp_body = "" } };
  static_setAnswers(answers, 1);

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain(first_url, HEADER_FETCH_HOP_RULE_SAME_SITE, NULL, NULL, &chain));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING(first_url, g_stub_requests[0].ma_url);
  TEST_ASSERT_EQUAL_STRING(first_url, chain.ma_hops[0].mp_url);
  header_fetch_chainFree(&chain);
}

void test_chain_follows_the_www_pair_and_keeps_a_cut_body(void)
{
  static const char* const redirect_lines[] = { "Location: https://www.example.com/robots.txt", NULL };
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 301, .mp_body = "", .mp_headerLines = redirect_lines },
    { .m_status = 200, .mp_body = "User-agent: *\nAllow: /\n", .m_isBodyCut = true },
  };
  static_setAnswers(answers, 2);

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://example.com/robots.txt", HEADER_FETCH_HOP_RULE_SAME_SITE, NULL, NULL, &chain));

  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("https://www.example.com/robots.txt", g_stub_requests[1].ma_url);
  static_assertSiteChainFlags(2);
  TEST_ASSERT_EQUAL_INT(2, chain.m_hopCount);
  TEST_ASSERT_EQUAL_INT(301, chain.ma_hops[0].m_httpStatus);
  TEST_ASSERT_EQUAL_INT(200, chain.ma_hops[1].m_httpStatus);
  TEST_ASSERT_EQUAL_STRING("https://www.example.com/robots.txt", chain.ma_hops[1].mp_url);
  TEST_ASSERT_EQUAL_STRING("User-agent: *\nAllow: /\n", chain.mp_body);
  TEST_ASSERT_EQUAL_size_t(strlen("User-agent: *\nAllow: /\n"), chain.m_bodyLen);
  TEST_ASSERT_TRUE(chain.m_isBodyCut);
  header_fetch_chainFree(&chain);
}

void test_chain_does_not_follow_a_redirect_off_the_site(void)
{
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 302, .mp_body = "moved", .mp_redirectUrl = "https://cdn.example.net/robots.txt" },
    { .m_status = 200 },
  };
  static_setAnswers(answers, 2);

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://example.com/robots.txt", HEADER_FETCH_HOP_RULE_SAME_SITE, NULL, NULL, &chain));

  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_OFF_SITE, chain.m_stopReason);
  TEST_ASSERT_EQUAL_INT(1, chain.m_hopCount);
  TEST_ASSERT_EQUAL_INT(302, chain.ma_hops[0].m_httpStatus);
  TEST_ASSERT_EQUAL_STRING("https://cdn.example.net/robots.txt", chain.mp_unfollowedUrl);
  TEST_ASSERT_EQUAL_STRING("moved", chain.mp_body);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, header_fetch_chainError(&chain));
  header_fetch_chainFree(&chain);
}

void test_failed_chain_keeps_nothing(void)
{
  static const HttpStubAnswer_t first_fails[] = {
    { .m_error = HTTP_ERROR_CONNECT },
  };
  static const HttpStubAnswer_t url_unwritten[] = {
    { .m_status = 200, .mp_body = "User-agent: *\nAllow: /\n" },
  };
  static const struct {
    const HttpStubAnswer_t* mp_answers;
    int                     m_failingCall;
    HttpError_t             m_error;
    const char*             mp_what;
  } cases[] = {
    { first_fails,   -1, HTTP_ERROR_CONNECT, "a first request that fails" },
    { url_unwritten, 4,  HTTP_ERROR_OTHER,   "a URL libcurl cannot write" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_setAnswers(cases[i].mp_answers, 1);
    g_stub_http_call_count  = 0;
    g_curlUrlGetCallCount   = 0;
    g_curlUrlGetFailingCall = cases[i].m_failingCall;
    HeaderFetchChain_t chain;
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_error, static_runChain("https://example.com/robots.txt", HEADER_FETCH_HOP_RULE_SAME_SITE, NULL, NULL, &chain), cases[i].mp_what);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_http_call_count, cases[i].mp_what);
    static_assertZeroedChain(&chain);
  }
}

void test_site_chain_resolves_a_location_as_a_browser_does(void)
{
  static const struct {
    const char*  mp_location;
    int          m_requestCount;
    const char*  mp_secondUrl;
    const char*  mp_unfollowedUrl;
  } cases[] = {
    { "next",              2, "https://example.com/a/b/next", NULL },
    { "/top?y=2",          2, "https://example.com/top?y=2",  NULL },
    { "../up",             2, "https://example.com/a/up",     NULL },
    { "//other.example/x", 1, "",                             "https://other.example/x" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char location_line[64];
    snprintf(location_line, sizeof(location_line), "Location: %s", cases[i].mp_location);
    const char* const lines[] = { location_line, NULL };
    HttpStubAnswer_t answers[] = {
      { .m_status = 302, .mp_headerLines = lines },
      { .m_status = 200 },
    };
    static_setAnswers(answers, 2);
    g_stub_http_call_count = 0;
    memset(g_stub_requests, 0, sizeof(g_stub_requests));

    HeaderFetchChain_t chain;
    TEST_ASSERT_EQUAL_INT_MESSAGE(HTTP_ERROR_NONE, static_runChain("https://example.com/a/b/page?x=1", HEADER_FETCH_HOP_RULE_SAME_SITE, NULL, NULL, &chain), cases[i].mp_location);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_requestCount, g_stub_http_call_count, cases[i].mp_location);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_secondUrl, g_stub_requests[1].ma_url, cases[i].mp_location);
    if (cases[i].mp_unfollowedUrl != NULL)
    {
      TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_FETCH_STOP_OFF_SITE, chain.m_stopReason, cases[i].mp_location);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_unfollowedUrl, chain.mp_unfollowedUrl, cases[i].mp_location);
    }
    else
      TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_FETCH_STOP_FINAL_ANSWER, chain.m_stopReason, cases[i].mp_location);
    header_fetch_chainFree(&chain);
  }
}

void test_site_chain_follows_a_redirect_whose_body_was_cut(void)
{
  static const char* const lines[] = { "Location: /next", NULL };
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 302, .mp_body = "cut", .mp_headerLines = lines, .m_isBodyCut = true },
    { .m_status = 200 },
  };
  static_setAnswers(answers, 2);

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://example.com/", HEADER_FETCH_HOP_RULE_SAME_SITE, NULL, NULL, &chain));
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("https://example.com/next", g_stub_requests[1].ma_url);
  TEST_ASSERT_EQUAL_INT(2, chain.m_hopCount);
  header_fetch_chainFree(&chain);
}

void test_site_chain_writes_no_query(void)
{
  static const char* const first_lines[]  = { "Location: /next?b=2", NULL };
  static const char* const second_lines[] = { "Location: https://other.example/x?c=3", NULL };
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 302, .mp_headerLines = first_lines },
    { .m_status = 302, .mp_headerLines = second_lines },
    { .m_status = 200 },
  };
  static_setAnswers(answers, 3);

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://example.com/start?a=1", HEADER_FETCH_HOP_RULE_SAME_SITE, NULL, NULL, &chain));
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("https://example.com/start?a=1", g_stub_requests[0].ma_url);
  TEST_ASSERT_EQUAL_STRING("https://example.com/next?b=2", g_stub_requests[1].ma_url);
  TEST_ASSERT_EQUAL_STRING("https://example.com/start", chain.ma_hops[0].mp_url);
  TEST_ASSERT_EQUAL_STRING("https://example.com/next", chain.ma_hops[1].mp_url);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_OFF_SITE, chain.m_stopReason);
  TEST_ASSERT_EQUAL_STRING("https://other.example/x", chain.mp_unfollowedUrl);
  header_fetch_chainFree(&chain);
}

void test_permission_is_asked_once_per_request_with_host_and_path(void)
{
  static const char* const lines[] = { "Location: /second?k=v", NULL };
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 301, .mp_headerLines = lines },
    { .m_status = 200 },
  };
  static_setAnswers(answers, 2);
  TestPermission_t permission = { .ma_answers = { HEADER_FETCH_PERMISSION_ALLOWED, HEADER_FETCH_PERMISSION_ALLOWED } };

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://www.example.com/first", HEADER_FETCH_HOP_RULE_SAME_SITE, NULL, &permission, &chain));
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(2, permission.m_callCount);
  TEST_ASSERT_EQUAL_STRING("www.example.com", permission.ma_hosts[0]);
  TEST_ASSERT_EQUAL_STRING("/first", permission.ma_pathsAndQueries[0]);
  TEST_ASSERT_EQUAL_STRING("www.example.com", permission.ma_hosts[1]);
  TEST_ASSERT_EQUAL_STRING("/second?k=v", permission.ma_pathsAndQueries[1]);
  TEST_ASSERT_EQUAL_PTR(&permission, permission.mp_seenContext);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_FINAL_ANSWER, chain.m_stopReason);
  header_fetch_chainFree(&chain);
}

void test_permission_refusal_sends_no_more_requests(void)
{
  static const char* const lines[] = { "Location: /second?k=v", NULL };
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 301, .mp_headerLines = lines },
    { .m_status = 200 },
  };
  static_setAnswers(answers, 2);
  TestPermission_t second_refused = { .ma_answers = { HEADER_FETCH_PERMISSION_ALLOWED, HEADER_FETCH_PERMISSION_REFUSED } };

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://example.com/first", HEADER_FETCH_HOP_RULE_SAME_SITE, NULL, &second_refused, &chain));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(2, second_refused.m_callCount);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_PERMISSION_REFUSED, chain.m_stopReason);
  TEST_ASSERT_EQUAL_INT(1, chain.m_hopCount);
  TEST_ASSERT_EQUAL_INT(301, chain.ma_hops[0].m_httpStatus);
  TEST_ASSERT_EQUAL_STRING("https://example.com/second", chain.mp_unfollowedUrl);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, header_fetch_chainError(&chain));
  header_fetch_chainFree(&chain);

  g_stub_http_call_count = 0;
  TestPermission_t first_refused = { .ma_answers = { HEADER_FETCH_PERMISSION_REFUSED } };
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://example.com/first", HEADER_FETCH_HOP_RULE_SAME_SITE, NULL, &first_refused, &chain));
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(1, first_refused.m_callCount);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_PERMISSION_REFUSED, chain.m_stopReason);
  TEST_ASSERT_EQUAL_INT(0, chain.m_hopCount);
  TEST_ASSERT_EQUAL_STRING("https://example.com/first", chain.mp_unfollowedUrl);
  TEST_ASSERT_NULL(chain.mp_body);
  header_fetch_chainFree(&chain);
}

void test_captured_list_holds_the_callers_names_only(void)
{
  static const char* const names[] = { "X-One", "X-Two", NULL };
  static const char* const lines[] = { "X-Two: two", "Location: /ignored", "Refresh: 0", NULL };
  static const HttpStubAnswer_t answers[] = { { .m_status = 200, .mp_headerLines = lines } };
  static_setAnswers(answers, 1);

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://example.com/", HEADER_FETCH_HOP_RULE_SAME_SITE, names, NULL, &chain));
  TEST_ASSERT_EQUAL_STRING("X-One\nX-Two\nLocation\nRefresh", g_stub_requests[0].ma_headerNamesToCapture);
  TEST_ASSERT_EQUAL_INT(2, chain.m_capturedHeaderValueCount);
  TEST_ASSERT_NULL(chain.mp_capturedHeaderValues[0]);
  TEST_ASSERT_EQUAL_STRING("two", chain.mp_capturedHeaderValues[1]);
  TEST_ASSERT_EQUAL_STRING("0", chain.ma_hops[0].mp_refresh);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_FINAL_ANSWER, chain.m_stopReason);
  header_fetch_chainFree(&chain);
}

void test_only_a_3xx_answer_is_followed(void)
{
  static const struct { int m_status; int m_requestCount; } cases[] = {
    { 199, 1 }, { 200, 1 }, { 299, 1 }, { 300, 2 }, { 399, 2 }, { 400, 1 },
  };
  static const char* const lines[] = { "Location: /next", NULL };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    HttpStubAnswer_t answers[] = {
      { .m_status = cases[i].m_status, .mp_headerLines = lines },
      { .m_status = 200 },
    };
    static_setAnswers(answers, 2);
    g_stub_http_call_count = 0;

    HeaderFetchChain_t chain;
    char message[16];
    snprintf(message, sizeof(message), "%d", cases[i].m_status);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HTTP_ERROR_NONE, static_runChain("https://example.com/", HEADER_FETCH_HOP_RULE_SAME_SITE, NULL, NULL, &chain), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_requestCount, g_stub_http_call_count, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_FETCH_STOP_FINAL_ANSWER, chain.m_stopReason, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, chain.ma_hops[0].m_httpStatus, message);
    header_fetch_chainFree(&chain);
  }
}

void test_long_first_url_is_sent(void)
{
  static char first_url[HEADER_FETCH_MAX_URL_BYTE_COUNT + 64];
  int n = snprintf(first_url, sizeof(first_url), "https://example.com/");
  memset(first_url + n, 'a', HEADER_FETCH_MAX_URL_BYTE_COUNT + 10 - n);
  first_url[HEADER_FETCH_MAX_URL_BYTE_COUNT + 10] = '\0';
  static const HttpStubAnswer_t answers[] = { { .m_status = 200 } };
  static_setAnswers(answers, 1);
  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain(first_url, HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST, NULL, NULL, &chain));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(1, chain.m_hopCount);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_FINAL_ANSWER, chain.m_stopReason);
  header_fetch_chainFree(&chain);
}

void test_public_web_chain_crosses_hosts_and_keeps_every_hop(void)
{
  static const char* const first_lines[]  = { "Location: https://b.example/p", NULL };
  static const char* const second_lines[] = { "Location: http://c.example/q?z=1", NULL };
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 301, .mp_headerLines = first_lines },
    { .m_status = 302, .mp_headerLines = second_lines },
    { .m_status = 200, .mp_body = "last" },
  };
  static_setAnswers(answers, 3);

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("http://a.example/", HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST, NULL, NULL, &chain));
  TEST_ASSERT_EQUAL_INT(3, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("http://a.example/", g_stub_requests[0].ma_url);
  TEST_ASSERT_FALSE(g_stub_requests[0].m_isHttpsOnly);
  TEST_ASSERT_EQUAL_UINT16(80, g_stub_requests[0].m_requiredPort);
  TEST_ASSERT_EQUAL_STRING("https://b.example/p", g_stub_requests[1].ma_url);
  TEST_ASSERT_TRUE(g_stub_requests[1].m_isHttpsOnly);
  TEST_ASSERT_EQUAL_UINT16(443, g_stub_requests[1].m_requiredPort);
  TEST_ASSERT_EQUAL_STRING("http://c.example/q?z=1", g_stub_requests[2].ma_url);
  TEST_ASSERT_FALSE(g_stub_requests[2].m_isHttpsOnly);
  TEST_ASSERT_EQUAL_UINT16(80, g_stub_requests[2].m_requiredPort);
  for (int i = 0; i < 3; i++)
  {
    TEST_ASSERT_FALSE(g_stub_requests[i].m_isTargetTrusted);
    TEST_ASSERT_TRUE(g_stub_requests[i].m_isRedirectLeftToCaller);
  }

  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_FINAL_ANSWER, chain.m_stopReason);
  TEST_ASSERT_EQUAL_INT(3, chain.m_hopCount);
  TEST_ASSERT_EQUAL_STRING("http://a.example/", chain.ma_hops[0].mp_url);
  TEST_ASSERT_EQUAL_INT(301, chain.ma_hops[0].m_httpStatus);
  TEST_ASSERT_EQUAL_STRING("https://b.example/p", chain.ma_hops[1].mp_url);
  TEST_ASSERT_EQUAL_INT(302, chain.ma_hops[1].m_httpStatus);
  TEST_ASSERT_EQUAL_STRING("http://c.example/q?z=1", chain.ma_hops[2].mp_url);
  TEST_ASSERT_EQUAL_INT(200, chain.ma_hops[2].m_httpStatus);
  TEST_ASSERT_NULL(chain.mp_unfollowedUrl);
  TEST_ASSERT_EQUAL_STRING("last", chain.mp_body);
  header_fetch_chainFree(&chain);
}

void test_any_public_host_rule_refuses_each_target_with_its_reason(void)
{
  static const struct {
    const char*              mp_target;
    HeaderFetchStopReason_t  m_stopReason;
    const char*              mp_unfollowedUrl;
  } cases[] = {
    { "https://h.example:8443/",  HEADER_FETCH_STOP_PORT_NOT_ALLOWED,        "https://h.example:8443/" },
    { "http://h.example:443/",    HEADER_FETCH_STOP_PORT_NOT_ALLOWED,        "http://h.example:443/" },
    { "ftp://h.example/f",        HEADER_FETCH_STOP_SCHEME_NOT_FOLLOWED,     "ftp://h.example/f" },
    { "https://192.0.2.1/",       HEADER_FETCH_STOP_IP_ADDRESS_NOT_FOLLOWED, "https://192.0.2.1/" },
    { "https://2130706433/",      HEADER_FETCH_STOP_IP_ADDRESS_NOT_FOLLOWED, "https://127.0.0.1/" },
    { "https://[2001:db8::1]/",   HEADER_FETCH_STOP_IP_ADDRESS_NOT_FOLLOWED, "https://[2001:db8::1]/" },
    { "https://db.internal/",     HEADER_FETCH_STOP_HOST_NOT_PUBLIC,         "https://db.internal/" },
    { "https://localhost/",       HEADER_FETCH_STOP_HOST_NOT_PUBLIC,         "https://localhost/" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    HttpStubAnswer_t answers[] = {
      { .m_status = 302, .mp_redirectUrl = cases[i].mp_target },
      { .m_status = 200 },
    };
    static_setAnswers(answers, 2);
    g_stub_http_call_count = 0;

    HeaderFetchChain_t chain;
    TEST_ASSERT_EQUAL_INT_MESSAGE(HTTP_ERROR_NONE, static_runChain("https://a.example/", HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST, NULL, NULL, &chain), cases[i].mp_target);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_http_call_count, cases[i].mp_target);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_stopReason, chain.m_stopReason, cases[i].mp_target);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, chain.m_hopCount, cases[i].mp_target);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_unfollowedUrl, chain.mp_unfollowedUrl, cases[i].mp_target);
    header_fetch_chainFree(&chain);
  }
}

void test_any_public_host_rule_checks_the_first_url(void)
{
  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://192.0.2.1/", HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST, NULL, NULL, &chain));
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(0, chain.m_hopCount);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_IP_ADDRESS_NOT_FOLLOWED, chain.m_stopReason);
  TEST_ASSERT_EQUAL_STRING("https://192.0.2.1/", chain.mp_unfollowedUrl);
  header_fetch_chainFree(&chain);
}

void test_location_libcurl_cannot_resolve_keeps_its_raw_text(void)
{
  static const char* const lines[] = { "Location: javascript:alert(1)", NULL };
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 302, .mp_headerLines = lines },
    { .m_status = 200 },
  };
  static_setAnswers(answers, 2);

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://a.example/", HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST, NULL, NULL, &chain));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_LOCATION_INVALID, chain.m_stopReason);
  TEST_ASSERT_EQUAL_STRING("javascript:alert(1)", chain.mp_invalidLocation);
  TEST_ASSERT_NULL(chain.mp_unfollowedUrl);
  TEST_ASSERT_EQUAL_STRING("https://a.example/", chain.ma_hops[0].mp_url);
  header_fetch_chainFree(&chain);
}

void test_target_of_4096_bytes_is_followed_and_4097_is_not(void)
{
  static char targets[2][4098];
  for (int i = 0; i < 2; i++)
  {
    size_t target_len = 4096 + (size_t)i;
    memcpy(targets[i], "https://b.example/", 18);
    memset(targets[i] + 18, 'p', target_len - 18);
    targets[i][target_len] = '\0';
  }

  HttpStubAnswer_t followed[] = { { .m_status = 302, .mp_redirectUrl = targets[0] }, { .m_status = 200 } };
  static_setAnswers(followed, 2);
  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://a.example/", HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST, NULL, NULL, &chain));
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_FINAL_ANSWER, chain.m_stopReason);
  TEST_ASSERT_EQUAL_STRING(targets[0], chain.ma_hops[1].mp_url);
  header_fetch_chainFree(&chain);

  HttpStubAnswer_t refused[] = { { .m_status = 302, .mp_redirectUrl = targets[1] }, { .m_status = 200 } };
  static_setAnswers(refused, 2);
  g_stub_http_call_count = 0;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://a.example/", HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST, NULL, NULL, &chain));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_LOCATION_TOO_LONG, chain.m_stopReason);
  TEST_ASSERT_EQUAL_STRING(targets[1], chain.mp_unfollowedUrl);
  header_fetch_chainFree(&chain);
}

void test_target_requested_already_is_a_loop(void)
{
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 302, .mp_redirectUrl = "https://b.example/" },
    { .m_status = 302, .mp_redirectUrl = "https://a.example/" },
    { .m_status = 200 },
  };
  static_setAnswers(answers, 3);

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://a.example/", HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST, NULL, NULL, &chain));
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_LOOP, chain.m_stopReason);
  TEST_ASSERT_EQUAL_INT(2, chain.m_hopCount);
  TEST_ASSERT_EQUAL_STRING("https://a.example/", chain.mp_unfollowedUrl);
  header_fetch_chainFree(&chain);
}

void test_tenth_request_is_sent_and_an_eleventh_target_is_the_limit(void)
{
  static const char* const targets[] = {
    "https://a.example/1", "https://a.example/2", "https://a.example/3", "https://a.example/4", "https://a.example/5",
    "https://a.example/6", "https://a.example/7", "https://a.example/8", "https://a.example/9", "https://a.example/10",
    "https://a.example/11",
  };
  static HttpStubAnswer_t answers[11];
  for (int i = 0; i < 11; i++)
    answers[i] = (HttpStubAnswer_t){ .m_status = 307, .mp_redirectUrl = targets[i] };
  static_setAnswers(answers, 11);

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://a.example/", HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST, NULL, NULL, &chain));
  TEST_ASSERT_EQUAL_INT(10, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("https://a.example/9", g_stub_requests[9].ma_url);
  TEST_ASSERT_EQUAL_INT(10, chain.m_hopCount);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_REQUEST_LIMIT, chain.m_stopReason);
  TEST_ASSERT_EQUAL_STRING("https://a.example/10", chain.mp_unfollowedUrl);
  TEST_ASSERT_EQUAL_STRING("https://a.example/9", chain.ma_hops[9].mp_url);
  header_fetch_chainFree(&chain);
}

void test_failed_third_request_ends_the_chain_with_its_hop(void)
{
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 302, .mp_body = "first",  .mp_redirectUrl = "https://b.example/" },
    { .m_status = 302, .mp_body = "second", .mp_redirectUrl = "https://c.example/" },
    { .m_error = HTTP_ERROR_TLS },
  };
  static_setAnswers(answers, 3);

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://a.example/", HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST, NULL, NULL, &chain));
  TEST_ASSERT_EQUAL_INT(3, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(3, chain.m_hopCount);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_REQUEST_FAILED, chain.m_stopReason);
  TEST_ASSERT_EQUAL_STRING("https://c.example/", chain.ma_hops[2].mp_url);
  TEST_ASSERT_EQUAL_INT(0, chain.ma_hops[2].m_httpStatus);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_TLS, chain.ma_hops[2].m_error);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, chain.ma_hops[1].m_error);
  TEST_ASSERT_NULL(chain.mp_unfollowedUrl);
  TEST_ASSERT_EQUAL_STRING("second", chain.mp_body);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_TLS, header_fetch_chainError(&chain));
  header_fetch_chainFree(&chain);
}

void test_deadline_before_a_later_request_ends_the_chain(void)
{
  static const int64_t readings[] = { 1000, 6000 };
  static_setClockReadings(readings, 2);
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 302, .mp_redirectUrl = "https://b.example/" },
    { .m_status = 200 },
  };
  static_setAnswers(answers, 2);

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://a.example/", HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST, NULL, NULL, &chain));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(1, chain.m_hopCount);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_DEADLINE, chain.m_stopReason);
  TEST_ASSERT_EQUAL_STRING("https://b.example/", chain.mp_unfollowedUrl);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_TIMEOUT, header_fetch_chainError(&chain));
  header_fetch_chainFree(&chain);
}

void test_chain_with_no_time_before_its_first_request_times_out(void)
{
  static const int64_t readings[] = { 6000 };
  static_setClockReadings(readings, 1);
  static const HttpStubAnswer_t answers[] = { { .m_status = 200 } };
  static_setAnswers(answers, 1);

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_TIMEOUT, static_runChain("https://a.example/", HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST, NULL, NULL, &chain));
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
  static_assertZeroedChain(&chain);
}

void test_failed_first_request_answers_its_error(void)
{
  static const HttpStubAnswer_t answers[] = { { .m_error = HTTP_ERROR_RESOLVE } };
  static_setAnswers(answers, 1);

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_RESOLVE, static_runChain("https://a.example/", HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST, NULL, NULL, &chain));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  static_assertZeroedChain(&chain);
}

void test_user_info_and_fragment_of_a_target_are_dropped(void)
{
  static const char* const targets[] = { "https://user:pw@h.example/x#frag", "https://user@h.example/x", "https://:pw@h.example/x" };
  for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++)
  {
    HttpStubAnswer_t answers[] = {
      { .m_status = 302, .mp_redirectUrl = targets[i] },
      { .m_status = 200 },
    };
    static_setAnswers(answers, 2);
    g_stub_http_call_count = 0;

    HeaderFetchChain_t chain;
    TEST_ASSERT_EQUAL_INT_MESSAGE(HTTP_ERROR_NONE, static_runChain("https://a.example/", HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST, NULL, NULL, &chain), targets[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, g_stub_http_call_count, targets[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("https://h.example/x", g_stub_requests[1].ma_url, targets[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("https://h.example/x", chain.ma_hops[1].mp_url, targets[i]);
    TEST_ASSERT_FALSE_MESSAGE(chain.ma_hops[0].m_isUserInfoDropped, targets[i]);
    TEST_ASSERT_TRUE_MESSAGE(chain.ma_hops[1].m_isUserInfoDropped, targets[i]);
    header_fetch_chainFree(&chain);
  }
}

void test_refresh_header_lands_in_its_hop(void)
{
  static const char* const lines[] = { "Refresh: 5; url=/x", NULL };
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 302, .mp_redirectUrl = "https://b.example/", .mp_headerLines = lines },
    { .m_status = 200 },
  };
  static_setAnswers(answers, 2);

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://a.example/", HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST, NULL, NULL, &chain));
  TEST_ASSERT_EQUAL_INT(2, chain.m_hopCount);
  TEST_ASSERT_EQUAL_STRING("5; url=/x", chain.ma_hops[0].mp_refresh);
  TEST_ASSERT_NULL(chain.ma_hops[1].mp_refresh);
  header_fetch_chainFree(&chain);
}

void test_throttled_permission_ends_the_chain_with_its_wait(void)
{
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 302, .mp_redirectUrl = "https://b.example/next?q=1" },
    { .m_status = 200 },
  };
  static_setAnswers(answers, 2);
  TestPermission_t permission = { .ma_answers = { HEADER_FETCH_PERMISSION_ALLOWED, HEADER_FETCH_PERMISSION_THROTTLED }, .m_retryAfterSeconds = 37 };

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://a.example/", HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST, NULL, &permission, &chain));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(1, chain.m_hopCount);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_THROTTLED, chain.m_stopReason);
  TEST_ASSERT_EQUAL_UINT(37, chain.m_retryAfterSeconds);
  TEST_ASSERT_EQUAL_STRING("b.example", permission.ma_hosts[1]);
  TEST_ASSERT_EQUAL_STRING("/next?q=1", permission.ma_pathsAndQueries[1]);
  TEST_ASSERT_EQUAL_STRING("https://b.example/next?q=1", chain.mp_unfollowedUrl);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, header_fetch_chainError(&chain));
  header_fetch_chainFree(&chain);
}

void test_chain_free_zeroes_the_chain_and_accepts_a_zeroed_one(void)
{
  static const char* const names[] = { "X-One", NULL };
  static const char* const lines[] = { "X-One: one", "Refresh: 1", NULL };
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 302, .mp_redirectUrl = "https://b.example/", .mp_headerLines = lines },
    { .m_status = 200, .mp_body = "body", .mp_headerLines = lines },
  };
  static_setAnswers(answers, 2);

  HeaderFetchChain_t chain;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_runChain("https://a.example/", HEADER_FETCH_HOP_RULE_ANY_PUBLIC_HOST, names, NULL, &chain));
  TEST_ASSERT_EQUAL_INT(2, chain.m_hopCount);
  TEST_ASSERT_EQUAL_STRING("one", chain.mp_capturedHeaderValues[0]);
  header_fetch_chainFree(&chain);
  static_assertZeroedChain(&chain);

  HeaderFetchChain_t zeroed_chain = { 0 };
  header_fetch_chainFree(&zeroed_chain);
  static_assertZeroedChain(&zeroed_chain);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(50, (int)Unity.NumberOfTests,
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
  RUN_TEST(test_unwritten_url_at_a_deadline_stop_fails_the_fetch);
  RUN_TEST(test_fetch_past_its_deadline_sends_no_request);
  RUN_TEST(test_request_error_is_the_error_of_the_fetch);
  RUN_TEST(test_host_name_of_253_bytes_is_fetched_and_254_is_refused);
  RUN_TEST(test_host_name_libcurl_cannot_parse_sends_no_request);
  RUN_TEST(test_url_handle_libcurl_cannot_make_fails_the_fetch);
  RUN_TEST(test_url_libcurl_cannot_write_fails_the_fetch);
  RUN_TEST(test_target_at_the_limit_libcurl_cannot_write_fails_the_fetch);
  RUN_TEST(test_target_part_libcurl_cannot_hand_back_stops_the_fetch);
  RUN_TEST(test_first_url_part_libcurl_cannot_hand_back_fails_the_fetch);
  RUN_TEST(test_chain_asks_its_path_and_keeps_the_body);
  RUN_TEST(test_chain_fits_the_longest_host_name);
  RUN_TEST(test_chain_follows_the_www_pair_and_keeps_a_cut_body);
  RUN_TEST(test_chain_does_not_follow_a_redirect_off_the_site);
  RUN_TEST(test_failed_chain_keeps_nothing);
  RUN_TEST(test_site_chain_resolves_a_location_as_a_browser_does);
  RUN_TEST(test_site_chain_follows_a_redirect_whose_body_was_cut);
  RUN_TEST(test_site_chain_writes_no_query);
  RUN_TEST(test_permission_is_asked_once_per_request_with_host_and_path);
  RUN_TEST(test_permission_refusal_sends_no_more_requests);
  RUN_TEST(test_captured_list_holds_the_callers_names_only);
  RUN_TEST(test_only_a_3xx_answer_is_followed);
  RUN_TEST(test_long_first_url_is_sent);
  RUN_TEST(test_public_web_chain_crosses_hosts_and_keeps_every_hop);
  RUN_TEST(test_any_public_host_rule_refuses_each_target_with_its_reason);
  RUN_TEST(test_any_public_host_rule_checks_the_first_url);
  RUN_TEST(test_location_libcurl_cannot_resolve_keeps_its_raw_text);
  RUN_TEST(test_target_of_4096_bytes_is_followed_and_4097_is_not);
  RUN_TEST(test_target_requested_already_is_a_loop);
  RUN_TEST(test_tenth_request_is_sent_and_an_eleventh_target_is_the_limit);
  RUN_TEST(test_failed_third_request_ends_the_chain_with_its_hop);
  RUN_TEST(test_deadline_before_a_later_request_ends_the_chain);
  RUN_TEST(test_chain_with_no_time_before_its_first_request_times_out);
  RUN_TEST(test_failed_first_request_answers_its_error);
  RUN_TEST(test_user_info_and_fragment_of_a_target_are_dropped);
  RUN_TEST(test_refresh_header_lands_in_its_hop);
  RUN_TEST(test_throttled_permission_ends_the_chain_with_its_wait);
  RUN_TEST(test_chain_free_zeroes_the_chain_and_accepts_a_zeroed_one);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
