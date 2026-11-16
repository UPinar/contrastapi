#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "unity/unity.h"
#include "external/cveservices.h"
#include "http_stub.h"

static const char CVESERVICES_TEST_PUBLISHED_BODY[] =
  R"({"cve_id":"CVE-2021-44228","cve_year":"2021","state":"PUBLISHED","owning_cna":"apache","dateUpdated":"2023-04-03T19:06:24.964Z"})";

static const char CVESERVICES_TEST_RESERVED_BODY[] =
  R"({"cve_id":"CVE-2027-0001","cve_year":"2027","state":"RESERVED","owning_cna":"[REDACTED]"})";

static const char CVESERVICES_TEST_REJECTED_BODY[] =
  R"({"cve_id":"CVE-2024-53667","cve_year":"2024","state":"REJECTED","owning_cna":"AMD","dateUpdated":"2026-09-02T20:23:23.753Z"})";

static const char CVESERVICES_TEST_NOT_FOUND_BODY[] =
  R"({"error":"CVE_ID_NOT_FOUND","message":"CVE-2001-3389 not found"})";

static const char CVESERVICES_TEST_BAD_INPUT_BODY[] =
  R"({"error":"BAD_INPUT","message":"Parameters were invalid","details":[{"msg":"Invalid value","param":"id","location":"params"}]})";

#define CVESERVICES_TEST_STATE_SENTINEL ((CveServicesCveIdState_t)77)

static int64_t g_nowMs = 0;

int64_t __wrap_monotonic_nowMs(void)
{
  return g_nowMs;
}

static unsigned int         g_retryAfterSeconds;
static CveServicesCveIdState_t g_state;

void setUp(void)
{
  g_retryAfterSeconds             = 7;
  g_state                         = CVESERVICES_TEST_STATE_SENTINEL;
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
  g_nowMs                         = 2000000;
}

void tearDown(void) {}

static bool static_tryReadState(const char* body, CveServicesCveIdState_t* state_out)
{
  *state_out = CVESERVICES_TEST_STATE_SENTINEL;
  return cveservices_tryReadCveIdState(body, strlen(body), state_out);
}

static void static_assertNoState(const char* body)
{
  CveServicesCveIdState_t state;
  TEST_ASSERT_FALSE_MESSAGE(static_tryReadState(body, &state), body);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, state, body);
}

static CveServicesStatus_t static_ask(const char* cve_id)
{
  return cveservices_askCveIdState(cve_id, g_nowMs + 2500, &g_state, &g_retryAfterSeconds);
}

void test_tryReadCveIdState_reads_each_state_the_server_sent(void)
{
  CveServicesCveIdState_t state;
  TEST_ASSERT_TRUE(static_tryReadState(CVESERVICES_TEST_PUBLISHED_BODY, &state));
  TEST_ASSERT_EQUAL_INT(CVESERVICES_CVE_ID_STATE_PUBLISHED, state);
  TEST_ASSERT_TRUE(static_tryReadState(CVESERVICES_TEST_RESERVED_BODY, &state));
  TEST_ASSERT_EQUAL_INT(CVESERVICES_CVE_ID_STATE_RESERVED, state);
  TEST_ASSERT_TRUE(static_tryReadState(CVESERVICES_TEST_REJECTED_BODY, &state));
  TEST_ASSERT_EQUAL_INT(CVESERVICES_CVE_ID_STATE_REJECTED, state);
}

void test_tryReadCveIdState_states_are_distinct_values(void)
{
  TEST_ASSERT_EQUAL_INT(0, CVESERVICES_CVE_ID_STATE_NOT_CHECKED);
  TEST_ASSERT_NOT_EQUAL(CVESERVICES_CVE_ID_STATE_PUBLISHED, CVESERVICES_CVE_ID_STATE_RESERVED);
  TEST_ASSERT_NOT_EQUAL(CVESERVICES_CVE_ID_STATE_PUBLISHED, CVESERVICES_CVE_ID_STATE_REJECTED);
  TEST_ASSERT_NOT_EQUAL(CVESERVICES_CVE_ID_STATE_RESERVED, CVESERVICES_CVE_ID_STATE_REJECTED);
  TEST_ASSERT_NOT_EQUAL(CVESERVICES_CVE_ID_STATE_UNKNOWN_ID, CVESERVICES_CVE_ID_STATE_PUBLISHED);
  TEST_ASSERT_NOT_EQUAL(CVESERVICES_CVE_ID_STATE_UNKNOWN_ID, CVESERVICES_CVE_ID_STATE_RESERVED);
  TEST_ASSERT_NOT_EQUAL(CVESERVICES_CVE_ID_STATE_UNKNOWN_ID, CVESERVICES_CVE_ID_STATE_REJECTED);
  TEST_ASSERT_NOT_EQUAL(0, CVESERVICES_CVE_ID_STATE_UNKNOWN_ID);
}

void test_tryReadCveIdState_reads_state_alone(void)
{
  CveServicesCveIdState_t state;
  TEST_ASSERT_TRUE(static_tryReadState(R"({"state":"REJECTED"})", &state));
  TEST_ASSERT_EQUAL_INT(CVESERVICES_CVE_ID_STATE_REJECTED, state);
  TEST_ASSERT_TRUE(static_tryReadState(" { \"state\" : \"RESERVED\" } ", &state));
  TEST_ASSERT_EQUAL_INT(CVESERVICES_CVE_ID_STATE_RESERVED, state);
}

void test_tryReadCveIdState_refuses_another_spelling_of_the_state(void)
{
  static_assertNoState(R"({"state":"published"})");
  static_assertNoState(R"({"state":"Published"})");
  static_assertNoState(R"({"state":"PUBLISHED "})");
  static_assertNoState(R"({"state":"PUBLISHE"})");
  static_assertNoState(R"({"state":"PUBLISHEDX"})");
  static_assertNoState(R"({"state":"RESERVE"})");
  static_assertNoState(R"({"state":"REJECTE"})");
  static_assertNoState(R"({"state":"DRAFT"})");
  static_assertNoState(R"({"state":""})");
  static_assertNoState(R"({"State":"PUBLISHED"})");
  static_assertNoState(R"({"states":"PUBLISHED"})");
}

void test_tryReadCveIdState_refuses_a_state_that_is_not_a_string(void)
{
  static_assertNoState(R"({"state":1})");
  static_assertNoState(R"({"state":null})");
  static_assertNoState(R"({"state":true})");
  static_assertNoState(R"({"state":["PUBLISHED"]})");
  static_assertNoState(R"({"state":{"state":"PUBLISHED"}})");
}

void test_tryReadCveIdState_refuses_a_body_without_a_top_level_state(void)
{
  static_assertNoState(R"({"cve_id":"CVE-2021-44228","cve_year":"2021"})");
  static_assertNoState(R"({"record":{"state":"PUBLISHED"}})");
  static_assertNoState(R"([{"state":"PUBLISHED"}])");
  static_assertNoState(R"(["state","PUBLISHED"])");
  static_assertNoState(R"("PUBLISHED")");
  static_assertNoState("{}");
  static_assertNoState("");
  static_assertNoState("   ");
  static_assertNoState(R"({"state":"PUBLISHED")");
  static_assertNoState(R"({"state":"PUBLISHED"}x)");
  static_assertNoState("<html><body>Bad Gateway</body></html>");
  static_assertNoState(CVESERVICES_TEST_NOT_FOUND_BODY);
}

void test_tryReadCveIdState_a_nested_state_is_not_read(void)
{
  CveServicesCveIdState_t state;
  TEST_ASSERT_TRUE(static_tryReadState(R"({"record":{"state":"PUBLISHED"},"state":"REJECTED"})", &state));
  TEST_ASSERT_EQUAL_INT(CVESERVICES_CVE_ID_STATE_REJECTED, state);
}

void test_tryReadCveIdState_first_of_two_states_wins(void)
{
  CveServicesCveIdState_t state;
  TEST_ASSERT_TRUE(static_tryReadState(R"({"state":"RESERVED","state":"PUBLISHED"})", &state));
  TEST_ASSERT_EQUAL_INT(CVESERVICES_CVE_ID_STATE_RESERVED, state);
}

void test_tryReadCveIdState_reads_only_body_len_bytes(void)
{
  static const char body[] = R"({"state":"PUBLISHED"}garbage)";
  CveServicesCveIdState_t state = CVESERVICES_TEST_STATE_SENTINEL;
  TEST_ASSERT_TRUE(cveservices_tryReadCveIdState(body, strlen(R"({"state":"PUBLISHED"})"), &state));
  TEST_ASSERT_EQUAL_INT(CVESERVICES_CVE_ID_STATE_PUBLISHED, state);

  state = CVESERVICES_TEST_STATE_SENTINEL;
  TEST_ASSERT_FALSE(cveservices_tryReadCveIdState(body, strlen(R"({"state":"PUBLISHED")"), &state));
  TEST_ASSERT_EQUAL_INT(0, state);
}

void test_isUnknownCveIdBody_reads_the_not_found_answer(void)
{
  TEST_ASSERT_TRUE(cveservices_isUnknownCveIdBody(CVESERVICES_TEST_NOT_FOUND_BODY, strlen(CVESERVICES_TEST_NOT_FOUND_BODY)));
  TEST_ASSERT_TRUE(cveservices_isUnknownCveIdBody(R"({"error":"CVE_ID_NOT_FOUND"})", strlen(R"({"error":"CVE_ID_NOT_FOUND"})")));
}

void test_isUnknownCveIdBody_refuses_every_other_body(void)
{
  static const char* const bodies[] = {
    CVESERVICES_TEST_BAD_INPUT_BODY,
    CVESERVICES_TEST_PUBLISHED_BODY,
    "<html><head><title>404 Not Found</title></head><body>nginx</body></html>",
    "",
    "{}",
    R"({"error":"cve_id_not_found"})",
    R"({"error":"CVE_ID_NOT_FOUN"})",
    R"({"error":"CVE_ID_NOT_FOUND "})",
    R"({"error":404})",
    R"({"Error":"CVE_ID_NOT_FOUND"})",
    R"({"message":"CVE_ID_NOT_FOUND"})",
    R"({"details":{"error":"CVE_ID_NOT_FOUND"}})",
    R"(["error","CVE_ID_NOT_FOUND"])",
    R"({"error":"CVE_ID_NOT_FOUND")",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
    TEST_ASSERT_FALSE_MESSAGE(cveservices_isUnknownCveIdBody(bodies[i], strlen(bodies[i])), bodies[i]);
}

void test_askCveIdState_sends_a_trusted_request_for_the_id(void)
{
  g_stub_next_body = CVESERVICES_TEST_PUBLISHED_BODY;
  TEST_ASSERT_EQUAL_INT(CVESERVICES_OK, static_ask("CVE-2021-44228"));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("https://cveawg.mitre.org/api/cve-id/CVE-2021-44228", g_stub_last_url);
  TEST_ASSERT_EQUAL_STRING("", g_stub_last_header);
  TEST_ASSERT_EQUAL_INT(2500, g_stub_last_timeout_ms);
  TEST_ASSERT_EQUAL_size_t(4096, g_stub_last_max_body_byte_count);
  TEST_ASSERT_TRUE(g_stub_last_is_target_trusted);
  TEST_ASSERT_FALSE(g_stub_requests[0].m_isBodyCutAccepted);
  TEST_ASSERT_FALSE(g_stub_requests[0].m_isPost);
  TEST_ASSERT_EQUAL_STRING("Retry-After", g_stub_requests[0].ma_headerNamesToCapture);
  TEST_ASSERT_EQUAL_INT(CVESERVICES_CVE_ID_STATE_PUBLISHED, g_state);
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
}

void test_askCveIdState_reads_each_state_of_a_200(void)
{
  g_stub_next_body = CVESERVICES_TEST_RESERVED_BODY;
  TEST_ASSERT_EQUAL_INT(CVESERVICES_OK, static_ask("CVE-2027-0001"));
  TEST_ASSERT_EQUAL_STRING("https://cveawg.mitre.org/api/cve-id/CVE-2027-0001", g_stub_last_url);
  TEST_ASSERT_EQUAL_INT(CVESERVICES_CVE_ID_STATE_RESERVED, g_state);

  g_stub_next_body = CVESERVICES_TEST_REJECTED_BODY;
  TEST_ASSERT_EQUAL_INT(CVESERVICES_OK, static_ask("CVE-2024-53667"));
  TEST_ASSERT_EQUAL_STRING("https://cveawg.mitre.org/api/cve-id/CVE-2024-53667", g_stub_last_url);
  TEST_ASSERT_EQUAL_INT(CVESERVICES_CVE_ID_STATE_REJECTED, g_state);
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
}

void test_askCveIdState_404_not_found_is_an_unknown_id(void)
{
  g_stub_next_status = 404;
  g_stub_next_body   = CVESERVICES_TEST_NOT_FOUND_BODY;
  TEST_ASSERT_EQUAL_INT(CVESERVICES_OK, static_ask("CVE-2001-3389"));
  TEST_ASSERT_EQUAL_STRING("https://cveawg.mitre.org/api/cve-id/CVE-2001-3389", g_stub_last_url);
  TEST_ASSERT_EQUAL_INT(CVESERVICES_CVE_ID_STATE_UNKNOWN_ID, g_state);
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
}

void test_askCveIdState_404_with_another_body_is_an_upstream_error(void)
{
  static const char* const bodies[] = {
    CVESERVICES_TEST_BAD_INPUT_BODY,
    CVESERVICES_TEST_PUBLISHED_BODY,
    "<html><body>404 Not Found</body></html>",
    "",
  };
  g_stub_next_status = 404;
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    g_state          = CVESERVICES_TEST_STATE_SENTINEL;
    g_stub_next_body = bodies[i];
    TEST_ASSERT_EQUAL_INT_MESSAGE(CVESERVICES_UPSTREAM_ERROR, static_ask("CVE-2001-3389"), bodies[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_state, bodies[i]);
  }

  g_state               = CVESERVICES_TEST_STATE_SENTINEL;
  g_stub_next_body_null = true;
  TEST_ASSERT_EQUAL_INT(CVESERVICES_UPSTREAM_ERROR, static_ask("CVE-2001-3389"));
  TEST_ASSERT_EQUAL_INT(0, g_state);
  TEST_ASSERT_EQUAL_INT(5, g_stub_http_call_count);
}

void test_askCveIdState_a_state_body_on_another_status_is_an_upstream_error(void)
{
  static const int statuses[] = { 201, 203, 299, 304, 400, 403, 410, 500, 502, 503 };
  g_stub_next_body = CVESERVICES_TEST_PUBLISHED_BODY;
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
  {
    g_state            = CVESERVICES_TEST_STATE_SENTINEL;
    g_stub_next_status = statuses[i];
    TEST_ASSERT_EQUAL_INT(CVESERVICES_UPSTREAM_ERROR, static_ask("CVE-2021-44228"));
    TEST_ASSERT_EQUAL_INT(0, g_state);
    TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  }
}

void test_askCveIdState_400_bad_input_and_200_not_found_are_upstream_errors(void)
{
  g_stub_next_status = 400;
  g_stub_next_body   = CVESERVICES_TEST_BAD_INPUT_BODY;
  TEST_ASSERT_EQUAL_INT(CVESERVICES_UPSTREAM_ERROR, static_ask("CVE-2021-44228"));
  TEST_ASSERT_EQUAL_INT(0, g_state);

  g_state            = CVESERVICES_TEST_STATE_SENTINEL;
  g_stub_next_status = 200;
  g_stub_next_body   = CVESERVICES_TEST_NOT_FOUND_BODY;
  TEST_ASSERT_EQUAL_INT(CVESERVICES_UPSTREAM_ERROR, static_ask("CVE-2021-44228"));
  TEST_ASSERT_EQUAL_INT(0, g_state);
}

void test_askCveIdState_200_without_a_readable_state_is_an_upstream_error(void)
{
  static const char* const bodies[] = {
    R"({"cve_id":"CVE-2021-44228","state":"DRAFT"})",
    R"({"cve_id":"CVE-2021-44228"})",
    R"({"state":"PUBLISHED")",
    "<html><body>OK</body></html>",
    "",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    g_state          = CVESERVICES_TEST_STATE_SENTINEL;
    g_stub_next_body = bodies[i];
    TEST_ASSERT_EQUAL_INT_MESSAGE(CVESERVICES_UPSTREAM_ERROR, static_ask("CVE-2021-44228"), bodies[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_state, bodies[i]);
  }

  g_state               = CVESERVICES_TEST_STATE_SENTINEL;
  g_stub_next_body_null = true;
  TEST_ASSERT_EQUAL_INT(CVESERVICES_UPSTREAM_ERROR, static_ask("CVE-2021-44228"));
  TEST_ASSERT_EQUAL_INT(0, g_state);
}

void test_askCveIdState_transport_failures_are_upstream_errors(void)
{
  static const HttpError_t errors[] = { HTTP_ERROR_TIMEOUT, HTTP_ERROR_BODY_TOO_LARGE, HTTP_ERROR_TLS, HTTP_ERROR_OTHER };
  g_stub_next_body = CVESERVICES_TEST_PUBLISHED_BODY;
  for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++)
  {
    g_state           = CVESERVICES_TEST_STATE_SENTINEL;
    g_stub_next_error = errors[i];
    TEST_ASSERT_EQUAL_INT(CVESERVICES_UPSTREAM_ERROR, static_ask("CVE-2021-44228"));
    TEST_ASSERT_EQUAL_INT(0, g_state);
  }
  TEST_ASSERT_EQUAL_INT(4, g_stub_http_call_count);
}

void test_askCveIdState_429_is_rate_limited_with_its_wait(void)
{
  static const char* const seconds_header[] = { "Retry-After: 45", NULL };
  static const char* const date_header[]    = { "Retry-After: Wed, 21 Oct 2026 07:28:00 GMT", NULL };
  static const HttpStubAnswer_t answers[] = {
    { .m_status = 429, .mp_headerLines = seconds_header, .mp_body = R"({"state":"PUBLISHED"})" },
    { .m_status = 429 },
    { .m_status = 429, .mp_headerLines = date_header },
    { .m_status = 503, .mp_headerLines = seconds_header },
  };
  g_stub_answers      = answers;
  g_stub_answer_count = (int)(sizeof(answers) / sizeof(answers[0]));
  static const unsigned int waits[] = { 45, 60, 60 };
  for (size_t i = 0; i < sizeof(waits) / sizeof(waits[0]); i++)
  {
    g_state = CVESERVICES_TEST_STATE_SENTINEL;
    TEST_ASSERT_EQUAL_INT(CVESERVICES_RATE_LIMITED, static_ask("CVE-2021-44228"));
    TEST_ASSERT_EQUAL_UINT(waits[i], g_retryAfterSeconds);
    TEST_ASSERT_EQUAL_INT(0, g_state);
  }
  g_state = CVESERVICES_TEST_STATE_SENTINEL;
  TEST_ASSERT_EQUAL_INT(CVESERVICES_UPSTREAM_ERROR, static_ask("CVE-2021-44228"));
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);
  TEST_ASSERT_EQUAL_INT(0, g_state);
  TEST_ASSERT_EQUAL_INT(4, g_stub_http_call_count);
}

void test_askCveIdState_waits_until_the_deadline_and_at_most_three_seconds(void)
{
  g_stub_next_body = CVESERVICES_TEST_PUBLISHED_BODY;

  TEST_ASSERT_EQUAL_INT(CVESERVICES_OK, cveservices_askCveIdState("CVE-2021-44228", g_nowMs + 1, &g_state, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(1, g_stub_last_timeout_ms);
  TEST_ASSERT_EQUAL_INT(CVESERVICES_OK, cveservices_askCveIdState("CVE-2021-44228", g_nowMs + 2999, &g_state, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(2999, g_stub_last_timeout_ms);
  TEST_ASSERT_EQUAL_INT(CVESERVICES_OK, cveservices_askCveIdState("CVE-2021-44228", g_nowMs + 3000, &g_state, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(3000, g_stub_last_timeout_ms);
  TEST_ASSERT_EQUAL_INT(CVESERVICES_OK, cveservices_askCveIdState("CVE-2021-44228", g_nowMs + 3001, &g_state, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(3000, g_stub_last_timeout_ms);
  TEST_ASSERT_EQUAL_INT(CVESERVICES_OK, cveservices_askCveIdState("CVE-2021-44228", g_nowMs + INT64_C(10000000000), &g_state, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(3000, g_stub_last_timeout_ms);
  TEST_ASSERT_EQUAL_INT(5, g_stub_http_call_count);
}

void test_askCveIdState_past_deadline_sends_no_request(void)
{
  TEST_ASSERT_EQUAL_INT(CVESERVICES_UPSTREAM_ERROR, cveservices_askCveIdState("CVE-2021-44228", g_nowMs, &g_state, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(0, g_state);
  TEST_ASSERT_EQUAL_UINT(0, g_retryAfterSeconds);

  g_state = CVESERVICES_TEST_STATE_SENTINEL;
  TEST_ASSERT_EQUAL_INT(CVESERVICES_UPSTREAM_ERROR, cveservices_askCveIdState("CVE-2021-44228", g_nowMs - 1, &g_state, &g_retryAfterSeconds));
  TEST_ASSERT_EQUAL_INT(0, g_state);
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
}

void test_askCveIdState_the_longest_id_is_sent(void)
{
  g_stub_next_body = CVESERVICES_TEST_RESERVED_BODY;
  TEST_ASSERT_EQUAL_INT(CVESERVICES_OK, static_ask("CVE-2026-123456789012345"));
  TEST_ASSERT_EQUAL_STRING("https://cveawg.mitre.org/api/cve-id/CVE-2026-123456789012345", g_stub_last_url);
  TEST_ASSERT_EQUAL_INT(CVESERVICES_CVE_ID_STATE_RESERVED, g_state);
}

void test_askCveIdState_refuses_an_id_it_cannot_send_as_it_is(void)
{
  static const char* const ids[] = {
    "CVE-2026-1234567890123456",
    "cve-2021-44228",
    "CVE-2021-4422a",
    "CVE-2021-44228/",
    "CVE-2021/44228",
    "CVE-2021-44228?x=1",
    "CVE-2021-44228#",
    "CVE-2021-44228 ",
    "CVE-2021-%34",
    "CVE-2021-44228.",
    "CVE_2021_44228",
    "",
  };
  g_stub_next_body = CVESERVICES_TEST_PUBLISHED_BODY;
  for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++)
  {
    g_state = CVESERVICES_TEST_STATE_SENTINEL;
    TEST_ASSERT_EQUAL_INT_MESSAGE(CVESERVICES_INVALID_ID, static_ask(ids[i]), ids[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_state, ids[i]);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, g_retryAfterSeconds, ids[i]);
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
}

void test_askCveIdState_accepts_every_byte_of_the_id_alphabet(void)
{
  g_stub_next_body = CVESERVICES_TEST_PUBLISHED_BODY;
  TEST_ASSERT_EQUAL_INT(CVESERVICES_OK, static_ask("ABCDEFGHIJKLMNOPQRSTUVWX"));
  TEST_ASSERT_EQUAL_INT(CVESERVICES_OK, static_ask("YZ-0123456789"));
  TEST_ASSERT_EQUAL_STRING("https://cveawg.mitre.org/api/cve-id/YZ-0123456789", g_stub_last_url);
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);

  static const char* const neighbours[] = { "@", "[", "/", ":", ",", "." };
  for (size_t i = 0; i < sizeof(neighbours) / sizeof(neighbours[0]); i++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(CVESERVICES_INVALID_ID, static_ask(neighbours[i]), neighbours[i]);
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
}

void test_cveIdStateName_names_each_state(void)
{
  TEST_ASSERT_EQUAL_STRING("published",  cveservices_cveIdStateName(CVESERVICES_CVE_ID_STATE_PUBLISHED));
  TEST_ASSERT_EQUAL_STRING("reserved",   cveservices_cveIdStateName(CVESERVICES_CVE_ID_STATE_RESERVED));
  TEST_ASSERT_EQUAL_STRING("rejected",   cveservices_cveIdStateName(CVESERVICES_CVE_ID_STATE_REJECTED));
  TEST_ASSERT_EQUAL_STRING("unknown_id", cveservices_cveIdStateName(CVESERVICES_CVE_ID_STATE_UNKNOWN_ID));
  TEST_ASSERT_NULL(cveservices_cveIdStateName(CVESERVICES_CVE_ID_STATE_NOT_CHECKED));
}

void test_cveIdStateName_matches_the_docs_table(void)
{
  static char text[1 << 20];
  FILE* docs_file = fopen("docs/API_Documentation.md", "r");
  TEST_ASSERT_NOT_NULL(docs_file);
  size_t read_len = fread(text, 1, sizeof(text) - 1, docs_file);
  fclose(docs_file);
  text[read_len] = '\0';
  const char* section = strstr(text, "\n### CVE.org state of a missing CVE\n");
  TEST_ASSERT_NOT_NULL(section);
  const char* section_end = strstr(section + 1, "\n### ");
  TEST_ASSERT_NOT_NULL(section_end);
  static const CveServicesCveIdState_t states[] = {
    CVESERVICES_CVE_ID_STATE_PUBLISHED, CVESERVICES_CVE_ID_STATE_RESERVED,
    CVESERVICES_CVE_ID_STATE_REJECTED,  CVESERVICES_CVE_ID_STATE_UNKNOWN_ID,
  };
  for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++)
  {
    char row[64];
    snprintf(row, sizeof(row), "\n| `%s` | `CVE not found;", cveservices_cveIdStateName(states[i]));
    const char* found = strstr(section, row);
    TEST_ASSERT_TRUE_MESSAGE(found != NULL && found < section_end, row);
  }
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_tryReadCveIdState_reads_each_state_the_server_sent);
  RUN_TEST(test_tryReadCveIdState_states_are_distinct_values);
  RUN_TEST(test_tryReadCveIdState_reads_state_alone);
  RUN_TEST(test_tryReadCveIdState_refuses_another_spelling_of_the_state);
  RUN_TEST(test_tryReadCveIdState_refuses_a_state_that_is_not_a_string);
  RUN_TEST(test_tryReadCveIdState_refuses_a_body_without_a_top_level_state);
  RUN_TEST(test_tryReadCveIdState_a_nested_state_is_not_read);
  RUN_TEST(test_tryReadCveIdState_first_of_two_states_wins);
  RUN_TEST(test_tryReadCveIdState_reads_only_body_len_bytes);
  RUN_TEST(test_isUnknownCveIdBody_reads_the_not_found_answer);
  RUN_TEST(test_isUnknownCveIdBody_refuses_every_other_body);
  RUN_TEST(test_askCveIdState_sends_a_trusted_request_for_the_id);
  RUN_TEST(test_askCveIdState_reads_each_state_of_a_200);
  RUN_TEST(test_askCveIdState_404_not_found_is_an_unknown_id);
  RUN_TEST(test_askCveIdState_404_with_another_body_is_an_upstream_error);
  RUN_TEST(test_askCveIdState_a_state_body_on_another_status_is_an_upstream_error);
  RUN_TEST(test_askCveIdState_400_bad_input_and_200_not_found_are_upstream_errors);
  RUN_TEST(test_askCveIdState_200_without_a_readable_state_is_an_upstream_error);
  RUN_TEST(test_askCveIdState_transport_failures_are_upstream_errors);
  RUN_TEST(test_askCveIdState_429_is_rate_limited_with_its_wait);
  RUN_TEST(test_askCveIdState_waits_until_the_deadline_and_at_most_three_seconds);
  RUN_TEST(test_askCveIdState_past_deadline_sends_no_request);
  RUN_TEST(test_askCveIdState_the_longest_id_is_sent);
  RUN_TEST(test_askCveIdState_refuses_an_id_it_cannot_send_as_it_is);
  RUN_TEST(test_askCveIdState_accepts_every_byte_of_the_id_alphabet);
  RUN_TEST(test_cveIdStateName_names_each_state);
  RUN_TEST(test_cveIdStateName_matches_the_docs_table);
  return UNITY_END();
}
