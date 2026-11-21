#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <curl/curl.h>

#include "unity/unity.h"
#include "well_known.h"
#include "http_stub.h"

#define TEST_NOW_EPOCH 1795132800

#define TEST_ROBOTS_URL        "https://example.com/robots.txt"
#define TEST_SECURITY_TXT_URL  "https://example.com/.well-known/security.txt"

#define TEST_SECURITY_TXT_BODY "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\nCanonical: https://example.com/.well-known/security.txt\n"

static const char* const TEST_TEXT_LINES[]     = { "Content-Type: text/plain; charset=utf-8", NULL };
static const char* const TEST_GZIP_LINES[]     = { "Content-Type: text/plain; charset=utf-8", "Content-Encoding: gzip", NULL };
static const char* const TEST_IDENTITY_LINES[] = { "Content-Type: text/plain; charset=utf-8", "Content-Encoding: IDENTITY", NULL };

#define TEST_CLOCK_MAX_READING_COUNT 8

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
static int g_curlUrlGetFailingCall = -1;

CURLU*    __real_curl_url(void);
CURLUcode __real_curl_url_get(const CURLU* url, CURLUPart part, char** text_out, unsigned int flags);

CURLU* __wrap_curl_url(void)
{
  g_curlUrlCallCount++;
  return __real_curl_url();
}

CURLUcode __wrap_curl_url_get(const CURLU* url, CURLUPart part, char** text_out, unsigned int flags)
{
  if (g_curlUrlGetCallCount++ == g_curlUrlGetFailingCall)
    return CURLUE_OUT_OF_MEMORY;
  return __real_curl_url_get(url, part, text_out, flags);
}

static bool g_isRobotsParseFailing = false;

bool __real_robotstxt_parse(const char* body, size_t body_len, bool is_body_cut, const char* product_token, RobotsTxt_t* robots_out);
bool __wrap_robotstxt_parse(const char* body, size_t body_len, bool is_body_cut, const char* product_token, RobotsTxt_t* robots_out)
{
  if (g_isRobotsParseFailing)
  {
    memset(robots_out, 0, sizeof(*robots_out));
    return false;
  }
  TEST_ASSERT_EQUAL_STRING("ContrastAPI", product_token);
  return __real_robotstxt_parse(body, body_len, is_body_cut, product_token, robots_out);
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
  g_isRobotsParseFailing = false;
  g_curlUrlCallCount     = 0;
  g_curlUrlGetCallCount  = 0;
  g_curlUrlGetFailingCall = -1;

  static const int64_t still_clock[] = { 1000 };
  static_setClockReadings(still_clock, 1);
}

void tearDown(void) {}

static void static_setAnswers(const HttpStubAnswer_t* answers, int count)
{
  g_stub_answers      = answers;
  g_stub_answer_count = count;
}

static HttpError_t static_fetchFiles(WellKnownReport_t* report_out)
{
  memset(report_out, 0xA5, sizeof(*report_out));
  return well_known_fetchFiles("example.com", TEST_NOW_EPOCH, report_out);
}

static HttpError_t static_fetchGate(WellKnownRobotsGate_t* gate_out)
{
  memset(gate_out, 0xA5, sizeof(*gate_out));
  return well_known_fetchRobotsGate("example.com", 6000, gate_out);
}

static void static_assertZeroedReport(const WellKnownReport_t* report)
{
  static const WellKnownReport_t zeroed_report;
  TEST_ASSERT_EQUAL_MEMORY(&zeroed_report, report, sizeof(*report));
}

static bool static_hasRobotsIssue(const RobotsTxt_t* robots, RobotsTxtIssueCode_t issue_code)
{
  for (int i = 0; i < robots->m_issueKeptCount; i++)
    if (robots->ma_issues[i].m_issueCode == issue_code)
      return true;
  return false;
}

static bool static_hasSecurityTxtIssue(const SecurityTxtReport_t* report, SecurityTxtIssueCode_t issue_code)
{
  for (int i = 0; i < report->m_issueKeptCount; i++)
    if (report->ma_issues[i].m_issueCode == issue_code)
      return true;
  return false;
}

void test_robots_gate_state_follows_the_status(void)
{
  static const struct { int m_status; WellKnownRobotsState_t m_state; } cases[] = {
    { 199, WELL_KNOWN_ROBOTS_UNKNOWN    },
    { 200, WELL_KNOWN_ROBOTS_FILE_READ },
    { 299, WELL_KNOWN_ROBOTS_FILE_READ },
    { 300, WELL_KNOWN_ROBOTS_UNKNOWN    },
    { 399, WELL_KNOWN_ROBOTS_UNKNOWN    },
    { 400, WELL_KNOWN_ROBOTS_NO_FILE    },
    { 428, WELL_KNOWN_ROBOTS_NO_FILE    },
    { 429, WELL_KNOWN_ROBOTS_UNKNOWN    },
    { 430, WELL_KNOWN_ROBOTS_NO_FILE    },
    { 499, WELL_KNOWN_ROBOTS_NO_FILE    },
    { 500, WELL_KNOWN_ROBOTS_UNKNOWN    },
    { 503, WELL_KNOWN_ROBOTS_UNKNOWN    },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    HttpStubAnswer_t answers[] = { { .m_status = cases[i].m_status, .mp_body = "User-agent: *\nDisallow: /x\n", .mp_headerLines = TEST_TEXT_LINES } };
    static_setAnswers(answers, 1);
    g_stub_http_call_count = 0;
    char message[16];
    snprintf(message, sizeof(message), "%d", cases[i].m_status);

    WellKnownRobotsGate_t gate;
    TEST_ASSERT_EQUAL_INT_MESSAGE(HTTP_ERROR_NONE, static_fetchGate(&gate), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_http_call_count, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_state, gate.m_state, message);
    TEST_ASSERT_FALSE_MESSAGE(gate.m_hasContentEncoding, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_state == WELL_KNOWN_ROBOTS_FILE_READ ? 1 : 0, gate.m_robots.m_ruleKeptCount, message);
    well_known_robotsGateFree(&gate);
  }
}

void test_check_path_answers_for_each_state(void)
{
  static const struct {
    int                  m_status;
    RobotsTxtDecision_t  m_xDecision;
    int                  m_xRule;
    RobotsTxtDecision_t  m_yDecision;
  } cases[] = {
    { 404, ROBOTSTXT_DECISION_ALLOWED,    -1, ROBOTSTXT_DECISION_ALLOWED },
    { 503, ROBOTSTXT_DECISION_UNKNOWN,    -1, ROBOTSTXT_DECISION_UNKNOWN },
    { 200, ROBOTSTXT_DECISION_DISALLOWED, 0,  ROBOTSTXT_DECISION_ALLOWED },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    HttpStubAnswer_t answers[] = { { .m_status = cases[i].m_status, .mp_body = "User-agent: *\nDisallow: /x\n" } };
    static_setAnswers(answers, 1);
    g_stub_http_call_count = 0;

    WellKnownRobotsGate_t gate;
    TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchGate(&gate));
    RobotsTxtVerdict_t x_verdict = well_known_robotsGateVerdict(&gate, "/x", 2);
    RobotsTxtVerdict_t y_verdict = well_known_robotsGateVerdict(&gate, "/y", 2);
    TEST_ASSERT_EQUAL_INT(cases[i].m_xDecision, x_verdict.m_decision);
    TEST_ASSERT_EQUAL_INT(cases[i].m_xRule, x_verdict.m_decidingRuleIndexInRules);
    TEST_ASSERT_EQUAL_INT(cases[i].m_yDecision, y_verdict.m_decision);
    TEST_ASSERT_EQUAL_INT(-1, y_verdict.m_decidingRuleIndexInRules);
    well_known_robotsGateFree(&gate);
  }
}

void test_robots_gate_does_not_read_an_encoded_body(void)
{
  HttpStubAnswer_t gzip_answers[] = { { .m_status = 200, .mp_body = "User-agent: *\nDisallow: /x\n", .mp_headerLines = TEST_GZIP_LINES } };
  static_setAnswers(gzip_answers, 1);
  WellKnownRobotsGate_t gate;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchGate(&gate));
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_ROBOTS_UNKNOWN, gate.m_state);
  TEST_ASSERT_TRUE(gate.m_hasContentEncoding);
  TEST_ASSERT_EQUAL_INT(0, gate.m_robots.m_ruleKeptCount);
  well_known_robotsGateFree(&gate);

  HttpStubAnswer_t identity_answers[] = { { .m_status = 200, .mp_body = "User-agent: *\nDisallow: /x\n", .mp_headerLines = TEST_IDENTITY_LINES } };
  static_setAnswers(identity_answers, 1);
  g_stub_http_call_count = 0;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchGate(&gate));
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_ROBOTS_FILE_READ, gate.m_state);
  TEST_ASSERT_FALSE(gate.m_hasContentEncoding);
  TEST_ASSERT_EQUAL_INT(1, gate.m_robots.m_ruleKeptCount);
  well_known_robotsGateFree(&gate);
}

void test_robots_gate_that_cannot_parse_is_unknown(void)
{
  HttpStubAnswer_t answers[] = { { .m_status = 200, .mp_body = "User-agent: *\nAllow: /\n" } };
  static_setAnswers(answers, 1);
  g_isRobotsParseFailing = true;

  WellKnownRobotsGate_t gate;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchGate(&gate));
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_ROBOTS_UNKNOWN, gate.m_state);
  TEST_ASSERT_FALSE(gate.m_hasContentEncoding);
  TEST_ASSERT_EQUAL_INT(ROBOTSTXT_DECISION_UNKNOWN, well_known_robotsGateVerdict(&gate, "/", 1).m_decision);
  well_known_robotsGateFree(&gate);
}

void test_robots_gate_notes_another_host_and_the_content_type(void)
{
  static const char* const redirect_lines[] = { "Location: https://www.example.com/robots.txt", NULL };
  static const char* const html_lines[]     = { "Content-Type: text/html", NULL };
  HttpStubAnswer_t www_answers[] = {
    { .m_status = 301, .mp_headerLines = redirect_lines },
    { .m_status = 200, .mp_body = "User-agent: *\nAllow: /\n", .mp_headerLines = TEST_TEXT_LINES },
  };
  static_setAnswers(www_answers, 2);
  WellKnownRobotsGate_t gate;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchGate(&gate));
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_ROBOTS_FILE_READ, gate.m_state);
  TEST_ASSERT_TRUE(static_hasRobotsIssue(&gate.m_robots, ROBOTSTXT_ISSUE_REDIRECTED_TO_OTHER_HOST));
  TEST_ASSERT_FALSE(static_hasRobotsIssue(&gate.m_robots, ROBOTSTXT_ISSUE_CONTENT_TYPE_NOT_TEXT_PLAIN));
  well_known_robotsGateFree(&gate);

  HttpStubAnswer_t html_answers[] = { { .m_status = 200, .mp_body = "User-agent: *\nAllow: /\n", .mp_headerLines = html_lines } };
  static_setAnswers(html_answers, 1);
  g_stub_http_call_count = 0;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchGate(&gate));
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_ROBOTS_FILE_READ, gate.m_state);
  TEST_ASSERT_FALSE(static_hasRobotsIssue(&gate.m_robots, ROBOTSTXT_ISSUE_REDIRECTED_TO_OTHER_HOST));
  TEST_ASSERT_TRUE(static_hasRobotsIssue(&gate.m_robots, ROBOTSTXT_ISSUE_CONTENT_TYPE_NOT_TEXT_PLAIN));
  well_known_robotsGateFree(&gate);
}

void test_robots_gate_compares_the_host_in_any_case(void)
{
  static const char* const redirect_lines[] = { "Location: https://EXAMPLE.COM/robots.txt", NULL };
  HttpStubAnswer_t answers[] = {
    { .m_status = 301, .mp_headerLines = redirect_lines },
    { .m_status = 200, .mp_body = "User-agent: *\nAllow: /\n", .mp_headerLines = TEST_TEXT_LINES },
  };
  static_setAnswers(answers, 2);
  WellKnownRobotsGate_t gate;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchGate(&gate));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_LOOP, gate.m_chain.m_stopReason);
  TEST_ASSERT_EQUAL_STRING("https://EXAMPLE.COM/robots.txt", gate.m_chain.mp_unfollowedUrl);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_ROBOTS_UNKNOWN, gate.m_state);
  well_known_robotsGateFree(&gate);
}

void test_failed_robots_gate_answers_its_error(void)
{
  static const WellKnownRobotsGate_t zeroed_gate;
  HttpStubAnswer_t first_fails[] = { { .m_error = HTTP_ERROR_CONNECT } };
  static_setAnswers(first_fails, 1);
  WellKnownRobotsGate_t gate;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_CONNECT, static_fetchGate(&gate));
  TEST_ASSERT_EQUAL_MEMORY(&zeroed_gate, &gate, sizeof(gate));

  HttpStubAnswer_t second_fails[] = {
    { .m_status = 301, .mp_body = "moved", .mp_redirectUrl = "https://www.example.com/robots.txt" },
    { .m_error = HTTP_ERROR_CONNECT },
  };
  static_setAnswers(second_fails, 2);
  g_stub_http_call_count = 0;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_CONNECT, static_fetchGate(&gate));
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_MEMORY(&zeroed_gate, &gate, sizeof(gate));
}

void test_robots_first_url_the_same_site_rule_refuses_is_unknown(void)
{
  HttpStubAnswer_t answers[] = { { .m_status = 200, .mp_body = "User-agent: *\nAllow: /\n" } };
  static_setAnswers(answers, 1);
  g_curlUrlGetFailingCall = 1;
  WellKnownRobotsGate_t gate;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchGate(&gate));
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_ROBOTS_UNKNOWN, gate.m_state);
  TEST_ASSERT_EQUAL_INT(ROBOTSTXT_DECISION_UNKNOWN, well_known_robotsGateVerdict(&gate, "/", 1).m_decision);
  well_known_robotsGateFree(&gate);
}

void test_security_txt_path_reaches_the_gate_whole(void)
{
  HttpStubAnswer_t answers[] = {
    { .m_status = 200, .mp_body = "User-agent: *\nDisallow: /.well-known/security.txt$\n", .mp_headerLines = TEST_TEXT_LINES },
    { .m_status = 200, .mp_body = TEST_SECURITY_TXT_BODY },
  };
  static_setAnswers(answers, 2);
  WellKnownReport_t report;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_SECURITY_TXT_ROBOTS_DISALLOWED, report.m_securityTxt.m_status);
  well_known_reportFree(&report);
}

void test_robots_disallow_keeps_security_txt_from_being_fetched(void)
{
  HttpStubAnswer_t answers[] = {
    { .m_status = 200, .mp_body = "User-agent: *\nAllow: /\nDisallow: /.well-known/\n", .mp_headerLines = TEST_TEXT_LINES },
    { .m_status = 200, .mp_body = TEST_SECURITY_TXT_BODY },
  };
  static_setAnswers(answers, 2);

  WellKnownReport_t report;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_SECURITY_TXT_ROBOTS_DISALLOWED, report.m_securityTxt.m_status);
  TEST_ASSERT_EQUAL_INT(ROBOTSTXT_DECISION_DISALLOWED, report.m_securityTxt.m_pathRobotsVerdict.m_decision);
  TEST_ASSERT_EQUAL_INT(1, report.m_securityTxt.m_pathRobotsVerdict.m_decidingRuleIndexInRules);
  TEST_ASSERT_EQUAL_INT(0, report.m_securityTxt.m_chain.m_hopCount);
  well_known_reportFree(&report);
  static_assertZeroedReport(&report);
}

void test_robots_404_lets_security_txt_be_fetched(void)
{
  HttpStubAnswer_t answers[] = {
    { .m_status = 404, .mp_body = "Disallow: /" },
    { .m_status = 404, .mp_body = "none" },
  };
  static_setAnswers(answers, 2);

  WellKnownReport_t report;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING(TEST_SECURITY_TXT_URL, g_stub_requests[1].ma_url);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_ROBOTS_NO_FILE, report.m_robotsGate.m_state);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_SECURITY_TXT_NOT_FOUND, report.m_securityTxt.m_status);
  TEST_ASSERT_EQUAL_INT(ROBOTSTXT_DECISION_ALLOWED, report.m_securityTxt.m_pathRobotsVerdict.m_decision);
  TEST_ASSERT_EQUAL_INT(-1, report.m_securityTxt.m_pathRobotsVerdict.m_decidingRuleIndexInRules);
  well_known_reportFree(&report);
}

void test_unreadable_robots_keeps_security_txt_from_being_fetched(void)
{
  static char long_rule[2200];
  memset(long_rule, 0, sizeof(long_rule));
  memcpy(long_rule, "User-agent: *\nDisallow: /", 25);
  memset(long_rule + 25, 'a', 2100);
  long_rule[2125] = '\n';

  static const HttpStubAnswer_t answers_429[]   = { { .m_status = 429, .mp_body = "slow down" }, { .m_status = 200 } };
  static const HttpStubAnswer_t answers_503[]   = { { .m_status = 503, .mp_body = "" }, { .m_status = 200 } };
  static const HttpStubAnswer_t answers_other[] = { { .m_status = 302, .mp_redirectUrl = "https://cdn.example.net/robots.txt" }, { .m_status = 200 } };
  static const HttpStubAnswer_t answers_gzip[]  = { { .m_status = 200, .mp_body = "x", .mp_headerLines = TEST_GZIP_LINES }, { .m_status = 200 } };
  const HttpStubAnswer_t        answers_long[]  = { { .m_status = 200, .mp_body = long_rule, .mp_headerLines = TEST_TEXT_LINES }, { .m_status = 200 } };
  const struct {
    const HttpStubAnswer_t*  mp_answers;
    WellKnownRobotsState_t   m_state;
    const char*              mp_what;
  } cases[] = {
    { answers_429,   WELL_KNOWN_ROBOTS_UNKNOWN,    "429" },
    { answers_503,   WELL_KNOWN_ROBOTS_UNKNOWN,    "503" },
    { answers_other, WELL_KNOWN_ROBOTS_UNKNOWN,    "redirect to another host" },
    { answers_gzip,  WELL_KNOWN_ROBOTS_UNKNOWN,    "gzip" },
    { answers_long,  WELL_KNOWN_ROBOTS_FILE_READ, "dropped rule" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    static_setAnswers(cases[i].mp_answers, 2);
    g_stub_http_call_count = 0;

    WellKnownReport_t report;
    TEST_ASSERT_EQUAL_INT_MESSAGE(HTTP_ERROR_NONE, static_fetchFiles(&report), cases[i].mp_what);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_stub_http_call_count, cases[i].mp_what);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_state, report.m_robotsGate.m_state, cases[i].mp_what);
    TEST_ASSERT_EQUAL_INT_MESSAGE(WELL_KNOWN_SECURITY_TXT_ROBOTS_UNKNOWN, report.m_securityTxt.m_status, cases[i].mp_what);
    TEST_ASSERT_EQUAL_INT_MESSAGE(ROBOTSTXT_DECISION_UNKNOWN, report.m_securityTxt.m_pathRobotsVerdict.m_decision, cases[i].mp_what);
    TEST_ASSERT_EQUAL_INT_MESSAGE(-1, report.m_securityTxt.m_pathRobotsVerdict.m_decidingRuleIndexInRules, cases[i].mp_what);
    well_known_reportFree(&report);
  }
}

void test_security_txt_200_is_read_against_the_last_url(void)
{
  static const char* const redirect_lines[] = { "Location: https://www.example.com/.well-known/security.txt", NULL };
  HttpStubAnswer_t direct[] = {
    { .m_status = 404 },
    { .m_status = 200, .mp_body = TEST_SECURITY_TXT_BODY, .mp_headerLines = TEST_TEXT_LINES },
  };
  static_setAnswers(direct, 2);
  WellKnownReport_t report;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_SECURITY_TXT_FOUND, report.m_securityTxt.m_status);
  TEST_ASSERT_FALSE(report.m_securityTxt.m_hasContentEncoding);
  const SecurityTxtReport_t* parsed = &report.m_securityTxt.m_report;
  TEST_ASSERT_EQUAL_INT(1, parsed->ma_valueKeptCount[SECURITYTXT_FIELD_CONTACT]);
  const SecurityTxtSpan_t* contact = &parsed->ma_values[SECURITYTXT_FIELD_CONTACT][0];
  TEST_ASSERT_EQUAL_STRING_LEN("mailto:security@example.com", report.m_securityTxt.m_chain.mp_body + contact->m_offset, contact->m_len);
  TEST_ASSERT_EQUAL_size_t(strlen("mailto:security@example.com"), contact->m_len);
  TEST_ASSERT_EQUAL_INT(0, parsed->m_issueTotalCount);
  well_known_reportFree(&report);

  static const char* const robots_redirect_lines[] = { "Location: https://www.example.com/robots.txt", NULL };
  HttpStubAnswer_t redirected[] = {
    { .m_status = 301, .mp_headerLines = robots_redirect_lines },
    { .m_status = 404 },
    { .m_status = 301, .mp_headerLines = redirect_lines },
    { .m_status = 200, .mp_body = TEST_SECURITY_TXT_BODY, .mp_headerLines = TEST_TEXT_LINES },
  };
  static_setAnswers(redirected, 4);
  g_stub_http_call_count = 0;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(4, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_SECURITY_TXT_FOUND, report.m_securityTxt.m_status);
  TEST_ASSERT_TRUE(static_hasSecurityTxtIssue(&report.m_securityTxt.m_report, SECURITYTXT_ISSUE_CANONICAL_MISMATCH));
  TEST_ASSERT_TRUE(static_hasSecurityTxtIssue(&report.m_securityTxt.m_report, SECURITYTXT_ISSUE_REDIRECTED_TO_OTHER_HOST));
  TEST_ASSERT_FALSE(static_hasSecurityTxtIssue(&report.m_securityTxt.m_report, SECURITYTXT_ISSUE_CONTENT_TYPE_INVALID));
  well_known_reportFree(&report);
}

void test_security_txt_status_follows_the_answer(void)
{
  static const struct {
    int                           m_status;
    bool                          m_isBodyCut;
    WellKnownSecurityTxtStatus_t  m_securityTxtStatus;
  } cases[] = {
    { 199, false, WELL_KNOWN_SECURITY_TXT_NOT_FOUND   },
    { 200, false, WELL_KNOWN_SECURITY_TXT_FOUND       },
    { 299, false, WELL_KNOWN_SECURITY_TXT_FOUND       },
    { 200, true,  WELL_KNOWN_SECURITY_TXT_TOO_LARGE   },
    { 300, false, WELL_KNOWN_SECURITY_TXT_NOT_FETCHED },
    { 399, false, WELL_KNOWN_SECURITY_TXT_NOT_FETCHED },
    { 400, false, WELL_KNOWN_SECURITY_TXT_NOT_FOUND   },
    { 404, false, WELL_KNOWN_SECURITY_TXT_NOT_FOUND   },
    { 404, true,  WELL_KNOWN_SECURITY_TXT_NOT_FOUND   },
    { 428, false, WELL_KNOWN_SECURITY_TXT_NOT_FOUND   },
    { 429, false, WELL_KNOWN_SECURITY_TXT_UNAVAILABLE },
    { 430, false, WELL_KNOWN_SECURITY_TXT_NOT_FOUND   },
    { 499, false, WELL_KNOWN_SECURITY_TXT_NOT_FOUND   },
    { 500, false, WELL_KNOWN_SECURITY_TXT_UNAVAILABLE },
    { 599, false, WELL_KNOWN_SECURITY_TXT_UNAVAILABLE },
    { 600, false, WELL_KNOWN_SECURITY_TXT_NOT_FOUND   },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    HttpStubAnswer_t answers[] = {
      { .m_status = 404 },
      { .m_status = cases[i].m_status, .mp_body = TEST_SECURITY_TXT_BODY, .m_isBodyCut = cases[i].m_isBodyCut, .mp_headerLines = TEST_TEXT_LINES },
    };
    static_setAnswers(answers, 2);
    g_stub_http_call_count = 0;
    char message[32];
    snprintf(message, sizeof(message), "%d cut=%d", cases[i].m_status, cases[i].m_isBodyCut);

    WellKnownReport_t report;
    TEST_ASSERT_EQUAL_INT_MESSAGE(HTTP_ERROR_NONE, static_fetchFiles(&report), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, g_stub_http_call_count, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_securityTxtStatus, report.m_securityTxt.m_status, message);
    int expected_contact_count = cases[i].m_securityTxtStatus == WELL_KNOWN_SECURITY_TXT_FOUND ? 1 : 0;
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected_contact_count, report.m_securityTxt.m_report.ma_valueKeptCount[SECURITYTXT_FIELD_CONTACT], message);
    well_known_reportFree(&report);
  }
}

void test_security_txt_redirect_to_a_disallowed_path_is_not_sent(void)
{
  static const char* const redirect_lines[] = { "Location: /private/security.txt", NULL };
  HttpStubAnswer_t answers[] = {
    { .m_status = 200, .mp_body = "User-agent: *\nDisallow: /private\n", .mp_headerLines = TEST_TEXT_LINES },
    { .m_status = 302, .mp_headerLines = redirect_lines },
    { .m_status = 200, .mp_body = TEST_SECURITY_TXT_BODY },
  };
  static_setAnswers(answers, 3);

  WellKnownReport_t report;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_SECURITY_TXT_ROBOTS_DISALLOWED, report.m_securityTxt.m_status);
  TEST_ASSERT_EQUAL_INT(ROBOTSTXT_DECISION_DISALLOWED, report.m_securityTxt.m_pathRobotsVerdict.m_decision);
  TEST_ASSERT_EQUAL_INT(0, report.m_securityTxt.m_pathRobotsVerdict.m_decidingRuleIndexInRules);
  TEST_ASSERT_EQUAL_INT(1, report.m_securityTxt.m_chain.m_hopCount);
  TEST_ASSERT_EQUAL_STRING("https://example.com/private/security.txt", report.m_securityTxt.m_chain.mp_unfollowedUrl);
  well_known_reportFree(&report);
}

void test_security_txt_redirect_to_a_host_without_robots_is_not_sent(void)
{
  static const char* const redirect_lines[] = { "Location: https://www.example.com/.well-known/security.txt", NULL };
  HttpStubAnswer_t answers[] = {
    { .m_status = 404 },
    { .m_status = 302, .mp_headerLines = redirect_lines },
    { .m_status = 200, .mp_body = TEST_SECURITY_TXT_BODY },
  };
  static_setAnswers(answers, 3);

  WellKnownReport_t report;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_SECURITY_TXT_ROBOTS_UNKNOWN, report.m_securityTxt.m_status);
  TEST_ASSERT_EQUAL_INT(ROBOTSTXT_DECISION_UNKNOWN, report.m_securityTxt.m_pathRobotsVerdict.m_decision);
  TEST_ASSERT_EQUAL_INT(-1, report.m_securityTxt.m_pathRobotsVerdict.m_decidingRuleIndexInRules);
  well_known_reportFree(&report);
}

void test_security_txt_redirect_to_the_host_robots_ended_on_is_sent(void)
{
  static const char* const robots_redirect_lines[]   = { "Location: https://WWW.example.com/robots.txt", NULL };
  static const char* const security_redirect_lines[] = { "Location: https://www.example.com/.well-known/security.txt", NULL };
  HttpStubAnswer_t answers[] = {
    { .m_status = 301, .mp_headerLines = robots_redirect_lines },
    { .m_status = 404 },
    { .m_status = 302, .mp_headerLines = security_redirect_lines },
    { .m_status = 200, .mp_body = TEST_SECURITY_TXT_BODY, .mp_headerLines = TEST_TEXT_LINES },
  };
  static_setAnswers(answers, 4);

  WellKnownReport_t report;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(4, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING("https://www.example.com/.well-known/security.txt", g_stub_requests[3].ma_url);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_SECURITY_TXT_FOUND, report.m_securityTxt.m_status);
  well_known_reportFree(&report);
}

void test_robots_redirect_to_another_path_leaves_its_host_unknown(void)
{
  static const char* const robots_redirect_lines[]   = { "Location: https://www.example.com/not-robots", NULL };
  static const char* const security_redirect_lines[] = { "Location: https://www.example.com/.well-known/security.txt", NULL };
  HttpStubAnswer_t answers[] = {
    { .m_status = 301, .mp_headerLines = robots_redirect_lines },
    { .m_status = 404 },
    { .m_status = 302, .mp_headerLines = security_redirect_lines },
    { .m_status = 200, .mp_body = TEST_SECURITY_TXT_BODY, .mp_headerLines = TEST_TEXT_LINES },
  };
  static_setAnswers(answers, 4);

  WellKnownReport_t report;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(3, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_SECURITY_TXT_ROBOTS_UNKNOWN, report.m_securityTxt.m_status);
  well_known_reportFree(&report);
}

void test_encoded_security_txt_is_found_and_not_read(void)
{
  static const SecurityTxtReport_t zeroed_report;
  HttpStubAnswer_t answers[] = {
    { .m_status = 404 },
    { .m_status = 200, .mp_body = TEST_SECURITY_TXT_BODY, .mp_headerLines = TEST_GZIP_LINES },
  };
  static_setAnswers(answers, 2);

  WellKnownReport_t report;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_SECURITY_TXT_FOUND, report.m_securityTxt.m_status);
  TEST_ASSERT_TRUE(report.m_securityTxt.m_hasContentEncoding);
  TEST_ASSERT_EQUAL_MEMORY(&zeroed_report, &report.m_securityTxt.m_report, sizeof(zeroed_report));
  well_known_reportFree(&report);
}

void test_two_fetches_share_one_deadline(void)
{
  HttpStubAnswer_t answers[] = {
    { .m_status = 404 },
    { .m_status = 200, .mp_body = TEST_SECURITY_TXT_BODY, .mp_headerLines = TEST_TEXT_LINES },
  };
  static_setAnswers(answers, 2);
  static const int64_t readings[] = { 1000, 1000, 3500 };
  static_setClockReadings(readings, 3);

  WellKnownReport_t report;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(5000, g_stub_requests[0].m_timeoutMs);
  TEST_ASSERT_EQUAL_INT(2500, g_stub_requests[1].m_timeoutMs);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_SECURITY_TXT_FOUND, report.m_securityTxt.m_status);
  well_known_reportFree(&report);

  static const int64_t late_readings[] = { 1000, 1000, 6000 };
  static_setClockReadings(late_readings, 3);
  g_stub_http_call_count = 0;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_SECURITY_TXT_NOT_FETCHED, report.m_securityTxt.m_status);
  TEST_ASSERT_EQUAL_INT(0, report.m_securityTxt.m_chain.m_hopCount);
  TEST_ASSERT_EQUAL_INT(ROBOTSTXT_DECISION_ALLOWED, report.m_securityTxt.m_pathRobotsVerdict.m_decision);
  TEST_ASSERT_EQUAL_INT(-1, report.m_securityTxt.m_pathRobotsVerdict.m_decidingRuleIndexInRules);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_ROBOTS_NO_FILE, report.m_robotsGate.m_state);
  well_known_reportFree(&report);
}

void test_deadline_inside_the_security_txt_chain_is_not_fetched(void)
{
  static const char* const redirect_lines[] = { "Location: /.well-known/security2.txt", NULL };
  HttpStubAnswer_t answers[] = {
    { .m_status = 404 },
    { .m_status = 301, .mp_headerLines = redirect_lines },
    { .m_status = 200, .mp_body = TEST_SECURITY_TXT_BODY },
  };
  static_setAnswers(answers, 3);
  static const int64_t readings[] = { 1000, 1000, 1000, 6000 };
  static_setClockReadings(readings, 4);

  WellKnownReport_t report;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_SECURITY_TXT_NOT_FETCHED, report.m_securityTxt.m_status);
  well_known_reportFree(&report);
}

void test_security_txt_url_the_rule_refuses_sends_nothing(void)
{
  HttpStubAnswer_t answers[] = {
    { .m_status = 404 },
    { .m_status = 200, .mp_body = TEST_SECURITY_TXT_BODY },
  };
  static_setAnswers(answers, 2);
  g_curlUrlGetFailingCall = 6;

  WellKnownReport_t report;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(0, report.m_securityTxt.m_chain.m_hopCount);
  TEST_ASSERT_EQUAL_INT(HEADER_FETCH_STOP_OFF_SITE, report.m_securityTxt.m_chain.m_stopReason);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_SECURITY_TXT_NOT_FOUND, report.m_securityTxt.m_status);
  TEST_ASSERT_EQUAL_INT(ROBOTSTXT_DECISION_UNKNOWN, report.m_securityTxt.m_pathRobotsVerdict.m_decision);
  TEST_ASSERT_EQUAL_INT(-1, report.m_securityTxt.m_pathRobotsVerdict.m_decidingRuleIndexInRules);
  well_known_reportFree(&report);
}

void test_each_request_carries_its_flags_and_body_limit(void)
{
  HttpStubAnswer_t answers[] = {
    { .m_status = 404 },
    { .m_status = 200, .mp_body = TEST_SECURITY_TXT_BODY, .mp_headerLines = TEST_TEXT_LINES },
  };
  static_setAnswers(answers, 2);

  WellKnownReport_t report;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING(TEST_ROBOTS_URL, g_stub_requests[0].ma_url);
  TEST_ASSERT_EQUAL_size_t(524288, g_stub_requests[0].m_maxBodyByteCount);
  TEST_ASSERT_EQUAL_STRING(TEST_SECURITY_TXT_URL, g_stub_requests[1].ma_url);
  TEST_ASSERT_EQUAL_size_t(32768, g_stub_requests[1].m_maxBodyByteCount);
  for (int i = 0; i < 2; i++)
  {
    const HttpStubRequest_t* request = &g_stub_requests[i];
    TEST_ASSERT_EQUAL_STRING("Content-Type\nContent-Encoding\nLocation\nRefresh", request->ma_headerNamesToCapture);
    TEST_ASSERT_FALSE(request->m_isTargetTrusted);
    TEST_ASSERT_TRUE(request->m_isHttpsOnly);
    TEST_ASSERT_TRUE(request->m_isRedirectLeftToCaller);
    TEST_ASSERT_TRUE(request->m_isBodyCutAccepted);
    TEST_ASSERT_EQUAL_UINT16(443, request->m_requiredPort);
  }
  well_known_reportFree(&report);
}

void test_failed_robots_request_fails_the_check(void)
{
  HttpStubAnswer_t answers[] = { { .m_error = HTTP_ERROR_TLS } };
  static_setAnswers(answers, 1);

  WellKnownReport_t report;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_TLS, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  static_assertZeroedReport(&report);
}

void test_failed_security_txt_request_fails_the_check(void)
{
  static const char* const redirect_lines[] = { "Location: /.well-known/security2.txt", NULL };
  HttpStubAnswer_t first_fails[] = {
    { .m_status = 404 },
    { .m_error = HTTP_ERROR_RESOLVE },
  };
  static_setAnswers(first_fails, 2);
  WellKnownReport_t report;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_RESOLVE, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  static_assertZeroedReport(&report);

  HttpStubAnswer_t second_fails[] = {
    { .m_status = 404 },
    { .m_status = 301, .mp_body = "moved", .mp_headerLines = redirect_lines },
    { .m_error = HTTP_ERROR_RESOLVE },
  };
  static_setAnswers(second_fails, 3);
  g_stub_http_call_count = 0;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_RESOLVE, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(3, g_stub_http_call_count);
  static_assertZeroedReport(&report);
}

void test_report_free_zeroes_the_report(void)
{
  HttpStubAnswer_t answers[] = {
    { .m_status = 200, .mp_body = "User-agent: *\nAllow: /\n", .mp_headerLines = TEST_TEXT_LINES },
    { .m_status = 200, .mp_body = TEST_SECURITY_TXT_BODY, .mp_headerLines = TEST_TEXT_LINES },
  };
  static_setAnswers(answers, 2);

  WellKnownReport_t report;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchFiles(&report));
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_ROBOTS_FILE_READ, report.m_robotsGate.m_state);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_SECURITY_TXT_FOUND, report.m_securityTxt.m_status);
  TEST_ASSERT_EQUAL_INT(ROBOTSTXT_DECISION_ALLOWED, report.m_securityTxt.m_pathRobotsVerdict.m_decision);
  TEST_ASSERT_EQUAL_INT(0, report.m_securityTxt.m_pathRobotsVerdict.m_decidingRuleIndexInRules);
  well_known_reportFree(&report);
  static_assertZeroedReport(&report);

  WellKnownReport_t zeroed = { 0 };
  well_known_reportFree(&zeroed);
  static_assertZeroedReport(&zeroed);
}

void test_failed_host_read_does_not_send_the_redirect(void)
{
  static const char* const redirect_lines[] = { "Location: https://www.example.com/.well-known/security.txt", NULL };
  HttpStubAnswer_t answers[] = {
    { .m_status = 404 },
    { .m_status = 302, .mp_headerLines = redirect_lines },
    { .m_status = 200, .mp_body = TEST_SECURITY_TXT_BODY },
  };
  for (int failing_call = 0; failing_call < 40; failing_call++)
  {
    static_setAnswers(answers, 3);
    g_stub_http_call_count  = 0;
    g_curlUrlGetCallCount   = 0;
    g_curlUrlGetFailingCall = failing_call;
    WellKnownReport_t report;
    (void)static_fetchFiles(&report);
    TEST_ASSERT_TRUE_MESSAGE(g_stub_http_call_count <= 2, "redirect to a host without robots was sent");
    well_known_reportFree(&report);
  }
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(29, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

void test_robots_redirect_to_its_host_in_another_case_is_no_other_host(void)
{
  static const char* const redirect_lines[] = { "Location: https://EXAMPLE.COM/robots.txt?v=1", NULL };
  HttpStubAnswer_t answers[] = {
    { .m_status = 301, .mp_headerLines = redirect_lines },
    { .m_status = 200, .mp_body = "User-agent: *\nAllow: /\n", .mp_headerLines = TEST_TEXT_LINES },
  };
  static_setAnswers(answers, 2);
  WellKnownRobotsGate_t gate;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, static_fetchGate(&gate));
  TEST_ASSERT_EQUAL_INT(2, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_INT(WELL_KNOWN_ROBOTS_FILE_READ, gate.m_state);
  TEST_ASSERT_FALSE(static_hasRobotsIssue(&gate.m_robots, ROBOTSTXT_ISSUE_REDIRECTED_TO_OTHER_HOST));
  well_known_robotsGateFree(&gate);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_robots_redirect_to_its_host_in_another_case_is_no_other_host);
  RUN_TEST(test_robots_gate_state_follows_the_status);
  RUN_TEST(test_check_path_answers_for_each_state);
  RUN_TEST(test_robots_gate_does_not_read_an_encoded_body);
  RUN_TEST(test_robots_gate_that_cannot_parse_is_unknown);
  RUN_TEST(test_robots_gate_notes_another_host_and_the_content_type);
  RUN_TEST(test_robots_gate_compares_the_host_in_any_case);
  RUN_TEST(test_failed_robots_gate_answers_its_error);
  RUN_TEST(test_robots_first_url_the_same_site_rule_refuses_is_unknown);
  RUN_TEST(test_security_txt_path_reaches_the_gate_whole);
  RUN_TEST(test_robots_disallow_keeps_security_txt_from_being_fetched);
  RUN_TEST(test_robots_404_lets_security_txt_be_fetched);
  RUN_TEST(test_unreadable_robots_keeps_security_txt_from_being_fetched);
  RUN_TEST(test_security_txt_200_is_read_against_the_last_url);
  RUN_TEST(test_security_txt_status_follows_the_answer);
  RUN_TEST(test_security_txt_redirect_to_a_disallowed_path_is_not_sent);
  RUN_TEST(test_security_txt_redirect_to_a_host_without_robots_is_not_sent);
  RUN_TEST(test_security_txt_redirect_to_the_host_robots_ended_on_is_sent);
  RUN_TEST(test_failed_host_read_does_not_send_the_redirect);
  RUN_TEST(test_robots_redirect_to_another_path_leaves_its_host_unknown);
  RUN_TEST(test_encoded_security_txt_is_found_and_not_read);
  RUN_TEST(test_two_fetches_share_one_deadline);
  RUN_TEST(test_deadline_inside_the_security_txt_chain_is_not_fetched);
  RUN_TEST(test_security_txt_url_the_rule_refuses_sends_nothing);
  RUN_TEST(test_each_request_carries_its_flags_and_body_limit);
  RUN_TEST(test_failed_robots_request_fails_the_check);
  RUN_TEST(test_failed_security_txt_request_fails_the_check);
  RUN_TEST(test_report_free_zeroes_the_report);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
