#include <stdio.h>
#include <string.h>

#include "unity/unity.h"
#include "header_check.h"

#define CSP_QUIET_TAIL "; object-src 'none'; base-uri 'self'"

#define TEXT_CSP_REPORT_ONLY      "Only Content-Security-Policy-Report-Only is set; a report-only policy is not enforced"
#define TEXT_CSP_NO_SCRIPT        "No default-src or script-src directive; scripts may load from any source"
#define TEXT_CSP_NO_OBJECT_SRC    "Missing object-src directive (recommended: object-src 'none')"
#define TEXT_CSP_NO_BASE_URI      "Missing base-uri directive (recommended: base-uri 'none' or 'self')"
#define TEXT_HSTS_NO_MAX_AGE      "Missing max-age directive"
#define TEXT_HSTS_MALFORMED       "Malformed max-age directive"
#define TEXT_HSTS_NO_SUBDOMAINS   "Missing includeSubDomains directive"
#define TEXT_HSTS_MULTIPLE        "More than one Strict-Transport-Security header; only the first is used"
#define TEXT_XCTO_INVALID         "Invalid value. Allowed: nosniff (case-insensitive)"
#define TEXT_XFO_INVALID          "Invalid value. Allowed: DENY, SAMEORIGIN (case-insensitive)"
#define TEXT_REFERRER_UNKNOWN     "No valid referrer policy token"
#define TEXT_REFERRER_UNSAFE_URL  "Policy unsafe-url sends the full URL, path and query included, to every origin"
#define TEXT_REFERRER_DOWNGRADE   "Policy no-referrer-when-downgrade sends the full URL to every HTTPS origin"
#define TEXT_XXP_ENABLED          "A value other than 0 turns on the legacy XSS filter, which can create XSS vulnerabilities"

#define TEXT_REFERRER_ORIGIN        "Policy origin sends the origin to plain http pages too; strict-origin does not"
#define TEXT_REFERRER_CROSS_ORIGIN  "Policy origin-when-cross-origin sends the origin to plain http pages too; strict-origin-when-cross-origin does not"
#define TEXT_PERMISSIONS_MALFORMED  "The value does not parse as a structured field dictionary (RFC 8941), so browsers ignore the whole header"
#define TEXT_PERMISSIONS_WILDCARD   "A feature allows every origin with *"

#define TEXT_CORS_NULL_ORIGIN       "Allowing the origin null lets any sandboxed frame read the answer"
#define TEXT_CORS_WILDCARD_CREDS    "Allowing credentials with the origin * is an error; browsers refuse * for a request with credentials"
#define TEXT_CORS_MULTIPLE_ORIGINS  "More than one origin; browsers accept only one, so every cross-origin read fails"

#define ASSERT_ISSUES(finding, ...)                                                          \
  do                                                                                         \
  {                                                                                          \
    const char* const expected_texts_[] = { __VA_ARGS__ };                                   \
    static_assertIssues((finding), expected_texts_, (int)(sizeof(expected_texts_) / sizeof(expected_texts_[0]))); \
  } while (0)

static char*               g_values[HEADER_CHECK_HEADER_COUNT];
static size_t              g_setCookieCopyCount;
static HeaderCheckReport_t g_report;

static char g_longValue[4096];

void setUp(void)
{
  memset(g_values, 0, sizeof(g_values));
  g_setCookieCopyCount = 0;
  memset(&g_report, 0xA5, sizeof(g_report));
}

void tearDown(void) {}

static const HeaderCheckFinding_t* static_evaluate(HeaderCheckHeader_t rule)
{
  header_check_evaluate(g_values, g_setCookieCopyCount, &g_report);
  return &g_report.ma_findings[rule];
}

static void static_assertIssues(const HeaderCheckFinding_t* finding, const char* const* expected_texts, int expected_count)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(expected_count, finding->m_issueCount, "issue count");
  for (int i = 0; i < expected_count; i++)
  {
    char text[HEADER_CHECK_ISSUE_TEXT_SIZE];
    char message[32];
    snprintf(message, sizeof(message), "issue %d", i);
    size_t text_len = header_check_writeIssueText(&finding->ma_issues[i], text, sizeof(text));
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected_texts[i], text, message);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(strlen(expected_texts[i]), text_len, message);
  }
}

static char* static_fillLongValue(const char* unit, int count, const char* tail)
{
  size_t unit_len = strlen(unit);
  size_t tail_len = strlen(tail);
  TEST_ASSERT_TRUE(unit_len * (size_t)count + tail_len < sizeof(g_longValue));

  size_t pos = 0;
  for (int i = 0; i < count; i++)
  {
    memcpy(g_longValue + pos, unit, unit_len);
    pos += unit_len;
  }
  memcpy(g_longValue + pos, tail, tail_len + 1);
  return g_longValue;
}

void test_capturedHeaderNames_lists_eleven_names_then_NULL(void)
{
  TEST_ASSERT_EQUAL_INT(11, HEADER_CHECK_HEADER_COUNT);
  TEST_ASSERT_EQUAL_INT(9, HEADER_CHECK_RULE_COUNT);
  TEST_ASSERT_EQUAL_STRING("Content-Security-Policy",             header_check_capturedHeaderNames[0]);
  TEST_ASSERT_EQUAL_STRING("Strict-Transport-Security",           header_check_capturedHeaderNames[1]);
  TEST_ASSERT_EQUAL_STRING("X-Content-Type-Options",              header_check_capturedHeaderNames[2]);
  TEST_ASSERT_EQUAL_STRING("X-Frame-Options",                     header_check_capturedHeaderNames[3]);
  TEST_ASSERT_EQUAL_STRING("Referrer-Policy",                     header_check_capturedHeaderNames[4]);
  TEST_ASSERT_EQUAL_STRING("Permissions-Policy",                  header_check_capturedHeaderNames[5]);
  TEST_ASSERT_EQUAL_STRING("X-XSS-Protection",                    header_check_capturedHeaderNames[6]);
  TEST_ASSERT_EQUAL_STRING("Set-Cookie",                          header_check_capturedHeaderNames[7]);
  TEST_ASSERT_EQUAL_STRING("Access-Control-Allow-Origin",         header_check_capturedHeaderNames[8]);
  TEST_ASSERT_EQUAL_STRING("Content-Security-Policy-Report-Only", header_check_capturedHeaderNames[9]);
  TEST_ASSERT_EQUAL_STRING("Access-Control-Allow-Credentials",    header_check_capturedHeaderNames[10]);
  TEST_ASSERT_NULL(header_check_capturedHeaderNames[11]);
}

void test_headerName_gives_the_name_of_each_header(void)
{
  TEST_ASSERT_EQUAL_STRING("Content-Security-Policy",             header_check_headerName(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY));
  TEST_ASSERT_EQUAL_STRING("Strict-Transport-Security",           header_check_headerName(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY));
  TEST_ASSERT_EQUAL_STRING("X-Content-Type-Options",              header_check_headerName(HEADER_CHECK_HEADER_X_CONTENT_TYPE_OPTIONS));
  TEST_ASSERT_EQUAL_STRING("X-Frame-Options",                     header_check_headerName(HEADER_CHECK_HEADER_X_FRAME_OPTIONS));
  TEST_ASSERT_EQUAL_STRING("Referrer-Policy",                     header_check_headerName(HEADER_CHECK_HEADER_REFERRER_POLICY));
  TEST_ASSERT_EQUAL_STRING("Permissions-Policy",                  header_check_headerName(HEADER_CHECK_HEADER_PERMISSIONS_POLICY));
  TEST_ASSERT_EQUAL_STRING("X-XSS-Protection",                    header_check_headerName(HEADER_CHECK_HEADER_X_XSS_PROTECTION));
  TEST_ASSERT_EQUAL_STRING("Set-Cookie",                          header_check_headerName(HEADER_CHECK_HEADER_SET_COOKIE));
  TEST_ASSERT_EQUAL_STRING("Access-Control-Allow-Origin",         header_check_headerName(HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN));
  TEST_ASSERT_EQUAL_STRING("Content-Security-Policy-Report-Only", header_check_headerName(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY_REPORT_ONLY));
  TEST_ASSERT_EQUAL_STRING("Access-Control-Allow-Credentials",    header_check_headerName(HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS));
}

void test_severityName_and_resultName_give_each_text(void)
{
  TEST_ASSERT_EQUAL_STRING("high",    header_check_severityName(HEADER_CHECK_SEVERITY_HIGH));
  TEST_ASSERT_EQUAL_STRING("medium",  header_check_severityName(HEADER_CHECK_SEVERITY_MEDIUM));
  TEST_ASSERT_EQUAL_STRING("low",     header_check_severityName(HEADER_CHECK_SEVERITY_LOW));
  TEST_ASSERT_EQUAL_STRING("pass",    header_check_resultName(HEADER_CHECK_RESULT_PASS));
  TEST_ASSERT_EQUAL_STRING("warn",    header_check_resultName(HEADER_CHECK_RESULT_WARN));
  TEST_ASSERT_EQUAL_STRING("fail",    header_check_resultName(HEADER_CHECK_RESULT_FAIL));
  TEST_ASSERT_EQUAL_STRING("missing", header_check_resultName(HEADER_CHECK_RESULT_MISSING));
}

void test_ruleRemediation_gives_the_text_of_each_rule(void)
{
  TEST_ASSERT_EQUAL_STRING("Add a Content-Security-Policy header with a strict policy; start with default-src 'self'", header_check_ruleRemediation(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY));
  TEST_ASSERT_EQUAL_STRING("Add Strict-Transport-Security: max-age=63072000; includeSubDomains",                       header_check_ruleRemediation(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY));
  TEST_ASSERT_EQUAL_STRING("Add X-Content-Type-Options: nosniff",                                                      header_check_ruleRemediation(HEADER_CHECK_HEADER_X_CONTENT_TYPE_OPTIONS));
  TEST_ASSERT_EQUAL_STRING("Add X-Frame-Options: DENY or SAMEORIGIN",                                                  header_check_ruleRemediation(HEADER_CHECK_HEADER_X_FRAME_OPTIONS));
  TEST_ASSERT_EQUAL_STRING("Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer",                       header_check_ruleRemediation(HEADER_CHECK_HEADER_REFERRER_POLICY));
  TEST_ASSERT_EQUAL_STRING("Add Permissions-Policy to disable unnecessary browser features (e.g., camera=(), microphone=())", header_check_ruleRemediation(HEADER_CHECK_HEADER_PERMISSIONS_POLICY));
  TEST_ASSERT_EQUAL_STRING("Remove X-XSS-Protection or set it to 0; use Content-Security-Policy against XSS",          header_check_ruleRemediation(HEADER_CHECK_HEADER_X_XSS_PROTECTION));
  TEST_ASSERT_EQUAL_STRING("Mark every cookie Secure with SameSite=Lax or Strict, and mark session cookies HttpOnly",  header_check_ruleRemediation(HEADER_CHECK_HEADER_SET_COOKIE));
  TEST_ASSERT_EQUAL_STRING("Send Access-Control-Allow-Origin with one trusted origin; never null, and never * with credentials", header_check_ruleRemediation(HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN));
}

void test_writeIssueText_gives_the_fixed_text_of_each_kind(void)
{
  static const struct
  {
    HeaderCheckIssueKind_t m_kind;
    const char*            mp_text;
  } fixed_kinds[] = {
    { HEADER_CHECK_ISSUE_CSP_REPORT_ONLY,                     TEXT_CSP_REPORT_ONLY },
    { HEADER_CHECK_ISSUE_CSP_NO_SCRIPT_DIRECTIVE,             TEXT_CSP_NO_SCRIPT },
    { HEADER_CHECK_ISSUE_CSP_NO_OBJECT_SRC,                   TEXT_CSP_NO_OBJECT_SRC },
    { HEADER_CHECK_ISSUE_CSP_NO_BASE_URI,                     TEXT_CSP_NO_BASE_URI },
    { HEADER_CHECK_ISSUE_HSTS_NO_MAX_AGE,                     TEXT_HSTS_NO_MAX_AGE },
    { HEADER_CHECK_ISSUE_HSTS_MALFORMED_MAX_AGE,              TEXT_HSTS_MALFORMED },
    { HEADER_CHECK_ISSUE_HSTS_NO_INCLUDE_SUBDOMAINS,          TEXT_HSTS_NO_SUBDOMAINS },
    { HEADER_CHECK_ISSUE_HSTS_MULTIPLE_HEADERS,               TEXT_HSTS_MULTIPLE },
    { HEADER_CHECK_ISSUE_XCTO_INVALID,                        TEXT_XCTO_INVALID },
    { HEADER_CHECK_ISSUE_XFO_INVALID,                         TEXT_XFO_INVALID },
    { HEADER_CHECK_ISSUE_REFERRER_NO_KNOWN_POLICY,            TEXT_REFERRER_UNKNOWN },
    { HEADER_CHECK_ISSUE_REFERRER_UNSAFE_URL,                 TEXT_REFERRER_UNSAFE_URL },
    { HEADER_CHECK_ISSUE_REFERRER_NO_REFERRER_WHEN_DOWNGRADE, TEXT_REFERRER_DOWNGRADE },
    { HEADER_CHECK_ISSUE_REFERRER_ORIGIN,                     TEXT_REFERRER_ORIGIN },
    { HEADER_CHECK_ISSUE_REFERRER_ORIGIN_WHEN_CROSS_ORIGIN,   TEXT_REFERRER_CROSS_ORIGIN },
    { HEADER_CHECK_ISSUE_PERMISSIONS_MALFORMED,               TEXT_PERMISSIONS_MALFORMED },
    { HEADER_CHECK_ISSUE_PERMISSIONS_WILDCARD,                TEXT_PERMISSIONS_WILDCARD },
    { HEADER_CHECK_ISSUE_XXP_FILTER_ENABLED,                  TEXT_XXP_ENABLED },
    { HEADER_CHECK_ISSUE_CORS_NULL_ORIGIN,                    TEXT_CORS_NULL_ORIGIN },
    { HEADER_CHECK_ISSUE_CORS_WILDCARD_WITH_CREDENTIALS,      TEXT_CORS_WILDCARD_CREDS },
    { HEADER_CHECK_ISSUE_CORS_MULTIPLE_ORIGINS,               TEXT_CORS_MULTIPLE_ORIGINS },
  };
  for (size_t i = 0; i < sizeof(fixed_kinds) / sizeof(fixed_kinds[0]); i++)
  {
    HeaderCheckIssue_t issue = { .m_kind = fixed_kinds[i].m_kind };
    char text[HEADER_CHECK_ISSUE_TEXT_SIZE];
    TEST_ASSERT_EQUAL_size_t(strlen(fixed_kinds[i].mp_text), header_check_writeIssueText(&issue, text, sizeof(text)));
    TEST_ASSERT_EQUAL_STRING(fixed_kinds[i].mp_text, text);
  }
}

void test_writeIssueText_puts_the_directive_or_the_max_age_between_the_fixed_parts(void)
{
  static const struct
  {
    HeaderCheckIssueKind_t m_kind;
    const char*            mp_text;
  } directive_kinds[] =    {
    { HEADER_CHECK_ISSUE_CSP_WILDCARD,           "Permissive CSP: 'script-src-elem *' allows any source (XSS risk)" },
    { HEADER_CHECK_ISSUE_CSP_UNSAFE_INLINE,      "Permissive CSP: 'script-src-elem' allows 'unsafe-inline' (XSS risk)" },
    { HEADER_CHECK_ISSUE_CSP_UNSAFE_EVAL,        "Permissive CSP: 'script-src-elem' allows 'unsafe-eval' (code injection risk)" },
    { HEADER_CHECK_ISSUE_CSP_HTTP_SCRIPT_SOURCE, "Permissive CSP: 'script-src-elem' allows scripts over plain http (XSS risk)" },
    { HEADER_CHECK_ISSUE_CSP_DATA_SCRIPT_SOURCE, "Permissive CSP: 'script-src-elem' allows data: URLs as scripts (XSS risk)" },
    { HEADER_CHECK_ISSUE_CSP_BROAD_SOURCE,       "Permissive CSP: 'script-src-elem' allows every host of a scheme (XSS risk)" },
    { HEADER_CHECK_ISSUE_CSP_REPEATED_DIRECTIVE, "'script-src-elem' appears more than once in a policy; the browser ignores every later copy" },
  };
  char text[HEADER_CHECK_ISSUE_TEXT_SIZE];
  for (size_t i = 0; i < sizeof(directive_kinds) / sizeof(directive_kinds[0]); i++)
  {
    HeaderCheckIssue_t issue = { .m_kind = directive_kinds[i].m_kind, .ma_detail = "script-src-elem" };
    TEST_ASSERT_EQUAL_size_t(strlen(directive_kinds[i].mp_text), header_check_writeIssueText(&issue, text, sizeof(text)));
    TEST_ASSERT_EQUAL_STRING(directive_kinds[i].mp_text, text);
  }

  HeaderCheckIssue_t short_max_age = { .m_kind = HEADER_CHECK_ISSUE_HSTS_SHORT_MAX_AGE, .ma_detail = "15551999" };
  const char* short_max_age_text = "max-age=15551999 is below recommended minimum of 15552000 (180 days)";
  TEST_ASSERT_EQUAL_size_t(strlen(short_max_age_text), header_check_writeIssueText(&short_max_age, text, sizeof(text)));
  TEST_ASSERT_EQUAL_STRING(short_max_age_text, text);
}

void test_writeIssueText_puts_the_cookie_count_into_each_cookie_text(void)
{
  static const struct
  {
    HeaderCheckIssueKind_t m_kind;
    const char*            mp_text;
  } cookie_kinds[] = {
    { HEADER_CHECK_ISSUE_COOKIE_NO_SECURE,                    "Cookies with no Secure attribute: 999999999999999" },
    { HEADER_CHECK_ISSUE_COOKIE_INVALID_SAMESITE,             "Cookies with a SameSite value other than Strict, Lax or None: 999999999999999" },
    { HEADER_CHECK_ISSUE_COOKIE_SAMESITE_NONE_WITHOUT_SECURE, "Cookies with SameSite=None and no Secure attribute: 999999999999999" },
    { HEADER_CHECK_ISSUE_COOKIE_BROKEN_PREFIX,                "Cookies that break the rules of their __Secure- or __Host- prefix: 999999999999999" },
    { HEADER_CHECK_ISSUE_COOKIE_SESSION_WITHOUT_HTTPONLY,     "Session or login cookies with no HttpOnly attribute: 999999999999999" },
    { HEADER_CHECK_ISSUE_COOKIE_CSRF_WITHOUT_SAMESITE,        "CSRF cookies with no SameSite attribute: 999999999999999" },
    { HEADER_CHECK_ISSUE_COOKIE_NOT_ALL_CHECKED,              "Cookies not checked: 999999999999999" },
  };
  char text[HEADER_CHECK_ISSUE_TEXT_SIZE];
  for (size_t i = 0; i < sizeof(cookie_kinds) / sizeof(cookie_kinds[0]); i++)
  {
    HeaderCheckIssue_t issue = { .m_kind = cookie_kinds[i].m_kind, .ma_detail = "999999999999999" };
    TEST_ASSERT_EQUAL_size_t(strlen(cookie_kinds[i].mp_text), header_check_writeIssueText(&issue, text, sizeof(text)));
    TEST_ASSERT_EQUAL_STRING(cookie_kinds[i].mp_text, text);
  }
}

void test_evaluate_with_no_header_gives_nine_findings_in_rule_order(void)
{
  static const HeaderCheckSeverity_t expected_severities[HEADER_CHECK_RULE_COUNT] = {
    HEADER_CHECK_SEVERITY_HIGH, HEADER_CHECK_SEVERITY_HIGH, HEADER_CHECK_SEVERITY_MEDIUM, HEADER_CHECK_SEVERITY_MEDIUM,
    HEADER_CHECK_SEVERITY_LOW, HEADER_CHECK_SEVERITY_LOW, HEADER_CHECK_SEVERITY_LOW, HEADER_CHECK_SEVERITY_MEDIUM,
    HEADER_CHECK_SEVERITY_LOW,
  };
  static const HeaderCheckResult_t expected_results[HEADER_CHECK_RULE_COUNT] = {
    HEADER_CHECK_RESULT_MISSING, HEADER_CHECK_RESULT_MISSING, HEADER_CHECK_RESULT_MISSING, HEADER_CHECK_RESULT_MISSING,
    HEADER_CHECK_RESULT_MISSING, HEADER_CHECK_RESULT_MISSING, HEADER_CHECK_RESULT_PASS, HEADER_CHECK_RESULT_PASS,
    HEADER_CHECK_RESULT_PASS,
  };

  header_check_evaluate(g_values, g_setCookieCopyCount, &g_report);

  for (int rule = 0; rule < HEADER_CHECK_RULE_COUNT; rule++)
  {
    const HeaderCheckFinding_t* finding = &g_report.ma_findings[rule];
    char message[16];
    snprintf(message, sizeof(message), "rule %d", rule);
    TEST_ASSERT_EQUAL_INT_MESSAGE(rule, finding->m_header, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected_severities[rule], finding->m_severity, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected_results[rule], finding->m_result, message);
    TEST_ASSERT_NULL_MESSAGE(finding->mp_value, message);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0, finding->m_cookieCount, message);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0, finding->m_valueLen, message);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0, finding->m_valueCodePointCount, message);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0, finding->m_shownValueLen, message);
    TEST_ASSERT_FALSE_MESSAGE(finding->m_isValueCut, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finding->m_issueCount, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", finding->ma_issues[0].ma_detail, message);
  }
}

void test_evaluate_points_each_finding_at_its_own_value(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY]   = "default-src 'self'" CSP_QUIET_TAIL;
  g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = "max-age=31536000; includeSubDomains";
  g_values[HEADER_CHECK_HEADER_X_CONTENT_TYPE_OPTIONS]    = "nosniff";
  g_values[HEADER_CHECK_HEADER_X_FRAME_OPTIONS]           = "DENY";
  g_values[HEADER_CHECK_HEADER_REFERRER_POLICY]           = "strict-origin-when-cross-origin";
  g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY]        = "camera=(), microphone=()";
  g_values[HEADER_CHECK_HEADER_X_XSS_PROTECTION]          = "0";
  g_values[HEADER_CHECK_HEADER_SET_COOKIE]                = "id=1; Secure; SameSite=Lax\ntheme=dark; Secure";
  g_values[HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN]      = "https://app.example";
  g_values[HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS] = "false";
  g_setCookieCopyCount = 2;

  header_check_evaluate(g_values, g_setCookieCopyCount, &g_report);

  static const size_t expected_lengths[HEADER_CHECK_RULE_COUNT] = { 54, 35, 7, 4, 31, 24, 1, 0, 19 };
  for (int rule = 0; rule < HEADER_CHECK_RULE_COUNT; rule++)
  {
    const HeaderCheckFinding_t* finding = &g_report.ma_findings[rule];
    char message[16];
    snprintf(message, sizeof(message), "rule %d", rule);
    TEST_ASSERT_EQUAL_PTR_MESSAGE(rule == HEADER_CHECK_HEADER_SET_COOKIE ? NULL : g_values[rule], finding->mp_value, message);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(rule == HEADER_CHECK_HEADER_SET_COOKIE ? 2 : 0, finding->m_cookieCount, message);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(expected_lengths[rule], finding->m_valueLen, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_PASS, finding->m_result, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finding->m_issueCount, message);
  }
}

void test_CSP_report_only_alone_warns_and_shows_its_value(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY_REPORT_ONLY] = "default-src *";

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_WARN, finding->m_result);
  TEST_ASSERT_EQUAL_PTR(g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY_REPORT_ONLY], finding->mp_value);
  TEST_ASSERT_EQUAL_size_t(13, finding->m_valueLen);
  ASSERT_ISSUES(finding, TEXT_CSP_REPORT_ONLY);
}

void test_CSP_enforced_policy_is_rated_and_report_only_is_not(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY]             = "default-src 'self'" CSP_QUIET_TAIL;
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY_REPORT_ONLY] = "default-src *";

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, finding->m_result);
  TEST_ASSERT_EQUAL_PTR(g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY], finding->mp_value);
  TEST_ASSERT_EQUAL_INT(0, finding->m_issueCount);
}

void test_CSP_strict_policy_passes(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src 'self'; script-src 'self'" CSP_QUIET_TAIL;

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, finding->m_result);
  TEST_ASSERT_EQUAL_INT(0, finding->m_issueCount);
}

void test_CSP_python_strict_vector_warns_about_object_src_and_base_uri(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src 'self'; script-src 'self'";

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_WARN, finding->m_result);
  ASSERT_ISSUES(finding, TEXT_CSP_NO_OBJECT_SRC, TEXT_CSP_NO_BASE_URI);
}

void test_CSP_empty_directive_is_skipped(void)
{
  static const char* const values[] = {
    "; default-src 'self'; object-src 'none'; base-uri 'none'",
    "default-src 'self';; object-src 'none'; base-uri 'none'",
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_PASS, finding->m_result, values[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finding->m_issueCount, values[i]);
  }
}

void test_CSP_script_src_elem_leaves_default_src_the_script_directive(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src http://cdn.example; script-src-elem 'self'" CSP_QUIET_TAIL;
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
  ASSERT_ISSUES(finding, "Permissive CSP: 'default-src' allows scripts over plain http (XSS risk)");
}

void test_CSP_wildcard_source_warns(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src *" CSP_QUIET_TAIL;
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_WARN, finding->m_result);
  ASSERT_ISSUES(finding, "Permissive CSP: 'default-src *' allows any source (XSS risk)");

  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src 'self' *" CSP_QUIET_TAIL;
  finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
  ASSERT_ISSUES(finding, "Permissive CSP: 'default-src *' allows any source (XSS risk)");

  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src 'self'; script-src *" CSP_QUIET_TAIL;
  finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
  ASSERT_ISSUES(finding, "Permissive CSP: 'script-src *' allows any source (XSS risk)");
}

void test_CSP_unsafe_inline_and_unsafe_eval_warn(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src 'self' 'unsafe-inline'" CSP_QUIET_TAIL;
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_WARN, finding->m_result);
  ASSERT_ISSUES(finding, "Permissive CSP: 'default-src' allows 'unsafe-inline' (XSS risk)");

  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src 'self' 'unsafe-eval'" CSP_QUIET_TAIL;
  finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_WARN, finding->m_result);
  ASSERT_ISSUES(finding, "Permissive CSP: 'default-src' allows 'unsafe-eval' (code injection risk)");
}

void test_CSP_three_permissive_sources_give_three_issues_in_rule_order(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src 'unsafe-eval' 'unsafe-inline' *" CSP_QUIET_TAIL;

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  ASSERT_ISSUES(finding,
                "Permissive CSP: 'default-src *' allows any source (XSS risk)",
                "Permissive CSP: 'default-src' allows 'unsafe-inline' (XSS risk)",
                "Permissive CSP: 'default-src' allows 'unsafe-eval' (code injection risk)");
}

void test_CSP_names_and_keywords_match_in_any_case(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "SCRIPT-SRC 'UNSAFE-INLINE' * 'Unsafe-Eval'" CSP_QUIET_TAIL;

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_WARN, finding->m_result);
  ASSERT_ISSUES(finding,
                "Permissive CSP: 'script-src *' allows any source (XSS risk)",
                "Permissive CSP: 'script-src' allows 'unsafe-inline' (XSS risk)",
                "Permissive CSP: 'script-src' allows 'unsafe-eval' (code injection risk)");
}

void test_CSP_sources_of_other_directives_raise_no_issue(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src 'self'; report-uri https://example.com/log?tag=unsafe-inline; frame-ancestors * 'unsafe-inline'" CSP_QUIET_TAIL;

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, finding->m_result);
  TEST_ASSERT_EQUAL_INT(0, finding->m_issueCount);
}

void test_CSP_without_default_src_and_script_src_fails(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "img-src 'self'";

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_FAIL, finding->m_result);
  ASSERT_ISSUES(finding, TEXT_CSP_NO_SCRIPT, TEXT_CSP_NO_OBJECT_SRC, TEXT_CSP_NO_BASE_URI);
}

void test_CSP_empty_value_fails(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "";

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_FAIL, finding->m_result);
  TEST_ASSERT_EQUAL_PTR(g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY], finding->mp_value);
  ASSERT_ISSUES(finding, TEXT_CSP_NO_SCRIPT, TEXT_CSP_NO_OBJECT_SRC, TEXT_CSP_NO_BASE_URI);
}

void test_CSP_script_src_or_default_src_alone_is_enough(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "script-src 'self'" CSP_QUIET_TAIL;
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY)->m_result);

  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src 'self'" CSP_QUIET_TAIL;
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY)->m_result);
}

void test_CSP_directive_without_sources_is_present(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "SCRIPT-SRC; OBJECT-SRC; BASE-URI";

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, finding->m_result);
  TEST_ASSERT_EQUAL_INT(0, finding->m_issueCount);
}

void test_CSP_default_src_that_matches_nothing_stands_for_object_src(void)
{
  static const char* const values[] = {
    "default-src 'none'; base-uri 'none'",
    "default-src 'NONE'; base-uri 'none'",
    "default-src; base-uri 'none'",
    "script-src 'self', default-src 'none'; base-uri 'none'",
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_PASS, finding->m_result, values[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finding->m_issueCount, values[i]);
  }
}

void test_CSP_default_src_that_matches_something_needs_object_src(void)
{
  static const char* const values[] = {
    "default-src 'none' 'self'; base-uri 'none'",
    "default-src 'self'; base-uri 'none'",
    "default-src 'nonesuch'; base-uri 'none'",
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_WARN, finding->m_result, values[i]);
    ASSERT_ISSUES(finding, TEXT_CSP_NO_OBJECT_SRC);
  }
}

void test_CSP_object_src_present_leaves_only_base_uri(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src 'self'; object-src 'self'";

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_WARN, finding->m_result);
  ASSERT_ISSUES(finding, TEXT_CSP_NO_BASE_URI);
}

void test_CSP_nonce_or_hash_makes_unsafe_inline_ignored(void)
{
  static const char* const values[] = {
    "script-src 'unsafe-inline' 'nonce-r4nd0m'" CSP_QUIET_TAIL,
    "script-src 'nonce-r4nd0m' 'unsafe-inline'" CSP_QUIET_TAIL,
    "script-src 'unsafe-inline' 'NONCE-R4nd0m'" CSP_QUIET_TAIL,
    "script-src 'unsafe-inline' 'sha256-YWJj'" CSP_QUIET_TAIL,
    "script-src 'unsafe-inline' 'sha384-YWJj'" CSP_QUIET_TAIL,
    "script-src 'unsafe-inline' 'sha512-YWJj'" CSP_QUIET_TAIL,
    "style-src 'unsafe-inline' 'nonce-x'; script-src 'self'" CSP_QUIET_TAIL,
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_PASS, finding->m_result, values[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finding->m_issueCount, values[i]);
  }
}

void test_CSP_broken_nonce_or_hash_leaves_unsafe_inline(void)
{
  static const char* const values[] = {
    "script-src 'unsafe-inline' 'nonce-'" CSP_QUIET_TAIL,
    "script-src 'unsafe-inline' 'nonce-abc" CSP_QUIET_TAIL,
    "script-src 'unsafe-inline' 'sha1-YWJj'" CSP_QUIET_TAIL,
    "script-src 'unsafe-inline' 'nonce:x'" CSP_QUIET_TAIL,
    "script-src 'unsafe-inline'; style-src 'nonce-x'" CSP_QUIET_TAIL,
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_WARN, finding->m_result, values[i]);
    ASSERT_ISSUES(finding, "Permissive CSP: 'script-src' allows 'unsafe-inline' (XSS risk)");
  }
}

void test_CSP_strict_dynamic_makes_unsafe_inline_ignored_in_script_directives(void)
{
  static const char* const values[] = {
    "script-src 'unsafe-inline' 'strict-dynamic'" CSP_QUIET_TAIL,
    "script-src 'self'; script-src-elem 'unsafe-inline' 'Strict-Dynamic'" CSP_QUIET_TAIL,
    "script-src 'self'; script-src-attr 'strict-dynamic' 'unsafe-inline'" CSP_QUIET_TAIL,
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_PASS, finding->m_result, values[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finding->m_issueCount, values[i]);
  }
}

void test_CSP_strict_dynamic_leaves_unsafe_inline_of_other_directives(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src 'unsafe-inline' 'strict-dynamic'" CSP_QUIET_TAIL;
  ASSERT_ISSUES(static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY), "Permissive CSP: 'default-src' allows 'unsafe-inline' (XSS risk)");

  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src 'self'; style-src 'unsafe-inline' 'strict-dynamic'" CSP_QUIET_TAIL;
  ASSERT_ISSUES(static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY), "Permissive CSP: 'style-src' allows 'unsafe-inline' (XSS risk)");
}

void test_CSP_http_and_data_sources_in_script_src_warn(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "script-src http:" CSP_QUIET_TAIL;
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_WARN, finding->m_result);
  ASSERT_ISSUES(finding, "Permissive CSP: 'script-src' allows scripts over plain http (XSS risk)");

  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "script-src HTTP://cdn.example.com" CSP_QUIET_TAIL;
  ASSERT_ISSUES(static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY), "Permissive CSP: 'script-src' allows scripts over plain http (XSS risk)");

  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "script-src Data:" CSP_QUIET_TAIL;
  ASSERT_ISSUES(static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY), "Permissive CSP: 'script-src' allows data: URLs as scripts (XSS risk)");

  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "script-src data: http:" CSP_QUIET_TAIL;
  ASSERT_ISSUES(static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY),
                "Permissive CSP: 'script-src' allows scripts over plain http (XSS risk)",
                "Permissive CSP: 'script-src' allows data: URLs as scripts (XSS risk)");
}

void test_CSP_sources_that_only_look_like_http_raise_no_issue(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "script-src https://cdn.example.com http httpx: data http:/x" CSP_QUIET_TAIL;

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, finding->m_result);
  TEST_ASSERT_EQUAL_INT(0, finding->m_issueCount);
}

void test_CSP_default_src_is_the_script_directive_of_a_policy_without_script_src(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src http: data:" CSP_QUIET_TAIL;

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_WARN, finding->m_result);
  ASSERT_ISSUES(finding,
                "Permissive CSP: 'default-src' allows scripts over plain http (XSS risk)",
                "Permissive CSP: 'default-src' allows data: URLs as scripts (XSS risk)");
}

void test_CSP_default_src_sources_are_no_scripts_beside_script_src(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src http: data:; script-src 'self'" CSP_QUIET_TAIL;

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, finding->m_result);
  TEST_ASSERT_EQUAL_INT(0, finding->m_issueCount);
}

void test_CSP_each_policy_has_its_own_script_directive(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "script-src 'self', default-src http:" CSP_QUIET_TAIL;

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  ASSERT_ISSUES(finding, "Permissive CSP: 'default-src' allows scripts over plain http (XSS risk)");
}

void test_CSP_http_and_data_in_other_directives_raise_no_issue(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src 'self'; img-src http: data:" CSP_QUIET_TAIL;

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, finding->m_result);
  TEST_ASSERT_EQUAL_INT(0, finding->m_issueCount);
}

void test_CSP_broad_source_in_the_script_directive_warns(void)
{
  static const char* const values[] = {
    "script-src https:" CSP_QUIET_TAIL,
    "script-src HTTPS:" CSP_QUIET_TAIL,
    "script-src 'self' https://*" CSP_QUIET_TAIL,
    "script-src HTTPS://*" CSP_QUIET_TAIL,
    "script-src ftp:" CSP_QUIET_TAIL,
    "script-src FTP:" CSP_QUIET_TAIL,
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_WARN, finding->m_result, values[i]);
    ASSERT_ISSUES(finding, "Permissive CSP: 'script-src' allows every host of a scheme (XSS risk)");
  }
}

void test_CSP_broad_source_in_default_src_or_object_src_warns(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src https:" CSP_QUIET_TAIL;
  ASSERT_ISSUES(static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY), "Permissive CSP: 'default-src' allows every host of a scheme (XSS risk)");

  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "script-src 'self'; object-src ftp:; base-uri 'self'";
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_WARN, finding->m_result);
  ASSERT_ISSUES(finding, "Permissive CSP: 'object-src' allows every host of a scheme (XSS risk)");
}

void test_CSP_broad_source_in_other_directives_raises_no_issue(void)
{
  static const char* const values[] = {
    "default-src 'self'; img-src https:" CSP_QUIET_TAIL,
    "default-src 'self'; style-src https: ftp:" CSP_QUIET_TAIL,
    "script-src 'self'; script-src-elem https:" CSP_QUIET_TAIL,
    "default-src https:; script-src 'self'" CSP_QUIET_TAIL,
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_PASS, finding->m_result, values[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finding->m_issueCount, values[i]);
  }
}

void test_CSP_sources_that_only_look_broad_raise_no_issue(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "script-src https://*.example.com https://cdn.example.com https:x https://** https://*.* https://*.*.* ftp://files.example.com ftp:x ws:" CSP_QUIET_TAIL;

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, finding->m_result);
  TEST_ASSERT_EQUAL_INT(0, finding->m_issueCount);
}

void test_CSP_http_source_is_no_broad_source(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "script-src https: http:" CSP_QUIET_TAIL;
  ASSERT_ISSUES(static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY),
                "Permissive CSP: 'script-src' allows scripts over plain http (XSS risk)",
                "Permissive CSP: 'script-src' allows every host of a scheme (XSS risk)");

  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "script-src http://*" CSP_QUIET_TAIL;
  ASSERT_ISSUES(static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY), "Permissive CSP: 'script-src' allows scripts over plain http (XSS risk)");
}

void test_CSP_each_kind_and_directive_is_raised_once(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src *; default-src *, img-src *; default-src *" CSP_QUIET_TAIL;

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  ASSERT_ISSUES(finding,
                "Permissive CSP: 'default-src *' allows any source (XSS risk)",
                "Permissive CSP: 'img-src *' allows any source (XSS risk)",
                "'default-src' appears more than once in a policy; the browser ignores every later copy");
}

void test_CSP_tabs_and_spaces_separate_words(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "\tdefault-src\t*\t'unsafe-eval'\t ;  object-src 'none' , base-uri\t'self' ";

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  ASSERT_ISSUES(finding,
                "Permissive CSP: 'default-src *' allows any source (XSS risk)",
                "Permissive CSP: 'default-src' allows 'unsafe-eval' (code injection risk)");
}

static const char* const CSP_TEST_FETCH_DIRECTIVES[] = {
  "default-src", "script-src", "script-src-elem", "script-src-attr", "style-src",
  "style-src-elem", "style-src-attr", "img-src", "connect-src", "font-src",
  "frame-src", "media-src", "object-src", "worker-src", "child-src",
};

static const char* const CSP_TEST_OTHER_REPEAT_DIRECTIVES[] = { "base-uri", "form-action", "frame-ancestors", "sandbox" };

void test_CSP_repeated_directive_warns_once(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "script-src 'self'; script-src 'self'; script-src 'self'" CSP_QUIET_TAIL;

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_WARN, finding->m_result);
  ASSERT_ISSUES(finding, "'script-src' appears more than once in a policy; the browser ignores every later copy");
}

void test_CSP_each_directive_of_the_repeat_list_is_checked(void)
{
  const char* names[sizeof(CSP_TEST_FETCH_DIRECTIVES) / sizeof(CSP_TEST_FETCH_DIRECTIVES[0]) + sizeof(CSP_TEST_OTHER_REPEAT_DIRECTIVES) / sizeof(CSP_TEST_OTHER_REPEAT_DIRECTIVES[0])];
  size_t      name_count = 0;
  for (size_t i = 0; i < sizeof(CSP_TEST_FETCH_DIRECTIVES) / sizeof(CSP_TEST_FETCH_DIRECTIVES[0]); i++)
    names[name_count++] = CSP_TEST_FETCH_DIRECTIVES[i];
  for (size_t i = 0; i < sizeof(CSP_TEST_OTHER_REPEAT_DIRECTIVES) / sizeof(CSP_TEST_OTHER_REPEAT_DIRECTIVES[0]); i++)
    names[name_count++] = CSP_TEST_OTHER_REPEAT_DIRECTIVES[i];
  TEST_ASSERT_EQUAL_size_t(19, name_count);

  for (size_t i = 0; i < name_count; i++)
  {
    char value[128];
    char upper_name[32];
    char expected[HEADER_CHECK_ISSUE_TEXT_SIZE];
    size_t name_len = strlen(names[i]);
    for (size_t k = 0; k <= name_len; k++)
      upper_name[k] = (names[i][k] >= 'a' && names[i][k] <= 'z') ? (char)(names[i][k] - 'a' + 'A') : names[i][k];
    snprintf(value, sizeof(value), "default-src 'self'" CSP_QUIET_TAIL "; %s; %s", names[i], upper_name);
    snprintf(expected, sizeof(expected), "'%s' appears more than once in a policy; the browser ignores every later copy", names[i]);
    g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = value;
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_WARN, finding->m_result, value);
    ASSERT_ISSUES(finding, expected);
  }
}

void test_CSP_directives_off_the_repeat_list_may_repeat(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src 'self'; report-uri /a; report-uri /b; report-to a; report-to b; upgrade-insecure-requests; upgrade-insecure-requests; x-future 1; x-future 2; sandboxx; sandboxx" CSP_QUIET_TAIL;

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, finding->m_result);
  TEST_ASSERT_EQUAL_INT(0, finding->m_issueCount);
}

void test_CSP_each_policy_counts_its_own_directives(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "script-src 'self'" CSP_QUIET_TAIL ", script-src 'self'; form-action 'self'";
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, finding->m_result);
  TEST_ASSERT_EQUAL_INT(0, finding->m_issueCount);

  char   value[512] = "";
  size_t value_len  = 0;
  for (size_t i = 0; i < sizeof(CSP_TEST_FETCH_DIRECTIVES) / sizeof(CSP_TEST_FETCH_DIRECTIVES[0]); i++)
    value_len += (size_t)snprintf(value + value_len, sizeof(value) - value_len, "%s 'self'; ", CSP_TEST_FETCH_DIRECTIVES[i]);
  snprintf(value + value_len, sizeof(value) - value_len, "base-uri 'self'; form-action 'self'; frame-ancestors 'self'; sandbox");
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = value;
  finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, finding->m_result);
  TEST_ASSERT_EQUAL_INT(0, finding->m_issueCount);

  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "script-src 'self'; script-src 'self'" CSP_QUIET_TAIL ", script-src 'self'; script-src 'self'";
  ASSERT_ISSUES(static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY), "'script-src' appears more than once in a policy; the browser ignores every later copy");
}

void test_CSP_repeat_issues_follow_the_other_issues(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src *; default-src 'self'";

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  ASSERT_ISSUES(finding,
                "Permissive CSP: 'default-src *' allows any source (XSS risk)",
                TEXT_CSP_NO_OBJECT_SRC,
                TEXT_CSP_NO_BASE_URI,
                "'default-src' appears more than once in a policy; the browser ignores every later copy");
}

void test_CSP_the_most_issues_fill_the_finding(void)
{
  char        value[2048] = "";
  size_t      value_len   = 0;
  static char expected[HEADER_CHECK_MAX_ISSUE_COUNT][HEADER_CHECK_ISSUE_TEXT_SIZE];
  const char* expected_texts[HEADER_CHECK_MAX_ISSUE_COUNT];
  int         expected_count = 0;
  for (size_t i = 0; i < sizeof(CSP_TEST_FETCH_DIRECTIVES) / sizeof(CSP_TEST_FETCH_DIRECTIVES[0]); i++)
  {
    const char* name = CSP_TEST_FETCH_DIRECTIVES[i];
    bool is_script_src = strcmp(name, "script-src") == 0;
    bool is_object_src = strcmp(name, "object-src") == 0;
    value_len += (size_t)snprintf(value + value_len, sizeof(value) - value_len, "%s * 'unsafe-inline' 'unsafe-eval'%s; ", name, is_script_src ? " http: data: https:" : is_object_src ? " ftp:" : "");
    snprintf(expected[expected_count++], HEADER_CHECK_ISSUE_TEXT_SIZE, "Permissive CSP: '%s *' allows any source (XSS risk)", name);
    snprintf(expected[expected_count++], HEADER_CHECK_ISSUE_TEXT_SIZE, "Permissive CSP: '%s' allows 'unsafe-inline' (XSS risk)", name);
    snprintf(expected[expected_count++], HEADER_CHECK_ISSUE_TEXT_SIZE, "Permissive CSP: '%s' allows 'unsafe-eval' (code injection risk)", name);
    if (is_script_src)
    {
      snprintf(expected[expected_count++], HEADER_CHECK_ISSUE_TEXT_SIZE, "Permissive CSP: 'script-src' allows scripts over plain http (XSS risk)");
      snprintf(expected[expected_count++], HEADER_CHECK_ISSUE_TEXT_SIZE, "Permissive CSP: 'script-src' allows data: URLs as scripts (XSS risk)");
    }
    if (is_script_src || is_object_src)
      snprintf(expected[expected_count++], HEADER_CHECK_ISSUE_TEXT_SIZE, "Permissive CSP: '%s' allows every host of a scheme (XSS risk)", name);
  }
  for (size_t i = 0; i < sizeof(CSP_TEST_FETCH_DIRECTIVES) / sizeof(CSP_TEST_FETCH_DIRECTIVES[0]); i++)
    value_len += (size_t)snprintf(value + value_len, sizeof(value) - value_len, "%s; ", CSP_TEST_FETCH_DIRECTIVES[i]);
  for (size_t i = 0; i < sizeof(CSP_TEST_OTHER_REPEAT_DIRECTIVES) / sizeof(CSP_TEST_OTHER_REPEAT_DIRECTIVES[0]); i++)
    value_len += (size_t)snprintf(value + value_len, sizeof(value) - value_len, "%s 'self'; %s 'self'; ", CSP_TEST_OTHER_REPEAT_DIRECTIVES[i], CSP_TEST_OTHER_REPEAT_DIRECTIVES[i]);
  snprintf(value + value_len, sizeof(value) - value_len, ", default-src http: data: https:");
  snprintf(expected[expected_count++], HEADER_CHECK_ISSUE_TEXT_SIZE, "Permissive CSP: 'default-src' allows scripts over plain http (XSS risk)");
  snprintf(expected[expected_count++], HEADER_CHECK_ISSUE_TEXT_SIZE, "Permissive CSP: 'default-src' allows data: URLs as scripts (XSS risk)");
  snprintf(expected[expected_count++], HEADER_CHECK_ISSUE_TEXT_SIZE, "Permissive CSP: 'default-src' allows every host of a scheme (XSS risk)");
  for (size_t i = 0; i < sizeof(CSP_TEST_FETCH_DIRECTIVES) / sizeof(CSP_TEST_FETCH_DIRECTIVES[0]); i++)
    snprintf(expected[expected_count++], HEADER_CHECK_ISSUE_TEXT_SIZE, "'%s' appears more than once in a policy; the browser ignores every later copy", CSP_TEST_FETCH_DIRECTIVES[i]);
  for (size_t i = 0; i < sizeof(CSP_TEST_OTHER_REPEAT_DIRECTIVES) / sizeof(CSP_TEST_OTHER_REPEAT_DIRECTIVES[0]); i++)
    snprintf(expected[expected_count++], HEADER_CHECK_ISSUE_TEXT_SIZE, "'%s' appears more than once in a policy; the browser ignores every later copy", CSP_TEST_OTHER_REPEAT_DIRECTIVES[i]);
  for (int i = 0; i < expected_count; i++)
    expected_texts[i] = expected[i];
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = value;

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_INT(71, HEADER_CHECK_MAX_ISSUE_COUNT);
  TEST_ASSERT_EQUAL_INT(71, expected_count);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_WARN, finding->m_result);
  static_assertIssues(finding, expected_texts, expected_count);
}

void test_HSTS_180_days_and_include_subdomains_pass(void)
{
  static const char* const values[] = {
    "max-age=31536000; includeSubDomains; preload",
    "max-age=15552000; includeSubDomains",
    "max-age=15552001; includeSubDomains",
    "max-age=31536000; includeSubDomains; nopreload",
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_PASS, finding->m_result, values[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finding->m_issueCount, values[i]);
  }
}

void test_HSTS_max_age_below_180_days_fails_with_its_number(void)
{
  g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = "max-age=3600; includeSubDomains";
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_FAIL, finding->m_result);
  ASSERT_ISSUES(finding, "max-age=3600 is below recommended minimum of 15552000 (180 days)");
  TEST_ASSERT_EQUAL_STRING("3600", finding->ma_issues[0].ma_detail);

  g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = "max-age=15551999; includeSubDomains";
  finding = static_evaluate(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_FAIL, finding->m_result);
  ASSERT_ISSUES(finding, "max-age=15551999 is below recommended minimum of 15552000 (180 days)");

  g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = "max-age=0; includeSubDomains";
  ASSERT_ISSUES(static_evaluate(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY), "max-age=0 is below recommended minimum of 15552000 (180 days)");

  g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = "max-age=0003600; includeSubDomains";
  ASSERT_ISSUES(static_evaluate(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY), "max-age=3600 is below recommended minimum of 15552000 (180 days)");
}

void test_HSTS_max_age_of_thirty_digits_passes(void)
{
  static const char* const values[] = {
    "max-age=999999999999999999999999999999; includeSubDomains",
    "max-age=4294967296; includeSubDomains",
    "max-age=429496729600000000000000000000; includeSubDomains",
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_PASS, finding->m_result, values[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finding->m_issueCount, values[i]);
  }
}

void test_HSTS_missing_max_age_or_include_subdomains_fails(void)
{
  g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = "includeSubDomains";
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_FAIL, finding->m_result);
  ASSERT_ISSUES(finding, TEXT_HSTS_NO_MAX_AGE);

  g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = "max-age=31536000";
  finding = static_evaluate(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_FAIL, finding->m_result);
  ASSERT_ISSUES(finding, TEXT_HSTS_NO_SUBDOMAINS);

  g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = "max-age=31536000; notincludesubdomains";
  ASSERT_ISSUES(static_evaluate(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY), TEXT_HSTS_NO_SUBDOMAINS);

  g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = "preload";
  ASSERT_ISSUES(static_evaluate(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY), TEXT_HSTS_NO_MAX_AGE, TEXT_HSTS_NO_SUBDOMAINS);
}

void test_HSTS_well_formed_spellings_pass(void)
{
  static const char* const values[] = {
    "max-age=\"31536000\"; includeSubDomains",
    "max-age = 31536000 ; includeSubDomains",
    "max-age\t=\t\"31536000\";\tincludeSubDomains\t",
    "MAX-AGE=31536000; INCLUDESUBDOMAINS",
    ";;max-age=31536000;;includeSubDomains;",
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_PASS, finding->m_result, values[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finding->m_issueCount, values[i]);
  }
}

void test_HSTS_malformed_max_age_fails(void)
{
  static const char* const values[] = {
    "max-age=31536000\"; includeSubDomains",
    "max-age=\"31536000; includeSubDomains",
    "max-age=abc; includeSubDomains",
    "max-age; includeSubDomains",
    "max-age 31536000; includeSubDomains",
    "max-age=; includeSubDomains",
    "max-age=\"\"; includeSubDomains",
    "max-agex=31536000; includeSubDomains",
    "max-age=31536000x; includeSubDomains",
    "max-age=\"31536000x; includeSubDomains",
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_FAIL, finding->m_result, values[i]);
    ASSERT_ISSUES(finding, TEXT_HSTS_MALFORMED);
  }
}

void test_HSTS_first_max_age_counts(void)
{
  g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = "max-age=0; max-age=31536000; includeSubDomains";

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_FAIL, finding->m_result);
  ASSERT_ISSUES(finding, "max-age=0 is below recommended minimum of 15552000 (180 days)");
}

void test_HSTS_second_copy_is_not_read_and_warns(void)
{
  g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = "max-age=31536000; includeSubDomains, max-age=0";

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_WARN, finding->m_result);
  ASSERT_ISSUES(finding, TEXT_HSTS_MULTIPLE);
}

void test_HSTS_trailing_comma_is_no_second_copy(void)
{
  static const char* const values[] = {
    "max-age=31536000; includeSubDomains,",
    "max-age=31536000; includeSubDomains, ",
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_PASS, finding->m_result, values[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finding->m_issueCount, values[i]);
  }

  g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = "max-age=31536000; includeSubDomains,x";
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_WARN, finding->m_result);
  ASSERT_ISSUES(finding, TEXT_HSTS_MULTIPLE);
}

void test_HSTS_first_copy_decides_the_result(void)
{
  g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = "max-age=0, max-age=31536000; includeSubDomains";

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY);

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_FAIL, finding->m_result);
  ASSERT_ISSUES(finding, "max-age=0 is below recommended minimum of 15552000 (180 days)", TEXT_HSTS_NO_SUBDOMAINS, TEXT_HSTS_MULTIPLE);
}

void test_XCTO_first_value_nosniff_passes(void)
{
  static const char* const values[] = { "nosniff", "NoSniff", " \tnosniff\t ", "nosniff, other" };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_X_CONTENT_TYPE_OPTIONS] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_X_CONTENT_TYPE_OPTIONS);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_PASS, finding->m_result, values[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finding->m_issueCount, values[i]);
  }
}

void test_XCTO_other_first_value_fails(void)
{
  static const char* const values[] = { "other, nosniff", "", "nosniffx", "nosnif" };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_X_CONTENT_TYPE_OPTIONS] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_X_CONTENT_TYPE_OPTIONS);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_FAIL, finding->m_result, values[i]);
    ASSERT_ISSUES(finding, TEXT_XCTO_INVALID);
  }
}

void test_XFO_deny_or_sameorigin_passes(void)
{
  static const char* const values[] = { "DENY", "SAMEORIGIN", "sameorigin", " \tDENY\t ", "deny, DENY", "SameOrigin,sameorigin, SAMEORIGIN" };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_X_FRAME_OPTIONS] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_X_FRAME_OPTIONS);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_PASS, finding->m_result, values[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finding->m_issueCount, values[i]);
  }
}

void test_XFO_other_value_fails_with_a_fixed_issue(void)
{
  static const char* const values[] = { "ALLOW", "ALLOW-FROM https://example.com", "", "DENY, SAMEORIGIN", "SAMEORIGIN, DENY", ", DENY", "DENY, ALLOW, DENY", "DEN" };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_X_FRAME_OPTIONS] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_X_FRAME_OPTIONS);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_FAIL, finding->m_result, values[i]);
    ASSERT_ISSUES(finding, TEXT_XFO_INVALID);
  }
}

void test_XFO_passes_when_the_policy_has_frame_ancestors(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src 'self'; FRAME-ANCESTORS 'none'";
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_X_FRAME_OPTIONS);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, finding->m_result);
  TEST_ASSERT_NULL(finding->mp_value);
  TEST_ASSERT_EQUAL_INT(0, finding->m_issueCount);

  g_values[HEADER_CHECK_HEADER_X_FRAME_OPTIONS] = "ALLOW";
  finding = static_evaluate(HEADER_CHECK_HEADER_X_FRAME_OPTIONS);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, finding->m_result);
  TEST_ASSERT_EQUAL_PTR(g_values[HEADER_CHECK_HEADER_X_FRAME_OPTIONS], finding->mp_value);
  TEST_ASSERT_EQUAL_INT(0, finding->m_issueCount);

  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src 'self', frame-ancestors 'self'";
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, static_evaluate(HEADER_CHECK_HEADER_X_FRAME_OPTIONS)->m_result);
}

void test_XFO_ignores_frame_ancestors_of_report_only(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY_REPORT_ONLY] = "frame-ancestors 'none'";
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_MISSING, static_evaluate(HEADER_CHECK_HEADER_X_FRAME_OPTIONS)->m_result);

  g_values[HEADER_CHECK_HEADER_X_FRAME_OPTIONS] = "ALLOW";
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_FAIL, static_evaluate(HEADER_CHECK_HEADER_X_FRAME_OPTIONS)->m_result);
}

void test_XFO_needs_frame_ancestors_as_a_directive_name(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = "default-src 'self' frame-ancestors; frame-ancestorsx 'none'";

  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_MISSING, static_evaluate(HEADER_CHECK_HEADER_X_FRAME_OPTIONS)->m_result);
}

void test_REFERRER_safe_policy_passes(void)
{
  static const char* const values[] = { "no-referrer", "Same-Origin", " STRICT-ORIGIN ", "\tstrict-origin-when-cross-origin" };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_REFERRER_POLICY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_REFERRER_POLICY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_PASS, finding->m_result, values[i]);
    TEST_ASSERT_EQUAL_PTR_MESSAGE(values[i], finding->mp_value, values[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finding->m_issueCount, values[i]);
  }
}

void test_REFERRER_policy_that_leaks_the_url_fails(void)
{
  g_values[HEADER_CHECK_HEADER_REFERRER_POLICY] = "unsafe-url";
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_REFERRER_POLICY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_FAIL, finding->m_result);
  ASSERT_ISSUES(finding, TEXT_REFERRER_UNSAFE_URL);

  g_values[HEADER_CHECK_HEADER_REFERRER_POLICY] = "UNSAFE-URL";
  ASSERT_ISSUES(static_evaluate(HEADER_CHECK_HEADER_REFERRER_POLICY), TEXT_REFERRER_UNSAFE_URL);

  g_values[HEADER_CHECK_HEADER_REFERRER_POLICY] = "no-referrer-when-downgrade";
  finding = static_evaluate(HEADER_CHECK_HEADER_REFERRER_POLICY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_FAIL, finding->m_result);
  ASSERT_ISSUES(finding, TEXT_REFERRER_DOWNGRADE);
}

void test_REFERRER_last_known_token_is_the_policy(void)
{
  g_values[HEADER_CHECK_HEADER_REFERRER_POLICY] = "unsafe-url, strict-origin";
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, static_evaluate(HEADER_CHECK_HEADER_REFERRER_POLICY)->m_result);

  g_values[HEADER_CHECK_HEADER_REFERRER_POLICY] = "strict-origin, unsafe-url";
  ASSERT_ISSUES(static_evaluate(HEADER_CHECK_HEADER_REFERRER_POLICY), TEXT_REFERRER_UNSAFE_URL);

  g_values[HEADER_CHECK_HEADER_REFERRER_POLICY] = "no-referrer,future-policy";
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, static_evaluate(HEADER_CHECK_HEADER_REFERRER_POLICY)->m_result);

  g_values[HEADER_CHECK_HEADER_REFERRER_POLICY] = "future-policy, no-referrer-when-downgrade";
  ASSERT_ISSUES(static_evaluate(HEADER_CHECK_HEADER_REFERRER_POLICY), TEXT_REFERRER_DOWNGRADE);
}

void test_REFERRER_origin_policies_warn(void)
{
  g_values[HEADER_CHECK_HEADER_REFERRER_POLICY] = "origin";
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_REFERRER_POLICY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_WARN, finding->m_result);
  ASSERT_ISSUES(finding, TEXT_REFERRER_ORIGIN);

  g_values[HEADER_CHECK_HEADER_REFERRER_POLICY] = " ORIGIN-WHEN-CROSS-ORIGIN\t";
  finding = static_evaluate(HEADER_CHECK_HEADER_REFERRER_POLICY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_WARN, finding->m_result);
  ASSERT_ISSUES(finding, TEXT_REFERRER_CROSS_ORIGIN);

  g_values[HEADER_CHECK_HEADER_REFERRER_POLICY] = "strict-origin, origin";
  finding = static_evaluate(HEADER_CHECK_HEADER_REFERRER_POLICY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_WARN, finding->m_result);
  ASSERT_ISSUES(finding, TEXT_REFERRER_ORIGIN);

  g_values[HEADER_CHECK_HEADER_REFERRER_POLICY] = "origin, strict-origin";
  finding = static_evaluate(HEADER_CHECK_HEADER_REFERRER_POLICY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, finding->m_result);
  TEST_ASSERT_EQUAL_INT(0, finding->m_issueCount);
}

void test_REFERRER_value_without_a_known_token_fails(void)
{
  static const char* const values[] = { "x", "", "no-referrerx" };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_REFERRER_POLICY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_REFERRER_POLICY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_FAIL, finding->m_result, values[i]);
    ASSERT_ISSUES(finding, TEXT_REFERRER_UNKNOWN);
  }
}

void test_PERMISSIONS_present_passes(void)
{
  g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = "camera=(), microphone=()";
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_PERMISSIONS_POLICY);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, finding->m_result);
  TEST_ASSERT_EQUAL_PTR(g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY], finding->mp_value);
  TEST_ASSERT_EQUAL_INT(0, finding->m_issueCount);

  g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = "";
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, static_evaluate(HEADER_CHECK_HEADER_PERMISSIONS_POLICY)->m_result);
}

void test_PERMISSIONS_valid_dictionary_passes(void)
{
  static const char* const values[] = {
    " ",
    "camera=(), microphone=()",
    "geolocation=(self \"https://a.example\"), fullscreen=self",
    "a",
    "zz=1",
    "*a=1",
    "a09_-.*z=?1",
    "a=?0",
    "a=-0",
    "a=123456789012345",
    "a=-123456789012.123",
    "a=1.5",
    "a=\" ~\\\\\\\"\"",
    "a=Az09!#$%&'*+-.^_`|~:/",
    "a=zAZ",
    "a=:YWJj:",
    "a=:+/=:",
    "a=:aGk0:",
    "a=::",
    "a=1;q=2;r;s=tok;t=\"x\";u=:YQ==:;v=?0;w=-1.25",
    "a=(1 2);x",
    "a=(  1   2  );x=1",
    "a=()",
    "a=();p=1",
    "a=( )",
    "a=(1;p=2 tok;q)",
    "a=1,\tb=2",
    "a=1\t, b=2",
    "a=1 , b=2",
    "a=1;  b",
    "a=1, a=2",
    "a=1,b=2",
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_PERMISSIONS_POLICY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_PASS, finding->m_result, values[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finding->m_issueCount, values[i]);
  }
}

void test_PERMISSIONS_malformed_value_fails(void)
{
  static const char* const values[] = {
    "camera 'none'",
    "camera 'none'; microphone 'self'",
    "Camera=()",
    "1a=()",
    "`a=()",
    "{a=()",
    "a+b=()",
    "aB=()",
    "camera=(),",
    "camera=(), ",
    ",camera=()",
    "a=1,,b=2",
    "a=1 b=2",
    "camera=()x",
    "a=",
    "a=(",
    "a=(1",
    "a=(1 2",
    "a=(1)(",
    "a=((1))",
    "a=(1,2)",
    "a=(1)x",
    "a=(1x)",
    "a=(?)",
    "a=\"x",
    "a=\"x\\",
    "a=\"\\x\"",
    "a=\"\x1f\"",
    "a=\"\x7f\"",
    "a=\"\xc3\xa9\"",
    "a=:YWJj",
    "a=:YW.j:",
    "a=:, b=1",
    "a=?",
    "a=?2",
    "a=-",
    "a=-x",
    "a=--1",
    "a=-.5",
    "a=1234567890123456",
    "a=1234567890123.1",
    "a=1.1234",
    "a=1.",
    "a=1.2.3",
    "a=1a",
    "a=@1",
    "a=%\"x\"",
    "a=$x",
    "a=.5",
    "a=1;",
    "a;",
    "a=1;=2",
    "a=1;B",
    "a=1;b=(1)",
    "a=1;b=",
    "\tcamera=()",
    "a=(1\t2)",
    "a=(\t1)",
    "a=(1 \t2)",
    "a=1;\tb",
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_PERMISSIONS_POLICY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_FAIL, finding->m_result, values[i]);
    ASSERT_ISSUES(finding, TEXT_PERMISSIONS_MALFORMED);
  }
}

void test_PERMISSIONS_wildcard_warns(void)
{
  static const char* const values[] = {
    "camera=*",
    "camera=*;p=1",
    "camera=(*)",
    "camera=(* self), microphone=()",
    "camera=(self *);p",
    "camera=*, microphone=(), geolocation=self",
    "camera=*, microphone=*",
    "camera=(), microphone=( * )",
    "camera=*, camera=()",
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_PERMISSIONS_POLICY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_WARN, finding->m_result, values[i]);
    ASSERT_ISSUES(finding, TEXT_PERMISSIONS_WILDCARD);
  }
}

void test_PERMISSIONS_star_that_is_no_member_value_passes(void)
{
  static const char* const values[] = {
    "a=\"*\"",
    "a=(\"*\")",
    "a=*x",
    "a=(*x)",
    "a=1;p=*",
    "a=(self);p=*",
    "a=(1;p=*)",
    "*=1",
    "a*",
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_PERMISSIONS_POLICY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_PASS, finding->m_result, values[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finding->m_issueCount, values[i]);
  }
}

void test_PERMISSIONS_malformed_value_raises_no_wildcard(void)
{
  static const char* const values[] = { "camera=*, Microphone=()", "camera=*," };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_PERMISSIONS_POLICY);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_FAIL, finding->m_result, values[i]);
    ASSERT_ISSUES(finding, TEXT_PERMISSIONS_MALFORMED);
  }
}

void test_XXP_zero_passes(void)
{
  static const char* const values[] = { "0", " \t0\t ", "0, 0", " 0 ,\t0" };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_X_XSS_PROTECTION] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_X_XSS_PROTECTION);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_PASS, finding->m_result, values[i]);
    TEST_ASSERT_EQUAL_PTR_MESSAGE(values[i], finding->mp_value, values[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finding->m_issueCount, values[i]);
  }
}

void test_XXP_other_value_warns(void)
{
  static const char* const values[] = { "1", "1; mode=block", "00", "", "0, 1", "1, 0", "0," };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    g_values[HEADER_CHECK_HEADER_X_XSS_PROTECTION] = (char*)values[i];
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_X_XSS_PROTECTION);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_WARN, finding->m_result, values[i]);
    ASSERT_ISSUES(finding, TEXT_XXP_ENABLED);
  }
}

typedef struct {
  const char*          mp_value;
  HeaderCheckResult_t  m_result;
  size_t               m_cookieCount;
  const char*          ma_texts[8];
} CookieCase_t;

static void static_assertCookieCases(const CookieCase_t* cases, size_t case_count)
{
  for (size_t i = 0; i < case_count; i++)
  {
    setUp();
    g_values[HEADER_CHECK_HEADER_SET_COOKIE] = (char*)cases[i].mp_value;
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_SET_COOKIE);
    const char* message = cases[i].mp_value;
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_result, finding->m_result, message);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(cases[i].m_cookieCount, finding->m_cookieCount, message);
    TEST_ASSERT_NULL_MESSAGE(finding->mp_value, message);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(0, finding->m_valueLen, message);

    int text_count = 0;
    while (text_count < 8 && cases[i].ma_texts[text_count] != NULL)
      text_count++;
    TEST_ASSERT_EQUAL_INT_MESSAGE(text_count, finding->m_issueCount, message);
    for (int k = 0; k < text_count; k++)
    {
      char text[HEADER_CHECK_ISSUE_TEXT_SIZE];
      header_check_writeIssueText(&finding->ma_issues[k], text, sizeof(text));
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].ma_texts[k], text, message);
    }
  }
}

void test_SETCOOKIE_secure_cookies_pass(void)
{
  static const CookieCase_t cases[] = {
    { "id=1; Secure; HttpOnly; SameSite=Lax",              HEADER_CHECK_RESULT_PASS, 1, { NULL } },
    { "id=1; secure; samesite=STRICT",                      HEADER_CHECK_RESULT_PASS, 1, { NULL } },
    { "id=1; SECURE=yes; SameSite=none",                    HEADER_CHECK_RESULT_PASS, 1, { NULL } },
    { "sessid=1; Secure; HTTPONLY=yes",                     HEADER_CHECK_RESULT_PASS, 1, { NULL } },
    { "id=1;Secure",                                        HEADER_CHECK_RESULT_PASS, 1, { NULL } },
    { " id = 1 ;\tSecure\t; SameSite = Lax ",               HEADER_CHECK_RESULT_PASS, 1, { NULL } },
    { "__Secure-id=1; Secure",                              HEADER_CHECK_RESULT_PASS, 1, { NULL } },
    { "__Host-id=1; Secure; Path=/",                        HEADER_CHECK_RESULT_PASS, 1, { NULL } },
    { "__HOST-id=1; Path= / ; Secure",                      HEADER_CHECK_RESULT_PASS, 1, { NULL } },
    { "__Host-id=1; Secure; Path=/; Domain=",               HEADER_CHECK_RESULT_PASS, 1, { NULL } },
    { "__Host-id=1; Secure; Path=/a; Path=/",               HEADER_CHECK_RESULT_PASS, 1, { NULL } },
    { "x__Host-id=1; Secure",                               HEADER_CHECK_RESULT_PASS, 1, { NULL } },
    { "id=1; Secure; SameSite=Bogus; SameSite=Lax",         HEADER_CHECK_RESULT_PASS, 1, { NULL } },
    { "PHPSESSID=1; Secure; HttpOnly",                      HEADER_CHECK_RESULT_PASS, 1, { NULL } },
    { "user_LOGIN=1; Secure; HttpOnly",                     HEADER_CHECK_RESULT_PASS, 1, { NULL } },
    { "theme=session; Secure; Path=/login",                 HEADER_CHECK_RESULT_PASS, 1, { NULL } },
    { "csrftoken=1; Secure; SameSite=Strict",               HEADER_CHECK_RESULT_PASS, 1, { NULL } },
    { "XSRF-TOKEN=1; Secure",                               HEADER_CHECK_RESULT_PASS, 1, { NULL } },
  };
  static_assertCookieCases(cases, sizeof(cases) / sizeof(cases[0]));
}

void test_SETCOOKIE_absent_passes_with_no_cookie(void)
{
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_SET_COOKIE);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, finding->m_result);
  TEST_ASSERT_EQUAL_size_t(0, finding->m_cookieCount);
  TEST_ASSERT_EQUAL_INT(0, finding->m_issueCount);
  TEST_ASSERT_NULL(finding->mp_value);
}

void test_SETCOOKIE_cookie_without_secure_fails(void)
{
  static const CookieCase_t cases[] = {
    { "id=1; HttpOnly; SameSite=Lax", HEADER_CHECK_RESULT_FAIL, 1, { "Cookies with no Secure attribute: 1" } },
    { "Secure=1",                     HEADER_CHECK_RESULT_FAIL, 1, { "Cookies with no Secure attribute: 1" } },
    { "id=Secure; Path=/secure",      HEADER_CHECK_RESULT_FAIL, 1, { "Cookies with no Secure attribute: 1" } },
    { "id=1; Secured",                HEADER_CHECK_RESULT_FAIL, 1, { "Cookies with no Secure attribute: 1" } },
    { "id=1 Secure",                  HEADER_CHECK_RESULT_FAIL, 1, { "Cookies with no Secure attribute: 1" } },
    { "",                             HEADER_CHECK_RESULT_FAIL, 1, { "Cookies with no Secure attribute: 1" } },
  };
  static_assertCookieCases(cases, sizeof(cases) / sizeof(cases[0]));

  setUp();
  g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = "max-age=63072000; includeSubDomains";
  g_values[HEADER_CHECK_HEADER_SET_COOKIE]                = "id=1";
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_SET_COOKIE);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_FAIL, finding->m_result);
  ASSERT_ISSUES(finding, "Cookies with no Secure attribute: 1");
}

void test_SETCOOKIE_issue_counts_the_cookies_of_its_kind(void)
{
  static const CookieCase_t cases[] = {
    { "a=1\nb=2; Secure\nc=3",                                                    HEADER_CHECK_RESULT_FAIL, 3, { "Cookies with no Secure attribute: 2" } },
    { "g=1; Secure\nh=1; Secure\ni=1; Secure\nj=1; Secure\nk=1; Secure\na=1\nb=2; Secure\nc=3", HEADER_CHECK_RESULT_FAIL, 8, { "Cookies with no Secure attribute: 2" } },
  };
  static_assertCookieCases(cases, sizeof(cases) / sizeof(cases[0]));
}

void test_SETCOOKIE_unknown_samesite_value_fails(void)
{
  static const CookieCase_t cases[] = {
    { "id=1; Secure; SameSite=Lazy",                 HEADER_CHECK_RESULT_FAIL, 1, { "Cookies with a SameSite value other than Strict, Lax or None: 1" } },
    { "id=1; Secure; SameSite=",                     HEADER_CHECK_RESULT_FAIL, 1, { "Cookies with a SameSite value other than Strict, Lax or None: 1" } },
    { "id=1; Secure; SameSite",                      HEADER_CHECK_RESULT_FAIL, 1, { "Cookies with a SameSite value other than Strict, Lax or None: 1" } },
    { "id=1; Secure; SameSite=Lax; SameSite=Bogus",  HEADER_CHECK_RESULT_FAIL, 1, { "Cookies with a SameSite value other than Strict, Lax or None: 1" } },
    { "id=1; Secure; SameSite=Lax Strict",           HEADER_CHECK_RESULT_FAIL, 1, { "Cookies with a SameSite value other than Strict, Lax or None: 1" } },
  };
  static_assertCookieCases(cases, sizeof(cases) / sizeof(cases[0]));
}

void test_SETCOOKIE_samesite_none_without_secure_fails(void)
{
  static const CookieCase_t cases[] = {
    { "id=1; SameSite=None",           HEADER_CHECK_RESULT_FAIL, 1, { "Cookies with no Secure attribute: 1", "Cookies with SameSite=None and no Secure attribute: 1" } },
    { "id=1; samesite=NONE",           HEADER_CHECK_RESULT_FAIL, 1, { "Cookies with no Secure attribute: 1", "Cookies with SameSite=None and no Secure attribute: 1" } },
    { "id=1; SameSite=Lax; SameSite=None", HEADER_CHECK_RESULT_FAIL, 1, { "Cookies with no Secure attribute: 1", "Cookies with SameSite=None and no Secure attribute: 1" } },
  };
  static_assertCookieCases(cases, sizeof(cases) / sizeof(cases[0]));
}

void test_SETCOOKIE_broken_prefix_fails(void)
{
  static const CookieCase_t cases[] = {
    { "__Secure-id=1",                                    HEADER_CHECK_RESULT_FAIL, 1, { "Cookies with no Secure attribute: 1", "Cookies that break the rules of their __Secure- or __Host- prefix: 1" } },
    { "__secure-id=1; SameSite=Lax",                      HEADER_CHECK_RESULT_FAIL, 1, { "Cookies with no Secure attribute: 1", "Cookies that break the rules of their __Secure- or __Host- prefix: 1" } },
    { "__Host-id=1; Path=/",                              HEADER_CHECK_RESULT_FAIL, 1, { "Cookies with no Secure attribute: 1", "Cookies that break the rules of their __Secure- or __Host- prefix: 1" } },
    { "__host-id=1; Secure; Path=/; Domain=example.com",  HEADER_CHECK_RESULT_FAIL, 1, { "Cookies that break the rules of their __Secure- or __Host- prefix: 1" } },
    { "__Host-id=1; Secure; Path=/a",                     HEADER_CHECK_RESULT_FAIL, 1, { "Cookies that break the rules of their __Secure- or __Host- prefix: 1" } },
    { "__Host-id=1; Secure",                              HEADER_CHECK_RESULT_FAIL, 1, { "Cookies that break the rules of their __Secure- or __Host- prefix: 1" } },
    { "__Host-id=1; Secure; Path=/; Path=/a",             HEADER_CHECK_RESULT_FAIL, 1, { "Cookies that break the rules of their __Secure- or __Host- prefix: 1" } },
    { "__Host-id; Secure",                                HEADER_CHECK_RESULT_FAIL, 1, { "Cookies that break the rules of their __Secure- or __Host- prefix: 1" } },
    { " __Host-id=1; Secure",                             HEADER_CHECK_RESULT_FAIL, 1, { "Cookies that break the rules of their __Secure- or __Host- prefix: 1" } },
    { "__Host-id=1; Secure; Path=/; Domain=a",            HEADER_CHECK_RESULT_FAIL, 1, { "Cookies that break the rules of their __Secure- or __Host- prefix: 1" } },
  };
  static_assertCookieCases(cases, sizeof(cases) / sizeof(cases[0]));
}

void test_SETCOOKIE_session_cookie_without_httponly_warns(void)
{
  static const CookieCase_t cases[] = {
    { "PHPSESSID=1; Secure; SameSite=Lax",    HEADER_CHECK_RESULT_WARN, 1, { "Session or login cookies with no HttpOnly attribute: 1" } },
    { "connect.sid_sess=1; Secure",           HEADER_CHECK_RESULT_WARN, 1, { "Session or login cookies with no HttpOnly attribute: 1" } },
    { "LOGIN=1; Secure",                      HEADER_CHECK_RESULT_WARN, 1, { "Session or login cookies with no HttpOnly attribute: 1" } },
    { "remember_login_token=1; Secure",       HEADER_CHECK_RESULT_WARN, 1, { "Session or login cookies with no HttpOnly attribute: 1" } },
    { "csrftoken=1; Secure; SameSite=Lax",    HEADER_CHECK_RESULT_PASS, 1, { NULL } },
  };
  static_assertCookieCases(cases, sizeof(cases) / sizeof(cases[0]));
}

void test_SETCOOKIE_csrf_cookie_without_samesite_warns(void)
{
  static const CookieCase_t cases[] = {
    { "csrftoken=1; Secure",                 HEADER_CHECK_RESULT_WARN, 1, { "CSRF cookies with no SameSite attribute: 1" } },
    { "_CSRF=1; Secure; HttpOnly",           HEADER_CHECK_RESULT_WARN, 1, { "CSRF cookies with no SameSite attribute: 1" } },
    { "csrf=1; Secure; SameSite=Bogus",      HEADER_CHECK_RESULT_FAIL, 1, { "Cookies with a SameSite value other than Strict, Lax or None: 1" } },
  };
  static_assertCookieCases(cases, sizeof(cases) / sizeof(cases[0]));
}

void test_SETCOOKIE_every_kind_comes_once_in_kind_order(void)
{
  static const CookieCase_t cases[] = {
    { "sess=1; SameSite=None\n__Host-a=1; Secure\ncsrf=1\nb=1; Secure; SameSite=x\nLOGIN=1; Secure; HttpOnly\nc=1",
      HEADER_CHECK_RESULT_FAIL, 6,
      { "Cookies with no Secure attribute: 3",
        "Cookies with a SameSite value other than Strict, Lax or None: 1",
        "Cookies with SameSite=None and no Secure attribute: 1",
        "Cookies that break the rules of their __Secure- or __Host- prefix: 1",
        "Session or login cookies with no HttpOnly attribute: 1",
        "CSRF cookies with no SameSite attribute: 1" } },
  };
  static_assertCookieCases(cases, sizeof(cases) / sizeof(cases[0]));
}

void test_SETCOOKIE_copy_count_above_the_cookies_of_the_value_raises_the_not_checked_issue(void)
{
  static const struct
  {
    const char*         mp_value;
    size_t              m_copyCount;
    HeaderCheckResult_t m_result;
    size_t              m_cookieCount;
    const char*         mp_lastText;
    int                 m_issueCount;
  } cases[] = {
    { "a=1; Secure\nb=1; Secure", 3,  HEADER_CHECK_RESULT_WARN, 3,  "Cookies not checked: 1",  1 },
    { "a=1; Secure\nb=1; Secure", 60, HEADER_CHECK_RESULT_WARN, 60, "Cookies not checked: 58", 1 },
    { "a=1; Secure\nb=1; Secure", 2,  HEADER_CHECK_RESULT_PASS, 2,  NULL,                      0 },
    { "a=1; Secure\nb=1; Secure", 0,  HEADER_CHECK_RESULT_PASS, 2,  NULL,                      0 },
    { "a=1\nb=1",                 60, HEADER_CHECK_RESULT_FAIL, 60, "Cookies not checked: 58", 2 },
    { "a=1; Secure\nb=1; Secure", 1000000000000001u, HEADER_CHECK_RESULT_WARN, 1000000000000001u, "Cookies not checked: 999999999999999", 1 },
    { "a=1; Secure\nb=1; Secure", 1000000000000002u, HEADER_CHECK_RESULT_WARN, 1000000000000002u, "Cookies not checked: 999999999999999", 1 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    g_values[HEADER_CHECK_HEADER_SET_COOKIE] = (char*)cases[i].mp_value;
    g_setCookieCopyCount = cases[i].m_copyCount;
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_SET_COOKIE);
    char message[32];
    snprintf(message, sizeof(message), "case %zu", i);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_result, finding->m_result, message);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(cases[i].m_cookieCount, finding->m_cookieCount, message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_issueCount, finding->m_issueCount, message);
    if (cases[i].mp_lastText != NULL)
    {
      char text[HEADER_CHECK_ISSUE_TEXT_SIZE];
      header_check_writeIssueText(&finding->ma_issues[finding->m_issueCount - 1], text, sizeof(text));
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_lastText, text, message);
    }
  }
}

void test_CORS_one_origin_star_without_credentials_or_empty_value_passes(void)
{
  static const struct
  {
    const char* mp_allowOrigin;
    const char* mp_allowCredentials;
  } cases[] = {
    { "https://app.example", "true" },
    { "*",                   NULL },
    { "*",                   "false" },
    { "*",                   "TRUE" },
    { "*",                   "true, true" },
    { "NULL",                NULL },
    { "",                    "true" },
    { " * ",                 NULL },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    g_values[HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN]      = (char*)cases[i].mp_allowOrigin;
    g_values[HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS] = (char*)cases[i].mp_allowCredentials;
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_PASS, finding->m_result, cases[i].mp_allowOrigin);
    TEST_ASSERT_EQUAL_PTR_MESSAGE(cases[i].mp_allowOrigin, finding->mp_value, cases[i].mp_allowOrigin);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, finding->m_issueCount, cases[i].mp_allowOrigin);
  }
}

void test_CORS_null_more_origins_and_star_with_credentials_warn(void)
{
  static const struct
  {
    const char* mp_allowOrigin;
    const char* mp_allowCredentials;
    const char* mp_text;
  } cases[] = {
    { "null",                                  NULL,      TEXT_CORS_NULL_ORIGIN },
    { "null",                                  "true",    TEXT_CORS_NULL_ORIGIN },
    { " null\t",                               NULL,      TEXT_CORS_NULL_ORIGIN },
    { "https://a.example, https://b.example",  NULL,      TEXT_CORS_MULTIPLE_ORIGINS },
    { "https://a.example,https://b.example",   NULL,      TEXT_CORS_MULTIPLE_ORIGINS },
    { "https://a.example https://b.example",   "true",    TEXT_CORS_MULTIPLE_ORIGINS },
    { "https://a.example\thttps://b.example",  NULL,      TEXT_CORS_MULTIPLE_ORIGINS },
    { "null, *",                               "true",    TEXT_CORS_MULTIPLE_ORIGINS },
    { "*",                                     "true",    TEXT_CORS_WILDCARD_CREDS },
    { "*",                                     " true ",  TEXT_CORS_WILDCARD_CREDS },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    g_values[HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN]      = (char*)cases[i].mp_allowOrigin;
    g_values[HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS] = (char*)cases[i].mp_allowCredentials;
    const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HEADER_CHECK_RESULT_WARN, finding->m_result, cases[i].mp_allowOrigin);
    TEST_ASSERT_EQUAL_PTR_MESSAGE(cases[i].mp_allowOrigin, finding->mp_value, cases[i].mp_allowOrigin);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, finding->m_issueCount, cases[i].mp_allowOrigin);
    char text[HEADER_CHECK_ISSUE_TEXT_SIZE];
    header_check_writeIssueText(&finding->ma_issues[0], text, sizeof(text));
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_text, text, cases[i].mp_allowOrigin);
  }
}

void test_CORS_credentials_without_origin_pass(void)
{
  g_values[HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS] = "true";
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN);
  TEST_ASSERT_EQUAL_INT(HEADER_CHECK_RESULT_PASS, finding->m_result);
  TEST_ASSERT_NULL(finding->mp_value);
  TEST_ASSERT_EQUAL_INT(0, finding->m_issueCount);
}

void test_value_of_500_code_points_is_shown_whole_and_501_is_cut(void)
{
  g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = static_fillLongValue("a", 499, "");
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_PERMISSIONS_POLICY);
  TEST_ASSERT_EQUAL_size_t(499, finding->m_valueLen);
  TEST_ASSERT_EQUAL_size_t(499, finding->m_valueCodePointCount);
  TEST_ASSERT_EQUAL_size_t(499, finding->m_shownValueLen);
  TEST_ASSERT_FALSE(finding->m_isValueCut);

  g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = static_fillLongValue("a", 500, "");
  finding = static_evaluate(HEADER_CHECK_HEADER_PERMISSIONS_POLICY);
  TEST_ASSERT_EQUAL_size_t(500, finding->m_valueLen);
  TEST_ASSERT_EQUAL_size_t(500, finding->m_valueCodePointCount);
  TEST_ASSERT_EQUAL_size_t(500, finding->m_shownValueLen);
  TEST_ASSERT_FALSE(finding->m_isValueCut);

  g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = static_fillLongValue("a", 501, "");
  finding = static_evaluate(HEADER_CHECK_HEADER_PERMISSIONS_POLICY);
  TEST_ASSERT_EQUAL_size_t(501, finding->m_valueLen);
  TEST_ASSERT_EQUAL_size_t(501, finding->m_valueCodePointCount);
  TEST_ASSERT_EQUAL_size_t(500, finding->m_shownValueLen);
  TEST_ASSERT_TRUE(finding->m_isValueCut);
}

void test_value_of_two_byte_sequences_is_cut_after_whole_sequences(void)
{
  g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = static_fillLongValue("\xc3\xa9", 500, "");
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_PERMISSIONS_POLICY);
  TEST_ASSERT_EQUAL_size_t(1000, finding->m_valueLen);
  TEST_ASSERT_EQUAL_size_t(500, finding->m_valueCodePointCount);
  TEST_ASSERT_EQUAL_size_t(1000, finding->m_shownValueLen);
  TEST_ASSERT_FALSE(finding->m_isValueCut);

  g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = static_fillLongValue("\xc3\xa9", 501, "");
  finding = static_evaluate(HEADER_CHECK_HEADER_PERMISSIONS_POLICY);
  TEST_ASSERT_EQUAL_size_t(1002, finding->m_valueLen);
  TEST_ASSERT_EQUAL_size_t(501, finding->m_valueCodePointCount);
  TEST_ASSERT_EQUAL_size_t(1000, finding->m_shownValueLen);
  TEST_ASSERT_TRUE(finding->m_isValueCut);
}

void test_value_cut_keeps_a_whole_three_or_four_byte_sequence(void)
{
  g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = static_fillLongValue("a", 499, "\xe2\x82\xac" "b");
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_PERMISSIONS_POLICY);
  TEST_ASSERT_EQUAL_size_t(503, finding->m_valueLen);
  TEST_ASSERT_EQUAL_size_t(501, finding->m_valueCodePointCount);
  TEST_ASSERT_EQUAL_size_t(502, finding->m_shownValueLen);
  TEST_ASSERT_TRUE(finding->m_isValueCut);

  g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = static_fillLongValue("a", 499, "\xf0\x9f\x98\x80" "b");
  finding = static_evaluate(HEADER_CHECK_HEADER_PERMISSIONS_POLICY);
  TEST_ASSERT_EQUAL_size_t(504, finding->m_valueLen);
  TEST_ASSERT_EQUAL_size_t(501, finding->m_valueCodePointCount);
  TEST_ASSERT_EQUAL_size_t(503, finding->m_shownValueLen);
  TEST_ASSERT_TRUE(finding->m_isValueCut);
}

void test_value_cut_counts_each_invalid_byte_as_one_code_point(void)
{
  g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = static_fillLongValue("a", 499, "\xff" "b");
  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_PERMISSIONS_POLICY);
  TEST_ASSERT_EQUAL_size_t(501, finding->m_valueLen);
  TEST_ASSERT_EQUAL_size_t(501, finding->m_valueCodePointCount);
  TEST_ASSERT_EQUAL_size_t(500, finding->m_shownValueLen);
  TEST_ASSERT_TRUE(finding->m_isValueCut);

  g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = static_fillLongValue("a", 499, "\xe2\x82" "b");
  finding = static_evaluate(HEADER_CHECK_HEADER_PERMISSIONS_POLICY);
  TEST_ASSERT_EQUAL_size_t(502, finding->m_valueLen);
  TEST_ASSERT_EQUAL_size_t(502, finding->m_valueCodePointCount);
  TEST_ASSERT_EQUAL_size_t(500, finding->m_shownValueLen);
  TEST_ASSERT_TRUE(finding->m_isValueCut);
}

void test_value_cut_does_not_cut_what_the_rule_reads(void)
{
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY] = static_fillLongValue("img-src https://cdn.example.com, ", 36, "default-src 'self'; script-src *" CSP_QUIET_TAIL);

  const HeaderCheckFinding_t* finding = static_evaluate(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY);

  TEST_ASSERT_EQUAL_size_t(1256, finding->m_valueLen);
  TEST_ASSERT_EQUAL_size_t(1256, finding->m_valueCodePointCount);
  TEST_ASSERT_EQUAL_size_t(500, finding->m_shownValueLen);
  TEST_ASSERT_TRUE(finding->m_isValueCut);
  TEST_ASSERT_EQUAL_PTR(g_longValue, finding->mp_value);
  ASSERT_ISSUES(finding, "Permissive CSP: 'script-src *' allows any source (XSS risk)");
}

static int static_evaluateWithoutReflection(bool kind_seen[HEADER_CHECK_ISSUE_KIND_COUNT])
{
  header_check_evaluate(g_values, g_setCookieCopyCount, &g_report);

  int issue_total = 0;
  for (int rule = 0; rule < HEADER_CHECK_RULE_COUNT; rule++)
  {
    const HeaderCheckFinding_t* finding = &g_report.ma_findings[rule];
    for (int i = 0; i < finding->m_issueCount; i++)
    {
      char text[HEADER_CHECK_ISSUE_TEXT_SIZE];
      header_check_writeIssueText(&finding->ma_issues[i], text, sizeof(text));
      TEST_ASSERT_NULL_MESSAGE(strstr(text, "REFLECTED"), text);
      TEST_ASSERT_NULL_MESSAGE(strstr(text, "reflected"), text);
      kind_seen[finding->ma_issues[i].m_kind] = true;
      issue_total++;
    }
  }
  return issue_total;
}

void test_no_issue_text_holds_a_byte_of_a_value(void)
{
  bool kind_seen[HEADER_CHECK_ISSUE_KIND_COUNT] = { false };
  g_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY]   = "REFLECTED-src *; script-src REFLECTED * 'unsafe-inline' http://REFLECTED https:; object-src ftp:; REFLECTED-src; object-src REFLECTED";
  g_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY] = "max-age=REFLECTED, REFLECTED";
  g_values[HEADER_CHECK_HEADER_X_CONTENT_TYPE_OPTIONS]    = "REFLECTED";
  g_values[HEADER_CHECK_HEADER_X_FRAME_OPTIONS]           = "ALLOW-FROM https://REFLECTED.example/";
  g_values[HEADER_CHECK_HEADER_REFERRER_POLICY]           = "REFLECTED";
  g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY]        = "REFLECTED";
  g_values[HEADER_CHECK_HEADER_X_XSS_PROTECTION]          = "1; report=https://REFLECTED.example/";
  g_values[HEADER_CHECK_HEADER_SET_COOKIE]                = "REFLECTED_sess=REFLECTED; SameSite=REFLECTED\n__Host-REFLECTED_csrf=REFLECTED; Domain=REFLECTED.example";
  g_values[HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN] = "https://REFLECTED.example, https://reflected.example";
  g_setCookieCopyCount = 60;
  TEST_ASSERT_EQUAL_INT(22, static_evaluateWithoutReflection(kind_seen));
  ASSERT_ISSUES(&g_report.ma_findings[HEADER_CHECK_HEADER_X_FRAME_OPTIONS], TEXT_XFO_INVALID);
  TEST_ASSERT_NULL(g_report.ma_findings[HEADER_CHECK_HEADER_SET_COOKIE].mp_value);

  g_values[HEADER_CHECK_HEADER_REFERRER_POLICY]    = "REFLECTED, origin";
  g_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY] = "reflected=*, camera=(\"https://REFLECTED.example\")";
  g_values[HEADER_CHECK_HEADER_SET_COOKIE]         = "REFLECTED=REFLECTED; SameSite=None";
  g_values[HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN] = "null";
  g_setCookieCopyCount = 0;
  TEST_ASSERT_EQUAL_INT(18, static_evaluateWithoutReflection(kind_seen));
  ASSERT_ISSUES(&g_report.ma_findings[HEADER_CHECK_HEADER_PERMISSIONS_POLICY], TEXT_PERMISSIONS_WILDCARD);

  g_values[HEADER_CHECK_HEADER_REFERRER_POLICY] = "REFLECTED, origin-when-cross-origin";
  g_values[HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN]      = "*";
  g_values[HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS] = "true";
  TEST_ASSERT_EQUAL_INT(18, static_evaluateWithoutReflection(kind_seen));

  static const HeaderCheckIssueKind_t new_kinds[] = {
    HEADER_CHECK_ISSUE_CSP_BROAD_SOURCE,
    HEADER_CHECK_ISSUE_CSP_REPEATED_DIRECTIVE,
    HEADER_CHECK_ISSUE_REFERRER_ORIGIN,
    HEADER_CHECK_ISSUE_REFERRER_ORIGIN_WHEN_CROSS_ORIGIN,
    HEADER_CHECK_ISSUE_PERMISSIONS_MALFORMED,
    HEADER_CHECK_ISSUE_PERMISSIONS_WILDCARD,
    HEADER_CHECK_ISSUE_COOKIE_NO_SECURE,
    HEADER_CHECK_ISSUE_COOKIE_INVALID_SAMESITE,
    HEADER_CHECK_ISSUE_COOKIE_SAMESITE_NONE_WITHOUT_SECURE,
    HEADER_CHECK_ISSUE_COOKIE_BROKEN_PREFIX,
    HEADER_CHECK_ISSUE_COOKIE_SESSION_WITHOUT_HTTPONLY,
    HEADER_CHECK_ISSUE_COOKIE_CSRF_WITHOUT_SAMESITE,
    HEADER_CHECK_ISSUE_COOKIE_NOT_ALL_CHECKED,
    HEADER_CHECK_ISSUE_CORS_NULL_ORIGIN,
    HEADER_CHECK_ISSUE_CORS_WILDCARD_WITH_CREDENTIALS,
    HEADER_CHECK_ISSUE_CORS_MULTIPLE_ORIGINS,
  };
  for (size_t i = 0; i < sizeof(new_kinds) / sizeof(new_kinds[0]); i++)
    TEST_ASSERT_TRUE_MESSAGE(kind_seen[new_kinds[i]], "a new kind raised no issue");
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(101, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_capturedHeaderNames_lists_eleven_names_then_NULL);
  RUN_TEST(test_headerName_gives_the_name_of_each_header);
  RUN_TEST(test_severityName_and_resultName_give_each_text);
  RUN_TEST(test_ruleRemediation_gives_the_text_of_each_rule);
  RUN_TEST(test_writeIssueText_gives_the_fixed_text_of_each_kind);
  RUN_TEST(test_writeIssueText_puts_the_directive_or_the_max_age_between_the_fixed_parts);
  RUN_TEST(test_writeIssueText_puts_the_cookie_count_into_each_cookie_text);
  RUN_TEST(test_evaluate_with_no_header_gives_nine_findings_in_rule_order);
  RUN_TEST(test_evaluate_points_each_finding_at_its_own_value);
  RUN_TEST(test_CSP_report_only_alone_warns_and_shows_its_value);
  RUN_TEST(test_CSP_enforced_policy_is_rated_and_report_only_is_not);
  RUN_TEST(test_CSP_strict_policy_passes);
  RUN_TEST(test_CSP_python_strict_vector_warns_about_object_src_and_base_uri);
  RUN_TEST(test_CSP_empty_directive_is_skipped);
  RUN_TEST(test_CSP_script_src_elem_leaves_default_src_the_script_directive);
  RUN_TEST(test_CSP_wildcard_source_warns);
  RUN_TEST(test_CSP_unsafe_inline_and_unsafe_eval_warn);
  RUN_TEST(test_CSP_three_permissive_sources_give_three_issues_in_rule_order);
  RUN_TEST(test_CSP_names_and_keywords_match_in_any_case);
  RUN_TEST(test_CSP_sources_of_other_directives_raise_no_issue);
  RUN_TEST(test_CSP_without_default_src_and_script_src_fails);
  RUN_TEST(test_CSP_empty_value_fails);
  RUN_TEST(test_CSP_script_src_or_default_src_alone_is_enough);
  RUN_TEST(test_CSP_directive_without_sources_is_present);
  RUN_TEST(test_CSP_default_src_that_matches_nothing_stands_for_object_src);
  RUN_TEST(test_CSP_default_src_that_matches_something_needs_object_src);
  RUN_TEST(test_CSP_object_src_present_leaves_only_base_uri);
  RUN_TEST(test_CSP_nonce_or_hash_makes_unsafe_inline_ignored);
  RUN_TEST(test_CSP_broken_nonce_or_hash_leaves_unsafe_inline);
  RUN_TEST(test_CSP_strict_dynamic_makes_unsafe_inline_ignored_in_script_directives);
  RUN_TEST(test_CSP_strict_dynamic_leaves_unsafe_inline_of_other_directives);
  RUN_TEST(test_CSP_http_and_data_sources_in_script_src_warn);
  RUN_TEST(test_CSP_sources_that_only_look_like_http_raise_no_issue);
  RUN_TEST(test_CSP_default_src_is_the_script_directive_of_a_policy_without_script_src);
  RUN_TEST(test_CSP_default_src_sources_are_no_scripts_beside_script_src);
  RUN_TEST(test_CSP_each_policy_has_its_own_script_directive);
  RUN_TEST(test_CSP_http_and_data_in_other_directives_raise_no_issue);
  RUN_TEST(test_CSP_broad_source_in_the_script_directive_warns);
  RUN_TEST(test_CSP_broad_source_in_default_src_or_object_src_warns);
  RUN_TEST(test_CSP_broad_source_in_other_directives_raises_no_issue);
  RUN_TEST(test_CSP_sources_that_only_look_broad_raise_no_issue);
  RUN_TEST(test_CSP_http_source_is_no_broad_source);
  RUN_TEST(test_CSP_each_kind_and_directive_is_raised_once);
  RUN_TEST(test_CSP_tabs_and_spaces_separate_words);
  RUN_TEST(test_CSP_repeated_directive_warns_once);
  RUN_TEST(test_CSP_each_directive_of_the_repeat_list_is_checked);
  RUN_TEST(test_CSP_directives_off_the_repeat_list_may_repeat);
  RUN_TEST(test_CSP_each_policy_counts_its_own_directives);
  RUN_TEST(test_CSP_repeat_issues_follow_the_other_issues);
  RUN_TEST(test_CSP_the_most_issues_fill_the_finding);
  RUN_TEST(test_HSTS_180_days_and_include_subdomains_pass);
  RUN_TEST(test_HSTS_max_age_below_180_days_fails_with_its_number);
  RUN_TEST(test_HSTS_max_age_of_thirty_digits_passes);
  RUN_TEST(test_HSTS_missing_max_age_or_include_subdomains_fails);
  RUN_TEST(test_HSTS_well_formed_spellings_pass);
  RUN_TEST(test_HSTS_malformed_max_age_fails);
  RUN_TEST(test_HSTS_first_max_age_counts);
  RUN_TEST(test_HSTS_second_copy_is_not_read_and_warns);
  RUN_TEST(test_HSTS_trailing_comma_is_no_second_copy);
  RUN_TEST(test_HSTS_first_copy_decides_the_result);
  RUN_TEST(test_XCTO_first_value_nosniff_passes);
  RUN_TEST(test_XCTO_other_first_value_fails);
  RUN_TEST(test_XFO_deny_or_sameorigin_passes);
  RUN_TEST(test_XFO_other_value_fails_with_a_fixed_issue);
  RUN_TEST(test_XFO_passes_when_the_policy_has_frame_ancestors);
  RUN_TEST(test_XFO_ignores_frame_ancestors_of_report_only);
  RUN_TEST(test_XFO_needs_frame_ancestors_as_a_directive_name);
  RUN_TEST(test_REFERRER_safe_policy_passes);
  RUN_TEST(test_REFERRER_policy_that_leaks_the_url_fails);
  RUN_TEST(test_REFERRER_last_known_token_is_the_policy);
  RUN_TEST(test_REFERRER_origin_policies_warn);
  RUN_TEST(test_REFERRER_value_without_a_known_token_fails);
  RUN_TEST(test_PERMISSIONS_present_passes);
  RUN_TEST(test_PERMISSIONS_valid_dictionary_passes);
  RUN_TEST(test_PERMISSIONS_malformed_value_fails);
  RUN_TEST(test_PERMISSIONS_wildcard_warns);
  RUN_TEST(test_PERMISSIONS_star_that_is_no_member_value_passes);
  RUN_TEST(test_PERMISSIONS_malformed_value_raises_no_wildcard);
  RUN_TEST(test_XXP_zero_passes);
  RUN_TEST(test_XXP_other_value_warns);
  RUN_TEST(test_SETCOOKIE_secure_cookies_pass);
  RUN_TEST(test_SETCOOKIE_absent_passes_with_no_cookie);
  RUN_TEST(test_SETCOOKIE_cookie_without_secure_fails);
  RUN_TEST(test_SETCOOKIE_issue_counts_the_cookies_of_its_kind);
  RUN_TEST(test_SETCOOKIE_unknown_samesite_value_fails);
  RUN_TEST(test_SETCOOKIE_samesite_none_without_secure_fails);
  RUN_TEST(test_SETCOOKIE_broken_prefix_fails);
  RUN_TEST(test_SETCOOKIE_session_cookie_without_httponly_warns);
  RUN_TEST(test_SETCOOKIE_csrf_cookie_without_samesite_warns);
  RUN_TEST(test_SETCOOKIE_every_kind_comes_once_in_kind_order);
  RUN_TEST(test_SETCOOKIE_copy_count_above_the_cookies_of_the_value_raises_the_not_checked_issue);
  RUN_TEST(test_CORS_one_origin_star_without_credentials_or_empty_value_passes);
  RUN_TEST(test_CORS_null_more_origins_and_star_with_credentials_warn);
  RUN_TEST(test_CORS_credentials_without_origin_pass);
  RUN_TEST(test_value_of_500_code_points_is_shown_whole_and_501_is_cut);
  RUN_TEST(test_value_of_two_byte_sequences_is_cut_after_whole_sequences);
  RUN_TEST(test_value_cut_keeps_a_whole_three_or_four_byte_sequence);
  RUN_TEST(test_value_cut_counts_each_invalid_byte_as_one_code_point);
  RUN_TEST(test_value_cut_does_not_cut_what_the_rule_reads);
  RUN_TEST(test_no_issue_text_holds_a_byte_of_a_value);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
