#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "header_check.h"
#include "bytes.h"
#include "utf8.h"

#define HEADER_CHECK_HSTS_MIN_MAX_AGE_SECONDS 15552000u

#define HEADER_CHECK_MAX_DETAIL_NUMBER 999999999999999u

#define HEADER_CHECK_HSTS_MAX_AGE_NAME      "max-age"
#define HEADER_CHECK_HSTS_MAX_AGE_NAME_LEN  (sizeof(HEADER_CHECK_HSTS_MAX_AGE_NAME) - 1)

#define HEADER_CHECK_CSP_FETCH_DIRECTIVE_COUNT 15

#define HEADER_CHECK_CSP_NON_FETCH_REPEAT_DIRECTIVE_COUNT 4

#define HEADER_CHECK_CSP_REPEAT_DIRECTIVE_COUNT (HEADER_CHECK_CSP_FETCH_DIRECTIVE_COUNT + HEADER_CHECK_CSP_NON_FETCH_REPEAT_DIRECTIVE_COUNT)
_Static_assert(HEADER_CHECK_CSP_REPEAT_DIRECTIVE_COUNT <= 32, "each directive of the repeat list has one bit of a uint32_t");

#define HEADER_CHECK_STRUCTURED_FIELD_INTEGER_MAX_DIGITS          15
#define HEADER_CHECK_STRUCTURED_FIELD_DECIMAL_MAX_INTEGER_DIGITS  12
#define HEADER_CHECK_STRUCTURED_FIELD_DECIMAL_MAX_FRACTION_DIGITS 3

typedef struct {
  const char*   mp_text;
  size_t        m_len;
} HeaderCheckSpan_t;

typedef struct {
  const char*   mp_name;
  bool          m_isScriptDirective;
} HeaderCheckCspDirective_t;

typedef struct {
  bool  m_hasDefaultSrc;
  bool  m_hasScriptSrc;
  bool  m_hasObjectSrc;
  bool  m_hasBaseUri;
  bool  m_hasFrameAncestors;
  bool  m_isDefaultSrcNone;
} HeaderCheckCspNames_t;

typedef struct {
  bool  m_hasWildcard;
  bool  m_hasUnsafeInline;
  bool  m_hasUnsafeEval;
  bool  m_hasNonceOrHash;
  bool  m_hasStrictDynamic;
  bool  m_hasHttpSource;
  bool  m_hasDataSource;
  bool  m_hasBroadSource;
} HeaderCheckCspSources_t;

typedef struct {
  HeaderCheckSpan_t   m_name;
  bool                m_hasSecure;
  bool                m_hasHttpOnly;
  bool                m_hasSameSite;
  HeaderCheckSpan_t   m_sameSiteValue;
  bool                m_hasDomain;
  bool                m_isPathRoot;
} HeaderCheckCookie_t;

typedef struct {
  size_t  m_noSecureCount;
  size_t  m_invalidSameSiteCount;
  size_t  m_sameSiteNoneWithoutSecureCount;
  size_t  m_brokenPrefixCount;
  size_t  m_sessionWithoutHttpOnlyCount;
  size_t  m_csrfWithoutSameSiteCount;
} HeaderCheckCookieCounts_t;

const char* const header_check_capturedHeaderNames[HEADER_CHECK_HEADER_COUNT + 1] = {
  "Content-Security-Policy",
  "Strict-Transport-Security",
  "X-Content-Type-Options",
  "X-Frame-Options",
  "Referrer-Policy",
  "Permissions-Policy",
  "X-XSS-Protection",
  "Set-Cookie",
  "Access-Control-Allow-Origin",
  "Content-Security-Policy-Report-Only",
  "Access-Control-Allow-Credentials",
  NULL,
};
_Static_assert(HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY_REPORT_ONLY == HEADER_CHECK_RULE_COUNT &&
               HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS    == HEADER_CHECK_RULE_COUNT + 1 &&
               HEADER_CHECK_HEADER_COUNT                               == HEADER_CHECK_RULE_COUNT + 2,
               "the headers with a rule come first, and only Report-Only and Access-Control-Allow-Credentials follow them");

static const HeaderCheckSeverity_t RULE_SEVERITIES[HEADER_CHECK_RULE_COUNT] = {
  HEADER_CHECK_SEVERITY_HIGH,
  HEADER_CHECK_SEVERITY_HIGH,
  HEADER_CHECK_SEVERITY_MEDIUM,
  HEADER_CHECK_SEVERITY_MEDIUM,
  HEADER_CHECK_SEVERITY_LOW,
  HEADER_CHECK_SEVERITY_LOW,
  HEADER_CHECK_SEVERITY_LOW,
  HEADER_CHECK_SEVERITY_MEDIUM,
  HEADER_CHECK_SEVERITY_LOW,
};

static const char* const RULE_REMEDIATIONS[HEADER_CHECK_RULE_COUNT] = {
  "Add a Content-Security-Policy header with a strict policy; start with default-src 'self'",
  "Add Strict-Transport-Security: max-age=63072000; includeSubDomains",
  "Add X-Content-Type-Options: nosniff",
  "Add X-Frame-Options: DENY or SAMEORIGIN",
  "Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer",
  "Add Permissions-Policy to disable unnecessary browser features (e.g., camera=(), microphone=())",
  "Remove X-XSS-Protection or set it to 0; use Content-Security-Policy against XSS",
  "Mark every cookie Secure with SameSite=Lax or Strict, and mark session cookies HttpOnly",
  "Send Access-Control-Allow-Origin with one trusted origin; never null, and never * with credentials",
};

static const char* const SEVERITY_NAMES[HEADER_CHECK_SEVERITY_COUNT] = { "high", "medium", "low" };
static const char* const RESULT_NAMES[HEADER_CHECK_RESULT_COUNT]     = { "pass", "warn", "fail", "missing" };

static const HeaderCheckCspDirective_t CSP_FETCH_DIRECTIVES[HEADER_CHECK_CSP_FETCH_DIRECTIVE_COUNT] = {
  { "default-src",     false },
  { "script-src",      true  },
  { "script-src-elem", true  },
  { "script-src-attr", true  },
  { "style-src",       false },
  { "style-src-elem",  false },
  { "style-src-attr",  false },
  { "img-src",         false },
  { "connect-src",     false },
  { "font-src",        false },
  { "frame-src",       false },
  { "media-src",       false },
  { "object-src",      false },
  { "worker-src",      false },
  { "child-src",       false },
};

static const HeaderCheckCspDirective_t* const CSP_DEFAULT_SRC = &CSP_FETCH_DIRECTIVES[0];
static const HeaderCheckCspDirective_t* const CSP_SCRIPT_SRC  = &CSP_FETCH_DIRECTIVES[1];
static const HeaderCheckCspDirective_t* const CSP_OBJECT_SRC  = &CSP_FETCH_DIRECTIVES[12];

static const HeaderCheckCspDirective_t CSP_NON_FETCH_REPEAT_DIRECTIVES[HEADER_CHECK_CSP_NON_FETCH_REPEAT_DIRECTIVE_COUNT] = {
  { "base-uri",        false },
  { "form-action",     false },
  { "frame-ancestors", false },
  { "sandbox",         false },
};

static const char* const CSP_BROAD_SOURCES[] = { "https:", "https://*", "ftp:" };

static const char* const CSP_NONCE_AND_HASH_PREFIXES[] = { "'nonce-", "'sha256-", "'sha384-", "'sha512-" };

static const char* const REFERRER_POLICY_TOKENS[] = {
  "no-referrer",
  "no-referrer-when-downgrade",
  "same-origin",
  "origin",
  "strict-origin",
  "origin-when-cross-origin",
  "strict-origin-when-cross-origin",
  "unsafe-url",
};

static const char* const COOKIE_SESSION_NAME_PARTS[] = { "sess", "login" };

static const char STRUCTURED_FIELD_TOKEN_PUNCTUATION[] = "!#$%&'*+-.^_`|~:/";

static void                             static_setHeaderValue                     (HeaderCheckFinding_t* finding, const char* header_value);
static void                             static_addIssue                           (HeaderCheckFinding_t* finding, HeaderCheckIssueKind_t kind);
static void                             static_addIssueWithDetail                 (HeaderCheckFinding_t* finding, HeaderCheckIssueKind_t kind, const char* detail);
static void                             static_addDirectiveIssue                  (HeaderCheckFinding_t* finding, HeaderCheckIssueKind_t kind, const HeaderCheckCspDirective_t* directive);
static void                             static_setResult                          (HeaderCheckFinding_t* finding, bool is_valid);
static HeaderCheckCspNames_t            static_checkCsp                           (const char* csp_value, const char* report_only_value, HeaderCheckFinding_t* finding);
static HeaderCheckCspNames_t            static_readCspNames                       (HeaderCheckSpan_t value);
static void                             static_addCspSourceIssues                 (HeaderCheckSpan_t value, HeaderCheckFinding_t* finding);
static bool                             static_hasScriptSrc                       (HeaderCheckSpan_t policy);
static bool                             static_tryReadNextDirective               (HeaderCheckSpan_t* policy, HeaderCheckSpan_t* name_out, HeaderCheckSpan_t* source_list_out);
static HeaderCheckCspSources_t          static_readCspSources                     (HeaderCheckSpan_t sources);
static bool                             static_isNonceOrHashSource                (HeaderCheckSpan_t source);
static bool                             static_isNoneSourceList                   (HeaderCheckSpan_t sources);
static bool                             static_isBroadSource                      (HeaderCheckSpan_t source);
static const HeaderCheckCspDirective_t* static_findFetchDirective                 (HeaderCheckSpan_t name);
static void                             static_addCspRepeatIssues                 (HeaderCheckSpan_t value, HeaderCheckFinding_t* finding);
static const HeaderCheckCspDirective_t* static_findRepeatDirective                (HeaderCheckSpan_t name, int* index_out);
static void                             static_checkHsts                          (const char* value, HeaderCheckFinding_t* finding);
static bool                             static_tryReadMaxAge                      (HeaderCheckSpan_t token, uint32_t* max_age_out);
static void                             static_checkXcto                          (const char* value, HeaderCheckFinding_t* finding);
static void                             static_checkXfo                           (const char* value, bool has_frame_ancestors, HeaderCheckFinding_t* finding);
static void                             static_checkReferrerPolicy                (const char* value, HeaderCheckFinding_t* finding);
static void                             static_checkPermissionsPolicy             (const char* value, HeaderCheckFinding_t* finding);
static bool                             static_tryReadStructuredFieldDictionary   (HeaderCheckSpan_t value, bool* has_wildcard_out);
static bool                             static_tryReadStructuredFieldInnerList    (HeaderCheckSpan_t* rest, bool* has_wildcard_out);
static bool                             static_tryReadStructuredFieldItem         (HeaderCheckSpan_t* rest, bool* is_wildcard_out);
static bool                             static_tryReadStructuredFieldParameters   (HeaderCheckSpan_t* rest);
static bool                             static_tryReadStructuredFieldKey          (HeaderCheckSpan_t* rest);
static bool                             static_tryReadStructuredFieldBareItem     (HeaderCheckSpan_t* rest, HeaderCheckSpan_t* bare_item_out);
static bool                             static_tryReadStructuredFieldNumber       (HeaderCheckSpan_t* rest);
static bool                             static_tryReadStructuredFieldString       (HeaderCheckSpan_t* rest);
static bool                             static_tryReadStructuredFieldByteSequence (HeaderCheckSpan_t* rest);
static bool                             static_isStructuredFieldTokenByte         (char c);
static void                             static_checkXxp                           (const char* value, HeaderCheckFinding_t* finding);
static void                             static_checkSetCookie                     (const char* value, size_t set_cookie_copy_count, HeaderCheckFinding_t* finding);
static HeaderCheckCookie_t              static_readCookie                         (HeaderCheckSpan_t cookie_text);
static void                             static_countCookieIssues                  (const HeaderCheckCookie_t* cookie, HeaderCheckCookieCounts_t* counts);
static void                             static_addCookieCountIssue                (HeaderCheckFinding_t* finding, HeaderCheckIssueKind_t kind, size_t cookie_count);
static void                             static_checkCors                          (const char* allow_origin_value, const char* allow_credentials_value, HeaderCheckFinding_t* finding);
static HeaderCheckSpan_t                static_spanOf                             (const char* text);
static HeaderCheckSpan_t                static_firstCopy                          (const char* value, bool* has_more_copies_out);
static bool                             static_tryReadNextItem                    (HeaderCheckSpan_t* rest, char separator, HeaderCheckSpan_t* item_out);
static bool                             static_tryReadNextWord                    (HeaderCheckSpan_t* rest, HeaderCheckSpan_t* word_out);
static HeaderCheckSpan_t                static_trim                               (HeaderCheckSpan_t span);
static bool                             static_isWhitespace                       (char c);
static void                             static_skipBytes                          (HeaderCheckSpan_t* rest, size_t count);
static bool                             static_isNextByte                         (HeaderCheckSpan_t rest, char c);
static bool                             static_tryReadByte                        (HeaderCheckSpan_t* rest, char c);
static void                             static_skipSpaces                         (HeaderCheckSpan_t* rest);
static void                             static_skipWhitespace                     (HeaderCheckSpan_t* rest);
static bool                             static_isEqual                            (HeaderCheckSpan_t span, const char* text);
static bool                             static_isEqualIgnoringCase                (HeaderCheckSpan_t span, const char* lower_text);
static bool                             static_hasPrefixIgnoringCase              (HeaderCheckSpan_t span, const char* lower_prefix);
static bool                             static_containsIgnoringCase               (HeaderCheckSpan_t span, const char* lower_text);

void header_check_evaluate(char* const* captured_values, size_t set_cookie_copy_count, HeaderCheckReport_t* report_out)
{
  assert(captured_values != NULL);
  assert(report_out != NULL);

  memset(report_out, 0, sizeof(*report_out));
  for (int rule = 0; rule < HEADER_CHECK_RULE_COUNT; rule++)
  {
    HeaderCheckFinding_t* finding = &report_out->ma_findings[rule];
    finding->m_header   = (HeaderCheckHeader_t)rule;
    finding->m_severity = RULE_SEVERITIES[rule];
    finding->m_result   = HEADER_CHECK_RESULT_MISSING;
    if (rule != HEADER_CHECK_HEADER_SET_COOKIE)
      static_setHeaderValue(finding, captured_values[rule]);
  }

  HeaderCheckFinding_t* findings = report_out->ma_findings;
  HeaderCheckCspNames_t csp_names = static_checkCsp(captured_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY],
                                                    captured_values[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY_REPORT_ONLY],
                                                    &findings[HEADER_CHECK_HEADER_CONTENT_SECURITY_POLICY]);
  static_checkHsts(captured_values[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY], &findings[HEADER_CHECK_HEADER_STRICT_TRANSPORT_SECURITY]);
  static_checkXcto(captured_values[HEADER_CHECK_HEADER_X_CONTENT_TYPE_OPTIONS], &findings[HEADER_CHECK_HEADER_X_CONTENT_TYPE_OPTIONS]);
  static_checkXfo(captured_values[HEADER_CHECK_HEADER_X_FRAME_OPTIONS], csp_names.m_hasFrameAncestors, &findings[HEADER_CHECK_HEADER_X_FRAME_OPTIONS]);
  static_checkReferrerPolicy(captured_values[HEADER_CHECK_HEADER_REFERRER_POLICY], &findings[HEADER_CHECK_HEADER_REFERRER_POLICY]);
  static_checkPermissionsPolicy(captured_values[HEADER_CHECK_HEADER_PERMISSIONS_POLICY], &findings[HEADER_CHECK_HEADER_PERMISSIONS_POLICY]);
  static_checkXxp(captured_values[HEADER_CHECK_HEADER_X_XSS_PROTECTION], &findings[HEADER_CHECK_HEADER_X_XSS_PROTECTION]);
  static_checkSetCookie(captured_values[HEADER_CHECK_HEADER_SET_COOKIE], set_cookie_copy_count, &findings[HEADER_CHECK_HEADER_SET_COOKIE]);
  static_checkCors(captured_values[HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN],
                   captured_values[HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS],
                   &findings[HEADER_CHECK_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN]);
}

const char* header_check_headerName(HeaderCheckHeader_t header)
{
  assert(header >= 0 && header < HEADER_CHECK_HEADER_COUNT);
  return header_check_capturedHeaderNames[header];
}

const char* header_check_severityName(HeaderCheckSeverity_t severity)
{
  assert(severity >= 0 && severity < HEADER_CHECK_SEVERITY_COUNT);
  return SEVERITY_NAMES[severity];
}

const char* header_check_resultName(HeaderCheckResult_t result)
{
  assert(result >= 0 && result < HEADER_CHECK_RESULT_COUNT);
  return RESULT_NAMES[result];
}

const char* header_check_ruleRemediation(HeaderCheckHeader_t rule)
{
  assert(rule >= 0 && rule < HEADER_CHECK_RULE_COUNT);
  return RULE_REMEDIATIONS[rule];
}

size_t header_check_writeIssueText(const HeaderCheckIssue_t* issue, char* text_out, size_t text_out_size)
{
  assert(issue != NULL);
  assert(issue->m_kind >= 0 && issue->m_kind < HEADER_CHECK_ISSUE_KIND_COUNT);
  assert(text_out != NULL);
  assert(text_out_size >= HEADER_CHECK_ISSUE_TEXT_SIZE);

  int text_len = -1;
  switch (issue->m_kind)
  {
    case HEADER_CHECK_ISSUE_CSP_REPORT_ONLY:
      text_len = snprintf(text_out, text_out_size, "Only Content-Security-Policy-Report-Only is set; a report-only policy is not enforced");
      break;
    case HEADER_CHECK_ISSUE_CSP_NO_SCRIPT_DIRECTIVE:
      text_len = snprintf(text_out, text_out_size, "No default-src or script-src directive; scripts may load from any source");
      break;
    case HEADER_CHECK_ISSUE_CSP_WILDCARD:
      text_len = snprintf(text_out, text_out_size, "Permissive CSP: '%s *' allows any source (XSS risk)", issue->ma_detail);
      break;
    case HEADER_CHECK_ISSUE_CSP_UNSAFE_INLINE:
      text_len = snprintf(text_out, text_out_size, "Permissive CSP: '%s' allows 'unsafe-inline' (XSS risk)", issue->ma_detail);
      break;
    case HEADER_CHECK_ISSUE_CSP_UNSAFE_EVAL:
      text_len = snprintf(text_out, text_out_size, "Permissive CSP: '%s' allows 'unsafe-eval' (code injection risk)", issue->ma_detail);
      break;
    case HEADER_CHECK_ISSUE_CSP_HTTP_SCRIPT_SOURCE:
      text_len = snprintf(text_out, text_out_size, "Permissive CSP: '%s' allows scripts over plain http (XSS risk)", issue->ma_detail);
      break;
    case HEADER_CHECK_ISSUE_CSP_DATA_SCRIPT_SOURCE:
      text_len = snprintf(text_out, text_out_size, "Permissive CSP: '%s' allows data: URLs as scripts (XSS risk)", issue->ma_detail);
      break;
    case HEADER_CHECK_ISSUE_CSP_BROAD_SOURCE:
      text_len = snprintf(text_out, text_out_size, "Permissive CSP: '%s' allows every host of a scheme (XSS risk)", issue->ma_detail);
      break;
    case HEADER_CHECK_ISSUE_CSP_NO_OBJECT_SRC:
      text_len = snprintf(text_out, text_out_size, "Missing object-src directive (recommended: object-src 'none')");
      break;
    case HEADER_CHECK_ISSUE_CSP_NO_BASE_URI:
      text_len = snprintf(text_out, text_out_size, "Missing base-uri directive (recommended: base-uri 'none' or 'self')");
      break;
    case HEADER_CHECK_ISSUE_CSP_REPEATED_DIRECTIVE:
      text_len = snprintf(text_out, text_out_size, "'%s' appears more than once in a policy; the browser ignores every later copy", issue->ma_detail);
      break;
    case HEADER_CHECK_ISSUE_HSTS_NO_MAX_AGE:
      text_len = snprintf(text_out, text_out_size, "Missing max-age directive");
      break;
    case HEADER_CHECK_ISSUE_HSTS_MALFORMED_MAX_AGE:
      text_len = snprintf(text_out, text_out_size, "Malformed max-age directive");
      break;
    case HEADER_CHECK_ISSUE_HSTS_SHORT_MAX_AGE:
      text_len = snprintf(text_out, text_out_size, "max-age=%s is below recommended minimum of %u (%u days)", issue->ma_detail, HEADER_CHECK_HSTS_MIN_MAX_AGE_SECONDS, HEADER_CHECK_HSTS_MIN_MAX_AGE_SECONDS / (24u * 60u * 60u));
      break;
    case HEADER_CHECK_ISSUE_HSTS_NO_INCLUDE_SUBDOMAINS:
      text_len = snprintf(text_out, text_out_size, "Missing includeSubDomains directive");
      break;
    case HEADER_CHECK_ISSUE_HSTS_MULTIPLE_HEADERS:
      text_len = snprintf(text_out, text_out_size, "More than one Strict-Transport-Security header; only the first is used");
      break;
    case HEADER_CHECK_ISSUE_XCTO_INVALID:
      text_len = snprintf(text_out, text_out_size, "Invalid value. Allowed: nosniff (case-insensitive)");
      break;
    case HEADER_CHECK_ISSUE_XFO_INVALID:
      text_len = snprintf(text_out, text_out_size, "Invalid value. Allowed: DENY, SAMEORIGIN (case-insensitive)");
      break;
    case HEADER_CHECK_ISSUE_REFERRER_NO_KNOWN_POLICY:
      text_len = snprintf(text_out, text_out_size, "No valid referrer policy token");
      break;
    case HEADER_CHECK_ISSUE_REFERRER_UNSAFE_URL:
      text_len = snprintf(text_out, text_out_size, "Policy unsafe-url sends the full URL, path and query included, to every origin");
      break;
    case HEADER_CHECK_ISSUE_REFERRER_NO_REFERRER_WHEN_DOWNGRADE:
      text_len = snprintf(text_out, text_out_size, "Policy no-referrer-when-downgrade sends the full URL to every HTTPS origin");
      break;
    case HEADER_CHECK_ISSUE_REFERRER_ORIGIN:
      text_len = snprintf(text_out, text_out_size, "Policy origin sends the origin to plain http pages too; strict-origin does not");
      break;
    case HEADER_CHECK_ISSUE_REFERRER_ORIGIN_WHEN_CROSS_ORIGIN:
      text_len = snprintf(text_out, text_out_size, "Policy origin-when-cross-origin sends the origin to plain http pages too; strict-origin-when-cross-origin does not");
      break;
    case HEADER_CHECK_ISSUE_PERMISSIONS_MALFORMED:
      text_len = snprintf(text_out, text_out_size, "The value does not parse as a structured field dictionary (RFC 8941), so browsers ignore the whole header");
      break;
    case HEADER_CHECK_ISSUE_PERMISSIONS_WILDCARD:
      text_len = snprintf(text_out, text_out_size, "A feature allows every origin with *");
      break;
    case HEADER_CHECK_ISSUE_XXP_FILTER_ENABLED:
      text_len = snprintf(text_out, text_out_size, "A value other than 0 turns on the legacy XSS filter, which can create XSS vulnerabilities");
      break;
    case HEADER_CHECK_ISSUE_COOKIE_NO_SECURE:
      text_len = snprintf(text_out, text_out_size, "Cookies with no Secure attribute: %s", issue->ma_detail);
      break;
    case HEADER_CHECK_ISSUE_COOKIE_INVALID_SAMESITE:
      text_len = snprintf(text_out, text_out_size, "Cookies with a SameSite value other than Strict, Lax or None: %s", issue->ma_detail);
      break;
    case HEADER_CHECK_ISSUE_COOKIE_SAMESITE_NONE_WITHOUT_SECURE:
      text_len = snprintf(text_out, text_out_size, "Cookies with SameSite=None and no Secure attribute: %s", issue->ma_detail);
      break;
    case HEADER_CHECK_ISSUE_COOKIE_BROKEN_PREFIX:
      text_len = snprintf(text_out, text_out_size, "Cookies that break the rules of their __Secure- or __Host- prefix: %s", issue->ma_detail);
      break;
    case HEADER_CHECK_ISSUE_COOKIE_SESSION_WITHOUT_HTTPONLY:
      text_len = snprintf(text_out, text_out_size, "Session or login cookies with no HttpOnly attribute: %s", issue->ma_detail);
      break;
    case HEADER_CHECK_ISSUE_COOKIE_CSRF_WITHOUT_SAMESITE:
      text_len = snprintf(text_out, text_out_size, "CSRF cookies with no SameSite attribute: %s", issue->ma_detail);
      break;
    case HEADER_CHECK_ISSUE_COOKIE_NOT_ALL_CHECKED:
      text_len = snprintf(text_out, text_out_size, "Cookies not checked: %s", issue->ma_detail);
      break;
    case HEADER_CHECK_ISSUE_CORS_NULL_ORIGIN:
      text_len = snprintf(text_out, text_out_size, "Allowing the origin null lets any sandboxed frame read the answer");
      break;
    case HEADER_CHECK_ISSUE_CORS_WILDCARD_WITH_CREDENTIALS:
      text_len = snprintf(text_out, text_out_size, "Allowing credentials with the origin * is an error; browsers refuse * for a request with credentials");
      break;
    case HEADER_CHECK_ISSUE_CORS_MULTIPLE_ORIGINS:
      text_len = snprintf(text_out, text_out_size, "More than one origin; browsers accept only one, so every cross-origin read fails");
      break;
    case HEADER_CHECK_ISSUE_KIND_COUNT:
      break;
  }

  if (text_len < 0 || (size_t)text_len >= text_out_size)
  {
    text_out[0] = '\0';
    return 0;
  }
  return (size_t)text_len;
}

size_t header_check_shownLength(const char* text, size_t* code_point_count_out)
{
  assert(text                 != NULL);
  assert(code_point_count_out != NULL);

  const unsigned char* bytes = (const unsigned char*)text;
  size_t text_len         = strlen(text);
  size_t pos              = 0;
  size_t code_point_count = 0;
  size_t shown_len        = 0;
  while (pos < text_len)
  {
    pos += utf8_readFirstSequence(bytes + pos, text_len - pos).m_length;
    code_point_count++;
    if (code_point_count <= HEADER_CHECK_SHOWN_VALUE_MAX_CODE_POINTS)
      shown_len = pos;
  }

  *code_point_count_out = code_point_count;
  return shown_len;
}

static void static_setHeaderValue(HeaderCheckFinding_t* finding, const char* header_value)
{
  assert(finding != NULL);

  finding->mp_value = header_value;
  if (header_value == NULL)
    return;

  size_t code_point_count = 0;
  size_t shown_len = header_check_shownLength(header_value, &code_point_count);

  finding->m_valueLen            = strlen(header_value);
  finding->m_valueCodePointCount = code_point_count;
  finding->m_shownValueLen       = shown_len;
  finding->m_isValueCut          = code_point_count > HEADER_CHECK_SHOWN_VALUE_MAX_CODE_POINTS;
}

static void static_addIssue(HeaderCheckFinding_t* finding, HeaderCheckIssueKind_t kind)
{
  assert(finding != NULL);
  assert(finding->m_issueCount < HEADER_CHECK_MAX_ISSUE_COUNT);

  finding->ma_issues[finding->m_issueCount].m_kind = kind;
  finding->m_issueCount++;
}

static void static_addIssueWithDetail(HeaderCheckFinding_t* finding, HeaderCheckIssueKind_t kind, const char* detail)
{
  assert(detail != NULL);
  assert(strlen(detail) < HEADER_CHECK_ISSUE_DETAIL_SIZE);

  static_addIssue(finding, kind);
  HeaderCheckIssue_t* issue = &finding->ma_issues[finding->m_issueCount - 1];
  snprintf(issue->ma_detail, sizeof(issue->ma_detail), "%s", detail);
}

static void static_addDirectiveIssue(HeaderCheckFinding_t* finding, HeaderCheckIssueKind_t kind, const HeaderCheckCspDirective_t* directive)
{
  assert(finding != NULL);
  assert(directive != NULL);

  for (int i = 0; i < finding->m_issueCount; i++)
  {
    if (finding->ma_issues[i].m_kind == kind && strncmp(finding->ma_issues[i].ma_detail, directive->mp_name, HEADER_CHECK_ISSUE_DETAIL_SIZE - 1) == 0)
      return;
  }

  static_addIssueWithDetail(finding, kind, directive->mp_name);
}

static void static_setResult(HeaderCheckFinding_t* finding, bool is_valid)
{
  assert(finding != NULL);

  if (!is_valid)
    finding->m_result = HEADER_CHECK_RESULT_FAIL;
  else if (finding->m_issueCount > 0)
    finding->m_result = HEADER_CHECK_RESULT_WARN;
  else
    finding->m_result = HEADER_CHECK_RESULT_PASS;
}

static HeaderCheckCspNames_t static_checkCsp(const char* csp_value, const char* report_only_value, HeaderCheckFinding_t* finding)
{
  assert(finding != NULL);

  HeaderCheckCspNames_t names = { 0 };
  if (csp_value == NULL)
  {
    if (report_only_value != NULL)
    {
      static_setHeaderValue(finding, report_only_value);
      static_addIssue(finding, HEADER_CHECK_ISSUE_CSP_REPORT_ONLY);
      finding->m_result = HEADER_CHECK_RESULT_WARN;
    }
    return names;
  }

  HeaderCheckSpan_t value = static_spanOf(csp_value);
  names = static_readCspNames(value);
  bool has_script_directive = names.m_hasDefaultSrc || names.m_hasScriptSrc;
  if (!has_script_directive)
    static_addIssue(finding, HEADER_CHECK_ISSUE_CSP_NO_SCRIPT_DIRECTIVE);
  static_addCspSourceIssues(value, finding);
  if (!names.m_hasObjectSrc && !names.m_isDefaultSrcNone)
    static_addIssue(finding, HEADER_CHECK_ISSUE_CSP_NO_OBJECT_SRC);
  if (!names.m_hasBaseUri)
    static_addIssue(finding, HEADER_CHECK_ISSUE_CSP_NO_BASE_URI);

  static_addCspRepeatIssues(value, finding);

  static_setResult(finding, has_script_directive);
  return names;
}

static HeaderCheckCspNames_t static_readCspNames(HeaderCheckSpan_t value)
{
  HeaderCheckCspNames_t names   = { 0 };
  HeaderCheckSpan_t policy      = { 0 };
  HeaderCheckSpan_t name        = { 0 };
  HeaderCheckSpan_t source_list = { 0 };
  while (static_tryReadNextItem(&value, ',', &policy))
  {
    while (static_tryReadNextDirective(&policy, &name, &source_list))
    {
      if (static_isEqualIgnoringCase(name, "default-src"))
      {
        names.m_hasDefaultSrc = true;
        if (static_isNoneSourceList(source_list))
          names.m_isDefaultSrcNone = true;
      }
      else if (static_isEqualIgnoringCase(name, "script-src"))
        names.m_hasScriptSrc = true;
      else if (static_isEqualIgnoringCase(name, "object-src"))
        names.m_hasObjectSrc = true;
      else if (static_isEqualIgnoringCase(name, "base-uri"))
        names.m_hasBaseUri = true;
      else if (static_isEqualIgnoringCase(name, "frame-ancestors"))
        names.m_hasFrameAncestors = true;
    }
  }
  return names;
}

static void static_addCspSourceIssues(HeaderCheckSpan_t value, HeaderCheckFinding_t* finding)
{
  assert(finding != NULL);

  HeaderCheckSpan_t policy      = { 0 };
  HeaderCheckSpan_t name        = { 0 };
  HeaderCheckSpan_t source_list = { 0 };
  while (static_tryReadNextItem(&value, ',', &policy))
  {
    bool has_script_src = static_hasScriptSrc(policy);
    while (static_tryReadNextDirective(&policy, &name, &source_list))
    {
      const HeaderCheckCspDirective_t* fetch_directive = static_findFetchDirective(name);
      if (fetch_directive == NULL)
        continue;

      HeaderCheckCspSources_t sources = static_readCspSources(source_list);
      bool is_inline_ignored             = sources.m_hasNonceOrHash || (fetch_directive->m_isScriptDirective && sources.m_hasStrictDynamic);
      bool is_effective_script_directive = fetch_directive == CSP_SCRIPT_SRC || (fetch_directive == CSP_DEFAULT_SRC && !has_script_src);
      if (sources.m_hasWildcard)
        static_addDirectiveIssue(finding, HEADER_CHECK_ISSUE_CSP_WILDCARD, fetch_directive);
      if (sources.m_hasUnsafeInline && !is_inline_ignored)
        static_addDirectiveIssue(finding, HEADER_CHECK_ISSUE_CSP_UNSAFE_INLINE, fetch_directive);
      if (sources.m_hasUnsafeEval)
        static_addDirectiveIssue(finding, HEADER_CHECK_ISSUE_CSP_UNSAFE_EVAL, fetch_directive);
      if (is_effective_script_directive && sources.m_hasHttpSource)
        static_addDirectiveIssue(finding, HEADER_CHECK_ISSUE_CSP_HTTP_SCRIPT_SOURCE, fetch_directive);
      if (is_effective_script_directive && sources.m_hasDataSource)
        static_addDirectiveIssue(finding, HEADER_CHECK_ISSUE_CSP_DATA_SCRIPT_SOURCE, fetch_directive);
      if ((is_effective_script_directive || fetch_directive == CSP_OBJECT_SRC) && sources.m_hasBroadSource)
        static_addDirectiveIssue(finding, HEADER_CHECK_ISSUE_CSP_BROAD_SOURCE, fetch_directive);
    }
  }
}

static bool static_hasScriptSrc(HeaderCheckSpan_t policy)
{
  HeaderCheckSpan_t name        = { 0 };
  HeaderCheckSpan_t source_list = { 0 };
  while (static_tryReadNextDirective(&policy, &name, &source_list))
  {
    if (static_isEqualIgnoringCase(name, "script-src"))
      return true;
  }
  return false;
}

static bool static_tryReadNextDirective(HeaderCheckSpan_t* policy, HeaderCheckSpan_t* name_out, HeaderCheckSpan_t* source_list_out)
{
  assert(policy != NULL);
  assert(name_out != NULL);
  assert(source_list_out != NULL);

  HeaderCheckSpan_t directive = { 0 };
  while (static_tryReadNextItem(policy, ';', &directive))
  {
    if (static_tryReadNextWord(&directive, name_out))
    {
      *source_list_out = directive;
      return true;
    }
  }
  return false;
}

static HeaderCheckCspSources_t static_readCspSources(HeaderCheckSpan_t sources)
{
  HeaderCheckCspSources_t found = { 0 };
  HeaderCheckSpan_t source = { 0 };
  while (static_tryReadNextWord(&sources, &source))
  {
    if (static_isEqualIgnoringCase(source, "*"))
      found.m_hasWildcard = true;
    else if (static_isEqualIgnoringCase(source, "'unsafe-inline'"))
      found.m_hasUnsafeInline = true;
    else if (static_isEqualIgnoringCase(source, "'unsafe-eval'"))
      found.m_hasUnsafeEval = true;
    else if (static_isEqualIgnoringCase(source, "'strict-dynamic'"))
      found.m_hasStrictDynamic = true;
    else if (static_isEqualIgnoringCase(source, "http:") || static_hasPrefixIgnoringCase(source, "http://"))
      found.m_hasHttpSource = true;
    else if (static_isEqualIgnoringCase(source, "data:"))
      found.m_hasDataSource = true;
    else if (static_isBroadSource(source))
      found.m_hasBroadSource = true;
    else if (static_isNonceOrHashSource(source))
      found.m_hasNonceOrHash = true;
  }
  return found;
}

static bool static_isNonceOrHashSource(HeaderCheckSpan_t source)
{
  for (size_t i = 0; i < sizeof(CSP_NONCE_AND_HASH_PREFIXES) / sizeof(CSP_NONCE_AND_HASH_PREFIXES[0]); i++)
  {
    size_t prefix_len = strlen(CSP_NONCE_AND_HASH_PREFIXES[i]);
    if (static_hasPrefixIgnoringCase(source, CSP_NONCE_AND_HASH_PREFIXES[i]))
      return source.m_len > prefix_len + 1 && source.mp_text[source.m_len - 1] == '\'';
  }
  return false;
}

static bool static_isNoneSourceList(HeaderCheckSpan_t sources)
{
  HeaderCheckSpan_t source = { 0 };
  if (!static_tryReadNextWord(&sources, &source))
    return true;
  return static_isEqualIgnoringCase(source, "'none'") && !static_tryReadNextWord(&sources, &source);
}

static bool static_isBroadSource(HeaderCheckSpan_t source)
{
  for (size_t i = 0; i < sizeof(CSP_BROAD_SOURCES) / sizeof(CSP_BROAD_SOURCES[0]); i++)
  {
    if (static_isEqualIgnoringCase(source, CSP_BROAD_SOURCES[i]))
      return true;
  }
  return false;
}

static const HeaderCheckCspDirective_t* static_findFetchDirective(HeaderCheckSpan_t name)
{
  for (int i = 0; i < HEADER_CHECK_CSP_FETCH_DIRECTIVE_COUNT; i++)
  {
    if (static_isEqualIgnoringCase(name, CSP_FETCH_DIRECTIVES[i].mp_name))
      return &CSP_FETCH_DIRECTIVES[i];
  }
  return NULL;
}

static void static_addCspRepeatIssues(HeaderCheckSpan_t value, HeaderCheckFinding_t* finding)
{
  assert(finding != NULL);

  HeaderCheckSpan_t policy      = { 0 };
  HeaderCheckSpan_t name        = { 0 };
  HeaderCheckSpan_t source_list = { 0 };
  while (static_tryReadNextItem(&value, ',', &policy))
  {
    uint32_t seen_directives = 0;
    while (static_tryReadNextDirective(&policy, &name, &source_list))
    {
      int index = 0;
      const HeaderCheckCspDirective_t* directive = static_findRepeatDirective(name, &index);
      if (directive == NULL)
        continue;

      uint32_t directive_bit = (uint32_t)1 << index;
      if ((seen_directives & directive_bit) != 0)
        static_addDirectiveIssue(finding, HEADER_CHECK_ISSUE_CSP_REPEATED_DIRECTIVE, directive);
      seen_directives |= directive_bit;
    }
  }
}

static const HeaderCheckCspDirective_t* static_findRepeatDirective(HeaderCheckSpan_t name, int* index_out)
{
  assert(index_out != NULL);

  const HeaderCheckCspDirective_t* fetch_directive = static_findFetchDirective(name);
  if (fetch_directive != NULL)
  {
    *index_out = (int)(fetch_directive - CSP_FETCH_DIRECTIVES);
    return fetch_directive;
  }

  for (int i = 0; i < HEADER_CHECK_CSP_NON_FETCH_REPEAT_DIRECTIVE_COUNT; i++)
  {
    if (static_isEqualIgnoringCase(name, CSP_NON_FETCH_REPEAT_DIRECTIVES[i].mp_name))
    {
      *index_out = HEADER_CHECK_CSP_FETCH_DIRECTIVE_COUNT + i;
      return &CSP_NON_FETCH_REPEAT_DIRECTIVES[i];
    }
  }
  return NULL;
}

static void static_checkHsts(const char* value, HeaderCheckFinding_t* finding)
{
  assert(finding != NULL);

  if (value == NULL)
    return;

  bool              has_more_copies = false;
  HeaderCheckSpan_t first_copy      = static_firstCopy(value, &has_more_copies);

  bool              has_max_age            = false;
  HeaderCheckSpan_t max_age_token          = { 0 };
  bool              has_include_subdomains = false;
  HeaderCheckSpan_t token                  = { 0 };
  while (static_tryReadNextItem(&first_copy, ';', &token))
  {
    token = static_trim(token);
    if (!has_max_age && static_hasPrefixIgnoringCase(token, HEADER_CHECK_HSTS_MAX_AGE_NAME))
    {
      has_max_age   = true;
      max_age_token = token;
    }
    else if (static_isEqualIgnoringCase(token, "includesubdomains"))
      has_include_subdomains = true;
  }

  bool     is_valid = true;
  uint32_t max_age  = 0;
  if (!has_max_age)
  {
    static_addIssue(finding, HEADER_CHECK_ISSUE_HSTS_NO_MAX_AGE);
    is_valid = false;
  }
  else if (!static_tryReadMaxAge(max_age_token, &max_age))
  {
    static_addIssue(finding, HEADER_CHECK_ISSUE_HSTS_MALFORMED_MAX_AGE);
    is_valid = false;
  }
  else if (max_age < HEADER_CHECK_HSTS_MIN_MAX_AGE_SECONDS)
  {
    char max_age_text[HEADER_CHECK_ISSUE_DETAIL_SIZE];
    snprintf(max_age_text, sizeof(max_age_text), "%" PRIu32, max_age);
    static_addIssueWithDetail(finding, HEADER_CHECK_ISSUE_HSTS_SHORT_MAX_AGE, max_age_text);
    is_valid = false;
  }

  if (!has_include_subdomains)
  {
    static_addIssue(finding, HEADER_CHECK_ISSUE_HSTS_NO_INCLUDE_SUBDOMAINS);
    is_valid = false;
  }
  if (has_more_copies)
    static_addIssue(finding, HEADER_CHECK_ISSUE_HSTS_MULTIPLE_HEADERS);

  static_setResult(finding, is_valid);
}

static bool static_tryReadMaxAge(HeaderCheckSpan_t token, uint32_t* max_age_out)
{
  assert(max_age_out != NULL);
  assert(token.m_len >= HEADER_CHECK_HSTS_MAX_AGE_NAME_LEN);

  size_t pos = HEADER_CHECK_HSTS_MAX_AGE_NAME_LEN;
  while (pos < token.m_len && static_isWhitespace(token.mp_text[pos]))
    pos++;
  if (pos == token.m_len || token.mp_text[pos] != '=')
    return false;
  pos++;
  while (pos < token.m_len && static_isWhitespace(token.mp_text[pos]))
    pos++;

  bool is_quoted = pos < token.m_len && token.mp_text[pos] == '"';
  if (is_quoted)
    pos++;

  size_t   digit_start = pos;
  uint32_t max_age     = 0;
  while (pos < token.m_len && token.mp_text[pos] >= '0' && token.mp_text[pos] <= '9')
  {
    if (max_age < HEADER_CHECK_HSTS_MIN_MAX_AGE_SECONDS)
      max_age = max_age * 10 + (uint32_t)(token.mp_text[pos] - '0');
    pos++;
  }
  if (pos == digit_start)
    return false;

  if (is_quoted)
  {
    if (pos == token.m_len || token.mp_text[pos] != '"')
      return false;
    pos++;
  }
  if (pos != token.m_len)
    return false;

  *max_age_out = max_age;
  return true;
}

static void static_checkXcto(const char* value, HeaderCheckFinding_t* finding)
{
  assert(finding != NULL);

  if (value == NULL)
    return;

  bool is_valid = static_isEqualIgnoringCase(static_trim(static_firstCopy(value, NULL)), "nosniff");
  if (!is_valid)
    static_addIssue(finding, HEADER_CHECK_ISSUE_XCTO_INVALID);
  static_setResult(finding, is_valid);
}

static void static_checkXfo(const char* value, bool has_frame_ancestors, HeaderCheckFinding_t* finding)
{
  assert(finding != NULL);

  if (has_frame_ancestors)
  {
    finding->m_result = HEADER_CHECK_RESULT_PASS;
    return;
  }
  if (value == NULL)
    return;

  HeaderCheckSpan_t rest           = static_spanOf(value);
  HeaderCheckSpan_t item           = { 0 };
  const char*       required_value = NULL;
  bool              is_valid       = true;
  while (is_valid && static_tryReadNextItem(&rest, ',', &item))
  {
    item = static_trim(item);
    if (required_value == NULL)
      required_value = static_isEqualIgnoringCase(item, "deny") ? "deny" : "sameorigin";
    is_valid = static_isEqualIgnoringCase(item, required_value);
  }
  if (!is_valid)
    static_addIssue(finding, HEADER_CHECK_ISSUE_XFO_INVALID);
  static_setResult(finding, is_valid);
}

static void static_checkReferrerPolicy(const char* value, HeaderCheckFinding_t* finding)
{
  assert(finding != NULL);

  if (value == NULL)
    return;

  const char*       policy = NULL;
  HeaderCheckSpan_t rest   = static_spanOf(value);
  HeaderCheckSpan_t item   = { 0 };
  while (static_tryReadNextItem(&rest, ',', &item))
  {
    item = static_trim(item);
    for (size_t i = 0; i < sizeof(REFERRER_POLICY_TOKENS) / sizeof(REFERRER_POLICY_TOKENS[0]); i++)
    {
      if (static_isEqualIgnoringCase(item, REFERRER_POLICY_TOKENS[i]))
        policy = REFERRER_POLICY_TOKENS[i];
    }
  }

  bool is_valid = true;
  if (policy == NULL)
  {
    static_addIssue(finding, HEADER_CHECK_ISSUE_REFERRER_NO_KNOWN_POLICY);
    is_valid = false;
  }
  else if (strcmp(policy, "unsafe-url") == 0)
  {
    static_addIssue(finding, HEADER_CHECK_ISSUE_REFERRER_UNSAFE_URL);
    is_valid = false;
  }
  else if (strcmp(policy, "no-referrer-when-downgrade") == 0)
  {
    static_addIssue(finding, HEADER_CHECK_ISSUE_REFERRER_NO_REFERRER_WHEN_DOWNGRADE);
    is_valid = false;
  }
  else if (strcmp(policy, "origin") == 0)
    static_addIssue(finding, HEADER_CHECK_ISSUE_REFERRER_ORIGIN);
  else if (strcmp(policy, "origin-when-cross-origin") == 0)
    static_addIssue(finding, HEADER_CHECK_ISSUE_REFERRER_ORIGIN_WHEN_CROSS_ORIGIN);

  static_setResult(finding, is_valid);
}

static void static_checkPermissionsPolicy(const char* value, HeaderCheckFinding_t* finding)
{
  assert(finding != NULL);

  if (value == NULL)
    return;

  bool has_wildcard = false;
  bool is_valid     = static_tryReadStructuredFieldDictionary(static_spanOf(value), &has_wildcard);
  if (!is_valid)
    static_addIssue(finding, HEADER_CHECK_ISSUE_PERMISSIONS_MALFORMED);
  else if (has_wildcard)
    static_addIssue(finding, HEADER_CHECK_ISSUE_PERMISSIONS_WILDCARD);
  
  static_setResult(finding, is_valid);
}

static bool static_tryReadStructuredFieldDictionary(HeaderCheckSpan_t value, bool* has_wildcard_out)
{
  assert(has_wildcard_out != NULL);

  *has_wildcard_out = false;
  static_skipSpaces(&value);
  while (value.m_len > 0)
  {
    if (!static_tryReadStructuredFieldKey(&value))
      return false;

    bool is_wildcard = false;
    if (!static_tryReadByte(&value, '='))
    {
      if (!static_tryReadStructuredFieldParameters(&value))
        return false;
    }
    else if (static_isNextByte(value, '('))
    {
      if (!static_tryReadStructuredFieldInnerList(&value, &is_wildcard))
        return false;
    }
    else if (!static_tryReadStructuredFieldItem(&value, &is_wildcard))
      return false;

    if (is_wildcard)
      *has_wildcard_out = true;

    static_skipWhitespace(&value);
    if (value.m_len == 0)
      return true;
    if (!static_tryReadByte(&value, ','))
      return false;
    static_skipWhitespace(&value);
    if (value.m_len == 0)
      return false;
  }

  return true;
}

static bool static_tryReadStructuredFieldInnerList(HeaderCheckSpan_t* rest, bool* has_wildcard_out)
{
  assert(rest != NULL);
  assert(has_wildcard_out != NULL);
  assert(static_isNextByte(*rest, '('));

  static_skipBytes(rest, 1);
  while (rest->m_len > 0)
  {
    static_skipSpaces(rest);
    if (static_tryReadByte(rest, ')'))
      return static_tryReadStructuredFieldParameters(rest);

    bool is_wildcard = false;
    if (!static_tryReadStructuredFieldItem(rest, &is_wildcard))
      return false;
    if (is_wildcard)
      *has_wildcard_out = true;
    if (!static_isNextByte(*rest, ' ') && !static_isNextByte(*rest, ')'))
      return false;
  }
  return false;
}

static bool static_tryReadStructuredFieldItem(HeaderCheckSpan_t* rest, bool* is_wildcard_out)
{
  assert(rest != NULL);
  assert(is_wildcard_out != NULL);

  HeaderCheckSpan_t bare_item = { 0 };
  if (!static_tryReadStructuredFieldBareItem(rest, &bare_item))
    return false;
  *is_wildcard_out = bare_item.m_len == 1 && bare_item.mp_text[0] == '*';
  return static_tryReadStructuredFieldParameters(rest);
}

static bool static_tryReadStructuredFieldParameters(HeaderCheckSpan_t* rest)
{
  assert(rest != NULL);

  while (static_tryReadByte(rest, ';'))
  {
    static_skipSpaces(rest);
    if (!static_tryReadStructuredFieldKey(rest))
      return false;

    HeaderCheckSpan_t bare_item = { 0 };
    if (static_tryReadByte(rest, '=') && !static_tryReadStructuredFieldBareItem(rest, &bare_item))
      return false;
  }
  return true;
}

static bool static_tryReadStructuredFieldKey(HeaderCheckSpan_t* rest)
{
  assert(rest != NULL);

  if (rest->m_len == 0 || !(islower((unsigned char)rest->mp_text[0]) || rest->mp_text[0] == '*'))
    return false;
  static_skipBytes(rest, 1);
  while (rest->m_len > 0)
  {
    char c = rest->mp_text[0];
    if (!islower((unsigned char)c) && !isdigit((unsigned char)c) && c != '_' && c != '-' && c != '.' && c != '*')
      break;
    static_skipBytes(rest, 1);
  }
  return true;
}

static bool static_tryReadStructuredFieldBareItem(HeaderCheckSpan_t* rest, HeaderCheckSpan_t* bare_item_out)
{
  assert(rest != NULL);
  assert(bare_item_out != NULL);

  if (rest->m_len == 0)
    return false;

  const char* start   = rest->mp_text;
  char        first   = rest->mp_text[0];
  bool        is_read = false;
  if (first == '-' || isdigit((unsigned char)first))
    is_read = static_tryReadStructuredFieldNumber(rest);
  else if (first == '"')
    is_read = static_tryReadStructuredFieldString(rest);
  else if (first == '*' || isalpha((unsigned char)first))
  {
    static_skipBytes(rest, 1);
    while (rest->m_len > 0 && static_isStructuredFieldTokenByte(rest->mp_text[0]))
      static_skipBytes(rest, 1);
    is_read = true;
  }
  else if (first == ':')
    is_read = static_tryReadStructuredFieldByteSequence(rest);
  else if (first == '?')
  {
    static_skipBytes(rest, 1);
    is_read = static_tryReadByte(rest, '0') || static_tryReadByte(rest, '1');
  }

  *bare_item_out = (HeaderCheckSpan_t){ start, (size_t)(rest->mp_text - start) };
  return is_read;
}

static bool static_tryReadStructuredFieldNumber(HeaderCheckSpan_t* rest)
{
  assert(rest != NULL);

  static_tryReadByte(rest, '-');
  if (rest->m_len == 0 || !isdigit((unsigned char)rest->mp_text[0]))
    return false;

  size_t integer_digit_count  = 0;
  size_t fraction_digit_count = 0;
  bool   is_decimal           = false;
  while (rest->m_len > 0)
  {
    char c = rest->mp_text[0];
    if (!is_decimal && c == '.')
    {
      if (integer_digit_count > HEADER_CHECK_STRUCTURED_FIELD_DECIMAL_MAX_INTEGER_DIGITS)
        return false;
      is_decimal = true;
    }
    else if (!isdigit((unsigned char)c))
      break;
    else if (is_decimal)
      fraction_digit_count++;
    else if (++integer_digit_count > HEADER_CHECK_STRUCTURED_FIELD_INTEGER_MAX_DIGITS)
      return false;
    static_skipBytes(rest, 1);
  }
  return !is_decimal || (fraction_digit_count > 0 && fraction_digit_count <= HEADER_CHECK_STRUCTURED_FIELD_DECIMAL_MAX_FRACTION_DIGITS);
}

static bool static_tryReadStructuredFieldString(HeaderCheckSpan_t* rest)
{
  assert(rest != NULL);
  assert(static_isNextByte(*rest, '"'));

  static_skipBytes(rest, 1);
  while (rest->m_len > 0)
  {
    unsigned char c = (unsigned char)rest->mp_text[0];
    static_skipBytes(rest, 1);
    if (c == '"')
      return true;
    if (c == '\\')
    {
      if (!static_tryReadByte(rest, '"') && !static_tryReadByte(rest, '\\'))
        return false;
    }
    else if (c < ' ' || c > '~')
      return false;
  }
  return false;
}

static bool static_tryReadStructuredFieldByteSequence(HeaderCheckSpan_t* rest)
{
  assert(rest != NULL);
  assert(static_isNextByte(*rest, ':'));

  static_skipBytes(rest, 1);
  const char* end = memchr(rest->mp_text, ':', rest->m_len);
  if (end == NULL)
    return false;

  size_t content_len = (size_t)(end - rest->mp_text);
  for (size_t i = 0; i < content_len; i++)
  {
    char c = rest->mp_text[i];
    if (!isalnum((unsigned char)c) && c != '+' && c != '/' && c != '=')
      return false;
  }
  static_skipBytes(rest, content_len + 1);
  return true;
}

static bool static_isStructuredFieldTokenByte(char c)
{
  return isalnum((unsigned char)c) || memchr(STRUCTURED_FIELD_TOKEN_PUNCTUATION, c, sizeof(STRUCTURED_FIELD_TOKEN_PUNCTUATION) - 1) != NULL;
}

static void static_checkXxp(const char* value, HeaderCheckFinding_t* finding)
{
  assert(finding != NULL);

  finding->m_result = HEADER_CHECK_RESULT_PASS;
  if (value == NULL)
    return;

  HeaderCheckSpan_t rest          = static_spanOf(value);
  HeaderCheckSpan_t item          = { 0 };
  bool              is_filter_off = true;
  while (is_filter_off && static_tryReadNextItem(&rest, ',', &item))
    is_filter_off = static_isEqualIgnoringCase(static_trim(item), "0");
  if (is_filter_off)
    return;

  static_addIssue(finding, HEADER_CHECK_ISSUE_XXP_FILTER_ENABLED);
  finding->m_result = HEADER_CHECK_RESULT_WARN;
}

static void static_checkSetCookie(const char* value, size_t set_cookie_copy_count, HeaderCheckFinding_t* finding)
{
  assert(finding != NULL);

  finding->m_result = HEADER_CHECK_RESULT_PASS;
  if (value == NULL)
    return;

  HeaderCheckCookieCounts_t counts               = { 0 };
  size_t                    checked_cookie_count = 0;
  HeaderCheckSpan_t         rest                 = static_spanOf(value);
  HeaderCheckSpan_t         cookie_text          = { 0 };
  while (static_tryReadNextItem(&rest, '\n', &cookie_text))
  {
    HeaderCheckCookie_t cookie = static_readCookie(cookie_text);
    static_countCookieIssues(&cookie, &counts);
    checked_cookie_count++;
  }
  finding->m_cookieCount = set_cookie_copy_count > checked_cookie_count ? set_cookie_copy_count : checked_cookie_count;

  static_addCookieCountIssue(finding, HEADER_CHECK_ISSUE_COOKIE_NO_SECURE,                    counts.m_noSecureCount);
  static_addCookieCountIssue(finding, HEADER_CHECK_ISSUE_COOKIE_INVALID_SAMESITE,             counts.m_invalidSameSiteCount);
  static_addCookieCountIssue(finding, HEADER_CHECK_ISSUE_COOKIE_SAMESITE_NONE_WITHOUT_SECURE, counts.m_sameSiteNoneWithoutSecureCount);
  static_addCookieCountIssue(finding, HEADER_CHECK_ISSUE_COOKIE_BROKEN_PREFIX,                counts.m_brokenPrefixCount);
  static_addCookieCountIssue(finding, HEADER_CHECK_ISSUE_COOKIE_SESSION_WITHOUT_HTTPONLY,     counts.m_sessionWithoutHttpOnlyCount);
  static_addCookieCountIssue(finding, HEADER_CHECK_ISSUE_COOKIE_CSRF_WITHOUT_SAMESITE,        counts.m_csrfWithoutSameSiteCount);
  static_addCookieCountIssue(finding, HEADER_CHECK_ISSUE_COOKIE_NOT_ALL_CHECKED,              finding->m_cookieCount - checked_cookie_count);

  bool is_valid = counts.m_noSecureCount                  == 0 &&
                  counts.m_invalidSameSiteCount           == 0 &&
                  counts.m_sameSiteNoneWithoutSecureCount == 0 &&
                  counts.m_brokenPrefixCount              == 0;
  static_setResult(finding, is_valid);
}

static HeaderCheckCookie_t static_readCookie(HeaderCheckSpan_t cookie_text)
{
  HeaderCheckCookie_t cookie     = { 0 };
  HeaderCheckSpan_t   attributes = cookie_text;
  HeaderCheckSpan_t   name_value = { 0 };
  static_tryReadNextItem(&attributes, ';', &name_value);
  static_tryReadNextItem(&name_value, '=', &cookie.m_name);
  cookie.m_name = static_trim(cookie.m_name);

  HeaderCheckSpan_t attribute = { 0 };
  while (static_tryReadNextItem(&attributes, ';', &attribute))
  {
    HeaderCheckSpan_t attribute_name = { 0 };
    static_tryReadNextItem(&attribute, '=', &attribute_name);
    attribute_name = static_trim(attribute_name);
    HeaderCheckSpan_t attribute_value = static_trim(attribute);

    if (static_isEqualIgnoringCase(attribute_name, "secure"))
      cookie.m_hasSecure = true;
    else if (static_isEqualIgnoringCase(attribute_name, "httponly"))
      cookie.m_hasHttpOnly = true;
    else if (static_isEqualIgnoringCase(attribute_name, "samesite"))
    {
      cookie.m_hasSameSite   = true;
      cookie.m_sameSiteValue = attribute_value;
    }
    else if (static_isEqualIgnoringCase(attribute_name, "domain") && attribute_value.m_len > 0)
      cookie.m_hasDomain = true;
    else if (static_isEqualIgnoringCase(attribute_name, "path"))
      cookie.m_isPathRoot = static_isEqual(attribute_value, "/");
  }
  return cookie;
}

static void static_countCookieIssues(const HeaderCheckCookie_t* cookie, HeaderCheckCookieCounts_t* counts)
{
  assert(cookie != NULL);
  assert(counts != NULL);

  bool is_same_site_none  = cookie->m_hasSameSite && static_isEqualIgnoringCase(cookie->m_sameSiteValue, "none");
  bool is_same_site_known = static_isEqualIgnoringCase(cookie->m_sameSiteValue, "strict") ||
                            static_isEqualIgnoringCase(cookie->m_sameSiteValue, "lax")    ||
                            is_same_site_none;
  bool is_secure_prefix_broken = static_hasPrefixIgnoringCase(cookie->m_name, "__secure-") && !cookie->m_hasSecure;
  bool is_host_prefix_broken   = static_hasPrefixIgnoringCase(cookie->m_name, "__host-") &&
                                 (!cookie->m_hasSecure || cookie->m_hasDomain || !cookie->m_isPathRoot);
  bool is_session_name = false;
  for (size_t i = 0; i < sizeof(COOKIE_SESSION_NAME_PARTS) / sizeof(COOKIE_SESSION_NAME_PARTS[0]); i++)
    is_session_name = is_session_name || static_containsIgnoringCase(cookie->m_name, COOKIE_SESSION_NAME_PARTS[i]);

  if (!cookie->m_hasSecure)
    counts->m_noSecureCount++;
  if (cookie->m_hasSameSite && !is_same_site_known)
    counts->m_invalidSameSiteCount++;
  if (is_same_site_none && !cookie->m_hasSecure)
    counts->m_sameSiteNoneWithoutSecureCount++;
  if (is_secure_prefix_broken || is_host_prefix_broken)
    counts->m_brokenPrefixCount++;
  if (is_session_name && !cookie->m_hasHttpOnly)
    counts->m_sessionWithoutHttpOnlyCount++;
  if (static_containsIgnoringCase(cookie->m_name, "csrf") && !cookie->m_hasSameSite)
    counts->m_csrfWithoutSameSiteCount++;
}

static void static_addCookieCountIssue(HeaderCheckFinding_t* finding, HeaderCheckIssueKind_t kind, size_t cookie_count)
{
  if (cookie_count == 0)
    return;

  char detail[HEADER_CHECK_ISSUE_DETAIL_SIZE];
  snprintf(detail, sizeof(detail), "%zu", cookie_count < HEADER_CHECK_MAX_DETAIL_NUMBER ? cookie_count : HEADER_CHECK_MAX_DETAIL_NUMBER);
  static_addIssueWithDetail(finding, kind, detail);
}

static void static_checkCors(const char* allow_origin_value, const char* allow_credentials_value, HeaderCheckFinding_t* finding)
{
  assert(finding != NULL);

  finding->m_result = HEADER_CHECK_RESULT_PASS;
  if (allow_origin_value == NULL)
    return;

  HeaderCheckSpan_t origin = static_trim(static_spanOf(allow_origin_value));
  bool has_more_origins = false;
  for (size_t i = 0; i < origin.m_len; i++)
  {
    has_more_origins =  has_more_origins                        || 
                        origin.mp_text[i] == ','                || 
                        static_isWhitespace(origin.mp_text[i]);

  }
  bool is_credentials_allowed = allow_credentials_value != NULL && static_isEqual(static_trim(static_spanOf(allow_credentials_value)), "true");

  if (has_more_origins)
    static_addIssue(finding, HEADER_CHECK_ISSUE_CORS_MULTIPLE_ORIGINS);
  else if (static_isEqual(origin, "null"))
    static_addIssue(finding, HEADER_CHECK_ISSUE_CORS_NULL_ORIGIN);
  else if (static_isEqual(origin, "*") && is_credentials_allowed)
    static_addIssue(finding, HEADER_CHECK_ISSUE_CORS_WILDCARD_WITH_CREDENTIALS);
  static_setResult(finding, true);
}

static HeaderCheckSpan_t static_spanOf(const char* text)
{
  assert(text != NULL);
  return (HeaderCheckSpan_t){ text, strlen(text) };
}

static HeaderCheckSpan_t static_firstCopy(const char* value, bool* has_more_copies_out)
{
  HeaderCheckSpan_t rest       = static_spanOf(value);
  HeaderCheckSpan_t first_copy = { 0 };
  static_tryReadNextItem(&rest, ',', &first_copy);
  if (has_more_copies_out != NULL)
    *has_more_copies_out = rest.mp_text != NULL && static_trim(rest).m_len > 0;
  return first_copy;
}

static bool static_tryReadNextItem(HeaderCheckSpan_t* rest, char separator, HeaderCheckSpan_t* item_out)
{
  assert(rest != NULL);
  assert(item_out != NULL);

  if (rest->mp_text == NULL)
    return false;

  const char* separator_at = memchr(rest->mp_text, separator, rest->m_len);
  if (separator_at == NULL)
  {
    *item_out = *rest;
    *rest     = (HeaderCheckSpan_t){ NULL, 0 };
    return true;
  }

  size_t item_len = (size_t)(separator_at - rest->mp_text);
  *item_out = (HeaderCheckSpan_t){ rest->mp_text, item_len };
  *rest     = (HeaderCheckSpan_t){ separator_at + 1, rest->m_len - item_len - 1 };
  return true;
}

static bool static_tryReadNextWord(HeaderCheckSpan_t* rest, HeaderCheckSpan_t* word_out)
{
  assert(rest != NULL);
  assert(word_out != NULL);

  size_t start = 0;
  while (start < rest->m_len && static_isWhitespace(rest->mp_text[start]))
    start++;
  if (start == rest->m_len)
    return false;

  size_t end = start;
  while (end < rest->m_len && !static_isWhitespace(rest->mp_text[end]))
    end++;

  *word_out = (HeaderCheckSpan_t){ rest->mp_text + start, end - start };
  *rest     = (HeaderCheckSpan_t){ rest->mp_text + end, rest->m_len - end };
  return true;
}

static HeaderCheckSpan_t static_trim(HeaderCheckSpan_t span)
{
  while (span.m_len > 0 && static_isWhitespace(span.mp_text[0]))
  {
    span.mp_text++;
    span.m_len--;
  }
  while (span.m_len > 0 && static_isWhitespace(span.mp_text[span.m_len - 1]))
    span.m_len--;
  return span;
}

static bool static_isWhitespace(char c)
{
  return c == ' ' || c == '\t';
}

static void static_skipBytes(HeaderCheckSpan_t* rest, size_t count)
{
  assert(rest != NULL);
  assert(count <= rest->m_len);

  rest->mp_text += count;
  rest->m_len   -= count;
}

static bool static_isNextByte(HeaderCheckSpan_t rest, char c)
{
  return rest.m_len > 0 && rest.mp_text[0] == c;
}

static bool static_tryReadByte(HeaderCheckSpan_t* rest, char c)
{
  assert(rest != NULL);

  if (!static_isNextByte(*rest, c))
    return false;
  static_skipBytes(rest, 1);
  return true;
}

static void static_skipSpaces(HeaderCheckSpan_t* rest)
{
  assert(rest != NULL);

  while (static_isNextByte(*rest, ' '))
    static_skipBytes(rest, 1);
}

static void static_skipWhitespace(HeaderCheckSpan_t* rest)
{
  assert(rest != NULL);

  while (rest->m_len > 0 && static_isWhitespace(rest->mp_text[0]))
    static_skipBytes(rest, 1);
}

static bool static_isEqual(HeaderCheckSpan_t span, const char* text)
{
  return bytes_isEqual(span.mp_text, span.m_len, text, false);
}

static bool static_isEqualIgnoringCase(HeaderCheckSpan_t span, const char* lower_text)
{
  return bytes_isEqual(span.mp_text, span.m_len, lower_text, true);
}

static bool static_hasPrefixIgnoringCase(HeaderCheckSpan_t span, const char* lower_prefix)
{
  assert(lower_prefix != NULL);
  return bytes_hasPrefix(span.mp_text, span.m_len, lower_prefix, strlen(lower_prefix), true);
}

static bool static_containsIgnoringCase(HeaderCheckSpan_t span, const char* lower_text)
{
  assert(lower_text != NULL);
  size_t text_len = strlen(lower_text);
  assert(text_len > 0);

  for (size_t start = 0; start + text_len <= span.m_len; start++)
  {
    if (strncasecmp(span.mp_text + start, lower_text, text_len) == 0)
      return true;
  }
  return false;
}
