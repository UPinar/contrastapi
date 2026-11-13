#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "datetime.h"
#include "securitytxt.h"
#include "bytes.h"
#include "utf8.h"

#define SECURITYTXT_LANGUAGE_PART_MAX_LEN   8

static const char BYTE_ORDER_MARK[]      = "\xEF\xBB\xBF";
static const char SIGNED_MESSAGE_LINE[]  = "-----BEGIN PGP SIGNED MESSAGE-----";
static const char SIGNATURE_BEGIN_LINE[] = "-----BEGIN PGP SIGNATURE-----";
static const char SIGNATURE_END_LINE[]   = "-----END PGP SIGNATURE-----";
static const char HASH_HEADER_PREFIX[]   = "Hash:";
static const char DASH_ESCAPE[]          = "- ";
static const char KEY_PREFIX[]           = "-----BEGIN";
static const char CSAF_PATH_SUFFIX[]     = "/provider-metadata.json";
static const char SCHEME_SEPARATOR[]     = "://";

static const struct {
  const char*   mp_reportName;
  const char*   mp_lineName;
} FIELDS[SECURITYTXT_FIELD_COUNT] = {
  [SECURITYTXT_FIELD_ACKNOWLEDGMENTS]     = { "acknowledgments",     "Acknowledgments"      },
  [SECURITYTXT_FIELD_CANONICAL]           = { "canonical",           "Canonical"            },
  [SECURITYTXT_FIELD_CONTACT]             = { "contact",             "Contact"              },
  [SECURITYTXT_FIELD_CSAF]                = { "csaf",                "CSAF"                 },
  [SECURITYTXT_FIELD_ENCRYPTION]          = { "encryption",          "Encryption"           },
  [SECURITYTXT_FIELD_EXPIRES]             = { "expires",             "Expires"              },
  [SECURITYTXT_FIELD_HIRING]              = { "hiring",              "Hiring"               },
  [SECURITYTXT_FIELD_POLICY]              = { "policy",              "Policy"               },
  [SECURITYTXT_FIELD_PREFERRED_LANGUAGES] = { "preferred_languages", "Preferred-Languages"  },
};

static const struct {
  const char*             mp_name;
  SecurityTxtSeverity_t   m_severity;
} ISSUES[SECURITYTXT_ISSUE_CODE_COUNT] = {
  [SECURITYTXT_ISSUE_CONTACT_MISSING]               = { "contact_missing",               SECURITYTXT_SEVERITY_ERROR   },
  [SECURITYTXT_ISSUE_EXPIRES_MISSING]               = { "expires_missing",               SECURITYTXT_SEVERITY_ERROR   },
  [SECURITYTXT_ISSUE_EXPIRES_DUPLICATE]             = { "expires_duplicate",             SECURITYTXT_SEVERITY_ERROR   },
  [SECURITYTXT_ISSUE_EXPIRES_INVALID]               = { "expires_invalid",               SECURITYTXT_SEVERITY_ERROR   },
  [SECURITYTXT_ISSUE_EXPIRED]                       = { "expired",                       SECURITYTXT_SEVERITY_ERROR   },
  [SECURITYTXT_ISSUE_EXPIRES_TOO_FAR_AHEAD]         = { "expires_too_far_ahead",         SECURITYTXT_SEVERITY_WARNING },
  [SECURITYTXT_ISSUE_PREFERRED_LANGUAGES_DUPLICATE] = { "preferred_languages_duplicate", SECURITYTXT_SEVERITY_ERROR   },
  [SECURITYTXT_ISSUE_LANGUAGE_TAG_INVALID]          = { "language_tag_invalid",          SECURITYTXT_SEVERITY_WARNING },
  [SECURITYTXT_ISSUE_ENCRYPTION_HOLDS_KEY]          = { "encryption_holds_key",          SECURITYTXT_SEVERITY_ERROR   },
  [SECURITYTXT_ISSUE_URI_INVALID]                   = { "uri_invalid",                   SECURITYTXT_SEVERITY_ERROR   },
  [SECURITYTXT_ISSUE_URI_NOT_HTTPS]                 = { "uri_not_https",                 SECURITYTXT_SEVERITY_ERROR   },
  [SECURITYTXT_ISSUE_CSAF_NOT_PROVIDER_METADATA]    = { "csaf_not_provider_metadata",    SECURITYTXT_SEVERITY_WARNING },
  [SECURITYTXT_ISSUE_CONTENT_TYPE_INVALID]          = { "content_type_invalid",          SECURITYTXT_SEVERITY_ERROR   },
  [SECURITYTXT_ISSUE_CANONICAL_MISMATCH]            = { "canonical_mismatch",            SECURITYTXT_SEVERITY_WARNING },
  [SECURITYTXT_ISSUE_REDIRECTED_TO_OTHER_HOST]      = { "redirected_to_other_host",      SECURITYTXT_SEVERITY_WARNING },
  [SECURITYTXT_ISSUE_SIGNATURE_MALFORMED]           = { "signature_malformed",           SECURITYTXT_SEVERITY_ERROR   },
  [SECURITYTXT_ISSUE_TEXT_AFTER_SIGNATURE]          = { "text_after_signature",          SECURITYTXT_SEVERITY_WARNING },
  [SECURITYTXT_ISSUE_SIGNED_WITHOUT_CANONICAL]      = { "signed_without_canonical",      SECURITYTXT_SEVERITY_INFO    },
  [SECURITYTXT_ISSUE_INVALID_LINE_ENDING]           = { "invalid_line_ending",           SECURITYTXT_SEVERITY_WARNING },
  [SECURITYTXT_ISSUE_INVALID_UTF8]                  = { "invalid_utf8",                  SECURITYTXT_SEVERITY_ERROR   },
  [SECURITYTXT_ISSUE_CONTAINS_NUL_BYTE]             = { "contains_nul_byte",             SECURITYTXT_SEVERITY_ERROR   },
  [SECURITYTXT_ISSUE_BYTE_ORDER_MARK]               = { "byte_order_mark",               SECURITYTXT_SEVERITY_WARNING },
  [SECURITYTXT_ISSUE_LINE_SYNTAX_INVALID]           = { "line_syntax_invalid",           SECURITYTXT_SEVERITY_WARNING },
  [SECURITYTXT_ISSUE_FIELD_EMPTY]                   = { "field_empty",                   SECURITYTXT_SEVERITY_WARNING },
  [SECURITYTXT_ISSUE_LINE_TOO_LONG]                 = { "line_too_long",                 SECURITYTXT_SEVERITY_WARNING },
  [SECURITYTXT_ISSUE_TOO_MANY_LINES]                = { "too_many_lines",                SECURITYTXT_SEVERITY_WARNING },
  [SECURITYTXT_ISSUE_TOO_MANY_VALUES]               = { "too_many_values",               SECURITYTXT_SEVERITY_WARNING },
  [SECURITYTXT_ISSUE_FILE_TOO_LARGE]                = { "file_too_large",                SECURITYTXT_SEVERITY_ERROR   },
};

static const char* const SEVERITY_NAMES[SECURITYTXT_SEVERITY_COUNT] = {
  [SECURITYTXT_SEVERITY_ERROR]   = "error",
  [SECURITYTXT_SEVERITY_WARNING] = "warning",
  [SECURITYTXT_SEVERITY_INFO]    = "info",
};

typedef enum {
  SECURITYTXT_ENVELOPE_START = 0,
  SECURITYTXT_ENVELOPE_UNSIGNED,
  SECURITYTXT_ENVELOPE_HASH_HEADERS,
  SECURITYTXT_ENVELOPE_CONTENT,
  SECURITYTXT_ENVELOPE_SIGNATURE,
  SECURITYTXT_ENVELOPE_AFTER_SIGNATURE
} SecurityTxtEnvelopeState_t;

typedef struct
{
  const char*                mp_body;
  SecurityTxtReport_t*       mp_report;
  int64_t                    m_nowEpoch;
  SecurityTxtEnvelopeState_t m_envelopeState;
  bool                       m_hasHashHeader;
  bool                       m_isSignatureMalformed;
  bool                       m_hasTextAfterSignature;
  bool                       m_hasLoneCr;
} SecurityTxtParser_t;

static void               static_addIssue                     (SecurityTxtReport_t* report, SecurityTxtIssueCode_t issue_code, SecurityTxtField_t field, int line_number);
static void               static_readLines                    (SecurityTxtParser_t* parser, size_t start, size_t body_len);
static void               static_readLine                     (SecurityTxtParser_t* parser, const char* line_start, const char* line_end, int line_number);
static size_t             static_skipLineEnd                  (const char* body, size_t line_end, size_t body_len, bool* is_lone_cr_out);
static void               static_readSignedContentLine        (SecurityTxtParser_t* parser, const char* line_start, const char* line_end, int line_number);
static void               static_finishEnvelope               (SecurityTxtParser_t* parser);
static void               static_raiseSignatureMalformed      (SecurityTxtParser_t* parser);
static void               static_readFieldLine                (SecurityTxtParser_t* parser, const char* line_start, const char* line_end, int line_number);
static SecurityTxtField_t static_findField                    (const char* name_start, const char* name_end);
static void               static_keepValue                    (SecurityTxtParser_t* parser, SecurityTxtField_t field, const char* value_start, const char* value_end, int line_number);
static void               static_checkUriValue                (SecurityTxtParser_t* parser, SecurityTxtField_t field, const char* value_start, const char* value_end, int line_number);
static size_t             static_measureScheme                (const char* value_start, const char* value_end);
static bool               static_isCsafPath                   (const char* value_start, const char* value_end);
static void               static_checkExpiresValue            (SecurityTxtParser_t* parser, const char* value_start, const char* value_end, int line_number);
static void               static_checkPreferredLanguagesValue (SecurityTxtParser_t* parser, const char* value_start, const char* value_end, int line_number);
static bool               static_isLanguageTag                (const char* tag_start, const char* tag_end);
static bool               static_isContentTypeValid           (const char* content_type);
static bool               static_isAnyCanonicalEqual          (const SecurityTxtReport_t* report, const char* body, const char* final_url);
static bool               static_isUrlEqual                   (const char* text, size_t len, const char* url);
static void               static_trim                         (const char** start, const char** end);
static bool               static_isBlankLine                  (const char* start, const char* end);
static bool               static_isTextEqual                  (const char* start, const char* end, const char* text);
static bool               static_hasPrefix                    (const char* start, const char* end, const char* prefix);
static bool               static_isTextEqualIgnoringCase      (const char* start, const char* end, const char* text);

void securitytxt_parse(const char* body, size_t body_len, bool is_body_cut, int64_t now_epoch, SecurityTxtReport_t* report_out)
{
  assert(report_out != NULL);
  assert(body != NULL || body_len == 0);

  memset(report_out, 0, sizeof(*report_out));
  if (is_body_cut)
  {
    static_addIssue(report_out, SECURITYTXT_ISSUE_FILE_TOO_LARGE, SECURITYTXT_FIELD_NONE, 0);
    return;
  }

  size_t start = 0;
  if (bytes_hasPrefix(body, body_len, BYTE_ORDER_MARK, sizeof(BYTE_ORDER_MARK) - 1, false))
  {
    start = sizeof(BYTE_ORDER_MARK) - 1;
    static_addIssue(report_out, SECURITYTXT_ISSUE_BYTE_ORDER_MARK, SECURITYTXT_FIELD_NONE, 0);
  }
  if (start < body_len)
  {
    if (!utf8_isTextValid(body + start, body_len - start))
      static_addIssue(report_out, SECURITYTXT_ISSUE_INVALID_UTF8, SECURITYTXT_FIELD_NONE, 0);
    if (memchr(body + start, '\0', body_len - start) != NULL)
      static_addIssue(report_out, SECURITYTXT_ISSUE_CONTAINS_NUL_BYTE, SECURITYTXT_FIELD_NONE, 0);
  }

  SecurityTxtParser_t parser = { 0 };
  parser.mp_body    = body;
  parser.mp_report  = report_out;
  parser.m_nowEpoch = now_epoch;
  static_readLines(&parser, start, body_len);
  static_finishEnvelope(&parser);

  if (report_out->ma_valueKeptCount[SECURITYTXT_FIELD_CONTACT] == 0)
    static_addIssue(report_out, SECURITYTXT_ISSUE_CONTACT_MISSING, SECURITYTXT_FIELD_CONTACT, 0);
  if (report_out->ma_valueKeptCount[SECURITYTXT_FIELD_EXPIRES] == 0)
    static_addIssue(report_out, SECURITYTXT_ISSUE_EXPIRES_MISSING, SECURITYTXT_FIELD_EXPIRES, 0);
  if (report_out->m_isOpenPgpSigned && report_out->ma_valueKeptCount[SECURITYTXT_FIELD_CANONICAL] == 0)
    static_addIssue(report_out, SECURITYTXT_ISSUE_SIGNED_WITHOUT_CANONICAL, SECURITYTXT_FIELD_CANONICAL, 0);
}

void securitytxt_checkResponse(SecurityTxtReport_t* report, const char* body, const char* content_type, const char* final_url, bool is_redirected_to_other_host)
{
  assert(report != NULL);

  if (!static_isContentTypeValid(content_type))
    static_addIssue(report, SECURITYTXT_ISSUE_CONTENT_TYPE_INVALID, SECURITYTXT_FIELD_NONE, 0);

  bool is_canonical_dropped = report->ma_valueTotalCount[SECURITYTXT_FIELD_CANONICAL] > report->ma_valueKeptCount[SECURITYTXT_FIELD_CANONICAL];
  if (report->ma_valueKeptCount[SECURITYTXT_FIELD_CANONICAL] > 0  &&
      !is_canonical_dropped                                       &&
      !static_isAnyCanonicalEqual(report, body, final_url))
  {
    static_addIssue(report, SECURITYTXT_ISSUE_CANONICAL_MISMATCH, SECURITYTXT_FIELD_CANONICAL, 0);
  }

  if (is_redirected_to_other_host)
    static_addIssue(report, SECURITYTXT_ISSUE_REDIRECTED_TO_OTHER_HOST, SECURITYTXT_FIELD_NONE, 0);
}

const char* securitytxt_fieldName(SecurityTxtField_t field)
{
  if ((unsigned int)field >= (unsigned int)SECURITYTXT_FIELD_COUNT)
    return NULL;

  return FIELDS[field].mp_reportName;
}

const char* securitytxt_issueCodeName(SecurityTxtIssueCode_t issue_code)
{
  if ((unsigned int)issue_code >= (unsigned int)SECURITYTXT_ISSUE_CODE_COUNT)
    return NULL;

  return ISSUES[issue_code].mp_name;
}

SecurityTxtSeverity_t securitytxt_issueSeverity(SecurityTxtIssueCode_t issue_code)
{
  if ((unsigned int)issue_code >= (unsigned int)SECURITYTXT_ISSUE_CODE_COUNT)
    return SECURITYTXT_SEVERITY_COUNT;

  return ISSUES[issue_code].m_severity;
}

const char* securitytxt_severityName(SecurityTxtSeverity_t severity)
{
  if ((unsigned int)severity >= (unsigned int)SECURITYTXT_SEVERITY_COUNT)
    return NULL;

  return SEVERITY_NAMES[severity];
}

static void static_addIssue(SecurityTxtReport_t* report, SecurityTxtIssueCode_t issue_code, SecurityTxtField_t field, int line_number)
{
  report->m_issueTotalCount++;
  report->ma_issueCountBySeverity[ISSUES[issue_code].m_severity]++;

  if (report->m_issueKeptCount < SECURITYTXT_MAX_ISSUE_COUNT)
  {
    SecurityTxtIssue_t* issue = &report->ma_issues[report->m_issueKeptCount];
    issue->m_issueCode  = issue_code;
    issue->m_field      = field;
    issue->m_lineNumber = line_number;
    report->m_issueKeptCount++;
  }
}

static void static_readLines(SecurityTxtParser_t* parser, size_t start, size_t body_len)
{
  const char* body        = parser->mp_body;
  size_t      position    = start;
  int         line_number = 0;
  while (position < body_len)
  {
    if (line_number >= SECURITYTXT_MAX_LINE_COUNT)
    {
      static_addIssue(parser->mp_report, SECURITYTXT_ISSUE_TOO_MANY_LINES, SECURITYTXT_FIELD_NONE, line_number + 1);
      return;
    }
    line_number++;

    size_t line_end = position;
    while (line_end < body_len && body[line_end] != '\n' && body[line_end] != '\r')
      line_end++;

    bool   is_lone_cr = false;
    size_t next       = static_skipLineEnd(body, line_end, body_len, &is_lone_cr);
    if (is_lone_cr && !parser->m_hasLoneCr)
    {
      parser->m_hasLoneCr = true;
      static_addIssue(parser->mp_report, SECURITYTXT_ISSUE_INVALID_LINE_ENDING, SECURITYTXT_FIELD_NONE, line_number);
    }

    static_readLine(parser, body + position, body + line_end, line_number);
    position = next;
  }
}

static size_t static_skipLineEnd(const char* body, size_t line_end, size_t body_len, bool* is_lone_cr_out)
{
  *is_lone_cr_out = false;
  if (line_end == body_len)
    return body_len;
  if (body[line_end] == '\n')
    return line_end + 1;
  if (line_end + 1 < body_len && body[line_end + 1] == '\n')
    return line_end + 2;
  *is_lone_cr_out = true;
  return line_end + 1;
}

static void static_readLine(SecurityTxtParser_t* parser, const char* line_start, const char* line_end, int line_number)
{
  switch (parser->m_envelopeState)
  {
    case SECURITYTXT_ENVELOPE_START:
      if (static_isBlankLine(line_start, line_end))
        return;
      if (static_isTextEqual(line_start, line_end, SIGNED_MESSAGE_LINE))
      {
        parser->m_envelopeState = SECURITYTXT_ENVELOPE_HASH_HEADERS;
        return;
      }
      parser->m_envelopeState = SECURITYTXT_ENVELOPE_UNSIGNED;
      static_readFieldLine(parser, line_start, line_end, line_number);
      return;
    case SECURITYTXT_ENVELOPE_UNSIGNED:
      static_readFieldLine(parser, line_start, line_end, line_number);
      return;
    case SECURITYTXT_ENVELOPE_HASH_HEADERS:
      if (static_isBlankLine(line_start, line_end))
      {
        if (!parser->m_hasHashHeader)
          static_raiseSignatureMalformed(parser);
        parser->m_envelopeState = SECURITYTXT_ENVELOPE_CONTENT;
        return;
      }
      if (static_hasPrefix(line_start, line_end, HASH_HEADER_PREFIX))
      {
        parser->m_hasHashHeader = true;
        return;
      }
      static_raiseSignatureMalformed(parser);
      parser->m_envelopeState = SECURITYTXT_ENVELOPE_CONTENT;
      static_readSignedContentLine(parser, line_start, line_end, line_number);
      return;
    case SECURITYTXT_ENVELOPE_CONTENT:
      static_readSignedContentLine(parser, line_start, line_end, line_number);
      return;
    case SECURITYTXT_ENVELOPE_SIGNATURE:
      if (static_isTextEqual(line_start, line_end, SIGNATURE_END_LINE))
        parser->m_envelopeState = SECURITYTXT_ENVELOPE_AFTER_SIGNATURE;
      return;
    case SECURITYTXT_ENVELOPE_AFTER_SIGNATURE:
      if (!static_isBlankLine(line_start, line_end) && !parser->m_hasTextAfterSignature)
      {
        parser->m_hasTextAfterSignature = true;
        static_addIssue(parser->mp_report, SECURITYTXT_ISSUE_TEXT_AFTER_SIGNATURE, SECURITYTXT_FIELD_NONE, line_number);
      }
      return;
  }
}

static void static_readSignedContentLine(SecurityTxtParser_t* parser, const char* line_start, const char* line_end, int line_number)
{
  if (static_isTextEqual(line_start, line_end, SIGNATURE_BEGIN_LINE))
  {
    parser->m_envelopeState = SECURITYTXT_ENVELOPE_SIGNATURE;
    return;
  }
  if (static_hasPrefix(line_start, line_end, DASH_ESCAPE))
    line_start += sizeof(DASH_ESCAPE) - 1;

  static_readFieldLine(parser, line_start, line_end, line_number);
}

static void static_finishEnvelope(SecurityTxtParser_t* parser)
{
  switch (parser->m_envelopeState)
  {
    case SECURITYTXT_ENVELOPE_HASH_HEADERS:
    case SECURITYTXT_ENVELOPE_CONTENT:
    case SECURITYTXT_ENVELOPE_SIGNATURE:
      static_raiseSignatureMalformed(parser);
      break;
    case SECURITYTXT_ENVELOPE_START:
    case SECURITYTXT_ENVELOPE_UNSIGNED:
    case SECURITYTXT_ENVELOPE_AFTER_SIGNATURE:
      break;
  }
  parser->mp_report->m_isOpenPgpSigned = parser->m_envelopeState == SECURITYTXT_ENVELOPE_AFTER_SIGNATURE && !parser->m_isSignatureMalformed;
}

static void static_raiseSignatureMalformed(SecurityTxtParser_t* parser)
{
  if (parser->m_isSignatureMalformed)
    return;
  parser->m_isSignatureMalformed = true;
  static_addIssue(parser->mp_report, SECURITYTXT_ISSUE_SIGNATURE_MALFORMED, SECURITYTXT_FIELD_NONE, 0);
}

static void static_readFieldLine(SecurityTxtParser_t* parser, const char* line_start, const char* line_end, int line_number)
{
  SecurityTxtReport_t* report   = parser->mp_report;
  const char*          colon    = memchr(line_start, ':', (size_t)(line_end - line_start));
  const char*          name_end = colon != NULL ? colon : line_start;
  const char*          name     = line_start;
  static_trim(&name, &name_end);
  SecurityTxtField_t field = static_findField(name, name_end);

  if ((size_t)(line_end - line_start) > SECURITYTXT_MAX_LINE_BYTE_COUNT)
  {
    static_addIssue(report, SECURITYTXT_ISSUE_LINE_TOO_LONG, field, line_number);
    return;
  }
  if (static_isBlankLine(line_start, line_end) || line_start[0] == '#')
    return;
  if (name == name_end)
  {
    static_addIssue(report, SECURITYTXT_ISSUE_LINE_SYNTAX_INVALID, SECURITYTXT_FIELD_NONE, line_number);
    return;
  }
  if (field == SECURITYTXT_FIELD_NONE)
  {
    report->m_unknownFieldCount++;
    return;
  }

  const char* value     = colon + 1;
  const char* value_end = line_end;
  static_trim(&value, &value_end);
  if (value == value_end)
  {
    static_addIssue(report, SECURITYTXT_ISSUE_FIELD_EMPTY, field, line_number);
    return;
  }

  if (field == SECURITYTXT_FIELD_EXPIRES)
    static_checkExpiresValue(parser, value, value_end, line_number);
  else if (field == SECURITYTXT_FIELD_PREFERRED_LANGUAGES)
    static_checkPreferredLanguagesValue(parser, value, value_end, line_number);
  else
  {
    static_keepValue(parser, field, value, value_end, line_number);
    static_checkUriValue(parser, field, value, value_end, line_number);
  }
}

static SecurityTxtField_t static_findField(const char* name_start, const char* name_end)
{
  for (int field = 0; field < SECURITYTXT_FIELD_COUNT; field++)
  {
    if (static_isTextEqualIgnoringCase(name_start, name_end, FIELDS[field].mp_lineName))
      return (SecurityTxtField_t)field;
  }

  return SECURITYTXT_FIELD_NONE;
}

static void static_keepValue(SecurityTxtParser_t* parser, SecurityTxtField_t field, const char* value_start, const char* value_end, int line_number)
{
  SecurityTxtReport_t* report = parser->mp_report;
  report->ma_valueTotalCount[field]++;
  if (report->ma_valueKeptCount[field] >= SECURITYTXT_MAX_VALUE_COUNT)
  {
    if (report->ma_valueTotalCount[field] == SECURITYTXT_MAX_VALUE_COUNT + 1)
      static_addIssue(report, SECURITYTXT_ISSUE_TOO_MANY_VALUES, field, line_number);
    return;
  }

  SecurityTxtSpan_t* span = &report->ma_values[field][report->ma_valueKeptCount[field]];
  span->m_offset     = (size_t)(value_start - parser->mp_body);
  span->m_len        = (size_t)(value_end - value_start);
  span->m_lineNumber = line_number;
  report->ma_valueKeptCount[field]++;
}

static void static_checkUriValue(SecurityTxtParser_t* parser, SecurityTxtField_t field, const char* value_start, const char* value_end, int line_number)
{
  SecurityTxtReport_t* report = parser->mp_report;
  if (field == SECURITYTXT_FIELD_ENCRYPTION && static_hasPrefix(value_start, value_end, KEY_PREFIX))
  {
    static_addIssue(report, SECURITYTXT_ISSUE_ENCRYPTION_HOLDS_KEY, field, line_number);
    return;
  }

  size_t scheme_len = static_measureScheme(value_start, value_end);
  if (scheme_len == 0)
    static_addIssue(report, SECURITYTXT_ISSUE_URI_INVALID, field, line_number);
  else if (static_isTextEqualIgnoringCase(value_start, value_start + scheme_len, "http"))
    static_addIssue(report, SECURITYTXT_ISSUE_URI_NOT_HTTPS, field, line_number);

  if (field == SECURITYTXT_FIELD_CSAF && !static_isCsafPath(value_start, value_end))
    static_addIssue(report, SECURITYTXT_ISSUE_CSAF_NOT_PROVIDER_METADATA, field, line_number);
}

static size_t static_measureScheme(const char* value_start, const char* value_end)
{
  assert(value_start < value_end);

  if (!isalpha((unsigned char)value_start[0]))
    return 0;
  const char* scheme_end = value_start + 1;
  while ( scheme_end < value_end && (isalpha((unsigned char)*scheme_end)  ||
          isdigit((unsigned char)*scheme_end)                             ||
          *scheme_end == '+' || *scheme_end == '-' || *scheme_end == '.'))
  {
    scheme_end++;
  }
  if (scheme_end < value_end && *scheme_end == ':')
    return (size_t)(scheme_end - value_start);

  return 0;
}

static bool static_isCsafPath(const char* value_start, const char* value_end)
{
  const char* path_end = value_start;
  while (path_end < value_end && *path_end != '?' && *path_end != '#')
    path_end++;

  return bytes_hasSuffix(value_start, (size_t)(path_end - value_start), CSAF_PATH_SUFFIX, sizeof(CSAF_PATH_SUFFIX) - 1, false);
}

static void static_checkExpiresValue(SecurityTxtParser_t* parser, const char* value_start, const char* value_end, int line_number)
{
  SecurityTxtReport_t* report = parser->mp_report;
  if (report->ma_valueTotalCount[SECURITYTXT_FIELD_EXPIRES] > 0)
  {
    report->ma_valueTotalCount[SECURITYTXT_FIELD_EXPIRES]++;
    static_addIssue(report, SECURITYTXT_ISSUE_EXPIRES_DUPLICATE, SECURITYTXT_FIELD_EXPIRES, line_number);
    return;
  }
  static_keepValue(parser, SECURITYTXT_FIELD_EXPIRES, value_start, value_end, line_number);

  int64_t epoch = 0;
  if (!datetime_tryReadDateTime(value_start, value_end, &epoch))
  {
    static_addIssue(report, SECURITYTXT_ISSUE_EXPIRES_INVALID, SECURITYTXT_FIELD_EXPIRES, line_number);
    return;
  }

  report->m_isExpiresDateRead = true;
  report->m_expiresEpoch      = epoch;
  if (epoch < parser->m_nowEpoch)
    static_addIssue(report, SECURITYTXT_ISSUE_EXPIRED, SECURITYTXT_FIELD_EXPIRES, line_number);
  else if (epoch > parser->m_nowEpoch + SECURITYTXT_EXPIRES_MAX_AHEAD_SECONDS)
    static_addIssue(report, SECURITYTXT_ISSUE_EXPIRES_TOO_FAR_AHEAD, SECURITYTXT_FIELD_EXPIRES, line_number);
}

static void static_checkPreferredLanguagesValue(SecurityTxtParser_t* parser, const char* value_start, const char* value_end, int line_number)
{
  SecurityTxtReport_t* report = parser->mp_report;
  if (report->ma_valueTotalCount[SECURITYTXT_FIELD_PREFERRED_LANGUAGES] > 0)
  {
    static_addIssue(report, SECURITYTXT_ISSUE_PREFERRED_LANGUAGES_DUPLICATE, SECURITYTXT_FIELD_PREFERRED_LANGUAGES, line_number);
    return;
  }

  bool is_any_tag_invalid = false;
  const char* part_start  = value_start;
  while (true)
  {
    const char* part_end = part_start;
    while (part_end < value_end && *part_end != ',')
      part_end++;

    const char* tag     = part_start;
    const char* tag_end = part_end;
    static_trim(&tag, &tag_end);
    static_keepValue(parser, SECURITYTXT_FIELD_PREFERRED_LANGUAGES, tag, tag_end, line_number);
    if (!static_isLanguageTag(tag, tag_end))
      is_any_tag_invalid = true;

    if (part_end == value_end)
      break;
    part_start = part_end + 1;
  }

  if (is_any_tag_invalid)
    static_addIssue(report, SECURITYTXT_ISSUE_LANGUAGE_TAG_INVALID, SECURITYTXT_FIELD_PREFERRED_LANGUAGES, line_number);
}

static bool static_isLanguageTag(const char* tag_start, const char* tag_end)
{
  const char* position  = tag_start;
  bool is_first_part    = true;
  while (true)
  {
    const char* part_start = position;
    while (position < tag_end && *position != '-')
    {
      if (!isalpha((unsigned char)*position) && (is_first_part || !isdigit((unsigned char)*position)))
        return false;
      position++;
    }
    size_t part_len = (size_t)(position - part_start);
    if (part_len == 0 || part_len > SECURITYTXT_LANGUAGE_PART_MAX_LEN)
      return false;
    if (position == tag_end)
      return true;

    position++;
    is_first_part = false;
  }
}

static bool static_isContentTypeValid(const char* content_type)
{
  if (content_type == NULL)
    return false;

  const char* end      = content_type + strlen(content_type);
  const char* part_end = content_type + strcspn(content_type, ";");
  const char* type     = content_type;
  const char* type_end = part_end;
  static_trim(&type, &type_end);
  if (!static_isTextEqualIgnoringCase(type, type_end, "text/plain"))
    return false;

  while (part_end < end)
  {
    const char* part_start = part_end + 1;
    part_end               = memchr(part_start, ';', (size_t)(end - part_start));
    part_end               = part_end != NULL ? part_end : end;
    const char* equals     = memchr(part_start, '=', (size_t)(part_end - part_start));
    if (equals == NULL)
      continue;

    const char* name     = part_start;
    const char* name_end = equals;
    static_trim(&name, &name_end);
    if (!static_isTextEqualIgnoringCase(name, name_end, "charset"))
      continue;

    const char* value     = equals + 1;
    const char* value_end = part_end;
    static_trim(&value, &value_end);
    if (value_end - value >= 2 && value[0] == '"' && value_end[-1] == '"')
    {
      value++;
      value_end--;
    }
    return static_isTextEqualIgnoringCase(value, value_end, "utf-8");
  }

  return false;
}

static bool static_isAnyCanonicalEqual(const SecurityTxtReport_t* report, const char* body, const char* final_url)
{
  assert(body != NULL);

  if (final_url == NULL)
    return false;

  for (int i = 0; i < report->ma_valueKeptCount[SECURITYTXT_FIELD_CANONICAL]; i++)
  {
    const SecurityTxtSpan_t* span = &report->ma_values[SECURITYTXT_FIELD_CANONICAL][i];
    if (static_isUrlEqual(body + span->m_offset, span->m_len, final_url))
      return true;
  }
  return false;
}

static bool static_isUrlEqual(const char* text, size_t len, const char* url)
{
  if (strlen(url) != len)
    return false;

  size_t scheme_len = static_measureScheme(text, text + len);
  if (scheme_len == 0 || !static_hasPrefix(text + scheme_len, text + len, SCHEME_SEPARATOR))
    return memcmp(text, url, len) == 0;

  size_t authority_start = scheme_len + sizeof(SCHEME_SEPARATOR) - 1;
  size_t authority_end   = authority_start;
  while (authority_end < len && text[authority_end] != '/' && text[authority_end] != '?' && text[authority_end] != '#')
    authority_end++;

  size_t host_start = authority_end;
  while (host_start > authority_start && text[host_start - 1] != '@')
    host_start--;

  if (strncasecmp(text, url, scheme_len) != 0)
    return false;
  if (memcmp(text + scheme_len, url + scheme_len, host_start - scheme_len) != 0)
    return false;
  if (strncasecmp(text + host_start, url + host_start, authority_end - host_start) != 0)
    return false;
  return memcmp(text + authority_end, url + authority_end, len - authority_end) == 0;
}

static void static_trim(const char** start, const char** end)
{
  while (*start < *end && isblank((unsigned char)**start))
    (*start)++;
  while (*end > *start && isblank((unsigned char)(*end)[-1]))
    (*end)--;
}

static bool static_isBlankLine(const char* start, const char* end)
{
  static_trim(&start, &end);
  return start == end;
}

static bool static_isTextEqual(const char* start, const char* end, const char* text)
{
  return bytes_isEqual(start, (size_t)(end - start), text, false);
}

static bool static_hasPrefix(const char* start, const char* end, const char* prefix)
{
  return bytes_hasPrefix(start, (size_t)(end - start), prefix, strlen(prefix), false);
}

static bool static_isTextEqualIgnoringCase(const char* start, const char* end, const char* text)
{
  return bytes_isEqual(start, (size_t)(end - start), text, true);
}
