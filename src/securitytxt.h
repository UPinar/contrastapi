#ifndef SECURITYTXT_H
#define SECURITYTXT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SECURITYTXT_MAX_BODY_BYTE_COUNT         (32 * 1024)
#define SECURITYTXT_MAX_LINE_BYTE_COUNT         2048
#define SECURITYTXT_MAX_LINE_COUNT              1000
#define SECURITYTXT_MAX_VALUE_COUNT             20
#define SECURITYTXT_MAX_ISSUE_COUNT             50
#define SECURITYTXT_EXPIRES_MAX_AHEAD_SECONDS   (365 * 24 * 60 * 60)

typedef enum {
  SECURITYTXT_FIELD_ACKNOWLEDGMENTS = 0,
  SECURITYTXT_FIELD_CANONICAL,
  SECURITYTXT_FIELD_CONTACT,
  SECURITYTXT_FIELD_CSAF,
  SECURITYTXT_FIELD_ENCRYPTION,
  SECURITYTXT_FIELD_EXPIRES,
  SECURITYTXT_FIELD_HIRING,
  SECURITYTXT_FIELD_POLICY,
  SECURITYTXT_FIELD_PREFERRED_LANGUAGES,
  SECURITYTXT_FIELD_COUNT,
  SECURITYTXT_FIELD_NONE
} SecurityTxtField_t;

typedef enum {
  SECURITYTXT_SEVERITY_ERROR = 0,
  SECURITYTXT_SEVERITY_WARNING,
  SECURITYTXT_SEVERITY_INFO,
  SECURITYTXT_SEVERITY_COUNT
} SecurityTxtSeverity_t;

typedef enum {
  SECURITYTXT_ISSUE_CONTACT_MISSING = 0,
  SECURITYTXT_ISSUE_EXPIRES_MISSING,
  SECURITYTXT_ISSUE_EXPIRES_DUPLICATE,
  SECURITYTXT_ISSUE_EXPIRES_INVALID,
  SECURITYTXT_ISSUE_EXPIRED,
  SECURITYTXT_ISSUE_EXPIRES_TOO_FAR_AHEAD,
  SECURITYTXT_ISSUE_PREFERRED_LANGUAGES_DUPLICATE,
  SECURITYTXT_ISSUE_LANGUAGE_TAG_INVALID,
  SECURITYTXT_ISSUE_ENCRYPTION_HOLDS_KEY,
  SECURITYTXT_ISSUE_URI_INVALID,
  SECURITYTXT_ISSUE_URI_NOT_HTTPS,
  SECURITYTXT_ISSUE_CSAF_NOT_PROVIDER_METADATA,
  SECURITYTXT_ISSUE_CONTENT_TYPE_INVALID,
  SECURITYTXT_ISSUE_CANONICAL_MISMATCH,
  SECURITYTXT_ISSUE_REDIRECTED_TO_OTHER_HOST,
  SECURITYTXT_ISSUE_SIGNATURE_MALFORMED,
  SECURITYTXT_ISSUE_TEXT_AFTER_SIGNATURE,
  SECURITYTXT_ISSUE_SIGNED_WITHOUT_CANONICAL,
  SECURITYTXT_ISSUE_INVALID_LINE_ENDING,
  SECURITYTXT_ISSUE_INVALID_UTF8,
  SECURITYTXT_ISSUE_CONTAINS_NUL_BYTE,
  SECURITYTXT_ISSUE_BYTE_ORDER_MARK,
  SECURITYTXT_ISSUE_LINE_SYNTAX_INVALID,
  SECURITYTXT_ISSUE_FIELD_EMPTY,
  SECURITYTXT_ISSUE_LINE_TOO_LONG,
  SECURITYTXT_ISSUE_TOO_MANY_LINES,
  SECURITYTXT_ISSUE_TOO_MANY_VALUES,
  SECURITYTXT_ISSUE_FILE_TOO_LARGE,
  SECURITYTXT_ISSUE_CODE_COUNT
} SecurityTxtIssueCode_t;

typedef struct
{
  size_t  m_offset;
  size_t  m_len;
  int     m_lineNumber;
} SecurityTxtSpan_t;

typedef struct
{
  SecurityTxtIssueCode_t  m_issueCode;
  SecurityTxtField_t      m_field;
  int                     m_lineNumber;
} SecurityTxtIssue_t;

typedef struct
{
  SecurityTxtSpan_t     ma_values[SECURITYTXT_FIELD_COUNT][SECURITYTXT_MAX_VALUE_COUNT];
  int                   ma_valueKeptCount[SECURITYTXT_FIELD_COUNT];
  int                   ma_valueTotalCount[SECURITYTXT_FIELD_COUNT];
  bool                  m_isOpenPgpSigned;
  bool                  m_isExpiresDateRead;
  int64_t               m_expiresEpoch;
  int                   m_unknownFieldCount;
  SecurityTxtIssue_t    ma_issues[SECURITYTXT_MAX_ISSUE_COUNT];
  int                   m_issueKeptCount;
  int                   m_issueTotalCount;
  int                   ma_issueCountBySeverity[SECURITYTXT_SEVERITY_COUNT];
} SecurityTxtReport_t;

void                  securitytxt_parse         (const char* body, size_t body_len, bool is_body_cut, int64_t now_epoch, SecurityTxtReport_t* report_out);
void                  securitytxt_checkResponse (SecurityTxtReport_t* report, const char* body, const char* content_type, const char* final_url, bool is_redirected_to_other_host);
const char*           securitytxt_fieldName     (SecurityTxtField_t field);
const char*           securitytxt_issueCodeName (SecurityTxtIssueCode_t issue_code);
SecurityTxtSeverity_t securitytxt_issueSeverity (SecurityTxtIssueCode_t issue_code);
const char*           securitytxt_severityName  (SecurityTxtSeverity_t severity);

#endif
