#ifndef ROBOTSTXT_H
#define ROBOTSTXT_H

#include <stdbool.h>
#include <stddef.h>

#define ROBOTSTXT_MAX_BODY_BYTE_COUNT     (512 * 1024)
#define ROBOTSTXT_MAX_LINE_BYTE_COUNT     2048
#define ROBOTSTXT_MAX_GROUP_COUNT         1024
#define ROBOTSTXT_MAX_RULE_COUNT          16384
#define ROBOTSTXT_MAX_USER_AGENT_COUNT    1024
#define ROBOTSTXT_MAX_SITEMAP_COUNT       100
#define ROBOTSTXT_MAX_ISSUE_COUNT         50

typedef struct
{
  size_t  m_offset;
  size_t  m_len;
  int     m_lineNumber;
} RobotsTxtSpan_t;

typedef enum {
  ROBOTSTXT_DIRECTIVE_NONE = 0,
  ROBOTSTXT_DIRECTIVE_USER_AGENT,
  ROBOTSTXT_DIRECTIVE_ALLOW,
  ROBOTSTXT_DIRECTIVE_DISALLOW,
  ROBOTSTXT_DIRECTIVE_CRAWL_DELAY,
  ROBOTSTXT_DIRECTIVE_SITEMAP,
  ROBOTSTXT_DIRECTIVE_COUNT
} RobotsTxtDirective_t;

typedef enum {
  ROBOTSTXT_RULE_ALLOW = 0,
  ROBOTSTXT_RULE_DISALLOW
} RobotsTxtRuleKind_t;

typedef struct
{
  RobotsTxtRuleKind_t   m_kind;
  RobotsTxtSpan_t       m_pattern;
} RobotsTxtRule_t;

typedef struct
{
  int    m_lineNumber;
  bool   m_hasOurUserAgent;
  bool   m_hasWildcardUserAgent;
  int    m_firstUserAgent;
  int    m_userAgentCount;
  int    m_firstRule;
  int    m_ruleCount;
  bool   m_hasCrawlDelay;
  double m_crawlDelaySeconds;
} RobotsTxtGroup_t;

typedef enum {
  ROBOTSTXT_SEVERITY_WARNING = 0,
  ROBOTSTXT_SEVERITY_INFO,
  ROBOTSTXT_SEVERITY_COUNT
} RobotsTxtSeverity_t;

typedef enum {
  ROBOTSTXT_ISSUE_FILE_TOO_LARGE = 0,
  ROBOTSTXT_ISSUE_BYTE_ORDER_MARK,
  ROBOTSTXT_ISSUE_INVALID_UTF8,
  ROBOTSTXT_ISSUE_CONTAINS_NUL_BYTE,
  ROBOTSTXT_ISSUE_LINE_TOO_LONG,
  ROBOTSTXT_ISSUE_LINE_SYNTAX_INVALID,
  ROBOTSTXT_ISSUE_RULE_BEFORE_USER_AGENT,
  ROBOTSTXT_ISSUE_EMPTY_USER_AGENT,
  ROBOTSTXT_ISSUE_UNKNOWN_DIRECTIVE,
  ROBOTSTXT_ISSUE_CRAWL_DELAY_INVALID,
  ROBOTSTXT_ISSUE_SITEMAP_NOT_ABSOLUTE,
  ROBOTSTXT_ISSUE_TOO_MANY_GROUPS,
  ROBOTSTXT_ISSUE_TOO_MANY_RULES,
  ROBOTSTXT_ISSUE_TOO_MANY_USER_AGENTS,
  ROBOTSTXT_ISSUE_TOO_MANY_SITEMAPS,
  ROBOTSTXT_ISSUE_REDIRECTED_TO_OTHER_HOST,
  ROBOTSTXT_ISSUE_CONTENT_TYPE_NOT_TEXT_PLAIN,
  ROBOTSTXT_ISSUE_CODE_COUNT
} RobotsTxtIssueCode_t;

typedef struct
{
  RobotsTxtIssueCode_t  m_issueCode;
  RobotsTxtDirective_t  m_field;
  int                   m_lineNumber;
} RobotsTxtIssue_t;

typedef enum {
  ROBOTSTXT_DECISION_ALLOWED = 0,
  ROBOTSTXT_DECISION_DISALLOWED,
  ROBOTSTXT_DECISION_UNKNOWN
} RobotsTxtDecision_t;

typedef struct
{
  RobotsTxtDecision_t   m_decision;
  int                   m_decidingRuleIndex;
} RobotsTxtVerdict_t;

typedef struct
{
  RobotsTxtGroup_t* mp_groups;
  int               m_groupKeptCount;
  int               m_groupTotalCount;
  RobotsTxtRule_t*  mp_rules;
  int               m_ruleKeptCount;
  int               m_ruleTotalCount;
  RobotsTxtSpan_t*  mp_userAgents;
  int               m_userAgentKeptCount;
  int               m_userAgentTotalCount;
  RobotsTxtSpan_t*  mp_sitemaps;
  int               m_sitemapKeptCount;
  int               m_sitemapTotalCount;
  bool              m_hasDroppedRule;
  RobotsTxtIssue_t  ma_issues[ROBOTSTXT_MAX_ISSUE_COUNT];
  int               m_issueKeptCount;
  int               m_issueTotalCount;
  int               ma_issueCountBySeverity[ROBOTSTXT_SEVERITY_COUNT];
} RobotsTxt_t;

bool                robotstxt_parse         (const char* body, size_t body_len, bool is_body_cut, const char* product_token, RobotsTxt_t* robots_out);
RobotsTxtVerdict_t  robotstxt_checkPath     (const RobotsTxt_t* robots, const char* body, const char* path, size_t path_len);
void                robotstxt_checkResponse (RobotsTxt_t* robots, const char* content_type, bool is_redirected_to_other_host);
void                robotstxt_free          (RobotsTxt_t* robots);
const char*         robotstxt_issueCodeName (RobotsTxtIssueCode_t issue_code);
RobotsTxtSeverity_t robotstxt_issueSeverity (RobotsTxtIssueCode_t issue_code);
const char*         robotstxt_severityName  (RobotsTxtSeverity_t severity);
const char*         robotstxt_directiveName (RobotsTxtDirective_t directive);

#endif
