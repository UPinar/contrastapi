#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "robotstxt.h"
#include "bytes.h"
#include "utf8.h"

#define ROBOTSTXT_INITIAL_ARRAY_CAPACITY 8

#define ROBOTSTXT_MAX_CRAWL_DELAY_SECONDS 86400

#define ROBOTSTXT_MAX_FRACTION_DIGIT_COUNT 9

#define ROBOTSTXT_BYTE_ORDER_MARK     "\xEF\xBB\xBF"
#define ROBOTSTXT_BYTE_ORDER_MARK_LEN 3

static const struct {
  const char*         mp_name;
  RobotsTxtSeverity_t m_severity;
} ISSUES[ROBOTSTXT_ISSUE_CODE_COUNT] = {
  [ROBOTSTXT_ISSUE_FILE_TOO_LARGE]              = { "file_too_large",              ROBOTSTXT_SEVERITY_WARNING },
  [ROBOTSTXT_ISSUE_BYTE_ORDER_MARK]             = { "byte_order_mark",             ROBOTSTXT_SEVERITY_INFO    },
  [ROBOTSTXT_ISSUE_INVALID_UTF8]                = { "invalid_utf8",                ROBOTSTXT_SEVERITY_WARNING },
  [ROBOTSTXT_ISSUE_CONTAINS_NUL_BYTE]           = { "contains_nul_byte",           ROBOTSTXT_SEVERITY_WARNING },
  [ROBOTSTXT_ISSUE_LINE_TOO_LONG]               = { "line_too_long",               ROBOTSTXT_SEVERITY_WARNING },
  [ROBOTSTXT_ISSUE_LINE_SYNTAX_INVALID]         = { "line_syntax_invalid",         ROBOTSTXT_SEVERITY_INFO    },
  [ROBOTSTXT_ISSUE_RULE_BEFORE_USER_AGENT]      = { "rule_before_user_agent",      ROBOTSTXT_SEVERITY_WARNING },
  [ROBOTSTXT_ISSUE_EMPTY_USER_AGENT]            = { "empty_user_agent",            ROBOTSTXT_SEVERITY_INFO    },
  [ROBOTSTXT_ISSUE_UNKNOWN_DIRECTIVE]           = { "unknown_directive",           ROBOTSTXT_SEVERITY_INFO    },
  [ROBOTSTXT_ISSUE_CRAWL_DELAY_INVALID]         = { "crawl_delay_invalid",         ROBOTSTXT_SEVERITY_INFO    },
  [ROBOTSTXT_ISSUE_SITEMAP_NOT_ABSOLUTE]        = { "sitemap_not_absolute",        ROBOTSTXT_SEVERITY_INFO    },
  [ROBOTSTXT_ISSUE_TOO_MANY_GROUPS]             = { "too_many_groups",             ROBOTSTXT_SEVERITY_WARNING },
  [ROBOTSTXT_ISSUE_TOO_MANY_RULES]              = { "too_many_rules",              ROBOTSTXT_SEVERITY_WARNING },
  [ROBOTSTXT_ISSUE_TOO_MANY_USER_AGENTS]        = { "too_many_user_agents",        ROBOTSTXT_SEVERITY_WARNING },
  [ROBOTSTXT_ISSUE_TOO_MANY_SITEMAPS]           = { "too_many_sitemaps",           ROBOTSTXT_SEVERITY_WARNING },
  [ROBOTSTXT_ISSUE_REDIRECTED_TO_OTHER_HOST]    = { "redirected_to_other_host",    ROBOTSTXT_SEVERITY_INFO    },
  [ROBOTSTXT_ISSUE_CONTENT_TYPE_NOT_TEXT_PLAIN] = { "content_type_not_text_plain", ROBOTSTXT_SEVERITY_INFO    },
};

static const char* const SEVERITY_NAMES[ROBOTSTXT_SEVERITY_COUNT] = { "warning", "info" };

static const char* const DIRECTIVE_NAMES[ROBOTSTXT_DIRECTIVE_COUNT] = {
  NULL, "user-agent", "allow", "disallow", "crawl-delay", "sitemap",
};

typedef enum {
  ROBOTSTXT_PHASE_BEFORE_USER_AGENT = 0,
  ROBOTSTXT_PHASE_USER_AGENT_LIST,
  ROBOTSTXT_PHASE_RULES_OF_KEPT_GROUP,
  ROBOTSTXT_PHASE_RULES_OF_SKIPPED_GROUP
} RobotsTxtParsePhase_t;

typedef struct
{
  int   m_lineNumber;
  bool  m_hasOurUserAgent;
  bool  m_hasWildcardUserAgent;
  int   m_firstUserAgent;
  int   m_valueCount;
  int   m_firstDroppedLine;
} RobotsTxtUserAgentList_t;

typedef struct
{
  const char*               mp_body;
  const char*               mp_productToken;
  RobotsTxt_t*              mp_robots;
  int                       m_groupCapacity;
  int                       m_ruleCapacity;
  int                       m_userAgentCapacity;
  int                       m_sitemapCapacity;
  RobotsTxtParsePhase_t     m_phase;
  RobotsTxtUserAgentList_t  m_list;
  bool                      ma_isIssueRaised[ROBOTSTXT_ISSUE_CODE_COUNT];
} RobotsTxtParseState_t;

typedef struct
{
  unsigned char   m_byte;
  size_t          m_len;
} RobotsTxtUnit_t;

static size_t               static_findLastLineEnd          (const char* body, size_t start, size_t body_len);
static bool                 static_tryReadLines             (RobotsTxtParseState_t* state, size_t start, size_t end);
static size_t               static_skipLineEnd              (const char* body, size_t line_end, size_t end);
static bool                 static_tryReadLine              (RobotsTxtParseState_t* state, size_t line_start, size_t line_end, int line_number);
static bool                 static_tryReadLongLine          (RobotsTxtParseState_t* state, RobotsTxtDirective_t directive, int line_number);
static RobotsTxtDirective_t static_findDirective            (const char* body, size_t name_start, size_t name_end);
static bool                 static_isCurrentGroupKept       (const RobotsTxtParseState_t* state);
static RobotsTxtGroup_t*    static_findCurrentGroup         (const RobotsTxtParseState_t* state);
static bool                 static_tryReadUserAgentLine     (RobotsTxtParseState_t* state, size_t value_offset, size_t value_len, int line_number);
static bool                 static_tryCloseUserAgentList    (RobotsTxtParseState_t* state);
static bool                 static_tryReadRuleLine          (RobotsTxtParseState_t* state, RobotsTxtDirective_t directive, size_t value_offset, size_t value_len, int line_number);
static bool                 static_tryReadCrawlDelayLine    (RobotsTxtParseState_t* state, size_t value_offset, size_t value_len, int line_number);
static bool                 static_tryReadSitemapLine       (RobotsTxtParseState_t* state, size_t value_offset, size_t value_len, int line_number);
static bool                 static_tryReadCrawlDelaySeconds (const char* text, size_t len, double* seconds_out);
static void*                static_reserveSlot              (void* items, int* capacity, int count, int max_count, size_t item_size);
static void                 static_addIssue                 (RobotsTxt_t* robots, RobotsTxtIssueCode_t issue_code, RobotsTxtDirective_t field, int line_number);
static void                 static_addIssueOnce             (RobotsTxtParseState_t* state, RobotsTxtIssueCode_t issue_code, int line_number);
static bool                 static_isRuleStronger           (const RobotsTxtRule_t* rule, const RobotsTxtRule_t* best_rule);
static bool                 static_isPatternMatching        (const char* pattern, size_t pattern_len, const char* path, size_t path_len);
static RobotsTxtUnit_t      static_readUnit                 (const char* text, size_t len, size_t position);
static bool                 static_isTextPlain              (const char* content_type);
static size_t               static_skipBlanks               (const char* text, size_t start, size_t end);
static size_t               static_trimBlanksAtEnd          (const char* text, size_t start, size_t end);
static bool                 static_isOurProductToken        (const RobotsTxtParseState_t* state, const char* value, size_t value_len);

bool robotstxt_parse(const char* body, size_t body_len, bool is_body_cut, const char* product_token, RobotsTxt_t* robots_out)
{
  assert(robots_out != NULL);
  assert(product_token != NULL && product_token[0] != '\0');
  assert(product_token[strspn(product_token, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-")] == '\0');
  assert(body != NULL || body_len == 0);

  memset(robots_out, 0, sizeof(*robots_out));
  if (body == NULL)
    body = "";

  RobotsTxtParseState_t state = { 0 };
  state.mp_body          = body;
  state.mp_productToken  = product_token;
  state.mp_robots        = robots_out;

  bool   has_byte_order_mark = bytes_hasPrefix(body, body_len, ROBOTSTXT_BYTE_ORDER_MARK, ROBOTSTXT_BYTE_ORDER_MARK_LEN, false);
  size_t start = has_byte_order_mark ? ROBOTSTXT_BYTE_ORDER_MARK_LEN : 0;
  size_t end   = is_body_cut ? static_findLastLineEnd(body, start, body_len) : body_len;

  if (is_body_cut)
    static_addIssue(robots_out, ROBOTSTXT_ISSUE_FILE_TOO_LARGE, ROBOTSTXT_DIRECTIVE_NONE, 0);
  if (has_byte_order_mark)
    static_addIssue(robots_out, ROBOTSTXT_ISSUE_BYTE_ORDER_MARK, ROBOTSTXT_DIRECTIVE_NONE, 0);
  if (!utf8_isTextValid(body + start, end - start))
    static_addIssue(robots_out, ROBOTSTXT_ISSUE_INVALID_UTF8, ROBOTSTXT_DIRECTIVE_NONE, 0);
  if (memchr(body + start, '\0', end - start) != NULL)
    static_addIssue(robots_out, ROBOTSTXT_ISSUE_CONTAINS_NUL_BYTE, ROBOTSTXT_DIRECTIVE_NONE, 0);

  if (!static_tryReadLines(&state, start, end))
  {
    robotstxt_free(robots_out);
    return false;
  }
  return true;
}

RobotsTxtVerdict_t robotstxt_checkPath(const RobotsTxt_t* robots, const char* body, const char* path, size_t path_len)
{
  assert(robots != NULL);
  assert(body != NULL || robots->m_ruleKeptCount == 0);
  assert(path != NULL || path_len == 0);

  RobotsTxtVerdict_t verdict = { ROBOTSTXT_DECISION_ALLOWED, -1 };
  if (robots->m_hasDroppedRule)
  {
    verdict.m_decision = ROBOTSTXT_DECISION_UNKNOWN;
    return verdict;
  }

  bool has_our_user_agent_group = false;
  for (int i = 0; i < robots->m_groupKeptCount; i++)
  {
    if (robots->mp_groups[i].m_hasOurUserAgent)
      has_our_user_agent_group = true;
  }

  int best_rule_index = -1;
  for (int i = 0; i < robots->m_groupKeptCount; i++)
  {
    const RobotsTxtGroup_t* group = &robots->mp_groups[i];
    bool is_deciding = has_our_user_agent_group ? group->m_hasOurUserAgent : group->m_hasWildcardUserAgent;
    if (!is_deciding)
      continue;

    for (int rule_index = group->m_firstRule; rule_index < group->m_firstRule + group->m_ruleCount; rule_index++)
    {
      const RobotsTxtRule_t* rule = &robots->mp_rules[rule_index];
      if (!static_isPatternMatching(body + rule->m_pattern.m_offset, rule->m_pattern.m_len, path, path_len))
        continue;
      if (best_rule_index < 0 || static_isRuleStronger(rule, &robots->mp_rules[best_rule_index]))
        best_rule_index = rule_index;
    }
  }

  if (best_rule_index >= 0)
  {
    bool is_allow = robots->mp_rules[best_rule_index].m_kind == ROBOTSTXT_RULE_ALLOW;
    verdict.m_decision          = is_allow ? ROBOTSTXT_DECISION_ALLOWED : ROBOTSTXT_DECISION_DISALLOWED;
    verdict.m_decidingRuleIndex = best_rule_index;
  }

  return verdict;
}

void robotstxt_checkResponse(RobotsTxt_t* robots, const char* content_type, bool is_redirected_to_other_host)
{
  assert(robots != NULL);

  if (is_redirected_to_other_host)
    static_addIssue(robots, ROBOTSTXT_ISSUE_REDIRECTED_TO_OTHER_HOST, ROBOTSTXT_DIRECTIVE_NONE, 0);
  if (!static_isTextPlain(content_type))
    static_addIssue(robots, ROBOTSTXT_ISSUE_CONTENT_TYPE_NOT_TEXT_PLAIN, ROBOTSTXT_DIRECTIVE_NONE, 0);
}

void robotstxt_free(RobotsTxt_t* robots)
{
  assert(robots != NULL);

  free(robots->mp_groups);
  free(robots->mp_rules);
  free(robots->mp_userAgents);
  free(robots->mp_sitemaps);
  memset(robots, 0, sizeof(*robots));
}

const char* robotstxt_issueCodeName(RobotsTxtIssueCode_t issue_code)
{
  assert(issue_code >= 0 && issue_code < ROBOTSTXT_ISSUE_CODE_COUNT);
  return ISSUES[issue_code].mp_name;
}

RobotsTxtSeverity_t robotstxt_issueSeverity(RobotsTxtIssueCode_t issue_code)
{
  assert(issue_code >= 0 && issue_code < ROBOTSTXT_ISSUE_CODE_COUNT);
  return ISSUES[issue_code].m_severity;
}

const char* robotstxt_severityName(RobotsTxtSeverity_t severity)
{
  assert(severity >= 0 && severity < ROBOTSTXT_SEVERITY_COUNT);
  return SEVERITY_NAMES[severity];
}

const char* robotstxt_directiveName(RobotsTxtDirective_t directive)
{
  assert(directive >= 0 && directive < ROBOTSTXT_DIRECTIVE_COUNT);
  return DIRECTIVE_NAMES[directive];
}

static size_t static_findLastLineEnd(const char* body, size_t start, size_t body_len)
{
  for (size_t end = body_len; end > start; end--)
  {
    if (body[end - 1] == '\n' || body[end - 1] == '\r')
      return end;
  }
  return start;
}

static bool static_tryReadLines(RobotsTxtParseState_t* state, size_t start, size_t end)
{
  const char* body        = state->mp_body;
  int         line_number = 0;
  size_t      line_start  = start;
  while (line_start < end)
  {
    size_t line_end = line_start;
    while (line_end < end && body[line_end] != '\n' && body[line_end] != '\r')
      line_end++;
    line_number++;
    if (!static_tryReadLine(state, line_start, line_end, line_number))
      return false;
    line_start = static_skipLineEnd(body, line_end, end);
  }
  return static_tryCloseUserAgentList(state);
}

static size_t static_skipLineEnd(const char* body, size_t line_end, size_t end)
{
  if (line_end == end)
    return end;
  if (body[line_end] == '\r' && line_end + 1 < end && body[line_end + 1] == '\n')
    return line_end + 2;
  return line_end + 1;
}

static bool static_tryReadLine(RobotsTxtParseState_t* state, size_t line_start, size_t line_end, int line_number)
{
  const char*  body   = state->mp_body;
  RobotsTxt_t* robots = state->mp_robots;

  size_t content_end = line_start;
  while (content_end < line_end && body[content_end] != '#')
    content_end++;

  size_t colon = line_start;
  while (colon < content_end && body[colon] != ':')
    colon++;
  bool has_colon = colon < content_end;
  RobotsTxtDirective_t directive = has_colon ? static_findDirective(body, line_start, colon) : ROBOTSTXT_DIRECTIVE_NONE;

  if (line_end - line_start > ROBOTSTXT_MAX_LINE_BYTE_COUNT)
    return static_tryReadLongLine(state, directive, line_number);

  size_t content_start = static_skipBlanks(body, line_start, content_end);
  if (content_start == content_end)
    return true;

  if (!has_colon)
  {
    static_addIssue(robots, ROBOTSTXT_ISSUE_LINE_SYNTAX_INVALID, ROBOTSTXT_DIRECTIVE_NONE, line_number);
    return true;
  }

  size_t value_start = static_skipBlanks(body, colon + 1, content_end);
  size_t value_end   = static_trimBlanksAtEnd(body, value_start, content_end);
  size_t value_len   = value_end - value_start;
  switch (directive)
  {
    case ROBOTSTXT_DIRECTIVE_USER_AGENT:
      return static_tryReadUserAgentLine(state, value_start, value_len, line_number);
    case ROBOTSTXT_DIRECTIVE_ALLOW:
    case ROBOTSTXT_DIRECTIVE_DISALLOW:
      return static_tryReadRuleLine(state, directive, value_start, value_len, line_number);
    case ROBOTSTXT_DIRECTIVE_CRAWL_DELAY:
      return static_tryReadCrawlDelayLine(state, value_start, value_len, line_number);
    case ROBOTSTXT_DIRECTIVE_SITEMAP:
      return static_tryReadSitemapLine(state, value_start, value_len, line_number);
    default:
      static_addIssue(robots, ROBOTSTXT_ISSUE_UNKNOWN_DIRECTIVE, ROBOTSTXT_DIRECTIVE_NONE, line_number);
      return true;
  }
}

static bool static_tryReadLongLine(RobotsTxtParseState_t* state, RobotsTxtDirective_t directive, int line_number)
{
  RobotsTxt_t* robots = state->mp_robots;

  static_addIssue(robots, ROBOTSTXT_ISSUE_LINE_TOO_LONG, directive, line_number);
  bool is_rule      = directive == ROBOTSTXT_DIRECTIVE_ALLOW || directive == ROBOTSTXT_DIRECTIVE_DISALLOW;
  bool is_kept_rule = is_rule && static_isCurrentGroupKept(state);
  if (directive == ROBOTSTXT_DIRECTIVE_USER_AGENT || is_kept_rule)
    robots->m_hasDroppedRule = true;
  if (is_rule || directive == ROBOTSTXT_DIRECTIVE_CRAWL_DELAY)
    return static_tryCloseUserAgentList(state);

  return true;
}

static RobotsTxtDirective_t static_findDirective(const char* body, size_t name_start, size_t name_end)
{
  size_t start = static_skipBlanks(body, name_start, name_end);
  size_t end   = static_trimBlanksAtEnd(body, start, name_end);

  for (int directive = ROBOTSTXT_DIRECTIVE_NONE + 1; directive < ROBOTSTXT_DIRECTIVE_COUNT; directive++)
  {
    if (bytes_isEqual(body + start, end - start, DIRECTIVE_NAMES[directive], true))
      return (RobotsTxtDirective_t)directive;
  }
  return ROBOTSTXT_DIRECTIVE_NONE;
}

static bool static_isCurrentGroupKept(const RobotsTxtParseState_t* state)
{
  if (state->m_phase == ROBOTSTXT_PHASE_USER_AGENT_LIST)
    return state->m_list.m_hasOurUserAgent || state->m_list.m_hasWildcardUserAgent;

  return state->m_phase == ROBOTSTXT_PHASE_RULES_OF_KEPT_GROUP;
}

static RobotsTxtGroup_t* static_findCurrentGroup(const RobotsTxtParseState_t* state)
{
  if (state->m_phase != ROBOTSTXT_PHASE_RULES_OF_KEPT_GROUP)
    return NULL;

  return &state->mp_robots->mp_groups[state->mp_robots->m_groupKeptCount - 1];
}

static bool static_tryReadUserAgentLine(RobotsTxtParseState_t* state, size_t value_offset, size_t value_len, int line_number)
{
  RobotsTxt_t* robots = state->mp_robots;
  const char*  value  = state->mp_body + value_offset;

  if (state->m_phase != ROBOTSTXT_PHASE_USER_AGENT_LIST)
  {
    state->m_phase = ROBOTSTXT_PHASE_USER_AGENT_LIST;
    state->m_list  = (RobotsTxtUserAgentList_t){ .m_lineNumber = line_number, .m_firstUserAgent = robots->m_userAgentKeptCount };
  }

  if (value_len == 0)
  {
    static_addIssue(robots, ROBOTSTXT_ISSUE_EMPTY_USER_AGENT, ROBOTSTXT_DIRECTIVE_USER_AGENT, line_number);
    return true;
  }
  if (value_len == 1 && value[0] == '*')
    state->m_list.m_hasWildcardUserAgent = true;
  else if (static_isOurProductToken(state, value, value_len))
    state->m_list.m_hasOurUserAgent = true;

  state->m_list.m_valueCount++;
  if (robots->m_userAgentKeptCount >= ROBOTSTXT_MAX_USER_AGENT_COUNT)
  {
    if (state->m_list.m_firstDroppedLine == 0)
      state->m_list.m_firstDroppedLine = line_number;
    return true;
  }
  RobotsTxtSpan_t* user_agents = static_reserveSlot(robots->mp_userAgents, &state->m_userAgentCapacity, robots->m_userAgentKeptCount, ROBOTSTXT_MAX_USER_AGENT_COUNT, sizeof(RobotsTxtSpan_t));
  if (user_agents == NULL)
    return false;
  robots->mp_userAgents = user_agents;
  user_agents[robots->m_userAgentKeptCount] = (RobotsTxtSpan_t){ value_offset, value_len, line_number };
  robots->m_userAgentKeptCount++;

  return true;
}

static bool static_tryCloseUserAgentList(RobotsTxtParseState_t* state)
{
  RobotsTxt_t* robots = state->mp_robots;

  if (state->m_phase != ROBOTSTXT_PHASE_USER_AGENT_LIST)
    return true;
  state->m_phase = ROBOTSTXT_PHASE_RULES_OF_SKIPPED_GROUP;

  if (!state->m_list.m_hasOurUserAgent && !state->m_list.m_hasWildcardUserAgent)
  {
    robots->m_userAgentKeptCount = state->m_list.m_firstUserAgent;
    return true;
  }

  robots->m_groupTotalCount++;
  if (robots->m_groupKeptCount >= ROBOTSTXT_MAX_GROUP_COUNT)
  {
    robots->m_userAgentKeptCount = state->m_list.m_firstUserAgent;
    robots->m_hasDroppedRule = true;
    static_addIssueOnce(state, ROBOTSTXT_ISSUE_TOO_MANY_GROUPS, state->m_list.m_lineNumber);
    return true;
  }

  RobotsTxtGroup_t* groups = static_reserveSlot(robots->mp_groups, &state->m_groupCapacity, robots->m_groupKeptCount, ROBOTSTXT_MAX_GROUP_COUNT, sizeof(RobotsTxtGroup_t));
  if (groups == NULL)
    return false;
  robots->mp_groups = groups;

  RobotsTxtGroup_t* group = &groups[robots->m_groupKeptCount];
  memset(group, 0, sizeof(*group));
  group->m_lineNumber           = state->m_list.m_lineNumber;
  group->m_hasOurUserAgent      = state->m_list.m_hasOurUserAgent;
  group->m_hasWildcardUserAgent = state->m_list.m_hasWildcardUserAgent;
  group->m_firstUserAgent       = state->m_list.m_firstUserAgent;
  group->m_userAgentCount       = robots->m_userAgentKeptCount - state->m_list.m_firstUserAgent;
  group->m_firstRule            = robots->m_ruleKeptCount;
  robots->m_groupKeptCount++;
  state->m_phase                = ROBOTSTXT_PHASE_RULES_OF_KEPT_GROUP;

  robots->m_userAgentTotalCount += state->m_list.m_valueCount;
  if (state->m_list.m_firstDroppedLine > 0)
    static_addIssueOnce(state, ROBOTSTXT_ISSUE_TOO_MANY_USER_AGENTS, state->m_list.m_firstDroppedLine);
  return true;
}

static bool static_tryReadRuleLine(RobotsTxtParseState_t* state, RobotsTxtDirective_t directive, size_t value_offset, size_t value_len, int line_number)
{
  RobotsTxt_t* robots = state->mp_robots;

  if (state->m_phase == ROBOTSTXT_PHASE_BEFORE_USER_AGENT)
  {
    static_addIssue(robots, ROBOTSTXT_ISSUE_RULE_BEFORE_USER_AGENT, directive, line_number);
    return true;
  }
  if (!static_tryCloseUserAgentList(state))
    return false;
  RobotsTxtGroup_t* group = static_findCurrentGroup(state);
  if (group == NULL || value_len == 0)
    return true;

  robots->m_ruleTotalCount++;
  if (robots->m_ruleKeptCount >= ROBOTSTXT_MAX_RULE_COUNT)
  {
    robots->m_hasDroppedRule = true;
    static_addIssueOnce(state, ROBOTSTXT_ISSUE_TOO_MANY_RULES, line_number);
    return true;
  }

  RobotsTxtRule_t* rules = static_reserveSlot(robots->mp_rules, &state->m_ruleCapacity, robots->m_ruleKeptCount, ROBOTSTXT_MAX_RULE_COUNT, sizeof(RobotsTxtRule_t));
  if (rules == NULL)
    return false;
  robots->mp_rules = rules;

  RobotsTxtRule_t* rule = &rules[robots->m_ruleKeptCount];
  rule->m_kind    = directive == ROBOTSTXT_DIRECTIVE_ALLOW ? ROBOTSTXT_RULE_ALLOW : ROBOTSTXT_RULE_DISALLOW;
  rule->m_pattern = (RobotsTxtSpan_t){ value_offset, value_len, line_number };
  robots->m_ruleKeptCount++;
  group->m_ruleCount++;

  return true;
}

static bool static_tryReadCrawlDelayLine(RobotsTxtParseState_t* state, size_t value_offset, size_t value_len, int line_number)
{
  RobotsTxt_t* robots = state->mp_robots;

  if (state->m_phase == ROBOTSTXT_PHASE_BEFORE_USER_AGENT)
  {
    static_addIssue(robots, ROBOTSTXT_ISSUE_RULE_BEFORE_USER_AGENT, ROBOTSTXT_DIRECTIVE_CRAWL_DELAY, line_number);
    return true;
  }
  if (!static_tryCloseUserAgentList(state))
    return false;

  double seconds = 0.0;
  if (!static_tryReadCrawlDelaySeconds(state->mp_body + value_offset, value_len, &seconds))
  {
    static_addIssue(robots, ROBOTSTXT_ISSUE_CRAWL_DELAY_INVALID, ROBOTSTXT_DIRECTIVE_CRAWL_DELAY, line_number);
    return true;
  }
  RobotsTxtGroup_t* group = static_findCurrentGroup(state);
  if (group != NULL)
  {
    group->m_hasCrawlDelay     = true;
    group->m_crawlDelaySeconds = seconds;
  }

  return true;
}

static bool static_tryReadSitemapLine(RobotsTxtParseState_t* state, size_t value_offset, size_t value_len, int line_number)
{
  RobotsTxt_t* robots = state->mp_robots;
  const char*  value  = state->mp_body + value_offset;

  robots->m_sitemapTotalCount++;
  bool is_http  = bytes_hasPrefix(value, value_len, "http://", strlen("http://"), true);
  bool is_https = bytes_hasPrefix(value, value_len, "https://", strlen("https://"), true);
  if (!is_http && !is_https)
    static_addIssue(robots, ROBOTSTXT_ISSUE_SITEMAP_NOT_ABSOLUTE, ROBOTSTXT_DIRECTIVE_SITEMAP, line_number);

  if (robots->m_sitemapKeptCount >= ROBOTSTXT_MAX_SITEMAP_COUNT)
  {
    static_addIssueOnce(state, ROBOTSTXT_ISSUE_TOO_MANY_SITEMAPS, line_number);
    return true;
  }
  RobotsTxtSpan_t* sitemaps = static_reserveSlot(robots->mp_sitemaps, &state->m_sitemapCapacity, robots->m_sitemapKeptCount, ROBOTSTXT_MAX_SITEMAP_COUNT, sizeof(RobotsTxtSpan_t));
  if (sitemaps == NULL)
    return false;
  robots->mp_sitemaps = sitemaps;
  sitemaps[robots->m_sitemapKeptCount] = (RobotsTxtSpan_t){ value_offset, value_len, line_number };
  robots->m_sitemapKeptCount++;

  return true;
}

static bool static_tryReadCrawlDelaySeconds(const char* text, size_t len, double* seconds_out)
{
  size_t position = 0;
  long   whole    = 0;
  while (position < len && isdigit((unsigned char)text[position]))
  {
    if (whole <= ROBOTSTXT_MAX_CRAWL_DELAY_SECONDS)
      whole = whole * 10 + (text[position] - '0');
    position++;
  }
  if (position == 0)
    return false;

  long numerator             = 0;
  long denominator           = 1;
  bool has_nonzero_fraction  = false;
  if (position < len && text[position] == '.')
  {
    position++;
    size_t first_fraction_digit = position;
    while (position < len && isdigit((unsigned char)text[position]))
    {
      if (text[position] != '0')
        has_nonzero_fraction = true;
      if (position - first_fraction_digit < ROBOTSTXT_MAX_FRACTION_DIGIT_COUNT)
      {
        numerator   = numerator * 10 + (text[position] - '0');
        denominator = denominator * 10;
      }
      position++;
    }
    if (position == first_fraction_digit)
      return false;
  }
  if (position != len)
    return false;
  if (whole > ROBOTSTXT_MAX_CRAWL_DELAY_SECONDS || (whole == ROBOTSTXT_MAX_CRAWL_DELAY_SECONDS && has_nonzero_fraction))
    return false;

  *seconds_out = (double)whole + (double)numerator / (double)denominator;
  return true;
}

static void* static_reserveSlot(void* items, int* capacity, int count, int max_count, size_t item_size)
{
  assert(count < max_count);

  if (count < *capacity)
    return items;

  int new_capacity = *capacity == 0 ? ROBOTSTXT_INITIAL_ARRAY_CAPACITY : *capacity * 2;
  if (new_capacity > max_count)
    new_capacity = max_count;

  void* grown = realloc(items, (size_t)new_capacity * item_size);
  if (grown == NULL)
    return NULL;

  *capacity = new_capacity;
  return grown;
}

static void static_addIssue(RobotsTxt_t* robots, RobotsTxtIssueCode_t issue_code, RobotsTxtDirective_t field, int line_number)
{
  robots->m_issueTotalCount++;
  robots->ma_issueCountBySeverity[ISSUES[issue_code].m_severity]++;
  if (robots->m_issueKeptCount >= ROBOTSTXT_MAX_ISSUE_COUNT)
    return;
  robots->ma_issues[robots->m_issueKeptCount] = (RobotsTxtIssue_t){ issue_code, field, line_number };
  robots->m_issueKeptCount++;
}

static void static_addIssueOnce(RobotsTxtParseState_t* state, RobotsTxtIssueCode_t issue_code, int line_number)
{
  if (state->ma_isIssueRaised[issue_code])
    return;
  state->ma_isIssueRaised[issue_code] = true;
  static_addIssue(state->mp_robots, issue_code, ROBOTSTXT_DIRECTIVE_NONE, line_number);
}

static bool static_isRuleStronger(const RobotsTxtRule_t* rule, const RobotsTxtRule_t* best_rule)
{
  if (rule->m_pattern.m_len != best_rule->m_pattern.m_len)
    return rule->m_pattern.m_len > best_rule->m_pattern.m_len;

  return rule->m_kind == ROBOTSTXT_RULE_ALLOW && best_rule->m_kind == ROBOTSTXT_RULE_DISALLOW;
}

static bool static_isPatternMatching(const char* pattern, size_t pattern_len, const char* path, size_t path_len)
{
  bool   is_anchored = pattern_len > 0 && pattern[pattern_len - 1] == '$';
  size_t pattern_end = is_anchored ? pattern_len - 1 : pattern_len;

  size_t pattern_position      = 0;
  size_t path_position         = 0;
  bool   has_star              = false;
  size_t star_pattern_position = 0;
  size_t star_path_position    = 0;
  for (;;)
  {
    if (pattern_position < pattern_end && pattern[pattern_position] == '*')
    {
      pattern_position++;
      has_star              = true;
      star_pattern_position = pattern_position;
      star_path_position    = path_position;
      continue;
    }
    if (pattern_position == pattern_end && (!is_anchored || path_position == path_len))
      return true;
    if (pattern_position < pattern_end && path_position < path_len)
    {
      RobotsTxtUnit_t pattern_unit = static_readUnit(pattern, pattern_end, pattern_position);
      RobotsTxtUnit_t path_unit    = static_readUnit(path, path_len, path_position);
      if (pattern_unit.m_byte == path_unit.m_byte)
      {
        pattern_position += pattern_unit.m_len;
        path_position    += path_unit.m_len;
        continue;
      }
    }

    if (!has_star || star_path_position >= path_len)
      return false;
    star_path_position += static_readUnit(path, path_len, star_path_position).m_len;
    path_position       = star_path_position;
    pattern_position    = star_pattern_position;
  }
}

static RobotsTxtUnit_t static_readUnit(const char* text, size_t len, size_t position)
{
  RobotsTxtUnit_t unit = { (unsigned char)text[position], 1 };
  if (text[position] != '%' || position + 2 >= len)
    return unit;

  int high_value = bytes_hexDigitValue(text[position + 1]);
  int low_value  = bytes_hexDigitValue(text[position + 2]);
  if (high_value < 0 || low_value < 0)
    return unit;

  unit.m_byte = (unsigned char)(high_value * 16 + low_value);
  unit.m_len  = 3;

  return unit;
}

static bool static_isTextPlain(const char* content_type)
{
  if (content_type == NULL)
    return false;
  size_t end   = strcspn(content_type, ";");
  size_t start = static_skipBlanks(content_type, 0, end);
  end = static_trimBlanksAtEnd(content_type, start, end);
  return bytes_isEqual(content_type + start, end - start, "text/plain", true);
}

static size_t static_skipBlanks(const char* text, size_t start, size_t end)
{
  while (start < end && isblank((unsigned char)text[start]))
    start++;
  return start;
}

static size_t static_trimBlanksAtEnd(const char* text, size_t start, size_t end)
{
  while (end > start && isblank((unsigned char)text[end - 1]))
    end--;
  return end;
}

static bool static_isOurProductToken(const RobotsTxtParseState_t* state, const char* value, size_t value_len)
{
  size_t name_len = 0;
  while (name_len < value_len && (isalnum((unsigned char)value[name_len]) || value[name_len] == '_' || value[name_len] == '-'))
    name_len++;
  return bytes_isEqual(value, name_len, state->mp_productToken, true);
}
