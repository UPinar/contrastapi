#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity/unity.h"
#include "robotstxt.h"

#define PRODUCT_TOKEN "ContrastAPI"

void* __wrap_realloc(void* ptr, size_t size);

static int    g_reallocFailAt      = 0;
static int    g_reallocCallCount   = 0;
static size_t g_largestReallocSize = 0;

void* __wrap_realloc(void* ptr, size_t size)
{
  g_reallocCallCount++;
  if (size > g_largestReallocSize)
    g_largestReallocSize = size;
  if (g_reallocCallCount == g_reallocFailAt)
    return NULL;
  char* grown = malloc(size);
  if (grown == NULL)
    return NULL;
  memset(grown, 0xA5, size);
  if (ptr != NULL)
  {
    size_t old_size = malloc_usable_size(ptr);
    memcpy(grown, ptr, old_size < size ? old_size : size);
    free(ptr);
  }
  return grown;
}

static RobotsTxt_t g_robots;
static char*       g_builtBody = NULL;

void setUp(void)
{
  g_reallocFailAt      = 0;
  g_reallocCallCount   = 0;
  g_largestReallocSize = 0;
}

void tearDown(void)
{
  robotstxt_free(&g_robots);
  free(g_builtBody);
  g_builtBody = NULL;
}

static void static_parseBytes(const char* body, size_t body_len, bool is_body_cut)
{
  robotstxt_free(&g_robots);
  TEST_ASSERT_TRUE(robotstxt_parse(body, body_len, is_body_cut, PRODUCT_TOKEN, &g_robots));
}

static void static_parse(const char* body)
{
  static_parseBytes(body, strlen(body), false);
}

static const char* static_buildBody(const char* head, const char* line, int count, const char* tail)
{
  free(g_builtBody);
  size_t head_len = strlen(head);
  size_t line_len = strlen(line);
  size_t tail_len = strlen(tail);
  g_builtBody = malloc(head_len + line_len * (size_t)count + tail_len + 1);
  TEST_ASSERT_NOT_NULL(g_builtBody);
  char* cursor = g_builtBody;
  memcpy(cursor, head, head_len);
  cursor += head_len;
  for (int i = 0; i < count; i++)
  {
    memcpy(cursor, line, line_len);
    cursor += line_len;
  }
  memcpy(cursor, tail, tail_len + 1);
  return g_builtBody;
}

static const char* static_buildLongLine(const char* head, size_t line_len, const char* tail)
{
  free(g_builtBody);
  size_t head_len = strlen(head);
  size_t tail_len = strlen(tail);
  g_builtBody = malloc(head_len + line_len + tail_len + 1);
  TEST_ASSERT_NOT_NULL(g_builtBody);
  memcpy(g_builtBody, head, head_len);
  memset(g_builtBody + head_len, 'a', line_len);
  memcpy(g_builtBody + head_len + line_len, tail, tail_len + 1);
  return g_builtBody;
}

static void static_assertIssue(int index, RobotsTxtIssueCode_t issue_code, RobotsTxtDirective_t field, int line)
{
  TEST_ASSERT_TRUE(index < g_robots.m_issueKeptCount);
  TEST_ASSERT_EQUAL_STRING(robotstxt_issueCodeName(issue_code), robotstxt_issueCodeName(g_robots.ma_issues[index].m_issueCode));
  TEST_ASSERT_EQUAL_INT(field, g_robots.ma_issues[index].m_field);
  TEST_ASSERT_EQUAL_INT(line, g_robots.ma_issues[index].m_lineNumber);
}

static void static_assertSpan(RobotsTxtSpan_t span, size_t offset, size_t len, int line)
{
  TEST_ASSERT_EQUAL_size_t(offset, span.m_offset);
  TEST_ASSERT_EQUAL_size_t(len, span.m_len);
  TEST_ASSERT_EQUAL_INT(line, span.m_lineNumber);
}

static void static_assertGroup(int index, int line, bool has_our_user_agent, bool has_wildcard_user_agent, int first_user_agent, int user_agent_count, int first_rule, int rule_count)
{
  TEST_ASSERT_TRUE(index < g_robots.m_groupKeptCount);
  const RobotsTxtGroup_t* group = &g_robots.mp_groups[index];
  TEST_ASSERT_EQUAL_INT(line, group->m_lineNumber);
  TEST_ASSERT_EQUAL(has_our_user_agent, group->m_hasOurUserAgent);
  TEST_ASSERT_EQUAL(has_wildcard_user_agent, group->m_hasWildcardUserAgent);
  TEST_ASSERT_EQUAL_INT(first_user_agent, group->m_firstUserAgent);
  TEST_ASSERT_EQUAL_INT(user_agent_count, group->m_userAgentCount);
  TEST_ASSERT_EQUAL_INT(first_rule, group->m_firstRule);
  TEST_ASSERT_EQUAL_INT(rule_count, group->m_ruleCount);
}

static void static_assertRule(int index, RobotsTxtRuleKind_t kind, size_t offset, size_t len, int line)
{
  TEST_ASSERT_TRUE(index < g_robots.m_ruleKeptCount);
  TEST_ASSERT_EQUAL_INT(kind, g_robots.mp_rules[index].m_kind);
  static_assertSpan(g_robots.mp_rules[index].m_pattern, offset, len, line);
}

static void static_assertCounts(int group_count, int group_total, int rule_count, int rule_total, int user_agent_count, int user_agent_total)
{
  TEST_ASSERT_EQUAL_INT(group_count, g_robots.m_groupKeptCount);
  TEST_ASSERT_EQUAL_INT(group_total, g_robots.m_groupTotalCount);
  TEST_ASSERT_EQUAL_INT(rule_count, g_robots.m_ruleKeptCount);
  TEST_ASSERT_EQUAL_INT(rule_total, g_robots.m_ruleTotalCount);
  TEST_ASSERT_EQUAL_INT(user_agent_count, g_robots.m_userAgentKeptCount);
  TEST_ASSERT_EQUAL_INT(user_agent_total, g_robots.m_userAgentTotalCount);
}

static void static_assertVerdict(const char* path, RobotsTxtDecision_t decision, int rule_index)
{
  RobotsTxtVerdict_t verdict = robotstxt_checkPath(&g_robots, g_builtBody, path, strlen(path));
  TEST_ASSERT_EQUAL_INT_MESSAGE(decision, verdict.m_decision, path);
  TEST_ASSERT_EQUAL_INT_MESSAGE(rule_index, verdict.m_decidingRuleIndex, path);
}

static void static_assertVerdictIn(const char* body, const char* path, RobotsTxtDecision_t decision, int rule_index)
{
  RobotsTxtVerdict_t verdict = robotstxt_checkPath(&g_robots, body, path, strlen(path));
  TEST_ASSERT_EQUAL_INT_MESSAGE(decision, verdict.m_decision, path);
  TEST_ASSERT_EQUAL_INT_MESSAGE(rule_index, verdict.m_decidingRuleIndex, path);
}

static bool static_isPatternMatchingBytes(const char* pattern, const char* path, size_t path_len)
{
  char body[512];
  int body_len = snprintf(body, sizeof(body), "User-agent: *\nDisallow: %s\n", pattern);
  TEST_ASSERT_TRUE(body_len > 0 && (size_t)body_len < sizeof(body));
  robotstxt_free(&g_robots);
  TEST_ASSERT_TRUE(robotstxt_parse(body, (size_t)body_len, false, PRODUCT_TOKEN, &g_robots));
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_ruleKeptCount);
  RobotsTxtVerdict_t verdict = robotstxt_checkPath(&g_robots, body, path, path_len);
  return verdict.m_decision == ROBOTSTXT_DECISION_DISALLOWED;
}

static bool static_isPatternMatching(const char* pattern, const char* path)
{
  return static_isPatternMatchingBytes(pattern, path, strlen(path));
}

#define ASSERT_MATCHES(pattern, path)     TEST_ASSERT_TRUE_MESSAGE(static_isPatternMatching(pattern, path), pattern " ~ " path)
#define ASSERT_NOT_MATCHES(pattern, path) TEST_ASSERT_FALSE_MESSAGE(static_isPatternMatching(pattern, path), pattern " !~ " path)

static void static_assertZeroed(const RobotsTxt_t* robots)
{
  RobotsTxt_t zero = { 0 };
  TEST_ASSERT_EQUAL_MEMORY(&zero, robots, sizeof(zero));
}

void test_caps_hold_their_values(void)
{
  TEST_ASSERT_EQUAL_INT(524288, ROBOTSTXT_MAX_BODY_BYTE_COUNT);
  TEST_ASSERT_EQUAL_INT(2048, ROBOTSTXT_MAX_LINE_BYTE_COUNT);
  TEST_ASSERT_EQUAL_INT(1024, ROBOTSTXT_MAX_GROUP_COUNT);
  TEST_ASSERT_EQUAL_INT(16384, ROBOTSTXT_MAX_RULE_COUNT);
  TEST_ASSERT_EQUAL_INT(1024, ROBOTSTXT_MAX_USER_AGENT_COUNT);
  TEST_ASSERT_EQUAL_INT(100, ROBOTSTXT_MAX_SITEMAP_COUNT);
  TEST_ASSERT_EQUAL_INT(50, ROBOTSTXT_MAX_ISSUE_COUNT);
}

void test_each_issue_code_has_its_name_and_severity(void)
{
  static const struct
  {
    RobotsTxtIssueCode_t m_issueCode;
    const char*          mp_name;
    RobotsTxtSeverity_t  m_severity;
  } ROWS[] = {
    { ROBOTSTXT_ISSUE_FILE_TOO_LARGE,              "file_too_large",              ROBOTSTXT_SEVERITY_WARNING },
    { ROBOTSTXT_ISSUE_BYTE_ORDER_MARK,             "byte_order_mark",             ROBOTSTXT_SEVERITY_INFO    },
    { ROBOTSTXT_ISSUE_INVALID_UTF8,                "invalid_utf8",                ROBOTSTXT_SEVERITY_WARNING },
    { ROBOTSTXT_ISSUE_CONTAINS_NUL_BYTE,           "contains_nul_byte",           ROBOTSTXT_SEVERITY_WARNING },
    { ROBOTSTXT_ISSUE_LINE_TOO_LONG,               "line_too_long",               ROBOTSTXT_SEVERITY_WARNING },
    { ROBOTSTXT_ISSUE_LINE_SYNTAX_INVALID,         "line_syntax_invalid",         ROBOTSTXT_SEVERITY_INFO    },
    { ROBOTSTXT_ISSUE_RULE_BEFORE_USER_AGENT,      "rule_before_user_agent",      ROBOTSTXT_SEVERITY_WARNING },
    { ROBOTSTXT_ISSUE_EMPTY_USER_AGENT,            "empty_user_agent",            ROBOTSTXT_SEVERITY_INFO    },
    { ROBOTSTXT_ISSUE_UNKNOWN_DIRECTIVE,           "unknown_directive",           ROBOTSTXT_SEVERITY_INFO    },
    { ROBOTSTXT_ISSUE_CRAWL_DELAY_INVALID,         "crawl_delay_invalid",         ROBOTSTXT_SEVERITY_INFO    },
    { ROBOTSTXT_ISSUE_SITEMAP_NOT_ABSOLUTE,        "sitemap_not_absolute",        ROBOTSTXT_SEVERITY_INFO    },
    { ROBOTSTXT_ISSUE_TOO_MANY_GROUPS,             "too_many_groups",             ROBOTSTXT_SEVERITY_WARNING },
    { ROBOTSTXT_ISSUE_TOO_MANY_RULES,              "too_many_rules",              ROBOTSTXT_SEVERITY_WARNING },
    { ROBOTSTXT_ISSUE_TOO_MANY_USER_AGENTS,        "too_many_user_agents",        ROBOTSTXT_SEVERITY_WARNING },
    { ROBOTSTXT_ISSUE_TOO_MANY_SITEMAPS,           "too_many_sitemaps",           ROBOTSTXT_SEVERITY_WARNING },
    { ROBOTSTXT_ISSUE_REDIRECTED_TO_OTHER_HOST,    "redirected_to_other_host",    ROBOTSTXT_SEVERITY_INFO    },
    { ROBOTSTXT_ISSUE_CONTENT_TYPE_NOT_TEXT_PLAIN, "content_type_not_text_plain", ROBOTSTXT_SEVERITY_INFO    },
  };
  TEST_ASSERT_EQUAL_INT(ROBOTSTXT_ISSUE_CODE_COUNT, (int)(sizeof(ROWS) / sizeof(ROWS[0])));
  for (size_t i = 0; i < sizeof(ROWS) / sizeof(ROWS[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT((int)i, ROWS[i].m_issueCode);
    TEST_ASSERT_EQUAL_STRING(ROWS[i].mp_name, robotstxt_issueCodeName(ROWS[i].m_issueCode));
    TEST_ASSERT_EQUAL_INT_MESSAGE(ROWS[i].m_severity, robotstxt_issueSeverity(ROWS[i].m_issueCode), ROWS[i].mp_name);
  }
}

void test_severity_and_directive_names(void)
{
  TEST_ASSERT_EQUAL_STRING("warning", robotstxt_severityName(ROBOTSTXT_SEVERITY_WARNING));
  TEST_ASSERT_EQUAL_STRING("info", robotstxt_severityName(ROBOTSTXT_SEVERITY_INFO));
  TEST_ASSERT_NULL(robotstxt_directiveName(ROBOTSTXT_DIRECTIVE_NONE));
  TEST_ASSERT_EQUAL_STRING("user-agent", robotstxt_directiveName(ROBOTSTXT_DIRECTIVE_USER_AGENT));
  TEST_ASSERT_EQUAL_STRING("allow", robotstxt_directiveName(ROBOTSTXT_DIRECTIVE_ALLOW));
  TEST_ASSERT_EQUAL_STRING("disallow", robotstxt_directiveName(ROBOTSTXT_DIRECTIVE_DISALLOW));
  TEST_ASSERT_EQUAL_STRING("crawl-delay", robotstxt_directiveName(ROBOTSTXT_DIRECTIVE_CRAWL_DELAY));
  TEST_ASSERT_EQUAL_STRING("sitemap", robotstxt_directiveName(ROBOTSTXT_DIRECTIVE_SITEMAP));
}

void test_null_and_empty_body_are_an_empty_file(void)
{
  static_parseBytes(NULL, 0, false);
  static_assertZeroed(&g_robots);
  static_parseBytes("", 0, false);
  static_assertZeroed(&g_robots);
}

void test_our_user_agent_group_is_kept_with_its_user_agent_and_rules(void)
{
  static_parse("User-agent: ContrastAPI\nDisallow: /private\nAllow: /private/pub\n");
  static_assertCounts(1, 1, 2, 2, 1, 1);
  static_assertGroup(0, 1, true, false, 0, 1, 0, 2);
  TEST_ASSERT_FALSE(g_robots.mp_groups[0].m_hasCrawlDelay);
  static_assertSpan(g_robots.mp_userAgents[0], 12, 11, 1);
  static_assertRule(0, ROBOTSTXT_RULE_DISALLOW, 34, 8, 2);
  static_assertRule(1, ROBOTSTXT_RULE_ALLOW, 50, 12, 3);
  TEST_ASSERT_FALSE(g_robots.m_hasDroppedRule);
  TEST_ASSERT_EQUAL_INT(0, g_robots.m_issueTotalCount);
  TEST_ASSERT_EQUAL_INT(0, g_robots.m_sitemapTotalCount);
}

void test_group_of_another_crawler_is_not_kept(void)
{
  static_parse("User-agent: Googlebot\nDisallow: /\nUser-agent: *\nDisallow: /tmp\n");
  static_assertCounts(1, 1, 1, 1, 1, 1);
  static_assertGroup(0, 3, false, true, 0, 1, 0, 1);
  static_assertSpan(g_robots.mp_userAgents[0], 46, 1, 3);
  static_assertRule(0, ROBOTSTXT_RULE_DISALLOW, 58, 4, 4);
}

void test_groups_index_their_own_values_and_rules(void)
{
  static_parse("User-agent: *\nUser-agent: a-bot\nDisallow: /a\nUser-agent: ContrastAPI\nAllow: /b\nAllow: /c\n");
  static_assertCounts(2, 2, 3, 3, 3, 3);
  static_assertGroup(0, 1, false, true, 0, 2, 0, 1);
  static_assertGroup(1, 4, true, false, 2, 1, 1, 2);
  static_assertSpan(g_robots.mp_userAgents[0], 12, 1, 1);
  static_assertSpan(g_robots.mp_userAgents[1], 26, 5, 2);
  static_assertSpan(g_robots.mp_userAgents[2], 57, 11, 4);
  static_assertRule(0, ROBOTSTXT_RULE_DISALLOW, 42, 2, 3);
  static_assertRule(1, ROBOTSTXT_RULE_ALLOW, 76, 2, 5);
  static_assertRule(2, ROBOTSTXT_RULE_ALLOW, 86, 2, 6);
}

void test_user_agent_matches_the_token_exactly_in_any_case(void)
{
  static_parse("User-agent: CONTRASTAPI/1.0\nDisallow: /a\n");
  static_assertGroup(0, 1, true, false, 0, 1, 0, 1);
  static_parse("User-agent: contrastapi\nDisallow: /a\n");
  static_assertGroup(0, 1, true, false, 0, 1, 0, 1);

  const char* OTHERS[] = { "Api", "Contrast", "a", "my-ContrastAPI", "ContrastAPI_", "ContrastAPI-bot", "ContrastAPI2", "ContrastAPI0", "ContrastAPI9", "ContrastAPIx", "contrastapx", "*x", "x" };
  for (size_t i = 0; i < sizeof(OTHERS) / sizeof(OTHERS[0]); i++)
  {
    char body[64];
    snprintf(body, sizeof(body), "User-agent: %s\nDisallow: /a\n", OTHERS[i]);
    static_parse(body);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_robots.m_groupKeptCount, OTHERS[i]);
  }

  const char* NAMED[] = { "ContrastAPI.x", "ContrastAPI bot" };
  for (size_t i = 0; i < sizeof(NAMED) / sizeof(NAMED[0]); i++)
  {
    char body[64];
    snprintf(body, sizeof(body), "User-agent: %s\nDisallow: /a\n", NAMED[i]);
    static_parse(body);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_robots.m_groupKeptCount, NAMED[i]);
    TEST_ASSERT_TRUE_MESSAGE(g_robots.mp_groups[0].m_hasOurUserAgent, NAMED[i]);
  }
  const char longer[] = "User-agent: ContrastAPI2\n";
  static_parseBytes(longer, strlen("User-agent: ContrastAPI"), false);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_groupKeptCount);
  TEST_ASSERT_TRUE(g_robots.mp_groups[0].m_hasOurUserAgent);

  const char* shorter = "User-agent: *\nDisallow: /\nUser-agent: Contrast\nDisallow: /tmp\n";
  static_parse(shorter);
  static_assertVerdictIn(shorter, "/x", ROBOTSTXT_DECISION_DISALLOWED, 0);
}

void test_product_token_letters_a_to_z_match_in_any_case(void)
{
  const char* body = "User-agent: az-BOT\nDisallow: /a\n";
  robotstxt_free(&g_robots);
  TEST_ASSERT_TRUE(robotstxt_parse(body, strlen(body), false, "AZ-bot", &g_robots));
  static_assertGroup(0, 1, true, false, 0, 1, 0, 1);
}

void test_empty_user_agent_binds_nothing_and_raises_an_issue(void)
{
  static_parse("User-agent:\nDisallow: /\n");
  static_assertCounts(0, 0, 0, 0, 0, 0);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_EMPTY_USER_AGENT, ROBOTSTXT_DIRECTIVE_USER_AGENT, 1);

  static_parse("User-agent: *\nUser-agent: \t\nDisallow: /a\n");
  static_assertCounts(1, 1, 1, 1, 1, 1);
  static_assertGroup(0, 1, false, true, 0, 1, 0, 1);
  static_assertIssue(0, ROBOTSTXT_ISSUE_EMPTY_USER_AGENT, ROBOTSTXT_DIRECTIVE_USER_AGENT, 2);
}

void test_user_agent_after_any_rule_opens_a_new_group(void)
{
  static_parse("User-agent: *\nCrawl-delay: 5\nUser-agent: ContrastAPI\nDisallow: /c\n");
  static_assertCounts(2, 2, 1, 1, 2, 2);
  static_assertGroup(0, 1, false, true, 0, 1, 0, 0);
  static_assertGroup(1, 3, true, false, 1, 1, 0, 1);

  static_parse("User-agent: *\nDisallow:\nUser-agent: ContrastAPI\nAllow: /a\n");
  static_assertCounts(2, 2, 1, 1, 2, 2);
  static_assertGroup(0, 1, false, true, 0, 1, 0, 0);
  static_assertGroup(1, 3, true, false, 1, 1, 0, 1);
}

void test_sitemap_and_unknown_directive_do_not_close_the_user_agent_list(void)
{
  static_parse("User-agent: Googlebot\nSitemap: https://e.com/s.xml\nHost: e.com\nUser-agent: *\nDisallow: /p\n");
  static_assertCounts(1, 1, 1, 1, 2, 2);
  static_assertGroup(0, 1, false, true, 0, 2, 0, 1);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_sitemapKeptCount);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_UNKNOWN_DIRECTIVE, ROBOTSTXT_DIRECTIVE_NONE, 3);
}

void test_rule_before_any_user_agent_is_ignored_and_raises_its_issue(void)
{
  static_parse("Disallow: /a\nAllow: /b\nCrawl-delay: 1\nUser-agent: *\nDisallow: /c\n");
  static_assertCounts(1, 1, 1, 1, 1, 1);
  static_assertGroup(0, 4, false, true, 0, 1, 0, 1);
  TEST_ASSERT_FALSE(g_robots.mp_groups[0].m_hasCrawlDelay);
  TEST_ASSERT_EQUAL_INT(3, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_RULE_BEFORE_USER_AGENT, ROBOTSTXT_DIRECTIVE_DISALLOW, 1);
  static_assertIssue(1, ROBOTSTXT_ISSUE_RULE_BEFORE_USER_AGENT, ROBOTSTXT_DIRECTIVE_ALLOW, 2);
  static_assertIssue(2, ROBOTSTXT_ISSUE_RULE_BEFORE_USER_AGENT, ROBOTSTXT_DIRECTIVE_CRAWL_DELAY, 3);
  TEST_ASSERT_EQUAL_INT(3, g_robots.ma_issueCountBySeverity[ROBOTSTXT_SEVERITY_WARNING]);
  TEST_ASSERT_EQUAL_INT(0, g_robots.ma_issueCountBySeverity[ROBOTSTXT_SEVERITY_INFO]);
}

void test_empty_rule_is_not_kept(void)
{
  static_parse("User-agent: *\nDisallow:  \nAllow: /a\n");
  static_assertCounts(1, 1, 1, 1, 1, 1);
  static_assertRule(0, ROBOTSTXT_RULE_ALLOW, 33, 2, 3);
  TEST_ASSERT_EQUAL_INT(0, g_robots.m_issueTotalCount);
}

void test_comments_blanks_and_name_case_are_ignored(void)
{
  static_parse("  User-agent :\t ContrastAPI # our bot\n# full: comment\n\n\t\nDISALLOW: /a#frag\nuSeR-aGeNt: *\n");
  static_assertCounts(2, 2, 1, 1, 2, 2);
  static_assertSpan(g_robots.mp_userAgents[0], 16, 11, 1);
  static_assertRule(0, ROBOTSTXT_RULE_DISALLOW, 67, 2, 5);
  static_assertSpan(g_robots.mp_userAgents[1], 87, 1, 6);
  TEST_ASSERT_EQUAL_INT(0, g_robots.m_issueTotalCount);
}

void test_line_without_colon_is_syntax_invalid(void)
{
  static_parse("User-agent *\nDisallow /a # x: y\n");
  static_assertCounts(0, 0, 0, 0, 0, 0);
  TEST_ASSERT_EQUAL_INT(2, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_LINE_SYNTAX_INVALID, ROBOTSTXT_DIRECTIVE_NONE, 1);
  static_assertIssue(1, ROBOTSTXT_ISSUE_LINE_SYNTAX_INVALID, ROBOTSTXT_DIRECTIVE_NONE, 2);
  TEST_ASSERT_EQUAL_INT(2, g_robots.ma_issueCountBySeverity[ROBOTSTXT_SEVERITY_INFO]);
}

void test_unknown_and_empty_names_are_unknown_directives(void)
{
  static_parse("Useragent: *\n: /a\nAllowance: /b\n");
  TEST_ASSERT_EQUAL_INT(3, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_UNKNOWN_DIRECTIVE, ROBOTSTXT_DIRECTIVE_NONE, 1);
  static_assertIssue(1, ROBOTSTXT_ISSUE_UNKNOWN_DIRECTIVE, ROBOTSTXT_DIRECTIVE_NONE, 2);
  static_assertIssue(2, ROBOTSTXT_ISSUE_UNKNOWN_DIRECTIVE, ROBOTSTXT_DIRECTIVE_NONE, 3);
}

void test_lf_cr_and_crlf_end_a_line(void)
{
  static_parse("User-agent: *\rDisallow: /a\r\nAllow: /b\nSitemap: http://x\n\rDisallow: /c");
  static_assertCounts(1, 1, 3, 3, 1, 1);
  static_assertRule(0, ROBOTSTXT_RULE_DISALLOW, 24, 2, 2);
  static_assertRule(1, ROBOTSTXT_RULE_ALLOW, 35, 2, 3);
  static_assertSpan(g_robots.mp_sitemaps[0], 47, 8, 4);
  static_assertRule(2, ROBOTSTXT_RULE_DISALLOW, 67, 2, 6);
}

void test_byte_order_mark_is_skipped(void)
{
  static_parse("\xEF\xBB\xBFUser-agent: *\nDisallow: /a\n");
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_BYTE_ORDER_MARK, ROBOTSTXT_DIRECTIVE_NONE, 0);
  static_assertGroup(0, 1, false, true, 0, 1, 0, 1);
  static_assertSpan(g_robots.mp_userAgents[0], 15, 1, 1);

  static_parse("\xEF\xBB\xBF");
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_BYTE_ORDER_MARK, ROBOTSTXT_DIRECTIVE_NONE, 0);

  static_parse("\xEF\xBB");
  TEST_ASSERT_EQUAL_INT(2, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_INVALID_UTF8, ROBOTSTXT_DIRECTIVE_NONE, 0);
  static_assertIssue(1, ROBOTSTXT_ISSUE_LINE_SYNTAX_INVALID, ROBOTSTXT_DIRECTIVE_NONE, 1);
}

void test_cut_body_drops_the_partial_last_line(void)
{
  const char* body = "User-agent: *\nDisallow: /a\nDisallow: /b";
  static_parseBytes(body, strlen(body), true);
  static_assertCounts(1, 1, 1, 1, 1, 1);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_FILE_TOO_LARGE, ROBOTSTXT_DIRECTIVE_NONE, 0);
  TEST_ASSERT_EQUAL_INT(1, g_robots.ma_issueCountBySeverity[ROBOTSTXT_SEVERITY_WARNING]);

  const char* bom_body = "\xEF\xBB\xBF" "User-agent: *";
  static_parseBytes(bom_body, strlen(bom_body), true);
  TEST_ASSERT_EQUAL_INT(0, g_robots.m_groupKeptCount);
  TEST_ASSERT_EQUAL_INT(2, g_robots.m_issueKeptCount);
  static_assertIssue(1, ROBOTSTXT_ISSUE_BYTE_ORDER_MARK, ROBOTSTXT_DIRECTIVE_NONE, 0);
}

void test_cut_body_keeps_lines_up_to_the_last_end(void)
{
  const char* lf_body = "User-agent: *\nDisallow: /a\nDisallow: /b\n";
  static_parseBytes(lf_body, strlen(lf_body), true);
  static_assertCounts(1, 1, 2, 2, 1, 1);
  static_assertIssue(0, ROBOTSTXT_ISSUE_FILE_TOO_LARGE, ROBOTSTXT_DIRECTIVE_NONE, 0);

  const char* cr_body = "User-agent: *\nDisallow: /a\r";
  static_parseBytes(cr_body, strlen(cr_body), true);
  static_assertCounts(1, 1, 1, 1, 1, 1);
  static_assertRule(0, ROBOTSTXT_RULE_DISALLOW, 24, 2, 2);

  const char* no_end_body = "User-agent: *";
  static_parseBytes(no_end_body, strlen(no_end_body), true);
  static_assertCounts(0, 0, 0, 0, 0, 0);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_FILE_TOO_LARGE, ROBOTSTXT_DIRECTIVE_NONE, 0);
}

void test_nul_byte_is_an_ordinary_byte_and_raises_an_issue(void)
{
  static const char BODY[] = "User-agent: *\nDisallow: /a\0b\nAllow: /c\n";
  static_parseBytes(BODY, sizeof(BODY) - 1, false);
  static_assertCounts(1, 1, 2, 2, 1, 1);
  static_assertRule(0, ROBOTSTXT_RULE_DISALLOW, 24, 4, 2);
  static_assertRule(1, ROBOTSTXT_RULE_ALLOW, 36, 2, 3);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_CONTAINS_NUL_BYTE, ROBOTSTXT_DIRECTIVE_NONE, 0);

  static const char CUT_BODY[] = "User-agent: *\nDisallow: /a\n\0";
  static_parseBytes(CUT_BODY, sizeof(CUT_BODY) - 1, true);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_FILE_TOO_LARGE, ROBOTSTXT_DIRECTIVE_NONE, 0);
}

void test_nul_byte_in_a_user_agent_or_a_name_matches_nothing(void)
{
  static const char USER_AGENT_BODY[] = "User-agent: Contr\0stAPI\nDisallow: /a\n";
  static_parseBytes(USER_AGENT_BODY, sizeof(USER_AGENT_BODY) - 1, false);
  static_assertCounts(0, 0, 0, 0, 0, 0);

  static const char NAME_BODY[] = "User-agent: *\nDis\0llow: /b\n";
  static_parseBytes(NAME_BODY, sizeof(NAME_BODY) - 1, false);
  static_assertCounts(1, 1, 0, 0, 1, 1);
  TEST_ASSERT_EQUAL_INT(2, g_robots.m_issueKeptCount);
  static_assertIssue(1, ROBOTSTXT_ISSUE_UNKNOWN_DIRECTIVE, ROBOTSTXT_DIRECTIVE_NONE, 2);
}

void test_invalid_utf8_is_checked_on_the_read_part(void)
{
  static_parse("User-agent: *\nDisallow: /\xFF\n");
  static_assertCounts(1, 1, 1, 1, 1, 1);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_INVALID_UTF8, ROBOTSTXT_DIRECTIVE_NONE, 0);

  const char* cut_body = "User-agent: *\nDisallow: /a\n\xFF";
  static_parseBytes(cut_body, strlen(cut_body), true);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_FILE_TOO_LARGE, ROBOTSTXT_DIRECTIVE_NONE, 0);
}

void test_body_issues_come_first_in_code_order(void)
{
  static const char BODY[] = "\xEF\xBB\xBF" "Disallow: \xFF\0\nDisallow: /x\0\nX";
  static_parseBytes(BODY, sizeof(BODY) - 1, true);
  TEST_ASSERT_EQUAL_INT(6, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_FILE_TOO_LARGE, ROBOTSTXT_DIRECTIVE_NONE, 0);
  static_assertIssue(1, ROBOTSTXT_ISSUE_BYTE_ORDER_MARK, ROBOTSTXT_DIRECTIVE_NONE, 0);
  static_assertIssue(2, ROBOTSTXT_ISSUE_INVALID_UTF8, ROBOTSTXT_DIRECTIVE_NONE, 0);
  static_assertIssue(3, ROBOTSTXT_ISSUE_CONTAINS_NUL_BYTE, ROBOTSTXT_DIRECTIVE_NONE, 0);
  static_assertIssue(4, ROBOTSTXT_ISSUE_RULE_BEFORE_USER_AGENT, ROBOTSTXT_DIRECTIVE_DISALLOW, 1);
  static_assertIssue(5, ROBOTSTXT_ISSUE_RULE_BEFORE_USER_AGENT, ROBOTSTXT_DIRECTIVE_DISALLOW, 2);
  TEST_ASSERT_EQUAL_INT(5, g_robots.ma_issueCountBySeverity[ROBOTSTXT_SEVERITY_WARNING]);
  TEST_ASSERT_EQUAL_INT(1, g_robots.ma_issueCountBySeverity[ROBOTSTXT_SEVERITY_INFO]);
}

void test_line_of_2047_and_2048_bytes_is_read_and_2049_is_not(void)
{
  static_parse(static_buildLongLine("User-agent: *\nDisallow: /", 2047 - 11, "\r\n"));
  static_assertCounts(1, 1, 1, 1, 1, 1);
  static_assertRule(0, ROBOTSTXT_RULE_DISALLOW, 24, 2037, 2);
  TEST_ASSERT_EQUAL_INT(0, g_robots.m_issueTotalCount);

  static_parse(static_buildLongLine("User-agent: *\nDisallow: /", 2048 - 11, "\r\n"));
  static_assertRule(0, ROBOTSTXT_RULE_DISALLOW, 24, 2038, 2);
  TEST_ASSERT_EQUAL_INT(0, g_robots.m_issueTotalCount);
  TEST_ASSERT_FALSE(g_robots.m_hasDroppedRule);

  static_parse(static_buildLongLine("User-agent: *\nDisallow: /", 2049 - 11, "\nAllow: /b\n"));
  static_assertCounts(1, 1, 1, 1, 1, 1);
  static_assertRule(0, ROBOTSTXT_RULE_ALLOW, 14 + 2049 + 1 + 7, 2, 3);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_LINE_TOO_LONG, ROBOTSTXT_DIRECTIVE_DISALLOW, 2);
  TEST_ASSERT_TRUE(g_robots.m_hasDroppedRule);
}

void test_long_user_agent_line_is_a_dropped_rule(void)
{
  static_parse(static_buildLongLine("User-agent: ", 2049 - 12, "\nUser-agent: *\nDisallow: /a\n"));
  static_assertIssue(0, ROBOTSTXT_ISSUE_LINE_TOO_LONG, ROBOTSTXT_DIRECTIVE_USER_AGENT, 1);
  TEST_ASSERT_TRUE(g_robots.m_hasDroppedRule);
  static_assertVerdict("/b", ROBOTSTXT_DECISION_UNKNOWN, -1);
}

void test_long_rule_of_our_user_agent_group_is_a_dropped_rule(void)
{
  static_parse(static_buildLongLine("User-agent: ContrastAPI\nDisallow: /a\nAllow: /", 2049 - 8, "\n"));
  static_assertIssue(0, ROBOTSTXT_ISSUE_LINE_TOO_LONG, ROBOTSTXT_DIRECTIVE_ALLOW, 3);
  TEST_ASSERT_TRUE(g_robots.m_hasDroppedRule);

  static_parse(static_buildLongLine("User-agent: ContrastAPI\nDisallow: /", 2049 - 11, "\n"));
  static_assertIssue(0, ROBOTSTXT_ISSUE_LINE_TOO_LONG, ROBOTSTXT_DIRECTIVE_DISALLOW, 2);
  TEST_ASSERT_TRUE(g_robots.m_hasDroppedRule);
}

void test_long_rule_or_crawl_delay_line_closes_the_user_agent_list(void)
{
  static_parse(static_buildLongLine("User-agent: *\nCrawl-delay: ", 2049 - 13, "\nUser-agent: Googlebot\nAllow: /\nUser-agent: *\nDisallow: /\n"));
  static_assertVerdict("/x", ROBOTSTXT_DECISION_DISALLOWED, 0);
  TEST_ASSERT_FALSE(g_robots.m_hasDroppedRule);

  static_parse(static_buildLongLine("User-agent: ContrastAPI\nCrawl-delay: ", 2049 - 13, "\nUser-agent: Googlebot\nAllow: /secret\nUser-agent: ContrastAPI\nDisallow: /\n"));
  static_assertVerdict("/secret", ROBOTSTXT_DECISION_DISALLOWED, 0);
  TEST_ASSERT_FALSE(g_robots.m_hasDroppedRule);

  static_parse(static_buildLongLine("User-agent: Googlebot\nAllow: /", 2049 - 8, "\nUser-agent: *\nDisallow: /a\n"));
  static_assertGroup(0, 3, false, true, 0, 1, 0, 1);
  TEST_ASSERT_FALSE(g_robots.m_hasDroppedRule);

  static_parse(static_buildLongLine("User-agent: ContrastAPI\nSitemap: http://", 2049 - 16, "\nUser-agent: Googlebot\nDisallow: /secret\n"));
  static_assertVerdict("/secret", ROBOTSTXT_DECISION_DISALLOWED, 0);
  static_parse(static_buildLongLine("User-agent: ContrastAPI\nHost: ", 2049 - 6, "\nUser-agent: Googlebot\nDisallow: /secret\n"));
  static_assertVerdict("/secret", ROBOTSTXT_DECISION_DISALLOWED, 0);
  static_parse(static_buildLongLine("User-agent: *\nUser-agent: ", 2049 - 12, "\nUser-agent: ContrastAPI\nDisallow: /x\n"));
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_groupKeptCount);
}

void test_long_lines_that_lose_no_kept_rule_drop_no_rule(void)
{
  static const struct
  {
    const char*          mp_head;
    size_t               m_headLenInLine;
    const char*          mp_tail;
    RobotsTxtDirective_t m_field;
    int                  m_lineNumber;
  } ROWS[] = {
    { "User-agent: Googlebot\nDisallow: /g\nDisallow: /", 11, "\nUser-agent: *\nDisallow: /a\n", ROBOTSTXT_DIRECTIVE_DISALLOW,    3 },
    { "Disallow: /",                                      11, "\nUser-agent: *\nDisallow: /a\n", ROBOTSTXT_DIRECTIVE_DISALLOW,    1 },
    { "User-agent: *\nDisallow: /a\nSitemap: http://",    16, "\n",                              ROBOTSTXT_DIRECTIVE_SITEMAP,     3 },
    { "User-agent: *\nDisallow: /a\nCrawl-delay: 1",      14, "\n",                              ROBOTSTXT_DIRECTIVE_CRAWL_DELAY, 3 },
    { "User-agent: *\nDisallow: /a\n",                     0, "\n",                              ROBOTSTXT_DIRECTIVE_NONE,        3 },
    { "User-agent: *\nDisallow: /a\n# Disallow",          10, ":\n",                             ROBOTSTXT_DIRECTIVE_NONE,        3 },
    { "User-agent: *\nDisallow: /a\nNoindex: /",          10, "\n",                              ROBOTSTXT_DIRECTIVE_NONE,        3 },
  };
  for (size_t i = 0; i < sizeof(ROWS) / sizeof(ROWS[0]); i++)
  {
    static_parse(static_buildLongLine(ROWS[i].mp_head, 2049 - ROWS[i].m_headLenInLine - (strcmp(ROWS[i].mp_tail, ":\n") == 0 ? 1 : 0), ROWS[i].mp_tail));
    TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueKeptCount);
    static_assertIssue(0, ROBOTSTXT_ISSUE_LINE_TOO_LONG, ROWS[i].m_field, ROWS[i].m_lineNumber);
    TEST_ASSERT_FALSE(g_robots.m_hasDroppedRule);
    TEST_ASSERT_EQUAL_INT(0, g_robots.m_sitemapTotalCount);
    TEST_ASSERT_FALSE(g_robots.m_groupKeptCount > 0 && g_robots.mp_groups[0].m_hasCrawlDelay);
  }
}

void test_valid_crawl_delays_are_read(void)
{
  static const struct
  {
    const char* mp_value;
    double      m_seconds;
  } ROWS[] = {
    { "0", 0.0 }, { "86400", 86400.0 }, { "1.5", 1.5 }, { "86400.000", 86400.0 }, { "007", 7.0 },
    { "0.25", 0.25 }, { "86399.75", 86399.75 }, { "9", 9.0 }, { "12.0000000005", 12.0 }, { "0.123456789", 0.123456789 },
  };
  for (size_t i = 0; i < sizeof(ROWS) / sizeof(ROWS[0]); i++)
  {
    char body[128];
    snprintf(body, sizeof(body), "User-agent: *\nCrawl-delay: %s\n", ROWS[i].mp_value);
    static_parse(body);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_robots.m_issueTotalCount, ROWS[i].mp_value);
    TEST_ASSERT_TRUE_MESSAGE(g_robots.mp_groups[0].m_hasCrawlDelay, ROWS[i].mp_value);
    TEST_ASSERT_TRUE_MESSAGE(g_robots.mp_groups[0].m_crawlDelaySeconds == ROWS[i].m_seconds, ROWS[i].mp_value);
  }
}

void test_invalid_crawl_delays_raise_an_issue(void)
{
  static const char* const VALUES[] = {
    "86400.5", "86401", "864000", "86400.0000000001", "-1", "+1", "1.", ".5", "1.2.3", "abc", "", "1e3", "1 0",
    "99999999999999999999", "1,5", "0x10", "/", ":", "1./", "1.:",
  };
  for (size_t i = 0; i < sizeof(VALUES) / sizeof(VALUES[0]); i++)
  {
    char body[128];
    snprintf(body, sizeof(body), "User-agent: *\nCrawl-delay: %s\n", VALUES[i]);
    static_parse(body);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_robots.m_issueKeptCount, VALUES[i]);
    static_assertIssue(0, ROBOTSTXT_ISSUE_CRAWL_DELAY_INVALID, ROBOTSTXT_DIRECTIVE_CRAWL_DELAY, 2);
    TEST_ASSERT_FALSE_MESSAGE(g_robots.mp_groups[0].m_hasCrawlDelay, VALUES[i]);
  }
}

void test_last_valid_crawl_delay_of_a_kept_group_wins(void)
{
  static_parse("User-agent: *\nCrawl-delay: 3\nCrawl-delay: 9\nCrawl-delay: x\nUser-agent: Googlebot\nCrawl-delay: 4\nCrawl-delay: y\n");
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_groupKeptCount);
  TEST_ASSERT_TRUE(g_robots.mp_groups[0].m_crawlDelaySeconds == 9.0);
  TEST_ASSERT_TRUE(g_robots.mp_groups[0].m_hasCrawlDelay);
  TEST_ASSERT_EQUAL_INT(2, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_CRAWL_DELAY_INVALID, ROBOTSTXT_DIRECTIVE_CRAWL_DELAY, 4);
  static_assertIssue(1, ROBOTSTXT_ISSUE_CRAWL_DELAY_INVALID, ROBOTSTXT_DIRECTIVE_CRAWL_DELAY, 7);
}

void test_sitemaps_are_kept_anywhere_and_relative_ones_raise_an_issue(void)
{
  static_parse("Sitemap: https://e.com/a.xml\nUser-agent: *\nsitemap: HTTP://e.com/b\nSitemap: /rel.xml\nSitemap: ftp://x\nSitemap:\nSitemap: http:/\nSitemap: HtTpS://e.com/c\nSitemap: http://\nSitemap: HTTPS://\n");
  TEST_ASSERT_EQUAL_INT(9, g_robots.m_sitemapKeptCount);
  TEST_ASSERT_EQUAL_INT(9, g_robots.m_sitemapTotalCount);
  static_assertSpan(g_robots.mp_sitemaps[0], 9, 19, 1);
  static_assertSpan(g_robots.mp_sitemaps[1], 52, 14, 3);
  static_assertSpan(g_robots.mp_sitemaps[2], 76, 8, 4);
  static_assertSpan(g_robots.mp_sitemaps[3], 94, 7, 5);
  static_assertSpan(g_robots.mp_sitemaps[4], 110, 0, 6);
  static_assertSpan(g_robots.mp_sitemaps[5], 120, 6, 7);
  static_assertSpan(g_robots.mp_sitemaps[6], 136, 15, 8);
  static_assertSpan(g_robots.mp_sitemaps[7], 161, 7, 9);
  static_assertSpan(g_robots.mp_sitemaps[8], 178, 8, 10);
  TEST_ASSERT_EQUAL_INT(4, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_SITEMAP_NOT_ABSOLUTE, ROBOTSTXT_DIRECTIVE_SITEMAP, 4);
  static_assertIssue(1, ROBOTSTXT_ISSUE_SITEMAP_NOT_ABSOLUTE, ROBOTSTXT_DIRECTIVE_SITEMAP, 5);
  static_assertIssue(2, ROBOTSTXT_ISSUE_SITEMAP_NOT_ABSOLUTE, ROBOTSTXT_DIRECTIVE_SITEMAP, 6);
  static_assertIssue(3, ROBOTSTXT_ISSUE_SITEMAP_NOT_ABSOLUTE, ROBOTSTXT_DIRECTIVE_SITEMAP, 7);
  static_assertGroup(0, 2, false, true, 0, 1, 0, 0);
}

void test_sitemap_with_one_slash_after_https_raises_an_issue(void)
{
  static_parse("Sitemap: https:/e.com/a.xml\n");
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_sitemapKeptCount);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_SITEMAP_NOT_ABSOLUTE, ROBOTSTXT_DIRECTIVE_SITEMAP, 1);
}

void test_sitemap_cap(void)
{
  static_parse(static_buildBody("", "Sitemap: http://e.com/s\n", 99, ""));
  TEST_ASSERT_EQUAL_INT(99, g_robots.m_sitemapKeptCount);
  TEST_ASSERT_EQUAL_INT(0, g_robots.m_issueTotalCount);

  static_parse(static_buildBody("", "Sitemap: http://e.com/s\n", 100, ""));
  TEST_ASSERT_EQUAL_INT(100, g_robots.m_sitemapKeptCount);
  TEST_ASSERT_EQUAL_INT(100, g_robots.m_sitemapTotalCount);
  TEST_ASSERT_EQUAL_INT(0, g_robots.m_issueTotalCount);

  g_largestReallocSize = 0;
  static_parse(static_buildBody("", "Sitemap: http://e.com/s\n", 101, ""));
  TEST_ASSERT_EQUAL_INT(100, g_robots.m_sitemapKeptCount);
  TEST_ASSERT_EQUAL_INT(101, g_robots.m_sitemapTotalCount);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_TOO_MANY_SITEMAPS, ROBOTSTXT_DIRECTIVE_NONE, 101);
  TEST_ASSERT_EQUAL_size_t(100 * sizeof(RobotsTxtSpan_t), g_largestReallocSize);
  static_assertSpan(g_robots.mp_sitemaps[99], 99 * 24 + 9, 14, 100);

  static_parse(static_buildBody("", "Sitemap: http://e.com/s\n", 102, ""));
  TEST_ASSERT_EQUAL_INT(102, g_robots.m_sitemapTotalCount);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueTotalCount);
  TEST_ASSERT_FALSE(g_robots.m_hasDroppedRule);
}

void test_group_cap(void)
{
  static_parse(static_buildBody("", "User-agent: *\nDisallow: /a\n", 1023, ""));
  static_assertCounts(1023, 1023, 1023, 1023, 1023, 1023);
  TEST_ASSERT_FALSE(g_robots.m_hasDroppedRule);

  static_parse(static_buildBody("", "User-agent: *\nDisallow: /a\n", 1024, ""));
  static_assertCounts(1024, 1024, 1024, 1024, 1024, 1024);
  static_assertGroup(1023, 2047, false, true, 1023, 1, 1023, 1);
  TEST_ASSERT_EQUAL_INT(0, g_robots.m_issueTotalCount);
  TEST_ASSERT_FALSE(g_robots.m_hasDroppedRule);

  static_parse(static_buildBody("", "User-agent: *\nDisallow: /a\n", 1025, ""));
  static_assertCounts(1024, 1025, 1024, 1024, 1024, 1024);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_TOO_MANY_GROUPS, ROBOTSTXT_DIRECTIVE_NONE, 2049);
  TEST_ASSERT_TRUE(g_robots.m_hasDroppedRule);

  static_parse(static_buildBody("", "User-agent: *\nDisallow: /a\n", 1026, ""));
  TEST_ASSERT_EQUAL_INT(1026, g_robots.m_groupTotalCount);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueTotalCount);
}

void test_two_caps_raise_two_issues(void)
{
  static_parse(static_buildBody("", "User-agent: *\nDisallow: /a\nSitemap: http://e.com/s\n", 1025, ""));
  TEST_ASSERT_EQUAL_INT(2, g_robots.m_issueTotalCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_TOO_MANY_SITEMAPS, ROBOTSTXT_DIRECTIVE_NONE, 303);
  static_assertIssue(1, ROBOTSTXT_ISSUE_TOO_MANY_GROUPS, ROBOTSTXT_DIRECTIVE_NONE, 3073);
}

void test_groups_of_another_crawler_do_not_count_toward_the_cap(void)
{
  static_parse(static_buildBody("", "User-agent: Googlebot\nDisallow: /a\n", 1025, ""));
  static_assertCounts(0, 0, 0, 0, 0, 0);
  TEST_ASSERT_EQUAL_INT(0, g_robots.m_issueTotalCount);
  TEST_ASSERT_FALSE(g_robots.m_hasDroppedRule);
}

void test_rule_cap(void)
{
  static_parse(static_buildBody("User-agent: *\n", "Disallow: /a\n", 16383, ""));
  static_assertCounts(1, 1, 16383, 16383, 1, 1);
  TEST_ASSERT_FALSE(g_robots.m_hasDroppedRule);

  static_parse(static_buildBody("User-agent: *\n", "Disallow: /a\n", 16384, ""));
  static_assertCounts(1, 1, 16384, 16384, 1, 1);
  static_assertGroup(0, 1, false, true, 0, 1, 0, 16384);
  TEST_ASSERT_EQUAL_INT(0, g_robots.m_issueTotalCount);
  TEST_ASSERT_FALSE(g_robots.m_hasDroppedRule);

  static_parse(static_buildBody("User-agent: *\n", "Disallow: /a\n", 16385, ""));
  static_assertCounts(1, 1, 16384, 16385, 1, 1);
  static_assertGroup(0, 1, false, true, 0, 1, 0, 16384);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_TOO_MANY_RULES, ROBOTSTXT_DIRECTIVE_NONE, 16386);
  TEST_ASSERT_TRUE(g_robots.m_hasDroppedRule);

  static_parse(static_buildBody("User-agent: *\n", "Disallow: /a\n", 16386, ""));
  TEST_ASSERT_EQUAL_INT(16386, g_robots.m_ruleTotalCount);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueTotalCount);
}

void test_rules_of_another_crawler_do_not_count_toward_the_cap(void)
{
  static_parse(static_buildBody("User-agent: Googlebot\n", "Disallow: /a\n", 16385, ""));
  static_assertCounts(0, 0, 0, 0, 0, 0);
  TEST_ASSERT_EQUAL_INT(0, g_robots.m_issueTotalCount);
  TEST_ASSERT_FALSE(g_robots.m_hasDroppedRule);
}

void test_user_agent_cap(void)
{
  static_parse(static_buildBody("", "User-agent: *\n", 1023, "Disallow: /a\n"));
  static_assertCounts(1, 1, 1, 1, 1023, 1023);

  static_parse(static_buildBody("", "User-agent: *\n", 1024, "Disallow: /a\n"));
  static_assertCounts(1, 1, 1, 1, 1024, 1024);
  static_assertGroup(0, 1, false, true, 0, 1024, 0, 1);
  TEST_ASSERT_EQUAL_INT(0, g_robots.m_issueTotalCount);

  static_parse(static_buildBody("", "User-agent: *\n", 1025, "Disallow: /a\n"));
  static_assertCounts(1, 1, 1, 1, 1024, 1025);
  static_assertGroup(0, 1, false, true, 0, 1024, 0, 1);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_TOO_MANY_USER_AGENTS, ROBOTSTXT_DIRECTIVE_NONE, 1025);
  TEST_ASSERT_FALSE(g_robots.m_hasDroppedRule);

  static_parse(static_buildBody("", "User-agent: *\n", 1026, "Disallow: /a\n"));
  TEST_ASSERT_EQUAL_INT(1026, g_robots.m_userAgentTotalCount);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueTotalCount);
}

void test_user_agents_of_another_crawler_free_their_slots(void)
{
  static_parse(static_buildBody("", "User-agent: Googlebot\n", 1025, "Disallow: /a\nUser-agent: *\nDisallow: /b\n"));
  static_assertCounts(1, 1, 1, 1, 1, 1);
  static_assertGroup(0, 1027, false, true, 0, 1, 0, 1);
  static_assertSpan(g_robots.mp_userAgents[0], 1025 * 22 + 13 + 12, 1, 1027);
  TEST_ASSERT_EQUAL_INT(0, g_robots.m_issueTotalCount);
}

void test_user_agent_cap_spans_groups(void)
{
  static_buildBody("", "User-agent: *\n", 1000, "Disallow: /a\n");
  char* first_part = g_builtBody;
  g_builtBody = NULL;
  static_buildBody(first_part, "User-agent: ContrastAPI\n", 30, "Disallow: /b\nUser-agent: *\nDisallow: /c\n");
  free(first_part);
  static_parse(g_builtBody);
  static_assertCounts(3, 3, 3, 3, 1024, 1031);
  static_assertGroup(1, 1002, true, false, 1000, 24, 1, 1);
  static_assertGroup(2, 1033, false, true, 1024, 0, 2, 1);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_issueTotalCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_TOO_MANY_USER_AGENTS, ROBOTSTXT_DIRECTIVE_NONE, 1026);
}

void test_issue_cap_keeps_50_and_counts_every_issue(void)
{
  static_parse(static_buildBody("Disallow: /a\n", "x\n", 48, ""));
  TEST_ASSERT_EQUAL_INT(49, g_robots.m_issueKeptCount);
  TEST_ASSERT_EQUAL_INT(49, g_robots.m_issueTotalCount);

  static_parse(static_buildBody("Disallow: /a\n", "x\n", 49, ""));
  TEST_ASSERT_EQUAL_INT(50, g_robots.m_issueKeptCount);
  TEST_ASSERT_EQUAL_INT(50, g_robots.m_issueTotalCount);
  static_assertIssue(49, ROBOTSTXT_ISSUE_LINE_SYNTAX_INVALID, ROBOTSTXT_DIRECTIVE_NONE, 50);

  static_parse(static_buildBody("Disallow: /a\n", "x\n", 50, ""));
  TEST_ASSERT_EQUAL_INT(50, g_robots.m_issueKeptCount);
  TEST_ASSERT_EQUAL_INT(51, g_robots.m_issueTotalCount);
  TEST_ASSERT_EQUAL_INT(1, g_robots.ma_issueCountBySeverity[ROBOTSTXT_SEVERITY_WARNING]);
  TEST_ASSERT_EQUAL_INT(50, g_robots.ma_issueCountBySeverity[ROBOTSTXT_SEVERITY_INFO]);
  static_assertIssue(0, ROBOTSTXT_ISSUE_RULE_BEFORE_USER_AGENT, ROBOTSTXT_DIRECTIVE_DISALLOW, 1);
  static_assertIssue(49, ROBOTSTXT_ISSUE_LINE_SYNTAX_INVALID, ROBOTSTXT_DIRECTIVE_NONE, 50);
}

void test_our_user_agent_groups_win_over_wildcard_groups(void)
{
  const char* body = "User-agent: *\nDisallow: /\nUser-agent: ContrastAPI\nDisallow: /private\nAllow: /private/pub\n";
  static_parse(body);
  static_assertVerdictIn(body, "/", ROBOTSTXT_DECISION_ALLOWED, -1);
  static_assertVerdictIn(body, "/private/x", ROBOTSTXT_DECISION_DISALLOWED, 1);
  static_assertVerdictIn(body, "/private/pub/a", ROBOTSTXT_DECISION_ALLOWED, 2);
}

void test_wildcard_groups_merge_when_no_group_has_our_user_agent(void)
{
  const char* body = "User-agent: *\nDisallow: /a\nUser-agent: Googlebot\nDisallow: /b\nUser-agent: *\nAllow: /a/b\n";
  static_parse(body);
  static_assertVerdictIn(body, "/a/x", ROBOTSTXT_DECISION_DISALLOWED, 0);
  static_assertVerdictIn(body, "/a/b", ROBOTSTXT_DECISION_ALLOWED, 1);
  static_assertVerdictIn(body, "/b", ROBOTSTXT_DECISION_ALLOWED, -1);

  const char* tie = "User-agent: *\nDisallow: /a\nUser-agent: *\nDisallow: /a\n";
  static_parse(tie);
  static_assertVerdictIn(tie, "/a", ROBOTSTXT_DECISION_DISALLOWED, 0);
}

void test_our_user_agent_groups_merge(void)
{
  const char* body = "User-agent: ContrastAPI\nDisallow: /a\nUser-agent: *\nDisallow: /\nUser-agent: contrastapi\nAllow: /a/b\n";
  static_parse(body);
  static_assertVerdictIn(body, "/a/x", ROBOTSTXT_DECISION_DISALLOWED, 0);
  static_assertVerdictIn(body, "/a/b", ROBOTSTXT_DECISION_ALLOWED, 2);
  static_assertVerdictIn(body, "/c", ROBOTSTXT_DECISION_ALLOWED, -1);
}

void test_no_kept_group_allows_every_path(void)
{
  const char* body = "User-agent: Googlebot\nDisallow: /\n";
  static_parse(body);
  static_assertVerdictIn(body, "/", ROBOTSTXT_DECISION_ALLOWED, -1);
  static_parseBytes(NULL, 0, false);
  static_assertVerdictIn(NULL, "/", ROBOTSTXT_DECISION_ALLOWED, -1);
}

void test_longest_pattern_wins_and_allow_wins_a_tie(void)
{
  const char* allow_last = "User-agent: *\nDisallow: /folder\nAllow: /folder\n";
  static_parse(allow_last);
  static_assertVerdictIn(allow_last, "/folder/x", ROBOTSTXT_DECISION_ALLOWED, 1);

  const char* allow_first = "User-agent: *\nAllow: /folder\nDisallow: /folder\n";
  static_parse(allow_first);
  static_assertVerdictIn(allow_first, "/folder/x", ROBOTSTXT_DECISION_ALLOWED, 0);

  const char* same_kind = "User-agent: *\nDisallow: /a*\nDisallow: /ab\nAllow: /ab\nDisallow: /ab\n";
  static_parse(same_kind);
  static_assertVerdictIn(same_kind, "/ac", ROBOTSTXT_DECISION_DISALLOWED, 0);
  static_assertVerdictIn(same_kind, "/abc", ROBOTSTXT_DECISION_ALLOWED, 2);

  const char* two_disallows = "User-agent: *\nDisallow: /x*\nDisallow: /xy\n";
  static_parse(two_disallows);
  static_assertVerdictIn(two_disallows, "/xyz", ROBOTSTXT_DECISION_DISALLOWED, 0);

  const char* two_allows = "User-agent: *\nDisallow: /\nAllow: /q*\nAllow: /qr\n";
  static_parse(two_allows);
  static_assertVerdictIn(two_allows, "/qrs", ROBOTSTXT_DECISION_ALLOWED, 1);

  const char* longer = "User-agent: *\nAllow: /a\nDisallow: /ab\nAllow: /abc\nDisallow: /a\n";
  static_parse(longer);
  static_assertVerdictIn(longer, "/abd", ROBOTSTXT_DECISION_DISALLOWED, 1);
  static_assertVerdictIn(longer, "/abcd", ROBOTSTXT_DECISION_ALLOWED, 2);
  static_assertVerdictIn(longer, "/ax", ROBOTSTXT_DECISION_ALLOWED, 0);
}

void test_pattern_length_is_counted_as_written(void)
{
  const char* body = "User-agent: *\nDisallow: /%61\nAllow: /ab\n";
  static_parse(body);
  static_assertVerdictIn(body, "/ab", ROBOTSTXT_DECISION_DISALLOWED, 0);
}

void test_fish_and_php_wildcard_rows(void)
{
  ASSERT_MATCHES("/fish", "/fish");
  ASSERT_MATCHES("/fish", "/fish.html");
  ASSERT_MATCHES("/fish", "/fishheads/yummy.html");
  ASSERT_NOT_MATCHES("/fish", "/Fish.asp");
  ASSERT_NOT_MATCHES("/fish", "/catfish");
  ASSERT_MATCHES("/fish*", "/fish");
  ASSERT_MATCHES("/fish*", "/fishheads");
  ASSERT_MATCHES("/fish/", "/fish/salmon.htm");
  ASSERT_NOT_MATCHES("/fish/", "/fish");
  ASSERT_MATCHES("/*.php", "/index.php");
  ASSERT_MATCHES("/*.php", "/folder/filename.php?parameters");
  ASSERT_MATCHES("/*.php", "/folder/any.php.file.html");
  ASSERT_NOT_MATCHES("/*.php", "/");
  ASSERT_NOT_MATCHES("/*.php", "/windows.PHP");
  ASSERT_MATCHES("/*.php$", "/filename.php");
  ASSERT_MATCHES("/*.php$", "/folder/filename.php");
  ASSERT_NOT_MATCHES("/*.php$", "/filename.php?parameters");
  ASSERT_NOT_MATCHES("/*.php$", "/filename.php/");
  ASSERT_NOT_MATCHES("/*.php$", "/filename.php5");
  ASSERT_MATCHES("/fish*.php", "/fish.php");
  ASSERT_MATCHES("/fish*.php", "/fishheads/catfish.php?parameters");
  ASSERT_NOT_MATCHES("/fish*.php", "/Fish.PHP");
}

void test_wildcard_and_anchor_edges(void)
{
  ASSERT_MATCHES("*", "/anything");
  ASSERT_MATCHES("*", "");
  ASSERT_MATCHES("$", "");
  ASSERT_NOT_MATCHES("$", "/");
  ASSERT_MATCHES("/a$b", "/a$b/c");
  ASSERT_NOT_MATCHES("/a$b", "/ab");
  ASSERT_MATCHES("/a$", "/a");
  ASSERT_NOT_MATCHES("/a$", "/ab");
  ASSERT_MATCHES("/a**b", "/axxb");
  ASSERT_MATCHES("/a*b*c$", "/axbxbyc");
  ASSERT_NOT_MATCHES("/a*b*c$", "/axbxbyd");
  ASSERT_MATCHES("/a*c", "/abcbc");
  ASSERT_NOT_MATCHES("/a*a", "/ab");
  ASSERT_NOT_MATCHES("/a*", "/");
  ASSERT_NOT_MATCHES("/", "");
  ASSERT_NOT_MATCHES("/a%00", "/a");
  ASSERT_MATCHES("/*$", "/x");
  ASSERT_MATCHES("/x*$", "/x");
}

void test_percent_encoded_bytes_match_their_bytes(void)
{
  ASSERT_MATCHES("/foo/bar?baz=quz", "/foo/bar?baz=quz");
  ASSERT_MATCHES("/foo/bar/\xE3\x83\x84", "/foo/bar/%E3%83%84");
  ASSERT_MATCHES("/foo/bar/%E3%83%84", "/foo/bar/%E3%83%84");
  ASSERT_MATCHES("/foo/bar/%E3%83%84", "/foo/bar/\xE3\x83\x84");
  ASSERT_MATCHES("/foo/bar/%62%61%7A", "/foo/bar/baz");
  ASSERT_MATCHES("/foo/bar/baz", "/foo/bar/%62%61%7A");
  ASSERT_MATCHES("/path/file-with-a-%2A.html", "/path/file-with-a-*.html");
  ASSERT_MATCHES("/path/foo-%24", "/path/foo-$");
  ASSERT_MATCHES("/%7e", "/~");
  ASSERT_MATCHES("/~", "/%7E");
  ASSERT_MATCHES("/a%2Fb", "/a/b");
  ASSERT_MATCHES("/a%0a", "/a%0A");
  ASSERT_MATCHES("/foo/bar/%e3%83%84", "/foo/bar/%E3%83%84");
  ASSERT_NOT_MATCHES("/a%2Ab", "/axb");
  ASSERT_NOT_MATCHES("/a%24", "/a");
  ASSERT_MATCHES("/a%24", "/a$x");
}

void test_wildcard_steps_over_whole_units(void)
{
  ASSERT_NOT_MATCHES("/*2", "/%62");
  ASSERT_MATCHES("/*b", "/%62");
  ASSERT_MATCHES("/*%62", "/xb");
}

void test_hex_digit_edges_of_percent_encoding(void)
{
  ASSERT_MATCHES("/%30", "/0");
  ASSERT_MATCHES("/%39", "/9");
  ASSERT_MATCHES("/%3A", "/:");
  ASSERT_MATCHES("/%3a", "/:");
  ASSERT_MATCHES("/%3F", "/?");
  ASSERT_MATCHES("/%3f", "/?");
  ASSERT_MATCHES("/%A0", "/\xA0");
  ASSERT_MATCHES("/%a0", "/\xA0");
  ASSERT_MATCHES("/%F0", "/\xF0");
  ASSERT_MATCHES("/%f0", "/\xF0");
  ASSERT_MATCHES("/%00", "/%00");
  ASSERT_MATCHES("/%3G", "/%3G");
  ASSERT_NOT_MATCHES("/%3G", "/%3g");
  ASSERT_NOT_MATCHES("/%3/", "//");
  ASSERT_NOT_MATCHES("/%3:", "/:");
  ASSERT_NOT_MATCHES("/%3@", "/9");
  ASSERT_NOT_MATCHES("/%3G", "/@");
  ASSERT_NOT_MATCHES("/%3`", "/9");
  ASSERT_NOT_MATCHES("/%3g", "/@");
  ASSERT_NOT_MATCHES("/%/3", "/\xF3");
  ASSERT_NOT_MATCHES("/%:3", "/\xA3");
  ASSERT_NOT_MATCHES("/%@3", "/\x93");
  ASSERT_NOT_MATCHES("/%G3", "/\x03");
  ASSERT_NOT_MATCHES("/%`3", "/\x93");
  ASSERT_NOT_MATCHES("/%g3", "/\x03");
}

void test_percent_at_the_end_is_an_ordinary_byte(void)
{
  ASSERT_MATCHES("/a%", "/a%");
  ASSERT_MATCHES("/a%4", "/a%4");
  ASSERT_NOT_MATCHES("/a%41", "/a%4");
  ASSERT_NOT_MATCHES("/a%4", "/a%41");
  ASSERT_NOT_MATCHES("/a%4$", "/a%41");
  ASSERT_MATCHES("/a%41$", "/aA");
  TEST_ASSERT_TRUE(static_isPatternMatchingBytes("/a%4$", "/a%41", 4));
  TEST_ASSERT_FALSE(static_isPatternMatchingBytes("/aA", "/a%41", 4));
}

void test_dropped_rule_answers_unknown(void)
{
  static_parse(static_buildBody("User-agent: *\n", "Disallow: /a\n", 16385, ""));
  static_assertVerdict("/zzz", ROBOTSTXT_DECISION_UNKNOWN, -1);
  static_assertVerdict("/a", ROBOTSTXT_DECISION_UNKNOWN, -1);
}

void test_text_plain_raises_no_response_issue(void)
{
  static const char* const TYPES[] = { "text/plain", "TEXT/Plain", "text/plain; charset=utf-8", " text/plain\t;charset=x", "text/plain;" };
  for (size_t i = 0; i < sizeof(TYPES) / sizeof(TYPES[0]); i++)
  {
    static_parse("");
    robotstxt_checkResponse(&g_robots, TYPES[i], false);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_robots.m_issueTotalCount, TYPES[i]);
  }
}

void test_other_content_types_raise_an_issue(void)
{
  static const char* const TYPES[] = { "", "text/html", "text/plainx", "text/plai", "text/plain x", "charset=utf-8; text/plain" };
  for (size_t i = 0; i < sizeof(TYPES) / sizeof(TYPES[0]); i++)
  {
    static_parse("");
    robotstxt_checkResponse(&g_robots, TYPES[i], false);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_robots.m_issueKeptCount, TYPES[i]);
    static_assertIssue(0, ROBOTSTXT_ISSUE_CONTENT_TYPE_NOT_TEXT_PLAIN, ROBOTSTXT_DIRECTIVE_NONE, 0);
  }
  static_parse("");
  robotstxt_checkResponse(&g_robots, NULL, false);
  static_assertIssue(0, ROBOTSTXT_ISSUE_CONTENT_TYPE_NOT_TEXT_PLAIN, ROBOTSTXT_DIRECTIVE_NONE, 0);
  TEST_ASSERT_EQUAL_INT(1, g_robots.ma_issueCountBySeverity[ROBOTSTXT_SEVERITY_INFO]);
}

void test_redirect_to_another_host_raises_an_issue(void)
{
  static_parse("Disallow: /a\n");
  robotstxt_checkResponse(&g_robots, "text/plain", true);
  TEST_ASSERT_EQUAL_INT(2, g_robots.m_issueKeptCount);
  static_assertIssue(1, ROBOTSTXT_ISSUE_REDIRECTED_TO_OTHER_HOST, ROBOTSTXT_DIRECTIVE_NONE, 0);

  static_parse("");
  robotstxt_checkResponse(&g_robots, "text/html", true);
  TEST_ASSERT_EQUAL_INT(2, g_robots.m_issueKeptCount);
  static_assertIssue(0, ROBOTSTXT_ISSUE_REDIRECTED_TO_OTHER_HOST, ROBOTSTXT_DIRECTIVE_NONE, 0);
  static_assertIssue(1, ROBOTSTXT_ISSUE_CONTENT_TYPE_NOT_TEXT_PLAIN, ROBOTSTXT_DIRECTIVE_NONE, 0);
  TEST_ASSERT_EQUAL_INT(2, g_robots.ma_issueCountBySeverity[ROBOTSTXT_SEVERITY_INFO]);
  TEST_ASSERT_EQUAL_INT(2, g_robots.m_issueTotalCount);
}

void test_failed_allocation_answers_false_with_the_result_zeroed(void)
{
  const char* body = static_buildBody("Sitemap: http://e.com/s\nUser-agent: *\n", "Disallow: /a\n", 20, "");
  for (int fail_at = 1; fail_at <= 6; fail_at++)
  {
    g_reallocCallCount = 0;
    g_reallocFailAt    = fail_at;
    RobotsTxt_t robots;
    memset(&robots, 0xA5, sizeof(robots));
    TEST_ASSERT_FALSE(robotstxt_parse(body, strlen(body), false, PRODUCT_TOKEN, &robots));
    static_assertZeroed(&robots);
  }
  g_reallocCallCount = 0;
  g_reallocFailAt    = 0;
  static_parse(body);
  TEST_ASSERT_EQUAL_INT(6, g_reallocCallCount);
  static_assertCounts(1, 1, 20, 20, 1, 1);
  TEST_ASSERT_EQUAL_INT(1, g_robots.m_sitemapKeptCount);

  const char* long_rule = static_buildLongLine("User-agent: *\nDisallow: /", 2049 - 11, "\n");
  g_reallocCallCount = 0;
  g_reallocFailAt    = 2;
  RobotsTxt_t long_robots;
  memset(&long_robots, 0xA5, sizeof(long_robots));
  TEST_ASSERT_FALSE(robotstxt_parse(long_rule, strlen(long_rule), false, PRODUCT_TOKEN, &long_robots));
  static_assertZeroed(&long_robots);
}

void test_free_takes_a_zeroed_result_and_a_second_call(void)
{
  RobotsTxt_t robots = { 0 };
  robotstxt_free(&robots);
  static_assertZeroed(&robots);
  const char* body = "User-agent: *\nDisallow: /a\nSitemap: http://e.com/s\nx\n";
  TEST_ASSERT_TRUE(robotstxt_parse(body, strlen(body), false, PRODUCT_TOKEN, &robots));
  robotstxt_free(&robots);
  static_assertZeroed(&robots);
  robotstxt_free(&robots);
  static_assertZeroed(&robots);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(64, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_caps_hold_their_values);
  RUN_TEST(test_each_issue_code_has_its_name_and_severity);
  RUN_TEST(test_severity_and_directive_names);
  RUN_TEST(test_null_and_empty_body_are_an_empty_file);
  RUN_TEST(test_our_user_agent_group_is_kept_with_its_user_agent_and_rules);
  RUN_TEST(test_group_of_another_crawler_is_not_kept);
  RUN_TEST(test_groups_index_their_own_values_and_rules);
  RUN_TEST(test_user_agent_matches_the_token_exactly_in_any_case);
  RUN_TEST(test_product_token_letters_a_to_z_match_in_any_case);
  RUN_TEST(test_empty_user_agent_binds_nothing_and_raises_an_issue);
  RUN_TEST(test_user_agent_after_any_rule_opens_a_new_group);
  RUN_TEST(test_sitemap_and_unknown_directive_do_not_close_the_user_agent_list);
  RUN_TEST(test_rule_before_any_user_agent_is_ignored_and_raises_its_issue);
  RUN_TEST(test_empty_rule_is_not_kept);
  RUN_TEST(test_comments_blanks_and_name_case_are_ignored);
  RUN_TEST(test_line_without_colon_is_syntax_invalid);
  RUN_TEST(test_unknown_and_empty_names_are_unknown_directives);
  RUN_TEST(test_lf_cr_and_crlf_end_a_line);
  RUN_TEST(test_byte_order_mark_is_skipped);
  RUN_TEST(test_cut_body_drops_the_partial_last_line);
  RUN_TEST(test_cut_body_keeps_lines_up_to_the_last_end);
  RUN_TEST(test_nul_byte_is_an_ordinary_byte_and_raises_an_issue);
  RUN_TEST(test_nul_byte_in_a_user_agent_or_a_name_matches_nothing);
  RUN_TEST(test_invalid_utf8_is_checked_on_the_read_part);
  RUN_TEST(test_body_issues_come_first_in_code_order);
  RUN_TEST(test_line_of_2047_and_2048_bytes_is_read_and_2049_is_not);
  RUN_TEST(test_long_user_agent_line_is_a_dropped_rule);
  RUN_TEST(test_long_rule_of_our_user_agent_group_is_a_dropped_rule);
  RUN_TEST(test_long_rule_or_crawl_delay_line_closes_the_user_agent_list);
  RUN_TEST(test_long_lines_that_lose_no_kept_rule_drop_no_rule);
  RUN_TEST(test_valid_crawl_delays_are_read);
  RUN_TEST(test_invalid_crawl_delays_raise_an_issue);
  RUN_TEST(test_last_valid_crawl_delay_of_a_kept_group_wins);
  RUN_TEST(test_sitemaps_are_kept_anywhere_and_relative_ones_raise_an_issue);
  RUN_TEST(test_sitemap_with_one_slash_after_https_raises_an_issue);
  RUN_TEST(test_sitemap_cap);
  RUN_TEST(test_group_cap);
  RUN_TEST(test_two_caps_raise_two_issues);
  RUN_TEST(test_groups_of_another_crawler_do_not_count_toward_the_cap);
  RUN_TEST(test_rule_cap);
  RUN_TEST(test_rules_of_another_crawler_do_not_count_toward_the_cap);
  RUN_TEST(test_user_agent_cap);
  RUN_TEST(test_user_agents_of_another_crawler_free_their_slots);
  RUN_TEST(test_user_agent_cap_spans_groups);
  RUN_TEST(test_issue_cap_keeps_50_and_counts_every_issue);
  RUN_TEST(test_our_user_agent_groups_win_over_wildcard_groups);
  RUN_TEST(test_wildcard_groups_merge_when_no_group_has_our_user_agent);
  RUN_TEST(test_our_user_agent_groups_merge);
  RUN_TEST(test_no_kept_group_allows_every_path);
  RUN_TEST(test_longest_pattern_wins_and_allow_wins_a_tie);
  RUN_TEST(test_pattern_length_is_counted_as_written);
  RUN_TEST(test_fish_and_php_wildcard_rows);
  RUN_TEST(test_wildcard_and_anchor_edges);
  RUN_TEST(test_percent_encoded_bytes_match_their_bytes);
  RUN_TEST(test_wildcard_steps_over_whole_units);
  RUN_TEST(test_hex_digit_edges_of_percent_encoding);
  RUN_TEST(test_percent_at_the_end_is_an_ordinary_byte);
  RUN_TEST(test_dropped_rule_answers_unknown);
  RUN_TEST(test_text_plain_raises_no_response_issue);
  RUN_TEST(test_other_content_types_raise_an_issue);
  RUN_TEST(test_redirect_to_another_host_raises_an_issue);
  RUN_TEST(test_failed_allocation_answers_false_with_the_result_zeroed);
  RUN_TEST(test_free_takes_a_zeroed_result_and_a_second_call);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
