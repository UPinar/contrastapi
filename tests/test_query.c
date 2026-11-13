#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "unity/unity.h"
#include "query.h"

void setUp(void)    {}
void tearDown(void) {}

void test_status_found_returns_ok(void)
{
  char out_buf[32];
  TEST_ASSERT_EQUAL_INT(QUERY_OK, query_paramGetStatus("severity=HIGH", "severity", out_buf, sizeof(out_buf)));
  TEST_ASSERT_EQUAL_STRING("HIGH", out_buf);
}

void test_status_missing_returns_notfound_and_clears(void)
{
  char out_buf[32] = "stale";
  TEST_ASSERT_EQUAL_INT(QUERY_NOTFOUND, query_paramGetStatus("severity=HIGH", "vendor", out_buf, sizeof(out_buf)));
  TEST_ASSERT_EQUAL_STRING("", out_buf);
}

void test_status_empty_query_returns_notfound_and_clears(void)
{
  char out_buf[32] = "stale";
  TEST_ASSERT_EQUAL_INT(QUERY_NOTFOUND, query_paramGetStatus("", "vendor", out_buf, sizeof(out_buf)));
  TEST_ASSERT_EQUAL_STRING("", out_buf);
}

void test_status_value_too_long_is_not_notfound(void)
{
  char out_buf[4];
  TEST_ASSERT_EQUAL_INT(QUERY_TOOLONG, query_paramGetStatus("vendor=cisco", "vendor", out_buf, sizeof(out_buf)));
}

void test_status_too_long_clears_out_buf(void)
{
  char out_buf[4] = "old";
  query_paramGetStatus("vendor=cisco", "vendor", out_buf, sizeof(out_buf));
  TEST_ASSERT_EQUAL_STRING("", out_buf);
}

void test_status_exact_fit_is_ok_not_too_long(void)
{
  char out_buf[4];
  TEST_ASSERT_EQUAL_INT(QUERY_OK, query_paramGetStatus("vendor=abc", "vendor", out_buf, sizeof(out_buf)));
  TEST_ASSERT_EQUAL_STRING("abc", out_buf);
}

void test_status_value_ending_at_ampersand_is_ok(void)
{
  char out_buf[4];
  TEST_ASSERT_EQUAL_INT(QUERY_OK, query_paramGetStatus("vendor=abc&limit=20", "vendor", out_buf, sizeof(out_buf)));
  TEST_ASSERT_EQUAL_STRING("abc", out_buf);
}

void test_status_leading_question_mark_tolerated(void)
{
  char out_buf[32];
  TEST_ASSERT_EQUAL_INT(QUERY_OK, query_paramGetStatus("?limit=20", "limit", out_buf, sizeof(out_buf)));
  TEST_ASSERT_EQUAL_STRING("20", out_buf);
}

void test_status_middle_param_found(void)
{
  char out_buf[32];
  TEST_ASSERT_EQUAL_INT(QUERY_OK, query_paramGetStatus("a=1&limit=20&z=9", "limit", out_buf, sizeof(out_buf)));
  TEST_ASSERT_EQUAL_STRING("20", out_buf);
}

void test_status_last_param_found(void)
{
  char out_buf[32];
  TEST_ASSERT_EQUAL_INT(QUERY_OK, query_paramGetStatus("a=1&offset=40", "offset", out_buf, sizeof(out_buf)));
  TEST_ASSERT_EQUAL_STRING("40", out_buf);
}

void test_status_prefix_key_no_false_match(void)
{
  char out_buf[32];
  TEST_ASSERT_EQUAL_INT(QUERY_NOTFOUND, query_paramGetStatus("limit=20", "lim", out_buf, sizeof(out_buf)));
}

void test_status_null_query_returns_notfound(void)
{
  char out_buf[32] = "stale";
  TEST_ASSERT_EQUAL_INT(QUERY_NOTFOUND, query_paramGetStatus(NULL, "limit", out_buf, sizeof(out_buf)));
  TEST_ASSERT_EQUAL_STRING("", out_buf);
}

void test_nextParamName_reads_each_segment_name(void)
{
  const struct { const char* mp_query; const char* mp_names; } cases[] = {
    { "",                 ""                },
    { "?",                ""                },
    { "?&&&",             ""                },
    { "limit=20",         "limit="          },
    { "?limit=20&sort",   "limit= sort"     },
    { "&&a=1&&b=2&",      "a= b="           },
    { "=x&a=b=c",         "= a="            },
    { "??a=1",            "?a="             },
    { "incl%75de=ghsa",   "incl%75de="      },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char names[64] = "";
    size_t used = 0;
    size_t offset = 0;
    QueryParamName_t param_name;
    while (query_nextParamName(cases[i].mp_query, &offset, &param_name))
    {
      int written = snprintf(names + used, sizeof(names) - used, "%s%.*s%s", used ? " " : "", (int)param_name.m_len, param_name.mp_start, param_name.m_hasValue ? "=" : "");
      TEST_ASSERT_TRUE_MESSAGE(written > 0 && (size_t)written < sizeof(names) - used, cases[i].mp_query);
      used += (size_t)written;
    }
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_names, names, cases[i].mp_query);
  }
}

void test_status_decodes_the_value_and_refuses_a_bad_escape(void)
{
  static const struct { const char* mp_query; const char* mp_name; size_t m_size; QueryStatus_t m_status; const char* mp_value; } cases[] = {
    { "v=a+b",             "v",      16, QUERY_OK,          "a b" },
    { "v=red%20hat",       "v",      16, QUERY_OK,          "red hat" },
    { "v=%2B",             "v",      16, QUERY_OK,          "+" },
    { "v=%2b",             "v",      16, QUERY_OK,          "+" },
    { "v=%2a%2f",          "v",      16, QUERY_OK,          "*/" },
    { "v=%25",             "v",      16, QUERY_OK,          "%" },
    { "v=%2541",           "v",      16, QUERY_OK,          "%41" },
    { "v=a%26limit%3D5",   "v",      16, QUERY_OK,          "a&limit=5" },
    { "v=%C3%BC",          "v",      16, QUERY_OK,          "\xC3\xBC" },
    { "v=a%0Ab",           "v",      16, QUERY_OK,          "a\nb" },
    { "v=%7F",             "v",      16, QUERY_OK,          "\x7F" },
    { "v=%",               "v",      16, QUERY_BADENCODING, "" },
    { "v=a%",              "v",      16, QUERY_BADENCODING, "" },
    { "v=%4",              "v",      16, QUERY_BADENCODING, "" },
    { "v=%4&w=1",          "v",      16, QUERY_BADENCODING, "" },
    { "v=%zz",             "v",      16, QUERY_BADENCODING, "" },
    { "v=%4g",             "v",      16, QUERY_BADENCODING, "" },
    { "v=%00",             "v",      16, QUERY_NUL,         "" },
    { "v=a%00b",           "v",      16, QUERY_NUL,         "" },
    { "in%5Fkev=true",     "in_kev", 16, QUERY_NOTFOUND,    "" },
    { "v=abc",             "v",      4,  QUERY_OK,          "abc" },
    { "v=abcd",            "v",      4,  QUERY_TOOLONG,     "" },
    { "v=%41%42%43",       "v",      4,  QUERY_OK,          "ABC" },
    { "v=%41%42%43%44",    "v",      4,  QUERY_TOOLONG,     "" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char out_buf[16] = "stale";
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, query_paramGetStatus(cases[i].mp_query, cases[i].mp_name, out_buf, cases[i].m_size), cases[i].mp_query);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_value, out_buf, cases[i].mp_query);
  }
}

void test_status_bad_escape_at_the_end_reads_nothing_past_it(void)
{
  static const char query[] = "v=%";
  char* heap_query = malloc(sizeof(query));
  TEST_ASSERT_NOT_NULL(heap_query);
  memcpy(heap_query, query, sizeof(query));
  char out_buf[16];
  TEST_ASSERT_EQUAL_INT(QUERY_BADENCODING, query_paramGetStatus(heap_query, "v", out_buf, sizeof(out_buf)));
  free(heap_query);
}

void test_status_empty_value_is_ok_not_notfound(void)
{
  char out_buf[32];
  TEST_ASSERT_EQUAL_INT(QUERY_OK, query_paramGetStatus("vendor=&limit=20", "vendor", out_buf, sizeof(out_buf)));
  TEST_ASSERT_EQUAL_STRING("", out_buf);
}

void test_percentDecode_decodes_and_names_each_refusal(void)
{
  static const struct { const char* mp_text; bool m_isPlusASpace; QueryStatus_t m_status; const char* mp_decoded; } cases[] = {
    { "a+b",      false, QUERY_OK,          "a+b" },
    { "a+b",      true,  QUERY_OK,          "a b" },
    { "a%2Bb",    false, QUERY_OK,          "a+b" },
    { "%40%2f",   false, QUERY_OK,          "@/" },
    { "1234567",  false, QUERY_OK,          "1234567" },
    { "12345678", false, QUERY_TOOLONG,     "" },
    { "%41%42%43%44%45%46%47%48", false, QUERY_TOOLONG, "" },
    { "a%",       false, QUERY_BADENCODING, "" },
    { "a%4",      false, QUERY_BADENCODING, "" },
    { "a%g1",     false, QUERY_BADENCODING, "" },
    { "a%1g",     false, QUERY_BADENCODING, "" },
    { "a%00",     false, QUERY_NUL,         "" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char out_buf[8] = "stale";
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, query_percentDecode(cases[i].mp_text, strlen(cases[i].mp_text), cases[i].m_isPlusASpace, out_buf, sizeof(out_buf)), cases[i].mp_text);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_decoded, out_buf, cases[i].mp_text);
  }
}

void test_percentDecode_reads_only_text_len_bytes(void)
{
  char out_buf[8];
  TEST_ASSERT_EQUAL_INT(QUERY_BADENCODING, query_percentDecode("ab%41", 3, false, out_buf, sizeof(out_buf)));
  TEST_ASSERT_EQUAL_INT(QUERY_BADENCODING, query_percentDecode("ab%41", 4, false, out_buf, sizeof(out_buf)));
  TEST_ASSERT_EQUAL_INT(QUERY_OK, query_percentDecode("ab%4142", 5, false, out_buf, sizeof(out_buf)));
  TEST_ASSERT_EQUAL_STRING("abA", out_buf);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_status_found_returns_ok);
  RUN_TEST(test_status_missing_returns_notfound_and_clears);
  RUN_TEST(test_status_empty_query_returns_notfound_and_clears);
  RUN_TEST(test_status_value_too_long_is_not_notfound);
  RUN_TEST(test_status_too_long_clears_out_buf);
  RUN_TEST(test_status_exact_fit_is_ok_not_too_long);
  RUN_TEST(test_status_value_ending_at_ampersand_is_ok);
  RUN_TEST(test_status_leading_question_mark_tolerated);
  RUN_TEST(test_status_middle_param_found);
  RUN_TEST(test_status_last_param_found);
  RUN_TEST(test_status_prefix_key_no_false_match);
  RUN_TEST(test_status_null_query_returns_notfound);
  RUN_TEST(test_status_empty_value_is_ok_not_notfound);
  RUN_TEST(test_status_decodes_the_value_and_refuses_a_bad_escape);
  RUN_TEST(test_status_bad_escape_at_the_end_reads_nothing_past_it);
  RUN_TEST(test_percentDecode_decodes_and_names_each_refusal);
  RUN_TEST(test_percentDecode_reads_only_text_len_bytes);
  RUN_TEST(test_nextParamName_reads_each_segment_name);
  return UNITY_END();
}
