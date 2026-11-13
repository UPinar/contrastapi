#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity/unity.h"
#include "jsonread.h"

void setUp(void)    {}
void tearDown(void) {}

static void static_spanToString(JsonReadSpan_t span, char* buf, size_t buf_size)
{
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToRawStringStatus(span, buf, buf_size));
}

void test_get_str_simple(void)
{
  char out[64];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_strStatus("{\"key\":\"value\"}", "key", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("value", out);
}

void test_get_str_missing(void)
{
  char out[64];
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_strStatus("{\"key\":\"value\"}", "other", out, sizeof(out)));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_strStatus("{\"key\":\"value\"}", "KEY", out, sizeof(out)));
}

void test_get_str_with_spaces(void)
{
  char out[64];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_strStatus("{\"key\" : \"val\"}", "key", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("val", out);
}

void test_get_str_escape_quote(void)
{
  char out[64];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_strStatus("{\"k\":\"a\\\"b\"}", "k", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("a\"b", out);
}

void test_get_str_escape_newline(void)
{
  char out[64];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_strStatus("{\"k\":\"a\\nb\"}", "k", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("a\nb", out);
}

void test_get_str_escape_backslash(void)
{
  char out[64];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_strStatus("{\"k\":\"a\\\\b\"}", "k", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("a\\b", out);
}

void test_get_str_buffer_too_small(void)
{
  char out[4];
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TOOLONG, jsonread_strStatus("{\"k\":\"hello\"}", "k", out, sizeof(out)));
}

void test_get_str_key_appears_as_value(void)
{
  char out[64];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_strStatus(
      "{\"other\":\"key\",\"key\":\"correct\"}", "key", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("correct", out);
}

void test_get_str_empty_value(void)
{
  char out[64];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_strStatus("{\"k\":\"\"}", "k", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("", out);
}

void test_get_str_escape_slash_cr_tab(void)
{
  char out[64];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_strStatus("{\"k\":\"a\\/b\\r\\tc\"}", "k", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("a/b\r\tc", out);
}

void test_get_str_escape_backspace_formfeed(void)
{
  char out[64];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_strStatus("{\"k\":\"x\\by\\fz\"}", "k", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("x\by\fz", out);
}

void test_get_str_invalid_escape_rejected(void)
{
  char out[64];
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_SYNTAX, jsonread_strStatus("{\"k\":\"a\\xb\"}", "k", out, sizeof(out)));
}

void test_get_str_type_mismatch_is_distinct_from_missing(void)
{
  char out[64];
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_strStatus("{\"k\":42}",      "k", out, sizeof(out)));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_strStatus("{\"k\":null}",    "k", out, sizeof(out)));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_strStatus("{\"k\":true}",    "k", out, sizeof(out)));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_strStatus("{\"k\":[1,2]}",   "k", out, sizeof(out)));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_strStatus("{\"k\":{\"a\":1}}", "k", out, sizeof(out)));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_strStatus("{\"k\":42}", "other", out, sizeof(out)));
}

void test_get_str_type_mismatch_leaves_out_empty(void)
{
  char out[16] = "published_time";
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_strStatus("{\"k\":42}", "k", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("", out);
}

void test_get_str_too_long_is_distinct_from_missing(void)
{
  char out[4];
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TOOLONG,  jsonread_strStatus("{\"k\":\"hello\"}", "k", out, sizeof(out)));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_strStatus("{\"k\":\"hello\"}", "other", out, sizeof(out)));
}

void test_get_str_too_long_leaves_out_empty(void)
{
  char out[4] = "zzz";
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TOOLONG, jsonread_strStatus("{\"k\":\"hello\"}", "k", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("", out);
}

void test_get_str_missing_keeps_the_callers_default(void)
{
  char out[16] = "published_time";
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_strStatus("{\"k\":\"v\"}", "other", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("published_time", out);
}

void test_get_str_exact_fit_accepted(void)
{
  char out[6];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_strStatus("{\"k\":\"hello\"}", "k", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("hello", out);
}

void test_get_str_one_over_is_too_long(void)
{
  char out[5];
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TOOLONG, jsonread_strStatus("{\"k\":\"hello\"}", "k", out, sizeof(out)));
}

void test_get_str_unterminated_is_syntax_not_too_long(void)
{
  char out[64];
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_SYNTAX, jsonread_strStatus("{\"k\":\"abc", "k", out, sizeof(out)));
}

void test_get_int_simple(void)
{
  long out = 0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_intStatus("{\"count\":42}", "count", &out));
  TEST_ASSERT_EQUAL_INT(42, (int)out);
}

void test_get_int_negative(void)
{
  long out = 0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_intStatus("{\"n\":-7}", "n", &out));
  TEST_ASSERT_EQUAL_INT(-7, (int)out);
}

void test_get_int_missing(void)
{
  long out = 0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_intStatus("{\"a\":1}", "b", &out));
}

void test_get_int_not_number(void)
{
  long out = 0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_intStatus("{\"k\":\"str\"}", "k", &out));
}

void test_get_int_zero(void)
{
  long out = -1;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_intStatus("{\"v\":0}", "v", &out));
  TEST_ASSERT_EQUAL_INT(0, (int)out);
}

void test_get_int_key_appears_as_value(void)
{
  long out = 0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_intStatus("{\"note\":\"count\",\"count\":7}", "count", &out));
  TEST_ASSERT_EQUAL_INT(7, (int)out);
}

void test_get_int_failure_leaves_out_untouched(void)
{
  long out = 111;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_intStatus("{\"a\":1}", "b", &out));
  TEST_ASSERT_EQUAL_INT(111, (int)out);
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE,     jsonread_intStatus("{\"k\":\"str\"}", "k", &out));
  TEST_ASSERT_EQUAL_INT(111, (int)out);

  out = 222;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_intStatus("{\"a\":1}", "b", &out));
  TEST_ASSERT_EQUAL_INT(222, (int)out);
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE,     jsonread_intStatus("{\"k\":\"str\"}", "k", &out));
  TEST_ASSERT_EQUAL_INT(222, (int)out);
}

void test_get_int_rejects_trailing_bytes(void)
{
  long out = 111;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_intStatus("{\"k\":50abc}", "k", &out));
  TEST_ASSERT_EQUAL_INT(111, (int)out);
}

void test_number_readers_reject_a_partially_consumed_number(void)
{
  double parsed_double = -1.0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_doubleStatus("{\"k\":1.2.3}", "k", &parsed_double));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_doubleStatus("{\"k\":1-2}",   "k", &parsed_double));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_doubleStatus("{\"k\":9.0e}",  "k", &parsed_double));
  TEST_ASSERT_EQUAL_INT(-100, (int)(parsed_double * 100.0));

  long parsed_int = -7;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_intStatus("{\"k\":1e3}",  "k", &parsed_int));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_intStatus("{\"k\":20.9}", "k", &parsed_int));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_intStatus("{\"k\":1.2.3}","k", &parsed_int));
  TEST_ASSERT_EQUAL_INT(-7, (int)parsed_int);
}

void test_number_readers_accept_every_value_terminator(void)
{
  long out = 0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_intStatus("{\"k\":50,\"x\":1}", "k", &out));
  TEST_ASSERT_EQUAL_INT(50, (int)out);
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_intStatus("{\"k\":50}", "k", &out));
  TEST_ASSERT_EQUAL_INT(50, (int)out);
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_intStatus("{\"k\":50]", "k", &out));
  TEST_ASSERT_EQUAL_INT(50, (int)out);
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_intStatus("{\"k\": 50 }", "k", &out));
  TEST_ASSERT_EQUAL_INT(50, (int)out);
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_intStatus("{\"k\":50", "k", &out));
  TEST_ASSERT_EQUAL_INT(50, (int)out);
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_intStatus("{\"k\":50\t}", "k", &out));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_intStatus("{\"k\":50\n}", "k", &out));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_intStatus("{\"k\":50\r\n}", "k", &out));
  TEST_ASSERT_EQUAL_INT(50, (int)out);

  double score = 0.0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_doubleStatus("{\"k\":1.2e3}", "k", &score));
  TEST_ASSERT_EQUAL_INT(120000, (int)(score * 100.0));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_doubleStatus("{\"k\":-1.5,\"x\":1}", "k", &score));
  TEST_ASSERT_EQUAL_INT(-150, (int)(score * 100.0));
}

void test_get_double_simple(void)
{
  double out = 0.0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_doubleStatus("{\"score\":0.85}", "score", &out));
  TEST_ASSERT_EQUAL_INT(850, (int)(out * 1000));
}

void test_get_double_integer_value(void)
{
  double out = 0.0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_doubleStatus("{\"v\":3}", "v", &out));
  TEST_ASSERT_EQUAL_INT(3, (int)out);
}

void test_get_double_missing(void)
{
  double out = 0.0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_doubleStatus("{\"a\":1.0}", "b", &out));
}

void test_get_double_negative(void)
{
  double out = 0.0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_doubleStatus("{\"v\":-1.5}", "v", &out));
  TEST_ASSERT_EQUAL_INT(-1500, (int)(out * 1000));
}

void test_get_double_scientific(void)
{
  double out = 0.0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_doubleStatus("{\"v\":9e3}", "v", &out));
  TEST_ASSERT_EQUAL_INT(9000, (int)out);
}

void test_get_double_failure_leaves_out_untouched(void)
{
  double out = 1.5;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_doubleStatus("{\"a\":1.0}", "b", &out));
  TEST_ASSERT_EQUAL_INT(1500, (int)(out * 1000));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE,     jsonread_doubleStatus("{\"k\":\"str\"}", "k", &out));
  TEST_ASSERT_EQUAL_INT(1500, (int)(out * 1000));

  out = -2.5;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_doubleStatus("{\"a\":1.0}", "b", &out));
  TEST_ASSERT_EQUAL_INT(-2500, (int)(out * 1000));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE,     jsonread_doubleStatus("{\"k\":\"str\"}", "k", &out));
  TEST_ASSERT_EQUAL_INT(-2500, (int)(out * 1000));
}

void test_bool_status_true_and_false_are_ok(void)
{
  bool out = false;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_boolStatus("{\"active\":true}", "active", &out));
  TEST_ASSERT_TRUE(out);

  out = true;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_boolStatus("{\"active\":false}", "active", &out));
  TEST_ASSERT_FALSE(out);
}

void test_bool_status_missing_is_notfound_and_leaves_out_untouched(void)
{
  bool out = true;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_boolStatus("{\"x\":true}", "y", &out));
  TEST_ASSERT_TRUE(out);

  out = false;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_boolStatus("{\"x\":true}", "y", &out));
  TEST_ASSERT_FALSE(out);
}

void test_bool_status_wrong_type_is_type_not_notfound(void)
{
  const char* bodies[] = {
    "{\"a\":1}", "{\"a\":0}", "{\"a\":-1}", "{\"a\":1.0}",
    "{\"a\":\"true\"}", "{\"a\":\"false\"}", "{\"a\":null}",
    "{\"a\":[]}", "{\"a\":[true]}", "{\"a\":{}}"
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    bool out = true;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_TYPE, jsonread_boolStatus(bodies[i], "a", &out), bodies[i]);
    TEST_ASSERT_TRUE_MESSAGE(out, bodies[i]);

    out = false;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_TYPE, jsonread_boolStatus(bodies[i], "a", &out), bodies[i]);
    TEST_ASSERT_FALSE_MESSAGE(out, bodies[i]);
  }
}

void test_bool_status_garbage_suffix_is_type(void)
{
  bool out = true;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_boolStatus("{\"a\":trueXYZ}", "a", &out));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_boolStatus("{\"a\":falsehood}", "a", &out));
  TEST_ASSERT_TRUE(out);

  out = false;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_boolStatus("{\"a\":trueXYZ}", "a", &out));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_boolStatus("{\"a\":falsehood}", "a", &out));
  TEST_ASSERT_FALSE(out);
}

void test_bool_status_terminators(void)
{
  bool out = false;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_boolStatus("{\"a\":true,\"b\":1}", "a", &out));
  TEST_ASSERT_TRUE(out);
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_boolStatus("{\"a\":false }", "a", &out));
  TEST_ASSERT_FALSE(out);
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_boolStatus("{\"a\":true}", "a", &out));
  TEST_ASSERT_TRUE(out);
}

void test_bool_status_truncated_literal_is_type(void)
{
  const char* bodies[] = {
    "{\"a\":tru}", "{\"a\":fals}", "{\"a\":t}", "{\"a\":f}",
    "{\"a\":tru,\"b\":1}", "{\"a\":fals }"
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    bool out = true;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_TYPE, jsonread_boolStatus(bodies[i], "a", &out), bodies[i]);
    TEST_ASSERT_TRUE_MESSAGE(out, bodies[i]);
  }
}

void test_root_simple_object(void)
{
  const char* json = "{\"a\":1}";
  JsonReadSpan_t root_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  char buf[32];
  static_spanToString(root_span, buf, sizeof buf);
  TEST_ASSERT_EQUAL_STRING("{\"a\":1}", buf);
}

void test_root_refuses_a_null_text(void)
{
  JsonReadSpan_t span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_SYNTAX, jsonread_root(NULL, 4, &span));
}

void test_root_rejects_empty(void)
{
  const char* json = "   ";
  JsonReadSpan_t root_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_SYNTAX, jsonread_root(json, strlen(json), &root_span));
}

void test_root_skips_utf8_bom(void)
{
  const char* json = "\xEF\xBB\xBF{\"a\":1}";
  JsonReadSpan_t root_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  char buf[32];
  static_spanToString(root_span, buf, sizeof buf);
  TEST_ASSERT_EQUAL_STRING("{\"a\":1}", buf);
}

void test_root_bom_alone_is_still_syntax_error(void)
{
  const char* json = "\xEF\xBB\xBF";
  JsonReadSpan_t root_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_SYNTAX, jsonread_root(json, strlen(json), &root_span));
}

void test_root_rejects_bom_inside_the_document(void)
{
  const char* json = "{\"a\":\xEF\xBB\xBF 1}";
  JsonReadSpan_t root_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_SYNTAX, jsonread_root(json, strlen(json), &root_span));
}

void test_root_rejects_second_bom(void)
{
  const char* json = "\xEF\xBB\xBF\xEF\xBB\xBF{\"a\":1}";
  JsonReadSpan_t root_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_SYNTAX, jsonread_root(json, strlen(json), &root_span));
}

void test_objectKey_string_value_keeps_quotes(void)
{
  const char* json = "{\"name\":\"cve_lookup\"}";
  JsonReadSpan_t root_span, name_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "name", &name_span));
  char buf[32];
  static_spanToString(name_span, buf, sizeof buf);
  TEST_ASSERT_EQUAL_STRING("\"cve_lookup\"", buf);
}

void test_objectKey_object_value(void)
{
  const char* json = "{\"params\":{\"x\":1},\"id\":3}";
  JsonReadSpan_t root_span, params_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "params", &params_span));
  char buf[32];
  static_spanToString(params_span, buf, sizeof buf);
  TEST_ASSERT_EQUAL_STRING("{\"x\":1}", buf);
}

void test_objectKey_array_value(void)
{
  const char* json = "{\"ids\":[\"a\",\"b\"]}";
  JsonReadSpan_t root_span, ids_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "ids", &ids_span));
  char buf[32];
  static_spanToString(ids_span, buf, sizeof buf);
  TEST_ASSERT_EQUAL_STRING("[\"a\",\"b\"]", buf);
}

void test_objectKey_not_found(void)
{
  const char* json = "{\"a\":1,\"b\":2}";
  JsonReadSpan_t root_span, missing_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_objectKey(root_span, "c", &missing_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_objectKey(root_span, "A", &missing_span));
}

void test_objectKey_nested_chain(void)
{
  const char* json =
    "{\"method\":\"tools/call\",\"params\":{\"name\":\"cve_lookup\","
    "\"arguments\":{\"id\":\"CVE-2021-44228\"}}}";
  JsonReadSpan_t root_span, params_span, args_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "params", &params_span));

  char params_buf[256];
  static_spanToString(params_span, params_buf, sizeof params_buf);
  char name[64];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_strStatus(params_buf, "name", name, sizeof name));
  TEST_ASSERT_EQUAL_STRING("cve_lookup", name);

  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(params_span, "arguments", &args_span));
  char args_buf[128];
  static_spanToString(args_span, args_buf, sizeof args_buf);
  char id[32];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_strStatus(args_buf, "id", id, sizeof id));
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", id);
}

void test_objectKey_skips_escaped_quote_value(void)
{
  const char* json = "{\"a\":\"va\\\"lue\",\"b\":\"found\"}";
  JsonReadSpan_t root_span, b_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "b", &b_span));
  char buf[32];
  static_spanToString(b_span, buf, sizeof buf);
  TEST_ASSERT_EQUAL_STRING("\"found\"", buf);
}

void test_arrayLen_empty(void)
{
  const char* json = "{\"ids\":[]}";
  JsonReadSpan_t root_span, ids_span;
  size_t n = 99;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "ids", &ids_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_arrayLen(ids_span, &n));
  TEST_ASSERT_EQUAL_size_t(0, n);
}

void test_arrayLen_three(void)
{
  const char* json = "{\"ids\":[\"a\",\"b\",\"c\"]}";
  JsonReadSpan_t root_span, ids_span;
  size_t n = 0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "ids", &ids_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_arrayLen(ids_span, &n));
  TEST_ASSERT_EQUAL_size_t(3, n);
}

void test_arrayNextElement_iterates(void)
{
  const char* json = "{\"ids\":[10,20,30]}";
  JsonReadSpan_t root_span, ids_span, element_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "ids", &ids_span));

  size_t offset = 0;
  char buf[16];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_arrayNextElement(ids_span, &offset, &element_span));
  static_spanToString(element_span, buf, sizeof buf);
  TEST_ASSERT_EQUAL_STRING("10", buf);
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_arrayNextElement(ids_span, &offset, &element_span));
  static_spanToString(element_span, buf, sizeof buf);
  TEST_ASSERT_EQUAL_STRING("20", buf);
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_arrayNextElement(ids_span, &offset, &element_span));
  static_spanToString(element_span, buf, sizeof buf);
  TEST_ASSERT_EQUAL_STRING("30", buf);
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_arrayNextElement(ids_span, &offset, &element_span));
}

void test_malformed_unbalanced_brace(void)
{
  const char* json = "{\"a\":{\"b\":1}";
  JsonReadSpan_t root_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_SYNTAX, jsonread_root(json, strlen(json), &root_span));
}

void test_malformed_unterminated_string(void)
{
  const char* json = "{\"a\":\"oops}";
  JsonReadSpan_t root_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_SYNTAX, jsonread_root(json, strlen(json), &root_span));
}

void test_depth_exceeded(void)
{
  char deep[128];
  int levels = 40;
  for (int i = 0; i < levels; i++)          deep[i]          = '[';
  for (int i = 0; i < levels; i++)          deep[levels + i] = ']';
  deep[2 * levels] = '\0';
  JsonReadSpan_t root_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_DEPTH, jsonread_root(deep, strlen(deep), &root_span));
}

void test_spanToString_truncates(void)
{
  const char* json = "{\"a\":1}";
  JsonReadSpan_t root_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  char tiny[3];
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TOOLONG, jsonread_spanToRawStringStatus(root_span, tiny, sizeof tiny));
}

void test_spanToString_fits_exactly_and_one_byte_less_is_toolong(void)
{
  const char* json = "{\"a\":1}";
  JsonReadSpan_t root_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  char buf[16];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToRawStringStatus(root_span, buf, 8));
  TEST_ASSERT_EQUAL_STRING(json, buf);

  memset(buf, 'z', sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TOOLONG, jsonread_spanToRawStringStatus(root_span, buf, 7));
  TEST_ASSERT_EQUAL_STRING("zzzzzzzzzzzzzzz", buf);
}

void test_objectKey_substring_collision(void)
{
  const char* json = "{\"vid\":1,\"id\":2}";
  JsonReadSpan_t root_span, id_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "id", &id_span));
  char buf[8];
  static_spanToString(id_span, buf, sizeof buf);
  TEST_ASSERT_EQUAL_STRING("2", buf);
}

void test_objectKey_duplicate_returns_first(void)
{
  const char* json = "{\"a\":1,\"a\":2}";
  JsonReadSpan_t root_span, a_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "a", &a_span));
  char buf[8];
  static_spanToString(a_span, buf, sizeof buf);
  TEST_ASSERT_EQUAL_STRING("1", buf);
}

void test_skip_string_with_escaped_backslash(void)
{
  const char* json = "{\"a\":\"\\\\\",\"b\":7}";
  JsonReadSpan_t root_span, b_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "b", &b_span));
  char buf[8];
  static_spanToString(b_span, buf, sizeof buf);
  TEST_ASSERT_EQUAL_STRING("7", buf);
}

void test_root_top_level_array(void)
{
  const char* json = "[1,2,3]";
  JsonReadSpan_t root_span;
  size_t n = 0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_arrayLen(root_span, &n));
  TEST_ASSERT_EQUAL_size_t(3, n);
}

void test_objectKey_on_array_is_syntax_error(void)
{
  const char* json = "{\"ids\":[1,2]}";
  JsonReadSpan_t root_span, ids_span, missing_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "ids", &ids_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_SYNTAX, jsonread_objectKey(ids_span, "x", &missing_span));
}

void test_objectKey_literal_values(void)
{
  const char* json = "{\"a\":true,\"b\":false,\"c\":null,\"d\":5}";
  JsonReadSpan_t root_span, a_span, b_span, c_span, d_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "a", &a_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "b", &b_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "c", &c_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "d", &d_span));
  char buf[8];
  static_spanToString(a_span, buf, sizeof buf); TEST_ASSERT_EQUAL_STRING("true",  buf);
  static_spanToString(b_span, buf, sizeof buf); TEST_ASSERT_EQUAL_STRING("false", buf);
  static_spanToString(c_span, buf, sizeof buf); TEST_ASSERT_EQUAL_STRING("null",  buf);
  static_spanToString(d_span, buf, sizeof buf); TEST_ASSERT_EQUAL_STRING("5",     buf);
}

void test_objectKey_bad_literal_is_syntax_error(void)
{
  const char* json = "{\"a\":tru}";
  JsonReadSpan_t root_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_SYNTAX, jsonread_root(json, strlen(json), &root_span));
}

void test_root_refuses_a_literal_in_another_case_or_with_its_last_letter_changed(void)
{
  static const char* const bodies[] = {
    "{\"a\":tRUE}", "{\"a\":fALSE}", "{\"a\":nULL}", "{\"a\":falsy}", "{\"a\":nulx}"
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    JsonReadSpan_t root_span;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_SYNTAX, jsonread_root(bodies[i], strlen(bodies[i]), &root_span), bodies[i]);
  }
}

void test_arrayNextElement_empty_array_is_notfound(void)
{
  static const char* const bodies[] = { "[]", "[ ]" };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    JsonReadSpan_t array_span = { bodies[i], strlen(bodies[i]) };
    JsonReadSpan_t element_span;
    size_t element_offset = 0;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_NOTFOUND, jsonread_arrayNextElement(array_span, &element_offset, &element_span), bodies[i]);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, element_offset, bodies[i]);
  }
}

void test_arrayLen_nested_elements(void)
{
  const char* json = "[{\"a\":1},{\"b\":[2,3]},{\"c\":4}]";
  JsonReadSpan_t root_span;
  size_t n = 0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_arrayLen(root_span, &n));
  TEST_ASSERT_EQUAL_size_t(3, n);
}

void test_root_trailing_garbage_rejected(void)
{
  const char* json = "{\"a\":1}garbage";
  JsonReadSpan_t root_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_SYNTAX, jsonread_root(json, strlen(json), &root_span));
}

void test_spanStr_plain(void)
{
  const char* json = "{\"name\":\"cve_lookup\"}";
  JsonReadSpan_t root_span, value_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "name", &value_span));
  char out[32];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToStrStatus(value_span, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("cve_lookup", out);
}

void test_spanStr_decodes_escapes(void)
{
  const char* json = "{\"k\":\"a\\\"b\\\\c\\/d\\ne\"}";
  JsonReadSpan_t root_span, value_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "k", &value_span));
  char out[32];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToStrStatus(value_span, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("a\"b\\c/d\ne", out);
}

void test_spanStr_array_element(void)
{
  const char* json = "[\"CVE-2021-44228\",\"CVE-2022-22965\"]";
  JsonReadSpan_t root_span, element_span;
  size_t offset = 0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_arrayNextElement(root_span, &offset, &element_span));
  char out[32];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToStrStatus(element_span, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", out);
}

void test_spanStr_rejects_non_string(void)
{
  const char* json = "{\"n\":42}";
  JsonReadSpan_t root_span, value_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "n", &value_span));
  char out[32];
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_spanToStrStatus(value_span, out, sizeof(out)));
}

void test_spanStr_and_get_str_decode_each_unicode_escape(void)
{
  static const struct { const char* mp_value; JsonReadStatus_t m_status; const char* mp_decoded; } cases[] = {
    { "a\\u0041b",      JSONREAD_OK,                 "aAb"              },
    { "\\u0001",        JSONREAD_OK,                 "\x01"             },
    { "\\u007f",        JSONREAD_OK,                 "\x7f"             },
    { "\\u0080",        JSONREAD_OK,                 "\xc2\x80"         },
    { "\\u07ff",        JSONREAD_OK,                 "\xdf\xbf"         },
    { "\\u0800",        JSONREAD_OK,                 "\xe0\xa0\x80"     },
    { "\\u09af",        JSONREAD_OK,                 "\xe0\xa6\xaf"     },
    { "\\u09AF",        JSONREAD_OK,                 "\xe0\xa6\xaf"     },
    { "\\ud7ff",        JSONREAD_OK,                 "\xed\x9f\xbf"     },
    { "\\ue000",        JSONREAD_OK,                 "\xee\x80\x80"     },
    { "\\uffff",        JSONREAD_OK,                 "\xef\xbf\xbf"     },
    { "\\ud800\\udc00", JSONREAD_OK,                 "\xf0\x90\x80\x80" },
    { "\\ud83d\\ude00", JSONREAD_OK,                 "\xf0\x9f\x98\x80" },
    { "\\udbff\\udfff", JSONREAD_OK,                 "\xf4\x8f\xbf\xbf" },
    { "\\udb40\\udc01", JSONREAD_OK,                 "\xf3\xa0\x80\x81" },
    { "a\\u0000b",      JSONREAD_ERR_NUL,            NULL               },
    { "\\ud800",        JSONREAD_ERR_LONE_SURROGATE, NULL               },
    { "\\udbff",        JSONREAD_ERR_LONE_SURROGATE, NULL               },
    { "\\udc00",        JSONREAD_ERR_LONE_SURROGATE, NULL               },
    { "\\udfff",        JSONREAD_ERR_LONE_SURROGATE, NULL               },
    { "\\ud800x",       JSONREAD_ERR_LONE_SURROGATE, NULL               },
    { "\\ud800\\n",     JSONREAD_ERR_LONE_SURROGATE, NULL               },
    { "\\ud800\\u0041", JSONREAD_ERR_LONE_SURROGATE, NULL               },
    { "\\ud800\\udbff", JSONREAD_ERR_LONE_SURROGATE, NULL               },
    { "\\udbff\\ue000", JSONREAD_ERR_LONE_SURROGATE, NULL               },
    { "\\ud800\\u12G4", JSONREAD_ERR_LONE_SURROGATE, NULL               },
    { "\\ud800\\xdc00", JSONREAD_ERR_LONE_SURROGATE, NULL               },
    { "\\ud800xudc00",  JSONREAD_ERR_LONE_SURROGATE, NULL               },
    { "\\u12G4",        JSONREAD_ERR_SYNTAX,         NULL               },
    { "\\u0g00",        JSONREAD_ERR_SYNTAX,         NULL               },
    { "\\u0:00",        JSONREAD_ERR_SYNTAX,         NULL               },
    { "\\u004",         JSONREAD_ERR_SYNTAX,         NULL               },
    { "\\U0041",        JSONREAD_ERR_SYNTAX,         NULL               },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char json[64];
    snprintf(json, sizeof(json), "{\"k\":\"%s\"}", cases[i].mp_value);
    char flat_out[32];
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, jsonread_strStatus(json, "k", flat_out, sizeof(flat_out)), cases[i].mp_value);

    JsonReadSpan_t root_span, value_span;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span), cases[i].mp_value);
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_OK, jsonread_objectKey(root_span, "k", &value_span), cases[i].mp_value);
    char span_out[32];
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_status, jsonread_spanToStrStatus(value_span, span_out, sizeof(span_out)), cases[i].mp_value);

    if (cases[i].m_status == JSONREAD_OK)
    {
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_decoded, flat_out, cases[i].mp_value);
      TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_decoded, span_out, cases[i].mp_value);
    }
    else
      TEST_ASSERT_EQUAL_STRING_MESSAGE("", flat_out, cases[i].mp_value);
  }
}

void test_spanStr_and_get_str_never_cut_a_decoded_character_short(void)
{
  static const struct { const char* mp_value; size_t m_decodedLen; } cases[] = {
    { "a\\u00e9",        3 },
    { "a\\u20ac",        4 },
    { "a\\ud83d\\ude00", 5 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char json[64];
    snprintf(json, sizeof(json), "{\"k\":\"%s\"}", cases[i].mp_value);
    JsonReadSpan_t root_span, value_span;
    TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
    TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "k", &value_span));
    const size_t fit = cases[i].m_decodedLen + 1;
    char out[8];

    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_OK, jsonread_strStatus(json, "k", out, fit), cases[i].mp_value);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(cases[i].m_decodedLen, strlen(out), cases[i].mp_value);
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_OK, jsonread_spanToStrStatus(value_span, out, fit), cases[i].mp_value);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(cases[i].m_decodedLen, strlen(out), cases[i].mp_value);

    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_TOOLONG, jsonread_strStatus(json, "k", out, fit - 1), cases[i].mp_value);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", out, cases[i].mp_value);
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_TOOLONG, jsonread_spanToStrStatus(value_span, out, fit - 1), cases[i].mp_value);
  }
}

void test_spanStr_reads_no_byte_past_a_span_that_ends_after_a_high_surrogate(void)
{
  static const char text[] = "\"\\ud800";
  char* exact = malloc(sizeof(text) - 1);
  TEST_ASSERT_NOT_NULL(exact);
  memcpy(exact, text, sizeof(text) - 1);
  JsonReadSpan_t span = { exact, sizeof(text) - 1 };
  char out[8];
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_LONE_SURROGATE, jsonread_spanToStrStatus(span, out, sizeof(out)));
  free(exact);
}

void test_spanStr_buffer_too_small(void)
{
  const char* json = "{\"k\":\"abcdef\"}";
  JsonReadSpan_t root_span, value_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "k", &value_span));
  char out[4];
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TOOLONG, jsonread_spanToStrStatus(value_span, out, sizeof(out)));
}

void test_spanStr_value_that_fills_the_buffer_exactly_is_read(void)
{
  const char*    text = "\"abc\"";
  JsonReadSpan_t span = { text, strlen(text) };
  char out[8];
  memset(out, 'z', sizeof(out) - 1);
  out[sizeof(out) - 1] = '\0';
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToStrStatus(span, out, 4));
  TEST_ASSERT_EQUAL_STRING("abc", out);
}

void test_spanStr_value_one_byte_over_the_buffer_is_refused(void)
{
  const char*    text = "\"abcd\"";
  JsonReadSpan_t span = { text, strlen(text) };
  char out[8];
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TOOLONG, jsonread_spanToStrStatus(span, out, 4));
}

void test_spanStr_size_limit_counts_decoded_bytes(void)
{
  const char*    quote_text     = "\"a\\\"b\"";
  const char*    backslash_text = "\"ab\\\\\"";
  const char*    over_text      = "\"ab\\\"c\"";
  JsonReadSpan_t quote_span     = { quote_text, strlen(quote_text) };
  JsonReadSpan_t backslash_span = { backslash_text, strlen(backslash_text) };
  JsonReadSpan_t over_span      = { over_text, strlen(over_text) };
  char out[8];

  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToStrStatus(quote_span, out, 4));
  TEST_ASSERT_EQUAL_STRING("a\"b", out);
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToStrStatus(backslash_span, out, 4));
  TEST_ASSERT_EQUAL_STRING("ab\\", out);
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TOOLONG, jsonread_spanToStrStatus(over_span, out, 4));
}

void test_spanStr_empty_string_fits_a_one_byte_buffer(void)
{
  const char*    text = "\"\"";
  JsonReadSpan_t span = { text, strlen(text) };
  char out[8] = "zzz";
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToStrStatus(span, out, 1));
  TEST_ASSERT_EQUAL_STRING("", out);
}

void test_spanStr_span_that_ends_before_its_closing_quote_is_refused(void)
{
  const char*    text = "\"abc\"";
  JsonReadSpan_t span = { text, strlen(text) - 1 };
  char out[8];
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_SYNTAX, jsonread_spanToStrStatus(span, out, sizeof(out)));
}

void test_spanStr_empty_span_is_type(void)
{
  const char*    text = "\"abc\"";
  JsonReadSpan_t span = { text, 0 };
  char out[8];
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_spanToStrStatus(span, out, sizeof(out)));
}

void test_spanStr_dangling_escape_is_syntax(void)
{
  char* text = malloc(4);
  TEST_ASSERT_NOT_NULL(text);
  memcpy(text, "\"ab\\", 4);
  JsonReadSpan_t span = { text, 4 };
  char out[8];
  JsonReadStatus_t status = jsonread_spanToStrStatus(span, out, sizeof(out));
  free(text);
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_SYNTAX, status);
}

void test_root_raw_control_char_in_value_or_name_is_syntax(void)
{
  static const char hex_digits[] = "0123456789abcdef";
  for (int control_byte = 0x01; control_byte < 0x20; control_byte++)
  {
    char message[] = { '0', 'x', hex_digits[control_byte >> 4], hex_digits[control_byte & 0x0F], '\0' };
    char in_value[] = { '{', '"', 'a', '"', ':', '"', 'x', (char)control_byte, '"', '}' };
    char in_name[]  = { '{', '"', (char)control_byte, '"', ':', '1', '}' };
    JsonReadSpan_t root_span;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_SYNTAX, jsonread_root(in_value, sizeof(in_value), &root_span), message);
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_SYNTAX, jsonread_root(in_name,  sizeof(in_name),  &root_span), message);
  }

  JsonReadSpan_t root_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root("{\"a\":\"x \"}", 10, &root_span));
}

void test_spanStr_raw_control_char_is_syntax(void)
{
  static const char hex_digits[] = "0123456789abcdef";
  for (int control_byte = 0x01; control_byte < 0x20; control_byte++)
  {
    char text[] = { '"', 'a', (char)control_byte, 'b', '"' };
    JsonReadSpan_t span = { text, sizeof(text) };
    char out[8];
    char message[] = { '0', 'x', hex_digits[control_byte >> 4], hex_digits[control_byte & 0x0F], '\0' };
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_SYNTAX, jsonread_spanToStrStatus(span, out, sizeof(out)), message);
  }

  const char*    text = "\"a b\"";
  JsonReadSpan_t span = { text, strlen(text) };
  char out[8];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToStrStatus(span, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("a b", out);
}

void test_spanStr_span_end_and_full_buffer_together_is_syntax(void)
{
  const char*    text = "\"abc\"";
  JsonReadSpan_t span = { text, strlen(text) - 1 };
  char out[8];
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_SYNTAX, jsonread_spanToStrStatus(span, out, 4));
}

void test_spanStr_decodes_the_remaining_escapes(void)
{
  const char*    text = "\"\\r\\t\\b\\f\"";
  JsonReadSpan_t span = { text, strlen(text) };
  char out[8];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToStrStatus(span, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("\r\t\b\f", out);
}

static JsonReadSpan_t static_spanOf(const char* text)
{
  JsonReadSpan_t span = { text, strlen(text) };
  return span;
}

void test_span_long_reads_a_number(void)
{
  long out = -1;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToLongStatus(static_spanOf("1234"), &out));
  TEST_ASSERT_EQUAL_INT(1234, out);

  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToLongStatus(static_spanOf("-7"), &out));
  TEST_ASSERT_EQUAL_INT(-7, out);

  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToLongStatus(static_spanOf("0"), &out));
  TEST_ASSERT_EQUAL_INT(0, out);
}

void test_span_long_rejects_trailing_bytes(void)
{
  long out = 99;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_spanToLongStatus(static_spanOf("12abc"), &out));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_spanToLongStatus(static_spanOf("1 2"), &out));
  TEST_ASSERT_EQUAL_INT(99, out);
}

void test_span_long_rejects_non_numeric_and_empty(void)
{
  long out = 99;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_spanToLongStatus(static_spanOf("true"), &out));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_spanToLongStatus(static_spanOf("\"12\""), &out));

  JsonReadSpan_t empty_span = { NULL, 0 };
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_spanToLongStatus(empty_span, &out));
  TEST_ASSERT_EQUAL_INT(99, out);
}

void test_span_long_rejects_an_implausibly_wide_span(void)
{
  long out = 99;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_RANGE, jsonread_spanToLongStatus(static_spanOf("1111111111111111111111111111111111111111"), &out));
  TEST_ASSERT_EQUAL_INT(99, out);
}

void test_span_long_status_separates_type_and_range(void)
{
  long out = 99;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_RANGE, jsonread_spanToLongStatus(static_spanOf("99999999999999999999"), &out));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_RANGE, jsonread_spanToLongStatus(static_spanOf("-99999999999999999999"), &out));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_RANGE, jsonread_spanToLongStatus(static_spanOf("-99999999999999999999999"), &out));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE,  jsonread_spanToLongStatus(static_spanOf("1.000000000000000000000000"), &out));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE,  jsonread_spanToLongStatus(static_spanOf("11111111111111111111111111e5"), &out));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE,  jsonread_spanToLongStatus(static_spanOf("99999999999999999999x"), &out));
  TEST_ASSERT_EQUAL_INT(99, out);
}

void test_span_long_wide_span_checks_every_byte_against_the_digits(void)
{
  long out = 99;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE,  jsonread_spanToLongStatus(static_spanOf("x1111111111111111111111111"), &out));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE,  jsonread_spanToLongStatus(static_spanOf("1111111111111111111111111x"), &out));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE,  jsonread_spanToLongStatus(static_spanOf("111111111111/1111111111111"), &out));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE,  jsonread_spanToLongStatus(static_spanOf("111111111111:1111111111111"), &out));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_RANGE, jsonread_spanToLongStatus(static_spanOf("10000000000000000000000000"), &out));
  TEST_ASSERT_EQUAL_INT(99, out);
}

void test_span_double_reads_a_number(void)
{
  double out = 0.0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToDoubleStatus(static_spanOf("41.0082"), &out));
  TEST_ASSERT_TRUE(out == 41.0082);
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToDoubleStatus(static_spanOf("-33.5"), &out));
  TEST_ASSERT_TRUE(out == -33.5);
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToDoubleStatus(static_spanOf("6.4e-05"), &out));
  TEST_ASSERT_TRUE(out == 6.4e-05);
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToDoubleStatus(static_spanOf("12"), &out));
  TEST_ASSERT_TRUE(out == 12.0);
}

void test_span_double_refuses_every_non_number_and_leaves_out_untouched(void)
{
  const char* spans[] = { "\"1.5\"", "true", "null", "nan", "inf", "-nan", "+1", "1.", "01", "-", "1.5x", "1 2" };
  for (size_t i = 0; i < sizeof(spans) / sizeof(spans[0]); i++)
  {
    double out = -2.5;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_TYPE, jsonread_spanToDoubleStatus(static_spanOf(spans[i]), &out), spans[i]);
    TEST_ASSERT_TRUE_MESSAGE(out == -2.5, spans[i]);
  }

  JsonReadSpan_t empty_span = { NULL, 0 };
  double out = -2.5;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_spanToDoubleStatus(empty_span, &out));
  TEST_ASSERT_TRUE(out == -2.5);
}

void test_span_double_overflow_and_underflow_are_range(void)
{
  double out = -2.5;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_RANGE, jsonread_spanToDoubleStatus(static_spanOf("1e999"), &out));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_RANGE, jsonread_spanToDoubleStatus(static_spanOf("-1e999"), &out));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_RANGE, jsonread_spanToDoubleStatus(static_spanOf("1e-999"), &out));
  TEST_ASSERT_TRUE(out == -2.5);
}

void test_span_double_number_of_63_bytes_is_read_and_64_bytes_is_range(void)
{
  char number[80];
  number[0] = '1';
  number[1] = '.';
  memset(number + 2, '0', 61);
  number[63] = '\0';
  double out = -2.5;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToDoubleStatus(static_spanOf(number), &out));
  TEST_ASSERT_TRUE(out == 1.0);

  number[63] = '0';
  number[64] = '\0';
  out = -2.5;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_RANGE, jsonread_spanToDoubleStatus(static_spanOf(number), &out));
  TEST_ASSERT_TRUE(out == -2.5);

  number[63] = 'x';
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_spanToDoubleStatus(static_spanOf(number), &out));
  TEST_ASSERT_TRUE(out == -2.5);
}

static void static_assertSpanText(JsonReadSpan_t span, const char* expected)
{
  TEST_ASSERT_EQUAL_UINT_MESSAGE(strlen(expected), span.m_len, expected);
  TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected, span.mp_start, span.m_len, expected);
}

void test_objectNextMember_walks_members_in_order(void)
{
  const char* json = "{\"a\":1, \"bc\" : \"x\" ,\"d\":{\"e\":true}}";
  JsonReadSpan_t root_span, key_span, value_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));

  size_t member_offset = 0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectNextMember(root_span, &member_offset, &key_span, &value_span));
  static_assertSpanText(key_span, "a");
  static_assertSpanText(value_span, "1");
  size_t after_first = member_offset;
  TEST_ASSERT_TRUE(after_first > 0);

  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectNextMember(root_span, &member_offset, &key_span, &value_span));
  static_assertSpanText(key_span, "bc");
  static_assertSpanText(value_span, "\"x\"");
  TEST_ASSERT_TRUE(member_offset > after_first);

  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectNextMember(root_span, &member_offset, &key_span, &value_span));
  static_assertSpanText(key_span, "d");
  static_assertSpanText(value_span, "{\"e\":true}");
  TEST_ASSERT_EQUAL_UINT(strlen(json) - 1, member_offset);

  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_objectNextMember(root_span, &member_offset, &key_span, &value_span));
  TEST_ASSERT_EQUAL_UINT(strlen(json) - 1, member_offset);
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_objectNextMember(root_span, &member_offset, &key_span, &value_span));
}

void test_objectNextMember_empty_object_is_notfound(void)
{
  static const char* const bodies[] = { "{}", "{ }" };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    JsonReadSpan_t key_span, value_span;
    size_t member_offset = 0;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_NOTFOUND, jsonread_objectNextMember(static_spanOf(bodies[i]), &member_offset, &key_span, &value_span), bodies[i]);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(0, member_offset, bodies[i]);
  }
}

void test_objectNextMember_never_reads_past_the_span(void)
{
  static const struct { const char* mp_text; size_t m_len; size_t m_goodMembers; } cases[] = {
    { "{}",         1, 0 },
    { "{\"",       1, 0 },
    { "{\"a\":1}", 6, 1 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    JsonReadSpan_t   object_span   = { cases[i].mp_text, cases[i].m_len };
    JsonReadSpan_t   key_span, value_span;
    size_t           member_offset = 0;
    size_t           good_members  = 0;
    JsonReadStatus_t walk_status   = JSONREAD_OK;
    while (good_members <= cases[i].m_goodMembers && (walk_status = jsonread_objectNextMember(object_span, &member_offset, &key_span, &value_span)) == JSONREAD_OK)
      good_members++;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_SYNTAX, walk_status, cases[i].mp_text);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(cases[i].m_goodMembers, good_members, cases[i].mp_text);
  }
}

void test_objectNextMember_on_non_object_is_syntax_error(void)
{
  static const char* const bodies[] = { "[{\"a\":1}]", "\"a\"", "1", "", "x\"a\":1}" };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    JsonReadSpan_t key_span, value_span;
    size_t member_offset = 0;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_SYNTAX, jsonread_objectNextMember(static_spanOf(bodies[i]), &member_offset, &key_span, &value_span), bodies[i]);
  }
}

void test_objectNextMember_key_is_raw_bytes(void)
{
  JsonReadSpan_t key_span, value_span;
  size_t member_offset = 0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectNextMember(static_spanOf("{\"g\\u0068sa\":true}"), &member_offset, &key_span, &value_span));
  static_assertSpanText(key_span, "g\\u0068sa");
  static_assertSpanText(value_span, "true");
}

void test_objectNextMember_refuses_each_malformed_member(void)
{
  static const struct { const char* mp_body; size_t m_goodMembers; } cases[] = {
    { "{\"a\":1 \"b\":2}", 1 },
    { "{\"a\":1;\"b\":2}", 1 },
    { "{\"a\":1,}",        1 },
    { "{\"a\":1",          1 },
    { "{\"a\"=1}",         0 },
    { "{\"a\" 12}",        0 },
    { "{\"a\":1,\"b",      1 },
    { "{a:1}",             0 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    JsonReadSpan_t   object_span   = static_spanOf(cases[i].mp_body);
    JsonReadSpan_t   key_span, value_span;
    size_t           member_offset = 0;
    size_t           good_members  = 0;
    JsonReadStatus_t walk_status   = JSONREAD_OK;
    while (good_members <= cases[i].m_goodMembers && (walk_status = jsonread_objectNextMember(object_span, &member_offset, &key_span, &value_span)) == JSONREAD_OK)
      good_members++;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_SYNTAX, walk_status, cases[i].mp_body);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(cases[i].m_goodMembers, good_members, cases[i].mp_body);
  }
}

void test_objectNextMember_depth_limit_matches_objectKey(void)
{
  char body[2 * JSONREAD_MAX_DEPTH + 8];
  for (size_t levels = JSONREAD_MAX_DEPTH - 1; levels <= JSONREAD_MAX_DEPTH; levels++)
  {
    memcpy(body, "{\"a\":", 5);
    memset(body + 5, '[', levels);
    memset(body + 5 + levels, ']', levels);
    body[5 + 2 * levels] = '}';
    body[6 + 2 * levels] = '\0';

    JsonReadStatus_t expected = (levels < JSONREAD_MAX_DEPTH) ? JSONREAD_OK : JSONREAD_ERR_DEPTH;
    JsonReadSpan_t   key_span, value_span, found_span;
    size_t           member_offset = 0;
    TEST_ASSERT_EQUAL_INT(expected, jsonread_objectNextMember(static_spanOf(body), &member_offset, &key_span, &value_span));
    TEST_ASSERT_EQUAL_INT(expected, jsonread_objectKey(static_spanOf(body), "a", &found_span));
  }
}

void test_arrayNextElement_walks_elements_in_order(void)
{
  const char* json = "[1, \"bc\" ,{\"d\":[true]}]";
  JsonReadSpan_t root_span, element_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));

  size_t element_offset = 0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_arrayNextElement(root_span, &element_offset, &element_span));
  static_assertSpanText(element_span, "1");
  size_t after_first = element_offset;
  TEST_ASSERT_TRUE(after_first > 0);

  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_arrayNextElement(root_span, &element_offset, &element_span));
  static_assertSpanText(element_span, "\"bc\"");
  TEST_ASSERT_TRUE(element_offset > after_first);

  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_arrayNextElement(root_span, &element_offset, &element_span));
  static_assertSpanText(element_span, "{\"d\":[true]}");
  TEST_ASSERT_EQUAL_UINT(strlen(json) - 1, element_offset);

  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_arrayNextElement(root_span, &element_offset, &element_span));
  TEST_ASSERT_EQUAL_UINT(strlen(json) - 1, element_offset);
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_arrayNextElement(root_span, &element_offset, &element_span));
}

void test_arrayNextElement_leaves_the_spaces_around_an_element_out(void)
{
  const char* json = "[ 1 ,\t2 ]";
  JsonReadSpan_t root_span, element_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));

  size_t element_offset = 0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_arrayNextElement(root_span, &element_offset, &element_span));
  static_assertSpanText(element_span, "1");
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_arrayNextElement(root_span, &element_offset, &element_span));
  static_assertSpanText(element_span, "2");
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_arrayNextElement(root_span, &element_offset, &element_span));
}

void test_isSpanEqual_holds_only_the_same_bytes(void)
{
  const char*    bytes      = "abcX";
  JsonReadSpan_t span       = { bytes, 3 };
  JsonReadSpan_t empty_span = { bytes, 0 };

  TEST_ASSERT_TRUE(jsonread_isSpanEqual(span, "abc"));
  TEST_ASSERT_FALSE(jsonread_isSpanEqual(span, "ab"));
  TEST_ASSERT_FALSE(jsonread_isSpanEqual(span, "abcX"));
  TEST_ASSERT_FALSE(jsonread_isSpanEqual(span, "ABC"));
  TEST_ASSERT_FALSE(jsonread_isSpanEqual(span, "abd"));

  TEST_ASSERT_TRUE(jsonread_isSpanEqual(empty_span, ""));
  TEST_ASSERT_FALSE(jsonread_isSpanEqual(empty_span, "a"));
}

static JsonReadSpan_t static_rootSpan(const char* json)
{
  JsonReadSpan_t span = { NULL, 0 };
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &span));
  return span;
}

void test_tryFindMembers_finds_each_looked_for_key(void)
{
  JsonReadMember_t members[] = { { .mp_key = "a" }, { .mp_key = "b" }, { .mp_key = "d" } };

  TEST_ASSERT_TRUE(jsonread_tryFindMembers(static_rootSpan("{\"a\":1,\"b\":\"x\",\"c\":{}}"), members, 3));
  TEST_ASSERT_TRUE(members[0].m_isFound);
  static_assertSpanText(members[0].m_valueSpan, "1");
  TEST_ASSERT_TRUE(members[1].m_isFound);
  static_assertSpanText(members[1].m_valueSpan, "\"x\"");
  TEST_ASSERT_FALSE(members[2].m_isFound);
  TEST_ASSERT_EQUAL_size_t(0, members[2].m_valueSpan.m_len);
}

void test_tryFindMembers_refuses_a_looked_for_key_twice(void)
{
  JsonReadMember_t member = { .mp_key = "a" };

  TEST_ASSERT_FALSE(jsonread_tryFindMembers(static_rootSpan("{\"a\":1,\"b\":2,\"a\":3}"), &member, 1));
}

void test_tryFindMembers_allows_another_key_twice(void)
{
  JsonReadMember_t member = { .mp_key = "a" };

  TEST_ASSERT_TRUE(jsonread_tryFindMembers(static_rootSpan("{\"z\":1,\"a\":2,\"z\":3}"), &member, 1));
  TEST_ASSERT_TRUE(member.m_isFound);
  static_assertSpanText(member.m_valueSpan, "2");
}

void test_tryFindMembers_refuses_a_backslash_in_any_key(void)
{
  static const char* const documents[] = {
    "{\"a\":1,\"x\\u0062\":2}",
    "{\"\\u0061\":1}",
    "{\"q\\\"\":1,\"a\":2}",
  };
  for (size_t i = 0; i < sizeof(documents) / sizeof(documents[0]); i++)
  {
    JsonReadMember_t member = { .mp_key = "a" };
    TEST_ASSERT_FALSE_MESSAGE(jsonread_tryFindMembers(static_rootSpan(documents[i]), &member, 1), documents[i]);
  }
}

void test_tryFindMembers_refuses_a_span_that_is_not_an_object(void)
{
  static const char* const documents[] = { "[{\"a\":1}]", "\"{\"", "1", "null" };
  for (size_t i = 0; i < sizeof(documents) / sizeof(documents[0]); i++)
  {
    JsonReadMember_t member = { .mp_key = "a" };
    TEST_ASSERT_FALSE_MESSAGE(jsonread_tryFindMembers(static_rootSpan(documents[i]), &member, 1), documents[i]);
  }

  JsonReadMember_t member     = { .mp_key = "a" };
  JsonReadSpan_t   empty_span = { "{\"a\":1}", 0 };
  TEST_ASSERT_FALSE(jsonread_tryFindMembers(empty_span, &member, 1));
}

void test_tryFindMembers_does_not_find_a_nested_key(void)
{
  JsonReadMember_t member = { .mp_key = "a" };

  TEST_ASSERT_TRUE(jsonread_tryFindMembers(static_rootSpan("{\"o\":{\"a\":1},\"l\":[{\"a\":2}]}"), &member, 1));
  TEST_ASSERT_FALSE(member.m_isFound);
}

void test_tryFindMembers_refuses_a_walk_that_fails(void)
{
  JsonReadMember_t member = { .mp_key = "a" };
  const char*      text   = "{\"a\":1,}";
  JsonReadSpan_t   span   = { text, strlen(text) };

  TEST_ASSERT_FALSE(jsonread_tryFindMembers(span, &member, 1));
}

void test_isObject_and_isArray_read_the_first_byte_of_the_span(void)
{
  JsonReadSpan_t object_span   = static_rootSpan("{\"a\":[1]}");
  JsonReadSpan_t array_span    = static_rootSpan("[{}]");
  JsonReadSpan_t string_span   = static_rootSpan("\"{[\"");
  JsonReadSpan_t number_span   = static_rootSpan("1");
  JsonReadSpan_t empty_brace   = { "{}", 0 };
  JsonReadSpan_t empty_bracket = { "[]", 0 };

  TEST_ASSERT_TRUE(jsonread_isObject(object_span));
  TEST_ASSERT_FALSE(jsonread_isObject(array_span));
  TEST_ASSERT_FALSE(jsonread_isObject(string_span));
  TEST_ASSERT_FALSE(jsonread_isObject(number_span));
  TEST_ASSERT_FALSE(jsonread_isObject(empty_brace));

  TEST_ASSERT_TRUE(jsonread_isArray(array_span));
  TEST_ASSERT_FALSE(jsonread_isArray(object_span));
  TEST_ASSERT_FALSE(jsonread_isArray(string_span));
  TEST_ASSERT_FALSE(jsonread_isArray(number_span));
  TEST_ASSERT_FALSE(jsonread_isArray(empty_bracket));
}

void test_isObject_and_isArray_take_a_span_of_one_byte(void)
{
  JsonReadSpan_t open_brace   = { "{[", 1 };
  JsonReadSpan_t open_bracket = { "[{", 1 };

  TEST_ASSERT_TRUE(jsonread_isObject(open_brace));
  TEST_ASSERT_FALSE(jsonread_isArray(open_brace));
  TEST_ASSERT_TRUE(jsonread_isArray(open_bracket));
  TEST_ASSERT_FALSE(jsonread_isObject(open_bracket));
}

void test_arrayNextElement_never_reads_past_the_span(void)
{
  static const struct { const char* mp_text; size_t m_len; size_t m_goodElements; } cases[] = {
    { "[]",    1, 0 },
    { "[\"",  1, 0 },
    { "[1]",   2, 1 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    JsonReadSpan_t   array_span     = { cases[i].mp_text, cases[i].m_len };
    JsonReadSpan_t   element_span;
    size_t           element_offset = 0;
    size_t           good_elements  = 0;
    JsonReadStatus_t walk_status    = JSONREAD_OK;
    while (good_elements <= cases[i].m_goodElements && (walk_status = jsonread_arrayNextElement(array_span, &element_offset, &element_span)) == JSONREAD_OK)
      good_elements++;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_SYNTAX, walk_status, cases[i].mp_text);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(cases[i].m_goodElements, good_elements, cases[i].mp_text);
  }
}

void test_arrayNextElement_on_non_array_is_syntax_error(void)
{
  static const char* const bodies[] = { "{\"a\":[1]}", "\"a\"", "1", "", "x1]" };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    JsonReadSpan_t element_span;
    size_t element_offset = 0;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_SYNTAX, jsonread_arrayNextElement(static_spanOf(bodies[i]), &element_offset, &element_span), bodies[i]);
  }
}

void test_arrayNextElement_refuses_each_malformed_element(void)
{
  static const struct { const char* mp_body; size_t m_goodElements; } cases[] = {
    { "[1 2]",      1 },
    { "[1;2]",      1 },
    { "[1,]",       1 },
    { "[1",         1 },
    { "[,1]",       0 },
    { "[1,\"b",    1 },
    { "[tru]",      0 },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    JsonReadSpan_t   array_span     = static_spanOf(cases[i].mp_body);
    JsonReadSpan_t   element_span;
    size_t           element_offset = 0;
    size_t           good_elements  = 0;
    JsonReadStatus_t walk_status    = JSONREAD_OK;
    while (good_elements <= cases[i].m_goodElements && (walk_status = jsonread_arrayNextElement(array_span, &element_offset, &element_span)) == JSONREAD_OK)
      good_elements++;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_SYNTAX, walk_status, cases[i].mp_body);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(cases[i].m_goodElements, good_elements, cases[i].mp_body);
  }
}

void test_arrayNextElement_depth_limit_matches_arrayLen(void)
{
  char body[2 * JSONREAD_MAX_DEPTH + 8];
  for (size_t levels = JSONREAD_MAX_DEPTH - 1; levels <= JSONREAD_MAX_DEPTH; levels++)
  {
    body[0] = '[';
    memset(body + 1, '[', levels);
    memset(body + 1 + levels, ']', levels);
    body[1 + 2 * levels] = ']';
    body[2 + 2 * levels] = '\0';

    JsonReadStatus_t expected = (levels < JSONREAD_MAX_DEPTH) ? JSONREAD_OK : JSONREAD_ERR_DEPTH;
    JsonReadSpan_t   element_span;
    size_t           element_offset = 0;
    size_t           element_count  = 0;
    TEST_ASSERT_EQUAL_INT(expected, jsonread_arrayNextElement(static_spanOf(body), &element_offset, &element_span));
    TEST_ASSERT_EQUAL_INT(expected, jsonread_arrayLen(static_spanOf(body), &element_count));
  }
}

void test_spanBool_reads_true_and_false(void)
{
  bool out = false;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToBoolStatus(static_spanOf("true"), &out));
  TEST_ASSERT_TRUE(out);
  out = true;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToBoolStatus(static_spanOf("false"), &out));
  TEST_ASSERT_FALSE(out);
}

void test_spanBool_refuses_every_other_span_and_leaves_out_untouched(void)
{
  static const char* const spans[] = {
    "\"true\"", "1", "0", "null", "tru", "trueX", "falsey", "True", "", " true", "trux", "falsy",
  };
  for (size_t i = 0; i < sizeof(spans) / sizeof(spans[0]); i++)
  {
    bool out = true;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_TYPE, jsonread_spanToBoolStatus(static_spanOf(spans[i]), &out), spans[i]);
    TEST_ASSERT_TRUE_MESSAGE(out, spans[i]);
    out = false;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_TYPE, jsonread_spanToBoolStatus(static_spanOf(spans[i]), &out), spans[i]);
    TEST_ASSERT_FALSE_MESSAGE(out, spans[i]);
  }
}

void test_number_readers_reject_non_json_numeric_literals(void)
{
  double parsed_double = -1.0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_doubleStatus("{\"min_cvss\":nan}",  "min_cvss", &parsed_double));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_doubleStatus("{\"min_cvss\":inf}",  "min_cvss", &parsed_double));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_doubleStatus("{\"min_cvss\":+1.0}", "min_cvss", &parsed_double));
  TEST_ASSERT_EQUAL_INT(-100, (int)(parsed_double * 100.0));

  long parsed_int = -7;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_intStatus("{\"limit\":nan}", "limit", &parsed_int));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_intStatus("{\"limit\":+5}",  "limit", &parsed_int));
  TEST_ASSERT_EQUAL_INT(-7, (int)parsed_int);

  double negative_nan = 0.0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_doubleStatus("{\"min_cvss\":-nan}", "min_cvss", &negative_nan));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_doubleStatus("{\"min_cvss\":-inf}", "min_cvss", &negative_nan));
  TEST_ASSERT_EQUAL_INT(0, (int)(negative_nan * 100.0));

  long negative_nan_int = -7;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_intStatus("{\"limit\":-nan}", "limit", &negative_nan_int));
  TEST_ASSERT_EQUAL_INT(-7, (int)negative_nan_int);
}

void test_double_status_separates_absent_type_and_range(void)
{
  double parsed_value = -1.0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_doubleStatus("{\"min_cvss\":9.0}", "min_cvss", &parsed_value));
  TEST_ASSERT_EQUAL_INT(900, (int)(parsed_value * 100.0));

  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_doubleStatus("{\"min_cvss\":9.0}", "other", &parsed_value));

  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_doubleStatus("{\"k\":\"9.0\"}", "k", &parsed_value));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_doubleStatus("{\"k\":\"nan\"}", "k", &parsed_value));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_doubleStatus("{\"k\":null}",    "k", &parsed_value));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_doubleStatus("{\"k\":true}",    "k", &parsed_value));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_doubleStatus("{\"k\":[1,2]}",   "k", &parsed_value));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_doubleStatus("{\"k\":-nan}",    "k", &parsed_value));

  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_RANGE, jsonread_doubleStatus("{\"k\":1e999}",  "k", &parsed_value));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_RANGE, jsonread_doubleStatus("{\"k\":-1e999}", "k", &parsed_value));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_RANGE, jsonread_doubleStatus("{\"k\":1e-999}", "k", &parsed_value));
}

void test_int_status_separates_absent_type_and_range(void)
{
  long parsed_value = -7;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_intStatus("{\"limit\":50}", "limit", &parsed_value));
  TEST_ASSERT_EQUAL_INT(50, (int)parsed_value);

  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_intStatus("{\"limit\":50}", "other", &parsed_value));

  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_intStatus("{\"k\":\"50\"}", "k", &parsed_value));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_intStatus("{\"k\":null}",   "k", &parsed_value));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_intStatus("{\"k\":false}",  "k", &parsed_value));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_intStatus("{\"k\":-nan}",   "k", &parsed_value));

  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_RANGE, jsonread_intStatus("{\"k\":99999999999999999999}",  "k", &parsed_value));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_RANGE, jsonread_intStatus("{\"k\":-99999999999999999999}", "k", &parsed_value));
}

void test_number_status_failures_leave_the_value_untouched(void)
{
  double parsed_double = -1.0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_doubleStatus("{\"a\":1.0}", "b",  &parsed_double));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE,     jsonread_doubleStatus("{\"b\":null}", "b", &parsed_double));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_RANGE,    jsonread_doubleStatus("{\"b\":1e999}", "b", &parsed_double));
  TEST_ASSERT_EQUAL_INT(-100, (int)(parsed_double * 100.0));

  long parsed_int = -7;
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_NOTFOUND, jsonread_intStatus("{\"a\":1}", "b",   &parsed_int));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE,     jsonread_intStatus("{\"b\":null}", "b", &parsed_int));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_RANGE,    jsonread_intStatus("{\"b\":99999999999999999999}", "b", &parsed_int));
  TEST_ASSERT_EQUAL_INT(-7, (int)parsed_int);
}

void test_number_readers_still_accept_ordinary_numbers(void)
{
  double parsed_double = 0.0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_doubleStatus("{\"v\":-1.5}", "v", &parsed_double));
  TEST_ASSERT_EQUAL_INT(-150, (int)(parsed_double * 100.0));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_doubleStatus("{\"v\":9e3}", "v", &parsed_double));
  TEST_ASSERT_EQUAL_INT(900000, (int)(parsed_double * 100.0));

  long parsed_int = 0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_intStatus("{\"n\":-7}", "n", &parsed_int));
  TEST_ASSERT_EQUAL_INT(-7, (int)parsed_int);
}

void test_number_readers_sign_hex_and_status_order(void)
{
  long   parsed_int    = 7;
  double parsed_double = 0.0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_intStatus("{\"k\":-0}", "k", &parsed_int));
  TEST_ASSERT_EQUAL_INT(0, (int)parsed_int);
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_doubleStatus("{\"k\":-0.5}", "k", &parsed_double));
  TEST_ASSERT_EQUAL_INT(-50, (int)(parsed_double * 100.0));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_intStatus("{\"k\":0x10}", "k", &parsed_int));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_intStatus("{\"k\":99999999999999999999x}", "k", &parsed_int));
  TEST_ASSERT_EQUAL_INT(JSONREAD_ERR_TYPE, jsonread_doubleStatus("{\"k\":1e999x}", "k", &parsed_double));
}

void test_isNumberToken_holds_a_token_to_the_json_grammar(void)
{
  static const char* const accepted[] = { "0", "-0", "7", "10", "0.5", "-1.5", "1e3", "1E+3", "1e-3", "2.5e10", "12345678901234567890123" };
  static const char* const refused[]  = { "", "-", "--1", "- 1", "+1", "01", "-01", "00", "1.", "1.e0", ".5", "-.5", "1e", "1e+", "0x1p3", "1-2", "1-2-3", "1.2.3", " 1", "1 ", "nan", "inf", "-nan", "-inf" };
  for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++)
    TEST_ASSERT_TRUE_MESSAGE(jsonread_isNumberToken(accepted[i], accepted[i] + strlen(accepted[i])), accepted[i]);
  for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
    TEST_ASSERT_FALSE_MESSAGE(jsonread_isNumberToken(refused[i], refused[i] + strlen(refused[i])), refused[i]);

  const char* const minus_then_digit = "-1";
  TEST_ASSERT_FALSE(jsonread_isNumberToken(minus_then_digit, minus_then_digit + 1));
  const char* const two_digits = "12";
  TEST_ASSERT_TRUE(jsonread_isNumberToken(two_digits, two_digits + 1));
  TEST_ASSERT_FALSE(jsonread_isNumberToken(two_digits, two_digits));
}

void test_number_readers_refuse_numbers_outside_the_json_grammar(void)
{
  static const char* const ints[]    = { "{\"k\":01}", "{\"k\":-01}", "{\"k\":00}" };
  static const char* const doubles[] = { "{\"k\":01}", "{\"k\":00}", "{\"k\":1.}", "{\"k\":01.5}", "{\"k\":1.e0}", "{\"k\":0x1p3}" };

  long parsed_int = -7;
  for (size_t i = 0; i < sizeof(ints) / sizeof(ints[0]); i++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_TYPE, jsonread_intStatus(ints[i], "k", &parsed_int), ints[i]);
  TEST_ASSERT_EQUAL_INT(-7, (int)parsed_int);

  double parsed_double = -1.0;
  for (size_t i = 0; i < sizeof(doubles) / sizeof(doubles[0]); i++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_TYPE, jsonread_doubleStatus(doubles[i], "k", &parsed_double), doubles[i]);
  TEST_ASSERT_EQUAL_INT(-100, (int)(parsed_double * 100.0));
}

static void static_fillShape(char* json, size_t json_size, const char* shape, const char* first_value, const char* second_value)
{
  const char* values[2]   = { first_value, second_value };
  size_t      value_index = 0;
  size_t      json_len    = 0;
  for (const char* cursor = shape; *cursor; cursor++)
  {
    const char* piece     = cursor;
    size_t      piece_len = 1;
    if (*cursor == '@' && value_index < 2)
    {
      piece     = values[value_index++];
      piece_len = strlen(piece);
    }
    TEST_ASSERT_TRUE(json_len + piece_len < json_size);
    memcpy(json + json_len, piece, piece_len);
    json_len += piece_len;
  }
  json[json_len] = '\0';
}

static const char* const TOP_LEVEL_WINS_SHAPES[] = {
  "{\"b\":{\"a\":@},\"a\":@}",
  "{\"b\":[{\"a\":@}],\"a\":@}",
  "{\"x\\\"a\":@,\"a\":@}",
  "{\"n\":\"{[\\\"a\\\":\",\"m\":@,\"a\":@}",
};

void test_flat_getters_read_the_top_level_member_over_an_earlier_nested_one(void)
{
  char json[128];
  for (size_t i = 0; i < sizeof(TOP_LEVEL_WINS_SHAPES) / sizeof(TOP_LEVEL_WINS_SHAPES[0]); i++)
  {
    const char* shape = TOP_LEVEL_WINS_SHAPES[i];

    char text[16] = "default";
    static_fillShape(json, sizeof(json), shape, "\"x\"", "\"y\"");
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_OK, jsonread_strStatus(json, "a", text, sizeof(text)), json);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("y", text, json);

    long integer = -7;
    static_fillShape(json, sizeof(json), shape, "1", "2");
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_OK, jsonread_intStatus(json, "a", &integer), json);
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, (int)integer, json);

    double real = -1.0;
    static_fillShape(json, sizeof(json), shape, "1.5", "2.5");
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_OK, jsonread_doubleStatus(json, "a", &real), json);
    TEST_ASSERT_EQUAL_INT_MESSAGE(250, (int)(real * 100.0), json);

    bool flag = false;
    static_fillShape(json, sizeof(json), shape, "false", "true");
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_OK, jsonread_boolStatus(json, "a", &flag), json);
    TEST_ASSERT_TRUE_MESSAGE(flag, json);
  }
}

void test_flat_getters_answer_nested_for_a_key_found_only_deeper(void)
{
  static const char* const shapes[] = {
    "{\"b\":{\"a\":@}}",
    "{\"b\":{\"a\" :@}}",
    "{\"b\":[{\"a\":@}]}",
    "[{\"a\":@}]",
  };
  char json[128];
  for (size_t i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++)
  {
    char text[16] = "default";
    static_fillShape(json, sizeof(json), shapes[i], "\"x\"", "");
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_NESTED, jsonread_strStatus(json, "a", text, sizeof(text)), json);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", text, json);

    long integer = -7;
    static_fillShape(json, sizeof(json), shapes[i], "1", "");
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_NESTED, jsonread_intStatus(json, "a", &integer), json);
    TEST_ASSERT_EQUAL_INT_MESSAGE(-7, (int)integer, json);

    double real = -1.0;
    static_fillShape(json, sizeof(json), shapes[i], "1.5", "");
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_NESTED, jsonread_doubleStatus(json, "a", &real), json);
    TEST_ASSERT_EQUAL_INT_MESSAGE(-100, (int)(real * 100.0), json);

    bool flag = true;
    static_fillShape(json, sizeof(json), shapes[i], "false", "");
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_NESTED, jsonread_boolStatus(json, "a", &flag), json);
    TEST_ASSERT_TRUE_MESSAGE(flag, json);
  }
}

void test_flat_getters_answer_notfound_when_no_member_has_the_key(void)
{
  static const char* const bodies[] = { "{\"b\":{\"c\":1}}", "{\"b\":\"\\\"a\\\"\"}", "{\"b\":\"a\"}" };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    char text[16] = "default";
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_NOTFOUND, jsonread_strStatus(bodies[i], "a", text, sizeof(text)), bodies[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("default", text, bodies[i]);
  }
}

void test_flat_getters_take_the_first_of_two_top_level_members(void)
{
  char text[16] = "";
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_strStatus("{\"a\":\"x\",\"a\":\"y\"}", "a", text, sizeof(text)));
  TEST_ASSERT_EQUAL_STRING("x", text);
}

void test_flat_getters_refuse_a_member_before_the_match_that_nests_too_deep(void)
{
  char body[2 * JSONREAD_MAX_DEPTH + 16];
  for (size_t levels = JSONREAD_MAX_DEPTH - 1; levels <= JSONREAD_MAX_DEPTH; levels++)
  {
    memcpy(body, "{\"b\":", 5);
    memset(body + 5, '[', levels);
    memset(body + 5 + levels, ']', levels);
    memcpy(body + 5 + 2 * levels, ",\"a\":1}", 8);

    JsonReadStatus_t expected = (levels < JSONREAD_MAX_DEPTH) ? JSONREAD_OK : JSONREAD_ERR_DEPTH;
    long             integer  = -7;
    JsonReadSpan_t   found_span;
    TEST_ASSERT_EQUAL_INT(expected, jsonread_intStatus(body, "a", &integer));
    TEST_ASSERT_EQUAL_INT(expected, jsonread_objectKey(static_spanOf(body), "a", &found_span));
    TEST_ASSERT_EQUAL_INT((levels < JSONREAD_MAX_DEPTH) ? 1 : -7, (int)integer);
  }
}

void test_flat_getters_refuse_a_malformed_member_before_the_match(void)
{
  static const char* const bodies[] = { "{b:1,\"a\":2}", "{\"b\" 1,\"a\":2}", "{\"b\":tru,\"a\":2}", "{\"b\":1 \"a\":2}" };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    long integer = -7;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_SYNTAX, jsonread_intStatus(bodies[i], "a", &integer), bodies[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(-7, (int)integer, bodies[i]);

    char text[16] = "default";
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_ERR_SYNTAX, jsonread_strStatus(bodies[i], "a", text, sizeof(text)), bodies[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", text, bodies[i]);
  }
}

int main(void)
{
  UNITY_BEGIN();

  RUN_TEST(test_get_str_simple);
  RUN_TEST(test_get_str_missing);
  RUN_TEST(test_get_str_with_spaces);
  RUN_TEST(test_get_str_escape_quote);
  RUN_TEST(test_get_str_escape_newline);
  RUN_TEST(test_get_str_escape_backslash);
  RUN_TEST(test_get_str_buffer_too_small);
  RUN_TEST(test_get_str_key_appears_as_value);
  RUN_TEST(test_get_str_empty_value);
  RUN_TEST(test_get_str_escape_slash_cr_tab);
  RUN_TEST(test_get_str_escape_backspace_formfeed);
  RUN_TEST(test_get_str_invalid_escape_rejected);
  RUN_TEST(test_get_str_type_mismatch_is_distinct_from_missing);
  RUN_TEST(test_get_str_type_mismatch_leaves_out_empty);
  RUN_TEST(test_get_str_too_long_is_distinct_from_missing);
  RUN_TEST(test_get_str_too_long_leaves_out_empty);
  RUN_TEST(test_get_str_missing_keeps_the_callers_default);
  RUN_TEST(test_get_str_exact_fit_accepted);
  RUN_TEST(test_get_str_one_over_is_too_long);
  RUN_TEST(test_get_str_unterminated_is_syntax_not_too_long);
  RUN_TEST(test_get_int_simple);
  RUN_TEST(test_get_int_negative);
  RUN_TEST(test_get_int_missing);
  RUN_TEST(test_get_int_not_number);
  RUN_TEST(test_get_int_zero);
  RUN_TEST(test_get_int_key_appears_as_value);
  RUN_TEST(test_get_int_failure_leaves_out_untouched);
  RUN_TEST(test_get_int_rejects_trailing_bytes);
  RUN_TEST(test_number_readers_reject_a_partially_consumed_number);
  RUN_TEST(test_number_readers_accept_every_value_terminator);
  RUN_TEST(test_get_double_simple);
  RUN_TEST(test_get_double_integer_value);
  RUN_TEST(test_get_double_missing);
  RUN_TEST(test_get_double_negative);
  RUN_TEST(test_get_double_scientific);
  RUN_TEST(test_get_double_failure_leaves_out_untouched);
  RUN_TEST(test_bool_status_true_and_false_are_ok);
  RUN_TEST(test_bool_status_missing_is_notfound_and_leaves_out_untouched);
  RUN_TEST(test_bool_status_wrong_type_is_type_not_notfound);
  RUN_TEST(test_bool_status_garbage_suffix_is_type);
  RUN_TEST(test_bool_status_terminators);
  RUN_TEST(test_bool_status_truncated_literal_is_type);

  RUN_TEST(test_root_simple_object);
  RUN_TEST(test_root_rejects_empty);
  RUN_TEST(test_root_refuses_a_null_text);
  RUN_TEST(test_root_skips_utf8_bom);
  RUN_TEST(test_root_bom_alone_is_still_syntax_error);
  RUN_TEST(test_root_rejects_bom_inside_the_document);
  RUN_TEST(test_root_rejects_second_bom);
  RUN_TEST(test_objectKey_string_value_keeps_quotes);
  RUN_TEST(test_objectKey_object_value);
  RUN_TEST(test_objectKey_array_value);
  RUN_TEST(test_objectKey_not_found);
  RUN_TEST(test_objectKey_nested_chain);
  RUN_TEST(test_objectKey_skips_escaped_quote_value);
  RUN_TEST(test_arrayLen_empty);
  RUN_TEST(test_arrayLen_three);
  RUN_TEST(test_arrayNextElement_iterates);
  RUN_TEST(test_malformed_unbalanced_brace);
  RUN_TEST(test_malformed_unterminated_string);
  RUN_TEST(test_depth_exceeded);
  RUN_TEST(test_spanToString_truncates);
  RUN_TEST(test_spanToString_fits_exactly_and_one_byte_less_is_toolong);
  RUN_TEST(test_objectKey_substring_collision);
  RUN_TEST(test_objectKey_duplicate_returns_first);
  RUN_TEST(test_skip_string_with_escaped_backslash);
  RUN_TEST(test_root_top_level_array);
  RUN_TEST(test_objectKey_on_array_is_syntax_error);
  RUN_TEST(test_objectKey_literal_values);
  RUN_TEST(test_objectKey_bad_literal_is_syntax_error);
  RUN_TEST(test_root_refuses_a_literal_in_another_case_or_with_its_last_letter_changed);
  RUN_TEST(test_arrayNextElement_empty_array_is_notfound);
  RUN_TEST(test_arrayLen_nested_elements);
  RUN_TEST(test_root_trailing_garbage_rejected);

  RUN_TEST(test_spanStr_plain);
  RUN_TEST(test_spanStr_decodes_escapes);
  RUN_TEST(test_spanStr_array_element);
  RUN_TEST(test_spanStr_rejects_non_string);
  RUN_TEST(test_spanStr_and_get_str_decode_each_unicode_escape);
  RUN_TEST(test_spanStr_and_get_str_never_cut_a_decoded_character_short);
  RUN_TEST(test_spanStr_reads_no_byte_past_a_span_that_ends_after_a_high_surrogate);
  RUN_TEST(test_spanStr_buffer_too_small);
  RUN_TEST(test_spanStr_value_that_fills_the_buffer_exactly_is_read);
  RUN_TEST(test_spanStr_value_one_byte_over_the_buffer_is_refused);
  RUN_TEST(test_spanStr_size_limit_counts_decoded_bytes);
  RUN_TEST(test_spanStr_empty_string_fits_a_one_byte_buffer);
  RUN_TEST(test_spanStr_span_that_ends_before_its_closing_quote_is_refused);
  RUN_TEST(test_spanStr_empty_span_is_type);
  RUN_TEST(test_spanStr_dangling_escape_is_syntax);
  RUN_TEST(test_spanStr_raw_control_char_is_syntax);
  RUN_TEST(test_root_raw_control_char_in_value_or_name_is_syntax);
  RUN_TEST(test_spanStr_span_end_and_full_buffer_together_is_syntax);
  RUN_TEST(test_spanStr_decodes_the_remaining_escapes);
  RUN_TEST(test_span_long_reads_a_number);
  RUN_TEST(test_span_long_rejects_trailing_bytes);
  RUN_TEST(test_span_long_rejects_non_numeric_and_empty);
  RUN_TEST(test_span_long_rejects_an_implausibly_wide_span);
  RUN_TEST(test_span_long_status_separates_type_and_range);
  RUN_TEST(test_span_long_wide_span_checks_every_byte_against_the_digits);
  RUN_TEST(test_span_double_reads_a_number);
  RUN_TEST(test_span_double_refuses_every_non_number_and_leaves_out_untouched);
  RUN_TEST(test_span_double_overflow_and_underflow_are_range);
  RUN_TEST(test_span_double_number_of_63_bytes_is_read_and_64_bytes_is_range);
  RUN_TEST(test_objectNextMember_walks_members_in_order);
  RUN_TEST(test_objectNextMember_empty_object_is_notfound);
  RUN_TEST(test_objectNextMember_on_non_object_is_syntax_error);
  RUN_TEST(test_objectNextMember_never_reads_past_the_span);
  RUN_TEST(test_objectNextMember_key_is_raw_bytes);
  RUN_TEST(test_objectNextMember_refuses_each_malformed_member);
  RUN_TEST(test_objectNextMember_depth_limit_matches_objectKey);
  RUN_TEST(test_arrayNextElement_walks_elements_in_order);
  RUN_TEST(test_arrayNextElement_leaves_the_spaces_around_an_element_out);
  RUN_TEST(test_isSpanEqual_holds_only_the_same_bytes);
  RUN_TEST(test_tryFindMembers_finds_each_looked_for_key);
  RUN_TEST(test_tryFindMembers_refuses_a_looked_for_key_twice);
  RUN_TEST(test_tryFindMembers_allows_another_key_twice);
  RUN_TEST(test_tryFindMembers_refuses_a_backslash_in_any_key);
  RUN_TEST(test_tryFindMembers_refuses_a_span_that_is_not_an_object);
  RUN_TEST(test_tryFindMembers_does_not_find_a_nested_key);
  RUN_TEST(test_tryFindMembers_refuses_a_walk_that_fails);
  RUN_TEST(test_isObject_and_isArray_read_the_first_byte_of_the_span);
  RUN_TEST(test_isObject_and_isArray_take_a_span_of_one_byte);
  RUN_TEST(test_arrayNextElement_never_reads_past_the_span);
  RUN_TEST(test_arrayNextElement_on_non_array_is_syntax_error);
  RUN_TEST(test_arrayNextElement_refuses_each_malformed_element);
  RUN_TEST(test_arrayNextElement_depth_limit_matches_arrayLen);
  RUN_TEST(test_spanBool_reads_true_and_false);
  RUN_TEST(test_spanBool_refuses_every_other_span_and_leaves_out_untouched);
  RUN_TEST(test_number_readers_reject_non_json_numeric_literals);
  RUN_TEST(test_double_status_separates_absent_type_and_range);
  RUN_TEST(test_int_status_separates_absent_type_and_range);
  RUN_TEST(test_number_status_failures_leave_the_value_untouched);
  RUN_TEST(test_number_readers_still_accept_ordinary_numbers);
  RUN_TEST(test_number_readers_sign_hex_and_status_order);
  RUN_TEST(test_isNumberToken_holds_a_token_to_the_json_grammar);
  RUN_TEST(test_number_readers_refuse_numbers_outside_the_json_grammar);
  RUN_TEST(test_flat_getters_read_the_top_level_member_over_an_earlier_nested_one);
  RUN_TEST(test_flat_getters_answer_nested_for_a_key_found_only_deeper);
  RUN_TEST(test_flat_getters_answer_notfound_when_no_member_has_the_key);
  RUN_TEST(test_flat_getters_take_the_first_of_two_top_level_members);
  RUN_TEST(test_flat_getters_refuse_a_member_before_the_match_that_nests_too_deep);
  RUN_TEST(test_flat_getters_refuse_a_malformed_member_before_the_match);
  return UNITY_END();
}
