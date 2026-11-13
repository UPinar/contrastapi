#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity/unity.h"
#include "jsonbuf.h"
#include "jsoncanon.h"
#include "jsonread.h"

#include "test_jsoncanon_vectors.h"

#define TEST_BODY_MAX (128 * 1024)

void setUp(void)    {}
void tearDown(void) {}

static char* static_canon(const char* body, size_t body_len)
{
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);

  bool is_written = jsoncanon_tryWrite(body, body_len, json_buf);
  char* text      = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);

  if (!is_written)
  {
    free(text);
    return NULL;
  }
  TEST_ASSERT_NOT_NULL(text);
  return text;
}

static void static_assertCanon(const char* body, const char* expected)
{
  char* text = static_canon(body, strlen(body));
  TEST_ASSERT_NOT_NULL_MESSAGE(text, body);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, text, body);
  free(text);
}

static void static_assertRefusedBytes(const char* body, size_t body_len)
{
  char* text = static_canon(body, body_len);
  TEST_ASSERT_NULL_MESSAGE(text, body);
}

static void static_assertRefused(const char* body)
{
  static_assertRefusedBytes(body, strlen(body));
}

static size_t static_buildObject(char* out, size_t member_count)
{
  size_t pos = 0;
  out[pos++] = '{';
  for (size_t i = 0; i < member_count; i++)
    pos += (size_t)snprintf(out + pos, TEST_BODY_MAX - pos, "%s\"k%04zu\":1", i > 0 ? "," : "", i);
  out[pos++] = '}';
  out[pos]   = '\0';
  return pos;
}

static size_t static_buildNested(char* out, size_t container_count, char opener)
{
  size_t pos = 0;
  pos += (size_t)snprintf(out + pos, TEST_BODY_MAX - pos, "{\"a\":");
  for (size_t i = 1; i < container_count; i++)
  {
    if (opener == '{' && i + 1 < container_count)
      pos += (size_t)snprintf(out + pos, TEST_BODY_MAX - pos, "{\"a\":");
    else if (opener == '{')
      pos += (size_t)snprintf(out + pos, TEST_BODY_MAX - pos, "{");
    else
      out[pos++] = '[';
  }
  if (container_count == 1)
    pos += (size_t)snprintf(out + pos, TEST_BODY_MAX - pos, "1");
  for (size_t i = 1; i < container_count; i++)
    out[pos++] = opener == '{' ? '}' : ']';
  out[pos++] = '}';
  out[pos]   = '\0';
  return pos;
}

static void test_root_empty_object(void)
{
  static_assertCanon("{}", "{}");
}

static void test_root_array_refused(void)
{
  static_assertRefused("[]");
}

static void test_root_string_refused(void)
{
  static_assertRefused("\"a\"");
}

static void test_root_number_refused(void)
{
  static_assertRefused("1");
}

static void test_null_body_refused(void)
{
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  TEST_ASSERT_FALSE(jsoncanon_tryWrite(NULL, 0, json_buf));
  TEST_ASSERT_FALSE(jsoncanon_tryWrite(NULL, JSONCANON_FLOAT_TEXT_MAX, json_buf));
  jsonbuf_destroy(json_buf);
}

static void test_empty_body_refused(void)
{
  static_assertRefusedBytes("", 0);
}

static void test_trailing_garbage_refused(void)
{
  static_assertRefused("{\"a\":1}x");
}

static void test_second_root_refused(void)
{
  static_assertRefused("{}{}");
}

static void test_bom_refused(void)
{
  static_assertRefused("\xEF\xBB\xBF{\"a\":1}");
}

static void test_bom_after_whitespace_refused(void)
{
  static_assertRefused(" \xEF\xBB\xBF{\"a\":1}");
}

static void test_whitespace_dropped(void)
{
  static_assertCanon(" \t\r\n{ \"b\" : [ 1 , 2 ] ,\n\"a\" : { } } \n", "{\"a\":{},\"b\":[1,2]}");
}

static void test_form_feed_is_not_whitespace(void)
{
  static_assertRefused("\f{\"a\":1}");
}

static void test_body_needs_no_terminator(void)
{
  char* text = static_canon("{\"a\":1}junk", 7);
  TEST_ASSERT_NOT_NULL(text);
  TEST_ASSERT_EQUAL_STRING("{\"a\":1}", text);
  free(text);
}

static void test_members_sorted(void)
{
  static_assertCanon("{\"b\":1,\"a\":2,\"c\":3}", "{\"a\":2,\"b\":1,\"c\":3}");
}

static void test_prefix_key_sorts_first(void)
{
  static_assertCanon("{\"ab\":1,\"a\":2}", "{\"a\":2,\"ab\":1}");
}

static void test_longer_key_after_prefix_in_input_order(void)
{
  static_assertCanon("{\"a\":2,\"ab\":1}", "{\"a\":2,\"ab\":1}");
}

static void test_empty_key_sorts_first(void)
{
  static_assertCanon("{\"a\":1,\"\":2}", "{\"\":2,\"a\":1}");
}

static void test_nested_objects_sorted(void)
{
  static_assertCanon("{\"z\":{\"b\":1,\"a\":2}}", "{\"z\":{\"a\":2,\"b\":1}}");
}

static void test_objects_inside_arrays_sorted(void)
{
  static_assertCanon("{\"z\":[{\"b\":1,\"a\":2},[{\"d\":1,\"c\":2}]]}", "{\"z\":[{\"a\":2,\"b\":1},[{\"c\":2,\"d\":1}]]}");
}

static void test_array_order_kept(void)
{
  static_assertCanon("{\"a\":[3,1,2]}", "{\"a\":[3,1,2]}");
}

static void test_empty_containers(void)
{
  static_assertCanon("{\"a\":[],\"b\":{}}", "{\"a\":[],\"b\":{}}");
}

static void test_unicode_keys_sort_by_code_point(void)
{
  static_assertCanon("{\"\xF0\x9F\x98\x80\":1,\"\xEE\x80\x80\":2}", "{\"\\ue000\":2,\"\\ud83d\\ude00\":1}");
}

static void test_member_count_255(void)
{
  char* body = malloc(TEST_BODY_MAX);
  TEST_ASSERT_NOT_NULL(body);
  size_t len = static_buildObject(body, 255);
  char* text = static_canon(body, len);
  TEST_ASSERT_NOT_NULL(text);
  TEST_ASSERT_EQUAL_STRING(body, text);
  free(text);
  free(body);
}

static void test_member_count_256_accepted(void)
{
  char* body = malloc(TEST_BODY_MAX);
  TEST_ASSERT_NOT_NULL(body);
  size_t len = static_buildObject(body, JSONCANON_OBJECT_MEMBER_MAX);
  char* text = static_canon(body, len);
  TEST_ASSERT_NOT_NULL(text);
  TEST_ASSERT_EQUAL_STRING(body, text);
  free(text);
  free(body);
}

static void test_member_count_257_refused(void)
{
  char* body = malloc(TEST_BODY_MAX);
  TEST_ASSERT_NOT_NULL(body);
  size_t len = static_buildObject(body, JSONCANON_OBJECT_MEMBER_MAX + 1);
  static_assertRefusedBytes(body, len);
  free(body);
}

static void test_member_max_is_256(void)
{
  TEST_ASSERT_EQUAL_INT(256, JSONCANON_OBJECT_MEMBER_MAX);
}

static void test_member_limit_applies_to_nested_object(void)
{
  char* body = malloc(TEST_BODY_MAX);
  TEST_ASSERT_NOT_NULL(body);
  memcpy(body, "{\"a\":", 5);
  size_t inner_len = static_buildObject(body + 5, JSONCANON_OBJECT_MEMBER_MAX + 1);
  body[5 + inner_len] = '}';
  static_assertRefusedBytes(body, 5 + inner_len + 1);
  free(body);
}

static void test_depth_31_accepted(void)
{
  char body[256];
  size_t len = static_buildNested(body, 31, '[');
  char* text = static_canon(body, len);
  TEST_ASSERT_NOT_NULL(text);
  TEST_ASSERT_EQUAL_STRING(body, text);
  free(text);
}

static void test_depth_32_accepted(void)
{
  char body[256];
  size_t len = static_buildNested(body, JSONREAD_MAX_DEPTH, '[');
  char* text = static_canon(body, len);
  TEST_ASSERT_NOT_NULL(text);
  TEST_ASSERT_EQUAL_STRING(body, text);
  free(text);
}

static void test_depth_33_refused(void)
{
  char body[256];
  size_t len = static_buildNested(body, JSONREAD_MAX_DEPTH + 1, '[');
  static_assertRefusedBytes(body, len);
}

static void test_object_depth_32_accepted(void)
{
  char body[512];
  size_t len = static_buildNested(body, JSONREAD_MAX_DEPTH, '{');
  char* text = static_canon(body, len);
  TEST_ASSERT_NOT_NULL(text);
  TEST_ASSERT_EQUAL_STRING(body, text);
  free(text);
}

static void test_object_depth_33_refused(void)
{
  char body[512];
  size_t len = static_buildNested(body, JSONREAD_MAX_DEPTH + 1, '{');
  static_assertRefusedBytes(body, len);
}

static void test_duplicate_key_refused(void)
{
  static_assertRefused("{\"a\":1,\"a\":2}");
}

static void test_duplicate_key_not_adjacent_in_input_refused(void)
{
  static_assertRefused("{\"a\":1,\"b\":3,\"a\":2}");
}

static void test_duplicate_key_nested_refused(void)
{
  static_assertRefused("{\"x\":{\"a\":1,\"a\":2}}");
}

static void test_duplicate_key_inside_array_refused(void)
{
  static_assertRefused("{\"x\":[{\"a\":1,\"a\":2}]}");
}

static void test_same_key_in_sibling_objects_accepted(void)
{
  static_assertCanon("{\"x\":{\"a\":1},\"y\":{\"a\":2}}", "{\"x\":{\"a\":1},\"y\":{\"a\":2}}");
}

static void test_key_with_backslash_escape_refused(void)
{
  static_assertRefused("{\"a\\u0062\":1}");
}

static void test_key_with_escaped_quote_refused(void)
{
  static_assertRefused("{\"a\\\"b\":1}");
}

static void test_key_with_slash_escape_refused(void)
{
  static_assertRefused("{\"a\\/b\":1}");
}

static void test_invalid_utf8_value_refused(void)
{
  static_assertRefused("{\"a\":\"\xFF\"}");
}

static void test_invalid_utf8_key_refused(void)
{
  static_assertRefused("{\"\xFF\":1}");
}

static void test_overlong_utf8_refused(void)
{
  static_assertRefused("{\"a\":\"\xC0\x80\"}");
}

static void test_utf8_surrogate_bytes_refused(void)
{
  static_assertRefused("{\"a\":\"\xED\xA0\x80\"}");
}

static void test_utf8_above_max_refused(void)
{
  static_assertRefused("{\"a\":\"\xF4\x90\x80\x80\"}");
}

static void test_truncated_utf8_refused(void)
{
  static_assertRefused("{\"a\":\"\xE2\x82\"}");
}

static void test_raw_control_in_value_refused(void)
{
  static_assertRefused("{\"a\":\"\x01\"}");
}

static void test_raw_newline_in_value_refused(void)
{
  static_assertRefused("{\"a\":\"\n\"}");
}

static void test_raw_control_in_key_refused(void)
{
  static_assertRefused("{\"a\x1f\":1}");
}

static void test_raw_0x7f_escaped(void)
{
  static_assertCanon("{\"a\":\"\x7f\"}", "{\"a\":\"\\u007f\"}");
}

static void test_short_escapes_kept(void)
{
  static_assertCanon("{\"a\":\"\\b\\f\\n\\r\\t\"}", "{\"a\":\"\\b\\f\\n\\r\\t\"}");
}

static void test_short_forms_from_unicode_escapes(void)
{
  static_assertCanon("{\"a\":\"\\u0008\\u000C\\u000a\\u000D\\u0009\"}", "{\"a\":\"\\b\\f\\n\\r\\t\"}");
}

static void test_quote_and_backslash(void)
{
  static_assertCanon("{\"a\":\"\\\"\\\\\"}", "{\"a\":\"\\\"\\\\\"}");
}

static void test_quote_and_backslash_from_unicode_escapes(void)
{
  static_assertCanon("{\"a\":\"\\u0022\\u005c\"}", "{\"a\":\"\\\"\\\\\"}");
}

static void test_slash_decoded_and_not_escaped(void)
{
  static_assertCanon("{\"a\":\"\\/\"}", "{\"a\":\"/\"}");
}

static void test_raw_slash_not_escaped(void)
{
  static_assertCanon("{\"a\":\"a/b\"}", "{\"a\":\"a/b\"}");
}

static void test_low_control_escape_is_lowercase_hex(void)
{
  static_assertCanon("{\"a\":\"\\u001F\\u0001\"}", "{\"a\":\"\\u001f\\u0001\"}");
}

static void test_ascii_escape_decoded(void)
{
  static_assertCanon("{\"a\":\"\\u0041\"}", "{\"a\":\"A\"}");
}

static void test_space_boundary_stays_raw(void)
{
  static_assertCanon("{\"a\":\"\\u0020\"}", "{\"a\":\" \"}");
}

static void test_tilde_boundary_stays_raw(void)
{
  static_assertCanon("{\"a\":\"\\u007e~\"}", "{\"a\":\"~~\"}");
}

static void test_0x7f_escape_stays_escaped(void)
{
  static_assertCanon("{\"a\":\"\\u007F\"}", "{\"a\":\"\\u007f\"}");
}

static void test_two_byte_utf8_escaped(void)
{
  static_assertCanon("{\"a\":\"\xC3\xA9\"}", "{\"a\":\"\\u00e9\"}");
}

static void test_three_byte_utf8_escaped(void)
{
  static_assertCanon("{\"a\":\"\xE2\x82\xAC\"}", "{\"a\":\"\\u20ac\"}");
}

static void test_bmp_top_escaped_without_pair(void)
{
  static_assertCanon("{\"a\":\"\xEF\xBF\xBF\"}", "{\"a\":\"\\uffff\"}");
}

static void test_four_byte_utf8_is_surrogate_pair(void)
{
  static_assertCanon("{\"a\":\"\xF0\x9F\x98\x80\"}", "{\"a\":\"\\ud83d\\ude00\"}");
}

static void test_lowest_four_byte_is_surrogate_pair(void)
{
  static_assertCanon("{\"a\":\"\xF0\x90\x80\x80\"}", "{\"a\":\"\\ud800\\udc00\"}");
}

static void test_highest_code_point_is_surrogate_pair(void)
{
  static_assertCanon("{\"a\":\"\xF4\x8F\xBF\xBF\"}", "{\"a\":\"\\udbff\\udfff\"}");
}

static void test_surrogate_pair_escape_decoded(void)
{
  static_assertCanon("{\"a\":\"\\uD83D\\uDE00\"}", "{\"a\":\"\\ud83d\\ude00\"}");
}

static void test_high_surrogate_edges_pair(void)
{
  static_assertCanon("{\"a\":\"\\uD800\\uDFFF\\uDBFF\\uDC00\"}", "{\"a\":\"\\ud800\\udfff\\udbff\\udc00\"}");
}

static void test_mixed_case_hex_decoded(void)
{
  static_assertCanon("{\"a\":\"\\uAbCd\"}", "{\"a\":\"\\uabcd\"}");
}

static void test_below_surrogate_range_accepted(void)
{
  static_assertCanon("{\"a\":\"\\uD7FF\"}", "{\"a\":\"\\ud7ff\"}");
}

static void test_above_surrogate_range_accepted(void)
{
  static_assertCanon("{\"a\":\"\\uE000\"}", "{\"a\":\"\\ue000\"}");
}

static void test_nul_escape_refused(void)
{
  static_assertRefused("{\"a\":\"\\u0000\"}");
}

static void test_lone_high_surrogate_refused(void)
{
  static_assertRefused("{\"a\":\"\\uD83D\"}");
}

static void test_lone_high_surrogate_at_top_edge_refused(void)
{
  static_assertRefused("{\"a\":\"\\uDBFF\"}");
}

static void test_high_surrogate_before_text_refused(void)
{
  static_assertRefused("{\"a\":\"\\uD83Dabcdef\"}");
}

static void test_high_surrogate_before_short_escape_refused(void)
{
  static_assertRefused("{\"a\":\"\\uD83D\\n\"}");
}

static void test_high_surrogate_before_non_low_refused(void)
{
  static_assertRefused("{\"a\":\"\\uD83D\\u0041\"}");
}

static void test_high_surrogate_before_high_refused(void)
{
  static_assertRefused("{\"a\":\"\\uD83D\\uD83D\"}");
}

static void test_high_surrogate_before_bad_low_hex_refused(void)
{
  static_assertRefused("{\"a\":\"\\uD83D\\uZZZZ\"}");
}

static void test_lone_low_surrogate_refused(void)
{
  static_assertRefused("{\"a\":\"\\uDE00\"}");
}

static void test_lowest_low_surrogate_refused(void)
{
  static_assertRefused("{\"a\":\"\\uDC00\"}");
}

static void test_highest_low_surrogate_refused(void)
{
  static_assertRefused("{\"a\":\"\\uDFFF\"}");
}

static void test_low_surrogate_range_below_edge_pairs_refused(void)
{
  static_assertRefused("{\"a\":\"\\uD83D\\uDBFF\"}");
}

static void test_low_surrogate_range_above_edge_pairs_refused(void)
{
  static_assertRefused("{\"a\":\"\\uD83D\\uE000\"}");
}

static void test_unknown_escape_refused(void)
{
  static_assertRefused("{\"a\":\"\\x41\"}");
}

static void test_short_unicode_escape_refused(void)
{
  static_assertRefused("{\"a\":\"\\u12\"}");
}

static void test_non_hex_unicode_escape_refused(void)
{
  static_assertRefused("{\"a\":\"\\uZZZZ\"}");
}

static void test_hex_digit_edges_refused(void)
{
  static_assertRefused("{\"a\":\"\\u000G\"}");
  static_assertRefused("{\"a\":\"\\u000g\"}");
  static_assertRefused("{\"a\":\"\\u000/\"}");
  static_assertRefused("{\"a\":\"\\u000:\"}");
  static_assertRefused("{\"a\":\"\\u000@\"}");
  static_assertRefused("{\"a\":\"\\u000`\"}");
}

static void test_hex_digit_edges_accepted(void)
{
  static_assertCanon("{\"a\":\"\\u0AfA\"}", "{\"a\":\"\\u0afa\"}");
  static_assertCanon("{\"a\":\"\\u0F90\"}", "{\"a\":\"\\u0f90\"}");
}

static void test_string_longer_than_a_chunk(void)
{
  size_t text_len = 70000;
  char*  body = malloc(text_len + 16);
  char*  want = malloc(text_len + 16);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_NOT_NULL(want);
  memcpy(body, "{\"a\":\"", 6);
  for (size_t i = 0; i < text_len; i++)
    body[6 + i] = (char)('a' + (i % 26));
  memcpy(body + 6 + text_len, "\"}", 3);
  memcpy(want, body, text_len + 9);

  char* text = static_canon(body, text_len + 8);
  TEST_ASSERT_NOT_NULL(text);
  TEST_ASSERT_EQUAL_size_t(text_len + 8, strlen(text));
  TEST_ASSERT_EQUAL_STRING(want, text);
  free(text);
  free(want);
  free(body);
}

static void test_literals_kept(void)
{
  static_assertCanon("{\"a\":true,\"b\":false,\"c\":null}", "{\"a\":true,\"b\":false,\"c\":null}");
}

static void test_literals_case_sensitive(void)
{
  static_assertRefused("{\"a\":TRUE}");
  static_assertRefused("{\"a\":Nul}");
}

static void test_nan_refused(void)
{
  static_assertRefused("{\"a\":NaN}");
}

static void test_infinity_refused(void)
{
  static_assertRefused("{\"a\":Infinity}");
}

static void test_negative_infinity_refused(void)
{
  static_assertRefused("{\"a\":-Infinity}");
}

static void test_float_overflow_refused(void)
{
  static_assertRefused("{\"a\":1e999}");
}

static void test_negative_float_overflow_refused(void)
{
  static_assertRefused("{\"a\":-1e999}");
}

static void test_number_grammar_refused(void)
{
  static_assertRefused("{\"a\":01}");
  static_assertRefused("{\"a\":1.}");
  static_assertRefused("{\"a\":-}");
  static_assertRefused("{\"a\":1e}");
  static_assertRefused("{\"a\":1-2}");
}

static void test_integers_kept_as_text(void)
{
  static_assertCanon("{\"a\":0}", "{\"a\":0}");
  static_assertCanon("{\"a\":-7}", "{\"a\":-7}");
  static_assertCanon("{\"a\":100000000000000000000}", "{\"a\":100000000000000000000}");
}

static void test_negative_zero_integer_loses_sign(void)
{
  static_assertCanon("{\"a\":-0}", "{\"a\":0}");
}

static void test_integer_longer_than_float_limit_kept(void)
{
  char body[JSONCANON_FLOAT_TEXT_MAX + 32];
  memcpy(body, "{\"a\":", 5);
  body[5] = '1';
  memset(body + 6, '2', JSONCANON_FLOAT_TEXT_MAX + 1);
  size_t token_end = 6 + (size_t)JSONCANON_FLOAT_TEXT_MAX + 1;
  body[token_end]     = '}';
  body[token_end + 1] = '\0';
  static_assertCanon(body, body);
}

static void test_float_text_max_is_1024(void)
{
  TEST_ASSERT_EQUAL_INT(1024, JSONCANON_FLOAT_TEXT_MAX);
}

static void test_float_token_at_limit_accepted(void)
{
  char body[JSONCANON_FLOAT_TEXT_MAX + 32];
  memcpy(body, "{\"a\":0.", 7);
  memset(body + 7, '0', JSONCANON_FLOAT_TEXT_MAX - 3);
  body[7 + JSONCANON_FLOAT_TEXT_MAX - 3] = '1';
  memcpy(body + 7 + JSONCANON_FLOAT_TEXT_MAX - 2, "}", 2);
  char* text = static_canon(body, strlen(body));
  TEST_ASSERT_NOT_NULL(text);
  free(text);
}

static void test_float_token_over_limit_refused(void)
{
  char body[JSONCANON_FLOAT_TEXT_MAX + 32];
  memcpy(body, "{\"a\":0.", 7);
  memset(body + 7, '0', JSONCANON_FLOAT_TEXT_MAX - 2);
  body[7 + JSONCANON_FLOAT_TEXT_MAX - 2] = '1';
  memcpy(body + 7 + JSONCANON_FLOAT_TEXT_MAX - 1, "}", 2);
  static_assertRefused(body);
}

static void test_float_measured_forms(void)
{
  static_assertCanon("{\"a\":1e-7}",   "{\"a\":1e-07}");
  static_assertCanon("{\"a\":0.00001}", "{\"a\":1e-05}");
  static_assertCanon("{\"a\":0.0001}", "{\"a\":0.0001}");
  static_assertCanon("{\"a\":15.0}",   "{\"a\":15.0}");
  static_assertCanon("{\"a\":1.10}",   "{\"a\":1.1}");
  static_assertCanon("{\"a\":1e15}",   "{\"a\":1000000000000000.0}");
  static_assertCanon("{\"a\":1e16}",   "{\"a\":1e+16}");
  static_assertCanon("{\"a\":1e22}",   "{\"a\":1e+22}");
  static_assertCanon("{\"a\":1E2}",    "{\"a\":100.0}");
  static_assertCanon("{\"a\":-0.0}",   "{\"a\":-0.0}");
}

static void test_float_underflow_is_zero(void)
{
  static_assertCanon("{\"a\":1e-999}",  "{\"a\":0.0}");
  static_assertCanon("{\"a\":-1e-999}", "{\"a\":-0.0}");
}

static void test_float_three_digit_exponent(void)
{
  static_assertCanon("{\"a\":1e100}",  "{\"a\":1e+100}");
  static_assertCanon("{\"a\":1e-100}", "{\"a\":1e-100}");
}

static void test_float_exponent_mantissa_keeps_digits(void)
{
  static_assertCanon("{\"a\":1.5e20}", "{\"a\":1.5e+20}");
  static_assertCanon("{\"a\":1.5e-6}", "{\"a\":1.5e-06}");
}

static void test_float_exponent_boundaries(void)
{
  static_assertCanon("{\"a\":0.00012}", "{\"a\":0.00012}");
  static_assertCanon("{\"a\":0.000012}", "{\"a\":1.2e-05}");
  static_assertCanon("{\"a\":1234567890123456.0}", "{\"a\":1234567890123456.0}");
  static_assertCanon("{\"a\":12345678901234567.0}", "{\"a\":1.2345678901234568e+16}");
}

static void test_float_positional_split(void)
{
  static_assertCanon("{\"a\":123.456}", "{\"a\":123.456}");
  static_assertCanon("{\"a\":1200.0}",  "{\"a\":1200.0}");
  static_assertCanon("{\"a\":-12.5}",   "{\"a\":-12.5}");
  static_assertCanon("{\"a\":-0.5}",    "{\"a\":-0.5}");
}

static void test_float_seventeen_digits(void)
{
  static_assertCanon("{\"a\":0.30000000000000004}", "{\"a\":0.30000000000000004}");
}

static void test_float_token_limit_counts_the_whole_body(void)
{
  TEST_ASSERT_EQUAL_INT(64, JSONCANON_FLOAT_TOKEN_MAX);
  char body[JSONCANON_FLOAT_TOKEN_MAX * 8 + 64];
  size_t used = (size_t)snprintf(body, sizeof(body), "{\"a\":[1,[0.5");
  for (size_t i = 1; i < JSONCANON_FLOAT_TOKEN_MAX; i++)
    used += (size_t)snprintf(body + used, sizeof(body) - used, ",0.5");
  snprintf(body + used, sizeof(body) - used, ",2]]}");
  char* text = static_canon(body, strlen(body));
  TEST_ASSERT_NOT_NULL_MESSAGE(text, "the limit is written");
  free(text);

  used = (size_t)snprintf(body, sizeof(body), "{\"a\":[1,[0.5");
  for (size_t i = 0; i < JSONCANON_FLOAT_TOKEN_MAX; i++)
    used += (size_t)snprintf(body + used, sizeof(body) - used, ",0.5");
  snprintf(body + used, sizeof(body) - used, ",2]]}");
  TEST_ASSERT_NULL_MESSAGE(static_canon(body, strlen(body)), "one float more is refused");
}

static void test_float_token_limit_is_not_per_container(void)
{
  char body[4096];
  size_t used = (size_t)snprintf(body, sizeof(body), "{\"a\":[0.5");
  for (size_t i = 1; i < 32; i++)
    used += (size_t)snprintf(body + used, sizeof(body) - used, ",0.5");
  used += (size_t)snprintf(body + used, sizeof(body) - used, "],\"b\":[1e0");
  for (size_t i = 1; i < 33; i++)
    used += (size_t)snprintf(body + used, sizeof(body) - used, ",1e0");
  snprintf(body + used, sizeof(body) - used, "]}");
  static_assertRefused(body);

  for (size_t count = 64; count <= 65; count++)
  {
    used = (size_t)snprintf(body, sizeof(body), "{");
    for (size_t i = 0; i < count; i++)
      used += (size_t)snprintf(body + used, sizeof(body) - used, "%s\"k%zu\":{\"x\":0.5}", i > 0 ? "," : "", i);
    snprintf(body + used, sizeof(body) - used, "}");
    if (count == 65)
    {
      static_assertRefused(body);
    }
    else
    {
      char* text = static_canon(body, strlen(body));
      TEST_ASSERT_NOT_NULL(text);
      free(text);
    }
  }
}

static void test_float_power_of_two_needs_digit_above(void)
{
  static_assertCanon("{\"a\":7.1202363472230444e-307}", "{\"a\":7.120236347223045e-307}");
}

static void test_float_carry_through_nines(void)
{
  static_assertCanon("{\"a\":9.9999999999999999e22}", "{\"a\":1e+23}");
}

static void test_key_followed_by_low_byte_sorts_by_length(void)
{
  static_assertCanon("{\"a!\":1,\"a\":2}", "{\"a\":2,\"a!\":1}");
}

static void test_escape_after_plain_text_decoded(void)
{
  static_assertCanon("{\"a\":\"x\\u0041\"}", "{\"a\":\"xA\"}");
}

static void test_high_surrogate_before_non_backslash_u_refused(void)
{
  static_assertRefused("{\"a\":\"\\uD83DxuDE00\"}");
}

static void test_high_surrogate_before_other_escape_with_hex_refused(void)
{
  static_assertRefused("{\"a\":\"\\uD83D\\nDE00\"}");
}

static void test_full_buffer_refused(void)
{
  JsonBuf_t* json_buf = jsonbuf_create(16, 16);
  TEST_ASSERT_NOT_NULL(json_buf);
  TEST_ASSERT_FALSE(jsoncanon_tryWrite("{\"a\":\"0123456789012345678901234567\"}", 35, json_buf));
  jsonbuf_destroy(json_buf);
}

static void test_ceiling_hit_during_escape_refused(void)
{
  JsonBuf_t* json_buf = jsonbuf_create(32, 32);
  TEST_ASSERT_NOT_NULL(json_buf);
  TEST_ASSERT_FALSE(jsoncanon_tryWrite("{\"a\":\"\\u0001\\u0001\\u0001\\u0001\\u0001\"}", 38, json_buf));
  jsonbuf_destroy(json_buf);
}

static void test_reference_vectors(void)
{
  size_t row_count = sizeof(JSONCANON_VECTORS) / sizeof(JSONCANON_VECTORS[0]);
  TEST_ASSERT_GREATER_OR_EQUAL_size_t(120, row_count);

  for (size_t i = 0; i < row_count; i++)
  {
    char message[64];
    snprintf(message, sizeof(message), "vector row %zu", i);

    char* text = static_canon(JSONCANON_VECTORS[i].mp_body, JSONCANON_VECTORS[i].m_bodyLen);
    if (JSONCANON_VECTORS[i].mp_expected == NULL)
    {
      TEST_ASSERT_NULL_MESSAGE(text, message);
      continue;
    }
    TEST_ASSERT_NOT_NULL_MESSAGE(text, message);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(JSONCANON_VECTORS[i].mp_expected, text, message);
    free(text);
  }
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_root_empty_object);
  RUN_TEST(test_root_array_refused);
  RUN_TEST(test_root_string_refused);
  RUN_TEST(test_root_number_refused);
  RUN_TEST(test_null_body_refused);
  RUN_TEST(test_empty_body_refused);
  RUN_TEST(test_trailing_garbage_refused);
  RUN_TEST(test_second_root_refused);
  RUN_TEST(test_bom_refused);
  RUN_TEST(test_bom_after_whitespace_refused);
  RUN_TEST(test_whitespace_dropped);
  RUN_TEST(test_form_feed_is_not_whitespace);
  RUN_TEST(test_body_needs_no_terminator);
  RUN_TEST(test_members_sorted);
  RUN_TEST(test_prefix_key_sorts_first);
  RUN_TEST(test_longer_key_after_prefix_in_input_order);
  RUN_TEST(test_empty_key_sorts_first);
  RUN_TEST(test_nested_objects_sorted);
  RUN_TEST(test_objects_inside_arrays_sorted);
  RUN_TEST(test_array_order_kept);
  RUN_TEST(test_empty_containers);
  RUN_TEST(test_unicode_keys_sort_by_code_point);
  RUN_TEST(test_member_count_255);
  RUN_TEST(test_member_count_256_accepted);
  RUN_TEST(test_member_count_257_refused);
  RUN_TEST(test_member_max_is_256);
  RUN_TEST(test_member_limit_applies_to_nested_object);
  RUN_TEST(test_depth_31_accepted);
  RUN_TEST(test_depth_32_accepted);
  RUN_TEST(test_depth_33_refused);
  RUN_TEST(test_object_depth_32_accepted);
  RUN_TEST(test_object_depth_33_refused);
  RUN_TEST(test_duplicate_key_refused);
  RUN_TEST(test_duplicate_key_not_adjacent_in_input_refused);
  RUN_TEST(test_duplicate_key_nested_refused);
  RUN_TEST(test_duplicate_key_inside_array_refused);
  RUN_TEST(test_same_key_in_sibling_objects_accepted);
  RUN_TEST(test_key_with_backslash_escape_refused);
  RUN_TEST(test_key_with_escaped_quote_refused);
  RUN_TEST(test_key_with_slash_escape_refused);
  RUN_TEST(test_invalid_utf8_value_refused);
  RUN_TEST(test_invalid_utf8_key_refused);
  RUN_TEST(test_overlong_utf8_refused);
  RUN_TEST(test_utf8_surrogate_bytes_refused);
  RUN_TEST(test_utf8_above_max_refused);
  RUN_TEST(test_truncated_utf8_refused);
  RUN_TEST(test_raw_control_in_value_refused);
  RUN_TEST(test_raw_newline_in_value_refused);
  RUN_TEST(test_raw_control_in_key_refused);
  RUN_TEST(test_raw_0x7f_escaped);
  RUN_TEST(test_short_escapes_kept);
  RUN_TEST(test_short_forms_from_unicode_escapes);
  RUN_TEST(test_quote_and_backslash);
  RUN_TEST(test_quote_and_backslash_from_unicode_escapes);
  RUN_TEST(test_slash_decoded_and_not_escaped);
  RUN_TEST(test_raw_slash_not_escaped);
  RUN_TEST(test_low_control_escape_is_lowercase_hex);
  RUN_TEST(test_ascii_escape_decoded);
  RUN_TEST(test_space_boundary_stays_raw);
  RUN_TEST(test_tilde_boundary_stays_raw);
  RUN_TEST(test_0x7f_escape_stays_escaped);
  RUN_TEST(test_two_byte_utf8_escaped);
  RUN_TEST(test_three_byte_utf8_escaped);
  RUN_TEST(test_bmp_top_escaped_without_pair);
  RUN_TEST(test_four_byte_utf8_is_surrogate_pair);
  RUN_TEST(test_lowest_four_byte_is_surrogate_pair);
  RUN_TEST(test_highest_code_point_is_surrogate_pair);
  RUN_TEST(test_surrogate_pair_escape_decoded);
  RUN_TEST(test_high_surrogate_edges_pair);
  RUN_TEST(test_mixed_case_hex_decoded);
  RUN_TEST(test_below_surrogate_range_accepted);
  RUN_TEST(test_above_surrogate_range_accepted);
  RUN_TEST(test_nul_escape_refused);
  RUN_TEST(test_lone_high_surrogate_refused);
  RUN_TEST(test_lone_high_surrogate_at_top_edge_refused);
  RUN_TEST(test_high_surrogate_before_text_refused);
  RUN_TEST(test_high_surrogate_before_short_escape_refused);
  RUN_TEST(test_high_surrogate_before_non_low_refused);
  RUN_TEST(test_high_surrogate_before_high_refused);
  RUN_TEST(test_high_surrogate_before_bad_low_hex_refused);
  RUN_TEST(test_lone_low_surrogate_refused);
  RUN_TEST(test_lowest_low_surrogate_refused);
  RUN_TEST(test_highest_low_surrogate_refused);
  RUN_TEST(test_low_surrogate_range_below_edge_pairs_refused);
  RUN_TEST(test_low_surrogate_range_above_edge_pairs_refused);
  RUN_TEST(test_unknown_escape_refused);
  RUN_TEST(test_short_unicode_escape_refused);
  RUN_TEST(test_non_hex_unicode_escape_refused);
  RUN_TEST(test_hex_digit_edges_refused);
  RUN_TEST(test_hex_digit_edges_accepted);
  RUN_TEST(test_string_longer_than_a_chunk);
  RUN_TEST(test_literals_kept);
  RUN_TEST(test_literals_case_sensitive);
  RUN_TEST(test_nan_refused);
  RUN_TEST(test_infinity_refused);
  RUN_TEST(test_negative_infinity_refused);
  RUN_TEST(test_float_overflow_refused);
  RUN_TEST(test_negative_float_overflow_refused);
  RUN_TEST(test_number_grammar_refused);
  RUN_TEST(test_integers_kept_as_text);
  RUN_TEST(test_negative_zero_integer_loses_sign);
  RUN_TEST(test_integer_longer_than_float_limit_kept);
  RUN_TEST(test_float_token_at_limit_accepted);
  RUN_TEST(test_float_token_over_limit_refused);
  RUN_TEST(test_float_measured_forms);
  RUN_TEST(test_float_underflow_is_zero);
  RUN_TEST(test_float_three_digit_exponent);
  RUN_TEST(test_float_exponent_mantissa_keeps_digits);
  RUN_TEST(test_float_exponent_boundaries);
  RUN_TEST(test_float_positional_split);
  RUN_TEST(test_float_seventeen_digits);
  RUN_TEST(test_float_token_limit_counts_the_whole_body);
  RUN_TEST(test_float_token_limit_is_not_per_container);
  RUN_TEST(test_float_power_of_two_needs_digit_above);
  RUN_TEST(test_float_carry_through_nines);
  RUN_TEST(test_full_buffer_refused);
  RUN_TEST(test_ceiling_hit_during_escape_refused);
  RUN_TEST(test_reference_vectors);
  RUN_TEST(test_float_text_max_is_1024);
  RUN_TEST(test_key_followed_by_low_byte_sorts_by_length);
  RUN_TEST(test_escape_after_plain_text_decoded);
  RUN_TEST(test_high_surrogate_before_non_backslash_u_refused);
  RUN_TEST(test_high_surrogate_before_other_escape_with_hex_refused);
  return UNITY_END();
}
