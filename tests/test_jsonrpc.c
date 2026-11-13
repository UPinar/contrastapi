#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity/unity.h"
#include "jsonrpc.h"
#include "jsonread.h"
#include "jsonbuf.h"

void setUp(void)    {}
void tearDown(void) {}

void test_parse_valid_request(void)
{
  const char* body = "{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":2}";
  JsonRpcRequest_t req;
  TEST_ASSERT_EQUAL_INT(JSONRPC_OK, jsonrpc_parse(body, strlen(body), &req));
  TEST_ASSERT_EQUAL_STRING("tools/list", req.ma_rpcMethod);
  TEST_ASSERT_TRUE(req.m_hasId);
  TEST_ASSERT_EQUAL_STRING("2", req.ma_id);
  TEST_ASSERT_FALSE(req.m_hasParams);
}

void test_parse_string_id_kept_raw(void)
{
  const char* body = "{\"jsonrpc\":\"2.0\",\"id\":\"abc-1\",\"method\":\"ping\"}";
  JsonRpcRequest_t req;
  TEST_ASSERT_EQUAL_INT(JSONRPC_OK, jsonrpc_parse(body, strlen(body), &req));
  TEST_ASSERT_TRUE(req.m_hasId);
  TEST_ASSERT_EQUAL_STRING("\"abc-1\"", req.ma_id);
}

void test_parse_notification_has_no_id(void)
{
  const char* body = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}";
  JsonRpcRequest_t req;
  TEST_ASSERT_EQUAL_INT(JSONRPC_OK, jsonrpc_parse(body, strlen(body), &req));
  TEST_ASSERT_FALSE(req.m_hasId);
  TEST_ASSERT_EQUAL_STRING("notifications/initialized", req.ma_rpcMethod);
}

void test_parse_params_span(void)
{
  const char* body =
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
    "\"params\":{\"name\":\"cve_lookup\",\"arguments\":{\"id\":\"CVE-2021-44228\"}}}";
  JsonRpcRequest_t req;
  TEST_ASSERT_EQUAL_INT(JSONRPC_OK, jsonrpc_parse(body, strlen(body), &req));
  TEST_ASSERT_TRUE(req.m_hasParams);

  JsonReadSpan_t name_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(req.m_params, "name", &name_span));
  char name[32];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToStrStatus(name_span, name, sizeof(name)));
  TEST_ASSERT_EQUAL_STRING("cve_lookup", name);

  JsonReadSpan_t args_span, id_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(req.m_params, "arguments", &args_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(args_span, "id", &id_span));
  char id[32];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToStrStatus(id_span, id, sizeof(id)));
  TEST_ASSERT_EQUAL_STRING("CVE-2021-44228", id);
}

void test_parse_missing_version_is_invalid(void)
{
  const char* body = "{\"method\":\"ping\",\"id\":1}";
  JsonRpcRequest_t req;
  TEST_ASSERT_EQUAL_INT(JSONRPC_INVALID, jsonrpc_parse(body, strlen(body), &req));
}

void test_parse_wrong_version_is_invalid(void)
{
  const char* body = "{\"jsonrpc\":\"1.0\",\"method\":\"ping\",\"id\":1}";
  JsonRpcRequest_t req;
  TEST_ASSERT_EQUAL_INT(JSONRPC_INVALID, jsonrpc_parse(body, strlen(body), &req));
}

void test_parse_missing_method_is_invalid(void)
{
  const char* body = "{\"jsonrpc\":\"2.0\",\"id\":1}";
  JsonRpcRequest_t req;
  TEST_ASSERT_EQUAL_INT(JSONRPC_INVALID, jsonrpc_parse(body, strlen(body), &req));
}

void test_parse_malformed_json(void)
{
  const char* body = "{\"jsonrpc\":\"2.0\",\"method\":";
  JsonRpcRequest_t req;
  TEST_ASSERT_EQUAL_INT(JSONRPC_MALFORMED, jsonrpc_parse(body, strlen(body), &req));
}

void test_parse_json_that_is_not_an_object_is_invalid(void)
{
  static const char* const bodies[] = { "[1,2,3]", "[]", "\"s\"", "42", "true", "null" };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    JsonRpcRequest_t req;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONRPC_INVALID, jsonrpc_parse(bodies[i], strlen(bodies[i]), &req), bodies[i]);
  }
}

void test_parse_body_that_is_not_valid_utf8_is_malformed(void)
{
  static const char* const bodies[] = {
    "{\"jsonrpc\":\"2.0\",\"id\":\"\xff\",\"method\":\"ping\"}",
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"pi\xc0\x80ng\"}",
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"cve_search\",\"arguments\":{\"vendor\":\"a\xe2\x82\"}}}",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    JsonRpcRequest_t req;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONRPC_MALFORMED, jsonrpc_parse(bodies[i], strlen(bodies[i]), &req), bodies[i]);
  }
}

static JsonRpcStatus_t static_parseWithId(const char* id_token, JsonRpcRequest_t* req)
{
  char body[256];
  int  body_len = snprintf(body, sizeof(body), "{\"jsonrpc\":\"2.0\",\"id\":%s,\"method\":\"ping\"}", id_token);
  TEST_ASSERT_TRUE_MESSAGE(body_len > 0 && (size_t)body_len < sizeof(body), id_token);
  return jsonrpc_parse(body, (size_t)body_len, req);
}

void test_parse_id_outside_the_grammar_is_invalid(void)
{
  static const char* const invalid_ids[] = {
    "-", "--", "-.5", "1-2-3", "00123", "01", "-01", "1.", "1.e5", "1.2.3", "1e", "1e+", "1e5e5", "1e+-5",
    "\"a\\qb\"", "\"\\u12\"", "\"\\u123\"", "\"\\u12G4\"", "\"\\uG123\"",
    "true", "false", "{}", "[1]", "{\"a\":1}",
  };
  for (size_t i = 0; i < sizeof(invalid_ids) / sizeof(invalid_ids[0]); i++)
  {
    JsonRpcRequest_t req;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONRPC_INVALID, static_parseWithId(invalid_ids[i], &req), invalid_ids[i]);
  }
}

void test_parse_id_inside_the_grammar_is_kept_raw(void)
{
  static const char* const valid_ids[] = {
    "0", "-0", "7", "9", "-1", "0.5", "1.5", "1e5", "1E+5", "-1.2e-3",
    "12345678901234567890123", "null",
    "\"\"", "\"abc\"", "\"a\\\"b\"", "\"\xc3\xa9\"", "\"\\/\"",
    "\"\\u00e9\"", "\"\\uABcd\"", "\"\\b\\f\\n\\r\\t\\\\\"",
  };
  for (size_t i = 0; i < sizeof(valid_ids) / sizeof(valid_ids[0]); i++)
  {
    JsonRpcRequest_t req;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONRPC_OK, static_parseWithId(valid_ids[i], &req), valid_ids[i]);
    TEST_ASSERT_TRUE_MESSAGE(req.m_hasId, valid_ids[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(valid_ids[i], req.ma_id, valid_ids[i]);
  }
}

void test_parse_id_every_undefined_escape_is_invalid(void)
{
  static const char legal_escapes[] = "\"\\/bfnrtu";
  for (int escaped = 0x20; escaped < 0x7f; escaped++)
  {
    if (strchr(legal_escapes, escaped) != NULL)
      continue;
    char id_token[8];
    int  token_len = snprintf(id_token, sizeof(id_token), "\"\\%c\"", escaped);
    TEST_ASSERT_TRUE(token_len > 0 && (size_t)token_len < sizeof(id_token));
    JsonRpcRequest_t req;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONRPC_INVALID, static_parseWithId(id_token, &req), id_token);
  }
}

void test_parse_id_with_a_hidden_character_is_invalid(void)
{
  static const char* const hidden_ids[] = {
    "\"\xe2\x80\xae\"", "\"a\xe2\x80\x8b" "b\"", "\"\xef\xbb\xbf\"", "\"\x7f\"",
    "\"\\u202e\"", "\"\\u202E\"", "\"a\\u2066b\"", "\"\\u007f\"", "\"\\ufeff\"",
  };
  for (size_t i = 0; i < sizeof(hidden_ids) / sizeof(hidden_ids[0]); i++)
  {
    JsonRpcRequest_t req;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONRPC_INVALID, static_parseWithId(hidden_ids[i], &req), hidden_ids[i]);
  }

  static const char* const neighbour_ids[] = {
    "\"\xe2\x80\xaf\"", "\"\\u202f\"", "\"\\u200a\"", "\"\\u2061\"", "\"\\u007e\"", "\"\\u0080\"",
    "\"a\\\\u2028\"",
  };
  for (size_t i = 0; i < sizeof(neighbour_ids) / sizeof(neighbour_ids[0]); i++)
  {
    JsonRpcRequest_t req;
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONRPC_OK, static_parseWithId(neighbour_ids[i], &req), neighbour_ids[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(neighbour_ids[i], req.ma_id, neighbour_ids[i]);
  }
}

void test_parse_id_at_the_length_limit_is_kept_raw(void)
{
  TEST_ASSERT_EQUAL_INT(64, JSONRPC_ID_MAX_LEN);

  char id_token[JSONRPC_ID_MAX_LEN + 1];
  memset(id_token, '1', JSONRPC_ID_MAX_LEN);
  id_token[JSONRPC_ID_MAX_LEN] = '\0';

  JsonRpcRequest_t req;
  TEST_ASSERT_EQUAL_INT(JSONRPC_OK, static_parseWithId(id_token, &req));
  TEST_ASSERT_TRUE(req.m_hasId);
  TEST_ASSERT_EQUAL_STRING(id_token, req.ma_id);
}

void test_parse_id_over_the_length_limit_echoes_null(void)
{
  char id_token[JSONRPC_ID_MAX_LEN + 2];
  memset(id_token, '1', JSONRPC_ID_MAX_LEN + 1);
  id_token[JSONRPC_ID_MAX_LEN + 1] = '\0';

  JsonRpcRequest_t req;
  TEST_ASSERT_EQUAL_INT(JSONRPC_OK, static_parseWithId(id_token, &req));
  TEST_ASSERT_TRUE(req.m_hasId);
  TEST_ASSERT_EQUAL_STRING("null", req.ma_id);
}

void test_parse_overlong_id_outside_the_grammar_is_invalid(void)
{
  char id_token[JSONRPC_ID_MAX_LEN + 2];
  memset(id_token, '1', JSONRPC_ID_MAX_LEN + 1);
  id_token[0] = '0';
  id_token[JSONRPC_ID_MAX_LEN + 1] = '\0';

  JsonRpcRequest_t req;
  TEST_ASSERT_EQUAL_INT(JSONRPC_INVALID, static_parseWithId(id_token, &req));
}

static JsonBuf_t* static_createBuf(void)
{
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  return json_buf;
}

static char* static_finishBody(JsonBuf_t* json_buf)
{
  char* body = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  TEST_ASSERT_NOT_NULL(body);
  return body;
}

void test_serialize_result_verbatim(void)
{
  JsonBuf_t* json_buf = static_createBuf();
  jsonrpc_serializeResult("7", "{\"ok\":true}", json_buf);
  char* body = static_finishBody(json_buf);
  TEST_ASSERT_EQUAL_STRING("{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}", body);
  free(body);
}

void test_serialize_result_string_id(void)
{
  JsonBuf_t* json_buf = static_createBuf();
  jsonrpc_serializeResult("\"abc\"", "{}", json_buf);
  char* body = static_finishBody(json_buf);
  TEST_ASSERT_EQUAL_STRING("{\"jsonrpc\":\"2.0\",\"id\":\"abc\",\"result\":{}}", body);
  free(body);
}

void test_serialize_error_escapes_message(void)
{
  JsonBuf_t* json_buf = static_createBuf();
  jsonrpc_serializeError("null", JSONRPC_ERR_METHOD, "Method not found", NULL, json_buf);
  char* body = static_finishBody(json_buf);
  TEST_ASSERT_EQUAL_STRING(
    "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}",
    body);
  free(body);
}

void test_serialize_error_message_with_quotes(void)
{
  JsonBuf_t* json_buf = static_createBuf();
  jsonrpc_serializeError("1", JSONRPC_ERR_PARAMS, "bad \"name\"", NULL, json_buf);
  char* body = static_finishBody(json_buf);
  TEST_ASSERT_EQUAL_STRING(
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"bad \\\"name\\\"\"}}",
    body);
  free(body);
}

void test_serialize_error_with_data_member(void)
{
  JsonBuf_t* json_buf = static_createBuf();
  jsonrpc_serializeError("2", JSONRPC_ERR_PARAMS, "Unsupported protocol version", "{\"supported\":[\"2026-07-28\"]}", json_buf);
  char* body = static_finishBody(json_buf);
  TEST_ASSERT_EQUAL_STRING(
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"error\":{\"code\":-32602,\"message\":\"Unsupported protocol version\","
    "\"data\":{\"supported\":[\"2026-07-28\"]}}}",
    body);
  free(body);
}

void test_parse_unreadable_method_is_invalid(void)
{
  static const char* const bodies[] = {
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":5}",
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/li\\ud800st\"}",
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/li\\xst\"}",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    JsonRpcRequest_t req;
    memset(&req, 0, sizeof(req));
    TEST_ASSERT_EQUAL_INT_MESSAGE(JSONRPC_INVALID, jsonrpc_parse(bodies[i], strlen(bodies[i]), &req), bodies[i]);
  }
}

void test_parse_method_with_a_unicode_escape_is_read_decoded(void)
{
  const char* body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/li\\u0073t\"}";
  JsonRpcRequest_t req;
  memset(&req, 0, sizeof(req));
  TEST_ASSERT_EQUAL_INT(JSONRPC_OK, jsonrpc_parse(body, strlen(body), &req));
  TEST_ASSERT_EQUAL_STRING("tools/list", req.ma_rpcMethod);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_parse_valid_request);
  RUN_TEST(test_parse_string_id_kept_raw);
  RUN_TEST(test_parse_notification_has_no_id);
  RUN_TEST(test_parse_params_span);
  RUN_TEST(test_parse_missing_version_is_invalid);
  RUN_TEST(test_parse_wrong_version_is_invalid);
  RUN_TEST(test_parse_missing_method_is_invalid);
  RUN_TEST(test_parse_malformed_json);
  RUN_TEST(test_parse_json_that_is_not_an_object_is_invalid);
  RUN_TEST(test_parse_body_that_is_not_valid_utf8_is_malformed);
  RUN_TEST(test_parse_id_outside_the_grammar_is_invalid);
  RUN_TEST(test_parse_id_inside_the_grammar_is_kept_raw);
  RUN_TEST(test_parse_id_every_undefined_escape_is_invalid);
  RUN_TEST(test_parse_id_with_a_hidden_character_is_invalid);
  RUN_TEST(test_parse_id_at_the_length_limit_is_kept_raw);
  RUN_TEST(test_parse_id_over_the_length_limit_echoes_null);
  RUN_TEST(test_parse_overlong_id_outside_the_grammar_is_invalid);
  RUN_TEST(test_serialize_result_verbatim);
  RUN_TEST(test_serialize_result_string_id);
  RUN_TEST(test_serialize_error_escapes_message);
  RUN_TEST(test_serialize_error_message_with_quotes);
  RUN_TEST(test_serialize_error_with_data_member);
  RUN_TEST(test_parse_unreadable_method_is_invalid);
  RUN_TEST(test_parse_method_with_a_unicode_escape_is_read_decoded);
  return UNITY_END();
}
