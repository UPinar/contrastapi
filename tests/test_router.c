#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "unity/unity.h"
#include "router.h"
#include "endpoint.h"
#include "db.h"

static const RequestCharge_t TEST_FULL_CHARGE = { .m_chargedCreditCount = ENDPOINT_FULL_CHARGE, .mp_creditBudget = NULL, .mp_x402Payment = NULL };


#define RESP_BUF 8192

static PGconn* g_conn = NULL;

void setUp(void)    {}
void tearDown(void) {}

static void static_callRouterMethod(const char* method, const char* path, char* buf, size_t len)
{
  char path_copy[512];
  char query_str[512] = "";
  strncpy(path_copy, path, sizeof(path_copy) - 1);
  path_copy[sizeof(path_copy) - 1] = '\0';
  char* query_separator = strchr(path_copy, '?');
  if (query_separator)
  {
    strncpy(query_str, query_separator + 1, sizeof(query_str) - 1);
    query_str[sizeof(query_str) - 1] = '\0';
    *query_separator = '\0';
  }

  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
  {
    perror("socketpair");
    return;
  }
  RouterParsedRequest_t req = { .mp_method = method, .mp_path = path_copy, .mp_query = query_str, .mp_body = "" };
  const char* path_segment   = NULL;
  const Endpoint_t* endpoint = endpoint_findByHttpPath(path_copy, &path_segment);
  router_dispatch(&req, endpoint, path_segment, fds[1], g_conn, &TEST_FULL_CHARGE);
  close(fds[1]);

  ssize_t n = read(fds[0], buf, len - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);
}

static void static_callRouter(const char* path, char* buf, size_t len)
{
  static_callRouterMethod("GET", path, buf, len);
}

static const PagesFile_t WEB_FILE = {
  "/robots.txt", "text/plain; charset=utf-8", "public, max-age=600", "", (const unsigned char*)"User-agent: *\n", 14,
};

static void static_callRouterWithWebFile(const char* method, const char* path, const PagesFile_t* web_file, char* buf, size_t len)
{
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
  {
    perror("socketpair");
    buf[0] = '\0';
    return;
  }
  RouterParsedRequest_t req = { .mp_method = method, .mp_path = path, .mp_query = "", .mp_body = "", .mp_webFile = web_file };
  const char* path_segment   = NULL;
  const Endpoint_t* endpoint = endpoint_findByHttpPath(path, &path_segment);
  router_dispatch(&req, endpoint, path_segment, fds[1], g_conn, &TEST_FULL_CHARGE);
  close(fds[1]);

  ssize_t n = read(fds[0], buf, len - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);
}

void test_HEALTH_route(void)
{
  char buf[RESP_BUF];
  static_callRouter("/health", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 503"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"status\":\"unavailable\""));
}

void test_CVELOOKUP_route_reaches_handler(void)
{
  g_conn = NULL;

  char buf[RESP_BUF];
  static_callRouter("/cve_lookup/CVE-2021-44228", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_CVELOOKUP_param_passed_to_handler_400(void)
{
  char buf[RESP_BUF];
  static_callRouter("/cve_lookup/cve-2021-44228", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"invalid_cve_id\""));
}

void test_CVELOOKUP_empty_suffix(void)
{
  char buf[RESP_BUF];
  static_callRouter("/cve_lookup/", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"missing CVE ID\""));
}

void test_unknown_path(void)
{
  char buf[RESP_BUF];
  static_callRouter("/unknown", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 404"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"not_found\""));
}

void test_HEALTH_exact_no_suffix(void)
{
  char buf[RESP_BUF];
  static_callRouter("/health/extra", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 404"));
}

void test_root_path(void)
{
  char buf[RESP_BUF];
  static_callRouter("/", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 404"));
}

void test_path_matching_is_case_sensitive_404(void)
{
  char buf[RESP_BUF];
  static_callRouter("/HEALTH", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 404"));
}

void test_CVESEARCH_no_filters_reaches_handler(void)
{
  g_conn = NULL;

  char buf[RESP_BUF];
  static_callRouter("/cve_search", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_CVESEARCH_with_qs_reaches_handler(void)
{
  g_conn = NULL;
  
  char buf[RESP_BUF];
  static_callRouter("/cve_search?severity=CRITICAL", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_CVESEARCH_bulk_not_matched_by_CVESEARCH_route(void)
{
  char buf[RESP_BUF];
  static_callRouter("/cve_search_bulk", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 404"));
}

void test_retired_list_paths_are_not_routed(void)
{
  static const char* const retired_paths[] = { "/cves", "/cve_trending" };
  for (size_t i = 0; i < sizeof(retired_paths) / sizeof(retired_paths[0]); i++)
  {
    g_conn = NULL;
    char buf[RESP_BUF];
    static_callRouter(retired_paths[i], buf, sizeof(buf));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 404"), retired_paths[i]);
  }
}

void test_KEVLOOKUP_route_reaches_handler(void)
{
  g_conn = NULL;

  char buf[RESP_BUF];
  static_callRouter("/kev_lookup/CVE-2021-44228", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_CWELOOKUP_route_reaches_handler(void)
{
  g_conn = NULL;

  char buf[RESP_BUF];
  static_callRouter("/cwe_lookup/CWE-79", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_CVELEADING_route_reaches_handler(void)
{
  g_conn = NULL;

  char buf[RESP_BUF];
  static_callRouter("/cve_leading", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_CVELEADING_with_qs_reaches_handler(void)
{
  g_conn = NULL;

  char buf[RESP_BUF];
  static_callRouter("/cve_leading?vendor=microsoft", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_POST_known_route_405(void)
{
  char buf[RESP_BUF];
  static_callRouterMethod("POST", "/health", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 405"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"method_not_allowed\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "Allow: GET"));
}

void test_disallowed_method_beats_a_refused_param_name(void)
{
  char buf[RESP_BUF];
  static_callRouterMethod("POST", "/health?_=1", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 405"));
  TEST_ASSERT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_DELETE_path_param_route_405(void)
{
  char buf[RESP_BUF];
  static_callRouterMethod("DELETE", "/cve_lookup/CVE-2021-44228", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 405"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"method_not_allowed\""));
}

void test_POST_unknown_path_still_404(void)
{
  char buf[RESP_BUF];
  static_callRouterMethod("POST", "/unknown", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 404"));
}

void test_MCP_route_reaches_handler(void)
{
  char buf[RESP_BUF];
  static_callRouterMethod("POST", "/mcp", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 200"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"jsonrpc\":\"2.0\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "-32700"));
}

void test_MCP_get_method_405(void)
{
  char buf[RESP_BUF];
  static_callRouterMethod("GET", "/mcp", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 405"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"method_not_allowed\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "Allow: POST"));
}

void test_PRODUCTEXPOSURE_route_reaches_handler(void)
{
  g_conn = NULL;

  char buf[RESP_BUF];
  static_callRouter("/product_exposure?vendor=cisco&product=ios", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
  TEST_ASSERT_NULL(strstr(buf, "HTTP/1.1 404"));
}

void test_CVSSCALCULATOR_route_reaches_handler(void)
{
  g_conn = NULL;

  char buf[RESP_BUF];
  static_callRouter("/cvss_calculator?vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", buf, sizeof(buf));

  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 200"));
}

void test_PRIVACYMYDATA_without_a_credit_budget_answers_500(void)
{
  char buf[RESP_BUF];
  static_callRouter("/privacy_my_data", buf, sizeof(buf));

  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"internal_error\""));
}

void test_PRIVACYMYDATA_post_method_405(void)
{
  char buf[RESP_BUF];
  static_callRouterMethod("POST", "/privacy_my_data", buf, sizeof(buf));

  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 405"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "Allow: GET"));
}

void test_CVSSCALCULATOR_post_method_405(void)
{
  char buf[RESP_BUF];
  static_callRouterMethod("POST", "/cvss_calculator", buf, sizeof(buf));

  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 405"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "Allow: GET"));
}

void test_web_file_is_answered_when_no_row_serves_the_path(void)
{
  char buf[RESP_BUF];
  static_callRouterWithWebFile("GET", "/robots.txt", &WEB_FILE, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 200 OK\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nContent-Type: text/plain; charset=utf-8\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\n\r\nUser-agent: *\n"));
}

void test_web_file_refuses_other_methods_with_405(void)
{
  static const char* const methods[] = { "POST", "PUT", "DELETE", "OPTIONS" };
  for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++)
  {
    char buf[RESP_BUF];
    static_callRouterWithWebFile(methods[i], "/robots.txt", &WEB_FILE, buf, sizeof(buf));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 405"), methods[i]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "\r\nAllow: GET, HEAD\r\n"), methods[i]);
    TEST_ASSERT_NULL_MESSAGE(strstr(buf, "User-agent"), methods[i]);
  }
}

void test_row_wins_over_a_web_file(void)
{
  char buf[RESP_BUF];
  static_callRouterWithWebFile("GET", "/health", &WEB_FILE, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"status\":\"unavailable\""));
  TEST_ASSERT_NULL(strstr(buf, "User-agent"));

  static_callRouterWithWebFile("HEAD", "/health", &WEB_FILE, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 405"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nAllow: GET\r\n"));
}

void test_post_hands_on_the_body_length(void)
{
  static const char body[] = "\xff\xd8\xff\xe0\0abc";
  static const struct { const char* mp_body; size_t m_bodyLen; const char* mp_expected; } cases[] = {
    { body,     5, "\"byte_count\":5," },
    { body + 5, 3, "HTTP/1.1 400 " },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    int fds[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
    RouterParsedRequest_t req = { .mp_method = "POST", .mp_path = "/image_inspect", .mp_query = "", .mp_body = cases[i].mp_body, .m_bodyLen = cases[i].m_bodyLen };
    const char* path_segment   = NULL;
    const Endpoint_t* endpoint = endpoint_findByHttpPath("/image_inspect", &path_segment);
    router_dispatch(&req, endpoint, path_segment, fds[1], g_conn, &TEST_FULL_CHARGE);
    close(fds[1]);
    char buf[RESP_BUF];
    ssize_t n = read(fds[0], buf, sizeof(buf) - 1);
    buf[n > 0 ? n : 0] = '\0';
    close(fds[0]);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, cases[i].mp_expected), buf);
  }
}

typedef struct {
  char ma_signature[17];
} TestSignedParams_t;

static const EndpointParamSpec_t TEST_SPEC_SIGNATURE = {
  .mp_name              = "X-Signature",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = 16,
};

static const EndpointParam_t TEST_SIGNED_PARAMS[] = {
  {
    .mp_spec              = &TEST_SPEC_SIGNATURE,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_HEADER,
    .m_isRequired         = true,
    .m_offset             = offsetof(TestSignedParams_t, ma_signature),
    .m_size               = sizeof(((TestSignedParams_t*)0)->ma_signature),
  },
};

#define TEST_RUN_MESSAGE "the \"test\" run says no"

static EndpointRunStatus_t static_runSigned(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)conn;
  const TestSignedParams_t* signed_params = (const TestSignedParams_t*)params;
  if (strcmp(signed_params->ma_signature, "bad") == 0)
  {
    *message_out = TEST_RUN_MESSAGE;
    return ENDPOINT_RUN_UNAUTHORIZED;
  }
  if (strcmp(signed_params->ma_signature, "old") == 0)
  {
    *message_out = TEST_RUN_MESSAGE;
    return ENDPOINT_RUN_GONE;
  }
  jsonbuf_appendFormat(json_buf, "{\"signature\":\"");
  jsonbuf_appendEscaped(json_buf, signed_params->ma_signature);
  jsonbuf_appendFormat(json_buf, "\"}");
  return ENDPOINT_RUN_OK;
}

static const Endpoint_t TEST_SIGNED_ROW = {
  .mp_httpPath          = "/test_signed",
  .ma_allowedMethods    = {"POST", NULL},
  .m_creditCost         = 0,
  .m_costRule           = ENDPOINT_COST_FLAT,
  .mp_params            = TEST_SIGNED_PARAMS,
  .m_paramCount         = 1,
  .m_paramsSize         = sizeof(TestSignedParams_t),
  .m_runFunction        = static_runSigned,
  .m_jsonCeiling        = JSONBUF_DEFAULT_CEILING,
};

static void static_dispatchSigned(const char* query, const struct phr_header* headers, size_t header_count, char* buf, size_t len)
{
  int fds[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  RouterParsedRequest_t req = { .mp_method = "POST", .mp_path = "/test_signed", .mp_query = query, .mp_body = "", .mp_headers = headers, .m_headerCount = header_count };
  router_dispatch(&req, &TEST_SIGNED_ROW, NULL, fds[1], g_conn, &TEST_FULL_CHARGE);
  close(fds[1]);
  ssize_t n = read(fds[0], buf, len - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);
}

void test_header_param_reaches_the_run(void)
{
  struct phr_header headers[] = { { "x-signature", 11, "good", 4 } };
  char buf[RESP_BUF];
  static_dispatchSigned("", headers, 1, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 200 "), buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "{\"signature\":\"good\"}"), buf);
}

void test_header_param_refusals_answer_400(void)
{
  char buf[RESP_BUF];
  static_dispatchSigned("", NULL, 0, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 400 "), buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "X-Signature is required"), buf);

  struct phr_header twice[] = { { "X-Signature", 11, "a", 1 }, { "X-Signature", 11, "a", 1 } };
  static_dispatchSigned("", twice, 2, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 400 "), buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "X-Signature appears more than once"), buf);

  static_dispatchSigned("X-Signature=good", twice, 1, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 400 "), buf);
  TEST_ASSERT_NULL_MESSAGE(strstr(buf, "\"signature\""), buf);
}

void test_unauthorized_run_answers_401_invalid_signature(void)
{
  struct phr_header headers[] = { { "X-Signature", 11, "bad", 3 } };
  char buf[RESP_BUF];
  static_dispatchSigned("", headers, 1, buf, sizeof(buf));
  TEST_ASSERT_EQUAL_STRING_LEN("HTTP/1.1 401 Unauthorized\r\n", buf, strlen("HTTP/1.1 401 Unauthorized\r\n"));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "{\"error\":{\"code\":\"invalid_signature\",\"message\":\"the \\\"test\\\" run says no\"}}"), buf);
  TEST_ASSERT_NULL(strstr(buf + 1, "HTTP/1.1 "));
}

void test_gone_run_answers_410(void)
{
  struct phr_header headers[] = { { "X-Signature", 11, "old", 3 } };
  char buf[RESP_BUF];
  static_dispatchSigned("", headers, 1, buf, sizeof(buf));
  TEST_ASSERT_EQUAL_STRING_LEN("HTTP/1.1 410 Gone\r\n", buf, strlen("HTTP/1.1 410 Gone\r\n"));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "{\"error\":{\"code\":\"gone\",\"message\":\"the \\\"test\\\" run says no\"}}"), buf);
  TEST_ASSERT_NULL(strstr(buf + 1, "HTTP/1.1 "));
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_HEALTH_route);
  RUN_TEST(test_CVELOOKUP_route_reaches_handler);
  RUN_TEST(test_CVELOOKUP_param_passed_to_handler_400);
  RUN_TEST(test_CVELOOKUP_empty_suffix);
  RUN_TEST(test_unknown_path);
  RUN_TEST(test_HEALTH_exact_no_suffix);
  RUN_TEST(test_root_path);
  RUN_TEST(test_path_matching_is_case_sensitive_404);
  RUN_TEST(test_CVESEARCH_no_filters_reaches_handler);
  RUN_TEST(test_CVESEARCH_with_qs_reaches_handler);
  RUN_TEST(test_CVESEARCH_bulk_not_matched_by_CVESEARCH_route);
  RUN_TEST(test_retired_list_paths_are_not_routed);
  RUN_TEST(test_KEVLOOKUP_route_reaches_handler);
  RUN_TEST(test_CWELOOKUP_route_reaches_handler);
  RUN_TEST(test_CVELEADING_route_reaches_handler);
  RUN_TEST(test_CVELEADING_with_qs_reaches_handler);
  RUN_TEST(test_POST_known_route_405);
  RUN_TEST(test_disallowed_method_beats_a_refused_param_name);
  RUN_TEST(test_DELETE_path_param_route_405);
  RUN_TEST(test_POST_unknown_path_still_404);
  RUN_TEST(test_MCP_route_reaches_handler);
  RUN_TEST(test_MCP_get_method_405);
  RUN_TEST(test_PRODUCTEXPOSURE_route_reaches_handler);
  RUN_TEST(test_CVSSCALCULATOR_route_reaches_handler);
  RUN_TEST(test_PRIVACYMYDATA_without_a_credit_budget_answers_500);
  RUN_TEST(test_PRIVACYMYDATA_post_method_405);
  RUN_TEST(test_CVSSCALCULATOR_post_method_405);
  RUN_TEST(test_web_file_is_answered_when_no_row_serves_the_path);
  RUN_TEST(test_web_file_refuses_other_methods_with_405);
  RUN_TEST(test_row_wins_over_a_web_file);
  RUN_TEST(test_post_hands_on_the_body_length);
  RUN_TEST(test_header_param_reaches_the_run);
  RUN_TEST(test_header_param_refusals_answer_400);
  RUN_TEST(test_unauthorized_run_answers_401_invalid_signature);
  RUN_TEST(test_gone_run_answers_410);
  return UNITY_END();
}
