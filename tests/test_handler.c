#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/evp.h>

#include "unity/unity.h"
#include "handler.h"
#include "endpoint.h"
#include "db.h"
#include "mcp.h"
#include "validate.h"
#include "imagescan.h"
#include "exifclient.h"
#include "usagelog.h"
#include "x402_request.h"
#include "x402_ledger_stub.h"
#include "jsonread.h"
#include "config.h"

extern ExifClientStatus_t g_stub_IMAGEINSPECT_exif_status;
extern ExifClientResult_t g_stub_IMAGEINSPECT_exif_result;
extern int                g_stub_IMAGEINSPECT_exif_call_count;
extern size_t             g_stub_IMAGEINSPECT_exif_last_byte_count;
extern unsigned char      g_stub_IMAGEINSPECT_exif_last_bytes[64];

static const RequestCharge_t TEST_FULL_CHARGE = { .m_chargedCreditCount = ENDPOINT_FULL_CHARGE, .mp_creditBudget = NULL, .mp_x402Payment = NULL };


#define REST_INPUT(path_segment, query, body, body_len) \
  (&(EndpointRestInput_t){ .mp_pathSegment = (path_segment), .mp_query = (query), .m_body = { (const unsigned char*)(body), (body_len) } })

#define RESP_BUF 8192

static PGconn* g_conn = NULL;

static bool g_isDigestFailing = false;

int __real_EVP_Digest(const void* data, size_t count, unsigned char* md, unsigned int* size, const EVP_MD* type, ENGINE* impl);

int __wrap_EVP_Digest(const void* data, size_t count, unsigned char* md, unsigned int* size, const EVP_MD* type, ENGINE* impl)
{
  if (g_isDigestFailing)
  {
    g_isDigestFailing = false;
    return 0;
  }
  return __real_EVP_Digest(data, count, md, size, type, impl);
}

void setUp(void)
{
  g_isDigestFailing = false;
  g_stub_IMAGEINSPECT_exif_status     = EXIFCLIENT_OK;
  g_stub_IMAGEINSPECT_exif_call_count = 0;
  memset(&g_stub_IMAGEINSPECT_exif_result, 0, sizeof(g_stub_IMAGEINSPECT_exif_result));
}
void tearDown(void) {}

static void static_callHandler(void (*handler_function)(int), char* buf, size_t len)
{
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
  {
    perror("socketpair");
    return;
  }
  handler_function(fds[1]);
  close(fds[1]);

  ssize_t n = read(fds[0], buf, len - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);
}

typedef enum { REFUSAL_UNAUTHORIZED, REFUSAL_API_KEY_INACTIVE, REFUSAL_RATE_LIMITED, REFUSAL_INTERNAL_ERROR, REFUSAL_RAW_BODY_BUSY } Refusal_t;

static void static_callRefusal(Refusal_t refusal, const char* body, unsigned int retry_after_sec, char* buf, size_t len)
{
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
  {
    perror("socketpair");
    return;
  }
  if (refusal == REFUSAL_UNAUTHORIZED)
    handler_mcpUnauthorized(fds[1], body);
  else if (refusal == REFUSAL_API_KEY_INACTIVE)
    handler_mcpApiKeyInactive(fds[1], body);
  else if (refusal == REFUSAL_RATE_LIMITED && body == NULL)
    handler_rateLimited(fds[1], retry_after_sec);
  else if (refusal == REFUSAL_RATE_LIMITED)
    handler_mcpRateLimited(fds[1], body, retry_after_sec);
  else if (refusal == REFUSAL_RAW_BODY_BUSY)
    handler_rawBodyBusy(fds[1]);
  else
    handler_mcpInternalError(fds[1], body);
  close(fds[1]);

  ssize_t n = read(fds[0], buf, len - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);
}

static const char* static_bodyOf(const char* buf)
{
  const char* head_end = strstr(buf, "\r\n\r\n");
  TEST_ASSERT_NOT_NULL(head_end);
  return head_end + 4;
}

static const Endpoint_t* static_rowOf(const char* http_path)
{
  for (int i = 0; i < endpoint_count; i++)
  {
    if (strcmp(endpoints[i].mp_httpPath, http_path) == 0)
      return &endpoints[i];
  }
  TEST_FAIL_MESSAGE("no endpoints[] row has this path");
  return NULL;
}

static void static_runEndpoint(const char* http_path, const char* path_segment, const char* query_str, const char* body, char* buf, size_t len)
{
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
  {
    perror("socketpair");
    return;
  }
  handler_runRestEndpoint(fds[1], static_rowOf(http_path), REST_INPUT(path_segment, query_str, body, body ? strlen(body) : 0), g_conn, &TEST_FULL_CHARGE);
  close(fds[1]);

  ssize_t n = read(fds[0], buf, len - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);
}

static void static_runImageInspect(const char* bytes, size_t byte_count, char* buf, size_t len)
{
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
  {
    perror("socketpair");
    return;
  }
  handler_runRestEndpoint(fds[1], static_rowOf("/image_inspect"), REST_INPUT(NULL, "", bytes, byte_count), g_conn, &TEST_FULL_CHARGE);
  close(fds[1]);

  ssize_t n = read(fds[0], buf, len - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);
}

static void static_runEndpointWithPathSegment(const char* http_path, const char* path_segment, char* buf, size_t len)
{
  static_runEndpoint(http_path, path_segment, "", NULL, buf, len);
}

static void static_runEndpointWithQuery(const char* http_path, const char* query_str, char* buf, size_t len)
{
  static_runEndpoint(http_path, NULL, query_str, NULL, buf, len);
}

static void static_runEndpointWithBody(const char* http_path, const char* body, char* buf, size_t len)
{
  static_runEndpoint(http_path, NULL, "", body, buf, len);
}

static void static_callMcpWithHeaders(const char* body, const McpRoutingHeaders_t* routing_headers, char* buf, size_t len)
{
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
  {
    perror("socketpair");
    return;
  }
  handler_MCP(fds[1], body, routing_headers, g_conn, &TEST_FULL_CHARGE);
  close(fds[1]);

  ssize_t n = read(fds[0], buf, len - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);
}

static void static_callMcp(const char* body, char* buf, size_t len)
{
  static_callMcpWithHeaders(body, NULL, buf, len);
}



void test_bad_request_400(void)
{
  char buf[RESP_BUF];
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) { perror("socketpair"); return; }
  handler_badRequest(fds[1], "missing CVE ID");
  close(fds[1]);
  ssize_t n = read(fds[0], buf, sizeof(buf) - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);

  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400 Bad Request\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"bad_request\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"missing CVE ID\""));
}

void test_raw_body_busy_503(void)
{
  char buf[RESP_BUF];
  static_callRefusal(REFUSAL_RAW_BODY_BUSY, NULL, 0, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 503 Service Unavailable\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nRetry-After: 10\r\n"));
  TEST_ASSERT_EQUAL_STRING("{\"error\":{\"code\":\"raw_body_busy\",\"message\":\"too many raw request bodies at once\"}}\n", static_bodyOf(buf));
}

void test_rate_limited_429(void)
{
  char buf[RESP_BUF];
  static_callRefusal(REFUSAL_RATE_LIMITED, NULL, 42, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 429 Too Many Requests\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nRetry-After: 42\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"rate_limited\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"rate limit exceeded\""));
}

void test_mcp_unauthorized_401(void)
{
  char buf[RESP_BUF];
  static_callRefusal(REFUSAL_UNAUTHORIZED, "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/list\"}", 0, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 401 Unauthorized\r\n"));
  TEST_ASSERT_EQUAL_STRING("{\"jsonrpc\":\"2.0\",\"id\":5,\"error\":{\"code\":-32001,\"message\":\"Invalid API key\"}}", static_bodyOf(buf));
}

void test_mcp_api_key_inactive_401(void)
{
  char buf[RESP_BUF];
  static_callRefusal(REFUSAL_API_KEY_INACTIVE, "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/list\"}", 0, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 401 Unauthorized\r\n"));
  TEST_ASSERT_EQUAL_STRING("{\"jsonrpc\":\"2.0\",\"id\":8,\"error\":{\"code\":-32004,\"message\":\"API key expired or revoked\"}}", static_bodyOf(buf));
}

void test_mcp_rate_limited_429(void)
{
  char buf[RESP_BUF];
  static_callRefusal(REFUSAL_RATE_LIMITED, "{\"jsonrpc\":\"2.0\",\"id\":\"q\",\"method\":\"tools/list\"}", 42, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 429 Too Many Requests\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nRetry-After: 42\r\n"));
  TEST_ASSERT_EQUAL_STRING("{\"jsonrpc\":\"2.0\",\"id\":\"q\",\"error\":{\"code\":-32000,\"message\":\"rate limit exceeded\","
                           "\"data\":{\"retry_after_seconds\":42}}}", static_bodyOf(buf));
}

void test_mcp_internal_error_500(void)
{
  char buf[RESP_BUF];
  static_callRefusal(REFUSAL_INTERNAL_ERROR, "{ not json", 0, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500 Internal Server Error\r\n"));
  TEST_ASSERT_EQUAL_STRING("{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"internal server error\"}}", static_bodyOf(buf));
}

void test_unauthorized_401(void)
{
  char buf[RESP_BUF];
  static_callHandler(handler_unauthorized, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 401 Unauthorized\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"unauthorized\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"Invalid API key\""));
}

void test_api_key_inactive_401(void)
{
  char buf[RESP_BUF];
  static_callHandler(handler_apiKeyInactive, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 401 Unauthorized\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"api_key_inactive\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"API key expired or revoked\""));
}

void test_uri_too_long_414(void)
{
  char buf[RESP_BUF];
  static_callHandler(handler_uriTooLong, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 414 URI Too Long"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"uri_too_long\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"request target too long\""));
}

void test_endpoint_not_found_404(void)
{
  char buf[RESP_BUF];
  static_callHandler(handler_endpointNotFound, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 404 Not Found\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"not_found\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"endpoint not found\""));
}

void test_internal_error_500(void)
{
  char buf[RESP_BUF];
  static_callHandler(handler_internalError, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500 Internal Server Error\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"internal_error\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"internal server error\""));
}

void test_response_has_json_content_type(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/health", "", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "Content-Type: application/json"));
}

void test_response_has_security_headers(void)
{
  char buf[RESP_BUF];
  static_callHandler(handler_endpointNotFound, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "X-Content-Type-Options: nosniff"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "X-Frame-Options: DENY"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "Permissions-Policy: camera=(), microphone=(), geolocation=()\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "Cache-Control: no-store"));
}

void test_HEALTH_no_db_answers_503(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/health", "", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 503 Service Unavailable\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nRetry-After: 5\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "{\"status\":\"unavailable\",\"version\":\"2.0.1\",\"db\":null}"));
}

void test_CVELOOKUP_null_param_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithPathSegment("/cve_lookup/", NULL, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"bad_request\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"missing CVE ID\""));
}

void test_CVELOOKUP_empty_param_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithPathSegment("/cve_lookup/", "", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"bad_request\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"missing CVE ID\""));
}

void test_CVELOOKUP_invalid_format_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithPathSegment("/cve_lookup/", "not-a-cve", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400 Bad Request\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "{\"error\":{\"code\":\"invalid_cve_id\",\"message\":\"CVE ID must be CVE-YYYY-NNNN[N...]\"}}"));
}

void test_CVELOOKUP_id_refusal_precedes_query_refusal(void)
{
  static const struct { const char* mp_id; const char* mp_body; } cases[] = {
    { "not-a-cve", "{\"error\":{\"code\":\"invalid_cve_id\",\"message\":\"CVE ID must be CVE-YYYY-NNNN[N...]\"}}" },
    { "",          "{\"error\":{\"code\":\"bad_request\",\"message\":\"missing CVE ID\"}}" },
    { NULL,        "{\"error\":{\"code\":\"bad_request\",\"message\":\"missing CVE ID\"}}" },
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    int fds[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
    handler_runRestEndpoint(fds[1], static_rowOf("/cve_lookup/"), REST_INPUT(cases[i].mp_id, "?include_ghsa=x", NULL, 0), NULL, &TEST_FULL_CHARGE);
    close(fds[1]);

    char buf[RESP_BUF];
    ssize_t read_len = read(fds[0], buf, sizeof(buf) - 1);
    buf[read_len > 0 ? read_len : 0] = '\0';
    close(fds[0]);

    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, cases[i].mp_body), buf);
    const char* status_line = strstr(buf, "HTTP/1.1 ");
    TEST_ASSERT_NOT_NULL(status_line);
    TEST_ASSERT_NULL(strstr(status_line + 1, "HTTP/1.1 "));
  }
}

static const EndpointParamSpec_t TEST_SPEC_DAY = {
  .mp_name              = "day",
  .m_type               = ENDPOINT_PARAM_TYPE_STRING,
  .m_maxLen             = 10,
  .m_validatorFunction  = validate_date,
  .mp_message           = "day must be YYYY-MM-DD",
};

static const EndpointParam_t TEST_DAY_PARAMS[] = {
  {
    .mp_spec              = &TEST_SPEC_DAY,
    .m_sources            = ENDPOINT_PARAM_SRC_REST_PATH_SEGMENT,
    .m_isRequired         = true,
    .m_offset             = 0,
    .m_size               = 11,
  },
};

static EndpointRunStatus_t static_runUpstreamError(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)conn;
  (void)params;
  (void)json_buf;
  (void)message_out;
  return ENDPOINT_RUN_UPSTREAM_ERROR;
}

static const Endpoint_t TEST_DAY_ROW = {
  .mp_httpPath               = "/test_day/",
  .m_hasPathSegment          = true,
  .ma_allowedMethods         = {"GET", NULL},
  .m_creditCost              = 1,
  .m_costRule                = ENDPOINT_COST_FLAT,
  .mp_params                 = TEST_DAY_PARAMS,
  .m_paramCount              = 1,
  .m_paramsSize              = 11,
  .m_runFunction             = static_runUpstreamError,
  .m_isDbRequired            = false,
  .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
};

#define TEST_UNREACHABLE_MESSAGE "the test host took no \"connection\""

static EndpointRunStatus_t static_runTargetUnreachable(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)conn;
  (void)params;
  (void)json_buf;
  *message_out = TEST_UNREACHABLE_MESSAGE;
  return ENDPOINT_RUN_TARGET_UNREACHABLE;
}

static const Endpoint_t TEST_UNREACHABLE_ROW = {
  .mp_httpPath               = "/test_unreachable/",
  .m_hasPathSegment          = true,
  .ma_allowedMethods         = {"GET", NULL},
  .m_creditCost              = 1,
  .m_costRule                = ENDPOINT_COST_FLAT,
  .mp_params                 = TEST_DAY_PARAMS,
  .m_paramCount              = 1,
  .m_paramsSize              = 11,
  .m_runFunction             = static_runTargetUnreachable,
  .m_isDbRequired            = false,
  .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
};

static void static_callRowWithDay(const Endpoint_t* row, const char* day, char* buf)
{
  int fds[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  handler_runRestEndpoint(fds[1], row, REST_INPUT(day, "", NULL, 0), NULL, &TEST_FULL_CHARGE);
  close(fds[1]);

  ssize_t read_len = read(fds[0], buf, RESP_BUF - 1);
  buf[read_len > 0 ? read_len : 0] = '\0';
  close(fds[0]);
}

static void static_callDayRow(const char* day, char* buf)
{
  static_callRowWithDay(&TEST_DAY_ROW, day, buf);
}

void test_text_path_segment_refusals_are_bad_request(void)
{
  static const struct { const char* mp_day; const char* mp_body; } cases[] = {
    { NULL,         "{\"error\":{\"code\":\"bad_request\",\"message\":\"day is required\"}}\n" },
    { "",           "{\"error\":{\"code\":\"bad_request\",\"message\":\"day is required\"}}\n" },
    { "2026-02-31", "{\"error\":{\"code\":\"bad_request\",\"message\":\"day must be YYYY-MM-DD\"}}\n" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char buf[RESP_BUF];
    static_callDayRow(cases[i].mp_day, buf);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 400 Bad Request\r\n"), buf);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(cases[i].mp_body, static_bodyOf(buf), buf);
  }
}

static const char IMAGE_POLYGLOT[] = "\xff\xd8\xff\xe0xx\xff\xd9" "PK\x03\x04\x2d\x00xx" "%PDF-1.7";
#define IMAGE_POLYGLOT_SHA256 "f14b811e80eb98f21325f3bb78aed636a7d37c7606f8bc62abcd869950e41482"

void test_IMAGEINSPECT_answers_the_format_the_hash_and_the_signatures(void)
{
  char buf[RESP_BUF];
  static_runImageInspect(IMAGE_POLYGLOT, sizeof(IMAGE_POLYGLOT) - 1, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 200 OK\r\n"), buf);
  TEST_ASSERT_EQUAL_STRING(
    "{\"format\":\"jpeg\",\"byte_count\":24,\"sha256\":\"" IMAGE_POLYGLOT_SHA256 "\","
    "\"embedded_file_signatures\":[{\"file_type\":\"zip\",\"match_count\":1,\"match_offsets\":[8]},"
    "{\"file_type\":\"pdf\",\"match_count\":1,\"match_offsets\":[16]}],"
    "\"embedded_file_signature_note\":\"A signature match is a sign, not proof: the compressed data of an image can hold the same bytes by chance.\","
    "\"metadata\":{\"camera_make\":null,\"camera_model\":null,\"software\":null,\"creator_tool\":null,\"digital_source_type\":null,"
    "\"date_time_original\":null,\"offset_time_original\":null,\"modify_date\":null,\"gps_date_time\":null,"
    "\"gps_position\":null,\"jpeg_quality_estimate\":null,\"thumbnail_byte_count\":0,\"c2pa_manifest\":false,\"c2pa_claim_generator\":null,"
    "\"generator_parameters\":false,\"identifiers_present\":{\"serial_number\":false,\"owner_name\":false,\"unique_id\":false,\"host_computer\":false,"
    "\"author\":false,\"copyright\":false,\"person_in_image\":false,\"original_file_name\":false},\"edit_history\":[],\"edit_history_has_more\":false},"
    "\"indicators\":[{\"code\":\"no_capture_metadata\",\"severity\":\"info\",\"note\":\"The file names no camera make, no model and no original time. Absent metadata is not a sign of forgery: many tools strip it.\"}],"
    "\"indicator_note\":\"An indicator is a sign, not proof. Metadata is easy to write, to edit and to strip, and absent metadata is not a sign of forgery.\"}\n",
    static_bodyOf(buf));
  TEST_ASSERT_EQUAL_INT(1, g_stub_IMAGEINSPECT_exif_call_count);
  TEST_ASSERT_EQUAL_size_t(24, g_stub_IMAGEINSPECT_exif_last_byte_count);
  TEST_ASSERT_EQUAL_MEMORY(IMAGE_POLYGLOT, g_stub_IMAGEINSPECT_exif_last_bytes, 24);
}

void test_IMAGEINSPECT_writes_the_metadata_and_the_indicators_of_the_answer(void)
{
  strcpy(g_stub_IMAGEINSPECT_exif_result.ma_cameraMake, "Canon");
  g_stub_IMAGEINSPECT_exif_result.m_hasGpsPosition = true;
  g_stub_IMAGEINSPECT_exif_result.m_gpsLatitude    = 41.0082;
  g_stub_IMAGEINSPECT_exif_result.m_gpsLongitude   = 28.9784;
  char buf[RESP_BUF];
  static_runImageInspect(IMAGE_POLYGLOT, sizeof(IMAGE_POLYGLOT) - 1, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 200 OK\r\n"), buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "\"camera_make\":\"Canon\","), buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "\"gps_position\":{\"latitude\":41.008200,\"longitude\":28.978400},"), buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "{\"code\":\"gps_position\","), buf);
  TEST_ASSERT_NULL_MESSAGE(strstr(buf, "no_capture_metadata"), buf);
}

void test_IMAGEINSPECT_answers_502_when_the_exif_service_gives_no_answer(void)
{
  static const ExifClientStatus_t statuses[] = { EXIFCLIENT_ERR_CONNECT, EXIFCLIENT_ERR_TRANSFER, EXIFCLIENT_ERR_DEADLINE, EXIFCLIENT_ERR_TOO_LARGE, EXIFCLIENT_ERR_MALFORMED };
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
  {
    g_stub_IMAGEINSPECT_exif_status = statuses[i];
    char buf[RESP_BUF];
    static_runImageInspect(IMAGE_POLYGLOT, sizeof(IMAGE_POLYGLOT) - 1, buf, sizeof(buf));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 502 Bad Gateway\r\n"), buf);
    TEST_ASSERT_EQUAL_STRING("{\"error\":{\"code\":\"upstream_unavailable\",\"message\":\"upstream service unavailable\"}}\n", static_bodyOf(buf));
  }
}

void test_IMAGEINSPECT_answers_400_for_a_refused_image_and_500_for_no_memory(void)
{
  g_stub_IMAGEINSPECT_exif_status = EXIFCLIENT_ERR_REFUSED;
  char buf[RESP_BUF];
  static_runImageInspect(IMAGE_POLYGLOT, sizeof(IMAGE_POLYGLOT) - 1, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 400 Bad Request\r\n"), buf);
  TEST_ASSERT_EQUAL_STRING("{\"error\":{\"code\":\"bad_request\",\"message\":\"" EXIFCLIENT_REFUSAL_MESSAGE "\"}}\n", static_bodyOf(buf));

  g_stub_IMAGEINSPECT_exif_status = EXIFCLIENT_ERR_NO_MEMORY;
  static_runImageInspect(IMAGE_POLYGLOT, sizeof(IMAGE_POLYGLOT) - 1, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 500 Internal Server Error\r\n"), buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "\"code\":\"internal_error\""), buf);
}

void test_IMAGEINSPECT_refuses_a_body_that_is_no_known_image(void)
{
  static const struct { const char* mp_bytes; size_t m_byteCount; const char* mp_message; } cases[] = {
    { "GIF89a\x01\x00", 8, IMAGESCAN_UNKNOWN_FORMAT_REFUSAL_MESSAGE },
    { NULL,              0, "image is required" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char buf[RESP_BUF];
    static_runImageInspect(cases[i].mp_bytes, cases[i].m_byteCount, buf, sizeof(buf));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 400 Bad Request\r\n"), buf);
    char expected[RESP_BUF];
    snprintf(expected, sizeof(expected), "{\"error\":{\"code\":\"bad_request\",\"message\":\"%s\"}}\n", cases[i].mp_message);
    TEST_ASSERT_EQUAL_STRING(expected, static_bodyOf(buf));
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_IMAGEINSPECT_exif_call_count);
}

void test_IMAGEINSPECT_hash_failure_answers_500(void)
{
  g_isDigestFailing = true;
  char buf[RESP_BUF];
  static_runImageInspect(IMAGE_POLYGLOT, sizeof(IMAGE_POLYGLOT) - 1, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 500 Internal Server Error\r\n"), buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "\"code\":\"internal_error\""), buf);
}

void test_upstream_error_run_answers_502(void)
{
  char buf[RESP_BUF];
  static_callDayRow("2026-02-28", buf);
  TEST_ASSERT_EQUAL_STRING_LEN("HTTP/1.1 502 Bad Gateway\r\n", buf, strlen("HTTP/1.1 502 Bad Gateway\r\n"));
  TEST_ASSERT_EQUAL_STRING("{\"error\":{\"code\":\"upstream_unavailable\",\"message\":\"upstream service unavailable\"}}\n", static_bodyOf(buf));
  TEST_ASSERT_NULL(strstr(buf + 1, "HTTP/1.1 "));
}

void test_target_unreachable_run_answers_504_with_its_reason(void)
{
  char buf[RESP_BUF];
  static_callRowWithDay(&TEST_UNREACHABLE_ROW, "2026-02-28", buf);
  TEST_ASSERT_EQUAL_STRING_LEN("HTTP/1.1 504 Gateway Timeout\r\n", buf, strlen("HTTP/1.1 504 Gateway Timeout\r\n"));
  TEST_ASSERT_EQUAL_STRING("{\"error\":{\"code\":\"target_unreachable\",\"message\":\"the test host took no \\\"connection\\\"\"}}\n", static_bodyOf(buf));
  TEST_ASSERT_NULL(strstr(buf + 1, "HTTP/1.1 "));
}

void test_CVELOOKUP_no_db_500(void)
{
  g_conn = NULL;
  
  char buf[RESP_BUF];
  static_runEndpointWithPathSegment("/cve_lookup/", "CVE-2021-44228", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_query_refusal_answers_400_without_db(void)
{
  const struct {
    const char* mp_httpPath;
    const char* mp_pathSegment;
    const char* mp_query;
  } cases[] = {
    { "/cve_lookup/",      "CVE-2021-44228", "?include_ghsa=x" },
    { "/cve_search",       NULL,             "?severity=x" },
    { "/cve_triage",       NULL,             "?limit=0" },
    { "/cve_leading",      NULL,             "?limit=0" },
    { "/product_exposure", NULL,             "?vendor=x" },
  };

  g_conn = NULL;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    int fds[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
    handler_runRestEndpoint(fds[1], static_rowOf(cases[i].mp_httpPath), REST_INPUT(cases[i].mp_pathSegment, cases[i].mp_query, NULL, 0), g_conn, &TEST_FULL_CHARGE);
    close(fds[1]);
    char buf[RESP_BUF];
    ssize_t n = read(fds[0], buf, sizeof(buf) - 1);
    buf[n > 0 ? n : 0] = '\0';
    close(fds[0]);

    int response_count = 0;
    for (const char* cursor = buf; (cursor = strstr(cursor, "HTTP/1.1 ")) != NULL; cursor += 9)
      response_count++;
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, response_count, cases[i].mp_query);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 400"), cases[i].mp_query);
  }
}

#define FAKE_CONN ((PGconn *)1)

void test_CVESEARCH_no_db_returns_500(void)
{
  g_conn = NULL;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_search", "", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_CVESEARCH_severity_invalid_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_search", "?severity=VERY_HIGH", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVESEARCH_limit_over_100_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_search", "?limit=101", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVESEARCH_limit_non_integer_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_search", "?limit=abc", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVESEARCH_min_cvss_out_of_range_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_search", "?min_cvss=11.0", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVESEARCH_min_cvss_nan_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_search", "?min_cvss=nan", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVESEARCH_min_epss_nan_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_search", "?min_epss=nan", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVESEARCH_min_cvss_infinity_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_search", "?min_cvss=inf", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVESEARCH_in_kev_invalid_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_search", "?in_kev=yes", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVESEARCH_published_after_invalid_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_search", "?published_after=31-13-9999", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVESEARCH_published_after_impossible_calendar_date_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_search", "?published_after=2026-02-31", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "published_after must be a valid calendar date"));
}

void test_CVESEARCH_vendor_wildcard_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_search", "?vendor=%25", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "vendor must not contain wildcard %"));
}

void test_CVESEARCH_known_ransomware_invalid_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_search", "?known_ransomware=false", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVESEARCH_sort_invalid_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_search", "?sort=bogus", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVESEARCH_offset_negative_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_search", "?offset=-1", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

static void static_buildLongQuery(char* out_buf, size_t out_buf_size, const char* prefix, size_t value_len, char fill)
{
  size_t prefix_len = strlen(prefix);
  TEST_ASSERT_TRUE(prefix_len + value_len + 1 <= out_buf_size);
  memcpy(out_buf, prefix, prefix_len);
  memset(out_buf + prefix_len, fill, value_len);
  out_buf[prefix_len + value_len] = '\0';
}

void test_CVESEARCH_severity_too_long_says_too_long(void)
{
  g_conn = FAKE_CONN;
  char query_str[64];
  char buf[RESP_BUF];
  static_buildLongQuery(query_str, sizeof(query_str), "?severity=", 17, 'A');
  static_runEndpointWithQuery("/cve_search", query_str, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "severity is too long"));
}

void test_CVESEARCH_published_after_too_long_says_too_long(void)
{
  g_conn = FAKE_CONN;
  char query_str[96];
  char buf[RESP_BUF];
  static_buildLongQuery(query_str, sizeof(query_str), "?published_after=", 32, '2');
  static_runEndpointWithQuery("/cve_search", query_str, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "published_after is too long"));
}

void test_CVESEARCH_sort_too_long_says_too_long(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_search", "?sort=published_time_and_then_some", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "sort is too long"));
}

void test_CVESEARCH_limit_too_long_says_too_long(void)
{
  g_conn = FAKE_CONN;
  char query_str[64];
  char buf[RESP_BUF];
  static_buildLongQuery(query_str, sizeof(query_str), "?limit=", 35, '0');
  static_runEndpointWithQuery("/cve_search", query_str, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "limit is too long"));
}

void test_KEVLOOKUP_null_param_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithPathSegment("/kev_lookup/", NULL, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"missing CVE ID\""));
}

void test_KEVLOOKUP_empty_param_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithPathSegment("/kev_lookup/", "", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"missing CVE ID\""));
}

void test_KEVLOOKUP_invalid_format_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithPathSegment("/kev_lookup/", "not-a-cve", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"invalid_cve_id\""));
}

void test_KEVLOOKUP_no_db_500(void)
{
  g_conn = NULL;
  char buf[RESP_BUF];
  static_runEndpointWithPathSegment("/kev_lookup/", "CVE-2021-44228", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_CWELOOKUP_null_param_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithPathSegment("/cwe_lookup/", NULL, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"missing CWE ID\""));
}

void test_CWELOOKUP_empty_param_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithPathSegment("/cwe_lookup/", "", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"missing CWE ID\""));
}

void test_CWELOOKUP_invalid_format_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithPathSegment("/cwe_lookup/", "not-a-cwe", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "{\"error\":{\"code\":\"invalid_cwe_id\",\"message\":\"CWE ID must be CWE-N\"}}"));
}

void test_CWELOOKUP_no_db_500(void)
{
  g_conn = NULL;
  char buf[RESP_BUF];
  static_runEndpointWithPathSegment("/cwe_lookup/", "CWE-89", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_CVELEADING_no_db_500(void)
{
  g_conn = NULL;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_leading", "", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_CVELEADING_limit_over_50_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_leading", "limit=51", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVELEADING_limit_zero_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_leading", "limit=0", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVELEADING_invalid_known_ransomware_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_leading", "known_ransomware=false", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVELEADING_invalid_in_kev_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_leading", "in_kev=maybe", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVELEADING_min_epss_out_of_range_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_leading", "min_epss=1.5", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVELEADING_min_epss_nan_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_leading", "min_epss=nan", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVELEADING_vendor_invalid_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_leading", "vendor=%25", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "vendor must not contain wildcard %"));
}

void test_CVELEADING_limit_non_integer_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_leading", "limit=abc", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_http_method_not_allowed_405_single_verb(void)
{
  char buf[RESP_BUF];
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) 
  { 
    perror("socketpair"); 
    return; 
  }

  const char* methods[] = { "GET", NULL };
  handler_httpMethodNotAllowed(fds[1], methods);

  close(fds[1]);
  ssize_t n = read(fds[0], buf, sizeof(buf) - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);

  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 405"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"method_not_allowed\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"method not allowed for this endpoint\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 405 Method Not Allowed\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "Allow: GET\r\n"));
}

void test_http_method_not_allowed_405_multi_verb(void)
{
  char buf[RESP_BUF];
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) 
  { 
    perror("socketpair"); 
    return; 
  }

  const char* methods[] = { "GET", "POST", NULL };
  handler_httpMethodNotAllowed(fds[1], methods);
  close(fds[1]);

  ssize_t n = read(fds[0], buf, sizeof(buf) - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);

  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 405"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "Allow: GET, POST\r\n"));
}

void test_CVELOOKUPBULK_no_body_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithBody("/cve_lookup_bulk", NULL, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"bad_request\""));
}

void test_CVELOOKUPBULK_empty_body_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithBody("/cve_lookup_bulk", "", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"cve_ids is required\""));
}

void test_CVELOOKUPBULK_bad_json_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithBody("/cve_lookup_bulk", "not json at all", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"body must be a JSON object\""));
}

void test_CVELOOKUPBULK_empty_array_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithBody("/cve_lookup_bulk", "{\"cve_ids\":[]}", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "cve_ids array must not be empty"));
}

void test_CVELOOKUPBULK_too_many_ids_400(void)
{
  char body[4096] = "{\"cve_ids\":[";
  for (int i = 0; i < 51; i++) 
  {
    if (i > 0) strcat(body, ",");
    char id[32];
    snprintf(id, sizeof(id), "\"CVE-2021-%04d\"", i + 1);
    strcat(body, id);
  }
  strcat(body, "]}");
  char buf[RESP_BUF];
  static_runEndpointWithBody("/cve_lookup_bulk", body, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "cve_ids array exceeds maximum of 50"));
}

static void static_writeHashesBody(char* body, size_t size, int count)
{
  size_t used = (size_t)snprintf(body, size, "{\"hashes\":[");
  for (int i = 0; i < count; i++)
    used += (size_t)snprintf(body + used, size - used, "%s\"%064x\"", i > 0 ? "," : "", i + 1);
  snprintf(body + used, size - used, "]}");
}

void test_DRIVERLOOKUPBULK_takes_20_hashes_and_refuses_21(void)
{
  g_conn = NULL;
  char body[4096];
  char buf[RESP_BUF];
  static_writeHashesBody(body, sizeof(body), 21);
  static_runEndpointWithBody("/driver_lookup_bulk", body, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "hashes array exceeds maximum of 20"));

  static_writeHashesBody(body, sizeof(body), 20);
  static_runEndpointWithBody("/driver_lookup_bulk", body, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_CVELOOKUPBULK_no_db_500(void)
{
  g_conn = NULL;
  char buf[RESP_BUF];
  static_runEndpointWithBody("/cve_lookup_bulk",
    "{\"cve_ids\":[\"CVE-2021-44228\",\"CVE-2022-12345\"]}",
    buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_CVELOOKUPBULK_wrong_key_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithBody("/cve_lookup_bulk", "{\"data\":[\"CVE-2021-44228\"]}", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVELOOKUPBULK_old_ids_key_400_names_cve_ids(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithBody("/cve_lookup_bulk", "{\"ids\":[\"CVE-2021-44228\"]}", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "cve_ids"));
}

void test_CVELOOKUPBULK_does_not_read_the_query(void)
{
  g_conn = NULL;
  char buf[RESP_BUF];
  static_runEndpoint("/cve_lookup_bulk", NULL, "zz=1", "{\"cve_ids\":[\"CVE-2021-44228\"]}", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
  TEST_ASSERT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVETRIAGE_no_db_returns_500(void)
{
  g_conn = NULL;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_triage", "", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_CVETRIAGE_min_risk_score_below_zero_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_triage", "?min_risk_score=-0.1", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "min_risk_score must be a number between 0.0 and 100.0"));
}

void test_CVETRIAGE_min_risk_score_over_100_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_triage", "?min_risk_score=100.1", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "min_risk_score must be a number between 0.0 and 100.0"));
}

void test_CVETRIAGE_min_risk_score_non_numeric_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_triage", "?min_risk_score=high", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "min_risk_score must be a number between 0.0 and 100.0"));
}

void test_CVETRIAGE_min_risk_score_nan_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_triage", "?min_risk_score=nan", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "min_risk_score must be a number between 0.0 and 100.0"));
}

void test_CVETRIAGE_limit_over_100_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_triage", "?limit=101", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVETRIAGE_offset_negative_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_triage", "?offset=-1", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVETRIAGE_vendor_wildcard_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_triage", "?vendor=%25", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "vendor must not contain wildcard %"));
}

void test_CVETRIAGE_limit_zero_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_triage", "?limit=0", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVETRIAGE_limit_non_numeric_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_triage", "?limit=abc", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVETRIAGE_offset_non_numeric_returns_400(void)
{
  g_conn = FAKE_CONN;
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_triage", "?offset=xyz", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVETRIAGEBULK_no_body_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithBody("/cve_triage_bulk", NULL, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"bad_request\""));
}

void test_CVETRIAGEBULK_empty_body_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithBody("/cve_triage_bulk", "", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"cve_ids is required\""));
}

void test_CVETRIAGEBULK_bad_json_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithBody("/cve_triage_bulk", "not json at all", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"body must be a JSON object\""));
}

void test_CVETRIAGEBULK_empty_array_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithBody("/cve_triage_bulk", "{\"cve_ids\":[]}", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "cve_ids array must not be empty"));
}

void test_CVETRIAGEBULK_too_many_ids_400(void)
{
  char body[4096] = "{\"cve_ids\":[";
  for (int i = 0; i < 51; i++)
  {
    if (i > 0) strcat(body, ",");
    char id[32];
    snprintf(id, sizeof(id), "\"CVE-2021-%04d\"", i + 1);
    strcat(body, id);
  }
  strcat(body, "]}");
  char buf[RESP_BUF];
  static_runEndpointWithBody("/cve_triage_bulk", body, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "cve_ids array exceeds maximum of 50"));
}

void test_BULK_no_db_500_when_every_element_is_skipped(void)
{
  g_conn = NULL;
  char buf[RESP_BUF];
  static_runEndpointWithBody("/cve_lookup_bulk", "{\"cve_ids\":[5,\"foo\"]}", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
  static_runEndpointWithBody("/cve_triage_bulk", "{\"cve_ids\":[5,\"foo\"]}", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_CVETRIAGEBULK_no_db_500(void)
{
  g_conn = NULL;
  char buf[RESP_BUF];
  static_runEndpointWithBody("/cve_triage_bulk",
    "{\"cve_ids\":[\"CVE-2021-44228\",\"CVE-2022-12345\"]}",
    buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_CVETRIAGEBULK_wrong_key_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithBody("/cve_triage_bulk", "{\"data\":[\"CVE-2021-44228\"]}", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
}

void test_CVETRIAGEBULK_old_ids_key_400_names_cve_ids(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithBody("/cve_triage_bulk", "{\"ids\":[\"CVE-2021-44228\"]}", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "cve_ids"));
}

void test_CVERISKSCORE_null_param_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithPathSegment("/cve_risk_score/", NULL, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"bad_request\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"missing CVE ID\""));
}

void test_CVERISKSCORE_empty_param_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithPathSegment("/cve_risk_score/", "", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"bad_request\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"missing CVE ID\""));
}

void test_CVERISKSCORE_invalid_format_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithPathSegment("/cve_risk_score/", "not-a-cve", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"invalid_cve_id\""));
}

void test_CVERISKSCORE_no_db_500(void)
{
  g_conn = NULL;
  char buf[RESP_BUF];
  static_runEndpointWithPathSegment("/cve_risk_score/", "CVE-2021-44228", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_MCP_request_without_id_returns_202_no_body(void)
{
  char buf[RESP_BUF];
  static_callMcp(
    "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}",
    buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 202"));
  TEST_ASSERT_NULL(strstr(buf, "\"jsonrpc\""));
}

void test_MCP_request_returns_200_result(void)
{
  char buf[RESP_BUF];
  static_callMcp(
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\","
    "\"params\":{\"protocolVersion\":\"2025-11-25\"}}",
    buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 200"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "Content-Type: application/json"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"protocolVersion\""));
}

void test_MCP_malformed_body_is_200_jsonrpc_error(void)
{
  char buf[RESP_BUF];
  static_callMcp("{ this is not json", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 200"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"error\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "-32700"));
}

void test_MCP_null_body_is_parse_error(void)
{
  char buf[RESP_BUF];
  static_callMcp(NULL, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 200"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "-32700"));
}

static void static_MCPFillModernHeaders(const char* method, McpRoutingHeaders_t* h)
{
  memset(h, 0, sizeof(*h));
  h->m_hasProtocolVersion = true;
  strncpy(h->ma_protocolVersion, "2026-07-28", sizeof(h->ma_protocolVersion) - 1);
  if (method)
  {
    h->m_hasMethod = true;
    strncpy(h->ma_method, method, sizeof(h->ma_method) - 1);
  }
}

void test_MCP_modern_ladder_failure_is_400_bad_request(void)
{
  McpRoutingHeaders_t h;
  static_MCPFillModernHeaders("tools/list", &h);
  char buf[RESP_BUF];
  static_callMcpWithHeaders(
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}",
    &h, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400 Bad Request"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "-32602"));
}

void test_MCP_modern_initialize_is_404_not_found(void)
{
  McpRoutingHeaders_t h;
  static_MCPFillModernHeaders("initialize", &h);
  char buf[RESP_BUF];
  static_callMcpWithHeaders(
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"initialize\","
    "\"params\":{\"_meta\":{"
    "\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\","
    "\"io.modelcontextprotocol/clientInfo\":{\"name\":\"p\",\"version\":\"1\"},"
    "\"io.modelcontextprotocol/clientCapabilities\":{}}}}",
    &h, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 404 Not Found"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "-32601"));
}

static void static_assertOverlongIdRefused(const char* http_path)
{
  char buf[RESP_BUF];
  static_runEndpointWithPathSegment(http_path,
    "CVE-2021-442280000000000000000000000000000000000000000000000000000000",
    buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"invalid_cve_id\""));
  TEST_ASSERT_NULL(strstr(buf, "HTTP/1.1 200"));
}

void test_CVELOOKUP_overlong_id_returns_400(void)
{
  static_assertOverlongIdRefused("/cve_lookup/");
}

void test_KEVLOOKUP_overlong_id_returns_400(void)
{
  static_assertOverlongIdRefused("/kev_lookup/");
}

void test_CVERISKSCORE_overlong_id_returns_400(void)
{
  static_assertOverlongIdRefused("/cve_risk_score/");
}

void test_CVESEARCH_unknown_param_name_returns_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_search", "zz=1", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "unknown query parameter; this endpoint takes severity"));
}

void test_CVESEARCH_malformed_and_repeated_param_names_return_400(void)
{
  char buf[RESP_BUF];
  static_runEndpointWithQuery("/cve_search", "vendor", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "every query parameter must be name=value"));
  static_runEndpointWithQuery("/cve_search", "limit=5&limit=5", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "limit appears more than once"));
}

void test_query_param_name_refusal_answers_another_status_with_a_fixed_400(void)
{
  int fds[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  const EndpointGateResult_t refusal = { .m_status = ENDPOINT_GATE_REJECT_BODY, .m_refusedParamIndex = -1 };
  handler_httpQueryParamNameRefused(fds[1], static_rowOf("/cve_search"), refusal);
  close(fds[1]);
  char buf[RESP_BUF];
  ssize_t n = read(fds[0], buf, sizeof(buf) - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);

  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"bad_request\""));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"message\":\"unknown query parameter\""));
}

static void static_longNameListRow(const char* http_path, unsigned int param_source, Endpoint_t* row_out, EndpointParam_t params_out[ENDPOINT_MAX_PARAMS])
{
  const Endpoint_t* base = static_rowOf(http_path);
  int longest_index = -1;
  for (int i = 0; i < base->m_paramCount; i++)
  {
    if (!(base->mp_params[i].m_sources & param_source))
      continue;
    if (longest_index < 0 || strlen(base->mp_params[i].mp_spec->mp_name) > strlen(base->mp_params[longest_index].mp_spec->mp_name))
      longest_index = i;
  }
  TEST_ASSERT_TRUE(longest_index >= 0);
  TEST_ASSERT_TRUE(ENDPOINT_MAX_PARAMS * (strlen(base->mp_params[longest_index].mp_spec->mp_name) + 2) > ENDPOINT_MESSAGE_BUF_SIZE);

  for (int i = 0; i < ENDPOINT_MAX_PARAMS; i++)
    params_out[i] = base->mp_params[longest_index];
  *row_out              = *base;
  row_out->mp_params    = params_out;
  row_out->m_paramCount = ENDPOINT_MAX_PARAMS;
}

static void static_runRow(const Endpoint_t* row, const char* query_str, const char* body, char* buf, size_t len)
{
  int fds[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  handler_runRestEndpoint(fds[1], row, REST_INPUT(NULL, query_str, body, body ? strlen(body) : 0), g_conn, &TEST_FULL_CHARGE);
  close(fds[1]);
  ssize_t n = read(fds[0], buf, len - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);
}

void test_unknown_name_with_a_list_too_long_answers_a_fixed_400(void)
{
  Endpoint_t      row;
  EndpointParam_t params[ENDPOINT_MAX_PARAMS];
  char            buf[RESP_BUF];

  static_longNameListRow("/cve_search", ENDPOINT_PARAM_SRC_REST_QUERY, &row, params);
  static_runRow(&row, "unknown_name=1", NULL, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_EQUAL_STRING("{\"error\":{\"code\":\"bad_request\",\"message\":\"unknown query parameter\"}}\n", static_bodyOf(buf));

  static_longNameListRow("/watchlist_edit", ENDPOINT_PARAM_SRC_REST_BODY, &row, params);
  static_runRow(&row, "", "{\"unknown_name\":1}", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400"));
  TEST_ASSERT_EQUAL_STRING("{\"error\":{\"code\":\"bad_request\",\"message\":\"unknown body parameter\"}}\n", static_bodyOf(buf));
}

void test_framing_refusals_413_431_501(void)
{
  static const struct {
    void      (*m_handlerFunction)(int);
    const char* mp_statusLine;
    const char* mp_body;
  } cases[] = {
    { handler_contentTooLarge,                "HTTP/1.1 413 Content Too Large\r\n",               "{\"error\":{\"code\":\"content_too_large\",\"message\":\"request body too large\"}}\n" },
    { handler_headerFieldsTooLarge,           "HTTP/1.1 431 Request Header Fields Too Large\r\n", "{\"error\":{\"code\":\"request_header_fields_too_large\",\"message\":\"request header fields too large\"}}\n" },
    { handler_transferEncodingNotImplemented, "HTTP/1.1 501 Not Implemented\r\n",                 "{\"error\":{\"code\":\"not_implemented\",\"message\":\"Transfer-Encoding is not supported; send Content-Length\"}}\n" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char buf[RESP_BUF];
    static_callHandler(cases[i].m_handlerFunction, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, strncmp(buf, cases[i].mp_statusLine, strlen(cases[i].mp_statusLine)), buf);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_body, static_bodyOf(buf));
  }
}

#define USAGELOG_TEST_INSTANCE_PORT 8002

static char g_usageLines[USAGELOG_DRAIN_BUF_SIZE];

static int static_runEndpointForUsageLine(const char* http_path, const char* path_segment, char* buf, size_t len)
{
  usagelog_start(USAGELOG_TEST_INSTANCE_PORT);
  usagelog_drainLines(g_usageLines, sizeof(g_usageLines));
  usagelog_beginRequest();
  static_runEndpoint(http_path, path_segment, "", NULL, buf, len);
  usagelog_writeRequest();
  usagelog_drainLines(g_usageLines, sizeof(g_usageLines));
  int line_count = 0;
  for (const char* c = g_usageLines; *c != '\0'; c++)
    line_count += *c == '\n';
  return line_count;
}

void test_rest_gate_refusal_is_the_usage_run_status(void)
{
  char buf[RESP_BUF];
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_runEndpointForUsageLine("/cve_lookup/", "not-a-cve", buf, sizeof(buf)), g_usageLines);
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 400 "));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"status\":400,\"run_status\":\"gate_refused\",\"duration_ms\":"), g_usageLines);
}

void test_rest_run_status_reaches_the_usage_line(void)
{
  char buf[RESP_BUF];
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_runEndpointForUsageLine("/health", NULL, buf, sizeof(buf)), g_usageLines);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"status\":503,\"run_status\":\"degraded\",\"duration_ms\":"), g_usageLines);

  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_runEndpointForUsageLine("/cve_lookup/", "CVE-2021-44228", buf, sizeof(buf)), g_usageLines);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"status\":500,\"run_status\":\"no_connection\",\"duration_ms\":"), g_usageLines);
}

#define TEST_PAID_NETWORK   "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
#define TEST_PAID_SIGNATURE "3PendingSignatureOfTheLedgerRow"

static EndpointRunStatus_t static_runPaidOk(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)conn;
  (void)params;
  (void)message_out;
  jsonbuf_appendJsonText(json_buf, "{\"paid\":true}");
  return ENDPOINT_RUN_OK;
}

static const Endpoint_t TEST_PAID_ROW = {
  .mp_httpPath               = "/test_paid/",
  .m_hasPathSegment          = true,
  .ma_allowedMethods         = {"GET", NULL},
  .m_creditCost              = 1,
  .m_costRule                = ENDPOINT_COST_FLAT,
  .mp_params                 = TEST_DAY_PARAMS,
  .m_paramCount              = 1,
  .m_paramsSize              = 11,
  .m_runFunction             = static_runPaidOk,
  .m_isDbRequired            = false,
  .m_isPayable               = true,
  .m_jsonCeiling             = JSONBUF_DEFAULT_CEILING,
};

static void static_openConfirmedPayment(X402RequestPayment_t* payment)
{
  memset(payment, 0, sizeof(*payment));
  payment->m_kind   = X402_REQUEST_PAYMENT_CONFIRMED;
  payment->m_isOpen = true;
  snprintf(payment->m_requirements.ma_network, sizeof(payment->m_requirements.ma_network), "%s", TEST_PAID_NETWORK);
  snprintf(payment->ma_signature, sizeof(payment->ma_signature), "%s", TEST_PAID_SIGNATURE);
  g_stub_X402_LEDGER_mark_settled_status = X402_LEDGER_MARKED;
  g_stub_X402_LEDGER_mark_settled_count  = 0;
  g_stub_X402_LEDGER_release_count       = 0;
}

static void static_callPaidRow(const Endpoint_t* row, const char* day, X402RequestPayment_t* payment, char* buf)
{
  const RequestCharge_t charge = { .m_chargedCreditCount = 1, .mp_creditBudget = NULL, .mp_x402Payment = payment };
  int fds[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  handler_runRestEndpoint(fds[1], row, REST_INPUT(day, "", NULL, 0), NULL, &charge);
  close(fds[1]);

  ssize_t read_len = read(fds[0], buf, RESP_BUF - 1);
  buf[read_len > 0 ? read_len : 0] = '\0';
  close(fds[0]);
}

void test_paid_run_ok_closes_once_and_sends_the_receipt(void)
{
  X402RequestPayment_t payment;
  static_openConfirmedPayment(&payment);
  char buf[RESP_BUF];
  static_callPaidRow(&TEST_PAID_ROW, "2026-02-28", &payment, buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 200 OK\r\n"), buf);
  TEST_ASSERT_EQUAL_STRING("{\"paid\":true}", static_bodyOf(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "\r\nPAYMENT-RESPONSE: eyJzdWNjZXNzIjp0cnVlLCJ0cmFuc2FjdGlvbiI6IjNQZW5kaW5nU2lnbmF0dXJlT2ZUaGVMZWRnZXJSb3ciLCJuZXR3b3JrIjoic29sYW5hOkV0V1RSQUJaYVlxNmlNZmVZS291UnUxNjZWVTJ4cWExIn0=\r\n"), buf);
  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_LEDGER_mark_settled_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_release_count);
  TEST_ASSERT_FALSE(payment.m_isOpen);
}

void test_paid_run_that_fails_releases_and_does_not_close(void)
{
  X402RequestPayment_t payment;
  static_openConfirmedPayment(&payment);
  char buf[RESP_BUF];
  static_callPaidRow(&TEST_DAY_ROW, "2026-02-28", &payment, buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 502 Bad Gateway\r\n"), buf);
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"upstream_unavailable\""));
  TEST_ASSERT_NULL(strstr(buf, "PAYMENT-RESPONSE"));
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_mark_settled_count);
  TEST_ASSERT_FALSE(payment.m_isOpen);
}

void test_paid_gate_refusal_releases_the_payment(void)
{
  X402RequestPayment_t payment;
  static_openConfirmedPayment(&payment);
  char buf[RESP_BUF];
  static_callPaidRow(&TEST_PAID_ROW, "2026-02-31", &payment, buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 400 Bad Request\r\n"), buf);
  TEST_ASSERT_NULL(strstr(buf, "PAYMENT-RESPONSE"));
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_mark_settled_count);
  TEST_ASSERT_FALSE(payment.m_isOpen);
}


#define TEST_MCP_CALL_BODY "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"cve_lookup\",\"arguments\":{\"cve_id\":\"CVE-2021-44228\"}}}"

#define TEST_CVSS_CALL_BODY "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"cvss_calculator\",\"arguments\":{\"vector\":\"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\"}}}"

static void static_startX402(void)
{
  ConfigX402_t config;
  memset(&config, 0, sizeof(config));
  snprintf(config.ma_network,           sizeof(config.ma_network),           "%s", TEST_PAID_NETWORK);
  snprintf(config.ma_usdcMint,          sizeof(config.ma_usdcMint),          "%s", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
  snprintf(config.ma_payTo,             sizeof(config.ma_payTo),             "%s", "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin");
  snprintf(config.ma_payToTokenAccount, sizeof(config.ma_payToTokenAccount), "%s", "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");
  snprintf(config.ma_feePayer,          sizeof(config.ma_feePayer),          "%s", "2wmVCSfPxGPjrnMMn7rchp4uaeoTqN39mXFC2zhPdri9");
  snprintf(config.ma_solanaRpcUrl,      sizeof(config.ma_solanaRpcUrl),      "%s", "https://rpc.example.com/v1/sample");
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_START_ON, x402_request_start(&config));
}

typedef enum {
  MCP_PAYMENT_ANSWER_REQUIRED,
  MCP_PAYMENT_ANSWER_REFUSED,
  MCP_PAYMENT_ANSWER_ALREADY_USED,
  MCP_PAYMENT_ANSWER_PENDING,
  MCP_PAYMENT_ANSWER_INVALID,
  MCP_PAYMENT_ANSWER_NOT_OFFERED,
  MCP_PAYMENT_ANSWER_BUSY,
  MCP_PAYMENT_ANSWER_LIMITED,
  MCP_PAYMENT_ANSWER_UNAVAILABLE
} McpPaymentAnswer_t;

static void static_callMcpPaymentAnswer(McpPaymentAnswer_t answer, unsigned int retry_after_sec, bool is_modern, char* buf)
{
  const Endpoint_t* row = endpoint_findByMcpName("cve_lookup");
  TEST_ASSERT_NOT_NULL(row);
  int fds[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  switch (answer)
  {
    case MCP_PAYMENT_ANSWER_REQUIRED:     handler_mcpPaymentRequired(fds[1], TEST_MCP_CALL_BODY, row, 1, retry_after_sec, is_modern); break;
    case MCP_PAYMENT_ANSWER_REFUSED:      handler_mcpPaymentRefused(fds[1], TEST_MCP_CALL_BODY, row, 1, is_modern);                   break;
    case MCP_PAYMENT_ANSWER_ALREADY_USED: handler_mcpPaymentAlreadyUsed(fds[1], TEST_MCP_CALL_BODY, row, 1, is_modern);               break;
    case MCP_PAYMENT_ANSWER_PENDING:      handler_mcpPaymentPending(fds[1], TEST_MCP_CALL_BODY, retry_after_sec, is_modern);          break;
    case MCP_PAYMENT_ANSWER_INVALID:      handler_mcpPaymentInvalid(fds[1], TEST_MCP_CALL_BODY, is_modern);                           break;
    case MCP_PAYMENT_ANSWER_NOT_OFFERED:  handler_mcpPaymentNotOffered(fds[1], TEST_MCP_CALL_BODY, is_modern);                        break;
    case MCP_PAYMENT_ANSWER_BUSY:         handler_mcpPaymentBusy(fds[1], TEST_MCP_CALL_BODY, retry_after_sec);                        break;
    case MCP_PAYMENT_ANSWER_LIMITED:      handler_mcpPaymentLimited(fds[1], TEST_MCP_CALL_BODY, retry_after_sec);                     break;
    case MCP_PAYMENT_ANSWER_UNAVAILABLE:  handler_mcpPaymentUnavailable(fds[1], TEST_MCP_CALL_BODY, retry_after_sec);                 break;
  }
  close(fds[1]);
  ssize_t read_len = read(fds[0], buf, RESP_BUF - 1);
  buf[read_len > 0 ? read_len : 0] = '\0';
  close(fds[0]);
}

static void static_assertMcpPaymentOffer(const char* body, const char* error_text)
{
  JsonReadSpan_t root, id, result, is_error, structured, error, resource, url, accepts, first, amount;
  size_t element_offset = 0;
  TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_OK, jsonread_root(body, strlen(body), &root), body);
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root, "id", &id));
  TEST_ASSERT_TRUE(jsonread_isSpanEqual(id, "4"));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root, "result", &result));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(result, "isError", &is_error));
  TEST_ASSERT_TRUE(jsonread_isSpanEqual(is_error, "true"));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(result, "structuredContent", &structured));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(structured, "error", &error));
  char error_buf[256];
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_spanToStrStatus(error, error_buf, sizeof(error_buf)));
  TEST_ASSERT_EQUAL_STRING(error_text, error_buf);
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(structured, "resource", &resource));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(resource, "url", &url));
  TEST_ASSERT_TRUE(jsonread_isSpanEqual(url, "\"mcp://tool/cve_lookup\""));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(structured, "accepts", &accepts));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_arrayNextElement(accepts, &element_offset, &first));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(first, "amount", &amount));
  TEST_ASSERT_TRUE(jsonread_isSpanEqual(amount, "\"10000\""));
}

void test_mcp_payment_required_is_a_tool_result_with_the_offer(void)
{
  static_startX402();
  char buf[RESP_BUF];
  static_callMcpPaymentAnswer(MCP_PAYMENT_ANSWER_REQUIRED, 30, false, buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 200 OK\r\n"), buf);
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nRetry-After: 30\r\n"));
  static_assertMcpPaymentOffer(static_bodyOf(buf), "Payment required: pay with x402 or retry after the reset.");
  TEST_ASSERT_NULL(strstr(buf, "resultType"));

  static_callMcpPaymentAnswer(MCP_PAYMENT_ANSWER_REQUIRED, 30, true, buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 200 OK\r\n"), buf);
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"resultType\":\"complete\""));
  x402_request_start(NULL);
}

void test_mcp_payment_required_with_x402_off_is_internal_error(void)
{
  x402_request_start(NULL);
  char buf[RESP_BUF];
  static_callMcpPaymentAnswer(MCP_PAYMENT_ANSWER_REQUIRED, 30, false, buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 500 Internal Server Error\r\n"), buf);
  TEST_ASSERT_NULL(strstr(buf, "accepts"));
}

void test_mcp_payment_refused_is_the_offer_with_its_text(void)
{
  static_startX402();
  char buf[RESP_BUF];
  static_callMcpPaymentAnswer(MCP_PAYMENT_ANSWER_REFUSED, 0, false, buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 200 OK\r\n"), buf);
  TEST_ASSERT_NULL(strstr(buf, "Retry-After"));
  static_assertMcpPaymentOffer(static_bodyOf(buf), "The payment was refused.");
  x402_request_start(NULL);
}

void test_mcp_payment_already_used_is_the_offer_with_its_text(void)
{
  static_startX402();
  char buf[RESP_BUF];
  static_callMcpPaymentAnswer(MCP_PAYMENT_ANSWER_ALREADY_USED, 0, false, buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 200 OK\r\n"), buf);
  TEST_ASSERT_NULL(strstr(buf, "Retry-After"));
  static_assertMcpPaymentOffer(static_bodyOf(buf), "This payment was already used.");
  x402_request_start(NULL);
}

void test_mcp_payment_pending_is_a_tool_error_without_an_offer(void)
{
  static_startX402();
  char buf[RESP_BUF];
  static_callMcpPaymentAnswer(MCP_PAYMENT_ANSWER_PENDING, 7, false, buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 200 OK\r\n"), buf);
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nRetry-After: 7\r\n"));
  TEST_ASSERT_EQUAL_STRING("{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"The payment is pending: retry with the same payment.\"}],\"isError\":true}}", static_bodyOf(buf));
  TEST_ASSERT_NULL(strstr(buf, "accepts"));
  x402_request_start(NULL);
}

void test_mcp_payment_invalid_and_not_offered_are_32602(void)
{
  struct { McpPaymentAnswer_t m_answer; const char* mp_body; } cases[] = {
    { MCP_PAYMENT_ANSWER_INVALID,     "{\"jsonrpc\":\"2.0\",\"id\":4,\"error\":{\"code\":-32602,\"message\":\"The payment in params._meta is not valid.\"}}" },
    { MCP_PAYMENT_ANSWER_NOT_OFFERED, "{\"jsonrpc\":\"2.0\",\"id\":4,\"error\":{\"code\":-32602,\"message\":\"This tool does not accept payment.\"}}" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char buf[RESP_BUF];
    static_callMcpPaymentAnswer(cases[i].m_answer, 0, false, buf);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 200 OK\r\n"), buf);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_body, static_bodyOf(buf));
    static_callMcpPaymentAnswer(cases[i].m_answer, 0, true, buf);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 400 Bad Request\r\n"), buf);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_body, static_bodyOf(buf));
  }
}

void test_mcp_payment_busy_limited_and_unavailable_carry_retry_after(void)
{
  struct { McpPaymentAnswer_t m_answer; const char* mp_status; const char* mp_body; } cases[] = {
    { MCP_PAYMENT_ANSWER_BUSY,        "HTTP/1.1 429 Too Many Requests\r\n",
      "{\"jsonrpc\":\"2.0\",\"id\":4,\"error\":{\"code\":-32000,\"message\":\"This payment or another one from its wallet is in flight: retry shortly.\",\"data\":{\"retry_after_seconds\":7}}}" },
    { MCP_PAYMENT_ANSWER_LIMITED,     "HTTP/1.1 429 Too Many Requests\r\n",
      "{\"jsonrpc\":\"2.0\",\"id\":4,\"error\":{\"code\":-32000,\"message\":\"Too many payment attempts: retry later.\",\"data\":{\"retry_after_seconds\":7}}}" },
    { MCP_PAYMENT_ANSWER_UNAVAILABLE, "HTTP/1.1 503 Service Unavailable\r\n",
      "{\"jsonrpc\":\"2.0\",\"id\":4,\"error\":{\"code\":-32003,\"message\":\"Payments are unavailable right now: retry shortly.\",\"data\":{\"retry_after_seconds\":7}}}" },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char buf[RESP_BUF];
    static_callMcpPaymentAnswer(cases[i].m_answer, 7, false, buf);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, cases[i].mp_status), buf);
    TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nRetry-After: 7\r\n"));
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_body, static_bodyOf(buf));
  }
}

void test_mcp_ladder_refusal_sends_the_envelope_with_its_status(void)
{
  const char* envelope = "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32020,\"message\":\"m\"}}";
  char* json = malloc(strlen(envelope) + 1);
  TEST_ASSERT_NOT_NULL(json);
  memcpy(json, envelope, strlen(envelope) + 1);
  char buf[RESP_BUF];
  int fds[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  handler_mcpLadderRefusal(fds[1], json, 400);
  close(fds[1]);
  ssize_t read_len = read(fds[0], buf, RESP_BUF - 1);
  buf[read_len > 0 ? read_len : 0] = '\0';
  close(fds[0]);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 400 Bad Request\r\n"), buf);
  TEST_ASSERT_EQUAL_STRING(envelope, static_bodyOf(buf));

  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  handler_mcpLadderRefusal(fds[1], NULL, 500);
  close(fds[1]);
  read_len = read(fds[0], buf, RESP_BUF - 1);
  buf[read_len > 0 ? read_len : 0] = '\0';
  close(fds[0]);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 500 Internal Server Error\r\n"), buf);
  TEST_ASSERT_NOT_NULL(strstr(static_bodyOf(buf), "\"code\":-32603"));
}

static void static_callPaidMcp(const char* body, X402RequestPayment_t* payment, char* buf)
{
  const RequestCharge_t charge = { .m_chargedCreditCount = 1, .mp_creditBudget = NULL, .mp_x402Payment = payment };
  int fds[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  handler_MCP(fds[1], body, NULL, NULL, &charge);
  close(fds[1]);
  ssize_t read_len = read(fds[0], buf, RESP_BUF - 1);
  buf[read_len > 0 ? read_len : 0] = '\0';
  close(fds[0]);
}

void test_handler_mcp_paid_call_that_runs_ok_is_settled_with_the_receipt(void)
{
  X402RequestPayment_t payment;
  static_openConfirmedPayment(&payment);
  char buf[RESP_BUF];
  static_callPaidMcp(TEST_CVSS_CALL_BODY, &payment, buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 200 OK\r\n"), buf);
  const char* body = static_bodyOf(buf);
  JsonReadSpan_t root, result, meta, receipt, transaction, network, content;
  TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_OK, jsonread_root(body, strlen(body), &root), body);
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root, "result", &result));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(result, "_meta", &meta));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(meta, "x402/payment-response", &receipt));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(receipt, "transaction", &transaction));
  TEST_ASSERT_TRUE(jsonread_isSpanEqual(transaction, "\"" TEST_PAID_SIGNATURE "\""));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(receipt, "network", &network));
  TEST_ASSERT_TRUE(jsonread_isSpanEqual(network, "\"" TEST_PAID_NETWORK "\""));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(result, "content", &content));
  TEST_ASSERT_NOT_NULL(strstr(body, "\"isError\":false"));
  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_LEDGER_mark_settled_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_release_count);
  TEST_ASSERT_FALSE(payment.m_isOpen);
}

static void static_callPaidMcpReadingStderr(const char* body, X402RequestPayment_t* payment, char* buf, char* stderr_text, size_t stderr_size)
{
  FILE* capture_file = tmpfile();
  TEST_ASSERT_NOT_NULL(capture_file);
  fflush(stderr);
  int saved_stderr_fd = dup(STDERR_FILENO);
  TEST_ASSERT_TRUE(saved_stderr_fd >= 0);
  TEST_ASSERT_TRUE(dup2(fileno(capture_file), STDERR_FILENO) >= 0);

  static_callPaidMcp(body, payment, buf);

  fflush(stderr);
  TEST_ASSERT_TRUE(dup2(saved_stderr_fd, STDERR_FILENO) >= 0);
  close(saved_stderr_fd);
  rewind(capture_file);
  size_t length = fread(stderr_text, 1, stderr_size - 1, capture_file);
  stderr_text[length] = '\0';
  fclose(capture_file);
}

void test_handler_mcp_paid_call_whose_receipt_fits_writes_no_stderr_line(void)
{
  X402RequestPayment_t payment;
  static_openConfirmedPayment(&payment);
  char buf[RESP_BUF];
  char stderr_text[1024];
  static_callPaidMcpReadingStderr(TEST_CVSS_CALL_BODY, &payment, buf, stderr_text, sizeof(stderr_text));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "\"x402/payment-response\""), buf);
  TEST_ASSERT_NULL_MESSAGE(strstr(stderr_text, "did not fit"), stderr_text);
}

void test_handler_mcp_paid_call_whose_settle_is_pending_withholds_the_answer(void)
{
  X402RequestPayment_t payment;
  static_openConfirmedPayment(&payment);
  g_stub_X402_LEDGER_mark_settled_status = X402_LEDGER_NOT_MARKED;
  char buf[RESP_BUF];
  static_callPaidMcp(TEST_CVSS_CALL_BODY, &payment, buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 200 OK\r\n"), buf);
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nRetry-After: 10\r\n"));
  TEST_ASSERT_EQUAL_STRING("{\"jsonrpc\":\"2.0\",\"id\":6,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"The payment is pending: retry with the same payment.\"}],\"isError\":true}}", static_bodyOf(buf));
  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_LEDGER_mark_settled_count);
}

void test_handler_mcp_paid_call_whose_run_fails_is_released(void)
{
  X402RequestPayment_t payment;
  static_openConfirmedPayment(&payment);
  char buf[RESP_BUF];
  static_callPaidMcp(TEST_MCP_CALL_BODY, &payment, buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "\"code\":-32603"), buf);
  TEST_ASSERT_NULL(strstr(buf, "x402/payment-response"));
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_mark_settled_count);
  TEST_ASSERT_FALSE(payment.m_isOpen);
}

void test_handler_mcp_paid_call_the_gate_refuses_is_released(void)
{
  X402RequestPayment_t payment;
  static_openConfirmedPayment(&payment);
  char buf[RESP_BUF];
  static_callPaidMcp("{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"cvss_calculator\",\"arguments\":{\"vector\":\"nope\"}}}", &payment, buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "\"isError\":true"), buf);
  TEST_ASSERT_NULL(strstr(buf, "x402/payment-response"));
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_mark_settled_count);
  TEST_ASSERT_FALSE(payment.m_isOpen);
}
int main(void)
{
  UNITY_BEGIN();

  RUN_TEST(test_bad_request_400);
  RUN_TEST(test_raw_body_busy_503);
  RUN_TEST(test_IMAGEINSPECT_answers_the_format_the_hash_and_the_signatures);
  RUN_TEST(test_IMAGEINSPECT_writes_the_metadata_and_the_indicators_of_the_answer);
  RUN_TEST(test_IMAGEINSPECT_answers_502_when_the_exif_service_gives_no_answer);
  RUN_TEST(test_IMAGEINSPECT_answers_400_for_a_refused_image_and_500_for_no_memory);
  RUN_TEST(test_IMAGEINSPECT_refuses_a_body_that_is_no_known_image);
  RUN_TEST(test_IMAGEINSPECT_hash_failure_answers_500);
  RUN_TEST(test_rate_limited_429);
  RUN_TEST(test_mcp_unauthorized_401);
  RUN_TEST(test_mcp_api_key_inactive_401);
  RUN_TEST(test_mcp_rate_limited_429);
  RUN_TEST(test_mcp_internal_error_500);
  RUN_TEST(test_unauthorized_401);
  RUN_TEST(test_api_key_inactive_401);
  RUN_TEST(test_uri_too_long_414);
  RUN_TEST(test_framing_refusals_413_431_501);
  RUN_TEST(test_endpoint_not_found_404);
  RUN_TEST(test_internal_error_500);
  RUN_TEST(test_response_has_json_content_type);
  RUN_TEST(test_response_has_security_headers);

  RUN_TEST(test_HEALTH_no_db_answers_503);

  RUN_TEST(test_CVELOOKUP_null_param_400);
  RUN_TEST(test_CVELOOKUP_empty_param_400);
  RUN_TEST(test_CVELOOKUP_invalid_format_400);
  RUN_TEST(test_CVELOOKUP_id_refusal_precedes_query_refusal);
  RUN_TEST(test_text_path_segment_refusals_are_bad_request);
  RUN_TEST(test_upstream_error_run_answers_502);
  RUN_TEST(test_target_unreachable_run_answers_504_with_its_reason);
  RUN_TEST(test_CVELOOKUP_no_db_500);
  RUN_TEST(test_query_refusal_answers_400_without_db);

  RUN_TEST(test_CVESEARCH_no_db_returns_500);
  RUN_TEST(test_CVESEARCH_severity_invalid_returns_400);
  RUN_TEST(test_CVESEARCH_limit_over_100_returns_400);
  RUN_TEST(test_CVESEARCH_limit_non_integer_returns_400);
  RUN_TEST(test_CVESEARCH_min_cvss_out_of_range_returns_400);
  RUN_TEST(test_CVESEARCH_min_cvss_nan_returns_400);
  RUN_TEST(test_CVESEARCH_min_epss_nan_returns_400);
  RUN_TEST(test_CVESEARCH_min_cvss_infinity_returns_400);
  RUN_TEST(test_CVESEARCH_in_kev_invalid_returns_400);
  RUN_TEST(test_CVESEARCH_published_after_invalid_returns_400);
  RUN_TEST(test_CVESEARCH_published_after_impossible_calendar_date_returns_400);
  RUN_TEST(test_CVESEARCH_vendor_wildcard_returns_400);
  RUN_TEST(test_CVESEARCH_known_ransomware_invalid_returns_400);
  RUN_TEST(test_CVESEARCH_sort_invalid_returns_400);
  RUN_TEST(test_CVESEARCH_offset_negative_returns_400);
  RUN_TEST(test_CVESEARCH_severity_too_long_says_too_long);
  RUN_TEST(test_CVESEARCH_published_after_too_long_says_too_long);
  RUN_TEST(test_CVESEARCH_sort_too_long_says_too_long);
  RUN_TEST(test_CVESEARCH_limit_too_long_says_too_long);

  RUN_TEST(test_KEVLOOKUP_null_param_400);
  RUN_TEST(test_KEVLOOKUP_empty_param_400);
  RUN_TEST(test_KEVLOOKUP_invalid_format_400);
  RUN_TEST(test_KEVLOOKUP_no_db_500);

  RUN_TEST(test_CWELOOKUP_null_param_400);
  RUN_TEST(test_CWELOOKUP_empty_param_400);
  RUN_TEST(test_CWELOOKUP_invalid_format_400);
  RUN_TEST(test_CWELOOKUP_no_db_500);

  RUN_TEST(test_CVELEADING_no_db_500);
  RUN_TEST(test_CVELEADING_limit_over_50_400);
  RUN_TEST(test_CVELEADING_limit_zero_400);
  RUN_TEST(test_CVELEADING_invalid_known_ransomware_400);
  RUN_TEST(test_CVELEADING_invalid_in_kev_400);
  RUN_TEST(test_CVELEADING_min_epss_out_of_range_400);
  RUN_TEST(test_CVELEADING_min_epss_nan_returns_400);
  RUN_TEST(test_CVELEADING_vendor_invalid_400);
  RUN_TEST(test_CVELEADING_limit_non_integer_400);

  RUN_TEST(test_CVELOOKUPBULK_no_body_400);
  RUN_TEST(test_CVELOOKUPBULK_empty_body_400);
  RUN_TEST(test_CVELOOKUPBULK_bad_json_400);
  RUN_TEST(test_CVELOOKUPBULK_empty_array_400);
  RUN_TEST(test_CVELOOKUPBULK_too_many_ids_400);
  RUN_TEST(test_DRIVERLOOKUPBULK_takes_20_hashes_and_refuses_21);
  RUN_TEST(test_CVELOOKUPBULK_no_db_500);
  RUN_TEST(test_CVELOOKUPBULK_wrong_key_400);
  RUN_TEST(test_CVELOOKUPBULK_old_ids_key_400_names_cve_ids);
  RUN_TEST(test_CVELOOKUPBULK_does_not_read_the_query);

  RUN_TEST(test_CVETRIAGE_no_db_returns_500);
  RUN_TEST(test_CVETRIAGE_min_risk_score_below_zero_returns_400);
  RUN_TEST(test_CVETRIAGE_min_risk_score_over_100_returns_400);
  RUN_TEST(test_CVETRIAGE_min_risk_score_non_numeric_returns_400);
  RUN_TEST(test_CVETRIAGE_min_risk_score_nan_returns_400);
  RUN_TEST(test_CVETRIAGE_limit_over_100_returns_400);
  RUN_TEST(test_CVETRIAGE_limit_zero_returns_400);
  RUN_TEST(test_CVETRIAGE_limit_non_numeric_returns_400);
  RUN_TEST(test_CVETRIAGE_offset_negative_returns_400);
  RUN_TEST(test_CVETRIAGE_offset_non_numeric_returns_400);
  RUN_TEST(test_CVETRIAGE_vendor_wildcard_returns_400);

  RUN_TEST(test_CVETRIAGEBULK_no_body_400);
  RUN_TEST(test_CVETRIAGEBULK_empty_body_400);
  RUN_TEST(test_CVETRIAGEBULK_bad_json_400);
  RUN_TEST(test_CVETRIAGEBULK_empty_array_400);
  RUN_TEST(test_CVETRIAGEBULK_too_many_ids_400);
  RUN_TEST(test_CVETRIAGEBULK_no_db_500);
  RUN_TEST(test_BULK_no_db_500_when_every_element_is_skipped);
  RUN_TEST(test_CVETRIAGEBULK_wrong_key_400);
  RUN_TEST(test_CVETRIAGEBULK_old_ids_key_400_names_cve_ids);

  RUN_TEST(test_http_method_not_allowed_405_single_verb);
  RUN_TEST(test_http_method_not_allowed_405_multi_verb);

  RUN_TEST(test_CVERISKSCORE_null_param_400);
  RUN_TEST(test_CVERISKSCORE_empty_param_400);
  RUN_TEST(test_CVERISKSCORE_invalid_format_400);
  RUN_TEST(test_CVERISKSCORE_no_db_500);

  RUN_TEST(test_MCP_request_without_id_returns_202_no_body);
  RUN_TEST(test_MCP_request_returns_200_result);
  RUN_TEST(test_MCP_malformed_body_is_200_jsonrpc_error);
  RUN_TEST(test_MCP_modern_ladder_failure_is_400_bad_request);
  RUN_TEST(test_MCP_modern_initialize_is_404_not_found);
  RUN_TEST(test_MCP_null_body_is_parse_error);

  RUN_TEST(test_CVELOOKUP_overlong_id_returns_400);
  RUN_TEST(test_KEVLOOKUP_overlong_id_returns_400);
  RUN_TEST(test_CVERISKSCORE_overlong_id_returns_400);
  RUN_TEST(test_CVESEARCH_unknown_param_name_returns_400);
  RUN_TEST(test_CVESEARCH_malformed_and_repeated_param_names_return_400);
  RUN_TEST(test_query_param_name_refusal_answers_another_status_with_a_fixed_400);
  RUN_TEST(test_unknown_name_with_a_list_too_long_answers_a_fixed_400);

  RUN_TEST(test_rest_gate_refusal_is_the_usage_run_status);
  RUN_TEST(test_rest_run_status_reaches_the_usage_line);
  RUN_TEST(test_paid_run_ok_closes_once_and_sends_the_receipt);
  RUN_TEST(test_paid_run_that_fails_releases_and_does_not_close);
  RUN_TEST(test_paid_gate_refusal_releases_the_payment);
  RUN_TEST(test_mcp_payment_required_is_a_tool_result_with_the_offer);
  RUN_TEST(test_mcp_payment_required_with_x402_off_is_internal_error);
  RUN_TEST(test_mcp_payment_refused_is_the_offer_with_its_text);
  RUN_TEST(test_mcp_payment_already_used_is_the_offer_with_its_text);
  RUN_TEST(test_mcp_payment_pending_is_a_tool_error_without_an_offer);
  RUN_TEST(test_mcp_payment_invalid_and_not_offered_are_32602);
  RUN_TEST(test_mcp_payment_busy_limited_and_unavailable_carry_retry_after);
  RUN_TEST(test_mcp_ladder_refusal_sends_the_envelope_with_its_status);
  RUN_TEST(test_handler_mcp_paid_call_that_runs_ok_is_settled_with_the_receipt);
  RUN_TEST(test_handler_mcp_paid_call_whose_receipt_fits_writes_no_stderr_line);
  RUN_TEST(test_handler_mcp_paid_call_whose_settle_is_pending_withholds_the_answer);
  RUN_TEST(test_handler_mcp_paid_call_whose_run_fails_is_released);
  RUN_TEST(test_handler_mcp_paid_call_the_gate_refuses_is_released);

  return UNITY_END();
}
