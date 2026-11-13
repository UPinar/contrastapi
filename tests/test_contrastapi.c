#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>

#include "unity/unity.h"
#include "connection.h"
#include "request.h"
#include "request_text.h"
#include "response.h"
#include "db.h"
#include "picohttpparser.h"
#include "cve.h"
#include "endpoint.h"
#include "pages.h"
#include "rawbody.h"
#include "upstream.h"
#include "usagelog.h"

#define RESP_BUF 8192

#define HEX48     "000000000000000000000000000000000000000000000000"
#define HEX48_CRC "0fa16679"
#define VALID_KEY "contrastapi_" HEX48 HEX48_CRC

static PGconn* g_conn = NULL;

static void*  g_mmapAddress             = NULL;
static size_t g_mmapLength              = 0;
static void*  g_munmapAddress           = NULL;
static size_t g_munmapLength            = 0;
static int    g_munmapCount             = 0;
static int    g_munmapPeerFd            = -1;
static bool   g_isAnswerWaitingAtMunmap = false;
static bool   g_isPlaceFreeAtMunmap     = false;

void* __real_mmap(void* address, size_t length, int protection, int flags, int fd, off_t offset);
int   __real_munmap(void* address, size_t length);

void* __wrap_mmap(void* address, size_t length, int protection, int flags, int fd, off_t offset)
{
  g_mmapAddress = __real_mmap(address, length, protection, flags, fd, offset);
  g_mmapLength  = length;
  return g_mmapAddress;
}

static void* static_probeRawBodyPlace(void* unused)
{
  (void)unused;
  g_isPlaceFreeAtMunmap = rawbody_tryEnter();
  rawbody_leaveIfEntered();
  return NULL;
}

int __wrap_munmap(void* address, size_t length)
{
  if (g_munmapPeerFd >= 0)
  {
    char peek;
    g_isAnswerWaitingAtMunmap = recv(g_munmapPeerFd, &peek, 1, MSG_PEEK | MSG_DONTWAIT) == 1;
    pthread_t probe;
    if (pthread_create(&probe, NULL, static_probeRawBodyPlace, NULL) == 0)
      pthread_join(probe, NULL);
  }
  g_munmapAddress = address;
  g_munmapLength  = length;
  g_munmapCount++;
  return __real_munmap(address, length);
}

#define BZERO_MARKER "X-Marker: clear-me"
static size_t g_bzeroLength     = 0;
static bool   g_isMarkerInBzero = false;

void __real_explicit_bzero(void* address, size_t length);
void __real___explicit_bzero_chk(void* address, size_t length, size_t address_size);

static void static_recordBzero(const void* address, size_t length)
{
  static const char marker[] = BZERO_MARKER;
  const char* bytes = address;
  g_bzeroLength     = length;
  g_isMarkerInBzero = false;
  for (size_t i = 0; i + sizeof(marker) - 1 <= length && !g_isMarkerInBzero; i++)
    g_isMarkerInBzero = memcmp(bytes + i, marker, sizeof(marker) - 1) == 0;
}

void __wrap_explicit_bzero(void* address, size_t length)
{
  static_recordBzero(address, length);
  __real_explicit_bzero(address, length);
}

void __wrap___explicit_bzero_chk(void* address, size_t length, size_t address_size)
{
  static_recordBzero(address, length);
  __real___explicit_bzero_chk(address, length, address_size);
}

void setUp(void)    { g_conn = NULL; }

void tearDown(void)
{
  rawbody_leaveIfEntered();
  rawbody_setThreadCount(0);
}

static void static_callRequestHandle(const char* req, char* buf, size_t len)
{
  ReceiveResult_t request;
  TEST_ASSERT_TRUE_MESSAGE(requestText_parse(req, &request), req);
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) 
  { 
    perror("socketpair"); 
    buf[0] = '\0'; 
    return; 
  }
  RequestHead_t head;
  request_readHead(&request, &head);
  request_handle(&request, &head, fds[1], "127.0.0.1", NULL, g_conn);
  ssize_t n = read(fds[0], buf, len - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);
}

void test_valid_key_no_db_free_path_is_served(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "X-API-Key: " VALID_KEY "\r\n\r\n";
  char buf[RESP_BUF];
  static_callRequestHandle(req, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 503"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"status\":\"unavailable\""));
  TEST_ASSERT_NULL    (strstr(buf, "HTTP/1.1 401"));
}

void test_bearer_valid_format_no_db_free_path_is_served(void)
{
  const char* req =
    "GET /health HTTP/1.1\r\n"
    "Authorization: Bearer " VALID_KEY "\r\n\r\n";
  char buf[RESP_BUF];
  static_callRequestHandle(req, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 503"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"status\":\"unavailable\""));
  TEST_ASSERT_NULL    (strstr(buf, "HTTP/1.1 401"));
}

void test_valid_key_no_db_paid_path_returns_500_not_401(void)
{
  const char* req =
    "GET /cve_lookup/CVE-2021-44228 HTTP/1.1\r\n"
    "X-API-Key: " VALID_KEY "\r\n\r\n";
  char buf[RESP_BUF];
  static_callRequestHandle(req, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
  TEST_ASSERT_NULL    (strstr(buf, "HTTP/1.1 401"));
}

void test_request_line_only_no_headers_reaches_router(void)
{
  const char* req = "GET /health HTTP/1.1\r\n\r\n";
  char buf[RESP_BUF];
  static_callRequestHandle(req, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 503"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"status\":\"unavailable\""));
}

void test_CVELOOKUP_valid_format_no_db_returns_500(void)
{
  const char* req =
    "GET /cve_lookup/CVE-2021-44228 HTTP/1.1\r\n"
    "Host: localhost\r\n\r\n";
  char buf[RESP_BUF];
  static_callRequestHandle(req, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_CVESEARCH_no_db_returns_500(void)
{
  const char* req =
    "GET /cve_search HTTP/1.1\r\n"
    "Host: localhost\r\n\r\n";
  char buf[RESP_BUF];
  static_callRequestHandle(req, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 500"));
}

void test_web_file_is_served_without_a_database(void)
{
  char buf[RESP_BUF];
  static_callRequestHandle("GET /robots.txt HTTP/1.1\r\n\r\n", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 200 OK\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nContent-Type: text/plain; charset=utf-8\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\n\r\n# ContrastAPI"));
  TEST_ASSERT_NULL(strstr(buf, "X-RateLimit-"));
}

void test_missing_static_file_without_a_database_returns_404(void)
{
  char buf[RESP_BUF];
  static_callRequestHandle("GET /static/missing.css HTTP/1.1\r\n\r\n", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 404"));
}

void test_POST_method_returns_405(void)
{
  const char* req =
    "POST /health HTTP/1.1\r\n"
    "Host: localhost\r\n\r\n";
  char buf[RESP_BUF];
  static_callRequestHandle(req, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 405"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"method_not_allowed\""));
}

void test_mcp_era_does_not_carry_over_to_the_next_request(void)
{
  char buf[RESP_BUF];
  static_callRequestHandle(
    "POST /mcp HTTP/1.1\r\n"
    "MCP-Protocol-Version: 2026-07-28\r\n"
    "Mcp-Method: ping\r\n\r\n"
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{\"_meta\":{"
    "\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\","
    "\"io.modelcontextprotocol/clientInfo\":{\"name\":\"p\",\"version\":\"1\"},"
    "\"io.modelcontextprotocol/clientCapabilities\":{}}}}",
    buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 200"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"resultType\":\"complete\""));

  static_callRequestHandle(
    "POST /mcp HTTP/1.1\r\n\r\n"
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}",
    buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 200"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"result\""));
  TEST_ASSERT_NULL(strstr(buf, "\"resultType\""));
}

void test_response_sendMethodNotAllowed405_includes_allow_header(void)
{
  int fds[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) { TEST_FAIL_MESSAGE("socketpair failed"); return; }
  response_sendMethodNotAllowed405(fds[1], "GET", "{}");
  close(fds[1]);
  char buf[RESP_BUF];
  ssize_t n = read(fds[0], buf, sizeof(buf) - 1);
  buf[n > 0 ? n : 0] = '\0';
  close(fds[0]);
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 405 Method Not Allowed"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "Allow: GET"));
}

void test_head_request_gets_its_405_without_a_body(void)
{
  char buf[RESP_BUF];
  static_callRequestHandle("HEAD /health HTTP/1.1\r\n\r\n", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 405"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nAllow: GET\r\n"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\r\nContent-Length: "));
  TEST_ASSERT_NULL(strstr(buf, "\r\nContent-Length: 0\r\n"));
  TEST_ASSERT_EQUAL_STRING("\r\n\r\n", buf + strlen(buf) - 4);
}

void test_head_mark_does_not_carry_over_to_the_next_request(void)
{
  char buf[RESP_BUF];
  static_callRequestHandle("HEAD /health HTTP/1.1\r\n\r\n", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 405"));

  char long_target_req[1200] = "GET /";
  memset(long_target_req + 5, 'a', 1100);
  memcpy(long_target_req + 1105, " HTTP/1.1\r\n\r\n", sizeof(" HTTP/1.1\r\n\r\n"));
  static_callRequestHandle(long_target_req, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 414"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"uri_too_long\""));
}

static void static_buildRequestWithTargetLen(size_t target_len, char* out_buf, size_t out_buf_size)
{
  const char* prefix = "/cve_search?vendor=";
  size_t prefix_len  = strlen(prefix);
  TEST_ASSERT_TRUE(target_len > prefix_len);

  char target[2048];
  TEST_ASSERT_TRUE(target_len < sizeof(target));
  memcpy(target, prefix, prefix_len);
  memset(target + prefix_len, 'a', target_len - prefix_len);
  target[target_len] = '\0';
  TEST_ASSERT_EQUAL_UINT(target_len, (unsigned int)strlen(target));

  int written = snprintf(out_buf, out_buf_size, "GET %s HTTP/1.1\r\n\r\n", target);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < out_buf_size);
}

void test_overlong_request_target_returns_414(void)
{
  char req[2560];
  static_buildRequestWithTargetLen(1100, req, sizeof(req));

  char buf[RESP_BUF];
  static_callRequestHandle(req, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 414 URI Too Long"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"uri_too_long\""));
}

void test_request_target_one_over_limit_returns_414(void)
{
  char req[2560];
  static_buildRequestWithTargetLen(1024, req, sizeof(req));

  char buf[RESP_BUF];
  static_callRequestHandle(req, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 414 URI Too Long"));
  TEST_ASSERT_NOT_NULL(strstr(buf, "\"code\":\"uri_too_long\""));
}

void test_request_target_at_limit_is_not_rejected_for_length(void)
{
  char req[2560];
  static_buildRequestWithTargetLen(1023, req, sizeof(req));

  char buf[RESP_BUF];
  static_callRequestHandle(req, buf, sizeof(buf));
  TEST_ASSERT_TRUE(buf[0] != '\0');
  TEST_ASSERT_NULL(strstr(buf, "414"));
}

void test_full_filter_cves_query_is_no_longer_dropped(void)
{
  char vendor[CVESEARCH_VENDOR_LEN + 1];
  char product[CVESEARCH_PRODUCT_LEN + 1];
  memset(vendor,  'a', CVESEARCH_VENDOR_LEN);
  memset(product, 'b', CVESEARCH_PRODUCT_LEN);
  vendor[CVESEARCH_VENDOR_LEN]   = '\0';
  product[CVESEARCH_PRODUCT_LEN] = '\0';

  char target[768];
  int written = snprintf(target, sizeof(target),
                         "/cve_search?vendor=%s&product=%s&severity=CRITICAL&min_cvss=7.0&min_epss=0.50&in_kev=true&known_ransomware=true&cwe_id=CWE-89&published_after=2024-01-01&published_before=2024-12-31&sort=epss&limit=20&offset=0",
                         vendor, product);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(target));
  TEST_ASSERT_TRUE(strlen(target) > 255);

  char req[1024];
  written = snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\n\r\n", target);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(req));

  char buf[RESP_BUF];
  static_callRequestHandle(req, buf, sizeof(buf));
  TEST_ASSERT_TRUE(buf[0] != '\0');
  TEST_ASSERT_NULL(strstr(buf, "HTTP/1.1 414"));
}

void test_overlong_target_answered_before_auth(void)
{
  const char* prefix = "/cve_search?vendor=";
  char target[1200];
  size_t prefix_len = strlen(prefix);
  memcpy(target, prefix, prefix_len);
  memset(target + prefix_len, 'a', 1100 - prefix_len);
  target[1100] = '\0';

  char req[2560];
  int written = snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nAuthorization: Bearer " VALID_KEY "\r\n\r\n", target);
  TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(req));

  char buf[RESP_BUF];
  static_callRequestHandle(req, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 414 URI Too Long"));
  TEST_ASSERT_NULL(strstr(buf, "HTTP/1.1 401"));
  TEST_ASSERT_NULL(strstr(buf, "HTTP/1.1 500"));
  TEST_ASSERT_NULL(strstr(buf, "X-RateLimit"));
}

typedef struct {
  int                m_fd;
  const char* const* mp_parts;
  size_t             m_partCount;
  long               m_gapMs;
  bool               m_isClosedAfter;
  size_t             m_firstPartLen;
} ClientScript_t;

static void* static_clientThread(void* script_arg)
{
  const ClientScript_t* script = (const ClientScript_t*)script_arg;
  for (size_t i = 0; i < script->m_partCount; i++)
  {
    if (i > 0)
    {
      struct timespec gap = { .tv_sec = script->m_gapMs / 1000, .tv_nsec = (script->m_gapMs % 1000) * 1000000L };
      nanosleep(&gap, NULL);
    }
    size_t part_len = (i == 0 && script->m_firstPartLen > 0) ? script->m_firstPartLen : strlen(script->mp_parts[i]);
    if (send(script->m_fd, script->mp_parts[i], part_len, MSG_NOSIGNAL) != (ssize_t)part_len)
      break;
  }
  if (script->m_isClosedAfter)
    shutdown(script->m_fd, SHUT_WR);
  return NULL;
}

static ConnectionServeStatus_t static_serveScript(ClientScript_t script, char* buf, size_t len)
{
  int fds[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  script.m_fd = fds[0];
  pthread_t client;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&client, NULL, static_clientThread, &script));

  g_munmapPeerFd = fds[0];
  ConnectionServeStatus_t serve_status = connection_serveRequest(fds[1], "127.0.0.1", NULL, g_conn);
  g_munmapPeerFd = -1;
  pthread_join(client, NULL);

  size_t total = 0;
  ssize_t n;
  while (total < len - 1 && (n = read(fds[0], buf + total, len - 1 - total)) > 0)
    total += (size_t)n;
  buf[total] = '\0';
  close(fds[0]);
  return serve_status;
}

void test_connection_answers_a_head_sent_in_parts(void)
{
  static const char* const parts[] = { "GET /health HTTP/1.1\r\n", "Host: x\r\n", "\r\n" };
  ClientScript_t script = { -1, parts, sizeof(parts) / sizeof(parts[0]), 300, false, 0 };
  char buf[RESP_BUF];
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, static_serveScript(script, buf, sizeof(buf)));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 503"));
}

void test_connection_answers_a_head_that_fills_the_buffer(void)
{
  static char head[REQUEST_BUFFER_SIZE];
  const char* head_start = "GET /health HTTP/1.1\r\nX-Pad: ";
  const char* head_end   = "\r\n\r\n";
  size_t pad_len = (REQUEST_BUFFER_SIZE - 1) - strlen(head_start) - strlen(head_end);
  size_t pos = 0;
  memcpy(head + pos, head_start, strlen(head_start));
  pos += strlen(head_start);
  memset(head + pos, 'a', pad_len);
  pos += pad_len;
  memcpy(head + pos, head_end, strlen(head_end) + 1);
  TEST_ASSERT_EQUAL_size_t(REQUEST_BUFFER_SIZE - 1, strlen(head));

  static const char* parts[1];
  parts[0] = head;
  ClientScript_t script = { -1, parts, 1, 0, false, 0 };
  char buf[RESP_BUF];
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, static_serveScript(script, buf, sizeof(buf)));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 503"));
}

void test_connection_closes_a_connection_whose_head_never_ends(void)
{
  static const char* const parts[] = { "GET /health HTTP/1.1\r\n" };
  ClientScript_t script = { -1, parts, 1, 0, true, 0 };
  char buf[RESP_BUF];
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_DROPPED, static_serveScript(script, buf, sizeof(buf)));
  TEST_ASSERT_EQUAL_STRING("", buf);
}

void test_connection_drops_a_method_longer_than_seven_bytes(void)
{
  static const struct { const char* mp_head; bool m_isAnswered; } cases[] = {
    { "OPTIONS /health HTTP/1.1\r\n\r\n",  true  },
    { "ABCDEFGH /health HTTP/1.1\r\n\r\n", false },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    const char* const parts[] = { cases[i].mp_head };
    ClientScript_t script = { -1, parts, 1, 0, true, 0 };
    char buf[RESP_BUF];
    TEST_ASSERT_EQUAL_INT_MESSAGE(CONNECTION_SERVE_HANDLED, static_serveScript(script, buf, sizeof(buf)), cases[i].mp_head);
    TEST_ASSERT_EQUAL_INT_MESSAGE((int)cases[i].m_isAnswered, (int)(buf[0] != '\0'), cases[i].mp_head);
  }
}

void test_connection_answers_414_for_a_whole_head_whose_target_is_too_long(void)
{
  char req[2560];
  static_buildRequestWithTargetLen(1500, req, sizeof(req));
  const char* const parts[] = { req };
  ClientScript_t script = { -1, parts, 1, 0, true, 0 };
  char buf[RESP_BUF];
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, static_serveScript(script, buf, sizeof(buf)));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 414 URI Too Long"));
}

typedef enum {
  FRAMING_TOO_MANY_HEADERS,
  FRAMING_HEAD_TOO_LARGE,
  FRAMING_URI_TOO_LONG,
  FRAMING_BAD_CONTENT_LENGTH,
  FRAMING_LENGTH_AND_TRANSFER_ENCODING,
  FRAMING_TRANSFER_ENCODING,
  FRAMING_CONTENT_TOO_LARGE,
  FRAMING_BODY_NUL,
} FramingKind_t;

static size_t static_buildFramingRequest(FramingKind_t kind, char* text, size_t text_size)
{
  size_t pos = 0;
  if (kind == FRAMING_TOO_MANY_HEADERS)
  {
    pos += (size_t)snprintf(text, text_size, "GET /health HTTP/1.1\r\n");
    for (int i = 0; i <= HTTP_MAX_HEADERS; i++)
      pos += (size_t)snprintf(text + pos, text_size - pos, "X: y\r\n");
    pos += (size_t)snprintf(text + pos, text_size - pos, "\r\n");
  }
  else if (kind == FRAMING_HEAD_TOO_LARGE || kind == FRAMING_URI_TOO_LONG)
  {
    pos += (size_t)snprintf(text, text_size, kind == FRAMING_URI_TOO_LONG ? "GET /" : "GET /health HTTP/1.1\r\nX-Pad: ");
    memset(text + pos, 'a', REQUEST_BUFFER_SIZE);
    pos += REQUEST_BUFFER_SIZE;
    text[pos] = '\0';
  }
  else if (kind == FRAMING_BAD_CONTENT_LENGTH)
    pos = (size_t)snprintf(text, text_size, "POST /mcp HTTP/1.1\r\nContent-Length: 5, 5\r\n\r\n");
  else if (kind == FRAMING_LENGTH_AND_TRANSFER_ENCODING)
    pos = (size_t)snprintf(text, text_size, "POST /mcp HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\nabcd");
  else if (kind == FRAMING_TRANSFER_ENCODING)
    pos = (size_t)snprintf(text, text_size, "POST /mcp HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
  else if (kind == FRAMING_CONTENT_TOO_LARGE)
    pos = (size_t)snprintf(text, text_size, "POST /cve_lookup_bulk HTTP/1.1\r\nContent-Length: %d\r\n\r\n", REQUEST_BUFFER_SIZE);
  else
  {
    pos = (size_t)snprintf(text, text_size, "POST /mcp HTTP/1.1\r\nContent-Length: 3\r\n\r\n");
    memcpy(text + pos, "a\0b", 3);
    pos += 3;
  }
  return pos;
}

void test_connection_answers_each_framing_refusal(void)
{
  static const struct {
    FramingKind_t m_kind;
    const char*   mp_statusLine;
    const char*   mp_code;
    const char*   mp_message;
  } cases[] = {
    { FRAMING_TOO_MANY_HEADERS,             "HTTP/1.1 431 ", "request_header_fields_too_large", "request header fields too large" },
    { FRAMING_HEAD_TOO_LARGE,               "HTTP/1.1 431 ", "request_header_fields_too_large", "request header fields too large" },
    { FRAMING_URI_TOO_LONG,                 "HTTP/1.1 414 ", "uri_too_long",                    "request target too long" },
    { FRAMING_BAD_CONTENT_LENGTH,           "HTTP/1.1 400 ", "bad_request",                     "Content-Length must be one decimal number" },
    { FRAMING_LENGTH_AND_TRANSFER_ENCODING, "HTTP/1.1 400 ", "bad_request",                     "send Content-Length or Transfer-Encoding, not both" },
    { FRAMING_TRANSFER_ENCODING,            "HTTP/1.1 501 ", "not_implemented",                 "Transfer-Encoding is not supported; send Content-Length" },
    { FRAMING_CONTENT_TOO_LARGE,            "HTTP/1.1 413 ", "content_too_large",               "request body too large" },
    { FRAMING_BODY_NUL,                     "HTTP/1.1 400 ", "bad_request",                     "request body must not contain a NUL byte" },
  };
  static char text[2 * REQUEST_BUFFER_SIZE];
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    size_t text_len = static_buildFramingRequest(cases[i].m_kind, text, sizeof(text));
    const char* parts[1] = { text };
    ClientScript_t script = { -1, parts, 1, 0, true, text_len };
    char buf[RESP_BUF];
    TEST_ASSERT_EQUAL_INT_MESSAGE(CONNECTION_SERVE_HANDLED, static_serveScript(script, buf, sizeof(buf)), cases[i].mp_code);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, strncmp(buf, cases[i].mp_statusLine, strlen(cases[i].mp_statusLine)), buf);
    char code_text[64];
    snprintf(code_text, sizeof(code_text), "\"code\":\"%s\"", cases[i].mp_code);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, code_text), buf);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, cases[i].mp_message), buf);
  }
}

void test_connection_closes_a_malformed_head_without_an_answer(void)
{
  static const char* const parts[] = { "GET / HTTP/x\r\n\r\n" };
  ClientScript_t script = { -1, parts, 1, 0, true, 0 };
  char buf[RESP_BUF];
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_DROPPED, static_serveScript(script, buf, sizeof(buf)));
  TEST_ASSERT_EQUAL_STRING("", buf);
}

void test_connection_framing_answer_carries_no_rate_limit_headers(void)
{
  response_setRateLimitInfo(30, 29, 0);
  static char text[2 * REQUEST_BUFFER_SIZE];
  size_t text_len = static_buildFramingRequest(FRAMING_CONTENT_TOO_LARGE, text, sizeof(text));
  const char* parts[1] = { text };
  ClientScript_t script = { -1, parts, 1, 0, true, text_len };
  char buf[RESP_BUF];
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, static_serveScript(script, buf, sizeof(buf)));
  TEST_ASSERT_NOT_NULL(strstr(buf, "HTTP/1.1 413 "));
  TEST_ASSERT_NULL(strstr(buf, "X-RateLimit"));
}

void test_connection_refuses_a_body_whose_last_byte_is_a_nul(void)
{
  static const char text[] = "POST /mcp HTTP/1.1\r\nContent-Length: 3\r\n\r\nab";
  const char* parts[1] = { text };
  ClientScript_t script = { -1, parts, 1, 0, true, sizeof(text) };
  char buf[RESP_BUF];
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, static_serveScript(script, buf, sizeof(buf)));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "request body must not contain a NUL byte"), buf);
}

void test_connection_refuses_a_nul_body_on_a_path_no_row_serves(void)
{
  static const char text[] = "POST /no_such_path HTTP/1.1\r\nContent-Length: 3\r\n\r\na\0b";
  const char* parts[1] = { text };
  ClientScript_t script = { -1, parts, 1, 0, true, sizeof(text) - 1 };
  char buf[RESP_BUF];
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, static_serveScript(script, buf, sizeof(buf)));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 400 "), buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "request body must not contain a NUL byte"), buf);
}

static void static_serveImageRequest(size_t content_length, const char* body, size_t body_len, char* buf, size_t len)
{
  static char text[256];
  int head_len = snprintf(text, sizeof(text), "POST /image_inspect HTTP/1.1\r\nContent-Length: %zu\r\n\r\n", content_length);
  TEST_ASSERT_TRUE(head_len > 0 && (size_t)head_len + body_len < sizeof(text));
  memcpy(text + head_len, body, body_len);
  const char* parts[1] = { text };
  ClientScript_t script = { -1, parts, 1, 0, true, (size_t)head_len + body_len };
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, static_serveScript(script, buf, len));
}

void test_connection_reads_a_body_that_fills_the_buffer_and_refuses_one_byte_more(void)
{
  static char text[REQUEST_BUFFER_SIZE + 64];
  for (size_t request_len = REQUEST_BUFFER_SIZE - 1; request_len <= REQUEST_BUFFER_SIZE; request_len++)
  {
    char head[96];
    int head_len = snprintf(head, sizeof(head), "POST /cve_lookup_bulk HTTP/1.1\r\nContent-Length: %zu\r\n\r\n", request_len - 56);
    TEST_ASSERT_EQUAL_INT(56, head_len);
    memcpy(text, head, (size_t)head_len);
    memset(text + head_len, 'a', request_len - (size_t)head_len);
    const char* parts[1] = { text };
    ClientScript_t script = { -1, parts, 1, 0, true, request_len };
    char buf[RESP_BUF];
    TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, static_serveScript(script, buf, sizeof(buf)));
    if (request_len == REQUEST_BUFFER_SIZE - 1)
      TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 500 "), buf);
    else
      TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 413 "), buf);
  }
}

static ConnectionServeStatus_t static_serveLargeImageRequest(bool is_body_sent, char* buf, size_t len)
{
  static char text[2 * REQUEST_BUFFER_SIZE];
  int head_len = snprintf(text, sizeof(text), "POST /image_inspect HTTP/1.1\r\nContent-Length: %d\r\n\r\n", REQUEST_BUFFER_SIZE);
  memset(text + head_len, 'x', REQUEST_BUFFER_SIZE);
  memcpy(text + head_len, "\xff\xd8\xff\xe0\0", 5);
  const char* parts[1] = { text };
  ClientScript_t script = { -1, parts, 1, 0, true, (size_t)head_len + (is_body_sent ? REQUEST_BUFFER_SIZE : 0) };
  return static_serveScript(script, buf, len);
}

void test_connection_answers_503_when_every_raw_body_thread_is_in_use(void)
{
  rawbody_setThreadCount(0);
  char buf[RESP_BUF];
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, static_serveLargeImageRequest(false, buf, sizeof(buf)));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 503 "), buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "\r\nRetry-After: 10\r\n"), buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "\"code\":\"raw_body_busy\""), buf);
  TEST_ASSERT_NULL(strstr(buf, "X-RateLimit"));
}

void test_connection_takes_a_raw_body_place_for_an_image_that_fits_the_read_buffer(void)
{
  rawbody_setThreadCount(0);
  char buf[RESP_BUF];
  static_serveImageRequest(5, "\xff\xd8\xff\xe0\0", 5, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 503 "), buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "\"code\":\"raw_body_busy\""), buf);

  rawbody_setThreadCount(1);
  static_serveImageRequest(5, "\xff\xd8\xff\xe0\0", 5, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 500 "), buf);
  TEST_ASSERT_TRUE(rawbody_tryEnter());
  rawbody_leaveIfEntered();
}

void test_connection_reads_the_body_away_after_a_busy_503(void)
{
  rawbody_setThreadCount(0);
  int fds[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  static char text[3 * REQUEST_BUFFER_SIZE];
  int head_len = snprintf(text, sizeof(text), "POST /image_inspect HTTP/1.1\r\nContent-Length: %d\r\n\r\n", 2 * REQUEST_BUFFER_SIZE);
  memset(text + head_len, 'b', 2 * REQUEST_BUFFER_SIZE);
  size_t text_len = (size_t)head_len + 2 * REQUEST_BUFFER_SIZE;
  TEST_ASSERT_EQUAL_INT((int)text_len, (int)send(fds[0], text, text_len, MSG_NOSIGNAL));
  TEST_ASSERT_EQUAL_INT(0, shutdown(fds[0], SHUT_WR));
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, connection_serveRequest(fds[1], "127.0.0.1", NULL, g_conn));

  char buf[RESP_BUF];
  size_t total = 0;
  ssize_t n;
  errno = 0;
  while ((n = read(fds[0], buf + total, sizeof(buf) - 1 - total)) > 0)
    total += (size_t)n;
  int read_errno = errno;
  buf[total] = '\0';
  close(fds[0]);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 503 "), buf);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, (int)n, strerror(read_errno));
}

void test_connection_reads_an_image_body_larger_than_the_read_buffer(void)
{
  g_mmapAddress   = NULL;
  g_mmapLength    = 0;
  g_munmapAddress = NULL;
  g_munmapLength  = 0;
  g_munmapCount   = 0;
  g_isAnswerWaitingAtMunmap = false;
  g_isPlaceFreeAtMunmap     = true;
  rawbody_setThreadCount(1);
  static char text[2 * REQUEST_BUFFER_SIZE];
  int head_len = snprintf(text, sizeof(text), "POST /image_inspect HTTP/1.1\r\nContent-Length: %d\r\n\r\n", REQUEST_BUFFER_SIZE);
  memset(text + head_len, 'x', REQUEST_BUFFER_SIZE);
  memcpy(text + head_len, "\xff\xd8\xff\xe0", 4);
  const char* parts[1] = { text };
  ClientScript_t script = { -1, parts, 1, 0, true, (size_t)head_len + REQUEST_BUFFER_SIZE };
  char buf[RESP_BUF];
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, static_serveScript(script, buf, sizeof(buf)));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 500 "), buf);
  TEST_ASSERT_EQUAL_size_t((size_t)head_len + REQUEST_BUFFER_SIZE + 1, g_mmapLength);
  TEST_ASSERT_EQUAL_INT(1, g_munmapCount);
  TEST_ASSERT_TRUE(g_munmapAddress == g_mmapAddress);
  TEST_ASSERT_EQUAL_size_t(g_mmapLength, g_munmapLength);
  TEST_ASSERT_TRUE(g_isAnswerWaitingAtMunmap);
  TEST_ASSERT_FALSE(g_isPlaceFreeAtMunmap);
}

void test_connection_reads_a_large_json_body_into_a_mapping_without_a_raw_body_place(void)
{
  rawbody_setThreadCount(0);
  static const struct { const char* mp_path; size_t m_limit; } cases[] = {
    { "/mcp",                ENDPOINT_MCP_MAX_BODY_BYTE_COUNT },
    { "/package_check_bulk", PACKAGECHECKBULK_JSON_OBJECT_BUF_SIZE },
  };
  static char text[ENDPOINT_MCP_MAX_BODY_BYTE_COUNT + 128];
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    for (size_t body_len = cases[i].m_limit; body_len <= cases[i].m_limit + 1; body_len++)
    {
      g_mmapLength  = 0;
      g_munmapCount = 0;
      int head_len = snprintf(text, sizeof(text), "POST %s HTTP/1.1\r\nContent-Length: %zu\r\n\r\n", cases[i].mp_path, body_len);
      TEST_ASSERT_TRUE(head_len > 0 && (size_t)head_len + body_len < sizeof(text));
      memset(text + head_len, 'a', body_len);
      const char* parts[1] = { text };
      ClientScript_t script = { -1, parts, 1, 0, true, (size_t)head_len + body_len };
      char buf[RESP_BUF];
      TEST_ASSERT_EQUAL_INT_MESSAGE(CONNECTION_SERVE_HANDLED, static_serveScript(script, buf, sizeof(buf)), cases[i].mp_path);
      if (body_len == cases[i].m_limit)
      {
        TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 500 "), buf);
        TEST_ASSERT_EQUAL_size_t_MESSAGE((size_t)head_len + body_len + 1, g_mmapLength, cases[i].mp_path);
        TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_munmapCount, cases[i].mp_path);
      }
      else
        TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 413 "), buf);
    }
  }
}

void test_connection_gives_the_raw_body_thread_back_after_each_answer(void)
{
  rawbody_setThreadCount(1);
  char buf[RESP_BUF];
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_DROPPED, static_serveLargeImageRequest(false, buf, sizeof(buf)));
  TEST_ASSERT_EQUAL_STRING("", buf);

  for (int i = 0; i < 2; i++)
  {
    TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, static_serveLargeImageRequest(true, buf, sizeof(buf)));
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 500 "), buf);
    TEST_ASSERT_NULL_MESSAGE(strstr(buf, "NUL byte"), buf);
  }

  TEST_ASSERT_TRUE(rawbody_tryEnter());
  rawbody_leaveIfEntered();
}

void test_connection_clears_the_read_buffer_before_it_returns(void)
{
  static const char* const health[] = { "GET /health HTTP/1.1\r\n" BZERO_MARKER "\r\n\r\n" };
  ClientScript_t health_script = { -1, health, 1, 0, true, 0 };
  char buf[RESP_BUF];
  g_bzeroLength = 0;
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, static_serveScript(health_script, buf, sizeof(buf)));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 503 "), buf);
  TEST_ASSERT_EQUAL_size_t(REQUEST_BUFFER_SIZE, g_bzeroLength);
  TEST_ASSERT_TRUE(g_isMarkerInBzero);

  rawbody_setThreadCount(0);
  char head[256];
  snprintf(head, sizeof(head), "POST /image_inspect HTTP/1.1\r\n" BZERO_MARKER "\r\nContent-Length: %d\r\n\r\n", REQUEST_BUFFER_SIZE);
  const char* const busy[] = { head };
  ClientScript_t busy_script = { -1, busy, 1, 0, true, 0 };
  g_bzeroLength = 0;
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, static_serveScript(busy_script, buf, sizeof(buf)));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "raw_body_busy"), buf);
  TEST_ASSERT_EQUAL_size_t(REQUEST_BUFFER_SIZE, g_bzeroLength);
  TEST_ASSERT_TRUE(g_isMarkerInBzero);
}

typedef struct {
  int                     m_fd;
  ConnectionServeStatus_t m_status;
} ServeThread_t;

static void* static_serveOnThread(void* arg)
{
  ServeThread_t* serve = arg;
  serve->m_status = connection_serveRequest(serve->m_fd, "127.0.0.1", NULL, g_conn);
  return NULL;
}

void test_connection_answers_a_framing_refusal_on_the_raw_body_row_without_a_place(void)
{
  rawbody_setThreadCount(0);
  static const char* const bad[] = { "POST /image_inspect HTTP/1.1\r\nContent-Length: 1x\r\n\r\n" };
  ClientScript_t script = { -1, bad, 1, 0, true, 0 };
  char buf[RESP_BUF];
  static_serveScript(script, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 400 "), buf);
  TEST_ASSERT_NULL_MESSAGE(strstr(buf, "raw_body_busy"), buf);
}

void test_connection_answers_413_without_taking_a_raw_body_place(void)
{
  rawbody_setThreadCount(1);
  int fds[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  char head[128];
  int head_len = snprintf(head, sizeof(head), "POST /image_inspect HTTP/1.1\r\nContent-Length: %u\r\n\r\n", ENDPOINT_MAX_BODY_BYTE_COUNT + 1u);
  TEST_ASSERT_EQUAL_INT(head_len, (int)send(fds[0], head, (size_t)head_len, MSG_NOSIGNAL));

  ServeThread_t serve = { fds[1], CONNECTION_SERVE_DROPPED };
  pthread_t thread;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&thread, NULL, static_serveOnThread, &serve));
  char buf[RESP_BUF];
  size_t total = 0;
  ssize_t n;
  buf[0] = '\0';
  while (strstr(buf, "content_too_large") == NULL && (n = read(fds[0], buf + total, sizeof(buf) - 1 - total)) > 0)
  {
    total += (size_t)n;
    buf[total] = '\0';
  }
  bool has_entered = rawbody_tryEnter();
  rawbody_leaveIfEntered();
  close(fds[0]);
  TEST_ASSERT_EQUAL_INT(0, pthread_join(thread, NULL));

  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 413 "), buf);
  TEST_ASSERT_TRUE(has_entered);
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, serve.m_status);
}

void test_connection_reads_the_refused_body_before_it_closes(void)
{
  int fds[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  static char text[3 * REQUEST_BUFFER_SIZE];
  int head_len = snprintf(text, sizeof(text), "POST /cve_lookup_bulk HTTP/1.1\r\nContent-Length: %d\r\n\r\n", 2 * REQUEST_BUFFER_SIZE);
  memset(text + head_len, 'b', 2 * REQUEST_BUFFER_SIZE);
  size_t text_len = (size_t)head_len + 2 * REQUEST_BUFFER_SIZE;
  TEST_ASSERT_EQUAL_INT((int)text_len, (int)send(fds[0], text, text_len, MSG_NOSIGNAL));
  TEST_ASSERT_EQUAL_INT(0, shutdown(fds[0], SHUT_WR));
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, connection_serveRequest(fds[1], "127.0.0.1", NULL, g_conn));

  char buf[RESP_BUF];
  size_t total = 0;
  ssize_t n;
  errno = 0;
  while ((n = read(fds[0], buf + total, sizeof(buf) - 1 - total)) > 0)
    total += (size_t)n;
  int read_errno = errno;
  buf[total] = '\0';
  close(fds[0]);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 413 "), buf);
  TEST_ASSERT_EQUAL_INT_MESSAGE(0, (int)n, strerror(read_errno));
}

void test_connection_drops_a_socket_whose_timeouts_cannot_be_set(void)
{
  int pipe_fds[2];
  TEST_ASSERT_EQUAL_INT(0, pipe(pipe_fds));
  static const char text[] = "POST /mcp HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
  TEST_ASSERT_EQUAL_INT((int)strlen(text), (int)write(pipe_fds[1], text, strlen(text)));
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_DROPPED, connection_serveRequest(pipe_fds[0], "127.0.0.1", NULL, g_conn));
  errno = 0;
  TEST_ASSERT_EQUAL_INT(-1, fcntl(pipe_fds[0], F_GETFD));
  TEST_ASSERT_EQUAL_INT(EBADF, errno);
  close(pipe_fds[1]);
}

static int g_closeUnreadPollReady;

static void* static_closeUnreadClient(void* fd_arg)
{
  int fd = *(const int*)fd_arg;
  static const char head[] = "POST /mcp HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n";
  struct pollfd poll_fd = { .fd = fd, .events = POLLIN };
  g_closeUnreadPollReady = -1;
  if (send(fd, head, sizeof(head) - 1, MSG_NOSIGNAL) == (ssize_t)(sizeof(head) - 1))
    g_closeUnreadPollReady = poll(&poll_fd, 1, 2000);
  close(fd);
  return NULL;
}

void test_connection_drops_a_connection_whose_read_fails(void)
{
  int fds[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  pthread_t client;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&client, NULL, static_closeUnreadClient, &fds[0]));
  ConnectionServeStatus_t serve_status = connection_serveRequest(fds[1], "127.0.0.1", NULL, g_conn);
  TEST_ASSERT_EQUAL_INT(0, pthread_join(client, NULL));
  TEST_ASSERT_EQUAL_INT(1, g_closeUnreadPollReady);
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_DROPPED, serve_status);
}

void test_connection_drops_a_connection_whose_continue_cannot_be_sent(void)
{
  int fds[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  static const char head[] = "POST /mcp HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n";
  TEST_ASSERT_EQUAL_INT((int)(sizeof(head) - 1), (int)send(fds[0], head, sizeof(head) - 1, MSG_NOSIGNAL));
  close(fds[0]);
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_DROPPED, connection_serveRequest(fds[1], "127.0.0.1", NULL, g_conn));
}

void test_connection_sets_both_socket_timeouts(void)
{
  int fds[2];
  TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  int dup_fd = dup(fds[1]);
  TEST_ASSERT_TRUE(dup_fd >= 0);
  static const char text[] = "POST /mcp HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
  TEST_ASSERT_EQUAL_INT((int)strlen(text), (int)send(fds[0], text, strlen(text), MSG_NOSIGNAL));
  TEST_ASSERT_EQUAL_INT(0, shutdown(fds[0], SHUT_WR));
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, connection_serveRequest(fds[1], "127.0.0.1", NULL, g_conn));

  struct timeval timeout = { 0 };
  socklen_t timeout_len = sizeof(timeout);
  TEST_ASSERT_EQUAL_INT(0, getsockopt(dup_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, &timeout_len));
  TEST_ASSERT_EQUAL_INT(CONNECTION_READ_TIMEOUT_SEC, (int)timeout.tv_sec);
  timeout_len = sizeof(timeout);
  TEST_ASSERT_EQUAL_INT(0, getsockopt(dup_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, &timeout_len));
  TEST_ASSERT_EQUAL_INT(CONNECTION_SEND_TIMEOUT_SEC, (int)timeout.tv_sec);
  close(dup_fd);
  close(fds[0]);
}

#define USAGELOG_TEST_INSTANCE_PORT 8002

static char g_usageLines[USAGELOG_DRAIN_BUF_SIZE];

static void static_startUsageLog(void)
{
  usagelog_start(USAGELOG_TEST_INSTANCE_PORT);
  usagelog_drainLines(g_usageLines, sizeof(g_usageLines));
}

static int static_drainUsageLines(void)
{
  usagelog_drainLines(g_usageLines, sizeof(g_usageLines));
  int line_count = 0;
  for (const char* c = g_usageLines; *c != '\0'; c++)
    line_count += *c == '\n';
  return line_count;
}

static void static_serveForUsageLine(const char* text, size_t text_len)
{
  static_startUsageLog();
  const char* parts[1] = { text };
  ClientScript_t script = { -1, parts, 1, 0, true, text_len };
  char buf[RESP_BUF];
  static_serveScript(script, buf, sizeof(buf));
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_drainUsageLines(), g_usageLines);
}

void test_usage_line_of_health_without_a_database(void)
{
  static_serveForUsageLine("GET /health HTTP/1.1\r\n\r\n", 0);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"surface\":\"rest\",\"endpoint\":\"health\",\"endpoint_exists\":true,\"tier\":\"free\",\"status\":503,\"run_status\":\"degraded\",\"duration_ms\":"), g_usageLines);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, ",\"credit_count\":0}\n"), g_usageLines);
}

void test_usage_line_of_a_framing_refusal_names_no_endpoint(void)
{
  static char text[2 * REQUEST_BUFFER_SIZE];
  size_t text_len = static_buildFramingRequest(FRAMING_TOO_MANY_HEADERS, text, sizeof(text));
  static_serveForUsageLine(text, text_len);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"surface\":\"connection\",\"tier\":\"free\",\"status\":431,\"duration_ms\":"), g_usageLines);
  TEST_ASSERT_NULL(strstr(g_usageLines, "\"endpoint\""));
}

void test_usage_line_of_a_connection_closed_before_its_head_ends(void)
{
  static_serveForUsageLine("GET /health HTTP/1.1\r\n", 0);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"surface\":\"connection\",\"tier\":\"free\",\"status\":0,\"duration_ms\":"), g_usageLines);
}

void test_usage_line_of_a_socket_whose_timeouts_cannot_be_set(void)
{
  static_startUsageLog();
  int pipe_fds[2];
  TEST_ASSERT_EQUAL_INT(0, pipe(pipe_fds));
  static const char text[] = "GET /health HTTP/1.1\r\n\r\n";
  TEST_ASSERT_EQUAL_INT((int)strlen(text), (int)write(pipe_fds[1], text, strlen(text)));
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_DROPPED, connection_serveRequest(pipe_fds[0], "127.0.0.1", NULL, g_conn));
  close(pipe_fds[1]);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_drainUsageLines(), g_usageLines);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"surface\":\"connection\",\"tier\":\"free\",\"status\":0,\"duration_ms\":"), g_usageLines);
}

void test_usage_line_of_a_raw_body_busy_answer(void)
{
  rawbody_setThreadCount(0);
  static_startUsageLog();
  char buf[RESP_BUF];
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, static_serveLargeImageRequest(false, buf, sizeof(buf)));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "\"code\":\"raw_body_busy\""), buf);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, static_drainUsageLines(), g_usageLines);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"status\":503,"), g_usageLines);
}

void test_usage_line_of_a_web_file_names_its_whole_path(void)
{
  static_serveForUsageLine("GET /robots.txt HTTP/1.1\r\n\r\n", 0);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"surface\":\"web\",\"endpoint\":\"/robots.txt\",\"endpoint_exists\":true,\"tier\":\"free\",\"status\":200,\"duration_ms\":"), g_usageLines);
}

void test_usage_line_of_an_unknown_path_names_its_first_segment(void)
{
  static_serveForUsageLine("GET /v1/cve_lookup/x HTTP/1.1\r\n\r\n", 0);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"surface\":\"rest\",\"endpoint\":\"v1\",\"endpoint_exists\":false,\"tier\":\"free\",\"status\":404,\"duration_ms\":"), g_usageLines);
}

void test_usage_line_of_a_path_that_fails_the_filter_is_unknown(void)
{
  static_serveForUsageLine("GET /a@b.c/x HTTP/1.1\r\n\r\n", 0);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"surface\":\"rest\",\"endpoint\":\"unknown\",\"endpoint_exists\":false,"), g_usageLines);
  TEST_ASSERT_NULL_MESSAGE(strchr(g_usageLines, '@'), g_usageLines);
}

void test_usage_line_of_a_path_with_two_leading_slashes(void)
{
  static_serveForUsageLine("GET //old_api/x HTTP/1.1\r\n\r\n", 0);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"surface\":\"rest\",\"endpoint\":\"old_api\",\"endpoint_exists\":false,"), g_usageLines);
}

void test_usage_line_of_a_malformed_key_is_pro_refused(void)
{
  static_serveForUsageLine("GET /health HTTP/1.1\r\nX-API-Key: contrastapi_abc\r\n\r\n", 0);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"surface\":\"rest\",\"endpoint\":\"health\",\"endpoint_exists\":true,\"tier\":\"pro_refused\",\"status\":401,\"duration_ms\":"), g_usageLines);
}

void test_usage_line_of_a_key_that_cannot_be_checked_is_free(void)
{
  static_serveForUsageLine("GET /health HTTP/1.1\r\nX-API-Key: " VALID_KEY "\r\n\r\n", 0);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"surface\":\"rest\",\"endpoint\":\"health\",\"endpoint_exists\":true,\"tier\":\"free\",\"status\":503,"), g_usageLines);
}

#define MCP_TOOLS_LIST_BODY "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"

void test_usage_line_of_mcp_without_a_database_names_the_row(void)
{
  char text[256];
  int text_len = snprintf(text, sizeof(text), "POST /mcp HTTP/1.1\r\nContent-Length: %zu\r\n\r\n" MCP_TOOLS_LIST_BODY, strlen(MCP_TOOLS_LIST_BODY));
  TEST_ASSERT_TRUE(text_len > 0 && (size_t)text_len < sizeof(text));
  static_serveForUsageLine(text, 0);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(g_usageLines, "\"surface\":\"mcp\",\"endpoint\":\"mcp\",\"endpoint_exists\":true,\"tier\":\"free\",\"status\":500,\"duration_ms\":"), g_usageLines);
}

#define TEST_SMALL_RAW_LIMIT 100

typedef struct {
  EndpointByteSpan_t m_bytes;
} TestRawParams_t;

static EndpointRunStatus_t static_runRawLength(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)conn;
  (void)message_out;
  jsonbuf_appendFormat(json_buf, "{\"byte_count\":%zu}", ((const TestRawParams_t*)params)->m_bytes.m_byteCount);
  return ENDPOINT_RUN_OK;
}

static const EndpointParamSpec_t TEST_SPEC_SMALL_RAW     = { .mp_name = "body", .m_type = ENDPOINT_PARAM_TYPE_BYTES, .m_maxLen = TEST_SMALL_RAW_LIMIT };
static const EndpointParamSpec_t TEST_SPEC_THRESHOLD_RAW = { .mp_name = "body", .m_type = ENDPOINT_PARAM_TYPE_BYTES, .m_maxLen = ENDPOINT_SMALL_RAW_BODY_MAX_BYTE_COUNT };
static const EndpointParamSpec_t TEST_SPEC_LARGE_RAW     = { .mp_name = "body", .m_type = ENDPOINT_PARAM_TYPE_BYTES, .m_maxLen = ENDPOINT_SMALL_RAW_BODY_MAX_BYTE_COUNT + 1 };

#define TEST_RAW_PARAM(spec) \
  { .mp_spec = (spec), .m_sources = ENDPOINT_PARAM_SRC_REST_RAW_BODY, .m_isRequired = true, .m_offset = offsetof(TestRawParams_t, m_bytes), .m_size = sizeof(EndpointByteSpan_t) }

static const EndpointParam_t TEST_SMALL_RAW_PARAMS[]     = { TEST_RAW_PARAM(&TEST_SPEC_SMALL_RAW) };
static const EndpointParam_t TEST_THRESHOLD_RAW_PARAMS[] = { TEST_RAW_PARAM(&TEST_SPEC_THRESHOLD_RAW) };
static const EndpointParam_t TEST_LARGE_RAW_PARAMS[]     = { TEST_RAW_PARAM(&TEST_SPEC_LARGE_RAW) };

#define TEST_RAW_ROW(path, params) \
  { .mp_httpPath = (path), .ma_allowedMethods = {"POST", NULL}, .m_creditCost = 0, .m_costRule = ENDPOINT_COST_FLAT, \
    .mp_params = (params), .m_paramCount = 1, .m_paramsSize = sizeof(TestRawParams_t), .m_runFunction = static_runRawLength, \
    .m_jsonCeiling = JSONBUF_DEFAULT_CEILING }

static const Endpoint_t TEST_RAW_ROWS[] = {
  TEST_RAW_ROW("/test_small_raw",     TEST_SMALL_RAW_PARAMS),
  TEST_RAW_ROW("/test_threshold_raw", TEST_THRESHOLD_RAW_PARAMS),
  TEST_RAW_ROW("/test_large_raw",     TEST_LARGE_RAW_PARAMS),
};

typedef struct {
  EndpointByteSpan_t m_bytes;
  char               ma_signature[17];
} TestSignedRawParams_t;

static EndpointRunStatus_t static_runSignedRaw(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)conn;
  (void)message_out;
  jsonbuf_appendFormat(json_buf, "{\"signature\":\"");
  jsonbuf_appendEscaped(json_buf, ((const TestSignedRawParams_t*)params)->ma_signature);
  jsonbuf_appendFormat(json_buf, "\"}");
  return ENDPOINT_RUN_OK;
}

static const EndpointParamSpec_t TEST_SPEC_SIGNATURE = { .mp_name = "X-Signature", .m_type = ENDPOINT_PARAM_TYPE_STRING, .m_maxLen = 16 };

static const EndpointParam_t TEST_SIGNED_RAW_PARAMS[] = {
  { .mp_spec = &TEST_SPEC_SMALL_RAW, .m_sources = ENDPOINT_PARAM_SRC_REST_RAW_BODY, .m_isRequired = true, .m_offset = offsetof(TestSignedRawParams_t, m_bytes), .m_size = sizeof(EndpointByteSpan_t) },
  { .mp_spec = &TEST_SPEC_SIGNATURE, .m_sources = ENDPOINT_PARAM_SRC_REST_HEADER,   .m_isRequired = true, .m_offset = offsetof(TestSignedRawParams_t, ma_signature), .m_size = 17 },
};

static const Endpoint_t TEST_SIGNED_RAW_ROW = {
  .mp_httpPath          = "/test_signed_raw",
  .ma_allowedMethods    = {"POST", NULL},
  .m_creditCost         = 0,
  .m_costRule           = ENDPOINT_COST_FLAT,
  .mp_params            = TEST_SIGNED_RAW_PARAMS,
  .m_paramCount         = 2,
  .m_paramsSize         = sizeof(TestSignedRawParams_t),
  .m_runFunction        = static_runSignedRaw,
  .m_callsUpstream      = true,
  .m_jsonCeiling        = JSONBUF_DEFAULT_CEILING,
};

const Endpoint_t* __real_endpoint_findByHttpPath(const char* path, const char** path_segment_out);
const Endpoint_t* __wrap_endpoint_findByHttpPath(const char* path, const char** path_segment_out);

const Endpoint_t* __wrap_endpoint_findByHttpPath(const char* path, const char** path_segment_out)
{
  for (size_t i = 0; i < sizeof(TEST_RAW_ROWS) / sizeof(TEST_RAW_ROWS[0]); i++)
  {
    if (strcmp(path, TEST_RAW_ROWS[i].mp_httpPath) == 0)
    {
      if (path_segment_out != NULL)
        *path_segment_out = NULL;
      return &TEST_RAW_ROWS[i];
    }
  }
  if (strcmp(path, TEST_SIGNED_RAW_ROW.mp_httpPath) == 0)
  {
    if (path_segment_out != NULL)
      *path_segment_out = NULL;
    return &TEST_SIGNED_RAW_ROW;
  }
  return __real_endpoint_findByHttpPath(path, path_segment_out);
}

static void static_serveRawPost(const char* path, size_t body_len, char* buf, size_t len)
{
  static char text[512];
  int head_len = snprintf(text, sizeof(text), "POST %s HTTP/1.1\r\nContent-Length: %zu\r\n\r\n", path, body_len);
  TEST_ASSERT_TRUE(head_len > 0 && (size_t)head_len + body_len < sizeof(text));
  memset(text + head_len, 'a', body_len);
  const char* parts[1] = { text };
  ClientScript_t script = { -1, parts, 1, 0, true, (size_t)head_len + body_len };
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, static_serveScript(script, buf, len));
}

void test_connection_serves_a_raw_body_at_its_row_limit_and_refuses_one_byte_more(void)
{
  rawbody_setThreadCount(1);
  char buf[RESP_BUF];
  static_serveRawPost("/test_small_raw", TEST_SMALL_RAW_LIMIT, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 200 "), buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "{\"byte_count\":100}"), buf);

  static_serveRawPost("/test_small_raw", TEST_SMALL_RAW_LIMIT + 1, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 413 "), buf);
}

void test_connection_takes_a_raw_body_place_only_for_a_large_raw_row(void)
{
  rawbody_setThreadCount(0);
  char buf[RESP_BUF];
  static_serveRawPost("/test_small_raw", 10, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 200 "), buf);

  static_serveRawPost("/test_threshold_raw", 10, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 200 "), buf);

  static_serveRawPost("/test_large_raw", 10, buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 503 "), buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "\"code\":\"raw_body_busy\""), buf);
}

static void static_serveSignedPost(const char* header_lines, char* buf, size_t len)
{
  static char text[512];
  int text_len = snprintf(text, sizeof(text), "POST /test_signed_raw HTTP/1.1\r\nContent-Length: 3\r\n%s\r\nabc", header_lines);
  TEST_ASSERT_TRUE(text_len > 0 && (size_t)text_len < sizeof(text));
  const char* parts[1] = { text };
  ClientScript_t script = { -1, parts, 1, 0, true, (size_t)text_len };
  TEST_ASSERT_EQUAL_INT(CONNECTION_SERVE_HANDLED, static_serveScript(script, buf, len));
}

void test_connection_reads_a_header_param_for_pricing_and_serving(void)
{
  char buf[RESP_BUF];
  upstream_setThreadCount(0);
  static_serveSignedPost("X-Signature: abc\r\n", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 503 "), buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "\"code\":\"upstream_busy\""), buf);

  static_serveSignedPost("", buf, sizeof(buf));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 400 "), buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "X-Signature is required"), buf);

  upstream_setThreadCount(1);
  static_serveSignedPost("x-signature: abc\r\n", buf, sizeof(buf));
  upstream_setThreadCount(0);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "HTTP/1.1 200 "), buf);
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(buf, "{\"signature\":\"abc\"}"), buf);
}

int main(void)
{
  if (!pages_init(endpoint_mcpToolCount()))
    return 1;

  UNITY_BEGIN();

  RUN_TEST(test_valid_key_no_db_free_path_is_served);
  RUN_TEST(test_bearer_valid_format_no_db_free_path_is_served);
  RUN_TEST(test_valid_key_no_db_paid_path_returns_500_not_401);

  RUN_TEST(test_request_line_only_no_headers_reaches_router);

  RUN_TEST(test_CVELOOKUP_valid_format_no_db_returns_500);
  RUN_TEST(test_CVESEARCH_no_db_returns_500);
  RUN_TEST(test_web_file_is_served_without_a_database);
  RUN_TEST(test_missing_static_file_without_a_database_returns_404);
  RUN_TEST(test_POST_method_returns_405);

  RUN_TEST(test_mcp_era_does_not_carry_over_to_the_next_request);
  RUN_TEST(test_response_sendMethodNotAllowed405_includes_allow_header);
  RUN_TEST(test_head_request_gets_its_405_without_a_body);
  RUN_TEST(test_head_mark_does_not_carry_over_to_the_next_request);

  RUN_TEST(test_overlong_request_target_returns_414);
  RUN_TEST(test_request_target_one_over_limit_returns_414);
  RUN_TEST(test_request_target_at_limit_is_not_rejected_for_length);
  RUN_TEST(test_full_filter_cves_query_is_no_longer_dropped);
  RUN_TEST(test_overlong_target_answered_before_auth);

  RUN_TEST(test_connection_answers_a_head_sent_in_parts);
  RUN_TEST(test_connection_answers_a_head_that_fills_the_buffer);
  RUN_TEST(test_connection_closes_a_connection_whose_head_never_ends);
  RUN_TEST(test_connection_drops_a_method_longer_than_seven_bytes);
  RUN_TEST(test_connection_answers_414_for_a_whole_head_whose_target_is_too_long);

  RUN_TEST(test_connection_answers_each_framing_refusal);
  RUN_TEST(test_connection_closes_a_malformed_head_without_an_answer);
  RUN_TEST(test_connection_framing_answer_carries_no_rate_limit_headers);
  RUN_TEST(test_connection_refuses_a_body_whose_last_byte_is_a_nul);
  RUN_TEST(test_connection_refuses_a_nul_body_on_a_path_no_row_serves);
  RUN_TEST(test_connection_reads_the_refused_body_before_it_closes);
  RUN_TEST(test_connection_answers_503_when_every_raw_body_thread_is_in_use);
  RUN_TEST(test_connection_takes_a_raw_body_place_for_an_image_that_fits_the_read_buffer);
  RUN_TEST(test_connection_reads_a_body_that_fills_the_buffer_and_refuses_one_byte_more);
  RUN_TEST(test_connection_clears_the_read_buffer_before_it_returns);
  RUN_TEST(test_connection_gives_the_raw_body_thread_back_after_each_answer);
  RUN_TEST(test_connection_reads_the_body_away_after_a_busy_503);
  RUN_TEST(test_connection_reads_an_image_body_larger_than_the_read_buffer);
  RUN_TEST(test_connection_reads_a_large_json_body_into_a_mapping_without_a_raw_body_place);
  RUN_TEST(test_connection_answers_413_without_taking_a_raw_body_place);
  RUN_TEST(test_connection_answers_a_framing_refusal_on_the_raw_body_row_without_a_place);
  RUN_TEST(test_connection_drops_a_socket_whose_timeouts_cannot_be_set);
  RUN_TEST(test_connection_drops_a_connection_whose_read_fails);
  RUN_TEST(test_connection_drops_a_connection_whose_continue_cannot_be_sent);
  RUN_TEST(test_connection_sets_both_socket_timeouts);

  RUN_TEST(test_usage_line_of_health_without_a_database);
  RUN_TEST(test_usage_line_of_a_framing_refusal_names_no_endpoint);
  RUN_TEST(test_usage_line_of_a_connection_closed_before_its_head_ends);
  RUN_TEST(test_usage_line_of_a_socket_whose_timeouts_cannot_be_set);
  RUN_TEST(test_usage_line_of_a_raw_body_busy_answer);
  RUN_TEST(test_usage_line_of_a_web_file_names_its_whole_path);
  RUN_TEST(test_usage_line_of_an_unknown_path_names_its_first_segment);
  RUN_TEST(test_usage_line_of_a_path_that_fails_the_filter_is_unknown);
  RUN_TEST(test_usage_line_of_a_path_with_two_leading_slashes);
  RUN_TEST(test_usage_line_of_a_malformed_key_is_pro_refused);
  RUN_TEST(test_usage_line_of_a_key_that_cannot_be_checked_is_free);
  RUN_TEST(test_usage_line_of_mcp_without_a_database_names_the_row);
  RUN_TEST(test_connection_serves_a_raw_body_at_its_row_limit_and_refuses_one_byte_more);
  RUN_TEST(test_connection_takes_a_raw_body_place_only_for_a_large_raw_row);
  RUN_TEST(test_connection_reads_a_header_param_for_pricing_and_serving);

  return UNITY_END();
}
