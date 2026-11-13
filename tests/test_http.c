#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <curl/curl.h>
#include "unity/unity.h"
#include "http.h"

CURLcode __real_curl_easy_setopt(CURL* curl, CURLoption option, ...);
CURLcode __wrap_curl_easy_setopt(CURL* curl, CURLoption option, ...);
CURLcode __real_curl_easy_perform(CURL* curl);
CURLcode __wrap_curl_easy_perform(CURL* curl);
struct curl_slist* __real_curl_slist_append(struct curl_slist* list, const char* data);
struct curl_slist* __wrap_curl_slist_append(struct curl_slist* list, const char* data);
CURLHcode __real_curl_easy_header(CURL* easy, const char* name, size_t index, unsigned int origin, int request, struct curl_header** hout);
CURLHcode __wrap_curl_easy_header(CURL* easy, const char* name, size_t index, unsigned int origin, int request, struct curl_header** hout);
char* __real_strdup(const char* text);
char* __wrap_strdup(const char* text);
void* __real_calloc(size_t count, size_t size);
void* __wrap_calloc(size_t count, size_t size);
void* __real_realloc(void* block, size_t size);
void* __wrap_realloc(void* block, size_t size);
bool __real_ipguard_isGloballyReachableSockaddr(const struct sockaddr* address, socklen_t address_len);
bool __wrap_ipguard_isGloballyReachableSockaddr(const struct sockaddr* address, socklen_t address_len);

typedef union {
  struct curl_sockaddr m_address;
  unsigned char        ma_storage[sizeof(struct curl_sockaddr) + sizeof(struct sockaddr_in6)];
  unsigned char        ma_unixStorage[sizeof(struct curl_sockaddr) + sizeof(struct sockaddr_un)];
} TestCurlSockaddr_t;

static const char*              g_url;
static const char*              g_protocolsStr;
static const char*              g_redirProtocolsStr;
static long                     g_connectTimeoutMs;
static char                     g_firstHeader[256];
static char                     g_secondHeader[256];
static int                      g_headerCount;
static long                     g_timeoutMs;
static long                     g_followLocation;
static long                     g_maxRedirs;
static long                     g_noSignal;
static long                     g_quickExit;
static const char*              g_proxy;
static const char*              g_userAgent;
static const void*              g_postFields;
static curl_off_t               g_postFieldSize;
static const char*              g_unixSocketPath;
static curl_write_callback      g_writeFunction;
static void*                    g_writeData;
static curl_opensocket_callback g_openSocketFunction;
static void*                    g_openSocketData;
static CURLoption               g_setoptFailOption;
static bool                     g_isTransferFaked;
static CURLcode                 g_performResult;
static size_t                   g_driveBodyLen;
static const char*              g_driveBodyText;
static size_t                   g_drivePieceLen;
static TestCurlSockaddr_t       g_driveAddresses[2];
static size_t                   g_driveAddressCount;
static bool                     g_isDrivenSocketOpen[2];
static int                      g_performCount;
static int                      g_slistAppendCount;
static int                      g_slistAppendFailCall;
static int                      g_headerLookupCount;
static int                      g_headerResult;
static const char*              g_fakeHeaderName;
static char                     g_fakeHeaderValue[64];
static size_t                   g_fakeHeaderCopyCount;
static char                     g_fakeHeaderCopyValue[32];
static int                      g_headerFailIndex;
static struct curl_header       g_fakeHeader;
static bool                     g_isHeaderLookupReal;
static int                      g_strdupCount;
static int                      g_strdupFailCall;
static bool                     g_callocFails;
static bool                     g_reallocFails;
static int                      g_socketCheckCount;
static bool                     g_isLoopbackAllowed;

CURLcode __wrap_curl_easy_setopt(CURL* curl, CURLoption option, ...)
{
  va_list args;
  va_start(args, option);
  CURLcode result;
  if (option == CURLOPT_WRITEFUNCTION)
  {
    curl_write_callback value = va_arg(args, curl_write_callback);
    g_writeFunction = value;
    result = __real_curl_easy_setopt(curl, option, value);
  }
  else if (option == CURLOPT_OPENSOCKETFUNCTION)
  {
    curl_opensocket_callback value = va_arg(args, curl_opensocket_callback);
    g_openSocketFunction = value;
    result = __real_curl_easy_setopt(curl, option, value);
  }
  else if (option < CURLOPTTYPE_OBJECTPOINT)
  {
    long value = va_arg(args, long);
    if (option == CURLOPT_CONNECTTIMEOUT_MS)
      g_connectTimeoutMs = value;
    else if (option == CURLOPT_TIMEOUT_MS)
      g_timeoutMs = value;
    else if (option == CURLOPT_FOLLOWLOCATION)
      g_followLocation = value;
    else if (option == CURLOPT_MAXREDIRS)
      g_maxRedirs = value;
    else if (option == CURLOPT_NOSIGNAL)
      g_noSignal = value;
    else if (option == CURLOPT_QUICK_EXIT)
      g_quickExit = value;
    result = __real_curl_easy_setopt(curl, option, value);
  }
  else if (option < CURLOPTTYPE_OFF_T)
  {
    void* value = va_arg(args, void*);
    if (option == CURLOPT_URL)
      g_url = value;
    else if (option == CURLOPT_PROTOCOLS_STR)
      g_protocolsStr = value;
    else if (option == CURLOPT_REDIR_PROTOCOLS_STR)
      g_redirProtocolsStr = value;
    else if (option == CURLOPT_PROXY)
      g_proxy = value;
    else if (option == CURLOPT_USERAGENT)
      g_userAgent = value;
    else if (option == CURLOPT_WRITEDATA)
      g_writeData = value;
    else if (option == CURLOPT_OPENSOCKETDATA)
      g_openSocketData = value;
    else if (option == CURLOPT_POSTFIELDS)
      g_postFields = value;
    else if (option == CURLOPT_UNIX_SOCKET_PATH)
      g_unixSocketPath = value;
    else if (option == CURLOPT_HTTPHEADER)
    {
      const struct curl_slist* header = value;
      g_headerCount = 0;
      snprintf(g_firstHeader, sizeof(g_firstHeader), "%s", header ? header->data : "");
      snprintf(g_secondHeader, sizeof(g_secondHeader), "%s", header && header->next ? header->next->data : "");
      for (; header != NULL; header = header->next)
        g_headerCount++;
    }
    result = __real_curl_easy_setopt(curl, option, value);
  }
  else if (option < CURLOPTTYPE_BLOB)
  {
    curl_off_t value = va_arg(args, curl_off_t);
    if (option == CURLOPT_POSTFIELDSIZE_LARGE)
      g_postFieldSize = value;
    result = __real_curl_easy_setopt(curl, option, value);
  }
  else
  {
    void* value = va_arg(args, void*);
    result = __real_curl_easy_setopt(curl, option, value);
  }
  va_end(args);
  if (option == g_setoptFailOption)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  return result;
}

CURLcode __wrap_curl_easy_perform(CURL* curl)
{
  g_performCount++;
  if (!g_isTransferFaked)
    return __real_curl_easy_perform(curl);

  for (size_t i = 0; i < g_driveAddressCount; i++)
  {
    TEST_ASSERT_NOT_NULL(g_openSocketFunction);
    curl_socket_t fd = g_openSocketFunction(g_openSocketData, CURLSOCKTYPE_IPCXN, &g_driveAddresses[i].m_address);
    g_isDrivenSocketOpen[i] = fd != CURL_SOCKET_BAD;
    if (fd != CURL_SOCKET_BAD)
      close(fd);
  }

  if (g_driveBodyLen > 0)
  {
    char* body = malloc(g_driveBodyLen);
    TEST_ASSERT_NOT_NULL(body);
    if (g_driveBodyText)
      memcpy(body, g_driveBodyText, g_driveBodyLen);
    else
      memset(body, 'b', g_driveBodyLen);
    for (size_t offset = 0; offset < g_driveBodyLen; offset += g_drivePieceLen)
    {
      size_t piece_len = g_driveBodyLen - offset < g_drivePieceLen ? g_driveBodyLen - offset : g_drivePieceLen;
      if (g_writeFunction(body + offset, 1, piece_len, g_writeData) != piece_len)
      {
        free(body);
        return CURLE_WRITE_ERROR;
      }
    }
    free(body);
  }
  return g_performResult;
}

struct curl_slist* __wrap_curl_slist_append(struct curl_slist* list, const char* data)
{
  g_slistAppendCount++;
  if (g_slistAppendCount == g_slistAppendFailCall)
    return NULL;
  return __real_curl_slist_append(list, data);
}

CURLHcode __wrap_curl_easy_header(CURL* easy, const char* name, size_t index, unsigned int origin, int request, struct curl_header** hout)
{
  g_headerLookupCount++;
  if (g_isHeaderLookupReal)
    return __real_curl_easy_header(easy, name, index, origin, request, hout);
  if (g_headerResult >= 0)
    return (CURLHcode)g_headerResult;
  if (!g_fakeHeaderName || strcasecmp(name, g_fakeHeaderName) != 0)
    return CURLHE_MISSING;
  if ((int)index == g_headerFailIndex)
    return CURLHE_OUT_OF_MEMORY;
  if (index >= g_fakeHeaderCopyCount)
    return CURLHE_BADINDEX;
  TEST_ASSERT_EQUAL_UINT(CURLH_HEADER, origin);
  TEST_ASSERT_EQUAL_INT(-1, request);
  snprintf(g_fakeHeaderCopyValue, sizeof(g_fakeHeaderCopyValue), "c%zu", index);
  g_fakeHeader.name   = (char*)g_fakeHeaderName;
  g_fakeHeader.value  = index == 0 ? g_fakeHeaderValue : g_fakeHeaderCopyValue;
  g_fakeHeader.amount = g_fakeHeaderCopyCount;
  g_fakeHeader.index  = index;
  *hout = &g_fakeHeader;
  return CURLHE_OK;
}

char* __wrap_strdup(const char* text)
{
  g_strdupCount++;
  if (g_strdupCount == g_strdupFailCall)
    return NULL;
  return __real_strdup(text);
}

void* __wrap_calloc(size_t count, size_t size)
{
  if (g_callocFails)
    return NULL;
  return __real_calloc(count, size);
}

void* __wrap_realloc(void* block, size_t size)
{
  if (g_reallocFails)
    return NULL;
  return __real_realloc(block, size);
}

bool __wrap_ipguard_isGloballyReachableSockaddr(const struct sockaddr* address, socklen_t address_len)
{
  g_socketCheckCount++;
  if (g_isLoopbackAllowed && address->sa_family == AF_INET && ((const struct sockaddr_in*)address)->sin_addr.s_addr == htonl(INADDR_LOOPBACK))
    return true;
  return __real_ipguard_isGloballyReachableSockaddr(address, address_len);
}

void setUp(void)
{
  g_url                 = NULL;
  g_protocolsStr        = NULL;
  g_redirProtocolsStr   = NULL;
  g_connectTimeoutMs    = 0;
  g_firstHeader[0]      = '\0';
  g_secondHeader[0]     = '\0';
  g_headerCount         = 0;
  g_timeoutMs           = -1;
  g_followLocation      = -1;
  g_maxRedirs           = -1;
  g_noSignal            = -1;
  g_quickExit           = -1;
  g_proxy               = NULL;
  g_userAgent           = NULL;
  g_postFields          = NULL;
  g_postFieldSize       = -1;
  g_unixSocketPath      = NULL;
  g_writeFunction       = NULL;
  g_writeData           = NULL;
  g_openSocketFunction  = NULL;
  g_openSocketData      = NULL;
  g_setoptFailOption    = (CURLoption)0;
  g_isTransferFaked     = true;
  g_performResult       = CURLE_COULDNT_CONNECT;
  g_driveBodyLen        = 0;
  g_driveBodyText       = NULL;
  g_drivePieceLen       = 10;
  g_driveAddressCount   = 0;
  g_isDrivenSocketOpen[0] = false;
  g_isDrivenSocketOpen[1] = false;
  g_performCount        = 0;
  g_slistAppendCount    = 0;
  g_slistAppendFailCall = 0;
  g_headerLookupCount   = 0;
  g_headerResult        = -1;
  g_fakeHeaderName      = NULL;
  g_fakeHeaderValue[0]  = '\0';
  g_fakeHeaderCopyCount = 1;
  g_headerFailIndex     = -1;
  g_isHeaderLookupReal  = false;
  g_strdupCount         = 0;
  g_strdupFailCall      = 0;
  g_callocFails         = false;
  g_reallocFails        = false;
  g_socketCheckCount    = 0;
  g_isLoopbackAllowed   = false;
}

void tearDown(void) {}

static void static_addDriveAddressOnPort(const char* ip_text, uint16_t port)
{
  TEST_ASSERT_TRUE(g_driveAddressCount < sizeof(g_driveAddresses) / sizeof(g_driveAddresses[0]));
  TestCurlSockaddr_t* drive_address = &g_driveAddresses[g_driveAddressCount++];
  memset(drive_address, 0, sizeof(*drive_address));
  drive_address->m_address.socktype = SOCK_STREAM;
  drive_address->m_address.protocol = IPPROTO_TCP;
  if (strchr(ip_text, ':'))
  {
    struct sockaddr_in6 address = { .sin6_family = AF_INET6, .sin6_port = htons(port) };
    TEST_ASSERT_EQUAL_INT(1, inet_pton(AF_INET6, ip_text, &address.sin6_addr));
    drive_address->m_address.family  = AF_INET6;
    drive_address->m_address.addrlen = sizeof(address);
    memcpy(&drive_address->m_address.addr, &address, sizeof(address));
  }
  else
  {
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons(port) };
    TEST_ASSERT_EQUAL_INT(1, inet_pton(AF_INET, ip_text, &address.sin_addr));
    drive_address->m_address.family  = AF_INET;
    drive_address->m_address.addrlen = sizeof(address);
    memcpy(&drive_address->m_address.addr, &address, sizeof(address));
  }
}

static void static_addDriveAddress(const char* ip_text)
{
  static_addDriveAddressOnPort(ip_text, 0);
}

typedef struct {
  int                m_listenFd;
  int                m_port;
  const char* const* mp_answers;
  size_t             m_answerCount;
  int                m_requestCount;
} TestServer_t;

static void static_listenOnLoopback(TestServer_t* server)
{
  server->m_listenFd = socket(AF_INET, SOCK_STREAM, 0);
  TEST_ASSERT_TRUE(server->m_listenFd >= 0);
  struct timeval accept_timeout = { .tv_sec = 5 };
  TEST_ASSERT_EQUAL_INT(0, setsockopt(server->m_listenFd, SOL_SOCKET, SO_RCVTIMEO, &accept_timeout, sizeof(accept_timeout)));
  struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
  TEST_ASSERT_EQUAL_INT(0, bind(server->m_listenFd, (const struct sockaddr*)&address, sizeof(address)));
  TEST_ASSERT_EQUAL_INT(0, listen(server->m_listenFd, 4));
  socklen_t address_len = sizeof(address);
  TEST_ASSERT_EQUAL_INT(0, getsockname(server->m_listenFd, (struct sockaddr*)&address, &address_len));
  server->m_port         = ntohs(address.sin_port);
  server->m_requestCount = 0;
}

static void* static_answerRequests(void* arg)
{
  TestServer_t* server = arg;
  for (size_t i = 0; i < server->m_answerCount; i++)
  {
    int connection = accept(server->m_listenFd, NULL, NULL);
    if (connection < 0)
      return NULL;
    char   request[4096];
    size_t request_len = 0;
    while (request_len < sizeof(request) - 1)
    {
      ssize_t received = recv(connection, request + request_len, sizeof(request) - 1 - request_len, 0);
      if (received <= 0)
        break;
      request_len += (size_t)received;
      request[request_len] = '\0';
      if (strstr(request, "\r\n\r\n"))
        break;
    }
    server->m_requestCount++;
    (void)send(connection, server->mp_answers[i], strlen(server->mp_answers[i]), MSG_NOSIGNAL);
    close(connection);
  }
  return NULL;
}

static int static_findClosedLoopbackPort(void)
{
  TestServer_t server;
  static_listenOnLoopback(&server);
  close(server.m_listenFd);
  return server.m_port;
}

void test_http_free_null_body(void)
{
  HttpResponse_t resp = { .m_status = 0, .mp_body = NULL, .m_bodyLen = 0 };
  http_free(&resp);
  TEST_ASSERT_NULL(resp.mp_body);
  TEST_ASSERT_EQUAL_INT(0, resp.m_status);
}

void test_http_free_null_ptr(void)
{
  http_free(NULL);
}

void test_upstream_request_is_https_only_with_a_connect_timeout(void)
{
  HttpResponse_t resp = http_GET("https://example.invalid/", 3000, NULL);
  TEST_ASSERT_EQUAL_STRING("https", g_protocolsStr);
  TEST_ASSERT_EQUAL_STRING("https", g_redirProtocolsStr);
  TEST_ASSERT_EQUAL_INT32(HTTP_CONNECT_TIMEOUT_MS, g_connectTimeoutMs);
  TEST_ASSERT_TRUE(HTTP_CONNECT_TIMEOUT_MS < 3000);
  TEST_ASSERT_EQUAL_INT(0, resp.m_status);
  http_free(&resp);

  setUp();
  resp = http_GET("https://example.invalid/", 3000, "Authorization: Bearer t");
  TEST_ASSERT_EQUAL_STRING("https", g_protocolsStr);
  TEST_ASSERT_EQUAL_STRING("https", g_redirProtocolsStr);
  TEST_ASSERT_EQUAL_INT32(HTTP_CONNECT_TIMEOUT_MS, g_connectTimeoutMs);
  http_free(&resp);
}

void test_extra_header_is_handed_to_libcurl(void)
{
  HttpResponse_t resp = http_GET("https://example.invalid/", 3000, "Authorization: Bearer t");
  TEST_ASSERT_EQUAL_INT(1, g_headerCount);
  TEST_ASSERT_EQUAL_STRING("Authorization: Bearer t", g_firstHeader);
  http_free(&resp);

  setUp();
  resp = http_GET("https://example.invalid/", 3000, NULL);
  TEST_ASSERT_EQUAL_INT(0, g_headerCount);
  http_free(&resp);
}

void test_request_timeout_and_redirect_bound_reach_libcurl(void)
{
  HttpResponse_t resp = http_GET("https://example.invalid/", 3000, NULL);
  TEST_ASSERT_EQUAL_STRING("https://example.invalid/", g_url);
  TEST_ASSERT_EQUAL_INT32(3000, g_timeoutMs);
  TEST_ASSERT_EQUAL_INT32(1, g_followLocation);
  TEST_ASSERT_EQUAL_INT32(5, g_maxRedirs);
  TEST_ASSERT_EQUAL_INT32(1, g_noSignal);
  TEST_ASSERT_EQUAL_INT32(1, g_quickExit);
  http_free(&resp);
}

void test_request_whose_header_cannot_be_added_is_not_sent(void)
{
  g_slistAppendFailCall = 1;
  HttpResponse_t resp = http_GET("https://example.invalid/", 3000, "Authorization: Bearer t");
  TEST_ASSERT_EQUAL_INT(0, g_performCount);
  TEST_ASSERT_EQUAL_INT(0, resp.m_status);
  TEST_ASSERT_NULL(resp.mp_body);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  http_free(&resp);
}

void test_file_url_is_refused(void)
{
  char path[] = "/tmp/test_http_XXXXXX";
  int fd = mkstemp(path);
  TEST_ASSERT_TRUE(fd >= 0);
  TEST_ASSERT_EQUAL_INT(5, (int)write(fd, "local", 5));
  close(fd);
  char url[64];
  TEST_ASSERT_TRUE(snprintf(url, sizeof(url), "file://%s", path) < (int)sizeof(url));

  g_isTransferFaked = false;
  HttpResponse_t resp = http_GET(url, 1000, NULL);
  unlink(path);

  TEST_ASSERT_EQUAL_INT(0, resp.m_status);
  TEST_ASSERT_NULL(resp.mp_body);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  http_free(&resp);
}

void test_every_request_ignores_proxies_and_names_the_bot_page(void)
{
  TEST_ASSERT_EQUAL_STRING("ContrastAPI/1.0.0 (+https://api.contrastcyber.com/bot; contact@contrastcyber.com)", HTTP_USER_AGENT);

  HttpResponse_t resp = http_GET("https://example.invalid/", 3000, NULL);
  TEST_ASSERT_NOT_NULL(g_proxy);
  TEST_ASSERT_EQUAL_STRING("", g_proxy);
  TEST_ASSERT_EQUAL_STRING(HTTP_USER_AGENT, g_userAgent);
  http_free(&resp);

  setUp();
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000 };
  resp = http_GETWithOptions(&request);
  TEST_ASSERT_NOT_NULL(g_proxy);
  TEST_ASSERT_EQUAL_STRING("", g_proxy);
  TEST_ASSERT_EQUAL_STRING(HTTP_USER_AGENT, g_userAgent);
  http_free(&resp);
}

void test_request_whose_option_cannot_be_set_is_not_sent(void)
{
  static const struct { CURLoption m_option; const char* mp_name; } options[] = {
    { CURLOPT_URL,               "URL"               },
    { CURLOPT_WRITEFUNCTION,     "WRITEFUNCTION"     },
    { CURLOPT_WRITEDATA,         "WRITEDATA"         },
    { CURLOPT_TIMEOUT_MS,        "TIMEOUT_MS"        },
    { CURLOPT_FOLLOWLOCATION,    "FOLLOWLOCATION"    },
    { CURLOPT_USERAGENT,         "USERAGENT"         },
    { CURLOPT_HTTPHEADER,        "HTTPHEADER"        },
    { CURLOPT_NOSIGNAL,          "NOSIGNAL"          },
    { CURLOPT_QUICK_EXIT,        "QUICK_EXIT"        },
    { CURLOPT_PROTOCOLS_STR,     "PROTOCOLS_STR"     },
    { CURLOPT_REDIR_PROTOCOLS_STR, "REDIR_PROTOCOLS_STR" },
    { CURLOPT_MAXREDIRS,         "MAXREDIRS"         },
    { CURLOPT_CONNECTTIMEOUT_MS, "CONNECTTIMEOUT_MS" },
    { CURLOPT_PROXY,             "PROXY"             },
    { CURLOPT_OPENSOCKETFUNCTION, "OPENSOCKETFUNCTION" },
    { CURLOPT_OPENSOCKETDATA,    "OPENSOCKETDATA"    },
  };
  for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++)
  {
    setUp();
    g_setoptFailOption  = options[i].m_option;
    HttpResponse_t resp = http_GET("https://example.invalid/", 3000, "Authorization: Bearer t");
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_performCount, options[i].mp_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HTTP_ERROR_OTHER, resp.m_error, options[i].mp_name);
    TEST_ASSERT_NULL_MESSAGE(resp.mp_body, options[i].mp_name);
    http_free(&resp);
  }
}

void test_untrusted_request_whose_socket_check_cannot_be_set_is_not_sent(void)
{
  const CURLoption options[] = { CURLOPT_OPENSOCKETFUNCTION, CURLOPT_OPENSOCKETDATA };
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000 };
  for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++)
  {
    setUp();
    g_setoptFailOption  = options[i];
    HttpResponse_t resp = http_GETWithOptions(&request);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_performCount, i == 0 ? "OPENSOCKETFUNCTION" : "OPENSOCKETDATA");
    TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
    http_free(&resp);
  }
}

void test_failed_transfer_reports_its_error_class(void)
{
  static const struct { CURLcode m_result; HttpError_t m_error; } cases[] = {
    { CURLE_OPERATION_TIMEDOUT,       HTTP_ERROR_TIMEOUT },
    { CURLE_COULDNT_RESOLVE_HOST,     HTTP_ERROR_RESOLVE },
    { CURLE_COULDNT_CONNECT,          HTTP_ERROR_CONNECT },
    { CURLE_SSL_CONNECT_ERROR,        HTTP_ERROR_TLS     },
    { CURLE_PEER_FAILED_VERIFICATION, HTTP_ERROR_TLS     },
    { CURLE_UNSUPPORTED_PROTOCOL,     HTTP_ERROR_OTHER   },
    { CURLE_TOO_MANY_REDIRECTS,       HTTP_ERROR_OTHER   },
    { CURLE_WRITE_ERROR,              HTTP_ERROR_OTHER   },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    setUp();
    g_performResult     = cases[i].m_result;
    HttpResponse_t resp = http_GET("https://example.invalid/", 3000, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_error, resp.m_error, curl_easy_strerror(cases[i].m_result));
    TEST_ASSERT_EQUAL_INT(0, resp.m_status);
    TEST_ASSERT_NULL(resp.mp_body);
    http_free(&resp);
  }
}

void test_finished_transfer_reports_no_error(void)
{
  g_performResult     = CURLE_OK;
  g_driveBodyLen      = 25;
  HttpResponse_t resp = http_GET("https://example.invalid/", 3000, NULL);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_size_t(25, resp.m_bodyLen);
  TEST_ASSERT_EQUAL_STRING("bbbbbbbbbbbbbbbbbbbbbbbbb", resp.mp_body);
  http_free(&resp);
}

void test_body_at_the_limit_is_kept_and_one_byte_more_is_refused(void)
{
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .m_maxBodyByteCount = 25 };
  g_performResult     = CURLE_OK;
  g_driveBodyLen      = 25;
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_size_t(25, resp.m_bodyLen);
  http_free(&resp);

  setUp();
  g_performResult = CURLE_OK;
  g_driveBodyLen  = 26;
  resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_BODY_TOO_LARGE, resp.m_error);
  TEST_ASSERT_NULL(resp.mp_body);
  TEST_ASSERT_EQUAL_size_t(0, resp.m_bodyLen);
  http_free(&resp);
}

void test_default_body_limit_is_HTTP_MAX_BODY(void)
{
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000 };
  g_performResult     = CURLE_OK;
  g_driveBodyLen      = HTTP_MAX_BODY;
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_size_t(HTTP_MAX_BODY, resp.m_bodyLen);
  http_free(&resp);

  setUp();
  g_performResult = CURLE_OK;
  g_driveBodyLen  = HTTP_MAX_BODY + 1;
  resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_BODY_TOO_LARGE, resp.m_error);
  http_free(&resp);

  setUp();
  g_performResult = CURLE_OK;
  g_driveBodyLen  = HTTP_MAX_BODY + 1;
  resp = http_GET("https://example.invalid/", 3000, NULL);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_BODY_TOO_LARGE, resp.m_error);
  http_free(&resp);
}

void test_body_limit_above_HTTP_MAX_BODY_is_not_sent(void)
{
  HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .m_maxBodyByteCount = HTTP_MAX_BODY };
  HttpResponse_t resp   = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(1, g_performCount);
  http_free(&resp);

  setUp();
  request.m_maxBodyByteCount = HTTP_MAX_BODY + 1;
  resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(0, g_performCount);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  http_free(&resp);
}

void test_body_that_cannot_grow_is_not_too_large(void)
{
  g_performResult     = CURLE_OK;
  g_driveBodyLen      = 5000;
  g_reallocFails      = true;
  HttpResponse_t resp = http_GET("https://example.invalid/", 3000, NULL);
  g_reallocFails      = false;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  TEST_ASSERT_NULL(resp.mp_body);
  http_free(&resp);
}

void test_every_extra_header_is_handed_to_libcurl(void)
{
  const char* const headers[] = { "X-API-Key: k", "Content-Type: text/plain", NULL };
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .mp_extraHeaders = headers, .m_isTargetTrusted = true };
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(2, g_headerCount);
  TEST_ASSERT_EQUAL_STRING("X-API-Key: k", g_firstHeader);
  TEST_ASSERT_EQUAL_STRING("Content-Type: text/plain", g_secondHeader);
  http_free(&resp);
}

void test_request_whose_second_header_cannot_be_added_is_not_sent(void)
{
  const char* const headers[] = { "X-API-Key: k", "Content-Type: text/plain", NULL };
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .mp_extraHeaders = headers, .m_isTargetTrusted = true };
  g_slistAppendFailCall = 2;
  HttpResponse_t resp   = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(0, g_performCount);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  http_free(&resp);
}

void test_named_response_headers_are_captured(void)
{
  const char* const names[]   = { "Retry-After", "Server", NULL };
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .mp_headerNamesToCapture = names };
  g_performResult  = CURLE_OK;
  g_fakeHeaderName = "Retry-After";
  TEST_ASSERT_TRUE(snprintf(g_fakeHeaderValue, sizeof(g_fakeHeaderValue), "%s", "120") < (int)sizeof(g_fakeHeaderValue));

  HttpResponse_t resp = http_GETWithOptions(&request);
  g_fakeHeaderValue[0] = '\0';
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(2, resp.m_capturedHeaderValueCount);
  TEST_ASSERT_EQUAL_STRING("120", resp.mp_capturedHeaderValues[0]);
  TEST_ASSERT_NULL(resp.mp_capturedHeaderValues[1]);

  http_free(&resp);
  TEST_ASSERT_NULL(resp.mp_capturedHeaderValues);
  TEST_ASSERT_EQUAL_INT(0, resp.m_capturedHeaderValueCount);
}

void test_request_without_header_names_captures_nothing(void)
{
  const char* const no_names[] = { NULL };
  HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000 };
  g_performResult       = CURLE_OK;
  HttpResponse_t resp   = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(0, g_headerLookupCount);
  TEST_ASSERT_NULL(resp.mp_capturedHeaderValues);
  http_free(&resp);

  setUp();
  g_performResult                 = CURLE_OK;
  request.mp_headerNamesToCapture = no_names;
  resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(0, g_headerLookupCount);
  TEST_ASSERT_NULL(resp.mp_capturedHeaderValues);
  TEST_ASSERT_EQUAL_INT(0, resp.m_capturedHeaderValueCount);
  http_free(&resp);
}

void test_answer_without_headers_captures_null(void)
{
  const char* const names[]   = { "Retry-After", NULL };
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .mp_headerNamesToCapture = names };
  g_performResult     = CURLE_OK;
  g_headerResult      = CURLHE_NOHEADERS;
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(1, resp.m_capturedHeaderValueCount);
  TEST_ASSERT_NULL(resp.mp_capturedHeaderValues[0]);
  http_free(&resp);
}

void test_header_that_cannot_be_captured_fails_the_answer(void)
{
  const char* const names[]   = { "Retry-After", NULL };
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .mp_headerNamesToCapture = names };

  for (int failure = 0; failure < 3; failure++)
  {
    setUp();
    g_performResult  = CURLE_OK;
    g_driveBodyLen   = 5;
    g_fakeHeaderName = "Retry-After";
    TEST_ASSERT_TRUE(snprintf(g_fakeHeaderValue, sizeof(g_fakeHeaderValue), "%s", "120") < (int)sizeof(g_fakeHeaderValue));
    g_headerResult   = failure == 0 ? CURLHE_NOT_BUILT_IN : -1;
    g_strdupFailCall = failure == 1 ? 1 : 0;
    g_callocFails    = failure == 2;
    HttpResponse_t resp = http_GETWithOptions(&request);
    g_callocFails    = false;
    TEST_ASSERT_EQUAL_INT_MESSAGE(HTTP_ERROR_OTHER, resp.m_error, failure == 0 ? "lookup" : failure == 1 ? "strdup" : "calloc");
    TEST_ASSERT_EQUAL_INT(0, resp.m_status);
    TEST_ASSERT_NULL(resp.mp_body);
    TEST_ASSERT_NULL(resp.mp_capturedHeaderValues);
    http_free(&resp);
  }
}

void test_only_untrusted_target_may_use_http_and_every_request_checks_its_sockets(void)
{
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000 };
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_STRING("http,https", g_protocolsStr);
  TEST_ASSERT_EQUAL_STRING("http,https", g_redirProtocolsStr);
  TEST_ASSERT_NOT_NULL(g_openSocketFunction);
  TEST_ASSERT_NOT_NULL(g_openSocketData);
  http_free(&resp);

  setUp();
  resp = http_GET("https://example.invalid/", 3000, NULL);
  TEST_ASSERT_EQUAL_STRING("https", g_protocolsStr);
  TEST_ASSERT_EQUAL_STRING("https", g_redirProtocolsStr);
  TEST_ASSERT_NOT_NULL(g_openSocketFunction);
  TEST_ASSERT_NOT_NULL(g_openSocketData);
  http_free(&resp);
}

void test_socket_check_refuses_an_address_that_is_not_globally_reachable(void)
{
  const char* const addresses[] = { "127.0.0.1", "::1" };
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000 };
  for (size_t i = 0; i < sizeof(addresses) / sizeof(addresses[0]); i++)
  {
    setUp();
    static_addDriveAddress(addresses[i]);
    HttpResponse_t resp = http_GETWithOptions(&request);
    TEST_ASSERT_FALSE_MESSAGE(g_isDrivenSocketOpen[0], addresses[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HTTP_ERROR_BLOCKED, resp.m_error, addresses[i]);
    TEST_ASSERT_EQUAL_INT(0, resp.m_status);
    http_free(&resp);
  }
}

void test_socket_check_opens_a_socket_for_a_globally_reachable_address(void)
{
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000 };
  static_addDriveAddress("8.8.8.8");
  static_addDriveAddress("2001:4860:4860::8888");
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_TRUE(g_isDrivenSocketOpen[0]);
  TEST_ASSERT_TRUE(g_isDrivenSocketOpen[1]);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_CONNECT, resp.m_error);
  http_free(&resp);
}

void test_refused_address_before_a_finished_transfer_is_no_error(void)
{
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000 };
  g_performResult = CURLE_OK;
  static_addDriveAddress("::1");
  static_addDriveAddress("8.8.8.8");
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_FALSE(g_isDrivenSocketOpen[0]);
  TEST_ASSERT_TRUE(g_isDrivenSocketOpen[1]);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  http_free(&resp);
}

void test_timeout_after_a_refused_address_is_a_timeout(void)
{
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000 };
  g_performResult = CURLE_OPERATION_TIMEDOUT;
  static_addDriveAddress("::1");
  static_addDriveAddress("8.8.8.8");
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_FALSE(g_isDrivenSocketOpen[0]);
  TEST_ASSERT_TRUE(g_isDrivenSocketOpen[1]);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_TIMEOUT, resp.m_error);
  http_free(&resp);
}

void test_body_too_large_after_a_refused_address_is_body_too_large(void)
{
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .m_maxBodyByteCount = 25 };
  g_performResult = CURLE_OK;
  g_driveBodyLen  = 26;
  static_addDriveAddress("::1");
  static_addDriveAddress("8.8.8.8");
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_BODY_TOO_LARGE, resp.m_error);
  http_free(&resp);
}

void test_loopback_target_is_blocked_trusted_or_not(void)
{
  char url[64];
  int  port = static_findClosedLoopbackPort();
  TEST_ASSERT_TRUE(snprintf(url, sizeof(url), "https://127.0.0.1:%d/", port) < (int)sizeof(url));
  HttpRequest_t request = { .mp_url = url, .m_timeoutMs = 3000 };

  g_isTransferFaked   = false;
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_BLOCKED, resp.m_error);
  TEST_ASSERT_EQUAL_INT(1, g_socketCheckCount);
  http_free(&resp);

  setUp();
  g_isTransferFaked         = false;
  request.m_isTargetTrusted = true;
  resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_BLOCKED, resp.m_error);
  TEST_ASSERT_EQUAL_INT(1, g_socketCheckCount);
  http_free(&resp);

  setUp();
  g_isTransferFaked   = false;
  g_isLoopbackAllowed = true;
  resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_CONNECT, resp.m_error);
  TEST_ASSERT_EQUAL_INT(1, g_socketCheckCount);
  http_free(&resp);
}

void test_redirect_to_a_refused_address_is_blocked(void)
{
  TestServer_t server;
  static_listenOnLoopback(&server);
  char answer[160];
  char url[64];
  TEST_ASSERT_TRUE(snprintf(answer, sizeof(answer), "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.2:%d/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", server.m_port) < (int)sizeof(answer));
  TEST_ASSERT_TRUE(snprintf(url, sizeof(url), "http://127.0.0.1:%d/", server.m_port) < (int)sizeof(url));
  const char* const answers[] = { answer };
  server.mp_answers    = answers;
  server.m_answerCount = 1;
  pthread_t thread;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&thread, NULL, static_answerRequests, &server));

  const HttpRequest_t request = { .mp_url = url, .m_timeoutMs = 3000 };
  g_isTransferFaked   = false;
  g_isLoopbackAllowed = true;
  HttpResponse_t resp = http_GETWithOptions(&request);
  pthread_join(thread, NULL);
  close(server.m_listenFd);

  TEST_ASSERT_EQUAL_INT(2, g_socketCheckCount);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_BLOCKED, resp.m_error);
  TEST_ASSERT_NULL(resp.mp_body);
  http_free(&resp);
}

void test_loopback_answer_carries_status_body_and_header(void)
{
  TestServer_t server;
  static_listenOnLoopback(&server);
  char url[64];
  TEST_ASSERT_TRUE(snprintf(url, sizeof(url), "http://127.0.0.1:%d/", server.m_port) < (int)sizeof(url));
  const char* const answers[] = { "HTTP/1.1 200 OK\r\nRetry-After: 120\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello" };
  server.mp_answers    = answers;
  server.m_answerCount = 1;
  pthread_t thread;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&thread, NULL, static_answerRequests, &server));

  const char* const names[]   = { "Retry-After", NULL };
  const HttpRequest_t request = { .mp_url = url, .m_timeoutMs = 3000, .mp_headerNamesToCapture = names };
  g_isTransferFaked    = false;
  g_isLoopbackAllowed  = true;
  g_isHeaderLookupReal = true;
  HttpResponse_t resp  = http_GETWithOptions(&request);
  pthread_join(thread, NULL);
  close(server.m_listenFd);

  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(200, resp.m_status);
  TEST_ASSERT_EQUAL_STRING("hello", resp.mp_body);
  TEST_ASSERT_EQUAL_INT(1, resp.m_capturedHeaderValueCount);
  TEST_ASSERT_EQUAL_STRING("120", resp.mp_capturedHeaderValues[0]);
  TEST_ASSERT_NULL(resp.mp_redirectUrl);
  TEST_ASSERT_FALSE(resp.m_isBodyCut);
  http_free(&resp);
}

void test_captured_header_comes_from_the_last_answer_of_a_redirect(void)
{
  TestServer_t server;
  static_listenOnLoopback(&server);
  char url[64];
  TEST_ASSERT_TRUE(snprintf(url, sizeof(url), "http://127.0.0.1:%d/", server.m_port) < (int)sizeof(url));
  const char* const answers[] = {
    "HTTP/1.1 302 Found\r\nLocation: /next\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    "HTTP/1.1 200 OK\r\nRetry-After: 120\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
  };
  server.mp_answers    = answers;
  server.m_answerCount = 2;
  pthread_t thread;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&thread, NULL, static_answerRequests, &server));

  const char* const names[]   = { "Retry-After", NULL };
  const HttpRequest_t request = { .mp_url = url, .m_timeoutMs = 3000, .mp_headerNamesToCapture = names };
  g_isTransferFaked    = false;
  g_isLoopbackAllowed  = true;
  g_isHeaderLookupReal = true;
  HttpResponse_t resp  = http_GETWithOptions(&request);
  pthread_join(thread, NULL);
  close(server.m_listenFd);

  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(200, resp.m_status);
  TEST_ASSERT_EQUAL_INT(1, resp.m_capturedHeaderValueCount);
  TEST_ASSERT_EQUAL_STRING("120", resp.mp_capturedHeaderValues[0]);
  TEST_ASSERT_NULL(resp.mp_redirectUrl);
  http_free(&resp);
}

void test_request_without_a_positive_timeout_is_not_sent(void)
{
  const int timeouts[] = { 0, -1 };
  for (size_t i = 0; i < sizeof(timeouts) / sizeof(timeouts[0]); i++)
  {
    setUp();
    HttpResponse_t resp = http_GET("https://example.invalid/", timeouts[i], NULL);
    TEST_ASSERT_EQUAL_INT(0, g_performCount);
    TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
    http_free(&resp);
  }

  setUp();
  HttpResponse_t resp = http_GET("https://example.invalid/", 1, NULL);
  TEST_ASSERT_EQUAL_INT(1, g_performCount);
  TEST_ASSERT_EQUAL_INT32(1, g_timeoutMs);
  http_free(&resp);
}

void test_untrusted_request_with_an_extra_header_is_not_sent(void)
{
  const char* const headers[]      = { "X-API-Key: k", NULL };
  const char* const auth_headers[] = { "Authorization: Bearer t", NULL };
  const char* const no_headers[]   = { NULL };
  HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .mp_extraHeaders = headers };
  HttpResponse_t resp   = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(0, g_performCount);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  http_free(&resp);

  setUp();
  request.mp_extraHeaders    = auth_headers;
  request.m_maxBodyByteCount = 25;
  resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(0, g_performCount);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  http_free(&resp);

  setUp();
  request.mp_extraHeaders    = headers;
  request.m_maxBodyByteCount = 0;
  request.m_isTargetTrusted  = true;
  resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(1, g_performCount);
  TEST_ASSERT_EQUAL_INT(1, g_headerCount);
  http_free(&resp);

  setUp();
  request.m_isTargetTrusted = false;
  request.mp_extraHeaders   = no_headers;
  resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(1, g_performCount);
  TEST_ASSERT_EQUAL_INT(0, g_headerCount);
  http_free(&resp);
}

void test_captured_values_follow_the_order_of_the_names(void)
{
  const char* const names[]   = { "Server", "Retry-After", NULL };
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .mp_headerNamesToCapture = names };
  g_performResult  = CURLE_OK;
  g_fakeHeaderName = "Retry-After";
  TEST_ASSERT_TRUE(snprintf(g_fakeHeaderValue, sizeof(g_fakeHeaderValue), "%s", "120") < (int)sizeof(g_fakeHeaderValue));
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(2, resp.m_capturedHeaderValueCount);
  TEST_ASSERT_NULL(resp.mp_capturedHeaderValues[0]);
  TEST_ASSERT_EQUAL_STRING("120", resp.mp_capturedHeaderValues[1]);
  http_free(&resp);
}

void test_failed_copy_of_a_later_header_fails_the_answer(void)
{
  const char* const names[]   = { "Retry-After", "Retry-After", NULL };
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .mp_headerNamesToCapture = names };
  g_performResult  = CURLE_OK;
  g_fakeHeaderName = "Retry-After";
  TEST_ASSERT_TRUE(snprintf(g_fakeHeaderValue, sizeof(g_fakeHeaderValue), "%s", "120") < (int)sizeof(g_fakeHeaderValue));
  g_strdupFailCall    = 2;
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(2, g_strdupCount);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  TEST_ASSERT_NULL(resp.mp_capturedHeaderValues);
  http_free(&resp);
}

void test_each_entry_point_hands_its_own_timeout_to_libcurl(void)
{
  HttpResponse_t resp = http_GET("https://example.invalid/", 1234, NULL);
  TEST_ASSERT_EQUAL_INT32(1234, g_timeoutMs);
  http_free(&resp);

  setUp();
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 4321 };
  resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT32(4321, g_timeoutMs);
  http_free(&resp);
}

void test_loopback_404_is_an_answer_and_http_free_clears_it(void)
{
  TestServer_t server;
  static_listenOnLoopback(&server);
  char url[64];
  TEST_ASSERT_TRUE(snprintf(url, sizeof(url), "http://127.0.0.1:%d/", server.m_port) < (int)sizeof(url));
  const char* const answers[] = { "HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope" };
  server.mp_answers    = answers;
  server.m_answerCount = 1;
  pthread_t thread;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&thread, NULL, static_answerRequests, &server));

  const HttpRequest_t request = { .mp_url = url, .m_timeoutMs = 3000 };
  g_isTransferFaked   = false;
  g_isLoopbackAllowed = true;
  HttpResponse_t resp = http_GETWithOptions(&request);
  pthread_join(thread, NULL);
  close(server.m_listenFd);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(404, resp.m_status);
  TEST_ASSERT_EQUAL_STRING("nope", resp.mp_body);
  http_free(&resp);
  TEST_ASSERT_EQUAL_INT(0, resp.m_status);

  setUp();
  resp = http_GET("https://example.invalid/", 3000, NULL);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_CONNECT, resp.m_error);
  http_free(&resp);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
}

void test_nul_byte_in_the_body_counts_in_its_length(void)
{
  g_performResult     = CURLE_OK;
  g_driveBodyText     = "ab\0cd";
  g_driveBodyLen      = 5;
  HttpResponse_t resp = http_GET("https://example.invalid/", 3000, NULL);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_size_t(5, resp.m_bodyLen);
  TEST_ASSERT_EQUAL_MEMORY("ab\0cd", resp.mp_body, 5);
  http_free(&resp);
}

void test_large_pieces_are_kept_whole(void)
{
  static char text[40000];
  for (size_t i = 0; i < sizeof(text); i++)
    text[i] = (char)('a' + i % 26);
  const size_t cases[][2] = { { 40000, CURL_MAX_WRITE_SIZE }, { 4096, 4096 } };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
  {
    setUp();
    g_performResult     = CURLE_OK;
    g_driveBodyText     = text;
    g_driveBodyLen      = cases[c][0];
    g_drivePieceLen     = cases[c][1];
    HttpResponse_t resp = http_GET("https://example.invalid/", 3000, NULL);
    TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
    TEST_ASSERT_EQUAL_size_t(cases[c][0], resp.m_bodyLen);
    TEST_ASSERT_EQUAL_MEMORY(text, resp.mp_body, cases[c][0]);
    TEST_ASSERT_EQUAL_CHAR('\0', resp.mp_body[cases[c][0]]);
    http_free(&resp);
  }
}

void test_refused_address_then_a_failed_connection_is_blocked(void)
{
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000 };
  static_addDriveAddress("::1");
  static_addDriveAddress("8.8.8.8");
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_TRUE(g_isDrivenSocketOpen[1]);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_BLOCKED, resp.m_error);
  http_free(&resp);
}

void test_body_limit_of_one_byte_is_a_limit(void)
{
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .m_maxBodyByteCount = 1 };
  g_performResult     = CURLE_OK;
  g_driveBodyLen      = 2;
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_BODY_TOO_LARGE, resp.m_error);
  http_free(&resp);
}

static HttpResponse_t static_askTestServer(TestServer_t* server, const char* const* answers, size_t answer_count, const char* path, HttpRequest_t request)
{
  char url[96];
  TEST_ASSERT_TRUE(snprintf(url, sizeof(url), "http://127.0.0.1:%d%s", server->m_port, path) < (int)sizeof(url));
  request.mp_url        = url;
  server->mp_answers    = answers;
  server->m_answerCount = answer_count;
  pthread_t thread;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&thread, NULL, static_answerRequests, server));
  g_isTransferFaked    = false;
  g_isLoopbackAllowed  = true;
  g_isHeaderLookupReal = true;
  HttpResponse_t resp  = http_GETWithOptions(&request);
  pthread_join(thread, NULL);
  return resp;
}

void test_https_only_request_is_limited_to_https_untrusted_or_not(void)
{
  HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .m_isHttpsOnly = true };
  HttpResponse_t resp   = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_STRING("https", g_protocolsStr);
  TEST_ASSERT_EQUAL_STRING("https", g_redirProtocolsStr);
  http_free(&resp);

  setUp();
  request.m_isHttpsOnly = false;
  resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_STRING("http,https", g_protocolsStr);
  TEST_ASSERT_EQUAL_STRING("http,https", g_redirProtocolsStr);
  http_free(&resp);

  setUp();
  request.m_isHttpsOnly     = true;
  request.m_isTargetTrusted = true;
  resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_STRING("https", g_protocolsStr);
  TEST_ASSERT_EQUAL_STRING("https", g_redirProtocolsStr);
  http_free(&resp);
}

void test_https_only_request_refuses_an_http_url(void)
{
  TestServer_t server;
  static_listenOnLoopback(&server);
  const char* const answers[] = { "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nplain" };
  HttpRequest_t request       = { .m_timeoutMs = 3000, .m_isHttpsOnly = true };

  HttpResponse_t resp = static_askTestServer(&server, answers, 0, "/", request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  TEST_ASSERT_EQUAL_INT(0, g_socketCheckCount);
  TEST_ASSERT_NULL(resp.mp_body);
  http_free(&resp);

  setUp();
  request.m_isHttpsOnly = false;
  resp = static_askTestServer(&server, answers, 1, "/", request);
  close(server.m_listenFd);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(200, resp.m_status);
  TEST_ASSERT_EQUAL_STRING("plain", resp.mp_body);
  TEST_ASSERT_EQUAL_INT(1, server.m_requestCount);
  http_free(&resp);
}

void test_returned_redirect_carries_its_status_headers_and_absolute_target(void)
{
  TestServer_t server;
  static_listenOnLoopback(&server);
  const char* const answers[] = { "HTTP/1.1 302 Found\r\nLocation: next?step=2\r\nRetry-After: 7\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" };
  const char* const names[]   = { "Retry-After", NULL };
  const HttpRequest_t request = { .m_timeoutMs = 3000, .mp_headerNamesToCapture = names, .m_isRedirectLeftToCaller = true };

  HttpResponse_t resp = static_askTestServer(&server, answers, 1, "/dir/page", request);
  close(server.m_listenFd);
  char expected_url[96];
  TEST_ASSERT_TRUE(snprintf(expected_url, sizeof(expected_url), "http://127.0.0.1:%d/dir/next?step=2", server.m_port) < (int)sizeof(expected_url));

  TEST_ASSERT_EQUAL_INT32(0, g_followLocation);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(302, resp.m_status);
  TEST_ASSERT_EQUAL_STRING(expected_url, resp.mp_redirectUrl);
  TEST_ASSERT_EQUAL_STRING("7", resp.mp_capturedHeaderValues[0]);
  TEST_ASSERT_EQUAL_INT(1, server.m_requestCount);
  http_free(&resp);
  TEST_ASSERT_NULL(resp.mp_redirectUrl);
}

void test_returned_redirect_without_a_location_has_no_target(void)
{
  TestServer_t server;
  static_listenOnLoopback(&server);
  const char* const answers[] = { "HTTP/1.1 301 Moved Permanently\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" };
  const HttpRequest_t request = { .m_timeoutMs = 3000, .m_isRedirectLeftToCaller = true };

  HttpResponse_t resp = static_askTestServer(&server, answers, 1, "/", request);
  close(server.m_listenFd);
  TEST_ASSERT_EQUAL_INT32(0, g_followLocation);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(301, resp.m_status);
  TEST_ASSERT_NULL(resp.mp_redirectUrl);
  http_free(&resp);
}

void test_redirect_target_that_cannot_be_copied_fails_the_answer(void)
{
  TestServer_t server;
  static_listenOnLoopback(&server);
  const char* const answers[] = { "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" };
  const HttpRequest_t request = { .m_timeoutMs = 3000, .m_isRedirectLeftToCaller = true };

  g_strdupFailCall    = 1;
  HttpResponse_t resp = static_askTestServer(&server, answers, 1, "/", request);
  close(server.m_listenFd);
  TEST_ASSERT_EQUAL_INT(1, g_strdupCount);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  TEST_ASSERT_EQUAL_INT(0, resp.m_status);
  TEST_ASSERT_NULL(resp.mp_body);
  TEST_ASSERT_NULL(resp.mp_redirectUrl);
  http_free(&resp);
}

void test_returned_redirect_whose_body_is_cut_has_no_target(void)
{
  TestServer_t server;
  static_listenOnLoopback(&server);
  const char* const answers[] = { "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 30\r\nConnection: close\r\n\r\n0123456789abcdefghijABCDEFGHIJ" };
  const HttpRequest_t request = { .m_timeoutMs = 3000, .m_maxBodyByteCount = 10, .m_isRedirectLeftToCaller = true, .m_isBodyCutAccepted = true };

  HttpResponse_t resp = static_askTestServer(&server, answers, 1, "/", request);
  close(server.m_listenFd);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(302, resp.m_status);
  TEST_ASSERT_TRUE(resp.m_isBodyCut);
  TEST_ASSERT_NULL(resp.mp_redirectUrl);
  TEST_ASSERT_EQUAL_INT(1, server.m_requestCount);
  http_free(&resp);
}

void test_accepted_body_cut_keeps_the_answer_and_the_body_up_to_the_limit(void)
{
  const char* const names[] = { "Retry-After", NULL };
  HttpRequest_t request     = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .m_maxBodyByteCount = 25, .mp_headerNamesToCapture = names, .m_isBodyCutAccepted = true };
  const size_t body_lens[]  = { 24, 25, 26 };
  for (size_t i = 0; i < sizeof(body_lens) / sizeof(body_lens[0]); i++)
  {
    setUp();
    g_performResult  = CURLE_OK;
    g_driveBodyLen   = body_lens[i];
    g_fakeHeaderName = "Retry-After";
    TEST_ASSERT_TRUE(snprintf(g_fakeHeaderValue, sizeof(g_fakeHeaderValue), "%s", "120") < (int)sizeof(g_fakeHeaderValue));
    HttpResponse_t resp = http_GETWithOptions(&request);
    TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
    TEST_ASSERT_EQUAL_STRING("120", resp.mp_capturedHeaderValues[0]);
    TEST_ASSERT_EQUAL_size_t(i < 2 ? body_lens[i] : 25, resp.m_bodyLen);
    TEST_ASSERT_EQUAL_CHAR('\0', resp.mp_body[resp.m_bodyLen]);
    TEST_ASSERT_EQUAL_INT(i == 2, resp.m_isBodyCut);
    http_free(&resp);
  }

  setUp();
  g_performResult             = CURLE_OK;
  g_driveBodyLen              = 26;
  request.m_isBodyCutAccepted = false;
  HttpResponse_t resp         = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_BODY_TOO_LARGE, resp.m_error);
  TEST_ASSERT_NULL(resp.mp_body);
  TEST_ASSERT_FALSE(resp.m_isBodyCut);
  http_free(&resp);
}

void test_accepted_body_cut_between_two_pieces_keeps_the_whole_pieces(void)
{
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .m_maxBodyByteCount = 20, .m_isBodyCutAccepted = true };
  g_performResult     = CURLE_OK;
  g_driveBodyText     = "abcdefghijklmnopqrstuvwxyz";
  g_driveBodyLen      = 26;
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_size_t(20, resp.m_bodyLen);
  TEST_ASSERT_EQUAL_STRING("abcdefghijklmnopqrst", resp.mp_body);
  TEST_ASSERT_TRUE(resp.m_isBodyCut);
  http_free(&resp);
}

void test_accepted_body_cut_that_cannot_grow_fails_the_answer(void)
{
  HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .m_maxBodyByteCount = 5000, .m_isBodyCutAccepted = true };
  g_performResult     = CURLE_OK;
  g_driveBodyLen      = 5001;
  g_drivePieceLen     = 5001;
  g_reallocFails      = true;
  HttpResponse_t resp = http_GETWithOptions(&request);
  g_reallocFails      = false;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  TEST_ASSERT_NULL(resp.mp_body);
  TEST_ASSERT_FALSE(resp.m_isBodyCut);
  http_free(&resp);

  setUp();
  g_performResult             = CURLE_OK;
  g_driveBodyLen              = 5001;
  g_drivePieceLen             = 5001;
  g_reallocFails              = true;
  request.m_isBodyCutAccepted = false;
  resp = http_GETWithOptions(&request);
  g_reallocFails              = false;
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_BODY_TOO_LARGE, resp.m_error);
  http_free(&resp);
}

void test_accepted_body_cut_reads_the_status_and_headers_of_a_loopback_answer(void)
{
  TestServer_t server;
  static_listenOnLoopback(&server);
  const char* const answers[] = { "HTTP/1.1 200 OK\r\nRetry-After: 120\r\nContent-Length: 30\r\nConnection: close\r\n\r\n0123456789abcdefghijABCDEFGHIJ" };
  const char* const names[]   = { "Retry-After", NULL };
  const HttpRequest_t request = { .m_timeoutMs = 3000, .m_maxBodyByteCount = 10, .mp_headerNamesToCapture = names, .m_isBodyCutAccepted = true };

  HttpResponse_t resp = static_askTestServer(&server, answers, 1, "/", request);
  close(server.m_listenFd);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(200, resp.m_status);
  TEST_ASSERT_EQUAL_STRING("120", resp.mp_capturedHeaderValues[0]);
  TEST_ASSERT_EQUAL_size_t(10, resp.m_bodyLen);
  TEST_ASSERT_EQUAL_STRING("0123456789", resp.mp_body);
  TEST_ASSERT_TRUE(resp.m_isBodyCut);
  http_free(&resp);
}

void test_required_port_refuses_an_address_on_another_port(void)
{
  static const struct { const char* mp_ip; uint16_t m_port; bool m_isOpen; } cases[] = {
    { "8.8.8.8",              443,  true  },
    { "8.8.8.8",              442,  false },
    { "8.8.8.8",              444,  false },
    { "2001:4860:4860::8888", 443,  true  },
    { "2001:4860:4860::8888", 8443, false },
    { "127.0.0.1",            443,  false },
  };
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .m_requiredPort = 443 };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    char label[48];
    TEST_ASSERT_TRUE(snprintf(label, sizeof(label), "%s port %u", cases[i].mp_ip, (unsigned int)cases[i].m_port) < (int)sizeof(label));
    setUp();
    static_addDriveAddressOnPort(cases[i].mp_ip, cases[i].m_port);
    HttpResponse_t resp = http_GETWithOptions(&request);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_isOpen, g_isDrivenSocketOpen[0], label);
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_isOpen ? HTTP_ERROR_CONNECT : HTTP_ERROR_BLOCKED, resp.m_error, label);
    http_free(&resp);
  }
}

void test_required_port_of_0_allows_any_port(void)
{
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000 };
  static_addDriveAddressOnPort("8.8.8.8", 8443);
  static_addDriveAddressOnPort("2001:4860:4860::8888", 442);
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_TRUE(g_isDrivenSocketOpen[0]);
  TEST_ASSERT_TRUE(g_isDrivenSocketOpen[1]);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_CONNECT, resp.m_error);
  http_free(&resp);
}

void test_required_port_lets_through_only_the_loopback_server_port(void)
{
  TestServer_t server;
  static_listenOnLoopback(&server);
  const char* const answers[] = { "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nport" };
  HttpRequest_t request       = { .m_timeoutMs = 3000, .m_requiredPort = (uint16_t)(server.m_port + 1) };

  HttpResponse_t resp = static_askTestServer(&server, answers, 0, "/", request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_BLOCKED, resp.m_error);
  TEST_ASSERT_EQUAL_INT(1, g_socketCheckCount);
  http_free(&resp);

  setUp();
  request.m_requiredPort = (uint16_t)server.m_port;
  resp = static_askTestServer(&server, answers, 1, "/", request);
  close(server.m_listenFd);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(200, resp.m_status);
  TEST_ASSERT_EQUAL_STRING("port", resp.mp_body);
  TEST_ASSERT_EQUAL_INT(1, server.m_requestCount);
  http_free(&resp);
}

void test_every_copy_of_a_captured_header_is_joined_in_order(void)
{
  const char* const names[]   = { "Retry-After", NULL };
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .mp_headerNamesToCapture = names };
  const char* const joined[]  = { "120, c1", "120, c1, c2" };
  for (size_t i = 0; i < sizeof(joined) / sizeof(joined[0]); i++)
  {
    setUp();
    g_performResult       = CURLE_OK;
    g_fakeHeaderName      = "Retry-After";
    g_fakeHeaderCopyCount = 2 + i;
    TEST_ASSERT_TRUE(snprintf(g_fakeHeaderValue, sizeof(g_fakeHeaderValue), "%s", "120") < (int)sizeof(g_fakeHeaderValue));
    HttpResponse_t resp = http_GETWithOptions(&request);
    TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
    TEST_ASSERT_EQUAL_STRING(joined[i], resp.mp_capturedHeaderValues[0]);
    http_free(&resp);
  }
}

void test_header_copies_past_HTTP_MAX_HEADER_COPY_COUNT_fail_the_answer(void)
{
  TEST_ASSERT_EQUAL_INT(16, HTTP_MAX_HEADER_COPY_COUNT);
  const char* const names[]   = { "Retry-After", NULL };
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .mp_headerNamesToCapture = names };
  for (size_t copy_count = HTTP_MAX_HEADER_COPY_COUNT - 1; copy_count <= HTTP_MAX_HEADER_COPY_COUNT; copy_count++)
  {
    char   expected[256] = "120";
    size_t expected_len  = strlen(expected);
    for (size_t k = 1; k < copy_count; k++)
      expected_len += (size_t)snprintf(expected + expected_len, sizeof(expected) - expected_len, ", c%zu", k);
    TEST_ASSERT_TRUE(expected_len < sizeof(expected));

    setUp();
    g_performResult       = CURLE_OK;
    g_fakeHeaderName      = "Retry-After";
    g_fakeHeaderCopyCount = copy_count;
    TEST_ASSERT_TRUE(snprintf(g_fakeHeaderValue, sizeof(g_fakeHeaderValue), "%s", "120") < (int)sizeof(g_fakeHeaderValue));
    HttpResponse_t resp = http_GETWithOptions(&request);
    TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
    TEST_ASSERT_EQUAL_STRING(expected, resp.mp_capturedHeaderValues[0]);
    http_free(&resp);
  }

  setUp();
  g_performResult       = CURLE_OK;
  g_fakeHeaderName      = "Retry-After";
  g_fakeHeaderCopyCount = HTTP_MAX_HEADER_COPY_COUNT + 1;
  HttpResponse_t resp   = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  TEST_ASSERT_EQUAL_INT(1, g_headerLookupCount);
  TEST_ASSERT_NULL(resp.mp_capturedHeaderValues);
  http_free(&resp);
}

void test_later_copy_that_cannot_be_joined_fails_the_answer(void)
{
  const char* const names[]   = { "Retry-After", NULL };
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .mp_headerNamesToCapture = names };
  for (int failure = 0; failure < 2; failure++)
  {
    setUp();
    g_performResult       = CURLE_OK;
    g_fakeHeaderName      = "Retry-After";
    g_fakeHeaderCopyCount = 2;
    g_headerFailIndex     = failure == 0 ? 1 : -1;
    g_reallocFails        = failure == 1;
    HttpResponse_t resp   = http_GETWithOptions(&request);
    g_reallocFails        = false;
    TEST_ASSERT_EQUAL_INT_MESSAGE(HTTP_ERROR_OTHER, resp.m_error, failure == 0 ? "lookup" : "realloc");
    TEST_ASSERT_NULL(resp.mp_capturedHeaderValues);
    http_free(&resp);
  }
}

void test_loopback_header_copies_join_and_early_hints_stay_out(void)
{
  TestServer_t server;
  static_listenOnLoopback(&server);
  const char* const answers[] = {
    "HTTP/1.1 103 Early Hints\r\nContent-Security-Policy: early\r\n\r\n"
    "HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'self'\r\ncontent-security-policy: script-src 'none'\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
  };
  const char* const names[]   = { "Content-Security-Policy", NULL };
  const HttpRequest_t request = { .m_timeoutMs = 3000, .mp_headerNamesToCapture = names };

  HttpResponse_t resp = static_askTestServer(&server, answers, 1, "/", request);
  close(server.m_listenFd);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(200, resp.m_status);
  TEST_ASSERT_EQUAL_STRING("default-src 'self', script-src 'none'", resp.mp_capturedHeaderValues[0]);
  http_free(&resp);
}

void test_set_cookie_copies_are_joined_with_a_newline_in_order(void)
{
  const char* const names[]   = { "Set-Cookie", NULL };
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .mp_headerNamesToCapture = names };
  g_performResult       = CURLE_OK;
  g_fakeHeaderName      = "Set-Cookie";
  g_fakeHeaderCopyCount = 3;
  TEST_ASSERT_TRUE(snprintf(g_fakeHeaderValue, sizeof(g_fakeHeaderValue), "%s", "id=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT") < (int)sizeof(g_fakeHeaderValue));

  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_STRING("id=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT\nc1\nc2", resp.mp_capturedHeaderValues[0]);
  TEST_ASSERT_EQUAL_size_t(3, resp.m_setCookieCopyCount);
  http_free(&resp);
}

void test_set_cookie_copies_past_HTTP_MAX_SET_COOKIE_COPY_COUNT_join_the_first_ones_and_count_all(void)
{
  TEST_ASSERT_EQUAL_INT(50, HTTP_MAX_SET_COOKIE_COPY_COUNT);
  const char* const names[]   = { "Set-Cookie", NULL };
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .mp_headerNamesToCapture = names };
  const size_t copy_counts[]  = { HTTP_MAX_HEADER_COPY_COUNT + 1, HTTP_MAX_SET_COOKIE_COPY_COUNT, HTTP_MAX_SET_COOKIE_COPY_COUNT + 1, 100000 };
  const size_t joined_counts[] = { HTTP_MAX_HEADER_COPY_COUNT + 1, HTTP_MAX_SET_COOKIE_COPY_COUNT, HTTP_MAX_SET_COOKIE_COPY_COUNT, HTTP_MAX_SET_COOKIE_COPY_COUNT };
  for (size_t i = 0; i < sizeof(copy_counts) / sizeof(copy_counts[0]); i++)
  {
    char   expected[512] = "id=1";
    size_t expected_len  = strlen(expected);
    for (size_t k = 1; k < joined_counts[i]; k++)
      expected_len += (size_t)snprintf(expected + expected_len, sizeof(expected) - expected_len, "\nc%zu", k);
    TEST_ASSERT_TRUE(expected_len < sizeof(expected));

    setUp();
    g_performResult       = CURLE_OK;
    g_fakeHeaderName      = "Set-Cookie";
    g_fakeHeaderCopyCount = copy_counts[i];
    TEST_ASSERT_TRUE(snprintf(g_fakeHeaderValue, sizeof(g_fakeHeaderValue), "%s", "id=1") < (int)sizeof(g_fakeHeaderValue));
    HttpResponse_t resp = http_GETWithOptions(&request);
    TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
    TEST_ASSERT_EQUAL_STRING(expected, resp.mp_capturedHeaderValues[0]);
    TEST_ASSERT_EQUAL_INT((int)joined_counts[i], g_headerLookupCount);
    TEST_ASSERT_EQUAL_size_t(copy_counts[i], resp.m_setCookieCopyCount);
    http_free(&resp);
  }
}

void test_set_cookie_name_matches_in_any_case_and_a_longer_name_keeps_the_comma(void)
{
  const char* const request_names[] = { "set-cookie", "SET-COOKIE", "Set-Cookie2" };
  const char* const joined[]        = { "id=1\nc1", "id=1\nc1", "id=1, c1" };
  const size_t set_cookie_counts[]  = { 2, 2, 0 };
  for (size_t i = 0; i < sizeof(request_names) / sizeof(request_names[0]); i++)
  {
    const char* const names[]   = { request_names[i], NULL };
    const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .mp_headerNamesToCapture = names };
    setUp();
    g_performResult       = CURLE_OK;
    g_fakeHeaderName      = request_names[i];
    g_fakeHeaderCopyCount = 2;
    TEST_ASSERT_TRUE(snprintf(g_fakeHeaderValue, sizeof(g_fakeHeaderValue), "%s", "id=1") < (int)sizeof(g_fakeHeaderValue));
    HttpResponse_t resp = http_GETWithOptions(&request);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HTTP_ERROR_NONE, resp.m_error, request_names[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(joined[i], resp.mp_capturedHeaderValues[0], request_names[i]);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(set_cookie_counts[i], resp.m_setCookieCopyCount, request_names[i]);
    http_free(&resp);
  }
}

void test_answer_without_set_cookie_captures_null(void)
{
  const char* const names[]   = { "Set-Cookie", "Retry-After", NULL };
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .mp_headerNamesToCapture = names };
  g_performResult       = CURLE_OK;
  g_fakeHeaderName      = "Retry-After";
  g_fakeHeaderCopyCount = 2;
  TEST_ASSERT_TRUE(snprintf(g_fakeHeaderValue, sizeof(g_fakeHeaderValue), "%s", "120") < (int)sizeof(g_fakeHeaderValue));

  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(2, resp.m_capturedHeaderValueCount);
  TEST_ASSERT_NULL(resp.mp_capturedHeaderValues[0]);
  TEST_ASSERT_EQUAL_STRING("120, c1", resp.mp_capturedHeaderValues[1]);
  TEST_ASSERT_EQUAL_size_t(0, resp.m_setCookieCopyCount);
  http_free(&resp);
}

void test_loopback_set_cookie_copies_join_with_a_newline_and_early_hints_stay_out(void)
{
  TestServer_t server;
  static_listenOnLoopback(&server);
  const char* const answers[] = {
    "HTTP/1.1 103 Early Hints\r\nSet-Cookie: early=1\r\n\r\n"
    "HTTP/1.1 200 OK\r\nSet-Cookie: id=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure\r\nset-cookie: theme=dark\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
  };
  const char* const names[]   = { "Set-Cookie", NULL };
  const HttpRequest_t request = { .m_timeoutMs = 3000, .mp_headerNamesToCapture = names };

  HttpResponse_t resp = static_askTestServer(&server, answers, 1, "/", request);
  close(server.m_listenFd);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(200, resp.m_status);
  TEST_ASSERT_EQUAL_STRING("id=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure\ntheme=dark", resp.mp_capturedHeaderValues[0]);
  TEST_ASSERT_EQUAL_size_t(2, resp.m_setCookieCopyCount);
  http_free(&resp);
}

void test_loopback_answer_head_of_300_KiB_is_read_and_one_byte_more_fails(void)
{
  static const char head_start[] = "HTTP/1.1 200 OK\r\n";
  static const char head_end[]   = "Content-Length: 0\r\nConnection: close\r\n\r\n";
  static const char line_start[] = "Set-Cookie: a=";
  const char* const names[]      = { "Set-Cookie", NULL };
  const HttpRequest_t request    = { .m_timeoutMs = 3000, .mp_headerNamesToCapture = names };
  for (size_t extra_byte_count = 0; extra_byte_count < 2; extra_byte_count++)
  {
    size_t head_len = 300 * 1024 + extra_byte_count;
    char*  answer   = malloc(head_len + 1);
    TEST_ASSERT_NOT_NULL(answer);
    memcpy(answer, head_start, sizeof(head_start) - 1);
    size_t answer_len  = sizeof(head_start) - 1;
    size_t line_budget = head_len - answer_len - (sizeof(head_end) - 1);
    size_t copy_count  = 0;
    size_t joined_len  = 0;
    while (line_budget > 0)
    {
      size_t line_len  = line_budget < 10240 ? line_budget : 10240;
      size_t value_len = line_len - (sizeof("Set-Cookie: ") - 1) - 2;
      memcpy(answer + answer_len, line_start, sizeof(line_start) - 1);
      memset(answer + answer_len + sizeof(line_start) - 1, 'v', line_len - (sizeof(line_start) - 1) - 2);
      memcpy(answer + answer_len + line_len - 2, "\r\n", 2);
      answer_len  += line_len;
      line_budget -= line_len;
      joined_len  += (copy_count > 0 ? 1 : 0) + value_len;
      copy_count++;
    }
    memcpy(answer + answer_len, head_end, sizeof(head_end));
    TEST_ASSERT_EQUAL_size_t(head_len, strlen(answer));
    TEST_ASSERT_EQUAL_size_t(30, copy_count);

    TestServer_t server;
    static_listenOnLoopback(&server);
    const char* const answers[] = { answer };
    HttpResponse_t resp = static_askTestServer(&server, answers, 1, "/", request);
    close(server.m_listenFd);
    free(answer);
    if (extra_byte_count == 0)
    {
      TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
      TEST_ASSERT_EQUAL_size_t(joined_len, strlen(resp.mp_capturedHeaderValues[0]));
      size_t newline_count = 0;
      for (const char* p = resp.mp_capturedHeaderValues[0]; (p = strchr(p, '\n')) != NULL; p++)
        newline_count++;
      TEST_ASSERT_EQUAL_size_t(29, newline_count);
      TEST_ASSERT_EQUAL_size_t(30, resp.m_setCookieCopyCount);
    }
    else
      TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
    http_free(&resp);
  }
}

typedef struct {
  int         m_listenFd;
  const char* mp_answer;
  char        ma_request[8192];
  size_t      m_requestByteCount;
  size_t      m_headByteCount;
  int         m_requestCount;
  char        ma_directory[32];
  char        ma_socketPath[64];
} TestRecordingServer_t;

static const char* static_findHeaderLine(const char* head, const char* name)
{
  size_t name_len = strlen(name);
  for (const char* line = strstr(head, "\r\n"); line != NULL; line = strstr(line + 2, "\r\n"))
  {
    if (strncasecmp(line + 2, name, name_len) == 0 && line[2 + name_len] == ':')
      return line + 2;
  }
  return NULL;
}

static void static_listenOnUnixSocket(TestRecordingServer_t* server)
{
  memset(server, 0, sizeof(*server));
  snprintf(server->ma_directory, sizeof(server->ma_directory), "/tmp/test_http.XXXXXX");
  TEST_ASSERT_NOT_NULL(mkdtemp(server->ma_directory));
  TEST_ASSERT_TRUE(snprintf(server->ma_socketPath, sizeof(server->ma_socketPath), "%s/x402.sock", server->ma_directory) < (int)sizeof(server->ma_socketPath));
  server->m_listenFd = socket(AF_UNIX, SOCK_STREAM, 0);
  TEST_ASSERT_TRUE(server->m_listenFd >= 0);
  struct timeval accept_timeout = { .tv_sec = 5 };
  TEST_ASSERT_EQUAL_INT(0, setsockopt(server->m_listenFd, SOL_SOCKET, SO_RCVTIMEO, &accept_timeout, sizeof(accept_timeout)));
  struct sockaddr_un address = { .sun_family = AF_UNIX };
  memcpy(address.sun_path, server->ma_socketPath, strlen(server->ma_socketPath) + 1);
  TEST_ASSERT_EQUAL_INT(0, bind(server->m_listenFd, (const struct sockaddr*)&address, sizeof(address)));
  TEST_ASSERT_EQUAL_INT(0, listen(server->m_listenFd, 4));
}

static void static_closeUnixSocket(TestRecordingServer_t* server)
{
  close(server->m_listenFd);
  unlink(server->ma_socketPath);
  rmdir(server->ma_directory);
}

static void* static_recordOneRequest(void* arg)
{
  TestRecordingServer_t* server = arg;
  int connection = accept(server->m_listenFd, NULL, NULL);
  if (connection < 0)
    return NULL;
  size_t capacity     = sizeof(server->ma_request) - 1;
  size_t wanted_count = capacity;
  while (server->m_requestByteCount < wanted_count)
  {
    ssize_t received = recv(connection, server->ma_request + server->m_requestByteCount, wanted_count - server->m_requestByteCount, 0);
    if (received <= 0)
      break;
    server->m_requestByteCount += (size_t)received;
    server->ma_request[server->m_requestByteCount] = '\0';
    const char* head_end = strstr(server->ma_request, "\r\n\r\n");
    if (server->m_headByteCount == 0 && head_end)
    {
      server->m_headByteCount = (size_t)(head_end - server->ma_request) + 4;
      const char* length_line = static_findHeaderLine(server->ma_request, "Content-Length");
      size_t      body_count  = length_line ? strtoul(length_line + strlen("Content-Length:"), NULL, 10) : 0;
      wanted_count = server->m_headByteCount + body_count < capacity ? server->m_headByteCount + body_count : capacity;
    }
  }
  server->m_requestCount++;
  (void)send(connection, server->mp_answer, strlen(server->mp_answer), MSG_NOSIGNAL);
  close(connection);
  return NULL;
}

static HttpResponse_t static_askRecordingServer(TestRecordingServer_t* server, const char* answer, const HttpRequest_t* request, bool is_post, const char* body, size_t body_byte_count)
{
  server->mp_answer = answer;
  pthread_t thread;
  TEST_ASSERT_EQUAL_INT(0, pthread_create(&thread, NULL, static_recordOneRequest, server));
  g_isTransferFaked    = false;
  g_isLoopbackAllowed  = true;
  g_isHeaderLookupReal = true;
  HttpResponse_t resp  = is_post ? http_POSTWithOptions(request, body, body_byte_count) : http_GETWithOptions(request);
  pthread_join(thread, NULL);
  return resp;
}

static void static_addDriveUnixAddress(const char* path)
{
  TEST_ASSERT_TRUE(g_driveAddressCount < sizeof(g_driveAddresses) / sizeof(g_driveAddresses[0]));
  TestCurlSockaddr_t* drive_address = &g_driveAddresses[g_driveAddressCount++];
  memset(drive_address, 0, sizeof(*drive_address));
  struct sockaddr_un address = { .sun_family = AF_UNIX };
  TEST_ASSERT_TRUE(strlen(path) < sizeof(address.sun_path));
  memcpy(address.sun_path, path, strlen(path) + 1);
  drive_address->m_address.family   = AF_UNIX;
  drive_address->m_address.socktype = SOCK_STREAM;
  drive_address->m_address.protocol = 0;
  drive_address->m_address.addrlen  = (unsigned int)(offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1);
  memcpy(&drive_address->m_address.addr, &address, sizeof(address));
}

void test_unix_socket_post_sends_its_exact_body_and_content_type(void)
{
  TestRecordingServer_t server;
  static_listenOnUnixSocket(&server);
  static const char  body[]          = "{\"a\":1}\0{\"b\":2}";
  const char* const  extra_headers[] = { "Content-Type: application/json", NULL };
  const HttpRequest_t request = {
    .mp_url            = "http://localhost/verify",
    .m_timeoutMs       = 3000,
    .mp_extraHeaders   = extra_headers,
    .m_isTargetTrusted = true,
    .mp_unixSocketPath = server.ma_socketPath,
  };
  HttpResponse_t resp = static_askRecordingServer(&server, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok", &request, true, body, sizeof(body) - 1);
  static_closeUnixSocket(&server);

  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(200, resp.m_status);
  TEST_ASSERT_EQUAL_STRING("ok", resp.mp_body);
  TEST_ASSERT_EQUAL_INT(1, server.m_requestCount);
  TEST_ASSERT_EQUAL_INT(0, g_socketCheckCount);
  TEST_ASSERT_EQUAL_INT(0, strncmp(server.ma_request, "POST /verify HTTP/1.1\r\n", strlen("POST /verify HTTP/1.1\r\n")));
  const char* content_type = static_findHeaderLine(server.ma_request, "Content-Type");
  TEST_ASSERT_NOT_NULL(content_type);
  TEST_ASSERT_EQUAL_INT(0, strncmp(content_type, "Content-Type: application/json\r\n", strlen("Content-Type: application/json\r\n")));
  TEST_ASSERT_EQUAL_size_t(sizeof(body) - 1, server.m_requestByteCount - server.m_headByteCount);
  TEST_ASSERT_EQUAL_MEMORY(body, server.ma_request + server.m_headByteCount, sizeof(body) - 1);
  http_free(&resp);
}

void test_post_of_2000_bytes_arrives_whole(void)
{
  TestRecordingServer_t server;
  static_listenOnUnixSocket(&server);
  char body[2000];
  memset(body, 'p', sizeof(body));
  const HttpRequest_t request = {
    .mp_url            = "http://localhost/settle",
    .m_timeoutMs       = 3000,
    .m_isTargetTrusted = true,
    .mp_unixSocketPath = server.ma_socketPath,
  };
  HttpResponse_t resp = static_askRecordingServer(&server, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", &request, true, body, sizeof(body));
  static_closeUnixSocket(&server);

  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(200, resp.m_status);
  TEST_ASSERT_TRUE(server.m_headByteCount > 0);
  TEST_ASSERT_EQUAL_size_t(sizeof(body), server.m_requestByteCount - server.m_headByteCount);
  TEST_ASSERT_EQUAL_MEMORY(body, server.ma_request + server.m_headByteCount, sizeof(body));
  http_free(&resp);
}

void test_post_with_a_null_body_sends_only_an_empty_body(void)
{
  TestRecordingServer_t server;
  static_listenOnUnixSocket(&server);
  const HttpRequest_t request = {
    .mp_url            = "http://localhost/empty",
    .m_timeoutMs       = 3000,
    .m_isTargetTrusted = true,
    .mp_unixSocketPath = server.ma_socketPath,
  };
  HttpResponse_t resp = static_askRecordingServer(&server, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", &request, true, NULL, 0);
  static_closeUnixSocket(&server);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(0, strncmp(server.ma_request, "POST /empty HTTP/1.1\r\n", strlen("POST /empty HTTP/1.1\r\n")));
  const char* content_length = static_findHeaderLine(server.ma_request, "Content-Length");
  TEST_ASSERT_NOT_NULL(content_length);
  TEST_ASSERT_EQUAL_INT(0, strncmp(content_length, "Content-Length: 0\r\n", strlen("Content-Length: 0\r\n")));
  TEST_ASSERT_EQUAL_size_t(server.m_headByteCount, server.m_requestByteCount);
  http_free(&resp);

  setUp();
  resp = http_POSTWithOptions(&request, NULL, 1);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  TEST_ASSERT_EQUAL_INT(0, g_performCount);
  http_free(&resp);
}

void test_post_to_an_untrusted_target_is_not_sent(void)
{
  HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000 };
  HttpResponse_t resp   = http_POSTWithOptions(&request, "x", 1);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  TEST_ASSERT_EQUAL_INT(0, g_performCount);
  http_free(&resp);

  setUp();
  request.m_isTargetTrusted = true;
  resp = http_POSTWithOptions(&request, "x", 1);
  TEST_ASSERT_EQUAL_INT(1, g_performCount);
  http_free(&resp);
}

void test_post_keeps_the_preconditions_of_a_get(void)
{
  HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 0, .m_isTargetTrusted = true };
  HttpResponse_t resp   = http_POSTWithOptions(&request, "x", 1);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  TEST_ASSERT_EQUAL_INT(0, g_performCount);
  http_free(&resp);

  setUp();
  request.m_timeoutMs        = 3000;
  request.m_maxBodyByteCount = HTTP_MAX_BODY + 1;
  resp = http_POSTWithOptions(&request, "x", 1);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  TEST_ASSERT_EQUAL_INT(0, g_performCount);
  http_free(&resp);

  setUp();
  const char* const extra_headers[] = { "Content-Type: application/json", NULL };
  request.m_maxBodyByteCount = 0;
  request.mp_extraHeaders    = extra_headers;
  g_slistAppendFailCall      = 1;
  resp = http_POSTWithOptions(&request, "x", 1);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  TEST_ASSERT_EQUAL_INT(0, g_performCount);
  http_free(&resp);
}

void test_post_returns_a_redirect_with_its_target(void)
{
  TestRecordingServer_t server;
  static_listenOnUnixSocket(&server);
  const HttpRequest_t request = {
    .mp_url            = "http://localhost/verify",
    .m_timeoutMs       = 3000,
    .m_isTargetTrusted = true,
    .mp_unixSocketPath = server.ma_socketPath,
  };
  HttpResponse_t resp = static_askRecordingServer(&server, "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", &request, true, "x", 1);
  static_closeUnixSocket(&server);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(302, resp.m_status);
  TEST_ASSERT_EQUAL_STRING("http://localhost/next", resp.mp_redirectUrl);
  TEST_ASSERT_EQUAL_INT(1, server.m_requestCount);
  http_free(&resp);
}

void test_unix_socket_request_speaks_http_alone_and_follows_no_redirect(void)
{
  const HttpRequest_t request = { .mp_url = "http://localhost/health", .m_timeoutMs = 3000, .m_isTargetTrusted = true, .mp_unixSocketPath = "/run/contrastapi-x402/x402.sock" };
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(1, g_performCount);
  TEST_ASSERT_EQUAL_STRING("/run/contrastapi-x402/x402.sock", g_unixSocketPath);
  TEST_ASSERT_EQUAL_STRING("http", g_protocolsStr);
  TEST_ASSERT_EQUAL_STRING("http", g_redirProtocolsStr);
  TEST_ASSERT_EQUAL_INT(0, g_followLocation);
  http_free(&resp);
}

void test_unix_socket_get_reaches_the_server_without_ipguard(void)
{
  TestRecordingServer_t server;
  static_listenOnUnixSocket(&server);
  const HttpRequest_t request = { .mp_url = "http://localhost/health", .m_timeoutMs = 3000, .m_isTargetTrusted = true, .mp_unixSocketPath = server.ma_socketPath };
  HttpResponse_t resp = static_askRecordingServer(&server, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nup", &request, false, NULL, 0);
  static_closeUnixSocket(&server);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_NONE, resp.m_error);
  TEST_ASSERT_EQUAL_INT(200, resp.m_status);
  TEST_ASSERT_EQUAL_STRING("up", resp.mp_body);
  TEST_ASSERT_EQUAL_INT(0, strncmp(server.ma_request, "GET /health HTTP/1.1\r\n", strlen("GET /health HTTP/1.1\r\n")));
  TEST_ASSERT_EQUAL_INT(0, g_socketCheckCount);
  http_free(&resp);
}

void test_unix_socket_request_that_is_untrusted_on_a_port_or_too_long_is_not_sent(void)
{
  HttpRequest_t request = { .mp_url = "http://localhost/", .m_timeoutMs = 3000, .mp_unixSocketPath = "/run/contrastapi-x402/x402.sock" };
  HttpResponse_t resp   = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  TEST_ASSERT_EQUAL_INT(0, g_performCount);
  http_free(&resp);

  setUp();
  request.m_isTargetTrusted = true;
  request.m_requiredPort    = 443;
  resp = http_POSTWithOptions(&request, "x", 1);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  TEST_ASSERT_EQUAL_INT(0, g_performCount);
  http_free(&resp);

  setUp();
  char long_path[sizeof(((struct sockaddr_un*)0)->sun_path) + 1];
  memset(long_path, 'u', sizeof(long_path) - 1);
  long_path[0]                     = '/';
  long_path[sizeof(long_path) - 1] = '\0';
  request.m_requiredPort      = 0;
  request.mp_unixSocketPath   = long_path;
  resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_OTHER, resp.m_error);
  TEST_ASSERT_EQUAL_INT(0, g_performCount);
  http_free(&resp);

  setUp();
  long_path[sizeof(long_path) - 2] = '\0';
  resp = http_GETWithOptions(&request);
  TEST_ASSERT_EQUAL_INT(1, g_performCount);
  TEST_ASSERT_EQUAL_STRING(long_path, g_unixSocketPath);
  http_free(&resp);
}

void test_unix_socket_check_accepts_only_its_own_path(void)
{
  const HttpRequest_t request = { .mp_url = "http://localhost/", .m_timeoutMs = 3000, .m_isTargetTrusted = true, .mp_unixSocketPath = "/tmp/x402.sock" };
  static_addDriveUnixAddress("/tmp/x402.sock");
  static_addDriveAddress("8.8.8.8");
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_TRUE(g_isDrivenSocketOpen[0]);
  TEST_ASSERT_FALSE(g_isDrivenSocketOpen[1]);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_BLOCKED, resp.m_error);
  http_free(&resp);

  setUp();
  static_addDriveUnixAddress("/tmp/x402.soc");
  static_addDriveUnixAddress("/tmp/x402.sockx");
  resp = http_POSTWithOptions(&request, "x", 1);
  TEST_ASSERT_FALSE(g_isDrivenSocketOpen[0]);
  TEST_ASSERT_FALSE(g_isDrivenSocketOpen[1]);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_BLOCKED, resp.m_error);
  http_free(&resp);

  setUp();
  static_addDriveUnixAddress("/tmp/x402.sock");
  resp = http_GETWithOptions(&request);
  TEST_ASSERT_TRUE(g_isDrivenSocketOpen[0]);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_CONNECT, resp.m_error);
  TEST_ASSERT_EQUAL_INT(0, g_socketCheckCount);
  http_free(&resp);
}

void test_unix_socket_check_takes_a_path_that_fills_sun_path(void)
{
  char full_path[sizeof(((struct sockaddr_un*)0)->sun_path)];
  memset(full_path, 'f', sizeof(full_path) - 1);
  full_path[0]                     = '/';
  full_path[sizeof(full_path) - 1] = '\0';
  const HttpRequest_t request = { .mp_url = "http://localhost/", .m_timeoutMs = 3000, .m_isTargetTrusted = true, .mp_unixSocketPath = full_path };
  static_addDriveUnixAddress(full_path);
  TEST_ASSERT_EQUAL_UINT(sizeof(struct sockaddr_un), g_driveAddresses[0].m_address.addrlen);
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_TRUE(g_isDrivenSocketOpen[0]);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_CONNECT, resp.m_error);
  http_free(&resp);

  setUp();
  static_addDriveUnixAddress(full_path);
  g_driveAddresses[0].m_address.addrlen = (unsigned int)sizeof(struct sockaddr_un) + 1;
  resp = http_GETWithOptions(&request);
  TEST_ASSERT_FALSE(g_isDrivenSocketOpen[0]);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_BLOCKED, resp.m_error);
  http_free(&resp);
}

void test_network_socket_check_refuses_a_unix_socket_address(void)
{
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .m_isTargetTrusted = true };
  static_addDriveUnixAddress("/tmp/x402.sock");
  HttpResponse_t resp = http_POSTWithOptions(&request, "x", 1);
  TEST_ASSERT_FALSE(g_isDrivenSocketOpen[0]);
  TEST_ASSERT_EQUAL_INT(1, g_socketCheckCount);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_BLOCKED, resp.m_error);
  http_free(&resp);
}

void test_network_post_follows_no_redirect(void)
{
  const HttpRequest_t request = { .mp_url = "https://example.invalid/", .m_timeoutMs = 3000, .m_isTargetTrusted = true };
  HttpResponse_t resp = http_POSTWithOptions(&request, "x", 1);
  TEST_ASSERT_EQUAL_INT(1, g_performCount);
  TEST_ASSERT_EQUAL_INT32(0, g_followLocation);
  http_free(&resp);
}

void test_unix_socket_check_refuses_another_family_with_the_path_bytes(void)
{
  const HttpRequest_t request = { .mp_url = "http://localhost/", .m_timeoutMs = 3000, .m_isTargetTrusted = true, .mp_unixSocketPath = "/tmp/x402.sock" };
  static_addDriveUnixAddress("/tmp/x402.sock");
  g_driveAddresses[0].m_address.family = AF_INET6;
  HttpResponse_t resp = http_GETWithOptions(&request);
  TEST_ASSERT_FALSE(g_isDrivenSocketOpen[0]);
  TEST_ASSERT_EQUAL_INT(HTTP_ERROR_BLOCKED, resp.m_error);
  http_free(&resp);
}

void test_post_or_unix_socket_request_whose_option_cannot_be_set_is_not_sent(void)
{
  static const struct { CURLoption m_option; const char* mp_name; } options[] = {
    { CURLOPT_POSTFIELDS,          "POSTFIELDS"          },
    { CURLOPT_POSTFIELDSIZE_LARGE, "POSTFIELDSIZE_LARGE" },
    { CURLOPT_UNIX_SOCKET_PATH,    "UNIX_SOCKET_PATH"    },
  };
  const HttpRequest_t request = { .mp_url = "http://localhost/", .m_timeoutMs = 3000, .m_isTargetTrusted = true, .mp_unixSocketPath = "/run/contrastapi-x402/x402.sock" };
  for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); i++)
  {
    setUp();
    g_setoptFailOption  = options[i].m_option;
    HttpResponse_t resp = http_POSTWithOptions(&request, "x", 1);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_performCount, options[i].mp_name);
    TEST_ASSERT_EQUAL_INT_MESSAGE(HTTP_ERROR_OTHER, resp.m_error, options[i].mp_name);
    http_free(&resp);
  }
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_http_free_null_body);
  RUN_TEST(test_http_free_null_ptr);
  RUN_TEST(test_upstream_request_is_https_only_with_a_connect_timeout);
  RUN_TEST(test_extra_header_is_handed_to_libcurl);
  RUN_TEST(test_file_url_is_refused);
  RUN_TEST(test_request_timeout_and_redirect_bound_reach_libcurl);
  RUN_TEST(test_request_whose_header_cannot_be_added_is_not_sent);
  RUN_TEST(test_every_request_ignores_proxies_and_names_the_bot_page);
  RUN_TEST(test_request_whose_option_cannot_be_set_is_not_sent);
  RUN_TEST(test_untrusted_request_whose_socket_check_cannot_be_set_is_not_sent);
  RUN_TEST(test_failed_transfer_reports_its_error_class);
  RUN_TEST(test_finished_transfer_reports_no_error);
  RUN_TEST(test_body_at_the_limit_is_kept_and_one_byte_more_is_refused);
  RUN_TEST(test_default_body_limit_is_HTTP_MAX_BODY);
  RUN_TEST(test_body_limit_above_HTTP_MAX_BODY_is_not_sent);
  RUN_TEST(test_body_that_cannot_grow_is_not_too_large);
  RUN_TEST(test_every_extra_header_is_handed_to_libcurl);
  RUN_TEST(test_request_whose_second_header_cannot_be_added_is_not_sent);
  RUN_TEST(test_named_response_headers_are_captured);
  RUN_TEST(test_request_without_header_names_captures_nothing);
  RUN_TEST(test_answer_without_headers_captures_null);
  RUN_TEST(test_header_that_cannot_be_captured_fails_the_answer);
  RUN_TEST(test_only_untrusted_target_may_use_http_and_every_request_checks_its_sockets);
  RUN_TEST(test_socket_check_refuses_an_address_that_is_not_globally_reachable);
  RUN_TEST(test_socket_check_opens_a_socket_for_a_globally_reachable_address);
  RUN_TEST(test_refused_address_before_a_finished_transfer_is_no_error);
  RUN_TEST(test_body_too_large_after_a_refused_address_is_body_too_large);
  RUN_TEST(test_timeout_after_a_refused_address_is_a_timeout);
  RUN_TEST(test_loopback_target_is_blocked_trusted_or_not);
  RUN_TEST(test_redirect_to_a_refused_address_is_blocked);
  RUN_TEST(test_loopback_answer_carries_status_body_and_header);
  RUN_TEST(test_captured_header_comes_from_the_last_answer_of_a_redirect);
  RUN_TEST(test_request_without_a_positive_timeout_is_not_sent);
  RUN_TEST(test_untrusted_request_with_an_extra_header_is_not_sent);
  RUN_TEST(test_captured_values_follow_the_order_of_the_names);
  RUN_TEST(test_failed_copy_of_a_later_header_fails_the_answer);
  RUN_TEST(test_each_entry_point_hands_its_own_timeout_to_libcurl);
  RUN_TEST(test_loopback_404_is_an_answer_and_http_free_clears_it);
  RUN_TEST(test_nul_byte_in_the_body_counts_in_its_length);
  RUN_TEST(test_large_pieces_are_kept_whole);
  RUN_TEST(test_refused_address_then_a_failed_connection_is_blocked);
  RUN_TEST(test_body_limit_of_one_byte_is_a_limit);
  RUN_TEST(test_https_only_request_is_limited_to_https_untrusted_or_not);
  RUN_TEST(test_https_only_request_refuses_an_http_url);
  RUN_TEST(test_returned_redirect_carries_its_status_headers_and_absolute_target);
  RUN_TEST(test_returned_redirect_without_a_location_has_no_target);
  RUN_TEST(test_redirect_target_that_cannot_be_copied_fails_the_answer);
  RUN_TEST(test_returned_redirect_whose_body_is_cut_has_no_target);
  RUN_TEST(test_accepted_body_cut_keeps_the_answer_and_the_body_up_to_the_limit);
  RUN_TEST(test_accepted_body_cut_between_two_pieces_keeps_the_whole_pieces);
  RUN_TEST(test_accepted_body_cut_that_cannot_grow_fails_the_answer);
  RUN_TEST(test_accepted_body_cut_reads_the_status_and_headers_of_a_loopback_answer);
  RUN_TEST(test_required_port_refuses_an_address_on_another_port);
  RUN_TEST(test_required_port_of_0_allows_any_port);
  RUN_TEST(test_required_port_lets_through_only_the_loopback_server_port);
  RUN_TEST(test_every_copy_of_a_captured_header_is_joined_in_order);
  RUN_TEST(test_header_copies_past_HTTP_MAX_HEADER_COPY_COUNT_fail_the_answer);
  RUN_TEST(test_later_copy_that_cannot_be_joined_fails_the_answer);
  RUN_TEST(test_loopback_header_copies_join_and_early_hints_stay_out);
  RUN_TEST(test_set_cookie_copies_are_joined_with_a_newline_in_order);
  RUN_TEST(test_set_cookie_copies_past_HTTP_MAX_SET_COOKIE_COPY_COUNT_join_the_first_ones_and_count_all);
  RUN_TEST(test_set_cookie_name_matches_in_any_case_and_a_longer_name_keeps_the_comma);
  RUN_TEST(test_answer_without_set_cookie_captures_null);
  RUN_TEST(test_loopback_set_cookie_copies_join_with_a_newline_and_early_hints_stay_out);
  RUN_TEST(test_loopback_answer_head_of_300_KiB_is_read_and_one_byte_more_fails);
  RUN_TEST(test_unix_socket_post_sends_its_exact_body_and_content_type);
  RUN_TEST(test_post_of_2000_bytes_arrives_whole);
  RUN_TEST(test_post_with_a_null_body_sends_only_an_empty_body);
  RUN_TEST(test_post_to_an_untrusted_target_is_not_sent);
  RUN_TEST(test_post_keeps_the_preconditions_of_a_get);
  RUN_TEST(test_post_returns_a_redirect_with_its_target);
  RUN_TEST(test_unix_socket_request_speaks_http_alone_and_follows_no_redirect);
  RUN_TEST(test_unix_socket_get_reaches_the_server_without_ipguard);
  RUN_TEST(test_unix_socket_request_that_is_untrusted_on_a_port_or_too_long_is_not_sent);
  RUN_TEST(test_unix_socket_check_accepts_only_its_own_path);
  RUN_TEST(test_unix_socket_check_takes_a_path_that_fills_sun_path);
  RUN_TEST(test_network_socket_check_refuses_a_unix_socket_address);
  RUN_TEST(test_network_post_follows_no_redirect);
  RUN_TEST(test_unix_socket_check_refuses_another_family_with_the_path_bytes);
  RUN_TEST(test_post_or_unix_socket_request_whose_option_cannot_be_set_is_not_sent);
  return UNITY_END();
}
