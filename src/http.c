#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <curl/curl.h>

#include "http.h"
#include "ipguard.h"

typedef struct {
  char*   mp_data;
  size_t  m_writtenByteCount;
  size_t  m_allocatedByteCount;
  size_t  m_maxByteCount;
  bool    m_isBodyTooLarge;
  bool    m_isBodyCutAccepted;
} HttpWriteBuf_t;

typedef struct {
  uint16_t     m_requiredPort;
  const char*  mp_unixSocketPath;
  bool         m_isAddressRefused;
} HttpSocketCheck_t;

#define HTTP_MAX_REDIRECTS 5

#define HTTP_HEADER_COPY_SEPARATOR ", "

#define HTTP_SET_COOKIE_COPY_SEPARATOR "\n"

static size_t         static_receiveBodyPiece           (char* received_bytes, size_t item_byte_count, size_t item_count, void* write_buf_arg);
static bool           static_tryAppendBodyBytes         (HttpWriteBuf_t* write_buf, const char* bytes, size_t byte_count);
static HttpResponse_t static_makeTransferError          (HttpError_t error);
static HttpWriteBuf_t static_createWriteBuf             (size_t max_byte_count, bool is_body_cut_accepted);
static HttpResponse_t static_sendRequest                (const HttpRequest_t* request, const char* post_body, size_t post_body_byte_count);
static bool           static_isUnixSocketRequestAllowed (const HttpRequest_t* request);
static bool           static_tryBuildHeaderList         (const char* const* extra_headers, struct curl_slist** header_list_out);
static bool           static_applyRequestOptions        (CURL* curl, const HttpRequest_t* request, HttpWriteBuf_t* write_buf, const struct curl_slist* header_list, bool is_redirect_followed);
static bool           static_applyPostBody              (CURL* curl, const char* post_body, size_t post_body_byte_count);
static bool           static_applyTransferGuards        (CURL* curl, const HttpRequest_t* request, HttpSocketCheck_t* socket_check);
static curl_socket_t  static_openAllowedSocket          (void* socket_check_arg, curlsocktype purpose, struct curl_sockaddr* address);
static bool           static_isOnRequiredPort           (const struct curl_sockaddr* address, uint16_t required_port);
static bool           static_isOwnUnixSocketAddress     (const struct curl_sockaddr* address, const char* unix_socket_path);
static HttpResponse_t static_runCurl                    (CURL* curl, HttpWriteBuf_t* write_buf, const HttpSocketCheck_t* socket_check, const char* const* header_names);
static HttpError_t    static_classifyTransferError      (CURLcode curl_result, bool is_body_too_large, bool is_address_refused);
static bool           static_tryCopyRedirectUrl         (CURL* curl, HttpResponse_t* response);
static bool           static_tryCaptureHeaders          (CURL* curl, const char* const* header_names, HttpResponse_t* response);
static bool           static_tryAppendHeaderCopy        (char** captured_header_value_inout, const char* copy_separator, const char* copy_value);

HttpResponse_t http_GET(const char* url, int timeout_ms, const char* extra_header)
{
  const char* const extra_headers[] = { extra_header, NULL };
  const HttpRequest_t request = {
    .mp_url            = url,
    .m_timeoutMs       = timeout_ms,
    .mp_extraHeaders   = extra_headers,
    .m_isTargetTrusted = true,
  };
  return http_GETWithOptions(&request);
}

HttpResponse_t http_GETWithOptions(const HttpRequest_t* request)
{
  assert(request != NULL);

  return static_sendRequest(request, NULL, 0);
}

HttpResponse_t http_POSTWithOptions(const HttpRequest_t* request, const char* body, size_t body_byte_count)
{
  assert(request != NULL);

  if (body == NULL && body_byte_count > 0)
    return static_makeTransferError(HTTP_ERROR_OTHER);
  return static_sendRequest(request, body ? body : "", body_byte_count);
}

void http_free(HttpResponse_t* response)
{
  if (!response)
    return;

  free(response->mp_body);

  for (int i = 0; i < response->m_capturedHeaderValueCount; i++)
    free(response->mp_capturedHeaderValues[i]);
  free(response->mp_capturedHeaderValues);
  free(response->mp_redirectUrl);

  *response = (HttpResponse_t){ 0 };
}

void http_globalInit(void)
{
  curl_global_init(CURL_GLOBAL_DEFAULT);
}

void http_globalCleanup(void)
{
  curl_global_cleanup();
}

static size_t static_receiveBodyPiece(char* received_bytes, size_t item_byte_count, size_t item_count, void* write_buf_arg)
{
  HttpWriteBuf_t* write_buf           = write_buf_arg;
  size_t          received_byte_count = item_byte_count * item_count;
  size_t          room_byte_count     = write_buf->m_maxByteCount - write_buf->m_writtenByteCount;

  if (received_byte_count <= room_byte_count)
    return static_tryAppendBodyBytes(write_buf, received_bytes, received_byte_count) ? received_byte_count : 0;

  if (write_buf->m_isBodyCutAccepted && !static_tryAppendBodyBytes(write_buf, received_bytes, room_byte_count))
    return 0;
  write_buf->m_isBodyTooLarge = true;
  return 0;
}

static bool static_tryAppendBodyBytes(HttpWriteBuf_t* write_buf, const char* bytes, size_t byte_count)
{
  assert(write_buf != NULL);
  assert(write_buf->m_writtenByteCount <= write_buf->m_maxByteCount);
  assert(byte_count <= write_buf->m_maxByteCount - write_buf->m_writtenByteCount);

  size_t needed_byte_count = write_buf->m_writtenByteCount + byte_count + 1;
  if (needed_byte_count > write_buf->m_allocatedByteCount)
  {
    size_t new_allocated_byte_count = write_buf->m_allocatedByteCount * 2 + byte_count + 1;
    char*  expanded_data = realloc(write_buf->mp_data, new_allocated_byte_count);
    if (!expanded_data)
      return false;

    write_buf->mp_data              = expanded_data;
    write_buf->m_allocatedByteCount = new_allocated_byte_count;
  }

  memcpy(write_buf->mp_data + write_buf->m_writtenByteCount, bytes, byte_count);
  write_buf->m_writtenByteCount += byte_count;
  write_buf->mp_data[write_buf->m_writtenByteCount] = '\0';
  return true;
}

static HttpResponse_t static_makeTransferError(HttpError_t error)
{
  return (HttpResponse_t){ .m_status = 0, .mp_body = NULL, .m_bodyLen = 0, .m_error = error };
}

static HttpWriteBuf_t static_createWriteBuf(size_t max_byte_count, bool is_body_cut_accepted)
{
  HttpWriteBuf_t write_buf = {  .mp_data              = malloc(4096),
                                .m_writtenByteCount   = 0,
                                .m_allocatedByteCount = 4096,
                                .m_maxByteCount       = max_byte_count,
                                .m_isBodyCutAccepted  = is_body_cut_accepted };
  if (write_buf.mp_data)
    write_buf.mp_data[0] = '\0';

  return write_buf;
}

static HttpResponse_t static_sendRequest(const HttpRequest_t* request, const char* post_body, size_t post_body_byte_count)
{
  assert(request         != NULL);
  assert(request->mp_url != NULL);

  bool   is_post_request     = post_body != NULL;
  bool   has_extra_header    = request->mp_extraHeaders && request->mp_extraHeaders[0];
  size_t max_body_byte_count = request->m_maxBodyByteCount == 0 ? HTTP_MAX_BODY : request->m_maxBodyByteCount;
  if (request->m_timeoutMs <= 0 || max_body_byte_count > HTTP_MAX_BODY || (has_extra_header && !request->m_isTargetTrusted))
    return static_makeTransferError(HTTP_ERROR_OTHER);
  if ((is_post_request && !request->m_isTargetTrusted) || !static_isUnixSocketRequestAllowed(request))
    return static_makeTransferError(HTTP_ERROR_OTHER);

  CURL* curl = curl_easy_init();
  if (!curl)
    return static_makeTransferError(HTTP_ERROR_OTHER);

  HttpWriteBuf_t write_buf = static_createWriteBuf(max_body_byte_count, request->m_isBodyCutAccepted);
  if (!write_buf.mp_data)
  {
    curl_easy_cleanup(curl);
    return static_makeTransferError(HTTP_ERROR_OTHER);
  }

  bool               is_redirect_followed = !request->m_isRedirectLeftToCaller && !is_post_request && request->mp_unixSocketPath == NULL;
  struct curl_slist* header_list          = NULL;
  HttpSocketCheck_t  socket_check         = { .m_requiredPort = request->m_requiredPort, .mp_unixSocketPath = request->mp_unixSocketPath };
  if (!static_tryBuildHeaderList(request->mp_extraHeaders, &header_list)                         ||
      !static_applyRequestOptions(curl, request, &write_buf, header_list, is_redirect_followed)  ||
      (is_post_request && !static_applyPostBody(curl, post_body, post_body_byte_count))          ||
      !static_applyTransferGuards(curl, request, &socket_check))
  {
    curl_slist_free_all(header_list);
    free(write_buf.mp_data);
    curl_easy_cleanup(curl);
    return static_makeTransferError(HTTP_ERROR_OTHER);
  }

  HttpResponse_t response = static_runCurl(curl, &write_buf, &socket_check, request->mp_headerNamesToCapture);

  curl_slist_free_all(header_list);
  return response;
}

static bool static_isUnixSocketRequestAllowed(const HttpRequest_t* request)
{
  assert(request != NULL);

  if (request->mp_unixSocketPath == NULL)
    return true;
  return request->m_isTargetTrusted && request->m_requiredPort == 0 &&
         strlen(request->mp_unixSocketPath) < sizeof(((struct sockaddr_un*)0)->sun_path);
}

static bool static_tryBuildHeaderList(const char* const* extra_headers, struct curl_slist** header_list_out)
{
  assert(header_list_out != NULL);

  struct curl_slist* header_list = NULL;
  for (size_t i = 0; extra_headers && extra_headers[i]; i++)
  {
    struct curl_slist* extended_list = curl_slist_append(header_list, extra_headers[i]);
    if (!extended_list)
    {
      curl_slist_free_all(header_list);
      return false;
    }
    header_list = extended_list;
  }

  *header_list_out = header_list;
  return true;
}

static bool static_applyRequestOptions(CURL* curl, const HttpRequest_t* request, HttpWriteBuf_t* write_buf, const struct curl_slist* header_list, bool is_redirect_followed)
{
  assert(curl      != NULL);
  assert(request   != NULL);
  assert(write_buf != NULL);

  long follow_location = is_redirect_followed ? 1L : 0L;
  bool is_set = curl_easy_setopt(curl, CURLOPT_URL, request->mp_url) == CURLE_OK                              &&
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, static_receiveBodyPiece) == CURLE_OK            &&
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, write_buf) == CURLE_OK                              &&
                curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)request->m_timeoutMs) == CURLE_OK            &&
                curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, follow_location) == CURLE_OK                   &&
                curl_easy_setopt(curl, CURLOPT_USERAGENT, HTTP_USER_AGENT) == CURLE_OK                        &&
                (header_list == NULL || curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list) == CURLE_OK);
  return is_set;
}

static bool static_applyPostBody(CURL* curl, const char* post_body, size_t post_body_byte_count)
{
  assert(curl      != NULL);
  assert(post_body != NULL);

  bool is_set = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body) == CURLE_OK  &&
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)post_body_byte_count) == CURLE_OK;
  return is_set;
}

static bool static_applyTransferGuards(CURL* curl, const HttpRequest_t* request, HttpSocketCheck_t* socket_check)
{
  assert(curl         != NULL);
  assert(request      != NULL);
  assert(socket_check != NULL);

  const char* protocols = request->mp_unixSocketPath ? "http" : request->m_isTargetTrusted || request->m_isHttpsOnly ? "https" : "http,https";
  bool is_guarded = curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) == CURLE_OK                                      &&
                    curl_easy_setopt(curl, CURLOPT_QUICK_EXIT, 1L) == CURLE_OK                                    &&
                    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, protocols) == CURLE_OK                          &&
                    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, protocols) == CURLE_OK                    &&
                    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, (long)HTTP_MAX_REDIRECTS) == CURLE_OK               &&
                    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, (long)HTTP_CONNECT_TIMEOUT_MS) == CURLE_OK  &&
                    curl_easy_setopt(curl, CURLOPT_PROXY, "") == CURLE_OK                                         &&
                    curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, static_openAllowedSocket) == CURLE_OK      &&
                    curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, socket_check) == CURLE_OK                      &&
                    (request->mp_unixSocketPath == NULL ||
                     curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, request->mp_unixSocketPath) == CURLE_OK);

  return is_guarded;
}

static curl_socket_t static_openAllowedSocket(void* socket_check_arg, curlsocktype purpose, struct curl_sockaddr* address)
{
  assert(socket_check_arg != NULL);
  assert(address          != NULL);
  (void)purpose;
  HttpSocketCheck_t* socket_check = socket_check_arg;

  bool is_accepted = socket_check->mp_unixSocketPath != NULL
                   ? static_isOwnUnixSocketAddress(address, socket_check->mp_unixSocketPath)
                   : ipguard_isGloballyReachableSockaddr(&address->addr, (socklen_t)address->addrlen) &&
                     static_isOnRequiredPort(address, socket_check->m_requiredPort);
  if (!is_accepted)
  {
    socket_check->m_isAddressRefused = true;
    return CURL_SOCKET_BAD;
  }
  return socket(address->family, address->socktype, address->protocol);
}

static bool static_isOnRequiredPort(const struct curl_sockaddr* address, uint16_t required_port)
{
  assert(address != NULL);

  if (required_port == 0)
    return true;
  if (address->family != AF_INET && address->family != AF_INET6)
    return false;

  in_port_t port = 0;
  if (address->family == AF_INET)
  {
    struct sockaddr_in ipv4_address;
    memcpy(&ipv4_address, &address->addr, sizeof(ipv4_address));
    port = ipv4_address.sin_port;
  }
  else
  {
    struct sockaddr_in6 ipv6_address;
    memcpy(&ipv6_address, &address->addr, sizeof(ipv6_address));
    port = ipv6_address.sin6_port;
  }

  return ntohs(port) == required_port;
}

static bool static_isOwnUnixSocketAddress(const struct curl_sockaddr* address, const char* unix_socket_path)
{
  assert(address          != NULL);
  assert(unix_socket_path != NULL);

  size_t path_byte_count = strlen(unix_socket_path) + 1;
  size_t path_offset     = offsetof(struct sockaddr_un, sun_path);
  if (address->family != AF_UNIX || address->addrlen < path_offset + path_byte_count || address->addrlen > sizeof(struct sockaddr_un))
    return false;

  struct sockaddr_un unix_address;
  memcpy(&unix_address, &address->addr, address->addrlen);
  return memcmp(unix_address.sun_path, unix_socket_path, path_byte_count) == 0;
}

static HttpResponse_t static_runCurl(CURL* curl, HttpWriteBuf_t* write_buf, const HttpSocketCheck_t* socket_check, const char* const* header_names)
{
  assert(curl         != NULL);
  assert(write_buf    != NULL);
  assert(socket_check != NULL);

  CURLcode curl_result = curl_easy_perform(curl);
  bool     is_body_cut = write_buf->m_isBodyTooLarge && write_buf->m_isBodyCutAccepted;
  if (curl_result != CURLE_OK && !is_body_cut)
  {
    free(write_buf->mp_data);
    curl_easy_cleanup(curl);
    return static_makeTransferError(static_classifyTransferError(curl_result, write_buf->m_isBodyTooLarge, socket_check->m_isAddressRefused));
  }

  long http_status = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);

  HttpResponse_t response = {
    .m_status    = (int)http_status,
    .mp_body     = write_buf->mp_data,
    .m_bodyLen   = write_buf->m_writtenByteCount,
    .m_error     = HTTP_ERROR_NONE,
    .m_isBodyCut = is_body_cut
  };

  if (!static_tryCopyRedirectUrl(curl, &response) || !static_tryCaptureHeaders(curl, header_names, &response))
  {
    http_free(&response);
    response = static_makeTransferError(HTTP_ERROR_OTHER);
  }

  curl_easy_cleanup(curl);
  return response;
}

static HttpError_t static_classifyTransferError(CURLcode curl_result, bool is_body_too_large, bool is_address_refused)
{
  if (is_body_too_large)
    return HTTP_ERROR_BODY_TOO_LARGE;
  if (is_address_refused && curl_result == CURLE_COULDNT_CONNECT)
    return HTTP_ERROR_BLOCKED;

  switch (curl_result)
  {
    case CURLE_OPERATION_TIMEDOUT:       return HTTP_ERROR_TIMEOUT;
    case CURLE_COULDNT_RESOLVE_HOST:     return HTTP_ERROR_RESOLVE;
    case CURLE_COULDNT_CONNECT:          return HTTP_ERROR_CONNECT;
    case CURLE_SSL_CONNECT_ERROR:        return HTTP_ERROR_TLS;
    case CURLE_PEER_FAILED_VERIFICATION: return HTTP_ERROR_TLS;
    default:                             return HTTP_ERROR_OTHER;
  }
}

static bool static_tryCopyRedirectUrl(CURL* curl, HttpResponse_t* response)
{
  assert(curl != NULL);
  assert(response != NULL);

  char* redirect_url = NULL;
  curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirect_url);
  if (!redirect_url)
    return true;

  response->mp_redirectUrl = strdup(redirect_url);
  return response->mp_redirectUrl != NULL;
}

static bool static_tryCaptureHeaders(CURL* curl, const char* const* header_names, HttpResponse_t* response)
{
  assert(curl != NULL);
  assert(response != NULL);

  int header_name_count = 0;
  while (header_names && header_names[header_name_count])
    header_name_count++;

  if (header_name_count == 0)
    return true;

  response->mp_capturedHeaderValues = calloc((size_t)header_name_count, sizeof(*response->mp_capturedHeaderValues));
  if (!response->mp_capturedHeaderValues)
    return false;
  response->m_capturedHeaderValueCount = header_name_count;

  for (int i = 0; i < header_name_count; i++)
  {
    struct curl_header* header = NULL;
    CURLHcode header_result = curl_easy_header(curl, header_names[i], 0, CURLH_HEADER, -1, &header);
    if (header_result == CURLHE_MISSING || header_result == CURLHE_NOHEADERS)
      continue;
    else if (header_result != CURLHE_OK)
      return false;

    size_t      header_copy_count = header->amount;
    bool        is_set_cookie     = strcasecmp(header_names[i], "Set-Cookie") == 0;
    const char* copy_separator    = is_set_cookie ? HTTP_SET_COOKIE_COPY_SEPARATOR : HTTP_HEADER_COPY_SEPARATOR;
    if (is_set_cookie)
    {
      response->m_setCookieCopyCount = header_copy_count;
      if (header_copy_count > HTTP_MAX_SET_COOKIE_COPY_COUNT)
        header_copy_count = HTTP_MAX_SET_COOKIE_COPY_COUNT;
    }
    else if (header_copy_count > HTTP_MAX_HEADER_COPY_COUNT)
      return false;

    response->mp_capturedHeaderValues[i] = strdup(header->value);
    if (!response->mp_capturedHeaderValues[i])
      return false;

    for (size_t copy_index = 1; copy_index < header_copy_count; copy_index++)
    {
      if (curl_easy_header(curl, header_names[i], copy_index, CURLH_HEADER, -1, &header) != CURLHE_OK)
        return false;
      if (!static_tryAppendHeaderCopy(&response->mp_capturedHeaderValues[i], copy_separator, header->value))
        return false;
    }
  }
  return true;
}

static bool static_tryAppendHeaderCopy(char** captured_header_value_inout, const char* copy_separator, const char* copy_value)
{
  assert(captured_header_value_inout  != NULL);
  assert(*captured_header_value_inout != NULL);
  assert(copy_separator               != NULL);
  assert(copy_value                   != NULL);

  size_t captured_header_value_len = strlen(*captured_header_value_inout);
  size_t separator_len             = strlen(copy_separator);
  size_t copy_len                  = strlen(copy_value);
  char*  extended_value            = realloc(*captured_header_value_inout, captured_header_value_len + separator_len + copy_len + 1);
  if (!extended_value)
    return false;

  memcpy(extended_value + captured_header_value_len, copy_separator, separator_len);
  memcpy(extended_value + captured_header_value_len + separator_len, copy_value, copy_len + 1);
  *captured_header_value_inout = extended_value;

  return true;
}
