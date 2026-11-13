#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "http.h"
#include "http_stub.h"

char                    g_stub_last_url[1024]   = "";
char                    g_stub_last_header[512] = "";
int                     g_stub_http_call_count  = 0;
int                     g_stub_next_status      = 200;
const char*             g_stub_next_body        = NULL;
bool                    g_stub_next_body_null   = false;
int                     g_stub_last_timeout_ms  = -1;
size_t                  g_stub_last_max_body_byte_count = 0;
bool                    g_stub_last_is_target_trusted   = false;
HttpError_t             g_stub_next_error               = HTTP_ERROR_NONE;
char                    g_stub_last_post_body[HTTP_STUB_MAX_POST_BODY_BYTE_COUNT + 1] = "";
size_t                  g_stub_last_post_body_byte_count = 0;
char                    g_stub_last_unix_socket_path[256] = "";
HttpStubRequest_t       g_stub_requests[HTTP_STUB_MAX_REQUEST_COUNT];
const HttpStubAnswer_t* g_stub_answers                  = NULL;
int                     g_stub_answer_count             = 0;

static void static_joinLines(const char* const* lines, char* joined, size_t joined_size)
{
  size_t used = 0;
  joined[0]   = '\0';
  for (const char* const* line = lines; line != NULL && *line != NULL; line++)
  {
    int written = snprintf(joined + used, joined_size - used, "%s%s", used > 0 ? "\n" : "", *line);
    if (written < 0 || (size_t)written >= joined_size - used)
    {
      joined[used] = '\0';
      break;
    }
    used += (size_t)written;
  }
}

static const char* static_findHeaderValue(const char* const* header_lines, const char* name)
{
  size_t name_len = strlen(name);
  for (const char* const* line = header_lines; line != NULL && *line != NULL; line++)
  {
    if (strncasecmp(*line, name, name_len) != 0 || (*line)[name_len] != ':')
      continue;
    const char* value = *line + name_len + 1;
    while (*value == ' ' || *value == '\t')
      value++;
    return value;
  }
  return NULL;
}

static HttpResponse_t static_answerFromList(const HttpStubAnswer_t* answer, const HttpRequest_t* request)
{
  HttpResponse_t resp = { 0 };
  if (answer == NULL)
  {
    resp.m_error = HTTP_ERROR_OTHER;
    return resp;
  }
  if (answer->m_error != HTTP_ERROR_NONE)
  {
    resp.m_error = answer->m_error;
    return resp;
  }

  resp.m_status             = answer->m_status;
  resp.m_isBodyCut          = answer->m_isBodyCut;
  resp.m_setCookieCopyCount = answer->m_setCookieCopyCount;
  resp.mp_body     = strdup(answer->mp_body ? answer->mp_body : "");
  resp.m_bodyLen   = resp.mp_body ? strlen(resp.mp_body) : 0;
  bool is_copied   = resp.mp_body != NULL;
  if (is_copied && answer->mp_redirectUrl)
  {
    resp.mp_redirectUrl = strdup(answer->mp_redirectUrl);
    is_copied           = resp.mp_redirectUrl != NULL;
  }

  int name_count = 0;
  while (request->mp_headerNamesToCapture && request->mp_headerNamesToCapture[name_count])
    name_count++;
  if (is_copied && name_count > 0)
  {
    resp.mp_capturedHeaderValues    = calloc((size_t)name_count, sizeof(*resp.mp_capturedHeaderValues));
    resp.m_capturedHeaderValueCount = resp.mp_capturedHeaderValues ? name_count : 0;
    is_copied                       = resp.mp_capturedHeaderValues != NULL;
    for (int i = 0; is_copied && i < name_count; i++)
    {
      const char* value = static_findHeaderValue(answer->mp_headerLines, request->mp_headerNamesToCapture[i]);
      if (value == NULL)
        continue;
      resp.mp_capturedHeaderValues[i] = strdup(value);
      is_copied                       = resp.mp_capturedHeaderValues[i] != NULL;
    }
  }

  if (!is_copied)
  {
    http_free(&resp);
    resp.m_error = HTTP_ERROR_OTHER;
  }
  return resp;
}

static HttpResponse_t static_recordRequest(const HttpRequest_t* request, const char* extra_header, bool is_post, const char* body, size_t body_byte_count)
{
  HttpResponse_t resp = { 0 };

  size_t kept_byte_count = body == NULL ? 0 : body_byte_count;
  if (kept_byte_count > HTTP_STUB_MAX_POST_BODY_BYTE_COUNT)
    kept_byte_count = HTTP_STUB_MAX_POST_BODY_BYTE_COUNT;
  if (kept_byte_count > 0)
    memcpy(g_stub_last_post_body, body, kept_byte_count);
  g_stub_last_post_body[kept_byte_count] = '\0';
  g_stub_last_post_body_byte_count       = is_post ? body_byte_count : 0;
  snprintf(g_stub_last_unix_socket_path, sizeof(g_stub_last_unix_socket_path), "%s",
           request->mp_unixSocketPath ? request->mp_unixSocketPath : "");

  int request_index = g_stub_http_call_count++;
  g_stub_last_url[0] = '\0';
  if (request->mp_url)
  {
    strncpy(g_stub_last_url, request->mp_url, sizeof(g_stub_last_url) - 1);
    g_stub_last_url[sizeof(g_stub_last_url) - 1] = '\0';
  }
  g_stub_last_header[0] = '\0';
  if (extra_header)
  {
    strncpy(g_stub_last_header, extra_header, sizeof(g_stub_last_header) - 1);
    g_stub_last_header[sizeof(g_stub_last_header) - 1] = '\0';
  }

  if (request_index >= 0 && request_index < HTTP_STUB_MAX_REQUEST_COUNT)
  {
    HttpStubRequest_t* record = &g_stub_requests[request_index];
    snprintf(record->ma_url, sizeof(record->ma_url), "%s", g_stub_last_url);
    static_joinLines(request->mp_headerNamesToCapture, record->ma_headerNamesToCapture, sizeof(record->ma_headerNamesToCapture));
    record->m_timeoutMs              = request->m_timeoutMs;
    record->m_maxBodyByteCount       = request->m_maxBodyByteCount;
    record->m_isTargetTrusted        = request->m_isTargetTrusted;
    record->m_isHttpsOnly            = request->m_isHttpsOnly;
    record->m_isRedirectLeftToCaller = request->m_isRedirectLeftToCaller;
    record->m_isBodyCutAccepted      = request->m_isBodyCutAccepted;
    record->m_requiredPort           = request->m_requiredPort;
    record->m_isPost                 = is_post;
  }

  if (g_stub_answers != NULL)
    return static_answerFromList(request_index >= 0 && request_index < g_stub_answer_count ? &g_stub_answers[request_index] : NULL, request);

  if (g_stub_next_error != HTTP_ERROR_NONE)
  {
    resp.m_error = g_stub_next_error;
    return resp;
  }

  resp.m_status  = g_stub_next_status;
  resp.mp_body   = g_stub_next_body_null ? NULL : strdup(g_stub_next_body ? g_stub_next_body : "{}");
  resp.m_bodyLen = resp.mp_body ? strlen(resp.mp_body) : 0;
  return resp;
}

HttpResponse_t http_GET(const char* url, int timeout_ms, const char* extra_header)
{
  const HttpRequest_t request = { .mp_url = url, .m_timeoutMs = timeout_ms, .m_isTargetTrusted = true };
  g_stub_last_timeout_ms = timeout_ms;
  return static_recordRequest(&request, extra_header, false, NULL, 0);
}

HttpResponse_t http_GETWithOptions(const HttpRequest_t* request)
{
  char header_lines[sizeof(g_stub_last_header)];
  static_joinLines(request->mp_extraHeaders, header_lines, sizeof(header_lines));

  g_stub_last_timeout_ms          = request->m_timeoutMs;
  g_stub_last_max_body_byte_count = request->m_maxBodyByteCount;
  g_stub_last_is_target_trusted   = request->m_isTargetTrusted;
  return static_recordRequest(request, header_lines, false, NULL, 0);
}

HttpResponse_t http_POSTWithOptions(const HttpRequest_t* request, const char* body, size_t body_byte_count)
{
  char header_lines[sizeof(g_stub_last_header)];
  static_joinLines(request->mp_extraHeaders, header_lines, sizeof(header_lines));

  g_stub_last_timeout_ms          = request->m_timeoutMs;
  g_stub_last_max_body_byte_count = request->m_maxBodyByteCount;
  g_stub_last_is_target_trusted   = request->m_isTargetTrusted;
  return static_recordRequest(request, header_lines, true, body, body_byte_count);
}

void http_free(HttpResponse_t* resp)
{
  if (!resp) return;

  free(resp->mp_body);
  for (int i = 0; i < resp->m_capturedHeaderValueCount; i++)
    free(resp->mp_capturedHeaderValues[i]);
  free(resp->mp_capturedHeaderValues);
  free(resp->mp_redirectUrl);
  *resp = (HttpResponse_t){ 0 };
}

void http_globalInit(void)    {}
void http_globalCleanup(void) {}
