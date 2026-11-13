#ifndef HTTP_STUB_H
#define HTTP_STUB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "http.h"

extern char g_stub_last_url[1024];
extern int  g_stub_http_call_count;

extern char g_stub_last_header[512];

extern int g_stub_next_status;

extern const char* g_stub_next_body;

extern bool g_stub_next_body_null;

extern int g_stub_last_timeout_ms;

extern size_t g_stub_last_max_body_byte_count;
extern bool   g_stub_last_is_target_trusted;

#define HTTP_STUB_MAX_POST_BODY_BYTE_COUNT 4096

extern char   g_stub_last_post_body[HTTP_STUB_MAX_POST_BODY_BYTE_COUNT + 1];
extern size_t g_stub_last_post_body_byte_count;

extern char g_stub_last_unix_socket_path[256];

extern HttpError_t g_stub_next_error;

#define HTTP_STUB_MAX_REQUEST_COUNT 8

typedef struct {
  char     ma_url[1024];
  char     ma_headerNamesToCapture[512];
  int      m_timeoutMs;
  size_t   m_maxBodyByteCount;
  bool     m_isTargetTrusted;
  bool     m_isHttpsOnly;
  bool     m_isRedirectLeftToCaller;
  bool     m_isBodyCutAccepted;
  uint16_t m_requiredPort;
  bool     m_isPost;
} HttpStubRequest_t;

extern HttpStubRequest_t g_stub_requests[HTTP_STUB_MAX_REQUEST_COUNT];

typedef struct {
  int                m_status;
  const char*        mp_body;
  HttpError_t        m_error;
  const char*        mp_redirectUrl;
  const char* const* mp_headerLines;
  bool               m_isBodyCut;
  size_t             m_setCookieCopyCount;
} HttpStubAnswer_t;

extern const HttpStubAnswer_t* g_stub_answers;
extern int                     g_stub_answer_count;

#endif
