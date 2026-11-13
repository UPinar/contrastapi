#ifndef HTTP_H
#define HTTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "version.h"

#define HTTP_MAX_BODY (4 * 1024 * 1024)

#define HTTP_CONNECT_TIMEOUT_MS 2000

#define HTTP_MAX_HEADER_COPY_COUNT  16

#define HTTP_MAX_SET_COOKIE_COPY_COUNT  50

#define HTTP_USER_AGENT "ContrastAPI/" CONTRASTAPI_VERSION " (+https://api.contrastcyber.com/bot; contact@contrastcyber.com)"

typedef enum {
  HTTP_ERROR_NONE = 0,
  HTTP_ERROR_TIMEOUT,
  HTTP_ERROR_RESOLVE,
  HTTP_ERROR_CONNECT,
  HTTP_ERROR_TLS,
  HTTP_ERROR_BODY_TOO_LARGE,
  HTTP_ERROR_BLOCKED,
  HTTP_ERROR_OTHER
} HttpError_t;

typedef struct {
  const char*         mp_url;
  int                 m_timeoutMs;
  const char* const*  mp_extraHeaders;
  size_t              m_maxBodyByteCount;
  const char* const*  mp_headerNamesToCapture;
  bool                m_isTargetTrusted;
  bool                m_isHttpsOnly;
  bool                m_isRedirectLeftToCaller;
  bool                m_isBodyCutAccepted;
  uint16_t            m_requiredPort;
  const char*         mp_unixSocketPath;
} HttpRequest_t;

typedef struct {
  int           m_status;
  char*         mp_body;
  size_t        m_bodyLen;
  HttpError_t   m_error;
  char**        mp_capturedHeaderValues;
  int           m_capturedHeaderValueCount;
  char*         mp_redirectUrl;
  bool          m_isBodyCut;
  size_t        m_setCookieCopyCount;
} HttpResponse_t;

HttpResponse_t http_GET             (const char* url, int timeout_ms, const char* extra_header);
HttpResponse_t http_GETWithOptions  (const HttpRequest_t* request);
HttpResponse_t http_POSTWithOptions (const HttpRequest_t* request, const char* body, size_t body_byte_count);
void           http_free            (HttpResponse_t* response);

void  http_globalInit    (void);
void  http_globalCleanup (void);

#endif
