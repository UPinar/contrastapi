#include <string.h>

#include "picohttpparser.h"
#include "request_text.h"

bool requestText_parse(const char* text, ReceiveResult_t* result_out)
{
  memset(result_out, 0, sizeof(*result_out));

  const char* method;
  const char* request_target;
  size_t      method_len, request_target_len;
  int         http_minor_version;
  size_t      header_count = HTTP_MAX_HEADERS;
  int head_len = phr_parse_request(text, strlen(text), &method, &method_len, &request_target, &request_target_len, &http_minor_version, result_out->ma_headers, &header_count, 0);
  if (head_len < 0)
  {
    memset(result_out, 0, sizeof(*result_out));
    return false;
  }

  result_out->m_headLen          = (size_t)head_len;
  result_out->mp_method          = method;
  result_out->m_methodLen        = method_len;
  result_out->mp_requestTarget   = request_target;
  result_out->m_requestTargetLen = request_target_len;
  result_out->m_httpMinorVersion = http_minor_version;
  result_out->m_headerCount      = header_count;
  result_out->mp_body            = text + head_len;
  result_out->m_bodyLen          = strlen(result_out->mp_body);
  result_out->m_requestLen       = result_out->m_headLen + result_out->m_bodyLen;
  return true;
}
