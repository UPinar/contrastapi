#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "jsonrpc.h"
#include "bytes.h"
#include "jsonread.h"
#include "jsonbuf.h"
#include "utf8.h"

#define JSONRPC_UNICODE_ESCAPE_HEX_DIGITS  4

static bool        static_isValidIdToken    (JsonReadSpan_t id_span);
static bool        static_isValidStringToken(const char* cursor, const char* end);

JsonRpcStatus_t jsonrpc_parse(const char* body, size_t len, JsonRpcRequest_t* request_out)
{
  assert(body != NULL);
  assert(request_out  != NULL);

  memset(request_out, 0, sizeof(*request_out));

  if (!utf8_isTextValid(body, len))
    return JSONRPC_MALFORMED;

  JsonReadSpan_t root_span;
  if (jsonread_root(body, len, &root_span) != JSONREAD_OK)
    return JSONRPC_MALFORMED;
  if (root_span.m_len == 0 || root_span.mp_start[0] != '{')
    return JSONRPC_INVALID;

  JsonReadSpan_t version_span;
  char version[8];
  if (jsonread_objectKey(root_span, "jsonrpc", &version_span) != JSONREAD_OK)
    return JSONRPC_INVALID;
  if (jsonread_spanToStrStatus(version_span, version, sizeof(version)) != JSONREAD_OK || strcmp(version, "2.0") != 0)
    return JSONRPC_INVALID;

  JsonReadSpan_t id_span;
  if (jsonread_objectKey(root_span, "id", &id_span) == JSONREAD_OK)
  {
    if (!static_isValidIdToken(id_span))
      return JSONRPC_INVALID;
    request_out->m_hasId = true;
    if (jsonread_spanToRawStringStatus(id_span, request_out->ma_id, sizeof(request_out->ma_id)) != JSONREAD_OK)
    {
      strcpy(request_out->ma_id, "null");
    }
  }

  JsonReadSpan_t rpc_method_span;
  if (jsonread_objectKey(root_span, "method", &rpc_method_span) != JSONREAD_OK)
    return JSONRPC_INVALID;
  if (jsonread_spanToStrStatus(rpc_method_span, request_out->ma_rpcMethod, sizeof(request_out->ma_rpcMethod)) != JSONREAD_OK)
    return JSONRPC_INVALID;

  if (jsonread_objectKey(root_span, "params", &request_out->m_params) == JSONREAD_OK)
    request_out->m_hasParams = true;

  return JSONRPC_OK;
}

static bool static_isValidIdToken(JsonReadSpan_t id_span)
{
  if (id_span.m_len == 0)
  {
    fprintf(stderr, "static_isValidIdToken: empty id token\n");
    return false;
  }

  const char* cursor = id_span.mp_start;
  const char* end    = id_span.mp_start + id_span.m_len;

  if (*cursor == 'n')
    return true;
  else if (*cursor == '"')
    return static_isValidStringToken(cursor, end);
  else
    return jsonread_isNumberToken(cursor, end);
}

static bool static_isValidStringToken(const char* cursor, const char* end)
{
  if (cursor >= end || *cursor != '"')
  {
    fprintf(stderr, "static_isValidStringToken: no opening quote\n");
    return false;
  }

  cursor++;
  while (cursor < end)
  {
    uint32_t code_point = 0;

    if (*cursor != '\\')
    {
      Utf8Sequence_t sequence = utf8_readFirstSequence((const unsigned char*)cursor, (size_t)(end - cursor));
      code_point = sequence.m_codePoint;
      cursor    += sequence.m_length;
    }
    else
    {
      cursor++;
      switch (*cursor)
      {
        case '"':
        case '\\':
        case '/':
        case 'b':
        case 'f':
        case 'n':
        case 'r':
        case 't':
          cursor++;
          break;
        case 'u':
          for (int digit = 1; digit <= JSONRPC_UNICODE_ESCAPE_HEX_DIGITS; digit++)
          {
            int digit_value = bytes_hexDigitValue(cursor[digit]);
            if (digit_value < 0)
              return false;
            code_point = (code_point << 4) | (uint32_t)digit_value;
          }
          cursor += 1 + JSONRPC_UNICODE_ESCAPE_HEX_DIGITS;
          break;
        default:
          return false;
      }
    }

    if (jsonbuf_isCodePointHidden(code_point))
      return false;
  }
  return true;
}

void jsonrpc_serializeResult(const char* id_raw, const char* result_json, JsonBuf_t* json_buf)
{
  assert(id_raw      != NULL);
  assert(result_json != NULL);

  jsonbuf_appendFormat(json_buf, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":%s}", id_raw, result_json);
}

void jsonrpc_serializeError(const char* id_raw, int code, const char* message, const char* data_json, JsonBuf_t* json_buf)
{
  assert(id_raw  != NULL);
  assert(message != NULL);

  jsonbuf_appendFormat(json_buf, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"error\":{\"code\":%d,\"message\":\"", id_raw, code);
  jsonbuf_appendEscaped(json_buf, message);
  if (data_json)
    jsonbuf_appendFormat(json_buf, "\",\"data\":%s}}", data_json);
  else
    jsonbuf_appendFormat(json_buf, "\"}}");
}
