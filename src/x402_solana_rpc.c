#include "x402_solana_rpc.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "http.h"
#include "jsonread.h"
#include "x402_solana.h"

#define X402_SOLANA_RPC_REQUEST_ID     1

#define X402_SOLANA_RPC_BODY_BUF_SIZE  256

#define X402_SOLANA_RPC_STATUS_TEXT_BUF_SIZE  16

#define X402_SOLANA_RPC_HTTP_OK        200

typedef enum {
  X402_SOLANA_RPC_ROOT_MEMBER_ID,
  X402_SOLANA_RPC_ROOT_MEMBER_RESULT,
  X402_SOLANA_RPC_ROOT_MEMBER_ERROR,
  X402_SOLANA_RPC_ROOT_MEMBER_COUNT
} X402SolanaRpcRootMember_t;

typedef enum {
  X402_SOLANA_RPC_STATUS_MEMBER_ERR,
  X402_SOLANA_RPC_STATUS_MEMBER_CONFIRMATION,
  X402_SOLANA_RPC_STATUS_MEMBER_COUNT
} X402SolanaRpcStatusMember_t;

static X402SolanaRpcSignatureStatus_t static_readAnswer  (const HttpResponse_t* response);
static X402SolanaRpcSignatureStatus_t static_readElement (JsonReadSpan_t element_span);

X402SolanaRpcSignatureStatus_t x402_solana_rpc_askSignatureStatus(const char* rpc_url, const char* signature_text)
{
  assert(rpc_url != NULL);
  assert(signature_text != NULL);

  uint8_t signature[X402_SOLANA_SIGNATURE_BYTE_COUNT];
  if (!x402_solana_tryDecodeSignature(signature_text, signature))
    return X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE;

  char body[X402_SOLANA_RPC_BODY_BUF_SIZE];
  int  body_len = snprintf(body, sizeof(body),
                           R"({"jsonrpc":"2.0","id":%d,"method":"getSignatureStatuses","params":[["%s"],{"searchTransactionHistory":true}]})",
                           X402_SOLANA_RPC_REQUEST_ID, signature_text);
  if (body_len < 0 || (size_t)body_len >= sizeof(body))
    return X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE;

  static const char* const json_headers[] = { "Content-Type: application/json", NULL };
  const HttpRequest_t request = {
    .mp_url                   = rpc_url,
    .m_timeoutMs              = X402_SOLANA_RPC_TIMEOUT_MS,
    .mp_extraHeaders          = json_headers,
    .m_maxBodyByteCount       = X402_SOLANA_RPC_MAX_ANSWER_BYTE_COUNT,
    .m_isTargetTrusted        = true,
    .m_isRedirectLeftToCaller = true,
  };
  HttpResponse_t                 response = http_POSTWithOptions(&request, body, (size_t)body_len);
  X402SolanaRpcSignatureStatus_t status   = static_readAnswer(&response);
  http_free(&response);
  return status;
}

static X402SolanaRpcSignatureStatus_t static_readAnswer(const HttpResponse_t* response)
{
  assert(response != NULL);

  if (response->m_error != HTTP_ERROR_NONE || response->m_status != X402_SOLANA_RPC_HTTP_OK
      || response->mp_body == NULL || response->m_isBodyCut
      || memchr(response->mp_body, '\0', response->m_bodyLen) != NULL)
  {
    return X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE;
  }

  JsonReadSpan_t   root_span;
  JsonReadMember_t members[X402_SOLANA_RPC_ROOT_MEMBER_COUNT] = {
    [X402_SOLANA_RPC_ROOT_MEMBER_ID]     = { .mp_key = "id" },
    [X402_SOLANA_RPC_ROOT_MEMBER_RESULT] = { .mp_key = "result" },
    [X402_SOLANA_RPC_ROOT_MEMBER_ERROR]  = { .mp_key = "error" },
  };
  if (jsonread_root(response->mp_body, response->m_bodyLen, &root_span) != JSONREAD_OK
      || !jsonread_tryFindMembers(root_span, members, X402_SOLANA_RPC_ROOT_MEMBER_COUNT)
      || members[X402_SOLANA_RPC_ROOT_MEMBER_ERROR].m_isFound
      || !members[X402_SOLANA_RPC_ROOT_MEMBER_ID].m_isFound)
  {
    return X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE;
  }

  long id = 0;
  if (jsonread_spanToLongStatus(members[X402_SOLANA_RPC_ROOT_MEMBER_ID].m_valueSpan, &id) != JSONREAD_OK || id != X402_SOLANA_RPC_REQUEST_ID)
    return X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE;

  JsonReadMember_t value = { .mp_key = "value" };
  size_t           element_count = 0;
  if (!jsonread_tryFindMembers(members[X402_SOLANA_RPC_ROOT_MEMBER_RESULT].m_valueSpan, &value, 1)
      || !value.m_isFound || !jsonread_isArray(value.m_valueSpan)
      || jsonread_arrayLen(value.m_valueSpan, &element_count) != JSONREAD_OK || element_count != 1)
  {
    return X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE;
  }

  size_t         element_offset = 0;
  JsonReadSpan_t element_span;
  if (jsonread_arrayNextElement(value.m_valueSpan, &element_offset, &element_span) != JSONREAD_OK)
    return X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE;
  return static_readElement(element_span);
}

static X402SolanaRpcSignatureStatus_t static_readElement(JsonReadSpan_t element_span)
{
  if (jsonread_isSpanEqual(element_span, "null"))
    return X402_SOLANA_RPC_SIGNATURE_NOT_FOUND;

  JsonReadMember_t members[X402_SOLANA_RPC_STATUS_MEMBER_COUNT] = {
    [X402_SOLANA_RPC_STATUS_MEMBER_ERR]          = { .mp_key = "err" },
    [X402_SOLANA_RPC_STATUS_MEMBER_CONFIRMATION] = { .mp_key = "confirmationStatus" },
  };
  if (!jsonread_tryFindMembers(element_span, members, X402_SOLANA_RPC_STATUS_MEMBER_COUNT) || !members[X402_SOLANA_RPC_STATUS_MEMBER_ERR].m_isFound)
    return X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE;

  char confirmation_text[X402_SOLANA_RPC_STATUS_TEXT_BUF_SIZE];
  if (!members[X402_SOLANA_RPC_STATUS_MEMBER_CONFIRMATION].m_isFound
      || jsonread_spanToStrStatus(members[X402_SOLANA_RPC_STATUS_MEMBER_CONFIRMATION].m_valueSpan, confirmation_text, sizeof(confirmation_text)) != JSONREAD_OK)
  {
    return X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE;
  }
  if (strcmp(confirmation_text, "processed") == 0)
    return X402_SOLANA_RPC_SIGNATURE_PROCESSED;
  if (strcmp(confirmation_text, "confirmed") != 0 && strcmp(confirmation_text, "finalized") != 0)
    return X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE;
  if (!jsonread_isSpanEqual(members[X402_SOLANA_RPC_STATUS_MEMBER_ERR].m_valueSpan, "null"))
    return X402_SOLANA_RPC_SIGNATURE_FAILED;
  return X402_SOLANA_RPC_SIGNATURE_CONFIRMED;
}
