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

static HttpResponse_t                 static_postToProvider    (const char* rpc_url, const char* body, size_t body_len, size_t max_answer_byte_count);
static bool                           static_tryReadEnvelope   (const HttpResponse_t* response, JsonReadSpan_t* result_out);
static X402SolanaRpcSignatureStatus_t static_readAnswer        (const HttpResponse_t* response);
static X402SolanaRpcSignatureStatus_t static_readElement       (JsonReadSpan_t element_span);
static X402SolanaRpcSignatureStatus_t static_readSignatureList (JsonReadSpan_t list_span, const uint8_t* tx, size_t tx_len, const uint8_t* fee_payer, char* signature_out);

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

  HttpResponse_t                 response = static_postToProvider(rpc_url, body, (size_t)body_len, X402_SOLANA_RPC_MAX_ANSWER_BYTE_COUNT);
  X402SolanaRpcSignatureStatus_t status   = static_readAnswer(&response);
  http_free(&response);
  return status;
}

X402SolanaRpcSignatureStatus_t x402_solana_rpc_findFeePayerSignature(const char* rpc_url, const uint8_t source[X402_SOLANA_ADDRESS_BYTE_COUNT], const uint8_t* tx, size_t tx_len, const uint8_t fee_payer[X402_SOLANA_ADDRESS_BYTE_COUNT], char signature_out[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE])
{
  assert(rpc_url != NULL);
  assert(source != NULL);
  assert(tx != NULL || tx_len == 0);
  assert(fee_payer != NULL);
  assert(signature_out != NULL);

  signature_out[0] = '\0';

  char source_text[X402_SOLANA_ADDRESS_TEXT_BUF_SIZE];
  if (!x402_solana_tryEncodeAddress(source, source_text, sizeof(source_text)))
    return X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE;

  char body[X402_SOLANA_RPC_BODY_BUF_SIZE];
  int  body_len = snprintf(body, sizeof(body),
                           R"({"jsonrpc":"2.0","id":%d,"method":"getSignaturesForAddress","params":["%s",{"limit":%d,"commitment":"confirmed"}]})",
                           X402_SOLANA_RPC_REQUEST_ID, source_text, X402_SOLANA_RPC_SIGNATURE_LIST_LIMIT);
  if (body_len < 0 || (size_t)body_len >= sizeof(body))
    return X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE;

  HttpResponse_t response = static_postToProvider(rpc_url, body, (size_t)body_len, X402_SOLANA_RPC_MAX_LIST_ANSWER_BYTE_COUNT);
  JsonReadSpan_t result_span;
  X402SolanaRpcSignatureStatus_t status = X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE;
  if (static_tryReadEnvelope(&response, &result_span))
    status = static_readSignatureList(result_span, tx, tx_len, fee_payer, signature_out);

  http_free(&response);
  return status;
}

static HttpResponse_t static_postToProvider(const char* rpc_url, const char* body, size_t body_len, size_t max_answer_byte_count)
{
  static const char* const json_headers[] = { "Content-Type: application/json", NULL };
  const HttpRequest_t request = {
    .mp_url                   = rpc_url,
    .m_timeoutMs              = X402_SOLANA_RPC_TIMEOUT_MS,
    .mp_extraHeaders          = json_headers,
    .m_maxBodyByteCount       = max_answer_byte_count,
    .m_isTargetTrusted        = true,
    .m_isRedirectLeftToCaller = true,
  };
  return http_POSTWithOptions(&request, body, body_len);
}

static bool static_tryReadEnvelope(const HttpResponse_t* response, JsonReadSpan_t* result_out)
{
  assert(response != NULL);
  assert(result_out != NULL);

  if (response->m_error != HTTP_ERROR_NONE                || 
      response->m_status != X402_SOLANA_RPC_HTTP_OK       ||
      response->mp_body == NULL || response->m_isBodyCut  ||
      memchr(response->mp_body, '\0', response->m_bodyLen) != NULL)
  {
    return false;
  }

  JsonReadSpan_t   root_span;
  JsonReadMember_t members[X402_SOLANA_RPC_ROOT_MEMBER_COUNT] = {
    [X402_SOLANA_RPC_ROOT_MEMBER_ID]     = { .mp_key = "id" },
    [X402_SOLANA_RPC_ROOT_MEMBER_RESULT] = { .mp_key = "result" },
    [X402_SOLANA_RPC_ROOT_MEMBER_ERROR]  = { .mp_key = "error" },
  };
  if (jsonread_root(response->mp_body, response->m_bodyLen, &root_span) != JSONREAD_OK  ||
      !jsonread_tryFindMembers(root_span, members, X402_SOLANA_RPC_ROOT_MEMBER_COUNT)   ||
      members[X402_SOLANA_RPC_ROOT_MEMBER_ERROR].m_isFound                              ||
      !members[X402_SOLANA_RPC_ROOT_MEMBER_ID].m_isFound)
  {
    return false;
  }

  long id = 0;
  if (jsonread_spanToLongStatus(members[X402_SOLANA_RPC_ROOT_MEMBER_ID].m_valueSpan, &id) != JSONREAD_OK || 
      id != X402_SOLANA_RPC_REQUEST_ID)
  {
    return false;
  }

  *result_out = members[X402_SOLANA_RPC_ROOT_MEMBER_RESULT].m_valueSpan;
  return true;
}

static X402SolanaRpcSignatureStatus_t static_readAnswer(const HttpResponse_t* response)
{
  assert(response != NULL);

  JsonReadSpan_t result_span;
  if (!static_tryReadEnvelope(response, &result_span))
    return X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE;

  JsonReadMember_t value = { .mp_key = "value" };
  size_t           element_count = 0;
  if (!jsonread_tryFindMembers(result_span, &value, 1)                    ||
      !value.m_isFound || !jsonread_isArray(value.m_valueSpan)            ||
      jsonread_arrayLen(value.m_valueSpan, &element_count) != JSONREAD_OK || 
      element_count != 1)
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
  if (!jsonread_tryFindMembers(element_span, members, X402_SOLANA_RPC_STATUS_MEMBER_COUNT) || 
      !members[X402_SOLANA_RPC_STATUS_MEMBER_ERR].m_isFound)
  {
    return X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE;
  }

  char confirmation_text[X402_SOLANA_RPC_STATUS_TEXT_BUF_SIZE];
  if (!members[X402_SOLANA_RPC_STATUS_MEMBER_CONFIRMATION].m_isFound ||
      jsonread_spanToStrStatus(members[X402_SOLANA_RPC_STATUS_MEMBER_CONFIRMATION].m_valueSpan, confirmation_text, sizeof(confirmation_text)) != JSONREAD_OK)
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

static X402SolanaRpcSignatureStatus_t static_readSignatureList(JsonReadSpan_t list_span, const uint8_t* tx, size_t tx_len, const uint8_t* fee_payer, char* signature_out)
{
  assert(tx != NULL || tx_len == 0);
  assert(fee_payer != NULL);
  assert(signature_out != NULL);

  size_t element_count = 0;
  if (!jsonread_isArray(list_span)                                || 
      jsonread_arrayLen(list_span, &element_count) != JSONREAD_OK ||
      element_count > X402_SOLANA_RPC_SIGNATURE_LIST_LIMIT)
  {
    return X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE;
  }

  bool           is_found = false;
  JsonReadSpan_t found_span = { 0 };
  char           found_text[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE] = "";
  size_t         element_offset = 0;
  for (size_t i = 0; i < element_count; i++)
  {
    JsonReadSpan_t   element_span;
    JsonReadMember_t signature_member = { .mp_key = "signature" };
    char             signature_text[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE];
    uint8_t          signature[X402_SOLANA_SIGNATURE_BYTE_COUNT];
    if (jsonread_arrayNextElement(list_span, &element_offset, &element_span) != JSONREAD_OK                           ||
        !jsonread_tryFindMembers(element_span, &signature_member, 1)                                                  ||
        jsonread_spanToStrStatus(signature_member.m_valueSpan, signature_text, sizeof(signature_text)) != JSONREAD_OK ||
        !x402_solana_tryDecodeSignature(signature_text, signature))
    {
      return X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE;
    }
    if (!is_found && x402_solana_isFeePayerSignatureValid(tx, tx_len, fee_payer, signature))
    {
      is_found   = true;
      found_span = element_span;
      memcpy(found_text, signature_text, strlen(signature_text) + 1);
    }
  }
  if (!is_found)
    return X402_SOLANA_RPC_SIGNATURE_NOT_FOUND;

  X402SolanaRpcSignatureStatus_t status = static_readElement(found_span);
  if (status == X402_SOLANA_RPC_SIGNATURE_CONFIRMED || 
      status == X402_SOLANA_RPC_SIGNATURE_FAILED    ||
      status == X402_SOLANA_RPC_SIGNATURE_PROCESSED)
  {
    memcpy(signature_out, found_text, strlen(found_text) + 1);
  }
  return status;
}
