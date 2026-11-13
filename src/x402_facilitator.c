#include "x402_facilitator.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "http.h"
#include "jsonbuf.h"
#include "jsonread.h"
#include "x402.h"
#include "x402_solana.h"

#define X402_FACILITATOR_VERIFY_URL     "http://localhost/verify"
#define X402_FACILITATOR_SETTLE_URL     "http://localhost/settle"
#define X402_FACILITATOR_SUPPORTED_URL  "http://localhost/supported"

#define X402_FACILITATOR_TEXT_BUF_SIZE  64

#define X402_FACILITATOR_TRANSACTION_BASE64_BUF_SIZE  (X402_BASE64_LEN(X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT) + 1)

#define X402_FACILITATOR_HTTP_OK                   200
#define X402_FACILITATOR_HTTP_BAD_REQUEST          400
#define X402_FACILITATOR_HTTP_PRECONDITION_FAILED  412

typedef enum {
  X402_FACILITATOR_SETTLE_MEMBER_SUCCESS,
  X402_FACILITATOR_SETTLE_MEMBER_NETWORK,
  X402_FACILITATOR_SETTLE_MEMBER_TRANSACTION,
  X402_FACILITATOR_SETTLE_MEMBER_COUNT
} X402FacilitatorSettleMember_t;

typedef enum {
  X402_FACILITATOR_SUPPORTED_MEMBER_KINDS,
  X402_FACILITATOR_SUPPORTED_MEMBER_SIGNERS,
  X402_FACILITATOR_SUPPORTED_MEMBER_COUNT
} X402FacilitatorSupportedMember_t;

typedef enum {
  X402_FACILITATOR_PAYMENT_KIND_MEMBER_VERSION,
  X402_FACILITATOR_PAYMENT_KIND_MEMBER_SCHEME,
  X402_FACILITATOR_PAYMENT_KIND_MEMBER_NETWORK,
  X402_FACILITATOR_PAYMENT_KIND_MEMBER_EXTRA,
  X402_FACILITATOR_PAYMENT_KIND_MEMBER_COUNT
} X402FacilitatorPaymentKindMember_t;

static char*                            static_tryBuildBody           (const X402Requirements_t* requirements, const X402Payment_t* payment);
static HttpRequest_t                    static_makeFacilitatorRequest (const char* url, int timeout_ms);
static HttpResponse_t                   static_getFromFacilitator     (const char* url, int timeout_ms);
static HttpResponse_t                   static_postToFacilitator      (const char* url, int timeout_ms, const char* body);
static X402FacilitatorVerifyStatus_t    static_readVerifyAnswer       (const HttpResponse_t* response);
static X402FacilitatorSettlement_t      static_readSettleAnswer       (const HttpResponse_t* response, const X402Requirements_t* requirements, const X402Payment_t* payment, const uint8_t fee_payer[X402_SOLANA_ADDRESS_BYTE_COUNT]);
static X402FacilitatorSupportedStatus_t static_readSupportedAnswer    (const HttpResponse_t* response, const X402Requirements_t* requirements);
static bool                             static_isOurPaymentKind       (JsonReadSpan_t payment_kind_span, const X402Requirements_t* requirements);
static bool                             static_isFeePayerListed       (JsonReadSpan_t signers_span, const X402Requirements_t* requirements);
static bool                             static_tryReadAnswerRoot      (const HttpResponse_t* response, JsonReadSpan_t* root_span_out);
static bool                             static_isMemberTrue           (const JsonReadMember_t* member);
static bool                             static_isMemberFalse          (const JsonReadMember_t* member);
static bool                             static_isStringEqual          (const JsonReadMember_t* member, const char* expected);

X402FacilitatorVerifyStatus_t x402_facilitator_verify(const X402Requirements_t* requirements, const X402Payment_t* payment)
{
  assert(requirements != NULL);
  assert(payment != NULL);

  char* body = static_tryBuildBody(requirements, payment);
  if (body == NULL)
    return X402_FACILITATOR_VERIFY_UNAVAILABLE;
  HttpResponse_t response = static_postToFacilitator(X402_FACILITATOR_VERIFY_URL, X402_FACILITATOR_VERIFY_TIMEOUT_MS, body);
  free(body);

  X402FacilitatorVerifyStatus_t status = static_readVerifyAnswer(&response);
  http_free(&response);
  return status;
}

X402FacilitatorSettlement_t x402_facilitator_settle(const X402Requirements_t* requirements, const X402Payment_t* payment)
{
  assert(requirements != NULL);
  assert(payment != NULL);

  X402FacilitatorSettlement_t refused = { .m_status = X402_FACILITATOR_SETTLE_REFUSED };
  uint8_t fee_payer[X402_SOLANA_ADDRESS_BYTE_COUNT];
  if (!x402_solana_tryDecodeAddress(requirements->ma_feePayer, fee_payer))
    return refused;

  char* body = static_tryBuildBody(requirements, payment);
  if (body == NULL)
    return refused;

  HttpResponse_t response = static_postToFacilitator(X402_FACILITATOR_SETTLE_URL, X402_FACILITATOR_SETTLE_TIMEOUT_MS, body);
  free(body);

  X402FacilitatorSettlement_t settlement = static_readSettleAnswer(&response, requirements, payment, fee_payer);
  http_free(&response);
  return settlement;
}

X402FacilitatorSupportedStatus_t x402_facilitator_supported(const X402Requirements_t* requirements)
{
  assert(requirements != NULL);

  HttpResponse_t response = static_getFromFacilitator(X402_FACILITATOR_SUPPORTED_URL, X402_FACILITATOR_SUPPORTED_TIMEOUT_MS);
  X402FacilitatorSupportedStatus_t status = static_readSupportedAnswer(&response, requirements);
  http_free(&response);
  return status;
}

static char* static_tryBuildBody(const X402Requirements_t* requirements, const X402Payment_t* payment)
{
  assert(requirements != NULL);
  assert(payment != NULL);

  if (payment->m_transactionByteCount == 0)
    return NULL;

  char transaction_base64[X402_FACILITATOR_TRANSACTION_BASE64_BUF_SIZE];
  if (payment->m_transactionByteCount > X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT
      || !x402_tryEncodeBase64(payment->ma_transaction, payment->m_transactionByteCount, transaction_base64, sizeof(transaction_base64)))
  {
    return NULL;
  }

  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  if (json_buf == NULL)
    return NULL;

  jsonbuf_appendFormat(json_buf, R"({"x402Version":%d,"paymentPayload":{"x402Version":%d,"accepted":)", X402_VERSION, X402_VERSION);
  x402_writePaymentRequirements(json_buf, requirements);
  jsonbuf_appendFormat(json_buf, R"(,"payload":{"transaction":")");
  jsonbuf_appendEscaped(json_buf, transaction_base64);
  jsonbuf_appendFormat(json_buf, R"("}},"paymentRequirements":)");
  x402_writePaymentRequirements(json_buf, requirements);
  bool  is_written = jsonbuf_appendFormat(json_buf, R"(})");
  char* body       = jsonbuf_finish(json_buf);

  jsonbuf_destroy(json_buf);
  if (!is_written)
  {
    free(body);
    return NULL;
  }

  return body;
}

static HttpRequest_t static_makeFacilitatorRequest(const char* url, int timeout_ms)
{
  assert(url != NULL);

  return (HttpRequest_t){
    .mp_url                   = url,
    .m_timeoutMs              = timeout_ms,
    .m_maxBodyByteCount       = X402_FACILITATOR_MAX_ANSWER_BYTE_COUNT,
    .m_isTargetTrusted        = true,
    .m_isRedirectLeftToCaller = true,
    .mp_unixSocketPath        = X402_FACILITATOR_SOCKET_PATH,
  };
}

static HttpResponse_t static_getFromFacilitator(const char* url, int timeout_ms)
{
  const HttpRequest_t request = static_makeFacilitatorRequest(url, timeout_ms);
  return http_GETWithOptions(&request);
}

static HttpResponse_t static_postToFacilitator(const char* url, int timeout_ms, const char* body)
{
  assert(body != NULL);

  static const char* const json_headers[] = { "Content-Type: application/json", NULL };
  HttpRequest_t request   = static_makeFacilitatorRequest(url, timeout_ms);
  request.mp_extraHeaders = json_headers;
  return http_POSTWithOptions(&request, body, strlen(body));
}

static X402FacilitatorVerifyStatus_t static_readVerifyAnswer(const HttpResponse_t* response)
{
  assert(response != NULL);

  bool is_verdict_status = response->m_status == X402_FACILITATOR_HTTP_OK
                        || response->m_status == X402_FACILITATOR_HTTP_BAD_REQUEST
                        || response->m_status == X402_FACILITATOR_HTTP_PRECONDITION_FAILED;
  JsonReadSpan_t   root_span;
  JsonReadMember_t is_valid = { .mp_key = "isValid" };
  if (!is_verdict_status || !static_tryReadAnswerRoot(response, &root_span) || !jsonread_tryFindMembers(root_span, &is_valid, 1))
    return X402_FACILITATOR_VERIFY_UNAVAILABLE;

  if (response->m_status == X402_FACILITATOR_HTTP_OK && static_isMemberTrue(&is_valid))
    return X402_FACILITATOR_VERIFY_VALID;

  if (static_isMemberFalse(&is_valid))
    return X402_FACILITATOR_VERIFY_INVALID;
  return X402_FACILITATOR_VERIFY_UNAVAILABLE;
}

static X402FacilitatorSettlement_t static_readSettleAnswer(const HttpResponse_t* response, const X402Requirements_t* requirements, const X402Payment_t* payment, const uint8_t fee_payer[X402_SOLANA_ADDRESS_BYTE_COUNT])
{
  assert(response != NULL);
  assert(requirements != NULL);
  assert(payment != NULL);
  assert(fee_payer != NULL);

  X402FacilitatorSettlement_t settlement = { .m_status = X402_FACILITATOR_SETTLE_PENDING };
  JsonReadSpan_t              root_span;
  JsonReadMember_t            members[X402_FACILITATOR_SETTLE_MEMBER_COUNT] = {
    [X402_FACILITATOR_SETTLE_MEMBER_SUCCESS]     = { .mp_key = "success" },
    [X402_FACILITATOR_SETTLE_MEMBER_NETWORK]     = { .mp_key = "network" },
    [X402_FACILITATOR_SETTLE_MEMBER_TRANSACTION] = { .mp_key = "transaction" },
  };
  if (!static_tryReadAnswerRoot(response, &root_span) || !jsonread_tryFindMembers(root_span, members, X402_FACILITATOR_SETTLE_MEMBER_COUNT))
    return settlement;

  char    signature_text[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE];
  uint8_t signature[X402_SOLANA_SIGNATURE_BYTE_COUNT];
  bool    has_signature = members[X402_FACILITATOR_SETTLE_MEMBER_TRANSACTION].m_isFound
              && jsonread_spanToStrStatus(members[X402_FACILITATOR_SETTLE_MEMBER_TRANSACTION].m_valueSpan, signature_text, sizeof(signature_text)) == JSONREAD_OK
              && x402_solana_tryDecodeSignature(signature_text, signature)
              && x402_solana_isFeePayerSignatureValid(payment->ma_transaction, payment->m_transactionByteCount, fee_payer, signature);
  if (has_signature)
  {
    settlement.m_hasSignature = true;
    memcpy(settlement.ma_signature, signature_text, sizeof(settlement.ma_signature));
  }

  if (response->m_status == X402_FACILITATOR_HTTP_OK
      && static_isMemberTrue(&members[X402_FACILITATOR_SETTLE_MEMBER_SUCCESS])
      && static_isStringEqual(&members[X402_FACILITATOR_SETTLE_MEMBER_NETWORK], requirements->ma_network)
      && has_signature)
  {
    settlement.m_status = X402_FACILITATOR_SETTLE_PAID;
  }
  else if ((response->m_status == X402_FACILITATOR_HTTP_BAD_REQUEST || response->m_status == X402_FACILITATOR_HTTP_PRECONDITION_FAILED)
           && static_isMemberFalse(&members[X402_FACILITATOR_SETTLE_MEMBER_SUCCESS])
           && !has_signature)
  {
    settlement.m_status = X402_FACILITATOR_SETTLE_REFUSED;
  }
  return settlement;
}

static X402FacilitatorSupportedStatus_t static_readSupportedAnswer(const HttpResponse_t* response, const X402Requirements_t* requirements)
{
  assert(response != NULL);
  assert(requirements != NULL);

  JsonReadSpan_t   root_span;
  JsonReadMember_t members[X402_FACILITATOR_SUPPORTED_MEMBER_COUNT] = {
    [X402_FACILITATOR_SUPPORTED_MEMBER_KINDS]   = { .mp_key = "kinds" },
    [X402_FACILITATOR_SUPPORTED_MEMBER_SIGNERS] = { .mp_key = "signers" },
  };
  if (response->m_status != X402_FACILITATOR_HTTP_OK
      || !static_tryReadAnswerRoot(response, &root_span)
      || !jsonread_tryFindMembers(root_span, members, X402_FACILITATOR_SUPPORTED_MEMBER_COUNT))
  {
    return X402_FACILITATOR_SUPPORTED_UNAVAILABLE;
  }

  JsonReadSpan_t kinds_span = members[X402_FACILITATOR_SUPPORTED_MEMBER_KINDS].m_valueSpan;
  if (!members[X402_FACILITATOR_SUPPORTED_MEMBER_KINDS].m_isFound
      || !jsonread_isArray(kinds_span)
      || !static_isFeePayerListed(members[X402_FACILITATOR_SUPPORTED_MEMBER_SIGNERS].m_valueSpan, requirements))
  {
    return X402_FACILITATOR_SUPPORTED_MISMATCH;
  }

  size_t         element_offset = 0;
  JsonReadSpan_t payment_kind_span;
  while (jsonread_arrayNextElement(kinds_span, &element_offset, &payment_kind_span) == JSONREAD_OK)
  {
    if (static_isOurPaymentKind(payment_kind_span, requirements))
      return X402_FACILITATOR_SUPPORTED_YES;
  }
  return X402_FACILITATOR_SUPPORTED_MISMATCH;
}

static bool static_isOurPaymentKind(JsonReadSpan_t payment_kind_span, const X402Requirements_t* requirements)
{
  assert(requirements != NULL);

  JsonReadMember_t members[X402_FACILITATOR_PAYMENT_KIND_MEMBER_COUNT] = {
    [X402_FACILITATOR_PAYMENT_KIND_MEMBER_VERSION] = { .mp_key = "x402Version" },
    [X402_FACILITATOR_PAYMENT_KIND_MEMBER_SCHEME]  = { .mp_key = "scheme" },
    [X402_FACILITATOR_PAYMENT_KIND_MEMBER_NETWORK] = { .mp_key = "network" },
    [X402_FACILITATOR_PAYMENT_KIND_MEMBER_EXTRA]   = { .mp_key = "extra" },
  };
  if (!jsonread_tryFindMembers(payment_kind_span, members, X402_FACILITATOR_PAYMENT_KIND_MEMBER_COUNT))
    return false;

  long version = 0;
  if (!members[X402_FACILITATOR_PAYMENT_KIND_MEMBER_VERSION].m_isFound
      || jsonread_spanToLongStatus(members[X402_FACILITATOR_PAYMENT_KIND_MEMBER_VERSION].m_valueSpan, &version) != JSONREAD_OK
      || version != X402_VERSION
      || !static_isStringEqual(&members[X402_FACILITATOR_PAYMENT_KIND_MEMBER_SCHEME], X402_SCHEME_EXACT)
      || !static_isStringEqual(&members[X402_FACILITATOR_PAYMENT_KIND_MEMBER_NETWORK], requirements->ma_network))
  {
    return false;
  }

  JsonReadMember_t fee_payer_member = { .mp_key = "feePayer" };
  return jsonread_tryFindMembers(members[X402_FACILITATOR_PAYMENT_KIND_MEMBER_EXTRA].m_valueSpan, &fee_payer_member, 1)
      && static_isStringEqual(&fee_payer_member, requirements->ma_feePayer);
}

static bool static_isFeePayerListed(JsonReadSpan_t signers_span, const X402Requirements_t* requirements)
{
  assert(requirements != NULL);

  JsonReadMember_t network = { .mp_key = requirements->ma_network };
  if (!jsonread_tryFindMembers(signers_span, &network, 1) || !network.m_isFound || !jsonread_isArray(network.m_valueSpan))
    return false;

  size_t           element_offset = 0;
  JsonReadMember_t signer         = { .mp_key = NULL, .m_isFound = true };
  while (jsonread_arrayNextElement(network.m_valueSpan, &element_offset, &signer.m_valueSpan) == JSONREAD_OK)
  {
    if (static_isStringEqual(&signer, requirements->ma_feePayer))
      return true;
  }
  return false;
}

static bool static_tryReadAnswerRoot(const HttpResponse_t* response, JsonReadSpan_t* root_span_out)
{
  assert(response != NULL);
  assert(root_span_out != NULL);

  if (response->m_error != HTTP_ERROR_NONE || response->mp_body == NULL || response->m_isBodyCut)
    return false;
  if (memchr(response->mp_body, '\0', response->m_bodyLen) != NULL)
    return false;
  return jsonread_root(response->mp_body, response->m_bodyLen, root_span_out) == JSONREAD_OK && jsonread_isObject(*root_span_out);
}

static bool static_isMemberTrue(const JsonReadMember_t* member)
{
  assert(member != NULL);

  bool value = false;
  return member->m_isFound && jsonread_spanToBoolStatus(member->m_valueSpan, &value) == JSONREAD_OK && value;
}

static bool static_isMemberFalse(const JsonReadMember_t* member)
{
  assert(member != NULL);

  bool value = true;
  return member->m_isFound && jsonread_spanToBoolStatus(member->m_valueSpan, &value) == JSONREAD_OK && !value;
}

static bool static_isStringEqual(const JsonReadMember_t* member, const char* expected)
{
  assert(member != NULL);
  assert(expected != NULL);

  char text[X402_FACILITATOR_TEXT_BUF_SIZE];
  return member->m_isFound
      && jsonread_spanToStrStatus(member->m_valueSpan, text, sizeof(text)) == JSONREAD_OK
      && strcmp(text, expected) == 0;
}
