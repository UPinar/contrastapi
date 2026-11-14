#include "x402_request.h"

#include <assert.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jsonbuf.h"
#include "package.h"
#include "pricing.h"
#include "throttle.h"
#include "x402_facilitator.h"
#include "x402_solana_rpc.h"

#define X402_REQUEST_MAX_TIMEOUT_SECONDS          60

#define X402_REQUEST_RESOURCE_DESCRIPTION         "ContrastAPI request"

#define X402_REQUEST_PAYMENT_REQUIRED_HEADER_NAME "PAYMENT-REQUIRED"
#define X402_REQUEST_RECEIPT_HEADER_NAME          "PAYMENT-RESPONSE"

#define X402_REQUEST_RESOURCE_URL_BUF_SIZE        256

_Static_assert((uint64_t)PACKAGECHECKBULK_MAX_ITEMS * PRICING_X402_USDC_ATOMIC_PER_CREDIT <= UINT32_MAX,
               "the price of the largest bulk request must fit 32 bits");

_Static_assert((uint64_t)UINT_MAX * PRICING_X402_USDC_ATOMIC_PER_CREDIT / PRICING_X402_USDC_ATOMIC_PER_CREDIT == UINT_MAX,
               "every unsigned int credit count must have a price that fits uint64_t");

_Static_assert(X402_REQUEST_RECEIPT_LINE_BUF_SIZE >=
                 sizeof(X402_REQUEST_RECEIPT_HEADER_NAME ": ") - 1 +
                 X402_BASE64_LEN(sizeof("{\"success\":true,\"transaction\":\"\",\"network\":\"\"}") - 1 +
                                 (X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE - 1) +
                                 2 * (X402_NETWORK_BUF_SIZE - 1)) +
                 sizeof("\r\n"),
               "X402_REQUEST_RECEIPT_LINE_BUF_SIZE must fit the longest PAYMENT-RESPONSE line");

_Static_assert(X402_REQUEST_PAYMENT_REQUIRED_LINE_BUF_SIZE + 598 <= 2048,
               "a PAYMENT-REQUIRED line and the other 598 bytes of a head must fit 2048 bytes");
_Static_assert(X402_REQUEST_RECEIPT_LINE_BUF_SIZE + 598 <= 2048,
               "a PAYMENT-RESPONSE line and the other 598 bytes of a head must fit 2048 bytes");

static const ThrottleRule_t X402_REQUEST_FAILED_ATTEMPT_THROTTLE_RULE = { "x402_failed_attempt", 60, 10 };

static const ThrottleRule_t X402_REQUEST_FAILED_SETTLE_THROTTLE_RULE  = { "x402_failed_settle", 3600, 3 };

static const ThrottleRule_t X402_REQUEST_STATUS_ASK_THROTTLE_RULE     = { "x402_status_ask", 60, 10 };

static const ThrottleRule_t X402_REQUEST_UNSERVED_RELEASE_THROTTLE_RULE = { "x402_unserved_release", 60, 3 };

static const ThrottleRule_t X402_REQUEST_UNSERVED_SOURCE_THROTTLE_RULE = { "x402_unserved_source", 3600, 5 };

static const ThrottleRule_t X402_REQUEST_REFUSED_ATTEMPT_THROTTLE_RULE = { "x402_refused_attempt", 60, 30 };

static const ThrottleRule_t X402_REQUEST_REFUSED_SOURCE_THROTTLE_RULE  = { "x402_refused_source", 3600, 30 };

static const ThrottleRule_t X402_REQUEST_WEIGH_THROTTLE_RULE           = { "x402_weigh", 60, 30 };

static bool               g_isOn = false;
static X402Requirements_t g_baseRequirements;
static X402SolanaPolicy_t g_policy;
static char               g_solanaRpcUrl[CONFIG_X402_SOLANA_RPC_URL_BUF_SIZE];

static atomic_int g_settlesInUse = 0;

static void                     static_clearState               (void);
static bool                     static_tryCopyText              (char* out, size_t out_size, const char* text, size_t text_buf_size);
static bool                     static_tryEnterSettle           (void);
static void                     static_leaveSettle              (void);
static X402RequestOpenResult_t  static_buildOpenResult          (X402RequestOpenStatus_t status, unsigned int retry_after_sec);
static X402RequestOpenStatus_t  static_dbCheckFailureLoad       (PGconn* conn, const ThrottleRule_t* rule, const char* target_name, unsigned int* retry_after_sec_out);
static X402RequestOpenStatus_t  static_dbCheckClientLoads       (PGconn* conn, const char* ip_hash, unsigned int* retry_after_sec_out);
static void                     static_dbCountFailure           (PGconn* conn, const ThrottleRule_t* rule, const char* target_name);
static X402RequestOpenResult_t  static_dbRefuseAttempt          (PGconn* conn, const char* ip_hash, X402RequestOpenStatus_t status);
static X402PaymentStatus_t      static_parsePaymentSource       (const X402RequestPaymentSource_t* source, const X402Requirements_t* requirements, X402Payment_t* payment_out);
static X402RequestOpenResult_t  static_dbReadPayment            (PGconn* conn, const X402RequestPaymentSource_t* source, unsigned int credit_count, const char* ip_hash, X402Requirements_t* requirements_out, X402Payment_t* payment_out, X402SolanaCheck_t* check_out);
static X402RequestOpenStatus_t  static_dbCheckPaymentLoads      (PGconn* conn, const X402LedgerHashes_t* hashes, unsigned int* retry_after_sec_out);
static X402RequestOpenResult_t  static_dbVerifyFresh            (PGconn* conn, const X402Requirements_t* requirements, const X402Payment_t* payment, const X402LedgerHashes_t* hashes, const char* ip_hash, X402RequestPayment_t* payment_out);
static X402RequestOpenResult_t  static_dbOpenHeldPayment        (PGconn* conn, const X402LedgerReservation_t* reservation, const X402LedgerHashes_t* hashes, X402RequestPayment_t* payment_out);
static void                     static_fillOpenPayment          (X402RequestPayment_t* payment_out, const X402Requirements_t* requirements, const X402Payment_t* payment, const char* ip_hash);
static X402RequestOpenResult_t  static_dbOpenPending            (PGconn* conn, const X402LedgerHashes_t* hashes, const char* signature_text, X402RequestPayment_t* payment_out);
static X402RequestCloseStatus_t static_dbCloseFresh             (PGconn* conn, const X402RequestPayment_t* payment, X402RequestReceipt_t* receipt_out);
static X402RequestCloseStatus_t static_dbCloseConfirmed         (PGconn* conn, const X402RequestPayment_t* payment, X402RequestReceipt_t* receipt_out);
static void                     static_fillReceipt              (const char* network, const char* signature_text, X402RequestReceipt_t* receipt_out);
static bool                     static_tryWriteBase64HeaderLine (JsonBuf_t* json_buf, bool is_written, const char* header_name, char* line_out, size_t line_size);
static const char*              static_markStatusName           (X402LedgerMarkStatus_t mark_status);

X402RequestStartStatus_t x402_request_start(const ConfigX402_t* config)
{
  static_clearState();
  if (!config)
    return X402_REQUEST_START_OFF;

  char token_account[sizeof(config->ma_payToTokenAccount)];
  uint8_t pay_to[X402_SOLANA_ADDRESS_BYTE_COUNT];
  if (!static_tryCopyText(g_baseRequirements.ma_network, sizeof(g_baseRequirements.ma_network), config->ma_network, sizeof(config->ma_network))
      || !static_tryCopyText(g_baseRequirements.ma_asset, sizeof(g_baseRequirements.ma_asset), config->ma_usdcMint, sizeof(config->ma_usdcMint))
      || !static_tryCopyText(g_baseRequirements.ma_payTo, sizeof(g_baseRequirements.ma_payTo), config->ma_payTo, sizeof(config->ma_payTo))
      || !static_tryCopyText(g_baseRequirements.ma_feePayer, sizeof(g_baseRequirements.ma_feePayer), config->ma_feePayer, sizeof(config->ma_feePayer))
      || !static_tryCopyText(token_account, sizeof(token_account), config->ma_payToTokenAccount, sizeof(config->ma_payToTokenAccount))
      || !static_tryCopyText(g_solanaRpcUrl, sizeof(g_solanaRpcUrl), config->ma_solanaRpcUrl, sizeof(config->ma_solanaRpcUrl))
      || !x402_solana_tryDecodeAddress(g_baseRequirements.ma_feePayer, g_policy.ma_feePayer)
      || !x402_solana_tryDecodeAddress(g_baseRequirements.ma_asset, g_policy.ma_mint)
      || !x402_solana_tryDecodeAddress(token_account, g_policy.ma_destination)
      || !x402_solana_tryDecodeAddress(g_baseRequirements.ma_payTo, pay_to))
  {
    static_clearState();
    return X402_REQUEST_START_INVALID;
  }
  g_baseRequirements.m_maxTimeoutSeconds = X402_REQUEST_MAX_TIMEOUT_SECONDS;

  switch (x402_facilitator_supported(&g_baseRequirements))
  {
    case X402_FACILITATOR_SUPPORTED_YES:
      g_isOn = true;
      return X402_REQUEST_START_ON;
    case X402_FACILITATOR_SUPPORTED_MISMATCH:
      static_clearState();
      return X402_REQUEST_START_MISMATCH;
    case X402_FACILITATOR_SUPPORTED_UNAVAILABLE:
      static_clearState();
      return X402_REQUEST_START_UNAVAILABLE;
  }
  static_clearState();
  return X402_REQUEST_START_UNAVAILABLE;
}

bool x402_request_isOn(void)
{
  return g_isOn;
}

X402RequestOpenResult_t x402_request_dbOpenPayment(PGconn* conn, const X402RequestPaymentSource_t* source, unsigned int credit_count, const char* ip_secret, const char* ip_hash, X402RequestPayment_t* payment_out)
{
  assert(source      != NULL);
  assert(ip_hash     != NULL);
  assert(payment_out != NULL);
  assert(source->mp_text != NULL || source->m_len == 0);

  memset(payment_out, 0, sizeof(*payment_out));
  if (!g_isOn)
  {
    fprintf(stderr, "x402_request_dbOpenPayment: x402 payments are off\n");
    return static_buildOpenResult(X402_REQUEST_OPEN_ERROR, 0);
  }
  if (credit_count == 0)
  {
    fprintf(stderr, "x402_request_dbOpenPayment: credit_count is 0\n");
    return static_buildOpenResult(X402_REQUEST_OPEN_ERROR, 0);
  }
  if (strlen(ip_hash) != SHA256_HEX_LEN)
  {
    fprintf(stderr, "x402_request_dbOpenPayment: ip_hash is not SHA256_HEX_LEN characters\n");
    return static_buildOpenResult(X402_REQUEST_OPEN_ERROR, 0);
  }

  unsigned int retry_after_sec = 0;
  X402RequestOpenStatus_t load_status = static_dbCheckClientLoads(conn, ip_hash, &retry_after_sec);
  if (load_status != X402_REQUEST_OPEN_OK)
    return static_buildOpenResult(load_status, retry_after_sec);

  X402Requirements_t      requirements;
  X402Payment_t           payment;
  X402SolanaCheck_t       check;
  X402RequestOpenResult_t read_result = static_dbReadPayment(conn, source, credit_count, ip_hash, &requirements, &payment, &check);
  if (read_result.m_status != X402_REQUEST_OPEN_OK)
    return read_result;

  X402LedgerHashes_t hashes;
  if (!x402_ledger_tryMakeHashes(ip_secret, &check, &hashes))
    return static_buildOpenResult(X402_REQUEST_OPEN_ERROR, 0);

  load_status = static_dbCheckPaymentLoads(conn, &hashes, &retry_after_sec);
  if (load_status != X402_REQUEST_OPEN_OK)
    return static_buildOpenResult(load_status, retry_after_sec);

  if (!static_tryEnterSettle())
    return static_buildOpenResult(X402_REQUEST_OPEN_UNAVAILABLE, X402_REQUEST_UNAVAILABLE_RETRY_AFTER_SEC);

  X402LedgerReservation_t reservation = x402_ledger_dbReserve(conn, &hashes);
  if (reservation.m_status == X402_LEDGER_RESERVED)
    return static_dbVerifyFresh(conn, &requirements, &payment, &hashes, ip_hash, payment_out);

  static_leaveSettle();

  X402RequestOpenResult_t held_result = static_dbOpenHeldPayment(conn, &reservation, &hashes, payment_out);
  if (held_result.m_status == X402_REQUEST_OPEN_OK)
    static_fillOpenPayment(payment_out, &requirements, &payment, ip_hash);
  return held_result;
}

X402RequestCloseStatus_t x402_request_dbCloseAfterRun(PGconn* conn, X402RequestPayment_t* payment, X402RequestReceipt_t* receipt_out)
{
  assert(payment     != NULL);
  assert(receipt_out != NULL);

  memset(receipt_out, 0, sizeof(*receipt_out));
  if (!payment->m_isOpen)
    return X402_REQUEST_CLOSE_PENDING;
  payment->m_isOpen = false;

  switch (payment->m_kind)
  {
    case X402_REQUEST_PAYMENT_FRESH:
    {
      X402RequestCloseStatus_t close_status = static_dbCloseFresh(conn, payment, receipt_out);
      static_leaveSettle();
      return close_status;
    }
    case X402_REQUEST_PAYMENT_CONFIRMED:
      return static_dbCloseConfirmed(conn, payment, receipt_out);
  }
  return X402_REQUEST_CLOSE_PENDING;
}

void x402_request_dbReleaseUnserved(PGconn* conn, X402RequestPayment_t* payment, X402RequestUnservedKind_t unserved_kind)
{
  assert(payment != NULL);

  if (!payment->m_isOpen)
    return;

  payment->m_isOpen = false;
  if (payment->m_kind != X402_REQUEST_PAYMENT_FRESH)
    return;

  static_dbCountFailure(conn, &X402_REQUEST_UNSERVED_RELEASE_THROTTLE_RULE, payment->m_hashes.ma_messageHash);
  switch (unserved_kind)
  {
    case X402_REQUEST_UNSERVED_FAILED_RUN:
      static_dbCountFailure(conn, &X402_REQUEST_FAILED_ATTEMPT_THROTTLE_RULE, payment->ma_ipHash);
      static_dbCountFailure(conn, &X402_REQUEST_UNSERVED_SOURCE_THROTTLE_RULE, payment->m_hashes.ma_sourceHash);
      break;
    case X402_REQUEST_UNSERVED_REFUSED_REQUEST:
      static_dbCountFailure(conn, &X402_REQUEST_REFUSED_ATTEMPT_THROTTLE_RULE, payment->ma_ipHash);
      static_dbCountFailure(conn, &X402_REQUEST_REFUSED_SOURCE_THROTTLE_RULE, payment->m_hashes.ma_sourceHash);
      break;
  }
  (void)x402_ledger_dbRelease(conn, &payment->m_hashes);
  static_leaveSettle();
}

X402RequestUnservedKind_t x402_request_findUnservedKind(EndpointRunStatus_t run_status)
{
  switch (run_status)
  {
    case ENDPOINT_RUN_NOT_FOUND:
    case ENDPOINT_RUN_REFUSED:
    case ENDPOINT_RUN_REFUSED_WITH_BODY:
    case ENDPOINT_RUN_UNAUTHORIZED:
    case ENDPOINT_RUN_GONE:
      return X402_REQUEST_UNSERVED_REFUSED_REQUEST;
    case ENDPOINT_RUN_OK:
    case ENDPOINT_RUN_DEGRADED:
    case ENDPOINT_RUN_DB_ERROR:
    case ENDPOINT_RUN_UPSTREAM_ERROR:
    case ENDPOINT_RUN_TARGET_UNREACHABLE:
    case ENDPOINT_RUN_NO_MEMORY:
    case ENDPOINT_RUN_NO_CONNECTION:
    case ENDPOINT_RUN_NO_CREDIT_BUDGET:
      break;
  }
  return X402_REQUEST_UNSERVED_FAILED_RUN;
}

X402RequestOpenResult_t x402_request_dbCheckBeforeWeigh(PGconn* conn, const X402RequestPaymentSource_t* source, const char* ip_hash)
{
  assert(source  != NULL);
  assert(ip_hash != NULL);
  assert(source->mp_text != NULL || source->m_len == 0);

  if (!g_isOn)
    return static_buildOpenResult(X402_REQUEST_OPEN_ERROR, 0);

  unsigned int            retry_after_sec = 0;
  X402RequestOpenStatus_t load_status     = static_dbCheckClientLoads(conn, ip_hash, &retry_after_sec);
  if (load_status != X402_REQUEST_OPEN_OK)
    return static_buildOpenResult(load_status, retry_after_sec);

  X402Payment_t payment;
  if (static_parsePaymentSource(source, &g_baseRequirements, &payment) == X402_PAYMENT_MALFORMED)
    return static_dbRefuseAttempt(conn, ip_hash, X402_REQUEST_OPEN_MALFORMED);

  return x402_request_dbThrottleWeigh(conn, ip_hash);
}

X402RequestOpenResult_t x402_request_dbThrottleWeigh(PGconn* conn, const char* ip_hash)
{
  assert(ip_hash != NULL);

  unsigned int retry_after_seconds = 0;
  switch (throttle_dbCharge(conn, &X402_REQUEST_WEIGH_THROTTLE_RULE, ip_hash, 1, &retry_after_seconds))
  {
    case THROTTLE_CHARGED:
      break;
    case THROTTLE_REFUSED:
      return static_buildOpenResult(X402_REQUEST_OPEN_LIMITED, retry_after_seconds);
    case THROTTLE_ERROR:
      return static_buildOpenResult(X402_REQUEST_OPEN_ERROR, 0);
  }
  return static_buildOpenResult(X402_REQUEST_OPEN_OK, 0);
}

bool x402_request_tryWritePaymentRequired(const Endpoint_t* endpoint, unsigned int credit_count, const char* error_text, char* line_out, size_t line_size)
{
  assert(endpoint              != NULL);
  assert(endpoint->mp_httpPath != NULL);
  assert(error_text            != NULL);
  assert(line_out              != NULL);
  assert(line_size              > 0);

  line_out[0] = '\0';
  char resource_url[X402_REQUEST_RESOURCE_URL_BUF_SIZE];
  int  resource_url_len = snprintf(resource_url, sizeof(resource_url), "%s%s", PRICING_API_BASE_URL, endpoint->mp_httpPath);
  if (resource_url_len < 0 || (size_t)resource_url_len >= sizeof(resource_url))
    return false;

  JsonBuf_t* json_buf = jsonbuf_create(line_size, line_size);
  if (!json_buf)
    return false;

  bool is_written = x402_request_appendPaymentRequired(json_buf, resource_url, credit_count, error_text);
  return static_tryWriteBase64HeaderLine(json_buf, is_written, X402_REQUEST_PAYMENT_REQUIRED_HEADER_NAME, line_out, line_size);
}

bool x402_request_appendPaymentRequired(JsonBuf_t* json_buf, const char* resource_url, unsigned int credit_count, const char* error_text)
{
  assert(json_buf     != NULL);
  assert(resource_url != NULL);
  assert(error_text   != NULL);

  if (!g_isOn || credit_count == 0)
    return false;

  X402Requirements_t requirements = g_baseRequirements;
  requirements.m_amountAtomic = (uint64_t)credit_count * PRICING_X402_USDC_ATOMIC_PER_CREDIT;
  return x402_writePaymentRequired(json_buf, &requirements, resource_url, X402_REQUEST_RESOURCE_DESCRIPTION, error_text);
}

bool x402_request_tryWriteReceiptLine(const X402RequestReceipt_t* receipt, char* line_out, size_t line_size)
{
  assert(receipt   != NULL);
  assert(line_out  != NULL);
  assert(line_size  > 0);

  line_out[0] = '\0';
  JsonBuf_t* json_buf = jsonbuf_create(line_size, line_size);
  if (!json_buf)
    return false;

  bool is_written = x402_request_appendReceipt(json_buf, receipt);
  return static_tryWriteBase64HeaderLine(json_buf, is_written, X402_REQUEST_RECEIPT_HEADER_NAME, line_out, line_size);
}

bool x402_request_appendReceipt(JsonBuf_t* json_buf, const X402RequestReceipt_t* receipt)
{
  assert(json_buf != NULL);
  assert(receipt  != NULL);

  return x402_writeSettlementResponse(json_buf, receipt->ma_network, receipt->ma_signature);
}

static void static_clearState(void)
{
  g_isOn = false;
  explicit_bzero(&g_baseRequirements, sizeof(g_baseRequirements));
  explicit_bzero(&g_policy, sizeof(g_policy));
  explicit_bzero(g_solanaRpcUrl, sizeof(g_solanaRpcUrl));
  atomic_store(&g_settlesInUse, 0);
}

static bool static_tryCopyText(char* out, size_t out_size, const char* text, size_t text_buf_size)
{
  assert(out  != NULL);
  assert(text != NULL);

  size_t text_len = strnlen(text, text_buf_size);
  if (text_len == text_buf_size || text_len >= out_size)
    return false;
  memcpy(out, text, text_len + 1);
  return true;
}

static bool static_tryEnterSettle(void)
{
  int settles_in_use = atomic_load(&g_settlesInUse);
  while (settles_in_use < X402_REQUEST_MAX_SETTLE_COUNT)
  {
    if (atomic_compare_exchange_weak(&g_settlesInUse, &settles_in_use, settles_in_use + 1))
      return true;
  }
  return false;
}

static void static_leaveSettle(void)
{
  int settles_before = atomic_fetch_sub(&g_settlesInUse, 1);
  assert(settles_before > 0);
  (void)settles_before;
}

static X402RequestOpenResult_t static_buildOpenResult(X402RequestOpenStatus_t status, unsigned int retry_after_sec)
{
  X402RequestOpenResult_t result = { status, retry_after_sec };
  return result;
}

static X402RequestOpenStatus_t static_dbCheckFailureLoad(PGconn* conn, const ThrottleRule_t* rule, const char* target_name, unsigned int* retry_after_sec_out)
{
  assert(rule                != NULL);
  assert(target_name         != NULL);
  assert(retry_after_sec_out != NULL);

  *retry_after_sec_out = 0;
  unsigned int load_count          = 0;
  unsigned int retry_after_seconds = 0;
  if (!throttle_dbTryReadLoad(conn, rule, target_name, &load_count, &retry_after_seconds))
    return X402_REQUEST_OPEN_ERROR;
  if (load_count >= rule->m_chargeLimit)
  {
    *retry_after_sec_out = retry_after_seconds;
    return X402_REQUEST_OPEN_LIMITED;
  }
  return X402_REQUEST_OPEN_OK;
}

static X402RequestOpenStatus_t static_dbCheckClientLoads(PGconn* conn, const char* ip_hash, unsigned int* retry_after_sec_out)
{
  X402RequestOpenStatus_t load_status = static_dbCheckFailureLoad(conn, &X402_REQUEST_FAILED_ATTEMPT_THROTTLE_RULE, ip_hash, retry_after_sec_out);
  if (load_status != X402_REQUEST_OPEN_OK)
    return load_status;
  return static_dbCheckFailureLoad(conn, &X402_REQUEST_REFUSED_ATTEMPT_THROTTLE_RULE, ip_hash, retry_after_sec_out);
}

static void static_dbCountFailure(PGconn* conn, const ThrottleRule_t* rule, const char* target_name)
{
  unsigned int retry_after_seconds = 0;
  (void)throttle_dbCharge(conn, rule, target_name, 1, &retry_after_seconds);
}

static X402RequestOpenResult_t static_dbRefuseAttempt(PGconn* conn, const char* ip_hash, X402RequestOpenStatus_t status)
{
  static_dbCountFailure(conn, &X402_REQUEST_FAILED_ATTEMPT_THROTTLE_RULE, ip_hash);
  return static_buildOpenResult(status, 0);
}

static X402PaymentStatus_t static_parsePaymentSource(const X402RequestPaymentSource_t* source, const X402Requirements_t* requirements, X402Payment_t* payment_out)
{
  switch (source->m_kind)
  {
    case X402_REQUEST_PAYMENT_SOURCE_HEADER_BASE64:
      return x402_parsePaymentHeader(source->mp_text, source->m_len, requirements, payment_out);
    case X402_REQUEST_PAYMENT_SOURCE_JSON:
      return x402_parsePaymentJson(source->mp_text, source->m_len, requirements, payment_out);
  }
  return X402_PAYMENT_MALFORMED;
}

static X402RequestOpenResult_t static_dbReadPayment(PGconn* conn, const X402RequestPaymentSource_t* source, unsigned int credit_count, const char* ip_hash, X402Requirements_t* requirements_out, X402Payment_t* payment_out, X402SolanaCheck_t* check_out)
{
  assert(requirements_out != NULL);
  assert(payment_out      != NULL);
  assert(check_out        != NULL);

  *requirements_out = g_baseRequirements;
  requirements_out->m_amountAtomic = (uint64_t)credit_count * PRICING_X402_USDC_ATOMIC_PER_CREDIT;

  switch (static_parsePaymentSource(source, requirements_out, payment_out))
  {
    case X402_PAYMENT_OK:
      break;
    case X402_PAYMENT_MALFORMED:
      return static_dbRefuseAttempt(conn, ip_hash, X402_REQUEST_OPEN_MALFORMED);
    case X402_PAYMENT_NOT_ACCEPTED:
      return static_dbRefuseAttempt(conn, ip_hash, X402_REQUEST_OPEN_REFUSED);
  }

  X402SolanaPolicy_t policy = g_policy;
  policy.m_amount = requirements_out->m_amountAtomic;
  X402SolanaStatus_t check_status = x402_solana_checkTransaction(payment_out->ma_transaction, payment_out->m_transactionByteCount, &policy, check_out);
  if (check_status == X402_SOLANA_MALFORMED)
    return static_dbRefuseAttempt(conn, ip_hash, X402_REQUEST_OPEN_MALFORMED);
  else if (check_status != X402_SOLANA_OK)
    return static_dbRefuseAttempt(conn, ip_hash, X402_REQUEST_OPEN_REFUSED);
  return static_buildOpenResult(X402_REQUEST_OPEN_OK, 0);
}

static X402RequestOpenStatus_t static_dbCheckPaymentLoads(PGconn* conn, const X402LedgerHashes_t* hashes, unsigned int* retry_after_sec_out)
{
  assert(hashes != NULL);

  X402RequestOpenStatus_t load_status = static_dbCheckFailureLoad(conn, &X402_REQUEST_FAILED_SETTLE_THROTTLE_RULE, hashes->ma_sourceHash, retry_after_sec_out);
  if (load_status != X402_REQUEST_OPEN_OK)
    return load_status;
  load_status = static_dbCheckFailureLoad(conn, &X402_REQUEST_UNSERVED_RELEASE_THROTTLE_RULE, hashes->ma_messageHash, retry_after_sec_out);
  if (load_status != X402_REQUEST_OPEN_OK)
    return load_status;
  load_status = static_dbCheckFailureLoad(conn, &X402_REQUEST_UNSERVED_SOURCE_THROTTLE_RULE, hashes->ma_sourceHash, retry_after_sec_out);
  if (load_status != X402_REQUEST_OPEN_OK)
    return load_status;
  return static_dbCheckFailureLoad(conn, &X402_REQUEST_REFUSED_SOURCE_THROTTLE_RULE, hashes->ma_sourceHash, retry_after_sec_out);
}

static X402RequestOpenResult_t static_dbVerifyFresh(PGconn* conn, const X402Requirements_t* requirements, const X402Payment_t* payment, const X402LedgerHashes_t* hashes, const char* ip_hash, X402RequestPayment_t* payment_out)
{
  assert(requirements != NULL);
  assert(payment      != NULL);
  assert(hashes       != NULL);
  assert(payment_out  != NULL);

  switch (x402_facilitator_verify(requirements, payment))
  {
    case X402_FACILITATOR_VERIFY_VALID:
      payment_out->m_kind   = X402_REQUEST_PAYMENT_FRESH;
      payment_out->m_isOpen = true;
      payment_out->m_hashes = *hashes;
      static_fillOpenPayment(payment_out, requirements, payment, ip_hash);
      return static_buildOpenResult(X402_REQUEST_OPEN_OK, 0);
    case X402_FACILITATOR_VERIFY_INVALID:
      static_dbCountFailure(conn, &X402_REQUEST_FAILED_ATTEMPT_THROTTLE_RULE, ip_hash);
      (void)x402_ledger_dbRelease(conn, hashes);
      static_leaveSettle();
      return static_buildOpenResult(X402_REQUEST_OPEN_REFUSED, 0);
    case X402_FACILITATOR_VERIFY_UNAVAILABLE:
      break;
  }
  (void)x402_ledger_dbRelease(conn, hashes);
  static_leaveSettle();
  return static_buildOpenResult(X402_REQUEST_OPEN_UNAVAILABLE, X402_REQUEST_UNAVAILABLE_RETRY_AFTER_SEC);
}

static X402RequestOpenResult_t static_dbOpenHeldPayment(PGconn* conn, const X402LedgerReservation_t* reservation, const X402LedgerHashes_t* hashes, X402RequestPayment_t* payment_out)
{
  assert(reservation != NULL);
  assert(hashes      != NULL);
  assert(payment_out != NULL);

  switch (reservation->m_status)
  {
    case X402_LEDGER_IN_FLIGHT:
    case X402_LEDGER_SOURCE_BUSY:
      return static_buildOpenResult(X402_REQUEST_OPEN_BUSY, X402_REQUEST_BUSY_RETRY_AFTER_SEC);
    case X402_LEDGER_SETTLED:
      return static_buildOpenResult(X402_REQUEST_OPEN_ALREADY_USED, 0);
    case X402_LEDGER_PENDING:
      if (reservation->ma_signature[0] == '\0')
        return static_buildOpenResult(X402_REQUEST_OPEN_PENDING, X402_REQUEST_PENDING_RETRY_AFTER_SEC);
      return static_dbOpenPending(conn, hashes, reservation->ma_signature, payment_out);
    case X402_LEDGER_RESERVED:
    case X402_LEDGER_ERROR:
      break;
  }
  return static_buildOpenResult(X402_REQUEST_OPEN_ERROR, 0);
}

static void static_fillOpenPayment(X402RequestPayment_t* payment_out, const X402Requirements_t* requirements, const X402Payment_t* payment, const char* ip_hash)
{
  assert(payment_out  != NULL);
  assert(requirements != NULL);
  assert(payment      != NULL);
  assert(ip_hash      != NULL);

  payment_out->m_requirements = *requirements;
  payment_out->m_payment      = *payment;
  memcpy(payment_out->ma_ipHash, ip_hash, SHA256_HEX_LEN + 1);
}

static X402RequestOpenResult_t static_dbOpenPending(PGconn* conn, const X402LedgerHashes_t* hashes, const char* signature_text, X402RequestPayment_t* payment_out)
{
  assert(hashes         != NULL);
  assert(signature_text != NULL);
  assert(payment_out    != NULL);

  unsigned int retry_after_seconds = 0;
  switch (throttle_dbCharge(conn, &X402_REQUEST_STATUS_ASK_THROTTLE_RULE, hashes->ma_messageHash, 1, &retry_after_seconds))
  {
    case THROTTLE_CHARGED:
      break;
    case THROTTLE_REFUSED:
      return static_buildOpenResult(X402_REQUEST_OPEN_LIMITED, retry_after_seconds);
    case THROTTLE_ERROR:
      return static_buildOpenResult(X402_REQUEST_OPEN_ERROR, 0);
  }

  switch (x402_solana_rpc_askSignatureStatus(g_solanaRpcUrl, signature_text))
  {
    case X402_SOLANA_RPC_SIGNATURE_CONFIRMED:
      payment_out->m_kind   = X402_REQUEST_PAYMENT_CONFIRMED;
      payment_out->m_isOpen = true;
      payment_out->m_hashes = *hashes;
      snprintf(payment_out->ma_signature, sizeof(payment_out->ma_signature), "%s", signature_text);
      return static_buildOpenResult(X402_REQUEST_OPEN_OK, 0);
    case X402_SOLANA_RPC_SIGNATURE_FAILED:
      (void)x402_ledger_dbRelease(conn, hashes);
      return static_buildOpenResult(X402_REQUEST_OPEN_REFUSED, 0);
    case X402_SOLANA_RPC_SIGNATURE_PROCESSED:
    case X402_SOLANA_RPC_SIGNATURE_NOT_FOUND:
    case X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE:
      break;
  }
  return static_buildOpenResult(X402_REQUEST_OPEN_PENDING, X402_REQUEST_PENDING_RETRY_AFTER_SEC);
}

static X402RequestCloseStatus_t static_dbCloseFresh(PGconn* conn, const X402RequestPayment_t* payment, X402RequestReceipt_t* receipt_out)
{
  X402FacilitatorSettlement_t settlement = x402_facilitator_settle(&payment->m_requirements, &payment->m_payment);
  switch (settlement.m_status)
  {
    case X402_FACILITATOR_SETTLE_PAID:
    {
      if (!settlement.m_hasSignature)
        break;
      X402LedgerMarkStatus_t settled_mark_status = x402_ledger_dbMarkSettled(conn, &payment->m_hashes);
      if (settled_mark_status != X402_LEDGER_MARKED)
        fprintf(stderr, "x402_request_dbCloseAfterRun: a paid settle was not marked settled (%s); the answer is served\n", static_markStatusName(settled_mark_status));
      static_fillReceipt(payment->m_requirements.ma_network, settlement.ma_signature, receipt_out);
      return X402_REQUEST_CLOSE_SERVE;
    }
    case X402_FACILITATOR_SETTLE_REFUSED:
      static_dbCountFailure(conn, &X402_REQUEST_FAILED_SETTLE_THROTTLE_RULE, payment->m_hashes.ma_sourceHash);
      static_dbCountFailure(conn, &X402_REQUEST_FAILED_ATTEMPT_THROTTLE_RULE, payment->ma_ipHash);
      (void)x402_ledger_dbRelease(conn, &payment->m_hashes);
      return X402_REQUEST_CLOSE_REFUSED;
    case X402_FACILITATOR_SETTLE_PENDING:
      break;
  }

  X402LedgerMarkStatus_t pending_mark_status = x402_ledger_dbMarkPending(conn, &payment->m_hashes, settlement.m_hasSignature ? settlement.ma_signature : "");
  if (pending_mark_status != X402_LEDGER_MARKED)
    fprintf(stderr, "x402_request_dbCloseAfterRun: a pending settle was not marked pending (%s); the row stays reserved\n", static_markStatusName(pending_mark_status));
  return X402_REQUEST_CLOSE_PENDING;
}

static X402RequestCloseStatus_t static_dbCloseConfirmed(PGconn* conn, const X402RequestPayment_t* payment, X402RequestReceipt_t* receipt_out)
{
  if (x402_ledger_dbMarkSettled(conn, &payment->m_hashes) != X402_LEDGER_MARKED)
    return X402_REQUEST_CLOSE_PENDING;
  static_fillReceipt(payment->m_requirements.ma_network, payment->ma_signature, receipt_out);
  return X402_REQUEST_CLOSE_SERVE;
}

static void static_fillReceipt(const char* network, const char* signature_text, X402RequestReceipt_t* receipt_out)
{
  snprintf(receipt_out->ma_network, sizeof(receipt_out->ma_network), "%s", network);
  snprintf(receipt_out->ma_signature, sizeof(receipt_out->ma_signature), "%s", signature_text);
}

static bool static_tryWriteBase64HeaderLine(JsonBuf_t* json_buf, bool is_written, const char* header_name, char* line_out, size_t line_size)
{
  assert(json_buf    != NULL);
  assert(header_name != NULL);
  assert(line_out    != NULL);
  assert(line_size    > 0);

  line_out[0] = '\0';
  char* json_text = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  if (!is_written || !json_text)
  {
    free(json_text);
    return false;
  }

  int name_len = snprintf(line_out, line_size, "%s: ", header_name);
  bool is_encoded = name_len >= 0 && (size_t)name_len + 3 <= line_size
                    && x402_tryEncodeBase64((const uint8_t*)json_text, strlen(json_text), line_out + name_len, line_size - (size_t)name_len - 2);
  free(json_text);
  if (!is_encoded)
  {
    line_out[0] = '\0';
    return false;
  }

  size_t line_len = strlen(line_out);
  memcpy(line_out + line_len, "\r\n", sizeof("\r\n"));
  return true;
}

static const char* static_markStatusName(X402LedgerMarkStatus_t mark_status)
{
  switch (mark_status)
  {
    case X402_LEDGER_MARKED:
      return "MARKED";
    case X402_LEDGER_NOT_MARKED:
      return "NOT_MARKED";
    case X402_LEDGER_MARK_ERROR:
      return "MARK_ERROR";
  }
  return "unknown";
}
