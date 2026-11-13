#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include "unity/unity.h"
#include "jsonbuf.h"
#include "jsonread.h"
#include "x402_request.h"
#include "x402.h"
#include "x402_solana.h"
#include "pricing.h"
#include "throttle_stub.h"
#include "x402_facilitator_stub.h"
#include "x402_ledger_stub.h"
#include "x402_solana_rpc_stub.h"

#define FIXTURE_NETWORK         "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
#define FIXTURE_MINT            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
#define FIXTURE_PAY_TO          "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
#define FIXTURE_TOKEN_ACCOUNT   "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
#define FIXTURE_FEE_PAYER       "2wmVCSfPxGPjrnMMn7rchp4uaeoTqN39mXFC2zhPdri9"
#define FIXTURE_RPC_URL         "https://rpc.example.com/v1/sample"
#define FIXTURE_IP_SECRET       "ip-secret-of-the-test-0123456789"
#define FIXTURE_HEADER          "aGVhZGVy"
#define FIXTURE_MESSAGE_HASH    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define FIXTURE_SOURCE_HASH     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define FIXTURE_IP_HASH         "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
#define FIXTURE_SIGNATURE       "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW"
#define FIXTURE_PENDING_SIG     "3PendingSignatureOfTheLedgerRow"
#define FIXTURE_BYTE_COUNT      321

#define FIXTURE_CONN ((PGconn*)1)

static const uint8_t FEE_PAYER_BYTES[32] = {
  0x1c, 0xe3, 0x59, 0xed, 0x5a, 0x01, 0x2e, 0x04, 0xfa, 0x14, 0x2b, 0x9c, 0x75, 0x1a, 0x1c, 0x5e,
  0x87, 0xcf, 0xd0, 0xa0, 0x16, 0x1b, 0x9c, 0x85, 0xff, 0xd3, 0x1b, 0x78, 0xcd, 0xfc, 0xd8, 0xf6
};
static const uint8_t MINT_BYTES[32] = {
  0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a, 0x3d, 0x65, 0xf3, 0x6a, 0xab, 0xc9, 0x74, 0x31,
  0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6, 0xe0, 0xe4, 0x7c, 0xa6, 0x02, 0x03, 0x45, 0x2f, 0x5d, 0x61
};
static const uint8_t TOKEN_ACCOUNT_BYTES[32] = {
  0x3b, 0x44, 0x2c, 0xb3, 0x91, 0x21, 0x57, 0xf1, 0x3a, 0x93, 0x3d, 0x01, 0x34, 0x28, 0x2d, 0x03,
  0x2b, 0x5f, 0xfe, 0xcd, 0x01, 0xa2, 0xdb, 0xf1, 0xb7, 0x79, 0x06, 0x08, 0xdf, 0x00, 0x2e, 0xa7
};

X402PaymentStatus_t __wrap_x402_parsePaymentHeader(const char* value, size_t value_len, const X402Requirements_t* requirements, X402Payment_t* payment_out);
X402PaymentStatus_t __wrap_x402_parsePaymentJson(const char* json, size_t json_len, const X402Requirements_t* requirements, X402Payment_t* payment_out);
X402SolanaStatus_t  __wrap_x402_solana_checkTransaction(const uint8_t* tx, size_t tx_len, const X402SolanaPolicy_t* policy, X402SolanaCheck_t* check_out);

static X402PaymentStatus_t g_parseStatus;
static int                 g_parseCount;
static int                 g_parseHeaderCount;
static int                 g_parseJsonCount;
static X402Requirements_t  g_parseLastRequirements;
static size_t              g_parseLastValueLen;

static X402SolanaStatus_t  g_checkStatus;
static int                 g_checkCount;
static X402SolanaPolicy_t  g_checkLastPolicy;
static size_t              g_checkLastTxLen;

static X402PaymentStatus_t static_answerParse(size_t value_len, const X402Requirements_t* requirements, X402Payment_t* payment_out)
{
  g_parseCount++;
  g_parseLastRequirements = *requirements;
  g_parseLastValueLen     = value_len;
  if (g_parseStatus == X402_PAYMENT_OK)
  {
    memset(payment_out, 0, sizeof(*payment_out));
    payment_out->ma_transaction[0]      = 0x42;
    payment_out->m_transactionByteCount = FIXTURE_BYTE_COUNT;
  }
  return g_parseStatus;
}

X402PaymentStatus_t __wrap_x402_parsePaymentHeader(const char* value, size_t value_len, const X402Requirements_t* requirements, X402Payment_t* payment_out)
{
  (void)value;
  g_parseHeaderCount++;
  return static_answerParse(value_len, requirements, payment_out);
}

X402PaymentStatus_t __wrap_x402_parsePaymentJson(const char* json, size_t json_len, const X402Requirements_t* requirements, X402Payment_t* payment_out)
{
  (void)json;
  g_parseJsonCount++;
  return static_answerParse(json_len, requirements, payment_out);
}

X402SolanaStatus_t __wrap_x402_solana_checkTransaction(const uint8_t* tx, size_t tx_len, const X402SolanaPolicy_t* policy, X402SolanaCheck_t* check_out)
{
  (void)tx;
  g_checkCount++;
  g_checkLastPolicy = *policy;
  g_checkLastTxLen  = tx_len;
  if (g_checkStatus == X402_SOLANA_OK)
  {
    memset(check_out->ma_messageHash, 0x11, sizeof(check_out->ma_messageHash));
    memset(check_out->ma_source, 0x22, sizeof(check_out->ma_source));
  }
  return g_checkStatus;
}

static void static_fixtureConfig(ConfigX402_t* config)
{
  memset(config, 0, sizeof(*config));
  snprintf(config->ma_network,           sizeof(config->ma_network),           "%s", FIXTURE_NETWORK);
  snprintf(config->ma_usdcMint,          sizeof(config->ma_usdcMint),          "%s", FIXTURE_MINT);
  snprintf(config->ma_payTo,             sizeof(config->ma_payTo),             "%s", FIXTURE_PAY_TO);
  snprintf(config->ma_payToTokenAccount, sizeof(config->ma_payToTokenAccount), "%s", FIXTURE_TOKEN_ACCOUNT);
  snprintf(config->ma_feePayer,          sizeof(config->ma_feePayer),          "%s", FIXTURE_FEE_PAYER);
  snprintf(config->ma_solanaRpcUrl,      sizeof(config->ma_solanaRpcUrl),      "%s", FIXTURE_RPC_URL);
}

static void static_resetStubs(void)
{
  g_parseStatus = X402_PAYMENT_OK;
  g_parseCount  = 0;
  g_parseHeaderCount = 0;
  g_parseJsonCount   = 0;
  memset(&g_parseLastRequirements, 0, sizeof(g_parseLastRequirements));
  g_parseLastValueLen = 0;
  g_checkStatus = X402_SOLANA_OK;
  g_checkCount  = 0;
  memset(&g_checkLastPolicy, 0, sizeof(g_checkLastPolicy));
  g_checkLastTxLen = 0;

  g_stub_THROTTLE_charge_status            = THROTTLE_CHARGED;
  g_stub_THROTTLE_retry_after_seconds      = 0;
  g_stub_THROTTLE_charge_count             = 0;
  memset(g_stub_THROTTLE_loads, 0, sizeof(g_stub_THROTTLE_loads));
  g_stub_THROTTLE_default_load             = 0;
  g_stub_THROTTLE_is_read_answered         = true;
  g_stub_THROTTLE_read_retry_after_seconds = 0;
  g_stub_THROTTLE_read_count               = 0;
  memset(g_stub_THROTTLE_calls, 0, sizeof(g_stub_THROTTLE_calls));
  g_stub_THROTTLE_call_count               = 0;

  g_stub_X402_FACILITATOR_verify_status    = X402_FACILITATOR_VERIFY_VALID;
  memset(&g_stub_X402_FACILITATOR_settlement, 0, sizeof(g_stub_X402_FACILITATOR_settlement));
  g_stub_X402_FACILITATOR_settlement.m_status = X402_FACILITATOR_SETTLE_PAID;
  g_stub_X402_FACILITATOR_settlement.m_hasSignature = true;
  snprintf(g_stub_X402_FACILITATOR_settlement.ma_signature, sizeof(g_stub_X402_FACILITATOR_settlement.ma_signature), "%s", FIXTURE_SIGNATURE);
  g_stub_X402_FACILITATOR_supported_status = X402_FACILITATOR_SUPPORTED_YES;
  g_stub_X402_FACILITATOR_verify_count     = 0;
  g_stub_X402_FACILITATOR_settle_count     = 0;
  g_stub_X402_FACILITATOR_supported_count  = 0;
  memset(&g_stub_X402_FACILITATOR_last_verify_requirements, 0, sizeof(X402Requirements_t));
  memset(&g_stub_X402_FACILITATOR_last_settle_requirements, 0, sizeof(X402Requirements_t));
  memset(&g_stub_X402_FACILITATOR_last_supported_requirements, 0, sizeof(X402Requirements_t));
  g_stub_X402_FACILITATOR_last_verify_byte_count = 0;
  g_stub_X402_FACILITATOR_last_settle_byte_count = 0;

  g_stub_X402_LEDGER_is_hashed = true;
  snprintf(g_stub_X402_LEDGER_hashes.ma_messageHash, sizeof(g_stub_X402_LEDGER_hashes.ma_messageHash), "%s", FIXTURE_MESSAGE_HASH);
  snprintf(g_stub_X402_LEDGER_hashes.ma_sourceHash, sizeof(g_stub_X402_LEDGER_hashes.ma_sourceHash), "%s", FIXTURE_SOURCE_HASH);
  g_stub_X402_LEDGER_make_hashes_count = 0;
  g_stub_X402_LEDGER_last_secret       = NULL;
  memset(&g_stub_X402_LEDGER_last_check, 0, sizeof(g_stub_X402_LEDGER_last_check));
  g_stub_X402_LEDGER_reservation.m_status          = X402_LEDGER_RESERVED;
  g_stub_X402_LEDGER_reservation.ma_signature[0]   = '\0';
  g_stub_X402_LEDGER_mark_settled_status = X402_LEDGER_MARKED;
  g_stub_X402_LEDGER_mark_pending_status = X402_LEDGER_MARKED;
  g_stub_X402_LEDGER_release_status      = X402_LEDGER_MARKED;
  g_stub_X402_LEDGER_reserve_count       = 0;
  g_stub_X402_LEDGER_mark_settled_count  = 0;
  g_stub_X402_LEDGER_mark_pending_count  = 0;
  g_stub_X402_LEDGER_release_count       = 0;
  g_stub_X402_LEDGER_on_release          = NULL;
  memset(&g_stub_X402_LEDGER_last_reserve_hashes, 0, sizeof(X402LedgerHashes_t));
  memset(&g_stub_X402_LEDGER_last_mark_settled_hashes, 0, sizeof(X402LedgerHashes_t));
  memset(&g_stub_X402_LEDGER_last_mark_pending_hashes, 0, sizeof(X402LedgerHashes_t));
  memset(&g_stub_X402_LEDGER_last_release_hashes, 0, sizeof(X402LedgerHashes_t));
  g_stub_X402_LEDGER_last_pending_signature[0] = '\0';

  g_stub_X402_SOLANA_RPC_status            = X402_SOLANA_RPC_SIGNATURE_NOT_FOUND;
  g_stub_X402_SOLANA_RPC_count             = 0;
  g_stub_X402_SOLANA_RPC_last_url[0]       = '\0';
  g_stub_X402_SOLANA_RPC_last_signature[0] = '\0';
}

static int g_releaseCallCountAtRelease;

static void static_recordReleaseCallCount(void)
{
  g_releaseCallCountAtRelease = g_stub_THROTTLE_call_count;
}

void setUp(void)
{
  static_resetStubs();
  ConfigX402_t config;
  static_fixtureConfig(&config);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_START_ON, x402_request_start(&config));
  static_resetStubs();
}

void tearDown(void)
{
  x402_request_start(NULL);
}

static const X402RequestPaymentSource_t HEADER_SOURCE = {
  .m_kind  = X402_REQUEST_PAYMENT_SOURCE_HEADER_BASE64,
  .mp_text = FIXTURE_HEADER,
  .m_len   = sizeof(FIXTURE_HEADER) - 1,
};

#define FIXTURE_PAYMENT_JSON "{\"x402Version\":2}"
static const X402RequestPaymentSource_t JSON_SOURCE = {
  .m_kind  = X402_REQUEST_PAYMENT_SOURCE_JSON,
  .mp_text = FIXTURE_PAYMENT_JSON,
  .m_len   = sizeof(FIXTURE_PAYMENT_JSON) - 1,
};

static X402RequestOpenResult_t static_open(unsigned int credit_count, X402RequestPayment_t* payment_out)
{
  return x402_request_dbOpenPayment(FIXTURE_CONN, &HEADER_SOURCE, credit_count, FIXTURE_IP_SECRET, FIXTURE_IP_HASH, payment_out);
}

static void static_openFresh(X402RequestPayment_t* payment_out)
{
  g_parseStatus                           = X402_PAYMENT_OK;
  g_checkStatus                           = X402_SOLANA_OK;
  memset(g_stub_THROTTLE_loads, 0, sizeof(g_stub_THROTTLE_loads));
  g_stub_THROTTLE_is_read_answered        = true;
  g_stub_X402_LEDGER_is_hashed            = true;
  g_stub_X402_LEDGER_reservation.m_status = X402_LEDGER_RESERVED;
  g_stub_X402_FACILITATOR_verify_status   = X402_FACILITATOR_VERIFY_VALID;
  X402RequestOpenResult_t result = static_open(1, payment_out);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_OK, result.m_status);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_PAYMENT_FRESH, payment_out->m_kind);
}

static void static_openConfirmed(X402RequestPayment_t* payment_out)
{
  g_stub_X402_LEDGER_reservation.m_status = X402_LEDGER_PENDING;
  snprintf(g_stub_X402_LEDGER_reservation.ma_signature, sizeof(g_stub_X402_LEDGER_reservation.ma_signature), "%s", FIXTURE_PENDING_SIG);
  g_stub_X402_SOLANA_RPC_status = X402_SOLANA_RPC_SIGNATURE_CONFIRMED;
  X402RequestOpenResult_t result = static_open(1, payment_out);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_OK, result.m_status);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_PAYMENT_CONFIRMED, payment_out->m_kind);
}

static void static_assertBothPlacesFree(void)
{
  X402RequestPayment_t first;
  X402RequestPayment_t second;
  static_openFresh(&first);
  static_openFresh(&second);
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &first, X402_REQUEST_UNSERVED_FAILED_RUN);
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &second, X402_REQUEST_UNSERVED_FAILED_RUN);
}

static void static_assertThrottleCall(int index, bool is_charge, const char* rule_name, unsigned int window_seconds, unsigned int charge_limit, const char* target_name)
{
  TEST_ASSERT_TRUE(index < g_stub_THROTTLE_call_count);
  const ThrottleStubCall_t* call = &g_stub_THROTTLE_calls[index];
  TEST_ASSERT_EQUAL(is_charge, call->m_isCharge);
  TEST_ASSERT_EQUAL_STRING(rule_name, call->ma_ruleName);
  TEST_ASSERT_EQUAL_UINT(window_seconds, call->m_windowSeconds);
  TEST_ASSERT_EQUAL_UINT(charge_limit, call->m_chargeLimit);
  TEST_ASSERT_EQUAL_STRING(target_name, call->ma_targetName);
  if (is_charge)
    TEST_ASSERT_EQUAL_UINT(1, call->m_chargedCount);
}

static size_t static_decodeBase64(const char* text, size_t text_len, char* out, size_t out_size)
{
  static const char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  TEST_ASSERT_EQUAL_size_t(0, text_len % 4);
  size_t byte_count = 0;
  for (size_t i = 0; i < text_len; i += 4)
  {
    unsigned int group      = 0;
    int          data_count = 0;
    for (size_t k = 0; k < 4; k++)
    {
      group <<= 6;
      if (text[i + k] == '=')
        continue;
      const char* found = strchr(ALPHABET, text[i + k]);
      TEST_ASSERT_NOT_NULL(found);
      group |= (unsigned int)(found - ALPHABET);
      data_count++;
    }
    TEST_ASSERT_TRUE(byte_count + 3 < out_size);
    out[byte_count++] = (char)((group >> 16) & 0xFF);
    if (data_count > 2)
      out[byte_count++] = (char)((group >> 8) & 0xFF);
    if (data_count > 3)
      out[byte_count++] = (char)(group & 0xFF);
  }
  out[byte_count] = '\0';
  return byte_count;
}

static void static_decodeLine(const char* line, const char* name, char* out, size_t out_size)
{
  size_t name_len = strlen(name);
  size_t line_len = strlen(line);
  TEST_ASSERT_TRUE(line_len > name_len + 4);
  TEST_ASSERT_EQUAL_INT(0, strncmp(line, name, name_len));
  TEST_ASSERT_EQUAL_INT(0, strncmp(line + name_len, ": ", 2));
  TEST_ASSERT_EQUAL_STRING("\r\n", line + line_len - 2);
  static_decodeBase64(line + name_len + 2, line_len - name_len - 4, out, out_size);
}

static X402RequestCloseStatus_t static_closeToLine(X402RequestPayment_t* payment, char* receipt_line_out, size_t receipt_line_size)
{
  X402RequestReceipt_t receipt;
  snprintf(receipt.ma_network, sizeof(receipt.ma_network), "%s", "sentinel");
  snprintf(receipt.ma_signature, sizeof(receipt.ma_signature), "%s", "sentinel");
  X402RequestCloseStatus_t close_status = x402_request_dbCloseAfterRun(FIXTURE_CONN, payment, &receipt);
  receipt_line_out[0] = '\0';
  if (close_status == X402_REQUEST_CLOSE_SERVE)
    TEST_ASSERT_TRUE(x402_request_tryWriteReceiptLine(&receipt, receipt_line_out, receipt_line_size));
  else
  {
    TEST_ASSERT_EQUAL_STRING("", receipt.ma_network);
    TEST_ASSERT_EQUAL_STRING("", receipt.ma_signature);
  }
  return close_status;
}

static FILE* g_stderrCaptureFile = NULL;
static int   g_savedStderrFd     = -1;

static void static_beginStderrCapture(void)
{
  g_stderrCaptureFile = tmpfile();
  TEST_ASSERT_NOT_NULL(g_stderrCaptureFile);
  fflush(stderr);
  g_savedStderrFd = dup(STDERR_FILENO);
  TEST_ASSERT_TRUE(g_savedStderrFd >= 0);
  TEST_ASSERT_TRUE(dup2(fileno(g_stderrCaptureFile), STDERR_FILENO) >= 0);
}

static void static_endStderrCapture(char* text, size_t text_size)
{
  fflush(stderr);
  TEST_ASSERT_TRUE(dup2(g_savedStderrFd, STDERR_FILENO) >= 0);
  close(g_savedStderrFd);
  g_savedStderrFd = -1;
  rewind(g_stderrCaptureFile);
  size_t length = fread(text, 1, text_size - 1, g_stderrCaptureFile);
  text[length] = '\0';
  fclose(g_stderrCaptureFile);
  g_stderrCaptureFile = NULL;
}

void test_start_without_settings_is_off(void)
{
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_START_OFF, x402_request_start(NULL));
  TEST_ASSERT_FALSE(x402_request_isOn());
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_FACILITATOR_supported_count);
}

void test_start_with_an_address_that_does_not_decode_is_invalid(void)
{
  for (int field = 0; field < 4; field++)
  {
    ConfigX402_t config;
    static_fixtureConfig(&config);
    char* const texts[4] = { config.ma_feePayer, config.ma_usdcMint, config.ma_payToTokenAccount, config.ma_payTo };
    texts[field][5] = '0';

    ConfigX402_t good_config;
    static_fixtureConfig(&good_config);
    TEST_ASSERT_EQUAL_INT(X402_REQUEST_START_ON, x402_request_start(&good_config));
    g_stub_X402_FACILITATOR_supported_count = 0;

    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_REQUEST_START_INVALID, x402_request_start(&config), "field");
    TEST_ASSERT_FALSE(x402_request_isOn());
    TEST_ASSERT_EQUAL_INT(0, g_stub_X402_FACILITATOR_supported_count);
  }
}

void test_start_keeps_the_facilitator_refusal(void)
{
  ConfigX402_t config;
  static_fixtureConfig(&config);

  g_stub_X402_FACILITATOR_supported_status = X402_FACILITATOR_SUPPORTED_MISMATCH;
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_START_MISMATCH, x402_request_start(&config));
  TEST_ASSERT_FALSE(x402_request_isOn());
  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_FACILITATOR_supported_count);

  g_stub_X402_FACILITATOR_supported_status = X402_FACILITATOR_SUPPORTED_UNAVAILABLE;
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_START_UNAVAILABLE, x402_request_start(&config));
  TEST_ASSERT_FALSE(x402_request_isOn());
  TEST_ASSERT_EQUAL_INT(2, g_stub_X402_FACILITATOR_supported_count);
}

void test_start_on_hands_the_facilitator_the_base_requirements(void)
{
  ConfigX402_t config;
  static_fixtureConfig(&config);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_START_ON, x402_request_start(&config));
  TEST_ASSERT_TRUE(x402_request_isOn());
  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_FACILITATOR_supported_count);

  const X402Requirements_t* requirements = &g_stub_X402_FACILITATOR_last_supported_requirements;
  TEST_ASSERT_EQUAL_STRING("solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", requirements->ma_network);
  TEST_ASSERT_EQUAL_STRING("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", requirements->ma_asset);
  TEST_ASSERT_EQUAL_STRING("9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", requirements->ma_payTo);
  TEST_ASSERT_EQUAL_STRING("2wmVCSfPxGPjrnMMn7rchp4uaeoTqN39mXFC2zhPdri9", requirements->ma_feePayer);
  TEST_ASSERT_EQUAL_UINT32(60, requirements->m_maxTimeoutSeconds);
}

void test_start_decodes_the_solana_policy(void)
{
  X402RequestPayment_t payment;
  static_openFresh(&payment);
  TEST_ASSERT_EQUAL_HEX8_ARRAY(FEE_PAYER_BYTES, g_checkLastPolicy.ma_feePayer, 32);
  TEST_ASSERT_EQUAL_HEX8_ARRAY(MINT_BYTES, g_checkLastPolicy.ma_mint, 32);
  TEST_ASSERT_EQUAL_HEX8_ARRAY(TOKEN_ACCOUNT_BYTES, g_checkLastPolicy.ma_destination, 32);
  TEST_ASSERT_EQUAL_size_t(321, g_checkLastTxLen);
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &payment, X402_REQUEST_UNSERVED_FAILED_RUN);
}

void test_open_when_off_is_error_with_no_call(void)
{
  x402_request_start(NULL);
  X402RequestPayment_t payment;
  memset(&payment, 0xA5, sizeof(payment));
  X402RequestOpenResult_t result = static_open(1, &payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_ERROR, result.m_status);
  TEST_ASSERT_EQUAL_UINT(0, result.m_retryAfterSec);
  TEST_ASSERT_EQUAL_INT(0, g_parseCount);
  TEST_ASSERT_EQUAL_INT(0, g_checkCount);
  TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_FACILITATOR_verify_count);
  TEST_ASSERT_FALSE(payment.m_isOpen);
  const uint8_t* bytes = (const uint8_t*)&payment;
  for (size_t i = 0; i < sizeof(payment); i++)
    TEST_ASSERT_EQUAL_HEX8(0x00, bytes[i]);
}

void test_open_for_0_credits_is_error_with_no_call(void)
{
  X402RequestPayment_t payment;
  X402RequestOpenResult_t result = static_open(0, &payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_ERROR, result.m_status);
  TEST_ASSERT_EQUAL_UINT(0, result.m_retryAfterSec);
  TEST_ASSERT_EQUAL_INT(0, g_parseCount);
  TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_call_count);
}

void test_open_hands_the_price_to_parse_check_and_verify(void)
{
  static const unsigned int credit_counts[] = { 1, 2, 500 };
  static const uint64_t     amounts[]       = { 10000, 20000, 5000000 };
  for (size_t i = 0; i < 3; i++)
  {
    X402RequestPayment_t payment;
    X402RequestOpenResult_t result = static_open(credit_counts[i], &payment);
    TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_OK, result.m_status);
    TEST_ASSERT_EQUAL_UINT64(amounts[i], g_parseLastRequirements.m_amountAtomic);
    TEST_ASSERT_EQUAL_UINT64(amounts[i], g_checkLastPolicy.m_amount);
    TEST_ASSERT_EQUAL_UINT64(amounts[i], g_stub_X402_FACILITATOR_last_verify_requirements.m_amountAtomic);
    TEST_ASSERT_EQUAL_UINT64(amounts[i], payment.m_requirements.m_amountAtomic);
    TEST_ASSERT_EQUAL_size_t(8, g_parseLastValueLen);
    TEST_ASSERT_EQUAL_STRING("solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", g_parseLastRequirements.ma_network);
    TEST_ASSERT_EQUAL_STRING("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", g_parseLastRequirements.ma_asset);
    TEST_ASSERT_EQUAL_STRING("9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", g_parseLastRequirements.ma_payTo);
    TEST_ASSERT_EQUAL_STRING("2wmVCSfPxGPjrnMMn7rchp4uaeoTqN39mXFC2zhPdri9", g_parseLastRequirements.ma_feePayer);
    TEST_ASSERT_EQUAL_UINT32(60, g_parseLastRequirements.m_maxTimeoutSeconds);
    TEST_ASSERT_EQUAL_size_t(321, g_stub_X402_FACILITATOR_last_verify_byte_count);
    x402_request_dbReleaseUnserved(FIXTURE_CONN, &payment, X402_REQUEST_UNSERVED_FAILED_RUN);
  }
}

void test_open_header_that_parse_refuses_goes_no_further(void)
{
  X402RequestPayment_t payment;
  g_parseStatus = X402_PAYMENT_MALFORMED;
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_MALFORMED, static_open(1, &payment).m_status);
  g_parseStatus = X402_PAYMENT_NOT_ACCEPTED;
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_REFUSED, static_open(1, &payment).m_status);
  TEST_ASSERT_FALSE(payment.m_isOpen);

  TEST_ASSERT_EQUAL_INT(2, g_parseCount);
  TEST_ASSERT_EQUAL_INT(0, g_checkCount);
  TEST_ASSERT_EQUAL_INT(6, g_stub_THROTTLE_call_count);
  for (int i = 0; i < 6; i += 3)
  {
    static_assertThrottleCall(i,     false, "x402_failed_attempt",  60, 10, FIXTURE_IP_HASH);
    static_assertThrottleCall(i + 1, false, "x402_refused_attempt", 60, 30, FIXTURE_IP_HASH);
    static_assertThrottleCall(i + 2, true,  "x402_failed_attempt",  60, 10, FIXTURE_IP_HASH);
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_FACILITATOR_verify_count);
  static_assertBothPlacesFree();
}

void test_open_transaction_that_the_check_refuses_goes_no_further(void)
{
  X402RequestPayment_t payment;
  g_checkStatus = X402_SOLANA_MALFORMED;
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_MALFORMED, static_open(1, &payment).m_status);

  static const X402SolanaStatus_t refusals[] = {
    X402_SOLANA_SIGNERS_REFUSED, X402_SOLANA_COMPUTE_REFUSED, X402_SOLANA_TRANSFER_REFUSED,
    X402_SOLANA_INSTRUCTION_REFUSED, X402_SOLANA_FEE_PAYER_IN_USE, X402_SOLANA_SIGNATURE_INVALID
  };
  for (size_t i = 0; i < sizeof(refusals) / sizeof(refusals[0]); i++)
  {
    g_checkStatus = refusals[i];
    TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_REFUSED, static_open(1, &payment).m_status);
    TEST_ASSERT_FALSE(payment.m_isOpen);
  }
  TEST_ASSERT_EQUAL_INT(7, g_checkCount);
  TEST_ASSERT_EQUAL_INT(21, g_stub_THROTTLE_call_count);
  TEST_ASSERT_EQUAL_INT(7, g_stub_THROTTLE_charge_count);
  for (int i = 0; i < THROTTLE_STUB_MAX_CALL_COUNT; i += 3)
  {
    static_assertThrottleCall(i,     false, "x402_failed_attempt",  60, 10, FIXTURE_IP_HASH);
    static_assertThrottleCall(i + 1, false, "x402_refused_attempt", 60, 30, FIXTURE_IP_HASH);
    static_assertThrottleCall(i + 2, true,  "x402_failed_attempt",  60, 10, FIXTURE_IP_HASH);
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_make_hashes_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_FACILITATOR_verify_count);
}

void test_open_reads_the_six_failure_loads_and_counts_nothing(void)
{
  X402RequestPayment_t payment;
  static_openFresh(&payment);
  TEST_ASSERT_EQUAL_INT(6, g_stub_THROTTLE_call_count);
  static_assertThrottleCall(0, false, "x402_failed_attempt",   60,   10, FIXTURE_IP_HASH);
  static_assertThrottleCall(1, false, "x402_refused_attempt",  60,   30, FIXTURE_IP_HASH);
  static_assertThrottleCall(2, false, "x402_failed_settle",    3600, 3,  FIXTURE_SOURCE_HASH);
  static_assertThrottleCall(3, false, "x402_unserved_release", 60,   3,  FIXTURE_MESSAGE_HASH);
  static_assertThrottleCall(4, false, "x402_unserved_source",  3600, 5,  FIXTURE_SOURCE_HASH);
  static_assertThrottleCall(5, false, "x402_refused_source",   3600, 30, FIXTURE_SOURCE_HASH);
  TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_charge_count);

  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_LEDGER_make_hashes_count);
  TEST_ASSERT_EQUAL_STRING(FIXTURE_IP_SECRET, g_stub_X402_LEDGER_last_secret);
  TEST_ASSERT_EQUAL_HEX8(0x11, g_stub_X402_LEDGER_last_check.ma_messageHash[0]);
  TEST_ASSERT_EQUAL_HEX8(0x22, g_stub_X402_LEDGER_last_check.ma_source[31]);
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &payment, X402_REQUEST_UNSERVED_FAILED_RUN);
}

void test_open_ip_at_its_failed_attempt_limit_is_limited(void)
{
  g_stub_THROTTLE_loads[0] = (ThrottleStubLoad_t){ "x402_failed_attempt", 10, false };
  g_stub_THROTTLE_read_retry_after_seconds = 42;
  X402RequestPayment_t payment;
  X402RequestOpenResult_t result = static_open(1, &payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_LIMITED, result.m_status);
  TEST_ASSERT_EQUAL_UINT(42, result.m_retryAfterSec);
  TEST_ASSERT_FALSE(payment.m_isOpen);
  TEST_ASSERT_EQUAL_INT(1, g_stub_THROTTLE_call_count);
  TEST_ASSERT_EQUAL_INT(0, g_parseCount);
  TEST_ASSERT_EQUAL_INT(0, g_checkCount);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_make_hashes_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_reserve_count);

  g_stub_THROTTLE_loads[0].m_loadCount = 9;
  result = static_open(1, &payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_OK, result.m_status);
  TEST_ASSERT_EQUAL_UINT(0, result.m_retryAfterSec);
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &payment, X402_REQUEST_UNSERVED_FAILED_RUN);
}

void test_open_source_at_its_failed_settle_limit_is_limited(void)
{
  g_stub_THROTTLE_loads[0] = (ThrottleStubLoad_t){ "x402_failed_settle", 3, false };
  g_stub_THROTTLE_read_retry_after_seconds = 1800;
  X402RequestPayment_t payment;
  X402RequestOpenResult_t result = static_open(1, &payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_LIMITED, result.m_status);
  TEST_ASSERT_EQUAL_UINT(1800, result.m_retryAfterSec);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_reserve_count);
  static_assertBothPlacesFree();

  g_stub_THROTTLE_loads[0].m_loadCount = 2;
  result = static_open(1, &payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_OK, result.m_status);
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &payment, X402_REQUEST_UNSERVED_FAILED_RUN);
}

void test_open_with_a_failed_read_or_hash_is_error(void)
{
  X402RequestPayment_t payment;
  g_stub_THROTTLE_loads[0] = (ThrottleStubLoad_t){ "x402_failed_attempt", 0, true };
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_ERROR, static_open(1, &payment).m_status);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_make_hashes_count);

  g_stub_THROTTLE_loads[0] = (ThrottleStubLoad_t){ "x402_failed_settle", 0, true };
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_ERROR, static_open(1, &payment).m_status);

  g_stub_THROTTLE_loads[0] = (ThrottleStubLoad_t){ NULL, 0, false };
  g_stub_X402_LEDGER_is_hashed = false;
  g_stub_THROTTLE_call_count = 0;
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_ERROR, static_open(1, &payment).m_status);
  TEST_ASSERT_EQUAL_INT(2, g_stub_THROTTLE_call_count);

  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_reserve_count);
  TEST_ASSERT_FALSE(payment.m_isOpen);
  static_assertBothPlacesFree();
}

void test_open_when_both_settle_places_are_taken_is_unavailable(void)
{
  X402RequestPayment_t first;
  X402RequestPayment_t second;
  X402RequestPayment_t third;
  static_openFresh(&first);
  static_openFresh(&second);
  TEST_ASSERT_EQUAL_INT(2, g_stub_X402_LEDGER_reserve_count);

  X402RequestOpenResult_t result = static_open(1, &third);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_UNAVAILABLE, result.m_status);
  TEST_ASSERT_EQUAL_UINT(5, result.m_retryAfterSec);
  TEST_ASSERT_FALSE(third.m_isOpen);
  TEST_ASSERT_EQUAL_INT(2, g_stub_X402_LEDGER_reserve_count);
  TEST_ASSERT_EQUAL_INT(2, g_stub_X402_FACILITATOR_verify_count);

  x402_request_dbReleaseUnserved(FIXTURE_CONN, &first, X402_REQUEST_UNSERVED_FAILED_RUN);
  static_openFresh(&third);
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &second, X402_REQUEST_UNSERVED_FAILED_RUN);
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &third, X402_REQUEST_UNSERVED_FAILED_RUN);
  static_assertBothPlacesFree();
}

void test_open_reserve_answers_map_to_their_status(void)
{
  static const X402LedgerReserveStatus_t      reserve_statuses[] = { X402_LEDGER_IN_FLIGHT, X402_LEDGER_SOURCE_BUSY, X402_LEDGER_SETTLED, X402_LEDGER_PENDING, X402_LEDGER_ERROR };
  static const X402RequestOpenStatus_t        open_statuses[]    = { X402_REQUEST_OPEN_BUSY, X402_REQUEST_OPEN_BUSY, X402_REQUEST_OPEN_ALREADY_USED, X402_REQUEST_OPEN_PENDING, X402_REQUEST_OPEN_ERROR };
  static const unsigned int                   retry_seconds[]    = { 5, 5, 0, 10, 0 };
  for (size_t i = 0; i < 5; i++)
  {
    g_stub_X402_LEDGER_reservation.m_status        = reserve_statuses[i];
    g_stub_X402_LEDGER_reservation.ma_signature[0] = '\0';
    X402RequestPayment_t payment;
    X402RequestOpenResult_t result = static_open(1, &payment);
    TEST_ASSERT_EQUAL_INT_MESSAGE(open_statuses[i], result.m_status, "status");
    TEST_ASSERT_EQUAL_UINT_MESSAGE(retry_seconds[i], result.m_retryAfterSec, "retry");
    TEST_ASSERT_FALSE(payment.m_isOpen);
    TEST_ASSERT_EQUAL_STRING(FIXTURE_MESSAGE_HASH, g_stub_X402_LEDGER_last_reserve_hashes.ma_messageHash);
    TEST_ASSERT_EQUAL_STRING(FIXTURE_SOURCE_HASH, g_stub_X402_LEDGER_last_reserve_hashes.ma_sourceHash);
    static_assertBothPlacesFree();
  }
  TEST_ASSERT_EQUAL_INT(2 * 5, g_stub_X402_FACILITATOR_verify_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_SOLANA_RPC_count);
  TEST_ASSERT_EQUAL_INT(2 * 5, g_stub_X402_LEDGER_release_count);
}

void test_open_verified_payment_is_open_and_fresh(void)
{
  X402RequestPayment_t payment;
  memset(&payment, 0xA5, sizeof(payment));
  X402RequestOpenResult_t result = static_open(2, &payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_OK, result.m_status);
  TEST_ASSERT_EQUAL_UINT(0, result.m_retryAfterSec);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_PAYMENT_FRESH, payment.m_kind);
  TEST_ASSERT_TRUE(payment.m_isOpen);
  TEST_ASSERT_EQUAL_UINT64(20000, payment.m_requirements.m_amountAtomic);
  TEST_ASSERT_EQUAL_STRING("solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", payment.m_requirements.ma_network);
  TEST_ASSERT_EQUAL_size_t(321, payment.m_payment.m_transactionByteCount);
  TEST_ASSERT_EQUAL_HEX8(0x42, payment.m_payment.ma_transaction[0]);
  TEST_ASSERT_EQUAL_STRING(FIXTURE_MESSAGE_HASH, payment.m_hashes.ma_messageHash);
  TEST_ASSERT_EQUAL_STRING(FIXTURE_SOURCE_HASH, payment.m_hashes.ma_sourceHash);
  TEST_ASSERT_EQUAL_STRING(FIXTURE_IP_HASH, payment.ma_ipHash);
  TEST_ASSERT_EQUAL_STRING("", payment.ma_signature);
  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_FACILITATOR_verify_count);
  TEST_ASSERT_TRUE(g_stub_X402_LEDGER_last_conn == FIXTURE_CONN);
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &payment, X402_REQUEST_UNSERVED_FAILED_RUN);
}

void test_open_payment_the_facilitator_refuses_is_released_and_counted(void)
{
  g_stub_X402_FACILITATOR_verify_status = X402_FACILITATOR_VERIFY_INVALID;
  g_stub_X402_LEDGER_on_release         = static_recordReleaseCallCount;
  X402RequestPayment_t payment;
  X402RequestOpenResult_t result = static_open(1, &payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_REFUSED, result.m_status);
  TEST_ASSERT_FALSE(payment.m_isOpen);
  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_LEDGER_release_count);
  TEST_ASSERT_EQUAL_STRING(FIXTURE_MESSAGE_HASH, g_stub_X402_LEDGER_last_release_hashes.ma_messageHash);
  TEST_ASSERT_EQUAL_INT(7, g_stub_THROTTLE_call_count);
  TEST_ASSERT_EQUAL_INT(7, g_releaseCallCountAtRelease);
  static_assertThrottleCall(6, true, "x402_failed_attempt", 60, 10, FIXTURE_IP_HASH);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_FACILITATOR_settle_count);
  static_assertBothPlacesFree();
}

void test_open_with_no_verify_answer_is_released_and_unavailable(void)
{
  g_stub_X402_FACILITATOR_verify_status = X402_FACILITATOR_VERIFY_UNAVAILABLE;
  X402RequestPayment_t payment;
  X402RequestOpenResult_t result = static_open(1, &payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_UNAVAILABLE, result.m_status);
  TEST_ASSERT_EQUAL_UINT(5, result.m_retryAfterSec);
  TEST_ASSERT_FALSE(payment.m_isOpen);
  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_LEDGER_release_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_charge_count);
  static_assertBothPlacesFree();
}

void test_open_pending_payment_that_solana_confirmed_is_open_and_confirmed(void)
{
  X402RequestPayment_t payment;
  static_openConfirmed(&payment);
  TEST_ASSERT_TRUE(payment.m_isOpen);
  TEST_ASSERT_EQUAL_STRING(FIXTURE_PENDING_SIG, payment.ma_signature);
  TEST_ASSERT_EQUAL_STRING(FIXTURE_MESSAGE_HASH, payment.m_hashes.ma_messageHash);
  TEST_ASSERT_EQUAL_STRING(FIXTURE_IP_HASH, payment.ma_ipHash);
  TEST_ASSERT_EQUAL_UINT64(10000, payment.m_requirements.m_amountAtomic);
  TEST_ASSERT_EQUAL_INT(7, g_stub_THROTTLE_call_count);
  static_assertThrottleCall(6, true, "x402_status_ask", 60, 10, FIXTURE_MESSAGE_HASH);
  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_SOLANA_RPC_count);
  TEST_ASSERT_EQUAL_STRING("https://rpc.example.com/v1/sample", g_stub_X402_SOLANA_RPC_last_url);
  TEST_ASSERT_EQUAL_STRING(FIXTURE_PENDING_SIG, g_stub_X402_SOLANA_RPC_last_signature);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_FACILITATOR_verify_count);
  static_assertBothPlacesFree();
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &payment, X402_REQUEST_UNSERVED_FAILED_RUN);
}

void test_open_pending_payment_that_failed_on_chain_is_released_and_refused(void)
{
  g_stub_X402_LEDGER_reservation.m_status = X402_LEDGER_PENDING;
  snprintf(g_stub_X402_LEDGER_reservation.ma_signature, sizeof(g_stub_X402_LEDGER_reservation.ma_signature), "%s", FIXTURE_PENDING_SIG);
  g_stub_X402_SOLANA_RPC_status = X402_SOLANA_RPC_SIGNATURE_FAILED;
  X402RequestPayment_t payment;
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_REFUSED, static_open(1, &payment).m_status);
  TEST_ASSERT_FALSE(payment.m_isOpen);
  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_LEDGER_release_count);
  static_assertBothPlacesFree();
}

void test_open_pending_payment_that_solana_has_not_decided_stays_pending(void)
{
  static const X402SolanaRpcSignatureStatus_t statuses[] = { X402_SOLANA_RPC_SIGNATURE_PROCESSED, X402_SOLANA_RPC_SIGNATURE_NOT_FOUND, X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE };
  g_stub_X402_LEDGER_reservation.m_status = X402_LEDGER_PENDING;
  snprintf(g_stub_X402_LEDGER_reservation.ma_signature, sizeof(g_stub_X402_LEDGER_reservation.ma_signature), "%s", FIXTURE_PENDING_SIG);
  for (size_t i = 0; i < 3; i++)
  {
    g_stub_X402_SOLANA_RPC_status = statuses[i];
    X402RequestPayment_t payment;
    X402RequestOpenResult_t result = static_open(1, &payment);
    TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_PENDING, result.m_status);
    TEST_ASSERT_EQUAL_UINT(10, result.m_retryAfterSec);
    TEST_ASSERT_FALSE(payment.m_isOpen);
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_release_count);
  TEST_ASSERT_EQUAL_INT(3, g_stub_X402_SOLANA_RPC_count);
}

void test_open_pending_payment_over_its_ask_limit_is_limited(void)
{
  g_stub_X402_LEDGER_reservation.m_status = X402_LEDGER_PENDING;
  snprintf(g_stub_X402_LEDGER_reservation.ma_signature, sizeof(g_stub_X402_LEDGER_reservation.ma_signature), "%s", FIXTURE_PENDING_SIG);
  g_stub_X402_SOLANA_RPC_status       = X402_SOLANA_RPC_SIGNATURE_CONFIRMED;
  g_stub_THROTTLE_charge_status       = THROTTLE_REFUSED;
  g_stub_THROTTLE_retry_after_seconds = 33;
  X402RequestPayment_t payment;
  X402RequestOpenResult_t result = static_open(1, &payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_LIMITED, result.m_status);
  TEST_ASSERT_EQUAL_UINT(33, result.m_retryAfterSec);

  g_stub_THROTTLE_charge_status = THROTTLE_ERROR;
  result = static_open(1, &payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_ERROR, result.m_status);
  TEST_ASSERT_EQUAL_UINT(0, result.m_retryAfterSec);
  TEST_ASSERT_FALSE(payment.m_isOpen);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_SOLANA_RPC_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_release_count);
}

void test_close_of_a_paid_fresh_payment_serves_with_a_receipt(void)
{
  X402RequestPayment_t payment;
  static_openFresh(&payment);
  char receipt_line[X402_REQUEST_RECEIPT_LINE_BUF_SIZE];
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_CLOSE_SERVE, static_closeToLine(&payment, receipt_line, sizeof(receipt_line)));
  TEST_ASSERT_FALSE(payment.m_isOpen);
  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_FACILITATOR_settle_count);
  TEST_ASSERT_EQUAL_UINT64(10000, g_stub_X402_FACILITATOR_last_settle_requirements.m_amountAtomic);
  TEST_ASSERT_EQUAL_size_t(321, g_stub_X402_FACILITATOR_last_settle_byte_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_LEDGER_mark_settled_count);
  TEST_ASSERT_EQUAL_STRING(FIXTURE_MESSAGE_HASH, g_stub_X402_LEDGER_last_mark_settled_hashes.ma_messageHash);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_release_count);

  char json[512];
  static_decodeLine(receipt_line, "PAYMENT-RESPONSE", json, sizeof(json));
  TEST_ASSERT_EQUAL_STRING("{\"success\":true,\"transaction\":\"5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW\","
                           "\"network\":\"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1\"}", json);
  static_assertBothPlacesFree();
}

void test_close_of_a_paid_payment_whose_mark_fails_still_serves(void)
{
  static const X402LedgerMarkStatus_t mark_statuses[] = { X402_LEDGER_NOT_MARKED, X402_LEDGER_MARK_ERROR };
  for (size_t i = 0; i < 2; i++)
  {
    g_stub_X402_LEDGER_mark_settled_status = mark_statuses[i];
    X402RequestPayment_t payment;
    static_openFresh(&payment);
    char receipt_line[X402_REQUEST_RECEIPT_LINE_BUF_SIZE];
    TEST_ASSERT_EQUAL_INT(X402_REQUEST_CLOSE_SERVE, static_closeToLine(&payment, receipt_line, sizeof(receipt_line)));
    TEST_ASSERT_EQUAL_INT(0, strncmp(receipt_line, "PAYMENT-RESPONSE: ", 18));
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_release_count);
  static_assertBothPlacesFree();
}

void test_close_of_a_paid_settle_without_a_signature_is_pending(void)
{
  g_stub_X402_FACILITATOR_settlement.m_hasSignature    = false;
  g_stub_X402_FACILITATOR_settlement.ma_signature[0]   = '\0';
  X402RequestPayment_t payment;
  static_openFresh(&payment);
  char receipt_line[X402_REQUEST_RECEIPT_LINE_BUF_SIZE] = "sentinel";
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_CLOSE_PENDING, static_closeToLine(&payment, receipt_line, sizeof(receipt_line)));
  TEST_ASSERT_EQUAL_STRING("", receipt_line);
  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_LEDGER_mark_pending_count);
  TEST_ASSERT_EQUAL_STRING("", g_stub_X402_LEDGER_last_pending_signature);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_mark_settled_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_release_count);
  TEST_ASSERT_FALSE(payment.m_isOpen);
  static_assertBothPlacesFree();
}

void test_close_of_a_refused_settle_releases_and_counts_both(void)
{
  g_stub_X402_FACILITATOR_settlement.m_status = X402_FACILITATOR_SETTLE_REFUSED;
  X402RequestPayment_t payment;
  static_openFresh(&payment);
  g_releaseCallCountAtRelease   = -1;
  g_stub_X402_LEDGER_on_release = static_recordReleaseCallCount;
  char receipt_line[X402_REQUEST_RECEIPT_LINE_BUF_SIZE] = "sentinel";
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_CLOSE_REFUSED, static_closeToLine(&payment, receipt_line, sizeof(receipt_line)));
  TEST_ASSERT_EQUAL_STRING("", receipt_line);
  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_LEDGER_release_count);
  TEST_ASSERT_EQUAL_STRING(FIXTURE_SOURCE_HASH, g_stub_X402_LEDGER_last_release_hashes.ma_sourceHash);
  TEST_ASSERT_EQUAL_INT(8, g_stub_THROTTLE_call_count);
  TEST_ASSERT_EQUAL_INT(8, g_releaseCallCountAtRelease);
  static_assertThrottleCall(6, true, "x402_failed_settle", 3600, 3, FIXTURE_SOURCE_HASH);
  static_assertThrottleCall(7, true, "x402_failed_attempt", 60, 10, FIXTURE_IP_HASH);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_mark_settled_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_mark_pending_count);
  TEST_ASSERT_FALSE(payment.m_isOpen);
  static_assertBothPlacesFree();
}

void test_close_of_a_pending_settle_marks_it_pending_and_never_releases(void)
{
  g_stub_X402_FACILITATOR_settlement.m_status = X402_FACILITATOR_SETTLE_PENDING;
  X402RequestPayment_t payment;
  char receipt_line[X402_REQUEST_RECEIPT_LINE_BUF_SIZE];
  static_openFresh(&payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_CLOSE_PENDING, static_closeToLine(&payment, receipt_line, sizeof(receipt_line)));
  TEST_ASSERT_EQUAL_STRING(FIXTURE_SIGNATURE, g_stub_X402_LEDGER_last_pending_signature);
  TEST_ASSERT_EQUAL_STRING(FIXTURE_MESSAGE_HASH, g_stub_X402_LEDGER_last_mark_pending_hashes.ma_messageHash);

  g_stub_X402_FACILITATOR_settlement.m_hasSignature = false;
  static_openFresh(&payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_CLOSE_PENDING, static_closeToLine(&payment, receipt_line, sizeof(receipt_line)));
  TEST_ASSERT_EQUAL_STRING("", g_stub_X402_LEDGER_last_pending_signature);

  g_stub_X402_LEDGER_mark_pending_status = X402_LEDGER_MARK_ERROR;
  static_openFresh(&payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_CLOSE_PENDING, static_closeToLine(&payment, receipt_line, sizeof(receipt_line)));

  TEST_ASSERT_EQUAL_INT(3, g_stub_X402_LEDGER_mark_pending_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_release_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_charge_count);
  static_assertBothPlacesFree();
}

void test_close_of_a_confirmed_payment_that_is_marked_serves(void)
{
  X402RequestPayment_t payment;
  static_openConfirmed(&payment);
  char receipt_line[X402_REQUEST_RECEIPT_LINE_BUF_SIZE];
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_CLOSE_SERVE, static_closeToLine(&payment, receipt_line, sizeof(receipt_line)));
  TEST_ASSERT_FALSE(payment.m_isOpen);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_FACILITATOR_settle_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_LEDGER_mark_settled_count);

  char json[512];
  static_decodeLine(receipt_line, "PAYMENT-RESPONSE", json, sizeof(json));
  TEST_ASSERT_EQUAL_STRING("{\"success\":true,\"transaction\":\"3PendingSignatureOfTheLedgerRow\","
                           "\"network\":\"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1\"}", json);
  static_assertBothPlacesFree();
}

void test_close_of_a_confirmed_payment_that_is_not_marked_is_pending(void)
{
  static const X402LedgerMarkStatus_t mark_statuses[] = { X402_LEDGER_NOT_MARKED, X402_LEDGER_MARK_ERROR };
  for (size_t i = 0; i < 2; i++)
  {
    X402RequestPayment_t payment;
    static_openConfirmed(&payment);
    g_stub_X402_LEDGER_mark_settled_status = mark_statuses[i];
    char receipt_line[X402_REQUEST_RECEIPT_LINE_BUF_SIZE] = "sentinel";
    TEST_ASSERT_EQUAL_INT(X402_REQUEST_CLOSE_PENDING, static_closeToLine(&payment, receipt_line, sizeof(receipt_line)));
    TEST_ASSERT_EQUAL_STRING("", receipt_line);
    TEST_ASSERT_FALSE(payment.m_isOpen);
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_release_count);
}

void test_close_of_a_payment_that_is_not_open_does_nothing(void)
{
  X402RequestPayment_t payment;
  memset(&payment, 0, sizeof(payment));
  char receipt_line[X402_REQUEST_RECEIPT_LINE_BUF_SIZE] = "sentinel";
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_CLOSE_PENDING, static_closeToLine(&payment, receipt_line, sizeof(receipt_line)));
  TEST_ASSERT_EQUAL_STRING("", receipt_line);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_FACILITATOR_settle_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_mark_settled_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_mark_pending_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_release_count);
}

void test_release_of_a_fresh_payment_releases_it_once(void)
{
  X402RequestPayment_t payment;
  static_openFresh(&payment);
  TEST_ASSERT_EQUAL_INT(6, g_stub_THROTTLE_call_count);
  g_releaseCallCountAtRelease   = -1;
  g_stub_X402_LEDGER_on_release = static_recordReleaseCallCount;
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &payment, X402_REQUEST_UNSERVED_FAILED_RUN);
  TEST_ASSERT_FALSE(payment.m_isOpen);
  TEST_ASSERT_EQUAL_INT(9, g_releaseCallCountAtRelease);
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &payment, X402_REQUEST_UNSERVED_FAILED_RUN);
  TEST_ASSERT_EQUAL_INT(9, g_stub_THROTTLE_call_count);
  static_assertThrottleCall(6, true, "x402_unserved_release", 60, 3, FIXTURE_MESSAGE_HASH);
  static_assertThrottleCall(7, true, "x402_failed_attempt", 60, 10, FIXTURE_IP_HASH);
  static_assertThrottleCall(8, true, "x402_unserved_source", 3600, 5, FIXTURE_SOURCE_HASH);
  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_LEDGER_release_count);
  TEST_ASSERT_EQUAL_STRING(FIXTURE_MESSAGE_HASH, g_stub_X402_LEDGER_last_release_hashes.ma_messageHash);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_FACILITATOR_settle_count);
  static_assertBothPlacesFree();
}

void test_release_of_a_confirmed_payment_keeps_it_pending(void)
{
  X402RequestPayment_t payment;
  static_openConfirmed(&payment);
  int charge_count = g_stub_THROTTLE_charge_count;
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &payment, X402_REQUEST_UNSERVED_FAILED_RUN);
  TEST_ASSERT_EQUAL_INT(charge_count, g_stub_THROTTLE_charge_count);
  TEST_ASSERT_FALSE(payment.m_isOpen);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_release_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_mark_settled_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_mark_pending_count);
}

void test_open_payment_at_its_unserved_release_limit_is_limited(void)
{
  g_stub_THROTTLE_loads[0] = (ThrottleStubLoad_t){ "x402_unserved_release", 3, false };
  g_stub_THROTTLE_read_retry_after_seconds = 50;
  X402RequestPayment_t payment;
  X402RequestOpenResult_t result = static_open(1, &payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_LIMITED, result.m_status);
  TEST_ASSERT_EQUAL_UINT(50, result.m_retryAfterSec);
  TEST_ASSERT_FALSE(payment.m_isOpen);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_reserve_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_FACILITATOR_verify_count);
  static_assertBothPlacesFree();

  g_stub_THROTTLE_loads[0].m_loadCount = 2;
  result = static_open(1, &payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_OK, result.m_status);
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &payment, X402_REQUEST_UNSERVED_FAILED_RUN);
}

void test_check_before_weigh_when_off_is_error_with_no_call(void)
{
  x402_request_start(NULL);
  X402RequestOpenResult_t result = x402_request_dbCheckBeforeWeigh(FIXTURE_CONN, &HEADER_SOURCE, FIXTURE_IP_HASH);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_ERROR, result.m_status);
  TEST_ASSERT_EQUAL_UINT(0, result.m_retryAfterSec);
  TEST_ASSERT_EQUAL_INT(0, g_parseCount);
  TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_call_count);
}

void test_check_before_weigh_reads_parses_and_counts_the_weigh(void)
{
  X402RequestOpenResult_t result = x402_request_dbCheckBeforeWeigh(FIXTURE_CONN, &HEADER_SOURCE, FIXTURE_IP_HASH);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_OK, result.m_status);
  g_parseStatus = X402_PAYMENT_NOT_ACCEPTED;
  result = x402_request_dbCheckBeforeWeigh(FIXTURE_CONN, &HEADER_SOURCE, FIXTURE_IP_HASH);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_OK, result.m_status);

  TEST_ASSERT_EQUAL_INT(2, g_parseCount);
  TEST_ASSERT_EQUAL_size_t(strlen(FIXTURE_HEADER), g_parseLastValueLen);
  TEST_ASSERT_EQUAL_UINT64(0, g_parseLastRequirements.m_amountAtomic);
  TEST_ASSERT_EQUAL_INT(6, g_stub_THROTTLE_call_count);
  for (int i = 0; i < 6; i += 3)
  {
    static_assertThrottleCall(i,     false, "x402_failed_attempt",  60, 10, FIXTURE_IP_HASH);
    static_assertThrottleCall(i + 1, false, "x402_refused_attempt", 60, 30, FIXTURE_IP_HASH);
    static_assertThrottleCall(i + 2, true,  "x402_weigh",           60, 30, FIXTURE_IP_HASH);
  }
  TEST_ASSERT_EQUAL_INT(0, g_checkCount);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_make_hashes_count);
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_reserve_count);
}

void test_check_before_weigh_of_a_client_at_its_failure_limit_is_limited(void)
{
  static const ThrottleStubLoad_t limits[] = {
    { "x402_failed_attempt", 10, false }, { "x402_refused_attempt", 30, false }
  };
  g_stub_THROTTLE_read_retry_after_seconds = 42;
  for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); i++)
  {
    g_stub_THROTTLE_loads[0] = limits[i];
    X402RequestOpenResult_t result = x402_request_dbCheckBeforeWeigh(FIXTURE_CONN, &HEADER_SOURCE, FIXTURE_IP_HASH);
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_REQUEST_OPEN_LIMITED, result.m_status, limits[i].mp_ruleName);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(42, result.m_retryAfterSec, limits[i].mp_ruleName);
  }
  TEST_ASSERT_EQUAL_INT(0, g_parseCount);
  TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_charge_count);
}

void test_check_before_weigh_of_a_malformed_header_counts_a_failed_attempt(void)
{
  g_parseStatus = X402_PAYMENT_MALFORMED;
  X402RequestOpenResult_t result = x402_request_dbCheckBeforeWeigh(FIXTURE_CONN, &HEADER_SOURCE, FIXTURE_IP_HASH);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_MALFORMED, result.m_status);
  TEST_ASSERT_EQUAL_UINT(0, result.m_retryAfterSec);
  TEST_ASSERT_EQUAL_INT(3, g_stub_THROTTLE_call_count);
  static_assertThrottleCall(2, true, "x402_failed_attempt", 60, 10, FIXTURE_IP_HASH);
  TEST_ASSERT_EQUAL_INT(1, g_stub_THROTTLE_charge_count);
}

void test_throttle_weigh_maps_each_throttle_answer(void)
{
  g_stub_THROTTLE_retry_after_seconds = 17;
  X402RequestOpenResult_t result = x402_request_dbThrottleWeigh(FIXTURE_CONN, FIXTURE_IP_HASH);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_OK, result.m_status);
  TEST_ASSERT_EQUAL_UINT(0, result.m_retryAfterSec);
  g_stub_THROTTLE_charge_status = THROTTLE_REFUSED;
  result = x402_request_dbThrottleWeigh(FIXTURE_CONN, FIXTURE_IP_HASH);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_LIMITED, result.m_status);
  TEST_ASSERT_EQUAL_UINT(17, result.m_retryAfterSec);
  g_stub_THROTTLE_charge_status = THROTTLE_ERROR;
  result = x402_request_dbThrottleWeigh(FIXTURE_CONN, FIXTURE_IP_HASH);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_ERROR, result.m_status);
  TEST_ASSERT_EQUAL_UINT(0, result.m_retryAfterSec);
  TEST_ASSERT_EQUAL_INT(3, g_stub_THROTTLE_call_count);
  for (int i = 0; i < 3; i++)
    static_assertThrottleCall(i, true, "x402_weigh", 60, 30, FIXTURE_IP_HASH);
}

void test_release_of_a_refused_request_counts_the_refusal_rules(void)
{
  X402RequestPayment_t payment;
  static_openFresh(&payment);
  g_releaseCallCountAtRelease   = -1;
  g_stub_X402_LEDGER_on_release = static_recordReleaseCallCount;
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &payment, X402_REQUEST_UNSERVED_REFUSED_REQUEST);
  TEST_ASSERT_EQUAL_INT(9, g_stub_THROTTLE_call_count);
  TEST_ASSERT_EQUAL_INT(9, g_releaseCallCountAtRelease);
  static_assertThrottleCall(6, true, "x402_unserved_release", 60,   3,  FIXTURE_MESSAGE_HASH);
  static_assertThrottleCall(7, true, "x402_refused_attempt",  60,   30, FIXTURE_IP_HASH);
  static_assertThrottleCall(8, true, "x402_refused_source",   3600, 30, FIXTURE_SOURCE_HASH);
  TEST_ASSERT_EQUAL_INT(3, g_stub_THROTTLE_charge_count);
  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_LEDGER_release_count);
  static_assertBothPlacesFree();
}

void test_open_over_an_unserved_or_refused_limit_answers_before_the_settle_place(void)
{
  X402RequestPayment_t first;
  X402RequestPayment_t second;
  X402RequestPayment_t third;
  static_openFresh(&first);
  static_openFresh(&second);
  int reserve_count = g_stub_X402_LEDGER_reserve_count;
  static const char* const rule_names[] = { "x402_refused_attempt", "x402_unserved_release", "x402_unserved_source", "x402_refused_source" };
  static const unsigned int loads[]     = { 30, 3, 5, 30 };
  for (size_t i = 0; i < sizeof(loads) / sizeof(loads[0]); i++)
  {
    g_stub_THROTTLE_loads[0] = (ThrottleStubLoad_t){ rule_names[i], loads[i], false };
    g_stub_THROTTLE_read_retry_after_seconds = 50;
    X402RequestOpenResult_t result = static_open(1, &third);
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_REQUEST_OPEN_LIMITED, result.m_status, rule_names[i]);
    TEST_ASSERT_EQUAL_UINT_MESSAGE(50, result.m_retryAfterSec, rule_names[i]);
    TEST_ASSERT_FALSE(third.m_isOpen);
  }
  TEST_ASSERT_EQUAL_INT(reserve_count, g_stub_X402_LEDGER_reserve_count);

  g_stub_THROTTLE_loads[0].m_loadCount = 4;
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &first, X402_REQUEST_UNSERVED_FAILED_RUN);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_OK, static_open(1, &third).m_status);
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &second, X402_REQUEST_UNSERVED_FAILED_RUN);
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &third, X402_REQUEST_UNSERVED_FAILED_RUN);
}

void test_open_with_a_failed_unserved_or_refused_read_is_error(void)
{
  static const char* const rule_names[] = { "x402_refused_attempt", "x402_unserved_release", "x402_unserved_source", "x402_refused_source" };
  for (size_t i = 0; i < sizeof(rule_names) / sizeof(rule_names[0]); i++)
  {
    g_stub_THROTTLE_loads[0] = (ThrottleStubLoad_t){ rule_names[i], 0, true };
    X402RequestPayment_t payment;
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_REQUEST_OPEN_ERROR, static_open(1, &payment).m_status, rule_names[i]);
    TEST_ASSERT_FALSE(payment.m_isOpen);
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_X402_LEDGER_reserve_count);
  static_assertBothPlacesFree();
}

void test_check_before_weigh_with_a_failed_read_is_error(void)
{
  static const char* const rule_names[] = { "x402_failed_attempt", "x402_refused_attempt" };
  for (size_t i = 0; i < sizeof(rule_names) / sizeof(rule_names[0]); i++)
  {
    g_stub_THROTTLE_loads[0] = (ThrottleStubLoad_t){ rule_names[i], 0, true };
    X402RequestOpenResult_t result = x402_request_dbCheckBeforeWeigh(FIXTURE_CONN, &HEADER_SOURCE, FIXTURE_IP_HASH);
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_REQUEST_OPEN_ERROR, result.m_status, rule_names[i]);
  }
  TEST_ASSERT_EQUAL_INT(0, g_parseCount);
  TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_charge_count);
}

void test_open_each_check_refusal_counts_one_failed_attempt(void)
{
  static const X402SolanaStatus_t refusals[] = {
    X402_SOLANA_MALFORMED, X402_SOLANA_SIGNERS_REFUSED, X402_SOLANA_COMPUTE_REFUSED, X402_SOLANA_TRANSFER_REFUSED,
    X402_SOLANA_INSTRUCTION_REFUSED, X402_SOLANA_FEE_PAYER_IN_USE, X402_SOLANA_SIGNATURE_INVALID
  };
  for (size_t i = 0; i < sizeof(refusals) / sizeof(refusals[0]); i++)
  {
    X402RequestPayment_t payment;
    g_checkStatus              = refusals[i];
    g_stub_THROTTLE_call_count = 0;
    (void)static_open(1, &payment);
    TEST_ASSERT_EQUAL_INT(3, g_stub_THROTTLE_call_count);
    static_assertThrottleCall(0, false, "x402_failed_attempt",  60, 10, FIXTURE_IP_HASH);
    static_assertThrottleCall(1, false, "x402_refused_attempt", 60, 30, FIXTURE_IP_HASH);
    static_assertThrottleCall(2, true,  "x402_failed_attempt",  60, 10, FIXTURE_IP_HASH);
  }
}

void test_unserved_kind_of_each_run_status(void)
{
  static const struct { EndpointRunStatus_t m_status; X402RequestUnservedKind_t m_kind; } cases[] = {
    { ENDPOINT_RUN_NOT_FOUND,          X402_REQUEST_UNSERVED_REFUSED_REQUEST },
    { ENDPOINT_RUN_REFUSED,            X402_REQUEST_UNSERVED_REFUSED_REQUEST },
    { ENDPOINT_RUN_REFUSED_WITH_BODY,  X402_REQUEST_UNSERVED_REFUSED_REQUEST },
    { ENDPOINT_RUN_UNAUTHORIZED,       X402_REQUEST_UNSERVED_REFUSED_REQUEST },
    { ENDPOINT_RUN_GONE,               X402_REQUEST_UNSERVED_REFUSED_REQUEST },
    { ENDPOINT_RUN_OK,                 X402_REQUEST_UNSERVED_FAILED_RUN },
    { ENDPOINT_RUN_DEGRADED,           X402_REQUEST_UNSERVED_FAILED_RUN },
    { ENDPOINT_RUN_DB_ERROR,           X402_REQUEST_UNSERVED_FAILED_RUN },
    { ENDPOINT_RUN_UPSTREAM_ERROR,     X402_REQUEST_UNSERVED_FAILED_RUN },
    { ENDPOINT_RUN_TARGET_UNREACHABLE, X402_REQUEST_UNSERVED_FAILED_RUN },
    { ENDPOINT_RUN_NO_MEMORY,          X402_REQUEST_UNSERVED_FAILED_RUN },
    { ENDPOINT_RUN_NO_CONNECTION,      X402_REQUEST_UNSERVED_FAILED_RUN },
    { ENDPOINT_RUN_NO_CREDIT_BUDGET,   X402_REQUEST_UNSERVED_FAILED_RUN },
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(cases[i].m_kind, x402_request_findUnservedKind(cases[i].m_status), "case index");
}

static char* static_readRepoFile(const char* path)
{
  FILE* file = fopen(path, "rb");
  TEST_ASSERT_NOT_NULL_MESSAGE(file, path);
  TEST_ASSERT_EQUAL_INT(0, fseek(file, 0, SEEK_END));
  long size = ftell(file);
  TEST_ASSERT_TRUE(size > 0);
  rewind(file);
  char* text = (char*)malloc((size_t)size + 1);
  TEST_ASSERT_NOT_NULL(text);
  TEST_ASSERT_EQUAL_size_t((size_t)size, fread(text, 1, (size_t)size, file));
  fclose(file);
  text[size] = '\0';
  return text;
}

static void static_assertRuleDocs(const char* api, const char* sentence)
{
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(api, sentence), sentence);
}


void test_docs_x402_limits_match_the_rules(void)
{
  ThrottleStubCall_t calls[8];
  X402RequestPayment_t payment;
  static_openFresh(&payment);
  TEST_ASSERT_EQUAL_INT(6, g_stub_THROTTLE_call_count);
  memcpy(calls, g_stub_THROTTLE_calls, 6 * sizeof(calls[0]));
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &payment, X402_REQUEST_UNSERVED_FAILED_RUN);
  g_stub_THROTTLE_call_count = 0;
  static_openConfirmed(&payment);
  calls[6] = g_stub_THROTTLE_calls[6];
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &payment, X402_REQUEST_UNSERVED_FAILED_RUN);
  g_stub_THROTTLE_call_count = 0;
  (void)x402_request_dbThrottleWeigh(FIXTURE_CONN, FIXTURE_IP_HASH);
  calls[7] = g_stub_THROTTLE_calls[0];

  static const char* const names[8] = { "x402_failed_attempt", "x402_refused_attempt", "x402_failed_settle", "x402_unserved_release", "x402_unserved_source", "x402_refused_source", "x402_status_ask", "x402_weigh" };
  char* api  = static_readRepoFile("docs/API_Documentation.md");
  for (int i = 0; i < 8; i++)
  {
    TEST_ASSERT_EQUAL_STRING(names[i], calls[i].ma_ruleName);
    unsigned int limit  = calls[i].m_chargeLimit;
    unsigned int window = calls[i].m_windowSeconds;
    char         sentence[160];
    switch (i)
    {
      case 0:  snprintf(sentence, sizeof(sentence), "A client address may fail %u payment attempts in %u seconds.", limit, window); break;
      case 1:  snprintf(sentence, sizeof(sentence), "A client address may have %u paid runs that answered `400`, `401`, `404` or `410` in %u seconds.", limit, window); break;
      case 2:  snprintf(sentence, sizeof(sentence), "A paying token account may have %u refused settles in %u seconds.", limit, window); break;
      case 3:  snprintf(sentence, sizeof(sentence), "A payment may be released %u times in %u seconds after a run", limit, window); break;
      case 4:  snprintf(sentence, sizeof(sentence), "A paying token account may have %u runs that answered `5xx` in %u seconds.", limit, window); break;
      case 5:  snprintf(sentence, sizeof(sentence), "A paying token account may have %u runs that answered `400`, `401`, `404` or `410` in %u seconds.", limit, window); break;
      case 6:  snprintf(sentence, sizeof(sentence), "A payment may be asked about %u times in %u seconds.", limit, window); break;
      default: snprintf(sentence, sizeof(sentence), "weighed %u times in %u seconds without a budget behind it.", limit, window); break;
    }
    static_assertRuleDocs(api, sentence);
  }
  free(api);
}

void test_payment_required_line_for_a_short_path(void)
{
  Endpoint_t endpoint = { .mp_httpPath = "/cve_lookup/" };
  char line[X402_REQUEST_PAYMENT_REQUIRED_LINE_BUF_SIZE];
  TEST_ASSERT_TRUE(x402_request_tryWritePaymentRequired(&endpoint, 2, "payment required", line, sizeof(line)));

  char json[1024];
  static_decodeLine(line, "PAYMENT-REQUIRED", json, sizeof(json));
  TEST_ASSERT_EQUAL_STRING(
    "{\"x402Version\":2,\"error\":\"payment required\","
    "\"resource\":{\"url\":\"https://api.contrastcyber.com/cve_lookup/\",\"description\":\"ContrastAPI request\",\"mimeType\":\"application/json\"},"
    "\"accepts\":[{\"scheme\":\"exact\",\"network\":\"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1\",\"amount\":\"20000\","
    "\"asset\":\"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v\",\"payTo\":\"9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin\","
    "\"maxTimeoutSeconds\":60,\"extra\":{\"feePayer\":\"2wmVCSfPxGPjrnMMn7rchp4uaeoTqN39mXFC2zhPdri9\"}}]}",
    json);
}

void test_payment_required_line_for_a_64_byte_path(void)
{
  Endpoint_t endpoint = { .mp_httpPath = "/a_path_of_sixty_four_bytes_that_is_longer_than_any_row_of_endpo" };
  TEST_ASSERT_EQUAL_size_t(64, strlen(endpoint.mp_httpPath));
  char line[X402_REQUEST_PAYMENT_REQUIRED_LINE_BUF_SIZE];
  TEST_ASSERT_TRUE(x402_request_tryWritePaymentRequired(&endpoint, 500, "payment required", line, sizeof(line)));

  char json[1024];
  static_decodeLine(line, "PAYMENT-REQUIRED", json, sizeof(json));
  TEST_ASSERT_EQUAL_STRING(
    "{\"x402Version\":2,\"error\":\"payment required\","
    "\"resource\":{\"url\":\"https://api.contrastcyber.com/a_path_of_sixty_four_bytes_that_is_longer_than_any_row_of_endpo\",\"description\":\"ContrastAPI request\",\"mimeType\":\"application/json\"},"
    "\"accepts\":[{\"scheme\":\"exact\",\"network\":\"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1\",\"amount\":\"5000000\","
    "\"asset\":\"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v\",\"payTo\":\"9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin\","
    "\"maxTimeoutSeconds\":60,\"extra\":{\"feePayer\":\"2wmVCSfPxGPjrnMMn7rchp4uaeoTqN39mXFC2zhPdri9\"}}]}",
    json);
}

_Static_assert(1152 + 536 <= 2048, "the PAYMENT-REQUIRED line and the other 536 bytes of a 402 head must fit 2048 bytes");

void test_payment_required_longest_line_fits_its_buffer(void)
{
  ConfigX402_t config;
  static_fixtureConfig(&config);
  memset(config.ma_network, '"', 63);
  config.ma_network[63] = '\0';
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_START_ON, x402_request_start(&config));

  Endpoint_t endpoint = { .mp_httpPath = "/a_path_of_sixty_four_bytes_that_is_longer_than_any_row_of_endpo" };
  char error_text[129];
  memset(error_text, 'e', 128);
  error_text[128] = '\0';
  char line[X402_REQUEST_PAYMENT_REQUIRED_LINE_BUF_SIZE];
  TEST_ASSERT_TRUE(x402_request_tryWritePaymentRequired(&endpoint, UINT_MAX, error_text, line, sizeof(line)));
  TEST_ASSERT_EQUAL_size_t(1000, strlen(line));
  TEST_ASSERT_EQUAL_size_t(1152, sizeof(line));
}

void test_payment_required_line_is_refused_when_off_short_or_free(void)
{
  Endpoint_t endpoint = { .mp_httpPath = "/cve_lookup/" };
  char line[X402_REQUEST_PAYMENT_REQUIRED_LINE_BUF_SIZE] = "sentinel";
  char short_line[100] = "sentinel";

  TEST_ASSERT_FALSE(x402_request_tryWritePaymentRequired(&endpoint, 1, "e", short_line, sizeof(short_line)));
  TEST_ASSERT_EQUAL_STRING("", short_line);

  TEST_ASSERT_FALSE(x402_request_tryWritePaymentRequired(&endpoint, 0, "e", line, sizeof(line)));
  TEST_ASSERT_EQUAL_STRING("", line);

  x402_request_start(NULL);
  snprintf(line, sizeof(line), "sentinel");
  TEST_ASSERT_FALSE(x402_request_tryWritePaymentRequired(&endpoint, 1, "e", line, sizeof(line)));
  TEST_ASSERT_EQUAL_STRING("", line);
}

void test_receipt_longest_line_fits_its_buffer(void)
{
  ConfigX402_t config;
  static_fixtureConfig(&config);
  memset(config.ma_network, '"', 63);
  config.ma_network[63] = '\0';
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_START_ON, x402_request_start(&config));

  X402RequestPayment_t payment;
  static_openFresh(&payment);
  char receipt_line[X402_REQUEST_RECEIPT_LINE_BUF_SIZE];
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_CLOSE_SERVE, static_closeToLine(&payment, receipt_line, sizeof(receipt_line)));
  TEST_ASSERT_EQUAL_size_t(368, strlen(receipt_line));
  TEST_ASSERT_EQUAL_size_t(384, sizeof(receipt_line));
}

void test_receipt_that_does_not_fit_still_serves(void)
{
  X402RequestPayment_t payment;
  static_openFresh(&payment);
  X402RequestReceipt_t receipt;
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_CLOSE_SERVE, x402_request_dbCloseAfterRun(FIXTURE_CONN, &payment, &receipt));
  TEST_ASSERT_EQUAL_INT(1, g_stub_X402_LEDGER_mark_settled_count);
  char receipt_line[16] = "sentinel";
  TEST_ASSERT_FALSE(x402_request_tryWriteReceiptLine(&receipt, receipt_line, sizeof(receipt_line)));
  TEST_ASSERT_EQUAL_STRING("", receipt_line);
}

void test_payment_header_name_is_payment_signature(void)
{
  TEST_ASSERT_EQUAL_STRING("PAYMENT-SIGNATURE", X402_REQUEST_PAYMENT_HEADER_NAME);
}

void test_open_with_an_ip_hash_of_another_length_is_error_with_no_call(void)
{
  X402RequestPayment_t payment;
  X402RequestOpenResult_t result = x402_request_dbOpenPayment(FIXTURE_CONN, &HEADER_SOURCE, 1, FIXTURE_IP_SECRET,
                                                              "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", &payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_ERROR, result.m_status);
  TEST_ASSERT_EQUAL_UINT(0, result.m_retryAfterSec);
  TEST_ASSERT_EQUAL_INT(0, g_parseCount);
  TEST_ASSERT_EQUAL_INT(0, g_stub_THROTTLE_call_count);
  TEST_ASSERT_FALSE(payment.m_isOpen);
}

void test_payment_required_line_fits_a_buffer_of_its_exact_size(void)
{
  Endpoint_t endpoint = { .mp_httpPath = "/cve_lookup/" };
  char line[X402_REQUEST_PAYMENT_REQUIRED_LINE_BUF_SIZE];
  TEST_ASSERT_TRUE(x402_request_tryWritePaymentRequired(&endpoint, 2, "payment required", line, sizeof(line)));
  size_t line_len = strlen(line);

  char exact_line[X402_REQUEST_PAYMENT_REQUIRED_LINE_BUF_SIZE];
  TEST_ASSERT_TRUE(x402_request_tryWritePaymentRequired(&endpoint, 2, "payment required", exact_line, line_len + 1));
  TEST_ASSERT_EQUAL_STRING(line, exact_line);

  TEST_ASSERT_FALSE(x402_request_tryWritePaymentRequired(&endpoint, 2, "payment required", exact_line, line_len));
  TEST_ASSERT_EQUAL_STRING("", exact_line);
}

void test_close_of_a_pending_settle_whose_mark_fails_names_it_on_stderr(void)
{
  static const struct { X402LedgerMarkStatus_t m_markStatus; const char* mp_stderrText; } cases[] = {
    { X402_LEDGER_MARKED,     "" },
    { X402_LEDGER_NOT_MARKED, "x402_request_dbCloseAfterRun: a pending settle was not marked pending (NOT_MARKED); the row stays reserved\n" },
    { X402_LEDGER_MARK_ERROR, "x402_request_dbCloseAfterRun: a pending settle was not marked pending (MARK_ERROR); the row stays reserved\n" },
  };
  g_stub_X402_FACILITATOR_settlement.m_status = X402_FACILITATOR_SETTLE_PENDING;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
  {
    g_stub_X402_LEDGER_mark_pending_status = cases[i].m_markStatus;
    X402RequestPayment_t payment;
    static_openFresh(&payment);
    char receipt_line[X402_REQUEST_RECEIPT_LINE_BUF_SIZE];
    char stderr_text[512];
    static_beginStderrCapture();
    X402RequestCloseStatus_t close_status = static_closeToLine(&payment, receipt_line, sizeof(receipt_line));
    static_endStderrCapture(stderr_text, sizeof(stderr_text));
    TEST_ASSERT_EQUAL_INT(X402_REQUEST_CLOSE_PENDING, close_status);
    TEST_ASSERT_EQUAL_STRING(cases[i].mp_stderrText, stderr_text);
  }
}

void test_receipt_line_that_does_not_fit_leaves_the_stderr_line_to_the_caller(void)
{
  X402RequestPayment_t payment;
  static_openFresh(&payment);
  X402RequestReceipt_t receipt;
  char stderr_text[512];
  static_beginStderrCapture();
  X402RequestCloseStatus_t close_status = x402_request_dbCloseAfterRun(FIXTURE_CONN, &payment, &receipt);
  static_endStderrCapture(stderr_text, sizeof(stderr_text));
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_CLOSE_SERVE, close_status);
  TEST_ASSERT_EQUAL_STRING("", stderr_text);

  char receipt_line[X402_REQUEST_RECEIPT_LINE_BUF_SIZE];
  TEST_ASSERT_TRUE(x402_request_tryWriteReceiptLine(&receipt, receipt_line, sizeof(receipt_line)));
  TEST_ASSERT_EQUAL_INT(0, strncmp(receipt_line, "PAYMENT-RESPONSE: ", 18));

  char short_line[16] = "sentinel";
  static_beginStderrCapture();
  bool is_written = x402_request_tryWriteReceiptLine(&receipt, short_line, sizeof(short_line));
  static_endStderrCapture(stderr_text, sizeof(stderr_text));
  TEST_ASSERT_FALSE(is_written);
  TEST_ASSERT_EQUAL_STRING("", short_line);
  TEST_ASSERT_NULL_MESSAGE(strstr(stderr_text, "did not fit"), stderr_text);
}

void test_payment_required_url_of_255_bytes_fits_and_256_does_not(void)
{
  size_t base_len = strlen(PRICING_API_BASE_URL);
  char   path[256];
  memset(path, 'a', sizeof(path));
  path[0]              = '/';
  path[255 - base_len] = '\0';
  Endpoint_t endpoint  = { .mp_httpPath = path };
  char line[X402_REQUEST_PAYMENT_REQUIRED_LINE_BUF_SIZE];
  TEST_ASSERT_TRUE(x402_request_tryWritePaymentRequired(&endpoint, 1, "e", line, sizeof(line)));
  char json[1024];
  static_decodeLine(line, "PAYMENT-REQUIRED", json, sizeof(json));
  char url_member[300];
  snprintf(url_member, sizeof(url_member), "\"url\":\"%s%s\"", PRICING_API_BASE_URL, path);
  TEST_ASSERT_EQUAL_size_t(255 + strlen("\"url\":\"\""), strlen(url_member));
  TEST_ASSERT_NOT_NULL_MESSAGE(strstr(json, url_member), json);

  path[255 - base_len]     = 'a';
  path[255 - base_len + 1] = '\0';
  snprintf(line, sizeof(line), "sentinel");
  TEST_ASSERT_FALSE(x402_request_tryWritePaymentRequired(&endpoint, 1, "e", line, sizeof(line)));
  TEST_ASSERT_EQUAL_STRING("", line);
}

void test_dbOpenPayment_reads_a_json_source(void)
{
  X402RequestPayment_t payment;
  X402RequestOpenResult_t result = x402_request_dbOpenPayment(FIXTURE_CONN, &JSON_SOURCE, 1, FIXTURE_IP_SECRET, FIXTURE_IP_HASH, &payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_OK, result.m_status);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_PAYMENT_FRESH, payment.m_kind);
  TEST_ASSERT_TRUE(payment.m_isOpen);
  TEST_ASSERT_EQUAL_INT(1, g_parseJsonCount);
  TEST_ASSERT_EQUAL_INT(0, g_parseHeaderCount);
  TEST_ASSERT_EQUAL_size_t(JSON_SOURCE.m_len, g_parseLastValueLen);
  TEST_ASSERT_EQUAL_UINT64(10000, g_parseLastRequirements.m_amountAtomic);
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &payment, X402_REQUEST_UNSERVED_FAILED_RUN);
}

void test_payment_source_kind_picks_its_parser(void)
{
  X402RequestPayment_t payment;
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_OK, x402_request_dbOpenPayment(FIXTURE_CONN, &HEADER_SOURCE, 1, FIXTURE_IP_SECRET, FIXTURE_IP_HASH, &payment).m_status);
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &payment, X402_REQUEST_UNSERVED_FAILED_RUN);
  TEST_ASSERT_EQUAL_INT(1, g_parseHeaderCount);
  TEST_ASSERT_EQUAL_INT(0, g_parseJsonCount);

  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_OK, x402_request_dbOpenPayment(FIXTURE_CONN, &JSON_SOURCE, 1, FIXTURE_IP_SECRET, FIXTURE_IP_HASH, &payment).m_status);
  x402_request_dbReleaseUnserved(FIXTURE_CONN, &payment, X402_REQUEST_UNSERVED_FAILED_RUN);
  TEST_ASSERT_EQUAL_INT(1, g_parseHeaderCount);
  TEST_ASSERT_EQUAL_INT(1, g_parseJsonCount);

  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_OK, x402_request_dbCheckBeforeWeigh(FIXTURE_CONN, &HEADER_SOURCE, FIXTURE_IP_HASH).m_status);
  TEST_ASSERT_EQUAL_INT(2, g_parseHeaderCount);
  TEST_ASSERT_EQUAL_INT(1, g_parseJsonCount);

  TEST_ASSERT_EQUAL_INT(X402_REQUEST_OPEN_OK, x402_request_dbCheckBeforeWeigh(FIXTURE_CONN, &JSON_SOURCE, FIXTURE_IP_HASH).m_status);
  TEST_ASSERT_EQUAL_INT(2, g_parseHeaderCount);
  TEST_ASSERT_EQUAL_INT(2, g_parseJsonCount);
  TEST_ASSERT_EQUAL_size_t(JSON_SOURCE.m_len, g_parseLastValueLen);
}

void test_dbCloseAfterRun_fills_the_receipt_on_serve(void)
{
  X402RequestPayment_t payment;
  X402RequestReceipt_t receipt;
  static_openFresh(&payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_CLOSE_SERVE, x402_request_dbCloseAfterRun(FIXTURE_CONN, &payment, &receipt));
  TEST_ASSERT_EQUAL_STRING(FIXTURE_NETWORK, receipt.ma_network);
  TEST_ASSERT_EQUAL_STRING(FIXTURE_SIGNATURE, receipt.ma_signature);

  static_openConfirmed(&payment);
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_CLOSE_SERVE, x402_request_dbCloseAfterRun(FIXTURE_CONN, &payment, &receipt));
  TEST_ASSERT_EQUAL_STRING(FIXTURE_NETWORK, receipt.ma_network);
  TEST_ASSERT_EQUAL_STRING(FIXTURE_PENDING_SIG, receipt.ma_signature);

  g_stub_X402_LEDGER_reservation.m_status     = X402_LEDGER_RESERVED;
  g_stub_X402_FACILITATOR_settlement.m_status = X402_FACILITATOR_SETTLE_REFUSED;
  static_openFresh(&payment);
  snprintf(receipt.ma_network, sizeof(receipt.ma_network), "%s", "sentinel");
  snprintf(receipt.ma_signature, sizeof(receipt.ma_signature), "%s", "sentinel");
  TEST_ASSERT_EQUAL_INT(X402_REQUEST_CLOSE_REFUSED, x402_request_dbCloseAfterRun(FIXTURE_CONN, &payment, &receipt));
  TEST_ASSERT_EQUAL_STRING("", receipt.ma_network);
  TEST_ASSERT_EQUAL_STRING("", receipt.ma_signature);
}

void test_tryWriteReceiptLine_writes_the_payment_response_line(void)
{
  X402RequestReceipt_t receipt = { .ma_network = FIXTURE_NETWORK, .ma_signature = FIXTURE_SIGNATURE };
  char receipt_line[X402_REQUEST_RECEIPT_LINE_BUF_SIZE];
  TEST_ASSERT_TRUE(x402_request_tryWriteReceiptLine(&receipt, receipt_line, sizeof(receipt_line)));
  char json[512];
  static_decodeLine(receipt_line, "PAYMENT-RESPONSE", json, sizeof(json));
  TEST_ASSERT_EQUAL_STRING("{\"success\":true,\"transaction\":\"5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW\","
                           "\"network\":\"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1\"}", json);

  char short_line[16] = "sentinel";
  TEST_ASSERT_FALSE(x402_request_tryWriteReceiptLine(&receipt, short_line, sizeof(short_line)));
  TEST_ASSERT_EQUAL_STRING("", short_line);
}

static void static_takeJson(JsonBuf_t* json_buf, char* out, size_t out_size)
{
  char* text = jsonbuf_finish(json_buf);
  jsonbuf_destroy(json_buf);
  snprintf(out, out_size, "%s", text != NULL ? text : "");
  free(text);
}

void test_appendReceipt_writes_the_settlement_response(void)
{
  X402RequestReceipt_t receipt = { .ma_network = FIXTURE_NETWORK, .ma_signature = FIXTURE_SIGNATURE };
  JsonBuf_t* appended = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  JsonBuf_t* written  = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(appended);
  TEST_ASSERT_NOT_NULL(written);
  TEST_ASSERT_TRUE(x402_request_appendReceipt(appended, &receipt));
  TEST_ASSERT_TRUE(x402_writeSettlementResponse(written, FIXTURE_NETWORK, FIXTURE_SIGNATURE));
  char appended_text[512];
  char written_text[512];
  static_takeJson(appended, appended_text, sizeof(appended_text));
  static_takeJson(written, written_text, sizeof(written_text));
  TEST_ASSERT_TRUE(appended_text[0] != '\0');
  TEST_ASSERT_EQUAL_STRING(written_text, appended_text);
}

static void static_assertStringMember(JsonReadSpan_t object_span, const char* key, const char* expected)
{
  JsonReadSpan_t value_span;
  TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_OK, jsonread_objectKey(object_span, key, &value_span), key);
  char text[256];
  TEST_ASSERT_EQUAL_INT_MESSAGE(JSONREAD_OK, jsonread_spanToStrStatus(value_span, text, sizeof(text)), key);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, text, key);
}

void test_appendPaymentRequired_writes_the_object_for_a_resource(void)
{
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  TEST_ASSERT_TRUE(x402_request_appendPaymentRequired(json_buf, "mcp://tool/cve_lookup", 1, "payment required"));
  char json[1024];
  static_takeJson(json_buf, json, sizeof(json));

  JsonReadSpan_t root_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_root(json, strlen(json), &root_span));
  static_assertStringMember(root_span, "error", "payment required");

  JsonReadSpan_t resource_span;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "resource", &resource_span));
  static_assertStringMember(resource_span, "url", "mcp://tool/cve_lookup");
  static_assertStringMember(resource_span, "description", "ContrastAPI request");

  JsonReadSpan_t accepts_span;
  JsonReadSpan_t first_span;
  size_t         element_offset = 0;
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_objectKey(root_span, "accepts", &accepts_span));
  TEST_ASSERT_EQUAL_INT(JSONREAD_OK, jsonread_arrayNextElement(accepts_span, &element_offset, &first_span));
  static_assertStringMember(first_span, "amount", "10000");
}

void test_appendPaymentRequired_is_false_for_zero_credits(void)
{
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  TEST_ASSERT_FALSE(x402_request_appendPaymentRequired(json_buf, "mcp://tool/cve_lookup", 0, "payment required"));
  char json[64];
  static_takeJson(json_buf, json, sizeof(json));
  TEST_ASSERT_EQUAL_STRING("", json);
}

void test_appendPaymentRequired_is_false_when_x402_is_off(void)
{
  x402_request_start(NULL);
  JsonBuf_t* json_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(json_buf);
  TEST_ASSERT_FALSE(x402_request_appendPaymentRequired(json_buf, "mcp://tool/cve_lookup", 1, "payment required"));
  char json[64];
  static_takeJson(json_buf, json, sizeof(json));
  TEST_ASSERT_EQUAL_STRING("", json);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(67, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_start_without_settings_is_off);
  RUN_TEST(test_start_with_an_address_that_does_not_decode_is_invalid);
  RUN_TEST(test_start_keeps_the_facilitator_refusal);
  RUN_TEST(test_start_on_hands_the_facilitator_the_base_requirements);
  RUN_TEST(test_start_decodes_the_solana_policy);
  RUN_TEST(test_open_when_off_is_error_with_no_call);
  RUN_TEST(test_open_for_0_credits_is_error_with_no_call);
  RUN_TEST(test_open_hands_the_price_to_parse_check_and_verify);
  RUN_TEST(test_open_header_that_parse_refuses_goes_no_further);
  RUN_TEST(test_open_transaction_that_the_check_refuses_goes_no_further);
  RUN_TEST(test_open_reads_the_six_failure_loads_and_counts_nothing);
  RUN_TEST(test_open_ip_at_its_failed_attempt_limit_is_limited);
  RUN_TEST(test_open_source_at_its_failed_settle_limit_is_limited);
  RUN_TEST(test_open_with_a_failed_read_or_hash_is_error);
  RUN_TEST(test_open_when_both_settle_places_are_taken_is_unavailable);
  RUN_TEST(test_open_reserve_answers_map_to_their_status);
  RUN_TEST(test_open_verified_payment_is_open_and_fresh);
  RUN_TEST(test_open_payment_the_facilitator_refuses_is_released_and_counted);
  RUN_TEST(test_open_with_no_verify_answer_is_released_and_unavailable);
  RUN_TEST(test_open_pending_payment_that_solana_confirmed_is_open_and_confirmed);
  RUN_TEST(test_open_pending_payment_that_failed_on_chain_is_released_and_refused);
  RUN_TEST(test_open_pending_payment_that_solana_has_not_decided_stays_pending);
  RUN_TEST(test_open_pending_payment_over_its_ask_limit_is_limited);
  RUN_TEST(test_close_of_a_paid_fresh_payment_serves_with_a_receipt);
  RUN_TEST(test_close_of_a_paid_payment_whose_mark_fails_still_serves);
  RUN_TEST(test_close_of_a_paid_settle_without_a_signature_is_pending);
  RUN_TEST(test_close_of_a_refused_settle_releases_and_counts_both);
  RUN_TEST(test_close_of_a_pending_settle_marks_it_pending_and_never_releases);
  RUN_TEST(test_close_of_a_confirmed_payment_that_is_marked_serves);
  RUN_TEST(test_close_of_a_confirmed_payment_that_is_not_marked_is_pending);
  RUN_TEST(test_close_of_a_payment_that_is_not_open_does_nothing);
  RUN_TEST(test_release_of_a_fresh_payment_releases_it_once);
  RUN_TEST(test_release_of_a_confirmed_payment_keeps_it_pending);
  RUN_TEST(test_open_payment_at_its_unserved_release_limit_is_limited);
  RUN_TEST(test_check_before_weigh_when_off_is_error_with_no_call);
  RUN_TEST(test_check_before_weigh_reads_parses_and_counts_the_weigh);
  RUN_TEST(test_check_before_weigh_of_a_client_at_its_failure_limit_is_limited);
  RUN_TEST(test_check_before_weigh_of_a_malformed_header_counts_a_failed_attempt);
  RUN_TEST(test_throttle_weigh_maps_each_throttle_answer);
  RUN_TEST(test_release_of_a_refused_request_counts_the_refusal_rules);
  RUN_TEST(test_open_over_an_unserved_or_refused_limit_answers_before_the_settle_place);
  RUN_TEST(test_open_with_a_failed_unserved_or_refused_read_is_error);
  RUN_TEST(test_check_before_weigh_with_a_failed_read_is_error);
  RUN_TEST(test_open_each_check_refusal_counts_one_failed_attempt);
  RUN_TEST(test_docs_x402_limits_match_the_rules);
  RUN_TEST(test_unserved_kind_of_each_run_status);
  RUN_TEST(test_payment_required_line_for_a_short_path);
  RUN_TEST(test_payment_required_line_for_a_64_byte_path);
  RUN_TEST(test_payment_required_longest_line_fits_its_buffer);
  RUN_TEST(test_payment_required_line_is_refused_when_off_short_or_free);
  RUN_TEST(test_receipt_longest_line_fits_its_buffer);
  RUN_TEST(test_receipt_that_does_not_fit_still_serves);
  RUN_TEST(test_payment_header_name_is_payment_signature);
  RUN_TEST(test_open_with_an_ip_hash_of_another_length_is_error_with_no_call);
  RUN_TEST(test_payment_required_line_fits_a_buffer_of_its_exact_size);
  RUN_TEST(test_close_of_a_pending_settle_whose_mark_fails_names_it_on_stderr);
  RUN_TEST(test_receipt_line_that_does_not_fit_leaves_the_stderr_line_to_the_caller);
  RUN_TEST(test_payment_required_url_of_255_bytes_fits_and_256_does_not);
  RUN_TEST(test_dbOpenPayment_reads_a_json_source);
  RUN_TEST(test_payment_source_kind_picks_its_parser);
  RUN_TEST(test_dbCloseAfterRun_fills_the_receipt_on_serve);
  RUN_TEST(test_tryWriteReceiptLine_writes_the_payment_response_line);
  RUN_TEST(test_appendReceipt_writes_the_settlement_response);
  RUN_TEST(test_appendPaymentRequired_writes_the_object_for_a_resource);
  RUN_TEST(test_appendPaymentRequired_is_false_for_zero_credits);
  RUN_TEST(test_appendPaymentRequired_is_false_when_x402_is_off);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
