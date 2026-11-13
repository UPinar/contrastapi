#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "unity/unity.h"
extern "C" {
#include "http_stub.h"
#include "x402.h"
#include "x402_facilitator.h"
#include "x402_solana.h"
}

#define FIXTURE_NETWORK     "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
#define FIXTURE_ASSET       "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
#define FIXTURE_PAY_TO      "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
#define FIXTURE_FEE_PAYER   "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"

#define FIXTURE_REQUIREMENTS_JSON \
  R"({"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","amount":"10000",)" \
  R"("asset":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","payTo":"9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",)" \
  R"("maxTimeoutSeconds":60,"extra":{"feePayer":"FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"}})"

#define PINNED_BODY \
  R"({"x402Version":2,"paymentPayload":{"x402Version":2,"accepted":)" FIXTURE_REQUIREMENTS_JSON \
  R"(,"payload":{"transaction":"AQIDBAU="}},"paymentRequirements":)" FIXTURE_REQUIREMENTS_JSON R"(})"

#define ANSWER_BUF_SIZE 1024

static const uint8_t FEE_PAYER_SEED[32] = {
  0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
  0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
};

static const uint8_t OTHER_SEED[32] = {
  0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
  0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb
};

static EVP_PKEY*          g_feePayerKey;
static EVP_PKEY*          g_otherKey;
static X402Requirements_t g_requirements;
static X402Payment_t      g_payment;
static X402Payment_t      g_pinnedPayment;
static size_t             g_messageOffset;
static char               g_signatureText[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE];
static char               g_otherSignatureText[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE];
static char               g_answer[ANSWER_BUF_SIZE];

static EVP_PKEY* static_keyFromSeed(const uint8_t seed[32])
{
  return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
}

static void static_encodeBase58(const uint8_t* bytes, size_t byte_count, char* out)
{
  static const char alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  uint8_t digits[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE * 2] = { 0 };
  size_t  digit_count = 0;
  for (size_t i = 0; i < byte_count; i++)
  {
    unsigned carry = bytes[i];
    for (size_t j = 0; j < digit_count; j++)
    {
      carry    += (unsigned)digits[j] << 8;
      digits[j] = (uint8_t)(carry % 58);
      carry    /= 58;
    }
    while (carry > 0)
    {
      digits[digit_count++] = (uint8_t)(carry % 58);
      carry /= 58;
    }
  }
  size_t text_len = 0;
  for (size_t i = 0; i < byte_count && bytes[i] == 0; i++)
    out[text_len++] = '1';
  for (size_t i = digit_count; i-- > 0;)
    out[text_len++] = alphabet[digits[i]];
  out[text_len] = '\0';
  TEST_ASSERT_TRUE(text_len < X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE);
}

static void static_signPayment(EVP_PKEY* key, char* text)
{
  uint8_t     signature[64];
  size_t      signature_len = sizeof(signature);
  EVP_MD_CTX* ctx           = EVP_MD_CTX_new();
  TEST_ASSERT_NOT_NULL(ctx);
  TEST_ASSERT_EQUAL_INT(1, EVP_DigestSignInit(ctx, NULL, NULL, NULL, key));
  TEST_ASSERT_EQUAL_INT(1, EVP_DigestSign(ctx, signature, &signature_len, g_payment.ma_transaction + g_messageOffset,
                                          g_payment.m_transactionByteCount - g_messageOffset));
  EVP_MD_CTX_free(ctx);
  static_encodeBase58(signature, sizeof(signature), text);
}

static void static_buildPayment(void)
{
  memset(&g_payment, 0, sizeof(g_payment));
  uint8_t* tx  = g_payment.ma_transaction;
  size_t   len = 0;
  tx[len++] = 1;
  len += 64;
  g_messageOffset = len;
  tx[len++] = 1;
  tx[len++] = 0;
  tx[len++] = 0;
  tx[len++] = 1;
  size_t public_key_len = 32;
  TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_get_raw_public_key(g_feePayerKey, tx + len, &public_key_len));
  len += 32;
  for (int i = 0; i < 32; i++)
    tx[len++] = (uint8_t)(0x44 + i);
  tx[len++] = 0;
  g_payment.m_transactionByteCount = len;

  static_signPayment(g_feePayerKey, g_signatureText);
  static_signPayment(g_otherKey, g_otherSignatureText);
}

void setUp(void)
{
  g_stub_answers                  = NULL;
  g_stub_answer_count             = 0;
  g_stub_http_call_count          = 0;
  g_stub_last_url[0]              = '\0';
  g_stub_last_header[0]           = '\0';
  g_stub_next_status              = 200;
  g_stub_next_body                = NULL;
  g_stub_next_body_null           = false;
  g_stub_next_error               = HTTP_ERROR_NONE;
  g_stub_last_timeout_ms          = -1;
  g_stub_last_max_body_byte_count = 0;
  g_stub_last_is_target_trusted   = false;
  g_stub_last_post_body[0]        = '\0';
  g_stub_last_post_body_byte_count = 0;
  g_stub_last_unix_socket_path[0] = '\0';
  memset(g_stub_requests, 0, sizeof(g_stub_requests));

  memset(&g_requirements, 0, sizeof(g_requirements));
  snprintf(g_requirements.ma_network,  sizeof(g_requirements.ma_network),  "%s", FIXTURE_NETWORK);
  snprintf(g_requirements.ma_asset,    sizeof(g_requirements.ma_asset),    "%s", FIXTURE_ASSET);
  snprintf(g_requirements.ma_payTo,    sizeof(g_requirements.ma_payTo),    "%s", FIXTURE_PAY_TO);
  snprintf(g_requirements.ma_feePayer, sizeof(g_requirements.ma_feePayer), "%s", FIXTURE_FEE_PAYER);
  g_requirements.m_amountAtomic      = 10000;
  g_requirements.m_maxTimeoutSeconds = 60;

  memset(&g_pinnedPayment, 0, sizeof(g_pinnedPayment));
  for (int i = 0; i < 5; i++)
    g_pinnedPayment.ma_transaction[i] = (uint8_t)(i + 1);
  g_pinnedPayment.m_transactionByteCount = 5;

  static_buildPayment();
}

void tearDown(void)
{
}

static void static_answer(int status, const char* body)
{
  g_stub_next_status = status;
  g_stub_next_body   = body;
}

static void static_expectTransport(const char* url, int timeout_ms, bool is_post)
{
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING(url, g_stub_requests[0].ma_url);
  TEST_ASSERT_EQUAL(is_post, g_stub_requests[0].m_isPost);
  TEST_ASSERT_EQUAL_STRING(X402_FACILITATOR_SOCKET_PATH, g_stub_last_unix_socket_path);
  TEST_ASSERT_EQUAL_STRING("/run/contrastapi-x402/x402.sock", g_stub_last_unix_socket_path);
  TEST_ASSERT_EQUAL_INT(timeout_ms, g_stub_requests[0].m_timeoutMs);
  TEST_ASSERT_EQUAL_size_t(16384, g_stub_requests[0].m_maxBodyByteCount);
  TEST_ASSERT_TRUE(g_stub_requests[0].m_isTargetTrusted);
  TEST_ASSERT_TRUE(g_stub_requests[0].m_isRedirectLeftToCaller);
  TEST_ASSERT_FALSE(g_stub_requests[0].m_isBodyCutAccepted);
  TEST_ASSERT_FALSE(g_stub_requests[0].m_isHttpsOnly);
  TEST_ASSERT_EQUAL_UINT16(0, g_stub_requests[0].m_requiredPort);
  TEST_ASSERT_EQUAL_STRING("", g_stub_requests[0].ma_headerNamesToCapture);
  TEST_ASSERT_EQUAL_STRING(is_post ? "Content-Type: application/json" : "", g_stub_last_header);
}

void test_verify_request_is_pinned(void)
{
  static_answer(200, R"({"isValid":true,"payer":"x"})");
  TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_VERIFY_VALID, x402_facilitator_verify(&g_requirements, &g_pinnedPayment));
  static_expectTransport("http://localhost/verify", 5000, true);
  TEST_ASSERT_EQUAL_STRING(PINNED_BODY, g_stub_last_post_body);
  TEST_ASSERT_EQUAL_size_t(strlen(PINNED_BODY), g_stub_last_post_body_byte_count);
}

void test_settle_request_is_pinned(void)
{
  static_answer(500, R"({"success":false,"network":"","transaction":""})");
  X402FacilitatorSettlement_t settlement = x402_facilitator_settle(&g_requirements, &g_pinnedPayment);
  TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_SETTLE_PENDING, settlement.m_status);
  static_expectTransport("http://localhost/settle", 30000, true);
  TEST_ASSERT_EQUAL_STRING(PINNED_BODY, g_stub_last_post_body);
  TEST_ASSERT_EQUAL_size_t(strlen(PINNED_BODY), g_stub_last_post_body_byte_count);
}

void test_supported_request_is_pinned(void)
{
  static_answer(200, R"({"kinds":[],"extensions":[],"signers":{}})");
  TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_SUPPORTED_MISMATCH, x402_facilitator_supported(&g_requirements));
  static_expectTransport("http://localhost/supported", 2000, false);
  TEST_ASSERT_EQUAL_size_t(0, g_stub_last_post_body_byte_count);
}

void test_body_that_cannot_be_built_sends_nothing(void)
{
  static_answer(200, R"({"isValid":true,"success":true})");
  size_t byte_counts[] = { 0, X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT + 1 };
  for (size_t i = 0; i < sizeof(byte_counts) / sizeof(byte_counts[0]); i++)
  {
    g_payment.m_transactionByteCount = byte_counts[i];
    TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_VERIFY_UNAVAILABLE, x402_facilitator_verify(&g_requirements, &g_payment));
    X402FacilitatorSettlement_t settlement = x402_facilitator_settle(&g_requirements, &g_payment);
    TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_SETTLE_REFUSED, settlement.m_status);
    TEST_ASSERT_FALSE(settlement.m_hasSignature);
    TEST_ASSERT_EQUAL_STRING("", settlement.ma_signature);
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
}

void test_payment_of_1232_bytes_is_sent(void)
{
  g_payment.m_transactionByteCount = X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT;
  static_answer(200, R"({"isValid":true})");
  TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_VERIFY_VALID, x402_facilitator_verify(&g_requirements, &g_payment));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  size_t pinned_base64_len = strlen("AQIDBAU=");
  TEST_ASSERT_EQUAL_size_t(strlen(PINNED_BODY) - pinned_base64_len + X402_BASE64_LEN(1232), g_stub_last_post_body_byte_count);
}

void test_verify_invalid_for_200_400_412_and_false(void)
{
  int statuses[] = { 200, 400, 412 };
  for (size_t i = 0; i < 3; i++)
  {
    static_answer(statuses[i], R"({"isValid":false,"invalidReason":"invalid_exact_svm_payload_transaction","payer":"x"})");
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_FACILITATOR_VERIFY_INVALID, x402_facilitator_verify(&g_requirements, &g_payment), "status");
  }
}

void test_verify_unavailable_for_other_statuses(void)
{
  int statuses[] = { 201, 204, 302, 401, 404, 500, 503 };
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
  {
    static_answer(statuses[i], R"({"isValid":true})");
    TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_VERIFY_UNAVAILABLE, x402_facilitator_verify(&g_requirements, &g_payment));
    static_answer(statuses[i], R"({"isValid":false})");
    TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_VERIFY_UNAVAILABLE, x402_facilitator_verify(&g_requirements, &g_payment));
  }
  static_answer(400, R"({"isValid":true})");
  TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_VERIFY_UNAVAILABLE, x402_facilitator_verify(&g_requirements, &g_payment));
  static_answer(412, R"({"isValid":true})");
  TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_VERIFY_UNAVAILABLE, x402_facilitator_verify(&g_requirements, &g_payment));
}

void test_verify_unavailable_for_transport_error(void)
{
  HttpError_t errors[] = { HTTP_ERROR_TIMEOUT, HTTP_ERROR_CONNECT, HTTP_ERROR_BODY_TOO_LARGE, HTTP_ERROR_OTHER };
  for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++)
  {
    g_stub_next_error = errors[i];
    TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_VERIFY_UNAVAILABLE, x402_facilitator_verify(&g_requirements, &g_payment));
  }
}

void test_verify_unavailable_for_a_body_that_is_not_the_answer(void)
{
  const char* bodies[] = {
    "", "[]", "true", "{", R"({"isValid":true}x)", R"([{"isValid":true}])", "{}",
    R"({"isValid":"true"})", R"({"isValid":1})", R"({"isValid":null})", R"({"isValid":"false"})",
    R"({"isValid":true,"isValid":true})", R"({"isValid":false,"isValid":true})",
    R"({"\u0069sValid":true})", R"({"isValid":true,"p\"":1})", R"({"data":{"isValid":true}})",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    static_answer(200, bodies[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_FACILITATOR_VERIFY_UNAVAILABLE, x402_facilitator_verify(&g_requirements, &g_payment), bodies[i]);
  }
  g_stub_next_body_null = true;
  TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_VERIFY_UNAVAILABLE, x402_facilitator_verify(&g_requirements, &g_payment));
}

void test_verify_unavailable_for_a_cut_body(void)
{
  static const HttpStubAnswer_t answers[] = { { 200, R"({"isValid":true})", HTTP_ERROR_NONE, NULL, NULL, true, 0 } };
  g_stub_answers      = answers;
  g_stub_answer_count = 1;
  TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_VERIFY_UNAVAILABLE, x402_facilitator_verify(&g_requirements, &g_payment));
}

static const char* static_settleAnswer(const char* success, const char* network, const char* transaction)
{
  snprintf(g_answer, sizeof(g_answer), R"({"success":%s,"payer":"x","transaction":"%s","network":"%s"})",
           success, transaction, network);
  return g_answer;
}

static void static_expectSettledAt(X402FacilitatorSettleStatus_t status, bool has_signature, int line)
{
  X402FacilitatorSettlement_t settlement = x402_facilitator_settle(&g_requirements, &g_payment);
  UNITY_TEST_ASSERT_EQUAL_INT(status, settlement.m_status, line, "status");
  UNITY_TEST_ASSERT(has_signature == settlement.m_hasSignature, line, "m_hasSignature");
  UNITY_TEST_ASSERT_EQUAL_STRING(has_signature ? g_signatureText : "", settlement.ma_signature, line, "ma_signature");
}

#define EXPECT_SETTLED(status, has_signature) static_expectSettledAt((status), (has_signature), __LINE__)

void test_settle_paid_for_the_explicit_answer(void)
{
  static_answer(200, static_settleAnswer("true", FIXTURE_NETWORK, g_signatureText));
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PAID, true);
}

void test_settle_pending_for_another_network(void)
{
  static_answer(200, static_settleAnswer("true", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", g_signatureText));
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, true);
  static_answer(200, static_settleAnswer("true", "", g_signatureText));
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, true);
  snprintf(g_answer, sizeof(g_answer), R"({"success":true,"transaction":"%s"})", g_signatureText);
  static_answer(200, g_answer);
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, true);
}

void test_settle_pending_for_a_signature_that_fails(void)
{
  static_answer(200, static_settleAnswer("true", FIXTURE_NETWORK, g_otherSignatureText));
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);
  static_answer(200, static_settleAnswer("true", FIXTURE_NETWORK, ""));
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);
  static_answer(200, static_settleAnswer("true", FIXTURE_NETWORK, "0OIl"));
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);
  static_answer(200, static_settleAnswer("true", FIXTURE_NETWORK, FIXTURE_FEE_PAYER));
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);

  char flipped[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE];
  memcpy(flipped, g_signatureText, sizeof(flipped));
  flipped[5] = flipped[5] == '2' ? '3' : '2';
  static_answer(200, static_settleAnswer("true", FIXTURE_NETWORK, flipped));
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);

  snprintf(g_answer, sizeof(g_answer), R"({"success":true,"network":"%s","transaction":1})", FIXTURE_NETWORK);
  static_answer(200, g_answer);
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);

  g_payment.ma_transaction[g_payment.m_transactionByteCount - 2] ^= 0x01;
  static_answer(200, static_settleAnswer("true", FIXTURE_NETWORK, g_signatureText));
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);
}

void test_settle_with_a_signature_of_another_fee_payer_is_not_paid(void)
{
  snprintf(g_requirements.ma_feePayer, sizeof(g_requirements.ma_feePayer), "%s", FIXTURE_PAY_TO);
  static_answer(200, static_settleAnswer("true", FIXTURE_NETWORK, g_signatureText));
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);

  snprintf(g_requirements.ma_feePayer, sizeof(g_requirements.ma_feePayer), "%s", FIXTURE_FEE_PAYER);
  size_t public_key_len = 32;
  TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_get_raw_public_key(g_otherKey, g_payment.ma_transaction + g_messageOffset + 4, &public_key_len));
  static_signPayment(g_otherKey, g_otherSignatureText);
  static_answer(200, static_settleAnswer("true", FIXTURE_NETWORK, g_otherSignatureText));
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);
}

void test_settle_with_a_fee_payer_that_does_not_decode_is_refused_unsent(void)
{
  const char* fee_payers[] = { "", "0OIl", "2wmVCSfPxGPjrnMMn7rchp4uaeoTqN39mXFC2zhPdri", FIXTURE_FEE_PAYER "1" };
  for (size_t i = 0; i < sizeof(fee_payers) / sizeof(fee_payers[0]); i++)
  {
    snprintf(g_requirements.ma_feePayer, sizeof(g_requirements.ma_feePayer), "%s", fee_payers[i]);
    static_answer(200, static_settleAnswer("true", FIXTURE_NETWORK, g_signatureText));
    g_stub_http_call_count = 0;
    EXPECT_SETTLED(X402_FACILITATOR_SETTLE_REFUSED, false);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_stub_http_call_count, fee_payers[i]);
  }
}

void test_settle_pending_for_success_that_is_not_true(void)
{
  const char* successes[] = { "false", R"("true")", "1", "null" };
  for (size_t i = 0; i < sizeof(successes) / sizeof(successes[0]); i++)
  {
    static_answer(200, static_settleAnswer(successes[i], FIXTURE_NETWORK, g_signatureText));
    EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, true);
  }
}

void test_settle_pending_for_another_status(void)
{
  int statuses[] = { 201, 302, 400, 412, 500 };
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
  {
    static_answer(statuses[i], static_settleAnswer("true", FIXTURE_NETWORK, g_signatureText));
    EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, true);
  }
}

void test_settle_refused_for_400_412_and_false(void)
{
  static_answer(400, R"({"success":false,"errorReason":"invalid_exact_svm_payload_transaction","network":"","transaction":""})");
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_REFUSED, false);
  static_answer(412, R"({"success":false})");
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_REFUSED, false);
  static_answer(200, R"({"success":false})");
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);
  static_answer(400, R"({"success":"false"})");
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);
  static_answer(400, R"({})");
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);
}

void test_settle_pending_for_a_refusal_with_a_signature(void)
{
  static_answer(400, static_settleAnswer("false", "", g_signatureText));
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, true);
  static_answer(412, static_settleAnswer("false", FIXTURE_NETWORK, g_signatureText));
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, true);
  static_answer(400, static_settleAnswer("false", "", g_otherSignatureText));
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_REFUSED, false);
}

void test_settle_pending_for_500(void)
{
  static_answer(500, R"({"success":false,"errorReason":"x","network":"","transaction":""})");
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);
  static_answer(500, static_settleAnswer("false", "", g_signatureText));
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, true);
}

void test_settle_pending_for_no_answer(void)
{
  HttpError_t errors[] = { HTTP_ERROR_TIMEOUT, HTTP_ERROR_CONNECT, HTTP_ERROR_BODY_TOO_LARGE, HTTP_ERROR_OTHER };
  for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++)
  {
    g_stub_next_error = errors[i];
    EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);
  }
  g_stub_next_error = HTTP_ERROR_NONE;

  const char* bodies[] = { "", "[]", "{", "null" };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    static_answer(200, bodies[i]);
    EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);
  }
  g_stub_next_body_null = true;
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);
}

void test_settle_pending_for_a_duplicate_or_escaped_key(void)
{
  snprintf(g_answer, sizeof(g_answer), R"({"success":false,"success":true,"network":"%s","transaction":"%s"})",
           FIXTURE_NETWORK, g_signatureText);
  static_answer(200, g_answer);
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);
  snprintf(g_answer, sizeof(g_answer), R"({"success":true,"network":"%s","transaction":"%s","transaction":"%s"})",
           FIXTURE_NETWORK, g_signatureText, g_signatureText);
  static_answer(200, g_answer);
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);
  snprintf(g_answer, sizeof(g_answer), R"({"\u0073uccess":true,"network":"%s","transaction":"%s"})",
           FIXTURE_NETWORK, g_signatureText);
  static_answer(200, g_answer);
  EXPECT_SETTLED(X402_FACILITATOR_SETTLE_PENDING, false);
}

static const char* static_supportedAnswer(const char* kind, const char* signers)
{
  snprintf(g_answer, sizeof(g_answer), R"({"kinds":[%s],"extensions":[],"signers":%s})", kind, signers);
  return g_answer;
}

#define GOOD_KIND    R"({"x402Version":2,"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","extra":{"feePayer":"FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"}})"
#define GOOD_SIGNERS R"({"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp":["FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"]})"

void test_supported_yes_for_our_kind_and_signer(void)
{
  static_answer(200, static_supportedAnswer(GOOD_KIND, GOOD_SIGNERS));
  TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_SUPPORTED_YES, x402_facilitator_supported(&g_requirements));

  static_answer(200, static_supportedAnswer(
    R"({"x402Version":1,"scheme":"exact","network":"solana"},)" GOOD_KIND,
    R"({"solana:x":["a"],"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp":["b","FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"]})"));
  TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_SUPPORTED_YES, x402_facilitator_supported(&g_requirements));
}

void test_supported_mismatch_for_one_part_that_differs(void)
{
  const char* kinds[] = {
    R"({"x402Version":1,"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","extra":{"feePayer":"FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"}})",
    R"({"x402Version":"2","scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","extra":{"feePayer":"FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"}})",
    R"({"x402Version":2,"scheme":"upto","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","extra":{"feePayer":"FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"}})",
    R"({"x402Version":2,"scheme":"exact","network":"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1","extra":{"feePayer":"FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"}})",
    R"({"x402Version":2,"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","extra":{"feePayer":"9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"}})",
    R"({"x402Version":2,"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"})",
    R"({"x402Version":2,"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","extra":{}})",
    R"({"x402Version":2,"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","extra":{"feePayer":"FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z","feePayer":"FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"}})",
    R"({"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","extra":{"feePayer":"FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"}})",
    R"("exact")",
  };
  for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++)
  {
    static_answer(200, static_supportedAnswer(kinds[i], GOOD_SIGNERS));
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_FACILITATOR_SUPPORTED_MISMATCH, x402_facilitator_supported(&g_requirements), kinds[i]);
  }

  const char* signers[] = {
    "{}",
    R"({"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp":[]})",
    R"({"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp":["9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"]})",
    R"({"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp":"FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"})",
    R"({"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1":["FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"]})",
    R"({"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp":[["FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"]]})",
    R"(["FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"])",
  };
  for (size_t i = 0; i < sizeof(signers) / sizeof(signers[0]); i++)
  {
    static_answer(200, static_supportedAnswer(GOOD_KIND, signers[i]));
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_FACILITATOR_SUPPORTED_MISMATCH, x402_facilitator_supported(&g_requirements), signers[i]);
  }

  static_answer(200, R"({"signers":{"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp":["FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"]}})");
  TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_SUPPORTED_MISMATCH, x402_facilitator_supported(&g_requirements));
  static_answer(200, R"({"kinds":[)" GOOD_KIND R"(]})");
  TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_SUPPORTED_MISMATCH, x402_facilitator_supported(&g_requirements));
  static_answer(200, R"({"kinds":)" GOOD_KIND R"(,"signers":)" GOOD_SIGNERS R"(})");
  TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_SUPPORTED_MISMATCH, x402_facilitator_supported(&g_requirements));
}

void test_supported_unavailable_for_anything_else(void)
{
  int statuses[] = { 201, 302, 400, 404, 500 };
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
  {
    static_answer(statuses[i], static_supportedAnswer(GOOD_KIND, GOOD_SIGNERS));
    TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_SUPPORTED_UNAVAILABLE, x402_facilitator_supported(&g_requirements));
  }

  const char* bodies[] = {
    "", "[]", "{", "null",
    R"({"kinds":[)" GOOD_KIND R"(],"signers":)" GOOD_SIGNERS R"(,"kinds":[]})",
    R"({"kinds":[)" GOOD_KIND R"(],"signers":)" GOOD_SIGNERS R"(,"signers":{}})",
    R"({"\u006binds":[)" GOOD_KIND R"(],"signers":)" GOOD_SIGNERS R"(})",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    static_answer(200, bodies[i]);
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_FACILITATOR_SUPPORTED_UNAVAILABLE, x402_facilitator_supported(&g_requirements), bodies[i]);
  }
  g_stub_next_body_null = true;
  TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_SUPPORTED_UNAVAILABLE, x402_facilitator_supported(&g_requirements));
  g_stub_next_body_null = false;

  g_stub_next_error = HTTP_ERROR_TIMEOUT;
  TEST_ASSERT_EQUAL_INT(X402_FACILITATOR_SUPPORTED_UNAVAILABLE, x402_facilitator_supported(&g_requirements));
}

void test_no_call_writes_to_stderr(void)
{
  FILE* capture = tmpfile();
  TEST_ASSERT_NOT_NULL(capture);
  fflush(stderr);
  int saved_fd = dup(fileno(stderr));
  TEST_ASSERT_TRUE(saved_fd >= 0);
  TEST_ASSERT_TRUE(dup2(fileno(capture), fileno(stderr)) >= 0);

  static_answer(400, R"({"isValid":false,"invalidReason":"reason_text","invalidReasonDetails":"details"})");
  (void)x402_facilitator_verify(&g_requirements, &g_payment);
  static_answer(500, R"({"success":false,"errorReason":"reason_text","errorReasonDetails":"details"})");
  (void)x402_facilitator_settle(&g_requirements, &g_payment);
  static_answer(200, "{");
  (void)x402_facilitator_supported(&g_requirements);
  g_stub_next_error = HTTP_ERROR_CONNECT;
  (void)x402_facilitator_verify(&g_requirements, &g_payment);
  (void)x402_facilitator_settle(&g_requirements, &g_payment);
  (void)x402_facilitator_supported(&g_requirements);
  g_payment.m_transactionByteCount = 0;
  (void)x402_facilitator_verify(&g_requirements, &g_payment);

  fflush(stderr);
  long written = ftell(capture);
  dup2(saved_fd, fileno(stderr));
  close(saved_fd);
  fclose(capture);
  TEST_ASSERT_EQUAL_INT(0, (int)written);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(27, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  g_feePayerKey = static_keyFromSeed(FEE_PAYER_SEED);
  g_otherKey    = static_keyFromSeed(OTHER_SEED);
  if (g_feePayerKey == NULL || g_otherKey == NULL)
    return 1;

  UNITY_BEGIN();
  RUN_TEST(test_verify_request_is_pinned);
  RUN_TEST(test_settle_request_is_pinned);
  RUN_TEST(test_supported_request_is_pinned);
  RUN_TEST(test_body_that_cannot_be_built_sends_nothing);
  RUN_TEST(test_payment_of_1232_bytes_is_sent);
  RUN_TEST(test_verify_invalid_for_200_400_412_and_false);
  RUN_TEST(test_verify_unavailable_for_other_statuses);
  RUN_TEST(test_verify_unavailable_for_transport_error);
  RUN_TEST(test_verify_unavailable_for_a_body_that_is_not_the_answer);
  RUN_TEST(test_verify_unavailable_for_a_cut_body);
  RUN_TEST(test_settle_paid_for_the_explicit_answer);
  RUN_TEST(test_settle_pending_for_another_network);
  RUN_TEST(test_settle_pending_for_a_signature_that_fails);
  RUN_TEST(test_settle_with_a_signature_of_another_fee_payer_is_not_paid);
  RUN_TEST(test_settle_with_a_fee_payer_that_does_not_decode_is_refused_unsent);
  RUN_TEST(test_settle_pending_for_success_that_is_not_true);
  RUN_TEST(test_settle_pending_for_another_status);
  RUN_TEST(test_settle_refused_for_400_412_and_false);
  RUN_TEST(test_settle_pending_for_a_refusal_with_a_signature);
  RUN_TEST(test_settle_pending_for_500);
  RUN_TEST(test_settle_pending_for_no_answer);
  RUN_TEST(test_settle_pending_for_a_duplicate_or_escaped_key);
  RUN_TEST(test_supported_yes_for_our_kind_and_signer);
  RUN_TEST(test_supported_mismatch_for_one_part_that_differs);
  RUN_TEST(test_supported_unavailable_for_anything_else);
  RUN_TEST(test_no_call_writes_to_stderr);
  RUN_TEST(test_registration_gate_test_count);
  int failures = UNITY_END();

  EVP_PKEY_free(g_feePayerKey);
  EVP_PKEY_free(g_otherKey);
  return failures;
}
