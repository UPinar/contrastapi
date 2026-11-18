#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "unity/unity.h"
extern "C" {
#include "http_stub.h"
#include "x402_solana.h"
#include "x402_solana_rpc.h"
}

#define RPC_URL "https://rpc.example.com/?api-key=secret"

#define SIGNATURE_TEXT "67rpwLCuS5DGA8KGZXKsVQ7dnPb9goRLoKfgGbLfQg9WoLUgNY77E2jT11fem3coV9nAkguBACzrU1iyZM4B8roQ"

#define ANSWER_BUF_SIZE 1024

static char g_answer[ANSWER_BUF_SIZE];

static void static_buildTx(void);

void setUp(void)
{
  g_stub_answers                   = NULL;
  g_stub_answer_count              = 0;
  g_stub_http_call_count           = 0;
  g_stub_last_url[0]               = '\0';
  g_stub_last_header[0]            = '\0';
  g_stub_next_status               = 200;
  g_stub_next_body                 = NULL;
  g_stub_next_body_null            = false;
  g_stub_next_body_byte_count      = 0;
  g_stub_next_error                = HTTP_ERROR_NONE;
  g_stub_last_timeout_ms           = -1;
  g_stub_last_max_body_byte_count  = 0;
  g_stub_last_is_target_trusted    = false;
  g_stub_last_post_body[0]         = '\0';
  g_stub_last_post_body_byte_count = 0;
  g_stub_last_unix_socket_path[0]  = '\0';
  memset(g_stub_requests, 0, sizeof(g_stub_requests));
  static_buildTx();
}

void tearDown(void)
{
}

static const char* static_valueAnswer(const char* element)
{
  snprintf(g_answer, sizeof(g_answer), R"({"jsonrpc":"2.0","result":{"context":{"slot":341197053},"value":[%s]},"id":1})", element);
  return g_answer;
}

static X402SolanaRpcSignatureStatus_t static_ask(int status, const char* body)
{
  g_stub_next_status = status;
  g_stub_next_body   = body;
  return x402_solana_rpc_askSignatureStatus(RPC_URL, SIGNATURE_TEXT);
}

void test_request_is_pinned(void)
{
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_NOT_FOUND, static_ask(200, static_valueAnswer("null")));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING(RPC_URL, g_stub_requests[0].ma_url);
  TEST_ASSERT_TRUE(g_stub_requests[0].m_isPost);
  TEST_ASSERT_EQUAL_STRING("", g_stub_last_unix_socket_path);
  TEST_ASSERT_EQUAL_INT(5000, g_stub_requests[0].m_timeoutMs);
  TEST_ASSERT_EQUAL_size_t(16384, g_stub_requests[0].m_maxBodyByteCount);
  TEST_ASSERT_TRUE(g_stub_requests[0].m_isTargetTrusted);
  TEST_ASSERT_TRUE(g_stub_requests[0].m_isRedirectLeftToCaller);
  TEST_ASSERT_FALSE(g_stub_requests[0].m_isBodyCutAccepted);
  TEST_ASSERT_EQUAL_STRING("", g_stub_requests[0].ma_headerNamesToCapture);
  TEST_ASSERT_EQUAL_STRING("Content-Type: application/json", g_stub_last_header);
  const char* expected =
    R"({"jsonrpc":"2.0","id":1,"method":"getSignatureStatuses","params":[[")" SIGNATURE_TEXT
    R"("],{"searchTransactionHistory":true}]})";
  TEST_ASSERT_EQUAL_STRING(expected, g_stub_last_post_body);
  TEST_ASSERT_EQUAL_size_t(strlen(expected), g_stub_last_post_body_byte_count);
}

void test_signature_text_that_does_not_decode_sends_nothing(void)
{
  g_stub_next_body = static_valueAnswer(R"({"slot":1,"confirmations":null,"err":null,"confirmationStatus":"finalized"})");
  const char* texts[] = {
    "", "0OIl", "2wmVCSfPxGPjrnMMn7rchp4uaeoTqN39mXFC2zhPdri9", "1" SIGNATURE_TEXT,
    SIGNATURE_TEXT "\"", "\"],[\"" SIGNATURE_TEXT,
  };
  for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); i++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, x402_solana_rpc_askSignatureStatus(RPC_URL, texts[i]), texts[i]);
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
}

void test_confirmed_and_finalized_are_confirmed(void)
{
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_CONFIRMED,
    static_ask(200, static_valueAnswer(R"({"slot":341197000,"confirmations":10,"err":null,"status":{"Ok":null},"confirmationStatus":"confirmed"})")));
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_CONFIRMED,
    static_ask(200, static_valueAnswer(R"({"slot":341197000,"confirmations":null,"err":null,"confirmationStatus":"finalized"})")));
}

void test_processed_is_processed(void)
{
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_PROCESSED,
    static_ask(200, static_valueAnswer(R"({"slot":341197050,"confirmations":0,"err":null,"confirmationStatus":"processed"})")));
}

void test_null_element_is_not_found(void)
{
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_NOT_FOUND, static_ask(200, static_valueAnswer("null")));
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_NOT_FOUND, static_ask(200, R"({"jsonrpc":"2.0","result":{"value":[ null ]},"id":1})"));
}

void test_err_that_is_not_null_is_failed(void)
{
  const char* elements[] = {
    R"({"slot":1,"confirmations":null,"err":{"InstructionError":[2,{"Custom":1}]},"confirmationStatus":"finalized"})",
    R"({"slot":1,"confirmations":10,"err":{"InstructionError":[2,{"Custom":1}]},"confirmationStatus":"confirmed"})",
    R"({"slot":1,"confirmations":null,"err":"AccountNotFound","confirmationStatus":"confirmed"})",
    R"({"slot":1,"confirmations":null,"err":"AccountNotFound","confirmationStatus":"finalized"})",
  };
  for (size_t i = 0; i < sizeof(elements) / sizeof(elements[0]); i++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_SOLANA_RPC_SIGNATURE_FAILED, static_ask(200, static_valueAnswer(elements[i])), elements[i]);
}

void test_processed_with_an_err_is_processed(void)
{
  const char* elements[] = {
    R"({"slot":1,"confirmations":0,"err":{},"confirmationStatus":"processed"})",
    R"({"slot":1,"confirmations":0,"err":{"InstructionError":[2,{"Custom":1}]},"confirmationStatus":"processed"})",
    R"({"slot":1,"confirmations":0,"err":"AccountNotFound","confirmationStatus":"processed"})",
  };
  for (size_t i = 0; i < sizeof(elements) / sizeof(elements[0]); i++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_SOLANA_RPC_SIGNATURE_PROCESSED, static_ask(200, static_valueAnswer(elements[i])), elements[i]);
}

void test_err_with_an_unknown_confirmation_status_is_unavailable(void)
{
  const char* elements[] = {
    R"({"err":0})",
    R"({"slot":1,"err":{"InstructionError":[2,{"Custom":1}]}})",
    R"({"slot":1,"err":{"InstructionError":[2,{"Custom":1}]},"confirmationStatus":"rooted"})",
    R"({"slot":1,"err":{},"confirmationStatus":"Finalized"})",
    R"({"slot":1,"err":{},"confirmationStatus":null})",
    R"({"slot":1,"err":"AccountNotFound","confirmationStatus":2})",
  };
  for (size_t i = 0; i < sizeof(elements) / sizeof(elements[0]); i++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, static_ask(200, static_valueAnswer(elements[i])), elements[i]);
}

void test_element_that_is_not_the_answer_is_unavailable(void)
{
  const char* elements[] = {
    R"({"slot":1,"confirmationStatus":"finalized"})",
    R"({"slot":1,"err":null})",
    R"({"slot":1,"err":null,"confirmationStatus":"rooted"})",
    R"({"slot":1,"err":null,"confirmationStatus":"Finalized"})",
    R"({"slot":1,"err":null,"confirmationStatus":null})",
    R"({"slot":1,"err":null,"confirmationStatus":2})",
    R"({"slot":1,"err":null,"confirmationStatus":["finalized"]})",
    R"({"slot":1,"err":null,"confirmationStatus":"finalized","err":{}})",
    R"({"slot":1,"err":null,"confirmationStatus":"processed","confirmationStatus":"finalized"})",
    R"({"slot":1,"err":{},"err":null,"confirmationStatus":"finalized"})",
    R"("finalized")", "0", "true", "[]", R"([null])",
  };
  for (size_t i = 0; i < sizeof(elements) / sizeof(elements[0]); i++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, static_ask(200, static_valueAnswer(elements[i])), elements[i]);
}

void test_envelope_that_is_not_the_answer_is_unavailable(void)
{
  const char* bodies[] = {
    R"({"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid param"},"id":1})",
    R"({"jsonrpc":"2.0","result":{"value":[null]},"error":{"code":-32000,"message":"x"},"id":1})",
    R"({"jsonrpc":"2.0","result":{"value":[null]},"id":2})",
    R"({"jsonrpc":"2.0","result":{"value":[null]},"id":"1"})",
    R"({"jsonrpc":"2.0","result":{"value":[null]},"id":1.0})",
    R"({"jsonrpc":"2.0","result":{"value":[null]}})",
    R"({"jsonrpc":"2.0","result":{"value":[null]},"id":1,"id":1})",
    R"({"jsonrpc":"2.0","result":{"value":[null]},"result":{"value":[null]},"id":1})",
    R"({"jsonrpc":"2.0","\u0072esult":{"value":[null]},"id":1})",
    R"({"jsonrpc":"2.0","result":{"v\u0061lue":[null]},"id":1})",
    R"({"jsonrpc":"2.0","id":1})",
    R"({"jsonrpc":"2.0","result":null,"id":1})",
    R"({"jsonrpc":"2.0","result":{"context":{"slot":1}},"id":1})",
    R"({"jsonrpc":"2.0","result":{"value":null},"id":1})",
    R"({"jsonrpc":"2.0","result":{"value":{"err":null}},"id":1})",
    R"({"jsonrpc":"2.0","result":{"value":[]},"id":1})",
    R"({"jsonrpc":"2.0","result":{"value":[null,null]},"id":1})",
    R"({"jsonrpc":"2.0","result":{"value":[null],"value":[null]},"id":1})",
    R"([{"jsonrpc":"2.0","result":{"value":[null]},"id":1}])",
    R"({"jsonrpc":"2.0","result":{"value":[null]},"id":1}x)",
    "", "{", "null",
  };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, static_ask(200, bodies[i]), bodies[i]);

  g_stub_next_body_null = true;
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, static_ask(200, NULL));
}

void test_status_other_than_200_or_no_answer_is_unavailable(void)
{
  const char* finalized = static_valueAnswer(R"({"slot":1,"err":null,"confirmationStatus":"finalized"})");
  int statuses[] = { 201, 301, 400, 401, 429, 500, 503 };
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
    TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, static_ask(statuses[i], finalized));

  HttpError_t errors[] = { HTTP_ERROR_TIMEOUT, HTTP_ERROR_RESOLVE, HTTP_ERROR_TLS, HTTP_ERROR_BODY_TOO_LARGE, HTTP_ERROR_OTHER };
  for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++)
  {
    g_stub_next_error = errors[i];
    TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, static_ask(200, finalized));
  }
  g_stub_next_error = HTTP_ERROR_NONE;

  static const HttpStubAnswer_t answers[] = { { 200, NULL, HTTP_ERROR_NONE, NULL, NULL, true, 0 } };
  HttpStubAnswer_t cut = answers[0];
  cut.mp_body          = finalized;
  g_stub_answers       = &cut;
  g_stub_answer_count  = 1;
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, x402_solana_rpc_askSignatureStatus(RPC_URL, SIGNATURE_TEXT));
}

void test_cut_body_is_unavailable(void)
{
  HttpStubAnswer_t answers[] = { {
    .m_status             = 200,
    .mp_body              = static_valueAnswer(R"({"err":null,"confirmationStatus":"confirmed"})"),
    .m_error              = HTTP_ERROR_NONE,
    .mp_redirectUrl       = NULL,
    .mp_headerLines       = NULL,
    .m_isBodyCut          = true,
    .m_setCookieCopyCount = 0,
  } };
  g_stub_answers      = answers;
  g_stub_answer_count = 1;
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, x402_solana_rpc_askSignatureStatus(RPC_URL, SIGNATURE_TEXT));
  g_stub_answers = NULL;
}

void test_no_call_writes_to_stderr(void)
{
  FILE* capture = tmpfile();
  TEST_ASSERT_NOT_NULL(capture);
  fflush(stderr);
  int saved_fd = dup(fileno(stderr));
  TEST_ASSERT_TRUE(saved_fd >= 0);
  TEST_ASSERT_TRUE(dup2(fileno(capture), fileno(stderr)) >= 0);

  (void)static_ask(200, R"({"jsonrpc":"2.0","error":{"code":-32602,"message":"message_text"},"id":1})");
  (void)static_ask(500, "{");
  g_stub_next_error = HTTP_ERROR_TLS;
  (void)static_ask(200, "{}");
  (void)x402_solana_rpc_askSignatureStatus(RPC_URL, "0");

  fflush(stderr);
  long written = ftell(capture);
  dup2(saved_fd, fileno(stderr));
  close(saved_fd);
  fclose(capture);
  TEST_ASSERT_EQUAL_INT(0, (int)written);
}

#define SOURCE_TEXT "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
static const uint8_t SOURCE_BYTES[32] = {
  0xc6, 0xfa, 0x7a, 0xf3, 0xbe, 0xdb, 0xad, 0x3a, 0x3d, 0x65, 0xf3, 0x6a, 0xab, 0xc9, 0x74, 0x31,
  0xb1, 0xbb, 0xe4, 0xc2, 0xd2, 0xf6, 0xe0, 0xe4, 0x7c, 0xa6, 0x02, 0x03, 0x45, 0x2f, 0x5d, 0x61
};

static const uint8_t FEE_PAYER_SEED[32] = {
  0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
  0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
};

static const uint8_t OTHER_SEED[32] = {
  0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
  0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb
};

#define FOUND_SENTINEL "sentinel"

#define TX_BUF_SIZE         256
#define LIST_ANSWER_BUF_SIZE 16384
#define ELEMENT_BUF_SIZE    512
#define MAX_TEST_ELEMENTS   24

static EVP_PKEY* g_feePayerKey;
static EVP_PKEY* g_otherKey;
static uint8_t   g_feePayer[32];
static uint8_t   g_tx[TX_BUF_SIZE];
static size_t    g_txLen;
static char      g_feePayerSignatureText[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE];
static char      g_otherSignatureText[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE];
static char      g_found[X402_SOLANA_SIGNATURE_TEXT_BUF_SIZE];
static char      g_listAnswer[LIST_ANSWER_BUF_SIZE];
static char      g_elements[MAX_TEST_ELEMENTS][ELEMENT_BUF_SIZE];

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

static void static_signTx(EVP_PKEY* key, size_t message_start, char* text)
{
  uint8_t     signature[64];
  size_t      signature_len = sizeof(signature);
  EVP_MD_CTX* ctx           = EVP_MD_CTX_new();
  TEST_ASSERT_NOT_NULL(ctx);
  TEST_ASSERT_EQUAL_INT(1, EVP_DigestSignInit(ctx, NULL, NULL, NULL, key));
  TEST_ASSERT_EQUAL_INT(1, EVP_DigestSign(ctx, signature, &signature_len, g_tx + message_start, g_txLen - message_start));
  EVP_MD_CTX_free(ctx);
  static_encodeBase58(signature, sizeof(signature), text);
}

static void static_buildTx(void)
{
  memset(g_tx, 0, sizeof(g_tx));
  size_t len = 0;
  g_tx[len++] = 1;
  len += 64;
  size_t message_start = len;
  g_tx[len++] = 1;
  g_tx[len++] = 0;
  g_tx[len++] = 0;
  g_tx[len++] = 1;
  size_t public_key_len = sizeof(g_feePayer);
  TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_get_raw_public_key(g_feePayerKey, g_feePayer, &public_key_len));
  memcpy(g_tx + len, g_feePayer, sizeof(g_feePayer));
  len += 32;
  for (int i = 0; i < 32; i++)
    g_tx[len++] = (uint8_t)(0x44 + i);
  g_tx[len++] = 0;
  g_txLen = len;

  static_signTx(g_feePayerKey, message_start, g_feePayerSignatureText);
  static_signTx(g_otherKey, message_start, g_otherSignatureText);
}

static const char* static_element(int index, const char* signature, const char* err, const char* confirmation)
{
  snprintf(g_elements[index], sizeof(g_elements[index]),
           R"({"signature":"%s","slot":341197000,"err":%s,"memo":null,"blockTime":1731456000,"confirmationStatus":"%s"})",
           signature, err, confirmation);
  return g_elements[index];
}

static const char* static_listAnswer(const char* const* elements, int element_count)
{
  size_t len = (size_t)snprintf(g_listAnswer, sizeof(g_listAnswer), R"({"jsonrpc":"2.0","result":[)");
  for (int i = 0; i < element_count; i++)
    len += (size_t)snprintf(g_listAnswer + len, sizeof(g_listAnswer) - len, "%s%s", i > 0 ? "," : "", elements[i]);
  len += (size_t)snprintf(g_listAnswer + len, sizeof(g_listAnswer) - len, R"(],"id":1})");
  TEST_ASSERT_TRUE(len < sizeof(g_listAnswer));
  return g_listAnswer;
}

static X402SolanaRpcSignatureStatus_t static_find(int status, const char* body)
{
  g_stub_next_status = status;
  g_stub_next_body   = body;
  snprintf(g_found, sizeof(g_found), "%s", FOUND_SENTINEL);
  return x402_solana_rpc_findFeePayerSignature(RPC_URL, SOURCE_BYTES, g_tx, g_txLen, g_feePayer, g_found);
}

void test_find_request_is_pinned(void)
{
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_NOT_FOUND, static_find(200, R"({"jsonrpc":"2.0","result":[],"id":1})"));
  TEST_ASSERT_EQUAL_STRING("", g_found);
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_EQUAL_STRING(RPC_URL, g_stub_requests[0].ma_url);
  TEST_ASSERT_TRUE(g_stub_requests[0].m_isPost);
  TEST_ASSERT_EQUAL_STRING("", g_stub_last_unix_socket_path);
  TEST_ASSERT_EQUAL_INT(5000, g_stub_requests[0].m_timeoutMs);
  TEST_ASSERT_EQUAL_size_t(65536, g_stub_requests[0].m_maxBodyByteCount);
  TEST_ASSERT_TRUE(g_stub_requests[0].m_isTargetTrusted);
  TEST_ASSERT_TRUE(g_stub_requests[0].m_isRedirectLeftToCaller);
  TEST_ASSERT_FALSE(g_stub_requests[0].m_isBodyCutAccepted);
  TEST_ASSERT_EQUAL_STRING("", g_stub_requests[0].ma_headerNamesToCapture);
  TEST_ASSERT_EQUAL_STRING("Content-Type: application/json", g_stub_last_header);
  const char* expected =
    R"({"jsonrpc":"2.0","id":1,"method":"getSignaturesForAddress","params":[")" SOURCE_TEXT
    R"(",{"limit":20,"commitment":"confirmed"}]})";
  TEST_ASSERT_EQUAL_STRING(expected, g_stub_last_post_body);
  TEST_ASSERT_EQUAL_size_t(strlen(expected), g_stub_last_post_body_byte_count);
}

void test_find_confirmed_fee_payer_signature_is_confirmed(void)
{
  const char* alone[] = { static_element(0, g_feePayerSignatureText, "null", "confirmed") };
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_CONFIRMED, static_find(200, static_listAnswer(alone, 1)));
  TEST_ASSERT_EQUAL_STRING(g_feePayerSignatureText, g_found);

  const char* last[] = {
    static_element(1, g_otherSignatureText, "null", "processed"),
    static_element(2, g_feePayerSignatureText, "null", "finalized"),
  };
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_CONFIRMED, static_find(200, static_listAnswer(last, 2)));
  TEST_ASSERT_EQUAL_STRING(g_feePayerSignatureText, g_found);
}

void test_find_failed_fee_payer_signature_is_failed(void)
{
  const char* elements[] = { static_element(0, g_feePayerSignatureText, R"({"InstructionError":[2,{"Custom":1}]})", "confirmed") };
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_FAILED, static_find(200, static_listAnswer(elements, 1)));
  TEST_ASSERT_EQUAL_STRING(g_feePayerSignatureText, g_found);
}

void test_find_processed_fee_payer_signature_is_processed(void)
{
  const char* elements[] = { static_element(0, g_feePayerSignatureText, "null", "processed") };
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_PROCESSED, static_find(200, static_listAnswer(elements, 1)));
  TEST_ASSERT_EQUAL_STRING(g_feePayerSignatureText, g_found);
}

void test_find_fee_payer_element_of_unknown_status_is_unavailable(void)
{
  const char* elements[] = { static_element(0, g_feePayerSignatureText, "null", "rooted") };
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, static_find(200, static_listAnswer(elements, 1)));
  TEST_ASSERT_EQUAL_STRING("", g_found);
}

void test_find_list_without_fee_payer_signature_is_not_found(void)
{
  const char* elements[] = {
    static_element(0, g_otherSignatureText, "null", "confirmed"),
    static_element(1, SIGNATURE_TEXT, "null", "finalized"),
  };
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_NOT_FOUND, static_find(200, static_listAnswer(elements, 2)));
  TEST_ASSERT_EQUAL_STRING("", g_found);
}

void test_find_skips_candidate_that_fails_ed25519(void)
{
  const char* elements[] = {
    static_element(0, g_otherSignatureText, "null", "confirmed"),
    static_element(1, g_feePayerSignatureText, R"("AccountNotFound")", "finalized"),
  };
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_FAILED, static_find(200, static_listAnswer(elements, 2)));
  TEST_ASSERT_EQUAL_STRING(g_feePayerSignatureText, g_found);

  const char* twice[] = {
    static_element(2, g_feePayerSignatureText, "null", "processed"),
    static_element(3, g_feePayerSignatureText, "null", "finalized"),
  };
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_PROCESSED, static_find(200, static_listAnswer(twice, 2)));
  TEST_ASSERT_EQUAL_STRING(g_feePayerSignatureText, g_found);
}

void test_find_envelope_that_is_not_the_answer_is_unavailable(void)
{
  const char* element = static_element(0, g_feePayerSignatureText, "null", "confirmed");
  char        bodies[9][ELEMENT_BUF_SIZE * 2];
  snprintf(bodies[0], sizeof(bodies[0]), R"({"jsonrpc":"2.0","result":[%s],"error":{"code":-32000,"message":"x"},"id":1})", element);
  snprintf(bodies[1], sizeof(bodies[1]), R"({"jsonrpc":"2.0","result":[%s],"id":2})", element);
  snprintf(bodies[2], sizeof(bodies[2]), R"({"jsonrpc":"2.0","result":[%s]})", element);
  snprintf(bodies[3], sizeof(bodies[3]), R"({"jsonrpc":"2.0","result":{"context":{"slot":1},"value":[%s]},"id":1})", element);
  snprintf(bodies[4], sizeof(bodies[4]), R"({"jsonrpc":"2.0","result":%s,"id":1})", element);
  snprintf(bodies[5], sizeof(bodies[5]), R"({"jsonrpc":"2.0","result":null,"id":1})");
  snprintf(bodies[6], sizeof(bodies[6]), R"({"jsonrpc":"2.0","id":1})");
  snprintf(bodies[7], sizeof(bodies[7]), R"({"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid param"},"id":1})");
  snprintf(bodies[8], sizeof(bodies[8]), R"({"jsonrpc":"2.0","result":[%s],"id":"1"})", element);
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, static_find(200, bodies[i]), bodies[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", g_found, bodies[i]);
  }
}

void test_find_element_that_is_not_a_signature_entry_is_unavailable(void)
{
  const char* bad_elements[] = {
    R"({"slot":1,"err":null,"confirmationStatus":"confirmed"})",
    R"({"signature":5,"err":null,"confirmationStatus":"confirmed"})",
    R"({"signature":null,"err":null,"confirmationStatus":"confirmed"})",
    R"({"signature":"0OIl","err":null,"confirmationStatus":"confirmed"})",
    R"({"signature":"PbGvaomYRfb7uHHdgYrHrM2HMLhjLftSPTPiKpZnXVnaXWyAn4HxUWeMm3wbfQZ2BFkN3q7HqdxMLECGdmX1jgorv","err":null,"confirmationStatus":"confirmed"})",
    R"({"signature":"2wmVCSfPxGPjrnMMn7rchp4uaeoTqN39mXFC2zhPdri9","err":null,"confirmationStatus":"confirmed"})",
    R"({"signature":")" SIGNATURE_TEXT R"(","signature":")" SIGNATURE_TEXT R"(","err":null,"confirmationStatus":"confirmed"})",
    "null", R"(")" SIGNATURE_TEXT R"(")", "[]", "0",
  };
  const char* fee_payer_element = static_element(0, g_feePayerSignatureText, "null", "confirmed");
  for (size_t i = 0; i < sizeof(bad_elements) / sizeof(bad_elements[0]); i++)
  {
    const char* after[] = { fee_payer_element, bad_elements[i] };
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, static_find(200, static_listAnswer(after, 2)), bad_elements[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", g_found, bad_elements[i]);
    const char* before[] = { bad_elements[i], fee_payer_element };
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, static_find(200, static_listAnswer(before, 2)), bad_elements[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", g_found, bad_elements[i]);
  }
}

void test_find_fee_payer_element_before_another_keeps_its_text(void)
{
  const char* elements[] = {
    static_element(0, g_feePayerSignatureText, "null", "confirmed"),
    static_element(1, g_otherSignatureText, "null", "finalized"),
  };
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_CONFIRMED, static_find(200, static_listAnswer(elements, 2)));
  TEST_ASSERT_EQUAL_STRING(g_feePayerSignatureText, g_found);
}

void test_find_list_of_20_elements_is_read(void)
{
  const char* elements[20];
  for (int i = 0; i < 19; i++)
    elements[i] = static_element(i, g_otherSignatureText, "null", "finalized");
  elements[19] = static_element(19, g_feePayerSignatureText, "null", "confirmed");
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_CONFIRMED, static_find(200, static_listAnswer(elements, 20)));
  TEST_ASSERT_EQUAL_STRING(g_feePayerSignatureText, g_found);
}

void test_find_list_of_21_elements_is_unavailable(void)
{
  const char* elements[21];
  elements[0] = static_element(0, g_feePayerSignatureText, "null", "confirmed");
  for (int i = 1; i < 21; i++)
    elements[i] = static_element(i, g_otherSignatureText, "null", "finalized");
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, static_find(200, static_listAnswer(elements, 21)));
  TEST_ASSERT_EQUAL_STRING("", g_found);
}

void test_find_transport_refusals_are_unavailable(void)
{
  const char* elements[] = { static_element(0, g_feePayerSignatureText, "null", "confirmed") };
  const char* good       = static_listAnswer(elements, 1);
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_CONFIRMED, static_find(200, good));

  int statuses[] = { 201, 302, 429, 500 };
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
  {
    TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, static_find(statuses[i], good));
    TEST_ASSERT_EQUAL_STRING("", g_found);
  }

  g_stub_next_error = HTTP_ERROR_TIMEOUT;
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, static_find(200, good));
  TEST_ASSERT_EQUAL_STRING("", g_found);
  g_stub_next_error = HTTP_ERROR_NONE;

  g_stub_next_body_null = true;
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, static_find(200, NULL));
  TEST_ASSERT_EQUAL_STRING("", g_found);
  g_stub_next_body_null = false;

  HttpStubAnswer_t answers[] = { {
    .m_status             = 200,
    .mp_body              = good,
    .m_error              = HTTP_ERROR_NONE,
    .mp_redirectUrl       = NULL,
    .mp_headerLines       = NULL,
    .m_isBodyCut          = true,
    .m_setCookieCopyCount = 0,
  } };
  g_stub_answers      = answers;
  g_stub_answer_count = 1;
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, static_find(200, good));
  TEST_ASSERT_EQUAL_STRING("", g_found);
  g_stub_answers      = NULL;
  g_stub_answer_count = 0;

  char nul_element[ELEMENT_BUF_SIZE];
  int  nul_element_len = snprintf(nul_element, sizeof(nul_element),
                                  R"({"signature":"%s","slot":1,"err":null,"memo":"a#b","confirmationStatus":"confirmed"})",
                                  g_feePayerSignatureText);
  TEST_ASSERT_TRUE(nul_element_len > 0 && (size_t)nul_element_len < sizeof(nul_element));
  const char* nul_elements[] = { nul_element };
  char*       body           = (char*)static_listAnswer(nul_elements, 1);
  size_t      body_len       = strlen(body);
  char*       hash           = strchr(body, '#');
  TEST_ASSERT_NOT_NULL(hash);
  *hash = '|';
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_CONFIRMED, static_find(200, body));
  *hash = '\0';
  g_stub_next_body_byte_count = body_len;
  TEST_ASSERT_EQUAL_INT(X402_SOLANA_RPC_SIGNATURE_UNAVAILABLE, static_find(200, body));
  TEST_ASSERT_EQUAL_STRING("", g_found);
  g_stub_next_body_byte_count = 0;
}

void test_find_writes_nothing_to_stderr(void)
{
  FILE* capture = tmpfile();
  TEST_ASSERT_NOT_NULL(capture);
  fflush(stderr);
  int saved_fd = dup(fileno(stderr));
  TEST_ASSERT_TRUE(saved_fd >= 0);
  TEST_ASSERT_TRUE(dup2(fileno(capture), fileno(stderr)) >= 0);

  (void)static_find(200, R"({"jsonrpc":"2.0","error":{"code":-32602,"message":"message_text"},"id":1})");
  (void)static_find(500, "{");
  g_stub_next_error = HTTP_ERROR_TLS;
  (void)static_find(200, "{}");
  g_stub_next_error = HTTP_ERROR_NONE;
  const char* elements[] = {
    static_element(0, g_otherSignatureText, "null", "confirmed"),
    static_element(1, g_feePayerSignatureText, "null", "confirmed"),
  };
  (void)static_find(200, static_listAnswer(elements, 2));

  fflush(stderr);
  long written = ftell(capture);
  dup2(saved_fd, fileno(stderr));
  close(saved_fd);
  fclose(capture);
  TEST_ASSERT_EQUAL_INT(0, (int)written);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(28, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  g_feePayerKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, FEE_PAYER_SEED, 32);
  g_otherKey    = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, OTHER_SEED, 32);
  if (g_feePayerKey == NULL || g_otherKey == NULL)
    return 1;

  UNITY_BEGIN();
  RUN_TEST(test_request_is_pinned);
  RUN_TEST(test_signature_text_that_does_not_decode_sends_nothing);
  RUN_TEST(test_confirmed_and_finalized_are_confirmed);
  RUN_TEST(test_processed_is_processed);
  RUN_TEST(test_null_element_is_not_found);
  RUN_TEST(test_err_that_is_not_null_is_failed);
  RUN_TEST(test_processed_with_an_err_is_processed);
  RUN_TEST(test_err_with_an_unknown_confirmation_status_is_unavailable);
  RUN_TEST(test_element_that_is_not_the_answer_is_unavailable);
  RUN_TEST(test_envelope_that_is_not_the_answer_is_unavailable);
  RUN_TEST(test_status_other_than_200_or_no_answer_is_unavailable);
  RUN_TEST(test_cut_body_is_unavailable);
  RUN_TEST(test_no_call_writes_to_stderr);
  RUN_TEST(test_find_request_is_pinned);
  RUN_TEST(test_find_confirmed_fee_payer_signature_is_confirmed);
  RUN_TEST(test_find_failed_fee_payer_signature_is_failed);
  RUN_TEST(test_find_processed_fee_payer_signature_is_processed);
  RUN_TEST(test_find_fee_payer_element_of_unknown_status_is_unavailable);
  RUN_TEST(test_find_list_without_fee_payer_signature_is_not_found);
  RUN_TEST(test_find_skips_candidate_that_fails_ed25519);
  RUN_TEST(test_find_envelope_that_is_not_the_answer_is_unavailable);
  RUN_TEST(test_find_element_that_is_not_a_signature_entry_is_unavailable);
  RUN_TEST(test_find_fee_payer_element_before_another_keeps_its_text);
  RUN_TEST(test_find_list_of_20_elements_is_read);
  RUN_TEST(test_find_list_of_21_elements_is_unavailable);
  RUN_TEST(test_find_transport_refusals_are_unavailable);
  RUN_TEST(test_find_writes_nothing_to_stderr);
  RUN_TEST(test_registration_gate_test_count);
  int failures = UNITY_END();

  EVP_PKEY_free(g_feePayerKey);
  EVP_PKEY_free(g_otherKey);
  return failures;
}
