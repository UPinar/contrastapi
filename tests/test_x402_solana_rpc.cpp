#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
  g_stub_next_error                = HTTP_ERROR_NONE;
  g_stub_last_timeout_ms           = -1;
  g_stub_last_max_body_byte_count  = 0;
  g_stub_last_is_target_trusted    = false;
  g_stub_last_post_body[0]         = '\0';
  g_stub_last_post_body_byte_count = 0;
  g_stub_last_unix_socket_path[0]  = '\0';
  memset(g_stub_requests, 0, sizeof(g_stub_requests));
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

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(14, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
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
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
