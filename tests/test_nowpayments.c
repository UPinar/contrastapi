#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "unity/unity.h"
#include "external/nowpayments.h"
#include "http_stub.h"

#define TEST_API_KEY   "npKey-31chars_aaaaaaaaaaaaaaaaa"
#define TEST_ORDER_ID  "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d"
#define VALID_URL      "https://nowpayments.io/payment/?iid=5532266"
#define VALID_BODY     "{\"id\":\"5532266\",\"invoice_url\":\"" VALID_URL "\"}"

#define KEY_HEADER_PREFIX     "X-API-Key: "
#define KEY_HEADER_PREFIX_LEN 11

static int  g_keyHeaderClearCount = 0;
static char g_answerBody[2048];

static void static_recordClear(void* bytes, size_t byte_count)
{
  if (byte_count >= KEY_HEADER_PREFIX_LEN && memcmp(bytes, KEY_HEADER_PREFIX, KEY_HEADER_PREFIX_LEN) == 0)
    g_keyHeaderClearCount++;
  memset(bytes, 0, byte_count);
}

void __wrap_explicit_bzero(void* bytes, size_t byte_count);
void __wrap___explicit_bzero_chk(void* bytes, size_t byte_count, size_t buffer_size);

void __wrap_explicit_bzero(void* bytes, size_t byte_count)
{
  static_recordClear(bytes, byte_count);
}

void __wrap___explicit_bzero_chk(void* bytes, size_t byte_count, size_t buffer_size)
{
  (void)buffer_size;
  static_recordClear(bytes, byte_count);
}

void setUp(void)
{
  g_stub_http_call_count = 0;
  g_stub_last_url[0]     = '\0';
  g_stub_last_header[0]  = '\0';
  g_stub_next_status     = 200;
  g_stub_next_body       = VALID_BODY;
  g_stub_next_body_null  = false;
  g_stub_next_error      = HTTP_ERROR_NONE;
  g_stub_last_timeout_ms = 0;
  g_stub_last_max_body_byte_count = 0;
  g_stub_last_is_target_trusted   = false;
  g_keyHeaderClearCount  = 0;
  nowpayments_setApiKey(TEST_API_KEY);
}

void tearDown(void)
{
  nowpayments_setApiKey(NULL);
}

static bool static_create(NowPaymentsInvoice_t* invoice)
{
  memset(invoice, 0xA5, sizeof(*invoice));
  return nowpayments_tryCreateInvoice(TEST_ORDER_ID, invoice);
}

static void static_assertFails(const char* what)
{
  NowPaymentsInvoice_t invoice;
  TEST_ASSERT_FALSE_MESSAGE(static_create(&invoice), what);
  TEST_ASSERT_EQUAL_STRING_MESSAGE("", invoice.ma_id, what);
  TEST_ASSERT_EQUAL_STRING_MESSAGE("", invoice.ma_url, what);
}

static void static_assertIdReads(const char* raw_id, const char* expected)
{
  snprintf(g_answerBody, sizeof(g_answerBody), "{\"id\":%s,\"invoice_url\":\"" VALID_URL "\"}", raw_id);
  g_stub_next_body = g_answerBody;
  NowPaymentsInvoice_t invoice;
  TEST_ASSERT_TRUE_MESSAGE(static_create(&invoice), raw_id);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, invoice.ma_id, raw_id);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(VALID_URL, invoice.ma_url, raw_id);
}

static void static_assertIdRefused(const char* raw_id)
{
  snprintf(g_answerBody, sizeof(g_answerBody), "{\"id\":%s,\"invoice_url\":\"" VALID_URL "\"}", raw_id);
  g_stub_next_body = g_answerBody;
  static_assertFails(raw_id);
}

static void static_setUrlBody(const char* raw_url)
{
  snprintf(g_answerBody, sizeof(g_answerBody), "{\"id\":\"7\",\"invoice_url\":%s}", raw_url);
  g_stub_next_body = g_answerBody;
}

void test_create_invoice_sends_the_request_the_contract_names(void)
{
  NowPaymentsInvoice_t invoice;
  TEST_ASSERT_TRUE(static_create(&invoice));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_TRUE(g_stub_requests[0].m_isPost);
  TEST_ASSERT_EQUAL_STRING("https://api.nowpayments.io/v1/invoice", g_stub_last_url);
  TEST_ASSERT_EQUAL_INT(10000, g_stub_last_timeout_ms);
  TEST_ASSERT_EQUAL_size_t(16384, g_stub_last_max_body_byte_count);
  TEST_ASSERT_TRUE(g_stub_last_is_target_trusted);
  TEST_ASSERT_TRUE(g_stub_requests[0].m_isRedirectLeftToCaller);
  TEST_ASSERT_EQUAL_STRING("X-API-Key: " TEST_API_KEY "\nContent-Type: application/json", g_stub_last_header);
  const char* expected_body =
    "{\"price_amount\":19,\"price_currency\":\"usd\","
    "\"order_id\":\"" TEST_ORDER_ID "\","
    "\"order_description\":\"ContrastAPI Pro 30-day key\","
    "\"ipn_callback_url\":\"https://api.contrastcyber.com/webhook_nowpayments\","
    "\"success_url\":\"https://api.contrastcyber.com/welcome?order_id=" TEST_ORDER_ID "\","
    "\"cancel_url\":\"https://api.contrastcyber.com/pricing\"}";
  TEST_ASSERT_EQUAL_STRING(expected_body, g_stub_last_post_body);
  TEST_ASSERT_EQUAL_size_t(strlen(expected_body), g_stub_last_post_body_byte_count);
  TEST_ASSERT_EQUAL_STRING("5532266", invoice.ma_id);
  TEST_ASSERT_EQUAL_STRING(VALID_URL, invoice.ma_url);
}

void test_key_header_is_cleared_after_success_and_failure(void)
{
  NowPaymentsInvoice_t invoice;
  TEST_ASSERT_TRUE(static_create(&invoice));
  TEST_ASSERT_EQUAL_INT(1, g_keyHeaderClearCount);

  g_stub_next_error = HTTP_ERROR_TIMEOUT;
  TEST_ASSERT_FALSE(static_create(&invoice));
  TEST_ASSERT_EQUAL_INT(2, g_keyHeaderClearCount);
}

void test_no_key_sends_no_request(void)
{
  nowpayments_setApiKey(NULL);
  static_assertFails("no key");
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
}

void test_key_limit_is_128_bytes(void)
{
  char key[130];
  memset(key, 'k', sizeof(key));
  key[128] = '\0';
  nowpayments_setApiKey(key);
  NowPaymentsInvoice_t invoice;
  TEST_ASSERT_TRUE(static_create(&invoice));
  TEST_ASSERT_EQUAL_INT(1, g_stub_http_call_count);
  TEST_ASSERT_NOT_NULL(strstr(g_stub_last_header, key));

  key[128] = 'k';
  key[129] = '\0';
  g_stub_http_call_count = 0;
  static_assertFails("129 bytes");
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
}

void test_order_id_that_is_not_a_uuid_sends_no_request(void)
{
  static const char* const bad_order_ids[] = {
    "",
    "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8",
    "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8dd",
    "5A6B7C8D-9E0F-4A1B-8C2D-3E4F5A6B7C8D",
    "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8\"",
  };
  for (size_t i = 0; i < sizeof(bad_order_ids) / sizeof(bad_order_ids[0]); i++)
  {
    NowPaymentsInvoice_t invoice;
    memset(&invoice, 0xA5, sizeof(invoice));
    TEST_ASSERT_FALSE_MESSAGE(nowpayments_tryCreateInvoice(bad_order_ids[i], &invoice), bad_order_ids[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("", invoice.ma_url, bad_order_ids[i]);
  }
  TEST_ASSERT_EQUAL_INT(0, g_stub_http_call_count);
}

void test_only_a_2xx_answer_succeeds(void)
{
  static const int good_statuses[] = { 200, 201, 299 };
  for (size_t i = 0; i < sizeof(good_statuses) / sizeof(good_statuses[0]); i++)
  {
    NowPaymentsInvoice_t invoice;
    g_stub_next_status = good_statuses[i];
    TEST_ASSERT_TRUE(static_create(&invoice));
  }
  static const int bad_statuses[] = { 199, 300, 403, 500 };
  for (size_t i = 0; i < sizeof(bad_statuses) / sizeof(bad_statuses[0]); i++)
  {
    g_stub_next_status = bad_statuses[i];
    static_assertFails("status");
  }
}

void test_transport_failure_and_no_body_fail(void)
{
  g_stub_next_error = HTTP_ERROR_TIMEOUT;
  static_assertFails("timeout");
  g_stub_next_error = HTTP_ERROR_NONE;
  g_stub_next_body_null = true;
  static_assertFails("no body");
}

void test_unreadable_or_incomplete_body_fails(void)
{
  static const char* const bad_bodies[] = {
    "not json",
    "[1,2]",
    "{\"id\":\"7\"}",
    "{\"invoice_url\":\"" VALID_URL "\"}",
  };
  for (size_t i = 0; i < sizeof(bad_bodies) / sizeof(bad_bodies[0]); i++)
  {
    g_stub_next_body = bad_bodies[i];
    static_assertFails(bad_bodies[i]);
  }
}

void test_id_reads_a_positive_number_or_a_text_up_to_32_bytes(void)
{
  static_assertIdReads("1", "1");
  static_assertIdReads("5532266", "5532266");
  static_assertIdReads("\"x\"", "x");
  static_assertIdReads("\"12345678901234567890123456789012\"", "12345678901234567890123456789012");
}

void test_id_refuses_zero_negative_empty_long_and_other_types(void)
{
  static_assertIdRefused("0");
  static_assertIdRefused("-1");
  static_assertIdRefused("\"\"");
  static_assertIdRefused("\"123456789012345678901234567890123\"");
  static_assertIdRefused("1.5");
  static_assertIdRefused("true");
  static_assertIdRefused("null");
  static_assertIdRefused("[]");
}

void test_invoice_url_outside_the_prefix_fails(void)
{
  static const char* const bad_urls[] = {
    "\"https://nowpayments.io\"",
    "\"http://nowpayments.io/x\"",
    "\"https://nowpayments.io.evil.example/x\"",
    "\"https://evil.example/https://nowpayments.io/\"",
    "\"HTTPS://nowpayments.io/x\"",
    "\"\"",
    "7",
  };
  for (size_t i = 0; i < sizeof(bad_urls) / sizeof(bad_urls[0]); i++)
  {
    static_setUrlBody(bad_urls[i]);
    static_assertFails(bad_urls[i]);
  }
}

void test_invoice_url_length_limit_is_512_bytes(void)
{
  NowPaymentsInvoice_t invoice;
  static_setUrlBody("\"https://nowpayments.io/\"");
  TEST_ASSERT_TRUE(static_create(&invoice));
  TEST_ASSERT_EQUAL_STRING("https://nowpayments.io/", invoice.ma_url);

  char url[514];
  memset(url, 'a', sizeof(url));
  memcpy(url, "https://nowpayments.io/", 23);
  url[512] = '\0';
  char raw_url[520];
  snprintf(raw_url, sizeof(raw_url), "\"%s\"", url);
  static_setUrlBody(raw_url);
  TEST_ASSERT_TRUE(static_create(&invoice));
  TEST_ASSERT_EQUAL_STRING(url, invoice.ma_url);

  url[512] = 'a';
  url[513] = '\0';
  snprintf(raw_url, sizeof(raw_url), "\"%s\"", url);
  static_setUrlBody(raw_url);
  static_assertFails("513 bytes");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_create_invoice_sends_the_request_the_contract_names);
  RUN_TEST(test_key_header_is_cleared_after_success_and_failure);
  RUN_TEST(test_no_key_sends_no_request);
  RUN_TEST(test_key_limit_is_128_bytes);
  RUN_TEST(test_order_id_that_is_not_a_uuid_sends_no_request);
  RUN_TEST(test_only_a_2xx_answer_succeeds);
  RUN_TEST(test_transport_failure_and_no_body_fail);
  RUN_TEST(test_unreadable_or_incomplete_body_fails);
  RUN_TEST(test_id_reads_a_positive_number_or_a_text_up_to_32_bytes);
  RUN_TEST(test_id_refuses_zero_negative_empty_long_and_other_types);
  RUN_TEST(test_invoice_url_outside_the_prefix_fails);
  RUN_TEST(test_invoice_url_length_limit_is_512_bytes);
  return UNITY_END();
}
