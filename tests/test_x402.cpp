#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity/unity.h"
extern "C" {
#include "jsonbuf.h"
#include "jsonread.h"
#include "x402.h"
}

#define FIXTURE_NETWORK     "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
#define FIXTURE_ASSET       "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
#define FIXTURE_PAY_TO      "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
#define FIXTURE_FEE_PAYER   "2wmVCSfPxGPjrnMMn7rchp4uaeoTqN39mXFC2zhPdri9"
#define FIXTURE_AMOUNT      10000
#define FIXTURE_TIMEOUT     60

#define QUOTED(text) "\"" text "\""

#define FIXTURE_JSON_BUF_SIZE   8192
#define FIXTURE_HEADER_BUF_SIZE (X402_BASE64_LEN(FIXTURE_JSON_BUF_SIZE) + 1)

#define FIXTURE_TRANSACTION_BYTE_COUNT 200

typedef struct {
  const char* mp_version;
  const char* mp_scheme;
  const char* mp_network;
  const char* mp_amount;
  const char* mp_asset;
  const char* mp_payTo;
  const char* mp_maxTimeoutSeconds;
  const char* mp_feePayer;
  const char* mp_transaction;
  const char* mp_acceptedRaw;
  const char* mp_extraRaw;
  const char* mp_payloadRaw;
  const char* mp_topExtraMembers;
  const char* mp_acceptedExtraMembers;
  const char* mp_extraExtraMembers;
  const char* mp_payloadExtraMembers;
  bool        m_isAcceptedLeftOut;
  bool        m_isExtraLeftOut;
  bool        m_isPayloadLeftOut;
} PaymentFields_t;

typedef struct {
  char   ma_text[FIXTURE_JSON_BUF_SIZE];
  size_t m_len;
} FixtureJson_t;

static X402Requirements_t g_requirements;
static uint8_t            g_transactionBytes[X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT + 8];
static char               g_transactionJson[X402_BASE64_LEN(sizeof(g_transactionBytes)) + 3];
static X402Payment_t      g_payment;
static X402Payment_t      g_paymentSentinel;

static const char* static_transactionJson(size_t byte_count)
{
  g_transactionJson[0] = '"';
  TEST_ASSERT_TRUE(x402_tryEncodeBase64(g_transactionBytes, byte_count, g_transactionJson + 1, sizeof(g_transactionJson) - 2));
  size_t text_len = strlen(g_transactionJson);
  g_transactionJson[text_len]     = '"';
  g_transactionJson[text_len + 1] = '\0';
  return g_transactionJson;
}

void setUp(void)
{
  memset(&g_requirements, 0, sizeof(g_requirements));
  snprintf(g_requirements.ma_network,  sizeof(g_requirements.ma_network),  "%s", FIXTURE_NETWORK);
  snprintf(g_requirements.ma_asset,    sizeof(g_requirements.ma_asset),    "%s", FIXTURE_ASSET);
  snprintf(g_requirements.ma_payTo,    sizeof(g_requirements.ma_payTo),    "%s", FIXTURE_PAY_TO);
  snprintf(g_requirements.ma_feePayer, sizeof(g_requirements.ma_feePayer), "%s", FIXTURE_FEE_PAYER);
  g_requirements.m_amountAtomic      = FIXTURE_AMOUNT;
  g_requirements.m_maxTimeoutSeconds = FIXTURE_TIMEOUT;

  for (size_t i = 0; i < sizeof(g_transactionBytes); i++)
    g_transactionBytes[i] = (uint8_t)(i * 131 + 7);

  memset(&g_paymentSentinel, 0xA5, sizeof(g_paymentSentinel));
}

void tearDown(void)
{
}

static PaymentFields_t static_validFields(void)
{
  PaymentFields_t fields;
  memset(&fields, 0, sizeof(fields));
  fields.mp_version           = "2";
  fields.mp_scheme            = QUOTED(X402_SCHEME_EXACT);
  fields.mp_network           = QUOTED(FIXTURE_NETWORK);
  fields.mp_amount            = QUOTED("10000");
  fields.mp_asset             = QUOTED(FIXTURE_ASSET);
  fields.mp_payTo             = QUOTED(FIXTURE_PAY_TO);
  fields.mp_maxTimeoutSeconds = "60";
  fields.mp_feePayer          = QUOTED(FIXTURE_FEE_PAYER);
  fields.mp_transaction       = static_transactionJson(FIXTURE_TRANSACTION_BYTE_COUNT);
  return fields;
}

static void static_append(FixtureJson_t* json, const char* text)
{
  if (text == NULL)
    return;
  size_t text_len = strlen(text);
  TEST_ASSERT_TRUE_MESSAGE(json->m_len + text_len < sizeof(json->ma_text), "fixture JSON buffer too small");
  memcpy(json->ma_text + json->m_len, text, text_len);
  json->m_len += text_len;
  json->ma_text[json->m_len] = '\0';
}

static void static_appendMember(FixtureJson_t* json, bool* is_first, const char* key, const char* raw_value)
{
  if (raw_value == NULL)
    return;
  if (!*is_first)
    static_append(json, ",");
  *is_first = false;
  static_append(json, "\"");
  static_append(json, key);
  static_append(json, "\":");
  static_append(json, raw_value);
}

static void static_writeJson(const PaymentFields_t* fields, FixtureJson_t* json)
{
  FixtureJson_t extra    = {};
  FixtureJson_t accepted = {};
  FixtureJson_t payload  = {};
  bool          is_first = true;

  static_append(&extra, "{");
  static_appendMember(&extra, &is_first, "feePayer", fields->mp_feePayer);
  static_append(&extra, fields->mp_extraExtraMembers);
  static_append(&extra, "}");

  is_first = true;
  static_append(&accepted, "{");
  static_appendMember(&accepted, &is_first, "scheme", fields->mp_scheme);
  static_appendMember(&accepted, &is_first, "network", fields->mp_network);
  static_appendMember(&accepted, &is_first, "amount", fields->mp_amount);
  static_appendMember(&accepted, &is_first, "asset", fields->mp_asset);
  static_appendMember(&accepted, &is_first, "payTo", fields->mp_payTo);
  static_appendMember(&accepted, &is_first, "maxTimeoutSeconds", fields->mp_maxTimeoutSeconds);
  if (!fields->m_isExtraLeftOut)
    static_appendMember(&accepted, &is_first, "extra", fields->mp_extraRaw != NULL ? fields->mp_extraRaw : extra.ma_text);
  static_append(&accepted, fields->mp_acceptedExtraMembers);
  static_append(&accepted, "}");

  is_first = true;
  static_append(&payload, "{");
  static_appendMember(&payload, &is_first, "transaction", fields->mp_transaction);
  static_append(&payload, fields->mp_payloadExtraMembers);
  static_append(&payload, "}");

  json->m_len      = 0;
  json->ma_text[0] = '\0';
  is_first         = true;
  static_append(json, "{");
  static_appendMember(json, &is_first, "x402Version", fields->mp_version);
  static_appendMember(json, &is_first, "resource",
                      R"({"url":"https://api.contrastcyber.com/cve_lookup/","description":"ContrastAPI request","mimeType":"application/json"})");
  if (!fields->m_isAcceptedLeftOut)
    static_appendMember(json, &is_first, "accepted", fields->mp_acceptedRaw != NULL ? fields->mp_acceptedRaw : accepted.ma_text);
  if (!fields->m_isPayloadLeftOut)
    static_appendMember(json, &is_first, "payload", fields->mp_payloadRaw != NULL ? fields->mp_payloadRaw : payload.ma_text);
  static_appendMember(json, &is_first, "extensions", "{}");
  static_append(json, fields->mp_topExtraMembers);
  static_append(json, "}");
}

static void static_padJson(FixtureJson_t* json, size_t target_len)
{
  TEST_ASSERT_TRUE(target_len >= json->m_len && target_len < sizeof(json->ma_text));
  json->m_len--;
  while (json->m_len < target_len - 1)
    json->ma_text[json->m_len++] = ' ';
  json->ma_text[json->m_len++] = '}';
  json->ma_text[json->m_len]   = '\0';
}

static size_t static_encodeHeader(const char* json, size_t json_len, char* header)
{
  TEST_ASSERT_TRUE(x402_tryEncodeBase64((const uint8_t*)json, json_len, header, FIXTURE_HEADER_BUF_SIZE));
  return strlen(header);
}

static X402PaymentStatus_t static_parseHeader(const char* header, size_t header_len)
{
  memcpy(&g_payment, &g_paymentSentinel, sizeof(g_payment));
  X402PaymentStatus_t status = x402_parsePaymentHeader(header, header_len, &g_requirements, &g_payment);
  if (status != X402_PAYMENT_OK)
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(&g_paymentSentinel, &g_payment, sizeof(g_payment), "a refusal wrote payment_out");
  return status;
}

static X402PaymentStatus_t static_parseJson(const FixtureJson_t* json)
{
  static char header[FIXTURE_HEADER_BUF_SIZE];
  size_t header_len = static_encodeHeader(json->ma_text, json->m_len, header);
  return static_parseHeader(header, header_len);
}

static X402PaymentStatus_t static_parseFields(const PaymentFields_t* fields)
{
  static FixtureJson_t json;
  static_writeJson(fields, &json);
  return static_parseJson(&json);
}

static size_t static_validHeader(char* header)
{
  PaymentFields_t      fields = static_validFields();
  static FixtureJson_t json;
  static_writeJson(&fields, &json);
  return static_encodeHeader(json.ma_text, json.m_len, header);
}

void test_payment_required_is_written_byte_for_byte(void)
{
  JsonBuf_t* buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(buf);

  TEST_ASSERT_TRUE(x402_writePaymentRequired(buf, &g_requirements, "https://api.contrastcyber.com/cve_lookup/",
                                             "CVE \\ lookup", "Pay \"first\"\n"));
  char* body = jsonbuf_finish(buf);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL_STRING(
    R"({"x402Version":2,"error":"Pay \"first\"\n",)"
    R"("resource":{"url":"https://api.contrastcyber.com/cve_lookup/","description":"CVE \\ lookup","mimeType":"application/json"},)"
    R"("accepts":[{"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","amount":"10000",)"
    R"("asset":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","payTo":"9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",)"
    R"("maxTimeoutSeconds":60,"extra":{"feePayer":"2wmVCSfPxGPjrnMMn7rchp4uaeoTqN39mXFC2zhPdri9"}}]})",
    body);
  free(body);
  jsonbuf_destroy(buf);
}

void test_payment_required_writes_the_largest_amount_and_timeout_in_full(void)
{
  g_requirements.m_amountAtomic      = UINT64_MAX;
  g_requirements.m_maxTimeoutSeconds = UINT32_MAX;
  JsonBuf_t* buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(buf);

  TEST_ASSERT_TRUE(x402_writePaymentRequired(buf, &g_requirements, "u", "d", "e"));
  char* body = jsonbuf_finish(buf);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_NOT_NULL(strstr(body, R"("amount":"18446744073709551615",)"));
  TEST_ASSERT_NOT_NULL(strstr(body, R"("maxTimeoutSeconds":4294967295,)"));
  free(body);
  jsonbuf_destroy(buf);
}

void test_payment_required_refuses_when_the_ceiling_is_reached(void)
{
  JsonBuf_t* buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_TRUE(x402_writePaymentRequired(buf, &g_requirements, "u", "d", "e"));
  char* body = jsonbuf_finish(buf);
  TEST_ASSERT_NOT_NULL(body);
  size_t body_len = strlen(body);
  free(body);
  jsonbuf_destroy(buf);

  JsonBuf_t* fitting_buf = jsonbuf_create(16, body_len + 1);
  TEST_ASSERT_NOT_NULL(fitting_buf);
  TEST_ASSERT_TRUE(x402_writePaymentRequired(fitting_buf, &g_requirements, "u", "d", "e"));
  char* fitting_body = jsonbuf_finish(fitting_buf);
  TEST_ASSERT_NOT_NULL(fitting_body);
  TEST_ASSERT_EQUAL_size_t(body_len, strlen(fitting_body));
  free(fitting_body);
  jsonbuf_destroy(fitting_buf);

  JsonBuf_t* short_buf = jsonbuf_create(16, body_len);
  TEST_ASSERT_NOT_NULL(short_buf);
  TEST_ASSERT_FALSE(x402_writePaymentRequired(short_buf, &g_requirements, "u", "d", "e"));
  jsonbuf_destroy(short_buf);
}

void test_requirements_are_written_byte_for_byte(void)
{
  JsonBuf_t* buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_TRUE(x402_writePaymentRequirements(buf, &g_requirements));
  char* body = jsonbuf_finish(buf);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL_STRING(
    R"({"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","amount":"10000",)"
    R"("asset":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","payTo":"9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",)"
    R"("maxTimeoutSeconds":60,"extra":{"feePayer":"2wmVCSfPxGPjrnMMn7rchp4uaeoTqN39mXFC2zhPdri9"}})",
    body);
  free(body);
  jsonbuf_destroy(buf);

  snprintf(g_requirements.ma_network, sizeof(g_requirements.ma_network), "%s", "a\"b");
  buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_TRUE(x402_writePaymentRequirements(buf, &g_requirements));
  body = jsonbuf_finish(buf);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_NOT_NULL(strstr(body, R"("network":"a\"b",)"));
  free(body);
  jsonbuf_destroy(buf);
}

void test_requirements_refuse_when_the_ceiling_is_reached(void)
{
  JsonBuf_t* buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(buf);
  TEST_ASSERT_TRUE(x402_writePaymentRequirements(buf, &g_requirements));
  char* body = jsonbuf_finish(buf);
  TEST_ASSERT_NOT_NULL(body);
  size_t body_len = strlen(body);
  free(body);
  jsonbuf_destroy(buf);

  JsonBuf_t* fitting_buf = jsonbuf_create(16, body_len + 1);
  TEST_ASSERT_NOT_NULL(fitting_buf);
  TEST_ASSERT_TRUE(x402_writePaymentRequirements(fitting_buf, &g_requirements));
  char* fitting_body = jsonbuf_finish(fitting_buf);
  TEST_ASSERT_NOT_NULL(fitting_body);
  TEST_ASSERT_EQUAL_size_t(body_len, strlen(fitting_body));
  free(fitting_body);
  jsonbuf_destroy(fitting_buf);

  JsonBuf_t* short_buf = jsonbuf_create(16, body_len);
  TEST_ASSERT_NOT_NULL(short_buf);
  TEST_ASSERT_FALSE(x402_writePaymentRequirements(short_buf, &g_requirements));
  jsonbuf_destroy(short_buf);
}

#define FIXTURE_SIGNATURE "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW"

void test_settlement_response_is_written_byte_for_byte(void)
{
  JsonBuf_t* buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(buf);

  TEST_ASSERT_TRUE(x402_writeSettlementResponse(buf, FIXTURE_NETWORK, FIXTURE_SIGNATURE));
  char* body = jsonbuf_finish(buf);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL_STRING(
    R"({"success":true,"transaction":"5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW",)"
    R"("network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"})",
    body);
  free(body);
  jsonbuf_destroy(buf);
}

void test_settlement_response_escapes_its_texts(void)
{
  JsonBuf_t* buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  TEST_ASSERT_NOT_NULL(buf);

  TEST_ASSERT_TRUE(x402_writeSettlementResponse(buf, "a\"b\\c", "s\"t"));
  char* body = jsonbuf_finish(buf);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL_STRING(R"({"success":true,"transaction":"s\"t","network":"a\"b\\c"})", body);
  free(body);
  jsonbuf_destroy(buf);
}

void test_settlement_response_refuses_when_the_ceiling_is_reached(void)
{
  size_t body_len = strlen(R"({"success":true,"transaction":"sig","network":"net"})");

  JsonBuf_t* fitting_buf = jsonbuf_create(16, body_len + 1);
  TEST_ASSERT_NOT_NULL(fitting_buf);
  TEST_ASSERT_TRUE(x402_writeSettlementResponse(fitting_buf, "net", "sig"));
  char* fitting_body = jsonbuf_finish(fitting_buf);
  TEST_ASSERT_NOT_NULL(fitting_body);
  TEST_ASSERT_EQUAL_STRING(R"({"success":true,"transaction":"sig","network":"net"})", fitting_body);
  free(fitting_body);
  jsonbuf_destroy(fitting_buf);

  JsonBuf_t* short_buf = jsonbuf_create(16, body_len);
  TEST_ASSERT_NOT_NULL(short_buf);
  TEST_ASSERT_FALSE(x402_writeSettlementResponse(short_buf, "net", "sig"));
  jsonbuf_destroy(short_buf);
}

void test_encode_base64_matches_the_rfc_4648_vectors(void)
{
  static const struct { const char* mp_bytes; const char* mp_text; } vectors[] = {
    { "", "" }, { "f", "Zg==" }, { "fo", "Zm8=" }, { "foo", "Zm9v" },
    { "foob", "Zm9vYg==" }, { "fooba", "Zm9vYmE=" }, { "foobar", "Zm9vYmFy" },
  };
  for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++)
  {
    char text[16];
    memset(text, 'X', sizeof(text));
    size_t out_size = strlen(vectors[i].mp_text) + 1;
    TEST_ASSERT_TRUE(x402_tryEncodeBase64((const uint8_t*)vectors[i].mp_bytes, strlen(vectors[i].mp_bytes), text, out_size));
    TEST_ASSERT_EQUAL_STRING(vectors[i].mp_text, text);
  }
}

void test_encode_base64_refuses_a_buffer_one_byte_short(void)
{
  char text[16];
  memset(text, 'X', sizeof(text));
  TEST_ASSERT_FALSE(x402_tryEncodeBase64((const uint8_t*)"f", 1, text, 4));
  TEST_ASSERT_EQUAL_STRING("", text);

  memset(text, 'X', sizeof(text));
  TEST_ASSERT_FALSE(x402_tryEncodeBase64((const uint8_t*)"foobar", 6, text, 8));
  TEST_ASSERT_EQUAL_STRING("", text);

  memset(text, 'X', sizeof(text));
  TEST_ASSERT_FALSE(x402_tryEncodeBase64((const uint8_t*)"", 0, text, 0));
  TEST_ASSERT_EQUAL_HEX8('X', (uint8_t)text[0]);
}

void test_valid_payload_is_ok_and_hands_on_the_transaction(void)
{
  PaymentFields_t fields = static_validFields();
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_OK, static_parseFields(&fields));
  TEST_ASSERT_EQUAL_size_t(FIXTURE_TRANSACTION_BYTE_COUNT, g_payment.m_transactionByteCount);
  TEST_ASSERT_EQUAL_MEMORY(g_transactionBytes, g_payment.ma_transaction, FIXTURE_TRANSACTION_BYTE_COUNT);
  for (size_t i = FIXTURE_TRANSACTION_BYTE_COUNT; i < X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT; i++)
    TEST_ASSERT_EQUAL_HEX8(0, g_payment.ma_transaction[i]);
}

__attribute__((noinline)) static void static_dirtyStack(void)
{
  volatile uint8_t dirt[32768];
  for (size_t i = 0; i < sizeof(dirt); i++)
    dirt[i] = 0xA5;
}

void test_transaction_of_1_to_1232_bytes_is_ok(void)
{
  static const size_t byte_counts[] = { 1, 2, 3, 1231, X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT };
  for (size_t i = 0; i < sizeof(byte_counts) / sizeof(byte_counts[0]); i++)
  {
    PaymentFields_t fields = static_validFields();
    fields.mp_transaction  = static_transactionJson(byte_counts[i]);
    TEST_ASSERT_EQUAL_INT(X402_PAYMENT_OK, static_parseFields(&fields));
    TEST_ASSERT_EQUAL_size_t(byte_counts[i], g_payment.m_transactionByteCount);
    TEST_ASSERT_EQUAL_MEMORY(g_transactionBytes, g_payment.ma_transaction, byte_counts[i]);
  }
  PaymentFields_t fields = static_validFields();
  fields.mp_transaction  = static_transactionJson(1);
  static FixtureJson_t json;
  static char          header[FIXTURE_HEADER_BUF_SIZE];
  static_writeJson(&fields, &json);
  size_t header_len = static_encodeHeader(json.ma_text, json.m_len, header);
  static_dirtyStack();
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_OK, x402_parsePaymentHeader(header, header_len, &g_requirements, &g_payment));
  for (size_t i = 1; i < X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT; i++)
    TEST_ASSERT_EQUAL_HEX8(0, g_payment.ma_transaction[i]);
}

void test_transaction_with_an_escaped_slash_is_ok(void)
{
  g_transactionBytes[0] = 0xFF;
  g_transactionBytes[1] = 0xFF;
  g_transactionBytes[2] = 0xFF;
  PaymentFields_t fields = static_validFields();
  fields.mp_transaction  = QUOTED("\\/\\/\\/\\/");
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_OK, static_parseFields(&fields));
  TEST_ASSERT_EQUAL_size_t(3, g_payment.m_transactionByteCount);
  TEST_ASSERT_EQUAL_MEMORY(g_transactionBytes, g_payment.ma_transaction, 3);
}

void test_unknown_keys_are_ignored(void)
{
  PaymentFields_t fields         = static_validFields();
  fields.mp_topExtraMembers      = R"(,"x402Versions":1,"acceptedX":[1,{"a":null}],"payloads":"x")";
  fields.mp_acceptedExtraMembers = R"(,"description":"d","amountX":"1","schemes":"upto")";
  fields.mp_extraExtraMembers    = R"(,"memo":"m","feePayers":"x")";
  fields.mp_payloadExtraMembers  = R"(,"signature":"s","transactions":1)";
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_OK, static_parseFields(&fields));
}

void test_amount_of_the_largest_atomic_value_is_ok(void)
{
  g_requirements.m_amountAtomic = UINT64_MAX;
  PaymentFields_t fields = static_validFields();
  fields.mp_amount       = QUOTED("18446744073709551615");
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_OK, static_parseFields(&fields));
}

void test_empty_value_is_malformed(void)
{
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseHeader("", 0));
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseHeader(NULL, 0));
}

void test_json_over_the_cap_is_malformed(void)
{
  PaymentFields_t      fields = static_validFields();
  static FixtureJson_t json;
  static char          header[FIXTURE_HEADER_BUF_SIZE];

  static_writeJson(&fields, &json);
  static_padJson(&json, 2559);
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_OK, static_parseJson(&json));

  static_writeJson(&fields, &json);
  static_padJson(&json, 2560);
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_OK, static_parseJson(&json));

  static_writeJson(&fields, &json);
  static_padJson(&json, 2561);
  TEST_ASSERT_EQUAL_size_t(3416, static_encodeHeader(json.ma_text, json.m_len, header));
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseJson(&json));
}

void test_header_over_the_cap_is_malformed(void)
{
  TEST_ASSERT_EQUAL_INT(3416, X402_PAYMENT_HEADER_MAX_LEN);

  PaymentFields_t      fields = static_validFields();
  static FixtureJson_t json;
  static char          header[FIXTURE_HEADER_BUF_SIZE];
  static_writeJson(&fields, &json);
  static_padJson(&json, 2560);
  size_t header_len = static_encodeHeader(json.ma_text, json.m_len, header);
  TEST_ASSERT_EQUAL_size_t(X402_PAYMENT_HEADER_MAX_LEN, header_len);
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_OK, static_parseHeader(header, header_len));

  memcpy(header + header_len, "AAAA", 5);
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseHeader(header, header_len + 1));
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseHeader(header, header_len + 4));
}

static size_t static_validHeaderWithInsertion(char inserted, char* header)
{
  size_t header_len = static_validHeader(header);
  memmove(header + 12, header + 8, header_len - 8 + 1);
  memset(header + 8, inserted, 4);
  return header_len + 4;
}

void test_header_with_a_byte_outside_the_alphabet_is_malformed(void)
{
  static const char replacements[] = { '-', '_', '.', (char)0x80, '\0', '@', '[', '`', '{' };
  static char header[FIXTURE_HEADER_BUF_SIZE];
  for (size_t i = 0; i < sizeof(replacements); i++)
  {
    size_t header_len = static_validHeaderWithInsertion(replacements[i], header);
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_PAYMENT_MALFORMED, static_parseHeader(header, header_len), "byte outside the alphabet");
  }
}

void test_header_with_whitespace_is_malformed(void)
{
  static const char replacements[] = { ' ', '\t', '\r', '\n' };
  static char header[FIXTURE_HEADER_BUF_SIZE];
  for (size_t i = 0; i < sizeof(replacements); i++)
  {
    size_t header_len = static_validHeaderWithInsertion(replacements[i], header);
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_PAYMENT_MALFORMED, static_parseHeader(header, header_len), "whitespace");
  }
}

void test_header_with_padding_before_the_end_is_malformed(void)
{
  static char header[FIXTURE_HEADER_BUF_SIZE];
  size_t      header_len = static_validHeader(header);
  header[8] = '=';
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseHeader(header, header_len));

  header_len = static_validHeader(header);
  header[header_len - 4] = '=';
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseHeader(header, header_len));
}

void test_header_with_three_or_four_padding_bytes_is_malformed(void)
{
  PaymentFields_t      fields = static_validFields();
  static FixtureJson_t json;
  static char          header[FIXTURE_HEADER_BUF_SIZE];
  static_writeJson(&fields, &json);
  static_padJson(&json, json.m_len + (3 - json.m_len % 3) % 3 + 1);
  size_t header_len = static_encodeHeader(json.ma_text, json.m_len, header);
  TEST_ASSERT_EQUAL_STRING("==", header + header_len - 2);
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_OK, static_parseHeader(header, header_len));

  header[header_len - 3] = '=';
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseHeader(header, header_len));

  memcpy(header + header_len - 4, "====", 4);
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseHeader(header, header_len));
}

void test_header_whose_length_is_not_a_multiple_of_4_is_malformed(void)
{
  PaymentFields_t      fields = static_validFields();
  static FixtureJson_t json;
  static char          header[FIXTURE_HEADER_BUF_SIZE];
  static_writeJson(&fields, &json);
  static_padJson(&json, json.m_len + (3 - json.m_len % 3) % 3 + 1);
  size_t header_len = static_encodeHeader(json.ma_text, json.m_len, header);
  TEST_ASSERT_EQUAL_STRING("==", header + header_len - 2);
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_OK, static_parseHeader(header, header_len));
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseHeader(header, header_len - 2));
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseHeader(header, header_len - 1));

  static char transaction_json[16];
  static_transactionJson(1);
  TEST_ASSERT_EQUAL_STRING("\"Bw==\"", g_transactionJson);
  snprintf(transaction_json, sizeof(transaction_json), "%s", "\"Bw\"");
  fields                = static_validFields();
  fields.mp_transaction = transaction_json;
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseFields(&fields));
}

void test_json_holding_a_nul_byte_is_malformed(void)
{
  PaymentFields_t      fields = static_validFields();
  static FixtureJson_t json;
  static_writeJson(&fields, &json);
  static_padJson(&json, json.m_len + 2);
  json.ma_text[json.m_len - 2] = '\0';
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseJson(&json));
}

void test_json_that_is_not_an_object_is_malformed(void)
{
  PaymentFields_t      fields = static_validFields();
  static FixtureJson_t json;
  static FixtureJson_t wrapped;
  static_writeJson(&fields, &json);
  wrapped.m_len = 0;
  static_append(&wrapped, "[");
  static_append(&wrapped, json.ma_text);
  static_append(&wrapped, "]");
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseJson(&wrapped));

  json.ma_text[--json.m_len] = '\0';
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseJson(&json));
}

void test_json_nested_deeper_than_the_limit_is_malformed(void)
{
  char nested[2 * JSONREAD_MAX_DEPTH + 16];
  for (size_t extra_depth = 0; extra_depth < 2; extra_depth++)
  {
    size_t array_count = JSONREAD_MAX_DEPTH - 1 + extra_depth;
    size_t len         = 0;
    nested[len++] = ',';
    memcpy(nested + len, "\"deep\":", 7);
    len += 7;
    for (size_t i = 0; i < array_count; i++)
      nested[len++] = '[';
    for (size_t i = 0; i < array_count; i++)
      nested[len++] = ']';
    nested[len] = '\0';

    PaymentFields_t fields    = static_validFields();
    fields.mp_topExtraMembers = nested;
    TEST_ASSERT_EQUAL_INT(extra_depth == 0 ? X402_PAYMENT_OK : X402_PAYMENT_MALFORMED, static_parseFields(&fields));
  }
}

void test_missing_version_is_malformed(void)
{
  PaymentFields_t fields = static_validFields();
  fields.mp_version      = NULL;
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseFields(&fields));
}

void test_version_that_is_not_an_integer_is_malformed(void)
{
  static const char* versions[] = { QUOTED("2"), "2.0", "2.5", "2e0", "null", "true", "{}", "99999999999999999999" };
  for (size_t i = 0; i < sizeof(versions) / sizeof(versions[0]); i++)
  {
    PaymentFields_t fields = static_validFields();
    fields.mp_version      = versions[i];
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_PAYMENT_MALFORMED, static_parseFields(&fields), versions[i]);
  }
}

void test_missing_accepted_is_malformed(void)
{
  PaymentFields_t fields   = static_validFields();
  fields.m_isAcceptedLeftOut = true;
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseFields(&fields));
}

void test_accepted_that_is_not_an_object_is_malformed(void)
{
  static const char* values[] = { QUOTED("{}"), "[]", "null", "1" };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    PaymentFields_t fields = static_validFields();
    fields.mp_acceptedRaw  = values[i];
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_PAYMENT_MALFORMED, static_parseFields(&fields), values[i]);
  }
}

void test_missing_payload_is_malformed(void)
{
  PaymentFields_t fields    = static_validFields();
  fields.m_isPayloadLeftOut = true;
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseFields(&fields));
}

void test_payload_that_is_not_an_object_is_malformed(void)
{
  static const char* values[] = { QUOTED("{}"), "[]", "null", "1" };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    PaymentFields_t fields = static_validFields();
    fields.mp_payloadRaw   = values[i];
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_PAYMENT_MALFORMED, static_parseFields(&fields), values[i]);
  }
}

void test_missing_transaction_is_malformed(void)
{
  PaymentFields_t fields = static_validFields();
  fields.mp_transaction  = NULL;
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseFields(&fields));
}

void test_transaction_that_is_not_a_string_is_malformed(void)
{
  static const char* values[] = { "1", "{}", "[]", "null", "true" };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    PaymentFields_t fields = static_validFields();
    fields.mp_transaction  = values[i];
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_PAYMENT_MALFORMED, static_parseFields(&fields), values[i]);
  }
}

void test_transaction_that_is_not_strict_base64_is_malformed(void)
{
  static const char* values[] = {
    QUOTED("AAA-"), QUOTED("AA A"), QUOTED("A=AA"), QUOTED("AAAAA"), QUOTED("A==="), QUOTED("AAA\\u0000"),
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    PaymentFields_t fields = static_validFields();
    fields.mp_transaction  = values[i];
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_PAYMENT_MALFORMED, static_parseFields(&fields), values[i]);
  }
}

void test_transaction_of_0_bytes_is_malformed(void)
{
  PaymentFields_t fields = static_validFields();
  fields.mp_transaction  = QUOTED("");
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseFields(&fields));
}

void test_transaction_over_1232_bytes_is_malformed(void)
{
  TEST_ASSERT_EQUAL_INT(X402_BASE64_LEN(X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT), X402_BASE64_LEN(X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT + 1));
  static const size_t byte_counts[] = { X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT + 1, X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT + 2 };
  for (size_t i = 0; i < sizeof(byte_counts) / sizeof(byte_counts[0]); i++)
  {
    PaymentFields_t fields = static_validFields();
    fields.mp_transaction  = static_transactionJson(byte_counts[i]);
    TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseFields(&fields));
  }
}

void test_duplicate_top_level_key_is_malformed(void)
{
  PaymentFields_t valid = static_validFields();
  static FixtureJson_t valid_json;
  static_writeJson(&valid, &valid_json);

  static char accepted_member[FIXTURE_JSON_BUF_SIZE];
  static char payload_member[FIXTURE_JSON_BUF_SIZE];
  const char* accepted_start = strstr(valid_json.ma_text, R"("accepted":)");
  const char* payload_start  = strstr(valid_json.ma_text, R"("payload":)");
  const char* payload_end    = strstr(valid_json.ma_text, R"(,"extensions")");
  TEST_ASSERT_NOT_NULL(accepted_start);
  TEST_ASSERT_NOT_NULL(payload_start);
  TEST_ASSERT_NOT_NULL(payload_end);
  snprintf(accepted_member, sizeof(accepted_member), ",%.*s", (int)(payload_start - 1 - accepted_start), accepted_start);
  snprintf(payload_member, sizeof(payload_member), ",%.*s", (int)(payload_end - payload_start), payload_start);

  const char* duplicates[] = { R"(,"x402Version":2)", accepted_member, payload_member };
  for (size_t i = 0; i < sizeof(duplicates) / sizeof(duplicates[0]); i++)
  {
    PaymentFields_t fields    = static_validFields();
    fields.mp_topExtraMembers = duplicates[i];
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_PAYMENT_MALFORMED, static_parseFields(&fields), duplicates[i]);
  }
}

void test_duplicate_accepted_key_is_malformed(void)
{
  static const char* duplicates[] = {
    R"(,"scheme":"exact")", R"(,"network":")" FIXTURE_NETWORK R"(")", R"(,"amount":"10000")",
    R"(,"asset":")" FIXTURE_ASSET R"(")", R"(,"payTo":")" FIXTURE_PAY_TO R"(")",
    R"(,"maxTimeoutSeconds":60)", R"(,"extra":{"feePayer":")" FIXTURE_FEE_PAYER R"("})",
  };
  for (size_t i = 0; i < sizeof(duplicates) / sizeof(duplicates[0]); i++)
  {
    PaymentFields_t fields         = static_validFields();
    fields.mp_acceptedExtraMembers = duplicates[i];
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_PAYMENT_MALFORMED, static_parseFields(&fields), duplicates[i]);
  }
}

void test_duplicate_fee_payer_or_transaction_is_malformed(void)
{
  PaymentFields_t fields      = static_validFields();
  fields.mp_extraExtraMembers = R"(,"feePayer":")" FIXTURE_FEE_PAYER R"(")";
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseFields(&fields));

  static char transaction_member[sizeof(g_transactionJson) + 32];
  fields = static_validFields();
  snprintf(transaction_member, sizeof(transaction_member), ",\"transaction\":%s", fields.mp_transaction);
  fields.mp_payloadExtraMembers = transaction_member;
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseFields(&fields));
}

void test_escaped_key_in_an_object_that_is_read_is_malformed(void)
{
  PaymentFields_t fields    = static_validFields();
  fields.mp_topExtraMembers = R"(,"x402Versio\u006e":2)";
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseFields(&fields));

  fields                         = static_validFields();
  fields.mp_acceptedExtraMembers = R"(,"amoun\u0074":"1")";
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseFields(&fields));

  fields                      = static_validFields();
  fields.mp_extraExtraMembers = R"(,"feePaye\u0072":"x")";
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseFields(&fields));

  fields                        = static_validFields();
  fields.mp_payloadExtraMembers = R"(,"transactio\u006e":"AAAA")";
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseFields(&fields));
}

void test_version_other_than_2_is_not_accepted(void)
{
  static const char* versions[] = { "1", "3", "0", "-2" };
  for (size_t i = 0; i < sizeof(versions) / sizeof(versions[0]); i++)
  {
    PaymentFields_t fields = static_validFields();
    fields.mp_version      = versions[i];
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_PAYMENT_NOT_ACCEPTED, static_parseFields(&fields), versions[i]);
  }
}

void test_scheme_other_than_exact_is_not_accepted(void)
{
  static const char* schemes[] = { QUOTED("exac"), QUOTED("exactt"), QUOTED("Exact"), QUOTED("upto"), "1", NULL };
  for (size_t i = 0; i < sizeof(schemes) / sizeof(schemes[0]); i++)
  {
    PaymentFields_t fields = static_validFields();
    fields.mp_scheme       = schemes[i];
    TEST_ASSERT_EQUAL_INT(X402_PAYMENT_NOT_ACCEPTED, static_parseFields(&fields));
  }
}

static void static_assertChangedTextNotAccepted(size_t member_offset, const char* text)
{
  static char changed[6][128];
  size_t      text_len = strlen(text);
  snprintf(changed[0], sizeof(changed[0]), "\"%c%s\"", text[0] == 'Z' ? 'Y' : 'Z', text + 1);
  snprintf(changed[1], sizeof(changed[1]), "\"%.*s%c\"", (int)(text_len - 1), text, text[text_len - 1] == 'Z' ? 'Y' : 'Z');
  snprintf(changed[2], sizeof(changed[2]), "\"%.*s\"", (int)(text_len - 1), text);
  snprintf(changed[3], sizeof(changed[3]), "\"%sZ\"", text);
  snprintf(changed[4], sizeof(changed[4]), "1");
  for (size_t i = 0; i < 6; i++)
  {
    PaymentFields_t fields = static_validFields();
    const char**    member = (const char**)((char*)&fields + member_offset);
    *member = (i < 5) ? changed[i] : NULL;
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_PAYMENT_NOT_ACCEPTED, static_parseFields(&fields), i < 5 ? changed[i] : "left out");
  }
}

void test_network_other_than_ours_is_not_accepted(void)
{
  static_assertChangedTextNotAccepted(offsetof(PaymentFields_t, mp_network), FIXTURE_NETWORK);
}

void test_network_of_the_longest_length_is_ok(void)
{
  char network[sizeof(g_requirements.ma_network)];
  memset(network, 'n', sizeof(network) - 1);
  network[sizeof(network) - 1] = '\0';
  memcpy(g_requirements.ma_network, network, sizeof(network));

  char network_json[sizeof(network) + 4];
  snprintf(network_json, sizeof(network_json), "\"%s\"", network);
  PaymentFields_t fields = static_validFields();
  fields.mp_network      = network_json;
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_OK, static_parseFields(&fields));

  snprintf(network_json, sizeof(network_json), "\"%sn\"", network);
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_NOT_ACCEPTED, static_parseFields(&fields));
}

void test_asset_other_than_ours_is_not_accepted(void)
{
  static_assertChangedTextNotAccepted(offsetof(PaymentFields_t, mp_asset), FIXTURE_ASSET);
}

void test_pay_to_other_than_ours_is_not_accepted(void)
{
  static_assertChangedTextNotAccepted(offsetof(PaymentFields_t, mp_payTo), FIXTURE_PAY_TO);
}

void test_fee_payer_other_than_ours_is_not_accepted(void)
{
  static_assertChangedTextNotAccepted(offsetof(PaymentFields_t, mp_feePayer), FIXTURE_FEE_PAYER);
}

void test_extra_that_is_missing_or_not_an_object_is_not_accepted(void)
{
  PaymentFields_t fields  = static_validFields();
  fields.m_isExtraLeftOut = true;
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_NOT_ACCEPTED, static_parseFields(&fields));

  static const char* values[] = { QUOTED(FIXTURE_FEE_PAYER), "[]", "null" };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
  {
    fields             = static_validFields();
    fields.mp_extraRaw = values[i];
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_PAYMENT_NOT_ACCEPTED, static_parseFields(&fields), values[i]);
  }
}

void test_amount_other_than_the_canonical_decimal_is_not_accepted(void)
{
  static const char* amounts[] = {
    QUOTED("010000"), QUOTED("10000.0"), QUOTED("1e4"), QUOTED("+10000"), QUOTED(" 10000"),
    QUOTED("9999"), QUOTED("10001"), QUOTED(""), "10000", NULL,
  };
  for (size_t i = 0; i < sizeof(amounts) / sizeof(amounts[0]); i++)
  {
    PaymentFields_t fields = static_validFields();
    fields.mp_amount       = amounts[i];
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_PAYMENT_NOT_ACCEPTED, static_parseFields(&fields), amounts[i] != NULL ? amounts[i] : "left out");
  }
}

void test_timeout_other_than_ours_is_not_accepted(void)
{
  g_requirements.m_maxTimeoutSeconds = 0;
  static const char* zero_timeouts[] = { "0", QUOTED("0"), NULL };
  for (size_t i = 0; i < sizeof(zero_timeouts) / sizeof(zero_timeouts[0]); i++)
  {
    PaymentFields_t fields      = static_validFields();
    fields.mp_maxTimeoutSeconds = zero_timeouts[i];
    TEST_ASSERT_EQUAL_INT(i == 0 ? X402_PAYMENT_OK : X402_PAYMENT_NOT_ACCEPTED, static_parseFields(&fields));
  }
  g_requirements.m_maxTimeoutSeconds = FIXTURE_TIMEOUT;

  static const char* timeouts[] = { "59", "61", QUOTED("60"), "60.0", NULL };
  for (size_t i = 0; i < sizeof(timeouts) / sizeof(timeouts[0]); i++)
  {
    PaymentFields_t fields       = static_validFields();
    fields.mp_maxTimeoutSeconds  = timeouts[i];
    TEST_ASSERT_EQUAL_INT_MESSAGE(X402_PAYMENT_NOT_ACCEPTED, static_parseFields(&fields), timeouts[i] != NULL ? timeouts[i] : "left out");
  }
}

void test_malformed_wins_over_not_accepted(void)
{
  PaymentFields_t fields    = static_validFields();
  fields.mp_version         = "1";
  fields.m_isPayloadLeftOut = true;
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseFields(&fields));

  fields                = static_validFields();
  fields.mp_amount      = QUOTED("1");
  fields.mp_transaction = QUOTED("");
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseFields(&fields));

  fields                         = static_validFields();
  fields.mp_network              = QUOTED("solana:devnet");
  fields.mp_acceptedExtraMembers = R"(,"payTo":")" FIXTURE_PAY_TO R"(")";
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseFields(&fields));

  fields                      = static_validFields();
  fields.mp_scheme            = QUOTED("upto");
  fields.mp_extraExtraMembers = R"(,"feePayer":")" FIXTURE_FEE_PAYER R"(")";
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseFields(&fields));

  static const char* const dup_fee_payer = R"(,"feePayer":")" FIXTURE_FEE_PAYER R"(")";
  fields                      = static_validFields();
  fields.mp_payTo             = QUOTED("someone-else");
  fields.mp_extraExtraMembers = dup_fee_payer;
  TEST_ASSERT_EQUAL_INT_MESSAGE(X402_PAYMENT_MALFORMED, static_parseFields(&fields), "payTo");
  fields                      = static_validFields();
  fields.mp_amount            = QUOTED("1");
  fields.mp_extraExtraMembers = dup_fee_payer;
  TEST_ASSERT_EQUAL_INT_MESSAGE(X402_PAYMENT_MALFORMED, static_parseFields(&fields), "amount");
  fields                      = static_validFields();
  fields.mp_maxTimeoutSeconds = "1";
  fields.mp_extraExtraMembers = dup_fee_payer;
  TEST_ASSERT_EQUAL_INT_MESSAGE(X402_PAYMENT_MALFORMED, static_parseFields(&fields), "timeout");
}

static X402PaymentStatus_t static_parseRawJson(const char* json, size_t json_len)
{
  memcpy(&g_payment, &g_paymentSentinel, sizeof(g_payment));
  X402PaymentStatus_t status = x402_parsePaymentJson(json, json_len, &g_requirements, &g_payment);
  if (status != X402_PAYMENT_OK)
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(&g_paymentSentinel, &g_payment, sizeof(g_payment), "a refusal wrote payment_out");
  return status;
}

void test_parsePaymentJson_accepts_the_payload_the_header_form_accepts(void)
{
  PaymentFields_t      fields = static_validFields();
  static FixtureJson_t json;
  static_writeJson(&fields, &json);

  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_OK, static_parseRawJson(json.ma_text, json.m_len));
  TEST_ASSERT_EQUAL_size_t(FIXTURE_TRANSACTION_BYTE_COUNT, g_payment.m_transactionByteCount);
  TEST_ASSERT_EQUAL_MEMORY(g_transactionBytes, g_payment.ma_transaction, FIXTURE_TRANSACTION_BYTE_COUNT);
  for (size_t i = FIXTURE_TRANSACTION_BYTE_COUNT; i < X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT; i++)
    TEST_ASSERT_EQUAL_HEX8(0, g_payment.ma_transaction[i]);

  static X402Payment_t raw_payment;
  memcpy(&raw_payment, &g_payment, sizeof(raw_payment));
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_OK, static_parseJson(&json));
  TEST_ASSERT_EQUAL_MEMORY(&raw_payment, &g_payment, sizeof(g_payment));
}

void test_parsePaymentJson_refuses_an_empty_or_oversize_payload(void)
{
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseRawJson("", 0));
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseRawJson(NULL, 0));

  PaymentFields_t      fields = static_validFields();
  static FixtureJson_t json;
  static_writeJson(&fields, &json);
  static_padJson(&json, X402_PAYMENT_JSON_MAX_BYTE_COUNT);
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_OK, static_parseRawJson(json.ma_text, json.m_len));

  static_writeJson(&fields, &json);
  static_padJson(&json, X402_PAYMENT_JSON_MAX_BYTE_COUNT + 1);
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseRawJson(json.ma_text, json.m_len));
}

void test_parsePaymentJson_refuses_a_nul_byte(void)
{
  PaymentFields_t      fields = static_validFields();
  static FixtureJson_t json;
  static_writeJson(&fields, &json);
  static_padJson(&json, json.m_len + 2);
  json.ma_text[json.m_len - 2] = '\0';
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseRawJson(json.ma_text, json.m_len));
}

void test_nul_byte_after_a_backslash_is_malformed(void)
{
  PaymentFields_t fields    = static_validFields();
  fields.mp_topExtraMembers = R"(,"note":"a\@")";
  static FixtureJson_t json;
  static_writeJson(&fields, &json);
  char* at_sign = strchr(json.ma_text, '@');
  TEST_ASSERT_NOT_NULL(at_sign);
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_OK, static_parseRawJson(json.ma_text, json.m_len));
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_OK, static_parseJson(&json));

  *at_sign = '\0';
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseRawJson(json.ma_text, json.m_len));
  TEST_ASSERT_EQUAL_INT(X402_PAYMENT_MALFORMED, static_parseJson(&json));
}

void test_parsePaymentHeader_is_the_json_form_after_base64(void)
{
  PaymentFields_t refused_fields[4];
  for (size_t i = 0; i < 4; i++)
    refused_fields[i] = static_validFields();
  refused_fields[0].m_isPayloadLeftOut = true;
  refused_fields[1].mp_version         = QUOTED("2");
  refused_fields[2].mp_amount          = QUOTED("10001");
  refused_fields[3].mp_network         = QUOTED("solana:other");
  static const X402PaymentStatus_t expected_statuses[4] = {
    X402_PAYMENT_MALFORMED, X402_PAYMENT_MALFORMED, X402_PAYMENT_NOT_ACCEPTED, X402_PAYMENT_NOT_ACCEPTED
  };
  for (size_t i = 0; i < 4; i++)
  {
    static FixtureJson_t json;
    static_writeJson(&refused_fields[i], &json);
    X402PaymentStatus_t raw_status = static_parseRawJson(json.ma_text, json.m_len);
    TEST_ASSERT_EQUAL_INT(expected_statuses[i], raw_status);
    TEST_ASSERT_EQUAL_INT(raw_status, static_parseJson(&json));
  }
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(58, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_payment_required_is_written_byte_for_byte);
  RUN_TEST(test_payment_required_writes_the_largest_amount_and_timeout_in_full);
  RUN_TEST(test_payment_required_refuses_when_the_ceiling_is_reached);
  RUN_TEST(test_requirements_are_written_byte_for_byte);
  RUN_TEST(test_requirements_refuse_when_the_ceiling_is_reached);
  RUN_TEST(test_settlement_response_is_written_byte_for_byte);
  RUN_TEST(test_settlement_response_escapes_its_texts);
  RUN_TEST(test_settlement_response_refuses_when_the_ceiling_is_reached);
  RUN_TEST(test_encode_base64_matches_the_rfc_4648_vectors);
  RUN_TEST(test_encode_base64_refuses_a_buffer_one_byte_short);
  RUN_TEST(test_valid_payload_is_ok_and_hands_on_the_transaction);
  RUN_TEST(test_transaction_of_1_to_1232_bytes_is_ok);
  RUN_TEST(test_transaction_with_an_escaped_slash_is_ok);
  RUN_TEST(test_unknown_keys_are_ignored);
  RUN_TEST(test_amount_of_the_largest_atomic_value_is_ok);
  RUN_TEST(test_empty_value_is_malformed);
  RUN_TEST(test_json_over_the_cap_is_malformed);
  RUN_TEST(test_header_over_the_cap_is_malformed);
  RUN_TEST(test_header_with_a_byte_outside_the_alphabet_is_malformed);
  RUN_TEST(test_header_with_whitespace_is_malformed);
  RUN_TEST(test_header_with_padding_before_the_end_is_malformed);
  RUN_TEST(test_header_with_three_or_four_padding_bytes_is_malformed);
  RUN_TEST(test_header_whose_length_is_not_a_multiple_of_4_is_malformed);
  RUN_TEST(test_json_holding_a_nul_byte_is_malformed);
  RUN_TEST(test_json_that_is_not_an_object_is_malformed);
  RUN_TEST(test_json_nested_deeper_than_the_limit_is_malformed);
  RUN_TEST(test_missing_version_is_malformed);
  RUN_TEST(test_version_that_is_not_an_integer_is_malformed);
  RUN_TEST(test_missing_accepted_is_malformed);
  RUN_TEST(test_accepted_that_is_not_an_object_is_malformed);
  RUN_TEST(test_missing_payload_is_malformed);
  RUN_TEST(test_payload_that_is_not_an_object_is_malformed);
  RUN_TEST(test_missing_transaction_is_malformed);
  RUN_TEST(test_transaction_that_is_not_a_string_is_malformed);
  RUN_TEST(test_transaction_that_is_not_strict_base64_is_malformed);
  RUN_TEST(test_transaction_of_0_bytes_is_malformed);
  RUN_TEST(test_transaction_over_1232_bytes_is_malformed);
  RUN_TEST(test_duplicate_top_level_key_is_malformed);
  RUN_TEST(test_duplicate_accepted_key_is_malformed);
  RUN_TEST(test_duplicate_fee_payer_or_transaction_is_malformed);
  RUN_TEST(test_escaped_key_in_an_object_that_is_read_is_malformed);
  RUN_TEST(test_version_other_than_2_is_not_accepted);
  RUN_TEST(test_scheme_other_than_exact_is_not_accepted);
  RUN_TEST(test_network_other_than_ours_is_not_accepted);
  RUN_TEST(test_network_of_the_longest_length_is_ok);
  RUN_TEST(test_asset_other_than_ours_is_not_accepted);
  RUN_TEST(test_pay_to_other_than_ours_is_not_accepted);
  RUN_TEST(test_fee_payer_other_than_ours_is_not_accepted);
  RUN_TEST(test_extra_that_is_missing_or_not_an_object_is_not_accepted);
  RUN_TEST(test_amount_other_than_the_canonical_decimal_is_not_accepted);
  RUN_TEST(test_timeout_other_than_ours_is_not_accepted);
  RUN_TEST(test_malformed_wins_over_not_accepted);
  RUN_TEST(test_parsePaymentJson_accepts_the_payload_the_header_form_accepts);
  RUN_TEST(test_parsePaymentJson_refuses_an_empty_or_oversize_payload);
  RUN_TEST(test_parsePaymentJson_refuses_a_nul_byte);
  RUN_TEST(test_nul_byte_after_a_backslash_is_malformed);
  RUN_TEST(test_parsePaymentHeader_is_the_json_form_after_base64);
  RUN_TEST(test_registration_gate_test_count);
  return UNITY_END();
}
