#include "x402.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "jsonbuf.h"
#include "jsonread.h"

#define X402_TRANSACTION_BASE64_MAX_LEN X402_BASE64_LEN(X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT)

#define X402_TEXT_FIELD_BUF_SIZE X402_NETWORK_BUF_SIZE

#define X402_AMOUNT_TEXT_BUF_SIZE 21

static const char BASE64_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

enum { X402_ROOT_MEMBER_VERSION, X402_ROOT_MEMBER_ACCEPTED, X402_ROOT_MEMBER_PAYLOAD, X402_ROOT_MEMBER_COUNT };
enum {
  X402_ACCEPTED_MEMBER_SCHEME, X402_ACCEPTED_MEMBER_NETWORK, X402_ACCEPTED_MEMBER_AMOUNT, X402_ACCEPTED_MEMBER_ASSET,
  X402_ACCEPTED_MEMBER_PAY_TO, X402_ACCEPTED_MEMBER_MAX_TIMEOUT_SECONDS, X402_ACCEPTED_MEMBER_EXTRA, X402_ACCEPTED_MEMBER_COUNT
};

bool x402_writePaymentRequired(JsonBuf_t* json_buf, const X402Requirements_t* requirements, const char* resource_url, const char* resource_description, const char* error_text)
{
  assert(json_buf != NULL);
  assert(requirements != NULL);
  assert(resource_url != NULL);
  assert(resource_description != NULL);
  assert(error_text != NULL);

  jsonbuf_appendFormat(json_buf, R"({"x402Version":%d,"error":")", X402_VERSION);
  jsonbuf_appendEscaped(json_buf, error_text);
  jsonbuf_appendFormat(json_buf, R"(","resource":{"url":")");
  jsonbuf_appendEscaped(json_buf, resource_url);
  jsonbuf_appendFormat(json_buf, R"(","description":")");
  jsonbuf_appendEscaped(json_buf, resource_description);
  jsonbuf_appendFormat(json_buf, R"(","mimeType":"application/json"},"accepts":[)");
  x402_writePaymentRequirements(json_buf, requirements);
  return jsonbuf_appendFormat(json_buf, R"(]})");
}

bool x402_writePaymentRequirements(JsonBuf_t* json_buf, const X402Requirements_t* requirements)
{
  assert(json_buf != NULL);
  assert(requirements != NULL);

  jsonbuf_appendFormat(json_buf, R"({"scheme":")" X402_SCHEME_EXACT R"(","network":")");
  jsonbuf_appendEscaped(json_buf, requirements->ma_network);
  jsonbuf_appendFormat(json_buf, R"(","amount":"%)" PRIu64 R"(","asset":")", requirements->m_amountAtomic);
  jsonbuf_appendEscaped(json_buf, requirements->ma_asset);
  jsonbuf_appendFormat(json_buf, R"(","payTo":")");
  jsonbuf_appendEscaped(json_buf, requirements->ma_payTo);
  jsonbuf_appendFormat(json_buf, R"(","maxTimeoutSeconds":%)" PRIu32 R"(,"extra":{"feePayer":")", requirements->m_maxTimeoutSeconds);
  jsonbuf_appendEscaped(json_buf, requirements->ma_feePayer);
  return jsonbuf_appendFormat(json_buf, R"("}})");
}

bool x402_writeSettlementResponse(JsonBuf_t* json_buf, const char* network, const char* signature_text)
{
  assert(json_buf       != NULL);
  assert(network        != NULL);
  assert(signature_text != NULL);

  jsonbuf_appendFormat(json_buf, R"({"success":true,"transaction":")");
  jsonbuf_appendEscaped(json_buf, signature_text);
  jsonbuf_appendFormat(json_buf, R"(","network":")");
  jsonbuf_appendEscaped(json_buf, network);
  return jsonbuf_appendFormat(json_buf, R"("})");
}

bool x402_tryEncodeBase64(const uint8_t* bytes, size_t byte_count, char* out, size_t out_size)
{
  assert(bytes != NULL || byte_count == 0);
  assert(out != NULL || out_size == 0);

  if (out_size == 0)
    return false;
  if ((out_size - 1) / 4 * 3 < byte_count)
  {
    out[0] = '\0';
    return false;
  }

  size_t text_len = 0;
  for (size_t i = 0; i < byte_count; i += 3)
  {
    size_t   group_len = byte_count - i < 3 ? byte_count - i : 3;
    uint32_t group     = (uint32_t)bytes[i] << 16;
    if (group_len > 1)
      group |= (uint32_t)bytes[i + 1] << 8;
    if (group_len > 2)
      group |= bytes[i + 2];

    out[text_len++] = BASE64_ALPHABET[(group >> 18) & 0x3F];
    out[text_len++] = BASE64_ALPHABET[(group >> 12) & 0x3F];
    out[text_len++] = group_len > 1 ? BASE64_ALPHABET[(group >> 6) & 0x3F] : '=';
    out[text_len++] = group_len > 2 ? BASE64_ALPHABET[group & 0x3F] : '=';
  }
  out[text_len] = '\0';
  return true;
}

static int static_base64DigitValue(char digit)
{
  if (digit >= 'A' && digit <= 'Z')
    return digit - 'A';
  if (digit >= 'a' && digit <= 'z')
    return digit - 'a' + 26;
  if (digit >= '0' && digit <= '9')
    return digit - '0' + 52;
  if (digit == '+')
    return 62;
  if (digit == '/')
    return 63;
  return -1;
}

static bool static_tryDecodeBase64(const char* text, size_t text_len, uint8_t* bytes_out, size_t bytes_out_size, size_t* byte_count_out)
{
  assert(text != NULL || text_len == 0);
  assert(bytes_out != NULL);
  assert(byte_count_out != NULL);

  if (text_len % 4 != 0)
    return false;

  size_t padding_len = 0;
  if (text_len > 0 && text[text_len - 1] == '=')
  {
    padding_len = 1;
    if (text[text_len - 2] == '=')
      padding_len = 2;
  }
  size_t byte_count = text_len / 4 * 3 - padding_len;
  if (byte_count > bytes_out_size)
    return false;

  uint32_t bit_buffer = 0;
  unsigned bit_count  = 0;
  size_t   out_index  = 0;
  for (size_t i = 0; i < text_len - padding_len; i++)
  {
    int digit_value = static_base64DigitValue(text[i]);
    if (digit_value < 0)
      return false;
    bit_buffer = (bit_buffer << 6) | (uint32_t)digit_value;
    bit_count += 6;
    if (bit_count >= 8)
    {
      bit_count -= 8;
      bytes_out[out_index++] = (uint8_t)(bit_buffer >> bit_count);
    }
  }
  *byte_count_out = out_index;
  return true;
}

static bool static_isStringEqual(const JsonReadMember_t* member, const char* expected)
{
  assert(member != NULL);
  assert(expected != NULL);

  char text[X402_TEXT_FIELD_BUF_SIZE];
  if (jsonread_spanToStrStatus(member->m_valueSpan, text, sizeof(text)) != JSONREAD_OK)
    return false;
  
  return strcmp(text, expected) == 0;
}

X402PaymentStatus_t x402_parsePaymentHeader(const char* value, size_t value_len, const X402Requirements_t* requirements, X402Payment_t* payment_out)
{
  assert(value != NULL || value_len == 0);
  assert(requirements != NULL);
  assert(payment_out != NULL);

  if (value_len == 0 || value_len > X402_PAYMENT_HEADER_MAX_LEN)
    return X402_PAYMENT_MALFORMED;

  uint8_t json_bytes[X402_PAYMENT_JSON_MAX_BYTE_COUNT];
  size_t  json_len = 0;
  if (!static_tryDecodeBase64(value, value_len, json_bytes, sizeof(json_bytes), &json_len))
    return X402_PAYMENT_MALFORMED;
  return x402_parsePaymentJson((const char*)json_bytes, json_len, requirements, payment_out);
}

X402PaymentStatus_t x402_parsePaymentJson(const char* json, size_t json_len, const X402Requirements_t* requirements, X402Payment_t* payment_out)
{
  assert(json != NULL || json_len == 0);
  assert(requirements != NULL);
  assert(payment_out != NULL);

  if (json_len == 0 || json_len > X402_PAYMENT_JSON_MAX_BYTE_COUNT)
    return X402_PAYMENT_MALFORMED;
  if (memchr(json, '\0', json_len) != NULL)
    return X402_PAYMENT_MALFORMED;

  JsonReadSpan_t root_span;
  if (jsonread_root(json, json_len, &root_span) != JSONREAD_OK)
    return X402_PAYMENT_MALFORMED;

  JsonReadMember_t root_members[X402_ROOT_MEMBER_COUNT] = {
    [X402_ROOT_MEMBER_VERSION]  = { .mp_key = "x402Version" },
    [X402_ROOT_MEMBER_ACCEPTED] = { .mp_key = "accepted" },
    [X402_ROOT_MEMBER_PAYLOAD]  = { .mp_key = "payload" },
  };
  if (!jsonread_tryFindMembers(root_span, root_members, X402_ROOT_MEMBER_COUNT))
    return X402_PAYMENT_MALFORMED;

  long version = 0;
  if (jsonread_spanToLongStatus(root_members[X402_ROOT_MEMBER_VERSION].m_valueSpan, &version) != JSONREAD_OK)
    return X402_PAYMENT_MALFORMED;

  JsonReadMember_t transaction_member = { .mp_key = "transaction" };
  if (!jsonread_tryFindMembers(root_members[X402_ROOT_MEMBER_PAYLOAD].m_valueSpan, &transaction_member, 1))
    return X402_PAYMENT_MALFORMED;

  char transaction_text[X402_TRANSACTION_BASE64_MAX_LEN + 1];
  if (jsonread_spanToStrStatus(transaction_member.m_valueSpan, transaction_text, sizeof(transaction_text)) != JSONREAD_OK)
    return X402_PAYMENT_MALFORMED;

  uint8_t transaction[X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT] = { 0 };
  size_t  transaction_byte_count = 0;
  if (!static_tryDecodeBase64(transaction_text, strlen(transaction_text), transaction, sizeof(transaction), &transaction_byte_count) || transaction_byte_count == 0)
    return X402_PAYMENT_MALFORMED;

  JsonReadMember_t accepted_members[X402_ACCEPTED_MEMBER_COUNT] = {
    [X402_ACCEPTED_MEMBER_SCHEME]              = { .mp_key = "scheme" },
    [X402_ACCEPTED_MEMBER_NETWORK]             = { .mp_key = "network" },
    [X402_ACCEPTED_MEMBER_AMOUNT]              = { .mp_key = "amount" },
    [X402_ACCEPTED_MEMBER_ASSET]               = { .mp_key = "asset" },
    [X402_ACCEPTED_MEMBER_PAY_TO]              = { .mp_key = "payTo" },
    [X402_ACCEPTED_MEMBER_MAX_TIMEOUT_SECONDS] = { .mp_key = "maxTimeoutSeconds" },
    [X402_ACCEPTED_MEMBER_EXTRA]               = { .mp_key = "extra" },
  };
  if (!jsonread_tryFindMembers(root_members[X402_ROOT_MEMBER_ACCEPTED].m_valueSpan, accepted_members, X402_ACCEPTED_MEMBER_COUNT))
    return X402_PAYMENT_MALFORMED;

  JsonReadMember_t fee_payer_member = { .mp_key = "feePayer" };
  if (jsonread_isObject(accepted_members[X402_ACCEPTED_MEMBER_EXTRA].m_valueSpan) &&
      !jsonread_tryFindMembers(accepted_members[X402_ACCEPTED_MEMBER_EXTRA].m_valueSpan, &fee_payer_member, 1))
    return X402_PAYMENT_MALFORMED;

  if (version != X402_VERSION)
    return X402_PAYMENT_NOT_ACCEPTED;
  if (!static_isStringEqual(&accepted_members[X402_ACCEPTED_MEMBER_SCHEME], X402_SCHEME_EXACT))
    return X402_PAYMENT_NOT_ACCEPTED;
  if (!static_isStringEqual(&accepted_members[X402_ACCEPTED_MEMBER_NETWORK], requirements->ma_network))
    return X402_PAYMENT_NOT_ACCEPTED;
  if (!static_isStringEqual(&accepted_members[X402_ACCEPTED_MEMBER_ASSET], requirements->ma_asset))
    return X402_PAYMENT_NOT_ACCEPTED;
  if (!static_isStringEqual(&accepted_members[X402_ACCEPTED_MEMBER_PAY_TO], requirements->ma_payTo))
    return X402_PAYMENT_NOT_ACCEPTED;

  char amount_text[X402_AMOUNT_TEXT_BUF_SIZE];
  snprintf(amount_text, sizeof(amount_text), "%" PRIu64, requirements->m_amountAtomic);
  if (!static_isStringEqual(&accepted_members[X402_ACCEPTED_MEMBER_AMOUNT], amount_text))
    return X402_PAYMENT_NOT_ACCEPTED;

  long timeout_seconds = 0;
  if (jsonread_spanToLongStatus(accepted_members[X402_ACCEPTED_MEMBER_MAX_TIMEOUT_SECONDS].m_valueSpan, &timeout_seconds) != JSONREAD_OK || timeout_seconds != (long)requirements->m_maxTimeoutSeconds)
    return X402_PAYMENT_NOT_ACCEPTED;

  if (!static_isStringEqual(&fee_payer_member, requirements->ma_feePayer))
    return X402_PAYMENT_NOT_ACCEPTED;

  memcpy(payment_out->ma_transaction, transaction, sizeof(transaction));
  payment_out->m_transactionByteCount = transaction_byte_count;
  return X402_PAYMENT_OK;
}
