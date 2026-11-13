#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "billing.h"
#include "bytes.h"
#include "datetime.h"
#include "jsonread.h"
#include "validate.h"

_Static_assert(BILLING_LEMONSQUEEZY_SIGNATURE_LEN == 2 * SHA256_DIGEST_LENGTH, "a signature is an HMAC-SHA256 in hex");

#define BILLING_LEMONSQUEEZY_DATA_TYPE_MAX_LEN  32
#define BILLING_LEMONSQUEEZY_TIME_MAX_LEN       35
#define BILLING_LEMONSQUEEZY_ORDER_STATUS_PAID  "paid"

typedef enum {
  BILLING_LEMONSQUEEZY_EVENT_ORDER_CREATED,
  BILLING_LEMONSQUEEZY_EVENT_SUBSCRIPTION_CANCELLED,
  BILLING_LEMONSQUEEZY_EVENT_SUBSCRIPTION_RESUMED,
  BILLING_LEMONSQUEEZY_EVENT_SUBSCRIPTION_EXPIRED,
  BILLING_LEMONSQUEEZY_EVENT_ORDER_REFUNDED,
  BILLING_LEMONSQUEEZY_EVENT_SUBSCRIPTION_PAYMENT_REFUNDED,
} BillingLemonSqueezyEventKind_t;

typedef struct {
  const char*                    mp_eventName;
  const char*                    mp_dataType;
  BillingLemonSqueezyEventKind_t m_kind;
} BillingLemonSqueezyEventRule_t;

static const BillingLemonSqueezyEventRule_t BILLING_LEMONSQUEEZY_EVENT_RULES[] = {
  { "order_created",                 "orders",                BILLING_LEMONSQUEEZY_EVENT_ORDER_CREATED },
  { "subscription_cancelled",        "subscriptions",         BILLING_LEMONSQUEEZY_EVENT_SUBSCRIPTION_CANCELLED },
  { "subscription_resumed",          "subscriptions",         BILLING_LEMONSQUEEZY_EVENT_SUBSCRIPTION_RESUMED },
  { "subscription_expired",          "subscriptions",         BILLING_LEMONSQUEEZY_EVENT_SUBSCRIPTION_EXPIRED },
  { "order_refunded",                "orders",                BILLING_LEMONSQUEEZY_EVENT_ORDER_REFUNDED },
  { "subscription_payment_refunded", "subscription-invoices", BILLING_LEMONSQUEEZY_EVENT_SUBSCRIPTION_PAYMENT_REFUNDED },
};

_Static_assert(sizeof(BILLING_LEMONSQUEEZY_EVENT_RULES) / sizeof(BILLING_LEMONSQUEEZY_EVENT_RULES[0]) == 6, "six handled events");
_Static_assert(sizeof("subscription_payment_refunded") - 1 <= BILLING_LEMONSQUEEZY_EVENT_NAME_MAX_LEN, "the longest handled name fits");
_Static_assert(sizeof("subscription-invoices") - 1 <= BILLING_LEMONSQUEEZY_DATA_TYPE_MAX_LEN, "the longest data type fits");
_Static_assert(sizeof(long) == sizeof(int64_t), "a number ref is read as a long");
_Static_assert(sizeof("9223372036854775807") - 1 == BILLING_LEMONSQUEEZY_REF_MAX_LEN, "the largest int64_t has BILLING_LEMONSQUEEZY_REF_MAX_LEN digits");

#define BILLING_NOWPAYMENTS_PAID_RATIO_MIN 0.99
#define BILLING_NOWPAYMENTS_STATUS_MAX_LEN 14

#define BILLING_NOWPAYMENTS_REF_SAFE_BYTES "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"

enum {
  BILLING_NOWPAYMENTS_MEMBER_PAYMENT_STATUS,
  BILLING_NOWPAYMENTS_MEMBER_ORDER_ID,
  BILLING_NOWPAYMENTS_MEMBER_INVOICE_ID,
  BILLING_NOWPAYMENTS_MEMBER_PAYMENT_ID,
  BILLING_NOWPAYMENTS_MEMBER_ACTUALLY_PAID,
  BILLING_NOWPAYMENTS_MEMBER_PAY_AMOUNT,
  BILLING_NOWPAYMENTS_MEMBER_PARENT_PAYMENT_ID,
  BILLING_NOWPAYMENTS_MEMBER_COUNT,
};

_Static_assert(SHA512_DIGEST_LENGTH * 2 == BILLING_NOWPAYMENTS_SIGNATURE_LEN, "the signature is an HMAC-SHA512 in hex");
_Static_assert(sizeof("partially_paid") - 1 == BILLING_NOWPAYMENTS_STATUS_MAX_LEN, "the longest paying status fits");

static const char* g_lemonSqueezySecret    = NULL;
static size_t      g_lemonSqueezySecretLen = 0;

static const char* g_nowPaymentsSecret    = NULL;
static size_t      g_nowPaymentsSecretLen = 0;

static bool                                  static_isDigestHexEqual                   (const char* expected_hex, const char* given_hex, size_t hex_len);
static bool                                  static_isHmacHexValid                     (const EVP_MD* digest_type, size_t secret_min_len, const char* secret, size_t secret_len, const char* body, size_t body_len, const char* signature_hex, size_t signature_hex_len);
static BillingNowPaymentsReason_t            static_readNowPaymentsEventReason         (const char* body, size_t body_len, BillingNowPaymentsEvent_t* event);
static BillingNowPaymentsReason_t            static_readNowPaymentsInvoiceRefReason    (JsonReadSpan_t invoice_span, JsonReadSpan_t payment_span, char* ref_out, size_t ref_size);
static bool                                  static_tryReadNowPaymentsRefText          (JsonReadSpan_t value_span, char* ref_out, size_t ref_size);
static bool                                  static_isFalsyValue                       (JsonReadSpan_t value_span);
static const char*                           static_nowPaymentsPaidEventName           (JsonReadSpan_t status_span, JsonReadSpan_t actually_paid_span, JsonReadSpan_t pay_amount_span);
static bool                                  static_isNowPaymentsPaidWithinTolerance   (JsonReadSpan_t actually_paid_span, JsonReadSpan_t pay_amount_span);
static bool                                  static_tryReadNowPaymentsAmount           (JsonReadSpan_t value_span, double* amount_out);
static bool                                  static_tryReadUuidSpan                    (JsonReadSpan_t value_span, char* uuid_out, size_t uuid_size);
static BillingLemonSqueezyReason_t           static_readLemonSqueezyEventReason        (const char* body, size_t body_len, BillingLemonSqueezyEvent_t* event);
static BillingLemonSqueezyReason_t           static_readLemonSqueezyEventFieldsReason  (BillingLemonSqueezyEventKind_t kind, JsonReadSpan_t data_span, JsonReadSpan_t attributes_span, BillingLemonSqueezyEvent_t* event);
static BillingLemonSqueezyReason_t           static_readLemonSqueezySubscriptionReason (BillingLemonSqueezyEventKind_t kind, JsonReadSpan_t data_span, JsonReadSpan_t attributes_span, BillingLemonSqueezyEvent_t* event);
static bool                                  static_isIgnoreReason                     (BillingLemonSqueezyReason_t reason);
static const BillingLemonSqueezyEventRule_t* static_findLemonSqueezyEventRule          (const char* event_name);
static bool                                  static_tryReadObject                      (JsonReadSpan_t object_span, const char* key, JsonReadSpan_t* value_out);
static bool                                  static_tryReadUuid                        (JsonReadSpan_t object_span, const char* key, char* uuid_out, size_t uuid_size);
static bool                                  static_tryReadLemonSqueezyIdText          (JsonReadSpan_t object_span, const char* key, char* ref_out);
static bool                                  static_tryReadLemonSqueezyIdNumber        (JsonReadSpan_t object_span, const char* key, char* ref_out);
static bool                                  static_tryReadLemonSqueezyTime            (JsonReadSpan_t object_span, const char* key, int64_t* epoch_out);

void billing_setLemonSqueezySecret(const char* secret)
{
  g_lemonSqueezySecret    = secret;
  g_lemonSqueezySecretLen = secret != NULL ? strlen(secret) : 0;
}

bool billing_isLemonSqueezyBodySigned(const char* body, size_t body_len, const char* signature, size_t signature_len)
{
  if (g_lemonSqueezySecret == NULL)
    return false;

  return billing_isLemonSqueezySignatureValid(g_lemonSqueezySecret, g_lemonSqueezySecretLen, body, body_len, signature, signature_len);
}

bool billing_isLemonSqueezySignatureValid(const char* secret, size_t secret_len, const char* body, size_t body_len, const char* signature, size_t signature_len)
{
  return static_isHmacHexValid( EVP_sha256(),
                                BILLING_LEMONSQUEEZY_SECRET_MIN_LEN,
                                secret, secret_len,
                                body, body_len,
                                signature, signature_len);
}

bool billing_isNowPaymentsSignatureWellFormed(const char* signature, size_t signature_len)
{
  assert(signature != NULL || signature_len == 0);

  if (signature_len != BILLING_NOWPAYMENTS_SIGNATURE_LEN)
    return false;

  for (size_t i = 0; i < signature_len; i++)
  {
    unsigned char byte = (unsigned char)signature[i];
    if (!isxdigit(byte) || isupper(byte))
      return false;
  }
  return true;
}

bool billing_isNowPaymentsSignatureValid(const char* secret, size_t secret_len, const char* canonical_body, size_t canonical_body_len, const char* signature, size_t signature_len)
{
  return static_isHmacHexValid( EVP_sha512(),
                                BILLING_NOWPAYMENTS_SECRET_MIN_LEN,
                                secret, secret_len,
                                canonical_body, canonical_body_len,
                                signature, signature_len);
}

void billing_setNowPaymentsSecret(const char* secret)
{
  g_nowPaymentsSecret    = secret;
  g_nowPaymentsSecretLen = secret != NULL ? strlen(secret) : 0;
}

bool billing_isNowPaymentsCanonicalBodySigned(const char* canonical_body, size_t canonical_body_len, const char* signature, size_t signature_len)
{
  if (g_nowPaymentsSecret == NULL)
    return false;

  return billing_isNowPaymentsSignatureValid( g_nowPaymentsSecret, g_nowPaymentsSecretLen,
                                              canonical_body, canonical_body_len,
                                              signature, signature_len);
}

void billing_parseNowPaymentsEvent(const char* body, size_t body_len, BillingNowPaymentsEvent_t* event_out)
{
  assert(body != NULL || body_len == 0);
  assert(event_out != NULL);

  BillingNowPaymentsEvent_t  event  = { 0 };
  BillingNowPaymentsReason_t reason = static_readNowPaymentsEventReason(body, body_len, &event);
  
  memset(event_out, 0, sizeof(*event_out));
  if (reason == BILLING_NOWPAYMENTS_REASON_NONE)
  {
    *event_out = event;
    event_out->m_action = BILLING_ACTION_ORDER_PAID;
    return;
  }
  event_out->m_action = reason == BILLING_NOWPAYMENTS_REASON_NOT_PAID ? BILLING_ACTION_IGNORE : BILLING_ACTION_REFUSE;
  event_out->m_reason = reason;
}

const char* billing_nowPaymentsReasonText(BillingNowPaymentsReason_t reason)
{
  switch (reason)
  {
    case BILLING_NOWPAYMENTS_REASON_NONE:                return "the event is read";
    case BILLING_NOWPAYMENTS_REASON_NOT_PAID:            return "the invoice is not paid";
    case BILLING_NOWPAYMENTS_REASON_BODY_BAD:            return "the body is not a readable JSON object";
    case BILLING_NOWPAYMENTS_REASON_INVOICE_REF_MISSING: return "invoice_id and payment_id are both missing";
    case BILLING_NOWPAYMENTS_REASON_INVOICE_REF_BAD:     return "invoice_id or payment_id is not an id of 1 to 64 safe characters";
    case BILLING_NOWPAYMENTS_REASON_ORDER_ID_BAD:        return "order_id is missing or not a lower-case UUID";
  }
  return "the event could not be read";
}


void billing_parseLemonSqueezyEvent(const char* body, size_t body_len, BillingLemonSqueezyEvent_t* event_out)
{
  assert(body != NULL || body_len == 0);
  assert(event_out != NULL);

  BillingLemonSqueezyEvent_t  event  = { 0 };
  BillingLemonSqueezyReason_t reason = static_readLemonSqueezyEventReason(body, body_len, &event);

  memset(event_out, 0, sizeof(*event_out));
  if (reason == BILLING_LEMONSQUEEZY_REASON_NONE)
  {
    *event_out = event;
    return;
  }
  event_out->m_action     = static_isIgnoreReason(reason) ? BILLING_ACTION_IGNORE : BILLING_ACTION_REFUSE;
  event_out->m_reason     = reason;
  event_out->mp_eventName = event.mp_eventName;
}

const char* billing_lemonSqueezyReasonText(BillingLemonSqueezyReason_t reason)
{
  switch (reason)
  {
    case BILLING_LEMONSQUEEZY_REASON_NONE:                 return "the event is read";
    case BILLING_LEMONSQUEEZY_REASON_TEST_MODE:            return "the event is a test-mode event";
    case BILLING_LEMONSQUEEZY_REASON_EVENT_NOT_HANDLED:    return "the event is not one this server handles";
    case BILLING_LEMONSQUEEZY_REASON_ORDER_NOT_PAID:       return "the order is not paid";
    case BILLING_LEMONSQUEEZY_REASON_BODY_NOT_OBJECT:      return "the body is not a JSON object";
    case BILLING_LEMONSQUEEZY_REASON_META_BAD:             return "meta is missing or not an object";
    case BILLING_LEMONSQUEEZY_REASON_EVENT_NAME_BAD:       return "meta.event_name is missing or not a string";
    case BILLING_LEMONSQUEEZY_REASON_TEST_MODE_BAD:        return "test_mode is missing or not a boolean";
    case BILLING_LEMONSQUEEZY_REASON_DATA_BAD:             return "data or data.attributes is missing or not an object";
    case BILLING_LEMONSQUEEZY_REASON_WEBHOOK_ID_BAD:       return "meta.webhook_id is missing or not a lower-case UUID";
    case BILLING_LEMONSQUEEZY_REASON_DATA_TYPE_BAD:        return "data.type does not match the event";
    case BILLING_LEMONSQUEEZY_REASON_ID_BAD:               return "data.id is not an id of 1 to 19 digits";
    case BILLING_LEMONSQUEEZY_REASON_ORDER_REF_BAD:        return "data.attributes.order_id is not a whole number of at least 1";
    case BILLING_LEMONSQUEEZY_REASON_SUBSCRIPTION_REF_BAD: return "data.attributes.subscription_id is not a whole number of at least 1";
    case BILLING_LEMONSQUEEZY_REASON_IDENTIFIER_BAD:       return "data.attributes.identifier is not a lower-case UUID";
    case BILLING_LEMONSQUEEZY_REASON_STATUS_BAD:           return "data.attributes.status is missing or not a string";
    case BILLING_LEMONSQUEEZY_REASON_UPDATED_AT_BAD:       return "data.attributes.updated_at is missing or not an RFC 3339 time";
    case BILLING_LEMONSQUEEZY_REASON_ENDS_AT_MISSING:      return "data.attributes.ends_at is missing";
    case BILLING_LEMONSQUEEZY_REASON_ENDS_AT_BAD:          return "data.attributes.ends_at is not an RFC 3339 time";
    case BILLING_LEMONSQUEEZY_REASON_REFUNDED_BAD:         return "data.attributes.refunded is missing or not a boolean";
  }
  return "the event could not be read";
}


static bool static_isDigestHexEqual(const char* expected_hex, const char* given_hex, size_t hex_len)
{
  assert(expected_hex != NULL);
  assert(given_hex != NULL);

  return CRYPTO_memcmp(expected_hex, given_hex, hex_len) == 0;
}

static bool static_isHmacHexValid(const EVP_MD* digest_type, size_t secret_min_len, const char* secret, size_t secret_len, const char* body, size_t body_len, const char* signature_hex, size_t signature_hex_len)
{
  assert(digest_type != NULL);
  assert(secret != NULL);
  assert(secret_len <= INT_MAX);
  assert(body != NULL || body_len == 0);
  assert(signature_hex != NULL || signature_hex_len == 0);

  size_t hex_len = (size_t)EVP_MD_size(digest_type) * 2;
  if (secret_len < secret_min_len)
    return false;
  if (signature_hex_len != hex_len)
    return false;

  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int  digest_len = 0;
  const unsigned char* body_bytes = (const unsigned char*)(body != NULL ? body : "");
  if (HMAC(digest_type, secret, (int)secret_len, body_bytes, body_len, digest, &digest_len) == NULL)
    return false;

  char expected_hex[EVP_MAX_MD_SIZE * 2 + 1];
  bytes_writeHex(digest, digest_len, expected_hex);
  return static_isDigestHexEqual(expected_hex, signature_hex, hex_len);
}

static BillingNowPaymentsReason_t static_readNowPaymentsEventReason(const char* body, size_t body_len, BillingNowPaymentsEvent_t* event)
{
  assert(event != NULL);

  JsonReadSpan_t root_span = { 0 };
  if (body == NULL || jsonread_root(body, body_len, &root_span) != JSONREAD_OK)
    return BILLING_NOWPAYMENTS_REASON_BODY_BAD;

  JsonReadMember_t members[BILLING_NOWPAYMENTS_MEMBER_COUNT] = {
    [BILLING_NOWPAYMENTS_MEMBER_PAYMENT_STATUS]    = { .mp_key = "payment_status" },
    [BILLING_NOWPAYMENTS_MEMBER_ORDER_ID]          = { .mp_key = "order_id" },
    [BILLING_NOWPAYMENTS_MEMBER_INVOICE_ID]        = { .mp_key = "invoice_id" },
    [BILLING_NOWPAYMENTS_MEMBER_PAYMENT_ID]        = { .mp_key = "payment_id" },
    [BILLING_NOWPAYMENTS_MEMBER_ACTUALLY_PAID]     = { .mp_key = "actually_paid" },
    [BILLING_NOWPAYMENTS_MEMBER_PAY_AMOUNT]        = { .mp_key = "pay_amount" },
    [BILLING_NOWPAYMENTS_MEMBER_PARENT_PAYMENT_ID] = { .mp_key = "parent_payment_id" },
  };
  if (!jsonread_tryFindMembers(root_span, members, BILLING_NOWPAYMENTS_MEMBER_COUNT))
    return BILLING_NOWPAYMENTS_REASON_BODY_BAD;

  BillingNowPaymentsReason_t ref_reason = static_readNowPaymentsInvoiceRefReason( members[BILLING_NOWPAYMENTS_MEMBER_INVOICE_ID].m_valueSpan,
                                                                                  members[BILLING_NOWPAYMENTS_MEMBER_PAYMENT_ID].m_valueSpan,
                                                                                  event->ma_providerOrderRef,
                                                                                  sizeof(event->ma_providerOrderRef));
  if (ref_reason != BILLING_NOWPAYMENTS_REASON_NONE)
    return ref_reason;

  if (!static_tryReadUuidSpan(members[BILLING_NOWPAYMENTS_MEMBER_ORDER_ID].m_valueSpan, event->ma_orderId, sizeof(event->ma_orderId)))
    return BILLING_NOWPAYMENTS_REASON_ORDER_ID_BAD;

  if (!static_isFalsyValue(members[BILLING_NOWPAYMENTS_MEMBER_PARENT_PAYMENT_ID].m_valueSpan))
    return BILLING_NOWPAYMENTS_REASON_NOT_PAID;

  event->mp_eventName = static_nowPaymentsPaidEventName(members[BILLING_NOWPAYMENTS_MEMBER_PAYMENT_STATUS].m_valueSpan,
                                                        members[BILLING_NOWPAYMENTS_MEMBER_ACTUALLY_PAID].m_valueSpan,
                                                        members[BILLING_NOWPAYMENTS_MEMBER_PAY_AMOUNT].m_valueSpan);
  if (event->mp_eventName == NULL)
    return BILLING_NOWPAYMENTS_REASON_NOT_PAID;

  int ref_len = snprintf(event->ma_eventRef, sizeof(event->ma_eventRef), "paid:%s", event->ma_providerOrderRef);
  if (ref_len < 0 || (size_t)ref_len >= sizeof(event->ma_eventRef))
    return BILLING_NOWPAYMENTS_REASON_BODY_BAD;
  return BILLING_NOWPAYMENTS_REASON_NONE;
}

static BillingNowPaymentsReason_t static_readNowPaymentsInvoiceRefReason(JsonReadSpan_t invoice_span, JsonReadSpan_t payment_span, char* ref_out, size_t ref_size)
{
  JsonReadSpan_t chosen_span = static_isFalsyValue(invoice_span) ? payment_span : invoice_span;
  if (static_isFalsyValue(chosen_span))
    return BILLING_NOWPAYMENTS_REASON_INVOICE_REF_MISSING;
  if (!static_tryReadNowPaymentsRefText(chosen_span, ref_out, ref_size))
    return BILLING_NOWPAYMENTS_REASON_INVOICE_REF_BAD;
  return BILLING_NOWPAYMENTS_REASON_NONE;
}

static bool static_tryReadNowPaymentsRefText(JsonReadSpan_t value_span, char* ref_out, size_t ref_size)
{
  assert(ref_out != NULL);
  assert(ref_size > 0);

  if (value_span.m_len > 0 && value_span.mp_start[0] == '"')
  {
    if (jsonread_spanToStrStatus(value_span, ref_out, ref_size) != JSONREAD_OK)
      return false;
  }
  else if (jsonread_isNumberToken(value_span.mp_start, value_span.mp_start + value_span.m_len) && value_span.m_len < ref_size)
  {
    memcpy(ref_out, value_span.mp_start, value_span.m_len);
    ref_out[value_span.m_len] = '\0';
  }
  else
  {
    return false;
  }

  return ref_out[strspn(ref_out, BILLING_NOWPAYMENTS_REF_SAFE_BYTES)] == '\0';
}

static bool static_isFalsyValue(JsonReadSpan_t value_span)
{
  if (value_span.m_len == 0)
    return true;
  if (jsonread_isSpanEqual(value_span, "null")  ||
      jsonread_isSpanEqual(value_span, "false") ||
      jsonread_isSpanEqual(value_span, "\"\"")  ||
      jsonread_isSpanEqual(value_span, "[]")    ||
      jsonread_isSpanEqual(value_span, "{}"))
  {
    return true;
  }

  double number = 1.0;
  return jsonread_spanToDoubleStatus(value_span, &number) == JSONREAD_OK && number == 0.0;
}

static const char* static_nowPaymentsPaidEventName(JsonReadSpan_t status_span, JsonReadSpan_t actually_paid_span, JsonReadSpan_t pay_amount_span)
{
  char status[BILLING_NOWPAYMENTS_STATUS_MAX_LEN + 1];
  if (jsonread_spanToStrStatus(status_span, status, sizeof(status)) != JSONREAD_OK)
    return NULL;

  if (strcmp(status, "finished") == 0)
    return "finished";
  if (strcmp(status, "partially_paid") == 0 && static_isNowPaymentsPaidWithinTolerance(actually_paid_span, pay_amount_span))
    return "partially_paid";
  return NULL;
}

static bool static_isNowPaymentsPaidWithinTolerance(JsonReadSpan_t actually_paid_span, JsonReadSpan_t pay_amount_span)
{
  double actually_paid = 0.0;
  double pay_amount    = 0.0;
  if (!static_tryReadNowPaymentsAmount(actually_paid_span, &actually_paid) ||
      !static_tryReadNowPaymentsAmount(pay_amount_span, &pay_amount))
  {
    return false;
  }
  if (pay_amount <= 0.0)
    return false;

  double ratio = actually_paid / pay_amount;
  return isfinite(ratio) && ratio >= BILLING_NOWPAYMENTS_PAID_RATIO_MIN;
}

static bool static_tryReadNowPaymentsAmount(JsonReadSpan_t value_span, double* amount_out)
{
  assert(amount_out != NULL);

  JsonReadSpan_t number_span = value_span;
  if (number_span.m_len >= 2 && number_span.mp_start[0] == '"')
  {
    number_span.mp_start += 1;
    number_span.m_len    -= 2;
  }
  return jsonread_spanToDoubleStatus(number_span, amount_out) == JSONREAD_OK;
}

static BillingLemonSqueezyReason_t static_readLemonSqueezyEventReason(const char* body, size_t body_len, BillingLemonSqueezyEvent_t* event)
{
  assert(event != NULL);

  JsonReadSpan_t root_span = { 0 };
  if (body == NULL || jsonread_root(body, body_len, &root_span) != JSONREAD_OK || root_span.m_len == 0 || root_span.mp_start[0] != '{')
    return BILLING_LEMONSQUEEZY_REASON_BODY_NOT_OBJECT;

  JsonReadSpan_t meta_span = { 0 };
  if (!static_tryReadObject(root_span, "meta", &meta_span))
    return BILLING_LEMONSQUEEZY_REASON_META_BAD;

  JsonReadSpan_t value_span = { 0 };
  char           event_name[BILLING_LEMONSQUEEZY_EVENT_NAME_MAX_LEN + 1];
  if (jsonread_objectKey(meta_span, "event_name", &value_span) != JSONREAD_OK)
    return BILLING_LEMONSQUEEZY_REASON_EVENT_NAME_BAD;
  JsonReadStatus_t name_status = jsonread_spanToStrStatus(value_span, event_name, sizeof(event_name));
  if (name_status != JSONREAD_OK && name_status != JSONREAD_ERR_TOOLONG)
    return BILLING_LEMONSQUEEZY_REASON_EVENT_NAME_BAD;

  bool is_test_mode = false;
  if (jsonread_objectKey(meta_span, "test_mode", &value_span) == JSONREAD_OK && jsonread_spanToBoolStatus(value_span, &is_test_mode) != JSONREAD_OK)
    return BILLING_LEMONSQUEEZY_REASON_TEST_MODE_BAD;
  if (is_test_mode)
    return BILLING_LEMONSQUEEZY_REASON_TEST_MODE;

  const BillingLemonSqueezyEventRule_t* rule = name_status == JSONREAD_OK ? static_findLemonSqueezyEventRule(event_name) : NULL;
  if (rule == NULL)
    return BILLING_LEMONSQUEEZY_REASON_EVENT_NOT_HANDLED;
  event->mp_eventName = rule->mp_eventName;

  JsonReadSpan_t data_span       = { 0 };
  JsonReadSpan_t attributes_span = { 0 };
  if (!static_tryReadObject(root_span, "data", &data_span) || !static_tryReadObject(data_span, "attributes", &attributes_span))
    return BILLING_LEMONSQUEEZY_REASON_DATA_BAD;

  if (jsonread_objectKey(attributes_span, "test_mode", &value_span) != JSONREAD_OK || jsonread_spanToBoolStatus(value_span, &is_test_mode) != JSONREAD_OK)
    return BILLING_LEMONSQUEEZY_REASON_TEST_MODE_BAD;
  if (is_test_mode)
    return BILLING_LEMONSQUEEZY_REASON_TEST_MODE;

  if (!static_tryReadUuid(meta_span, "webhook_id", event->ma_webhookId, sizeof(event->ma_webhookId)))
    return BILLING_LEMONSQUEEZY_REASON_WEBHOOK_ID_BAD;

  char data_type[BILLING_LEMONSQUEEZY_DATA_TYPE_MAX_LEN + 1];
  if (jsonread_objectKey(data_span, "type", &value_span) != JSONREAD_OK                 || 
      jsonread_spanToStrStatus(value_span, data_type, sizeof(data_type)) != JSONREAD_OK || 
      strcmp(data_type, rule->mp_dataType) != 0)
  {
    return BILLING_LEMONSQUEEZY_REASON_DATA_TYPE_BAD;
  }

  return static_readLemonSqueezyEventFieldsReason(rule->m_kind, data_span, attributes_span, event);
}

static BillingLemonSqueezyReason_t static_readLemonSqueezyEventFieldsReason(BillingLemonSqueezyEventKind_t kind, JsonReadSpan_t data_span, JsonReadSpan_t attributes_span, BillingLemonSqueezyEvent_t* event)
{
  assert(event != NULL);

  JsonReadSpan_t value_span = { 0 };
  switch (kind)
  {
    case BILLING_LEMONSQUEEZY_EVENT_ORDER_CREATED:
    {
      if (!static_tryReadUuid(attributes_span, "identifier", event->ma_orderId, sizeof(event->ma_orderId)))
        return BILLING_LEMONSQUEEZY_REASON_IDENTIFIER_BAD;
      if (!static_tryReadLemonSqueezyIdText(data_span, "id", event->ma_providerOrderRef))
        return BILLING_LEMONSQUEEZY_REASON_ID_BAD;

      char status[sizeof(BILLING_LEMONSQUEEZY_ORDER_STATUS_PAID)];
      if (jsonread_objectKey(attributes_span, "status", &value_span) != JSONREAD_OK)
        return BILLING_LEMONSQUEEZY_REASON_STATUS_BAD;
      JsonReadStatus_t status_status = jsonread_spanToStrStatus(value_span, status, sizeof(status));
      if (status_status == JSONREAD_ERR_TOOLONG)
        return BILLING_LEMONSQUEEZY_REASON_ORDER_NOT_PAID;
      else if (status_status != JSONREAD_OK)
        return BILLING_LEMONSQUEEZY_REASON_STATUS_BAD;

      if (strcmp(status, BILLING_LEMONSQUEEZY_ORDER_STATUS_PAID) != 0)
        return BILLING_LEMONSQUEEZY_REASON_ORDER_NOT_PAID;

      event->m_action = BILLING_ACTION_ORDER_PAID;
      return BILLING_LEMONSQUEEZY_REASON_NONE;
    }
    case BILLING_LEMONSQUEEZY_EVENT_SUBSCRIPTION_CANCELLED:
    case BILLING_LEMONSQUEEZY_EVENT_SUBSCRIPTION_RESUMED:
    case BILLING_LEMONSQUEEZY_EVENT_SUBSCRIPTION_EXPIRED:
      return static_readLemonSqueezySubscriptionReason(kind, data_span, attributes_span, event);
    case BILLING_LEMONSQUEEZY_EVENT_ORDER_REFUNDED:
    {
      if (!static_tryReadLemonSqueezyIdText(data_span, "id", event->ma_providerOrderRef))
        return BILLING_LEMONSQUEEZY_REASON_ID_BAD;

      bool is_refunded_in_full = false;
      if (jsonread_objectKey(attributes_span, "refunded", &value_span) != JSONREAD_OK  || 
          jsonread_spanToBoolStatus(value_span, &is_refunded_in_full) != JSONREAD_OK)
      {
        return BILLING_LEMONSQUEEZY_REASON_REFUNDED_BAD;
      }
      event->m_action = is_refunded_in_full ? BILLING_ACTION_REVOKE : BILLING_ACTION_RECORD;
      return BILLING_LEMONSQUEEZY_REASON_NONE;
    }
    case BILLING_LEMONSQUEEZY_EVENT_SUBSCRIPTION_PAYMENT_REFUNDED:
    {
      if (!static_tryReadLemonSqueezyIdNumber(attributes_span, "subscription_id", event->ma_providerSubscriptionRef))
        return BILLING_LEMONSQUEEZY_REASON_SUBSCRIPTION_REF_BAD;
      
      event->m_action = BILLING_ACTION_RECORD;
      return BILLING_LEMONSQUEEZY_REASON_NONE;
    }
  }
  assert(!"static_readLemonSqueezyEventFieldsReason: a kind with no case");
  return BILLING_LEMONSQUEEZY_REASON_EVENT_NOT_HANDLED;
}

static BillingLemonSqueezyReason_t static_readLemonSqueezySubscriptionReason(BillingLemonSqueezyEventKind_t kind, JsonReadSpan_t data_span, JsonReadSpan_t attributes_span, BillingLemonSqueezyEvent_t* event)
{
  assert(event != NULL);

  if (!static_tryReadLemonSqueezyIdText(data_span, "id", event->ma_providerSubscriptionRef))
    return BILLING_LEMONSQUEEZY_REASON_ID_BAD;
  if (!static_tryReadLemonSqueezyIdNumber(attributes_span, "order_id", event->ma_providerOrderRef))
    return BILLING_LEMONSQUEEZY_REASON_ORDER_REF_BAD;
  if (kind == BILLING_LEMONSQUEEZY_EVENT_SUBSCRIPTION_EXPIRED)
  {
    event->m_action = BILLING_ACTION_REVOKE;
    return BILLING_LEMONSQUEEZY_REASON_NONE;
  }

  if (!static_tryReadLemonSqueezyTime(attributes_span, "updated_at", &event->m_providerUpdatedAt))
    return BILLING_LEMONSQUEEZY_REASON_UPDATED_AT_BAD;
  if (kind == BILLING_LEMONSQUEEZY_EVENT_SUBSCRIPTION_RESUMED)
  {
    event->m_action = BILLING_ACTION_CLEAR_EXPIRY;
    return BILLING_LEMONSQUEEZY_REASON_NONE;
  }

  JsonReadSpan_t value_span = { 0 };
  if (jsonread_objectKey(attributes_span, "ends_at", &value_span) != JSONREAD_OK || jsonread_isSpanEqual(value_span, "null"))
    return BILLING_LEMONSQUEEZY_REASON_ENDS_AT_MISSING;
  if (!static_tryReadLemonSqueezyTime(attributes_span, "ends_at", &event->m_endsAt))
    return BILLING_LEMONSQUEEZY_REASON_ENDS_AT_BAD;
  event->m_action = BILLING_ACTION_SET_EXPIRY;

  return BILLING_LEMONSQUEEZY_REASON_NONE;
}

static bool static_isIgnoreReason(BillingLemonSqueezyReason_t reason)
{
  return  reason == BILLING_LEMONSQUEEZY_REASON_TEST_MODE         || 
          reason == BILLING_LEMONSQUEEZY_REASON_EVENT_NOT_HANDLED || 
          reason == BILLING_LEMONSQUEEZY_REASON_ORDER_NOT_PAID;
}

static const BillingLemonSqueezyEventRule_t* static_findLemonSqueezyEventRule(const char* event_name)
{
  assert(event_name != NULL);

  for (size_t i = 0; i < sizeof(BILLING_LEMONSQUEEZY_EVENT_RULES) / sizeof(BILLING_LEMONSQUEEZY_EVENT_RULES[0]); i++)
  {
    if (strcmp(BILLING_LEMONSQUEEZY_EVENT_RULES[i].mp_eventName, event_name) == 0)
      return &BILLING_LEMONSQUEEZY_EVENT_RULES[i];
  }
  return NULL;
}

static bool static_tryReadObject(JsonReadSpan_t object_span, const char* key, JsonReadSpan_t* value_out)
{
  assert(key != NULL);
  assert(value_out != NULL);

  return jsonread_objectKey(object_span, key, value_out) == JSONREAD_OK && value_out->m_len > 0 && value_out->mp_start[0] == '{';
}

static bool static_tryReadUuid(JsonReadSpan_t object_span, const char* key, char* uuid_out, size_t uuid_size)
{
  assert(key != NULL);
  assert(uuid_out != NULL);
  assert(uuid_size > VALIDATE_UUID_LEN);

  JsonReadSpan_t value_span = { 0 };
  return  jsonread_objectKey(object_span, key, &value_span) == JSONREAD_OK &&
          static_tryReadUuidSpan(value_span, uuid_out, uuid_size);
}

static bool static_tryReadUuidSpan(JsonReadSpan_t value_span, char* uuid_out, size_t uuid_size)
{
  return jsonread_spanToStrStatus(value_span, uuid_out, uuid_size) == JSONREAD_OK && validate_uuid(uuid_out);
}

static bool static_tryReadLemonSqueezyIdText(JsonReadSpan_t object_span, const char* key, char* ref_out)
{
  assert(key != NULL);
  assert(ref_out != NULL);

  JsonReadSpan_t value_span = { 0 };
  if (jsonread_objectKey(object_span, key, &value_span) != JSONREAD_OK || jsonread_spanToStrStatus(value_span, ref_out, BILLING_LEMONSQUEEZY_REF_MAX_LEN + 1) != JSONREAD_OK)
    return false;
  if (!isdigit((unsigned char)ref_out[0]) || ref_out[0] == '0')
    return false;
  for (size_t i = 1; ref_out[i] != '\0'; i++)
  {
    if (!isdigit((unsigned char)ref_out[i]))
      return false;
  }
  return true;
}

static bool static_tryReadLemonSqueezyIdNumber(JsonReadSpan_t object_span, const char* key, char* ref_out)
{
  assert(key != NULL);
  assert(ref_out != NULL);

  JsonReadSpan_t value_span = { 0 };
  long           value      = 0;
  if (jsonread_objectKey(object_span, key, &value_span) != JSONREAD_OK || jsonread_spanToLongStatus(value_span, &value) != JSONREAD_OK)
    return false;
  if (value < 1)
    return false;
  snprintf(ref_out, BILLING_LEMONSQUEEZY_REF_MAX_LEN + 1, "%ld", value);
  return true;
}

static bool static_tryReadLemonSqueezyTime(JsonReadSpan_t object_span, const char* key, int64_t* epoch_out)
{
  assert(key != NULL);
  assert(epoch_out != NULL);

  JsonReadSpan_t value_span = { 0 };
  char           time_text[BILLING_LEMONSQUEEZY_TIME_MAX_LEN + 1];
  if (jsonread_objectKey(object_span, key, &value_span) != JSONREAD_OK || jsonread_spanToStrStatus(value_span, time_text, sizeof(time_text)) != JSONREAD_OK)
    return false;
  return datetime_tryReadDateTime(time_text, time_text + strlen(time_text), epoch_out);
}
