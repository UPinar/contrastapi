#include <stdio.h>
#include <string.h>

#include "unity/unity.h"
#include "billing.h"

void setUp(void)    { billing_setLemonSqueezySecret(NULL); billing_setNowPaymentsSecret(NULL); }
void tearDown(void) { billing_setLemonSqueezySecret(NULL); billing_setNowPaymentsSecret(NULL); }

#define RFC4231_KEY_LEN    131
#define RFC4231_CASE6_DATA "Test Using Larger Than Block-Size Key - Hash Key First"
#define RFC4231_CASE6_HMAC "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
#define RFC4231_CASE7_DATA "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
#define RFC4231_CASE7_HMAC "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"

#define LEMONSQUEEZY_SECRET      "t_lemonsqueezy_secret_0123456789abcdef01"
#define LEMONSQUEEZY_BODY        "{\"meta\":{\"test_mode\":false,\"event_name\":\"order_created\"}}"
#define LEMONSQUEEZY_BODY_HMAC   "e5acf6572119995d6e4f6c46e36cf07204c3c28eb09a5fad91d2097280411faf"
#define LEMONSQUEEZY_BODY_HMAC32 "4854e7e31178dc6b8f571b46fb77036b0836faf6574c95bcaa47483a835939ae"
#define LEMONSQUEEZY_BODY_HMAC31 "167b701c079fd5e6d40ba15a3e7850d44a1cdf8c1130f8c28fef259352732a7d"
#define LEMONSQUEEZY_NUL_BODY_HMAC "421194fb328c038ae16c31d5adb0905e78c7015c2419df2c2d04f642f5af98d8"
#define LEMONSQUEEZY_A_BODY_HMAC "3b594643c74325b3022a20596bc4509dcf1db70696ba4e3c9a04a7b64958a1c2"

_Static_assert(sizeof(LEMONSQUEEZY_SECRET) - 1 == 40, "LEMONSQUEEZY_SECRET");
_Static_assert(sizeof(LEMONSQUEEZY_BODY_HMAC) - 1 == BILLING_LEMONSQUEEZY_SIGNATURE_LEN, "LEMONSQUEEZY_BODY_HMAC");

static bool static_isLemonSqueezyBodySignatureValid(const char* signature, size_t signature_len)
{
  return billing_isLemonSqueezySignatureValid(LEMONSQUEEZY_SECRET, strlen(LEMONSQUEEZY_SECRET), LEMONSQUEEZY_BODY, strlen(LEMONSQUEEZY_BODY), signature, signature_len);
}

void test_body_signed_only_with_a_stored_secret(void)
{
  TEST_ASSERT_FALSE(billing_isLemonSqueezyBodySigned(LEMONSQUEEZY_BODY, strlen(LEMONSQUEEZY_BODY), LEMONSQUEEZY_BODY_HMAC, strlen(LEMONSQUEEZY_BODY_HMAC)));

  billing_setLemonSqueezySecret(LEMONSQUEEZY_SECRET);
  TEST_ASSERT_TRUE(billing_isLemonSqueezyBodySigned(LEMONSQUEEZY_BODY, strlen(LEMONSQUEEZY_BODY), LEMONSQUEEZY_BODY_HMAC, strlen(LEMONSQUEEZY_BODY_HMAC)));

  billing_setLemonSqueezySecret(NULL);
  TEST_ASSERT_FALSE(billing_isLemonSqueezyBodySigned(LEMONSQUEEZY_BODY, strlen(LEMONSQUEEZY_BODY), LEMONSQUEEZY_BODY_HMAC, strlen(LEMONSQUEEZY_BODY_HMAC)));
}

void test_body_signed_refuses_a_wrong_or_empty_signature(void)
{
  billing_setLemonSqueezySecret(LEMONSQUEEZY_SECRET);
  TEST_ASSERT_FALSE(billing_isLemonSqueezyBodySigned(LEMONSQUEEZY_BODY, strlen(LEMONSQUEEZY_BODY), LEMONSQUEEZY_BODY_HMAC32, strlen(LEMONSQUEEZY_BODY_HMAC32)));
  TEST_ASSERT_FALSE(billing_isLemonSqueezyBodySigned(LEMONSQUEEZY_BODY, strlen(LEMONSQUEEZY_BODY) - 1, LEMONSQUEEZY_BODY_HMAC, strlen(LEMONSQUEEZY_BODY_HMAC)));
  TEST_ASSERT_FALSE(billing_isLemonSqueezyBodySigned(LEMONSQUEEZY_BODY, strlen(LEMONSQUEEZY_BODY), NULL, 0));
  TEST_ASSERT_FALSE(billing_isLemonSqueezyBodySigned(LEMONSQUEEZY_BODY, strlen(LEMONSQUEEZY_BODY), "", 0));
}

void test_signature_rfc4231_cases_6_and_7_verify(void)
{
  char key[RFC4231_KEY_LEN];
  memset(key, 0xaa, sizeof(key));
  TEST_ASSERT_TRUE(billing_isLemonSqueezySignatureValid(key, sizeof(key), RFC4231_CASE6_DATA, strlen(RFC4231_CASE6_DATA), RFC4231_CASE6_HMAC, strlen(RFC4231_CASE6_HMAC)));
  TEST_ASSERT_TRUE(billing_isLemonSqueezySignatureValid(key, sizeof(key), RFC4231_CASE7_DATA, strlen(RFC4231_CASE7_DATA), RFC4231_CASE7_HMAC, strlen(RFC4231_CASE7_HMAC)));
  TEST_ASSERT_FALSE(billing_isLemonSqueezySignatureValid(key, sizeof(key), RFC4231_CASE6_DATA, strlen(RFC4231_CASE6_DATA), RFC4231_CASE7_HMAC, strlen(RFC4231_CASE7_HMAC)));
}

void test_signature_lemonsqueezy_body_verifies(void)
{
  TEST_ASSERT_TRUE(static_isLemonSqueezyBodySignatureValid(LEMONSQUEEZY_BODY_HMAC, strlen(LEMONSQUEEZY_BODY_HMAC)));
}

void test_signature_secret_floor_32_used_31_refused(void)
{
  TEST_ASSERT_EQUAL_INT(32, BILLING_LEMONSQUEEZY_SECRET_MIN_LEN);
  TEST_ASSERT_TRUE(billing_isLemonSqueezySignatureValid(LEMONSQUEEZY_SECRET, 32, LEMONSQUEEZY_BODY, strlen(LEMONSQUEEZY_BODY), LEMONSQUEEZY_BODY_HMAC32, BILLING_LEMONSQUEEZY_SIGNATURE_LEN));
  TEST_ASSERT_FALSE(billing_isLemonSqueezySignatureValid(LEMONSQUEEZY_SECRET, 31, LEMONSQUEEZY_BODY, strlen(LEMONSQUEEZY_BODY), LEMONSQUEEZY_BODY_HMAC31, BILLING_LEMONSQUEEZY_SIGNATURE_LEN));
}

void test_signature_body_with_nul_is_signed_whole(void)
{
  static const char nul_body[3] = { 'a', '\0', 'b' };
  TEST_ASSERT_TRUE(billing_isLemonSqueezySignatureValid(LEMONSQUEEZY_SECRET, strlen(LEMONSQUEEZY_SECRET), nul_body, sizeof(nul_body), LEMONSQUEEZY_NUL_BODY_HMAC, BILLING_LEMONSQUEEZY_SIGNATURE_LEN));
  TEST_ASSERT_FALSE(billing_isLemonSqueezySignatureValid(LEMONSQUEEZY_SECRET, strlen(LEMONSQUEEZY_SECRET), nul_body, 1, LEMONSQUEEZY_NUL_BODY_HMAC, BILLING_LEMONSQUEEZY_SIGNATURE_LEN));
  TEST_ASSERT_TRUE(billing_isLemonSqueezySignatureValid(LEMONSQUEEZY_SECRET, strlen(LEMONSQUEEZY_SECRET), nul_body, 1, LEMONSQUEEZY_A_BODY_HMAC, BILLING_LEMONSQUEEZY_SIGNATURE_LEN));
}

void test_signature_length_63_65_0_refused(void)
{
  char longer[BILLING_LEMONSQUEEZY_SIGNATURE_LEN + 2];
  memcpy(longer, LEMONSQUEEZY_BODY_HMAC, BILLING_LEMONSQUEEZY_SIGNATURE_LEN);
  longer[BILLING_LEMONSQUEEZY_SIGNATURE_LEN]     = '0';
  longer[BILLING_LEMONSQUEEZY_SIGNATURE_LEN + 1] = '\0';

  TEST_ASSERT_FALSE(static_isLemonSqueezyBodySignatureValid(LEMONSQUEEZY_BODY_HMAC, BILLING_LEMONSQUEEZY_SIGNATURE_LEN - 1));
  TEST_ASSERT_FALSE(static_isLemonSqueezyBodySignatureValid(longer, BILLING_LEMONSQUEEZY_SIGNATURE_LEN + 1));
  TEST_ASSERT_FALSE(static_isLemonSqueezyBodySignatureValid("", 0));
}

void test_signature_upper_case_copy_refused(void)
{
  char upper[BILLING_LEMONSQUEEZY_SIGNATURE_LEN + 1];
  for (size_t i = 0; i <= BILLING_LEMONSQUEEZY_SIGNATURE_LEN; i++)
    upper[i] = (LEMONSQUEEZY_BODY_HMAC[i] >= 'a' && LEMONSQUEEZY_BODY_HMAC[i] <= 'f') ? (char)(LEMONSQUEEZY_BODY_HMAC[i] - 'a' + 'A') : LEMONSQUEEZY_BODY_HMAC[i];
  TEST_ASSERT_FALSE(static_isLemonSqueezyBodySignatureValid(upper, BILLING_LEMONSQUEEZY_SIGNATURE_LEN));
}

void test_signature_first_or_last_byte_changed_refused(void)
{
  char changed[BILLING_LEMONSQUEEZY_SIGNATURE_LEN + 1];

  memcpy(changed, LEMONSQUEEZY_BODY_HMAC, sizeof(changed));
  changed[0] = changed[0] == '0' ? '1' : '0';
  TEST_ASSERT_FALSE(static_isLemonSqueezyBodySignatureValid(changed, BILLING_LEMONSQUEEZY_SIGNATURE_LEN));

  memcpy(changed, LEMONSQUEEZY_BODY_HMAC, sizeof(changed));
  changed[BILLING_LEMONSQUEEZY_SIGNATURE_LEN - 1] = changed[BILLING_LEMONSQUEEZY_SIGNATURE_LEN - 1] == '0' ? '1' : '0';
  TEST_ASSERT_FALSE(static_isLemonSqueezyBodySignatureValid(changed, BILLING_LEMONSQUEEZY_SIGNATURE_LEN));
}

void test_signature_body_byte_changed_refused(void)
{
  char body[sizeof(LEMONSQUEEZY_BODY)];
  memcpy(body, LEMONSQUEEZY_BODY, sizeof(body));
  body[strlen(LEMONSQUEEZY_BODY) - 3] = 'X';
  TEST_ASSERT_FALSE(billing_isLemonSqueezySignatureValid(LEMONSQUEEZY_SECRET, strlen(LEMONSQUEEZY_SECRET), body, strlen(body), LEMONSQUEEZY_BODY_HMAC, BILLING_LEMONSQUEEZY_SIGNATURE_LEN));
}

#define ORDER_BODY "{\"meta\":{\"test_mode\":false,\"event_name\":\"order_created\",\"webhook_id\":\"0f8e4b1a-2c3d-4e5f-8a9b-0c1d2e3f4a5b\",\"custom_data\":{\"note\":\"x\"}},\"data\":{\"type\":\"orders\",\"id\":\"9915543\",\"attributes\":{\"store_id\":1,\"identifier\":\"5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d\",\"order_number\":1001,\"status\":\"paid\",\"refunded\":false,\"test_mode\":false,\"updated_at\":\"2026-11-01T04:20:44.000000Z\",\"urls\":{\"receipt\":\"https:\\/\\/example.invalid\\/r\\/1\"}}}}"
#define SUB_BODY "{\"meta\":{\"test_mode\":false,\"event_name\":\"subscription_cancelled\",\"webhook_id\":\"1b2c3d4e-5f60-4718-9a2b-3c4d5e6f7081\"},\"data\":{\"type\":\"subscriptions\",\"id\":\"1234567\",\"attributes\":{\"store_id\":1,\"order_id\":9915543,\"status\":\"cancelled\",\"cancelled\":true,\"test_mode\":false,\"updated_at\":\"2026-11-01T04:20:44.000000Z\",\"ends_at\":\"2026-12-01T04:20:44.000000Z\",\"urls\":{\"customer_portal\":\"https:\\/\\/example.invalid\\/p\"}}}}"
#define INVOICE_BODY "{\"meta\":{\"test_mode\":false,\"event_name\":\"subscription_payment_refunded\",\"webhook_id\":\"2c3d4e5f-6071-4829-8b3c-4d5e6f708192\"},\"data\":{\"type\":\"subscription-invoices\",\"id\":\"555\",\"attributes\":{\"store_id\":1,\"subscription_id\":1234567,\"status\":\"refunded\",\"refunded\":true,\"test_mode\":false,\"updated_at\":\"2026-11-01T04:20:44.000000Z\"}}}"

#define ORDER_WEBHOOK_ID   "0f8e4b1a-2c3d-4e5f-8a9b-0c1d2e3f4a5b"
#define ORDER_IDENTIFIER   "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d"
#define SUB_WEBHOOK_ID     "1b2c3d4e-5f60-4718-9a2b-3c4d5e6f7081"
#define INVOICE_WEBHOOK_ID "2c3d4e5f-6071-4829-8b3c-4d5e6f708192"

#define UPDATED_AT_EPOCH 1793506844
#define ENDS_AT_EPOCH    1796098844

#define BODY_BUF_SIZE 4096

static char                       g_bodyBuf[2][BODY_BUF_SIZE];
static BillingLemonSqueezyEvent_t g_event;

static const char* static_bodyWithIn(int slot, const char* base, const char* old_text, const char* new_text)
{
  const char* hit = strstr(base, old_text);
  TEST_ASSERT_NOT_NULL_MESSAGE(hit, old_text);
  TEST_ASSERT_NULL_MESSAGE(strstr(hit + 1, old_text), old_text);
  int written = snprintf(g_bodyBuf[slot], BODY_BUF_SIZE, "%.*s%s%s", (int)(hit - base), base, new_text, hit + strlen(old_text));
  TEST_ASSERT_TRUE(written > 0 && written < BODY_BUF_SIZE);
  return g_bodyBuf[slot];
}

static const char* static_bodyWith(const char* base, const char* old_text, const char* new_text)
{
  return static_bodyWithIn(0, base, old_text, new_text);
}

static const char* static_bodyWith2(const char* base, const char* old_1, const char* new_1, const char* old_2, const char* new_2)
{
  const char* first = static_bodyWithIn(0, base, old_1, new_1);
  return static_bodyWithIn(1, first, old_2, new_2);
}

static void static_parse(const char* body)
{
  memset(&g_event, 0xA5, sizeof(g_event));
  billing_parseLemonSqueezyEvent(body, strlen(body), &g_event);
}

#define F_WEBHOOK    0x01
#define F_ORDER_ID   0x02
#define F_ORDER_REF  0x04
#define F_SUB_REF    0x08
#define F_UPDATED_AT 0x10
#define F_ENDS_AT    0x20

static void static_assertOnlyFields(int fields)
{
  if (!(fields & F_WEBHOOK))    TEST_ASSERT_EQUAL_STRING("", g_event.ma_webhookId);
  if (!(fields & F_ORDER_ID))   TEST_ASSERT_EQUAL_STRING("", g_event.ma_orderId);
  if (!(fields & F_ORDER_REF))  TEST_ASSERT_EQUAL_STRING("", g_event.ma_providerOrderRef);
  if (!(fields & F_SUB_REF))    TEST_ASSERT_EQUAL_STRING("", g_event.ma_providerSubscriptionRef);
  if (!(fields & F_UPDATED_AT)) TEST_ASSERT_EQUAL_INT64(0, g_event.m_providerUpdatedAt);
  if (!(fields & F_ENDS_AT))    TEST_ASSERT_EQUAL_INT64(0, g_event.m_endsAt);
}

static void static_assertRefused(const char* body, BillingLemonSqueezyReason_t reason)
{
  static_parse(body);
  TEST_ASSERT_EQUAL_INT_MESSAGE(BILLING_ACTION_REFUSE, g_event.m_action, body);
  TEST_ASSERT_EQUAL_INT_MESSAGE(reason, g_event.m_reason, body);
  static_assertOnlyFields(0);
}

static void static_assertIgnored(const char* body, BillingLemonSqueezyReason_t reason)
{
  static_parse(body);
  TEST_ASSERT_EQUAL_INT_MESSAGE(BILLING_ACTION_IGNORE, g_event.m_action, body);
  TEST_ASSERT_EQUAL_INT_MESSAGE(reason, g_event.m_reason, body);
  static_assertOnlyFields(0);
}

static void static_assertActs(const char* body, BillingAction_t action)
{
  static_parse(body);
  TEST_ASSERT_EQUAL_INT_MESSAGE(BILLING_LEMONSQUEEZY_REASON_NONE, g_event.m_reason, body);
  TEST_ASSERT_EQUAL_INT_MESSAGE(action, g_event.m_action, body);
}

void test_parse_row1_meta_test_mode_true_ignored_before_later_fields(void)
{
  static_assertIgnored(static_bodyWith(ORDER_BODY, "{\"test_mode\":false,", "{\"test_mode\":true,"), BILLING_LEMONSQUEEZY_REASON_TEST_MODE);
  TEST_ASSERT_NULL(g_event.mp_eventName);
  static_assertIgnored("{\"meta\":{\"test_mode\":true,\"event_name\":\"order_created\"}}", BILLING_LEMONSQUEEZY_REASON_TEST_MODE);
  static_assertIgnored("{\"meta\":{\"test_mode\":true,\"event_name\":\"order_created\",\"webhook_id\":\"bad\"},\"data\":1}", BILLING_LEMONSQUEEZY_REASON_TEST_MODE);
  static_assertIgnored("{\"meta\":{\"event_name\":\"subscription_paused\",\"test_mode\":true}}", BILLING_LEMONSQUEEZY_REASON_TEST_MODE);
}

void test_parse_row2_unhandled_names_ignored(void)
{
  static const char* const names[] = {
    "subscription_paused", "subscription_unpaused", "subscription_created", "subscription_updated",
    "subscription_payment_success", "subscription_payment_failed", "subscription_payment_recovered",
    "subscription_plan_changed", "license_key_created", "order_create", "order_createdx", "ORDER_CREATED", "",
  };
  char quoted[64];
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
  {
    snprintf(quoted, sizeof(quoted), "\"%s\"", names[i]);
    static_assertIgnored(static_bodyWith(ORDER_BODY, "\"order_created\"", quoted), BILLING_LEMONSQUEEZY_REASON_EVENT_NOT_HANDLED);
    TEST_ASSERT_NULL(g_event.mp_eventName);
  }
  static_assertIgnored("{\"meta\":{\"event_name\":\"subscription_paused\"}}", BILLING_LEMONSQUEEZY_REASON_EVENT_NOT_HANDLED);
  static_assertIgnored("{\"meta\":{\"event_name\":\"subscription_unpaused\"},\"data\":[]}", BILLING_LEMONSQUEEZY_REASON_EVENT_NOT_HANDLED);
}

void test_parse_row2_too_long_name_not_handled(void)
{
  char body[512];
  char name[301];
  memset(name, 'a', 300);
  name[300] = '\0';
  snprintf(body, sizeof(body), "{\"meta\":{\"event_name\":\"%s\"}}", name);
  static_assertIgnored(body, BILLING_LEMONSQUEEZY_REASON_EVENT_NOT_HANDLED);
  name[BILLING_LEMONSQUEEZY_EVENT_NAME_MAX_LEN + 1] = '\0';
  snprintf(body, sizeof(body), "{\"meta\":{\"event_name\":\"%s\"}}", name);
  static_assertIgnored(body, BILLING_LEMONSQUEEZY_REASON_EVENT_NOT_HANDLED);
  snprintf(body, sizeof(body), "{\"meta\":{\"event_name\":\"%s\",\"test_mode\":true}}", name);
  static_assertIgnored(body, BILLING_LEMONSQUEEZY_REASON_TEST_MODE);
}

void test_parse_row3_attributes_test_mode_true_ignored(void)
{
  static_assertIgnored(static_bodyWith(ORDER_BODY, "\"test_mode\":false,\"updated_at\"", "\"test_mode\":true,\"updated_at\""), BILLING_LEMONSQUEEZY_REASON_TEST_MODE);
  TEST_ASSERT_EQUAL_STRING("order_created", g_event.mp_eventName);
  static_assertIgnored(static_bodyWith2(ORDER_BODY, "\"test_mode\":false,\"updated_at\"", "\"test_mode\":true,\"updated_at\"", ORDER_WEBHOOK_ID, "bad"), BILLING_LEMONSQUEEZY_REASON_TEST_MODE);
  static_assertIgnored(static_bodyWith2(ORDER_BODY, "\"test_mode\":false,\"updated_at\"", "\"test_mode\":true,\"updated_at\"", ORDER_IDENTIFIER, "BAD"), BILLING_LEMONSQUEEZY_REASON_TEST_MODE);
  static_assertIgnored(static_bodyWith(SUB_BODY, "\"test_mode\":false,\"updated_at\"", "\"test_mode\":true,\"updated_at\""), BILLING_LEMONSQUEEZY_REASON_TEST_MODE);
}

void test_parse_row4_order_paid(void)
{
  static_assertActs(ORDER_BODY, BILLING_ACTION_ORDER_PAID);
  TEST_ASSERT_EQUAL_STRING("order_created", g_event.mp_eventName);
  TEST_ASSERT_EQUAL_STRING(ORDER_WEBHOOK_ID, g_event.ma_webhookId);
  TEST_ASSERT_EQUAL_STRING(ORDER_IDENTIFIER, g_event.ma_orderId);
  TEST_ASSERT_EQUAL_STRING("9915543", g_event.ma_providerOrderRef);
  static_assertOnlyFields(F_WEBHOOK | F_ORDER_ID | F_ORDER_REF);
}

void test_parse_row5_order_not_paid_ignored(void)
{
  static const char* const statuses[] = { "\"pending\"", "\"failed\"", "\"refunded\"", "\"Paid\"", "\"paid \"", "\"pai\"", "\"paidpaidpaidpaidpaidpaidpaidpaidpaidpaid\"", "\"pa\\/id\"", "\"\"" };
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
  {
    static_assertIgnored(static_bodyWith(ORDER_BODY, "\"paid\"", statuses[i]), BILLING_LEMONSQUEEZY_REASON_ORDER_NOT_PAID);
    TEST_ASSERT_EQUAL_STRING("order_created", g_event.mp_eventName);
  }
}

void test_parse_row6_subscription_cancelled_sets_expiry(void)
{
  static_assertActs(SUB_BODY, BILLING_ACTION_SET_EXPIRY);
  TEST_ASSERT_EQUAL_STRING("subscription_cancelled", g_event.mp_eventName);
  TEST_ASSERT_EQUAL_STRING(SUB_WEBHOOK_ID, g_event.ma_webhookId);
  TEST_ASSERT_EQUAL_STRING("1234567", g_event.ma_providerSubscriptionRef);
  TEST_ASSERT_EQUAL_STRING("9915543", g_event.ma_providerOrderRef);
  TEST_ASSERT_EQUAL_INT64(UPDATED_AT_EPOCH, g_event.m_providerUpdatedAt);
  TEST_ASSERT_EQUAL_INT64(ENDS_AT_EPOCH, g_event.m_endsAt);
  static_assertOnlyFields(F_WEBHOOK | F_ORDER_REF | F_SUB_REF | F_UPDATED_AT | F_ENDS_AT);
}

void test_parse_row7_cancelled_without_ends_at_refused(void)
{
  static_assertRefused(static_bodyWith(SUB_BODY, "\"2026-12-01T04:20:44.000000Z\"", "null"), BILLING_LEMONSQUEEZY_REASON_ENDS_AT_MISSING);
  static_assertRefused(static_bodyWith(SUB_BODY, "\"ends_at\":\"2026-12-01T04:20:44.000000Z\",", ""), BILLING_LEMONSQUEEZY_REASON_ENDS_AT_MISSING);
}

void test_parse_row8_subscription_resumed_clears_expiry(void)
{
  const char* resumed_null = static_bodyWith2(SUB_BODY, "subscription_cancelled", "subscription_resumed", "\"2026-12-01T04:20:44.000000Z\"", "null");
  static_assertActs(resumed_null, BILLING_ACTION_CLEAR_EXPIRY);
  TEST_ASSERT_EQUAL_STRING("subscription_resumed", g_event.mp_eventName);
  TEST_ASSERT_EQUAL_STRING(SUB_WEBHOOK_ID, g_event.ma_webhookId);
  TEST_ASSERT_EQUAL_STRING("1234567", g_event.ma_providerSubscriptionRef);
  TEST_ASSERT_EQUAL_STRING("9915543", g_event.ma_providerOrderRef);
  TEST_ASSERT_EQUAL_INT64(UPDATED_AT_EPOCH, g_event.m_providerUpdatedAt);
  static_assertOnlyFields(F_WEBHOOK | F_ORDER_REF | F_SUB_REF | F_UPDATED_AT);

  static_assertActs(static_bodyWith2(SUB_BODY, "subscription_cancelled", "subscription_resumed", "\"2026-12-01T04:20:44.000000Z\"", "5"), BILLING_ACTION_CLEAR_EXPIRY);
  static_assertOnlyFields(F_WEBHOOK | F_ORDER_REF | F_SUB_REF | F_UPDATED_AT);
}

void test_parse_row9_subscription_expired_revokes(void)
{
  static_assertActs(static_bodyWith(SUB_BODY, "subscription_cancelled", "subscription_expired"), BILLING_ACTION_REVOKE);
  TEST_ASSERT_EQUAL_STRING("subscription_expired", g_event.mp_eventName);
  TEST_ASSERT_EQUAL_STRING(SUB_WEBHOOK_ID, g_event.ma_webhookId);
  TEST_ASSERT_EQUAL_STRING("1234567", g_event.ma_providerSubscriptionRef);
  TEST_ASSERT_EQUAL_STRING("9915543", g_event.ma_providerOrderRef);
  static_assertOnlyFields(F_WEBHOOK | F_ORDER_REF | F_SUB_REF);

  static_assertActs(static_bodyWith2(SUB_BODY, "subscription_cancelled", "subscription_expired", "\"2026-11-01T04:20:44.000000Z\"", "5"), BILLING_ACTION_REVOKE);
  static_assertOnlyFields(F_WEBHOOK | F_ORDER_REF | F_SUB_REF);
}

void test_parse_row10_order_fully_refunded_revokes(void)
{
  const char* refunded = static_bodyWith2(ORDER_BODY, "order_created", "order_refunded", "\"refunded\":false", "\"refunded\":true");
  static_assertActs(refunded, BILLING_ACTION_REVOKE);
  TEST_ASSERT_EQUAL_STRING("order_refunded", g_event.mp_eventName);
  TEST_ASSERT_EQUAL_STRING(ORDER_WEBHOOK_ID, g_event.ma_webhookId);
  TEST_ASSERT_EQUAL_STRING("9915543", g_event.ma_providerOrderRef);
  static_assertOnlyFields(F_WEBHOOK | F_ORDER_REF);

  const char* no_identifier = static_bodyWith(refunded, ORDER_IDENTIFIER, "BAD");
  static_assertActs(static_bodyWithIn(1, no_identifier, "\"paid\"", "1"), BILLING_ACTION_REVOKE);
}

void test_parse_row11_order_partly_refunded_recorded(void)
{
  static_assertActs(static_bodyWith(ORDER_BODY, "order_created", "order_refunded"), BILLING_ACTION_RECORD);
  TEST_ASSERT_EQUAL_STRING("order_refunded", g_event.mp_eventName);
  TEST_ASSERT_EQUAL_STRING(ORDER_WEBHOOK_ID, g_event.ma_webhookId);
  TEST_ASSERT_EQUAL_STRING("9915543", g_event.ma_providerOrderRef);
  static_assertOnlyFields(F_WEBHOOK | F_ORDER_REF);
}

void test_parse_row12_subscription_payment_refunded_recorded(void)
{
  static_assertActs(INVOICE_BODY, BILLING_ACTION_RECORD);
  TEST_ASSERT_EQUAL_STRING("subscription_payment_refunded", g_event.mp_eventName);
  TEST_ASSERT_EQUAL_STRING(INVOICE_WEBHOOK_ID, g_event.ma_webhookId);
  TEST_ASSERT_EQUAL_STRING("1234567", g_event.ma_providerSubscriptionRef);
  static_assertOnlyFields(F_WEBHOOK | F_SUB_REF);
}

void test_parse_body_not_object_refused(void)
{
  static const char* const bodies[] = { "", "   ", "[]", "\"x\"", "null", "1", "{", ORDER_BODY "x" };
  for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); i++)
    static_assertRefused(bodies[i], BILLING_LEMONSQUEEZY_REASON_BODY_NOT_OBJECT);

  memset(&g_event, 0xA5, sizeof(g_event));
  billing_parseLemonSqueezyEvent(NULL, 0, &g_event);
  TEST_ASSERT_EQUAL_INT(BILLING_ACTION_REFUSE, g_event.m_action);
  TEST_ASSERT_EQUAL_INT(BILLING_LEMONSQUEEZY_REASON_BODY_NOT_OBJECT, g_event.m_reason);
}

void test_parse_reads_body_len_bytes_only(void)
{
  memset(&g_event, 0xA5, sizeof(g_event));
  billing_parseLemonSqueezyEvent(ORDER_BODY, strlen(ORDER_BODY) - 1, &g_event);
  TEST_ASSERT_EQUAL_INT(BILLING_LEMONSQUEEZY_REASON_BODY_NOT_OBJECT, g_event.m_reason);
}

void test_parse_meta_bad_refused(void)
{
  static_assertRefused("{\"data\":{}}", BILLING_LEMONSQUEEZY_REASON_META_BAD);
  static_assertRefused("{\"meta\":[]}", BILLING_LEMONSQUEEZY_REASON_META_BAD);
  static_assertRefused("{\"meta\":\"order_created\"}", BILLING_LEMONSQUEEZY_REASON_META_BAD);
}

void test_parse_event_name_bad_refused(void)
{
  static_assertRefused("{\"meta\":{\"test_mode\":true}}", BILLING_LEMONSQUEEZY_REASON_EVENT_NAME_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"order_created\"", "7"), BILLING_LEMONSQUEEZY_REASON_EVENT_NAME_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"order_created\"", "null"), BILLING_LEMONSQUEEZY_REASON_EVENT_NAME_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"order_created\"", "\"order\\u0000created\""), BILLING_LEMONSQUEEZY_REASON_EVENT_NAME_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"order_created\"", "\"order\\ud800created\""), BILLING_LEMONSQUEEZY_REASON_EVENT_NAME_BAD);
}

void test_parse_test_mode_bad_refused(void)
{
  static_assertRefused(static_bodyWith(ORDER_BODY, "{\"test_mode\":false,", "{\"test_mode\":\"true\","), BILLING_LEMONSQUEEZY_REASON_TEST_MODE_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, "{\"test_mode\":false,", "{\"test_mode\":1,"), BILLING_LEMONSQUEEZY_REASON_TEST_MODE_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, "{\"test_mode\":false,", "{\"test_mode\":null,"), BILLING_LEMONSQUEEZY_REASON_TEST_MODE_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"test_mode\":false,\"updated_at\"", "\"updated_at\""), BILLING_LEMONSQUEEZY_REASON_TEST_MODE_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"test_mode\":false,\"updated_at\"", "\"test_mode\":\"false\",\"updated_at\""), BILLING_LEMONSQUEEZY_REASON_TEST_MODE_BAD);
}

void test_parse_meta_test_mode_absent_acts(void)
{
  static_assertActs(static_bodyWith(SUB_BODY, "{\"test_mode\":false,", "{"), BILLING_ACTION_SET_EXPIRY);
  static_assertActs(static_bodyWith(ORDER_BODY, "{\"test_mode\":false,", "{"), BILLING_ACTION_ORDER_PAID);
}

void test_parse_data_bad_refused(void)
{
  static_assertRefused("{\"meta\":{\"event_name\":\"order_created\",\"webhook_id\":\"" ORDER_WEBHOOK_ID "\"}}", BILLING_LEMONSQUEEZY_REASON_DATA_BAD);
  static_assertRefused("{\"meta\":{\"event_name\":\"order_created\"},\"data\":\"x\"}", BILLING_LEMONSQUEEZY_REASON_DATA_BAD);
  static_assertRefused("{\"meta\":{\"event_name\":\"order_created\"},\"data\":{\"type\":\"orders\"}}", BILLING_LEMONSQUEEZY_REASON_DATA_BAD);
  static_assertRefused("{\"meta\":{\"event_name\":\"order_created\"},\"data\":{\"attributes\":[]}}", BILLING_LEMONSQUEEZY_REASON_DATA_BAD);
}

void test_parse_webhook_id_bad_refused(void)
{
  static_assertRefused(static_bodyWith(ORDER_BODY, ",\"webhook_id\":\"" ORDER_WEBHOOK_ID "\"", ""), BILLING_LEMONSQUEEZY_REASON_WEBHOOK_ID_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, ORDER_WEBHOOK_ID, "0F8E4B1A-2C3D-4E5F-8A9B-0C1D2E3F4A5B"), BILLING_LEMONSQUEEZY_REASON_WEBHOOK_ID_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, ORDER_WEBHOOK_ID, "0f8e4b1a-2c3d-4e5f-8a9b-0c1d2e3f4a5"), BILLING_LEMONSQUEEZY_REASON_WEBHOOK_ID_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, ORDER_WEBHOOK_ID, "0f8e4b1a-2c3d-4e5f-8a9b-0c1d2e3f4a5b0"), BILLING_LEMONSQUEEZY_REASON_WEBHOOK_ID_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"" ORDER_WEBHOOK_ID "\"", "12345"), BILLING_LEMONSQUEEZY_REASON_WEBHOOK_ID_BAD);
}

void test_parse_data_type_bad_refused(void)
{
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"orders\"", "\"subscriptions\""), BILLING_LEMONSQUEEZY_REASON_DATA_TYPE_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"orders\"", "\"Orders\""), BILLING_LEMONSQUEEZY_REASON_DATA_TYPE_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"orders\"", "\"orders-and-more-than-thirty-two-bytes\""), BILLING_LEMONSQUEEZY_REASON_DATA_TYPE_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"type\":\"orders\",", ""), BILLING_LEMONSQUEEZY_REASON_DATA_TYPE_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"orders\"", "1"), BILLING_LEMONSQUEEZY_REASON_DATA_TYPE_BAD);
  static_assertRefused(static_bodyWith(SUB_BODY, "\"subscriptions\"", "\"orders\""), BILLING_LEMONSQUEEZY_REASON_DATA_TYPE_BAD);
  static_assertRefused(static_bodyWith(INVOICE_BODY, "\"subscription-invoices\"", "\"subscriptions\""), BILLING_LEMONSQUEEZY_REASON_DATA_TYPE_BAD);
  static_assertRefused(static_bodyWith2(ORDER_BODY, "order_created", "order_refunded", "\"orders\"", "\"subscriptions\""), BILLING_LEMONSQUEEZY_REASON_DATA_TYPE_BAD);
  static_assertRefused(static_bodyWith2(SUB_BODY, "subscription_cancelled", "subscription_expired", "\"subscriptions\"", "\"orders\""), BILLING_LEMONSQUEEZY_REASON_DATA_TYPE_BAD);
}

void test_parse_id_bad_refused(void)
{
  static const char* const ids[] = { "\"0\"", "\"01\"", "\"12a\"", "\"\"", "\"12345678901234567890\"", "9915543", "\"-1\"", "\" 1\"", "\"/1\"", "\":1\"", "\"1/\"", "\"1:\"" };
  for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++)
  {
    static_assertRefused(static_bodyWith(ORDER_BODY, "\"9915543\"", ids[i]), BILLING_LEMONSQUEEZY_REASON_ID_BAD);
    static_assertRefused(static_bodyWith(SUB_BODY, "\"1234567\"", ids[i]), BILLING_LEMONSQUEEZY_REASON_ID_BAD);
  }
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"id\":\"9915543\",", ""), BILLING_LEMONSQUEEZY_REASON_ID_BAD);
}

void test_parse_id_19_digits_and_1_digit_read(void)
{
  static_assertActs(static_bodyWith(ORDER_BODY, "\"9915543\"", "\"1234567890123456789\""), BILLING_ACTION_ORDER_PAID);
  TEST_ASSERT_EQUAL_STRING("1234567890123456789", g_event.ma_providerOrderRef);
  static_assertActs(static_bodyWith(SUB_BODY, "\"1234567\"", "\"9\""), BILLING_ACTION_SET_EXPIRY);
  TEST_ASSERT_EQUAL_STRING("9", g_event.ma_providerSubscriptionRef);
}

void test_parse_order_ref_bad_refused(void)
{
  static const char* const refs[] = { "0", "-1", "1.5", "\"9915543\"", "1e3", "null", "9223372036854775808" };
  for (size_t i = 0; i < sizeof(refs) / sizeof(refs[0]); i++)
    static_assertRefused(static_bodyWith(SUB_BODY, "9915543", refs[i]), BILLING_LEMONSQUEEZY_REASON_ORDER_REF_BAD);
  static_assertRefused(static_bodyWith(SUB_BODY, "\"order_id\":9915543,", ""), BILLING_LEMONSQUEEZY_REASON_ORDER_REF_BAD);
}

void test_parse_order_ref_text_same_from_string_and_number(void)
{
  static_assertActs(ORDER_BODY, BILLING_ACTION_ORDER_PAID);
  char from_order[BILLING_LEMONSQUEEZY_REF_MAX_LEN + 1];
  memcpy(from_order, g_event.ma_providerOrderRef, sizeof(from_order));
  static_assertActs(SUB_BODY, BILLING_ACTION_SET_EXPIRY);
  TEST_ASSERT_EQUAL_STRING(from_order, g_event.ma_providerOrderRef);

  static_assertActs(static_bodyWith(SUB_BODY, "9915543", "9223372036854775807"), BILLING_ACTION_SET_EXPIRY);
  TEST_ASSERT_EQUAL_STRING("9223372036854775807", g_event.ma_providerOrderRef);
  static_assertActs(static_bodyWith(SUB_BODY, "9915543", "1"), BILLING_ACTION_SET_EXPIRY);
  TEST_ASSERT_EQUAL_STRING("1", g_event.ma_providerOrderRef);
}

void test_parse_subscription_ref_bad_refused(void)
{
  static const char* const refs[] = { "0", "-5", "\"1234567\"", "2.0" };
  for (size_t i = 0; i < sizeof(refs) / sizeof(refs[0]); i++)
    static_assertRefused(static_bodyWith(INVOICE_BODY, "1234567", refs[i]), BILLING_LEMONSQUEEZY_REASON_SUBSCRIPTION_REF_BAD);
  static_assertRefused(static_bodyWith(INVOICE_BODY, "\"subscription_id\":1234567,", ""), BILLING_LEMONSQUEEZY_REASON_SUBSCRIPTION_REF_BAD);
}

void test_parse_identifier_bad_refused(void)
{
  static_assertRefused(static_bodyWith(ORDER_BODY, ORDER_IDENTIFIER, "5A6B7C8D-9E0F-4A1B-8C2D-3E4F5A6B7C8D"), BILLING_LEMONSQUEEZY_REASON_IDENTIFIER_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, ORDER_IDENTIFIER, "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8"), BILLING_LEMONSQUEEZY_REASON_IDENTIFIER_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"identifier\":\"" ORDER_IDENTIFIER "\",", ""), BILLING_LEMONSQUEEZY_REASON_IDENTIFIER_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"" ORDER_IDENTIFIER "\"", "42"), BILLING_LEMONSQUEEZY_REASON_IDENTIFIER_BAD);
}

void test_parse_status_bad_refused(void)
{
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"status\":\"paid\",", ""), BILLING_LEMONSQUEEZY_REASON_STATUS_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"paid\"", "1"), BILLING_LEMONSQUEEZY_REASON_STATUS_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"paid\"", "null"), BILLING_LEMONSQUEEZY_REASON_STATUS_BAD);
  static_assertRefused(static_bodyWith(ORDER_BODY, "\"paid\"", "\"pa\\u0000\""), BILLING_LEMONSQUEEZY_REASON_STATUS_BAD);
}

void test_parse_updated_at_bad_refused(void)
{
  static const char* const times[] = { "\"2026-11-01T04:20:44.000000\"", "\"2026-02-30T04:20:44Z\"", "1793506844", "null", "\"2026-11-01\"", "\"\"" };
  for (size_t i = 0; i < sizeof(times) / sizeof(times[0]); i++)
  {
    static_assertRefused(static_bodyWith(SUB_BODY, "\"2026-11-01T04:20:44.000000Z\"", times[i]), BILLING_LEMONSQUEEZY_REASON_UPDATED_AT_BAD);
    static_assertRefused(static_bodyWith2(SUB_BODY, "subscription_cancelled", "subscription_resumed", "\"2026-11-01T04:20:44.000000Z\"", times[i]), BILLING_LEMONSQUEEZY_REASON_UPDATED_AT_BAD);
  }
  static_assertRefused(static_bodyWith(SUB_BODY, "\"updated_at\":\"2026-11-01T04:20:44.000000Z\",", ""), BILLING_LEMONSQUEEZY_REASON_UPDATED_AT_BAD);
}

void test_parse_updated_at_offset_read_as_utc(void)
{
  static_assertActs(static_bodyWith(SUB_BODY, "\"2026-11-01T04:20:44.000000Z\"", "\"2026-11-01T07:20:44+03:00\""), BILLING_ACTION_SET_EXPIRY);
  TEST_ASSERT_EQUAL_INT64(UPDATED_AT_EPOCH, g_event.m_providerUpdatedAt);
}

void test_parse_time_of_35_bytes_read_36_refused(void)
{
  static const char time_34[] = "\"2026-11-01T07:20:44.12345678+03:00\"";
  static const char time_35[] = "\"2026-11-01T07:20:44.123456789+03:00\"";
  static const char time_36[] = "\"2026-11-01T07:20:44.1234567890+03:00\"";
  TEST_ASSERT_EQUAL_size_t(34, sizeof(time_34) - 3);
  TEST_ASSERT_EQUAL_size_t(35, sizeof(time_35) - 3);
  TEST_ASSERT_EQUAL_size_t(36, sizeof(time_36) - 3);

  static_assertActs(static_bodyWith(SUB_BODY, "\"2026-11-01T04:20:44.000000Z\"", time_34), BILLING_ACTION_SET_EXPIRY);
  TEST_ASSERT_EQUAL_INT64(1793506844, g_event.m_providerUpdatedAt);
  static_assertActs(static_bodyWith(SUB_BODY, "\"2026-11-01T04:20:44.000000Z\"", time_35), BILLING_ACTION_SET_EXPIRY);
  TEST_ASSERT_EQUAL_INT64(1793506844, g_event.m_providerUpdatedAt);
  static_assertRefused(static_bodyWith(SUB_BODY, "\"2026-11-01T04:20:44.000000Z\"", time_36), BILLING_LEMONSQUEEZY_REASON_UPDATED_AT_BAD);

  static_assertActs(static_bodyWith(SUB_BODY, "\"2026-12-01T04:20:44.000000Z\"", time_35), BILLING_ACTION_SET_EXPIRY);
  TEST_ASSERT_EQUAL_INT64(1793506844, g_event.m_endsAt);
  static_assertRefused(static_bodyWith(SUB_BODY, "\"2026-12-01T04:20:44.000000Z\"", time_36), BILLING_LEMONSQUEEZY_REASON_ENDS_AT_BAD);
}

void test_parse_ends_at_bad_refused(void)
{
  static const char* const times[] = { "5", "true", "\"2026-12-01T04:20:44\"", "\"2026-02-30T00:00:00Z\"", "{}" };
  for (size_t i = 0; i < sizeof(times) / sizeof(times[0]); i++)
    static_assertRefused(static_bodyWith(SUB_BODY, "\"2026-12-01T04:20:44.000000Z\"", times[i]), BILLING_LEMONSQUEEZY_REASON_ENDS_AT_BAD);
}

void test_parse_refunded_bad_refused(void)
{
  const char* refunded = static_bodyWith(ORDER_BODY, "order_created", "order_refunded");
  static const char* const values[] = { "\"refunded\":\"true\"", "\"refunded\":1", "\"refunded\":null", "\"refundedx\":true" };
  char base[BODY_BUF_SIZE];
  snprintf(base, sizeof(base), "%s", refunded);
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
    static_assertRefused(static_bodyWithIn(1, base, "\"refunded\":false", values[i]), BILLING_LEMONSQUEEZY_REASON_REFUNDED_BAD);
}

void test_parse_read_order_earlier_field_names_reason(void)
{
  static_assertRefused("{\"meta\":{\"event_name\":\"subscription_paused\",\"test_mode\":\"yes\"}}", BILLING_LEMONSQUEEZY_REASON_TEST_MODE_BAD);
  static_assertRefused(static_bodyWith2(ORDER_BODY, "\"test_mode\":false,\"updated_at\"", "\"updated_at\"", ORDER_WEBHOOK_ID, "bad"), BILLING_LEMONSQUEEZY_REASON_TEST_MODE_BAD);
  static_assertRefused(static_bodyWith2(ORDER_BODY, ORDER_WEBHOOK_ID, "bad", "\"orders\"", "\"subscriptions\""), BILLING_LEMONSQUEEZY_REASON_WEBHOOK_ID_BAD);
  static_assertRefused(static_bodyWith2(ORDER_BODY, "\"orders\"", "\"subscriptions\"", "\"9915543\"", "\"0\""), BILLING_LEMONSQUEEZY_REASON_DATA_TYPE_BAD);
  static_assertRefused(static_bodyWith2(ORDER_BODY, ORDER_IDENTIFIER, "bad", "\"9915543\"", "\"0\""), BILLING_LEMONSQUEEZY_REASON_IDENTIFIER_BAD);
  static_assertRefused(static_bodyWith2(ORDER_BODY, "\"9915543\"", "\"0\"", "\"paid\"", "\"pending\""), BILLING_LEMONSQUEEZY_REASON_ID_BAD);
  static_assertRefused(static_bodyWith2(ORDER_BODY, "\"9915543\"", "\"0\"", "\"paid\"", "1"), BILLING_LEMONSQUEEZY_REASON_ID_BAD);
  static_assertRefused(static_bodyWith2(SUB_BODY, "\"1234567\"", "\"0\"", "9915543", "0"), BILLING_LEMONSQUEEZY_REASON_ID_BAD);
  static_assertRefused(static_bodyWith2(SUB_BODY, "9915543", "0", "\"2026-11-01T04:20:44.000000Z\"", "5"), BILLING_LEMONSQUEEZY_REASON_ORDER_REF_BAD);
  static_assertRefused(static_bodyWith2(SUB_BODY, "\"2026-11-01T04:20:44.000000Z\"", "5", "\"2026-12-01T04:20:44.000000Z\"", "null"), BILLING_LEMONSQUEEZY_REASON_UPDATED_AT_BAD);
  const char* refunded_bad_id = static_bodyWith2(ORDER_BODY, "order_created", "order_refunded", "\"9915543\"", "\"0\"");
  static_assertRefused(refunded_bad_id, BILLING_LEMONSQUEEZY_REASON_ID_BAD);
  static_assertRefused(static_bodyWithIn(0, refunded_bad_id, "\"refunded\":false", "\"refunded\":1"), BILLING_LEMONSQUEEZY_REASON_ID_BAD);
  static_assertRefused(static_bodyWith2(INVOICE_BODY, "\"subscription-invoices\"", "\"orders\"", "1234567", "0"), BILLING_LEMONSQUEEZY_REASON_DATA_TYPE_BAD);
}

void test_parse_escaped_strings_decoded(void)
{
  const char* escaped = static_bodyWith2(ORDER_BODY, "\"order_created\"", "\"order\\u005fcreated\"", "\"orders\"", "\"\\u006frders\"");
  static_assertActs(escaped, BILLING_ACTION_ORDER_PAID);
  TEST_ASSERT_EQUAL_STRING("order_created", g_event.mp_eventName);
  static_assertActs(static_bodyWith(ORDER_BODY, "\"paid\"", "\"pa\\u0069d\""), BILLING_ACTION_ORDER_PAID);
}

void test_parse_unused_fields_reset_for_every_answer(void)
{
  static_assertActs(ORDER_BODY, BILLING_ACTION_ORDER_PAID);
  static_assertOnlyFields(F_WEBHOOK | F_ORDER_ID | F_ORDER_REF);
  TEST_ASSERT_EQUAL_INT64(0, g_event.m_providerUpdatedAt);
  static_assertActs(INVOICE_BODY, BILLING_ACTION_RECORD);
  static_assertOnlyFields(F_WEBHOOK | F_SUB_REF);
  static_assertRefused(static_bodyWith(SUB_BODY, "\"2026-12-01T04:20:44.000000Z\"", "5"), BILLING_LEMONSQUEEZY_REASON_ENDS_AT_BAD);
  TEST_ASSERT_EQUAL_STRING("subscription_cancelled", g_event.mp_eventName);
  static_assertIgnored("{\"meta\":{\"event_name\":\"subscription_paused\"}}", BILLING_LEMONSQUEEZY_REASON_EVENT_NOT_HANDLED);
  TEST_ASSERT_NULL(g_event.mp_eventName);
}

void test_registration_gate_test_count(void)
{
  TEST_ASSERT_EQUAL_INT_MESSAGE(48, (int)Unity.NumberOfTests,
    "RUN_TEST list and test definitions have drifted apart - a test may be unregistered");
}

#define NOWPAYMENTS_SECRET         "t_nowpayments_ipn_secret_0123456"
#define NOWPAYMENTS_ORDER_ID       "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d"
#define NOWPAYMENTS_VECTOR1_CANON  "{\"actually_paid\":0.5,\"invoice_id\":4522625843,\"note\":\"caf\\u00e9\",\"order_id\":\"5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d\",\"pay_amount\":0.5,\"payment_id\":5077125051,\"payment_status\":\"finished\"}"
#define NOWPAYMENTS_VECTOR1_HMAC   "045cf3401dbaabda212e4288ec3d5081e3697df1977059408049f98999354aec995eb9c11faf0c549b9b357644d5844445832bda0ac1270e70649f1548199647"
#define NOWPAYMENTS_VECTOR2_CANON  "{\"actually_paid\":0.99,\"order_id\":\"5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d\",\"pay_amount\":1.0,\"payment_id\":\"77\",\"payment_status\":\"partially_paid\"}"
#define NOWPAYMENTS_VECTOR2_HMAC   "6cd84788628fd801d5bf997afcf5a7aa39a1f834a8ec217689253622143efd56a7488deecbdc928564a905025bd43c802d9235159b669ba4f870f1356e13ff55"
#define NOWPAYMENTS_VECTOR2_HMAC31 "8868df2498f9593d0d39cf6a77119a6c6971ff3a5971f3d7022a626157d96dd1d36a949fc972d4f15e504013f763954577d4f89cf1a0a5e51439c466e7a42da7"
_Static_assert(sizeof(NOWPAYMENTS_SECRET) - 1 == BILLING_NOWPAYMENTS_SECRET_MIN_LEN, "NOWPAYMENTS_SECRET is at the floor");
_Static_assert(sizeof(NOWPAYMENTS_VECTOR1_HMAC) - 1 == BILLING_NOWPAYMENTS_SIGNATURE_LEN, "NOWPAYMENTS_VECTOR1_HMAC");

void test_nowpayments_constants(void)
{
  TEST_ASSERT_EQUAL_size_t(128, BILLING_NOWPAYMENTS_SIGNATURE_LEN);
  TEST_ASSERT_EQUAL_size_t(32, BILLING_NOWPAYMENTS_SECRET_MIN_LEN);
  TEST_ASSERT_EQUAL_size_t(65536, BILLING_NOWPAYMENTS_BODY_MAX_BYTE_COUNT);
  TEST_ASSERT_EQUAL_size_t(64, BILLING_NOWPAYMENTS_REF_MAX_LEN);
}

static void static_nowPaymentsSignature(char out[BILLING_NOWPAYMENTS_SIGNATURE_LEN + 1], char fill, char last)
{
  memset(out, fill, BILLING_NOWPAYMENTS_SIGNATURE_LEN);
  out[BILLING_NOWPAYMENTS_SIGNATURE_LEN - 1] = last;
  out[BILLING_NOWPAYMENTS_SIGNATURE_LEN]     = '\0';
}

void test_nowpayments_signature_shape(void)
{
  char signature[BILLING_NOWPAYMENTS_SIGNATURE_LEN + 1];
  static const char hex_digits[] = "0123456789abcdef";
  for (size_t i = 0; i < sizeof(hex_digits) - 1; i++)
  {
    static_nowPaymentsSignature(signature, hex_digits[i], hex_digits[i]);
    TEST_ASSERT_TRUE_MESSAGE(billing_isNowPaymentsSignatureWellFormed(signature, BILLING_NOWPAYMENTS_SIGNATURE_LEN), signature);
  }
  static_nowPaymentsSignature(signature, '0', '0');
  TEST_ASSERT_FALSE(billing_isNowPaymentsSignatureWellFormed(signature, BILLING_NOWPAYMENTS_SIGNATURE_LEN - 1));
  TEST_ASSERT_FALSE(billing_isNowPaymentsSignatureWellFormed(NULL, 0));
  char long_signature[BILLING_NOWPAYMENTS_SIGNATURE_LEN + 2];
  memset(long_signature, '0', sizeof(long_signature) - 1);
  long_signature[sizeof(long_signature) - 1] = '\0';
  TEST_ASSERT_FALSE(billing_isNowPaymentsSignatureWellFormed(long_signature, BILLING_NOWPAYMENTS_SIGNATURE_LEN + 1));

  static const char bad_last_bytes[] = "ABCDEFg/:@`G";
  for (size_t i = 0; i < sizeof(bad_last_bytes) - 1; i++)
  {
    static_nowPaymentsSignature(signature, '0', bad_last_bytes[i]);
    TEST_ASSERT_FALSE_MESSAGE(billing_isNowPaymentsSignatureWellFormed(signature, BILLING_NOWPAYMENTS_SIGNATURE_LEN), signature);
  }
}

void test_nowpayments_signature_reference_vectors(void)
{
  const size_t secret_len = strlen(NOWPAYMENTS_SECRET);
  TEST_ASSERT_TRUE(billing_isNowPaymentsSignatureValid(NOWPAYMENTS_SECRET, secret_len, NOWPAYMENTS_VECTOR1_CANON, strlen(NOWPAYMENTS_VECTOR1_CANON), NOWPAYMENTS_VECTOR1_HMAC, strlen(NOWPAYMENTS_VECTOR1_HMAC)));
  TEST_ASSERT_TRUE(billing_isNowPaymentsSignatureValid(NOWPAYMENTS_SECRET, secret_len, NOWPAYMENTS_VECTOR2_CANON, strlen(NOWPAYMENTS_VECTOR2_CANON), NOWPAYMENTS_VECTOR2_HMAC, strlen(NOWPAYMENTS_VECTOR2_HMAC)));

  TEST_ASSERT_FALSE(billing_isNowPaymentsSignatureValid(NOWPAYMENTS_SECRET, secret_len - 1, NOWPAYMENTS_VECTOR2_CANON, strlen(NOWPAYMENTS_VECTOR2_CANON), NOWPAYMENTS_VECTOR2_HMAC31, strlen(NOWPAYMENTS_VECTOR2_HMAC31)));
  TEST_ASSERT_FALSE(billing_isNowPaymentsSignatureValid(NOWPAYMENTS_SECRET, secret_len, NOWPAYMENTS_VECTOR1_CANON, strlen(NOWPAYMENTS_VECTOR1_CANON), NOWPAYMENTS_VECTOR2_HMAC, strlen(NOWPAYMENTS_VECTOR2_HMAC)));
  TEST_ASSERT_FALSE(billing_isNowPaymentsSignatureValid(NOWPAYMENTS_SECRET, secret_len, NOWPAYMENTS_VECTOR1_CANON, strlen(NOWPAYMENTS_VECTOR1_CANON) - 1, NOWPAYMENTS_VECTOR1_HMAC, strlen(NOWPAYMENTS_VECTOR1_HMAC)));
  TEST_ASSERT_FALSE(billing_isNowPaymentsSignatureValid(NOWPAYMENTS_SECRET, secret_len, NOWPAYMENTS_VECTOR1_CANON, strlen(NOWPAYMENTS_VECTOR1_CANON), NOWPAYMENTS_VECTOR1_HMAC, strlen(NOWPAYMENTS_VECTOR1_HMAC) - 1));
  char last_byte_differs[] = NOWPAYMENTS_VECTOR1_HMAC;
  last_byte_differs[BILLING_NOWPAYMENTS_SIGNATURE_LEN - 1] ^= 1;
  TEST_ASSERT_FALSE(billing_isNowPaymentsSignatureValid(NOWPAYMENTS_SECRET, secret_len, NOWPAYMENTS_VECTOR1_CANON, strlen(NOWPAYMENTS_VECTOR1_CANON), last_byte_differs, strlen(last_byte_differs)));
}

void test_nowpayments_body_signed_only_with_its_own_stored_secret(void)
{
  TEST_ASSERT_FALSE(billing_isNowPaymentsCanonicalBodySigned(NOWPAYMENTS_VECTOR1_CANON, strlen(NOWPAYMENTS_VECTOR1_CANON), NOWPAYMENTS_VECTOR1_HMAC, strlen(NOWPAYMENTS_VECTOR1_HMAC)));
  billing_setLemonSqueezySecret(NOWPAYMENTS_SECRET);
  TEST_ASSERT_FALSE(billing_isNowPaymentsCanonicalBodySigned(NOWPAYMENTS_VECTOR1_CANON, strlen(NOWPAYMENTS_VECTOR1_CANON), NOWPAYMENTS_VECTOR1_HMAC, strlen(NOWPAYMENTS_VECTOR1_HMAC)));
  billing_setLemonSqueezySecret(NULL);
  billing_setNowPaymentsSecret(NOWPAYMENTS_SECRET);
  TEST_ASSERT_TRUE(billing_isNowPaymentsCanonicalBodySigned(NOWPAYMENTS_VECTOR1_CANON, strlen(NOWPAYMENTS_VECTOR1_CANON), NOWPAYMENTS_VECTOR1_HMAC, strlen(NOWPAYMENTS_VECTOR1_HMAC)));
  billing_setNowPaymentsSecret(NULL);
  TEST_ASSERT_FALSE(billing_isNowPaymentsCanonicalBodySigned(NOWPAYMENTS_VECTOR1_CANON, strlen(NOWPAYMENTS_VECTOR1_CANON), NOWPAYMENTS_VECTOR1_HMAC, strlen(NOWPAYMENTS_VECTOR1_HMAC)));
}

static char g_nowPaymentsBody[4096];

static const char* static_nowPaymentsBody(const char* status_json, const char* invoice_json, const char* payment_json, const char* order_json, const char* paid_json, const char* amount_json)
{
  static const char* const keys[] = { "actually_paid", "invoice_id", "order_id", "pay_amount", "payment_id", "payment_status" };
  const char* const values[] = { paid_json, invoice_json, order_json, amount_json, payment_json, status_json };
  size_t used = 0;
  g_nowPaymentsBody[used++] = '{';
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
  {
    if (values[i] == NULL)
      continue;
    used += (size_t)snprintf(g_nowPaymentsBody + used, sizeof(g_nowPaymentsBody) - used, "%s\"%s\":%s", used > 1 ? "," : "", keys[i], values[i]);
  }
  snprintf(g_nowPaymentsBody + used, sizeof(g_nowPaymentsBody) - used, "}");
  return g_nowPaymentsBody;
}

#define NP_ORDER "\"" NOWPAYMENTS_ORDER_ID "\""

static void static_assertNowPaymentsPaid(const char* body, const char* event_name, const char* order_ref, const char* message)
{
  BillingNowPaymentsEvent_t event;
  billing_parseNowPaymentsEvent(body, strlen(body), &event);
  TEST_ASSERT_EQUAL_INT_MESSAGE(BILLING_ACTION_ORDER_PAID, event.m_action, message);
  TEST_ASSERT_EQUAL_INT_MESSAGE(BILLING_NOWPAYMENTS_REASON_NONE, event.m_reason, message);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(event_name, event.mp_eventName, message);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(NOWPAYMENTS_ORDER_ID, event.ma_orderId, message);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(order_ref, event.ma_providerOrderRef, message);
  char expected_ref[BILLING_NOWPAYMENTS_EVENT_REF_MAX_LEN + 1];
  snprintf(expected_ref, sizeof(expected_ref), "paid:%s", order_ref);
  TEST_ASSERT_EQUAL_STRING_MESSAGE(expected_ref, event.ma_eventRef, message);
}

static void static_assertNowPaymentsNotActed(const char* body, BillingAction_t action, BillingNowPaymentsReason_t reason, const char* message)
{
  BillingNowPaymentsEvent_t event;
  billing_parseNowPaymentsEvent(body, strlen(body), &event);
  TEST_ASSERT_EQUAL_INT_MESSAGE(action, event.m_action, message);
  TEST_ASSERT_EQUAL_INT_MESSAGE(reason, event.m_reason, message);
  TEST_ASSERT_NULL_MESSAGE(event.mp_eventName, message);
  TEST_ASSERT_EQUAL_STRING_MESSAGE("", event.ma_orderId, message);
  TEST_ASSERT_EQUAL_STRING_MESSAGE("", event.ma_providerOrderRef, message);
  TEST_ASSERT_EQUAL_STRING_MESSAGE("", event.ma_eventRef, message);
}

void test_nowpayments_finished_is_paid_with_each_field_from_its_key(void)
{
  static_assertNowPaymentsPaid(static_nowPaymentsBody("\"finished\"", "4522625843", "5077125051", NP_ORDER, "0.1", "9"), "finished", "4522625843", "finished");
  static_assertNowPaymentsPaid(NOWPAYMENTS_VECTOR1_CANON, "finished", "4522625843", "the reference vector");
}

void test_nowpayments_partially_paid_tolerance(void)
{
  static const struct { const char* mp_paid; const char* mp_amount; bool m_isPaid; } rows[] = {
    { "0.989999", "1.0", false },
    { "0.0693", "0.07", false },
    { "0.9899999999999999", "1", false },
    { "\"\"", "1", false },
    { "1", "\"\"", false },
    { "0.99",     "1.0", true  },
    { "1.0",      "1.0", true  },
    { "\"0.99\"", "\"1\"", true  },
    { "0.99",     "\"1.0\"", true },
    { "\"0.989999\"", "1.0", false },
    { "2",        "1",   true  },
    { "0.5",      "1",   false },
    { "1",        "0.5", true  },
    { "990",      "1000", true },
    { "989",      "1000", false },
  };
  for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
  {
    char message[64];
    snprintf(message, sizeof(message), "row %zu", i);
    const char* body = static_nowPaymentsBody("\"partially_paid\"", "11", NULL, NP_ORDER, rows[i].mp_paid, rows[i].mp_amount);
    if (rows[i].m_isPaid)
      static_assertNowPaymentsPaid(body, "partially_paid", "11", message);
    else
      static_assertNowPaymentsNotActed(body, BILLING_ACTION_IGNORE, BILLING_NOWPAYMENTS_REASON_NOT_PAID, message);
  }
}

void test_nowpayments_partially_paid_unreadable_amounts_are_ignored(void)
{
  static const struct { const char* mp_paid; const char* mp_amount; } rows[] = {
    { NULL,    "1"  }, { "1",   NULL  }, { "null", "1" }, { "1", "null" },
    { "true",  "1"  }, { "1",   "true" },
    { "\"abc\"", "1" }, { "1", "\"abc\"" }, { "\"\"", "1" }, { "1", "\"\"" },
    { "\"inf\"", "1" }, { "1", "\"nan\"" }, { "\"NaN\"", "1" }, { "1", "\"Infinity\"" },
    { "1",     "0"  }, { "1",   "0.0" }, { "1", "-1" }, { "-1", "-1" }, { "-1", "1" }, { "1", "\"0\"" }, { "1", "\"-1\"" },
    { "1e308", "1e-300" },
  };
  for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
  {
    char message[32];
    snprintf(message, sizeof(message), "row %zu", i);
    const char* body = static_nowPaymentsBody("\"partially_paid\"", "11", NULL, NP_ORDER, rows[i].mp_paid, rows[i].mp_amount);
    static_assertNowPaymentsNotActed(body, BILLING_ACTION_IGNORE, BILLING_NOWPAYMENTS_REASON_NOT_PAID, message);
  }
}

void test_nowpayments_other_statuses_are_ignored(void)
{
  static const char* const statuses[] = {
    "\"waiting\"", "\"confirming\"", "\"confirmed\"", "\"sending\"", "\"failed\"", "\"refunded\"", "\"expired\"",
    "\"finished \"", "\"FINISHED\"", "\"\"", "\"partially_paid_x\"", "\"a_very_long_status_that_fits_no_buffer\"", "null", "1", "true", "{}", "[]",
  };
  for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
  {
    const char* body = static_nowPaymentsBody(statuses[i], "11", NULL, NP_ORDER, "1", "1");
    static_assertNowPaymentsNotActed(body, BILLING_ACTION_IGNORE, BILLING_NOWPAYMENTS_REASON_NOT_PAID, statuses[i]);
  }
  static_assertNowPaymentsNotActed(static_nowPaymentsBody(NULL, "11", NULL, NP_ORDER, "1", "1"), BILLING_ACTION_IGNORE, BILLING_NOWPAYMENTS_REASON_NOT_PAID, "absent");
}

void test_nowpayments_repeated_deposit_is_ignored(void)
{
  static_assertNowPaymentsNotActed("{\"invoice_id\":11,\"order_id\":" NP_ORDER ",\"parent_payment_id\":5077125051,\"payment_status\":\"finished\"}", BILLING_ACTION_IGNORE, BILLING_NOWPAYMENTS_REASON_NOT_PAID, "number");
  static_assertNowPaymentsNotActed("{\"actually_paid\":1,\"invoice_id\":11,\"order_id\":" NP_ORDER ",\"parent_payment_id\":5077125051,\"pay_amount\":1,\"payment_status\":\"partially_paid\"}", BILLING_ACTION_IGNORE, BILLING_NOWPAYMENTS_REASON_NOT_PAID, "partial");
  static_assertNowPaymentsNotActed("{\"invoice_id\":11,\"order_id\":" NP_ORDER ",\"parent_payment_id\":\"5077125051\",\"payment_status\":\"finished\"}", BILLING_ACTION_IGNORE, BILLING_NOWPAYMENTS_REASON_NOT_PAID, "text");
  static_assertNowPaymentsPaid("{\"invoice_id\":11,\"order_id\":" NP_ORDER ",\"parent_payment_id\":null,\"payment_status\":\"finished\"}", "finished", "11", "null");
  static_assertNowPaymentsNotActed("{\"order_id\":" NP_ORDER ",\"parent_payment_id\":5,\"payment_status\":\"finished\"}", BILLING_ACTION_REFUSE, BILLING_NOWPAYMENTS_REASON_INVOICE_REF_MISSING, "parent no ref");
  static_assertNowPaymentsNotActed("{\"invoice_id\":11,\"order_id\":\"nope\",\"parent_payment_id\":5,\"payment_status\":\"finished\"}", BILLING_ACTION_REFUSE, BILLING_NOWPAYMENTS_REASON_ORDER_ID_BAD, "parent bad order");
  static_assertNowPaymentsPaid("{\"invoice_id\":11,\"order_id\":" NP_ORDER ",\"payment_status\":\"finished\"}", "finished", "11", "absent");
}

void test_nowpayments_invoice_ref_falls_through_to_payment_id(void)
{
  static const char* const empty_values[] = { "null", "0", "0.0", "-0.0", "\"\"", "false", "[]", "{}" };
  for (size_t i = 0; i < sizeof(empty_values) / sizeof(empty_values[0]); i++)
    static_assertNowPaymentsPaid(static_nowPaymentsBody("\"finished\"", empty_values[i], "5077", NP_ORDER, NULL, NULL), "finished", "5077", empty_values[i]);
  static_assertNowPaymentsPaid(static_nowPaymentsBody("\"finished\"", NULL, "5077", NP_ORDER, NULL, NULL), "finished", "5077", "absent");
  static_assertNowPaymentsPaid(static_nowPaymentsBody("\"finished\"", NULL, "\"p-77\"", NP_ORDER, NULL, NULL), "finished", "p-77", "string payment_id");
  static_assertNowPaymentsPaid(static_nowPaymentsBody("\"finished\"", "4522", "5077", NP_ORDER, NULL, NULL), "finished", "4522", "both, a number");
  static_assertNowPaymentsPaid(static_nowPaymentsBody("\"finished\"", "\"inv_7.aA-Z\"", "5077", NP_ORDER, NULL, NULL), "finished", "inv_7.aA-Z", "both, a string");
  static_assertNowPaymentsPaid(static_nowPaymentsBody("\"finished\"", "1.5", NULL, NP_ORDER, NULL, NULL), "finished", "1.5", "a float in its canonical form");

  static const char* const missing_pairs[][2] = { { NULL, NULL }, { "null", "null" }, { "0", "\"\"" }, { "false", "[]" } };
  for (size_t i = 0; i < sizeof(missing_pairs) / sizeof(missing_pairs[0]); i++)
    static_assertNowPaymentsNotActed(static_nowPaymentsBody("\"finished\"", missing_pairs[i][0], missing_pairs[i][1], NP_ORDER, NULL, NULL), BILLING_ACTION_REFUSE, BILLING_NOWPAYMENTS_REASON_INVOICE_REF_MISSING, "both empty");
}

void test_nowpayments_bad_invoice_ref_is_refused(void)
{
  static const char* const bad_values[] = { "true", "[1]", "{\"a\":1}", "\"a b\"", "\"a/b\"", "\"a+b\"", "\"caf\\u00e9\"", "1e+22", "\"a\\\"b\"" };
  for (size_t i = 0; i < sizeof(bad_values) / sizeof(bad_values[0]); i++)
    static_assertNowPaymentsNotActed(static_nowPaymentsBody("\"finished\"", bad_values[i], "5077", NP_ORDER, NULL, NULL), BILLING_ACTION_REFUSE, BILLING_NOWPAYMENTS_REASON_INVOICE_REF_BAD, bad_values[i]);

  char ref[BILLING_NOWPAYMENTS_REF_MAX_LEN + 2];
  memset(ref, '7', sizeof(ref) - 1);
  ref[sizeof(ref) - 1] = '\0';
  ref[BILLING_NOWPAYMENTS_REF_MAX_LEN] = '\0';

  char json[BILLING_NOWPAYMENTS_REF_MAX_LEN + 8];
  static_assertNowPaymentsPaid(static_nowPaymentsBody("\"finished\"", ref, NULL, NP_ORDER, NULL, NULL), "finished", ref, "64 digits");
  snprintf(json, sizeof(json), "\"%s\"", ref);
  static_assertNowPaymentsPaid(static_nowPaymentsBody("\"finished\"", json, NULL, NP_ORDER, NULL, NULL), "finished", ref, "a string of 64");

  memset(ref, '7', sizeof(ref) - 1);
  static_assertNowPaymentsNotActed(static_nowPaymentsBody("\"finished\"", ref, NULL, NP_ORDER, NULL, NULL), BILLING_ACTION_REFUSE, BILLING_NOWPAYMENTS_REASON_INVOICE_REF_BAD, "65 digits");
  snprintf(json, sizeof(json), "\"%s\"", ref);
  static_assertNowPaymentsNotActed(static_nowPaymentsBody("\"finished\"", json, NULL, NP_ORDER, NULL, NULL), BILLING_ACTION_REFUSE, BILLING_NOWPAYMENTS_REASON_INVOICE_REF_BAD, "a string of 65");
}

void test_nowpayments_order_id_is_strict(void)
{
  static const char* const bad_ids[] = { "\"5A6B7C8D-9E0F-4A1B-8C2D-3E4F5A6B7C8D\"", "\"5a6b7c8d9e0f4a1b8c2d3e4f5a6b7c8d\"", "\"not-a-uuid\"", "1", "null", "true", "\"\"" };
  for (size_t i = 0; i < sizeof(bad_ids) / sizeof(bad_ids[0]); i++)
    static_assertNowPaymentsNotActed(static_nowPaymentsBody("\"finished\"", "11", NULL, bad_ids[i], NULL, NULL), BILLING_ACTION_REFUSE, BILLING_NOWPAYMENTS_REASON_ORDER_ID_BAD, bad_ids[i]);
  static_assertNowPaymentsNotActed(static_nowPaymentsBody("\"finished\"", "11", NULL, NULL, NULL, NULL), BILLING_ACTION_REFUSE, BILLING_NOWPAYMENTS_REASON_ORDER_ID_BAD, "absent");
  static_assertNowPaymentsNotActed(static_nowPaymentsBody("\"waiting\"", "11", NULL, "\"nope\"", NULL, NULL), BILLING_ACTION_REFUSE, BILLING_NOWPAYMENTS_REASON_ORDER_ID_BAD, "an ignored status");
  static_assertNowPaymentsNotActed(static_nowPaymentsBody("\"finished\"", "true", NULL, "\"nope\"", NULL, NULL), BILLING_ACTION_REFUSE, BILLING_NOWPAYMENTS_REASON_INVOICE_REF_BAD, "the invoice ref first");
}

void test_nowpayments_root_only_and_no_repeated_key(void)
{
  static const char* const bad_bodies[] = {
    "{\"actually_paid\":1,\"actually_paid\":1,\"invoice_id\":1,\"order_id\":" NP_ORDER ",\"pay_amount\":1,\"payment_status\":\"finished\"}",
    "{\"invoice_id\":1,\"invoice_id\":2,\"order_id\":" NP_ORDER ",\"payment_status\":\"finished\"}",
    "{\"invoice_id\":1,\"order_id\":" NP_ORDER ",\"order_id\":" NP_ORDER ",\"payment_status\":\"finished\"}",
    "{\"invoice_id\":1,\"order_id\":" NP_ORDER ",\"pay_amount\":1,\"pay_amount\":1,\"payment_status\":\"finished\"}",
    "{\"invoice_id\":1,\"order_id\":" NP_ORDER ",\"payment_id\":1,\"payment_id\":1,\"payment_status\":\"finished\"}",
    "{\"invoice_id\":1,\"order_id\":" NP_ORDER ",\"payment_status\":\"waiting\",\"payment_status\":\"finished\"}",
    "{\"invoice_id\":1,\"order_id\":" NP_ORDER ",\"payment_\\u0073tatus\":\"finished\"}",
    "not json", "[]", "1", "",
  };
  for (size_t i = 0; i < sizeof(bad_bodies) / sizeof(bad_bodies[0]); i++)
    static_assertNowPaymentsNotActed(bad_bodies[i], BILLING_ACTION_REFUSE, BILLING_NOWPAYMENTS_REASON_BODY_BAD, bad_bodies[i]);

  BillingNowPaymentsEvent_t event;
  billing_parseNowPaymentsEvent(NULL, 0, &event);
  TEST_ASSERT_EQUAL_INT(BILLING_NOWPAYMENTS_REASON_BODY_BAD, event.m_reason);

  static_assertNowPaymentsNotActed("{\"invoice_id\":1,\"nested\":{\"payment_status\":\"finished\"},\"order_id\":" NP_ORDER ",\"payment_status\":\"waiting\"}", BILLING_ACTION_IGNORE, BILLING_NOWPAYMENTS_REASON_NOT_PAID, "nested status");
  static_assertNowPaymentsNotActed("{\"nested\":{\"invoice_id\":1},\"order_id\":" NP_ORDER ",\"payment_status\":\"finished\"}", BILLING_ACTION_REFUSE, BILLING_NOWPAYMENTS_REASON_INVOICE_REF_MISSING, "nested ref");
}

void test_nowpayments_reason_texts(void)
{
  TEST_ASSERT_EQUAL_STRING("the event is read", billing_nowPaymentsReasonText(BILLING_NOWPAYMENTS_REASON_NONE));
  TEST_ASSERT_EQUAL_STRING("the invoice is not paid", billing_nowPaymentsReasonText(BILLING_NOWPAYMENTS_REASON_NOT_PAID));
  TEST_ASSERT_EQUAL_STRING("the body is not a readable JSON object", billing_nowPaymentsReasonText(BILLING_NOWPAYMENTS_REASON_BODY_BAD));
  TEST_ASSERT_EQUAL_STRING("invoice_id and payment_id are both missing", billing_nowPaymentsReasonText(BILLING_NOWPAYMENTS_REASON_INVOICE_REF_MISSING));
  TEST_ASSERT_EQUAL_STRING("invoice_id or payment_id is not an id of 1 to 64 safe characters", billing_nowPaymentsReasonText(BILLING_NOWPAYMENTS_REASON_INVOICE_REF_BAD));
  TEST_ASSERT_EQUAL_STRING("order_id is missing or not a lower-case UUID", billing_nowPaymentsReasonText(BILLING_NOWPAYMENTS_REASON_ORDER_ID_BAD));
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_signature_rfc4231_cases_6_and_7_verify);
  RUN_TEST(test_signature_lemonsqueezy_body_verifies);
  RUN_TEST(test_signature_secret_floor_32_used_31_refused);
  RUN_TEST(test_signature_body_with_nul_is_signed_whole);
  RUN_TEST(test_signature_length_63_65_0_refused);
  RUN_TEST(test_signature_upper_case_copy_refused);
  RUN_TEST(test_signature_first_or_last_byte_changed_refused);
  RUN_TEST(test_signature_body_byte_changed_refused);
  RUN_TEST(test_parse_row1_meta_test_mode_true_ignored_before_later_fields);
  RUN_TEST(test_parse_row2_unhandled_names_ignored);
  RUN_TEST(test_parse_row2_too_long_name_not_handled);
  RUN_TEST(test_parse_row3_attributes_test_mode_true_ignored);
  RUN_TEST(test_parse_row4_order_paid);
  RUN_TEST(test_parse_row5_order_not_paid_ignored);
  RUN_TEST(test_parse_row6_subscription_cancelled_sets_expiry);
  RUN_TEST(test_parse_row7_cancelled_without_ends_at_refused);
  RUN_TEST(test_parse_row8_subscription_resumed_clears_expiry);
  RUN_TEST(test_parse_row9_subscription_expired_revokes);
  RUN_TEST(test_parse_row10_order_fully_refunded_revokes);
  RUN_TEST(test_parse_row11_order_partly_refunded_recorded);
  RUN_TEST(test_parse_row12_subscription_payment_refunded_recorded);
  RUN_TEST(test_parse_body_not_object_refused);
  RUN_TEST(test_parse_reads_body_len_bytes_only);
  RUN_TEST(test_parse_meta_bad_refused);
  RUN_TEST(test_parse_event_name_bad_refused);
  RUN_TEST(test_parse_test_mode_bad_refused);
  RUN_TEST(test_parse_meta_test_mode_absent_acts);
  RUN_TEST(test_parse_data_bad_refused);
  RUN_TEST(test_parse_webhook_id_bad_refused);
  RUN_TEST(test_parse_data_type_bad_refused);
  RUN_TEST(test_parse_id_bad_refused);
  RUN_TEST(test_parse_id_19_digits_and_1_digit_read);
  RUN_TEST(test_parse_order_ref_bad_refused);
  RUN_TEST(test_parse_order_ref_text_same_from_string_and_number);
  RUN_TEST(test_parse_subscription_ref_bad_refused);
  RUN_TEST(test_parse_identifier_bad_refused);
  RUN_TEST(test_parse_status_bad_refused);
  RUN_TEST(test_parse_updated_at_bad_refused);
  RUN_TEST(test_parse_updated_at_offset_read_as_utc);
  RUN_TEST(test_parse_time_of_35_bytes_read_36_refused);
  RUN_TEST(test_parse_ends_at_bad_refused);
  RUN_TEST(test_parse_refunded_bad_refused);
  RUN_TEST(test_parse_read_order_earlier_field_names_reason);
  RUN_TEST(test_parse_escaped_strings_decoded);
  RUN_TEST(test_parse_unused_fields_reset_for_every_answer);
  RUN_TEST(test_body_signed_only_with_a_stored_secret);
  RUN_TEST(test_body_signed_refuses_a_wrong_or_empty_signature);
  RUN_TEST(test_registration_gate_test_count);
  RUN_TEST(test_nowpayments_constants);
  RUN_TEST(test_nowpayments_signature_shape);
  RUN_TEST(test_nowpayments_signature_reference_vectors);
  RUN_TEST(test_nowpayments_body_signed_only_with_its_own_stored_secret);
  RUN_TEST(test_nowpayments_finished_is_paid_with_each_field_from_its_key);
  RUN_TEST(test_nowpayments_partially_paid_tolerance);
  RUN_TEST(test_nowpayments_partially_paid_unreadable_amounts_are_ignored);
  RUN_TEST(test_nowpayments_other_statuses_are_ignored);
  RUN_TEST(test_nowpayments_repeated_deposit_is_ignored);
  RUN_TEST(test_nowpayments_invoice_ref_falls_through_to_payment_id);
  RUN_TEST(test_nowpayments_bad_invoice_ref_is_refused);
  RUN_TEST(test_nowpayments_order_id_is_strict);
  RUN_TEST(test_nowpayments_root_only_and_no_repeated_key);
  RUN_TEST(test_nowpayments_reason_texts);
  return UNITY_END();
}
