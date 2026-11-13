#ifndef BILLING_H
#define BILLING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "auth.h"
#include "validate.h"

#define BILLING_LEMONSQUEEZY_SECRET_MIN_LEN 32
#define BILLING_LEMONSQUEEZY_SIGNATURE_LEN  SHA256_HEX_LEN

#define BILLING_LEMONSQUEEZY_SIGNATURE_REFUSAL_MESSAGE "X-Signature does not match the body"

#define BILLING_LEMONSQUEEZY_BODY_MAX_BYTE_COUNT 65536

#define BILLING_LEMONSQUEEZY_EVENT_NAME_MAX_LEN 40
#define BILLING_LEMONSQUEEZY_REF_MAX_LEN        19

#define BILLING_NOWPAYMENTS_SECRET_MIN_LEN 32
#define BILLING_NOWPAYMENTS_SIGNATURE_LEN  128

#define BILLING_NOWPAYMENTS_SIGNATURE_REFUSAL_MESSAGE "x-nowpayments-sig does not match the body"

#define BILLING_NOWPAYMENTS_BODY_MAX_BYTE_COUNT 65536

#define BILLING_NOWPAYMENTS_REF_MAX_LEN       64
#define BILLING_NOWPAYMENTS_EVENT_REF_MAX_LEN (5 + BILLING_NOWPAYMENTS_REF_MAX_LEN)

typedef enum {
  BILLING_ACTION_IGNORE,
  BILLING_ACTION_ORDER_PAID,
  BILLING_ACTION_SET_EXPIRY,
  BILLING_ACTION_CLEAR_EXPIRY,
  BILLING_ACTION_REVOKE,
  BILLING_ACTION_RECORD,
  BILLING_ACTION_REFUSE,
} BillingAction_t;

typedef enum {
  BILLING_LEMONSQUEEZY_REASON_NONE,
  BILLING_LEMONSQUEEZY_REASON_TEST_MODE,
  BILLING_LEMONSQUEEZY_REASON_EVENT_NOT_HANDLED,
  BILLING_LEMONSQUEEZY_REASON_ORDER_NOT_PAID,
  BILLING_LEMONSQUEEZY_REASON_BODY_NOT_OBJECT,
  BILLING_LEMONSQUEEZY_REASON_META_BAD,
  BILLING_LEMONSQUEEZY_REASON_EVENT_NAME_BAD,
  BILLING_LEMONSQUEEZY_REASON_TEST_MODE_BAD,
  BILLING_LEMONSQUEEZY_REASON_DATA_BAD,
  BILLING_LEMONSQUEEZY_REASON_WEBHOOK_ID_BAD,
  BILLING_LEMONSQUEEZY_REASON_DATA_TYPE_BAD,
  BILLING_LEMONSQUEEZY_REASON_ID_BAD,
  BILLING_LEMONSQUEEZY_REASON_ORDER_REF_BAD,
  BILLING_LEMONSQUEEZY_REASON_SUBSCRIPTION_REF_BAD,
  BILLING_LEMONSQUEEZY_REASON_IDENTIFIER_BAD,
  BILLING_LEMONSQUEEZY_REASON_STATUS_BAD,
  BILLING_LEMONSQUEEZY_REASON_UPDATED_AT_BAD,
  BILLING_LEMONSQUEEZY_REASON_ENDS_AT_MISSING,
  BILLING_LEMONSQUEEZY_REASON_ENDS_AT_BAD,
  BILLING_LEMONSQUEEZY_REASON_REFUNDED_BAD,
} BillingLemonSqueezyReason_t;

typedef struct {
  BillingAction_t             m_action;
  BillingLemonSqueezyReason_t m_reason;
  const char*                 mp_eventName;
  char                        ma_webhookId[VALIDATE_UUID_LEN + 1];
  char                        ma_orderId[VALIDATE_UUID_LEN + 1];
  char                        ma_providerOrderRef[BILLING_LEMONSQUEEZY_REF_MAX_LEN + 1];
  char                        ma_providerSubscriptionRef[BILLING_LEMONSQUEEZY_REF_MAX_LEN + 1];
  int64_t                     m_providerUpdatedAt;
  int64_t                     m_endsAt;
} BillingLemonSqueezyEvent_t;

typedef enum {
  BILLING_NOWPAYMENTS_REASON_NONE,
  BILLING_NOWPAYMENTS_REASON_NOT_PAID,
  BILLING_NOWPAYMENTS_REASON_BODY_BAD,
  BILLING_NOWPAYMENTS_REASON_INVOICE_REF_MISSING,
  BILLING_NOWPAYMENTS_REASON_INVOICE_REF_BAD,
  BILLING_NOWPAYMENTS_REASON_ORDER_ID_BAD,
} BillingNowPaymentsReason_t;

typedef struct {
  BillingAction_t            m_action;
  BillingNowPaymentsReason_t m_reason;
  const char*                mp_eventName;
  char                       ma_eventRef[BILLING_NOWPAYMENTS_EVENT_REF_MAX_LEN + 1];
  char                       ma_orderId[VALIDATE_UUID_LEN + 1];
  char                       ma_providerOrderRef[BILLING_NOWPAYMENTS_REF_MAX_LEN + 1];
} BillingNowPaymentsEvent_t;

bool        billing_isLemonSqueezySignatureValid    (const char* secret, size_t secret_len, const char* body, size_t body_len, const char* signature, size_t signature_len) __attribute__((warn_unused_result));
void        billing_setLemonSqueezySecret           (const char* secret);
bool        billing_isLemonSqueezyBodySigned        (const char* body, size_t body_len, const char* signature, size_t signature_len) __attribute__((warn_unused_result));
void        billing_parseLemonSqueezyEvent          (const char* body, size_t body_len, BillingLemonSqueezyEvent_t* event_out);
const char* billing_lemonSqueezyReasonText          (BillingLemonSqueezyReason_t reason);

bool        billing_isNowPaymentsSignatureWellFormed(const char* signature, size_t signature_len) __attribute__((warn_unused_result));
bool        billing_isNowPaymentsSignatureValid     (const char* secret, size_t secret_len, const char* canonical_body, size_t canonical_body_len, const char* signature, size_t signature_len) __attribute__((warn_unused_result));
void        billing_setNowPaymentsSecret            (const char* secret);
bool        billing_isNowPaymentsCanonicalBodySigned(const char* canonical_body, size_t canonical_body_len, const char* signature, size_t signature_len) __attribute__((warn_unused_result));
void        billing_parseNowPaymentsEvent           (const char* body, size_t body_len, BillingNowPaymentsEvent_t* event_out);
const char* billing_nowPaymentsReasonText           (BillingNowPaymentsReason_t reason);

#endif
