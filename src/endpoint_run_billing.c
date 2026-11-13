#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "endpoint_run.h"
#include "auth.h"
#include "billing.h"
#include "db.h"
#include "jsonbuf.h"
#include "jsoncanon.h"
#include "serialize.h"
#include "external/nowpayments.h"

EndpointRunStatus_t endpoint_WEBHOOKLEMONSQUEEZYRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  assert(message_out != NULL);

  const WEBHOOKLEMONSQUEEZYParams_t* webhook = &params->m_webhookLemonSqueezy;
  const char* body     = (const char*)webhook->m_body.mp_bytes;
  size_t      body_len = webhook->m_body.m_byteCount;
  if (!billing_isLemonSqueezyBodySigned(body, body_len, webhook->ma_signature, strlen(webhook->ma_signature)))
  {
    *message_out = BILLING_LEMONSQUEEZY_SIGNATURE_REFUSAL_MESSAGE;
    return ENDPOINT_RUN_UNAUTHORIZED;
  }

  BillingLemonSqueezyEvent_t event;
  billing_parseLemonSqueezyEvent(body, body_len, &event);
  DbBillingEventStatus_t event_status = DB_BILLING_EVENT_APPLIED;
  DbStatus_t             db_status    = DB_OK;
  switch (event.m_action)
  {
    case BILLING_ACTION_REFUSE:
      *message_out = billing_lemonSqueezyReasonText(event.m_reason);
      return ENDPOINT_RUN_REFUSED;
    case BILLING_ACTION_IGNORE:
      serialize_WEBHOOK_status_response("ignored", json_buf);
      return ENDPOINT_RUN_OK;
    case BILLING_ACTION_ORDER_PAID:
      db_status = db_billingLemonSqueezyOrderPaid(conn, &event, &event_status);
      break;
    case BILLING_ACTION_SET_EXPIRY:
      db_status = db_billingLemonSqueezySetExpiry(conn, &event, &event_status);
      break;
    case BILLING_ACTION_CLEAR_EXPIRY:
      db_status = db_billingLemonSqueezyClearExpiry(conn, &event, &event_status);
      break;
    case BILLING_ACTION_REVOKE:
      db_status = db_billingLemonSqueezyRevoke(conn, &event, &event_status);
      break;
    case BILLING_ACTION_RECORD:
      db_status = db_billingLemonSqueezyEventRecord(conn, &event, &event_status);
      break;
  }
  if (db_status != DB_OK)
    return ENDPOINT_RUN_DB_ERROR;

  serialize_WEBHOOK_status_response(db_billingEventStatusText(event_status), json_buf);
  return ENDPOINT_RUN_OK;
}

static EndpointRunStatus_t static_readSignedNowPaymentsEvent(const char* body, size_t body_len, const char* signature, size_t signature_len, BillingNowPaymentsEvent_t* event_out)
{
  JsonBuf_t* canonical_buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  if (canonical_buf == NULL)
    return ENDPOINT_RUN_NO_MEMORY;

  bool   is_written    = jsoncanon_tryWrite(body, body_len, canonical_buf);
  size_t canonical_len = jsonbuf_length(canonical_buf);
  char*  canonical     = jsonbuf_finish(canonical_buf);
  jsonbuf_destroy(canonical_buf);

  EndpointRunStatus_t run_status = ENDPOINT_RUN_UNAUTHORIZED;
  if (is_written && canonical != NULL && billing_isNowPaymentsCanonicalBodySigned(canonical, canonical_len, signature, signature_len))
  {
    billing_parseNowPaymentsEvent(canonical, canonical_len, event_out);
    run_status = ENDPOINT_RUN_OK;
  }
  free(canonical);
  return run_status;
}

EndpointRunStatus_t endpoint_WEBHOOKNOWPAYMENTSRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  assert(message_out != NULL);

  const WEBHOOKNOWPAYMENTSParams_t* webhook = &params->m_webhookNowPayments;
  size_t signature_len = strlen(webhook->ma_signature);
  if (!billing_isNowPaymentsSignatureWellFormed(webhook->ma_signature, signature_len))
  {
    *message_out = BILLING_NOWPAYMENTS_SIGNATURE_REFUSAL_MESSAGE;
    return ENDPOINT_RUN_UNAUTHORIZED;
  }

  BillingNowPaymentsEvent_t event;
  EndpointRunStatus_t signed_status = static_readSignedNowPaymentsEvent((const char*)webhook->m_body.mp_bytes, webhook->m_body.m_byteCount, webhook->ma_signature, signature_len, &event);
  if (signed_status == ENDPOINT_RUN_UNAUTHORIZED)
    *message_out = BILLING_NOWPAYMENTS_SIGNATURE_REFUSAL_MESSAGE;
  if (signed_status != ENDPOINT_RUN_OK)
    return signed_status;

  if (event.m_action == BILLING_ACTION_REFUSE)
  {
    *message_out = billing_nowPaymentsReasonText(event.m_reason);
    return ENDPOINT_RUN_REFUSED;
  }
  if (event.m_action != BILLING_ACTION_ORDER_PAID)
  {
    serialize_WEBHOOK_status_response("ignored", json_buf);
    return ENDPOINT_RUN_OK;
  }

  DbBillingEventStatus_t event_status = DB_BILLING_EVENT_APPLIED;
  if (db_billingNowPaymentsOrderPaid(conn, event.ma_eventRef, event.mp_eventName, event.ma_orderId, event.ma_providerOrderRef, &event_status) != DB_OK)
    return ENDPOINT_RUN_DB_ERROR;

  serialize_WEBHOOK_status_response(db_billingEventStatusText(event_status), json_buf);
  return ENDPOINT_RUN_OK;
}

#define APIKEYCLAIM_ALREADY_CLAIMED_REFUSAL_MESSAGE "the API key of this order was claimed already; it is shown only once, so contact support"
#define APIKEYCLAIM_LAPSED_REFUSAL_MESSAGE          "the 24-hour claim window of this order has passed; contact support"
#define APIKEYCLAIM_REVOKED_REFUSAL_MESSAGE         "this order was refunded or has ended"

EndpointRunStatus_t endpoint_APIKEYCLAIMRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  assert(message_out != NULL);

  char api_key[API_KEY_TOTAL_LEN + 1];
  if (!auth_tryGenerateApiKey(api_key))
    return ENDPOINT_RUN_NO_MEMORY;

  char key_hash[SHA256_HEX_LEN + 1];
  auth_hashApiKey(api_key, key_hash);
  DbBillingClaimStatus_t claim_status = DB_BILLING_CLAIM_UNKNOWN;
  EndpointRunStatus_t    run_status   = ENDPOINT_RUN_DB_ERROR;
  if (db_billingClaim(conn, params->m_apiKeyClaim.ma_orderId, key_hash, &claim_status) == DB_OK)
  {
    switch (claim_status)
    {
      case DB_BILLING_CLAIM_CLAIMED:
        serialize_APIKEYCLAIM_response(api_key, json_buf);
        run_status = ENDPOINT_RUN_OK;
        break;
      case DB_BILLING_CLAIM_UNKNOWN:
        run_status = ENDPOINT_RUN_NOT_FOUND;
        break;
      case DB_BILLING_CLAIM_ALREADY_CLAIMED:
        *message_out = APIKEYCLAIM_ALREADY_CLAIMED_REFUSAL_MESSAGE;
        run_status   = ENDPOINT_RUN_GONE;
        break;
      case DB_BILLING_CLAIM_LAPSED:
        *message_out = APIKEYCLAIM_LAPSED_REFUSAL_MESSAGE;
        run_status   = ENDPOINT_RUN_GONE;
        break;
      case DB_BILLING_CLAIM_REVOKED:
        *message_out = APIKEYCLAIM_REVOKED_REFUSAL_MESSAGE;
        run_status   = ENDPOINT_RUN_GONE;
        break;
    }
  }
  explicit_bzero(api_key, sizeof(api_key));
  return run_status;
}

EndpointRunStatus_t endpoint_CRYPTOCHECKOUTRun(PGconn* conn, const EndpointAnyParams_t* params, JsonBuf_t* json_buf, const char** message_out)
{
  (void)conn;
  (void)params;
  (void)message_out;

  char order_id[VALIDATE_UUID_LEN + 1];
  if (!auth_tryGenerateUuid(order_id, sizeof(order_id)))
    return ENDPOINT_RUN_NO_MEMORY;

  NowPaymentsInvoice_t invoice;
  if (!nowpayments_tryCreateInvoice(order_id, &invoice))
    return ENDPOINT_RUN_UPSTREAM_ERROR;

  serialize_CRYPTOCHECKOUT_response(invoice.ma_id, invoice.ma_url, order_id, json_buf);
  return ENDPOINT_RUN_OK;
}
