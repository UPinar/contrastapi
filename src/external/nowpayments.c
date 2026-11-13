#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "nowpayments.h"
#include "http.h"
#include "jsonread.h"
#include "pricing.h"
#include "validate.h"

#define NOWPAYMENTS_CREATE_INVOICE_URL "https://api.nowpayments.io/v1/invoice"

#define NOWPAYMENTS_API_KEY_HEADER_PREFIX "X-API-Key: "

#define NOWPAYMENTS_CONTENT_TYPE_HEADER "Content-Type: application/json"

#define NOWPAYMENTS_ORDER_DESCRIPTION "ContrastAPI Pro 30-day key"

#define NOWPAYMENTS_INVOICE_URL_PREFIX "https://nowpayments.io/"

#define NOWPAYMENTS_REQUEST_BODY_BUF_SIZE 512

static const char* g_apiKey = NULL;

static bool static_tryBuildBody       (const char* order_id, char* body_out, size_t body_size);
static bool static_tryReadInvoice     (const HttpResponse_t* response, NowPaymentsInvoice_t* invoice_out);
static bool static_tryReadInvoiceId   (JsonReadSpan_t id_span, char* id_out, size_t id_size);

void nowpayments_setApiKey(const char* api_key)
{
  g_apiKey = api_key;
}

bool nowpayments_tryCreateInvoice(const char* order_id, NowPaymentsInvoice_t* invoice_out)
{
  assert(order_id != NULL);
  assert(invoice_out != NULL);

  memset(invoice_out, 0, sizeof(*invoice_out));
  if (g_apiKey == NULL || !validate_uuid(order_id))
    return false;

  char body[NOWPAYMENTS_REQUEST_BODY_BUF_SIZE];
  if (!static_tryBuildBody(order_id, body, sizeof(body)))
    return false;

  bool is_invoice_read = false;
  char key_header[sizeof(NOWPAYMENTS_API_KEY_HEADER_PREFIX) + NOWPAYMENTS_API_KEY_MAX_LEN];
  int  key_header_len = snprintf(key_header, sizeof(key_header), NOWPAYMENTS_API_KEY_HEADER_PREFIX "%s", g_apiKey);
  if (key_header_len >= 0 && (size_t)key_header_len < sizeof(key_header))
  {
    const char* const   header_lines[] = { key_header, NOWPAYMENTS_CONTENT_TYPE_HEADER, NULL };
    const HttpRequest_t request = {
      .mp_url                   = NOWPAYMENTS_CREATE_INVOICE_URL,
      .m_timeoutMs              = NOWPAYMENTS_TIMEOUT_MS,
      .mp_extraHeaders          = header_lines,
      .m_maxBodyByteCount       = NOWPAYMENTS_MAX_BODY_BYTE_COUNT,
      .m_isTargetTrusted        = true,
      .m_isRedirectLeftToCaller = true,
    };
    HttpResponse_t response = http_POSTWithOptions(&request, body, strlen(body));
    is_invoice_read = static_tryReadInvoice(&response, invoice_out);
    http_free(&response);
  }
  explicit_bzero(key_header, sizeof(key_header));

  if (!is_invoice_read)
    memset(invoice_out, 0, sizeof(*invoice_out));
  return is_invoice_read;
}

static bool static_tryBuildBody(const char* order_id, char* body_out, size_t body_size)
{
  int written = snprintf(body_out, body_size,
    R"({)"
      R"("price_amount":%d,)"
      R"("price_currency":"usd",)"
      R"("order_id":"%s",)"
      R"("order_description":")" NOWPAYMENTS_ORDER_DESCRIPTION R"(",)"
      R"("ipn_callback_url":")" PRICING_API_BASE_URL R"(/webhook_nowpayments",)"
      R"("success_url":")" PRICING_API_BASE_URL R"(/welcome?order_id=%s",)"
      R"("cancel_url":")" PRICING_PAGE_URL R"(")"
    R"(})",
    PRICING_PRO_MONTHLY_USD, order_id, order_id);
  return written > 0 && (size_t)written < body_size;
}

static bool static_tryReadInvoice(const HttpResponse_t* response, NowPaymentsInvoice_t* invoice_out)
{
  if (response->m_status < 200 || response->m_status > 299)
    return false;

  JsonReadSpan_t root_span = { 0 };
  JsonReadSpan_t id_span   = { 0 };
  JsonReadSpan_t url_span  = { 0 };
  if (jsonread_root(response->mp_body, response->m_bodyLen, &root_span) != JSONREAD_OK  ||
      jsonread_objectKey(root_span, "id", &id_span) != JSONREAD_OK                      ||
      jsonread_objectKey(root_span, "invoice_url", &url_span) != JSONREAD_OK)
  {
    return false;
  }

  if (!static_tryReadInvoiceId(id_span, invoice_out->ma_id, sizeof(invoice_out->ma_id)))
    return false;
  if (jsonread_spanToStrStatus(url_span, invoice_out->ma_url, sizeof(invoice_out->ma_url)) != JSONREAD_OK)
    return false;
  return strncmp(invoice_out->ma_url, NOWPAYMENTS_INVOICE_URL_PREFIX, strlen(NOWPAYMENTS_INVOICE_URL_PREFIX)) == 0;
}

static bool static_tryReadInvoiceId(JsonReadSpan_t id_span, char* id_out, size_t id_size)
{
  JsonReadStatus_t text_status = jsonread_spanToStrStatus(id_span, id_out, id_size);
  if (text_status == JSONREAD_OK)
    return id_out[0] != '\0';
  if (text_status != JSONREAD_ERR_TYPE)
    return false;

  long id_number = 0;
  if (jsonread_spanToLongStatus(id_span, &id_number) != JSONREAD_OK || id_number <= 0)
    return false;
  
  int id_len = snprintf(id_out, id_size, "%ld", id_number);
  return id_len >= 0 && (size_t)id_len < id_size;
}
