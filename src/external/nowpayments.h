#ifndef NOWPAYMENTS_H
#define NOWPAYMENTS_H

#include <stdbool.h>

#define NOWPAYMENTS_TIMEOUT_MS 10000

#define NOWPAYMENTS_MAX_BODY_BYTE_COUNT (16 * 1024)

#define NOWPAYMENTS_API_KEY_MAX_LEN 128

#define NOWPAYMENTS_INVOICE_ID_MAX_LEN 32

#define NOWPAYMENTS_INVOICE_URL_MAX_LEN 512

typedef struct {
  char  ma_id[NOWPAYMENTS_INVOICE_ID_MAX_LEN + 1];
  char  ma_url[NOWPAYMENTS_INVOICE_URL_MAX_LEN + 1];
} NowPaymentsInvoice_t;

void nowpayments_setApiKey         (const char* api_key);
bool nowpayments_tryCreateInvoice  (const char* order_id, NowPaymentsInvoice_t* invoice_out) __attribute__((warn_unused_result));

#endif
