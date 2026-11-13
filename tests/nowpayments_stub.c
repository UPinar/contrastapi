#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "external/nowpayments.h"
#include "nowpayments_stub.h"

bool        g_stub_nowpayments_should_fail   = false;
const char* g_stub_nowpayments_invoice_id    = "5532266";
const char* g_stub_nowpayments_invoice_url   = "https://nowpayments.io/payment/?iid=5532266";
int         g_stub_nowpayments_call_count    = 0;
char        g_stub_nowpayments_last_order_id[VALIDATE_UUID_LEN + 1];

void nowpayments_setApiKey(const char* api_key)
{
  (void)api_key;
}

bool nowpayments_tryCreateInvoice(const char* order_id, NowPaymentsInvoice_t* invoice_out)
{
  g_stub_nowpayments_call_count++;
  snprintf(g_stub_nowpayments_last_order_id, sizeof(g_stub_nowpayments_last_order_id), "%s", order_id);
  memset(invoice_out, 0, sizeof(*invoice_out));
  if (g_stub_nowpayments_should_fail)
    return false;
  snprintf(invoice_out->ma_id, sizeof(invoice_out->ma_id), "%s", g_stub_nowpayments_invoice_id);
  snprintf(invoice_out->ma_url, sizeof(invoice_out->ma_url), "%s", g_stub_nowpayments_invoice_url);
  return true;
}
