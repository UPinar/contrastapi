#ifndef NOWPAYMENTS_STUB_H
#define NOWPAYMENTS_STUB_H

#include <stdbool.h>

#include "validate.h"

extern bool g_stub_nowpayments_should_fail;

extern const char* g_stub_nowpayments_invoice_id;
extern const char* g_stub_nowpayments_invoice_url;

extern int  g_stub_nowpayments_call_count;
extern char g_stub_nowpayments_last_order_id[VALIDATE_UUID_LEN + 1];

#endif
