#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jsonbuf.h"
#include "x402.h"

static X402Requirements_t static_requirements(void)
{
  X402Requirements_t requirements;
  memset(&requirements, 0, sizeof(requirements));
  snprintf(requirements.ma_network,  sizeof(requirements.ma_network),  "%s", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp");
  snprintf(requirements.ma_asset,    sizeof(requirements.ma_asset),    "%s", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
  snprintf(requirements.ma_payTo,    sizeof(requirements.ma_payTo),    "%s", "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin");
  snprintf(requirements.ma_feePayer, sizeof(requirements.ma_feePayer), "%s", "2wmVCSfPxGPjrnMMn7rchp4uaeoTqN39mXFC2zhPdri9");
  requirements.m_amountAtomic      = 10000;
  requirements.m_maxTimeoutSeconds = 60;
  return requirements;
}

static void static_parse(const char* value, size_t value_len, const X402Requirements_t* requirements, bool is_json)
{
  char* exact = malloc(value_len > 0 ? value_len : 1);
  if (exact == NULL)
    abort();
  memcpy(exact, value, value_len);

  X402Payment_t payment;
  memset(&payment, 0, sizeof(payment));
  X402PaymentStatus_t status = is_json ? x402_parsePaymentJson(exact, value_len, requirements, &payment)
                                       : x402_parsePaymentHeader(exact, value_len, requirements, &payment);
  if (status == X402_PAYMENT_OK &&
      (payment.m_transactionByteCount == 0 || payment.m_transactionByteCount > X402_SOLANA_MAX_TRANSACTION_BYTE_COUNT))
    abort();
  free(exact);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  X402Requirements_t requirements = static_requirements();

  static_parse((const char*)data, size, &requirements, false);
  static_parse((const char*)data, size, &requirements, true);

  size_t base64_size = X402_BASE64_LEN(size) + 1;
  char*  base64_text = malloc(base64_size);
  if (base64_text == NULL)
    abort();
  if (!x402_tryEncodeBase64(data, size, base64_text, base64_size))
    abort();
  static_parse(base64_text, base64_size - 1, &requirements, false);
  if (x402_tryEncodeBase64(data, size, base64_text, base64_size - 1))
    abort();
  free(base64_text);

  char* error_text = malloc(size + 1);
  if (error_text == NULL)
    abort();
  memcpy(error_text, data, size);
  error_text[size] = '\0';
  JsonBuf_t* buf = jsonbuf_create(JSONBUF_INITIAL_CAP, JSONBUF_DEFAULT_CEILING);
  if (buf == NULL)
    abort();
  (void)x402_writePaymentRequired(buf, &requirements, error_text, error_text, error_text);
  free(jsonbuf_finish(buf));
  jsonbuf_destroy(buf);
  free(error_text);

  return 0;
}
